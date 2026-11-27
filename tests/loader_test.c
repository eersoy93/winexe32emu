/*
Copyright 2026 Erdem Ersoy (eersoy93)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
Loader and memory test - a DLL the EXE imports (loader_test_dll.dll: bound
and initialized before main), DLL reference counts and unloading with
FreeLibrary, DLL_THREAD_ATTACH/DETACH and DisableThreadLibraryCalls,
process and thread ids, and the page protections: VirtualProtect, guard
pages, reserved and committed pages, the image sections and DEP.

"loader_test.exe" runs the tests and sets the DLL's process exit marker;
"loader_test.exe exitcheck" (a second run) checks that DllMain saw the end
of the first process. Every check prints PASS or FAIL; the exit code is the
failure count.
*/

#include <windows.h>
#include <stdio.h>
#include <string.h>

/* The DLL's exports (a static import: linked with loader_test_dll.dll) */
__declspec(dllimport) int __stdcall loader_add(int a, int b);
__declspec(dllimport) LONG loader_count(int which);
__declspec(dllimport) void loader_set_marker(const char *path);

#define EXIT_MARKER "C:\\Windows\\Temp\\loader_test_exit.tmp"
#define FREE_MARKER "C:\\Windows\\Temp\\loader_test_free.tmp"
#define DLLONEXIT_MARKER "C:\\Windows\\Temp\\loader_test_dllonexit.tmp"
#define DLL_COPY "C:\\Windows\\Temp\\loader_copy.dll"

static int failures = 0;

static void check(int ok, const char *name)
{
    printf("%s: %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok)
        failures++;
}

static int read_marker(const char *path, char *text)
{
    DWORD done = 0;
    HANDLE file = CreateFileA(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    text[0] = 0;
    if (file == INVALID_HANDLE_VALUE)
        return 0;
    ReadFile(file, text, 4, &done, NULL);
    text[done] = 0;
    CloseHandle(file);
    return 1;
}

/* ---- Memory probes: an access that faults resumes at probe_resume ---- */

void probe_read(void *address);
void probe_write(void *address);
void probe_exec(void *address);
void probe_resume(void);

__asm__(
    ".globl _probe_read\n_probe_read:\n"
    "    movl 4(%esp), %eax\n"
    "    movl (%eax), %eax\n"
    "    ret\n"
    ".globl _probe_write\n_probe_write:\n"
    "    movl 4(%esp), %eax\n"
    "    movl $0x5A5A5A5A, (%eax)\n"
    "    ret\n"
    ".globl _probe_exec\n_probe_exec:\n"
    "    jmp *4(%esp)\n"   /* the code there returns to the caller */
    ".globl _probe_resume\n_probe_resume:\n"
    "    ret\n");

static volatile DWORD fault_code, fault_kind, fault_address;

static LONG CALLBACK probe_handler(EXCEPTION_POINTERS *pointers)
{
    EXCEPTION_RECORD *record = pointers->ExceptionRecord;
    if (record->ExceptionCode != EXCEPTION_ACCESS_VIOLATION &&
        record->ExceptionCode != STATUS_GUARD_PAGE_VIOLATION)
        return EXCEPTION_CONTINUE_SEARCH;
    fault_code = record->ExceptionCode;
    fault_kind = record->NumberParameters >= 2 ? record->ExceptionInformation[0] : 0xFF;
    fault_address = record->NumberParameters >= 2 ? record->ExceptionInformation[1] : 0;
    pointers->ContextRecord->Eip = (DWORD)probe_resume;
    return EXCEPTION_CONTINUE_EXECUTION;
}

/* The exception code an access raises (0 if none) */
static DWORD probe(void (*access)(void *), void *address)
{
    fault_code = 0;
    access(address);
    return fault_code;
}

/* ---- Loader ---- */

static LIST_ENTRY *ldr_head(void)
{
    BYTE *peb;
    __asm__ volatile("movl %%fs:0x30, %0" : "=r"(peb));
    return (LIST_ENTRY *)(*(BYTE **)(peb + 0x0C) + 0x0C);
}

static int in_loader_list(const WCHAR *name)
{
    LIST_ENTRY *head = ldr_head(), *link;
    for (link = head->Flink; link != head; link = link->Flink) {
        WCHAR *base_name = *(WCHAR **)((BYTE *)link + 0x30);
        if (base_name && _wcsicmp(base_name, name) == 0)
            return 1;
    }
    return 0;
}

static DWORD WINAPI returning_thread(LPVOID param)
{
    return 0;
}

static DWORD WINAPI exiting_thread(LPVOID param)
{
    ExitThread(0);
    return 1;
}

static void run_thread(LPTHREAD_START_ROUTINE start)
{
    HANDLE thread = CreateThread(NULL, 0, start, NULL, 0, NULL);
    if (thread == NULL) {
        check(0, "CreateThread");
        return;
    }
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
}

static void test_static_import(void)
{
    check(loader_add(2, 3) == 5, "A static import of the program's DLL is bound");
    check(loader_count(0) == 1, "Its DllMain(DLL_PROCESS_ATTACH) ran before main");
    check(in_loader_list(L"loader_test_dll.dll"), "It is in PEB->Ldr");
}

static void test_thread_notifications(void)
{
    LONG attach = loader_count(1), detach = loader_count(2);
    run_thread(returning_thread);
    check(loader_count(1) == attach + 1, "DLL_THREAD_ATTACH for a new thread");
    check(loader_count(2) == detach + 1, "DLL_THREAD_DETACH when it returns");
    run_thread(exiting_thread);
    check(loader_count(2) == detach + 2, "DLL_THREAD_DETACH when it calls ExitThread");
}

static void test_free_library(void)
{
    char path[MAX_PATH], text[8];
    HMODULE copy, again;
    LONG (*copy_count)(int);
    void (*copy_set_marker)(const char *), (*copy_set_exit_marker)(const char *);
    BOOL (*copy_disable)(HMODULE);
    LONG static_attach;

    GetModuleFileNameA(GetModuleHandleA("loader_test_dll.dll"), path, sizeof(path));
    DeleteFileA(FREE_MARKER);
    DeleteFileA(DLLONEXIT_MARKER);
    check(CopyFileA(path, DLL_COPY, FALSE), "Copy the DLL");
    copy = LoadLibraryA(DLL_COPY);
    again = LoadLibraryA("loader_copy.dll");
    check(copy != NULL && again == copy, "LoadLibrary twice: one module");
    if (copy == NULL)
        return;
    copy_count = (LONG (*)(int))(void *)GetProcAddress(copy, "loader_count");
    copy_set_marker = (void (*)(const char *))(void *)GetProcAddress(copy, "loader_set_marker");
    copy_set_exit_marker = (void (*)(const char *))(void *)GetProcAddress(
        copy, "loader_set_exit_marker");
    copy_disable = (BOOL (*)(HMODULE))(void *)GetProcAddress(copy, "loader_disable_thread_calls");
    check(copy_count && copy_count(0) == 1, "The copy has its own DllMain and data");
    copy_set_marker(FREE_MARKER);
    copy_set_exit_marker(DLLONEXIT_MARKER);

    static_attach = loader_count(1);
    check(copy_disable(copy), "DisableThreadLibraryCalls");
    run_thread(returning_thread);
    check(copy_count(1) == 0 && loader_count(1) == static_attach + 1,
          "No DLL_THREAD_ATTACH after DisableThreadLibraryCalls");

    check(FreeLibrary(copy) && GetModuleHandleA("loader_copy.dll") == copy,
          "FreeLibrary of one of two references keeps the DLL");
    check(!read_marker(FREE_MARKER, text), "No DLL_PROCESS_DETACH yet");
    check(FreeLibrary(again) && GetModuleHandleA("loader_copy.dll") == NULL,
          "FreeLibrary of the last reference unloads the DLL");
    check(read_marker(FREE_MARKER, text) && strcmp(text, "free") == 0,
          "DllMain(DLL_PROCESS_DETACH) of FreeLibrary");
    /* Run at exit() instead, the handler would call into the unloaded DLL */
    check(read_marker(DLLONEXIT_MARKER, text) && strcmp(text, "dlox") == 0,
          "__dllonexit fills the DLL's own table, run at FreeLibrary");
    check(!in_loader_list(L"loader_copy.dll"), "The unloaded DLL left PEB->Ldr");
    SetLastError(0);
    check(!FreeLibrary((HMODULE)0x12340000) && GetLastError() == ERROR_MOD_NOT_FOUND,
          "FreeLibrary of no module fails");
    DeleteFileA(FREE_MARKER);
    DeleteFileA(DLLONEXIT_MARKER);
    DeleteFileA(DLL_COPY);
}

/* ---- Process and thread ids ---- */

static void test_ids(void)
{
    DWORD pid = GetCurrentProcessId(), teb_pid, teb_tid, code = 0;
    HANDLE self;
    WCHAR exe[MAX_PATH], command[MAX_PATH + 16];
    STARTUPINFOW startup;
    PROCESS_INFORMATION info;

    __asm__ volatile("movl %%fs:0x20, %0" : "=r"(teb_pid));
    __asm__ volatile("movl %%fs:0x24, %0" : "=r"(teb_tid));
    check(teb_pid == pid && teb_tid == GetCurrentThreadId(), "The TEB holds the ids");
    self = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    check(self != NULL && GetProcessId(self) == pid, "OpenProcess of the own id");
    if (self)
        CloseHandle(self);

    GetModuleFileNameW(NULL, exe, MAX_PATH);
    swprintf(command, MAX_PATH + 16, L"\"%ls\" child", exe);
    memset(&startup, 0, sizeof(startup));
    startup.cb = sizeof(startup);
    if (!CreateProcessW(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &info)) {
        check(0, "CreateProcess of a child");
        return;
    }
    WaitForSingleObject(info.hProcess, INFINITE);
    GetExitCodeProcess(info.hProcess, &code);
    check(info.dwProcessId != pid && info.dwThreadId != GetCurrentThreadId(),
          "A child process has its own ids");
    check(code == info.dwProcessId, "The child's GetCurrentProcessId is its id");
    CloseHandle(info.hProcess);
    CloseHandle(info.hThread);
}

/* ---- Page protections ---- */

static const char rdata_value[] = "constant";

static BYTE *thread_probe_page;
static DWORD thread_probe_result;

static DWORD WINAPI probing_thread(LPVOID param)
{
    thread_probe_result = probe(probe_write, thread_probe_page);
    return 0;
}

static void test_memory(void)
{
    BYTE *page = VirtualAlloc(NULL, 0x3000, MEM_COMMIT, PAGE_READWRITE);
    BYTE *reserved;
    DWORD old = 0;
    MEMORY_BASIC_INFORMATION mbi;
    IMAGE_NT_HEADERS32 *nt;
    BYTE *image = (BYTE *)GetModuleHandleA(NULL);
    PVOID handler = AddVectoredExceptionHandler(1, probe_handler);

    check(page != NULL && probe(probe_write, page) == 0, "VirtualAlloc(PAGE_READWRITE): write");
    check(VirtualProtect(page, 0x1000, PAGE_READONLY, &old) && old == PAGE_READWRITE,
          "VirtualProtect(PAGE_READONLY) returns the old protection");
    check(probe(probe_read, page) == 0, "Read of a read-only page");
    check(probe(probe_write, page + 4) == EXCEPTION_ACCESS_VIOLATION && fault_kind == 1 &&
          fault_address == (DWORD)(page + 4), "Write of a read-only page: an access violation");
    check(probe(probe_write, page + 0x1000) == 0, "The next page stays writable");
    check(VirtualQuery(page, &mbi, sizeof(mbi)) && mbi.Protect == PAGE_READONLY &&
          mbi.RegionSize == 0x1000, "VirtualQuery: the read-only page");
    check(VirtualProtect(page, 0x1000, PAGE_NOACCESS, &old) && old == PAGE_READONLY &&
          probe(probe_read, page) == EXCEPTION_ACCESS_VIOLATION && fault_kind == 0,
          "PAGE_NOACCESS: a read is an access violation");
    SetLastError(0);
    check(!VirtualProtect(page, 0x1000, 0x03, &old) && GetLastError() == ERROR_INVALID_PARAMETER,
          "VirtualProtect of an invalid protection fails");

    /* Guard pages: an exception at the first access only */
    check(VirtualProtect(page + 0x2000, 0x1000, PAGE_READWRITE | PAGE_GUARD, &old),
          "VirtualProtect(PAGE_GUARD)");
    check(probe(probe_read, page + 0x2000) == STATUS_GUARD_PAGE_VIOLATION,
          "First access of a guard page: STATUS_GUARD_PAGE_VIOLATION");
    check(probe(probe_write, page + 0x2000) == 0, "Then it is an ordinary page");
    check(VirtualQuery(page + 0x2000, &mbi, sizeof(mbi)) && mbi.Protect == PAGE_READWRITE,
          "VirtualQuery: the guard is gone");
    VirtualProtect(page, 0x1000, PAGE_READWRITE, &old);

    /* Many changes (the emulator compacts its record of them), then a thread
       started afterwards sees the result */
    {
        int i, ok = 1;
        for (i = 0; i < 1500 && ok; i++)
            ok = VirtualProtect(page + 0x1000, 0x1000, i % 2 ? PAGE_READWRITE : PAGE_READONLY,
                                &old);
        thread_probe_page = page + 0x1000;
        thread_probe_result = 0;
        run_thread(probing_thread);
        check(ok && thread_probe_result == 0, "1500 VirtualProtect calls; a new thread writes");
        VirtualProtect(page + 0x1000, 0x1000, PAGE_READONLY, &old);
        run_thread(probing_thread);
        check(thread_probe_result == EXCEPTION_ACCESS_VIOLATION,
              "A new thread sees the read-only page");
    }
    check(VirtualFree(page, 0, MEM_RELEASE), "VirtualFree(MEM_RELEASE)");

    /* Reserved pages: no access until committed */
    reserved = VirtualAlloc(NULL, 0x2000, MEM_RESERVE, PAGE_READWRITE);
    check(reserved != NULL && probe(probe_read, reserved) == EXCEPTION_ACCESS_VIOLATION,
          "MEM_RESERVE: the pages cannot be accessed");
    check(VirtualQuery(reserved, &mbi, sizeof(mbi)) && mbi.State == MEM_RESERVE,
          "VirtualQuery: MEM_RESERVE");
    SetLastError(0);
    check(!VirtualProtect(reserved, 0x1000, PAGE_READONLY, &old) &&
          GetLastError() == ERROR_INVALID_ADDRESS, "VirtualProtect of reserved pages fails");
    check(VirtualAlloc(reserved, 0x1000, MEM_COMMIT, PAGE_READWRITE) == reserved &&
          probe(probe_write, reserved) == 0 &&
          probe(probe_write, reserved + 0x1000) == EXCEPTION_ACCESS_VIOLATION,
          "MEM_COMMIT of one page: only that page is accessible");
    check(VirtualFree(reserved, 0x1000, MEM_DECOMMIT) &&
          probe(probe_read, reserved) == EXCEPTION_ACCESS_VIOLATION,
          "MEM_DECOMMIT: no access again");
    check(VirtualAlloc(reserved, 0x1000, MEM_COMMIT, PAGE_READWRITE) == reserved &&
          *(volatile DWORD *)reserved == 0, "Committed again: zeroed");
    VirtualFree(reserved, 0, MEM_RELEASE);

    /* The image: read-only headers and constants */
    check(probe(probe_write, image) == EXCEPTION_ACCESS_VIOLATION,
          "The image headers are read-only");
    check(probe(probe_write, (void *)rdata_value) == EXCEPTION_ACCESS_VIOLATION &&
          strcmp(rdata_value, "constant") == 0, "The read-only data section is read-only");

    /* DEP: only for NX-compatible programs (like 32-bit Windows by default) */
    nt = (IMAGE_NT_HEADERS32 *)(image + ((IMAGE_DOS_HEADER *)image)->e_lfanew);
    page = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    if (page) {
        page[0] = 0xC3;  /* ret */
        if (nt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
            check(probe(probe_exec, page) == EXCEPTION_ACCESS_VIOLATION && fault_kind == 8,
                  "DEP (NX-compatible program): no execution of PAGE_READWRITE memory");
        else
            check(probe(probe_exec, page) == 0, "No DEP: PAGE_READWRITE memory executes");
        check(VirtualProtect(page, 0x1000, PAGE_EXECUTE_READ, &old) &&
              probe(probe_exec, page) == 0, "PAGE_EXECUTE_READ memory executes");
        VirtualFree(page, 0, MEM_RELEASE);
    }
    RemoveVectoredExceptionHandler(handler);
}

int main(int argc, char **argv)
{
    char text[8];

    if (argc > 1 && strcmp(argv[1], "child") == 0)
        return (int)GetCurrentProcessId();
    if (argc > 1 && strcmp(argv[1], "exitcheck") == 0) {
        printf("=== Loader test (process exit) ===\n");
        check(read_marker(EXIT_MARKER, text) && strcmp(text, "exit") == 0,
              "DllMain(DLL_PROCESS_DETACH) when the previous process ended");
        DeleteFileA(EXIT_MARKER);
        printf("\n== %d failure(s) ==\n", failures);
        return failures;
    }

    printf("=== Loader test ===\n");
    DeleteFileA(EXIT_MARKER);
    test_static_import();
    test_thread_notifications();
    test_free_library();
    test_ids();
    test_memory();
    loader_set_marker(EXIT_MARKER);
    printf("\n== %d failure(s) ==\n", failures);
    return failures;
}
