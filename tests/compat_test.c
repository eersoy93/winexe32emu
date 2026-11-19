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
Compatibility test - what programs expect of Windows beyond the API calls:
case-insensitive file names, the trailing dots and invalid characters of
names, the NUL/CON devices, the buffer sizes the path APIs return, the
in-memory images of the system DLLs (MZ/PE headers, export table), the
PEB's loader data and process parameters, and static TLS with TLS
callbacks. Every check prints PASS or FAIL; the exit code is the failure
count.
*/

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

static int failures = 0;

static void check(int ok, const char *name)
{
    printf("%s: %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok)
        failures++;
}

/* ---- Static TLS and TLS callbacks (the PE TLS directory of MinGW's tlssup) ---- */

extern ULONG _tls_index;
extern char _tls_start;

/* A static TLS variable: in the .tls section, after _tls_start */
__attribute__((section(".tls$AAB"), used)) int tls_value = 42;

static volatile LONG process_attach_calls = 0, thread_attach_calls = 0;
static volatile LONG thread_detach_calls = 0;
static volatile LONG entry_reached = 0;

static void NTAPI tls_callback(PVOID module, DWORD reason, PVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH && !entry_reached)
        process_attach_calls++;
    else if (reason == DLL_THREAD_ATTACH)
        thread_attach_calls++;
    else if (reason == DLL_THREAD_DETACH)
        thread_detach_calls++;
}

__attribute__((section(".CRT$XLB"), used)) PIMAGE_TLS_CALLBACK tls_callback_ptr = tls_callback;

/* This thread's copy of tls_value, found like compiled __declspec(thread) code does */
static int *tls_value_ptr(void)
{
    void **array;
    __asm__ volatile("movl %%fs:0x2C, %0" : "=r"(array));
    if (array == NULL || array[_tls_index] == NULL)
        return NULL;
    return (int *)((char *)array[_tls_index] + ((char *)&tls_value - &_tls_start));
}

static int *thread_tls_ptr;
static int thread_tls_initial;

static DWORD WINAPI tls_thread(LPVOID param)
{
    thread_tls_ptr = tls_value_ptr();
    thread_tls_initial = thread_tls_ptr ? *thread_tls_ptr : -1;
    return 0;
}

static void test_tls(void)
{
    int *mine = tls_value_ptr();
    HANDLE thread;

    check(process_attach_calls >= 1, "TLS callback DLL_PROCESS_ATTACH before the entry point");
    check(mine != NULL && *mine == 42, "Static TLS: the main thread's copy of the template");
    if (mine)
        *mine = 7;
    thread = CreateThread(NULL, 0, tls_thread, NULL, 0, NULL);
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    check(thread_tls_ptr != NULL && thread_tls_ptr != mine,
          "Static TLS: a new thread gets its own block");
    check(thread_tls_initial == 42, "Static TLS: the new thread's copy is the template");
    check(mine != NULL && *mine == 7, "Static TLS: the main thread's value is kept");
    check(thread_attach_calls >= 1, "TLS callback DLL_THREAD_ATTACH");
    check(thread_detach_calls >= 1, "TLS callback DLL_THREAD_DETACH");
}

/* ---- File names ---- */

static void test_file_names(void)
{
    HANDLE file;
    DWORD done;
    char buffer[16];
    WIN32_FIND_DATAA find;
    HANDLE search;

    file = CreateFileA("C:\\Windows\\Temp\\Compat_Test.tmp", GENERIC_WRITE, 0, NULL,
                       CREATE_ALWAYS, 0, NULL);
    check(file != INVALID_HANDLE_VALUE, "CreateFile(Compat_Test.tmp)");
    WriteFile(file, "case", 4, &done, NULL);
    CloseHandle(file);
    file = CreateFileA("c:\\WINDOWS\\temp\\COMPAT_TEST.TMP", GENERIC_READ, 0, NULL,
                       OPEN_EXISTING, 0, NULL);
    check(file != INVALID_HANDLE_VALUE, "Case-insensitive names: c:\\WINDOWS\\temp\\COMPAT_TEST.TMP");
    memset(buffer, 0, sizeof(buffer));
    if (file != INVALID_HANDLE_VALUE) {
        ReadFile(file, buffer, sizeof(buffer) - 1, &done, NULL);
        CloseHandle(file);
    }
    check(strcmp(buffer, "case") == 0, "Case-insensitive names: the same file");
    check(GetFileAttributesA("C:\\WINDOWS\\SYSTEM32") == FILE_ATTRIBUTE_DIRECTORY,
          "Case-insensitive names: GetFileAttributes(C:\\WINDOWS\\SYSTEM32)");
    check(DeleteFileA("C:\\windows\\TEMP\\compat_test.TMP"), "Case-insensitive names: DeleteFile");

    /* Trailing dots and spaces are dropped */
    file = CreateFileA("C:\\Windows\\Temp\\compat_dot.tmp. .", GENERIC_WRITE, 0, NULL,
                       CREATE_ALWAYS, 0, NULL);
    check(file != INVALID_HANDLE_VALUE, "CreateFile(\"compat_dot.tmp. .\")");
    CloseHandle(file);
    check(GetFileAttributesA("C:\\Windows\\Temp\\compat_dot.tmp") != INVALID_FILE_ATTRIBUTES,
          "Trailing dots and spaces are dropped");
    DeleteFileA("C:\\Windows\\Temp\\compat_dot.tmp");

    /* Invalid names: an alternate data stream (C: is FAT32), wildcards */
    SetLastError(0);
    file = CreateFileA("C:\\Windows\\Temp\\compat.tmp:stream", GENERIC_WRITE, 0, NULL,
                       CREATE_ALWAYS, 0, NULL);
    check(file == INVALID_HANDLE_VALUE && GetLastError() == ERROR_INVALID_NAME,
          "CreateFile(\"x:stream\") -> ERROR_INVALID_NAME");
    file = CreateFileA("C:\\Windows\\Temp\\a*b.tmp", GENERIC_WRITE, 0, NULL,
                       CREATE_ALWAYS, 0, NULL);
    check(file == INVALID_HANDLE_VALUE && GetLastError() == ERROR_INVALID_NAME,
          "CreateFile(\"a*b.tmp\") -> ERROR_INVALID_NAME");

    /* Devices: NUL takes everything, no file of that name is created */
    file = CreateFileA("NUL", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    check(file != INVALID_HANDLE_VALUE, "CreateFile(NUL)");
    check(WriteFile(file, "12345", 5, &done, NULL) && done == 5, "WriteFile(NUL)");
    check(ReadFile(file, buffer, 4, &done, NULL) && done == 0, "ReadFile(NUL): end of file");
    check(GetFileType(file) == FILE_TYPE_CHAR, "GetFileType(NUL) == FILE_TYPE_CHAR");
    CloseHandle(file);
    file = CreateFileA("C:\\Windows\\Temp\\nul.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                       0, NULL);
    check(file != INVALID_HANDLE_VALUE, "CreateFile(C:\\Windows\\Temp\\nul.txt) is NUL");
    CloseHandle(file);
    search = FindFirstFileA("C:\\Windows\\Temp\\nul*", &find);
    check(search == INVALID_HANDLE_VALUE, "No file named NUL is created");
    if (search != INVALID_HANDLE_VALUE)
        FindClose(search);
    file = CreateFileA("COM1", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    check(file == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_NOT_FOUND,
          "CreateFile(COM1): no serial port");
    file = CreateFileA("CONOUT$", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    check(file != INVALID_HANDLE_VALUE && WriteFile(file, "CONOUT$ works\n", 14, &done, NULL),
          "CreateFile(CONOUT$) writes to the console");

    {
        FILE *stream = fopen("NUL", "w");
        check(stream != NULL && fprintf(stream, "nothing") == 7, "fopen(NUL)");
        if (stream)
            fclose(stream);
        stream = fopen("CON", "w");
        check(stream != NULL, "fopen(CON)");
        if (stream) {
            fprintf(stream, "CON works\n");
            fclose(stream);
        }
    }
}

/* ---- Buffer sizes of the path APIs ---- */

static void test_buffer_sizes(void)
{
    char small[4] = "zzz";
    WCHAR wsmall[4] = L"zzz";
    char full[MAX_PATH];

    check(GetSystemDirectoryA(small, sizeof(small)) == strlen("C:\\Windows\\System32") + 1 &&
          small[0] == 'z', "GetSystemDirectoryA(small buffer): the size needed");
    check(GetSystemDirectoryA(full, sizeof(full)) == strlen("C:\\Windows\\System32") &&
          strcmp(full, "C:\\Windows\\System32") == 0, "GetSystemDirectoryA");
    check(GetWindowsDirectoryA(small, sizeof(small)) == strlen("C:\\Windows") + 1,
          "GetWindowsDirectoryA(small buffer): the size needed");
    check(GetWindowsDirectoryW(wsmall, 4) == wcslen(L"C:\\Windows") + 1,
          "GetWindowsDirectoryW(small buffer): the size needed");
    check(GetSystemDirectoryW(wsmall, 4) == wcslen(L"C:\\Windows\\System32") + 1,
          "GetSystemDirectoryW(small buffer): the size needed");
    check(GetTempPathA(sizeof(small), small) == strlen("C:\\Windows\\Temp\\") + 1,
          "GetTempPathA(small buffer): the size needed");
    check(GetTempPathA(sizeof(full), full) == strlen(full) && full[strlen(full) - 1] == '\\',
          "GetTempPathA");
}

/* ---- The system DLLs in memory ---- */

static FARPROC export_by_name(HMODULE module, const char *name)
{
    BYTE *base = (BYTE *)module;
    IMAGE_NT_HEADERS32 *nt = (IMAGE_NT_HEADERS32 *)(base + ((IMAGE_DOS_HEADER *)base)->e_lfanew);
    IMAGE_DATA_DIRECTORY *dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    IMAGE_EXPORT_DIRECTORY *exports = (IMAGE_EXPORT_DIRECTORY *)(base + dir->VirtualAddress);
    DWORD *names = (DWORD *)(base + exports->AddressOfNames);
    WORD *ordinals = (WORD *)(base + exports->AddressOfNameOrdinals);
    DWORD *functions = (DWORD *)(base + exports->AddressOfFunctions);
    DWORD i;

    for (i = 0; i < exports->NumberOfNames; i++)
        if (strcmp((char *)base + names[i], name) == 0)
            return (FARPROC)(base + functions[ordinals[i]]);
    return NULL;
}

static void test_system_dll_images(void)
{
    HMODULE kernel32 = GetModuleHandleA("KERNEL32.DLL");
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)kernel32;
    IMAGE_NT_HEADERS32 *nt;
    FARPROC found;
    char path[MAX_PATH];

    check(kernel32 != NULL && dos->e_magic == IMAGE_DOS_SIGNATURE,
          "GetModuleHandle(kernel32): an MZ header");
    if (kernel32 == NULL || dos->e_magic != IMAGE_DOS_SIGNATURE)
        return;
    nt = (IMAGE_NT_HEADERS32 *)((BYTE *)kernel32 + dos->e_lfanew);
    check(nt->Signature == IMAGE_NT_SIGNATURE && nt->FileHeader.Machine == IMAGE_FILE_MACHINE_I386 &&
          (nt->FileHeader.Characteristics & IMAGE_FILE_DLL) &&
          nt->OptionalHeader.ImageBase == (DWORD)kernel32, "kernel32: a PE header of a DLL");
    found = export_by_name(kernel32, "GetProcAddress");
    check(found != NULL && found == GetProcAddress(kernel32, "GetProcAddress"),
          "kernel32 export table: GetProcAddress");
    found = export_by_name(kernel32, "GetCurrentThreadId");
    check(found != NULL && ((DWORD (WINAPI *)(void))found)() == GetCurrentThreadId(),
          "kernel32 export table: calling GetCurrentThreadId");
    check(GetModuleFileNameA(kernel32, path, sizeof(path)) &&
          _stricmp(path, "C:\\Windows\\System32\\kernel32.dll") == 0,
          "GetModuleFileName(kernel32)");
    check(LoadLibraryA("kernel32.dll") == kernel32, "LoadLibrary(kernel32) is the same image");
}

/* ---- The PEB ---- */

typedef struct {
    USHORT Length, MaximumLength;
    PWSTR Buffer;
} USTRING;

typedef struct {
    LIST_ENTRY InLoadOrderLinks, InMemoryOrderLinks, InInitializationOrderLinks;
    PVOID DllBase, EntryPoint;
    ULONG SizeOfImage;
    USTRING FullDllName, BaseDllName;
} LDR_ENTRY;

static BYTE *peb(void)
{
    BYTE *p;
    __asm__ volatile("movl %%fs:0x30, %0" : "=r"(p));
    return p;
}

static void test_peb(void)
{
    BYTE *ldr = *(BYTE **)(peb() + 0x0C);
    BYTE *params = *(BYTE **)(peb() + 0x10);
    LIST_ENTRY *head, *link;
    LDR_ENTRY *entry;
    int found_kernel32 = 0, count = 0;
    USTRING *command_line, *image_path, *current;
    WCHAR directory[MAX_PATH];

    check(ldr != NULL, "PEB->Ldr");
    if (ldr) {
        head = (LIST_ENTRY *)(ldr + 0x0C);
        entry = (LDR_ENTRY *)head->Flink;
        check(entry->DllBase == GetModuleHandleA(NULL), "PEB->Ldr: the EXE comes first");
        for (link = head->Flink; link != head && count < 100; link = link->Flink, count++) {
            entry = (LDR_ENTRY *)link;
            if (entry->DllBase == (PVOID)GetModuleHandleA("kernel32.dll") &&
                _wcsicmp(entry->BaseDllName.Buffer, L"kernel32.dll") == 0)
                found_kernel32 = 1;
        }
        check(found_kernel32, "PEB->Ldr: kernel32.dll in the load order list");
        head = (LIST_ENTRY *)(ldr + 0x1C);
        entry = (LDR_ENTRY *)((BYTE *)head->Flink - 0x10);
        check(head->Flink != head && _wcsicmp(entry->BaseDllName.Buffer, L"ntdll.dll") == 0,
              "PEB->Ldr: ntdll.dll is initialized first");
    }

    check(params != NULL, "PEB->ProcessParameters");
    if (params) {
        command_line = (USTRING *)(params + 0x40);
        image_path = (USTRING *)(params + 0x38);
        current = (USTRING *)(params + 0x24);
        check(command_line->Buffer == GetCommandLineW() &&
              command_line->Length == 2 * wcslen(GetCommandLineW()),
              "ProcessParameters->CommandLine");
        check(image_path->Buffer && wcsstr(image_path->Buffer, L"compat_test.exe") != NULL,
              "ProcessParameters->ImagePathName");
        SetCurrentDirectoryA("C:\\Windows");
        GetCurrentDirectoryW(MAX_PATH, directory);
        wcscat(directory, L"\\");
        check(current->Buffer && _wcsicmp(current->Buffer, directory) == 0 &&
              current->Length == 2 * wcslen(directory),
              "ProcessParameters->CurrentDirectory follows SetCurrentDirectory");
    }
}

int main(void)
{
    entry_reached = 1;
    printf("=== Compatibility test ===\n");
    test_tls();
    test_file_names();
    test_buffer_sizes();
    test_system_dll_images();
    test_peb();
    printf("\n== %d failure(s) ==\n", failures);
    return failures;
}
