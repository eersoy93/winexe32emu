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
Thread test - exercises threads (CreateThread, _beginthreadex, suspended
threads, exit codes), synchronization objects (events, semaphores, mutexes,
critical sections, WaitForMultipleObjects), thread local storage, named
objects, file mappings, 64-bit file pointers and loading a real DLL
(thread_test_dll.dll). Every check prints PASS or FAIL; the exit code is
the failure count.
*/

#include <windows.h>
#include <process.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;

static void check(int ok, const char *name)
{
    printf("%s: %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok)
        failures++;
}

static CRITICAL_SECTION cs;
static HANDLE start_event, done_semaphore;
static volatile LONG finished = 0;
static int shared_counter = 0;
static DWORD tls_index;

static DWORD WINAPI counting_thread(LPVOID param)
{
    int i;
    WaitForSingleObject(start_event, INFINITE);
    TlsSetValue(tls_index, param);
    for (i = 0; i < 500; i++) {
        EnterCriticalSection(&cs);
        shared_counter++;
        if (i % 50 == 0)
            Sleep(0);  /* Let the other threads try to enter meanwhile */
        LeaveCriticalSection(&cs);
    }
    InterlockedIncrement(&finished);
    ReleaseSemaphore(done_semaphore, 1, NULL);
    return TlsGetValue(tls_index) == param ? (DWORD)(INT_PTR)param : 0xBAD;
}

static HANDLE ping_event, pong_event;

static DWORD WINAPI pong_thread(LPVOID param)
{
    int i;
    for (i = 0; i < 50; i++) {
        WaitForSingleObject(ping_event, INFINITE);
        SetEvent(pong_event);
    }
    return 0;
}

static DWORD WINAPI exit_thread(LPVOID param)
{
    ExitThread(77);
    return 1;
}

static unsigned __stdcall crt_thread(void *param)
{
    *(int *)param = 42;
    return 5;
}

static HANDLE mutex;

static DWORD WINAPI mutex_thread(LPVOID param)
{
    return WaitForSingleObject(mutex, 0);
}

static DWORD WINAPI mapping_thread(LPVOID param)
{
    HANDLE mapping = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, "emu_thread_test_map");
    char *view;
    DWORD ok;
    if (!mapping)
        return 0;
    view = (char *)MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    ok = view && strcmp(view, "shared text") == 0;
    if (view)
        strcpy(view + 64, "written by thread");
    CloseHandle(mapping);
    return ok;
}

static void test_threads(void)
{
    HANDLE threads[4];
    DWORD code, id;
    int i, value = 0;
    HANDLE thread;

    InitializeCriticalSection(&cs);
    tls_index = TlsAlloc();
    check(tls_index != TLS_OUT_OF_INDEXES, "TlsAlloc");
    TlsSetValue(tls_index, (LPVOID)1234);
    start_event = CreateEventA(NULL, TRUE, FALSE, NULL);
    done_semaphore = CreateSemaphoreA(NULL, 0, 10, NULL);
    for (i = 0; i < 3; i++)
        threads[i] = CreateThread(NULL, 0, counting_thread, (LPVOID)(INT_PTR)(10 + i), 0, &id);
    threads[3] = CreateThread(NULL, 0, counting_thread, (LPVOID)13, CREATE_SUSPENDED, &id);
    check(threads[0] && threads[3], "CreateThread");
    check(WaitForSingleObject(start_event, 0) == WAIT_TIMEOUT, "unsignaled event times out");
    check(ResumeThread(threads[3]) == 1, "ResumeThread returns the previous suspend count");
    SetEvent(start_event);
    check(WaitForMultipleObjects(4, threads, TRUE, 20000) == WAIT_OBJECT_0,
          "WaitForMultipleObjects (wait all threads)");
    check(finished == 4 && shared_counter == 2000, "critical section and InterlockedIncrement");
    for (i = 0; i < 4; i++) {
        check(GetExitCodeThread(threads[i], &code) && code == (DWORD)(10 + i),
              "GetExitCodeThread (thread TLS value)");
        CloseHandle(threads[i]);
    }
    check(TlsGetValue(tls_index) == (LPVOID)1234, "TLS value of the main thread is kept");
    for (i = 0; i < 4; i++)
        WaitForSingleObject(done_semaphore, 0);
    check(WaitForSingleObject(done_semaphore, 0) == WAIT_TIMEOUT, "semaphore count");

    ping_event = CreateEventA(NULL, FALSE, FALSE, NULL);
    pong_event = CreateEventA(NULL, FALSE, FALSE, NULL);
    thread = CreateThread(NULL, 0, pong_thread, NULL, 0, &id);
    for (i = 0; i < 50; i++) {
        SetEvent(ping_event);
        if (WaitForSingleObject(pong_event, 10000) != WAIT_OBJECT_0)
            break;
    }
    check(i == 50, "auto-reset events ping-pong between two threads");
    check(WaitForSingleObject(thread, 10000) == WAIT_OBJECT_0, "thread handle is signaled at exit");
    CloseHandle(thread);

    thread = CreateThread(NULL, 0, exit_thread, NULL, 0, &id);
    WaitForSingleObject(thread, 10000);
    check(GetExitCodeThread(thread, &code) && code == 77, "ExitThread exit code");
    CloseHandle(thread);

    thread = (HANDLE)_beginthreadex(NULL, 0, crt_thread, &value, 0, NULL);
    WaitForSingleObject(thread, 10000);
    check(value == 42 && GetExitCodeThread(thread, &code) && code == 5, "_beginthreadex");
    CloseHandle(thread);

    mutex = CreateMutexA(NULL, TRUE, NULL);
    thread = CreateThread(NULL, 0, mutex_thread, NULL, 0, &id);
    WaitForSingleObject(thread, 10000);
    check(GetExitCodeThread(thread, &code) && code == WAIT_TIMEOUT, "owned mutex blocks other threads");
    CloseHandle(thread);
    check(ReleaseMutex(mutex), "ReleaseMutex");
    CloseHandle(mutex);
    DeleteCriticalSection(&cs);
    TlsFree(tls_index);
}

static void test_named_objects(void)
{
    HANDLE event, again, opened, mapping, thread;
    char *view;
    DWORD code, id;

    event = CreateEventA(NULL, TRUE, FALSE, "emu_thread_test_event");
    again = CreateEventA(NULL, TRUE, FALSE, "emu_thread_test_event");
    check(again && GetLastError() == ERROR_ALREADY_EXISTS, "named event already exists");
    opened = OpenEventA(EVENT_ALL_ACCESS, FALSE, "emu_thread_test_event");
    check(opened != NULL, "OpenEventA");
    SetEvent(opened);
    check(WaitForSingleObject(event, 0) == WAIT_OBJECT_0, "named event handles share the object");
    CloseHandle(event);
    CloseHandle(again);
    CloseHandle(opened);
    check(OpenEventA(EVENT_ALL_ACCESS, FALSE, "emu_thread_test_event") == NULL &&
          GetLastError() == ERROR_FILE_NOT_FOUND, "the last handle destroys a named event");

    mapping = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 4096,
                                 "emu_thread_test_map");
    view = (char *)MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    check(view != NULL, "CreateFileMappingA / MapViewOfFile");
    strcpy(view, "shared text");
    thread = CreateThread(NULL, 0, mapping_thread, NULL, 0, &id);
    WaitForSingleObject(thread, 10000);
    check(GetExitCodeThread(thread, &code) && code == 1 && strcmp(view + 64, "written by thread") == 0,
          "file mapping shared with another thread (OpenFileMappingA)");
    CloseHandle(thread);
    UnmapViewOfFile(view);
    CloseHandle(mapping);
}

static void test_file_pointer(void)
{
    char path[] = "C:\\Windows\\Temp\\thread_test.bin";
    HANDLE file = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    LONG high = -1;
    DWORD written, low;
    check(file != INVALID_HANDLE_VALUE, "CreateFileA (temporary file)");
    WriteFile(file, "0123456789", 10, &written, NULL);
    low = SetFilePointer(file, -4, &high, FILE_END);
    check(low == 6 && high == 0, "SetFilePointer with a high part (negative move from the end)");
    high = 0;
    low = SetFilePointer(file, 0, &high, FILE_CURRENT);
    check(low == 6 && high == 0, "SetFilePointer reports the 64-bit position");
    CloseHandle(file);
    DeleteFileA(path);
}

typedef int (__stdcall *add_func)(int, int);
typedef int (*int_func)(void);
typedef const char *(*str_func)(void);
typedef DWORD (*dword_func)(void);

/* GetProcAddress result as another function pointer type (without -Wcast-function-type) */
#define PROC(type, module, name) ((type)(void (*)(void))GetProcAddress(module, name))

static void test_dll(void)
{
    HMODULE dll = LoadLibraryA("thread_test_dll.dll");
    char path[MAX_PATH];
    add_func add;
    int_func attach_count;
    str_func greeting;
    dword_func thread_id;

    check(dll != NULL, "LoadLibraryA of a real DLL");
    if (!dll)
        return;
    check(GetModuleHandleA("thread_test_dll.dll") == dll, "GetModuleHandleA of the loaded DLL");
    check(LoadLibraryA("thread_test_dll.dll") == dll, "loading a DLL twice gives the same module");
    add = PROC(add_func, dll, "dll_add@8");
    if (!add)
        add = PROC(add_func, dll, "dll_add");
    attach_count = PROC(int_func, dll, "dll_attach_count");
    greeting = PROC(str_func, dll, "dll_greeting");
    thread_id = PROC(dword_func, dll, "dll_thread_id");
    check(add && attach_count && greeting && thread_id, "GetProcAddress of DLL exports");
    if (add && attach_count && greeting && thread_id) {
        check(add(40, 2) == 42, "calling a DLL export (stdcall)");
        check(attach_count() == 1, "DllMain(DLL_PROCESS_ATTACH) ran once");
        check(strcmp(greeting(), "Hello from DLL") == 0, "relocated DLL data");
        check(thread_id() == GetCurrentThreadId(), "DLL imports are bound to the emulated APIs");
    }
    check(GetModuleFileNameA(dll, path, sizeof(path)) &&
          strstr(path, "thread_test_dll.dll") != NULL, "GetModuleFileNameA of the DLL");
    check(GetProcAddress(dll, "no_such_export") == NULL, "GetProcAddress of a missing export");
    check(LoadLibraryA("C:\\Windows\\Temp\\missing_dll.dll") == NULL &&
          GetLastError() == ERROR_MOD_NOT_FOUND, "LoadLibraryA of a missing DLL");
    FreeLibrary(dll);
}

int main(void)
{
    printf("=== Thread test ===\n");
    test_threads();
    test_named_objects();
    test_file_pointer();
    test_dll();
    printf("\n== %d failure(s) ==\n", failures);
    return failures;
}
