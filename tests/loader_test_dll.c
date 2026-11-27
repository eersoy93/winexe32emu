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
DLL of loader_test.exe: imported by the EXE (a static import) and loaded
again from a copy with LoadLibrary. DllMain counts its notifications and,
when the DLL is unloaded, writes a marker file ("free" from FreeLibrary,
"exit" when the process ends). Like a DLL built with Microsoft's compiler,
it keeps its own exit handler table filled by msvcrt's __dllonexit and runs
it at DLL_PROCESS_DETACH; the handler writes "dlox" to a second marker. The
handlers must not run at the process's exit() instead: after FreeLibrary
they would call into an unloaded DLL.
*/

#include <windows.h>
#include <stdlib.h>

/* msvcrt's DLL exit handler registration (Microsoft Learn: __dllonexit);
   the MinGW-w64 headers do not declare it */
typedef void (__cdecl *exit_handler)(void);
_onexit_t __cdecl __dllonexit(_onexit_t func, exit_handler **pbegin, exit_handler **pend);

static LONG process_attach = 0, thread_attach = 0, thread_detach = 0;
static char detach_marker[MAX_PATH], exit_marker[MAX_PATH];
static exit_handler *exit_begin, *exit_end;

static void write_marker(const char *path, const char *text)
{
    DWORD written;
    HANDLE file = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (file != INVALID_HANDLE_VALUE) {
        WriteFile(file, text, 4, &written, NULL);
        CloseHandle(file);
    }
}

static int __cdecl dll_exit_handler(void)
{
    if (exit_marker[0])
        write_marker(exit_marker, "dlox");
    return 0;
}

static void run_exit_handlers(void)
{
    exit_handler *entry;

    if (exit_begin == NULL)
        return;
    for (entry = exit_end; entry-- > exit_begin;)
        if (*entry)
            (*entry)();
    free(exit_begin);
    exit_begin = exit_end = NULL;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        process_attach++;
        __dllonexit(dll_exit_handler, &exit_begin, &exit_end);
        break;
    case DLL_THREAD_ATTACH:
        thread_attach++;
        break;
    case DLL_THREAD_DETACH:
        thread_detach++;
        break;
    case DLL_PROCESS_DETACH:
        if (detach_marker[0])
            write_marker(detach_marker, reserved ? "exit" : "free");
        run_exit_handlers();
        break;
    }
    return TRUE;
}

__declspec(dllexport) int __stdcall loader_add(int a, int b)
{
    return a + b;
}

/* 0: DLL_PROCESS_ATTACH, 1: DLL_THREAD_ATTACH, 2: DLL_THREAD_DETACH calls */
__declspec(dllexport) LONG loader_count(int which)
{
    return which == 0 ? process_attach : which == 1 ? thread_attach : thread_detach;
}

__declspec(dllexport) void loader_set_marker(const char *path)
{
    lstrcpynA(detach_marker, path, MAX_PATH);
}

__declspec(dllexport) void loader_set_exit_marker(const char *path)
{
    lstrcpynA(exit_marker, path, MAX_PATH);
}

__declspec(dllexport) BOOL loader_disable_thread_calls(HMODULE module)
{
    return DisableThreadLibraryCalls(module);
}
