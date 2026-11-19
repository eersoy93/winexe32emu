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
"exit" when the process ends).
*/

#include <windows.h>

static LONG process_attach = 0, thread_attach = 0, thread_detach = 0;
static char detach_marker[MAX_PATH];

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    HANDLE file;
    DWORD written;

    switch (reason) {
    case DLL_PROCESS_ATTACH:
        process_attach++;
        break;
    case DLL_THREAD_ATTACH:
        thread_attach++;
        break;
    case DLL_THREAD_DETACH:
        thread_detach++;
        break;
    case DLL_PROCESS_DETACH:
        if (detach_marker[0]) {
            file = CreateFileA(detach_marker, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
            if (file != INVALID_HANDLE_VALUE) {
                WriteFile(file, reserved ? "exit" : "free", 4, &written, NULL);
                CloseHandle(file);
            }
        }
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

__declspec(dllexport) BOOL loader_disable_thread_calls(HMODULE module)
{
    return DisableThreadLibraryCalls(module);
}
