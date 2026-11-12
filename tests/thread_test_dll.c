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
DLL loaded by thread_test.exe with LoadLibrary: DllMain counts the process
attach, the exports use an import (kernel32) and a relocated global.
*/

#include <windows.h>

static int attach_count = 0;
static const char *greeting = "Hello from DLL";

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH)
        attach_count++;
    return TRUE;
}

__declspec(dllexport) int __stdcall dll_add(int a, int b)
{
    return a + b;
}

__declspec(dllexport) int dll_attach_count(void)
{
    return attach_count;
}

__declspec(dllexport) const char *dll_greeting(void)
{
    return greeting;
}

__declspec(dllexport) DWORD dll_thread_id(void)
{
    return GetCurrentThreadId();
}
