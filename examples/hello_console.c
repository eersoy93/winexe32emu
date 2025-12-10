/*
Copyright 2025 Erdem Ersoy (eersoy93)

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

#include <windows.h>

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
    if (!AllocConsole()) {
        return 1;
    }

    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    const char msg[] = "Hello, World!\r\n";
    DWORD written;
    WriteConsoleA(hOut, msg, (DWORD)(sizeof(msg) - 1), &written, NULL);

    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    char buf[16];
    DWORD read;
    ReadConsoleA(hIn, buf, sizeof(buf) - 1, &read, NULL);

    return 0;
}
