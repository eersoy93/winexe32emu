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
Console demo - covers the emulator's console features in one program:
AllocConsole, GetStdHandle, WriteConsoleA, WriteFile, ReadConsoleA
(with ReadFile fallback), lstr* string functions and ExitProcess.
*/

#include <windows.h>

// Write a zero-terminated string to a console handle
static void WriteString(HANDLE hOut, const char* text)
{
    DWORD written = 0;
    WriteConsoleA(hOut, text, (DWORD)lstrlenA(text), &written, NULL);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nShowCmd)
{
    if (!AllocConsole())
    {
        return 1;
    }

    HANDLE hIn  = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);

    // Handle check
    if (hIn == INVALID_HANDLE_VALUE || hOut == INVALID_HANDLE_VALUE)
    {
        ExitProcess(1);
    }

    WriteString(hOut, "Hello, World!\r\n");
    WriteString(hOut, "What is your name? ");

    // Read a line: first try ReadConsole, if it fails use ReadFile
    CHAR buf[256];
    DWORD read = 0;
    if (!ReadConsoleA(hIn, buf, (DWORD)sizeof(buf) - 1, &read, NULL))
    {
        DWORD actual = 0;
        if (!ReadFile(hIn, buf, (DWORD)sizeof(buf) - 1, &actual, NULL))
        {
            ExitProcess(1);
        }
        read = actual;
    }

    // Remove trailing CR/LF characters
    while (read > 0 && (buf[read - 1] == '\n' || buf[read - 1] == '\r'))
    {
        --read;
    }
    buf[read] = '\0';

    // Compose and write the greeting (WriteFile also reaches the console)
    CHAR message[300];
    if (read == 0)
    {
        lstrcpyA(message, "You did not tell me your name!\r\n");
    }
    else
    {
        lstrcpyA(message, "Hello, ");
        lstrcatA(message, buf);
        lstrcatA(message, "!\r\n");
    }

    DWORD written = 0;
    WriteFile(hOut, message, (DWORD)lstrlenA(message), &written, NULL);

    ExitProcess(0);
    return 0;
}
