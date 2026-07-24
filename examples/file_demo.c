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
File I/O demo - exercises the emulator's sandboxed file support.

Everything happens inside the emulated C: drive (the host c_drive/ folder):
  1. Win32 CreateFile/WriteFile/ReadFile round-trip.
  2. msvcrt fopen/fwrite/fgets round-trip.
  3. A sandbox-escape attempt ("..\\escape.txt") that must be refused.
*/

#include <windows.h>
#include <stdio.h>

static void WriteString(HANDLE hOut, const char *text)
{
    DWORD written = 0;
    WriteFile(hOut, text, (DWORD)lstrlenA(text), &written, NULL);
}

int main(void)
{
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    char buffer[128];
    DWORD written = 0, read = 0;

    /* ---- 1. Win32 API round-trip ---- */
    HANDLE hFile = CreateFileA("hello.txt", GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        const char *msg = "Hello from the sandbox!\n";
        WriteFile(hFile, msg, (DWORD)lstrlenA(msg), &written, NULL);
        CloseHandle(hFile);
        WriteString(hOut, "(Win32) 'hello.txt' has been written!\n");
    }
    else
    {
        WriteString(hOut, "(Win32) 'hello.txt' couldn't be created!'\n");
    }

    hFile = CreateFileA("hello.txt", GENERIC_READ, 0, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        read = 0;
        if (ReadFile(hFile, buffer, sizeof(buffer) - 1, &read, NULL))
        {
            buffer[read] = '\0';
            WriteString(hOut, "(Win32) 'hello.txt' has been read!\n");
            WriteString(hOut, buffer);
        }
        CloseHandle(hFile);
    }

    /* ---- 2. msvcrt (fopen) round-trip ---- */
    FILE *fp = fopen("notes.txt", "w");
    if (fp)
    {
        fputs("line written with fputs\n", fp);
        fwrite("more bytes written\n", 1, 11, fp);
        fclose(fp);
        WriteString(hOut, "(CRT) 'notes.txt' has been written!\n");
    }

    fp = fopen("notes.txt", "r");
    if (fp)
    {
        if (fgets(buffer, sizeof(buffer), fp))
        {
            WriteString(hOut, "(CRT) 'notes.txt' has been read!\n");
            WriteString(hOut, buffer);
        }
        fclose(fp);
    }

    /* ---- 3. Sandbox escape must be refused ---- */
    hFile = CreateFileA("..\\escape.txt", GENERIC_WRITE, 0, NULL,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        WriteString(hOut, "Sandbox escape via '..\\escape.txt' was blocked! Good!\n");
    else
    {
        WriteString(hOut, "Sandbox escape via '..\\escape.txt' succeeded! Bad!\n");
        CloseHandle(hFile);
    }

    ExitProcess(0);
    return 0;
}
