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
System information test - exercises kernel32/user32/advapi32 query APIs
and the wide/copy/move file APIs of the sandboxed C: drive.
*/

/* GetTickCount64 needs Vista+ declarations on older MinGW headers */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#include <windows.h>
#include <stdio.h>

int main(void)
{
    char name[64], text[32], dir[MAX_PATH];
    DWORD size;
    SYSTEM_INFO si;
    MEMORYSTATUS ms;
    LARGE_INTEGER freq, t0, t1;
    ULONGLONG ticks;
    BOOL ok;

    SetConsoleTitleA("System Information");
    printf("=== System information test ===\n\n");

    size = sizeof(name);
    if (GetComputerNameA(name, &size))
        printf("Computer name : %s (%lu chars)\n", name, size);
    size = sizeof(name);
    if (GetUserNameA(name, &size))
        printf("User name     : %s (%lu with NUL)\n", name, size);
    size = 2;
    ok = GetComputerNameA(name, &size);
    printf("Small buffer  : GetComputerNameA -> %d, error %lu, needs %lu\n",
           ok, GetLastError(), size);

    GetSystemInfo(&si);
    printf("Processors    : %lu (type %lu, level %u), page size %lu\n",
           si.dwNumberOfProcessors, si.dwProcessorType, si.wProcessorLevel, si.dwPageSize);

    ms.dwLength = sizeof(ms);
    GlobalMemoryStatus(&ms);
    printf("Memory        : %lu KiB free of %lu KiB (load %lu%%)\n",
           (unsigned long)(ms.dwAvailPhys / 1024), (unsigned long)(ms.dwTotalPhys / 1024),
           ms.dwMemoryLoad);

    GetCurrentDirectoryA(sizeof(dir), dir);
    printf("Current dir   : %s\n", dir);
    printf("Code pages    : ANSI %u, OEM %u\n", GetACP(), GetOEMCP());

    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);
    Sleep(50);
    QueryPerformanceCounter(&t1);
    ticks = GetTickCount64();
    printf("Timer         : %lu Hz, Sleep(50) = %lu ms, uptime ticks %s\n",
           (unsigned long)freq.QuadPart,
           (unsigned long)((t1.QuadPart - t0.QuadPart) * 1000 / freq.QuadPart),
           ticks ? "ok" : "zero");

    printf("Colors        : window 0x%06lx, button face 0x%06lx, highlight 0x%06lx\n",
           GetSysColor(COLOR_WINDOW), GetSysColor(COLOR_BTNFACE), GetSysColor(COLOR_HIGHLIGHT));
    printf("Desktop hwnd  : %s, double click %u ms\n",
           GetDesktopWindow() ? "ok" : "NULL", GetDoubleClickTime());

    lstrcpyA(text, "Hello, World 123");
    CharUpperA(text);
    printf("CharUpperA    : %s\n", text);
    CharLowerA(text);
    printf("CharLowerA    : %s\n", text);
    printf("IsCharAlphaA  : 'a'=%d '1'=%d, IsCharAlphaNumericA '1'=%d '#'=%d\n",
           IsCharAlphaA('a'), IsCharAlphaA('1'),
           IsCharAlphaNumericA('1'), IsCharAlphaNumericA('#'));

    printf("\nFile APIs (C:\\Windows\\Temp):\n");
    CreateDirectoryW(L"C:\\Windows\\Temp\\SysInfo", NULL);
    {
        HANDLE h = CreateFileA("C:\\Windows\\Temp\\SysInfo\\a.txt", GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        DWORD written;
        if (h != INVALID_HANDLE_VALUE)
        {
            WriteFile(h, "data", 4, &written, NULL);
            CloseHandle(h);
        }
        else
        {
            printf("  CreateFileA a.txt       : failed, error %lu\n", GetLastError());
        }
    }
    printf("  CopyFileA a->b          : %d\n",
           CopyFileA("C:\\Windows\\Temp\\SysInfo\\a.txt", "C:\\Windows\\Temp\\SysInfo\\b.txt", FALSE));
    ok = CopyFileA("C:\\Windows\\Temp\\SysInfo\\a.txt", "C:\\Windows\\Temp\\SysInfo\\b.txt", TRUE);
    printf("  CopyFileA a->b (no ovr) : %d, error %lu\n", ok, GetLastError());
    printf("  MoveFileA b->c          : %d\n",
           MoveFileA("C:\\Windows\\Temp\\SysInfo\\b.txt", "C:\\Windows\\Temp\\SysInfo\\c.txt"));
    printf("  GetFileAttributesW c    : 0x%lx\n",
           GetFileAttributesW(L"C:\\Windows\\Temp\\SysInfo\\c.txt"));
    printf("  DeleteFileW a, c        : %d %d\n",
           DeleteFileW(L"C:\\Windows\\Temp\\SysInfo\\a.txt"),
           DeleteFileW(L"C:\\Windows\\Temp\\SysInfo\\c.txt"));
    printf("  RemoveDirectoryW        : %d\n", RemoveDirectoryW(L"C:\\Windows\\Temp\\SysInfo"));
    ok = CopyFileA("C:\\Windows\\win.ini", "C:\\..\\escape.txt", FALSE);
    printf("  Escape attempt (copy)   : %d, error %lu\n", ok, GetLastError());

    printf("\nDone!\n");
    return 0;
}
