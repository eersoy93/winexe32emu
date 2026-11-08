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
API example - exercises kernel32 directory search, current directory,
INI file, string and environment APIs, user32 character and window APIs,
gdi32 DC attribute APIs and the advapi32 registry.
Every check prints PASS or FAIL; the exit code is the failure count.
*/

#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

static int failures = 0;

static void check(int ok, const char *name)
{
    printf("%s: %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok)
        failures++;
}

static int format_v(char *buf, const char *fmt, ...)
{
    va_list ap;
    int n;
    va_start(ap, fmt);
    n = wvsprintfA(buf, fmt, ap);
    va_end(ap);
    return n;
}

/* Number of entries matching pattern; *dirs counts the directories */
static int count_files(const char *pattern, int *dirs)
{
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern, &fd);
    int n = 0;
    if (dirs)
        *dirs = 0;
    if (h == INVALID_HANDLE_VALUE)
        return 0;
    do {
        n++;
        if (dirs && (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            (*dirs)++;
    } while (FindNextFileA(h, &fd));
    check(GetLastError() == ERROR_NO_MORE_FILES, "FindNextFileA ends with ERROR_NO_MORE_FILES");
    FindClose(h);
    return n;
}

static void test_files(void)
{
    char buf[MAX_PATH], *part = NULL;
    char tmp[MAX_PATH];
    WIN32_FIND_DATAW fdw;
    HANDLE h;
    DWORD written;
    int dirs;

    printf("\n--- kernel32: directories and files ---\n");
    CreateDirectoryA("C:\\ApiTest", NULL);
    check(SetCurrentDirectoryA("C:\\ApiTest"), "SetCurrentDirectoryA");
    GetCurrentDirectoryA(sizeof(buf), buf);
    check(strcmp(buf, "C:\\ApiTest") == 0, "GetCurrentDirectoryA follows it");

    GetFullPathNameA("sub\\file.txt", sizeof(buf), buf, &part);
    check(strcmp(buf, "C:\\ApiTest\\sub\\file.txt") == 0 && part && strcmp(part, "file.txt") == 0,
          "GetFullPathNameA (relative)");
    GetFullPathNameA("..\\x.txt", sizeof(buf), buf, NULL);
    check(strcmp(buf, "C:\\x.txt") == 0, "GetFullPathNameA (..)");

    /* Relative names are created in the current directory */
    h = CreateFileA("a.txt", GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    check(h != INVALID_HANDLE_VALUE, "CreateFileA relative to the current directory");
    WriteFile(h, "Hello, World!", 13, &written, NULL);
    check(FlushFileBuffers(h), "FlushFileBuffers");
    SetFilePointer(h, 5, NULL, FILE_BEGIN);
    check(SetEndOfFile(h) && GetFileSize(h, NULL) == 5, "SetEndOfFile truncates");
    CloseHandle(h);
    check(GetFileAttributesA("C:\\ApiTest\\a.txt") != INVALID_FILE_ATTRIBUTES,
          "File is inside C:\\ApiTest");

    check(GetTempFileNameA(".", "tst", 0, tmp) != 0, "GetTempFileNameA (unique, creates file)");
    check(GetFileAttributesA(tmp) != INVALID_FILE_ATTRIBUTES, "Temporary file exists");
    printf("    temp file: %s\n", tmp);
    check(GetTempFileNameA(".", "abcdef", 0x12, buf) == 0x12 && strcmp(buf, ".\\abc12.TMP") == 0,
          "GetTempFileNameA (given number)");

    check(count_files("*.txt", NULL) == 1, "FindFirstFileA *.txt");
    check(count_files("*", &dirs) == 4 && dirs == 2, "FindFirstFileA * (with . and ..)");
    h = FindFirstFileW(L"*.TMP", &fdw);
    check(h != INVALID_HANDLE_VALUE && fdw.nFileSizeLow == 0, "FindFirstFileW *.TMP");
    if (h != INVALID_HANDLE_VALUE)
        FindClose(h);
    h = FindFirstFileA("nothing*.xyz", (WIN32_FIND_DATAA *)&fdw);
    check(h == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_NOT_FOUND,
          "FindFirstFileA without match");

    check(!SetCurrentDirectoryA("NoSuchDir") && GetLastError() == ERROR_FILE_NOT_FOUND,
          "SetCurrentDirectoryA to a missing folder fails");
    check(!SetCurrentDirectoryA("..\\.."), "SetCurrentDirectoryA cannot leave c_drive");

    DeleteFileA("a.txt");
    DeleteFileA(tmp);
    check(SetCurrentDirectoryW(L"C:\\"), "SetCurrentDirectoryW back to C:\\");
    check(RemoveDirectoryA("ApiTest"), "Test folder removed");
}

static void test_strings(void)
{
    WCHAR w[64];
    char buf[64];
    DWORD n;

    printf("\n--- kernel32: strings and environment ---\n");
    lstrcpyW(w, L"Hello, ");
    lstrcatW(w, L"World");
    check(lstrcmpW(w, L"Hello, World") == 0, "lstrcpyW / lstrcatW / lstrcmpW");
    check(lstrcmpW(L"a", L"b") < 0 && lstrcmpW(L"b", L"a") > 0, "lstrcmpW ordering");
    check(lstrcmpiW(L"abc", L"ABC") == 0, "lstrcmpiW");

    check(SetEnvironmentVariableA("API_TEST", "value1"), "SetEnvironmentVariableA");
    n = GetEnvironmentVariableW(L"API_TEST", w, 64);
    check(n == 6 && lstrcmpW(w, L"value1") == 0, "GetEnvironmentVariableW");
    check(GetEnvironmentVariableW(L"API_TEST", w, 3) == 7, "GetEnvironmentVariableW (needed size)");
    check(SetEnvironmentVariableW(L"API_TEST", NULL), "SetEnvironmentVariableW (remove)");
    check(GetEnvironmentVariableA("API_TEST", buf, sizeof(buf)) == 0 &&
          GetLastError() == ERROR_ENVVAR_NOT_FOUND, "Variable is gone");
}

static void test_profile(void)
{
    const char *ini = "api_example.ini";  /* In the Windows directory */
    char buf[64];

    printf("\n--- kernel32: INI files ---\n");
    check(WritePrivateProfileStringA("General", "Name", "Tester", ini), "WritePrivateProfileStringA");
    WritePrivateProfileStringA("General", "Count", "42", ini);
    WritePrivateProfileStringA("Other", "Key", "\"quoted\"", ini);
    check(GetFileAttributesA("C:\\Windows\\api_example.ini") != INVALID_FILE_ATTRIBUTES,
          "INI file is in C:\\Windows");

    GetPrivateProfileStringA("general", "NAME", "none", buf, sizeof(buf), ini);
    check(strcmp(buf, "Tester") == 0, "GetPrivateProfileStringA (case-insensitive)");
    GetPrivateProfileStringA("Other", "Key", "", buf, sizeof(buf), ini);
    check(strcmp(buf, "quoted") == 0, "GetPrivateProfileStringA strips quotes");
    GetPrivateProfileStringA("General", "Missing", "default  ", buf, sizeof(buf), ini);
    check(strcmp(buf, "default") == 0, "GetPrivateProfileStringA default");
    check(GetPrivateProfileStringA(NULL, NULL, "", buf, sizeof(buf), ini) == 14 &&
          memcmp(buf, "General\0Other\0\0", 15) == 0, "GetPrivateProfileStringA section names");

    WritePrivateProfileStringA("General", "Count", NULL, ini);
    GetPrivateProfileStringA("General", NULL, "", buf, sizeof(buf), ini);
    check(memcmp(buf, "Name\0\0", 6) == 0, "WritePrivateProfileStringA deletes a key");
    WritePrivateProfileStringA("Other", NULL, NULL, ini);
    GetPrivateProfileStringA("Other", "Key", "gone", buf, sizeof(buf), ini);
    check(strcmp(buf, "gone") == 0, "WritePrivateProfileStringA deletes a section");
    DeleteFileA("C:\\Windows\\api_example.ini");
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

static void test_user32(void)
{
    char s[16] = "hello", buf[64];
    WCHAR w[16] = L"hello";
    WNDCLASSA wc;
    HWND hwnd;
    RECT r = {0, 0, 200, 100};
    char *p;

    printf("\n--- user32: characters and formatting ---\n");
    CharUpperW(w);
    check(lstrcmpW(w, L"HELLO") == 0, "CharUpperW (string)");
    check((WCHAR)(ULONG_PTR)CharLowerW((LPWSTR)(ULONG_PTR)L'Q') == L'q', "CharLowerW (character)");
    check(IsCharUpperA('A') && !IsCharUpperA('a'), "IsCharUpperA");
    check(IsCharLowerA('a') && !IsCharLowerA('A'), "IsCharLowerA");
    p = CharNextA(s);
    check(p == s + 1 && CharNextA(s + 5) == s + 5, "CharNextA");
    check(CharPrevA(s, s + 2) == s + 1 && CharPrevA(s, s) == s, "CharPrevA");
    if (GetACP() == CP_UTF8) {
        /* "aé" in UTF-8: é is two bytes */
        const char *u = "a\xc3\xa9!";
        check(CharNextA((LPSTR)u + 1) == u + 3 && CharPrevA(u, u + 3) == u + 1,
              "CharNextA / CharPrevA (UTF-8 character)");
    }
    format_v(buf, "%s-%d-%04x", "abc", 42, 255);
    check(strcmp(buf, "abc-42-00ff") == 0, "wvsprintfA");

    printf("\n--- user32: windows ---\n");
    check(AdjustWindowRect(&r, WS_OVERLAPPEDWINDOW, FALSE) && r.left < 0 && r.top < r.left &&
          r.right > 200 && r.bottom > 100, "AdjustWindowRect grows the rectangle");
    printf("    window rect: (%ld, %ld, %ld, %ld)\n", r.left, r.top, r.right, r.bottom);

    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.lpszClassName = "ApiExampleClass";
    RegisterClassA(&wc);
    hwnd = CreateWindowExA(0, "ApiExampleClass", "API Example", WS_OVERLAPPEDWINDOW,
                           CW_USEDEFAULT, CW_USEDEFAULT, 300, 200, NULL, NULL, wc.hInstance, NULL);
    if (!IsWindow(hwnd)) {
        printf("SKIP: window checks (no GUI)\n");
        return;
    }
    check(FindWindowA("ApiExampleClass", NULL) == hwnd, "FindWindowA (class)");
    check(FindWindowA(NULL, "API Example") == hwnd, "FindWindowA (title)");
    check(FindWindowA("NoSuchClass", NULL) == NULL, "FindWindowA (no match)");
    check(GetClassNameA(hwnd, buf, sizeof(buf)) == 15 && strcmp(buf, "ApiExampleClass") == 0,
          "GetClassNameA");
    check(GetWindowTextLengthA(hwnd) == 11, "GetWindowTextLengthA");
    ShowWindow(hwnd, SW_SHOW);
    check(BringWindowToTop(hwnd), "BringWindowToTop");
    check(SetForegroundWindow(hwnd) && GetForegroundWindow() == hwnd, "SetForegroundWindow");
    DestroyWindow(hwnd);
}

static void test_gdi32(void)
{
    HDC hdc = CreateCompatibleDC(NULL);
    LOGPEN lp = {PS_SOLID, {2, 0}, RGB(255, 0, 0)};
    LOGBRUSH lb = {BS_SOLID, RGB(0, 0, 255), 0};
    TEXTMETRICA tm;
    HPEN pen;
    HBRUSH brush;

    printf("\n--- gdi32: device context ---\n");
    SetTextColor(hdc, RGB(1, 2, 3));
    check(GetTextColor(hdc) == RGB(1, 2, 3), "GetTextColor");
    SetBkColor(hdc, RGB(4, 5, 6));
    check(GetBkColor(hdc) == RGB(4, 5, 6), "GetBkColor");
    check(SetTextAlign(hdc, TA_CENTER | TA_BASELINE) == (TA_LEFT | TA_TOP) &&
          SetTextAlign(hdc, TA_LEFT) == (TA_CENTER | TA_BASELINE), "SetTextAlign");
    check(SetROP2(hdc, R2_XORPEN) == R2_COPYPEN && SetROP2(hdc, R2_COPYPEN) == R2_XORPEN,
          "SetROP2");

    pen = CreatePenIndirect(&lp);
    check(pen != NULL && SelectObject(hdc, pen) != NULL, "CreatePenIndirect");
    brush = CreateBrushIndirect(&lb);
    check(brush != NULL && SelectObject(hdc, brush) != NULL, "CreateBrushIndirect");
    lb.lbStyle = BS_NULL;
    check(CreateBrushIndirect(&lb) == GetStockObject(NULL_BRUSH), "CreateBrushIndirect (BS_NULL)");

    check(GetTextMetricsA(hdc, &tm) && tm.tmHeight > 0 && tm.tmAveCharWidth > 0 &&
          tm.tmAscent + tm.tmDescent == tm.tmHeight, "GetTextMetricsA");
    printf("    font: height %ld, ascent %ld, average width %ld\n",
           tm.tmHeight, tm.tmAscent, tm.tmAveCharWidth);
    DeleteDC(hdc);
    DeleteObject(pen);
    DeleteObject(brush);
}

static void test_registry(void)
{
    HKEY hk, child;
    DWORD disp, type, size, count = 42, i;
    char name[64], data[64];
    WCHAR wdata[32];
    LONG rc;

    printf("\n--- advapi32: registry ---\n");
    rc = RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\WinExe32Emu\\ApiExample", 0, NULL, 0,
                         KEY_ALL_ACCESS, NULL, &hk, &disp);
    check(rc == ERROR_SUCCESS && disp == REG_CREATED_NEW_KEY, "RegCreateKeyExA (new key)");
    RegSetValueExA(hk, "Name", 0, REG_SZ, (const BYTE *)"Tester", 7);
    RegSetValueExA(hk, "Count", 0, REG_DWORD, (const BYTE *)&count, sizeof(count));

    size = 0;
    rc = RegQueryValueExA(hk, "Name", NULL, &type, NULL, &size);
    check(rc == ERROR_SUCCESS && type == REG_SZ && size == 7, "RegQueryValueExA (size)");
    size = sizeof(data);
    RegQueryValueExA(hk, "name", NULL, NULL, (BYTE *)data, &size);
    check(strcmp(data, "Tester") == 0, "RegQueryValueExA (data)");
    size = sizeof(wdata);
    RegQueryValueExW(hk, L"Name", NULL, NULL, (BYTE *)wdata, &size);
    check(lstrcmpW(wdata, L"Tester") == 0 && size == 14, "RegQueryValueExW reads an ANSI value");
    size = 2;
    check(RegQueryValueExA(hk, "Name", NULL, NULL, (BYTE *)data, &size) == ERROR_MORE_DATA,
          "RegQueryValueExA (small buffer)");

    RegCreateKeyExA(hk, "Child2", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &child, NULL);
    RegCloseKey(child);
    RegCreateKeyExA(hk, "Child1", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &child, NULL);
    RegCloseKey(child);
    data[0] = 0;
    for (i = 0; ; i++) {
        size = sizeof(name);
        if (RegEnumKeyExA(hk, i, name, &size, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
            break;
        strcat(data, name);
        strcat(data, ";");
    }
    check(strcmp(data, "Child1;Child2;") == 0, "RegEnumKeyExA");
    size = 3;
    check(RegEnumKeyExA(hk, 0, name, &size, NULL, NULL, NULL, NULL) == ERROR_MORE_DATA,
          "RegEnumKeyExA (small buffer)");

    data[0] = 0;
    for (i = 0; ; i++) {
        BYTE value[64];
        DWORD value_size = sizeof(value);
        size = sizeof(name);
        if (RegEnumValueA(hk, i, name, &size, NULL, &type, value, &value_size) != ERROR_SUCCESS)
            break;
        strcat(data, name);
        strcat(data, type == REG_DWORD ? "(dword);" : "(sz);");
    }
    check(strcmp(data, "Name(sz);Count(dword);") == 0, "RegEnumValueA");

    check(RegDeleteValueA(hk, "Count") == ERROR_SUCCESS, "RegDeleteValueA");
    check(RegQueryValueExA(hk, "Count", NULL, NULL, NULL, NULL) == ERROR_FILE_NOT_FOUND,
          "Deleted value is gone");
    check(RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\WinExe32Emu") != ERROR_SUCCESS,
          "RegDeleteKeyA refuses a key with subkeys");
    RegDeleteKeyA(hk, "Child1");
    RegDeleteKeyA(hk, "Child2");
    RegCloseKey(hk);
    check(RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\WinExe32Emu\\ApiExample") == ERROR_SUCCESS &&
          RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\WinExe32Emu") == ERROR_SUCCESS,
          "RegDeleteKeyA");
    check(RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\WinExe32Emu", 0, KEY_READ, &hk) ==
          ERROR_FILE_NOT_FOUND, "Deleted key is gone");
}

int main(void)
{
    printf("=== API example ===\n");
    test_files();
    test_strings();
    test_profile();
    test_user32();
    test_gdi32();
    test_registry();
    printf("\n== %d failure(s) ==\n", failures);
    return failures;
}
