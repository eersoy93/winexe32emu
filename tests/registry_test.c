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
Registry test - the registry is saved (C:\Windows\System32\config) and the
W APIs keep names and data that the ANSI code page can't represent.
run_tests.sh runs it twice, as two processes:
  registry_test write - creates the keys and values
  registry_test read  - finds them again (except the volatile key), then
                        deletes them
Every check prints PASS or FAIL; the exit code is the failure count.
*/

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#define TEST_KEY L"Software\\WinExe32Emu\\RegistryTest"
#define PARENT_KEY L"Software\\WinExe32Emu"
/* "Name ğ 中" and "Value ğ 中": not in code page 1252 */
#define UNICODE_NAME L"Name \x011F \x4E2D"
#define UNICODE_DATA L"Value \x011F \x4E2D"
#define UNICODE_SUBKEY L"Sub \x011F \x4E2D"
#define CLASS_KEY L".winexe32emu-test"

static int failures = 0;

static void check(int ok, const char *name)
{
    printf("%s: %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok)
        failures++;
}

static void delete_test_keys(void)
{
    HKEY hk;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, TEST_KEY, 0, KEY_ALL_ACCESS, &hk) == ERROR_SUCCESS) {
        RegDeleteKeyW(hk, UNICODE_SUBKEY);
        RegDeleteKeyW(hk, L"Volatile");
        RegCloseKey(hk);
    }
    RegDeleteKeyW(HKEY_CURRENT_USER, TEST_KEY);
    RegDeleteKeyW(HKEY_CURRENT_USER, PARENT_KEY);
    RegDeleteKeyW(HKEY_CLASSES_ROOT, CLASS_KEY);
}

static void write_keys(void)
{
    HKEY hk, child;
    DWORD disp = 0, number = 0x12345678;
    BYTE binary[5] = {0, 1, 2, 0xFE, 0xFF};
    WCHAR name[64];
    DWORD size = 64, type = 0, data_size = 0;
    LONG rc;

    delete_test_keys();  /* leftovers of a failed run */
    rc = RegCreateKeyExW(HKEY_CURRENT_USER, TEST_KEY, 0, NULL, 0, KEY_ALL_ACCESS, NULL,
                         &hk, &disp);
    check(rc == ERROR_SUCCESS && disp == REG_CREATED_NEW_KEY, "RegCreateKeyExW");
    check(RegSetValueExW(hk, UNICODE_NAME, 0, REG_SZ, (const BYTE *)UNICODE_DATA,
                         sizeof(UNICODE_DATA)) == ERROR_SUCCESS, "RegSetValueExW (Unicode)");
    RegSetValueExW(hk, L"Number", 0, REG_DWORD, (const BYTE *)&number, sizeof(number));
    RegSetValueExW(hk, L"Binary", 0, REG_BINARY, binary, sizeof(binary));
    check(RegEnumValueW(hk, 0, name, &size, NULL, &type, NULL, &data_size) == ERROR_SUCCESS &&
          wcscmp(name, UNICODE_NAME) == 0 && size == wcslen(UNICODE_NAME) &&
          type == REG_SZ && data_size == sizeof(UNICODE_DATA), "RegEnumValueW (Unicode name)");

    rc = RegCreateKeyExW(hk, UNICODE_SUBKEY, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &child, NULL);
    check(rc == ERROR_SUCCESS, "RegCreateKeyExW (Unicode subkey)");
    RegCloseKey(child);
    size = 64;
    check(RegEnumKeyExW(hk, 0, name, &size, NULL, NULL, NULL, NULL) == ERROR_SUCCESS &&
          wcscmp(name, UNICODE_SUBKEY) == 0, "RegEnumKeyExW (Unicode name)");
    rc = RegCreateKeyExW(hk, L"Volatile", 0, NULL, REG_OPTION_VOLATILE, KEY_ALL_ACCESS, NULL,
                         &child, NULL);
    check(rc == ERROR_SUCCESS, "RegCreateKeyExW (REG_OPTION_VOLATILE)");
    RegSetValueExW(child, L"Gone", 0, REG_DWORD, (const BYTE *)&number, sizeof(number));
    RegCloseKey(child);
    check(RegFlushKey(hk) == ERROR_SUCCESS, "RegFlushKey");
    RegCloseKey(hk);

    rc = RegCreateKeyExW(HKEY_CLASSES_ROOT, CLASS_KEY, 0, NULL, 0, KEY_ALL_ACCESS, NULL,
                         &hk, NULL);
    check(rc == ERROR_SUCCESS, "RegCreateKeyExW (HKEY_CLASSES_ROOT)");
    RegCloseKey(hk);
    check(RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Classes\\" CLASS_KEY, 0, KEY_READ,
                        &hk) == ERROR_SUCCESS, "HKEY_CLASSES_ROOT is HKLM\\SOFTWARE\\Classes");
    RegCloseKey(hk);
}

static void read_keys(void)
{
    HKEY hk, child;
    WCHAR data[64];
    char ansi[64];
    BYTE binary[16];
    DWORD size, type, number = 0;
    LONG rc;

    rc = RegOpenKeyExW(HKEY_CURRENT_USER, TEST_KEY, 0, KEY_ALL_ACCESS, &hk);
    check(rc == ERROR_SUCCESS, "the key is still there in a new process");
    if (rc != ERROR_SUCCESS)
        return;
    size = sizeof(data);
    rc = RegQueryValueExW(hk, UNICODE_NAME, NULL, &type, (BYTE *)data, &size);
    check(rc == ERROR_SUCCESS && type == REG_SZ && wcscmp(data, UNICODE_DATA) == 0 &&
          size == sizeof(UNICODE_DATA), "Unicode value name and data are kept");
    size = sizeof(number);
    check(RegQueryValueExW(hk, L"number", NULL, &type, (BYTE *)&number, &size) ==
          ERROR_SUCCESS && type == REG_DWORD && number == 0x12345678, "REG_DWORD is kept");
    size = sizeof(binary);
    check(RegQueryValueExA(hk, "Binary", NULL, &type, binary, &size) == ERROR_SUCCESS &&
          type == REG_BINARY && size == 5 && binary[3] == 0xFE && binary[4] == 0xFF,
          "REG_BINARY is kept");
    size = sizeof(ansi);
    check(RegQueryValueExA(hk, "Binary", NULL, NULL, (BYTE *)ansi, &size) == ERROR_SUCCESS,
          "RegQueryValueExA of the same key");
    check(RegOpenKeyExW(hk, UNICODE_SUBKEY, 0, KEY_READ, &child) == ERROR_SUCCESS,
          "Unicode subkey is kept");
    RegCloseKey(child);
    check(RegOpenKeyExW(hk, L"Volatile", 0, KEY_READ, &child) == ERROR_FILE_NOT_FOUND,
          "the volatile key is not saved");

    check(RegDeleteValueW(hk, UNICODE_NAME) == ERROR_SUCCESS &&
          RegQueryValueExW(hk, UNICODE_NAME, NULL, NULL, NULL, NULL) == ERROR_FILE_NOT_FOUND,
          "RegDeleteValueW (Unicode name)");
    check(RegDeleteKeyW(hk, UNICODE_SUBKEY) == ERROR_SUCCESS, "RegDeleteKeyW (Unicode name)");
    RegCloseKey(hk);
    check(RegOpenKeyExW(HKEY_CLASSES_ROOT, CLASS_KEY, 0, KEY_READ, &hk) == ERROR_SUCCESS,
          "HKEY_CLASSES_ROOT key is kept");
    RegCloseKey(hk);

    delete_test_keys();
    check(RegOpenKeyExW(HKEY_CURRENT_USER, PARENT_KEY, 0, KEY_READ, &hk) ==
          ERROR_FILE_NOT_FOUND, "the test keys are deleted");
}

int main(int argc, char **argv)
{
    if (argc < 2 || (strcmp(argv[1], "write") != 0 && strcmp(argv[1], "read") != 0)) {
        printf("Usage: registry_test write|read\n");
        return 1;
    }
    printf("=== Registry test (%s) ===\n", argv[1]);
    if (strcmp(argv[1], "write") == 0)
        write_keys();
    else
        read_keys();
    printf("\n== %d failure(s) ==\n", failures);
    return failures;
}
