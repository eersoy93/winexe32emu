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
Extended API test - exercises the API groups added after the basic ones:
shlwapi paths and strings, more registry and INI file functions, advapi32
security (SIDs, tokens, security descriptors, ACLs), CryptoAPI and BCrypt
hashes, the service manager, kernel32 atoms, version checks, handles,
memory and the 16-bit file functions, ntdll, user32 keyboard layouts,
characters, window properties, window stations and (with the GUI) window
enumeration and subclassing, shell32 command lines, known folders and
directories, COM GUIDs, rpcrt4 UUIDs, psapi, Windows Sockets, uxtheme,
dwmapi and version.dll. Every check prints PASS or FAIL; the exit code is
the failure count.
*/

#define _WIN32_WINNT 0x0600
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shlwapi.h>
#include <shlobj.h>
#include <shellapi.h>
#include <sddl.h>
#include <aclapi.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <psapi.h>
#include <rpc.h>
#include <commctrl.h>
#include <uxtheme.h>
#include <dwmapi.h>
#define SECURITY_WIN32
#include <security.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

static int failures = 0;

static void check(int ok, const char *name)
{
    printf("%s: %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok)
        failures++;
}

static void hex(const BYTE *data, DWORD size, char *out)
{
    DWORD i;
    for (i = 0; i < size; i++)
        sprintf(out + 2 * i, "%02x", data[i]);
}

/* ---- shlwapi ---- */

static void test_shlwapi(void)
{
    char path[MAX_PATH], buf[64];
    WCHAR wpath[MAX_PATH];
    char *dup;
    int value = 0;

    printf("\n--- shlwapi: paths ---\n");
    check(strcmp(PathFindFileNameA("C:\\dir\\file.txt"), "file.txt") == 0, "PathFindFileNameA");
    check(strcmp(PathFindFileNameA("C:\\dir\\sub\\"), "sub\\") == 0,
          "PathFindFileNameA (trailing backslash)");
    check(strcmp(PathFindExtensionA("C:\\a.b\\file.tar.gz"), ".gz") == 0, "PathFindExtensionA");
    check(*PathFindExtensionA("C:\\a.b\\file") == 0, "PathFindExtensionA (no extension)");
    check(PathCombineA(path, "C:\\a\\b", "..\\c.txt") == path &&
          strcmp(path, "C:\\a\\c.txt") == 0, "PathCombineA with ..");
    check(PathCombineA(path, "C:\\a\\b", "\\x") && strcmp(path, "C:\\x") == 0,
          "PathCombineA with a rooted file");
    strcpy(path, "C:\\Windows");
    check(PathAppendA(path, "System32\\drivers") && strcmp(path, "C:\\Windows\\System32\\drivers") == 0,
          "PathAppendA");
    check(PathRemoveFileSpecA(path) && strcmp(path, "C:\\Windows\\System32") == 0,
          "PathRemoveFileSpecA");
    strcpy(path, "C:\\file.txt");
    check(PathRemoveFileSpecA(path) && strcmp(path, "C:\\") == 0, "PathRemoveFileSpecA (root)");
    strcpy(path, "C:\\dir");
    check(PathAddBackslashA(path) == path + 7 && strcmp(path, "C:\\dir\\") == 0, "PathAddBackslashA");
    PathRemoveBackslashA(path);
    check(strcmp(path, "C:\\dir") == 0, "PathRemoveBackslashA");
    check(PathIsRelativeA("dir\\file") && !PathIsRelativeA("C:\\dir") && !PathIsRelativeA("\\dir"),
          "PathIsRelativeA");
    check(PathIsRootA("C:\\") && PathIsRootA("\\") && !PathIsRootA("C:\\dir"), "PathIsRootA");
    check(PathFileExistsA("C:\\Windows") && !PathFileExistsA("C:\\NoSuchFolder"), "PathFileExistsA");
    check(PathIsDirectoryA("C:\\Windows") != 0, "PathIsDirectoryA");
    check(PathMatchSpecA("readme.TXT", "*.doc;*.txt") && !PathMatchSpecA("readme.md", "*.txt"),
          "PathMatchSpecA");
    check(PathCanonicalizeA(path, "C:\\a\\.\\b\\..\\c") && strcmp(path, "C:\\a\\c") == 0,
          "PathCanonicalizeA");
    strcpy(path, "C:\\dir\\name.old");
    check(PathRenameExtensionA(path, ".new") && strcmp(path, "C:\\dir\\name.new") == 0,
          "PathRenameExtensionA");
    PathStripPathA(path);
    check(strcmp(path, "name.new") == 0, "PathStripPathA");
    strcpy(path, "C:\\Program Files\\app.exe");
    PathQuoteSpacesA(path);
    check(strcmp(path, "\"C:\\Program Files\\app.exe\"") == 0, "PathQuoteSpacesA");
    PathUnquoteSpacesA(path);
    check(strcmp(path, "C:\\Program Files\\app.exe") == 0, "PathUnquoteSpacesA");
    check(PathGetDriveNumberA("d:\\x") == 3 && PathGetDriveNumberA("x") == -1,
          "PathGetDriveNumberA");
    check(strcmp(PathGetArgsA("\"my app.exe\" -a -b"), "-a -b") == 0, "PathGetArgsA");
    check(PathCombineW(wpath, L"C:\\Users", L"Public") && wcscmp(wpath, L"C:\\Users\\Public") == 0,
          "PathCombineW");
    check(wcscmp(PathFindFileNameW(L"D:\\x\\y.dat"), L"y.dat") == 0, "PathFindFileNameW");

    printf("\n--- shlwapi: strings ---\n");
    check(strcmp(StrStrIA("Hello World", "WORLD"), "World") == 0, "StrStrIA");
    check(StrStrA("abc", "x") == NULL, "StrStrA (no match)");
    check(strcmp(StrChrA("a,b,c", ','), ",b,c") == 0, "StrChrA");
    check(strcmp(StrRChrA("a,b,c", NULL, ','), ",c") == 0, "StrRChrA");
    check(StrCmpNIA("HELLO there", "hello world", 5) == 0, "StrCmpNIA");
    check(StrCmpLogicalW(L"file2", L"file10") < 0 && StrCmpLogicalW(L"a", L"A") == 0,
          "StrCmpLogicalW");
    check(StrCmpIW(L"Abc", L"aBC") == 0 && StrCmpW(L"a", L"b") < 0, "StrCmpIW / StrCmpW");
    check(StrToIntA("  -42x") == -42, "StrToIntA");
    check(StrToIntExA("0x1F", STIF_SUPPORT_HEX, &value) && value == 31, "StrToIntExA (hex)");
    check(StrFormatByteSizeA(1536, buf, sizeof(buf)) && strcmp(buf, "1.50 KB") == 0,
          "StrFormatByteSizeA");
    StrFormatByteSizeA(532, buf, sizeof(buf));
    check(strcmp(buf, "532 bytes") == 0, "StrFormatByteSizeA (bytes)");
    check(StrFormatKBSizeA(1234567, buf, sizeof(buf)) && strcmp(buf, "1,206 KB") == 0,
          "StrFormatKBSizeA");
    strcpy(buf, "  trim me  ");
    check(StrTrimA(buf, " ") && strcmp(buf, "trim me") == 0, "StrTrimA");
    dup = StrDupA("copy");
    check(dup && strcmp(dup, "copy") == 0, "StrDupA");
    LocalFree(dup);
    check(wnsprintfA(buf, sizeof(buf), "%d-%s", 42, "x") == 4 && strcmp(buf, "42-x") == 0,
          "wnsprintfA");
    check(wsprintfW(wpath, L"%s=%d", L"n", 7) == 3 && wcscmp(wpath, L"n=7") == 0, "wsprintfW");
}

/* ---- Registry and INI files ---- */

static void test_registry_and_profiles(void)
{
    HKEY hk;
    DWORD type, size, data = 1234, count = 0, values = 0;
    char text[64], sections[128];
    WCHAR wtext[64];
    struct { int a, b; } record = {7, 9}, loaded = {0, 0};
    const char *ini = "C:\\Windows\\Temp\\ext_api_test.ini";

    printf("\n--- shlwapi and advapi32: registry ---\n");
    check(SHSetValueA(HKEY_CURRENT_USER, "Software\\WinExe32Emu\\ExtTest\\Sub", "Number", REG_DWORD,
                      &data, sizeof(data)) == ERROR_SUCCESS, "SHSetValueA (creates the key)");
    size = sizeof(data);
    data = 0;
    check(SHGetValueA(HKEY_CURRENT_USER, "Software\\WinExe32Emu\\ExtTest\\Sub", "Number", &type,
                      &data, &size) == ERROR_SUCCESS && type == REG_DWORD && data == 1234,
          "SHGetValueA");
    size = sizeof(data);
    data = 0;
    check(RegGetValueA(HKEY_CURRENT_USER, "Software\\WinExe32Emu\\ExtTest\\Sub", "Number",
                       RRF_RT_REG_DWORD, NULL, &data, &size) == ERROR_SUCCESS && data == 1234,
          "RegGetValueA (DWORD)");
    size = sizeof(text);
    check(RegGetValueA(HKEY_CURRENT_USER, "Software\\WinExe32Emu\\ExtTest\\Sub", "Number",
                       RRF_RT_REG_SZ, NULL, text, &size) == ERROR_UNSUPPORTED_TYPE,
          "RegGetValueA (type filter)");
    check(RegSetValueA(HKEY_CURRENT_USER, "Software\\WinExe32Emu\\ExtTest", REG_SZ, "Default", 7)
          == ERROR_SUCCESS, "RegSetValueA");
    size = sizeof(text);
    check(RegQueryValueA(HKEY_CURRENT_USER, "Software\\WinExe32Emu\\ExtTest", text, (LONG *)&size)
          == ERROR_SUCCESS && strcmp(text, "Default") == 0, "RegQueryValueA");
    check(RegOpenKeyA(HKEY_CURRENT_USER, "Software\\WinExe32Emu\\ExtTest", &hk) == ERROR_SUCCESS,
          "RegOpenKeyA");
    check(RegQueryInfoKeyA(hk, NULL, NULL, NULL, &count, NULL, NULL, &values, NULL, NULL, NULL,
                           NULL) == ERROR_SUCCESS && count == 1 && values == 1,
          "RegQueryInfoKeyA");
    RegCloseKey(hk);
    check(SHDeleteKeyA(HKEY_CURRENT_USER, "Software\\WinExe32Emu\\ExtTest") == ERROR_SUCCESS,
          "SHDeleteKeyA (with subkeys)");
    check(RegOpenKeyA(HKEY_CURRENT_USER, "Software\\WinExe32Emu\\ExtTest", &hk) ==
          ERROR_FILE_NOT_FOUND, "SHDeleteKeyA removed the key");

    printf("\n--- kernel32: INI files ---\n");
    DeleteFileA(ini);
    check(WritePrivateProfileStringW(L"Main", L"Name", L"Wide value", L"C:\\Windows\\Temp\\ext_api_test.ini"),
          "WritePrivateProfileStringW");
    WritePrivateProfileStringA("Main", "Count", "3", ini);
    WritePrivateProfileStringA("Other", "Key", "x", ini);
    check(GetPrivateProfileStringW(L"main", L"name", L"", wtext, 64,
                                   L"C:\\Windows\\Temp\\ext_api_test.ini") == 10 &&
          wcscmp(wtext, L"Wide value") == 0, "GetPrivateProfileStringW");
    size = GetPrivateProfileSectionA("Main", sections, sizeof(sections), ini);
    check(size == 24 && strcmp(sections, "Name=Wide value") == 0 &&
          strcmp(sections + 16, "Count=3") == 0, "GetPrivateProfileSectionA");
    size = GetPrivateProfileSectionNamesA(sections, sizeof(sections), ini);
    check(size == 11 && strcmp(sections, "Main") == 0 && strcmp(sections + 5, "Other") == 0,
          "GetPrivateProfileSectionNamesA");
    check(WritePrivateProfileStructA("Data", "Record", &record, sizeof(record), ini) &&
          GetPrivateProfileStructA("Data", "Record", &loaded, sizeof(loaded), ini) &&
          loaded.a == 7 && loaded.b == 9, "Write/GetPrivateProfileStructA");
    check(WritePrivateProfileSectionA("Other", "A=1\0B=2\0", ini) &&
          GetPrivateProfileIntA("Other", "B", 0, ini) == 2 &&
          GetPrivateProfileIntA("Other", "Key", 99, ini) == 99, "WritePrivateProfileSectionA");
    DeleteFileA(ini);
}

/* ---- advapi32 security, crypto, services ---- */

static void test_security(void)
{
    SID_IDENTIFIER_AUTHORITY nt = {SECURITY_NT_AUTHORITY};
    PSID admins = NULL, parsed = NULL;
    BYTE world[SECURITY_MAX_SID_SIZE], token_buf[256];
    DWORD size, needed;
    BOOL member = FALSE, present = FALSE, defaulted = TRUE;
    char *text = NULL, name[64], domain[64];
    SID_NAME_USE use;
    HANDLE token;
    TOKEN_ELEVATION elevation;
    SECURITY_DESCRIPTOR sd;
    PACL dacl = NULL;
    BYTE acl_buf[128];
    PACL acl = (PACL)acl_buf;
    void *ace = NULL;

    printf("\n--- advapi32: SIDs and tokens ---\n");
    check(AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                                   0, 0, 0, 0, 0, 0, &admins), "AllocateAndInitializeSid");
    check(IsValidSid(admins) && GetLengthSid(admins) == 16, "IsValidSid / GetLengthSid");
    check(ConvertSidToStringSidA(admins, &text) && strcmp(text, "S-1-5-32-544") == 0,
          "ConvertSidToStringSidA");
    LocalFree(text);
    check(ConvertStringSidToSidA("BA", &parsed) && EqualSid(parsed, admins),
          "ConvertStringSidToSidA (SDDL alias)");
    LocalFree(parsed);
    check(*GetSidSubAuthorityCount(admins) == 2 && *GetSidSubAuthority(admins, 1) == 544,
          "GetSidSubAuthority(Count)");
    check(CheckTokenMembership(NULL, admins, &member) && member, "CheckTokenMembership (admin)");
    size = sizeof(name);
    needed = sizeof(domain);
    check(LookupAccountSidA(NULL, admins, name, &size, domain, &needed, &use) &&
          strcmp(name, "Administrators") == 0 && strcmp(domain, "BUILTIN") == 0 &&
          use == SidTypeAlias, "LookupAccountSidA");
    size = sizeof(world);
    check(CreateWellKnownSid(WinWorldSid, NULL, world, &size) && size == 12, "CreateWellKnownSid");
    check(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token), "OpenProcessToken");
    check(GetTokenInformation(token, TokenUser, NULL, 0, &needed) == FALSE &&
          GetLastError() == ERROR_INSUFFICIENT_BUFFER && needed > 8,
          "GetTokenInformation (size)");
    check(GetTokenInformation(token, TokenUser, token_buf, sizeof(token_buf), &needed) &&
          IsValidSid(((TOKEN_USER *)token_buf)->User.Sid), "GetTokenInformation (TokenUser)");
    if (ConvertSidToStringSidA(((TOKEN_USER *)token_buf)->User.Sid, &text)) {
        printf("    user SID: %s\n", text);
        LocalFree(text);
    }
    check(GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &needed) &&
          elevation.TokenIsElevated, "GetTokenInformation (TokenElevation)");
    CloseHandle(token);
    check(!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token) &&
          GetLastError() == ERROR_NO_TOKEN, "OpenThreadToken (no impersonation)");

    printf("\n--- advapi32: security descriptors and ACLs ---\n");
    check(InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION) &&
          IsValidSecurityDescriptor(&sd), "InitializeSecurityDescriptor");
    check(SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE) &&
          GetSecurityDescriptorDacl(&sd, &present, &dacl, &defaulted) && present && !dacl &&
          !defaulted, "Set/GetSecurityDescriptorDacl (NULL DACL)");
    check(InitializeAcl(acl, sizeof(acl_buf), ACL_REVISION) &&
          AddAccessAllowedAce(acl, ACL_REVISION, GENERIC_READ, admins) &&
          acl->AceCount == 1 && GetAce(acl, 0, &ace) &&
          ((ACCESS_ALLOWED_ACE *)ace)->Mask == GENERIC_READ &&
          EqualSid((PSID)&((ACCESS_ALLOWED_ACE *)ace)->SidStart, admins),
          "InitializeAcl / AddAccessAllowedAce / GetAce");
    FreeSid(admins);

    printf("\n--- advapi32 and bcrypt: hashes and random numbers ---\n");
    {
        HCRYPTPROV prov;
        HCRYPTHASH hash;
        BYTE digest[64], random[16] = {0};
        char digest_hex[129];
        BCRYPT_ALG_HANDLE alg;
        BCRYPT_HASH_HANDLE bhash;
        DWORD length = 0, result;
        int nonzero = 0, i;

        check(CryptAcquireContextA(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT),
              "CryptAcquireContextA");
        check(CryptGenRandom(prov, sizeof(random), random), "CryptGenRandom");
        for (i = 0; i < 16; i++)
            nonzero |= random[i];
        check(nonzero != 0, "CryptGenRandom gives random bytes");
        size = sizeof(digest);
        check(CryptCreateHash(prov, CALG_MD5, 0, 0, &hash) &&
              CryptHashData(hash, (const BYTE *)"abc", 3, 0) &&
              CryptGetHashParam(hash, HP_HASHVAL, digest, &size, 0) && size == 16,
              "CryptCreateHash / CryptHashData (MD5)");
        hex(digest, 16, digest_hex);
        check(strcmp(digest_hex, "900150983cd24fb0d6963f7d28e17f72") == 0, "MD5 of \"abc\"");
        CryptDestroyHash(hash);
        CryptReleaseContext(prov, 0);

        check(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0) == 0,
              "BCryptOpenAlgorithmProvider (SHA256)");
        check(BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, (PUCHAR)&length, sizeof(length), &result, 0)
              == 0 && length == 32, "BCryptGetProperty (hash length)");
        check(BCryptCreateHash(alg, &bhash, NULL, 0, NULL, 0, 0) == 0 &&
              BCryptHashData(bhash, (PUCHAR)"abc", 3, 0) == 0 &&
              BCryptFinishHash(bhash, digest, 32, 0) == 0, "BCryptCreateHash / HashData / FinishHash");
        hex(digest, 32, digest_hex);
        check(strcmp(digest_hex,
                     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0,
              "SHA-256 of \"abc\"");
        BCryptDestroyHash(bhash);
        BCryptCloseAlgorithmProvider(alg, 0);
        check(BCryptGenRandom(NULL, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0,
              "BCryptGenRandom");
    }

    printf("\n--- advapi32 and secur32: services and names ---\n");
    {
        SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
        check(scm != NULL, "OpenSCManagerA");
        check(OpenServiceA(scm, "NoSuchService", SERVICE_QUERY_STATUS) == NULL &&
              GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST, "OpenServiceA (not installed)");
        check(CloseServiceHandle(scm), "CloseServiceHandle");
        size = sizeof(name);
        check(GetUserNameExA(NameSamCompatible, name, &size) && strchr(name, '\\') != NULL &&
              size == strlen(name), "GetUserNameExA (NameSamCompatible)");
        printf("    user: %s\n", name);
    }
}

/* ---- kernel32 and ntdll ---- */

static void test_kernel32(void)
{
    ATOM atom;
    char buf[MAX_PATH];
    OSVERSIONINFOEXA vi;
    DWORDLONG mask;
    BOOL wow64 = TRUE;
    DWORD size, value = 0x12345678;
    WIN32_FILE_ATTRIBUTE_DATA fad;
    HANDLE file, dup = NULL, thread = NULL;
    HFILE hf;
    OFSTRUCT ofs;
    char *block;
    const char *tmp = "C:\\Windows\\Temp\\ext_api_test.tmp";
    FILETIME written;

    printf("\n--- kernel32: atoms ---\n");
    atom = GlobalAddAtomA("ExtApiTestAtom");
    check(atom >= 0xC000, "GlobalAddAtomA");
    check(GlobalFindAtomA("extapitestatom") == atom, "GlobalFindAtomA (case-insensitive)");
    check(GlobalGetAtomNameA(atom, buf, sizeof(buf)) == 14 && strcmp(buf, "ExtApiTestAtom") == 0,
          "GlobalGetAtomNameA");
    check(GlobalDeleteAtom(atom) == 0 && GlobalFindAtomA("ExtApiTestAtom") == 0,
          "GlobalDeleteAtom");
    check(AddAtomA("#100") == 100 && AddAtomA(MAKEINTATOM(5)) == 5, "AddAtomA (integer atoms)");

    printf("\n--- kernel32: versions and system information ---\n");
    memset(&vi, 0, sizeof(vi));
    vi.dwOSVersionInfoSize = sizeof(vi);
    vi.dwMajorVersion = 5;
    vi.dwMinorVersion = 1;
    mask = VerSetConditionMask(VerSetConditionMask(0, VER_MAJORVERSION, VER_GREATER_EQUAL),
                               VER_MINORVERSION, VER_GREATER_EQUAL);
    check(VerifyVersionInfoA(&vi, VER_MAJORVERSION | VER_MINORVERSION, mask),
          "VerifyVersionInfoA (at least XP)");
    vi.dwMajorVersion = 10;
    vi.dwMinorVersion = 0;
    check(!VerifyVersionInfoA(&vi, VER_MAJORVERSION | VER_MINORVERSION, mask) &&
          GetLastError() == ERROR_OLD_WIN_VERSION, "VerifyVersionInfoA (not Windows 10)");
    check(IsWow64Process(GetCurrentProcess(), &wow64) && !wow64, "IsWow64Process");
    check(GetSystemWindowsDirectoryA(buf, sizeof(buf)) == 10 && strcmp(buf, "C:\\Windows") == 0,
          "GetSystemWindowsDirectoryA");
    size = sizeof(buf);
    check(GetComputerNameExA(ComputerNameDnsHostname, buf, &size) && size == strlen(buf) && size,
          "GetComputerNameExA");
    check(GetUserDefaultUILanguage() == GetSystemDefaultLangID(), "GetUserDefaultUILanguage");

    printf("\n--- kernel32: files and handles ---\n");
    check(GetFileAttributesExA("C:\\Windows", GetFileExInfoStandard, &fad) &&
          (fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY), "GetFileAttributesExA (folder)");
    file = CreateFileA(tmp, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    WriteFile(file, "abcdef", 6, &size, NULL);
    check(GetFileTime(file, NULL, NULL, &written) && written.dwHighDateTime != 0, "GetFileTime");
    check(DuplicateHandle(GetCurrentProcess(), file, GetCurrentProcess(), &dup, 0, FALSE,
                          DUPLICATE_SAME_ACCESS) && dup && dup != file, "DuplicateHandle (file)");
    CloseHandle(file);
    SetFilePointer(dup, 2, NULL, FILE_BEGIN);
    check(ReadFile(dup, buf, 2, &size, NULL) && size == 2 && memcmp(buf, "cd", 2) == 0,
          "The duplicate works after closing the original");
    CloseHandle(dup);
    check(DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &thread,
                          0, FALSE, DUPLICATE_SAME_ACCESS) &&
          GetThreadId(thread) == GetCurrentThreadId(), "DuplicateHandle (current thread)");
    CloseHandle(thread);
    check(GetProcessId(GetCurrentProcess()) == GetCurrentProcessId(), "GetProcessId");

    hf = _lcreat(tmp, 0);
    check(hf != HFILE_ERROR && _lwrite(hf, "hello", 5) == 5, "_lcreat / _lwrite");
    check(_llseek(hf, 1, FILE_BEGIN) == 1 && _lread(hf, buf, 3) == 3 && memcmp(buf, "ell", 3) == 0,
          "_llseek / _lread");
    check(_lclose(hf) == 0, "_lclose");
    check(OpenFile(tmp, &ofs, OF_EXIST) != HFILE_ERROR && ofs.nErrCode == 0, "OpenFile (OF_EXIST)");
    check(OpenFile(tmp, &ofs, OF_DELETE) != HFILE_ERROR && GetFileAttributesA(tmp) ==
          INVALID_FILE_ATTRIBUTES, "OpenFile (OF_DELETE)");

    printf("\n--- kernel32: memory ---\n");
    block = LocalAlloc(LMEM_FIXED, 16);
    strcpy(block, "keep me");
    block = LocalReAlloc(block, 4096, LMEM_MOVEABLE);
    check(block && strcmp(block, "keep me") == 0 && LocalSize(block) >= 4096, "LocalReAlloc");
    LocalFree(block);
    check(IsBadReadPtr(NULL, 4) && !IsBadReadPtr(&value, 4), "IsBadReadPtr");
    check(!IsBadWritePtr(&value, 4) && !IsBadStringPtrA("text", 10), "IsBadWritePtr / IsBadStringPtrA");
    check(HeapValidate(GetProcessHeap(), 0, NULL), "HeapValidate");

    printf("\n--- ntdll ---\n");
    {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        LONG (WINAPI *get_version)(OSVERSIONINFOW *) =
            (LONG (WINAPI *)(OSVERSIONINFOW *))GetProcAddress(ntdll, "RtlGetVersion");
        ULONG (WINAPI *to_dos)(LONG) =
            (ULONG (WINAPI *)(LONG))GetProcAddress(ntdll, "RtlNtStatusToDosError");
        OSVERSIONINFOW ovi;
        ovi.dwOSVersionInfoSize = sizeof(ovi);
        check(get_version && get_version(&ovi) == 0 && ovi.dwMajorVersion == 6,
              "RtlGetVersion");
        check(to_dos && to_dos((LONG)0xC0000034) == ERROR_FILE_NOT_FOUND,
              "RtlNtStatusToDosError");
    }
}

/* ---- user32 ---- */

static int g_enum_count;

static BOOL CALLBACK count_windows(HWND hwnd, LPARAM param)
{
    g_enum_count++;
    return TRUE;
}

static LRESULT CALLBACK subclass_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp,
                                      UINT_PTR id, DWORD_PTR data)
{
    if (msg == WM_USER + 1)
        return 1000 + (LRESULT)data + DefSubclassProc(hwnd, msg, wp, lp);
    return DefSubclassProc(hwnd, msg, wp, lp);
}

static LRESULT CALLBACK base_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    if (msg == WM_USER + 1)
        return 5;
    return DefWindowProcA(hwnd, msg, wp, lp);
}

static void test_user32(void)
{
    char buf[64];
    BYTE state[256] = {0};
    WORD chars = 0;
    USEROBJECTFLAGS flags;
    DWORD needed;
    RECT r, a = {0, 0, 100, 100}, b = {0, 0, 100, 30};
    HWND fake = (HWND)0x12340;
    WNDCLASSA wc;
    HWND hwnd;

    printf("\n--- user32: keyboard and characters ---\n");
    check(VkKeyScanA('a') == 'A' && VkKeyScanA('A') == 0x141 && VkKeyScanA('!') == 0x131,
          "VkKeyScanA");
    check(ToAscii('A', 0x1E, state, &chars, 0) == 1 && chars == 'a', "ToAscii");
    state[VK_SHIFT] = 0x80;
    check(ToAscii('1', 0x02, state, &chars, 0) == 1 && chars == '!', "ToAscii (shift)");
    check(GetKeyNameTextA(0x1C << 16, buf, sizeof(buf)) == 5 && strcmp(buf, "Enter") == 0,
          "GetKeyNameTextA");
    check(GetKeyboardLayoutNameA(buf) && strcmp(buf, "00000409") == 0, "GetKeyboardLayoutNameA");
    strcpy(buf, "MiXeD");
    check(CharUpperBuffA(buf, 3) == 3 && strcmp(buf, "MIXeD") == 0, "CharUpperBuffA");
    check(IsCharAlphaW(L'x') && !IsCharAlphaW(L'1') && IsCharUpperW(L'Q'), "IsCharAlphaW / IsCharUpperW");

    printf("\n--- user32: window stations, DPI, properties, rectangles ---\n");
    check(GetUserObjectInformationA(GetProcessWindowStation(), UOI_FLAGS, &flags, sizeof(flags),
                                    &needed) && (flags.dwFlags & WSF_VISIBLE),
          "GetUserObjectInformationA (visible window station)");
    check(GetUserObjectInformationA(GetThreadDesktop(GetCurrentThreadId()), UOI_NAME, buf,
                                    sizeof(buf), &needed) && strcmp(buf, "Default") == 0,
          "GetUserObjectInformationA (desktop name)");
    check(SetProcessDPIAware() && IsProcessDPIAware(), "SetProcessDPIAware");
    check(SetPropA(fake, "ExtProp", (HANDLE)0x55) && GetPropA(fake, "ExtProp") == (HANDLE)0x55,
          "SetPropA / GetPropA");
    check(RemovePropA(fake, "ExtProp") == (HANDLE)0x55 && GetPropA(fake, "ExtProp") == NULL,
          "RemovePropA");
    check(SubtractRect(&r, &a, &b) && r.top == 30 && r.bottom == 100, "SubtractRect");
    g_enum_count = 0;
    check(EnumWindows(count_windows, 0), "EnumWindows");

    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc = base_proc;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.lpszClassName = "ExtApiTestClass";
    RegisterClassA(&wc);
    hwnd = CreateWindowExA(0, "ExtApiTestClass", "Ext API Test", WS_OVERLAPPEDWINDOW,
                           0, 0, 200, 100, NULL, NULL, wc.hInstance, NULL);
    if (!IsWindow(hwnd)) {
        printf("SKIP: window enumeration and subclassing (no GUI)\n");
        return;
    }
    g_enum_count = 0;
    EnumWindows(count_windows, 0);
    check(g_enum_count >= 1, "EnumWindows finds the window");
    check(GetWindowThreadProcessId(hwnd, &needed) == GetCurrentThreadId() &&
          needed == GetCurrentProcessId(), "GetWindowThreadProcessId");
    check(GetAncestor(hwnd, GA_ROOT) == hwnd, "GetAncestor");
    check(SendMessageA(hwnd, WM_USER + 1, 0, 0) == 5, "Before subclassing");
    check(SetWindowSubclass(hwnd, subclass_proc, 1, 20), "SetWindowSubclass");
    check(SendMessageA(hwnd, WM_USER + 1, 0, 0) == 1025, "The subclass runs, then the window procedure");
    check(RemoveWindowSubclass(hwnd, subclass_proc, 1) &&
          SendMessageA(hwnd, WM_USER + 1, 0, 0) == 5, "RemoveWindowSubclass");
    DestroyWindow(hwnd);
}

/* ---- shell32, COM GUIDs, rpcrt4 ---- */

static void test_shell_and_guids(void)
{
    int argc = 0;
    LPWSTR *argv;
    PWSTR folder = NULL;
    GUID guid, parsed;
    WCHAR text[64];
    UUID id, id2;
    RPC_CSTR rpc_text = NULL;
    RPC_STATUS status;

    printf("\n--- shell32 ---\n");
    argv = CommandLineToArgvW(L"prog.exe \"two words\" last", &argc);
    check(argv && argc == 3 && wcscmp(argv[1], L"two words") == 0 && wcscmp(argv[2], L"last") == 0,
          "CommandLineToArgvW");
    LocalFree(argv);
    check(SHGetKnownFolderPath(&FOLDERID_LocalAppData, 0, NULL, &folder) == S_OK && folder &&
          folder[1] == L':', "SHGetKnownFolderPath (LocalAppData)");
    if (folder)
        printf("    LocalAppData: %ls\n", folder);
    CoTaskMemFree(folder);
    check(SHCreateDirectoryExA(NULL, "C:\\Windows\\Temp\\ExtApi\\A\\B", NULL) == ERROR_SUCCESS &&
          PathIsDirectoryA("C:\\Windows\\Temp\\ExtApi\\A\\B"), "SHCreateDirectoryExA (nested)");
    check(SHCreateDirectoryExA(NULL, "C:\\Windows\\Temp\\ExtApi", NULL) == ERROR_ALREADY_EXISTS,
          "SHCreateDirectoryExA (exists)");
    RemoveDirectoryA("C:\\Windows\\Temp\\ExtApi\\A\\B");
    RemoveDirectoryA("C:\\Windows\\Temp\\ExtApi\\A");
    RemoveDirectoryA("C:\\Windows\\Temp\\ExtApi");
    check(IsUserAnAdmin(), "IsUserAnAdmin");

    printf("\n--- ole32 and rpcrt4: GUIDs ---\n");
    check(CoCreateGuid(&guid) == S_OK, "CoCreateGuid");
    check(StringFromGUID2(&guid, text, 64) == 39 && text[0] == L'{' && text[37] == L'}',
          "StringFromGUID2");
    check(CLSIDFromString(text, &parsed) == S_OK && IsEqualGUID(&guid, &parsed),
          "CLSIDFromString round trip");
    check(IIDFromString(L"not a guid", &parsed) != S_OK, "IIDFromString (invalid)");
    check(UuidCreate(&id) == RPC_S_OK && UuidToStringA(&id, &rpc_text) == RPC_S_OK &&
          strlen((char *)rpc_text) == 36, "UuidCreate / UuidToStringA");
    check(UuidFromStringA(rpc_text, &id2) == RPC_S_OK && UuidEqual(&id, &id2, &status),
          "UuidFromStringA / UuidEqual");
    RpcStringFreeA(&rpc_text);
    check(rpc_text == NULL, "RpcStringFreeA");
    UuidCreateNil(&id2);
    check(UuidIsNil(&id2, &status) && !UuidIsNil(&id, &status), "UuidCreateNil / UuidIsNil");
}

/* ---- psapi, sockets, themes, version ---- */

static void test_system(void)
{
    char buf[MAX_PATH];
    PROCESS_MEMORY_COUNTERS pmc;
    HMODULE modules[16];
    DWORD needed = 0;
    WSADATA wsa;
    struct hostent *host;
    struct addrinfo hints, *info = NULL;
    BOOL composition = TRUE;

    printf("\n--- psapi ---\n");
    check(GetModuleBaseNameA(GetCurrentProcess(), NULL, buf, sizeof(buf)) &&
          lstrcmpiA(buf, "ext_api_test.exe") == 0, "GetModuleBaseNameA");
    check(GetModuleFileNameExA(GetCurrentProcess(), NULL, buf, sizeof(buf)) &&
          strstr(buf, "ext_api_test.exe") != NULL, "GetModuleFileNameExA");
    check(EnumProcessModules(GetCurrentProcess(), modules, sizeof(modules), &needed) &&
          needed >= 4 && modules[0] == GetModuleHandleA(NULL), "EnumProcessModules");
    pmc.cb = sizeof(pmc);
    check(GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc)) && pmc.WorkingSetSize > 0,
          "GetProcessMemoryInfo");

    printf("\n--- ws2_32: an offline computer ---\n");
    check(WSAStartup(MAKEWORD(2, 2), &wsa) == 0 && wsa.wVersion == MAKEWORD(2, 2), "WSAStartup");
    check(htons(0x1234) == 0x3412 && ntohl(htonl(0x11223344)) == 0x11223344, "htons / htonl");
    check(inet_addr("127.0.0.1") == 0x0100007F && inet_addr("bad") == INADDR_NONE, "inet_addr");
    {
        struct in_addr addr;
        addr.s_addr = inet_addr("10.1.2.3");
        check(strcmp(inet_ntoa(addr), "10.1.2.3") == 0, "inet_ntoa");
    }
    check(gethostname(buf, sizeof(buf)) == 0 && buf[0], "gethostname");
    host = gethostbyname("localhost");
    check(host && host->h_length == 4 &&
          memcmp(host->h_addr_list[0], "\x7f\x00\x00\x01", 4) == 0, "gethostbyname (localhost)");
    check(gethostbyname("example.invalid") == NULL && WSAGetLastError() == WSAHOST_NOT_FOUND,
          "gethostbyname (unknown host)");
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    check(getaddrinfo("localhost", "8080", &hints, &info) == 0 && info &&
          ntohs(((struct sockaddr_in *)info->ai_addr)->sin_port) == 8080, "getaddrinfo");
    if (info)
        freeaddrinfo(info);
    check(socket(AF_INET, SOCK_STREAM, 0) == INVALID_SOCKET && WSAGetLastError() == WSAENETDOWN,
          "socket (network is down)");
    check(WSACleanup() == 0, "WSACleanup");

    printf("\n--- uxtheme, dwmapi, version ---\n");
    check(!IsThemeActive() && OpenThemeData(NULL, L"BUTTON") == NULL, "IsThemeActive / OpenThemeData");
    check(DwmIsCompositionEnabled(&composition) == S_OK && !composition, "DwmIsCompositionEnabled");
    check(VerLanguageNameA(0x0409, buf, sizeof(buf)) == 23 &&
          strcmp(buf, "English (United States)") == 0, "VerLanguageNameA");
}

int main(void)
{
    printf("=== Extended API test ===\n");
    test_shlwapi();
    test_registry_and_profiles();
    test_security();
    test_kernel32();
    test_user32();
    test_shell_and_guids();
    test_system();
    printf("\n== %d failure(s) ==\n", failures);
    return failures;
}
