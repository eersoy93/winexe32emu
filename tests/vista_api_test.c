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
Vista+ API test - exercises the kernel32 APIs that the Visual C++ 2015+
runtime (vcruntime140/ucrtbase and the static CRT) uses: pointer encoding,
fiber local storage, interlocked SLists, SRW locks, condition variables,
InitOnce, VirtualProtect/VirtualQuery, GetModuleHandleEx, locales, date and
time formats, the time zone, and the vcruntime140.dll exports (checking
their calling conventions). Every check prints PASS or FAIL; the exit code
is the failure count.
*/

#define _WIN32_WINNT 0x0600
#include <windows.h>
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

/* ---- Calls through a function pointer that check the stack pointer ---- */

/* Globals have absolute addresses, so pushing them doesn't depend on ESP */
static DWORD g_func, g_args[3], g_before, g_after, g_result;

/* Call a cdecl function with 3 arguments; TRUE if ESP is balanced */
static int call_cdecl3(FARPROC func, DWORD a, DWORD b, DWORD c, DWORD *result)
{
    g_func = (DWORD)func;
    g_args[0] = a;
    g_args[1] = b;
    g_args[2] = c;
    __asm__ volatile(
        "movl %%esp, %[before]\n\t"
        "pushl %[a2]\n\t"
        "pushl %[a1]\n\t"
        "pushl %[a0]\n\t"
        "call *%[fn]\n\t"
        "addl $12, %%esp\n\t"
        "movl %%esp, %[after]\n\t"
        "movl %%eax, %[res]\n\t"
        : [before] "=m"(g_before), [after] "=m"(g_after), [res] "=m"(g_result)
        : [a0] "m"(g_args[0]), [a1] "m"(g_args[1]), [a2] "m"(g_args[2]), [fn] "m"(g_func)
        : "eax", "ecx", "edx", "memory", "cc");
    if (result)
        *result = g_result;
    return g_before == g_after;
}

/* Call a stdcall function with 3 arguments; TRUE if ESP is balanced */
static int call_stdcall3(FARPROC func, DWORD a, DWORD b, DWORD c, DWORD *result)
{
    g_func = (DWORD)func;
    g_args[0] = a;
    g_args[1] = b;
    g_args[2] = c;
    __asm__ volatile(
        "movl %%esp, %[before]\n\t"
        "pushl %[a2]\n\t"
        "pushl %[a1]\n\t"
        "pushl %[a0]\n\t"
        "call *%[fn]\n\t"
        "movl %%esp, %[after]\n\t"
        "movl %%eax, %[res]\n\t"
        : [before] "=m"(g_before), [after] "=m"(g_after), [res] "=m"(g_result)
        : [a0] "m"(g_args[0]), [a1] "m"(g_args[1]), [a2] "m"(g_args[2]), [fn] "m"(g_func)
        : "eax", "ecx", "edx", "memory", "cc");
    if (result)
        *result = g_result;
    return g_before == g_after;
}

/* ---- Pointer encoding, FLS, SLists ---- */

static PVOID fls_freed_value = NULL;

static void WINAPI fls_callback(PVOID value)
{
    fls_freed_value = value;
}

typedef struct {
    SLIST_ENTRY entry;
    int value;
} slist_item;

static void test_runtime_basics(void)
{
    DWORD index;
    SLIST_HEADER head;
    slist_item a, b, *item;
    PSLIST_ENTRY rest;
    static int marker;

    printf("\n--- Pointer encoding, FLS, SLists ---\n");
    check(DecodePointer(EncodePointer(&marker)) == &marker, "EncodePointer/DecodePointer");

    index = FlsAlloc(fls_callback);
    check(index != FLS_OUT_OF_INDEXES, "FlsAlloc");
    check(FlsGetValue(index) == NULL, "FlsGetValue of a new slot is NULL");
    check(FlsSetValue(index, &marker) && FlsGetValue(index) == &marker,
          "FlsSetValue/FlsGetValue");
    check(FlsFree(index) && fls_freed_value == &marker, "FlsFree runs the callback");

    a.value = 1;
    b.value = 2;
    InitializeSListHead(&head);
    InterlockedPushEntrySList(&head, &a.entry);
    InterlockedPushEntrySList(&head, &b.entry);
    check(QueryDepthSList(&head) == 2, "InterlockedPushEntrySList/QueryDepthSList");
    item = (slist_item *)InterlockedPopEntrySList(&head);
    check(item == &b && QueryDepthSList(&head) == 1, "InterlockedPopEntrySList (LIFO)");
    rest = InterlockedFlushSList(&head);
    check(rest == &a.entry && QueryDepthSList(&head) == 0 &&
          InterlockedPopEntrySList(&head) == NULL, "InterlockedFlushSList");
}

/* ---- SRW locks, condition variables, InitOnce ---- */

static SRWLOCK srw = SRWLOCK_INIT;
static CRITICAL_SECTION cv_cs;
static CONDITION_VARIABLE cv = CONDITION_VARIABLE_INIT;
static volatile int srw_counter = 0, cv_ready = 0;

static DWORD WINAPI srw_thread(LPVOID param)
{
    int i;
    for (i = 0; i < 300; i++) {
        int value;
        AcquireSRWLockExclusive(&srw);
        value = srw_counter;
        if (i % 30 == 0)
            Sleep(0);  /* The other thread must wait for the lock meanwhile */
        srw_counter = value + 1;
        ReleaseSRWLockExclusive(&srw);
    }
    return 0;
}

static DWORD WINAPI cv_thread(LPVOID param)
{
    Sleep(20);
    EnterCriticalSection(&cv_cs);
    cv_ready = 1;
    LeaveCriticalSection(&cv_cs);
    WakeConditionVariable(&cv);
    return 0;
}

static int init_once_calls = 0;

static BOOL CALLBACK init_once_callback(PINIT_ONCE once, PVOID parameter, PVOID *context)
{
    init_once_calls++;
    *context = (PVOID)(0x1230 + (DWORD)(INT_PTR)parameter);
    return TRUE;
}

static void test_synchronization(void)
{
    HANDLE threads[2];
    INIT_ONCE once = INIT_ONCE_STATIC_INIT;
    PVOID context = NULL;
    BOOL ok;

    printf("\n--- SRW locks, condition variables, InitOnce ---\n");
    AcquireSRWLockExclusive(&srw);
    check(!TryAcquireSRWLockShared(&srw) && !TryAcquireSRWLockExclusive(&srw),
          "an exclusive SRW lock blocks the others");
    ReleaseSRWLockExclusive(&srw);
    check(TryAcquireSRWLockShared(&srw) && TryAcquireSRWLockShared(&srw),
          "shared SRW lock taken twice");
    check(!TryAcquireSRWLockExclusive(&srw), "a shared SRW lock blocks writers");
    ReleaseSRWLockShared(&srw);
    ReleaseSRWLockShared(&srw);
    check(TryAcquireSRWLockExclusive(&srw), "SRW lock is free after the releases");
    ReleaseSRWLockExclusive(&srw);

    threads[0] = CreateThread(NULL, 0, srw_thread, NULL, 0, NULL);
    threads[1] = CreateThread(NULL, 0, srw_thread, NULL, 0, NULL);
    WaitForMultipleObjects(2, threads, TRUE, INFINITE);
    check(srw_counter == 600, "AcquireSRWLockExclusive serializes two threads");
    CloseHandle(threads[0]);
    CloseHandle(threads[1]);

    InitializeCriticalSection(&cv_cs);
    EnterCriticalSection(&cv_cs);
    SetLastError(0);
    ok = SleepConditionVariableCS(&cv, &cv_cs, 30);
    check(!ok && GetLastError() == ERROR_TIMEOUT, "SleepConditionVariableCS timeout");
    threads[0] = CreateThread(NULL, 0, cv_thread, NULL, 0, NULL);
    while (!cv_ready) {
        if (!SleepConditionVariableCS(&cv, &cv_cs, 5000))
            break;
    }
    check(cv_ready, "SleepConditionVariableCS wakes up (WakeConditionVariable)");
    check(TryEnterCriticalSection(&cv_cs), "the critical section is owned again");
    LeaveCriticalSection(&cv_cs);
    LeaveCriticalSection(&cv_cs);
    WaitForSingleObject(threads[0], INFINITE);
    CloseHandle(threads[0]);
    DeleteCriticalSection(&cv_cs);

    AcquireSRWLockExclusive(&srw);
    ok = SleepConditionVariableSRW(&cv, &srw, 10, 0);
    check(!ok && GetLastError() == ERROR_TIMEOUT && !TryAcquireSRWLockShared(&srw),
          "SleepConditionVariableSRW timeout (lock taken back)");
    ReleaseSRWLockExclusive(&srw);

    ok = InitOnceExecuteOnce(&once, init_once_callback, (PVOID)4, &context);
    check(ok && context == (PVOID)0x1234, "InitOnceExecuteOnce runs the callback");
    context = NULL;
    ok = InitOnceExecuteOnce(&once, init_once_callback, (PVOID)8, &context);
    check(ok && init_once_calls == 1 && context == (PVOID)0x1234,
          "InitOnceExecuteOnce runs it only once");
}

/* ---- Memory and modules ---- */

static int static_data = 5;

static void test_memory_and_modules(void)
{
    BYTE *block;
    DWORD old = 0;
    MEMORY_BASIC_INFORMATION mbi;
    HMODULE module = NULL, exe = GetModuleHandleA(NULL);
    PVOID base = NULL;
    CONTEXT context;

    printf("\n--- Memory and modules ---\n");
    block = VirtualAlloc(NULL, 0x3000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    check(block != NULL, "VirtualAlloc");
    check(VirtualProtect(block + 0x1000, 0x1000, PAGE_READONLY, &old) && old != 0,
          "VirtualProtect returns the old protection");
    check(VirtualProtect(block + 0x1000, 0x1000, PAGE_READWRITE, &old) &&
          old == PAGE_READONLY, "VirtualProtect remembers the protection");
    VirtualProtect(block + 0x1000, 0x1000, PAGE_EXECUTE_READ, &old);
    check(VirtualQuery(block + 0x1234, &mbi, sizeof(mbi)) == sizeof(mbi) &&
          mbi.BaseAddress == block + 0x1000 && mbi.AllocationBase == block &&
          mbi.State == MEM_COMMIT && mbi.Protect == PAGE_EXECUTE_READ &&
          mbi.RegionSize == 0x1000, "VirtualQuery of a VirtualAlloc block");
    check(!VirtualProtect(block, 0x1000, PAGE_READWRITE, NULL),
          "VirtualProtect needs lpflOldProtect");
    VirtualFree(block, 0, MEM_RELEASE);

    check(VirtualQuery(&static_data, &mbi, sizeof(mbi)) == sizeof(mbi) &&
          mbi.AllocationBase == (PVOID)exe && mbi.Type == MEM_IMAGE,
          "VirtualQuery of the EXE image");
    check(VirtualQuery(NULL, &mbi, sizeof(mbi)) == sizeof(mbi) && mbi.State == MEM_FREE,
          "VirtualQuery of the NULL page (MEM_FREE)");

    check(GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                             GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                             (LPCWSTR)&static_data, &module) && module == exe,
          "GetModuleHandleExW from an address");
    check(GetModuleHandleExW(0, L"kernel32.dll", &module) && module != NULL,
          "GetModuleHandleExW by name");
    check(!GetModuleHandleExA(0, "no_such_module.dll", &module) && module == NULL &&
          GetLastError() == ERROR_MOD_NOT_FOUND, "GetModuleHandleExA of a missing module");
    check(RtlPcToFileHeader(&static_data, &base) == exe && base == exe, "RtlPcToFileHeader");

    memset(&context, 0, sizeof(context));
    RtlCaptureContext(&context);
    check((context.ContextFlags & CONTEXT_CONTROL) == CONTEXT_CONTROL &&
          context.Esp > (DWORD)(INT_PTR)&context - 0x10000 &&
          context.Esp <= (DWORD)(INT_PTR)&context + 0x10000 && context.Eip != 0,
          "RtlCaptureContext");
}

/* ---- Locales, date and time formats ---- */

static int locale_enum_count = 0;

static BOOL CALLBACK locale_enum(LPWSTR name, DWORD flags, LPARAM param)
{
    if (param == 77 && wcscmp(name, L"en-US") == 0)
        locale_enum_count++;
    return TRUE;
}

static void test_locales(void)
{
    WCHAR text[128], upper[16];
    char ansi[64];
    DWORD number = 0;
    int length;
    SYSTEMTIME st;

    printf("\n--- Locales, date and time formats ---\n");
    check(GetLocaleInfoW(LOCALE_USER_DEFAULT, LOCALE_SDECIMAL, text, 128) == 2 &&
          wcscmp(text, L".") == 0, "GetLocaleInfoW(LOCALE_SDECIMAL)");
    check(GetLocaleInfoA(LOCALE_USER_DEFAULT, LOCALE_SMONTHNAME3, ansi, 64) &&
          strcmp(ansi, "March") == 0, "GetLocaleInfoA(LOCALE_SMONTHNAME3)");
    length = GetLocaleInfoEx(L"en-US", LOCALE_SNAME, NULL, 0);
    check(length == 6 && GetLocaleInfoEx(L"en-US", LOCALE_SNAME, text, length) == 6 &&
          wcscmp(text, L"en-US") == 0, "GetLocaleInfoEx size query and LOCALE_SNAME");
    check(GetLocaleInfoEx(NULL, LOCALE_IDEFAULTANSICODEPAGE | LOCALE_RETURN_NUMBER,
                          (LPWSTR)&number, sizeof(number) / sizeof(WCHAR)) == 2 &&
          number == GetACP(), "GetLocaleInfoEx(LOCALE_RETURN_NUMBER) code page = GetACP");
    check(GetLocaleInfoW(LOCALE_USER_DEFAULT, 0xFFFF, text, 128) == 0 &&
          GetLastError() == ERROR_INVALID_FLAGS, "GetLocaleInfoW of an unknown LCTYPE");
    check(GetUserDefaultLocaleName(text, 128) == 6 && wcscmp(text, L"en-US") == 0,
          "GetUserDefaultLocaleName");
    check(LocaleNameToLCID(L"en-US", 0) == 0x0409 && LocaleNameToLCID(L"xx-YY", 0) == 0,
          "LocaleNameToLCID");
    check(LCIDToLocaleName(0x0409, text, 128, 0) == 6 && wcscmp(text, L"en-US") == 0,
          "LCIDToLocaleName");
    check(IsValidLocaleName(L"en-US") && IsValidLocale(0x0409, LCID_INSTALLED),
          "IsValidLocaleName/IsValidLocale");
    check(EnumSystemLocalesEx(locale_enum, LOCALE_WINDOWS, 77, NULL) &&
          locale_enum_count == 1, "EnumSystemLocalesEx");
    check(IsValidCodePage(1252) && IsValidCodePage(65001) && !IsValidCodePage(0),
          "IsValidCodePage");

    check(CompareStringW(LOCALE_USER_DEFAULT, NORM_IGNORECASE, L"Hello", -1,
                         L"hELLO", -1) == CSTR_EQUAL, "CompareStringW(NORM_IGNORECASE)");
    check(CompareStringEx(L"en-US", 0, L"apple", -1, L"Banana", -1, NULL, NULL, 0) ==
          CSTR_LESS_THAN, "CompareStringEx (linguistic order)");
    check(CompareStringOrdinal(L"apple", -1, L"Banana", -1, FALSE) == CSTR_GREATER_THAN &&
          CompareStringOrdinal(L"ABC", 3, L"abc", 3, TRUE) == CSTR_EQUAL,
          "CompareStringOrdinal");
    length = LCMapStringEx(L"en-US", LCMAP_UPPERCASE, L"mixed", -1, upper, 16,
                           NULL, NULL, 0);
    check(length == 6 && wcscmp(upper, L"MIXED") == 0, "LCMapStringEx(LCMAP_UPPERCASE)");

    memset(&st, 0, sizeof(st));
    st.wYear = 2024;
    st.wMonth = 3;
    st.wDay = 5;
    st.wHour = 14;
    st.wMinute = 7;
    st.wSecond = 9;
    check(GetDateFormatW(LOCALE_USER_DEFAULT, DATE_SHORTDATE, &st, NULL, text, 128) &&
          wcscmp(text, L"3/5/2024") == 0, "GetDateFormatW(DATE_SHORTDATE)");
    check(GetDateFormatEx(L"en-US", DATE_LONGDATE, &st, NULL, text, 128, NULL) &&
          wcscmp(text, L"Tuesday, March 5, 2024") == 0, "GetDateFormatEx(DATE_LONGDATE)");
    check(GetDateFormatA(LOCALE_USER_DEFAULT, 0, &st, "yyyy'-'MM'-'dd ddd", ansi, 64) &&
          strcmp(ansi, "2024-03-05 Tue") == 0, "GetDateFormatA with a picture");
    check(GetTimeFormatW(LOCALE_USER_DEFAULT, 0, &st, NULL, text, 128) &&
          wcscmp(text, L"2:07:09 PM") == 0, "GetTimeFormatW");
    check(GetTimeFormatEx(L"en-US", TIME_NOSECONDS | TIME_NOTIMEMARKER |
                          TIME_FORCE24HOURFORMAT, &st, NULL, text, 128) &&
          wcscmp(text, L"14:07") == 0, "GetTimeFormatEx (24 hours, no seconds)");
    check(GetDateFormatW(LOCALE_USER_DEFAULT, 0, &st, L"d MMMM", text, 3) == 0 &&
          GetLastError() == ERROR_INSUFFICIENT_BUFFER, "GetDateFormatW small buffer");
}

/* ---- Time zone, files, console, random ---- */

static void test_misc(void)
{
    TIME_ZONE_INFORMATION tzi;
    DWORD result;
    WCHAR path[MAX_PATH];
    LPWSTR part = NULL;
    WIN32_FIND_DATAW find;
    HANDLE handle, out;
    BYTE random[16] = {0};
    BOOLEAN (WINAPI *gen_random)(PVOID, ULONG);
    int i, nonzero = 0;

    printf("\n--- Time zone, files, console, random ---\n");
    result = GetTimeZoneInformation(&tzi);
    check(result != TIME_ZONE_ID_INVALID && tzi.Bias >= -14 * 60 && tzi.Bias <= 12 * 60,
          "GetTimeZoneInformation");
    check((result == TIME_ZONE_ID_UNKNOWN) == (tzi.DaylightDate.wMonth == 0),
          "GetTimeZoneInformation daylight saving rule");

    SetCurrentDirectoryW(L"C:\\Windows");
    check(GetFullPathNameW(L"Temp\\file.txt", MAX_PATH, path, &part) &&
          wcscmp(path, L"C:\\Windows\\Temp\\file.txt") == 0 && part &&
          wcscmp(part, L"file.txt") == 0, "GetFullPathNameW");
    check(GetFullPathNameW(L"x.txt", 3, path, NULL) == 17,  /* C:\Windows\x.txt + NUL */
          "GetFullPathNameW returns the needed size");

    handle = FindFirstFileExW(L"C:\\Windows\\*", FindExInfoBasic, &find,
                              FindExSearchNameMatch, NULL, 0);
    check(handle != INVALID_HANDLE_VALUE, "FindFirstFileExW");
    if (handle != INVALID_HANDLE_VALUE)
        FindClose(handle);

    out = GetStdHandle(STD_OUTPUT_HANDLE);
    check(SetStdHandle(STD_ERROR_HANDLE, out) && GetStdHandle(STD_ERROR_HANDLE) == out,
          "SetStdHandle/GetStdHandle");
    check(GetConsoleOutputCP() == GetACP() && GetConsoleCP() == GetACP(),
          "GetConsoleOutputCP/GetConsoleCP");
    OutputDebugStringA("vista_api_test debug string\n");

    gen_random = (BOOLEAN (WINAPI *)(PVOID, ULONG))(void (*)(void))
        GetProcAddress(LoadLibraryA("advapi32.dll"), "SystemFunction036");
    check(gen_random != NULL && gen_random(random, sizeof(random)), "RtlGenRandom");
    for (i = 0; i < 16; i++)
        nonzero += random[i] != 0;
    check(nonzero > 4, "RtlGenRandom fills the buffer");
    check(GetProcAddress(GetModuleHandleA("kernel32.dll"), "InitializeSListHead") != NULL,
          "GetProcAddress of a Vista+ API");
}

/* ---- vcruntime140.dll ---- */

typedef struct {
    const char *what;
    char do_free;
} std_exception_data;

typedef struct {
    const char *undecorated;
    char decorated[32];
} type_info_data;

static void test_vcruntime(void)
{
    HMODULE vcrt = LoadLibraryA("vcruntime140.dll");
    FARPROC func;
    DWORD result = 0;
    char buffer[16];
    char message[] = "owned message";
    std_exception_data source = {message, 1}, copy = {NULL, 0}, borrowed = {NULL, 0};
    type_info_data foo = {NULL, ".?AVFoo@bar@@"}, foo2 = {NULL, ".?AVFoo@bar@@"};
    type_info_data other = {NULL, ".?AUOther@@"}, basic = {NULL, ".H"};
    CRITICAL_SECTION section;

    printf("\n--- vcruntime140.dll ---\n");
    check(vcrt != NULL, "LoadLibraryA(vcruntime140.dll)");
    if (!vcrt)
        return;

    func = GetProcAddress(vcrt, "memset");
    memset(buffer, 0, sizeof(buffer));
    check(func && call_cdecl3(func, (DWORD)buffer, 'x', 4, &result) &&
          result == (DWORD)buffer && memcmp(buffer, "xxxx\0", 5) == 0,
          "memset is cdecl");
    func = GetProcAddress(vcrt, "strchr");
    check(func && call_cdecl3(func, (DWORD)"abcdef", 'd', 0, &result) &&
          strcmp((const char *)result, "def") == 0, "strchr is cdecl");

    func = GetProcAddress(vcrt, "__std_exception_copy");
    check(func && call_cdecl3(func, (DWORD)&source, (DWORD)&copy, 0, NULL) &&
          copy.do_free == 1 && copy.what != message && strcmp(copy.what, message) == 0,
          "__std_exception_copy duplicates an owned message");
    source.do_free = 0;
    check(func && call_cdecl3(func, (DWORD)&source, (DWORD)&borrowed, 0, NULL) &&
          borrowed.do_free == 0 && borrowed.what == message,
          "__std_exception_copy shares a literal message");
    func = GetProcAddress(vcrt, "__std_exception_destroy");
    check(func && call_cdecl3(func, (DWORD)&copy, 0, 0, NULL) && copy.what == NULL,
          "__std_exception_destroy");

    func = GetProcAddress(vcrt, "__std_type_info_compare");
    check(func && call_cdecl3(func, (DWORD)&foo, (DWORD)&foo2, 0, &result) && result == 0,
          "__std_type_info_compare of equal types");
    check(func && call_cdecl3(func, (DWORD)&foo, (DWORD)&other, 0, &result) && result != 0,
          "__std_type_info_compare of different types");
    func = GetProcAddress(vcrt, "__std_type_info_name");
    check(func && call_cdecl3(func, (DWORD)&foo, 0, 0, &result) &&
          strcmp((const char *)result, "class bar::Foo") == 0 &&
          foo.undecorated == (const char *)result, "__std_type_info_name of a class");
    check(func && call_cdecl3(func, (DWORD)&basic, 0, 0, &result) &&
          strcmp((const char *)result, "int") == 0, "__std_type_info_name of int");

    func = GetProcAddress(vcrt, "__vcrt_InitializeCriticalSectionEx");
    check(func && call_stdcall3(func, (DWORD)&section, 0, 0, &result) && result,
          "__vcrt_InitializeCriticalSectionEx is stdcall");
    if (func && result) {
        EnterCriticalSection(&section);
        LeaveCriticalSection(&section);
        DeleteCriticalSection(&section);
    }
    check(GetProcAddress(vcrt, "__current_exception") != NULL,
          "GetProcAddress(__current_exception)");
}

int main(void)
{
    printf("=== Vista+ API test ===\n");
    test_runtime_basics();
    test_synchronization();
    test_memory_and_modules();
    test_locales();
    test_misc();
    test_vcruntime();
    printf("\n== %d failure(s) ==\n", failures);
    return failures;
}
