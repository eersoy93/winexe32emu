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
C runtime example - exercises the emulator's msvcrt support:
formatted I/O, strings, wide strings, number conversion, math,
time, environment, file system, signals and setjmp/longjmp.
Every check prints PASS or FAIL; the exit code is the failure count.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <wctype.h>
#include <math.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <setjmp.h>
#include <stdarg.h>
#include <io.h>
#include <direct.h>

static int failures = 0;

static void check(int ok, const char *name)
{
    printf("%s: %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok)
        failures++;
}

static int near(double a, double b)
{
    return fabs(a - b) < 1e-9;
}

static int format_v(char *buf, size_t size, const char *fmt, ...)
{
    va_list ap;
    int n;
    va_start(ap, fmt);
    n = _vsnprintf(buf, size, fmt, ap);
    va_end(ap);
    return n;
}

static volatile int signal_seen = 0;

static void on_signal(int sig)
{
    signal_seen = sig;
}

static jmp_buf jump_target;

static void jump_back(int value)
{
    longjmp(jump_target, value);
}

static void test_formatting(void)
{
    char buf[64];
    wchar_t wbuf[64];
    int n;

    n = _snprintf(buf, sizeof(buf), "%d-%s-%.2f", 42, "abc", 3.14159);
    check(n == 11 && strcmp(buf, "42-abc-3.14") == 0, "_snprintf");
    n = _snprintf(buf, 4, "%s", "truncated");
    check(n == -1 && memcmp(buf, "trun", 4) == 0, "_snprintf truncation");
    check(format_v(buf, sizeof(buf), "%5d|%-3s|%x", 7, "a", 255) == 12 &&
          strcmp(buf, "    7|a  |ff") == 0,
          "_vsnprintf");
    check(_scprintf("%d%d", 10, 20) == 4, "_scprintf");
    swprintf(wbuf, 64, L"%ls=%d", L"wide", 5);
    check(wcscmp(wbuf, L"wide=5") == 0, "swprintf");
    fprintf(stdout, "fprintf to stdout: %s %lld\n", "ok", 1234567890123LL);
    fprintf(stderr, "fprintf to stderr works\n");
    wprintf(L"wprintf: %ls %lc\n", L"wide text", L'W');
}

static void test_scanning(void)
{
    int a = 0, b = 0, consumed = 0;
    unsigned int hex = 0;
    double d = 0;
    char word[16] = "", rest[16] = "";
    wchar_t wword[16] = L"";

    int n = sscanf("12 0x1F 2.5 hello world!", "%d %x %lf %15s %[a-z]%n",
                   &a, &hex, &d, word, rest, &consumed);
    check(n == 5 && a == 12 && hex == 31 && near(d, 2.5) &&
          strcmp(word, "hello") == 0 && strcmp(rest, "world") == 0 &&
          consumed == 23, "sscanf");
    check(sscanf("", "%d", &a) == EOF, "sscanf EOF");
    check(sscanf("7:8", "%d:%d", &a, &b) == 2 && a == 7 && b == 8, "sscanf literals");
    check(swscanf(L"99 wide", L"%d %ls", &a, wword) == 2 && a == 99 &&
          wcscmp(wword, L"wide") == 0, "swscanf");
}

static void test_strings(void)
{
    char buf[64] = "alpha,beta;;gamma";
    char *tok;
    int count = 0;
    wchar_t wbuf[32];

    for (tok = strtok(buf, ",;"); tok; tok = strtok(NULL, ",;"))
        count++;
    check(count == 3, "strtok");
    check(strcmp(strerror(ENOENT), "No such file or directory") == 0, "strerror");
    check(_stricmp("HeLLo", "hello") == 0 && _strcmpi("a", "B") < 0, "_stricmp/_strcmpi");
    check(strnlen("abcdef", 3) == 3, "strnlen");
    /* _TRUNCATE avoids the invalid parameter handler that terminates on real msvcrt */
    check(strncpy_s(buf, 4, "toolong", _TRUNCATE) == STRUNCATE && strcmp(buf, "too") == 0,
          "strncpy_s truncation");

    wcscpy(wbuf, L"Hello");
    wcscat(wbuf, L" World");
    check(wcscmp(wbuf, L"Hello World") == 0 && wcslen(wbuf) == 11, "wcscpy/wcscat");
    check(wcschr(wbuf, L'W') == wbuf + 6 && wcsrchr(wbuf, L'o') == wbuf + 7, "wcschr/wcsrchr");
    check(wcsstr(wbuf, L"World") == wbuf + 6, "wcsstr");
    check(_wcsicmp(L"ABC", L"abc") == 0 && wcsncmp(L"abcd", L"abcx", 3) == 0, "_wcsicmp/wcsncmp");
    check(towupper(L'q') == L'Q' && iswdigit(L'7') && !iswalpha(L'7'), "towupper/iswdigit");
    check(mbstowcs(wbuf, "conv", 32) == 4 && wcscmp(wbuf, L"conv") == 0, "mbstowcs");
    check(wcstombs(buf, L"back", sizeof(buf)) == 4 && strcmp(buf, "back") == 0, "wcstombs");
}

static void test_numbers(void)
{
    char buf[32];
    char *end;
    div_t q = div(-7, 2);
    ldiv_t lq = ldiv(17, 5);

    check(near(atof("3.5e2"), 350.0), "atof");
    check(near(strtod("  -1.25xyz", &end), -1.25) && strcmp(end, "xyz") == 0, "strtod");
    check(_atoi64("-9000000000") == -9000000000LL, "_atoi64");
    check(_strtoui64("ffffffffffffffff", NULL, 16) == 0xFFFFFFFFFFFFFFFFULL, "_strtoui64");
    check(wcstol(L"0x10", NULL, 0) == 16, "wcstol");
    check(strcmp(_i64toa(-1234567890123LL, buf, 10), "-1234567890123") == 0, "_i64toa");
    check(q.quot == -3 && q.rem == -1 && lq.quot == 3 && lq.rem == 2, "div/ldiv");
    check(_abs64(-5000000000LL) == 5000000000LL, "_abs64");
    check(_rotl(0x80000001u, 1) == 3, "_rotl");
}

static void test_math(void)
{
    double ip;
    int e;
    volatile double x = 2.0;

    check(near(sqrt(x * 8), 4.0), "sqrt");
    check(near(sin(0.0), 0.0) && near(cos(0.0), 1.0), "sin/cos");
    check(near(pow(x, 10), 1024.0), "pow");
    check(near(floor(-2.5), -3.0) && near(ceil(2.1), 3.0), "floor/ceil");
    check(near(atan2(1.0, 1.0) * 4, 3.14159265358979), "atan2");
    check(near(fmod(7.5, 2.0), 1.5), "fmod");
    check(near(log(exp(x)), 2.0) && near(log10(1000.0), 3.0), "log/exp/log10");
    check(near(modf(3.75, &ip), 0.75) && near(ip, 3.0), "modf");
    check(near(frexp(8.0, &e), 0.5) && e == 4 && near(ldexp(0.5, 4), 8.0), "frexp/ldexp");
    errno = 0;
    check(isnan(sqrt(-x)) && errno == EDOM, "sqrt domain error");
    check((int)(x * 3.7) == 7, "double to int");
}

static void test_time(void)
{
    struct tm t = {0};
    char buf[64];
    time_t stamp;

    t.tm_year = 100;  /* 2000 */
    t.tm_mon = 0;
    t.tm_mday = 32;   /* normalizes to February 1 */
    t.tm_hour = 12;
    t.tm_isdst = -1;
    stamp = mktime(&t);
    check(stamp != (time_t)-1 && t.tm_mon == 1 && t.tm_mday == 1, "mktime normalization");
    check(strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M %A", &t) > 0 &&
          strcmp(buf, "2000-02-01 12:00 Tuesday") == 0, "strftime");
    check(strcmp(asctime(&t), "Tue Feb 01 12:00:00 2000\n") == 0, "asctime");
    check(localtime(&stamp) != NULL && localtime(&stamp)->tm_year == 100, "localtime");
    check(gmtime(&stamp) != NULL, "gmtime");
    check(near(difftime(stamp + 60, stamp), 60.0), "difftime");
    check(time(NULL) > 1600000000, "time");
}

static void test_environment_and_files(void)
{
    FILE *fp;
    int value = 0;
    char word[16] = "";
    char cwd[_MAX_PATH];

    check(getenv("WINDIR") != NULL && strcmp(getenv("WINDIR"), "C:\\Windows") == 0, "getenv");
    check(_putenv("CRT_EXAMPLE=yes") == 0 && strcmp(getenv("CRT_EXAMPLE"), "yes") == 0, "_putenv");
    check(getenv("NO_SUCH_VARIABLE") == NULL, "getenv missing");
    check(_getcwd(cwd, sizeof(cwd)) != NULL &&
          strcmp(cwd, "C:\\Windows\\Examples\\crt_example") == 0, "_getcwd (EXE folder)");

    fp = fopen("crt_example.txt", "w");
    if (fp)
    {
        fprintf(fp, "%d %s\n", 2026, "scan");
        fclose(fp);
    }
    fp = fopen("crt_example.txt", "r");
    check(fp != NULL && fscanf(fp, "%d %15s", &value, word) == 2 &&
          value == 2026 && strcmp(word, "scan") == 0, "fprintf/fscanf");
    if (fp)
        fclose(fp);

    remove("crt_example_renamed.txt");
    check(rename("crt_example.txt", "crt_example_renamed.txt") == 0, "rename");
    check(_access("crt_example_renamed.txt", 0) == 0, "_access");
    check(remove("crt_example_renamed.txt") == 0 && _access("crt_example_renamed.txt", 0) == -1, "remove");
    errno = 0;
    check(fopen("missing_file.txt", "r") == NULL && errno == ENOENT, "fopen errno");
}

static void test_control_flow(void)
{
    volatile int stage = 0;
    volatile int result = 0;

    signal(SIGINT, on_signal);
    raise(SIGINT);
    check(signal_seen == SIGINT, "signal/raise");

    /* setjmp may only appear in a controlling expression like this one */
    switch (setjmp(jump_target))
    {
        case 0:
            stage = 1;
            jump_back(5);
            stage = 99;  /* never reached */
            break;
        case 5:
            result = 5;
            break;
        default:
            result = -1;
            break;
    }
    check(result == 5 && stage == 1, "setjmp/longjmp");
}

int main(void)
{
    puts("== CRT example ==");
    test_formatting();
    test_scanning();
    test_strings();
    test_numbers();
    test_math();
    test_time();
    test_environment_and_files();
    test_control_flow();
    printf("== %d failure(s) ==\n", failures);
    return failures;
}
