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
Argv test - the C runtime splits the command line into argc/argv
(__getmainargs, __argc/__argv) by the Microsoft rules for quotes and
backslashes. run_tests.sh starts it with these arguments:
    plain "two words" a\b "q\"uote" "" end
Every check prints PASS or FAIL; the exit code is the failure count.
*/

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

static void check(int ok, const char *name)
{
    printf("%s: %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok)
        failures++;
}

int main(int argc, char **argv)
{
    static const char *expected[] = {"plain", "two words", "a\\b", "q\"uote", "", "end"};
    static const char program[] = "\\argv_test.exe";
    int i, ok = 1;
    size_t length;

    printf("=== Argv test ===\n");
    printf("Command line: %s\n", GetCommandLineA());
    for (i = 0; i < argc; i++)
        printf("  argv[%d] = [%s]\n", i, argv[i]);

    length = strlen(argv[0]);
    check(argv[0][1] == ':' && length >= sizeof(program) - 1 &&
          _stricmp(argv[0] + length - (sizeof(program) - 1), program) == 0,
          "argv[0] is the program path");
    check(argc == 7, "argc counts the arguments");
    for (i = 0; i < 6 && i + 1 < argc; i++)
        ok &= strcmp(argv[i + 1], expected[i]) == 0;
    check(argc == 7 && ok, "quotes and backslashes");
    check(argv[argc] == NULL, "argv[argc] is NULL");
    /* MinGW's start-up code gives main a copy of __argv */
    ok = __argc == argc;
    for (i = 0; ok && i < argc; i++)
        ok = strcmp(__argv[i], argv[i]) == 0;
    check(ok, "__argc/__argv match main's arguments");
    printf("\n== %d failure(s) ==\n", failures);
    return failures;
}
