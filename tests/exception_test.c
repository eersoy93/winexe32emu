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
Exception test - CPU exceptions and software interrupts (INT 3, division by
zero, INT 0x2E, INT 0x21) must reach the program's structured exception
handlers like on Windows. GCC has no __try/__except, so seh_try() builds the
same SEH frame MSVC does for _except_handler3 (msvcrt.dll). Every check
prints PASS or FAIL; the exit code is the failure count.

With an argument it ends the process instead (run_tests.sh checks this):
  fastfail - __fastfail(7) (INT 0x29): terminated, no handler runs
  int3     - INT 3 outside of any __try: an unhandled exception
*/

#include <windows.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;

static void check(int ok, const char *name)
{
    printf("%s: %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok)
        failures++;
}

/*
DWORD seh_try(int kind): runs one faulting instruction inside
    __try { ... } __except (record code, EXCEPTION_EXECUTE_HANDLER) { ... }
and returns the exception code (0 if nothing was raised).
kind: 0 = INT 3, 1 = DIV by zero, 2 = INT 0x2E, 3 = INT 0x21, else none.

Frame layout of _except_handler3 (EBP-relative):
  -0x18 saved ESP, -0x14 EXCEPTION_POINTERS*, -0x10 next record,
  -0x0C handler, -0x08 scope table, -0x04 try level
*/
DWORD seh_try(int kind);
volatile DWORD seh_filter_code = 0;
volatile DWORD seh_saved_ebx = 0;

__asm__(
    ".intel_syntax noprefix\n"
    ".text\n"
    ".globl _seh_try\n"
    "_seh_try:\n"
    "    push ebp\n"
    "    mov ebp, esp\n"
    "    push -1\n"
    "    push offset _seh_scope_table\n"
    "    push dword ptr [__imp___except_handler3]\n"
    "    push dword ptr fs:[0]\n"
    "    mov dword ptr fs:[0], esp\n"
    "    sub esp, 8\n"
    "    push ebx\n"
    "    push esi\n"
    "    push edi\n"
    "    mov dword ptr [ebp-0x18], esp\n"
    "    mov ebx, 0x5EB5EB\n"              /* must survive the exception */
    "    mov dword ptr [ebp-4], 0\n"       /* enter __try */
    "    mov eax, dword ptr [ebp+8]\n"
    "    cmp eax, 0\n"
    "    je _seh_int3\n"
    "    cmp eax, 1\n"
    "    je _seh_div\n"
    "    cmp eax, 2\n"
    "    je _seh_int2e\n"
    "    cmp eax, 3\n"
    "    je _seh_int21\n"
    "    xor eax, eax\n"
    "    jmp _seh_done\n"
    "_seh_int3:\n"
    "    int3\n"
    "    xor eax, eax\n"
    "    jmp _seh_done\n"
    "_seh_div:\n"
    "    xor ecx, ecx\n"
    "    mov eax, 1\n"
    "    xor edx, edx\n"
    "    div ecx\n"
    "    xor eax, eax\n"
    "    jmp _seh_done\n"
    "_seh_int2e:\n"
    "    mov eax, 0x1234\n"
    "    int 0x2e\n"
    "    xor eax, eax\n"
    "    jmp _seh_done\n"
    "_seh_int21:\n"
    "    mov ah, 0x4c\n"
    "    int 0x21\n"
    "    xor eax, eax\n"
    "    jmp _seh_done\n"
    /* Filter: runs on the frame (EBP) of seh_try */
    "_seh_filter:\n"
    "    mov eax, dword ptr [ebp-0x14]\n"
    "    mov eax, dword ptr [eax]\n"       /* ExceptionRecord */
    "    mov eax, dword ptr [eax]\n"       /* ExceptionCode */
    "    mov dword ptr [_seh_filter_code], eax\n"
    "    mov eax, 1\n"                     /* EXCEPTION_EXECUTE_HANDLER */
    "    ret\n"
    /* __except block: ESP is the saved ESP */
    "_seh_handler:\n"
    "    mov dword ptr [_seh_saved_ebx], ebx\n"
    "    mov eax, dword ptr [_seh_filter_code]\n"
    "_seh_done:\n"
    "    mov dword ptr [ebp-4], -1\n"
    "    mov ecx, dword ptr [ebp-0x10]\n"
    "    mov dword ptr fs:[0], ecx\n"
    "    pop edi\n"
    "    pop esi\n"
    "    pop ebx\n"
    "    mov esp, ebp\n"
    "    pop ebp\n"
    "    ret\n"
    ".data\n"
    "_seh_scope_table:\n"
    "    .long -1, _seh_filter, _seh_handler\n"
    ".text\n"
    ".att_syntax prefix\n");

static void test_handled(int kind, DWORD expected, const char *name)
{
    DWORD code;
    seh_filter_code = 0;
    seh_saved_ebx = 0;
    code = seh_try(kind);
    printf("  %s: code 0x%08lx\n", name, (unsigned long)code);
    check(code == expected, name);
    check(seh_saved_ebx == 0x5EB5EB, "registers are kept in the __except block");
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "fastfail") == 0) {
        printf("Calling __fastfail(7)...\n");
        fflush(stdout);
        __asm__ volatile("movl $7, %%ecx\n\tint $0x29" ::: "ecx");
        printf("FAIL: __fastfail returned\n");
        return 1;
    }
    if (argc > 1 && strcmp(argv[1], "int3") == 0) {
        printf("Executing INT 3 without a handler...\n");
        fflush(stdout);
        __asm__ volatile("int3");
        printf("FAIL: INT 3 was ignored\n");
        return 1;
    }

    printf("=== Exception test ===\n");
    check(seh_try(99) == 0, "seh_try without an exception");
    test_handled(0, EXCEPTION_BREAKPOINT, "INT 3 -> EXCEPTION_BREAKPOINT");
    test_handled(1, EXCEPTION_INT_DIVIDE_BY_ZERO, "DIV by zero -> EXCEPTION_INT_DIVIDE_BY_ZERO");
    test_handled(2, EXCEPTION_ACCESS_VIOLATION, "INT 0x2E -> EXCEPTION_ACCESS_VIOLATION");
    test_handled(3, EXCEPTION_ACCESS_VIOLATION, "INT 0x21 -> EXCEPTION_ACCESS_VIOLATION");
    check(seh_try(1) == EXCEPTION_INT_DIVIDE_BY_ZERO, "a second exception in the same frame");
    printf("\n== %d failure(s) ==\n", failures);
    return failures;
}
