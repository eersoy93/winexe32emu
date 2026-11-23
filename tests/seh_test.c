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
SEH test - structured exception handling like Windows does it: access
violations, illegal instructions and RaiseException reach the program's
handlers; __finally blocks run during the unwind (also of the frames of
other handlers, which get EXCEPTION_UNWINDING); a handler can continue the
faulting code with a changed CONTEXT; vectored handlers and the
SetUnhandledExceptionFilter filter are called.

GCC has no __try, so the frames are built like MSVC builds them:
  seh3_try - _except_handler3 (msvcrt.dll), scope table in the clear
  seh4_try - _except_handler4 (Visual C++ 2005+): the scope table is XORed
             with the security cookie and the outermost level is -2
Both have two levels: __try { __try { fault } __finally { ... } }
__except (filter: record the exception, EXCEPTION_EXECUTE_HANDLER).

With the argument "av" it reads address 0 without a handler (run_tests.sh
checks that the process is terminated). Every check prints PASS or FAIL;
the exit code is the failure count.
*/

#include <windows.h>
#include <excpt.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;

static void check(int ok, const char *name)
{
    printf("%s: %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok)
        failures++;
}

/* Written by the filters and the __finally blocks */
volatile DWORD seh_code, seh_info0, seh_info1, seh_finally_ran;
/* RaiseException arguments of fault kind 3 */
DWORD raise_args[2] = {0x11, 0x22};
/* Security cookie of the SEH4 frame (the scope table is XORed with it) */
DWORD seh4_cookie = 0xBB40E64E;
/* Calls of the search_handler frame (kind 4): handling / unwinding */
volatile int search_calls, search_unwind_calls;

EXCEPTION_DISPOSITION __cdecl search_handler(EXCEPTION_RECORD *record, void *frame,
                                              CONTEXT *context, void *dispatcher)
{
    if (record->ExceptionFlags & (EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND))
        search_unwind_calls++;
    else
        search_calls++;
    return ExceptionContinueSearch;
}

/* The common part of an exception, run with a frame as its handler */
int __cdecl seh4_common_dummy(void)
{
    return ExceptionContinueSearch;  /* only if the emulator called the stub */
}

DWORD seh3_try(int kind);
DWORD seh4_try(int kind);
DWORD custom_continue(void);
DWORD unwind_try(int kind);
/* The frame of unwind_try (its except block restores them) */
DWORD unwind_frame_esp, unwind_frame_ebp;

/*
do_fault(kind): 0 = read of address 0, 1 = write of address 0,
2 = illegal instruction (UD2), 3 = RaiseException(0xE0001234, 0, 2, raise_args),
4 = a frame of search_handler, then UD2 (its frame is unwound)
*/
__asm__(
    ".intel_syntax noprefix\n"
    ".text\n"
    "_do_fault:\n"
    "    mov eax, dword ptr [esp+4]\n"
    "    cmp eax, 0\n"
    "    je _fault_read\n"
    "    cmp eax, 1\n"
    "    je _fault_write\n"
    "    cmp eax, 2\n"
    "    je _fault_ud2\n"
    "    cmp eax, 3\n"
    "    je _fault_raise\n"
    "    push offset _search_handler\n"
    "    push dword ptr fs:[0]\n"
    "    mov dword ptr fs:[0], esp\n"
    "    ud2\n"
    "_fault_read:\n"
    "    mov eax, dword ptr ds:[0]\n"
    "    ret\n"
    "_fault_write:\n"
    "    mov dword ptr ds:[0], 1\n"
    "    ret\n"
    "_fault_ud2:\n"
    "    ud2\n"
    "    ret\n"
    "_fault_raise:\n"
    "    push offset _raise_args\n"
    "    push 2\n"
    "    push 0\n"
    "    push 0xE0001234\n"
    "    call dword ptr [__imp__RaiseException@16]\n"
    "    ret\n"

    /* Filter (both frames): record the exception, EXCEPTION_EXECUTE_HANDLER */
    "_seh_filter:\n"
    "    mov eax, dword ptr [ebp-0x14]\n"
    "    mov eax, dword ptr [eax]\n"       /* ExceptionRecord */
    "    mov ecx, dword ptr [eax]\n"
    "    mov dword ptr [_seh_code], ecx\n"
    "    mov ecx, dword ptr [eax+0x14]\n"  /* ExceptionInformation[0] */
    "    mov dword ptr [_seh_info0], ecx\n"
    "    mov ecx, dword ptr [eax+0x18]\n"
    "    mov dword ptr [_seh_info1], ecx\n"
    "    mov eax, 1\n"
    "    ret\n"
    "_seh_finally:\n"
    "    mov dword ptr [_seh_finally_ran], 1\n"
    "    ret\n"
    /* __except block: ESP is the saved ESP */
    "_seh_handler:\n"
    "    mov eax, dword ptr [_seh_code]\n"
    "    jmp _seh_leave\n"

    /* DWORD seh3_try(int kind) */
    ".globl _seh3_try\n"
    "_seh3_try:\n"
    "    push ebp\n"
    "    mov ebp, esp\n"
    "    push -1\n"
    "    push offset _seh3_table\n"
    "    push dword ptr [__imp___except_handler3]\n"
    "    push dword ptr fs:[0]\n"
    "    mov dword ptr fs:[0], esp\n"
    "    sub esp, 8\n"
    "    push ebx\n"
    "    push esi\n"
    "    push edi\n"
    "    mov dword ptr [ebp-0x18], esp\n"
    "    mov dword ptr [ebp-4], 1\n"       /* inside both __try blocks */
    "    push dword ptr [ebp+8]\n"
    "    call _do_fault\n"
    "    add esp, 4\n"
    "    xor eax, eax\n"
    "    jmp _seh_leave\n"

    /* DWORD seh4_try(int kind) */
    ".globl _seh4_try\n"
    "_seh4_try:\n"
    "    push ebp\n"
    "    mov ebp, esp\n"
    "    push -2\n"
    "    mov eax, offset _seh4_table\n"
    "    xor eax, dword ptr [_seh4_cookie]\n"
    "    push eax\n"
    "    push offset _seh4_stub\n"
    "    push dword ptr fs:[0]\n"
    "    mov dword ptr fs:[0], esp\n"
    "    sub esp, 8\n"
    "    push ebx\n"
    "    push esi\n"
    "    push edi\n"
    "    mov dword ptr [ebp-0x18], esp\n"
    "    mov dword ptr [ebp-4], 1\n"
    "    push dword ptr [ebp+8]\n"
    "    call _do_fault\n"
    "    add esp, 4\n"
    "    xor eax, eax\n"

    /* Both frames: unregister and return EAX */
    "_seh_leave:\n"
    "    mov ecx, dword ptr [ebp-0x10]\n"
    "    mov dword ptr fs:[0], ecx\n"
    "    pop edi\n"
    "    pop esi\n"
    "    pop ebx\n"
    "    mov esp, ebp\n"
    "    pop ebp\n"
    "    ret\n"

    /* The _except_handler4 stub of the Visual C++ runtime */
    "_seh4_stub:\n"
    "    push ebp\n"
    "    mov ebp, esp\n"
    "    push dword ptr [ebp+0x14]\n"
    "    push dword ptr [ebp+0x10]\n"
    "    push dword ptr [ebp+0x0C]\n"
    "    push dword ptr [ebp+0x08]\n"
    "    push offset _seh4_common_dummy\n"
    "    push offset _seh4_cookie\n"
    "    call _seh4_common_dummy\n"
    "    add esp, 0x18\n"
    "    pop ebp\n"
    "    ret\n"

    /* DWORD custom_continue(void): a handler continues after the fault with
       EAX = 0x1234 and EBX = 0x5678 (set in the CONTEXT) */
    ".globl _custom_continue\n"
    ".globl _continue_resume\n"
    "_custom_continue:\n"
    "    push ebx\n"
    "    push offset _continue_handler\n"
    "    push dword ptr fs:[0]\n"
    "    mov dword ptr fs:[0], esp\n"
    "    xor ebx, ebx\n"
    "    mov eax, dword ptr ds:[0]\n"
    "_continue_resume:\n"
    "    mov ecx, dword ptr [esp]\n"
    "    mov dword ptr fs:[0], ecx\n"
    "    add esp, 8\n"
    "    add eax, ebx\n"
    "    pop ebx\n"
    "    ret\n"

    /*
    DWORD unwind_try(int kind): a frame whose handler works like Delphi's
    (_HandleAnyException): it calls RtlUnwind and then jumps to the except
    block of its frame without returning
    */
    ".globl _unwind_try\n"
    "_unwind_try:\n"
    "    push ebp\n"
    "    mov ebp, esp\n"
    "    push ebx\n"
    "    push esi\n"
    "    push edi\n"
    "    push offset _unwind_handler\n"
    "    push dword ptr fs:[0]\n"
    "    mov dword ptr fs:[0], esp\n"
    "    mov dword ptr [_unwind_frame_esp], esp\n"
    "    mov dword ptr [_unwind_frame_ebp], ebp\n"
    "    push dword ptr [ebp+8]\n"
    "    call _do_fault\n"
    "    add esp, 4\n"
    "    xor eax, eax\n"                     /* no exception */
    "    jmp _unwind_leave\n"
    "_unwind_except:\n"
    "    call dword ptr [__imp__GetTickCount@0]\n"  /* an API call in the except block */
    "    mov eax, dword ptr [_seh_code]\n"
    "_unwind_leave:\n"
    "    pop dword ptr fs:[0]\n"
    "    add esp, 4\n"
    "    pop edi\n"
    "    pop esi\n"
    "    pop ebx\n"
    "    pop ebp\n"
    "    ret\n"
    /* EXCEPTION_DISPOSITION unwind_handler(record, frame, context, dispatcher) */
    "_unwind_handler:\n"
    "    mov eax, dword ptr [esp+4]\n"
    "    test dword ptr [eax+4], 6\n"       /* EXCEPTION_UNWINDING, EXCEPTION_EXIT_UNWIND */
    "    jnz _unwind_handler_search\n"
    "    mov ecx, dword ptr [eax]\n"
    "    mov dword ptr [_seh_code], ecx\n"
    "    mov ecx, dword ptr [esp+8]\n"
    "    push 0\n"                           /* ReturnValue */
    "    push eax\n"                         /* ExceptionRecord */
    "    push offset _unwind_except\n"      /* TargetIp */
    "    push ecx\n"                         /* TargetFrame */
    "    call dword ptr [__imp__RtlUnwind@16]\n"
    "    mov esp, dword ptr [_unwind_frame_esp]\n"
    "    mov ebp, dword ptr [_unwind_frame_ebp]\n"
    "    jmp _unwind_except\n"
    "_unwind_handler_search:\n"
    "    mov eax, 1\n"                       /* ExceptionContinueSearch */
    "    ret\n"

    ".data\n"
    "_seh3_table:\n"
    "    .long -1, _seh_filter, _seh_handler\n"  /* level 0: __except */
    "    .long 0, 0, _seh_finally\n"              /* level 1: __finally */
    "_seh4_table:\n"
    "    .long -2, 0, -2, 0\n"                    /* GS and EH cookie offsets */
    "    .long -2, _seh_filter, _seh_handler\n"
    "    .long 0, 0, _seh_finally\n"
    ".text\n"
    ".att_syntax prefix\n");

extern char continue_resume[];

EXCEPTION_DISPOSITION __cdecl continue_handler(EXCEPTION_RECORD *record, void *frame,
                                                CONTEXT *context, void *dispatcher)
{
    if (record->ExceptionFlags & (EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND) ||
            record->ExceptionCode != EXCEPTION_ACCESS_VIOLATION)
        return ExceptionContinueSearch;
    context->Eip = (DWORD)continue_resume;
    context->Eax = 0x1234;
    context->Ebx = 0x5678;
    return ExceptionContinueExecution;
}

static DWORD seh_head(void)
{
    DWORD head;
    __asm__ volatile("movl %%fs:0, %0" : "=r"(head));
    return head;
}

static void test_frame(DWORD (*try_func)(int), const char *frame_name)
{
    char name[128];
    DWORD head = seh_head();

    seh_finally_ran = 0;
    seh_code = 0;
    sprintf(name, "%s: read of NULL -> access violation, __finally ran", frame_name);
    check(try_func(0) == EXCEPTION_ACCESS_VIOLATION && seh_info0 == 0 && seh_info1 == 0 &&
          seh_finally_ran, name);
    seh_finally_ran = 0;
    sprintf(name, "%s: write of NULL (ExceptionInformation[0] = 1)", frame_name);
    check(try_func(1) == EXCEPTION_ACCESS_VIOLATION && seh_info0 == 1 && seh_info1 == 0 &&
          seh_finally_ran, name);
    sprintf(name, "%s: UD2 -> EXCEPTION_ILLEGAL_INSTRUCTION", frame_name);
    check(try_func(2) == EXCEPTION_ILLEGAL_INSTRUCTION, name);
    sprintf(name, "%s: RaiseException with parameters", frame_name);
    check(try_func(3) == 0xE0001234 && seh_info0 == 0x11 && seh_info1 == 0x22, name);
    search_calls = search_unwind_calls = 0;
    seh_finally_ran = 0;
    sprintf(name, "%s: an inner frame's handler searches, then unwinds", frame_name);
    check(try_func(4) == EXCEPTION_ILLEGAL_INSTRUCTION && search_calls == 1 &&
          search_unwind_calls == 1 && seh_finally_ran, name);
    sprintf(name, "%s: the SEH chain is restored", frame_name);
    check(seh_head() == head, name);
}

static volatile int veh_calls = 0, filter_calls = 0;

static LONG CALLBACK breakpoint_veh(EXCEPTION_POINTERS *pointers)
{
    if (pointers->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT)
        return EXCEPTION_CONTINUE_SEARCH;
    veh_calls++;
    pointers->ContextRecord->Eip++;  /* skip the INT 3 */
    return EXCEPTION_CONTINUE_EXECUTION;
}

static LONG WINAPI top_level_filter(EXCEPTION_POINTERS *pointers)
{
    if (pointers->ExceptionRecord->ExceptionCode != 0xE0000001)
        return EXCEPTION_CONTINUE_SEARCH;
    filter_calls++;
    return EXCEPTION_CONTINUE_EXECUTION;
}

int main(int argc, char **argv)
{
    PVOID veh;
    LPTOP_LEVEL_EXCEPTION_FILTER previous;

    if (argc > 1 && strcmp(argv[1], "av") == 0) {
        printf("Reading address 0 without a handler...\n");
        fflush(stdout);
        printf("FAIL: read %lu\n", (unsigned long)*(volatile DWORD *)0);
        return 1;
    }

    printf("=== SEH test ===\n");
    test_frame(seh3_try, "_except_handler3");
    test_frame(seh4_try, "_except_handler4");

    check(custom_continue() == 0x1234 + 0x5678,
          "ExceptionContinueExecution continues with the changed CONTEXT");

    {
        /* More exceptions than the emulator's nesting limit (8): each
           handler continues in its frame without returning */
        DWORD head = seh_head();
        int i, ok = 1;
        for (i = 0; i < 20; i++) {
            int kind = i % 2 ? 3 : 0;
            DWORD expected = kind == 3 ? 0xE0001234 : EXCEPTION_ACCESS_VIOLATION;
            seh_code = 0;
            if (unwind_try(kind) != expected)
                ok = 0;
        }
        check(ok && seh_head() == head,
              "20 exceptions taken by handlers that unwind and do not return");
    }

    veh = AddVectoredExceptionHandler(1, breakpoint_veh);
    __asm__ volatile("int3");
    check(veh != NULL && veh_calls == 1, "a vectored handler continues after INT 3");
    check(RemoveVectoredExceptionHandler(veh), "RemoveVectoredExceptionHandler");

    previous = SetUnhandledExceptionFilter(top_level_filter);
    RaiseException(0xE0000001, 0, 0, NULL);
    check(filter_calls == 1, "the SetUnhandledExceptionFilter filter continues");
    check(SetUnhandledExceptionFilter(previous) == top_level_filter,
          "SetUnhandledExceptionFilter returns the previous filter");

    printf("\n== %d failure(s) ==\n", failures);
    return failures;
}
