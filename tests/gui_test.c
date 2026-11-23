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
GUI test - a window and its messages on the fake desktop: WM_CREATE with
the creation parameter, sent and posted messages, child controls (an edit
control's text, a button's WM_COMMAND), window data, a timer, and the end
of the message loop (WM_DESTROY, PostQuitMessage); WH_CBT hooks and a
subclassed dialog, ShowWindow and the priority of WM_PAINT. Every check
prints PASS or FAIL; the exit code is the failure count.
*/

#include <windows.h>
#include <stdio.h>
#include <string.h>

#define ID_BUTTON 101
#define ID_EDIT 102
#define WM_APP_SUM (WM_USER + 1)
#define WM_APP_POSTED (WM_USER + 2)

static int failures = 0;
static int create_seen, posted_seen, command_seen, timer_seen, destroy_seen;
static int window_alive_in_destroy;
static LPARAM create_param;
static HWND button, edit;

static void check(int ok, const char *name)
{
    printf("%s: %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok)
        failures++;
}

static LRESULT CALLBACK window_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_CREATE:
        create_seen++;
        create_param = (LPARAM)((CREATESTRUCTA *)lParam)->lpCreateParams;
        button = CreateWindowExA(0, "BUTTON", "Push", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                 10, 10, 80, 24, hwnd, (HMENU)ID_BUTTON, NULL, NULL);
        edit = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD | WS_VISIBLE,
                               10, 40, 160, 22, hwnd, (HMENU)ID_EDIT, NULL, NULL);
        return 0;
    case WM_APP_SUM:
        return (LRESULT)(wParam + lParam);
    case WM_APP_POSTED:
        posted_seen++;
        return 0;
    case WM_COMMAND:
        if (LOWORD(wParam) == ID_BUTTON && HIWORD(wParam) == BN_CLICKED &&
            (HWND)lParam == button)
            command_seen++;
        return 0;
    case WM_TIMER:
        if (wParam == 1) {
            timer_seen++;
            KillTimer(hwnd, 1);
            /* Like the close button: DefWindowProc's WM_CLOSE destroys it */
            PostMessageA(hwnd, WM_CLOSE, 0, 0);
        }
        return 0;
    case WM_DESTROY:
        destroy_seen++;
        window_alive_in_destroy = IsWindow(hwnd) && IsWindow(edit);
        PostQuitMessage(7);
        return 0;
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

/* ---------- WH_CBT hooks (MFC attaches its window objects in one) ---------- */

static HHOOK first_hook, second_hook;
static int first_hook_calls, second_hook_calls, destroy_hook_seen;
static LPVOID hooked_create_param;
static HWND hooked_window, hooked_dialog;
static WNDPROC hooked_old_proc, dialog_old_proc;
static int subclass_nccreate, subclass_saw_before_class, class_proc_nccreate;
static int dialog_subclass_init, dialog_proc_init, dialog_proc_app, dialog_click_seen;

static LRESULT CALLBACK hooked_class_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == WM_NCCREATE)
        class_proc_nccreate++;
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

static LRESULT CALLBACK hooked_subclass(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == WM_NCCREATE) {
        subclass_nccreate++;
        subclass_saw_before_class = class_proc_nccreate == 0;
    }
    return CallWindowProcA(hooked_old_proc, hwnd, msg, wParam, lParam);
}

static LRESULT CALLBACK dialog_subclass(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == WM_INITDIALOG)
        dialog_subclass_init++;
    return CallWindowProcA(dialog_old_proc, hwnd, msg, wParam, lParam);
}

static INT_PTR CALLBACK hooked_dialog_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == WM_INITDIALOG) {
        dialog_proc_init++;
        return TRUE;
    }
    if (msg == WM_APP_SUM) {
        dialog_proc_app++;
        return TRUE;
    }
    if (msg == WM_COMMAND && LOWORD(wParam) == 5 && HIWORD(wParam) == BN_CLICKED)
        dialog_click_seen++;
    return FALSE;
}

/* Installed first: called second. Subclasses the windows it is told about. */
static LRESULT CALLBACK first_cbt(int code, WPARAM wParam, LPARAM lParam)
{
    first_hook_calls++;
    if (code == HCBT_CREATEWND) {
        CREATESTRUCTA *cs = ((CBT_CREATEWNDA *)lParam)->lpcs;
        if (cs->lpszClass == (LPCSTR)MAKEINTATOM(0x8002)) {  /* A dialog (#32770) */
            hooked_dialog = (HWND)wParam;
            dialog_old_proc = (WNDPROC)SetWindowLongPtrA((HWND)wParam, GWLP_WNDPROC,
                                                         (LONG_PTR)dialog_subclass);
        } else if (HIWORD(cs->lpszClass) && !strcmp(cs->lpszClass, "HookedWindow")) {
            hooked_window = (HWND)wParam;
            hooked_create_param = cs->lpCreateParams;
            hooked_old_proc = (WNDPROC)SetWindowLongPtrA((HWND)wParam, GWLP_WNDPROC,
                                                         (LONG_PTR)hooked_subclass);
        } else if (HIWORD(cs->lpszClass) && !strcmp(cs->lpszClass, "RefusedWindow")) {
            return 1;  /* The window is not created */
        }
    } else if (code == HCBT_DESTROYWND && (HWND)wParam == hooked_window) {
        destroy_hook_seen = IsWindow((HWND)wParam);
    }
    return CallNextHookEx(first_hook, code, wParam, lParam);
}

static LRESULT CALLBACK second_cbt(int code, WPARAM wParam, LPARAM lParam)
{
    second_hook_calls++;
    return CallNextHookEx(second_hook, code, wParam, lParam);
}

static void test_hooks(void)
{
    WNDCLASSA wc;
    HWND hwnd, dialog;
    /* DLGTEMPLATE: no menu, no class, no title, no controls */
    static WORD dialog_template[16] __attribute__((aligned(4)));
    DLGTEMPLATE *dt = (DLGTEMPLATE *)dialog_template;

    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc = hooked_class_proc;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.lpszClassName = "HookedWindow";
    RegisterClassA(&wc);
    wc.lpszClassName = "RefusedWindow";
    RegisterClassA(&wc);

    first_hook = SetWindowsHookExA(WH_CBT, first_cbt, NULL, GetCurrentThreadId());
    second_hook = SetWindowsHookExA(WH_CBT, second_cbt, NULL, GetCurrentThreadId());
    check(first_hook && second_hook, "SetWindowsHookEx(WH_CBT)");

    hwnd = CreateWindowExA(0, "HookedWindow", "Hooked", WS_OVERLAPPEDWINDOW, 0, 0, 100, 100,
                           NULL, NULL, wc.hInstance, (LPVOID)0x99);
    check(hwnd && hooked_window == hwnd && hooked_create_param == (LPVOID)0x99,
          "HCBT_CREATEWND: the new window and its CREATESTRUCT");
    check(second_hook_calls >= 1 && first_hook_calls == second_hook_calls,
          "The newest hook is called first; CallNextHookEx calls the next one");
    check(hooked_old_proc == hooked_class_proc && subclass_nccreate == 1 &&
          subclass_saw_before_class && class_proc_nccreate == 1,
          "A window subclassed in the hook gets WM_NCCREATE through its new procedure");
    check(CreateWindowExA(0, "RefusedWindow", "", WS_OVERLAPPEDWINDOW, 0, 0, 10, 10,
                          NULL, NULL, wc.hInstance, NULL) == NULL,
          "A hook that returns nonzero refuses the window");
    DestroyWindow(hwnd);
    check(destroy_hook_seen, "HCBT_DESTROYWND while the window still exists");

    memset(dialog_template, 0, sizeof(dialog_template));
    dt->style = WS_POPUP | WS_CAPTION;
    dt->cx = 100;
    dt->cy = 50;
    dialog = CreateDialogIndirectParamA(wc.hInstance, dt, NULL, hooked_dialog_proc, 0);
    check(dialog && hooked_dialog == dialog && dialog_old_proc != NULL,
          "HCBT_CREATEWND for a dialog; its GWLP_WNDPROC is DefDlgProc");
    check(dialog_subclass_init == 1 && dialog_proc_init == 1,
          "A subclassed dialog: WM_INITDIALOG goes through the subclass to the dialog procedure");
    SendMessageA(dialog, WM_APP_SUM, 1, 2);
    check(dialog_proc_app == 1, "SendMessage to a subclassed dialog reaches its dialog procedure");
    {
        /* A message posted to a dialog's control goes to the control */
        MSG msg;
        int i;
        HWND button = CreateWindowExA(0, "BUTTON", "OK", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                      5, 5, 40, 20, dialog, (HMENU)5, NULL, NULL);
        PostMessageA(button, BM_CLICK, 0, 0);
        for (i = 0; i < 20 && !dialog_click_seen; i++) {
            if (PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE))
                DispatchMessageA(&msg);
        }
        check(dialog_click_seen == 1,
              "BM_CLICK posted to a dialog's button: BN_CLICKED to the dialog procedure");
    }
    DestroyWindow(dialog);

    check(UnhookWindowsHookEx(second_hook) && UnhookWindowsHookEx(first_hook),
          "UnhookWindowsHookEx");
}

/* ---------- ShowWindow, and WM_PAINT after the posted messages ---------- */

static int paint_count, paint_posted_seen;

static LRESULT CALLBACK paint_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    PAINTSTRUCT ps;
    if (msg == WM_PAINT) {
        paint_count++;
        BeginPaint(hwnd, &ps);
        EndPaint(hwnd, &ps);
        InvalidateRect(hwnd, NULL, FALSE);  /* Paints again and again (an animation) */
        return 0;
    }
    if (msg == WM_APP_POSTED) {
        paint_posted_seen++;
        return 0;
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

static void test_show_and_paint(HWND main_window)
{
    WNDCLASSA wc;
    HWND hwnd;
    MSG msg;
    int i;

    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc = paint_proc;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.lpszClassName = "PaintTestWindow";
    RegisterClassA(&wc);
    hwnd = CreateWindowExA(0, "PaintTestWindow", "Paint", WS_OVERLAPPEDWINDOW, 20, 20, 100, 80,
                           NULL, NULL, wc.hInstance, NULL);

    check(ShowWindow(hwnd, SW_SHOWNOACTIVATE) == 0 && IsWindowVisible(hwnd) &&
          GetActiveWindow() != hwnd,
          "ShowWindow(SW_SHOWNOACTIVATE) shows without activating, returns 0 (was hidden)");
    check(ShowWindow(hwnd, SW_SHOWMINIMIZED) != 0 && IsWindowVisible(hwnd) && IsIconic(hwnd),
          "ShowWindow(SW_SHOWMINIMIZED) minimizes, returns nonzero (was visible)");
    ShowWindow(hwnd, SW_RESTORE);
    check(!IsIconic(hwnd) && IsWindowVisible(hwnd), "ShowWindow(SW_RESTORE)");

    PostMessageA(hwnd, WM_APP_POSTED, 0, 0);
    for (i = 0; i < 20 && !paint_posted_seen; i++) {
        if (PeekMessageA(&msg, hwnd, 0, 0, PM_REMOVE))
            DispatchMessageA(&msg);
    }
    check(paint_posted_seen == 1, "A window that always repaints still gets posted messages");
    DestroyWindow(hwnd);
    SetActiveWindow(main_window);
}

int main(void)
{
    WNDCLASSA wc;
    HWND hwnd;
    MSG msg;
    RECT client;
    char text[64];
    int loops = 0;
    BOOL result;

    printf("=== GUI test ===\n");
    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc = window_proc;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.lpszClassName = "GuiTestWindow";
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.hCursor = LoadCursorA(NULL, (LPCSTR)IDC_ARROW);
    check(RegisterClassA(&wc) != 0, "RegisterClass");

    hwnd = CreateWindowExA(0, "GuiTestWindow", "GUI test", WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                           50, 50, 300, 200, NULL, NULL, wc.hInstance, (LPVOID)0x1234);
    check(hwnd != NULL, "CreateWindowEx");
    check(create_seen == 1 && create_param == 0x1234, "WM_CREATE with the creation parameter");
    check(button && edit && GetParent(button) == hwnd && GetDlgItem(hwnd, ID_EDIT) == edit,
          "Child controls");
    check(GetClientRect(hwnd, &client) && client.right > 0 && client.bottom > 0,
          "GetClientRect");
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    check(SendMessageA(hwnd, WM_APP_SUM, 5, 6) == 11, "SendMessage returns the result");
    SetWindowTextA(edit, "Hello, edit");
    check(GetWindowTextA(edit, text, sizeof(text)) == 11 && strcmp(text, "Hello, edit") == 0,
          "Set/GetWindowText of an edit control");
    check(SendMessageA(edit, WM_GETTEXTLENGTH, 0, 0) == 11, "WM_GETTEXTLENGTH");
    SendMessageA(button, BM_CLICK, 0, 0);
    check(command_seen == 1, "BM_CLICK: WM_COMMAND/BN_CLICKED to the parent");

    SetWindowLongPtrA(hwnd, GWLP_USERDATA, 0x5678);
    check(GetWindowLongPtrA(hwnd, GWLP_USERDATA) == 0x5678, "GWLP_USERDATA");
    check(GetWindowTextA(hwnd, text, sizeof(text)) && strcmp(text, "GUI test") == 0,
          "The window's title");

    check(PostMessageA(hwnd, WM_APP_POSTED, 0, 0), "PostMessage");
    check(posted_seen == 0, "A posted message waits for the message loop");
    check(SetTimer(hwnd, 1, 10, NULL) == 1, "SetTimer");

    test_hooks();
    test_show_and_paint(hwnd);

    while ((result = GetMessageA(&msg, NULL, 0, 0)) > 0 && loops < 100000) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
        loops++;
    }
    check(result == 0 && msg.message == WM_QUIT && msg.wParam == 7,
          "GetMessage returns 0 for WM_QUIT (PostQuitMessage's code)");
    check(posted_seen == 1, "The posted message is dispatched");
    check(window_alive_in_destroy, "The window and its controls exist during WM_DESTROY");
    check(timer_seen == 1, "WM_TIMER");
    check(destroy_seen == 1 && !IsWindow(hwnd) && !IsWindow(edit),
          "WM_CLOSE -> DestroyWindow: WM_DESTROY, the window and its controls are gone");

    printf("\n== %d failure(s) ==\n", failures);
    return failures;
}
