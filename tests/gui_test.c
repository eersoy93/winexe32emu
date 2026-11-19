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
of the message loop (WM_DESTROY, PostQuitMessage). Every check prints PASS
or FAIL; the exit code is the failure count.
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
