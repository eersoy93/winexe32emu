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
Controls demo - shows the emulator's interactive control messages:
LISTBOX (LB_ADDSTRING, LB_DELETESTRING, LB_GETCURSEL, LB_GETTEXT and
LBN_SELCHANGE), COMBOBOX (CB_ADDSTRING, CB_SETCURSEL, CBN_SELCHANGE),
an auto checkbox read with IsDlgButtonChecked, and EDIT + buttons
wired together through WM_COMMAND.
*/

#include <windows.h>

static const char* CLASS_NAME = "ControlsDemoClass";

#define IDC_ITEM_EDIT   101
#define IDC_ADD_BUTTON  102
#define IDC_DEL_BUTTON  103
#define IDC_ITEM_LIST   104
#define IDC_COLOR_COMBO 105
#define IDC_UPPER_CHECK 106
#define IDC_STATUS      107

/* Update the status line; uppercase it when the checkbox is ticked */
static void SetStatus(HWND hwnd, const char* text)
{
    char buffer[192];
    int i;

    lstrcpyA(buffer, text);

    if (IsDlgButtonChecked(hwnd, IDC_UPPER_CHECK))
    {
        for (i = 0; buffer[i] != '\0'; i++)
        {
            if (buffer[i] >= 'a' && buffer[i] <= 'z')
            {
                buffer[i] = (char)(buffer[i] - 'a' + 'A');
            }
        }
    }

    SetDlgItemTextA(hwnd, IDC_STATUS, buffer);
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
        case WM_CREATE:
        {
            HINSTANCE hInstance = ((LPCREATESTRUCT)lParam)->hInstance;
            HWND list, combo;

            CreateWindowExA(0, "STATIC", "New item:",
                            WS_CHILD | WS_VISIBLE,
                            20, 12, 90, 20,
                            hwnd, NULL, hInstance, NULL);

            CreateWindowExA(0, "EDIT", "",
                            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT,
                            20, 34, 170, 24,
                            hwnd, (HMENU)IDC_ITEM_EDIT, hInstance, NULL);

            CreateWindowExA(0, "BUTTON", "Add",
                            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                            200, 34, 70, 24,
                            hwnd, (HMENU)IDC_ADD_BUTTON, hInstance, NULL);

            CreateWindowExA(0, "BUTTON", "Remove",
                            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                            278, 34, 80, 24,
                            hwnd, (HMENU)IDC_DEL_BUTTON, hInstance, NULL);

            list = CreateWindowExA(0, "LISTBOX", "",
                                   WS_CHILD | WS_VISIBLE | WS_BORDER | LBS_NOTIFY,
                                   20, 72, 170, 150,
                                   hwnd, (HMENU)IDC_ITEM_LIST, hInstance, NULL);

            combo = CreateWindowExA(0, "COMBOBOX", "",
                                    WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST,
                                    200, 72, 158, 150,
                                    hwnd, (HMENU)IDC_COLOR_COMBO, hInstance, NULL);

            CreateWindowExA(0, "BUTTON", "UPPERCASE status",
                            WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                            200, 110, 158, 20,
                            hwnd, (HMENU)IDC_UPPER_CHECK, hInstance, NULL);

            CreateWindowExA(0, "STATIC", "Ready.",
                            WS_CHILD | WS_VISIBLE,
                            20, 240, 350, 20,
                            hwnd, (HMENU)IDC_STATUS, hInstance, NULL);

            /* Preload some list items */
            SendMessageA(list, LB_ADDSTRING, 0, (LPARAM)"Apple");
            SendMessageA(list, LB_ADDSTRING, 0, (LPARAM)"Banana");
            SendMessageA(list, LB_ADDSTRING, 0, (LPARAM)"Cherry");

            /* Preload combobox colors and select the first one */
            SendMessageA(combo, CB_ADDSTRING, 0, (LPARAM)"Red");
            SendMessageA(combo, CB_ADDSTRING, 0, (LPARAM)"Green");
            SendMessageA(combo, CB_ADDSTRING, 0, (LPARAM)"Blue");
            SendMessageA(combo, CB_SETCURSEL, 0, 0);
            return 0;
        }

        case WM_COMMAND:
        {
            WORD id = LOWORD(wParam);
            WORD code = HIWORD(wParam);
            HWND list = GetDlgItem(hwnd, IDC_ITEM_LIST);
            HWND combo = GetDlgItem(hwnd, IDC_COLOR_COMBO);
            char item[128];
            char status[192];

            if (id == IDC_ADD_BUTTON)
            {
                GetDlgItemTextA(hwnd, IDC_ITEM_EDIT, item, sizeof(item));
                if (item[0] == '\0')
                {
                    SetStatus(hwnd, "Type an item name first!");
                }
                else
                {
                    SendMessageA(list, LB_ADDSTRING, 0, (LPARAM)item);
                    SetDlgItemTextA(hwnd, IDC_ITEM_EDIT, "");
                    wsprintfA(status, "Added: %s (%d items)",
                              item, (int)SendMessageA(list, LB_GETCOUNT, 0, 0));
                    SetStatus(hwnd, status);
                }
            }
            else if (id == IDC_DEL_BUTTON)
            {
                int sel = (int)SendMessageA(list, LB_GETCURSEL, 0, 0);
                if (sel == LB_ERR)
                {
                    SetStatus(hwnd, "Select a list item first!");
                }
                else
                {
                    SendMessageA(list, LB_GETTEXT, sel, (LPARAM)item);
                    SendMessageA(list, LB_DELETESTRING, sel, 0);
                    wsprintfA(status, "Removed: %s (%d items left)",
                              item, (int)SendMessageA(list, LB_GETCOUNT, 0, 0));
                    SetStatus(hwnd, status);
                }
            }
            else if (id == IDC_ITEM_LIST && code == LBN_SELCHANGE)
            {
                int sel = (int)SendMessageA(list, LB_GETCURSEL, 0, 0);
                if (sel != LB_ERR)
                {
                    SendMessageA(list, LB_GETTEXT, sel, (LPARAM)item);
                    wsprintfA(status, "List selection: %s (index %d)", item, sel);
                    SetStatus(hwnd, status);
                }
            }
            else if (id == IDC_COLOR_COMBO && code == CBN_SELCHANGE)
            {
                int sel = (int)SendMessageA(combo, CB_GETCURSEL, 0, 0);
                if (sel != CB_ERR)
                {
                    SendMessageA(combo, CB_GETLBTEXT, sel, (LPARAM)item);
                    wsprintfA(status, "Color: %s", item);
                    SetStatus(hwnd, status);
                }
            }
            else if (id == IDC_UPPER_CHECK)
            {
                if (IsDlgButtonChecked(hwnd, IDC_UPPER_CHECK))
                {
                    SetStatus(hwnd, "Uppercase mode is ON");
                }
                else
                {
                    SetStatus(hwnd, "Uppercase mode is off");
                }
            }
            return 0;
        }

        case WM_KEYDOWN:
            if (wParam == VK_ESCAPE)
            {
                PostQuitMessage(0);
            }
            return 0;

        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;

        case WM_CLOSE:
            DestroyWindow(hwnd);
            return 0;
    }

    return DefWindowProcA(hwnd, uMsg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow)
{
    WNDCLASSA wc = {0};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);

    if (!RegisterClassA(&wc))
    {
        MessageBoxA(NULL, "Window class not registered!", "Error", MB_ICONERROR);
        return 1;
    }

    HWND hwnd = CreateWindowExA(
        0, CLASS_NAME, "Controls Demo",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        400, 330,
        NULL, NULL, hInstance, NULL);

    if (hwnd == NULL)
    {
        MessageBoxA(NULL, "Window could not be created!", "Error", MB_ICONERROR);
        return 1;
    }

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg = {0};
    while (GetMessageA(&msg, NULL, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }

    return (int)msg.wParam;
}
