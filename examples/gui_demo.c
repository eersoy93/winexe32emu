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
GUI demo - a single, sectioned tour of the emulator's window & control APIs:

  - Menu bar with dropdowns and a separator (CreateMenu / CreatePopupMenu /
    AppendMenuA / SetMenu / DrawMenuBar) plus WM_COMMAND from menu items.
  - STATIC / EDIT / BUTTON controls wired through WM_COMMAND, MessageBoxA.
  - A calculator that reads and writes EDIT boxes as integers
    (GetDlgItemInt / SetDlgItemInt).
  - A "sort the numbers" box driven by the msvcrt C runtime helpers
    strtol / qsort together with the ctype predicates isdigit / isspace.
  - LISTBOX (LB_ADDSTRING / LB_DELETESTRING / LB_GETCURSEL / LB_GETTEXT and
    LBN_SELCHANGE), COMBOBOX (CB_ADDSTRING / CB_SETCURSEL / CBN_SELCHANGE)
    and an auto checkbox read with IsDlgButtonChecked.
  - A status bar with a live clock (SetTimer / WM_TIMER / GetLocalTime).
  - WM_PAINT paints coloured section headers so the form reads as a layout.

Press ESC to quit.
*/

#include <windows.h>
#include <stdlib.h>
#include <ctype.h>

static const char* CLASS_NAME = "GUIDemoClass";

/* ---- Control identifiers (grouped by section) ---- */
#define IDC_NAME_EDIT   101
#define IDC_HELLO_BTN   102

#define IDC_A_EDIT      111
#define IDC_B_EDIT      112
#define IDC_ADD_BTN     113
#define IDC_SUB_BTN     114
#define IDC_MUL_BTN     115
#define IDC_DIV_BTN     116
#define IDC_RESULT      117

#define IDC_LIST_EDIT   121
#define IDC_SORT_BTN    122
#define IDC_SORTED      123

#define IDC_ITEM_EDIT   131
#define IDC_ITEM_ADD    132
#define IDC_ITEM_DEL    133
#define IDC_ITEM_LIST   134

#define IDC_COLOR_COMBO 141
#define IDC_UPPER_CHECK 142

#define IDC_STATUS      151
#define IDC_CLOCK       152

/* ---- Menu command identifiers ---- */
#define IDM_FILE_HELLO  201
#define IDM_FILE_EXIT   202
#define IDM_HELP_ABOUT  203

/* ---- Timer identifier ---- */
#define IDT_CLOCK 1

/* One colored section header drawn in WM_PAINT */
typedef struct { int x, y, w; const char* title; } Header;

static const Header g_headers[] =
{
    {  16,   8, 208, "Greeting"      },
    {  16, 116, 208, "Calculator"    },
    {  16, 224, 208, "Sort Numbers"  },
    { 240,   8, 208, "List Manager"  },
    { 240, 238, 208, "Options"       },
};
#define HEADER_COUNT (int)(sizeof(g_headers) / sizeof(g_headers[0]))

/* Update the status line; uppercase it when the checkbox is ticked. */
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

/* Greeting section: read the name box and greet with a message box. */
static void SayHello(HWND hwnd)
{
    char name[128];
    char message[192];

    GetDlgItemTextA(hwnd, IDC_NAME_EDIT, name, sizeof(name));

    if (name[0] == '\0')
    {
        lstrcpyA(message, "Please type your name first!");
    }
    else
    {
        lstrcpyA(message, "Hello, ");
        lstrcatA(message, name);
        lstrcatA(message, "!");
    }

    MessageBoxA(hwnd, message, "Greeting", MB_OK | MB_ICONINFORMATION);
    SetStatus(hwnd, "Said hello!");
}

/* Calculator section: read both boxes as integers, compute, write back. */
static void DoCompute(HWND hwnd, char op)
{
    BOOL okA = FALSE, okB = FALSE;
    int a = (int)GetDlgItemInt(hwnd, IDC_A_EDIT, &okA, TRUE);
    int b = (int)GetDlgItemInt(hwnd, IDC_B_EDIT, &okB, TRUE);
    char status[192];

    if (!okA || !okB)
    {
        SetStatus(hwnd, "Enter whole numbers in both A and B.");
        return;
    }

    switch (op)
    {
        case '+': SetDlgItemInt(hwnd, IDC_RESULT, a + b, TRUE); break;
        case '-': SetDlgItemInt(hwnd, IDC_RESULT, a - b, TRUE); break;
        case 'x': SetDlgItemInt(hwnd, IDC_RESULT, a * b, TRUE); break;
        case '/':
            if (b == 0)
            {
                SetDlgItemTextA(hwnd, IDC_RESULT, "inf");
                SetStatus(hwnd, "Division by zero!");
                return;
            }
            SetDlgItemInt(hwnd, IDC_RESULT, a / b, TRUE);
            break;
    }

    wsprintfA(status, "Computed %d %c %d", a, (op == 'x' ? '*' : op), b);
    SetStatus(hwnd, status);
}

/* Ascending integer comparison for qsort. */
static int cmp_int(const void* a, const void* b)
{
    int ia = *(const int*)a;
    int ib = *(const int*)b;
    return (ia > ib) - (ia < ib);
}

/* Sort section: parse a free-form list with strtol, sort it with qsort. */
static void DoSort(HWND hwnd)
{
    char raw[256];
    char out[256];
    int  numbers[64];
    int  count = 0;
    char* p;
    char status[192];

    GetDlgItemTextA(hwnd, IDC_LIST_EDIT, raw, sizeof(raw));

    /* Walk the string with strtol; its endptr tells us where each number
       ends, and we skip anything that cannot start a number in between. */
    p = raw;
    while (*p != '\0' && count < 64)
    {
        char* end;
        long value;

        while (*p != '\0' && !isdigit((unsigned char)*p) &&
               *p != '-' && *p != '+')
        {
            p++;
        }
        if (*p == '\0')
        {
            break;
        }

        value = strtol(p, &end, 10);
        if (end == p)
        {
            p++;  /* No digits consumed, avoid an infinite loop */
            continue;
        }
        numbers[count++] = (int)value;
        p = end;
    }

    if (count == 0)
    {
        SetDlgItemTextA(hwnd, IDC_SORTED, "");
        SetStatus(hwnd, "Type some numbers to sort, e.g. 5, 2, 9, 1");
        return;
    }

    qsort(numbers, count, sizeof(int), cmp_int);

    /* Build the sorted, comma-separated output string. */
    out[0] = '\0';
    {
        int i;
        char piece[16];
        for (i = 0; i < count; i++)
        {
            wsprintfA(piece, (i == 0 ? "%d" : ", %d"), numbers[i]);
            lstrcatA(out, piece);
        }
    }
    SetDlgItemTextA(hwnd, IDC_SORTED, out);

    wsprintfA(status, "Sorted %d numbers (min %d, max %d)",
              count, numbers[0], numbers[count - 1]);
    SetStatus(hwnd, status);
}

/* List manager: append the edit-box text to the listbox. */
static void AddItem(HWND hwnd)
{
    HWND list = GetDlgItem(hwnd, IDC_ITEM_LIST);
    char item[128];
    char status[192];

    GetDlgItemTextA(hwnd, IDC_ITEM_EDIT, item, sizeof(item));
    if (item[0] == '\0')
    {
        SetStatus(hwnd, "Type an item name first!");
        return;
    }

    SendMessageA(list, LB_ADDSTRING, 0, (LPARAM)item);
    SetDlgItemTextA(hwnd, IDC_ITEM_EDIT, "");
    wsprintfA(status, "Added: %s (%d items)",
              item, (int)SendMessageA(list, LB_GETCOUNT, 0, 0));
    SetStatus(hwnd, status);
}

/* List manager: remove the selected listbox item. */
static void RemoveItem(HWND hwnd)
{
    HWND list = GetDlgItem(hwnd, IDC_ITEM_LIST);
    char item[128];
    char status[192];
    int sel = (int)SendMessageA(list, LB_GETCURSEL, 0, 0);

    if (sel == LB_ERR)
    {
        SetStatus(hwnd, "Select a list item first!");
        return;
    }

    SendMessageA(list, LB_GETTEXT, sel, (LPARAM)item);
    SendMessageA(list, LB_DELETESTRING, sel, 0);
    wsprintfA(status, "Removed: %s (%d items left)",
              item, (int)SendMessageA(list, LB_GETCOUNT, 0, 0));
    SetStatus(hwnd, status);
}

/* Create every child control once, at WM_CREATE time. */
static void CreateControls(HWND hwnd, HINSTANCE hInstance)
{
    HWND list, combo;

    /* --- Greeting --- */
    CreateWindowExA(0, "STATIC", "Your name:",
                    WS_CHILD | WS_VISIBLE,
                    16, 32, 100, 18, hwnd, NULL, hInstance, NULL);
    CreateWindowExA(0, "EDIT", "",
                    WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT,
                    16, 52, 208, 22,
                    hwnd, (HMENU)IDC_NAME_EDIT, hInstance, NULL);
    CreateWindowExA(0, "BUTTON", "Say Hello",
                    WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                    16, 80, 110, 24,
                    hwnd, (HMENU)IDC_HELLO_BTN, hInstance, NULL);

    /* --- Calculator --- */
    CreateWindowExA(0, "STATIC", "A",
                    WS_CHILD | WS_VISIBLE, 16, 142, 12, 18,
                    hwnd, NULL, hInstance, NULL);
    CreateWindowExA(0, "EDIT", "12",
                    WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT,
                    32, 138, 62, 22,
                    hwnd, (HMENU)IDC_A_EDIT, hInstance, NULL);
    CreateWindowExA(0, "STATIC", "B",
                    WS_CHILD | WS_VISIBLE, 104, 142, 12, 18,
                    hwnd, NULL, hInstance, NULL);
    CreateWindowExA(0, "EDIT", "34",
                    WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT,
                    120, 138, 62, 22,
                    hwnd, (HMENU)IDC_B_EDIT, hInstance, NULL);

    CreateWindowExA(0, "BUTTON", "+",
                    WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                    16, 166, 46, 24, hwnd, (HMENU)IDC_ADD_BTN, hInstance, NULL);
    CreateWindowExA(0, "BUTTON", "-",
                    WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                    66, 166, 46, 24, hwnd, (HMENU)IDC_SUB_BTN, hInstance, NULL);
    CreateWindowExA(0, "BUTTON", "x",
                    WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                    116, 166, 46, 24, hwnd, (HMENU)IDC_MUL_BTN, hInstance, NULL);
    CreateWindowExA(0, "BUTTON", "/",
                    WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                    166, 166, 46, 24, hwnd, (HMENU)IDC_DIV_BTN, hInstance, NULL);

    CreateWindowExA(0, "STATIC", "=",
                    WS_CHILD | WS_VISIBLE, 16, 198, 12, 18,
                    hwnd, NULL, hInstance, NULL);
    CreateWindowExA(0, "EDIT", "",
                    WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT | ES_READONLY,
                    32, 194, 192, 22,
                    hwnd, (HMENU)IDC_RESULT, hInstance, NULL);

    /* --- Sort numbers --- */
    CreateWindowExA(0, "EDIT", "5, 2, 9, 1, 7, 3",
                    WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT,
                    16, 248, 140, 22,
                    hwnd, (HMENU)IDC_LIST_EDIT, hInstance, NULL);
    CreateWindowExA(0, "BUTTON", "Sort",
                    WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                    160, 248, 64, 22,
                    hwnd, (HMENU)IDC_SORT_BTN, hInstance, NULL);
    CreateWindowExA(0, "EDIT", "",
                    WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT | ES_READONLY,
                    16, 276, 208, 22,
                    hwnd, (HMENU)IDC_SORTED, hInstance, NULL);

    /* --- List manager --- */
    CreateWindowExA(0, "EDIT", "",
                    WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT,
                    240, 32, 208, 22,
                    hwnd, (HMENU)IDC_ITEM_EDIT, hInstance, NULL);
    CreateWindowExA(0, "BUTTON", "Add",
                    WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                    240, 60, 100, 24,
                    hwnd, (HMENU)IDC_ITEM_ADD, hInstance, NULL);
    CreateWindowExA(0, "BUTTON", "Remove",
                    WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                    348, 60, 100, 24,
                    hwnd, (HMENU)IDC_ITEM_DEL, hInstance, NULL);
    list = CreateWindowExA(0, "LISTBOX", "",
                    WS_CHILD | WS_VISIBLE | WS_BORDER | LBS_NOTIFY,
                    240, 90, 208, 138,
                    hwnd, (HMENU)IDC_ITEM_LIST, hInstance, NULL);

    /* --- Options --- */
    combo = CreateWindowExA(0, "COMBOBOX", "",
                    WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST,
                    240, 262, 150, 140,
                    hwnd, (HMENU)IDC_COLOR_COMBO, hInstance, NULL);
    CreateWindowExA(0, "BUTTON", "UPPERCASE status",
                    WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                    240, 292, 208, 20,
                    hwnd, (HMENU)IDC_UPPER_CHECK, hInstance, NULL);

    /* --- Status bar --- */
    CreateWindowExA(0, "STATIC", "Ready.",
                    WS_CHILD | WS_VISIBLE,
                    24, 322, 300, 18,
                    hwnd, (HMENU)IDC_STATUS, hInstance, NULL);
    CreateWindowExA(0, "STATIC", "--:--:--",
                    WS_CHILD | WS_VISIBLE,
                    360, 322, 88, 18,
                    hwnd, (HMENU)IDC_CLOCK, hInstance, NULL);

    /* Preload the list and the colour combo. */
    SendMessageA(list, LB_ADDSTRING, 0, (LPARAM)"Apple");
    SendMessageA(list, LB_ADDSTRING, 0, (LPARAM)"Banana");
    SendMessageA(list, LB_ADDSTRING, 0, (LPARAM)"Cherry");

    SendMessageA(combo, CB_ADDSTRING, 0, (LPARAM)"Red");
    SendMessageA(combo, CB_ADDSTRING, 0, (LPARAM)"Green");
    SendMessageA(combo, CB_ADDSTRING, 0, (LPARAM)"Blue");
    SendMessageA(combo, CB_SETCURSEL, 0, 0);
}

/* Build the menu bar. */
static void CreateMenuBar(HWND hwnd)
{
    HMENU hMenuBar  = CreateMenu();
    HMENU hFileMenu = CreatePopupMenu();
    HMENU hHelpMenu = CreatePopupMenu();

    AppendMenuA(hFileMenu, MF_STRING, IDM_FILE_HELLO, "Say Hello");
    AppendMenuA(hFileMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuA(hFileMenu, MF_STRING, IDM_FILE_EXIT, "Exit");
    AppendMenuA(hHelpMenu, MF_STRING, IDM_HELP_ABOUT, "About...");

    AppendMenuA(hMenuBar, MF_POPUP, (UINT_PTR)hFileMenu, "File");
    AppendMenuA(hMenuBar, MF_POPUP, (UINT_PTR)hHelpMenu, "Help");

    SetMenu(hwnd, hMenuBar);
    DrawMenuBar(hwnd);
}

/* Paint the colored section headers and the status-bar strip. */
static void OnPaint(HWND hwnd)
{
    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(hwnd, &ps);
    RECT client;
    RECT rc;
    HFONT font;
    HFONT oldFont;
    HBRUSH headBrush;
    HBRUSH statusBrush;
    HPEN linePen;
    HPEN oldPen;
    int i;

    GetClientRect(hwnd, &client);

    font = CreateFontA(-13, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                       ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                       DEFAULT_QUALITY, DEFAULT_PITCH, "Arial");
    oldFont = (HFONT)SelectObject(hdc, font);

    headBrush = CreateSolidBrush(RGB(0, 90, 160));
    SetBkMode(hdc, TRANSPARENT);

    for (i = 0; i < HEADER_COUNT; i++)
    {
        SetRect(&rc, g_headers[i].x, g_headers[i].y,
                g_headers[i].x + g_headers[i].w, g_headers[i].y + 20);
        FillRect(hdc, &rc, headBrush);
        SetTextColor(hdc, RGB(255, 255, 255));
        TextOutA(hdc, rc.left + 8, rc.top + 3,
                 g_headers[i].title, lstrlenA(g_headers[i].title));
    }

    /* Status-bar strip along the bottom. */
    statusBrush = CreateSolidBrush(RGB(232, 236, 240));
    SetRect(&rc, 0, 316, client.right, client.bottom);
    FillRect(hdc, &rc, statusBrush);

    linePen = CreatePen(PS_SOLID, 1, RGB(180, 190, 200));
    oldPen = (HPEN)SelectObject(hdc, linePen);
    MoveToEx(hdc, 0, 316, NULL);
    LineTo(hdc, client.right, 316);

    SelectObject(hdc, oldPen);
    SelectObject(hdc, oldFont);
    DeleteObject(font);
    DeleteObject(headBrush);
    DeleteObject(statusBrush);
    DeleteObject(linePen);

    EndPaint(hwnd, &ps);
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
        case WM_CREATE:
            CreateMenuBar(hwnd);
            CreateControls(hwnd, ((LPCREATESTRUCT)lParam)->hInstance);
            SetTimer(hwnd, IDT_CLOCK, 1000, NULL);
            return 0;

        case WM_PAINT:
            OnPaint(hwnd);
            return 0;

        case WM_TIMER:
            if (wParam == IDT_CLOCK)
            {
                SYSTEMTIME now;
                char clock[16];
                GetLocalTime(&now);
                wsprintfA(clock, "%02d:%02d:%02d",
                          now.wHour, now.wMinute, now.wSecond);
                SetDlgItemTextA(hwnd, IDC_CLOCK, clock);
            }
            return 0;

        case WM_COMMAND:
        {
            WORD id   = LOWORD(wParam);
            WORD code = HIWORD(wParam);
            char item[128];
            char status[192];

            switch (id)
            {
                case IDC_HELLO_BTN:
                case IDM_FILE_HELLO:  SayHello(hwnd);        break;

                case IDC_ADD_BTN:     DoCompute(hwnd, '+');  break;
                case IDC_SUB_BTN:     DoCompute(hwnd, '-');  break;
                case IDC_MUL_BTN:     DoCompute(hwnd, 'x');  break;
                case IDC_DIV_BTN:     DoCompute(hwnd, '/');  break;

                case IDC_SORT_BTN:    DoSort(hwnd);          break;

                case IDC_ITEM_ADD:    AddItem(hwnd);         break;
                case IDC_ITEM_DEL:    RemoveItem(hwnd);      break;

                case IDM_FILE_EXIT:   DestroyWindow(hwnd);   break;
                case IDM_HELP_ABOUT:
                    MessageBoxA(hwnd,
                        "winexe32emu - GUI Demo",
                        "About", MB_OK | MB_ICONINFORMATION);
                    break;

                case IDC_UPPER_CHECK:
                    SetStatus(hwnd, IsDlgButtonChecked(hwnd, IDC_UPPER_CHECK)
                                    ? "Uppercase mode is ON"
                                    : "Uppercase mode is OFF");
                    break;

                case IDC_ITEM_LIST:
                    if (code == LBN_SELCHANGE)
                    {
                        HWND list = GetDlgItem(hwnd, IDC_ITEM_LIST);
                        int sel = (int)SendMessageA(list, LB_GETCURSEL, 0, 0);
                        if (sel != LB_ERR)
                        {
                            SendMessageA(list, LB_GETTEXT, sel, (LPARAM)item);
                            wsprintfA(status, "List selection: %s (index %d)",
                                      item, sel);
                            SetStatus(hwnd, status);
                        }
                    }
                    break;

                case IDC_COLOR_COMBO:
                    if (code == CBN_SELCHANGE)
                    {
                        HWND combo = GetDlgItem(hwnd, IDC_COLOR_COMBO);
                        int sel = (int)SendMessageA(combo, CB_GETCURSEL, 0, 0);
                        if (sel != CB_ERR)
                        {
                            SendMessageA(combo, CB_GETLBTEXT, sel, (LPARAM)item);
                            wsprintfA(status, "Color: %s", item);
                            SetStatus(hwnd, status);
                        }
                    }
                    break;
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
            KillTimer(hwnd, IDT_CLOCK);
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
    wc.style = CS_HREDRAW | CS_VREDRAW;

    if (!RegisterClassA(&wc))
    {
        MessageBoxA(NULL, "Window class not registered!", "Error", MB_ICONERROR);
        return 1;
    }

    HWND hwnd = CreateWindowExA(
        0, CLASS_NAME, "GUI Demo",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        480, 430,
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
