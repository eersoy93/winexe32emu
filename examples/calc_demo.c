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
Calculator / form demo - exercises the emulator's form-oriented APIs:

  - EDIT controls read as integers with GetDlgItemInt(bSigned) and written
    back with SetDlgItemInt.
  - The msvcrt C runtime helpers strtol, qsort, strchr, toupper and the
    ctype predicates (isdigit / isspace) drive a small "sort the numbers"
    feature that parses a free-form list typed into an EDIT box.

Type two numbers, press +, -, x or / to compute. Type a comma/space list
of integers into the third box and press "Sort" to sort them ascending.
Press ESC to quit.
*/

#include <windows.h>
#include <stdlib.h>   /* strtol, qsort */
#include <string.h>   /* strchr */
#include <ctype.h>    /* isdigit, isspace, toupper */

static const char* CLASS_NAME = "CalcDemoClass";

#define IDC_A_EDIT     201
#define IDC_B_EDIT     202
#define IDC_ADD_BTN    203
#define IDC_SUB_BTN    204
#define IDC_MUL_BTN    205
#define IDC_DIV_BTN    206
#define IDC_RESULT     207
#define IDC_LIST_EDIT  208
#define IDC_SORT_BTN   209
#define IDC_SORTED     210
#define IDC_STATUS     211

/* Comparison callback for qsort - ascending integer order */
static int cmp_int(const void* a, const void* b)
{
    int ia = *(const int*)a;
    int ib = *(const int*)b;
    if (ia < ib) return -1;
    if (ia > ib) return 1;
    return 0;
}

/* Compute one arithmetic operation and show the result. */
static void DoCompute(HWND hwnd, char op)
{
    BOOL okA = FALSE, okB = FALSE;
    int a = (int)GetDlgItemInt(hwnd, IDC_A_EDIT, &okA, TRUE);
    int b = (int)GetDlgItemInt(hwnd, IDC_B_EDIT, &okB, TRUE);
    char status[192];

    if (!okA || !okB)
    {
        SetDlgItemTextA(hwnd, IDC_STATUS, "Enter whole numbers in both boxes.");
        return;
    }

    switch (op)
    {
        case '+':
            SetDlgItemInt(hwnd, IDC_RESULT, a + b, TRUE);
            break;
        case '-':
            SetDlgItemInt(hwnd, IDC_RESULT, a - b, TRUE);
            break;
        case 'x':
            SetDlgItemInt(hwnd, IDC_RESULT, a * b, TRUE);
            break;
        case '/':
            if (b == 0)
            {
                SetDlgItemTextA(hwnd, IDC_RESULT, "inf");
                SetDlgItemTextA(hwnd, IDC_STATUS, "Division by zero!");
                return;
            }
            SetDlgItemInt(hwnd, IDC_RESULT, a / b, TRUE);
            break;
    }

    wsprintfA(status, "Computed %d %c %d", a, (op == 'x' ? '*' : op), b);
    SetDlgItemTextA(hwnd, IDC_STATUS, status);
}

/* Parse the free-form list, sort it with qsort and display the result. */
static void DoSort(HWND hwnd)
{
    char raw[256];
    char out[256];
    int  numbers[64];
    int  count = 0;
    char* p;
    char status[192];

    GetDlgItemTextA(hwnd, IDC_LIST_EDIT, raw, sizeof(raw));

    /* Walk the string with strtol, which skips leading whitespace and
       reports where each number ends via its endptr argument. */
    p = raw;
    while (*p != '\0' && count < 64)
    {
        char* end;
        long value;

        /* Skip anything that cannot start a number (commas, spaces, ...) */
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
            /* No digits consumed - skip this character to avoid a loop */
            p++;
            continue;
        }
        numbers[count++] = (int)value;
        p = end;
    }

    if (count == 0)
    {
        SetDlgItemTextA(hwnd, IDC_SORTED, "");
        SetDlgItemTextA(hwnd, IDC_STATUS, "Type some numbers to sort, e.g. 5, 2, 9, 1");
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
    SetDlgItemTextA(hwnd, IDC_STATUS, status);
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
        case WM_CREATE:
        {
            HINSTANCE hInstance = ((LPCREATESTRUCT)lParam)->hInstance;

            CreateWindowExA(0, "STATIC", "A:",
                            WS_CHILD | WS_VISIBLE,
                            20, 16, 20, 20, hwnd, NULL, hInstance, NULL);
            CreateWindowExA(0, "EDIT", "12",
                            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT,
                            44, 12, 90, 24,
                            hwnd, (HMENU)IDC_A_EDIT, hInstance, NULL);

            CreateWindowExA(0, "STATIC", "B:",
                            WS_CHILD | WS_VISIBLE,
                            150, 16, 20, 20, hwnd, NULL, hInstance, NULL);
            CreateWindowExA(0, "EDIT", "34",
                            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT,
                            174, 12, 90, 24,
                            hwnd, (HMENU)IDC_B_EDIT, hInstance, NULL);

            CreateWindowExA(0, "BUTTON", "+",
                            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                            20, 48, 55, 26,
                            hwnd, (HMENU)IDC_ADD_BTN, hInstance, NULL);
            CreateWindowExA(0, "BUTTON", "-",
                            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                            83, 48, 55, 26,
                            hwnd, (HMENU)IDC_SUB_BTN, hInstance, NULL);
            CreateWindowExA(0, "BUTTON", "x",
                            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                            146, 48, 55, 26,
                            hwnd, (HMENU)IDC_MUL_BTN, hInstance, NULL);
            CreateWindowExA(0, "BUTTON", "/",
                            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                            209, 48, 55, 26,
                            hwnd, (HMENU)IDC_DIV_BTN, hInstance, NULL);

            CreateWindowExA(0, "STATIC", "=",
                            WS_CHILD | WS_VISIBLE,
                            20, 90, 20, 20, hwnd, NULL, hInstance, NULL);
            CreateWindowExA(0, "EDIT", "",
                            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT | ES_READONLY,
                            44, 86, 220, 24,
                            hwnd, (HMENU)IDC_RESULT, hInstance, NULL);

            CreateWindowExA(0, "STATIC", "Numbers to sort:",
                            WS_CHILD | WS_VISIBLE,
                            20, 128, 130, 20, hwnd, NULL, hInstance, NULL);
            CreateWindowExA(0, "EDIT", "5, 2, 9, 1, 7, 3",
                            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT,
                            20, 150, 244, 24,
                            hwnd, (HMENU)IDC_LIST_EDIT, hInstance, NULL);
            CreateWindowExA(0, "BUTTON", "Sort",
                            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                            272, 150, 88, 24,
                            hwnd, (HMENU)IDC_SORT_BTN, hInstance, NULL);
            CreateWindowExA(0, "EDIT", "",
                            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT | ES_READONLY,
                            20, 182, 340, 24,
                            hwnd, (HMENU)IDC_SORTED, hInstance, NULL);

            CreateWindowExA(0, "STATIC", "Ready.",
                            WS_CHILD | WS_VISIBLE,
                            20, 222, 350, 20,
                            hwnd, (HMENU)IDC_STATUS, hInstance, NULL);
            return 0;
        }

        case WM_COMMAND:
        {
            WORD id = LOWORD(wParam);
            switch (id)
            {
                case IDC_ADD_BTN: DoCompute(hwnd, '+'); break;
                case IDC_SUB_BTN: DoCompute(hwnd, '-'); break;
                case IDC_MUL_BTN: DoCompute(hwnd, 'x'); break;
                case IDC_DIV_BTN: DoCompute(hwnd, '/'); break;
                case IDC_SORT_BTN: DoSort(hwnd); break;
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
        0, CLASS_NAME, "Calculator Demo",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        400, 300,
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
