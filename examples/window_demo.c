/*
Copyright 2025-2026 Erdem Ersoy (eersoy93)

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
Window demo - covers the emulator's GUI features in one program:
window class + window creation, menu bar with dropdowns and a separator,
STATIC/EDIT/BUTTON controls, WM_COMMAND from both buttons and menus,
SetTimer/WM_TIMER with an InvalidateRect repaint loop, GDI drawing
(pens, brushes, Rectangle, Ellipse, MoveToEx/LineTo, SetPixel,
SetTextColor, TextOutA, wsprintfA) and MessageBoxA.
*/

#include <windows.h>

// Window class name
static const char* CLASS_NAME = "WindowDemoClass";

// Control identifiers
#define IDC_NAME_EDIT    101
#define IDC_HELLO_BUTTON 102

// Menu command identifiers
#define IDM_FILE_HELLO 201
#define IDM_FILE_EXIT  202
#define IDM_HELP_ABOUT 203

// Timer identifier
#define IDT_COUNTER 1

// Seconds elapsed since the program started
static int g_seconds = 0;

// Read the name from the edit box and greet with a message box
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

    MessageBoxA(hwnd, message, "Greeting", MB_OK);
}

// Window procedure - handles messages
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
        case WM_CREATE:
        {
            HINSTANCE hInstance = ((LPCREATESTRUCT)lParam)->hInstance;

            // Menu bar: File and Help dropdowns
            HMENU hMenuBar = CreateMenu();
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

            // Form controls: label, text box, button
            CreateWindowExA(
                0, "STATIC", "Your name:",
                WS_CHILD | WS_VISIBLE,
                20, 12, 100, 20,
                hwnd, NULL, hInstance, NULL);

            CreateWindowExA(
                0, "EDIT", "",
                WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT,
                20, 34, 220, 24,
                hwnd, (HMENU)IDC_NAME_EDIT, hInstance, NULL);

            CreateWindowExA(
                0, "BUTTON", "Say Hello",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                250, 34, 110, 24,
                hwnd, (HMENU)IDC_HELLO_BUTTON, hInstance, NULL);

            // Fire WM_TIMER once per second
            SetTimer(hwnd, IDT_COUNTER, 1000, NULL);
            return 0;
        }

        case WM_COMMAND:
            switch (LOWORD(wParam))
            {
                case IDC_HELLO_BUTTON:
                case IDM_FILE_HELLO:
                    SayHello(hwnd);
                    break;

                case IDM_FILE_EXIT:
                    DestroyWindow(hwnd);
                    break;

                case IDM_HELP_ABOUT:
                    MessageBoxA(hwnd, "Window Demo - winexe32emu example", "About", MB_OK);
                    break;
            }
            return 0;

        case WM_TIMER:
            if (wParam == IDT_COUNTER)
            {
                g_seconds++;
                // Request a repaint with the new counter value
                InvalidateRect(hwnd, NULL, TRUE);
            }
            return 0;

        case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);

            // Counter driven by WM_TIMER
            char buffer[64];
            wsprintfA(buffer, "Elapsed seconds: %d", g_seconds);
            SetTextColor(hdc, RGB(0, 0, 128));
            TextOutA(hdc, 20, 72, buffer, lstrlenA(buffer));

            // Progress bar that grows one step per second (wraps at 60)
            HBRUSH barBrush = CreateSolidBrush(RGB(0, 160, 0));
            HBRUSH oldBrush = (HBRUSH)SelectObject(hdc, barBrush);
            Rectangle(hdc, 20, 95, 20 + (g_seconds % 60) * 5, 115);

            // Red-bordered yellow rectangle
            HPEN redPen = CreatePen(PS_SOLID, 2, RGB(255, 0, 0));
            HBRUSH yellowBrush = CreateSolidBrush(RGB(255, 255, 0));
            HPEN oldPen = (HPEN)SelectObject(hdc, redPen);
            SelectObject(hdc, yellowBrush);
            Rectangle(hdc, 200, 130, 360, 190);

            // Blue-bordered light blue ellipse
            HPEN bluePen = CreatePen(PS_SOLID, 2, RGB(0, 0, 255));
            HBRUSH cyanBrush = CreateSolidBrush(RGB(128, 224, 255));
            SelectObject(hdc, bluePen);
            SelectObject(hdc, cyanBrush);
            Ellipse(hdc, 20, 130, 180, 190);

            // Green zigzag lines
            HPEN greenPen = CreatePen(PS_SOLID, 3, RGB(0, 160, 0));
            SelectObject(hdc, greenPen);
            MoveToEx(hdc, 20, 205, NULL);
            LineTo(hdc, 360, 205);
            LineTo(hdc, 20, 225);
            LineTo(hdc, 360, 225);

            // Purple pixel dots
            int i;
            for (i = 0; i < 40; i++)
            {
                SetPixel(hdc, 20 + i * 8, 240, RGB(160, 0, 160));
                SetPixel(hdc, 20 + i * 8, 242, RGB(160, 0, 160));
            }

            TextOutA(hdc, 20, 252, "Press ESC to quit.", 18);

            // Restore and free GDI objects
            SelectObject(hdc, oldPen);
            SelectObject(hdc, oldBrush);
            DeleteObject(barBrush);
            DeleteObject(redPen);
            DeleteObject(yellowBrush);
            DeleteObject(bluePen);
            DeleteObject(cyanBrush);
            DeleteObject(greenPen);

            EndPaint(hwnd, &ps);
            return 0;
        }

        case WM_KEYDOWN:
            // Close when ESC key is pressed
            if (wParam == VK_ESCAPE)
            {
                PostQuitMessage(0);
            }
            return 0;

        case WM_DESTROY:
            KillTimer(hwnd, IDT_COUNTER);
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
    // Register window class
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

    // Create the window
    HWND hwnd = CreateWindowExA(
        0, CLASS_NAME, "Window Demo",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        400, 340,
        NULL, NULL, hInstance, NULL);

    if (hwnd == NULL)
    {
        MessageBoxA(NULL, "Window could not be created!", "Error", MB_ICONERROR);
        return 1;
    }

    // Show the window
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    // Message loop
    MSG msg = {0};
    while (GetMessageA(&msg, NULL, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }

    return (int)msg.wParam;
}
