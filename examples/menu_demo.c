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

#include <windows.h>

// Window class name
static const char* CLASS_NAME = "MenuDemoClass";

// Menu command identifiers
#define IDM_FILE_HELLO 101
#define IDM_FILE_EXIT  102
#define IDM_HELP_ABOUT 201

// Window procedure - handles messages
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
        case WM_CREATE:
        {
            // Build the menu bar: File and Help dropdowns
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
            return 0;
        }

        case WM_COMMAND:
            switch (LOWORD(wParam))
            {
                case IDM_FILE_HELLO:
                    MessageBoxA(hwnd, "Hello from the File menu!", "Menu Demo", MB_OK);
                    break;

                case IDM_FILE_EXIT:
                    DestroyWindow(hwnd);
                    break;

                case IDM_HELP_ABOUT:
                    MessageBoxA(hwnd, "Menu Demo - winexe32emu example", "About", MB_OK);
                    break;
            }
            return 0;

        case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            TextOutA(hdc, 20, 20, "Use the File and Help menus above.", 34);
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
        0, CLASS_NAME, "Menu Demo",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        400, 250,
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
