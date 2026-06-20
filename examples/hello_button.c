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
static const char* CLASS_NAME = "ButtonWindowClass";

// Control identifier for the button
#define IDC_BUTTON 101

// Window procedure - handles messages
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
        case WM_CREATE:
            // Create a push button as a child control
            CreateWindowExA(
                0, "BUTTON", "Click me!",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                120, 100, 120, 30,
                hwnd, (HMENU)IDC_BUTTON,
                ((LPCREATESTRUCT)lParam)->hInstance, NULL);
            return 0;

        case WM_COMMAND:
            // Button clicked -> show a message box
            if (LOWORD(wParam) == IDC_BUTTON)
            {
                MessageBoxA(hwnd, "Button clicked!", "Info", MB_OK);
            }
            return 0;

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
        0,                             // Extended style
        CLASS_NAME,                    // Class name
        "Button Demo",                 // Window title
        WS_OVERLAPPEDWINDOW,           // Window style
        CW_USEDEFAULT, CW_USEDEFAULT,  // Position (default)
        400, 300,                      // Size
        NULL,                          // Parent window
        NULL,                          // Menu
        hInstance,                     // Application instance
        NULL                           // Additional data
    );

    if (hwnd == NULL)
    {
        MessageBoxA(NULL, "Window!", "Error", MB_ICONERROR);
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
