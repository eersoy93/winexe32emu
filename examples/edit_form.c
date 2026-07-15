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
static const char* CLASS_NAME = "EditFormClass";

// Control identifiers
#define IDC_NAME_EDIT 101
#define IDC_HELLO_BUTTON 102

// Window procedure - handles messages
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
        case WM_CREATE:
        {
            HINSTANCE hInstance = ((LPCREATESTRUCT)lParam)->hInstance;

            // Label
            CreateWindowExA(
                0, "STATIC", "Your name:",
                WS_CHILD | WS_VISIBLE,
                20, 20, 100, 20,
                hwnd, NULL, hInstance, NULL);

            // Single-line text box
            CreateWindowExA(
                0, "EDIT", "",
                WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT,
                20, 45, 220, 24,
                hwnd, (HMENU)IDC_NAME_EDIT, hInstance, NULL);

            // Greeting button
            CreateWindowExA(
                0, "BUTTON", "Say Hello",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                250, 45, 100, 24,
                hwnd, (HMENU)IDC_HELLO_BUTTON, hInstance, NULL);

            return 0;
        }

        case WM_COMMAND:
            if (LOWORD(wParam) == IDC_HELLO_BUTTON)
            {
                // Read the text box content and greet
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
        0, CLASS_NAME, "Edit Form Demo",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        400, 160,
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
