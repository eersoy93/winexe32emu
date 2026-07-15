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
static const char* CLASS_NAME = "GdiDrawingClass";

// Window procedure - handles messages
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
        case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);

            // Red-bordered yellow rectangle
            HPEN redPen = CreatePen(PS_SOLID, 2, RGB(255, 0, 0));
            HBRUSH yellowBrush = CreateSolidBrush(RGB(255, 255, 0));
            HPEN oldPen = (HPEN)SelectObject(hdc, redPen);
            HBRUSH oldBrush = (HBRUSH)SelectObject(hdc, yellowBrush);
            Rectangle(hdc, 20, 20, 160, 100);

            // Blue-bordered light blue ellipse
            HPEN bluePen = CreatePen(PS_SOLID, 2, RGB(0, 0, 255));
            HBRUSH cyanBrush = CreateSolidBrush(RGB(128, 224, 255));
            SelectObject(hdc, bluePen);
            SelectObject(hdc, cyanBrush);
            Ellipse(hdc, 200, 20, 360, 100);

            // Green diagonal lines
            HPEN greenPen = CreatePen(PS_SOLID, 3, RGB(0, 160, 0));
            SelectObject(hdc, greenPen);
            MoveToEx(hdc, 20, 130, NULL);
            LineTo(hdc, 360, 130);
            LineTo(hdc, 20, 180);
            LineTo(hdc, 360, 180);

            // Purple pixel dots
            int i;
            for (i = 0; i < 40; i++)
            {
                SetPixel(hdc, 20 + i * 8, 200, RGB(160, 0, 160));
                SetPixel(hdc, 20 + i * 8, 202, RGB(160, 0, 160));
            }

            // Label
            SetTextColor(hdc, RGB(0, 0, 128));
            TextOutA(hdc, 20, 215, "GDI drawing demo!", 17);

            // Restore and free GDI objects
            SelectObject(hdc, oldPen);
            SelectObject(hdc, oldBrush);
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
        0, CLASS_NAME, "GDI Drawing Demo",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        400, 300,
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
