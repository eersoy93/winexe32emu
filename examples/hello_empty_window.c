/*
Copyright 2025 Erdem Ersoy (eersoy93)

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
static const char* CLASS_NAME = "EmptyWindowClass";

// Window procedure - handles messages
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
        case WM_CREATE:
            // When window is created
            return 0;

        case WM_PAINT:
        {
            // Paint the window
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            
            // Make background white
            FillRect(hdc, &ps.rcPaint, (HBRUSH)(COLOR_WINDOW + 1));
            
            // Write text in center
            const char* text = "Hello, World!";
            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, RGB(0, 0, 128));
            
            RECT rect;
            GetClientRect(hwnd, &rect);
            DrawTextA(hdc, text, -1, &rect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            
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
            // When window is closed
            PostQuitMessage(0);
            return 0;

        case WM_CLOSE:
            // Close request
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
        "Empty Win32 Window",          // Window title
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

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
                   LPSTR lpCmdLine, int nCmdShow)
{
    // Pencere sınıfını kaydet
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

    // Pencereyi oluştur
    HWND hwnd = CreateWindowExA(
        0,                             // Genişletilmiş stil
        CLASS_NAME,                    // Sınıf adı
        "Empty Win32 Window",          // Pencere başlığı
        WS_OVERLAPPEDWINDOW,           // Pencere stili
        CW_USEDEFAULT, CW_USEDEFAULT,  // Pozisyon (varsayılan)
        400, 300,                      // Boyut
        NULL,                          // Üst pencere
        NULL,                          // Menü
        hInstance,                     // Uygulama örneği
        NULL                           // Ek veri
    );

    if (hwnd == NULL)
    {
        MessageBoxA(NULL, "Window!", "Error", MB_ICONERROR);
        return 1;
    }

    // Pencereyi göster
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    // Mesaj döngüsü
    MSG msg = {0};
    while (GetMessageA(&msg, NULL, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }

    return (int)msg.wParam;
}
