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
GDI demo - shows the emulator's richer drawing features:
CreateFontA (sizes, bold, italic, underline), Polygon (a star),
Pie (a small pie chart), RoundRect, Arc and Polyline.
*/

#include <windows.h>

static const char* CLASS_NAME = "GdiDemoClass";

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
        case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            int i;

            /* Big bold title */
            HFONT titleFont = CreateFontA(-28, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                                          ANSI_CHARSET, OUT_DEFAULT_PRECIS,
                                          CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
                                          DEFAULT_PITCH, "Arial");
            HFONT oldFont = (HFONT)SelectObject(hdc, titleFont);
            SetTextColor(hdc, RGB(0, 0, 128));
            TextOutA(hdc, 20, 12, "GDI Demo", 8);

            /* Italic subtitle */
            HFONT italicFont = CreateFontA(-16, 0, 0, 0, FW_NORMAL, TRUE, FALSE, FALSE,
                                           ANSI_CHARSET, OUT_DEFAULT_PRECIS,
                                           CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
                                           DEFAULT_PITCH, "Arial");
            SelectObject(hdc, italicFont);
            SetTextColor(hdc, RGB(64, 64, 64));
            TextOutA(hdc, 20, 46, "Fonts, polygons, pies, arcs...", 30);

            /* Underlined note */
            HFONT underFont = CreateFontA(-13, 0, 0, 0, FW_NORMAL, FALSE, TRUE, FALSE,
                                          ANSI_CHARSET, OUT_DEFAULT_PRECIS,
                                          CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
                                          DEFAULT_PITCH, "Arial");
            SelectObject(hdc, underFont);
            SetTextColor(hdc, RGB(128, 0, 0));
            TextOutA(hdc, 20, 70, "Press ESC to quit.", 18);
            SelectObject(hdc, oldFont);

            /* Five-pointed star with Polygon */
            POINT star[10];
            static const int sx[10] = { 60, 74, 120, 84, 96, 60, 24, 36, 0, 46 };
            static const int sy[10] = { 100, 140, 140, 165, 210, 180, 210, 165, 140, 140 };
            for (i = 0; i < 10; i++)
            {
                star[i].x = 30 + sx[i];
                star[i].y = sy[i];
            }
            HPEN starPen = CreatePen(PS_SOLID, 2, RGB(160, 96, 0));
            HBRUSH starBrush = CreateSolidBrush(RGB(255, 176, 0));
            HPEN oldPen = (HPEN)SelectObject(hdc, starPen);
            HBRUSH oldBrush = (HBRUSH)SelectObject(hdc, starBrush);
            Polygon(hdc, star, 10);

            /* Small pie chart with three slices */
            HBRUSH slice1 = CreateSolidBrush(RGB(0, 160, 0));
            HBRUSH slice2 = CreateSolidBrush(RGB(0, 96, 208));
            HBRUSH slice3 = CreateSolidBrush(RGB(208, 48, 48));
            HPEN piePen = CreatePen(PS_SOLID, 1, RGB(32, 32, 32));
            SelectObject(hdc, piePen);

            /* Half green, quarter blue, quarter red */
            SelectObject(hdc, slice1);
            Pie(hdc, 200, 100, 320, 220, 320, 160, 200, 160);
            SelectObject(hdc, slice2);
            Pie(hdc, 200, 100, 320, 220, 200, 160, 260, 220);
            SelectObject(hdc, slice3);
            Pie(hdc, 200, 100, 320, 220, 260, 220, 320, 160);

            /* Rounded rectangle */
            HPEN rrPen = CreatePen(PS_SOLID, 2, RGB(0, 96, 0));
            HBRUSH rrBrush = CreateSolidBrush(RGB(176, 240, 176));
            SelectObject(hdc, rrPen);
            SelectObject(hdc, rrBrush);
            RoundRect(hdc, 350, 100, 480, 160, 24, 24);

            /* Arc (upper half of an ellipse) */
            HPEN arcPen = CreatePen(PS_SOLID, 3, RGB(96, 0, 160));
            SelectObject(hdc, arcPen);
            Arc(hdc, 350, 170, 480, 230, 480, 200, 350, 200);

            /* Zigzag polyline */
            POINT zig[8];
            for (i = 0; i < 8; i++)
            {
                zig[i].x = 30 + i * 60;
                zig[i].y = (i % 2 == 0) ? 250 : 280;
            }
            HPEN zigPen = CreatePen(PS_SOLID, 2, RGB(208, 96, 0));
            SelectObject(hdc, zigPen);
            Polyline(hdc, zig, 8);

            /* Restore and free GDI objects */
            SelectObject(hdc, oldPen);
            SelectObject(hdc, oldBrush);
            DeleteObject(titleFont);
            DeleteObject(italicFont);
            DeleteObject(underFont);
            DeleteObject(starPen);
            DeleteObject(starBrush);
            DeleteObject(slice1);
            DeleteObject(slice2);
            DeleteObject(slice3);
            DeleteObject(piePen);
            DeleteObject(rrPen);
            DeleteObject(rrBrush);
            DeleteObject(arcPen);
            DeleteObject(zigPen);

            EndPaint(hwnd, &ps);
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
        0, CLASS_NAME, "GDI Demo",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        540, 360,
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
