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
GDI demo - a small "graphics gallery" that shows off the emulator's drawing
features in a composed layout:

  - CreateFontA at several sizes with bold / italic / underline styles, and a
    drop-shadow title drawn by painting the text twice.
  - A left-to-right colour gradient built from thin FillRect strips (header
    band, a swatch card and a rainbow spectrum strip).
  - RoundRect "cards" that frame each sample, plus Polygon (a star), Pie (a
    three-slice chart), Arc / Ellipse and Polyline (a zigzag wave).

Press ESC to quit.
*/

#include <windows.h>

static const char* CLASS_NAME = "GdiDemoClass";

#define CARD_W 152
#define CARD_H 150
#define CARD_Y 82

/* Fill a rectangle with a smooth left-to-right gradient between two colours. */
static void GradientH(HDC hdc, int x, int y, int w, int h,
                      COLORREF c1, COLORREF c2)
{
    int r1 = GetRValue(c1), g1 = GetGValue(c1), b1 = GetBValue(c1);
    int r2 = GetRValue(c2), g2 = GetGValue(c2), b2 = GetBValue(c2);
    int i;

    for (i = 0; i < w; i += 2)
    {
        RECT rc;
        int r = r1 + (r2 - r1) * i / w;
        int g = g1 + (g2 - g1) * i / w;
        int b = b1 + (b2 - b1) * i / w;
        HBRUSH br = CreateSolidBrush(RGB(r, g, b));
        SetRect(&rc, x + i, y, x + i + 2, y + h);
        FillRect(hdc, &rc, br);
        DeleteObject(br);
    }
}

/* Draw a rounded card background with a coloured title in its top-left. */
static void DrawCard(HDC hdc, int x, int y, const char* title, HFONT labelFont)
{
    HBRUSH bg = CreateSolidBrush(RGB(247, 249, 252));
    HPEN border = CreatePen(PS_SOLID, 1, RGB(198, 206, 214));
    HBRUSH oldB = (HBRUSH)SelectObject(hdc, bg);
    HPEN oldP = (HPEN)SelectObject(hdc, border);
    HFONT oldF;

    RoundRect(hdc, x, y, x + CARD_W, y + CARD_H, 14, 14);

    oldF = (HFONT)SelectObject(hdc, labelFont);
    SetTextColor(hdc, RGB(0, 90, 160));
    TextOutA(hdc, x + 12, y + 9, title, lstrlenA(title));
    SelectObject(hdc, oldF);

    SelectObject(hdc, oldB);
    SelectObject(hdc, oldP);
    DeleteObject(bg);
    DeleteObject(border);
}

static void OnPaint(HWND hwnd)
{
    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(hwnd, &ps);
    RECT client;
    HFONT titleFont, subFont, cardFont, boldFont, italicFont, underFont, oldFont;
    HPEN oldPen;
    HBRUSH oldBrush;
    int cx0, cx1, cx2, cx3;
    int i;

    GetClientRect(hwnd, &client);
    SetBkMode(hdc, TRANSPARENT);

    /* ---- Header band with gradient and drop-shadow title ---- */
    GradientH(hdc, 0, 0, client.right, 66, RGB(0, 78, 150), RGB(0, 158, 138));

    titleFont = CreateFontA(-30, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                            ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                            DEFAULT_QUALITY, DEFAULT_PITCH, "Arial");
    oldFont = (HFONT)SelectObject(hdc, titleFont);
    SetTextColor(hdc, RGB(0, 40, 70));            /* shadow */
    TextOutA(hdc, 26, 13, "GDI Gallery", 11);
    SetTextColor(hdc, RGB(255, 255, 255));        /* highlight */
    TextOutA(hdc, 24, 11, "GDI Gallery", 11);

    subFont = CreateFontA(-14, 0, 0, 0, FW_NORMAL, TRUE, FALSE, FALSE,
                          ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                          DEFAULT_QUALITY, DEFAULT_PITCH, "Arial");
    SelectObject(hdc, subFont);
    SetTextColor(hdc, RGB(220, 240, 245));
    TextOutA(hdc, 26, 44, "Fonts, polygons, pies, arcs and gradients", 41);
    SelectObject(hdc, oldFont);

    /* Card title font, reused for every card. */
    cardFont = CreateFontA(-13, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                           ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                           DEFAULT_QUALITY, DEFAULT_PITCH, "Arial");

    cx0 = 16;
    cx1 = cx0 + CARD_W + 12;
    cx2 = cx1 + CARD_W + 12;
    cx3 = cx2 + CARD_W + 12;

    /* ---- Card 1: Polygon (a five-pointed star) ---- */
    DrawCard(hdc, cx0, CARD_Y, "Polygon", cardFont);
    {
        static const int off[10][2] = {
            {0,-46},{11,-15},{44,-14},{17,6},{27,37},
            {0,18},{-27,37},{-17,6},{-44,-14},{-11,-15}
        };
        POINT star[10];
        int scx = cx0 + CARD_W / 2;
        int scy = CARD_Y + 92;
        HPEN pen = CreatePen(PS_SOLID, 2, RGB(160, 96, 0));
        HBRUSH br = CreateSolidBrush(RGB(255, 184, 0));
        oldPen = (HPEN)SelectObject(hdc, pen);
        oldBrush = (HBRUSH)SelectObject(hdc, br);
        for (i = 0; i < 10; i++)
        {
            star[i].x = scx + off[i][0];
            star[i].y = scy + off[i][1];
        }
        Polygon(hdc, star, 10);
        SelectObject(hdc, oldPen);
        SelectObject(hdc, oldBrush);
        DeleteObject(pen);
        DeleteObject(br);
    }

    /* ---- Card 2: Pie (half green, quarter blue, quarter red) ---- */
    DrawCard(hdc, cx1, CARD_Y, "Pie", cardFont);
    {
        int L = cx1 + 20, T = CARD_Y + 40, R = cx1 + CARD_W - 20, B = CARD_Y + 136;
        int mcy = (T + B) / 2;
        HBRUSH s1 = CreateSolidBrush(RGB(0, 168, 92));
        HBRUSH s2 = CreateSolidBrush(RGB(0, 110, 210));
        HBRUSH s3 = CreateSolidBrush(RGB(220, 60, 60));
        HPEN pen = CreatePen(PS_SOLID, 1, RGB(40, 40, 40));
        oldPen = (HPEN)SelectObject(hdc, pen);
        oldBrush = (HBRUSH)SelectObject(hdc, s1);
        Pie(hdc, L, T, R, B, R, mcy, L, mcy);
        SelectObject(hdc, s2);
        Pie(hdc, L, T, R, B, L, mcy, (L + R) / 2, B);
        SelectObject(hdc, s3);
        Pie(hdc, L, T, R, B, (L + R) / 2, B, R, mcy);
        SelectObject(hdc, oldPen);
        SelectObject(hdc, oldBrush);
        DeleteObject(s1);
        DeleteObject(s2);
        DeleteObject(s3);
        DeleteObject(pen);
    }

    /* ---- Card 3: Arc and Ellipse ---- */
    DrawCard(hdc, cx2, CARD_Y, "Arc", cardFont);
    {
        int L = cx2 + 18, T = CARD_Y + 42, R = cx2 + CARD_W - 18, B = CARD_Y + 128;
        HBRUSH br = CreateSolidBrush(RGB(206, 232, 255));
        HPEN thin = CreatePen(PS_SOLID, 1, RGB(0, 96, 160));
        HPEN thick = CreatePen(PS_SOLID, 3, RGB(120, 0, 170));
        oldBrush = (HBRUSH)SelectObject(hdc, br);
        oldPen = (HPEN)SelectObject(hdc, thin);
        Ellipse(hdc, L, T + 18, R, B);
        SelectObject(hdc, thick);
        Arc(hdc, L, T, R, B + 6, R, (T + B) / 2, L, (T + B) / 2);
        SelectObject(hdc, oldPen);
        SelectObject(hdc, oldBrush);
        DeleteObject(br);
        DeleteObject(thin);
        DeleteObject(thick);
    }

    /* ---- Card 4: Polyline (a zigzag wave) ---- */
    DrawCard(hdc, cx3, CARD_Y, "Polyline", cardFont);
    {
        POINT zig[9];
        HPEN pen = CreatePen(PS_SOLID, 2, RGB(210, 96, 0));
        oldPen = (HPEN)SelectObject(hdc, pen);
        for (i = 0; i < 9; i++)
        {
            zig[i].x = cx3 + 16 + i * 15;
            zig[i].y = CARD_Y + ((i % 2 == 0) ? 60 : 118);
        }
        Polyline(hdc, zig, 9);
        SelectObject(hdc, oldPen);
        DeleteObject(pen);
    }

    /* ---- Fonts panel ---- */
    {
        int py = CARD_Y + CARD_H + 12;
        HBRUSH bg = CreateSolidBrush(RGB(250, 250, 245));
        HPEN border = CreatePen(PS_SOLID, 1, RGB(210, 210, 200));
        oldBrush = (HBRUSH)SelectObject(hdc, bg);
        oldPen = (HPEN)SelectObject(hdc, border);
        RoundRect(hdc, 16, py, client.right - 16, py + 76, 14, 14);
        SelectObject(hdc, oldBrush);
        SelectObject(hdc, oldPen);
        DeleteObject(bg);
        DeleteObject(border);

        boldFont = CreateFontA(-20, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                               ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                               DEFAULT_QUALITY, DEFAULT_PITCH, "Arial");
        italicFont = CreateFontA(-15, 0, 0, 0, FW_NORMAL, TRUE, FALSE, FALSE,
                                 ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                 DEFAULT_QUALITY, DEFAULT_PITCH, "Arial");
        underFont = CreateFontA(-14, 0, 0, 0, FW_NORMAL, FALSE, TRUE, FALSE,
                                ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                DEFAULT_QUALITY, DEFAULT_PITCH, "Arial");

        SelectObject(hdc, boldFont);
        SetTextColor(hdc, RGB(0, 0, 128));
        TextOutA(hdc, 30, py + 10, "Bold Headline", 13);
        SelectObject(hdc, italicFont);
        SetTextColor(hdc, RGB(80, 80, 80));
        TextOutA(hdc, 30, py + 38, "Italic Subheading", 17);
        SelectObject(hdc, underFont);
        SetTextColor(hdc, RGB(150, 0, 0));
        TextOutA(hdc, 250, py + 40, "Underlined Note", 15);
        SelectObject(hdc, oldFont);
        DeleteObject(boldFont);
        DeleteObject(italicFont);
        DeleteObject(underFont);
    }

    /* ---- Rainbow spectrum strip ---- */
    {
        int sy = CARD_Y + CARD_H + 100;
        int sx = 16;
        int sw = client.right - 32;
        int seg = sw / 6;
        HPEN border;
        HBRUSH nullBrush;
        GradientH(hdc, sx + 0 * seg, sy, seg, 24, RGB(230, 30, 30),  RGB(240, 200, 0));
        GradientH(hdc, sx + 1 * seg, sy, seg, 24, RGB(240, 200, 0),  RGB(30, 190, 60));
        GradientH(hdc, sx + 2 * seg, sy, seg, 24, RGB(30, 190, 60),  RGB(0, 190, 200));
        GradientH(hdc, sx + 3 * seg, sy, seg, 24, RGB(0, 190, 200),  RGB(30, 90, 220));
        GradientH(hdc, sx + 4 * seg, sy, seg, 24, RGB(30, 90, 220),  RGB(150, 40, 200));
        GradientH(hdc, sx + 5 * seg, sy, seg, 24, RGB(150, 40, 200), RGB(230, 30, 30));

        border = CreatePen(PS_SOLID, 1, RGB(120, 120, 120));
        nullBrush = (HBRUSH)GetStockObject(NULL_BRUSH);
        oldPen = (HPEN)SelectObject(hdc, border);
        oldBrush = (HBRUSH)SelectObject(hdc, nullBrush);
        Rectangle(hdc, sx, sy, sx + seg * 6, sy + 24);
        SelectObject(hdc, oldPen);
        SelectObject(hdc, oldBrush);
        DeleteObject(border);

        SetTextColor(hdc, RGB(90, 90, 90));
        TextOutA(hdc, sx, sy + 30, "Press ESC to quit.", 18);
    }

    DeleteObject(titleFont);
    DeleteObject(subFont);
    DeleteObject(cardFont);

    EndPaint(hwnd, &ps);
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
        case WM_PAINT:
            OnPaint(hwnd);
            return 0;

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
    wc.style = CS_HREDRAW | CS_VREDRAW;

    if (!RegisterClassA(&wc))
    {
        MessageBoxA(NULL, "Window class not registered!", "Error", MB_ICONERROR);
        return 1;
    }

    HWND hwnd = CreateWindowExA(
        0, CLASS_NAME, "GDI Demo",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        700, 480,
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
