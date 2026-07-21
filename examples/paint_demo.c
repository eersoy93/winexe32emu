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
Paint demo - a tiny paint program that exercises the emulator's mouse
and utility APIs: WM_MOUSEMOVE with MK_LBUTTON dragging, mouse capture
(SetCapture/ReleaseCapture), RECT helpers (SetRect, PtInRect,
InflateRect), FrameRect/PatBlt fills, GetLocalTime clock display and
CRT rand/srand/time for the random-color palette slot.

Left-drag on the canvas to draw, click a palette square to change the
pen color (the "?" slot picks a random color), right-click clears.
*/

#include <windows.h>
#include <stdlib.h>
#include <time.h>

static const char* CLASS_NAME = "PaintDemoClass";

// Palette layout
#define PALETTE_COUNT  8
#define PALETTE_SIZE   30
#define PALETTE_TOP    8
#define PALETTE_LEFT   8
#define PALETTE_GAP    6

// Canvas layout (inside the client area)
#define CANVAS_TOP     46
#define CANVAS_MARGIN  8
#define STATUS_HEIGHT  22

// Stored line segments of the drawing
#define MAX_SEGMENTS   4096

static COLORREF g_palette[PALETTE_COUNT - 1] =
{
    RGB(0, 0, 0),       // Black
    RGB(255, 0, 0),     // Red
    RGB(0, 160, 0),     // Green
    RGB(0, 0, 255),     // Blue
    RGB(255, 160, 0),   // Orange
    RGB(160, 0, 200),   // Purple
    RGB(128, 128, 128), // Gray
};

static COLORREF g_color = RGB(0, 0, 0);  // Current pen color
static int g_selected = 0;               // Selected palette index (7 = random)

static int g_segx1[MAX_SEGMENTS];
static int g_segy1[MAX_SEGMENTS];
static int g_segx2[MAX_SEGMENTS];
static int g_segy2[MAX_SEGMENTS];
static COLORREF g_segcolor[MAX_SEGMENTS];
static int g_segments = 0;

static BOOL g_drawing = FALSE;  // Left button held on the canvas?
static int g_lastx = 0;
static int g_lasty = 0;

// Screen rectangle of one palette slot
static void PaletteRect(int index, RECT* rc)
{
    int x = PALETTE_LEFT + index * (PALETTE_SIZE + PALETTE_GAP);
    SetRect(rc, x, PALETTE_TOP, x + PALETTE_SIZE, PALETTE_TOP + PALETTE_SIZE);
}

// Canvas rectangle inside the client area
static void CanvasRect(HWND hwnd, RECT* rc)
{
    RECT client;
    GetClientRect(hwnd, &client);
    SetRect(rc, CANVAS_MARGIN, CANVAS_TOP,
            client.right - CANVAS_MARGIN,
            client.bottom - CANVAS_MARGIN - STATUS_HEIGHT);
}

// A random palette color for the "?" slot
static COLORREF RandomColor(void)
{
    return RGB(rand() % 256, rand() % 256, rand() % 256);
}

static void AddSegment(int x1, int y1, int x2, int y2)
{
    if (g_segments >= MAX_SEGMENTS)
    {
        return;
    }
    g_segx1[g_segments] = x1;
    g_segy1[g_segments] = y1;
    g_segx2[g_segments] = x2;
    g_segy2[g_segments] = y2;
    g_segcolor[g_segments] = g_color;
    g_segments++;
}

static void OnPaint(HWND hwnd)
{
    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(hwnd, &ps);
    RECT client;
    RECT canvas;
    RECT rc;
    HBRUSH black_brush;
    HBRUSH fill;
    HPEN framePen;
    HPEN oldPen;
    HBRUSH oldBrush;
    SYSTEMTIME now;
    char status[128];
    int i;

    GetClientRect(hwnd, &client);
    black_brush = (HBRUSH)GetStockObject(BLACK_BRUSH);
    SetBkMode(hdc, TRANSPARENT);

    // Toolbar strip behind the palette, with a coloured accent line
    SetRect(&rc, 0, 0, client.right, PALETTE_TOP + PALETTE_SIZE + PALETTE_TOP - 2);
    fill = CreateSolidBrush(RGB(238, 240, 244));
    FillRect(hdc, &rc, fill);
    DeleteObject(fill);
    SetRect(&rc, 0, rc.bottom, client.right, rc.bottom + 2);
    fill = CreateSolidBrush(RGB(0, 120, 160));
    FillRect(hdc, &rc, fill);
    DeleteObject(fill);

    // Palette swatches as rounded squares (last one is the random-color slot)
    framePen = CreatePen(PS_SOLID, 1, RGB(70, 70, 70));
    for (i = 0; i < PALETTE_COUNT; i++)
    {
        PaletteRect(i, &rc);
        oldPen = (HPEN)SelectObject(hdc, framePen);

        if (i < PALETTE_COUNT - 1)
        {
            fill = CreateSolidBrush(g_palette[i]);
            oldBrush = (HBRUSH)SelectObject(hdc, fill);
            RoundRect(hdc, rc.left, rc.top, rc.right, rc.bottom, 6, 6);
            SelectObject(hdc, oldBrush);
            DeleteObject(fill);
        }
        else
        {
            oldBrush = (HBRUSH)SelectObject(hdc, GetStockObject(WHITE_BRUSH));
            RoundRect(hdc, rc.left, rc.top, rc.right, rc.bottom, 6, 6);
            SelectObject(hdc, oldBrush);
            SetTextColor(hdc, RGB(0, 0, 0));
            TextOutA(hdc, rc.left + 11, rc.top + 7, "?", 1);
        }
        SelectObject(hdc, oldPen);

        // Highlight the selected slot with a thick accent frame
        if (i == g_selected)
        {
            HPEN selPen = CreatePen(PS_SOLID, 2, RGB(0, 120, 200));
            InflateRect(&rc, 3, 3);
            oldPen = (HPEN)SelectObject(hdc, selPen);
            oldBrush = (HBRUSH)SelectObject(hdc, GetStockObject(NULL_BRUSH));
            RoundRect(hdc, rc.left, rc.top, rc.right, rc.bottom, 8, 8);
            SelectObject(hdc, oldPen);
            SelectObject(hdc, oldBrush);
            DeleteObject(selPen);
        }
    }
    DeleteObject(framePen);

    // Canvas: a soft drop shadow, a white surface and a thin frame
    CanvasRect(hwnd, &canvas);
    rc = canvas;
    OffsetRect(&rc, 3, 3);
    fill = CreateSolidBrush(RGB(205, 208, 214));
    FillRect(hdc, &rc, fill);
    DeleteObject(fill);
    PatBlt(hdc, canvas.left, canvas.top,
           canvas.right - canvas.left, canvas.bottom - canvas.top, WHITENESS);
    FrameRect(hdc, &canvas, black_brush);

    // The drawing itself
    for (i = 0; i < g_segments; i++)
    {
        HPEN pen = CreatePen(PS_SOLID, 2, g_segcolor[i]);
        HPEN old_pen = (HPEN)SelectObject(hdc, pen);
        MoveToEx(hdc, g_segx1[i], g_segy1[i], NULL);
        LineTo(hdc, g_segx2[i], g_segy2[i]);
        SelectObject(hdc, old_pen);
        DeleteObject(pen);
    }

    // Status bar: clock, stroke count and usage hint
    SetRect(&rc, 0, canvas.bottom + 2, client.right, client.bottom);
    fill = CreateSolidBrush(RGB(238, 240, 244));
    FillRect(hdc, &rc, fill);
    DeleteObject(fill);

    GetLocalTime(&now);
    wsprintfA(status, "%02d:%02d:%02d  |  %d strokes  |  right-click clears",
              now.wHour, now.wMinute, now.wSecond, g_segments);
    SetTextColor(hdc, RGB(40, 40, 40));
    TextOutA(hdc, CANVAS_MARGIN, canvas.bottom + 5, status, lstrlenA(status));

    EndPaint(hwnd, &ps);
}

static void OnLeftDown(HWND hwnd, int x, int y)
{
    RECT rc;
    int i;

    // Palette click selects the pen color
    for (i = 0; i < PALETTE_COUNT; i++)
    {
        PaletteRect(i, &rc);
        if (PtInRect(&rc, (POINT){ x, y }))
        {
            g_selected = i;
            g_color = (i < PALETTE_COUNT - 1) ? g_palette[i] : RandomColor();
            InvalidateRect(hwnd, NULL, TRUE);
            return;
        }
    }

    // Canvas click starts a stroke
    CanvasRect(hwnd, &rc);
    if (PtInRect(&rc, (POINT){ x, y }))
    {
        g_drawing = TRUE;
        g_lastx = x;
        g_lasty = y;
        SetCapture(hwnd);
    }
}

static void OnMouseMove(HWND hwnd, WPARAM wParam, int x, int y)
{
    RECT rc;

    if (!g_drawing || !(wParam & MK_LBUTTON))
    {
        return;
    }

    // Only draw while the cursor stays on the canvas
    CanvasRect(hwnd, &rc);
    if (PtInRect(&rc, (POINT){ x, y }))
    {
        AddSegment(g_lastx, g_lasty, x, y);
        InvalidateRect(hwnd, NULL, FALSE);
    }
    g_lastx = x;
    g_lasty = y;
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
        case WM_PAINT:
            OnPaint(hwnd);
            return 0;

        case WM_LBUTTONDOWN:
            OnLeftDown(hwnd, (short)LOWORD(lParam), (short)HIWORD(lParam));
            return 0;

        case WM_MOUSEMOVE:
            OnMouseMove(hwnd, wParam, (short)LOWORD(lParam), (short)HIWORD(lParam));
            return 0;

        case WM_LBUTTONUP:
            if (g_drawing)
            {
                g_drawing = FALSE;
                ReleaseCapture();
            }
            return 0;

        case WM_RBUTTONDOWN:
            g_segments = 0;
            InvalidateRect(hwnd, NULL, TRUE);
            return 0;

        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }

    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow)
{
    WNDCLASSA wc;
    HWND hwnd;
    MSG msg;

    // Seed the random-color slot
    srand((unsigned int)time(NULL));

    ZeroMemory(&wc, sizeof(wc));
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    RegisterClassA(&wc);

    hwnd = CreateWindowExA(0, CLASS_NAME, "Paint Demo",
                           WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                           140, 90, 520, 420,
                           NULL, NULL, hInstance, NULL);
    if (hwnd == NULL)
    {
        return 1;
    }

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    while (GetMessageA(&msg, NULL, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }

    return (int)msg.wParam;
}
