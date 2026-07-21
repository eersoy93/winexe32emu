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
Scroll demo - SCROLLBAR controls, StretchBlt and GetPixel in one program:
a small scene is drawn into a memory DC and StretchBlt-scaled into the
window. The horizontal scrollbar zooms the scene (50%..250%), the
vertical scrollbar pans it up and down. WM_HSCROLL/WM_VSCROLL handle
the SB_LINE, SB_PAGE and SB_THUMBTRACK codes with SetScrollPos and
GetScrollPos, and GetPixel probes the color under the scene's center
for the status line.
*/

#include <windows.h>

static const char* CLASS_NAME = "ScrollDemoClass";

// Control identifiers
#define IDC_VSCROLL 101
#define IDC_HSCROLL 102

// Source scene size in the memory DC
#define SCENE_W 200
#define SCENE_H 150

// Canvas placement in the client area
#define CANVAS_X 8
#define CANVAS_Y 8

static HWND g_vscroll = NULL;
static HWND g_hscroll = NULL;

static int g_zoom_pos = 25;  // 0..100 -> zoom 50%..250%
static int g_pan_pos = 0;    // 0..100 -> vertical pan in pixels

// Draw the source scene into a DC (coordinates are scene-local)
static void DrawScene(HDC hdc)
{
    HBRUSH brush;
    HPEN pen;
    HPEN old_pen;
    POINT roof[3];
    RECT rc;

    // Sky
    SetRect(&rc, 0, 0, SCENE_W, SCENE_H);
    brush = CreateSolidBrush(RGB(170, 210, 255));
    FillRect(hdc, &rc, brush);
    DeleteObject(brush);

    // Grass
    SetRect(&rc, 0, SCENE_H - 40, SCENE_W, SCENE_H);
    brush = CreateSolidBrush(RGB(90, 180, 90));
    FillRect(hdc, &rc, brush);
    DeleteObject(brush);

    // Sun
    brush = CreateSolidBrush(RGB(255, 220, 0));
    SelectObject(hdc, brush);
    Ellipse(hdc, SCENE_W - 60, 10, SCENE_W - 15, 55);
    DeleteObject(brush);

    // Clouds
    brush = CreateSolidBrush(RGB(255, 255, 255));
    SelectObject(hdc, brush);
    Ellipse(hdc, 20, 20, 60, 40);
    Ellipse(hdc, 40, 14, 82, 38);
    Ellipse(hdc, 62, 22, 98, 42);
    DeleteObject(brush);

    // House body
    brush = CreateSolidBrush(RGB(220, 120, 60));
    SelectObject(hdc, brush);
    Rectangle(hdc, 40, 70, 120, 130);
    DeleteObject(brush);

    // Roof
    roof[0].x = 30;  roof[0].y = 70;
    roof[1].x = 80;  roof[1].y = 35;
    roof[2].x = 130; roof[2].y = 70;
    brush = CreateSolidBrush(RGB(160, 40, 40));
    SelectObject(hdc, brush);
    Polygon(hdc, roof, 3);
    DeleteObject(brush);

    // Door
    brush = CreateSolidBrush(RGB(90, 60, 30));
    SelectObject(hdc, brush);
    Rectangle(hdc, 70, 95, 90, 130);
    DeleteObject(brush);

    // Window with a cross frame
    brush = CreateSolidBrush(RGB(180, 220, 255));
    SelectObject(hdc, brush);
    Rectangle(hdc, 96, 82, 114, 102);
    DeleteObject(brush);
    pen = CreatePen(PS_SOLID, 1, RGB(80, 60, 30));
    old_pen = (HPEN)SelectObject(hdc, pen);
    MoveToEx(hdc, 105, 82, NULL);
    LineTo(hdc, 105, 102);
    MoveToEx(hdc, 96, 92, NULL);
    LineTo(hdc, 114, 92);
    SelectObject(hdc, old_pen);
    DeleteObject(pen);

    // Fence line
    pen = CreatePen(PS_SOLID, 2, RGB(255, 255, 255));
    old_pen = (HPEN)SelectObject(hdc, pen);
    MoveToEx(hdc, 0, SCENE_H - 20, NULL);
    LineTo(hdc, SCENE_W, SCENE_H - 20);
    SelectObject(hdc, old_pen);
    DeleteObject(pen);
}

static void OnPaint(HWND hwnd)
{
    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(hwnd, &ps);
    HDC memdc;
    HBITMAP bitmap;
    HBITMAP old_bitmap;
    COLORREF probe;
    char status[160];
    int zoom;      // Percent
    int dst_w;
    int dst_h;
    int dst_y;
    int probe_x;
    int probe_y;

    // Render the scene off-screen
    memdc = CreateCompatibleDC(hdc);
    bitmap = CreateCompatibleBitmap(hdc, SCENE_W, SCENE_H);
    old_bitmap = (HBITMAP)SelectObject(memdc, bitmap);
    DrawScene(memdc);

    // Zoom from the horizontal scrollbar, pan from the vertical one
    zoom = 50 + g_zoom_pos * 2;
    dst_w = SCENE_W * zoom / 100;
    dst_h = SCENE_H * zoom / 100;
    dst_y = CANVAS_Y - g_pan_pos;

    StretchBlt(hdc, CANVAS_X, dst_y, dst_w, dst_h,
               memdc, 0, 0, SCENE_W, SCENE_H, SRCCOPY);

    SelectObject(memdc, old_bitmap);
    DeleteObject(bitmap);
    DeleteDC(memdc);

    // Probe the color at the center of the scaled scene
    probe_x = CANVAS_X + dst_w / 2;
    probe_y = dst_y + dst_h / 2;
    probe = GetPixel(hdc, probe_x, probe_y);

    // Status bar strip along the bottom
    {
        RECT client;
        RECT bar;
        HBRUSH strip;
        GetClientRect(hwnd, &client);
        SetRect(&bar, 0, 356, client.right, client.bottom);
        strip = CreateSolidBrush(RGB(238, 240, 244));
        FillRect(hdc, &bar, strip);
        DeleteObject(strip);
    }

    wsprintfA(status, "zoom %d%%  |  pan %d px  |  pixel(%d,%d) = RGB(%d,%d,%d)",
              zoom, g_pan_pos, probe_x, probe_y,
              (int)GetRValue(probe), (int)GetGValue(probe), (int)GetBValue(probe));
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, RGB(40, 40, 40));
    TextOutA(hdc, 8, 362, status, lstrlenA(status));

    EndPaint(hwnd, &ps);
}

// Shared handler for both scrollbars; returns the updated position
static int HandleScroll(HWND scrollbar, WPARAM wParam, int page)
{
    int pos = GetScrollPos(scrollbar, SB_CTL);

    switch (LOWORD(wParam))
    {
        case SB_LINEUP:        pos -= 1;                       break;
        case SB_LINEDOWN:      pos += 1;                       break;
        case SB_PAGEUP:        pos -= page;                    break;
        case SB_PAGEDOWN:      pos += page;                    break;
        case SB_THUMBTRACK:
        case SB_THUMBPOSITION: pos = (short)HIWORD(wParam);    break;
        default:               return pos;
    }

    if (pos < 0)
    {
        pos = 0;
    }
    if (pos > 100)
    {
        pos = 100;
    }
    SetScrollPos(scrollbar, SB_CTL, pos, TRUE);
    return pos;
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
        case WM_CREATE:
            g_vscroll = CreateWindowExA(0, "SCROLLBAR", "",
                                        WS_CHILD | WS_VISIBLE | SBS_VERT,
                                        526, 8, 16, 340,
                                        hwnd, (HMENU)IDC_VSCROLL, NULL, NULL);
            g_hscroll = CreateWindowExA(0, "SCROLLBAR", "",
                                        WS_CHILD | WS_VISIBLE | SBS_HORZ,
                                        8, 336, 510, 16,
                                        hwnd, (HMENU)IDC_HSCROLL, NULL, NULL);
            SetScrollRange(g_vscroll, SB_CTL, 0, 100, FALSE);
            SetScrollRange(g_hscroll, SB_CTL, 0, 100, FALSE);
            SetScrollPos(g_vscroll, SB_CTL, g_pan_pos, FALSE);
            SetScrollPos(g_hscroll, SB_CTL, g_zoom_pos, FALSE);
            return 0;

        case WM_VSCROLL:
            if ((HWND)lParam == g_vscroll)
            {
                g_pan_pos = HandleScroll(g_vscroll, wParam, 10);
                InvalidateRect(hwnd, NULL, TRUE);
            }
            return 0;

        case WM_HSCROLL:
            if ((HWND)lParam == g_hscroll)
            {
                g_zoom_pos = HandleScroll(g_hscroll, wParam, 10);
                InvalidateRect(hwnd, NULL, TRUE);
            }
            return 0;

        case WM_PAINT:
            OnPaint(hwnd);
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

    ZeroMemory(&wc, sizeof(wc));
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    RegisterClassA(&wc);

    hwnd = CreateWindowExA(0, CLASS_NAME, "Scroll Demo",
                           WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                           120, 80, 560, 420,
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
