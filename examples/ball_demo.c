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
Ball demo - a small paddle-and-ball game showing the emulator's game-loop
features: a PeekMessageA-based real-time main loop, GetAsyncKeyState polling
(left/right arrows move the paddle), double buffering with
CreateCompatibleDC / CreateCompatibleBitmap / BitBlt, and Sleep-paced frames.

The rendering is dressed up with a vertical gradient background, a fading
ball trail, a glowing highlighted ball, a rounded paddle and a HUD bar.
Run with -n 0 (unlimited instructions).
*/

#include <windows.h>

static const char* CLASS_NAME = "BallDemoClass";

#define BALL_SIZE     24
#define PADDLE_W      96
#define PADDLE_H      14
#define PADDLE_MARGIN 26
#define TRAIL_LEN     8
#define HUD_H         34

/* Game state (integer math only) */
static int g_ball_x, g_ball_y;   /* Ball top-left corner */
static int g_ball_dx, g_ball_dy; /* Ball velocity per frame */
static int g_paddle_x;           /* Paddle left edge */
static int g_score;
static int g_misses;

/* Ring buffer of recent ball centres, used to draw a fading trail */
static int g_tx[TRAIL_LEN], g_ty[TRAIL_LEN];
static int g_thead = 0;
static int g_tcount = 0;

static void ResetBall(int client_w)
{
    g_ball_x = (client_w - BALL_SIZE) / 2;
    g_ball_y = HUD_H + 20;
    g_ball_dx = 4;
    g_ball_dy = 4;
    g_tcount = 0;
    g_thead = 0;
}

static void PushTrail(int cx, int cy)
{
    g_tx[g_thead] = cx;
    g_ty[g_thead] = cy;
    g_thead = (g_thead + 1) % TRAIL_LEN;
    if (g_tcount < TRAIL_LEN)
    {
        g_tcount++;
    }
}

/* Fill a rectangle with a smooth top-to-bottom gradient between two colours. */
static void GradientV(HDC hdc, int x, int y, int w, int h,
                      COLORREF c1, COLORREF c2)
{
    int r1 = GetRValue(c1), g1 = GetGValue(c1), b1 = GetBValue(c1);
    int r2 = GetRValue(c2), g2 = GetGValue(c2), b2 = GetBValue(c2);
    int i;

    for (i = 0; i < h; i += 2)
    {
        RECT rc;
        int r = r1 + (r2 - r1) * i / h;
        int g = g1 + (g2 - g1) * i / h;
        int b = b1 + (b2 - b1) * i / h;
        HBRUSH br = CreateSolidBrush(RGB(r, g, b));
        SetRect(&rc, x, y + i, x + w, y + i + 2);
        FillRect(hdc, &rc, br);
        DeleteObject(br);
    }
}

static void FillEllipse(HDC hdc, int cx, int cy, int radius, COLORREF color)
{
    HBRUSH br = CreateSolidBrush(color);
    HBRUSH old = (HBRUSH)SelectObject(hdc, br);
    HPEN pen = (HPEN)SelectObject(hdc, GetStockObject(NULL_PEN));
    Ellipse(hdc, cx - radius, cy - radius, cx + radius, cy + radius);
    SelectObject(hdc, pen);
    SelectObject(hdc, old);
    DeleteObject(br);
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
        case WM_PAINT:
        {
            /* Rendering happens in the game loop; just validate here */
            PAINTSTRUCT ps;
            BeginPaint(hwnd, &ps);
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

/* Draw one frame into the memory DC, then blit it to the window */
static void RenderFrame(HWND hwnd, HDC hdc, int cw, int ch)
{
    char buffer[80];
    int i;
    int bcx = g_ball_x + BALL_SIZE / 2;
    int bcy = g_ball_y + BALL_SIZE / 2;

    HDC memdc = CreateCompatibleDC(hdc);
    HBITMAP bmp = CreateCompatibleBitmap(hdc, cw, ch);
    HBITMAP oldbmp = (HBITMAP)SelectObject(memdc, bmp);
    RECT rc;
    HBRUSH hudBrush;
    HBRUSH paddleBrush;
    HPEN paddlePen;
    HPEN oldPen;
    HBRUSH oldBrush;

    SetBkMode(memdc, TRANSPARENT);

    /* Background gradient (deep blue at the top, lighter towards the floor) */
    GradientV(memdc, 0, 0, cw, ch, RGB(8, 14, 44), RGB(26, 60, 120));

    /* Fading ball trail: oldest and smallest first, newest on top */
    for (i = g_tcount - 1; i >= 1; i--)
    {
        int idx = (g_thead - 1 - i + 2 * TRAIL_LEN) % TRAIL_LEN;
        int strength = (g_tcount - i);            /* 1 .. g_tcount */
        int radius = 4 + (BALL_SIZE / 2 - 4) * strength / g_tcount;
        int lum = 40 + 150 * strength / g_tcount;
        FillEllipse(memdc, g_tx[idx], g_ty[idx], radius,
                    RGB(lum, (lum * 85) / 100, 24));
    }

    /* Ball: a soft glow, the bright body, then a small white highlight */
    FillEllipse(memdc, bcx, bcy, BALL_SIZE / 2 + 4, RGB(90, 80, 24));
    FillEllipse(memdc, bcx, bcy, BALL_SIZE / 2,     RGB(255, 208, 0));
    FillEllipse(memdc, bcx - 4, bcy - 4, 4,         RGB(255, 250, 220));

    /* Paddle: a rounded bar with a lighter top highlight */
    paddleBrush = CreateSolidBrush(RGB(228, 234, 245));
    paddlePen = CreatePen(PS_SOLID, 1, RGB(120, 150, 200));
    oldBrush = (HBRUSH)SelectObject(memdc, paddleBrush);
    oldPen = (HPEN)SelectObject(memdc, paddlePen);
    RoundRect(memdc, g_paddle_x, ch - PADDLE_MARGIN,
              g_paddle_x + PADDLE_W, ch - PADDLE_MARGIN + PADDLE_H, 8, 8);
    SelectObject(memdc, oldPen);
    SelectObject(memdc, oldBrush);
    DeleteObject(paddleBrush);
    DeleteObject(paddlePen);

    SetRect(&rc, g_paddle_x + 6, ch - PADDLE_MARGIN + 3,
            g_paddle_x + PADDLE_W - 6, ch - PADDLE_MARGIN + 6);
    hudBrush = CreateSolidBrush(RGB(255, 255, 255));
    FillRect(memdc, &rc, hudBrush);
    DeleteObject(hudBrush);

    /* HUD bar across the top */
    SetRect(&rc, 0, 0, cw, HUD_H);
    hudBrush = CreateSolidBrush(RGB(6, 10, 30));
    FillRect(memdc, &rc, hudBrush);
    DeleteObject(hudBrush);
    SetRect(&rc, 0, HUD_H - 1, cw, HUD_H);
    hudBrush = CreateSolidBrush(RGB(90, 160, 255));
    FillRect(memdc, &rc, hudBrush);
    DeleteObject(hudBrush);

    SetTextColor(memdc, RGB(120, 220, 140));
    wsprintfA(buffer, "Score %d", g_score);
    TextOutA(memdc, 12, 9, buffer, lstrlenA(buffer));
    SetTextColor(memdc, RGB(255, 150, 150));
    wsprintfA(buffer, "Misses %d", g_misses);
    TextOutA(memdc, 110, 9, buffer, lstrlenA(buffer));
    SetTextColor(memdc, RGB(180, 190, 210));
    TextOutA(memdc, cw - 210, 9, "arrows move  -  ESC quits", 25);

    /* Present the frame */
    BitBlt(hdc, 0, 0, cw, ch, memdc, 0, 0, SRCCOPY);

    /* Free GDI objects */
    SelectObject(memdc, oldbmp);
    DeleteObject(bmp);
    DeleteDC(memdc);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow)
{
    WNDCLASSA wc = {0};
    RECT client;
    int cw, ch;
    BOOL running = TRUE;

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
        0, CLASS_NAME, "Ball Demo",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        480, 360,
        NULL, NULL, hInstance, NULL);

    if (hwnd == NULL)
    {
        MessageBoxA(NULL, "Window could not be created!", "Error", MB_ICONERROR);
        return 1;
    }

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    GetClientRect(hwnd, &client);
    cw = client.right;
    ch = client.bottom;

    ResetBall(cw);
    g_paddle_x = (cw - PADDLE_W) / 2;

    /* Real-time game loop: drain messages, poll input, update, render */
    while (running)
    {
        MSG msg;
        while (PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE))
        {
            if (msg.message == WM_QUIT)
            {
                running = FALSE;
                break;
            }
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
        if (!running)
        {
            break;
        }

        /* Poll the keyboard (game-style input) */
        if (GetAsyncKeyState(VK_LEFT) & 0x8000)
        {
            g_paddle_x -= 8;
        }
        if (GetAsyncKeyState(VK_RIGHT) & 0x8000)
        {
            g_paddle_x += 8;
        }
        if (g_paddle_x < 0)
        {
            g_paddle_x = 0;
        }
        if (g_paddle_x > cw - PADDLE_W)
        {
            g_paddle_x = cw - PADDLE_W;
        }

        /* Move the ball and bounce off the walls */
        g_ball_x += g_ball_dx;
        g_ball_y += g_ball_dy;

        if (g_ball_x <= 0 || g_ball_x >= cw - BALL_SIZE)
        {
            g_ball_dx = -g_ball_dx;
        }
        if (g_ball_y <= HUD_H)
        {
            g_ball_dy = -g_ball_dy;
        }

        /* Paddle bounce or miss */
        int paddle_top = ch - PADDLE_MARGIN;
        if (g_ball_y + BALL_SIZE >= paddle_top && g_ball_dy > 0)
        {
            int ball_center = g_ball_x + BALL_SIZE / 2;
            if (ball_center >= g_paddle_x && ball_center <= g_paddle_x + PADDLE_W)
            {
                g_ball_dy = -g_ball_dy;
                g_ball_y = paddle_top - BALL_SIZE;
                g_score++;
            }
            else if (g_ball_y >= ch)
            {
                g_misses++;
                ResetBall(cw);
            }
        }

        /* Record the ball centre for the trail */
        PushTrail(g_ball_x + BALL_SIZE / 2, g_ball_y + BALL_SIZE / 2);

        /* Render the frame with double buffering */
        HDC hdc = GetDC(hwnd);
        RenderFrame(hwnd, hdc, cw, ch);
        ReleaseDC(hwnd, hdc);

        Sleep(16); /* ~60 FPS */
    }

    return 0;
}
