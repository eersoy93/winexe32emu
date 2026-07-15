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
Ball demo - a small paddle-and-ball game showing the emulator's
game loop features: PeekMessageA-based real-time main loop,
GetAsyncKeyState polling (left/right arrows move the paddle),
double buffering with CreateCompatibleDC/CreateCompatibleBitmap/BitBlt,
and Sleep-paced frames. Run with -n 0 (unlimited instructions).
*/

#include <windows.h>

static const char* CLASS_NAME = "BallDemoClass";

#define BALL_SIZE   24
#define PADDLE_W    90
#define PADDLE_H    12
#define PADDLE_MARGIN 24

/* Game state (integer math only) */
static int g_ball_x, g_ball_y;   /* Ball top-left corner */
static int g_ball_dx, g_ball_dy; /* Ball velocity per frame */
static int g_paddle_x;           /* Paddle left edge */
static int g_score;
static int g_misses;

static void ResetBall(int client_w)
{
    g_ball_x = (client_w - BALL_SIZE) / 2;
    g_ball_y = 40;
    g_ball_dx = 4;
    g_ball_dy = 4;
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
    char buffer[64];

    HDC memdc = CreateCompatibleDC(hdc);
    HBITMAP bmp = CreateCompatibleBitmap(hdc, cw, ch);
    HBITMAP oldbmp = (HBITMAP)SelectObject(memdc, bmp);

    /* Background */
    RECT rc;
    rc.left = 0; rc.top = 0; rc.right = cw; rc.bottom = ch;
    HBRUSH bg = CreateSolidBrush(RGB(0, 32, 96));
    FillRect(memdc, &rc, bg);

    /* Ball */
    HBRUSH ballBrush = CreateSolidBrush(RGB(255, 208, 0));
    HBRUSH oldBrush = (HBRUSH)SelectObject(memdc, ballBrush);
    Ellipse(memdc, g_ball_x, g_ball_y,
            g_ball_x + BALL_SIZE, g_ball_y + BALL_SIZE);

    /* Paddle */
    HBRUSH paddleBrush = CreateSolidBrush(RGB(240, 240, 240));
    SelectObject(memdc, paddleBrush);
    Rectangle(memdc, g_paddle_x, ch - PADDLE_MARGIN,
              g_paddle_x + PADDLE_W, ch - PADDLE_MARGIN + PADDLE_H);

    /* Score line */
    wsprintfA(buffer, "Score: %d   Misses: %d   (arrows move, ESC quits)",
              g_score, g_misses);
    SetTextColor(memdc, RGB(255, 255, 255));
    TextOutA(memdc, 10, 8, buffer, lstrlenA(buffer));

    /* Present the frame */
    BitBlt(hdc, 0, 0, cw, ch, memdc, 0, 0, SRCCOPY);

    /* Free GDI objects */
    SelectObject(memdc, oldBrush);
    SelectObject(memdc, oldbmp);
    DeleteObject(bg);
    DeleteObject(ballBrush);
    DeleteObject(paddleBrush);
    DeleteObject(bmp);
    DeleteDC(memdc);
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

    /* Client area size */
    RECT client;
    GetClientRect(hwnd, &client);
    int cw = client.right;
    int ch = client.bottom;

    ResetBall(cw);
    g_paddle_x = (cw - PADDLE_W) / 2;

    /* Real-time game loop: drain messages, poll input, update, render */
    BOOL running = TRUE;
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
        if (g_ball_y <= 0)
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

        /* Render the frame with double buffering */
        HDC hdc = GetDC(hwnd);
        RenderFrame(hwnd, hdc, cw, ch);
        ReleaseDC(hwnd, hdc);

        Sleep(16); /* ~60 FPS */
    }

    return 0;
}
