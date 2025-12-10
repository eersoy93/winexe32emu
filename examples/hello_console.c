#include <windows.h>

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
    if (!AllocConsole()) {
        return 1;
    }

    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    const char msg[] = "Hello, World!\r\n";
    DWORD written;
    WriteConsoleA(hOut, msg, (DWORD)(sizeof(msg) - 1), &written, NULL);

    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    char buf[16];
    DWORD read;
    ReadConsoleA(hIn, buf, sizeof(buf) - 1, &read, NULL);

    return 0;
}
