#include <windows.h>

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
     MessageBoxA(NULL, "Hello, World!", "Hello", MB_OK | MB_ICONINFORMATION);
     return 0;
}