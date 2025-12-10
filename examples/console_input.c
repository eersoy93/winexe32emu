#include <windows.h>

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
     HANDLE hIn  = GetStdHandle(STD_INPUT_HANDLE);
     HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
     
     // Handle check
     if (hIn == INVALID_HANDLE_VALUE || hOut == INVALID_HANDLE_VALUE) {
          ExitProcess(1);
     }

     CHAR buf[4096];
     DWORD read = 0;

     // First try ReadConsole, if it fails use ReadFile
     if (!ReadConsoleA(hIn, buf, (DWORD)sizeof(buf) - 1, &read, NULL)) {
          DWORD actual = 0;
          if (!ReadFile(hIn, buf, (DWORD)sizeof(buf) - 1, &actual, NULL)) {
                ExitProcess(1);
          }
          read = actual;
     }

     // Remove trailing CR/LF characters
     while (read > 0 && (buf[read - 1] == '\n' || buf[read - 1] == '\r')) {
          --read;
     }

     // Write the read data
     DWORD written = 0;
     if (read > 0) {
          WriteFile(hOut, buf, read, &written, NULL);
     }

     ExitProcess(0);
     return 0;
}
