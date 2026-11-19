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
Windows Help (WINHLP32.EXE) - the program setups and shortcuts start for Help
files. There is no Help viewer yet:

  - winhlp32 -S file.hlp / -G file.hlp: set up a Help file (Microsoft Office
    95 Setup runs this and waits for it). The file's folder is entered under
    HKLM\SOFTWARE\Microsoft\Windows\Help, like Windows Help does, and the
    program ends with exit code 0 without a window.
  - winhlp32 [-H] [-I topic] [-N number] [-K keyword] [-P] [file.hlp]: show a
    Help file. A message box tells that Help files cannot be shown.

Usage: winhlp32.exe [options] [file.hlp]
*/

#include <windows.h>
#include <string.h>

#define HELP_FILES_KEY "SOFTWARE\\Microsoft\\Windows\\Help"

/* Next space separated (or quoted) word of *line, copied to word; NULL at the end */
static char *next_word(char **line, char *word, size_t size)
{
    char *p = *line;
    size_t n = 0;

    while (*p == ' ' || *p == '\t') {
        p++;
    }
    if (*p == '\0') {
        return NULL;
    }
    if (*p == '"') {
        p++;
        while (*p && *p != '"') {
            if (n + 1 < size) {
                word[n++] = *p;
            }
            p++;
        }
        if (*p == '"') {
            p++;
        }
    } else {
        while (*p && *p != ' ' && *p != '\t') {
            if (n + 1 < size) {
                word[n++] = *p;
            }
            p++;
        }
    }
    word[n] = '\0';
    *line = p;
    return word;
}

/* Enter the folder of a Help file under HKLM\...\Windows\Help (value: its file name) */
static void register_help_file(const char *path)
{
    char full[MAX_PATH];
    char *name = NULL;
    HKEY key;

    if (!GetFullPathNameA(path, sizeof(full), full, &name) || name == NULL || name == full) {
        return;
    }
    name[-1] = '\0';  /* full: the folder, name: the file name */
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, HELP_FILES_KEY, 0, NULL, 0, KEY_SET_VALUE, NULL, &key,
                        NULL) == ERROR_SUCCESS) {
        RegSetValueExA(key, name, 0, REG_SZ, (const BYTE *)full, (DWORD)strlen(full) + 1);
        RegCloseKey(key);
    }
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
    char word[MAX_PATH];
    char file[MAX_PATH] = "";
    char message[MAX_PATH + 160];
    char *line = lpCmdLine;
    BOOL setup = FALSE;

    while (next_word(&line, word, sizeof(word)) != NULL) {
        if (word[0] == '-' || word[0] == '/') {
            char option = word[1] >= 'a' && word[1] <= 'z' ? (char)(word[1] - 'a' + 'A') : word[1];
            if (option == 'S' || option == 'G') {
                setup = TRUE;
            } else if ((option == 'I' || option == 'N' || option == 'K') && word[2] == '\0') {
                next_word(&line, word, sizeof(word));  /* The topic, number or keyword */
            }
        } else {
            lstrcpynA(file, word, sizeof(file));
        }
    }

    if (setup) {
        if (file[0]) {
            register_help_file(file);
        }
        return 0;
    }

    if (file[0]) {
        wsprintfA(message, "Cannot show the Help file\n%s\n\n"
                  "Windows Help cannot show Help files in the emulator yet.", file);
    } else {
        lstrcpyA(message, "Windows Help cannot show Help files in the emulator yet.");
    }
    MessageBoxA(NULL, message, "Windows Help", MB_OK | MB_ICONINFORMATION);
    return 0;
}
