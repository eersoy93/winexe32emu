/*
Copyright 2025-2026 Erdem Ersoy (eersoy93)

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
File Manager - browses the emulated C drive and runs EXE files.

  - Double-click / Enter / Open: enter a folder, or run an EXE
  - Backspace / Up: go to the parent folder
  - F5 / Refresh: read the folder again
  - The status line shows the size and date of the selected entry

Usage: filemanager.exe [folder]  (default: C:\)
*/

#include <windows.h>
#include <stdlib.h>
#include <string.h>

#define ID_UP       101
#define ID_OPEN     102
#define ID_REFRESH  103
#define ID_PATH     104
#define ID_LIST     105
#define ID_STATUS   106

#define IDM_OPEN    201
#define IDM_UP      202
#define IDM_REFRESH 203
#define IDM_EXIT    204
#define IDM_ABOUT   205

#define BUTTON_W 70
#define BAR_H    28
#define STATUS_H 22

typedef struct {
    char name[MAX_PATH];
    DWORD attributes;
    DWORD size;
    FILETIME modified;
} Entry;

static HWND hMain, hPath, hList, hStatus;
static char current[MAX_PATH] = "C:\\";
static Entry *entries;
static int entry_count, entry_capacity;
static int has_parent;  /* entries[0] is ".." */

static int is_dir(const Entry *e)
{
    return (e->attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

static int is_exe(const char *name)
{
    size_t n = strlen(name);
    return n > 4 && lstrcmpiA(name + n - 4, ".exe") == 0;
}

static int is_root(const char *path)
{
    return lstrlenA(path) <= 3;  /* "C:\" */
}

/* Folders first, then files; both by name, case-insensitive */
static int compare_entries(const void *a, const void *b)
{
    const Entry *x = a, *y = b;
    if (is_dir(x) != is_dir(y))
        return is_dir(x) ? -1 : 1;
    return lstrcmpiA(x->name, y->name);
}

static void join_path(char *out, const char *folder, const char *name)
{
    if (out != folder)
        lstrcpyA(out, folder);
    if (out[lstrlenA(out) - 1] != '\\')
        lstrcatA(out, "\\");
    lstrcatA(out, name);
}

/* 1234567 -> "1,234,567" */
static void format_number(char *out, DWORD value)
{
    char digits[16];
    int len, i, j = 0;
    wsprintfA(digits, "%lu", (unsigned long)value);
    len = lstrlenA(digits);
    for (i = 0; i < len; i++) {
        if (i > 0 && (len - i) % 3 == 0)
            out[j++] = ',';
        out[j++] = digits[i];
    }
    out[j] = '\0';
}

static void format_time(char *out, const FILETIME *ft)
{
    FILETIME local;
    SYSTEMTIME st;
    if (!FileTimeToLocalFileTime(ft, &local) || !FileTimeToSystemTime(&local, &st)) {
        lstrcpyA(out, "?");
        return;
    }
    wsprintfA(out, "%04d-%02d-%02d %02d:%02d", st.wYear, st.wMonth, st.wDay,
              st.wHour, st.wMinute);
}

static int add_entry(const WIN32_FIND_DATAA *fd)
{
    if (entry_count == entry_capacity) {
        int capacity = entry_capacity ? entry_capacity * 2 : 64;
        Entry *grown = realloc(entries, capacity * sizeof(Entry));
        if (!grown)
            return 0;
        entries = grown;
        entry_capacity = capacity;
    }
    lstrcpynA(entries[entry_count].name, fd->cFileName, MAX_PATH);
    entries[entry_count].attributes = fd->dwFileAttributes;
    entries[entry_count].size = fd->nFileSizeLow;
    entries[entry_count].modified = fd->ftLastWriteTime;
    entry_count++;
    return 1;
}

/* Summary of the folder, or the details of the selected entry */
static void update_status(void)
{
    char text[MAX_PATH + 96], number[32], date[32];
    int sel = (int)SendMessageA(hList, LB_GETCURSEL, 0, 0);
    if (sel == LB_ERR || sel >= entry_count || (has_parent && sel == 0)) {
        int i, folders = 0, files = 0;
        DWORD total = 0;
        for (i = has_parent; i < entry_count; i++) {
            if (is_dir(&entries[i])) {
                folders++;
            } else {
                files++;
                total += entries[i].size;
            }
        }
        format_number(number, total);
        wsprintfA(text, "%s%d folder(s), %d file(s), %s bytes",
                  (has_parent && sel == 0) ? "Parent folder - here: " : "",
                  folders, files, number);
    } else {
        const Entry *e = &entries[sel];
        format_time(date, &e->modified);
        if (is_dir(e)) {
            wsprintfA(text, "%s - folder, modified %s", e->name, date);
        } else {
            format_number(number, e->size);
            wsprintfA(text, "%s - %s bytes, modified %s%s", e->name, number, date,
                      is_exe(e->name) ? " (program)" : "");
        }
    }
    SetWindowTextA(hStatus, text);
}

/* Read the current folder into the list; select is a name to select or NULL */
static void load_folder(const char *select)
{
    char pattern[MAX_PATH], title[MAX_PATH + 32], label[MAX_PATH + 4];
    WIN32_FIND_DATAA fd;
    HANDLE hFind;
    int i, sel = -1;

    entry_count = 0;
    has_parent = !is_root(current);
    if (has_parent) {
        memset(&fd, 0, sizeof(fd));
        lstrcpyA(fd.cFileName, "..");
        fd.dwFileAttributes = FILE_ATTRIBUTE_DIRECTORY;
        add_entry(&fd);
    }

    join_path(pattern, current, "*");
    hFind = FindFirstFileA(pattern, &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (lstrcmpA(fd.cFileName, ".") == 0 || lstrcmpA(fd.cFileName, "..") == 0)
                continue;
            if (!add_entry(&fd))
                break;
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }
    qsort(entries + has_parent, entry_count - has_parent, sizeof(Entry), compare_entries);

    SendMessageA(hList, LB_RESETCONTENT, 0, 0);
    for (i = 0; i < entry_count; i++) {
        if (is_dir(&entries[i]))
            wsprintfA(label, "[%s]", entries[i].name);
        else
            lstrcpyA(label, entries[i].name);
        SendMessageA(hList, LB_ADDSTRING, 0, (LPARAM)label);
        if (select && lstrcmpiA(entries[i].name, select) == 0)
            sel = i;
    }
    if (sel < 0 && entry_count > 0)
        sel = 0;
    if (sel >= 0)
        SendMessageA(hList, LB_SETCURSEL, sel, 0);

    SetWindowTextA(hPath, current);
    wsprintfA(title, "File Manager - %s", current);
    SetWindowTextA(hMain, title);
    update_status();
}

static void go_up(void)
{
    char *slash, child[MAX_PATH];
    if (is_root(current))
        return;
    slash = strrchr(current, '\\');
    if (!slash)
        return;
    lstrcpyA(child, slash + 1);
    if (slash - current == 2)
        slash[1] = '\0';  /* Keep "C:\" */
    else
        *slash = '\0';
    load_folder(child);  /* The folder we came from stays selected */
}

static void run_program(const Entry *e)
{
    char path[MAX_PATH], command[MAX_PATH + 2], message[MAX_PATH + 64];
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    join_path(path, current, e->name);
    wsprintfA(command, "\"%s\"", path);
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    if (CreateProcessA(path, command, NULL, NULL, FALSE, 0, NULL, current, &si, &pi)) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    } else {
        wsprintfA(message, "Cannot run %s (error %lu).", path, (unsigned long)GetLastError());
        MessageBoxA(hMain, message, "File Manager", MB_OK | MB_ICONERROR);
    }
}

static void open_selected(void)
{
    char message[MAX_PATH + 160], number[32], date[32];
    const Entry *e;
    int sel = (int)SendMessageA(hList, LB_GETCURSEL, 0, 0);
    if (sel == LB_ERR || sel >= entry_count)
        return;
    e = &entries[sel];
    if (has_parent && sel == 0) {
        go_up();
    } else if (is_dir(e)) {
        join_path(current, current, e->name);
        load_folder(NULL);
    } else if (is_exe(e->name)) {
        run_program(e);
    } else {
        format_number(number, e->size);
        format_time(date, &e->modified);
        wsprintfA(message, "%s\n\nSize: %s bytes\nModified: %s\n\nOnly EXE files can be opened.",
                  e->name, number, date);
        MessageBoxA(hMain, message, "File Manager", MB_OK | MB_ICONINFORMATION);
    }
}

static void move_selection(int delta)
{
    int count = (int)SendMessageA(hList, LB_GETCOUNT, 0, 0);
    int sel = (int)SendMessageA(hList, LB_GETCURSEL, 0, 0);
    if (count <= 0)
        return;
    sel = (sel == LB_ERR) ? 0 : sel + delta;
    if (sel < 0)
        sel = 0;
    if (sel >= count)
        sel = count - 1;
    SendMessageA(hList, LB_SETCURSEL, sel, 0);
    update_status();
}

static void refresh(void)
{
    char name[MAX_PATH] = "";
    int sel = (int)SendMessageA(hList, LB_GETCURSEL, 0, 0);
    if (sel != LB_ERR && sel < entry_count)
        lstrcpyA(name, entries[sel].name);
    load_folder(name);
}

static void layout(int width, int height)
{
    int list_y = BAR_H + 4;
    MoveWindow(GetDlgItem(hMain, ID_UP), 4, 4, BUTTON_W, BAR_H - 4, TRUE);
    MoveWindow(GetDlgItem(hMain, ID_OPEN), 8 + BUTTON_W, 4, BUTTON_W, BAR_H - 4, TRUE);
    MoveWindow(GetDlgItem(hMain, ID_REFRESH), 12 + 2 * BUTTON_W, 4, BUTTON_W, BAR_H - 4, TRUE);
    MoveWindow(hPath, 20 + 3 * BUTTON_W, 8, width - 24 - 3 * BUTTON_W, BAR_H - 8, TRUE);
    MoveWindow(hList, 4, list_y, width - 8, height - list_y - STATUS_H - 6, TRUE);
    MoveWindow(hStatus, 4, height - STATUS_H - 2, width - 8, STATUS_H, TRUE);
}

static HMENU create_menu(void)
{
    HMENU menu = CreateMenu(), file = CreatePopupMenu(), help = CreatePopupMenu();
    AppendMenuA(file, MF_STRING, IDM_OPEN, "&Open\tEnter");
    AppendMenuA(file, MF_STRING, IDM_UP, "&Up One Level\tBackspace");
    AppendMenuA(file, MF_STRING, IDM_REFRESH, "&Refresh\tF5");
    AppendMenuA(file, MF_SEPARATOR, 0, NULL);
    AppendMenuA(file, MF_STRING, IDM_EXIT, "E&xit");
    AppendMenuA(help, MF_STRING, IDM_ABOUT, "&About File Manager");
    AppendMenuA(menu, MF_POPUP, (UINT_PTR)file, "&File");
    AppendMenuA(menu, MF_POPUP, (UINT_PTR)help, "&Help");
    return menu;
}

static HWND create_child(const char *cls, DWORD ex_style, DWORD style, int id)
{
    return CreateWindowExA(ex_style, cls, "", WS_CHILD | WS_VISIBLE | style, 0, 0, 0, 0,
                           hMain, (HMENU)(INT_PTR)id, GetModuleHandleA(NULL), NULL);
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    RECT rc;
    switch (msg) {
    case WM_CREATE:
        hMain = hwnd;
        SetWindowTextA(create_child("BUTTON", 0, BS_PUSHBUTTON, ID_UP), "Up");
        SetWindowTextA(create_child("BUTTON", 0, BS_PUSHBUTTON, ID_OPEN), "Open");
        SetWindowTextA(create_child("BUTTON", 0, BS_PUSHBUTTON, ID_REFRESH), "Refresh");
        hPath = create_child("STATIC", 0, 0, ID_PATH);
        hList = create_child("LISTBOX", WS_EX_CLIENTEDGE, WS_VSCROLL | LBS_NOTIFY, ID_LIST);
        hStatus = create_child("STATIC", 0, 0, ID_STATUS);
        GetClientRect(hwnd, &rc);
        layout(rc.right, rc.bottom);
        load_folder(NULL);
        return 0;

    case WM_SIZE:
        if (hList)
            layout(LOWORD(lParam), HIWORD(lParam));
        return 0;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case ID_LIST:
            if (HIWORD(wParam) == LBN_DBLCLK)
                open_selected();
            else if (HIWORD(wParam) == LBN_SELCHANGE)
                update_status();
            break;
        case ID_OPEN:
        case IDM_OPEN:
            open_selected();
            break;
        case ID_UP:
        case IDM_UP:
            go_up();
            break;
        case ID_REFRESH:
        case IDM_REFRESH:
            refresh();
            break;
        case IDM_EXIT:
            DestroyWindow(hwnd);
            break;
        case IDM_ABOUT:
            MessageBoxA(hwnd, "File Manager for winexe32emu\n\n"
                        "Double-click a folder to open it, or an EXE file to run it.",
                        "About File Manager", MB_OK | MB_ICONINFORMATION);
            break;
        }
        return 0;

    case WM_KEYDOWN:
        switch (wParam) {
        case VK_RETURN: open_selected(); break;
        case VK_BACK:   go_up(); break;
        case VK_F5:     refresh(); break;
        case VK_UP:     move_selection(-1); break;
        case VK_DOWN:   move_selection(1); break;
        case VK_PRIOR:  move_selection(-10); break;
        case VK_NEXT:   move_selection(10); break;
        case VK_HOME:   move_selection(-entry_count); break;
        case VK_END:    move_selection(entry_count); break;
        }
        return 0;

    case WM_DESTROY:
        free(entries);
        entries = NULL;
        entry_count = entry_capacity = 0;
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

/* Start folder from the command line, if it names an existing folder */
static void read_start_folder(const char *cmdline)
{
    char folder[MAX_PATH], full[MAX_PATH];
    DWORD attributes;
    int len;
    while (*cmdline == ' ')
        cmdline++;
    lstrcpynA(folder, *cmdline == '"' ? cmdline + 1 : cmdline, MAX_PATH);
    len = lstrlenA(folder);
    while (len > 0 && (folder[len - 1] == '"' || folder[len - 1] == ' '))
        folder[--len] = '\0';
    if (len == 0 || !GetFullPathNameA(folder, MAX_PATH, full, NULL))
        return;
    attributes = GetFileAttributesA(full);
    if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY))
        return;
    len = lstrlenA(full);
    if (len > 3 && full[len - 1] == '\\')
        full[len - 1] = '\0';
    lstrcpyA(current, full);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    WNDCLASSA wc;
    MSG msg;
    HWND hwnd;

    read_start_folder(lpCmdLine);

    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursorA(NULL, IDC_ARROW);
    wc.hIcon = LoadIconA(NULL, IDI_APPLICATION);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = "WinExe32EmuFileManager";
    if (!RegisterClassA(&wc))
        return 1;

    hwnd = CreateWindowExA(0, wc.lpszClassName, "File Manager", WS_OVERLAPPEDWINDOW,
                           CW_USEDEFAULT, CW_USEDEFAULT, 560, 420,
                           NULL, create_menu(), hInstance, NULL);
    if (!hwnd)
        return 1;
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    while (GetMessageA(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }
    return (int)msg.wParam;
}
