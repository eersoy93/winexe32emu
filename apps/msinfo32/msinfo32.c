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
winexe32emu System Info (MSINFO32.EXE) - the emulator's System Information
program, compiled into C:\Windows\System32 like the msinfo32.exe of Windows
(see install_dir). A window
with a category list and the information of the chosen category:

  - System: Windows version, computer and user name, processor, folders
  - Display: screen size, colors, DPI
  - Memory: physical memory and the page file
  - Drives: type, file system, label, size and free space of each drive
  - Fonts: the font families
  - Running Applications: the titles of the top-level windows

The command line options of Office's MSINFO32 (/MSINFO_...) are accepted and
ignored, so it never fails on them.

Usage: msinfo32.exe [options]
*/

#include <windows.h>
#include <stdio.h>
#include <string.h>

#define ID_CATEGORY 100
#define ID_INFO 101
#define IDM_EXIT 200
#define IDM_ABOUT 201

#define MARGIN 8
#define COMBO_HEIGHT 160
#define LABEL_HEIGHT 16

static const char *const categories[] = {
    "System", "Display", "Memory", "Drives", "Fonts", "Running Applications"
};
#define CATEGORY_COUNT (sizeof(categories) / sizeof(categories[0]))

static HWND category_box, info_box, category_label;
static HFONT gui_font;

/* Append a "name: value" line (value printf-formatted) to the information list */
static void add_line(const char *name, const char *format, ...)
{
    char value[512], line[640];
    va_list args;
    va_start(args, format);
    vsnprintf(value, sizeof(value), format, args);
    va_end(args);
    if (name && *name)
        snprintf(line, sizeof(line), "%s: %s", name, value);
    else
        snprintf(line, sizeof(line), "%s", value);
    SendMessageA(info_box, LB_ADDSTRING, 0, (LPARAM)line);
}

/* Bytes as KB or MB, like "65,536 KB" */
static void format_size(char *out, size_t size, unsigned long long bytes)
{
    unsigned long long kb = bytes / 1024;
    if (kb >= 10 * 1024)
        snprintf(out, size, "%llu MB", kb / 1024);
    else
        snprintf(out, size, "%llu KB", kb);
}

static void show_system(void)
{
    OSVERSIONINFOA version;
    SYSTEM_INFO info;
    char text[MAX_PATH];
    DWORD size;
    const char *platform = "Windows";

    version.dwOSVersionInfoSize = sizeof(version);
    if (GetVersionExA(&version)) {
        if (version.dwPlatformId == VER_PLATFORM_WIN32_NT)
            platform = "Windows NT";
        else if (version.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS)
            platform = "Windows 95";
        add_line("Operating System", "%s %lu.%lu (Build %lu) %s", platform,
                 version.dwMajorVersion, version.dwMinorVersion,
                 version.dwBuildNumber & 0xFFFF, version.szCSDVersion);
    }
    size = sizeof(text);
    if (GetComputerNameA(text, &size))
        add_line("Computer Name", "%s", text);
    size = sizeof(text);
    if (GetUserNameA(text, &size))
        add_line("User Name", "%s", text);

    GetSystemInfo(&info);
    switch (info.wProcessorArchitecture) {
    case PROCESSOR_ARCHITECTURE_INTEL:
        add_line("Processor", "Intel x86 compatible, level %u, revision %04X",
                 info.wProcessorLevel, info.wProcessorRevision);
        break;
    default:
        add_line("Processor", "Architecture %u", info.wProcessorArchitecture);
        break;
    }
    add_line("Number of Processors", "%lu", info.dwNumberOfProcessors);
    add_line("Page Size", "%lu bytes", info.dwPageSize);

    if (GetWindowsDirectoryA(text, sizeof(text)))
        add_line("Windows Folder", "%s", text);
    if (GetSystemDirectoryA(text, sizeof(text)))
        add_line("System Folder", "%s", text);
    if (GetTempPathA(sizeof(text), text))
        add_line("Temporary Folder", "%s", text);
    if (GetCurrentDirectoryA(sizeof(text), text))
        add_line("Current Folder", "%s", text);
}

static void show_display(void)
{
    HDC dc = GetDC(NULL);
    int bits = GetDeviceCaps(dc, BITSPIXEL) * GetDeviceCaps(dc, PLANES);

    add_line("Resolution", "%d x %d", GetSystemMetrics(SM_CXSCREEN),
             GetSystemMetrics(SM_CYSCREEN));
    if (bits >= 24)
        add_line("Colors", "True Color (%d bits per pixel)", bits);
    else if (bits >= 15)
        add_line("Colors", "High Color (%d bits per pixel)", bits);
    else
        add_line("Colors", "%d colors", 1 << bits);
    add_line("Logical Pixels per Inch", "%d x %d", GetDeviceCaps(dc, LOGPIXELSX),
             GetDeviceCaps(dc, LOGPIXELSY));
    add_line("Mouse", "%s, %d buttons",
             GetSystemMetrics(SM_MOUSEPRESENT) ? "Present" : "Not present",
             GetSystemMetrics(SM_CMOUSEBUTTONS));
    ReleaseDC(NULL, dc);
}

static void show_memory(void)
{
    MEMORYSTATUS status;
    char total[64], free_text[64];

    status.dwLength = sizeof(status);
    GlobalMemoryStatus(&status);
    add_line("Memory Load", "%lu%%", status.dwMemoryLoad);
    format_size(total, sizeof(total), status.dwTotalPhys);
    format_size(free_text, sizeof(free_text), status.dwAvailPhys);
    add_line("Physical Memory", "%s total, %s free", total, free_text);
    format_size(total, sizeof(total), status.dwTotalPageFile);
    format_size(free_text, sizeof(free_text), status.dwAvailPageFile);
    add_line("Page File", "%s total, %s free", total, free_text);
    format_size(total, sizeof(total), status.dwTotalVirtual);
    format_size(free_text, sizeof(free_text), status.dwAvailVirtual);
    add_line("Virtual Memory", "%s total, %s free", total, free_text);
}

static const char *drive_type_name(UINT type)
{
    switch (type) {
    case DRIVE_REMOVABLE: return "Floppy Disk";
    case DRIVE_FIXED: return "Local Disk";
    case DRIVE_REMOTE: return "Network Drive";
    case DRIVE_CDROM: return "CD-ROM";
    case DRIVE_RAMDISK: return "RAM Disk";
    default: return "Unknown";
    }
}

static void show_drives(void)
{
    char roots[256], *root;

    if (!GetLogicalDriveStringsA(sizeof(roots), roots))
        return;
    for (root = roots; *root; root += strlen(root) + 1) {
        char label[MAX_PATH] = "", fs[32] = "", total[64], free_text[64];
        DWORD serial = 0, spc, bps, free_clusters, clusters;
        UINT type = GetDriveTypeA(root);
        UINT mode = SetErrorMode(SEM_FAILCRITICALERRORS);

        add_line(root, "%s", drive_type_name(type));
        if (GetVolumeInformationA(root, label, sizeof(label), &serial, NULL, NULL,
                                  fs, sizeof(fs))) {
            add_line("    Volume Label", "%s", *label ? label : "(none)");
            add_line("    File System", "%s", fs);
            add_line("    Serial Number", "%04lX-%04lX", serial >> 16, serial & 0xFFFF);
        }
        if (GetDiskFreeSpaceA(root, &spc, &bps, &free_clusters, &clusters)) {
            unsigned long long cluster = (unsigned long long)spc * bps;
            format_size(total, sizeof(total), cluster * clusters);
            format_size(free_text, sizeof(free_text), cluster * free_clusters);
            add_line("    Size", "%s total, %s free", total, free_text);
        }
        SetErrorMode(mode);
    }
}

static int CALLBACK add_font(const LOGFONTA *font, const TEXTMETRICA *metrics, DWORD type,
                             LPARAM param)
{
    add_line(NULL, "%s%s", font->lfFaceName,
             type & TRUETYPE_FONTTYPE ? " (TrueType)" : "");
    return 1;
}

static void show_fonts(void)
{
    HDC dc = GetDC(NULL);
    EnumFontFamiliesA(dc, NULL, (FONTENUMPROCA)add_font, 0);
    ReleaseDC(NULL, dc);
}

static BOOL CALLBACK add_window(HWND hwnd, LPARAM param)
{
    char title[256];
    if (IsWindowVisible(hwnd) && GetWindowTextA(hwnd, title, sizeof(title)) > 0)
        add_line(NULL, "%s", title);
    return TRUE;
}

static void show_category(int index)
{
    SendMessageA(info_box, WM_SETREDRAW, FALSE, 0);
    SendMessageA(info_box, LB_RESETCONTENT, 0, 0);
    switch (index) {
    case 0: show_system(); break;
    case 1: show_display(); break;
    case 2: show_memory(); break;
    case 3: show_drives(); break;
    case 4: show_fonts(); break;
    case 5: EnumWindows(add_window, 0); break;
    }
    SendMessageA(info_box, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(info_box, NULL, TRUE);
}

static void layout(HWND hwnd)
{
    RECT client;
    int top = MARGIN + LABEL_HEIGHT + 4 + 24 + MARGIN;
    GetClientRect(hwnd, &client);
    MoveWindow(category_label, MARGIN, MARGIN, 200, LABEL_HEIGHT, TRUE);
    MoveWindow(category_box, MARGIN, MARGIN + LABEL_HEIGHT + 4,
               client.right - 2 * MARGIN, COMBO_HEIGHT, TRUE);
    MoveWindow(info_box, MARGIN, top, client.right - 2 * MARGIN,
               client.bottom - top - MARGIN, TRUE);
}

static LRESULT CALLBACK window_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_CREATE: {
        HINSTANCE instance = ((CREATESTRUCTA *)lParam)->hInstance;
        unsigned i;
        category_label = CreateWindowExA(0, "STATIC", "&Choose a category:",
                                         WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd, NULL,
                                         instance, NULL);
        category_box = CreateWindowExA(0, "COMBOBOX", "",
                                       WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST,
                                       0, 0, 0, 0, hwnd, (HMENU)ID_CATEGORY, instance, NULL);
        info_box = CreateWindowExA(WS_EX_CLIENTEDGE, "LISTBOX", "",
                                   WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_TABSTOP |
                                   LBS_NOINTEGRALHEIGHT | LBS_NOSEL,
                                   0, 0, 0, 0, hwnd, (HMENU)ID_INFO, instance, NULL);
        SendMessageA(category_label, WM_SETFONT, (WPARAM)gui_font, 0);
        SendMessageA(category_box, WM_SETFONT, (WPARAM)gui_font, 0);
        SendMessageA(info_box, WM_SETFONT, (WPARAM)gui_font, 0);
        for (i = 0; i < CATEGORY_COUNT; i++)
            SendMessageA(category_box, CB_ADDSTRING, 0, (LPARAM)categories[i]);
        SendMessageA(category_box, CB_SETCURSEL, 0, 0);
        layout(hwnd);
        show_category(0);
        return 0;
    }
    case WM_SIZE:
        layout(hwnd);
        return 0;
    case WM_SETFOCUS:
        SetFocus(category_box);
        return 0;
    case WM_COMMAND:
        if (LOWORD(wParam) == ID_CATEGORY && HIWORD(wParam) == CBN_SELCHANGE) {
            int index = (int)SendMessageA(category_box, CB_GETCURSEL, 0, 0);
            if (index >= 0)
                show_category(index);
        } else if (LOWORD(wParam) == IDM_EXIT) {
            DestroyWindow(hwnd);
        } else if (LOWORD(wParam) == IDM_ABOUT) {
            MessageBoxA(hwnd, "winexe32emu System Info\n\n"
                        "Shows information about the emulated computer.\n"
                        "Part of the Windows 32-bit EXE Emulator.",
                        "About winexe32emu System Info", MB_OK | MB_ICONINFORMATION);
        }
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

static HMENU create_menu(void)
{
    HMENU menu = CreateMenu(), file = CreatePopupMenu(), help = CreatePopupMenu();
    AppendMenuA(file, MF_STRING, IDM_EXIT, "E&xit");
    AppendMenuA(help, MF_STRING, IDM_ABOUT, "&About System Info...");
    AppendMenuA(menu, MF_POPUP, (UINT_PTR)file, "&File");
    AppendMenuA(menu, MF_POPUP, (UINT_PTR)help, "&Help");
    return menu;
}

int WINAPI WinMain(HINSTANCE instance, HINSTANCE previous, LPSTR command_line, int show)
{
    WNDCLASSA wc;
    HWND hwnd;
    MSG msg;

    gui_font = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc = window_proc;
    wc.hInstance = instance;
    wc.hIcon = LoadIconA(NULL, (LPCSTR)IDI_INFORMATION);
    wc.hCursor = LoadCursorA(NULL, (LPCSTR)IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = "MSInfo32";
    if (!RegisterClassA(&wc))
        return 1;

    hwnd = CreateWindowExA(0, "MSInfo32", "winexe32emu System Info", WS_OVERLAPPEDWINDOW,
                           CW_USEDEFAULT, CW_USEDEFAULT, 520, 400, NULL, create_menu(),
                           instance, NULL);
    if (!hwnd)
        return 1;
    ShowWindow(hwnd, show);
    UpdateWindow(hwnd);

    while (GetMessageA(&msg, NULL, 0, 0) > 0) {
        if (!IsDialogMessageA(hwnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
    }
    return (int)msg.wParam;
}
