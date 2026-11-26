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
Explorer (the desktop's My Computer) - browses the emulated drives (A:, C:, D:),
runs EXE files and copies, moves, renames and deletes files.

  - Left: the folder tree (My Computer, the drives, their folders); right: the
    folder's items with icons and Name, Size, Type, Modified columns (click a
    column to sort by it)
  - Back / Forward (Alt+Left / Alt+Right), Up (Backspace) and the address bar
    (Alt+D: type a path, Enter goes there)
  - Double-click / Enter: enter a drive or folder, or run an EXE
  - New Folder (Ctrl+Shift+N), Rename (F2), Delete (Del), Cut / Copy / Paste
    (Ctrl+X / C / V), Select All (Ctrl+A), Properties (Alt+Enter), Refresh (F5)
  - Right-click an item, the empty space or a tree folder for its menu
  - The CD-ROM D: is read-only: nothing on it can be changed
  - Delete sends files to the Recycle Bin (SHFileOperation with
    FOF_ALLOWUNDO; on the floppy A: they are deleted for good), Shift+Delete
    deletes them for good
  - The Recycle Bin lists the deleted items with their original location and
    deletion date: Restore, Delete (for good), Empty Recycle Bin
  - The network folder is empty: the emulated PC has no network

Usage: explorer.exe [folder]  (default: My Computer; also the Recycle Bin's
and the network's parsing names, BIN_PATH and NETWORK_PATH)
*/

#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <shlobj.h>
#include <stdlib.h>
#include <string.h>

#include "resource.h"

#define ID_BACK     101
#define ID_FORWARD  102
#define ID_UP       103
#define ID_ADDRESS_LABEL 104
#define ID_ADDRESS  105
#define ID_GO       106
#define ID_TREE     107
#define ID_LIST     108
#define ID_STATUS   109

#define BUTTON_W 64
#define BAR_H    30
#define TREE_W   190
#define HISTORY  32

#define COL_NAME     0
#define COL_SIZE     1
#define COL_TYPE     2
#define COL_MODIFIED 3

/* The virtual folders besides My Computer (""): their shell parsing names */
#define BIN_PATH     "::{645FF040-5081-101B-9F08-00AA002F954E}"
#define NETWORK_PATH "::{208D2C60-3AEA-1069-A2D7-08002B30309D}"
#define BIN_NAME     "Recycle Bin"
#define NETWORK_NAME "Network"

/* The Recycle Bin store of a drive (written by the emulator's shell32,
   src/recycle_bin.py): X:\$Recycle holds the deleted items and INDEX.TXT,
   UTF-8 lines "stored name TAB FILETIME TAB size TAB F|D TAB original path"
   after a header line */
#define BIN_STORE        "$Recycle"
#define BIN_INDEX        "INDEX.TXT"
#define BIN_INDEX_HEADER "winexe32emu recycle bin 1"

/* The Recycle Bin's columns */
#define COL_ORIGIN  1
#define COL_DELETED 2
#define COL_BINSIZE 3

typedef struct {
    char name[MAX_PATH];  /* A drive's root ("C:\") in My Computer */
    char type[80];
    DWORD attributes;
    ULONGLONG size;       /* Drives: total bytes */
    ULONGLONG free;       /* Drives: free bytes */
    FILETIME modified;    /* Recycle Bin: the deletion time */
    int image;
    char origin[MAX_PATH];  /* Recycle Bin: the path it was deleted from */
    char store[MAX_PATH];   /* Recycle Bin: the stored item (X:\$Recycle\R000001.txt) */
} Entry;

static HINSTANCE hInst;
static HWND hMain, hAddress, hTree, hList, hStatus;
static HIMAGELIST hImages;
static WNDPROC address_proc;
static char current[MAX_PATH] = "";  /* "": My Computer, the drives */
static Entry *entries;
static int entry_count, entry_capacity;
static int sort_column = COL_NAME, sort_ascending = 1;
static char back_stack[HISTORY][MAX_PATH], forward_stack[HISTORY][MAX_PATH];
static int back_count, forward_count;
static int syncing_tree;  /* The tree selection follows the list: no navigation */
static int bin_items_shown = -1;  /* Items in the Recycle Bin when its icon was set */

#define BIN_TIMER 1

/* Cut / Copy: the paths (double-NUL list) and whether Paste moves them */
static char *clip_paths;
static int clip_cut;

static void navigate(const char *path, int add_history);
static void refresh(void);
static Entry *add_entry(const char *name, DWORD attributes);
static void properties_of_selection(void);

/* ---------- Helpers ---------- */

static int is_computer(const char *path)
{
    return path[0] == '\0';
}

static int is_bin(const char *path)
{
    return lstrcmpiA(path, BIN_PATH) == 0;
}

static int is_network(const char *path)
{
    return lstrcmpiA(path, NETWORK_PATH) == 0;
}

/* My Computer, the Recycle Bin, the network: no folder of a drive */
static int is_virtual(const char *path)
{
    return is_computer(path) || is_bin(path) || is_network(path);
}

static int is_root(const char *path)
{
    return lstrlenA(path) <= 3;  /* "C:\" (or My Computer) */
}

static int is_dir(const Entry *e)
{
    return (e->attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

static int is_exe(const char *name)
{
    size_t n = strlen(name);
    return n > 4 && lstrcmpiA(name + n - 4, ".exe") == 0;
}

static void join_path(char *out, const char *folder, const char *name)
{
    if (out != folder)
        lstrcpyA(out, folder);
    if (out[0] && out[lstrlenA(out) - 1] != '\\')
        lstrcatA(out, "\\");
    lstrcatA(out, name);
}

/* The folder holding a path ("C:\a\b" -> "C:\a", "C:\a" -> "C:\", "C:\" -> "") */
static void parent_path(char *out, const char *path)
{
    char *slash;
    lstrcpyA(out, path);
    if (is_root(out)) {
        out[0] = '\0';
        return;
    }
    slash = strrchr(out, '\\');
    if (!slash)
        out[0] = '\0';
    else if (slash - out == 2)
        slash[1] = '\0';
    else
        *slash = '\0';
}

static const char *base_name(const char *path)
{
    const char *slash = strrchr(path, '\\');
    return (slash && slash[1]) ? slash + 1 : path;
}

/* Is the folder on the CD-ROM D: (nothing can be changed there)? */
static int is_read_only(const char *path)
{
    char root[4];
    if (is_virtual(path))
        return 1;
    lstrcpynA(root, path, 4);
    return GetDriveTypeA(root) == DRIVE_CDROM;
}

static void read_only_message(void)
{
    if (is_virtual(current))
        MessageBoxA(hMain, "Files cannot be created or changed here.", "My Computer",
                    MB_OK | MB_ICONINFORMATION);
    else
        MessageBoxA(hMain, "This drive is a CD-ROM: its files cannot be changed.",
                    "My Computer", MB_OK | MB_ICONINFORMATION);
}

static int folder_exists(const char *path)
{
    DWORD attributes;
    if (is_virtual(path))
        return 1;
    attributes = GetFileAttributesA(path);
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY);
}

/* 1234567 -> "1,234,567" */
static void format_number(char *out, ULONGLONG value)
{
    char digits[32];
    int len, i, j = 0;
    wsprintfA(digits, "%I64u", value);
    len = lstrlenA(digits);
    for (i = 0; i < len; i++) {
        if (i > 0 && (len - i) % 3 == 0)
            out[j++] = ',';
        out[j++] = digits[i];
    }
    out[j] = '\0';
}

/* Explorer's size: "0 KB", "12 KB", "3.4 MB", "1.2 GB" */
static void format_size(char *out, ULONGLONG bytes)
{
    char number[32];
    if (bytes < 1024 * 1024) {
        format_number(number, (bytes + 1023) / 1024);
        wsprintfA(out, "%s KB", number);
    } else if (bytes < (ULONGLONG)1024 * 1024 * 1024) {
        ULONGLONG tenths = bytes * 10 / (1024 * 1024);
        wsprintfA(out, "%u.%u MB", (unsigned)(tenths / 10), (unsigned)(tenths % 10));
    } else {
        ULONGLONG tenths = bytes * 10 / ((ULONGLONG)1024 * 1024 * 1024);
        wsprintfA(out, "%u.%u GB", (unsigned)(tenths / 10), (unsigned)(tenths % 10));
    }
}

static void format_time(char *out, const FILETIME *ft)
{
    FILETIME local;
    SYSTEMTIME st;
    if (!FileTimeToLocalFileTime(ft, &local) || !FileTimeToSystemTime(&local, &st)) {
        lstrcpyA(out, "");
        return;
    }
    wsprintfA(out, "%04d-%02d-%02d %02d:%02d", st.wYear, st.wMonth, st.wDay,
              st.wHour, st.wMinute);
}

/* "3½ Floppy (A:)", "Local Disk (C:)", "CD Drive (D:)" (or the volume label) */
static void drive_label(char *out, const char *root)
{
    char volume[MAX_PATH] = "";
    const char *type;
    switch (GetDriveTypeA(root)) {
    case DRIVE_REMOVABLE: type = "3\xBD Floppy"; break;
    case DRIVE_CDROM:     type = "CD Drive"; break;
    default:              type = "Local Disk"; break;
    }
    if (!GetVolumeInformationA(root, volume, sizeof(volume), NULL, NULL, NULL, NULL, 0))
        volume[0] = '\0';
    wsprintfA(out, "%s (%c:)", volume[0] ? volume : type, root[0]);
}

/* What the address bar and the title show for a folder */
static void display_name(char *out, const char *path)
{
    if (is_computer(path))
        lstrcpyA(out, "My Computer");
    else if (is_bin(path))
        lstrcpyA(out, BIN_NAME);
    else if (is_network(path))
        lstrcpyA(out, NETWORK_NAME);
    else
        lstrcpyA(out, path);
}

/* System image list index (and type name) of a path: a file's own icon
   (a program's icon, a shortcut's target icon); folders by
   their attributes only */
static int shell_icon(const char *path, DWORD attributes, char *type, int type_size)
{
    SHFILEINFOA info;
    UINT flags = SHGFI_SYSICONINDEX | SHGFI_SMALLICON | SHGFI_TYPENAME;
    memset(&info, 0, sizeof(info));
    if (!is_root(path) && (attributes & FILE_ATTRIBUTE_DIRECTORY))
        flags |= SHGFI_USEFILEATTRIBUTES;
    SHGetFileInfoA(path, attributes, &info, sizeof(info), flags);
    if (type)
        lstrcpynA(type, info.szTypeName, type_size);
    return info.iIcon;
}

/* Icon of a virtual folder (CSIDL_DRIVES, CSIDL_BITBUCKET: empty or full, CSIDL_NETWORK) */
static int special_icon(int csidl)
{
    LPITEMIDLIST pidl = NULL;
    SHFILEINFOA info;
    memset(&info, 0, sizeof(info));
    if (SHGetSpecialFolderLocation(NULL, csidl, &pidl) == S_OK) {
        SHGetFileInfoA((LPCSTR)pidl, 0, &info, sizeof(info),
                       SHGFI_PIDL | SHGFI_SYSICONINDEX | SHGFI_SMALLICON);
        CoTaskMemFree(pidl);
    }
    return info.iIcon;
}

static int computer_icon(void)
{
    return special_icon(CSIDL_DRIVES);
}

/* ---------- The Recycle Bin ---------- */

/* UTF-8 (the index) -> the ANSI code page of the A functions */
static void utf8_to_ansi(char *out, int size, const char *text)
{
    WCHAR wide[MAX_PATH];
    if (!MultiByteToWideChar(CP_UTF8, 0, text, -1, wide, MAX_PATH) ||
            !WideCharToMultiByte(CP_ACP, 0, wide, -1, out, size, NULL, NULL))
        lstrcpynA(out, text, size);
}

/* A decimal number of the index */
static ULONGLONG parse_number(const char *text)
{
    ULONGLONG value = 0;
    while (*text >= '0' && *text <= '9')
        value = value * 10 + (ULONGLONG)(*text++ - '0');
    return value;
}

/* The whole index file of a drive's bin ("C:\"), NUL-terminated (free it), or NULL */
static char *read_bin_index(const char *root)
{
    char path[MAX_PATH], *data;
    DWORD size, got = 0;
    HANDLE file;
    wsprintfA(path, "%s%s\\%s", root, BIN_STORE, BIN_INDEX);
    file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                       OPEN_EXISTING, 0, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return NULL;
    size = GetFileSize(file, NULL);
    data = size != INVALID_FILE_SIZE && size < 16 * 1024 * 1024 ? malloc(size + 1) : NULL;
    if (data && (!ReadFile(file, data, size, &got, NULL) || got != size)) {
        free(data);
        data = NULL;
    }
    CloseHandle(file);
    if (data)
        data[size] = '\0';
    return data;
}

/* One index line: "name TAB time TAB size TAB kind TAB original" (cut in place) */
static void add_bin_line(const char *root, char *line)
{
    char *fields[5], ansi[MAX_PATH], store[MAX_PATH];
    ULONGLONG deleted;
    DWORD attributes;
    Entry *e;
    int i;
    fields[0] = line;
    for (i = 1; i < 5; i++) {
        fields[i] = strchr(fields[i - 1], '\t');
        if (!fields[i])
            return;
        *fields[i]++ = '\0';
    }
    wsprintfA(store, "%s%s\\%s", root, BIN_STORE, fields[0]);
    attributes = GetFileAttributesA(store);
    if (attributes == INVALID_FILE_ATTRIBUTES)
        return;  /* Gone meanwhile */
    utf8_to_ansi(ansi, sizeof(ansi), fields[4]);
    e = add_entry(base_name(ansi), attributes);
    if (!e)
        return;
    lstrcpynA(e->origin, ansi, MAX_PATH);
    lstrcpynA(e->store, store, MAX_PATH);
    deleted = parse_number(fields[1]);
    e->modified.dwLowDateTime = (DWORD)deleted;
    e->modified.dwHighDateTime = (DWORD)(deleted >> 32);
    e->size = parse_number(fields[2]);
    e->image = shell_icon(store, attributes, e->type, sizeof(e->type));
}

/* The items of the bins of all hard disks */
static void load_bin(void)
{
    char roots[256], *root;
    DWORD length = GetLogicalDriveStringsA(sizeof(roots), roots);
    if (length == 0 || length >= sizeof(roots))
        return;
    for (root = roots; *root; root += lstrlenA(root) + 1) {
        char *data, *line, *next;
        if (GetDriveTypeA(root) != DRIVE_FIXED || !(data = read_bin_index(root)))
            continue;
        for (line = data, next = NULL; line && *line; line = next) {
            char *end = strchr(line, '\n');
            next = end ? end + 1 : NULL;
            if (end)
                *end = '\0';
            if (end && end > line && end[-1] == '\r')
                end[-1] = '\0';
            if (line == data) {
                if (lstrcmpA(line, BIN_INDEX_HEADER) != 0)
                    break;  /* Not an index this Explorer knows */
                continue;
            }
            add_bin_line(root, line);
        }
        free(data);
    }
}

/* Is there anything in the Recycle Bin? */
static int bin_has_items(void)
{
    SHQUERYRBINFO info;
    memset(&info, 0, sizeof(info));
    info.cbSize = sizeof(info);
    return SHQueryRecycleBinA(NULL, &info) == S_OK && info.i64NumItems > 0;
}

/* ---------- The list (right pane) ---------- */

static Entry *add_entry(const char *name, DWORD attributes)
{
    Entry *e;
    if (entry_count == entry_capacity) {
        int capacity = entry_capacity ? entry_capacity * 2 : 64;
        Entry *grown = realloc(entries, capacity * sizeof(Entry));
        if (!grown)
            return NULL;
        entries = grown;
        entry_capacity = capacity;
    }
    e = &entries[entry_count++];
    memset(e, 0, sizeof(*e));
    lstrcpynA(e->name, name, MAX_PATH);
    e->attributes = attributes;
    return e;
}

static void load_drives(void)
{
    char roots[256], *root;
    DWORD length = GetLogicalDriveStringsA(sizeof(roots), roots);
    if (length == 0 || length >= sizeof(roots))
        return;
    for (root = roots; *root; root += lstrlenA(root) + 1) {
        ULARGE_INTEGER free_bytes, total_bytes;
        Entry *e = add_entry(root, FILE_ATTRIBUTE_DIRECTORY);
        if (!e)
            break;
        e->image = shell_icon(root, FILE_ATTRIBUTE_DIRECTORY, e->type, sizeof(e->type));
        if (GetDiskFreeSpaceExA(root, &free_bytes, &total_bytes, NULL)) {
            e->size = total_bytes.QuadPart;
            e->free = free_bytes.QuadPart;
        }
    }
}

static void load_files(void)
{
    char pattern[MAX_PATH], path[MAX_PATH];
    WIN32_FIND_DATAA fd;
    HANDLE find;
    join_path(pattern, current, "*");
    find = FindFirstFileA(pattern, &fd);
    if (find == INVALID_HANDLE_VALUE)
        return;
    do {
        Entry *e;
        if (lstrcmpA(fd.cFileName, ".") == 0 || lstrcmpA(fd.cFileName, "..") == 0)
            continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN)
            continue;  /* Like Explorer by default (the Recycle Bin's store) */
        e = add_entry(fd.cFileName, fd.dwFileAttributes);
        if (!e)
            break;
        e->size = ((ULONGLONG)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
        e->modified = fd.ftLastWriteTime;
        join_path(path, current, fd.cFileName);
        e->image = shell_icon(path, fd.dwFileAttributes, e->type, sizeof(e->type));
    } while (FindNextFileA(find, &fd));
    FindClose(find);
}

/* Folders first, then by the sort column */
static int CALLBACK compare_items(LPARAM a, LPARAM b, LPARAM unused)
{
    const Entry *x = &entries[a], *y = &entries[b];
    int result = 0;
    if (is_bin(current)) {
        /* Name, Original Location, Date Deleted, Size */
        switch (sort_column) {
        case COL_ORIGIN:
            result = lstrcmpiA(x->origin, y->origin);
            break;
        case COL_DELETED:
            result = CompareFileTime(&x->modified, &y->modified);
            break;
        case COL_BINSIZE:
            result = x->size < y->size ? -1 : x->size > y->size;
            break;
        }
        if (!result)
            result = lstrcmpiA(x->name, y->name);
        return sort_ascending ? result : -result;
    }
    if (is_computer(current))
        result = lstrcmpiA(x->name, y->name);  /* Drives: by letter */
    else if (is_dir(x) != is_dir(y))
        return is_dir(x) ? -1 : 1;
    if (!result) {
        switch (sort_column) {
        case COL_SIZE:
            result = x->size < y->size ? -1 : x->size > y->size;
            break;
        case COL_TYPE:
            result = lstrcmpiA(x->type, y->type);
            break;
        case COL_MODIFIED:
            result = CompareFileTime(&x->modified, &y->modified);
            break;
        }
        if (!result)
            result = lstrcmpiA(x->name, y->name);
    }
    return sort_ascending ? result : -result;
}

static void set_column(int index, const char *text, int width, int right)
{
    LVCOLUMNA column;
    memset(&column, 0, sizeof(column));
    column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT | LVCF_SUBITEM;
    column.pszText = (char *)text;
    column.cx = width;
    column.fmt = right ? LVCFMT_RIGHT : LVCFMT_LEFT;
    column.iSubItem = index;
    if (!SendMessageA(hList, LVM_SETCOLUMNA, index, (LPARAM)&column))
        SendMessageA(hList, LVM_INSERTCOLUMNA, index, (LPARAM)&column);
}

/* My Computer: Name, Type, Total Size, Free Space; folders: Name, Size, Type, Modified */
static void set_columns(void)
{
    if (is_computer(current)) {
        set_column(COL_NAME, "Name", 170, 0);
        set_column(COL_SIZE, "Type", 110, 0);
        set_column(COL_TYPE, "Total Size", 90, 1);
        set_column(COL_MODIFIED, "Free Space", 90, 1);
    } else if (is_bin(current)) {
        set_column(COL_NAME, "Name", 160, 0);
        set_column(COL_ORIGIN, "Original Location", 170, 0);
        set_column(COL_DELETED, "Date Deleted", 120, 0);
        set_column(COL_BINSIZE, "Size", 70, 1);
    } else if (is_network(current)) {
        set_column(COL_NAME, "Name", 190, 0);
        set_column(COL_SIZE, "Comment", 260, 0);
        set_column(COL_TYPE, "", 0, 0);
        set_column(COL_MODIFIED, "", 0, 0);
    } else {
        set_column(COL_NAME, "Name", 190, 0);
        set_column(COL_SIZE, "Size", 80, 1);
        set_column(COL_TYPE, "Type", 120, 0);
        set_column(COL_MODIFIED, "Modified", 120, 0);
    }
}

/* The sort arrow in the header */
static void show_sort_arrow(void)
{
    HWND header = (HWND)SendMessageA(hList, LVM_GETHEADER, 0, 0);
    HDITEMA item;
    int i;
    if (!header)
        return;
    for (i = 0; i < 4; i++) {
        memset(&item, 0, sizeof(item));
        item.mask = HDI_FORMAT;
        SendMessageA(header, HDM_GETITEMA, i, (LPARAM)&item);
        item.fmt &= ~(HDF_SORTUP | HDF_SORTDOWN);
        if (i == sort_column && !is_computer(current) && !is_network(current))
            item.fmt |= sort_ascending ? HDF_SORTUP : HDF_SORTDOWN;
        SendMessageA(header, HDM_SETITEMA, i, (LPARAM)&item);
    }
}

static void sort_list(void)
{
    SendMessageA(hList, LVM_SORTITEMS, 0, (LPARAM)compare_items);
    show_sort_arrow();
}

static void set_item_text(int row, int column, const char *text)
{
    LVITEMA item;
    memset(&item, 0, sizeof(item));
    item.iSubItem = column;
    item.pszText = (char *)text;
    SendMessageA(hList, LVM_SETITEMTEXTA, row, (LPARAM)&item);
}

static int entry_of_row(int row)
{
    LVITEMA item;
    memset(&item, 0, sizeof(item));
    item.mask = LVIF_PARAM;
    item.iItem = row;
    if (row < 0 || !SendMessageA(hList, LVM_GETITEMA, 0, (LPARAM)&item))
        return -1;
    return (int)item.lParam;
}

static int row_of_entry(int index)
{
    LVFINDINFOA find;
    memset(&find, 0, sizeof(find));
    find.flags = LVFI_PARAM;
    find.lParam = index;
    return (int)SendMessageA(hList, LVM_FINDITEMA, (WPARAM)-1, (LPARAM)&find);
}

static void select_row(int row, int only)
{
    LVITEMA item;
    memset(&item, 0, sizeof(item));
    if (only) {
        item.stateMask = LVIS_SELECTED;
        SendMessageA(hList, LVM_SETITEMSTATE, (WPARAM)-1, (LPARAM)&item);
    }
    if (row < 0)
        return;
    item.state = item.stateMask = LVIS_SELECTED | LVIS_FOCUSED;
    SendMessageA(hList, LVM_SETITEMSTATE, row, (LPARAM)&item);
    SendMessageA(hList, LVM_ENSUREVISIBLE, row, FALSE);
}

static int selected_count(void)
{
    return (int)SendMessageA(hList, LVM_GETSELECTEDCOUNT, 0, 0);
}

static int first_selected(void)
{
    return (int)SendMessageA(hList, LVM_GETNEXTITEM, (WPARAM)-1, LVNI_SELECTED);
}

/* Full path of a list entry */
static void entry_path(char *out, const Entry *e)
{
    if (is_computer(current))
        lstrcpyA(out, e->name);
    else if (is_bin(current))
        lstrcpyA(out, e->store);  /* The file operations work on the stored item */
    else
        join_path(out, current, e->name);
}

/* Double-NUL list of the selected items' paths (free it) */
static char *selected_paths(void)
{
    int row = -1, size = 1;
    char *list = malloc(1), path[MAX_PATH];
    if (!list)
        return NULL;
    list[0] = '\0';
    while ((row = (int)SendMessageA(hList, LVM_GETNEXTITEM, row, LVNI_SELECTED)) >= 0) {
        int index = entry_of_row(row), length;
        char *grown;
        if (index < 0)
            continue;
        entry_path(path, &entries[index]);
        length = lstrlenA(path) + 1;
        grown = realloc(list, size + length);
        if (!grown)
            break;
        list = grown;
        memcpy(list + size - 1, path, length);
        size += length;
        list[size - 1] = '\0';
    }
    return list;
}

/* The status line: the selection or the folder's summary */
static void update_status(void)
{
    char text[3 * MAX_PATH], number[32], second[32];
    int count = selected_count();
    int index = entry_of_row(first_selected());
    if (is_network(current)) {
        lstrcpyA(text, "The network is not available: this computer is not connected to a "
                 "network.");
    } else if (count == 1 && index >= 0 && is_bin(current)) {
        const Entry *e = &entries[index];
        format_time(second, &e->modified);
        format_size(number, e->size);
        wsprintfA(text, "%s - %s, deleted from %s on %s", e->name, number, e->origin,
                  second);
    } else if (count == 1 && index >= 0) {
        const Entry *e = &entries[index];
        if (is_computer(current)) {
            format_size(number, e->free);
            format_size(second, e->size);
            drive_label(text, e->name);
            wsprintfA(text + lstrlenA(text), " - %s free of %s%s", number, second,
                      GetDriveTypeA(e->name) == DRIVE_CDROM ? " (read-only)" : "");
        } else if (is_dir(e)) {
            wsprintfA(text, "%s - %s", e->name, e->type);
        } else {
            format_number(number, e->size);
            wsprintfA(text, "%s - %s bytes, %s", e->name, number, e->type);
        }
    } else if (count > 1) {
        wsprintfA(text, "%d objects selected", count);
    } else {
        ULONGLONG total = 0;
        int i;
        for (i = 0; i < entry_count; i++)
            if (!is_dir(&entries[i]) || is_bin(current))  /* (the bin knows folder sizes) */
                total += entries[i].size;
        if (is_computer(current)) {
            wsprintfA(text, "%d drive(s)", entry_count);
        } else {
            format_size(number, total);
            wsprintfA(text, "%d object(s) - %s%s", entry_count, number,
                      !is_virtual(current) && is_read_only(current) ? " (read-only)" : "");
        }
    }
    SetWindowTextA(hStatus, text);
}

/* Read the current folder into the list; select names an item to select */
static void load_list(const char *select)
{
    char text[MAX_PATH + 32], number[32];
    LVITEMA item;
    int i, row;

    entry_count = 0;
    if (is_computer(current))
        load_drives();
    else if (is_bin(current))
        load_bin();
    else if (!is_network(current))  /* (no network: nothing to list) */
        load_files();

    SendMessageA(hList, WM_SETREDRAW, FALSE, 0);
    SendMessageA(hList, LVM_DELETEALLITEMS, 0, 0);
    set_columns();
    for (i = 0; i < entry_count; i++) {
        Entry *e = &entries[i];
        memset(&item, 0, sizeof(item));
        item.mask = LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM;
        item.iItem = i;
        if (is_computer(current))
            drive_label(text, e->name);
        else
            lstrcpynA(text, e->name, sizeof(text));
        item.pszText = text;
        item.iImage = e->image;
        item.lParam = i;
        row = (int)SendMessageA(hList, LVM_INSERTITEMA, 0, (LPARAM)&item);
        if (is_computer(current)) {
            set_item_text(row, COL_SIZE, e->type);
            format_size(number, e->size);
            set_item_text(row, COL_TYPE, e->size ? number : "");
            format_size(number, e->free);
            set_item_text(row, COL_MODIFIED, e->size ? number : "");
        } else if (is_bin(current)) {
            char folder[MAX_PATH];
            parent_path(folder, e->origin);
            set_item_text(row, COL_ORIGIN, folder);
            format_time(number, &e->modified);
            set_item_text(row, COL_DELETED, number);
            format_size(number, e->size);
            set_item_text(row, COL_BINSIZE, number);
        } else {
            if (!is_dir(e)) {
                format_size(number, e->size);
                set_item_text(row, COL_SIZE, number);
            }
            set_item_text(row, COL_TYPE, e->type);
            format_time(number, &e->modified);
            set_item_text(row, COL_MODIFIED, number);
        }
    }
    sort_list();
    SendMessageA(hList, WM_SETREDRAW, TRUE, 0);

    row = -1;
    for (i = 0; select && i < entry_count; i++)
        if (lstrcmpiA(entries[i].name, select) == 0)
            row = row_of_entry(i);
    select_row(row >= 0 ? row : (entry_count ? 0 : -1), 1);
    if (row < 0 && entry_count)
        select_row(-1, 1), SendMessageA(hList, LVM_SETSELECTIONMARK, 0, 0);

    display_name(text, current);
    SetWindowTextA(hAddress, text);
    if (is_virtual(current)) {
        SetWindowTextA(hMain, text);  /* "My Computer", "Recycle Bin", "Network" */
    } else {
        wsprintfA(text, "My Computer - %s", current);
        SetWindowTextA(hMain, text);
    }
    update_status();
}

/* ---------- The folder tree (left pane) ---------- */

/* Path of a tree item (its lParam: a malloc'd string, "" for My Computer) */
static const char *tree_path(HTREEITEM item)
{
    TVITEMA tv;
    memset(&tv, 0, sizeof(tv));
    tv.mask = TVIF_PARAM;
    tv.hItem = item;
    if (!item || !SendMessageA(hTree, TVM_GETITEMA, 0, (LPARAM)&tv) || !tv.lParam)
        return NULL;
    return (const char *)tv.lParam;
}

static int has_subfolders(const char *path)
{
    char pattern[MAX_PATH];
    WIN32_FIND_DATAA fd;
    HANDLE find;
    int found = 0;
    join_path(pattern, path, "*");
    find = FindFirstFileA(pattern, &fd);
    if (find == INVALID_HANDLE_VALUE)
        return 0;
    do {
        if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                !(fd.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN) &&
                lstrcmpA(fd.cFileName, ".") && lstrcmpA(fd.cFileName, "..")) {
            found = 1;
            break;
        }
    } while (FindNextFileA(find, &fd));
    FindClose(find);
    return found;
}

static HTREEITEM add_tree_item(HTREEITEM parent, const char *label, const char *path,
                               int image, int children, HTREEITEM after)
{
    TVINSERTSTRUCTA insert;
    char *copy = malloc(lstrlenA(path) + 1);
    if (!copy)
        return NULL;
    lstrcpyA(copy, path);
    memset(&insert, 0, sizeof(insert));
    insert.hParent = parent;
    insert.hInsertAfter = after;
    insert.item.mask = TVIF_TEXT | TVIF_IMAGE | TVIF_SELECTEDIMAGE | TVIF_PARAM |
                       TVIF_CHILDREN;
    insert.item.pszText = (char *)label;
    insert.item.iImage = insert.item.iSelectedImage = image;
    insert.item.cChildren = children;
    insert.item.lParam = (LPARAM)copy;
    return (HTREEITEM)SendMessageA(hTree, TVM_INSERTITEMA, 0, (LPARAM)&insert);
}

/* Fill a tree item with its drives or subfolders (once; refresh empties it) */
static void fill_tree_item(HTREEITEM item)
{
    const char *path = tree_path(item);
    char pattern[MAX_PATH], child[MAX_PATH], label[MAX_PATH];
    WIN32_FIND_DATAA fd;
    HANDLE find;
    TVITEMA tv;
    if (!path || SendMessageA(hTree, TVM_GETNEXTITEM, TVGN_CHILD, (LPARAM)item) ||
            is_bin(path) || is_network(path))
        return;
    if (is_computer(path)) {
        char roots[256], *root;
        DWORD length = GetLogicalDriveStringsA(sizeof(roots), roots);
        if (length == 0 || length >= sizeof(roots))
            return;
        for (root = roots; *root; root += lstrlenA(root) + 1) {
            drive_label(label, root);
            add_tree_item(item, label, root, shell_icon(root, FILE_ATTRIBUTE_DIRECTORY, NULL, 0),
                          1, TVI_LAST);
        }
        return;
    }
    join_path(pattern, path, "*");
    find = FindFirstFileA(pattern, &fd);
    if (find != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
                    (fd.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN) ||
                    !lstrcmpA(fd.cFileName, ".") || !lstrcmpA(fd.cFileName, ".."))
                continue;
            join_path(child, path, fd.cFileName);
            add_tree_item(item, fd.cFileName, child,
                          shell_icon(child, FILE_ATTRIBUTE_DIRECTORY, NULL, 0),
                          has_subfolders(child), TVI_SORT);
        } while (FindNextFileA(find, &fd));
        FindClose(find);
    }
    if (!SendMessageA(hTree, TVM_GETNEXTITEM, TVGN_CHILD, (LPARAM)item)) {
        /* No subfolders: no +/- box */
        memset(&tv, 0, sizeof(tv));
        tv.mask = TVIF_CHILDREN;
        tv.hItem = item;
        SendMessageA(hTree, TVM_SETITEMA, 0, (LPARAM)&tv);
    }
}

/* The child of a tree item whose path is path (filling it first) */
static HTREEITEM find_tree_child(HTREEITEM parent, const char *path)
{
    HTREEITEM child;
    fill_tree_item(parent);
    for (child = (HTREEITEM)SendMessageA(hTree, TVM_GETNEXTITEM, TVGN_CHILD, (LPARAM)parent);
         child;
         child = (HTREEITEM)SendMessageA(hTree, TVM_GETNEXTITEM, TVGN_NEXT, (LPARAM)child)) {
        const char *child_path = tree_path(child);
        if (child_path && lstrcmpiA(child_path, path) == 0)
            return child;
    }
    return NULL;
}

/* The tree item of a folder: My Computer, then a drive, then each folder */
static HTREEITEM tree_item_of(const char *path, int expand)
{
    HTREEITEM item = (HTREEITEM)SendMessageA(hTree, TVM_GETNEXTITEM, TVGN_ROOT, 0);
    char step[MAX_PATH];
    int position;
    if (item && (is_bin(path) || is_network(path))) {
        /* The Recycle Bin and the network are roots of their own after My Computer */
        for (; item; item = (HTREEITEM)SendMessageA(hTree, TVM_GETNEXTITEM, TVGN_NEXT,
                                                    (LPARAM)item)) {
            const char *root = tree_path(item);
            if (root && lstrcmpiA(root, path) == 0)
                return item;
        }
        return NULL;
    }
    if (!item || is_computer(path))
        return item;
    lstrcpynA(step, path, 4);  /* "C:\" */
    position = 3;
    for (;;) {
        HTREEITEM child = find_tree_child(item, step);
        if (!child)
            return item;
        if (expand)
            SendMessageA(hTree, TVM_EXPAND, TVE_EXPAND, (LPARAM)item);
        item = child;
        if (!path[position])
            return item;
        while (path[position] && path[position] != '\\')
            position++;
        lstrcpynA(step, path, position + 1);
        if (path[position] == '\\')
            position++;
        if (lstrlenA(step) > 3 && step[lstrlenA(step) - 1] == '\\')
            step[lstrlenA(step) - 1] = '\0';
    }
}

static void sync_tree(void)
{
    HTREEITEM item = tree_item_of(current, 1);
    syncing_tree = 1;
    if (item)
        SendMessageA(hTree, TVM_SELECTITEM, TVGN_CARET, (LPARAM)item);
    syncing_tree = 0;
}

/* Read a folder's subfolders again (after a change), keeping it expanded */
static void refresh_tree_folder(const char *path)
{
    HTREEITEM item = tree_item_of(path, 0), child;
    TVITEMA tv;
    const char *found;
    if (!item || !(found = tree_path(item)) || lstrcmpiA(found, path) != 0)
        return;
    memset(&tv, 0, sizeof(tv));
    tv.mask = TVIF_STATE;
    tv.hItem = item;
    tv.stateMask = TVIS_EXPANDED;
    SendMessageA(hTree, TVM_GETITEMA, 0, (LPARAM)&tv);
    while ((child = (HTREEITEM)SendMessageA(hTree, TVM_GETNEXTITEM, TVGN_CHILD, (LPARAM)item)))
        SendMessageA(hTree, TVM_DELETEITEM, 0, (LPARAM)child);
    tv.mask = TVIF_CHILDREN;
    tv.cChildren = 1;
    SendMessageA(hTree, TVM_SETITEMA, 0, (LPARAM)&tv);
    if (tv.state & TVIS_EXPANDED) {
        fill_tree_item(item);
        SendMessageA(hTree, TVM_EXPAND, TVE_EXPAND, (LPARAM)item);
    }
}

static void build_tree(void)
{
    HTREEITEM root = add_tree_item(TVI_ROOT, "My Computer", "", computer_icon(), 1, TVI_LAST);
    fill_tree_item(root);
    SendMessageA(hTree, TVM_EXPAND, TVE_EXPAND, (LPARAM)root);
    add_tree_item(TVI_ROOT, NETWORK_NAME, NETWORK_PATH, special_icon(CSIDL_NETWORK), 0,
                  TVI_LAST);
    add_tree_item(TVI_ROOT, BIN_NAME, BIN_PATH, special_icon(CSIDL_BITBUCKET), 0, TVI_LAST);
}

/* The Recycle Bin's tree icon shows whether it is empty: after every deletion */
static void update_bin_icon(void)
{
    SHQUERYRBINFO info;
    HTREEITEM item = tree_item_of(BIN_PATH, 0);
    TVITEMA tv;
    if (!item)
        return;
    memset(&tv, 0, sizeof(tv));
    tv.mask = TVIF_IMAGE | TVIF_SELECTEDIMAGE;
    tv.hItem = item;
    tv.iImage = tv.iSelectedImage = special_icon(CSIDL_BITBUCKET);
    SendMessageA(hTree, TVM_SETITEMA, 0, (LPARAM)&tv);
    memset(&info, 0, sizeof(info));
    info.cbSize = sizeof(info);
    if (SHQueryRecycleBinA(NULL, &info) == S_OK)
        bin_items_shown = (int)info.i64NumItems;
}

/* Every second: the Recycle Bin may have changed elsewhere (emptied from the
   desktop, files deleted by a program): its icon and its open view follow */
static void check_bin(void)
{
    SHQUERYRBINFO info;
    memset(&info, 0, sizeof(info));
    info.cbSize = sizeof(info);
    if (SHQueryRecycleBinA(NULL, &info) != S_OK || (int)info.i64NumItems == bin_items_shown)
        return;
    update_bin_icon();
    if (is_bin(current) && !SendMessageA(hList, LVM_GETEDITCONTROL, 0, 0))
        refresh();
}

/* ---------- Navigation ---------- */

static void update_buttons(void)
{
    EnableWindow(GetDlgItem(hMain, ID_BACK), back_count > 0);
    EnableWindow(GetDlgItem(hMain, ID_FORWARD), forward_count > 0);
    EnableWindow(GetDlgItem(hMain, ID_UP), !is_virtual(current));
}

static void push(char stack[][MAX_PATH], int *count, const char *path)
{
    if (*count == HISTORY) {
        memmove(stack[0], stack[1], (HISTORY - 1) * MAX_PATH);
        (*count)--;
    }
    lstrcpyA(stack[(*count)++], path);
}

/* Go to a folder ("" is My Computer); select names an item to select */
static void navigate_select(const char *path, int add_history, const char *select)
{
    char child[MAX_PATH];
    if (!folder_exists(path)) {
        char message[MAX_PATH + 64];
        wsprintfA(message, "Cannot find '%s'.", path);
        MessageBoxA(hMain, message, "My Computer", MB_OK | MB_ICONERROR);
        return;
    }
    if (add_history && lstrcmpiA(path, current) != 0) {
        push(back_stack, &back_count, current);
        forward_count = 0;
    }
    if (!select && !is_computer(current)) {
        /* Going to an ancestor (Up, Back): the folder we came from is selected */
        int len = lstrlenA(path);
        if (is_computer(path)) {
            lstrcpynA(child, current, 4);  /* Its drive, "C:\" */
            select = child;
        } else if (len < lstrlenA(current) && _strnicmp(current, path, len) == 0 &&
                   (path[len - 1] == '\\' || current[len] == '\\')) {
            const char *rest = current + len + (current[len] == '\\');
            char *slash;
            lstrcpynA(child, rest, MAX_PATH);
            slash = strchr(child, '\\');
            if (slash)
                *slash = '\0';
            select = child;
        }
    }
    lstrcpyA(current, path);
    load_list(select);
    sync_tree();
    update_buttons();
}

static void navigate(const char *path, int add_history)
{
    navigate_select(path, add_history, NULL);
}

static void go_back(void)
{
    if (!back_count)
        return;
    push(forward_stack, &forward_count, current);
    navigate(back_stack[--back_count], 0);
}

static void go_forward(void)
{
    if (!forward_count)
        return;
    push(back_stack, &back_count, current);
    navigate(forward_stack[--forward_count], 0);
}

static void go_up(void)
{
    char parent[MAX_PATH], child[MAX_PATH];
    if (is_virtual(current))
        return;  /* (the top of the tree) */
    lstrcpyA(child, is_root(current) ? current : base_name(current));
    parent_path(parent, current);
    navigate_select(parent, 1, child);  /* The folder we came from stays selected */
}

/* The virtual folder a typed name or parsing name stands for, or NULL */
static const char *virtual_folder_of(const char *text)
{
    if (lstrcmpiA(text, BIN_NAME) == 0 || is_bin(text))
        return BIN_PATH;
    if (lstrcmpiA(text, NETWORK_NAME) == 0 || is_network(text) ||
            lstrcmpiA(text, "Network Neighborhood") == 0)
        return NETWORK_PATH;
    return NULL;
}

/* The address bar: a folder path, "My Computer", or an EXE to run */
static void go_address(void)
{
    char text[MAX_PATH], full[MAX_PATH], message[MAX_PATH + 64];
    DWORD attributes;
    int len;
    GetWindowTextA(hAddress, text, sizeof(text));
    len = lstrlenA(text);
    while (len > 0 && text[len - 1] == ' ')
        text[--len] = '\0';
    if (len == 0 || lstrcmpiA(text, "My Computer") == 0) {
        navigate("", 1);
        return;
    }
    if (virtual_folder_of(text)) {
        navigate(virtual_folder_of(text), 1);
        SetFocus(hList);
        return;
    }
    if (len == 2 && text[1] == ':')
        lstrcatA(text, "\\");
    if (!GetFullPathNameA(text, MAX_PATH, full, NULL))
        lstrcpyA(full, text);
    len = lstrlenA(full);
    if (len > 3 && full[len - 1] == '\\')
        full[len - 1] = '\0';
    attributes = GetFileAttributesA(full);
    if (attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY) &&
            is_exe(full)) {
        char folder[MAX_PATH], command[MAX_PATH + 2];
        STARTUPINFOA si;
        PROCESS_INFORMATION pi;
        parent_path(folder, full);
        wsprintfA(command, "\"%s\"", full);
        memset(&si, 0, sizeof(si));
        si.cb = sizeof(si);
        if (CreateProcessA(full, command, NULL, NULL, FALSE, 0, NULL, folder, &si, &pi)) {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
        return;
    }
    if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY)) {
        wsprintfA(message, "Cannot find '%s'. Check the spelling and try again.", text);
        MessageBoxA(hMain, message, "My Computer", MB_OK | MB_ICONERROR);
        return;
    }
    navigate(full, 1);
    SetFocus(hList);
}

/* ---------- Opening ---------- */

static void run_program(const char *path)
{
    char command[MAX_PATH + 2], message[MAX_PATH + 64], folder[MAX_PATH];
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    parent_path(folder, path);
    wsprintfA(command, "\"%s\"", path);
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    if (CreateProcessA(path, command, NULL, NULL, FALSE, 0, NULL, folder, &si, &pi)) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    } else {
        wsprintfA(message, "Cannot run %s (error %lu).", path, (unsigned long)GetLastError());
        MessageBoxA(hMain, message, "My Computer", MB_OK | MB_ICONERROR);
    }
}

static void open_entry(int index)
{
    char path[MAX_PATH], message[MAX_PATH + 96];
    const Entry *e;
    if (index < 0 || index >= entry_count)
        return;
    e = &entries[index];
    entry_path(path, e);
    if (is_bin(current)) {
        properties_of_selection();  /* Deleted items open only after Restore */
    } else if (is_dir(e)) {
        navigate(path, 1);
    } else if (is_exe(e->name)) {
        run_program(path);
    } else if ((INT_PTR)ShellExecuteA(hMain, "open", path, NULL, current,
                                      SW_SHOWNORMAL) > 32) {
        /* A document: its associated program opened it */
    } else {
        wsprintfA(message, "%s\n\nThere is no program to open %s files with.",
                  e->name, e->type);
        MessageBoxA(hMain, message, "My Computer", MB_OK | MB_ICONINFORMATION);
    }
}

static void open_selected(void)
{
    open_entry(entry_of_row(first_selected()));
}

/* ---------- File operations ---------- */

/* Copy or move paths (double-NUL list) into the current folder */
static void paste_into(const char *folder)
{
    SHFILEOPSTRUCTA op;
    char *targets = NULL, source_folder[MAX_PATH], *p;
    int same, length = 1;
    if (!clip_paths || !clip_paths[0])
        return;
    if (is_read_only(folder)) {
        read_only_message();
        return;
    }
    parent_path(source_folder, clip_paths);
    same = lstrcmpiA(source_folder, folder) == 0;
    if (same && clip_cut)
        return;  /* Moving into the same folder: nothing to do */
    memset(&op, 0, sizeof(op));
    op.hwnd = hMain;
    op.wFunc = clip_cut ? FO_MOVE : FO_COPY;
    op.pFrom = clip_paths;
    op.pTo = folder;
    if (same) {
        /* A copy into the same folder: "Copy of x", "Copy (2) of x"... */
        targets = malloc(1);
        if (!targets)
            return;
        targets[0] = '\0';
        for (p = clip_paths; *p; p += lstrlenA(p) + 1) {
            char target[MAX_PATH], name[MAX_PATH];
            int n = 1;
            char *grown;
            int size;
            do {
                if (n == 1)
                    wsprintfA(name, "Copy of %s", base_name(p));
                else
                    wsprintfA(name, "Copy (%d) of %s", n, base_name(p));
                join_path(target, folder, name);
                n++;
            } while (GetFileAttributesA(target) != INVALID_FILE_ATTRIBUTES);
            size = lstrlenA(target) + 1;
            grown = realloc(targets, length + size);
            if (!grown)
                break;
            targets = grown;
            memcpy(targets + length - 1, target, size);
            length += size;
            targets[length - 1] = '\0';
        }
        op.pTo = targets;
        op.fFlags = FOF_MULTIDESTFILES;
    }
    SHFileOperationA(&op);
    free(targets);
    if (clip_cut) {
        refresh_tree_folder(source_folder);
        free(clip_paths);
        clip_paths = NULL;
    }
    refresh_tree_folder(folder);
    refresh();
}

static void copy_selection(int cut)
{
    if (is_virtual(current) || !selected_count())
        return;
    if (cut && is_read_only(current)) {
        read_only_message();
        return;
    }
    free(clip_paths);
    clip_paths = selected_paths();
    clip_cut = cut;
}

/* Delete: to the Recycle Bin (the shell decides: the floppy A: has none),
   for good with permanent or Shift held, and always in the Recycle Bin itself */
static void delete_selection(int permanent)
{
    SHFILEOPSTRUCTA op;
    char *paths;
    if (is_computer(current) || is_network(current) || !selected_count())
        return;
    if (!is_bin(current) && is_read_only(current)) {
        read_only_message();
        return;
    }
    paths = selected_paths();
    if (!paths)
        return;
    memset(&op, 0, sizeof(op));
    op.hwnd = hMain;
    op.wFunc = FO_DELETE;
    op.pFrom = paths;
    if (!permanent && !is_bin(current) && GetKeyState(VK_SHIFT) >= 0)
        op.fFlags = FOF_ALLOWUNDO;
    SHFileOperationA(&op);  /* It asks before deleting */
    free(paths);
    if (!is_bin(current))
        refresh_tree_folder(current);
    update_bin_icon();
    refresh();
}

/* Restore: the selected Recycle Bin items go back where they were deleted
   from (the shell makes their folders again and asks before replacing) */
static void restore_selection(void)
{
    SHFILEOPSTRUCTA op;
    char *sources, *targets, folder[MAX_PATH];
    int row = -1, size = 1;
    if (!is_bin(current) || !selected_count() || !(sources = selected_paths()))
        return;
    targets = malloc(1);
    if (!targets) {
        free(sources);
        return;
    }
    targets[0] = '\0';
    /* The targets in the order of selected_paths(): the selected rows */
    while ((row = (int)SendMessageA(hList, LVM_GETNEXTITEM, row, LVNI_SELECTED)) >= 0) {
        int index = entry_of_row(row), length;
        char *grown;
        if (index < 0)
            continue;
        length = lstrlenA(entries[index].origin) + 1;
        grown = realloc(targets, size + length);
        if (!grown)
            break;
        targets = grown;
        memcpy(targets + size - 1, entries[index].origin, length);
        size += length;
        targets[size - 1] = '\0';
    }
    memset(&op, 0, sizeof(op));
    op.hwnd = hMain;
    op.wFunc = FO_MOVE;
    op.pFrom = sources;
    op.pTo = targets;
    op.fFlags = FOF_MULTIDESTFILES;
    SHFileOperationA(&op);
    /* The folders that got their items back (or were made again) show them in the tree */
    for (row = -1; (row = (int)SendMessageA(hList, LVM_GETNEXTITEM, row, LVNI_SELECTED)) >= 0;) {
        int index = entry_of_row(row);
        char grandparent[MAX_PATH];
        if (index < 0)
            continue;
        parent_path(folder, entries[index].origin);
        parent_path(grandparent, folder);
        refresh_tree_folder(grandparent);
        refresh_tree_folder(folder);
    }
    free(sources);
    free(targets);
    update_bin_icon();
    refresh();
}

static void empty_bin(void)
{
    if (!bin_has_items()) {
        MessageBoxA(hMain, "The Recycle Bin is already empty.", BIN_NAME,
                    MB_OK | MB_ICONINFORMATION);
        return;
    }
    SHEmptyRecycleBinA(hMain, NULL, 0);  /* It asks first */
    update_bin_icon();
    if (is_bin(current))
        refresh();
}

static void new_folder(void)
{
    char path[MAX_PATH], name[MAX_PATH];
    int n = 1, i;
    if (is_read_only(current)) {
        read_only_message();
        return;
    }
    do {
        if (n == 1)
            lstrcpyA(name, "New Folder");
        else
            wsprintfA(name, "New Folder (%d)", n);
        join_path(path, current, name);
        n++;
    } while (GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES);
    if (!CreateDirectoryA(path, NULL)) {
        MessageBoxA(hMain, "Cannot create the folder.", "My Computer", MB_OK | MB_ICONERROR);
        return;
    }
    refresh_tree_folder(current);
    load_list(name);
    SetFocus(hList);
    for (i = 0; i < entry_count; i++)
        if (lstrcmpiA(entries[i].name, name) == 0)
            SendMessageA(hList, LVM_EDITLABELA, row_of_entry(i), 0);
}

static void rename_selection(void)
{
    int row = first_selected();
    if (is_computer(current) || row < 0)
        return;
    if (is_read_only(current)) {
        read_only_message();
        return;
    }
    SetFocus(hList);
    SendMessageA(hList, LVM_EDITLABELA, row, 0);
}

/* The label editor closed: rename the file (TRUE keeps the new label) */
static int finish_rename(int row, const char *name)
{
    char old_path[MAX_PATH], new_path[MAX_PATH], message[MAX_PATH + 96];
    int index = entry_of_row(row);
    if (!name || index < 0)
        return FALSE;
    if (!name[0] || strpbrk(name, "\\/:*?\"<>|")) {
        MessageBoxA(hMain, "A file name can't be empty or contain any of these characters:\n"
                    "\\ / : * ? \" < > |", "Rename", MB_OK | MB_ICONERROR);
        return FALSE;
    }
    if (lstrcmpA(name, entries[index].name) == 0)
        return FALSE;
    entry_path(old_path, &entries[index]);
    join_path(new_path, current, name);
    if (!MoveFileA(old_path, new_path)) {
        wsprintfA(message, "Cannot rename %s: %s", entries[index].name,
                  GetLastError() == ERROR_ALREADY_EXISTS ?
                  "a file with that name already exists." : "access is denied.");
        MessageBoxA(hMain, message, "Rename", MB_OK | MB_ICONERROR);
        return FALSE;
    }
    if (is_dir(&entries[index]))
        refresh_tree_folder(current);
    lstrcpynA(entries[index].name, name, MAX_PATH);
    PostMessageA(hMain, WM_COMMAND, IDM_REFRESH, 0);
    return TRUE;
}

/* ---------- Properties ---------- */

typedef struct {
    char title[MAX_PATH + 16];
    char name[MAX_PATH];
    char labels[7][32];
    char values[7][MAX_PATH];
    int rows;
    int attributes;  /* -1: no attributes (drives, My Computer) */
} Properties;

static void add_row(Properties *p, const char *label, const char *value)
{
    if (p->rows < 7) {
        lstrcpynA(p->labels[p->rows], label, 32);
        lstrcpynA(p->values[p->rows], value, MAX_PATH);
        p->rows++;
    }
}

/* Total size, files and folders inside a folder */
static void folder_totals(const char *path, ULONGLONG *bytes, int *files, int *folders, int depth)
{
    char pattern[MAX_PATH], child[MAX_PATH];
    WIN32_FIND_DATAA fd;
    HANDLE find;
    if (depth > 32)
        return;
    join_path(pattern, path, "*");
    find = FindFirstFileA(pattern, &fd);
    if (find == INVALID_HANDLE_VALUE)
        return;
    do {
        if (!lstrcmpA(fd.cFileName, ".") || !lstrcmpA(fd.cFileName, ".."))
            continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            (*folders)++;
            join_path(child, path, fd.cFileName);
            folder_totals(child, bytes, files, folders, depth + 1);
        } else {
            (*files)++;
            *bytes += ((ULONGLONG)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
        }
    } while (FindNextFileA(find, &fd));
    FindClose(find);
}

static void size_text(char *out, ULONGLONG bytes)
{
    char size[32], number[32];
    format_size(size, bytes);
    format_number(number, bytes);
    wsprintfA(out, "%s (%s bytes)", size, number);
}

static void fill_properties(Properties *p, const char *path)
{
    char text[MAX_PATH], folder[MAX_PATH];
    memset(p, 0, sizeof(*p));
    p->attributes = -1;
    if (is_computer(path)) {
        char roots[256], *root;
        int drives = 0;
        lstrcpyA(p->name, "My Computer");
        add_row(p, "Type:", "System Folder");
        if (GetLogicalDriveStringsA(sizeof(roots), roots))
            for (root = roots; *root; root += lstrlenA(root) + 1)
                drives++;
        wsprintfA(text, "%d", drives);
        add_row(p, "Drives:", text);
    } else if (is_bin(path)) {
        SHQUERYRBINFO info;
        lstrcpyA(p->name, BIN_NAME);
        add_row(p, "Type:", "System Folder");
        memset(&info, 0, sizeof(info));
        info.cbSize = sizeof(info);
        if (SHQueryRecycleBinA(NULL, &info) == S_OK) {
            wsprintfA(text, "%u", (unsigned)info.i64NumItems);
            add_row(p, "Items:", text);
            size_text(text, (ULONGLONG)info.i64Size);
            add_row(p, "Size:", text);
        }
        add_row(p, "", "Deleted files of the hard disks. The floppy A: has none.");
    } else if (is_network(path)) {
        lstrcpyA(p->name, NETWORK_NAME);
        add_row(p, "Type:", "System Folder");
        add_row(p, "", "This computer is not connected to a network.");
    } else if (is_root(path)) {
        char file_system[32] = "";
        ULARGE_INTEGER free_bytes, total_bytes;
        drive_label(p->name, path);
        shell_icon(path, FILE_ATTRIBUTE_DIRECTORY, text, sizeof(text));
        add_row(p, "Type:", text);
        GetVolumeInformationA(path, NULL, 0, NULL, NULL, NULL, file_system, sizeof(file_system));
        add_row(p, "File system:", file_system);
        if (GetDiskFreeSpaceExA(path, &free_bytes, &total_bytes, NULL)) {
            size_text(text, total_bytes.QuadPart - free_bytes.QuadPart);
            add_row(p, "Used space:", text);
            size_text(text, free_bytes.QuadPart);
            add_row(p, "Free space:", text);
            size_text(text, total_bytes.QuadPart);
            add_row(p, "Capacity:", text);
        }
        if (GetDriveTypeA(path) == DRIVE_CDROM)
            add_row(p, "", "Read-only (CD-ROM)");
    } else {
        WIN32_FIND_DATAA fd;
        HANDLE find = FindFirstFileA(path, &fd);
        if (find == INVALID_HANDLE_VALUE) {
            lstrcpyA(p->name, base_name(path));
            add_row(p, "", "The item does not exist any more.");
        } else {
            ULONGLONG bytes = ((ULONGLONG)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
            FindClose(find);
            lstrcpyA(p->name, fd.cFileName);
            shell_icon(path, fd.dwFileAttributes, text, sizeof(text));
            add_row(p, "Type:", text);
            parent_path(folder, path);
            add_row(p, "Location:", folder);
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                int files = 0, folders = 0;
                bytes = 0;
                folder_totals(path, &bytes, &files, &folders, 0);
                size_text(text, bytes);
                add_row(p, "Size:", text);
                wsprintfA(text, "%d Files, %d Folders", files, folders);
                add_row(p, "Contains:", text);
            } else {
                size_text(text, bytes);
                add_row(p, "Size:", text);
            }
            format_time(text, &fd.ftLastWriteTime);
            add_row(p, "Modified:", text);
            format_time(text, &fd.ftLastAccessTime);
            add_row(p, "Accessed:", text);
            p->attributes = (int)fd.dwFileAttributes;
        }
    }
    wsprintfA(p->title, "%s Properties", p->name);
}

static INT_PTR CALLBACK PropertiesProc(HWND dlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    const Properties *p;
    int i;
    switch (msg) {
    case WM_INITDIALOG:
        p = (const Properties *)lParam;
        SetWindowTextA(dlg, p->title);
        SetDlgItemTextA(dlg, IDC_PROP_NAME, p->name);
        for (i = 0; i < 7; i++) {
            SetDlgItemTextA(dlg, IDC_PROP_LABEL1 + i, i < p->rows ? p->labels[i] : "");
            SetDlgItemTextA(dlg, IDC_PROP_VALUE1 + i, i < p->rows ? p->values[i] : "");
        }
        if (p->attributes < 0) {
            ShowWindow(GetDlgItem(dlg, IDC_PROP_ATTR_LABEL), SW_HIDE);
            ShowWindow(GetDlgItem(dlg, IDC_PROP_READONLY), SW_HIDE);
            ShowWindow(GetDlgItem(dlg, IDC_PROP_HIDDEN), SW_HIDE);
        } else {
            CheckDlgButton(dlg, IDC_PROP_READONLY,
                           p->attributes & FILE_ATTRIBUTE_READONLY ? BST_CHECKED : BST_UNCHECKED);
            CheckDlgButton(dlg, IDC_PROP_HIDDEN,
                           p->attributes & FILE_ATTRIBUTE_HIDDEN ? BST_CHECKED : BST_UNCHECKED);
        }
        return TRUE;
    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL) {
            EndDialog(dlg, 0);
            return TRUE;
        }
        break;
    case WM_CLOSE:
        EndDialog(dlg, 0);
        return TRUE;
    }
    return FALSE;
}

static void show_properties(const char *path)
{
    Properties *p = malloc(sizeof(Properties));
    if (!p)
        return;
    fill_properties(p, path);
    DialogBoxParamA(hInst, MAKEINTRESOURCEA(IDD_PROPERTIES), hMain, PropertiesProc, (LPARAM)p);
    free(p);
}

/* A deleted item: where it came from and when it was deleted */
static void show_bin_properties(const Entry *e)
{
    char text[MAX_PATH];
    Properties *p = malloc(sizeof(Properties));
    if (!p)
        return;
    memset(p, 0, sizeof(*p));
    p->attributes = -1;
    lstrcpynA(p->name, e->name, MAX_PATH);
    add_row(p, "Type:", e->type);
    parent_path(text, e->origin);
    add_row(p, "Origin:", text);
    format_time(text, &e->modified);
    add_row(p, "Deleted:", text);
    size_text(text, e->size);
    add_row(p, "Size:", text);
    add_row(p, "", "Restore it to open it.");
    wsprintfA(p->title, "%s Properties", p->name);
    DialogBoxParamA(hInst, MAKEINTRESOURCEA(IDD_PROPERTIES), hMain, PropertiesProc, (LPARAM)p);
    free(p);
}

/* Properties of the selection, or of the current folder */
static void properties_of_selection(void)
{
    char path[MAX_PATH];
    int index = entry_of_row(first_selected());
    if (selected_count() == 1 && index >= 0 && is_bin(current)) {
        show_bin_properties(&entries[index]);
        return;
    }
    if (selected_count() == 1 && index >= 0)
        entry_path(path, &entries[index]);
    else
        lstrcpyA(path, current);
    show_properties(path);
}

/* ---------- Menus ---------- */

static HMENU create_menu(void)
{
    HMENU menu = CreateMenu(), file = CreatePopupMenu(), edit = CreatePopupMenu();
    HMENU view = CreatePopupMenu(), go = CreatePopupMenu(), help = CreatePopupMenu();
    AppendMenuA(file, MF_STRING, IDM_OPEN, "&Open\tEnter");
    AppendMenuA(file, MF_SEPARATOR, 0, NULL);
    AppendMenuA(file, MF_STRING, IDM_NEWFOLDER, "New &Folder\tCtrl+Shift+N");
    AppendMenuA(file, MF_SEPARATOR, 0, NULL);
    AppendMenuA(file, MF_STRING, IDM_DELETE, "&Delete\tDel");
    AppendMenuA(file, MF_STRING, IDM_PURGE, "Delete Per&manently\tShift+Del");
    AppendMenuA(file, MF_STRING, IDM_RENAME, "Rena&me\tF2");
    AppendMenuA(file, MF_STRING, IDM_PROPERTIES, "P&roperties\tAlt+Enter");
    AppendMenuA(file, MF_SEPARATOR, 0, NULL);
    AppendMenuA(file, MF_STRING, IDM_RESTORE, "R&estore");
    AppendMenuA(file, MF_STRING, IDM_EMPTYBIN, "Empty Recycle &Bin");
    AppendMenuA(file, MF_SEPARATOR, 0, NULL);
    AppendMenuA(file, MF_STRING, IDM_EXIT, "&Close");
    AppendMenuA(edit, MF_STRING, IDM_CUT, "Cu&t\tCtrl+X");
    AppendMenuA(edit, MF_STRING, IDM_COPY, "&Copy\tCtrl+C");
    AppendMenuA(edit, MF_STRING, IDM_PASTE, "&Paste\tCtrl+V");
    AppendMenuA(edit, MF_SEPARATOR, 0, NULL);
    AppendMenuA(edit, MF_STRING, IDM_SELECTALL, "Select &All\tCtrl+A");
    AppendMenuA(view, MF_STRING, IDM_REFRESH, "&Refresh\tF5");
    AppendMenuA(go, MF_STRING, IDM_BACK, "&Back\tAlt+Left");
    AppendMenuA(go, MF_STRING, IDM_FORWARD, "&Forward\tAlt+Right");
    AppendMenuA(go, MF_STRING, IDM_UP, "&Up One Level\tBackspace");
    AppendMenuA(go, MF_SEPARATOR, 0, NULL);
    AppendMenuA(go, MF_STRING, IDM_COMPUTER, "&My Computer");
    AppendMenuA(go, MF_STRING, IDM_GO_USER, "U&ser Folder");
    AppendMenuA(go, MF_STRING, IDM_GO_NETWORK, "&Network");
    AppendMenuA(go, MF_STRING, IDM_GO_BIN, "&Recycle Bin");
    AppendMenuA(help, MF_STRING, IDM_ABOUT, "&About My Computer");
    AppendMenuA(menu, MF_POPUP, (UINT_PTR)file, "&File");
    AppendMenuA(menu, MF_POPUP, (UINT_PTR)edit, "&Edit");
    AppendMenuA(menu, MF_POPUP, (UINT_PTR)view, "&View");
    AppendMenuA(menu, MF_POPUP, (UINT_PTR)go, "&Go");
    AppendMenuA(menu, MF_POPUP, (UINT_PTR)help, "&Help");
    return menu;
}

/* Gray out the commands that can't be used now */
static void update_menu(HMENU menu)
{
    int selection = selected_count() > 0 && !is_computer(current);
    int writable = !is_read_only(current);
    int deletable = selection && (writable || is_bin(current));
    EnableMenuItem(menu, IDM_OPEN, selected_count() == 1 ? MF_ENABLED : MF_GRAYED);
    EnableMenuItem(menu, IDM_NEWFOLDER, writable ? MF_ENABLED : MF_GRAYED);
    EnableMenuItem(menu, IDM_DELETE, deletable ? MF_ENABLED : MF_GRAYED);
    EnableMenuItem(menu, IDM_PURGE, deletable ? MF_ENABLED : MF_GRAYED);
    EnableMenuItem(menu, IDM_RESTORE, selection && is_bin(current) ? MF_ENABLED : MF_GRAYED);
    EnableMenuItem(menu, IDM_EMPTYBIN, bin_has_items() ? MF_ENABLED : MF_GRAYED);
    EnableMenuItem(menu, IDM_RENAME, selected_count() == 1 && selection && writable ?
                   MF_ENABLED : MF_GRAYED);
    EnableMenuItem(menu, IDM_CUT, selection && writable ? MF_ENABLED : MF_GRAYED);
    EnableMenuItem(menu, IDM_COPY, selection ? MF_ENABLED : MF_GRAYED);
    EnableMenuItem(menu, IDM_PASTE, clip_paths && writable ? MF_ENABLED : MF_GRAYED);
    EnableMenuItem(menu, IDM_BACK, back_count ? MF_ENABLED : MF_GRAYED);
    EnableMenuItem(menu, IDM_FORWARD, forward_count ? MF_ENABLED : MF_GRAYED);
    EnableMenuItem(menu, IDM_UP, !is_virtual(current) ? MF_ENABLED : MF_GRAYED);
}

static void popup_at(HMENU menu, int x, int y)
{
    int command;
    update_menu(menu);
    command = (int)TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, x, y, 0, hMain, NULL);
    DestroyMenu(menu);
    if (command)
        SendMessageA(hMain, WM_COMMAND, command, 0);
}

/* The list's context menu: the selected items', or the folder's on empty space */
static void list_context_menu(int x, int y)
{
    HMENU menu = CreatePopupMenu();
    if (is_bin(current)) {
        /* Deleted items: back where they were, or gone for good */
        if (selected_count() > 0) {
            AppendMenuA(menu, MF_STRING, IDM_RESTORE, "R&estore");
            AppendMenuA(menu, MF_SEPARATOR, 0, NULL);
            AppendMenuA(menu, MF_STRING, IDM_DELETE, "&Delete");
        } else {
            AppendMenuA(menu, MF_STRING, IDM_REFRESH, "R&efresh");
            AppendMenuA(menu, MF_SEPARATOR, 0, NULL);
            AppendMenuA(menu, MF_STRING, IDM_EMPTYBIN, "Empty Recycle &Bin");
        }
    } else if (is_network(current)) {
        AppendMenuA(menu, MF_STRING, IDM_REFRESH, "R&efresh");
    } else if (selected_count() > 0) {
        AppendMenuA(menu, MF_STRING, IDM_OPEN, "&Open");
        if (!is_computer(current)) {
            AppendMenuA(menu, MF_SEPARATOR, 0, NULL);
            AppendMenuA(menu, MF_STRING, IDM_CUT, "Cu&t");
            AppendMenuA(menu, MF_STRING, IDM_COPY, "&Copy");
            AppendMenuA(menu, MF_SEPARATOR, 0, NULL);
            AppendMenuA(menu, MF_STRING, IDM_DELETE, "&Delete");
            AppendMenuA(menu, MF_STRING, IDM_RENAME, "Rena&me");
        }
    } else {
        AppendMenuA(menu, MF_STRING, IDM_REFRESH, "R&efresh");
        if (!is_computer(current)) {
            AppendMenuA(menu, MF_SEPARATOR, 0, NULL);
            AppendMenuA(menu, MF_STRING, IDM_PASTE, "&Paste");
            AppendMenuA(menu, MF_SEPARATOR, 0, NULL);
            AppendMenuA(menu, MF_STRING, IDM_NEWFOLDER, "New &Folder");
        }
    }
    AppendMenuA(menu, MF_SEPARATOR, 0, NULL);
    AppendMenuA(menu, MF_STRING, IDM_PROPERTIES, "P&roperties");
    popup_at(menu, x, y);
}

/* A tree folder's context menu: Expand/Collapse, Open, Paste, Properties */
static void tree_context_menu(int x, int y)
{
    TVHITTESTINFO hit;
    HMENU menu;
    const char *path;
    char folder[MAX_PATH];
    TVITEMA tv;
    int command;
    POINT pt;
    pt.x = x;
    pt.y = y;
    ScreenToClient(hTree, &pt);
    memset(&hit, 0, sizeof(hit));
    hit.pt = pt;
    SendMessageA(hTree, TVM_HITTEST, 0, (LPARAM)&hit);
    if (!hit.hItem)
        hit.hItem = (HTREEITEM)SendMessageA(hTree, TVM_GETNEXTITEM, TVGN_CARET, 0);
    path = tree_path(hit.hItem);
    if (!path)
        return;
    lstrcpyA(folder, path);
    memset(&tv, 0, sizeof(tv));
    tv.mask = TVIF_STATE;
    tv.hItem = hit.hItem;
    tv.stateMask = TVIS_EXPANDED;
    SendMessageA(hTree, TVM_GETITEMA, 0, (LPARAM)&tv);
    menu = CreatePopupMenu();
    AppendMenuA(menu, MF_STRING, IDM_EXPAND, tv.state & TVIS_EXPANDED ? "Collapse" : "&Expand");
    AppendMenuA(menu, MF_STRING, IDM_OPEN, "&Open");
    if (!is_virtual(folder)) {
        AppendMenuA(menu, MF_SEPARATOR, 0, NULL);
        AppendMenuA(menu, MF_STRING | (clip_paths && !is_read_only(folder) ? 0 : MF_GRAYED),
                    IDM_PASTE, "&Paste");
    } else if (is_bin(folder)) {
        AppendMenuA(menu, MF_SEPARATOR, 0, NULL);
        AppendMenuA(menu, MF_STRING | (bin_has_items() ? 0 : MF_GRAYED), IDM_EMPTYBIN,
                    "Empty Recycle &Bin");
    }
    AppendMenuA(menu, MF_SEPARATOR, 0, NULL);
    AppendMenuA(menu, MF_STRING, IDM_PROPERTIES, "P&roperties");
    command = (int)TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, x, y, 0, hMain, NULL);
    DestroyMenu(menu);
    switch (command) {
    case IDM_EXPAND:
        SendMessageA(hTree, TVM_EXPAND, TVE_TOGGLE, (LPARAM)hit.hItem);
        break;
    case IDM_OPEN:
        navigate(folder, 1);
        break;
    case IDM_PASTE:
        paste_into(folder);
        break;
    case IDM_EMPTYBIN:
        empty_bin();
        break;
    case IDM_PROPERTIES:
        show_properties(folder);
        break;
    }
}

/* ---------- The window ---------- */

static void layout(int width, int height)
{
    RECT status;
    int status_h, body_y = BAR_H + 2, body_h;
    SendMessageA(hStatus, WM_SIZE, 0, 0);
    GetWindowRect(hStatus, &status);
    status_h = status.bottom - status.top;
    body_h = height - body_y - status_h;
    MoveWindow(GetDlgItem(hMain, ID_BACK), 4, 4, BUTTON_W, BAR_H - 6, TRUE);
    MoveWindow(GetDlgItem(hMain, ID_FORWARD), 8 + BUTTON_W, 4, BUTTON_W, BAR_H - 6, TRUE);
    MoveWindow(GetDlgItem(hMain, ID_UP), 12 + 2 * BUTTON_W, 4, BUTTON_W, BAR_H - 6, TRUE);
    MoveWindow(GetDlgItem(hMain, ID_ADDRESS_LABEL), 22 + 3 * BUTTON_W, 9, 52, 16, TRUE);
    MoveWindow(hAddress, 78 + 3 * BUTTON_W, 5, width - 124 - 3 * BUTTON_W, BAR_H - 8, TRUE);
    MoveWindow(GetDlgItem(hMain, ID_GO), width - 42, 4, 38, BAR_H - 6, TRUE);
    MoveWindow(hTree, 0, body_y, TREE_W, body_h, TRUE);
    MoveWindow(hList, TREE_W + 3, body_y, width - TREE_W - 3, body_h, TRUE);
}

static HWND create_child(const char *cls, const char *text, DWORD ex_style, DWORD style, int id)
{
    return CreateWindowExA(ex_style, cls, text, WS_CHILD | WS_VISIBLE | style, 0, 0, 0, 0,
                           hMain, (HMENU)(INT_PTR)id, hInst, NULL);
}

/* The address bar: Enter goes to the typed path, Escape restores it */
static LRESULT CALLBACK AddressProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == WM_KEYDOWN && wParam == VK_RETURN) {
        PostMessageA(hMain, WM_COMMAND, IDM_GO, 0);
        return 0;
    }
    if (msg == WM_KEYDOWN && wParam == VK_ESCAPE) {
        char text[MAX_PATH];
        display_name(text, current);
        SetWindowTextA(hwnd, text);
        SetFocus(hList);
        return 0;
    }
    if (msg == WM_CHAR && (wParam == '\r' || wParam == 27))
        return 0;
    return CallWindowProcA(address_proc, hwnd, msg, wParam, lParam);
}

static void create_controls(HWND hwnd)
{
    SHFILEINFOA info;
    hMain = hwnd;
    create_child("BUTTON", "< Back", 0, BS_PUSHBUTTON, ID_BACK);
    create_child("BUTTON", "Forward >", 0, BS_PUSHBUTTON, ID_FORWARD);
    create_child("BUTTON", "Up", 0, BS_PUSHBUTTON, ID_UP);
    create_child("STATIC", "Address", 0, 0, ID_ADDRESS_LABEL);
    hAddress = create_child("EDIT", "", WS_EX_CLIENTEDGE, ES_AUTOHSCROLL | WS_TABSTOP,
                            ID_ADDRESS);
    address_proc = (WNDPROC)SetWindowLongA(hAddress, GWL_WNDPROC, (LONG)(LONG_PTR)AddressProc);
    create_child("BUTTON", "Go", 0, BS_PUSHBUTTON, ID_GO);
    hTree = create_child(WC_TREEVIEWA, "", WS_EX_CLIENTEDGE,
                         TVS_HASBUTTONS | TVS_HASLINES | TVS_LINESATROOT | TVS_SHOWSELALWAYS |
                         WS_TABSTOP, ID_TREE);
    hList = create_child(WC_LISTVIEWA, "", WS_EX_CLIENTEDGE,
                         LVS_REPORT | LVS_SHOWSELALWAYS | LVS_EDITLABELS | WS_TABSTOP, ID_LIST);
    hStatus = CreateStatusWindowA(WS_CHILD | WS_VISIBLE, "", hwnd, ID_STATUS);
    SendMessageA(hList, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_FULLROWSELECT,
                 LVS_EX_FULLROWSELECT);
    memset(&info, 0, sizeof(info));
    hImages = (HIMAGELIST)SHGetFileInfoA("C:\\", 0, &info, sizeof(info),
                                         SHGFI_SYSICONINDEX | SHGFI_SMALLICON);
    SendMessageA(hList, LVM_SETIMAGELIST, LVSIL_SMALL, (LPARAM)hImages);
    SendMessageA(hTree, TVM_SETIMAGELIST, TVSIL_NORMAL, (LPARAM)hImages);
    build_tree();
}

static LRESULT on_notify(NMHDR *nm)
{
    if (nm->hwndFrom == hList) {
        switch (nm->code) {
        case NM_DBLCLK:
        case NM_RETURN: {
            int row = nm->code == NM_DBLCLK ? ((NMITEMACTIVATE *)nm)->iItem : first_selected();
            if (row >= 0)
                open_entry(entry_of_row(row));
            return 0;
        }
        case LVN_ITEMCHANGED:
            update_status();
            return 0;
        case LVN_COLUMNCLICK: {
            int column = ((NMLISTVIEW *)nm)->iSubItem;
            if (is_computer(current) || is_network(current))
                return 0;
            if (column == sort_column)
                sort_ascending = !sort_ascending;
            else
                sort_column = column, sort_ascending = 1;
            sort_list();
            return 0;
        }
        case LVN_BEGINLABELEDITA:
        case LVN_BEGINLABELEDITW:
            /* No renaming in My Computer or on the CD-ROM */
            return is_computer(current) || is_read_only(current);
        case LVN_ENDLABELEDITA: {
            NMLVDISPINFOA *info = (NMLVDISPINFOA *)nm;
            return finish_rename(info->item.iItem, info->item.pszText);
        }
        case LVN_ENDLABELEDITW: {
            NMLVDISPINFOW *info = (NMLVDISPINFOW *)nm;
            char name[MAX_PATH];
            if (!info->item.pszText)
                return FALSE;
            WideCharToMultiByte(CP_ACP, 0, info->item.pszText, -1, name, sizeof(name),
                                NULL, NULL);
            return finish_rename(info->item.iItem, name);
        }
        }
    } else if (nm->hwndFrom == hTree) {
        switch (nm->code) {
        case TVN_ITEMEXPANDINGA:
        case TVN_ITEMEXPANDINGW: {
            NMTREEVIEWA *tv = (NMTREEVIEWA *)nm;
            if (tv->action & TVE_EXPAND)
                fill_tree_item(tv->itemNew.hItem);
            return FALSE;
        }
        case TVN_SELCHANGEDA:
        case TVN_SELCHANGEDW: {
            NMTREEVIEWA *tv = (NMTREEVIEWA *)nm;
            const char *path = tree_path(tv->itemNew.hItem);
            if (!syncing_tree && path && lstrcmpiA(path, current) != 0) {
                char target[MAX_PATH];
                lstrcpyA(target, path);
                navigate(target, 1);
            }
            return 0;
        }
        case TVN_DELETEITEMA:
        case TVN_DELETEITEMW:
            free((void *)((NMTREEVIEWA *)nm)->itemOld.lParam);
            return 0;
        }
    }
    return 0;
}

static void on_command(int id)
{
    switch (id) {
    case ID_BACK:
    case IDM_BACK:
        go_back();
        break;
    case ID_FORWARD:
    case IDM_FORWARD:
        go_forward();
        break;
    case ID_UP:
    case IDM_UP:
        go_up();
        break;
    case ID_GO:
    case IDM_GO:
        go_address();
        break;
    case IDM_ADDRESS:
        SetFocus(hAddress);
        SendMessageA(hAddress, EM_SETSEL, 0, -1);
        break;
    case IDM_COMPUTER:
        navigate("", 1);
        break;
    case IDM_OPEN:
        open_selected();
        break;
    case IDM_REFRESH:
        refresh();
        break;
    case IDM_NEWFOLDER:
        new_folder();
        break;
    case IDM_DELETE:
        delete_selection(0);
        break;
    case IDM_PURGE:
        delete_selection(1);
        break;
    case IDM_RESTORE:
        restore_selection();
        break;
    case IDM_EMPTYBIN:
        empty_bin();
        break;
    case IDM_GO_USER: {
        char profile[MAX_PATH];
        if (SHGetSpecialFolderPathA(hMain, profile, CSIDL_PROFILE, TRUE))
            navigate(profile, 1);
        break;
    }
    case IDM_GO_NETWORK:
        navigate(NETWORK_PATH, 1);
        break;
    case IDM_GO_BIN:
        navigate(BIN_PATH, 1);
        break;
    case IDM_RENAME:
        rename_selection();
        break;
    case IDM_PROPERTIES:
        properties_of_selection();
        break;
    case IDM_CUT:
        copy_selection(1);
        break;
    case IDM_COPY:
        copy_selection(0);
        break;
    case IDM_PASTE:
        paste_into(current);
        break;
    case IDM_SELECTALL: {
        LVITEMA item;
        memset(&item, 0, sizeof(item));
        item.state = item.stateMask = LVIS_SELECTED;
        SendMessageA(hList, LVM_SETITEMSTATE, (WPARAM)-1, (LPARAM)&item);
        SetFocus(hList);
        break;
    }
    case IDM_EXIT:
        DestroyWindow(hMain);
        break;
    case IDM_ABOUT:
        MessageBoxA(hMain, "My Computer for winexe32emu\n\n"
                    "Browse the drives A: (floppy disk), C: and D: (CD-ROM, read-only), "
                    "run programs and copy, move, rename or delete files. Deleted files "
                    "go to the Recycle Bin, where they can be restored.\n\n"
                    "This project is not endorsed by, affiliated with, or sponsored by "
                    "Microsoft Corporation in any way. Windows, Win32, and related "
                    "trademarks are the property of Microsoft Corporation.",
                    "About My Computer", MB_OK | MB_ICONINFORMATION);
        break;
    }
}

static void refresh(void)
{
    char name[MAX_PATH] = "";
    int index = entry_of_row(first_selected());
    if (index >= 0)
        lstrcpyA(name, entries[index].name);
    if (!folder_exists(current)) {
        /* The folder is gone: go to the nearest existing one */
        char parent[MAX_PATH];
        while (!folder_exists(current)) {
            parent_path(parent, current);
            lstrcpyA(current, parent);
        }
        navigate(current, 0);
        return;
    }
    load_list(name);
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    RECT rc;
    switch (msg) {
    case WM_CREATE:
        create_controls(hwnd);
        GetClientRect(hwnd, &rc);
        layout(rc.right, rc.bottom);
        navigate(current, 0);
        SetFocus(hList);
        update_bin_icon();
        SetTimer(hwnd, BIN_TIMER, 1000, NULL);
        return 0;

    case WM_TIMER:
        if (wParam == BIN_TIMER)
            check_bin();
        return 0;

    case WM_SIZE:
        if (hList)
            layout(LOWORD(lParam), HIWORD(lParam));
        return 0;

    case WM_SETFOCUS:
        if (hList)
            SetFocus(hList);
        return 0;

    case WM_NOTIFY:
        return on_notify((NMHDR *)lParam);

    case WM_CONTEXTMENU: {
        int x = (short)LOWORD(lParam), y = (short)HIWORD(lParam);
        if (x == -1 && y == -1) {
            POINT pt;
            GetCursorPos(&pt);
            x = pt.x;
            y = pt.y;
        }
        if ((HWND)wParam == hTree)
            tree_context_menu(x, y);
        else if ((HWND)wParam == hList)
            list_context_menu(x, y);
        return 0;
    }

    case WM_INITMENUPOPUP:
        update_menu((HMENU)wParam);
        return 0;

    case WM_COMMAND:
        on_command(LOWORD(wParam));
        return 0;

    case WM_DESTROY:
        KillTimer(hwnd, BIN_TIMER);
        free(entries);
        entries = NULL;
        entry_count = entry_capacity = 0;
        free(clip_paths);
        clip_paths = NULL;
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

/* Start folder from the command line, if it names an existing folder */
static void read_start_folder(const char *cmdline)
{
    char folder[MAX_PATH], full[MAX_PATH];
    int len;
    while (*cmdline == ' ')
        cmdline++;
    lstrcpynA(folder, *cmdline == '"' ? cmdline + 1 : cmdline, MAX_PATH);
    len = lstrlenA(folder);
    while (len > 0 && (folder[len - 1] == '"' || folder[len - 1] == ' '))
        folder[--len] = '\0';
    if (virtual_folder_of(folder)) {  /* The desktop's Recycle Bin and network icons */
        lstrcpyA(current, virtual_folder_of(folder));
        return;
    }
    if (len == 0 || !GetFullPathNameA(folder, MAX_PATH, full, NULL))
        return;
    len = lstrlenA(full);
    if (len > 3 && full[len - 1] == '\\')
        full[len - 1] = '\0';
    if (folder_exists(full))
        lstrcpyA(current, full);
}

/* Keyboard shortcuts, except while typing (the address bar, a label being edited) */
static int is_typing(void)
{
    HWND focus = GetFocus();
    return focus && (focus == hAddress ||
                     focus == (HWND)SendMessageA(hList, LVM_GETEDITCONTROL, 0, 0));
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    WNDCLASSA wc;
    MSG msg;
    HWND hwnd;
    HACCEL accelerators;
    INITCOMMONCONTROLSEX icc;

    hInst = hInstance;
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_TREEVIEW_CLASSES | ICC_BAR_CLASSES;
    InitCommonControlsEx(&icc);
    read_start_folder(lpCmdLine);

    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursorA(NULL, IDC_ARROW);
    wc.hIcon = LoadIconA(hInstance, MAKEINTRESOURCEA(1));
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = "WinExe32EmuExplorer";
    if (!RegisterClassA(&wc))
        return 1;

    hwnd = CreateWindowExA(0, wc.lpszClassName, "My Computer", WS_OVERLAPPEDWINDOW,
                           CW_USEDEFAULT, CW_USEDEFAULT, 720, 460,
                           NULL, create_menu(), hInstance, NULL);
    if (!hwnd)
        return 1;
    accelerators = LoadAcceleratorsA(hInstance, MAKEINTRESOURCEA(IDA_EXPLORER));
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    while (GetMessageA(&msg, NULL, 0, 0) > 0) {
        if (!is_typing() && TranslateAcceleratorA(hwnd, accelerators, &msg))
            continue;
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }
    return (int)msg.wParam;
}
