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
Notepad - a plain text editor.

  - File: New (Ctrl+N), Open (Ctrl+O: the encoding is detected), Open with
    Encoding, Reopen with Encoding, Save (Ctrl+S: keeps the file's encoding
    and line breaks), Save As (Ctrl+Shift+S: asks for both), Exit
  - Edit: Undo, Cut, Copy, Paste, Delete, Find (Ctrl+F), Find Next (F3),
    Replace (Ctrl+H), Go To (Ctrl+G), Select All, Time/Date (F5)
  - Format: Word Wrap, Line Breaks (Windows CRLF / Unix LF / Macintosh CR),
    Encoding
  - View: Status Bar (line and column, line breaks, encoding)
  - Encodings: ANSI (the system code page), UTF-8 with or without BOM,
    UTF-16 LE / BE and the other code pages the system supports; a warning
    before saving characters the chosen encoding cannot represent

The text is kept as UTF-16 with CR LF line breaks in the edit control; the
file's encoding and line breaks are converted by textcodec.c.

Usage: notepad.exe [file]  (a file that does not exist can be created)
*/

#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <stdlib.h>
#include <string.h>

#include "resource.h"
#include "textcodec.h"

#define APP_NAME L"Notepad"
#define PATH_SIZE 1024
#define FIND_SIZE 256
#define STATUS_TIMER 1

static HINSTANCE hInst;
static HWND hMain, hEdit, hStatus, hFindDialog;
static WCHAR file_path[PATH_SIZE];       /* "": Untitled */
static TextEncoding encoding = {TC_UTF8, FALSE};
static int eol = TC_EOL_CRLF;
static BOOL format_changed;              /* Encoding or line breaks chosen since the save */
static BOOL word_wrap, show_status = TRUE;
static UINT find_message;
static FINDREPLACEW find_replace;
static WCHAR find_what[FIND_SIZE], replace_with[FIND_SIZE];
static WCHAR status_shown[3][96];

/* ---------- Small helpers ---------- */

static void message_box(const WCHAR *text, UINT flags)
{
    MessageBoxW(hMain, text, APP_NAME, flags);
}

static const WCHAR *file_title(void)
{
    const WCHAR *name = file_path, *p;
    if (!file_path[0])
        return L"Untitled";
    for (p = file_path; *p; p++)
        if (*p == '\\' || *p == '/' || *p == ':')
            name = p + 1;
    return name;
}

static void update_title(void)
{
    WCHAR title[PATH_SIZE + 32];
    wsprintfW(title, L"%s - Notepad", file_title());
    SetWindowTextW(hMain, title);
}

static BOOL is_modified(void)
{
    return format_changed || SendMessageW(hEdit, EM_GETMODIFY, 0, 0);
}

static void set_unmodified(void)
{
    format_changed = FALSE;
    SendMessageW(hEdit, EM_SETMODIFY, FALSE, 0);
}

/* The edit control's text (malloc); *length: characters */
static WCHAR *edit_text(size_t *length)
{
    int size = GetWindowTextLengthW(hEdit);
    WCHAR *text = malloc((size + 1) * sizeof(WCHAR));
    if (!text)
        return NULL;
    *length = GetWindowTextW(hEdit, text, size + 1);
    text[*length] = 0;
    return text;
}

/* ---------- Status bar ---------- */

static void set_status_part(int part, const WCHAR *text)
{
    if (lstrcmpW(status_shown[part], text) == 0)
        return;  /* Unchanged: the timer would repaint it all the time */
    lstrcpynW(status_shown[part], text, 96);
    SendMessageW(hStatus, SB_SETTEXTW, part, (LPARAM)text);
}

static void update_status(void)
{
    WCHAR text[96];
    DWORD caret = 0;
    LRESULT line, start;

    if (!show_status || !hStatus)
        return;
    SendMessageW(hEdit, EM_GETSEL, 0, (LPARAM)&caret);
    line = SendMessageW(hEdit, EM_LINEFROMCHAR, caret, 0);
    start = SendMessageW(hEdit, EM_LINEINDEX, line, 0);
    wsprintfW(text, L"Ln %d, Col %d", (int)line + 1, (int)(caret - start) + 1);
    set_status_part(0, text);
    set_status_part(1, tc_eol_name(eol));
    tc_encoding_name(&encoding, text, 96);
    set_status_part(2, text);
}

static void layout(void)
{
    RECT client, bar;
    int status_h = 0;
    GetClientRect(hMain, &client);
    if (show_status && hStatus) {
        int parts[3];
        SendMessageW(hStatus, WM_SIZE, 0, 0);
        GetWindowRect(hStatus, &bar);
        status_h = bar.bottom - bar.top;
        parts[0] = client.right - 330 > 120 ? client.right - 330 : 120;
        parts[1] = parts[0] + 130;
        parts[2] = -1;
        SendMessageW(hStatus, SB_SETPARTS, 3, (LPARAM)parts);
    }
    MoveWindow(hEdit, 0, 0, client.right, client.bottom - status_h, TRUE);
}

/* ---------- The edit control ---------- */

static HWND create_edit(void)
{
    /* Without word wrap the text scrolls sideways; with it the edit control
       breaks the long lines at its width */
    DWORD style = WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL |
                  ES_NOHIDESEL | ES_WANTRETURN;
    HWND edit;
    if (!word_wrap)
        style |= WS_HSCROLL | ES_AUTOHSCROLL;
    edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", style, 0, 0, 100, 100, hMain,
                           (HMENU)IDC_EDIT, hInst, NULL);
    /* No 32K default limit: a text file can be a few megabytes */
    SendMessageW(edit, EM_SETLIMITTEXT, 0, 0);
    return edit;
}

static void set_word_wrap(BOOL wrap)
{
    size_t length;
    WCHAR *text = edit_text(&length);
    DWORD start = 0, end = 0;
    BOOL modified = SendMessageW(hEdit, EM_GETMODIFY, 0, 0) != 0;
    HWND old = hEdit;

    if (!text)
        return;
    SendMessageW(hEdit, EM_GETSEL, (WPARAM)&start, (LPARAM)&end);
    word_wrap = wrap;
    hEdit = create_edit();
    DestroyWindow(old);
    SetWindowTextW(hEdit, text);
    free(text);
    SendMessageW(hEdit, EM_SETSEL, start, end);
    SendMessageW(hEdit, EM_SCROLLCARET, 0, 0);
    SendMessageW(hEdit, EM_SETMODIFY, modified, 0);
    layout();
    SetFocus(hEdit);
    update_status();
}

/* ---------- Encoding dialog ---------- */

#define ENC_OPEN   0  /* Encoding of a file to open: "Auto-detect" first */
#define ENC_SAVE   1  /* Encoding and line breaks to save in */
#define ENC_FORMAT 2  /* Encoding and line breaks of the document */

typedef struct {
    int mode;
    TextEncoding encoding;
    BOOL detect;  /* ENC_OPEN: Auto-detect chosen */
    int eol;
} EncodingChoice;

#define AUTO_DETECT ((LPARAM)-1)

static LPARAM encoding_key(const TextEncoding *enc)
{
    return (LPARAM)((enc->codepage << 1) | (enc->bom ? 1 : 0));
}

static void add_encoding(HWND combo, const WCHAR *name, LPARAM key)
{
    LRESULT index = SendMessageW(combo, CB_ADDSTRING, 0, (LPARAM)name);
    SendMessageW(combo, CB_SETITEMDATA, index, key);
}

static void fill_encodings(HWND combo, EncodingChoice *choice)
{
    WCHAR name[128];
    LPARAM current = encoding_key(&choice->encoding);
    BOOL listed = FALSE;
    int i, count;

    if (choice->mode == ENC_OPEN)
        add_encoding(combo, L"Auto-detect", AUTO_DETECT);
    for (i = 0; i < tc_encoding_count; i++) {
        const TextEncodingInfo *info = &tc_encodings[i];
        TextEncoding enc;
        enc.codepage = info->codepage;
        enc.bom = info->bom;
        if (info->codepage == TC_ANSI) {
            tc_encoding_name(&enc, name, 128);
        } else if (info->codepage == TC_UTF8 || info->codepage == TC_UTF16LE ||
                   info->codepage == TC_UTF16BE) {
            lstrcpynW(name, info->name, 128);
        } else if (!IsValidCodePage(info->codepage)) {
            continue;  /* The system has no table for it */
        } else {
            lstrcpynW(name, info->name, 128);
        }
        add_encoding(combo, name, encoding_key(&enc));
        if (encoding_key(&enc) == current)
            listed = TRUE;
    }
    if (!listed && choice->mode != ENC_OPEN) {
        /* UTF-16 without a byte order mark, a code page not in the list */
        tc_encoding_name(&choice->encoding, name, 128);
        add_encoding(combo, name, current);
    }
    count = (int)SendMessageW(combo, CB_GETCOUNT, 0, 0);
    for (i = 0; i < count; i++) {
        LPARAM key = SendMessageW(combo, CB_GETITEMDATA, i, 0);
        if ((choice->mode == ENC_OPEN && choice->detect) ? key == AUTO_DETECT : key == current) {
            SendMessageW(combo, CB_SETCURSEL, i, 0);
            break;
        }
    }
}

static INT_PTR CALLBACK encoding_proc(HWND dlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    EncodingChoice *choice = (EncodingChoice *)GetWindowLongPtrW(dlg, DWLP_USER);
    HWND eol_combo;
    int i;

    switch (msg) {
    case WM_INITDIALOG:
        choice = (EncodingChoice *)lParam;
        SetWindowLongPtrW(dlg, DWLP_USER, (LONG_PTR)choice);
        fill_encodings(GetDlgItem(dlg, IDC_ENCODING), choice);
        eol_combo = GetDlgItem(dlg, IDC_EOL);
        for (i = TC_EOL_CRLF; i <= TC_EOL_CR; i++)
            SendMessageW(eol_combo, CB_ADDSTRING, 0, (LPARAM)tc_eol_name(i));
        SendMessageW(eol_combo, CB_SETCURSEL, choice->eol, 0);
        if (choice->mode == ENC_OPEN) {
            ShowWindow(eol_combo, SW_HIDE);
            ShowWindow(GetDlgItem(dlg, IDC_EOL_LABEL), SW_HIDE);
            SetWindowTextW(dlg, L"Open with Encoding");
            SetDlgItemTextW(dlg, IDC_ENCODING_NOTE,
                            L"Read the file in this encoding (its line breaks are "
                            L"recognized by themselves):");
        } else {
            SetWindowTextW(dlg, choice->mode == ENC_SAVE ? L"Save As - Encoding" : L"Encoding");
            SetDlgItemTextW(dlg, IDC_ENCODING_NOTE, choice->mode == ENC_SAVE ?
                            L"Save the file in this encoding, with these line breaks:" :
                            L"The encoding and line breaks the next Save writes:");
        }
        return TRUE;
    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK) {
            HWND combo = GetDlgItem(dlg, IDC_ENCODING);
            LRESULT index = SendMessageW(combo, CB_GETCURSEL, 0, 0);
            if (index >= 0) {
                LPARAM key = SendMessageW(combo, CB_GETITEMDATA, index, 0);
                choice->detect = key == AUTO_DETECT;
                if (!choice->detect) {
                    choice->encoding.codepage = (UINT)key >> 1;
                    choice->encoding.bom = (key & 1) != 0;
                }
            }
            index = SendMessageW(GetDlgItem(dlg, IDC_EOL), CB_GETCURSEL, 0, 0);
            if (index >= TC_EOL_CRLF && index <= TC_EOL_CR)
                choice->eol = (int)index;
            EndDialog(dlg, IDOK);
            return TRUE;
        }
        if (LOWORD(wParam) == IDCANCEL) {
            EndDialog(dlg, IDCANCEL);
            return TRUE;
        }
        break;
    case WM_CLOSE:
        EndDialog(dlg, IDCANCEL);
        return TRUE;
    }
    return FALSE;
}

static BOOL choose_encoding(EncodingChoice *choice)
{
    return DialogBoxParamW(hInst, MAKEINTRESOURCEW(IDD_ENCODING), hMain, encoding_proc,
                           (LPARAM)choice) == IDOK;
}

/* ---------- Files ---------- */

static BOOL file_exists(const WCHAR *path)
{
    DWORD attributes = GetFileAttributesW(path);
    return attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY);
}

static void show_error(const WCHAR *what, const WCHAR *path)
{
    WCHAR text[PATH_SIZE + 160];
    wsprintfW(text, L"%s\n%s\n\n(error %lu)", what, path, (unsigned long)GetLastError());
    message_box(text, MB_OK | MB_ICONERROR);
}

/* Read a file into the edit control; forced: its encoding (NULL: detect) */
static BOOL load_file(const WCHAR *path, const TextEncoding *forced)
{
    HANDLE file;
    LARGE_INTEGER size;
    unsigned char *data;
    DWORD read = 0;
    TextDocument doc;
    BOOL ok;

    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        show_error(L"Cannot open the file:", path);
        return FALSE;
    }
    if (!GetFileSizeEx(file, &size) || size.QuadPart > 256 * 1024 * 1024) {
        CloseHandle(file);
        message_box(L"The file is too large for Notepad.", MB_OK | MB_ICONERROR);
        return FALSE;
    }
    data = malloc((size_t)size.QuadPart + 1);
    if (!data) {
        CloseHandle(file);
        message_box(L"Not enough memory to open the file.", MB_OK | MB_ICONERROR);
        return FALSE;
    }
    ok = ReadFile(file, data, (DWORD)size.QuadPart, &read, NULL);
    CloseHandle(file);
    if (!ok) {
        free(data);
        show_error(L"Cannot read the file:", path);
        return FALSE;
    }
    ok = tc_load(data, read, forced, &doc);
    free(data);
    if (!ok) {
        message_box(L"The file cannot be read in this encoding.", MB_OK | MB_ICONERROR);
        return FALSE;
    }
    SetWindowTextW(hEdit, doc.text);
    free(doc.text);
    SendMessageW(hEdit, EM_SETSEL, 0, 0);
    SendMessageW(hEdit, EM_SCROLLCARET, 0, 0);
    SendMessageW(hEdit, EM_EMPTYUNDOBUFFER, 0, 0);
    if (path != file_path)
        lstrcpynW(file_path, path, PATH_SIZE);
    encoding = doc.encoding;
    eol = doc.eol;
    set_unmodified();
    update_title();
    update_status();
    if (doc.invalid) {
        WCHAR name[96], text[256];
        tc_encoding_name(&encoding, name, 96);
        wsprintfW(text, L"Some bytes of this file are not valid %s text: they are shown "
                  L"as replacement characters. Use File > Reopen with Encoding to read it "
                  L"in another encoding.", name);
        message_box(text, MB_OK | MB_ICONWARNING);
    }
    if (doc.mixed_eol) {
        WCHAR text[256];
        wsprintfW(text, L"This file has more than one kind of line break. They are shown as "
                  L"line breaks, and saving writes %s ones everywhere.", tc_eol_name(eol));
        message_box(text, MB_OK | MB_ICONINFORMATION);
    }
    return TRUE;
}

/* Write the text in enc with line breaks new_eol; FALSE if not saved */
static BOOL write_file(const WCHAR *path, const TextEncoding *enc, int new_eol)
{
    size_t length, size = 0;
    WCHAR *text = edit_text(&length);
    unsigned char *data;
    BOOL lossy = FALSE, ok;
    HANDLE file;
    DWORD written = 0;

    if (!text) {
        message_box(L"Not enough memory to save the file.", MB_OK | MB_ICONERROR);
        return FALSE;
    }
    data = tc_save(text, length, enc, new_eol, &size, &lossy);
    free(text);
    if (!data) {
        message_box(L"The text cannot be converted to this encoding.", MB_OK | MB_ICONERROR);
        return FALSE;
    }
    if (lossy) {
        WCHAR name[96], message[400];
        tc_encoding_name(enc, name, 96);
        wsprintfW(message, L"This file contains characters that cannot be saved in the "
                  L"%s encoding: they will be lost (replaced).\n\nTo keep them, choose "
                  L"Cancel and save it with Save As in a Unicode encoding (UTF-8).\n\n"
                  L"Save in %s anyway?", name, name);
        if (MessageBoxW(hMain, message, APP_NAME, MB_OKCANCEL | MB_ICONWARNING |
                        MB_DEFBUTTON2) != IDOK) {
            free(data);
            return FALSE;
        }
    }
    file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                       NULL);
    if (file == INVALID_HANDLE_VALUE) {
        free(data);
        show_error(L"Cannot create the file:", path);
        return FALSE;
    }
    ok = size == 0 || (WriteFile(file, data, (DWORD)size, &written, NULL) && written == size);
    CloseHandle(file);
    free(data);
    if (!ok) {
        show_error(L"Cannot write the file:", path);
        return FALSE;
    }
    if (path != file_path)
        lstrcpynW(file_path, path, PATH_SIZE);
    encoding = *enc;
    eol = new_eol;
    set_unmodified();
    update_title();
    update_status();
    return TRUE;
}

static BOOL ask_file_name(WCHAR *path, BOOL save)
{
    OPENFILENAMEW ofn;
    memset(&ofn, 0, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hMain;
    ofn.lpstrFilter = L"Text Documents (*.txt)\0*.txt\0All Files (*.*)\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFile = path;
    ofn.nMaxFile = PATH_SIZE;
    ofn.lpstrDefExt = L"txt";
    ofn.Flags = save ? OFN_OVERWRITEPROMPT | OFN_HIDEREADONLY | OFN_PATHMUSTEXIST
                     : OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
    return save ? GetSaveFileNameW(&ofn) : GetOpenFileNameW(&ofn);
}

static BOOL save_as(void)
{
    WCHAR path[PATH_SIZE];
    EncodingChoice choice;

    lstrcpynW(path, file_path[0] ? file_path : L"*.txt", PATH_SIZE);
    if (!ask_file_name(path, TRUE))
        return FALSE;
    choice.mode = ENC_SAVE;
    choice.encoding = encoding;
    choice.detect = FALSE;
    choice.eol = eol;
    if (!choose_encoding(&choice))
        return FALSE;
    return write_file(path, &choice.encoding, choice.eol);
}

static BOOL save(void)
{
    if (!file_path[0])
        return save_as();
    return write_file(file_path, &encoding, eol);
}

/* "Do you want to save changes?" before the text is replaced; FALSE: keep it */
static BOOL may_discard(void)
{
    WCHAR text[PATH_SIZE + 64];
    if (!is_modified())
        return TRUE;
    wsprintfW(text, L"Do you want to save changes to %s?", file_path[0] ? file_path
                                                                       : L"Untitled");
    switch (MessageBoxW(hMain, text, APP_NAME, MB_YESNOCANCEL | MB_ICONWARNING)) {
    case IDYES:
        return save();
    case IDNO:
        return TRUE;
    default:
        return FALSE;
    }
}

static void new_file(void)
{
    file_path[0] = 0;
    encoding.codepage = TC_UTF8;
    encoding.bom = FALSE;
    eol = TC_EOL_CRLF;
    SetWindowTextW(hEdit, L"");
    SendMessageW(hEdit, EM_EMPTYUNDOBUFFER, 0, 0);
    set_unmodified();
    update_title();
    update_status();
}

static void open_file(BOOL choose)
{
    WCHAR path[PATH_SIZE] = L"*.txt";
    EncodingChoice choice;

    if (!may_discard() || !ask_file_name(path, FALSE))
        return;
    if (!choose) {
        load_file(path, NULL);
        return;
    }
    choice.mode = ENC_OPEN;
    choice.encoding = encoding;
    choice.detect = TRUE;
    choice.eol = eol;
    if (choose_encoding(&choice))
        load_file(path, choice.detect ? NULL : &choice.encoding);
}

static void reopen_with_encoding(void)
{
    EncodingChoice choice;
    WCHAR path[PATH_SIZE];

    if (!file_path[0] || !may_discard())
        return;
    choice.mode = ENC_OPEN;
    choice.encoding = encoding;
    choice.detect = FALSE;
    choice.eol = eol;
    if (choose_encoding(&choice)) {
        lstrcpynW(path, file_path, PATH_SIZE);
        load_file(path, choice.detect ? NULL : &choice.encoding);
    }
}

static void choose_format(void)
{
    EncodingChoice choice;
    choice.mode = ENC_FORMAT;
    choice.encoding = encoding;
    choice.detect = FALSE;
    choice.eol = eol;
    if (!choose_encoding(&choice))
        return;
    if (encoding_key(&choice.encoding) != encoding_key(&encoding) || choice.eol != eol)
        format_changed = TRUE;
    encoding = choice.encoding;
    eol = choice.eol;
    update_status();
}

static void set_eol(int new_eol)
{
    if (new_eol != eol)
        format_changed = TRUE;
    eol = new_eol;
    update_status();
}

/* The file named on the command line: the rest of it after the program's
   name, without quotes (7-Zip runs notepad.exe "C:\a b\file.txt"); a name
   without an extension that does not exist gets ".txt" */
static void open_command_line(void)
{
    const WCHAR *p = GetCommandLineW();
    WCHAR name[PATH_SIZE], full[PATH_SIZE], text[PATH_SIZE + 128];
    int length = 0, i;
    BOOL has_extension = FALSE;
    HANDLE file;

    if (*p == '"') {
        for (p++; *p && *p != '"'; p++)
            ;
        if (*p)
            p++;
    } else {
        while (*p && *p != ' ' && *p != '\t')
            p++;
    }
    while (*p == ' ' || *p == '\t')
        p++;
    if (*p == '"') {
        for (p++; *p && *p != '"' && length < PATH_SIZE - 1; p++)
            name[length++] = *p;
    } else {
        for (; *p && length < PATH_SIZE - 1; p++)
            name[length++] = *p;
        while (length > 0 && (name[length - 1] == ' ' || name[length - 1] == '\t'))
            length--;
    }
    name[length] = 0;
    if (!length)
        return;
    if (!GetFullPathNameW(name, PATH_SIZE, full, NULL))
        lstrcpynW(full, name, PATH_SIZE);
    for (i = lstrlenW(full) - 1; i >= 0 && full[i] != '\\' && full[i] != '/'; i--)
        if (full[i] == '.')
            has_extension = TRUE;
    if (!file_exists(full) && !has_extension && lstrlenW(full) < PATH_SIZE - 5)
        lstrcatW(full, L".txt");
    if (file_exists(full)) {
        load_file(full, NULL);
        return;
    }
    wsprintfW(text, L"Cannot find the %s file.\n\nDo you want to create a new file?", full);
    switch (MessageBoxW(hMain, text, APP_NAME, MB_YESNOCANCEL | MB_ICONWARNING)) {
    case IDYES:
        file = CreateFileW(full, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL,
                           NULL);
        if (file == INVALID_HANDLE_VALUE) {
            show_error(L"Cannot create the file:", full);
            return;
        }
        CloseHandle(file);
        lstrcpynW(file_path, full, PATH_SIZE);
        update_title();
        update_status();
        break;
    case IDCANCEL:
        PostQuitMessage(0);
        break;
    }
}

/* ---------- Find and Replace ---------- */

static WCHAR fold(WCHAR c, BOOL match_case)
{
    WCHAR buffer[2] = {c, 0};
    if (match_case)
        return c;
    CharUpperBuffW(buffer, 1);
    return buffer[0];
}

static BOOL is_word_char(WCHAR c)
{
    return IsCharAlphaNumericW(c) || c == '_';
}

static BOOL matches_at(const WCHAR *text, size_t length, size_t pos, const WCHAR *what,
                       size_t what_length, DWORD flags)
{
    size_t i;
    BOOL match_case = (flags & FR_MATCHCASE) != 0;
    if (pos + what_length > length)
        return FALSE;
    for (i = 0; i < what_length; i++)
        if (fold(text[pos + i], match_case) != fold(what[i], match_case))
            return FALSE;
    if (flags & FR_WHOLEWORD) {
        if (pos > 0 && is_word_char(text[pos - 1]))
            return FALSE;
        if (pos + what_length < length && is_word_char(text[pos + what_length]))
            return FALSE;
    }
    return TRUE;
}

/* Select the next match of find_what after (or, upwards, before) the
   selection; FALSE if there is none */
static BOOL find_next(DWORD flags, BOOL quiet)
{
    size_t length, what_length = lstrlenW(find_what), pos;
    WCHAR *text;
    DWORD start = 0, end = 0;
    BOOL found = FALSE;

    if (!what_length)
        return FALSE;
    text = edit_text(&length);
    if (!text)
        return FALSE;
    SendMessageW(hEdit, EM_GETSEL, (WPARAM)&start, (LPARAM)&end);
    if (flags & FR_DOWN) {
        for (pos = end; pos + what_length <= length; pos++) {
            if (matches_at(text, length, pos, find_what, what_length, flags)) {
                found = TRUE;
                break;
            }
        }
    } else {
        for (pos = start; pos-- > 0;) {
            if (matches_at(text, length, pos, find_what, what_length, flags)) {
                found = TRUE;
                break;
            }
        }
    }
    free(text);
    if (found) {
        SendMessageW(hEdit, EM_SETSEL, pos, pos + what_length);
        SendMessageW(hEdit, EM_SCROLLCARET, 0, 0);
    } else if (!quiet) {
        WCHAR message[FIND_SIZE + 40];
        wsprintfW(message, L"Cannot find \"%s\"", find_what);
        MessageBoxW(hFindDialog ? hFindDialog : hMain, message, APP_NAME,
                    MB_OK | MB_ICONINFORMATION);
    }
    return found;
}

static BOOL selection_matches(DWORD flags)
{
    size_t length, what_length = lstrlenW(find_what);
    DWORD start = 0, end = 0;
    WCHAR *text;
    BOOL same;

    SendMessageW(hEdit, EM_GETSEL, (WPARAM)&start, (LPARAM)&end);
    if (end - start != what_length || !what_length)
        return FALSE;
    text = edit_text(&length);
    if (!text)
        return FALSE;
    same = matches_at(text, length, start, find_what, what_length, flags & ~FR_WHOLEWORD);
    free(text);
    return same;
}

static void replace_all(DWORD flags)
{
    size_t length, what_length = lstrlenW(find_what), with_length = lstrlenW(replace_with);
    size_t pos, count = 0, out_length = 0, capacity;
    WCHAR *text, *out;
    WCHAR message[64];

    if (!what_length)
        return;
    text = edit_text(&length);
    if (!text)
        return;
    capacity = length + 1;
    out = malloc(capacity * sizeof(WCHAR));
    if (!out) {
        free(text);
        return;
    }
    for (pos = 0; pos < length;) {
        if (matches_at(text, length, pos, find_what, what_length, flags)) {
            if (out_length + with_length + 1 > capacity) {
                WCHAR *bigger;
                capacity = (capacity + with_length + 1) * 2;
                bigger = realloc(out, capacity * sizeof(WCHAR));
                if (!bigger) {
                    free(out);
                    free(text);
                    return;
                }
                out = bigger;
            }
            memcpy(out + out_length, replace_with, with_length * sizeof(WCHAR));
            out_length += with_length;
            pos += what_length;
            count++;
        } else {
            if (out_length + 2 > capacity) {
                WCHAR *bigger;
                capacity *= 2;
                bigger = realloc(out, capacity * sizeof(WCHAR));
                if (!bigger) {
                    free(out);
                    free(text);
                    return;
                }
                out = bigger;
            }
            out[out_length++] = text[pos++];
        }
    }
    out[out_length] = 0;
    if (count) {
        /* One edit (undoable as a whole): select everything and replace it */
        SendMessageW(hEdit, EM_SETSEL, 0, -1);
        SendMessageW(hEdit, EM_REPLACESEL, TRUE, (LPARAM)out);
        SendMessageW(hEdit, EM_SETSEL, 0, 0);
    }
    free(out);
    free(text);
    wsprintfW(message, L"%d replacement(s) made.", (int)count);
    MessageBoxW(hFindDialog ? hFindDialog : hMain, message, APP_NAME,
                MB_OK | MB_ICONINFORMATION);
}

static void show_find(BOOL replace)
{
    DWORD start = 0, end = 0;
    if (hFindDialog) {
        DestroyWindow(hFindDialog);
        hFindDialog = NULL;
    }
    /* A short selection on one line is what to look for */
    SendMessageW(hEdit, EM_GETSEL, (WPARAM)&start, (LPARAM)&end);
    if (end > start && end - start < FIND_SIZE) {
        size_t length;
        WCHAR *text = edit_text(&length);
        if (text) {
            size_t i;
            BOOL one_line = TRUE;
            for (i = start; i < end; i++)
                if (text[i] == '\r' || text[i] == '\n')
                    one_line = FALSE;
            if (one_line && end <= length) {
                memcpy(find_what, text + start, (end - start) * sizeof(WCHAR));
                find_what[end - start] = 0;
            }
            free(text);
        }
    }
    memset(&find_replace, 0, sizeof(find_replace));
    find_replace.lStructSize = sizeof(find_replace);
    find_replace.hwndOwner = hMain;
    find_replace.Flags = FR_DOWN;
    find_replace.lpstrFindWhat = find_what;
    find_replace.wFindWhatLen = FIND_SIZE;
    find_replace.lpstrReplaceWith = replace_with;
    find_replace.wReplaceWithLen = FIND_SIZE;
    hFindDialog = replace ? ReplaceTextW(&find_replace) : FindTextW(&find_replace);
}

static void on_find_message(FINDREPLACEW *fr)
{
    if (fr->Flags & FR_DIALOGTERM) {
        hFindDialog = NULL;
        return;
    }
    if (fr->Flags & FR_FINDNEXT) {
        find_next(fr->Flags, FALSE);
    } else if (fr->Flags & FR_REPLACE) {
        /* The selected match is replaced, then the next one selected */
        if (selection_matches(fr->Flags))
            SendMessageW(hEdit, EM_REPLACESEL, TRUE, (LPARAM)replace_with);
        find_next(fr->Flags | FR_DOWN, FALSE);
    } else if (fr->Flags & FR_REPLACEALL) {
        replace_all(fr->Flags);
    }
}

/* ---------- Go To and About ---------- */

static INT_PTR CALLBACK goto_proc(HWND dlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_INITDIALOG:
        SetDlgItemInt(dlg, IDC_LINE, (UINT)lParam, FALSE);
        SendDlgItemMessageW(dlg, IDC_LINE, EM_SETSEL, 0, -1);
        SetFocus(GetDlgItem(dlg, IDC_LINE));
        return FALSE;
    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK) {
            BOOL ok = FALSE;
            UINT line = GetDlgItemInt(dlg, IDC_LINE, &ok, FALSE);
            LRESULT count = SendMessageW(hEdit, EM_GETLINECOUNT, 0, 0);
            if (!ok || line < 1 || (LRESULT)line > count) {
                MessageBoxW(dlg, L"The line number is beyond the total number of lines",
                            L"Notepad - Go To Line", MB_OK);
                return TRUE;
            }
            EndDialog(dlg, (INT_PTR)line);
            return TRUE;
        }
        if (LOWORD(wParam) == IDCANCEL) {
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

static void go_to_line(void)
{
    DWORD caret = 0;
    INT_PTR line;
    LRESULT start;
    SendMessageW(hEdit, EM_GETSEL, 0, (LPARAM)&caret);
    line = SendMessageW(hEdit, EM_LINEFROMCHAR, caret, 0) + 1;
    line = DialogBoxParamW(hInst, MAKEINTRESOURCEW(IDD_GOTO), hMain, goto_proc, line);
    if (line <= 0)
        return;
    start = SendMessageW(hEdit, EM_LINEINDEX, line - 1, 0);
    SendMessageW(hEdit, EM_SETSEL, start, start);
    SendMessageW(hEdit, EM_SCROLLCARET, 0, 0);
}

static INT_PTR CALLBACK about_proc(HWND dlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_INITDIALOG:
        SetDlgItemTextW(dlg, IDC_ABOUT_TEXT,
                        L"A plain text editor of winexe32emu.\n\n"
                        L"Opens and saves ANSI, UTF-8, UTF-16 and other code pages "
                        L"with Windows, Unix or Macintosh line breaks.");
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

/* ---------- Menus ---------- */

static HMENU create_menu(void)
{
    HMENU menu = CreateMenu(), file = CreatePopupMenu(), edit = CreatePopupMenu();
    HMENU format = CreatePopupMenu(), breaks = CreatePopupMenu(), view = CreatePopupMenu();
    HMENU help = CreatePopupMenu();

    AppendMenuW(file, MF_STRING, IDM_NEW, L"&New\tCtrl+N");
    AppendMenuW(file, MF_STRING, IDM_OPEN, L"&Open...\tCtrl+O");
    AppendMenuW(file, MF_STRING, IDM_OPEN_AS, L"Open &with Encoding...");
    AppendMenuW(file, MF_STRING, IDM_REOPEN_AS, L"&Reopen with Encoding...");
    AppendMenuW(file, MF_STRING, IDM_SAVE, L"&Save\tCtrl+S");
    AppendMenuW(file, MF_STRING, IDM_SAVE_AS, L"Save &As...\tCtrl+Shift+S");
    AppendMenuW(file, MF_SEPARATOR, 0, NULL);
    AppendMenuW(file, MF_STRING, IDM_EXIT, L"E&xit");
    AppendMenuW(edit, MF_STRING, IDM_UNDO, L"&Undo\tCtrl+Z");
    AppendMenuW(edit, MF_SEPARATOR, 0, NULL);
    AppendMenuW(edit, MF_STRING, IDM_CUT, L"Cu&t\tCtrl+X");
    AppendMenuW(edit, MF_STRING, IDM_COPY, L"&Copy\tCtrl+C");
    AppendMenuW(edit, MF_STRING, IDM_PASTE, L"&Paste\tCtrl+V");
    AppendMenuW(edit, MF_STRING, IDM_DELETE, L"De&lete\tDel");
    AppendMenuW(edit, MF_SEPARATOR, 0, NULL);
    AppendMenuW(edit, MF_STRING, IDM_FIND, L"&Find...\tCtrl+F");
    AppendMenuW(edit, MF_STRING, IDM_FIND_NEXT, L"Find &Next\tF3");
    AppendMenuW(edit, MF_STRING, IDM_REPLACE, L"&Replace...\tCtrl+H");
    AppendMenuW(edit, MF_STRING, IDM_GOTO, L"&Go To...\tCtrl+G");
    AppendMenuW(edit, MF_SEPARATOR, 0, NULL);
    AppendMenuW(edit, MF_STRING, IDM_SELECT_ALL, L"Select &All\tCtrl+A");
    AppendMenuW(edit, MF_STRING, IDM_TIME_DATE, L"Time/&Date\tF5");
    AppendMenuW(breaks, MF_STRING, IDM_EOL_CRLF, L"&Windows (CRLF)");
    AppendMenuW(breaks, MF_STRING, IDM_EOL_LF, L"&Unix (LF)");
    AppendMenuW(breaks, MF_STRING, IDM_EOL_CR, L"&Macintosh (CR)");
    AppendMenuW(format, MF_STRING, IDM_WORD_WRAP, L"&Word Wrap");
    AppendMenuW(format, MF_SEPARATOR, 0, NULL);
    AppendMenuW(format, MF_POPUP, (UINT_PTR)breaks, L"&Line Breaks");
    AppendMenuW(format, MF_STRING, IDM_ENCODING, L"&Encoding...");
    AppendMenuW(view, MF_STRING, IDM_STATUS_BAR, L"&Status Bar");
    AppendMenuW(help, MF_STRING, IDM_ABOUT, L"&About Notepad");
    AppendMenuW(menu, MF_POPUP, (UINT_PTR)file, L"&File");
    AppendMenuW(menu, MF_POPUP, (UINT_PTR)edit, L"&Edit");
    AppendMenuW(menu, MF_POPUP, (UINT_PTR)format, L"F&ormat");
    AppendMenuW(menu, MF_POPUP, (UINT_PTR)view, L"&View");
    AppendMenuW(menu, MF_POPUP, (UINT_PTR)help, L"&Help");
    return menu;
}

/* Check marks and grayed items as the menus open */
static void init_menu(HMENU menu)
{
    DWORD start = 0, end = 0;
    UINT has_selection, can_paste;

    SendMessageW(hEdit, EM_GETSEL, (WPARAM)&start, (LPARAM)&end);
    has_selection = end > start ? MF_ENABLED : MF_GRAYED;
    can_paste = IsClipboardFormatAvailable(CF_UNICODETEXT) ||
                IsClipboardFormatAvailable(CF_TEXT) ? MF_ENABLED : MF_GRAYED;
    EnableMenuItem(menu, IDM_REOPEN_AS, file_path[0] ? MF_ENABLED : MF_GRAYED);
    EnableMenuItem(menu, IDM_UNDO, SendMessageW(hEdit, EM_CANUNDO, 0, 0) ? MF_ENABLED
                                                                          : MF_GRAYED);
    EnableMenuItem(menu, IDM_CUT, has_selection);
    EnableMenuItem(menu, IDM_COPY, has_selection);
    EnableMenuItem(menu, IDM_DELETE, has_selection);
    EnableMenuItem(menu, IDM_PASTE, can_paste);
    EnableMenuItem(menu, IDM_FIND_NEXT, find_what[0] ? MF_ENABLED : MF_GRAYED);
    /* Wrapped lines are not the file's lines */
    EnableMenuItem(menu, IDM_GOTO, word_wrap ? MF_GRAYED : MF_ENABLED);
    CheckMenuItem(menu, IDM_WORD_WRAP, word_wrap ? MF_CHECKED : MF_UNCHECKED);
    CheckMenuItem(menu, IDM_STATUS_BAR, show_status ? MF_CHECKED : MF_UNCHECKED);
    CheckMenuRadioItem(menu, IDM_EOL_CRLF, IDM_EOL_CR, IDM_EOL_CRLF + eol, MF_BYCOMMAND);
}

static void insert_time_date(void)
{
    WCHAR time_text[64], date_text[64], text[140];
    GetTimeFormatW(LOCALE_USER_DEFAULT, TIME_NOSECONDS, NULL, NULL, time_text, 64);
    GetDateFormatW(LOCALE_USER_DEFAULT, DATE_SHORTDATE, NULL, NULL, date_text, 64);
    wsprintfW(text, L"%s %s", time_text, date_text);
    SendMessageW(hEdit, EM_REPLACESEL, TRUE, (LPARAM)text);
}

static void toggle_status_bar(void)
{
    show_status = !show_status;
    ShowWindow(hStatus, show_status ? SW_SHOW : SW_HIDE);
    status_shown[0][0] = status_shown[1][0] = status_shown[2][0] = 0;
    layout();
    update_status();
}

static void on_command(WORD id)
{
    switch (id) {
    case IDM_NEW:
        if (may_discard())
            new_file();
        break;
    case IDM_OPEN:
        open_file(FALSE);
        break;
    case IDM_OPEN_AS:
        open_file(TRUE);
        break;
    case IDM_REOPEN_AS:
        reopen_with_encoding();
        break;
    case IDM_SAVE:
        save();
        break;
    case IDM_SAVE_AS:
        save_as();
        break;
    case IDM_EXIT:
        PostMessageW(hMain, WM_CLOSE, 0, 0);
        break;
    case IDM_UNDO:
        SendMessageW(hEdit, EM_UNDO, 0, 0);
        break;
    case IDM_CUT:
        SendMessageW(hEdit, WM_CUT, 0, 0);
        break;
    case IDM_COPY:
        SendMessageW(hEdit, WM_COPY, 0, 0);
        break;
    case IDM_PASTE:
        SendMessageW(hEdit, WM_PASTE, 0, 0);
        break;
    case IDM_DELETE:
        SendMessageW(hEdit, WM_CLEAR, 0, 0);
        break;
    case IDM_FIND:
        show_find(FALSE);
        break;
    case IDM_FIND_NEXT:
        if (find_what[0])
            find_next(find_replace.Flags | FR_DOWN, FALSE);
        else
            show_find(FALSE);
        break;
    case IDM_REPLACE:
        show_find(TRUE);
        break;
    case IDM_GOTO:
        if (!word_wrap)
            go_to_line();
        break;
    case IDM_SELECT_ALL:
        SendMessageW(hEdit, EM_SETSEL, 0, -1);
        break;
    case IDM_TIME_DATE:
        insert_time_date();
        break;
    case IDM_WORD_WRAP:
        set_word_wrap(!word_wrap);
        break;
    case IDM_EOL_CRLF:
    case IDM_EOL_LF:
    case IDM_EOL_CR:
        set_eol(id - IDM_EOL_CRLF);
        break;
    case IDM_ENCODING:
        choose_format();
        break;
    case IDM_STATUS_BAR:
        toggle_status_bar();
        break;
    case IDM_ABOUT:
        DialogBoxParamW(hInst, MAKEINTRESOURCEW(IDD_ABOUT), hMain, about_proc, 0);
        break;
    }
    update_status();
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (find_message && msg == find_message) {
        on_find_message((FINDREPLACEW *)lParam);
        return 0;
    }
    switch (msg) {
    case WM_CREATE:
        hMain = hwnd;
        hEdit = create_edit();
        hStatus = CreateWindowExW(0, STATUSCLASSNAMEW, L"", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0,
                                  hwnd, (HMENU)IDC_STATUS, hInst, NULL);
        SetTimer(hwnd, STATUS_TIMER, 200, NULL);
        return 0;
    case WM_SIZE:
        layout();
        return 0;
    case WM_SETFOCUS:
        SetFocus(hEdit);
        return 0;
    case WM_TIMER:
        /* The caret moves without notifications: follow it for the status bar */
        if (wParam == STATUS_TIMER)
            update_status();
        return 0;
    case WM_INITMENUPOPUP:
        init_menu((HMENU)wParam);
        return 0;
    case WM_COMMAND:
        if (LOWORD(wParam) == IDC_EDIT) {
            if (HIWORD(wParam) == EN_ERRSPACE || HIWORD(wParam) == EN_MAXTEXT)
                message_box(L"Not enough memory to complete this operation.",
                            MB_OK | MB_ICONWARNING);
            return 0;
        }
        on_command(LOWORD(wParam));
        return 0;
    case WM_CLOSE:
        if (may_discard())
            DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        KillTimer(hwnd, STATUS_TIMER);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    WNDCLASSW wc;
    MSG msg;
    HACCEL accelerators;
    INITCOMMONCONTROLSEX icc;

    hInst = hInstance;
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_BAR_CLASSES;
    InitCommonControlsEx(&icc);
    find_message = RegisterWindowMessageW(FINDMSGSTRINGW);

    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    wc.hIcon = LoadIconW(hInstance, MAKEINTRESOURCEW(IDI_NOTEPAD));
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"Notepad";
    if (!RegisterClassW(&wc))
        return 1;

    if (!CreateWindowExW(0, wc.lpszClassName, L"Untitled - Notepad", WS_OVERLAPPEDWINDOW,
                         CW_USEDEFAULT, CW_USEDEFAULT, 640, 440, NULL, create_menu(),
                         hInstance, NULL))
        return 1;
    accelerators = LoadAcceleratorsW(hInstance, MAKEINTRESOURCEW(IDA_NOTEPAD));
    ShowWindow(hMain, nCmdShow);
    UpdateWindow(hMain);
    update_title();
    open_command_line();
    layout();
    update_status();
    SetFocus(hEdit);

    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        if (hFindDialog && IsDialogMessageW(hFindDialog, &msg))
            continue;
        if (TranslateAcceleratorW(hMain, accelerators, &msg))
            continue;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}
