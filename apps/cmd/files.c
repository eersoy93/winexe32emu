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

/* The file and directory commands of the Command Prompt: DIR, CD, the drive
   switch, MD, RD, COPY, MOVE, DEL, REN, TYPE, VOL, PUSHD and POPD. They use
   only the Win32 file APIs, so they reach just what the emulator's drives
   allow. */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cmd.h"

#define MAX_ARGS 64

/* ==================== HELPERS ==================== */

int full_path(const char *name, char *path, int size)
{
    DWORD length = GetFullPathNameA(name, size, path, NULL);
    if (length == 0 || length >= (DWORD)size) {
        snprintf(path, size, "%s", name);
        return 0;
    }
    return 1;
}

/* 1234567 -> "1,234,567" */
void format_number(ULONGLONG value, char *text)
{
    char digits[32];
    int count = 0, length = 0;
    do {
        digits[count++] = (char)('0' + value % 10);
        value /= 10;
    } while (value);
    for (int i = count - 1; i >= 0; i--) {
        text[length++] = digits[i];
        if (i > 0 && i % 3 == 0)
            text[length++] = ',';
    }
    text[length] = '\0';
}

static int is_directory(const char *path)
{
    DWORD attributes = GetFileAttributesA(path);
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY);
}

static int exists(const char *path)
{
    return GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES;
}

/* "C:\dir\name" -> folder "C:\dir\" (with its separator) and name */
static void split_path(const char *path, char *folder, int size, const char **name)
{
    const char *slash = strrchr(path, '\\');
    const char *colon = strchr(path, ':');
    const char *end = slash ? slash + 1 : colon ? colon + 1 : path;
    int length = (int)(end - path);
    if (length >= size)
        length = size - 1;
    memcpy(folder, path, length);
    folder[length] = '\0';
    *name = end;
}

static void join_path(const char *folder, const char *name, char *path, int size)
{
    size_t length = strlen(folder);
    if (length && folder[length - 1] != '\\' && folder[length - 1] != ':')
        snprintf(path, size, "%s\\%s", folder, name);
    else
        snprintf(path, size, "%s%s", folder, name);
}

static int is_dots(const char *name)
{
    return strcmp(name, ".") == 0 || strcmp(name, "..") == 0;
}

/* The arguments of a command split into switches (letters after '/', several
   may be glued: /w/b) and the other words */
struct arguments {
    int count;
    char *words[MAX_ARGS];
    int switch_count;
    char *switches[MAX_ARGS];
    char buffer[LINE_SIZE];
};

static void parse_arguments(const char *args, struct arguments *a)
{
    char token[PATH_SIZE];
    char *cursor = (char *)args;
    int used = 0;
    a->count = a->switch_count = 0;
    while (next_token(&cursor, token, sizeof(token))) {
        if (token[0] == '/') {
            /* "/w/b" holds two switches */
            for (char *s = strtok(token, "/"); s; s = strtok(NULL, "/")) {
                int length = (int)strlen(s) + 1;
                if (used + length > LINE_SIZE || a->switch_count >= MAX_ARGS)
                    break;
                memcpy(a->buffer + used, s, length);
                a->switches[a->switch_count++] = a->buffer + used;
                used += length;
            }
            continue;
        }
        int length = (int)strlen(token) + 1;
        if (used + length > LINE_SIZE || a->count >= MAX_ARGS)
            break;
        memcpy(a->buffer + used, token, length);
        a->words[a->count++] = a->buffer + used;
        used += length;
    }
}

/* Is switch letter on (e.g. "Y"); -1 when it is given as -Y */
static int has_switch(const struct arguments *a, const char *name)
{
    int result = 0;
    for (int i = 0; i < a->switch_count; i++) {
        const char *s = a->switches[i];
        if (_stricmp(s, name) == 0)
            result = 1;
        else if (s[0] == '-' && _stricmp(s + 1, name) == 0)
            result = -1;
    }
    return result;
}

/* The value of a switch like /A:HS or /OD ("" if given alone, NULL if not) */
static const char *switch_value(const struct arguments *a, char letter)
{
    for (int i = 0; i < a->switch_count; i++) {
        const char *s = a->switches[i];
        if (toupper((unsigned char)s[0]) == toupper((unsigned char)letter))
            return s[1] == ':' ? s + 2 : s + 1;
    }
    return NULL;
}

static void syntax_error(void)
{
    errf("The syntax of the command is incorrect.\n");
}

/* The files (and, with dirs, folders) matching pattern; callback gets the full
   path and the find data; returns the number of matches */
typedef int (*match_callback)(const char *path, const WIN32_FIND_DATAA *data, void *context);

static int for_each_match(const char *pattern, int dirs, match_callback callback, void *context)
{
    WIN32_FIND_DATAA data;
    char folder[PATH_SIZE], path[PATH_SIZE];
    const char *name;
    int count = 0;
    split_path(pattern, folder, sizeof(folder), &name);
    HANDLE find = FindFirstFileA(pattern, &data);
    if (find == INVALID_HANDLE_VALUE)
        return 0;
    do {
        if (is_dots(data.cFileName))
            continue;
        if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && !dirs)
            continue;
        join_path(folder, data.cFileName, path, sizeof(path));
        count++;
        if (callback && !callback(path, &data, context))
            break;
    } while (FindNextFileA(find, &data));
    FindClose(find);
    return count;
}

/* ==================== DRIVES AND CD ==================== */

int cmd_drive(char letter)
{
    char variable[4] = "=C:", dir[PATH_SIZE];
    letter = (char)toupper((unsigned char)letter);
    variable[1] = letter;
    remember_current_directory();
    if (!GetEnvironmentVariableA(variable, dir, sizeof(dir)))
        snprintf(dir, sizeof(dir), "%c:\\", letter);
    if (!SetCurrentDirectoryA(dir)) {
        snprintf(dir, sizeof(dir), "%c:\\", letter);
        if (!SetCurrentDirectoryA(dir)) {
            print_error(ERROR_INVALID_DRIVE);
            return 1;
        }
    }
    remember_current_directory();
    return 0;
}

/* The current directory of a drive (the saved "=X:" one, or its root) */
static void drive_directory(char letter, char *dir, int size)
{
    char variable[4] = "=C:", current[PATH_SIZE];
    letter = (char)toupper((unsigned char)letter);
    if (GetCurrentDirectoryA(sizeof(current), current) &&
            toupper((unsigned char)current[0]) == letter) {
        snprintf(dir, size, "%s", current);
        return;
    }
    variable[1] = letter;
    if (!GetEnvironmentVariableA(variable, dir, size))
        snprintf(dir, size, "%c:\\", letter);
}

int cmd_cd(char *args)
{
    char path[PATH_SIZE], full[PATH_SIZE], current[PATH_SIZE];
    char *p = skip_spaces(args);
    int change_drive = 0;
    if ((p[0] == '/' || p[0] == '-') && toupper((unsigned char)p[1]) == 'D' &&
            (p[2] == '\0' || p[2] == ' ' || p[2] == '\t')) {
        change_drive = 1;
        p = skip_spaces(p + 2);
    }
    /* Like cmd, the rest is one path even with spaces and without quotes */
    snprintf(path, sizeof(path), "%s", p);
    strip_quotes(path);
    trim_right(path);
    if (!path[0]) {
        GetCurrentDirectoryA(sizeof(current), current);
        outf("%s\n", current);
        return 0;
    }
    if (path[1] == ':' && path[2] == '\0') {
        drive_directory(path[0], current, sizeof(current));
        outf("%s\n", current);
        return 0;
    }
    if (!full_path(path, full, sizeof(full)) || !exists(full)) {
        print_error(ERROR_PATH_NOT_FOUND);
        return 1;
    }
    if (!is_directory(full)) {
        print_error(ERROR_DIRECTORY);
        return 1;
    }
    size_t length = strlen(full);
    if (length > 3 && full[length - 1] == '\\')
        full[length - 1] = '\0';
    GetCurrentDirectoryA(sizeof(current), current);
    if (change_drive || toupper((unsigned char)full[0]) == toupper((unsigned char)current[0])) {
        if (!SetCurrentDirectoryA(full)) {
            print_error(GetLastError());
            return 1;
        }
        remember_current_directory();
    } else {
        /* Another drive: only its saved directory changes */
        char variable[4] = "=C:";
        variable[1] = (char)toupper((unsigned char)full[0]);
        SetEnvironmentVariableA(variable, full);
    }
    return 0;
}

/* ==================== PUSHD / POPD ==================== */

#define DIR_STACK_SIZE 32
static char *dir_stack[DIR_STACK_SIZE];
static int dir_stack_count;

int cmd_pushd(char *args)
{
    char current[PATH_SIZE], path[PATH_SIZE];
    GetCurrentDirectoryA(sizeof(current), current);
    snprintf(path, sizeof(path), "%s", skip_spaces(args));
    strip_quotes(path);
    trim_right(path);
    if (!path[0]) {
        for (int i = dir_stack_count - 1; i >= 0; i--)
            outf("%s\n", dir_stack[i]);
        return 0;
    }
    if (dir_stack_count >= DIR_STACK_SIZE) {
        errf("Too many directories are saved by PUSHD.\n");
        return 1;
    }
    char command[PATH_SIZE + 8];
    snprintf(command, sizeof(command), "/D %s", path);
    if (cmd_cd(command))
        return 1;
    dir_stack[dir_stack_count++] = _strdup(current);
    return 0;
}

int cmd_popd(char *args)
{
    if (dir_stack_count == 0)
        return 0;
    char *dir = dir_stack[--dir_stack_count];
    if (dir) {
        if (SetCurrentDirectoryA(dir))
            remember_current_directory();
        free(dir);
    }
    return 0;
}

/* ==================== MD / RD ==================== */

int cmd_md(char *args)
{
    struct arguments a;
    int status = 0;
    parse_arguments(args, &a);
    if (a.count == 0) {
        syntax_error();
        return 1;
    }
    for (int i = 0; i < a.count; i++) {
        char full[PATH_SIZE];
        full_path(a.words[i], full, sizeof(full));
        if (exists(full)) {
            errf("A subdirectory or file %s already exists.\n", a.words[i]);
            status = 1;
            continue;
        }
        /* Create the missing parents first, like MD of Windows NT */
        for (char *p = full + 3; *p; p++) {
            if (*p != '\\')
                continue;
            *p = '\0';
            if (!exists(full))
                CreateDirectoryA(full, NULL);
            *p = '\\';
        }
        if (!CreateDirectoryA(full, NULL)) {
            print_error(GetLastError());
            status = 1;
        }
    }
    return status;
}

/* Delete a folder with all its files and subfolders */
static int delete_tree(const char *dir)
{
    WIN32_FIND_DATAA data;
    char pattern[PATH_SIZE], path[PATH_SIZE];
    int ok = 1;
    join_path(dir, "*", pattern, sizeof(pattern));
    HANDLE find = FindFirstFileA(pattern, &data);
    if (find != INVALID_HANDLE_VALUE) {
        do {
            if (is_dots(data.cFileName))
                continue;
            join_path(dir, data.cFileName, path, sizeof(path));
            if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                ok &= delete_tree(path);
            } else {
                SetFileAttributesA(path, FILE_ATTRIBUTE_NORMAL);
                if (!DeleteFileA(path)) {
                    errf("%s - ", path);
                    print_error(GetLastError());
                    ok = 0;
                }
            }
        } while (FindNextFileA(find, &data));
        FindClose(find);
    }
    if (!RemoveDirectoryA(dir)) {
        errf("%s - ", dir);
        print_error(GetLastError());
        ok = 0;
    }
    return ok;
}

int cmd_rd(char *args)
{
    struct arguments a;
    int status = 0;
    parse_arguments(args, &a);
    int tree = has_switch(&a, "S") > 0, quiet = has_switch(&a, "Q") > 0;
    if (a.count == 0) {
        syntax_error();
        return 1;
    }
    for (int i = 0; i < a.count; i++) {
        char full[PATH_SIZE], current[PATH_SIZE], question[PATH_SIZE + 32];
        full_path(a.words[i], full, sizeof(full));
        if (!exists(full)) {
            print_error(ERROR_FILE_NOT_FOUND);
            status = 1;
            continue;
        }
        if (!is_directory(full)) {
            print_error(ERROR_DIRECTORY);
            status = 1;
            continue;
        }
        GetCurrentDirectoryA(sizeof(current), current);
        if (_strnicmp(current, full, strlen(full)) == 0 &&
                (current[strlen(full)] == '\0' || current[strlen(full)] == '\\')) {
            errf("The process cannot access the file because it is being used by "
                 "another process.\n");
            status = 1;
            continue;
        }
        if (!tree) {
            if (!RemoveDirectoryA(full)) {
                print_error(GetLastError());
                status = 1;
            }
            continue;
        }
        if (!quiet) {
            snprintf(question, sizeof(question), "%s, Are you sure", a.words[i]);
            if (ask_yes_no(question, 0) != 1)
                continue;
        }
        if (!delete_tree(full))
            status = 1;
    }
    return status;
}

/* ==================== DIR ==================== */

struct entry {
    char name[MAX_PATH];
    DWORD attributes;
    ULONGLONG size;
    FILETIME time;
};

struct dir_options {
    int wide, bare, recurse;
    const char *attributes;  /* NULL: no /A (hidden and system left out) */
    const char *order;       /* NULL: by name */
    ULONGLONG total_files, total_bytes;
    unsigned long total_file_count, total_dir_count;
    int found;
};

static int wanted(const struct dir_options *o, DWORD attributes)
{
    if (!o->attributes)
        return !(attributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM));
    int negate = 0;
    for (const char *p = o->attributes; *p; p++) {
        DWORD bit = 0;
        switch (toupper((unsigned char)*p)) {
        case '-': negate = 1; continue;
        case 'D': bit = FILE_ATTRIBUTE_DIRECTORY; break;
        case 'R': bit = FILE_ATTRIBUTE_READONLY; break;
        case 'H': bit = FILE_ATTRIBUTE_HIDDEN; break;
        case 'S': bit = FILE_ATTRIBUTE_SYSTEM; break;
        case 'A': bit = FILE_ATTRIBUTE_ARCHIVE; break;
        default: break;
        }
        if (bit && (!(attributes & bit)) != negate)
            return 0;
        negate = 0;
    }
    return 1;
}

static const char *sort_order;

static int compare_entries(const void *a, const void *b)
{
    const struct entry *x = a, *y = b;
    const char *order = sort_order && *sort_order ? sort_order : "N";
    for (const char *p = order; *p; p++) {
        int reverse = 0, result = 0;
        if (*p == '-') {
            reverse = 1;
            if (!*++p)
                break;
        }
        switch (toupper((unsigned char)*p)) {
        case 'N':
            result = _stricmp(x->name, y->name);
            break;
        case 'E': {
            const char *ex = strrchr(x->name, '.'), *ey = strrchr(y->name, '.');
            result = _stricmp(ex ? ex : "", ey ? ey : "");
            break;
        }
        case 'S':
            result = x->size < y->size ? -1 : x->size > y->size;
            break;
        case 'D':
            result = CompareFileTime(&x->time, &y->time);
            break;
        case 'G':
            result = !(x->attributes & FILE_ATTRIBUTE_DIRECTORY) -
                     !(y->attributes & FILE_ATTRIBUTE_DIRECTORY);
            break;
        default:
            break;
        }
        if (result)
            return reverse ? -result : result;
    }
    return _stricmp(x->name, y->name);
}

/* The entries of folder matching pattern, sorted; NULL if there are none */
static struct entry *read_entries(const char *folder, const char *pattern,
                                  struct dir_options *o, int *count)
{
    WIN32_FIND_DATAA data;
    char spec[PATH_SIZE];
    struct entry *list = NULL;
    int used = 0, capacity = 0;
    join_path(folder, pattern, spec, sizeof(spec));
    *count = 0;
    HANDLE find = FindFirstFileA(spec, &data);
    if (find == INVALID_HANDLE_VALUE)
        return NULL;
    do {
        if (!wanted(o, data.dwFileAttributes))
            continue;
        if (o->bare && is_dots(data.cFileName))
            continue;
        if (used == capacity) {
            capacity = capacity ? capacity * 2 : 64;
            struct entry *bigger = realloc(list, capacity * sizeof(*list));
            if (!bigger)
                break;
            list = bigger;
        }
        struct entry *e = &list[used++];
        snprintf(e->name, sizeof(e->name), "%s", data.cFileName);
        e->attributes = data.dwFileAttributes;
        e->size = (ULONGLONG)data.nFileSizeHigh << 32 | data.nFileSizeLow;
        e->time = data.ftLastWriteTime;
    } while (FindNextFileA(find, &data));
    FindClose(find);
    sort_order = o->order;
    if (used > 1) {
        /* "." and ".." stay first, like in Windows */
        int dots = 0;
        while (dots < used && is_dots(list[dots].name))
            dots++;
        qsort(list + dots, used - dots, sizeof(*list), compare_entries);
    }
    *count = used;
    return list;
}

static void format_time(const FILETIME *time, char *text, int size)
{
    FILETIME local;
    SYSTEMTIME t;
    if (!FileTimeToLocalFileTime(time, &local) || !FileTimeToSystemTime(&local, &t)) {
        snprintf(text, size, "%-20s", "");
        return;
    }
    int hour = t.wHour % 12;
    snprintf(text, size, "%02d/%02d/%04d  %02d:%02d %s", t.wMonth, t.wDay, t.wYear,
             hour ? hour : 12, t.wMinute, t.wHour < 12 ? "AM" : "PM");
}

static void print_summary(unsigned long files, ULONGLONG bytes)
{
    char number[32];
    format_number(bytes, number);
    outf("%16lu File(s) %14s bytes\n", files, number);
}

static void print_free(const char *folder, unsigned long dirs)
{
    ULARGE_INTEGER free_bytes, total, total_free;
    char number[32];
    if (!GetDiskFreeSpaceExA(folder, &free_bytes, &total, &total_free))
        free_bytes.QuadPart = 0;
    format_number(free_bytes.QuadPart, number);
    outf("%16lu Dir(s) %15s bytes free\n", dirs, number);
}

/* List one folder (and its subfolders with /S) */
static void list_folder(const char *folder, const char *pattern, struct dir_options *o)
{
    int count;
    struct entry *list = read_entries(folder, pattern, o, &count);
    if (count > 0) {
        unsigned long files = 0, dirs = 0;
        ULONGLONG bytes = 0;
        int width = 0;
        o->found = 1;
        if (!o->bare)
            outf(" Directory of %s\n\n", folder);
        if (o->wide) {
            for (int i = 0; i < count; i++) {
                int length = (int)strlen(list[i].name) + 2;
                if (length > width)
                    width = length;
            }
            width += 2;
        }
        int columns = o->wide ? (79 / width > 0 ? 79 / width : 1) : 1, column = 0;
        for (int i = 0; i < count; i++) {
            struct entry *e = &list[i];
            int is_dir = (e->attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            if (is_dir)
                dirs++;
            else {
                files++;
                bytes += e->size;
            }
            if (o->bare) {
                if (o->recurse) {
                    char path[PATH_SIZE];
                    join_path(folder, e->name, path, sizeof(path));
                    outf("%s\n", path);
                } else {
                    outf("%s\n", e->name);
                }
            } else if (o->wide) {
                char name[MAX_PATH + 3];
                snprintf(name, sizeof(name), is_dir ? "[%s]" : "%s", e->name);
                if (++column == columns || i == count - 1) {
                    outf("%s\n", name);
                    column = 0;
                } else {
                    outf("%-*s", width, name);
                }
            } else {
                char time[40], number[32];
                format_time(&e->time, time, sizeof(time));
                if (is_dir) {
                    outf("%s    <DIR>          %s\n", time, e->name);
                } else {
                    format_number(e->size, number);
                    outf("%s %17s %s\n", time, number, e->name);
                }
            }
        }
        if (!o->bare)
            print_summary(files, bytes);
        if (o->recurse && !o->bare)
            out("\n");
        o->total_file_count += files;
        o->total_dir_count += dirs;
        o->total_bytes += bytes;
    }
    free(list);

    if (!o->recurse)
        return;
    /* The subfolders, whatever the pattern */
    WIN32_FIND_DATAA data;
    char spec[PATH_SIZE], sub[PATH_SIZE];
    join_path(folder, "*", spec, sizeof(spec));
    HANDLE find = FindFirstFileA(spec, &data);
    if (find == INVALID_HANDLE_VALUE)
        return;
    char **names = NULL;
    int used = 0;
    do {
        if (!(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || is_dots(data.cFileName))
            continue;
        char **bigger = realloc(names, (used + 1) * sizeof(*names));
        if (!bigger)
            break;
        names = bigger;
        names[used++] = _strdup(data.cFileName);
    } while (FindNextFileA(find, &data));
    FindClose(find);
    for (int i = 0; i < used; i++) {
        if (names[i]) {
            join_path(folder, names[i], sub, sizeof(sub));
            list_folder(sub, pattern, o);
            free(names[i]);
        }
    }
    free(names);
}

static void print_volume_header(char letter)
{
    char root[4] = "C:\\", label[MAX_PATH] = "";
    DWORD serial = 0;
    root[0] = letter;
    if (!GetVolumeInformationA(root, label, sizeof(label), &serial, NULL, NULL, NULL, 0)) {
        print_error(GetLastError());
        return;
    }
    if (label[0])
        outf(" Volume in drive %c is %s\n", letter, label);
    else
        outf(" Volume in drive %c has no label.\n", letter);
    outf(" Volume Serial Number is %04X-%04X\n", (unsigned)(serial >> 16),
         (unsigned)(serial & 0xFFFF));
}

int cmd_dir(char *args)
{
    struct arguments a;
    struct dir_options o;
    char env[256];
    char *defaults = NULL;
    memset(&o, 0, sizeof(o));
    /* DIRCMD holds default switches, like on Windows */
    if (GetEnvironmentVariableA("DIRCMD", env, sizeof(env))) {
        size_t length = strlen(env) + strlen(args) + 2;
        defaults = malloc(length);
        if (defaults) {
            snprintf(defaults, length, "%s %s", env, args);
            args = defaults;
        }
    }
    parse_arguments(args, &a);
    free(defaults);
    o.wide = has_switch(&a, "W") > 0;
    o.bare = has_switch(&a, "B") > 0;
    o.recurse = has_switch(&a, "S") > 0;
    o.attributes = switch_value(&a, 'A');
    o.order = switch_value(&a, 'O');
    char *here = ".";
    char **paths = a.count ? a.words : &here;
    int count = a.count ? a.count : 1, status = 0;

    for (int i = 0; i < count; i++) {
        char full[PATH_SIZE], folder[PATH_SIZE];
        const char *pattern;
        if (!full_path(paths[i], full, sizeof(full))) {
            print_error(ERROR_INVALID_NAME);
            status = 1;
            continue;
        }
        if (!has_wildcard(full) && is_directory(full)) {
            snprintf(folder, sizeof(folder), "%s", full);
            pattern = "*";
        } else {
            split_path(full, folder, sizeof(folder), &pattern);
            size_t length = strlen(folder);
            if (length > 3 && folder[length - 1] == '\\')
                folder[length - 1] = '\0';
            if (!*pattern)
                pattern = "*";
            if (!is_directory(folder)) {
                if (!o.bare)
                    print_volume_header((char)toupper((unsigned char)full[0]));
                print_error(ERROR_PATH_NOT_FOUND);
                status = 1;
                continue;
            }
        }
        if (!o.bare && i == 0) {
            print_volume_header((char)toupper((unsigned char)full[0]));
            out("\n");
        }
        o.found = 0;
        list_folder(folder, pattern, &o);
        if (!o.found) {
            if (!o.bare && !o.recurse)
                outf(" Directory of %s\n\n", folder);
            errf("File Not Found\n");
            status = 1;
            continue;
        }
        if (!o.bare && i == count - 1) {
            if (o.recurse) {
                out("     Total Files Listed:\n");
                print_summary(o.total_file_count, o.total_bytes);
            }
            print_free(folder, o.total_dir_count);
        }
    }
    return status;
}

/* ==================== COPY / MOVE ==================== */

/* Ask before replacing dest unless /Y (or COPYCMD=/Y): 1 replace, 0 skip */
static int confirm_replace(const char *dest, int *replace_all)
{
    if (*replace_all)
        return 1;
    char question[PATH_SIZE + 16];
    snprintf(question, sizeof(question), "Overwrite %s", dest);
    int answer = ask_yes_no(question, 1);
    if (answer == 2)
        *replace_all = 1;
    return answer >= 1;
}

static int replace_without_asking(const struct arguments *a)
{
    char env[64];
    int value = has_switch(a, "Y");
    if (value)
        return value > 0;
    if (GetEnvironmentVariableA("COPYCMD", env, sizeof(env))) {
        _strupr(env);
        if (strstr(env, "/-Y"))
            return 0;
        if (strstr(env, "/Y"))
            return 1;
    }
    /* A batch file does not stop to ask */
    return current_batch != NULL;
}

/* Append the file source to the open handle dest */
static int append_file(HANDLE dest, const char *source)
{
    char buffer[16384];
    DWORD count, written;
    HANDLE in = CreateFileA(source, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                            OPEN_EXISTING, 0, NULL);
    if (in == INVALID_HANDLE_VALUE)
        return 0;
    while (ReadFile(in, buffer, sizeof(buffer), &count, NULL) && count > 0)
        WriteFile(dest, buffer, count, &written, NULL);
    CloseHandle(in);
    return 1;
}

struct copy_job {
    char dest[PATH_SIZE];
    int dest_is_dir, show_names, replace_all, moving, count, failed;
    HANDLE concat;  /* Several files into one: the open destination */
};

static int copy_one(const char *path, const WIN32_FIND_DATAA *data, void *context)
{
    struct copy_job *job = context;
    char target[PATH_SIZE], source_full[PATH_SIZE], target_full[PATH_SIZE];
    if (job->show_names)
        outf("%s\n", path);
    if (job->concat) {
        if (append_file(job->concat, path))
            job->count = 1;
        return 1;
    }
    if (job->dest_is_dir)
        join_path(job->dest, data->cFileName, target, sizeof(target));
    else
        snprintf(target, sizeof(target), "%s", job->dest);
    full_path(path, source_full, sizeof(source_full));
    full_path(target, target_full, sizeof(target_full));
    if (_stricmp(source_full, target_full) == 0) {
        if (!job->moving) {
            errf("The file cannot be copied onto itself.\n");
            job->failed = 1;
        }
        return 1;
    }
    if (exists(target_full) && !confirm_replace(target_full, &job->replace_all))
        return 1;
    BOOL ok = job->moving ? MoveFileExA(source_full, target_full,
                                        MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED)
                          : CopyFileA(source_full, target_full, FALSE);
    if (!ok) {
        print_error(GetLastError());
        job->failed = 1;
        return 1;
    }
    job->count++;
    return 1;
}

int cmd_copy(char *args)
{
    char joined[LINE_SIZE];
    struct arguments a;
    struct copy_job job;
    int used = 0;
    /* "a + b" and "a+b": the sources joined by + are concatenated */
    for (const char *p = args; *p && used < LINE_SIZE - 1; p++) {
        if (*p == ' ' || *p == '\t') {
            const char *next = skip_spaces(p);
            if (*next == '+' || (used > 0 && joined[used - 1] == '+')) {
                p = next - 1;
                continue;
            }
        }
        joined[used++] = *p;
    }
    joined[used] = '\0';
    parse_arguments(joined, &a);
    memset(&job, 0, sizeof(job));
    job.replace_all = replace_without_asking(&a);
    if (a.count == 0 || a.count > 2) {
        syntax_error();
        return 1;
    }
    char sources[LINE_SIZE];
    snprintf(sources, sizeof(sources), "%s", a.words[0]);
    int concat = strchr(sources, '+') != NULL;
    full_path(a.count == 2 ? a.words[1] : ".", job.dest, sizeof(job.dest));
    size_t dlength = strlen(job.dest);
    job.dest_is_dir = is_directory(job.dest) ||
                      (dlength && job.dest[dlength - 1] == '\\');

    if (!concat) {
        char pattern[PATH_SIZE];
        full_path(sources, pattern, sizeof(pattern));
        if (!has_wildcard(pattern) && is_directory(pattern)) {
            size_t length = strlen(pattern);
            snprintf(pattern + length, sizeof(pattern) - length, "%s*",
                     pattern[length - 1] == '\\' ? "" : "\\");
        }
        int matches = for_each_match(pattern, 0, NULL, NULL);
        if (matches == 0) {
            print_error(ERROR_FILE_NOT_FOUND);
            outf("%9d file(s) copied.\n", 0);
            return 1;
        }
        job.show_names = has_wildcard(pattern) || matches > 1;
        if (matches > 1 && !job.dest_is_dir)
            concat = 1;  /* copy *.txt all.txt concatenates, like cmd */
        else {
            for_each_match(pattern, 0, copy_one, &job);
            outf("%9d file(s) copied.\n", job.count);
            return job.failed || job.count == 0;
        }
    }

    /* Concatenation into one file */
    if (job.dest_is_dir) {
        /* "copy a+b" without a destination: appended to the first source */
        char first[PATH_SIZE];
        char *plus = strchr(sources, '+');
        snprintf(first, sizeof(first), "%.*s", plus ? (int)(plus - sources) : (int)strlen(sources),
                 sources);
        if (has_wildcard(first)) {
            syntax_error();
            return 1;
        }
        full_path(first, job.dest, sizeof(job.dest));
    }
    char temp_dir[PATH_SIZE], temp[PATH_SIZE];
    GetTempPathA(sizeof(temp_dir), temp_dir);
    GetTempFileNameA(temp_dir, "cpy", 0, temp);
    job.concat = CreateFileA(temp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (job.concat == INVALID_HANDLE_VALUE) {
        print_error(GetLastError());
        return 1;
    }
    job.show_names = 1;
    for (char *s = strtok(sources, "+"); s; s = strtok(NULL, "+")) {
        char pattern[PATH_SIZE];
        full_path(s, pattern, sizeof(pattern));
        if (for_each_match(pattern, 0, copy_one, &job) == 0) {
            outf("%s\n", s);
            print_error(ERROR_FILE_NOT_FOUND);
        }
    }
    CloseHandle(job.concat);
    if (job.count && exists(job.dest) && !confirm_replace(job.dest, &job.replace_all))
        job.count = 0;
    if (job.count && !CopyFileA(temp, job.dest, FALSE)) {
        print_error(GetLastError());
        job.count = 0;
    }
    DeleteFileA(temp);
    outf("%9d file(s) copied.\n", job.count);
    return job.count == 0;
}

int cmd_move(char *args)
{
    struct arguments a;
    struct copy_job job;
    parse_arguments(args, &a);
    memset(&job, 0, sizeof(job));
    job.moving = 1;
    job.replace_all = replace_without_asking(&a);
    if (a.count != 2) {
        syntax_error();
        return 1;
    }
    char source[PATH_SIZE];
    full_path(a.words[0], source, sizeof(source));
    full_path(a.words[1], job.dest, sizeof(job.dest));
    job.dest_is_dir = is_directory(job.dest);

    if (!has_wildcard(source) && is_directory(source)) {
        /* A folder: renamed, or moved into an existing one */
        char target[PATH_SIZE];
        const char *name;
        char folder[PATH_SIZE];
        split_path(source, folder, sizeof(folder), &name);
        if (job.dest_is_dir)
            join_path(job.dest, name, target, sizeof(target));
        else
            snprintf(target, sizeof(target), "%s", job.dest);
        if (!MoveFileA(source, target)) {
            print_error(GetLastError());
            return 1;
        }
        outf("%9d dir(s) moved.\n", 1);
        return 0;
    }
    int matches = for_each_match(source, 0, NULL, NULL);
    if (matches == 0) {
        print_error(ERROR_FILE_NOT_FOUND);
        return 1;
    }
    if (matches > 1 && !job.dest_is_dir) {
        errf("Cannot move multiple files to a single file.\n");
        return 1;
    }
    job.show_names = has_wildcard(source);
    for_each_match(source, 0, copy_one, &job);
    outf("%9d file(s) moved.\n", job.count);
    return job.failed || job.count == 0;
}

/* ==================== DEL ==================== */

struct delete_job {
    int force, ask, recurse, count, failed;
};

static int delete_one(const char *path, const WIN32_FIND_DATAA *data, void *context)
{
    struct delete_job *job = context;
    if (job->ask) {
        char question[PATH_SIZE + 16];
        snprintf(question, sizeof(question), "%s, Delete", path);
        int answer = ask_yes_no(question, 0);
        if (answer < 0)
            return 0;
        if (answer == 0)
            return 1;
    }
    if (data->dwFileAttributes & FILE_ATTRIBUTE_READONLY) {
        if (!job->force) {
            errf("Access is denied - %s\n", path);
            job->failed = 1;
            return 1;
        }
        SetFileAttributesA(path, FILE_ATTRIBUTE_NORMAL);
    }
    if (!DeleteFileA(path)) {
        errf("%s - ", path);
        print_error(GetLastError());
        job->failed = 1;
        return 1;
    }
    if (job->recurse)
        outf("Deleted file - %s\n", path);
    job->count++;
    return 1;
}

/* Delete the files of folder matching name (and in its subfolders with /S) */
static int delete_in(const char *folder, const char *name, struct delete_job *job)
{
    char pattern[PATH_SIZE];
    join_path(folder, name, pattern, sizeof(pattern));
    int found = for_each_match(pattern, 0, delete_one, job);
    if (!job->recurse)
        return found;
    WIN32_FIND_DATAA data;
    char spec[PATH_SIZE], sub[PATH_SIZE];
    join_path(folder, "*", spec, sizeof(spec));
    HANDLE find = FindFirstFileA(spec, &data);
    if (find == INVALID_HANDLE_VALUE)
        return found;
    do {
        if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && !is_dots(data.cFileName)) {
            join_path(folder, data.cFileName, sub, sizeof(sub));
            found += delete_in(sub, name, job);
        }
    } while (FindNextFileA(find, &data));
    FindClose(find);
    return found;
}

int cmd_del(char *args)
{
    struct arguments a;
    struct delete_job job;
    int status = 0;
    parse_arguments(args, &a);
    memset(&job, 0, sizeof(job));
    job.force = has_switch(&a, "F") > 0;
    job.ask = has_switch(&a, "P") > 0;
    job.recurse = has_switch(&a, "S") > 0;
    int quiet = has_switch(&a, "Q") > 0;
    if (a.count == 0) {
        syntax_error();
        return 1;
    }
    for (int i = 0; i < a.count; i++) {
        char full[PATH_SIZE], folder[PATH_SIZE];
        const char *name;
        full_path(a.words[i], full, sizeof(full));
        if (!has_wildcard(full) && is_directory(full)) {
            snprintf(folder, sizeof(folder), "%s", full);
            name = "*";
        } else {
            split_path(full, folder, sizeof(folder), &name);
        }
        if (!quiet && !job.ask && (strcmp(name, "*") == 0 || strcmp(name, "*.*") == 0)) {
            char question[PATH_SIZE + 32], shown[PATH_SIZE];
            join_path(folder, "*", shown, sizeof(shown));
            snprintf(question, sizeof(question), "%s, Are you sure", shown);
            if (ask_yes_no(question, 0) != 1)
                continue;
        }
        if (delete_in(folder, name, &job) == 0) {
            errf("Could Not Find %s\n", full);
            status = 1;
        }
    }
    return status || job.failed;
}

/* ==================== REN ==================== */

/* The new name of name under a wildcard pattern (REN *.txt *.bak) */
static void rename_by_pattern(const char *name, const char *pattern, char *result, int size)
{
    int used = 0;
    const char *s = name;
    for (const char *p = pattern; *p && used < size - 1; p++) {
        if (*p == '?') {
            if (*s && *s != '.')
                result[used++] = *s++;
        } else if (*p == '*') {
            /* Up to the last place where the pattern's next character is */
            const char *stop = p[1] ? strrchr(s, p[1]) : NULL;
            const char *end = stop ? stop : s + strlen(s);
            while (s < end && used < size - 1)
                result[used++] = *s++;
        } else if (*p == '.') {
            const char *dot = strchr(s, '.');
            s = dot ? dot + 1 : s + strlen(s);
            result[used++] = '.';
        } else {
            result[used++] = *p;
            if (*s && *s != '.')
                s++;
        }
    }
    while (used > 0 && result[used - 1] == '.')
        used--;
    result[used] = '\0';
}

struct rename_job {
    const char *pattern;
    int count, failed;
};

static int rename_one(const char *path, const WIN32_FIND_DATAA *data, void *context)
{
    struct rename_job *job = context;
    char folder[PATH_SIZE], new_name[MAX_PATH], target[PATH_SIZE];
    const char *name;
    split_path(path, folder, sizeof(folder), &name);
    if (has_wildcard(job->pattern))
        rename_by_pattern(data->cFileName, job->pattern, new_name, sizeof(new_name));
    else
        snprintf(new_name, sizeof(new_name), "%s", job->pattern);
    join_path(folder, new_name, target, sizeof(target));
    if (_stricmp(path, target) != 0 && exists(target)) {
        errf("A file with the new name already exists, or the file cannot be found.\n");
        job->failed = 1;
        return 1;
    }
    if (!MoveFileA(path, target)) {
        print_error(GetLastError());
        job->failed = 1;
        return 1;
    }
    job->count++;
    return 1;
}

int cmd_ren(char *args)
{
    struct arguments a;
    struct rename_job job;
    char full[PATH_SIZE];
    parse_arguments(args, &a);
    if (a.count != 2 || strpbrk(a.words[1], "\\:")) {
        syntax_error();
        return 1;
    }
    memset(&job, 0, sizeof(job));
    job.pattern = a.words[1];
    full_path(a.words[0], full, sizeof(full));
    if (for_each_match(full, 1, rename_one, &job) == 0) {
        errf("A file with the new name already exists, or the file cannot be found.\n");
        return 1;
    }
    return job.failed;
}

/* ==================== TYPE ==================== */

static int type_one(const char *path, const WIN32_FIND_DATAA *data, void *context)
{
    char buffer[8192];
    DWORD count, written;
    if (*(int *)context)
        errf("\n%s\n\n\n", path);  /* Several files: each one's name first */
    HANDLE file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                              OPEN_EXISTING, 0, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        print_error(GetLastError());
        return 1;
    }
    while (ReadFile(file, buffer, sizeof(buffer), &count, NULL) && count > 0) {
        /* Text stops at Ctrl+Z, like TYPE of MS-DOS and Windows */
        char *eof = memchr(buffer, 0x1A, count);
        if (eof)
            count = (DWORD)(eof - buffer);
        WriteFile(out_h, buffer, count, &written, NULL);
        if (eof)
            break;
    }
    CloseHandle(file);
    return 1;
}

int cmd_type(char *args)
{
    struct arguments a;
    int status = 0;
    parse_arguments(args, &a);
    if (a.count == 0) {
        syntax_error();
        return 1;
    }
    for (int i = 0; i < a.count; i++) {
        char full[PATH_SIZE];
        full_path(a.words[i], full, sizeof(full));
        if (!has_wildcard(full) && is_directory(full)) {
            print_error(ERROR_ACCESS_DENIED);
            status = 1;
            continue;
        }
        int show_names = has_wildcard(full) || a.count > 1;
        if (for_each_match(full, 0, type_one, &show_names) == 0) {
            print_error(ERROR_FILE_NOT_FOUND);
            errf("Error occurred while processing: %s.\n", a.words[i]);
            status = 1;
        }
    }
    return status;
}

/* ==================== VOL ==================== */

int cmd_vol(char *args)
{
    struct arguments a;
    char current[PATH_SIZE], root[4] = "C:\\";
    parse_arguments(args, &a);
    GetCurrentDirectoryA(sizeof(current), current);
    char letter = a.count ? a.words[0][0] : current[0];
    if (a.count && (a.words[0][1] != ':' || a.words[0][2] != '\0')) {
        print_error(ERROR_INVALID_NAME);
        return 1;
    }
    root[0] = (char)toupper((unsigned char)letter);
    if (!GetVolumeInformationA(root, NULL, 0, NULL, NULL, NULL, NULL, 0)) {
        print_error(ERROR_INVALID_DRIVE);
        return 1;
    }
    print_volume_header(root[0]);
    return 0;
}
