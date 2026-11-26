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
winexe32emu Command Prompt (CMD.EXE) - the emulator's command interpreter,
compiled into C:\Windows\System32 like the cmd.exe of Windows (see
install_dir); COMSPEC names it, so system() and "cmd /c" of other programs
run it too. A console program (see the console file of this folder).

  cmd                 interactive prompt
  cmd /c command      runs the command, then ends (exit code: its ERRORLEVEL)
  cmd /k command      runs the command, then shows the prompt
  cmd /q              echo off

This file reads and expands the command lines, splits them at & && || |,
handles the redirections (> >> < 2> 2>&1) and runs the internal commands
(files.c, builtins.c, batch.c) or the programs found in the current folder
and on the PATH.
*/

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cmd.h"

HANDLE out_h, err_h, in_h;
int echo_on = 1;
int errorlevel = 0;
int abort_line = 0;
int screen_cleared = 0;
int calling_batch = 0;

/* ==================== OUTPUT AND INPUT ==================== */

/* Write text to a handle; a lone LF becomes CR LF like the console and the
   text files of Windows expect */
static void write_text(HANDLE handle, const char *text)
{
    char buffer[1024];
    int used = 0;
    DWORD written;
    for (const char *p = text; *p; p++) {
        if (*p == '\n' && (p == text || p[-1] != '\r'))
            buffer[used++] = '\r';
        buffer[used++] = *p;
        if (used >= (int)sizeof(buffer) - 2) {
            WriteFile(handle, buffer, used, &written, NULL);
            used = 0;
        }
    }
    if (used)
        WriteFile(handle, buffer, used, &written, NULL);
}

void out(const char *text)
{
    write_text(out_h, text);
}

void outf(const char *format, ...)
{
    char text[LINE_SIZE];
    va_list args;
    va_start(args, format);
    vsnprintf(text, sizeof(text), format, args);
    va_end(args);
    text[sizeof(text) - 1] = '\0';
    write_text(out_h, text);
}

void errf(const char *format, ...)
{
    char text[LINE_SIZE];
    va_list args;
    va_start(args, format);
    vsnprintf(text, sizeof(text), format, args);
    va_end(args);
    text[sizeof(text) - 1] = '\0';
    write_text(err_h, text);
}

/* The message of a Win32 error code, the ones file commands meet */
void print_error(DWORD code)
{
    const char *text;
    switch (code) {
    case ERROR_FILE_NOT_FOUND: text = "The system cannot find the file specified."; break;
    case ERROR_PATH_NOT_FOUND: text = "The system cannot find the path specified."; break;
    case ERROR_ACCESS_DENIED: text = "Access is denied."; break;
    case ERROR_INVALID_DRIVE: text = "The system cannot find the drive specified."; break;
    case ERROR_SHARING_VIOLATION:
        text = "The process cannot access the file because it is being used by "
               "another process.";
        break;
    case ERROR_FILE_EXISTS: text = "The file exists."; break;
    case ERROR_ALREADY_EXISTS:
        text = "Cannot create a file when that file already exists.";
        break;
    case ERROR_DIR_NOT_EMPTY: text = "The directory is not empty."; break;
    case ERROR_INVALID_NAME:
        text = "The filename, directory name, or volume label syntax is incorrect.";
        break;
    case ERROR_DIRECTORY: text = "The directory name is invalid."; break;
    case ERROR_WRITE_PROTECT: text = "The media is write protected."; break;
    case ERROR_DISK_FULL: text = "There is not enough space on the disk."; break;
    case ERROR_NOT_READY: text = "The device is not ready."; break;
    case ERROR_BAD_EXE_FORMAT: text = "This program is not a valid Win32 application."; break;
    default:
        errf("Error %lu.\n", (unsigned long)code);
        return;
    }
    errf("%s\n", text);
}

/* Read one line (without its CR LF) from the console or a file; -1 at the
   end of the input */
int read_line(HANDLE handle, char *buffer, int size)
{
    DWORD mode, count = 0;
    int length = 0;
    if (GetConsoleMode(handle, &mode)) {
        if (!ReadConsoleA(handle, buffer, size - 1, &count, NULL) || count == 0)
            return -1;
        length = (int)count;
    } else {
        /* A file or a pipe: byte by byte, so nothing after the line is consumed */
        char c;
        for (;;) {
            if (!ReadFile(handle, &c, 1, &count, NULL) || count == 0) {
                if (length == 0)
                    return -1;
                break;
            }
            if (c == '\n')
                break;
            if (length < size - 1)
                buffer[length++] = c;
        }
    }
    buffer[length] = '\0';
    while (length > 0 && (buffer[length - 1] == '\n' || buffer[length - 1] == '\r'))
        buffer[--length] = '\0';
    return length;
}

/* Ask "question (Yes/No[/All])? "; 1 yes, 0 no, 2 all (-1 at the end of the input) */
int ask_yes_no(const char *question, int allow_all)
{
    char answer[64];
    for (;;) {
        outf("%s (Yes/No%s)? ", question, allow_all ? "/All" : "");
        if (read_line(in_h, answer, sizeof(answer)) < 0) {
            out("\n");
            return -1;
        }
        char *a = skip_spaces(answer);
        if (*a == 'y' || *a == 'Y')
            return 1;
        if (*a == 'n' || *a == 'N')
            return 0;
        if (allow_all && (*a == 'a' || *a == 'A'))
            return 2;
    }
}

/* ==================== TEXT HELPERS ==================== */

char *skip_spaces(const char *text)
{
    while (*text == ' ' || *text == '\t')
        text++;
    return (char *)text;
}

void trim_right(char *text)
{
    size_t length = strlen(text);
    while (length > 0 && (text[length - 1] == ' ' || text[length - 1] == '\t'))
        text[--length] = '\0';
}

static int is_separator(char c)
{
    return c == ' ' || c == '\t' || c == ',' || c == ';';
}

/* Next argument of *cursor into token, its quotes removed; 0 if there is none */
int next_token(char **cursor, char *token, int size)
{
    char *p = *cursor;
    int quoted = 0, length = 0;
    while (*p && is_separator(*p))
        p++;
    if (!*p) {
        *cursor = p;
        token[0] = '\0';
        return 0;
    }
    while (*p && (quoted || !is_separator(*p))) {
        if (*p == '"')
            quoted = !quoted;
        else if (length < size - 1)
            token[length++] = *p;
        p++;
    }
    token[length] = '\0';
    *cursor = p;
    return 1;
}

/* Is token the switch /name (any letter case)? */
int is_option(const char *token, const char *name)
{
    return (token[0] == '/' || token[0] == '-') && _stricmp(token + 1, name) == 0;
}

int has_wildcard(const char *name)
{
    return strchr(name, '*') != NULL || strchr(name, '?') != NULL;
}

void strip_quotes(char *text)
{
    char *dst = text;
    for (char *src = text; *src; src++)
        if (*src != '"')
            *dst++ = *src;
    *dst = '\0';
}

/* Append text to buffer (of size bytes) without overflowing it */
static void append(char *buffer, int size, int *used, const char *text, int length)
{
    if (length < 0)
        length = (int)strlen(text);
    if (*used + length > size - 1)
        length = size - 1 - *used;
    if (length > 0) {
        memcpy(buffer + *used, text, length);
        *used += length;
    }
    buffer[*used] = '\0';
}

/* ==================== VARIABLES ==================== */

/* Keep the hidden "=C:" variable of the current drive up to date: Windows
   keeps the current folder of each drive there, so "D:" and "cd D:" return to
   the folder last used on that drive */
void remember_current_directory(void)
{
    char dir[PATH_SIZE], name[4] = "=C:";
    if (!GetCurrentDirectoryA(sizeof(dir), dir) || dir[1] != ':')
        return;
    name[1] = (char)toupper((unsigned char)dir[0]);
    SetEnvironmentVariableA(name, dir);
}

/* Value of an environment variable, or of the dynamic ones cmd provides
   (CD, DATE, TIME, ERRORLEVEL, RANDOM, CMDCMDLINE) */
static int get_variable(const char *name, char *value, int size)
{
    DWORD length = GetEnvironmentVariableA(name, value, size);
    if (length > 0 && length < (DWORD)size)
        return 1;
    SYSTEMTIME t;
    if (_stricmp(name, "CD") == 0)
        return GetCurrentDirectoryA(size, value) > 0;
    if (_stricmp(name, "ERRORLEVEL") == 0) {
        snprintf(value, size, "%d", errorlevel);
        return 1;
    }
    if (_stricmp(name, "RANDOM") == 0) {
        snprintf(value, size, "%d", rand() % 32768);
        return 1;
    }
    if (_stricmp(name, "CMDCMDLINE") == 0) {
        snprintf(value, size, "%s", GetCommandLineA());
        return 1;
    }
    if (_stricmp(name, "DATE") == 0) {
        static const char *const days[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
        GetLocalTime(&t);
        snprintf(value, size, "%s %02d/%02d/%04d", days[t.wDayOfWeek % 7], t.wMonth, t.wDay,
                 t.wYear);
        return 1;
    }
    if (_stricmp(name, "TIME") == 0) {
        GetLocalTime(&t);
        snprintf(value, size, "%2d:%02d:%02d.%02d", t.wHour, t.wMinute, t.wSecond,
                 t.wMilliseconds / 10);
        return 1;
    }
    return 0;
}

/* %NAME:~start,length% and %NAME:old=new% applied to value */
static void edit_variable(const char *edit, char *value, int size)
{
    char result[LINE_SIZE];
    int used = 0;
    if (edit[0] == '~') {
        int length = (int)strlen(value);
        char *end;
        long start = strtol(edit + 1, &end, 10);
        long count = length;
        if (*end == ',')
            count = strtol(end + 1, NULL, 10);
        if (start < 0)
            start = length + start < 0 ? 0 : length + start;
        if (start > length)
            start = length;
        if (count < 0)
            count = length - start + count;
        if (count < 0)
            count = 0;
        if (start + count > length)
            count = length - start;
        memmove(value, value + start, count);
        value[count] = '\0';
        return;
    }
    const char *equals = strchr(edit, '=');
    if (!equals)
        return;
    char old[LINE_SIZE];
    int old_length = (int)(equals - edit), anchored = 0;
    if (old_length > 0 && edit[0] == '*') {
        /* *old=new: everything up to the first old is replaced */
        anchored = 1;
        edit++;
        old_length--;
    }
    if (old_length <= 0 || old_length >= (int)sizeof(old))
        return;
    memcpy(old, edit, old_length);
    old[old_length] = '\0';
    const char *new_text = equals + 1;
    result[0] = '\0';
    for (const char *p = value; *p;) {
        if (_strnicmp(p, old, old_length) == 0) {
            if (anchored)
                used = 0;
            append(result, sizeof(result), &used, new_text, -1);
            p += old_length;
            if (anchored) {
                append(result, sizeof(result), &used, p, -1);
                break;
            }
        } else {
            append(result, sizeof(result), &used, p, 1);
            p++;
        }
    }
    snprintf(value, size, "%s", result);
}

/* Expand %NAME% (and, in a batch file, %0..%9, %*, %~mods0..9 and %% to %).
   Like cmd, an unknown variable stays as typed at the prompt and disappears
   in a batch file. */
void expand_variables(const char *line, char *result, int size, int in_batch)
{
    char name[LINE_SIZE], value[LINE_SIZE];
    int used = 0;
    result[0] = '\0';
    for (int i = 0; line[i];) {
        if (line[i] != '%') {
            append(result, size, &used, line + i, 1);
            i++;
            continue;
        }
        if (in_batch) {
            char next = line[i + 1];
            if (next == '%') {
                append(result, size, &used, "%", 1);
                i += 2;
                continue;
            }
            if (next >= '0' && next <= '9') {
                if (batch_argument(next - '0', value, sizeof(value)))
                    append(result, size, &used, value, -1);
                i += 2;
                continue;
            }
            if (next == '*') {
                if (batch_all_arguments(value, sizeof(value)))
                    append(result, size, &used, value, -1);
                i += 2;
                continue;
            }
            if (next == '~') {
                /* %~dp0, %~nx1...: modifiers then the argument digit */
                int j = i + 2;
                char mods[32];
                int m = 0;
                while (line[j] && strchr("fdpnxsatz", line[j]) && m < 31)
                    mods[m++] = line[j++];
                mods[m] = '\0';
                if (line[j] >= '0' && line[j] <= '9') {
                    char arg[LINE_SIZE];
                    if (batch_argument(line[j] - '0', arg, sizeof(arg)) &&
                            apply_modifiers(mods, arg, value, sizeof(value)))
                        append(result, size, &used, value, -1);
                    i = j + 1;
                    continue;
                }
            }
        }
        const char *close = strchr(line + i + 1, '%');
        if (close && close > line + i + 1) {
            int length = (int)(close - (line + i + 1));
            memcpy(name, line + i + 1, length);
            name[length] = '\0';
            char *colon = strchr(name, ':');
            if (colon)
                *colon = '\0';
            if (get_variable(name, value, sizeof(value))) {
                if (colon)
                    edit_variable(colon + 1, value, sizeof(value));
                append(result, size, &used, value, -1);
                i += length + 2;
                continue;
            }
            if (in_batch) {
                i += length + 2;
                continue;
            }
        } else if (in_batch) {
            i++;  /* A lone % disappears in a batch file */
            continue;
        }
        append(result, size, &used, "%", 1);
        i++;
    }
}

/* ==================== PROMPT ==================== */

void print_prompt(void)
{
    char format[LINE_SIZE], text[LINE_SIZE], dir[PATH_SIZE];
    int used = 0;
    if (!GetEnvironmentVariableA("PROMPT", format, sizeof(format)))
        strcpy(format, "$P$G");
    text[0] = '\0';
    for (const char *p = format; *p; p++) {
        if (*p != '$') {
            append(text, sizeof(text), &used, p, 1);
            continue;
        }
        p++;
        char c = (char)toupper((unsigned char)*p);
        SYSTEMTIME t;
        char piece[PATH_SIZE] = "";
        switch (c) {
        case 'P':
            if (GetCurrentDirectoryA(sizeof(dir), dir))
                snprintf(piece, sizeof(piece), "%s", dir);
            break;
        case 'N':
            if (GetCurrentDirectoryA(sizeof(dir), dir))
                snprintf(piece, sizeof(piece), "%c", dir[0]);
            break;
        case 'G': strcpy(piece, ">"); break;
        case 'L': strcpy(piece, "<"); break;
        case 'B': strcpy(piece, "|"); break;
        case 'Q': strcpy(piece, "="); break;
        case 'A': strcpy(piece, "&"); break;
        case 'C': strcpy(piece, "("); break;
        case 'F': strcpy(piece, ")"); break;
        case 'S': strcpy(piece, " "); break;
        case '$': strcpy(piece, "$"); break;
        case '_': strcpy(piece, "\n"); break;
        case 'E': strcpy(piece, "\x1b"); break;
        case 'H':
            if (used > 0)
                text[--used] = '\0';
            break;
        case 'T':
            GetLocalTime(&t);
            snprintf(piece, sizeof(piece), "%2d:%02d:%02d.%02d", t.wHour, t.wMinute,
                     t.wSecond, t.wMilliseconds / 10);
            break;
        case 'D':
            get_variable("DATE", piece, sizeof(piece));
            break;
        case 'V': {
            OSVERSIONINFOA version;
            memset(&version, 0, sizeof(version));
            version.dwOSVersionInfoSize = sizeof(version);
            GetVersionExA(&version);
            snprintf(piece, sizeof(piece), "Windows Version %lu.%lu",
                     (unsigned long)version.dwMajorVersion,
                     (unsigned long)version.dwMinorVersion);
            break;
        }
        case '\0':
            p--;
            break;
        default:
            break;
        }
        append(text, sizeof(text), &used, piece, -1);
    }
    out(text);
}

/* ==================== COMMAND TABLE ==================== */

struct command {
    const char *name;
    int (*run)(char *args);
    const char *summary;
    const char *usage;
};

static const struct command commands[] = {
    {"CALL", cmd_call, "Runs a batch file (or a label of this one) and comes back.",
     "CALL [drive:][path]filename [arguments]\nCALL :label [arguments]\n"},
    {"CD", cmd_cd, "Shows or changes the current directory.",
     "CD [/D] [drive:][path]\nCD ..\n\n  ..   The parent directory.\n"
     "  /D   Also changes the current drive.\n\nCD drive: shows the current directory "
     "of that drive; CD alone the current one.\n"},
    {"CHDIR", cmd_cd, "Shows or changes the current directory.", NULL},
    {"CLS", cmd_cls, "Clears the screen.", "CLS\n"},
    {"COPY", cmd_copy, "Copies files to another place.",
     "COPY [/Y | /-Y] source [+ source...] [destination]\n\n"
     "  source       The file(s) to copy (wildcards allowed).\n"
     "  destination  The folder or file name of the copies.\n"
     "  /Y           Replaces existing files without asking.\n"
     "  /-Y          Asks before replacing a file.\n"},
    {"DATE", cmd_date, "Shows the date.", "DATE [/T]\n\nThe date cannot be changed here.\n"},
    {"DEL", cmd_del, "Deletes files.",
     "DEL [/P] [/F] [/S] [/Q] names\nERASE [/P] [/F] [/S] [/Q] names\n\n"
     "  names  Files or folders (all their files); wildcards allowed.\n"
     "  /P     Asks before deleting each file.\n"
     "  /F     Also deletes read-only files.\n"
     "  /S     Also deletes the matching files of the subfolders.\n"
     "  /Q     Does not ask before deleting all the files of a folder.\n"},
    {"DIR", cmd_dir, "Lists the files and subdirectories of a directory.",
     "DIR [drive:][path][filename] [/A[[:]attributes]] [/B] [/O[[:]order]] [/S] [/W]\n\n"
     "  /A   Lists the files with these attributes (D folders, R read-only,\n"
     "       H hidden, S system, A archive; - means not); /A alone: all.\n"
     "  /B   Names only, without header and summary.\n"
     "  /O   Order: N name, E extension, S size, D date, G folders first\n"
     "       (- reverses).\n"
     "  /S   Also lists the subfolders.\n"
     "  /W   Wide list, several names per line.\n"},
    {"ECHO", cmd_echo, "Shows a message, or turns command echoing on or off.",
     "ECHO [ON | OFF]\nECHO [message]\nECHO.\n\nECHO alone shows whether echoing is on.\n"},
    {"ENDLOCAL", cmd_endlocal, "Ends the environment changes started with SETLOCAL.",
     "ENDLOCAL\n"},
    {"ERASE", cmd_del, "Deletes files.", NULL},
    {"EXIT", cmd_exit, "Quits the command prompt (or the batch file).",
     "EXIT [/B] [exitcode]\n\n  /B        Leaves only the current batch file.\n"
     "  exitcode  The exit code (ERRORLEVEL) to end with.\n"},
    {"FOR", cmd_for, "Runs a command for each file or word of a set.",
     "FOR %variable IN (set) DO command\nFOR /D %variable IN (set) DO command\n"
     "FOR /L %variable IN (start,step,end) DO command\n\n"
     "In a batch file write %%variable instead of %variable.\n"
     "Wildcards of the set are replaced by the matching files (/D: folders).\n"
     "%~nvariable, %~xvariable, %~fvariable, %~dvariable, %~pvariable give parts\n"
     "of the value.\n"},
    {"GOTO", cmd_goto, "Jumps to a label of a batch file.",
     "GOTO label\nGOTO :EOF\n\nA label is a line of the batch file like :label.\n"},
    {"HELP", cmd_help, "Lists the commands, or shows the help of one.", "HELP [command]\n"},
    {"IF", cmd_if, "Runs a command only if a condition holds.",
     "IF [NOT] ERRORLEVEL number command\n"
     "IF [/I] [NOT] string1==string2 command\n"
     "IF [/I] string1 EQU|NEQ|LSS|LEQ|GTR|GEQ string2 command\n"
     "IF [NOT] EXIST filename command\nIF [NOT] DEFINED variable command\n\n"
     "IF condition (command) ELSE (command)\n"},
    {"MD", cmd_md, "Creates a directory.",
     "MD [drive:]path\nMKDIR [drive:]path\n\nMissing parent folders are created too.\n"},
    {"MKDIR", cmd_md, "Creates a directory.", NULL},
    {"MOVE", cmd_move, "Moves files, or renames a directory.",
     "MOVE [/Y | /-Y] source destination\n\n"
     "  source       The file(s) to move (wildcards allowed) or a folder.\n"
     "  destination  The folder to move to, or the new name.\n"
     "  /Y           Replaces existing files without asking.\n"},
    {"PATH", cmd_path, "Shows or sets the program search path.",
     "PATH [[drive:]path[;...][;%PATH%]]\nPATH ;\n\nPATH ; clears it; PATH alone shows it.\n"},
    {"PAUSE", cmd_pause, "Waits for the Enter key.", "PAUSE\n"},
    {"POPD", cmd_popd, "Returns to the directory saved by PUSHD.", "POPD\n"},
    {"PROMPT", cmd_prompt, "Changes the command prompt.",
     "PROMPT [text]\n\n  $P  current drive and path   $G  >   $L  <   $B  |\n"
     "  $N  current drive             $Q  =   $$  $   $_  new line\n"
     "  $D  date   $T  time   $V  Windows version   $S  space   $H  backspace\n\n"
     "PROMPT alone restores $P$G.\n"},
    {"PUSHD", cmd_pushd, "Saves the current directory, then changes it.", "PUSHD [path]\n"},
    {"RD", cmd_rd, "Removes a directory.",
     "RD [/S] [/Q] [drive:]path\nRMDIR [/S] [/Q] [drive:]path\n\n"
     "  /S  Also removes all its files and subfolders.\n"
     "  /Q  Does not ask before removing with /S.\n"},
    {"REM", cmd_rem, "Marks a comment in a batch file.", "REM [comment]\n"},
    {"REN", cmd_ren, "Renames files.",
     "REN [drive:][path]filename newname\nRENAME [drive:][path]filename newname\n\n"
     "Wildcards are allowed: REN *.txt *.bak\n"},
    {"RENAME", cmd_ren, "Renames files.", NULL},
    {"RMDIR", cmd_rd, "Removes a directory.", NULL},
    {"SET", cmd_set, "Shows, sets or removes environment variables.",
     "SET [variable=[value]]\nSET prefix\nSET /A expression\nSET /P variable=[prompt]\n\n"
     "SET alone lists all variables; SET prefix the ones whose name starts so.\n"
     "SET variable= removes the variable. %variable% in a command is its value.\n"
     "/A computes an integer expression (+ - * / % ( ) and = += -= *= /=).\n"
     "/P asks for the value.\n"},
    {"SETLOCAL", cmd_setlocal, "Starts local environment changes of a batch file.",
     "SETLOCAL\n\nENDLOCAL, or the end of the batch file, restores the variables.\n"},
    {"SHIFT", cmd_shift, "Shifts the arguments of a batch file.",
     "SHIFT\n\n%1 becomes %0, %2 becomes %1, and so on.\n"},
    {"START", cmd_start, "Starts a program or opens a file in its own window.",
     "START [\"title\"] [/D path] [/WAIT] [/B] [/MIN] [/MAX] [command [arguments]]\n\n"
     "  \"title\"  The title of a new console window.\n"
     "  /D       The starting directory.\n"
     "  /WAIT    Waits until the program ends.\n"
     "  /B       A console program shares this console.\n\n"
     "START alone opens a new command prompt.\n"},
    {"TIME", cmd_time, "Shows the time.", "TIME [/T]\n\nThe time cannot be changed here.\n"},
    {"TITLE", cmd_title, "Sets the title of the console window.", "TITLE [text]\n"},
    {"TYPE", cmd_type, "Shows the contents of text files.", "TYPE [drive:][path]filename\n"},
    {"VER", cmd_ver, "Shows the Windows version.", "VER\n"},
    {"VOL", cmd_vol, "Shows the label and serial number of a drive.", "VOL [drive:]\n"},
};
#define COMMAND_COUNT (int)(sizeof(commands) / sizeof(commands[0]))

static const struct command *find_command(const char *name)
{
    for (int i = 0; i < COMMAND_COUNT; i++)
        if (_stricmp(commands[i].name, name) == 0)
            return &commands[i];
    return NULL;
}

/* The command that shares its help with an alias (CHDIR -> CD) */
static const struct command *help_of(const struct command *c)
{
    for (int i = 0; i < COMMAND_COUNT && !c->usage; i++)
        if (commands[i].run == c->run && commands[i].usage)
            c = &commands[i];
    return c;
}

void show_command_help(const char *name)
{
    const struct command *c = find_command(name);
    if (!c) {
        outf("There is no help for \"%s\": it is not an internal command.\n"
             "Try \"%s /?\" if it is a program.\n", name, name);
        return;
    }
    const struct command *h = help_of(c);
    outf("%s\n\n%s", h->summary, h->usage);
}

int cmd_help(char *args)
{
    char name[64];
    char *p = args;
    if (next_token(&p, name, sizeof(name))) {
        show_command_help(name);
        return 0;
    }
    out("For more information on a command, type HELP command-name or command /?\n\n");
    for (int i = 0; i < COMMAND_COUNT; i++)
        outf("%-10s %s\n", commands[i].name, commands[i].summary);
    out("\nOther programs run by their name (searched in the current directory\n"
        "and on the PATH). command > file, command >> file and command < file\n"
        "redirect; command1 & command2, && (if it worked), || (if it failed) and\n"
        "command1 | command2 chain commands.\n");
    return 0;
}

/* Run the internal command name; 0 if there is none of that name */
int run_cmd_command(const char *name, char *args, int *status)
{
    const struct command *c = find_command(name);
    if (!c)
        return 0;
    char first[16];
    char *p = args;
    if (next_token(&p, first, sizeof(first)) && strcmp(first, "/?") == 0) {
        show_command_help(name);
        *status = 0;
        return 1;
    }
    *status = c->run(args);
    return 1;
}

/* ==================== RUNNING PROGRAMS ==================== */

/* Kind of the file at path: 1 a program, 2 a batch file, 0 neither */
static int program_kind(const char *path)
{
    DWORD attributes = GetFileAttributesA(path);
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY))
        return 0;
    const char *dot = strrchr(path, '.');
    const char *slash = strrchr(path, '\\');
    if (!dot || (slash && dot < slash))
        return 0;
    if (_stricmp(dot, ".bat") == 0 || _stricmp(dot, ".cmd") == 0)
        return 2;
    if (_stricmp(dot, ".exe") == 0 || _stricmp(dot, ".com") == 0)
        return 1;
    return 0;
}

/* Try folder\name and folder\name.EXT for the PATHEXT extensions */
static int try_folder(const char *folder, const char *name, char *path, int size)
{
    char base[PATH_SIZE], candidate[PATH_SIZE], exts[512];
    if (folder && *folder) {
        size_t length = strlen(folder);
        snprintf(base, sizeof(base), "%s%s%s", folder,
                 folder[length - 1] == '\\' ? "" : "\\", name);
    } else {
        snprintf(base, sizeof(base), "%s", name);
    }
    const char *dot = strrchr(name, '.');
    const char *slash = strrchr(name, '\\');
    if (dot && (!slash || dot > slash)) {
        int kind = program_kind(base);
        if (kind) {
            full_path(base, path, size);
            return kind;
        }
    }
    if (!GetEnvironmentVariableA("PATHEXT", exts, sizeof(exts)))
        strcpy(exts, ".COM;.EXE;.BAT;.CMD");
    for (char *ext = strtok(exts, ";"); ext; ext = strtok(NULL, ";")) {
        snprintf(candidate, sizeof(candidate), "%s%s", base, ext);
        int kind = program_kind(candidate);
        if (kind) {
            full_path(candidate, path, size);
            return kind;
        }
    }
    return 0;
}

/* Find the program or batch file name names, like cmd: as given if it has a
   path, else in the current directory and then the PATH folders */
int find_program(const char *name, char *path, int size)
{
    char dirs[LINE_SIZE];
    if (!*name)
        return 0;
    if (strpbrk(name, "\\/:"))
        return try_folder(NULL, name, path, size);
    int kind = try_folder(".", name, path, size);
    if (kind)
        return kind;
    if (!GetEnvironmentVariableA("PATH", dirs, sizeof(dirs)))
        return 0;
    char *cursor = dirs;
    while (*cursor) {
        char *end = strchr(cursor, ';');
        if (end)
            *end = '\0';
        strip_quotes(cursor);
        if (*cursor && (kind = try_folder(cursor, name, path, size)) != 0)
            return kind;
        if (!end)
            break;
        cursor = end + 1;
    }
    return 0;
}

/* Subsystem of an EXE (2 GUI, 3 console; 0 if unknown): only console
   programs are waited for at the prompt, like cmd does */
static int exe_subsystem(const char *path)
{
    HANDLE file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                              OPEN_EXISTING, 0, NULL);
    unsigned char header[0x40], pe[0x60];
    DWORD count;
    int subsystem = 0;
    if (file == INVALID_HANDLE_VALUE)
        return 0;
    if (ReadFile(file, header, sizeof(header), &count, NULL) && count == sizeof(header) &&
            header[0] == 'M' && header[1] == 'Z') {
        DWORD offset = header[0x3C] | header[0x3D] << 8 | header[0x3E] << 16 |
                       (DWORD)header[0x3F] << 24;
        /* Signature (4), file header (20), then Subsystem at 68 of the optional one */
        if (SetFilePointer(file, offset, NULL, FILE_BEGIN) == offset &&
                ReadFile(file, pe, sizeof(pe), &count, NULL) && count == sizeof(pe) &&
                memcmp(pe, "PE\0\0", 4) == 0)
            subsystem = pe[24 + 68] | pe[24 + 69] << 8;
    }
    CloseHandle(file);
    return subsystem;
}

/* Run a program (or batch file) by its command line; must_wait: also wait
   for a GUI program. Returns its exit code (9009 when nothing is found). */
int run_external(const char *command, int must_wait)
{
    char name[PATH_SIZE], path[PATH_SIZE], cmdline[LINE_SIZE];
    char *cursor = (char *)command;
    next_token(&cursor, name, sizeof(name));
    int kind = find_program(name, path, sizeof(path));
    if (kind == 2) {
        int was_calling = calling_batch;
        struct batch_file *caller = current_batch;
        calling_batch = 0;
        int status = run_batch(path, name, cursor, NULL);
        if (caller && !was_calling) {
            /* Without CALL a batch file replaces the running one */
            stop_batch(caller);
            abort_line = 1;
        }
        return status;
    }
    if (kind == 0) {
        DWORD attributes = GetFileAttributesA(name);
        if (attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY)) {
            /* A document: open it with its program, like Explorer */
            if ((INT_PTR)ShellExecuteA(NULL, "open", name, NULL, NULL, SW_SHOWNORMAL) > 32)
                return 0;
        }
        errf("'%s' is not recognized as an internal or external command,\n"
             "operable program or batch file.\n", name);
        return 9009;
    }

    /* The child gets the command line as typed, and our (redirected) handles */
    snprintf(cmdline, sizeof(cmdline), "%s", skip_spaces(command));
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = in_h;
    si.hStdOutput = out_h;
    si.hStdError = err_h;
    if (!CreateProcessA(path, cmdline, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        DWORD error = GetLastError();
        if (error == ERROR_BAD_EXE_FORMAT)
            errf("%s cannot be run here: it is not a 32-bit Windows program.\n", name);
        else
            print_error(error);
        return 1;
    }
    DWORD code = 0;
    if (must_wait || current_batch || exe_subsystem(path) != IMAGE_SUBSYSTEM_WINDOWS_GUI) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        GetExitCodeProcess(pi.hProcess, &code);
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return (int)code;
}

/* ==================== PARSING ==================== */

enum { OP_END, OP_AMP, OP_AND, OP_OR, OP_PIPE };

/* Does the command text start with word (IF, FOR, REM) as a whole word? */
static int starts_with_word(const char *text, const char *word)
{
    text = skip_spaces(text);
    while (*text == '@')
        text = skip_spaces(text + 1);
    size_t length = strlen(word);
    return _strnicmp(text, word, length) == 0 &&
           (text[length] == '\0' || text[length] == ' ' || text[length] == '\t' ||
            text[length] == '/' || text[length] == '(');
}

/* Index of the ')' closing the '(' at text[start], or -1 */
int matching_paren(const char *text, int start)
{
    int depth = 0, quoted = 0;
    for (int i = start; text[i]; i++) {
        char c = text[i];
        if (c == '"')
            quoted = !quoted;
        else if (quoted)
            continue;
        else if (c == '^' && text[i + 1])
            i++;
        else if (c == '(')
            depth++;
        else if (c == ')' && --depth == 0)
            return i;
    }
    return -1;
}

/* Remove the carets of the text outside quotes: ^x stands for x */
static void remove_carets(char *text)
{
    char *dst = text;
    int quoted = 0;
    for (char *src = text; *src; src++) {
        if (*src == '"')
            quoted = !quoted;
        if (*src == '^' && !quoted && src[1]) {
            src++;
        }
        *dst++ = *src;
    }
    *dst = '\0';
}

/* Run one simple command (or a ( block )) with the current handles */
static int exec_command(char *text)
{
    char name[PATH_SIZE];
    char *p = skip_spaces(text);
    while (*p == '@')
        p = skip_spaces(p + 1);
    trim_right(p);
    if (!*p || *p == ':')
        return 0;
    if (*p == '(') {
        int close = matching_paren(p, 0);
        if (close < 0) {
            errf("The syntax of the command is incorrect.\n");
            return 1;
        }
        p[close] = '\0';
        return run_line(p + 1);
    }

    /* The command name ends at a space or at the switch, block or argument
       characters cmd allows right after it ("dir/w", "cd..", "echo.") */
    int length = 0;
    while (p[length] && !strchr(" \t/=,;+(\"", p[length]) && length < (int)sizeof(name) - 1) {
        name[length] = p[length];
        length++;
    }
    name[length] = '\0';
    if (length == 2 && name[1] == ':' && isalpha((unsigned char)name[0]) &&
            !*skip_spaces(p + 2))
        return cmd_drive(name[0]);

    int status;
    if (run_cmd_command(name, p + length, &status)) {
        if (status)
            errorlevel = status;
        return status;
    }
    /* "cd..", "echo.text", "cd\": an internal command glued to its argument */
    for (int i = 1; i < length; i++) {
        if (strchr(".\\:[]", name[i])) {
            char head[PATH_SIZE];
            memcpy(head, name, i);
            head[i] = '\0';
            if (find_command(head) && run_cmd_command(head, p + i, &status)) {
                if (status)
                    errorlevel = status;
                return status;
            }
            break;
        }
    }
    status = run_external(p, 0);
    errorlevel = status;
    return status;
}

struct redirection {
    int fd;          /* 0 input, 1 output, 2 errors */
    int append;      /* >> */
    int duplicate;   /* 2>&1: the fd it copies, else -1 */
    char file[PATH_SIZE];
};

/* Take the redirections out of text (outside quotes and blocks) */
static int parse_redirections(char *text, struct redirection *list, int max)
{
    int count = 0, quoted = 0, depth = 0;
    for (int i = 0; text[i]; i++) {
        char c = text[i];
        if (c == '"') {
            quoted = !quoted;
            continue;
        }
        if (quoted)
            continue;
        if (c == '^' && text[i + 1]) {
            i++;
            continue;
        }
        if (c == '(') {
            depth++;
            continue;
        }
        if (c == ')' && depth > 0) {
            depth--;
            continue;
        }
        if (depth > 0 || (c != '>' && c != '<') || count >= max)
            continue;
        struct redirection *r = &list[count];
        int start = i;
        r->fd = c == '<' ? 0 : 1;
        r->append = 0;
        r->duplicate = -1;
        if (i > 0 && text[i - 1] >= '0' && text[i - 1] <= '2' &&
                (i == 1 || text[i - 2] == ' ' || text[i - 2] == '\t')) {
            r->fd = text[i - 1] - '0';
            start = i - 1;
        }
        i++;
        if (c == '>' && text[i] == '>') {
            r->append = 1;
            i++;
        }
        if (text[i] == '&' && text[i + 1] >= '0' && text[i + 1] <= '2') {
            r->duplicate = text[i + 1] - '0';
            i += 2;
            r->file[0] = '\0';
        } else {
            while (text[i] == ' ' || text[i] == '\t')
                i++;
            int length = 0, q = 0;
            while (text[i] && (q || !strchr(" \t<>|&", text[i]))) {
                if (text[i] == '"')
                    q = !q;
                else if (length < PATH_SIZE - 1)
                    r->file[length++] = text[i];
                i++;
            }
            r->file[length] = '\0';
            if (!length) {
                errf("The syntax of the command is incorrect.\n");
                return -1;
            }
        }
        for (int j = start; j < i; j++)
            text[j] = ' ';
        i--;
        count++;
    }
    return count;
}

/* Run a command with its redirections; pipe_in/pipe_out: the temporary
   files of a pipe (or NULL) */
static int run_segment(char *text, HANDLE pipe_in, HANDLE pipe_out)
{
    HANDLE saved[3] = {in_h, out_h, err_h};
    HANDLE opened[8];
    int opened_count = 0, status;
    struct redirection list[8];
    int count = 0;
    int compound = starts_with_word(text, "IF") || starts_with_word(text, "FOR") ||
                   starts_with_word(text, "REM");
    if (pipe_in)
        in_h = pipe_in;
    if (pipe_out)
        out_h = pipe_out;
    if (!compound) {
        count = parse_redirections(text, list, 8);
        if (count < 0) {
            in_h = saved[0];
            out_h = saved[1];
            return 1;
        }
    }
    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    for (int i = 0; i < count; i++) {
        struct redirection *r = &list[i];
        HANDLE *target = r->fd == 0 ? &in_h : r->fd == 1 ? &out_h : &err_h;
        if (r->duplicate >= 0) {
            *target = r->duplicate == 0 ? in_h : r->duplicate == 1 ? out_h : err_h;
            continue;
        }
        HANDLE h;
        if (r->fd == 0)
            h = CreateFileA(r->file, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa,
                            OPEN_EXISTING, 0, NULL);
        else
            h = CreateFileA(r->file, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa,
                            r->append ? OPEN_ALWAYS : CREATE_ALWAYS, 0, NULL);
        if (h == INVALID_HANDLE_VALUE) {
            DWORD error = GetLastError();
            in_h = saved[0];
            out_h = saved[1];
            err_h = saved[2];
            print_error(error);
            for (int j = 0; j < opened_count; j++)
                CloseHandle(opened[j]);
            return 1;
        }
        if (r->append)
            SetFilePointer(h, 0, NULL, FILE_END);
        opened[opened_count++] = h;
        *target = h;
    }
    if (!compound && !starts_with_word(text, "("))
        remove_carets(text);
    status = exec_command(text);
    in_h = saved[0];
    out_h = saved[1];
    err_h = saved[2];
    for (int i = 0; i < opened_count; i++)
        CloseHandle(opened[i]);
    return status;
}

/* Run cmd1 | cmd2 | ...: each one's output goes to a temporary file that is
   the next one's input (the emulated programs run one after the other) */
static int run_pipeline(char **parts, int count)
{
    char temp_dir[PATH_SIZE], files[2][PATH_SIZE];
    HANDLE input = NULL;
    int status = 0, current = 0;
    if (count == 1)
        return run_segment(parts[0], NULL, NULL);
    if (!GetTempPathA(sizeof(temp_dir), temp_dir))
        strcpy(temp_dir, ".");
    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    for (int i = 0; i < count; i++) {
        HANDLE output = NULL;
        if (i < count - 1) {
            GetTempFileNameA(temp_dir, "cmd", 0, files[current]);
            output = CreateFileA(files[current], GENERIC_READ | GENERIC_WRITE,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, CREATE_ALWAYS,
                                 FILE_ATTRIBUTE_TEMPORARY, NULL);
            if (output == INVALID_HANDLE_VALUE)
                output = NULL;
        }
        status = run_segment(parts[i], input, output);
        if (input) {
            CloseHandle(input);
            DeleteFileA(files[!current]);
        }
        input = NULL;
        if (output) {
            CloseHandle(output);
            input = CreateFileA(files[current], GENERIC_READ, FILE_SHARE_READ, &sa,
                                OPEN_EXISTING, 0, NULL);
            if (input == INVALID_HANDLE_VALUE)
                input = NULL;
            current = !current;
        }
    }
    return status;
}

/* Run a command line: its commands joined by & && || | (an IF, FOR or REM
   takes the rest of the line, like in cmd). Returns the last status. */
int run_line(const char *line)
{
    char *buffer = malloc(LINE_SIZE);
    char *parts[64];
    int ops[64], count = 0, status = 0;
    if (!buffer)
        return 1;
    snprintf(buffer, LINE_SIZE, "%s", line);

    char *start = buffer;
    int quoted = 0, depth = 0;
    for (char *p = buffer;; p++) {
        if (p == start && (starts_with_word(p, "IF") || starts_with_word(p, "FOR") ||
                           starts_with_word(p, "REM"))) {
            parts[count] = start;
            ops[count++] = OP_END;
            break;
        }
        char c = *p;
        if (c == '\0') {
            parts[count] = start;
            ops[count++] = OP_END;
            break;
        }
        if (c == '"') {
            quoted = !quoted;
            continue;
        }
        if (quoted)
            continue;
        if (c == '^' && p[1]) {
            p++;
            continue;
        }
        if (c == '(')
            depth++;
        else if (c == ')' && depth > 0)
            depth--;
        if (depth > 0 || (c != '&' && c != '|'))
            continue;
        /* "2>&1" is a redirection, not a command separator */
        if (c == '&' && p > buffer && p[-1] == '>')
            continue;
        int op = c == '&' ? OP_AMP : OP_PIPE;
        *p = '\0';
        if (p[1] == c) {
            op = c == '&' ? OP_AND : OP_OR;
            p++;
        }
        parts[count] = start;
        ops[count++] = op;
        start = p + 1;
        if (count >= 63) {
            parts[count] = start;
            ops[count++] = OP_END;
            break;
        }
    }

    int previous = OP_AMP;
    for (int i = 0; i < count && !abort_line;) {
        int j = i;
        while (j < count - 1 && ops[j] == OP_PIPE)
            j++;
        int run = previous == OP_AMP || previous == OP_END ||
                  (previous == OP_AND && status == 0) || (previous == OP_OR && status != 0);
        if (run && *skip_spaces(parts[i]))
            status = run_pipeline(parts + i, j - i + 1);
        previous = ops[j];
        i = j + 1;
    }
    free(buffer);
    return status;
}

/* ==================== MAIN ==================== */

/* Unbalanced parentheses: the block goes on in the next lines */
int count_open_parens(const char *line)
{
    int depth = 0, quoted = 0;
    for (const char *p = line; *p; p++) {
        if (*p == '"')
            quoted = !quoted;
        else if (!quoted && *p == '^' && p[1])
            p++;
        else if (!quoted && *p == '(')
            depth++;
        else if (!quoted && *p == ')' && depth > 0)
            depth--;
    }
    return depth;
}

static void interactive(void)
{
    char *line = malloc(LINE_SIZE), *expanded = malloc(LINE_SIZE);
    if (!line || !expanded)
        return;
    for (;;) {
        if (echo_on)
            print_prompt();
        if (read_line(in_h, line, LINE_SIZE) < 0)
            break;
        while (count_open_parens(line) > 0) {
            char more[LINE_SIZE];
            out("More? ");
            if (read_line(in_h, more, sizeof(more)) < 0)
                break;
            size_t used = strlen(line);
            snprintf(line + used, LINE_SIZE - used, " & %s", more);
        }
        expand_variables(line, expanded, LINE_SIZE, 0);
        if (*skip_spaces(expanded)) {
            screen_cleared = 0;
            run_line(expanded);
            if (echo_on && !screen_cleared)
                out("\n");  /* After CLS the prompt stays on the top line */
        }
        abort_line = 0;
    }
    free(line);
    free(expanded);
}

/* The command of "cmd /c" or "cmd /k": like cmd, quotes around the whole
   command are removed, unless it is one quoted program name ("C:\Program
   Files\x.exe") */
static void unquote_command(char *command)
{
    int quotes = 0;
    for (char *p = command; *p; p++)
        quotes += *p == '"';
    if (command[0] != '"')
        return;
    char *close = strrchr(command, '"');
    if (quotes == 2 && !strpbrk(command, "&<>()@^|") && strpbrk(command, " \t")) {
        char name[PATH_SIZE], path[PATH_SIZE];
        int length = (int)(close - command - 1);
        if (length > 0 && length < PATH_SIZE) {
            memcpy(name, command + 1, length);
            name[length] = '\0';
            if (find_program(name, path, sizeof(path)))
                return;
        }
    }
    memmove(close, close + 1, strlen(close));
    memmove(command, command + 1, strlen(command));
}

int main(void)
{
    char *command = NULL, *expanded;
    int mode = 0;  /* 'C' or 'K' */
    in_h = GetStdHandle(STD_INPUT_HANDLE);
    out_h = GetStdHandle(STD_OUTPUT_HANDLE);
    err_h = GetStdHandle(STD_ERROR_HANDLE);
    srand(GetTickCount());
    remember_current_directory();

    /* Skip the program name, then the options up to /C or /K */
    char *p = skip_spaces(GetCommandLineA());
    if (*p == '"') {
        p = strchr(p + 1, '"');
        p = p ? p + 1 : p + strlen(p);
    } else {
        while (*p && *p != ' ' && *p != '\t')
            p++;
    }
    for (;;) {
        p = skip_spaces(p);
        if (*p != '/' && *p != '-')
            break;
        char option = (char)toupper((unsigned char)p[1]);
        if (option == 'C' || option == 'K') {
            mode = option;
            command = skip_spaces(p + 2);
            break;
        }
        if (option == 'Q')
            echo_on = 0;
        /* /D /A /U /S /T:fg /E:ON /F:OFF /V:ON... are accepted and ignored */
        p++;
        while (*p && *p != ' ' && *p != '\t' && *p != '/')
            p++;
    }

    if (command) {
        char *copy = malloc(LINE_SIZE);
        expanded = malloc(LINE_SIZE);
        if (!copy || !expanded)
            return 1;
        snprintf(copy, LINE_SIZE, "%s", command);
        unquote_command(copy);
        expand_variables(copy, expanded, LINE_SIZE, 0);
        int status = run_line(expanded);
        free(copy);
        free(expanded);
        if (mode == 'C')
            return status;
        abort_line = 0;
        if (echo_on)
            out("\n");
    } else {
        print_banner();
    }
    interactive();
    return errorlevel;
}
