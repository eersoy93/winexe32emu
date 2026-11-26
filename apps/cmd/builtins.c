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

/* The internal commands of the Command Prompt that are not about files:
   ECHO, SET, PATH, PROMPT, TITLE, VER, DATE, TIME, CLS, EXIT, START, PAUSE,
   REM, SETLOCAL and ENDLOCAL */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cmd.h"

/* ==================== ECHO, REM, PAUSE ==================== */

int cmd_echo(char *args)
{
    char word[16];
    char *text = skip_spaces(args);
    if (!*text && (!*args || *args == ' ' || *args == '\t')) {
        outf("ECHO is %s.\n", echo_on ? "on" : "off");
        return 0;
    }
    snprintf(word, sizeof(word), "%.15s", text);
    trim_right(word);
    if (_stricmp(word, "on") == 0 || _stricmp(word, "off") == 0) {
        echo_on = _stricmp(word, "on") == 0;
        return 0;
    }
    /* The one character after ECHO separates it from the message: "echo."
       prints an empty line, "echo  x" keeps the second space */
    outf("%s\n", args + 1);
    return 0;
}

int cmd_rem(char *args)
{
    return 0;
}

int cmd_pause(char *args)
{
    char line[256];
    out("Press Enter to continue . . . ");
    read_line(in_h, line, sizeof(line));
    return 0;
}

/* ==================== SET ==================== */

/* SET /A: integer expressions with the C operators and assignments */
struct expression {
    const char *p;
    int error;
};

static long parse_assignment(struct expression *e);

static void skip(struct expression *e)
{
    while (*e->p == ' ' || *e->p == '\t')
        e->p++;
}

static long variable_value(const char *name)
{
    char value[64];
    if (!GetEnvironmentVariableA(name, value, sizeof(value)))
        return 0;
    return strtol(value, NULL, 0);
}

static void set_number(const char *name, long value)
{
    char text[32];
    snprintf(text, sizeof(text), "%ld", value);
    SetEnvironmentVariableA(name, text);
}

static long parse_primary(struct expression *e)
{
    skip(e);
    char c = *e->p;
    if (c == '(') {
        e->p++;
        long value = parse_assignment(e);
        skip(e);
        if (*e->p == ')')
            e->p++;
        else
            e->error = 1;
        return value;
    }
    if (c == '-' || c == '+' || c == '!' || c == '~') {
        e->p++;
        long value = parse_primary(e);
        return c == '-' ? -value : c == '!' ? !value : c == '~' ? ~value : value;
    }
    if (isdigit((unsigned char)c)) {
        char *end;
        long value = strtol(e->p, &end, 0);
        e->p = end;
        return value;
    }
    if (isalpha((unsigned char)c) || c == '_') {
        char name[256];
        int length = 0;
        while ((isalnum((unsigned char)*e->p) || *e->p == '_') && length < 255)
            name[length++] = *e->p++;
        name[length] = '\0';
        return variable_value(name);
    }
    e->error = 1;
    return 0;
}

static long parse_binary(struct expression *e, int level)
{
    /* Lowest to highest: | ^ & << >> + - * / % */
    static const char *const levels[][3] = {
        {"|", NULL, NULL}, {"^", NULL, NULL}, {"&", NULL, NULL},
        {"<<", ">>", NULL}, {"+", "-", NULL}, {"*", "/", "%"},
    };
    if (level == 6)
        return parse_primary(e);
    long value = parse_binary(e, level + 1);
    for (;;) {
        skip(e);
        const char *op = NULL;
        for (int i = 0; i < 3 && levels[level][i]; i++) {
            size_t length = strlen(levels[level][i]);
            if (strncmp(e->p, levels[level][i], length) == 0 && e->p[length] != '=') {
                op = levels[level][i];
                break;
            }
        }
        if (!op)
            return value;
        e->p += strlen(op);
        long right = parse_binary(e, level + 1);
        switch (op[0]) {
        case '|': value |= right; break;
        case '^': value ^= right; break;
        case '&': value &= right; break;
        case '<': value <<= right; break;
        case '>': value >>= right; break;
        case '+': value += right; break;
        case '-': value -= right; break;
        case '*': value *= right; break;
        case '/':
        case '%':
            if (right == 0) {
                e->error = 2;
                return 0;
            }
            value = op[0] == '/' ? value / right : value % right;
            break;
        default: break;
        }
    }
}

static long parse_assignment(struct expression *e)
{
    skip(e);
    const char *start = e->p;
    if (isalpha((unsigned char)*e->p) || *e->p == '_') {
        char name[256];
        int length = 0;
        while ((isalnum((unsigned char)*e->p) || *e->p == '_') && length < 255)
            name[length++] = *e->p++;
        name[length] = '\0';
        skip(e);
        char op = 0;
        if (e->p[0] == '=' && e->p[1] != '=') {
            op = '=';
            e->p++;
        } else if (strchr("+-*/%&|^", e->p[0]) && e->p[0] && e->p[1] == '=') {
            op = e->p[0];
            e->p += 2;
        }
        if (op) {
            long right = parse_assignment(e), value = variable_value(name);
            switch (op) {
            case '=': value = right; break;
            case '+': value += right; break;
            case '-': value -= right; break;
            case '*': value *= right; break;
            case '&': value &= right; break;
            case '|': value |= right; break;
            case '^': value ^= right; break;
            case '/':
            case '%':
                if (right == 0) {
                    e->error = 2;
                    return 0;
                }
                value = op == '/' ? value / right : value % right;
                break;
            default: break;
            }
            set_number(name, value);
            return value;
        }
        e->p = start;
    }
    return parse_binary(e, 0);
}

static int set_arithmetic(char *text)
{
    struct expression e = {text, 0};
    strip_quotes(text);
    long value = 0;
    do {
        if (*e.p == ',')
            e.p++;
        value = parse_assignment(&e);
        skip(&e);
    } while (!e.error && *e.p == ',');
    if (e.error == 2) {
        errf("Division by zero.\n");
        return 1;
    }
    if (e.error || *e.p) {
        errf("Missing operand or operator in the expression.\n");
        return 1;
    }
    if (!current_batch)
        outf("%ld\n", value);  /* At the prompt the result is shown */
    return 0;
}

/* List the variables whose name starts with prefix ("" for all); the number
   of them */
static int list_variables(const char *prefix)
{
    char *block = GetEnvironmentStringsA();
    int count = 0;
    size_t length = strlen(prefix);
    if (!block)
        return 0;
    for (char *p = block; *p; p += strlen(p) + 1) {
        if (*p == '=')
            continue;  /* The hidden "=C:" folders of the drives */
        if (_strnicmp(p, prefix, length) == 0) {
            outf("%s\n", p);
            count++;
        }
    }
    FreeEnvironmentStringsA(block);
    return count;
}

int cmd_set(char *args)
{
    char text[LINE_SIZE];
    snprintf(text, sizeof(text), "%s", skip_spaces(args));
    trim_right(text);
    if (!text[0]) {
        list_variables("");
        return 0;
    }
    if ((text[0] == '/' || text[0] == '-') && toupper((unsigned char)text[1]) == 'A' &&
            (text[2] == ' ' || text[2] == '\t' || text[2] == '"' || !text[2]))
        return set_arithmetic(skip_spaces(text + 2));
    int ask = 0;
    char *p = text;
    if ((p[0] == '/' || p[0] == '-') && toupper((unsigned char)p[1]) == 'P' &&
            (p[2] == ' ' || p[2] == '\t')) {
        ask = 1;
        p = skip_spaces(p + 2);
    }
    /* set "name=value": the quotes only delimit */
    if (*p == '"') {
        p++;
        char *close = strrchr(p, '"');
        if (close)
            *close = '\0';
    }
    char *equals = strchr(p, '=');
    if (!equals) {
        if (ask) {
            errf("The syntax of the command is incorrect.\n");
            return 1;
        }
        if (list_variables(p) == 0) {
            errf("Environment variable %s not defined\n", p);
            return 1;
        }
        return 0;
    }
    if (equals == p) {
        errf("The syntax of the command is incorrect.\n");
        return 1;
    }
    *equals = '\0';
    char *value = equals + 1;
    if (ask) {
        char line[LINE_SIZE];
        out(value);
        if (read_line(in_h, line, sizeof(line)) <= 0)
            return 1;
        SetEnvironmentVariableA(p, line);
        return 0;
    }
    SetEnvironmentVariableA(p, *value ? value : NULL);
    return 0;
}

int cmd_path(char *args)
{
    char value[LINE_SIZE];
    char *p = skip_spaces(args);
    if (*p == '=')
        p = skip_spaces(p + 1);
    snprintf(value, sizeof(value), "%s", p);
    trim_right(value);
    if (!value[0]) {
        char path[LINE_SIZE];
        if (GetEnvironmentVariableA("PATH", path, sizeof(path)))
            outf("PATH=%s\n", path);
        else
            out("No Path\n");
        return 0;
    }
    SetEnvironmentVariableA("PATH", strcmp(value, ";") == 0 ? NULL : value);
    return 0;
}

int cmd_prompt(char *args)
{
    char value[LINE_SIZE];
    char *p = skip_spaces(args);
    if (*p == '=')
        p = skip_spaces(p + 1);
    snprintf(value, sizeof(value), "%s", p);
    SetEnvironmentVariableA("PROMPT", value[0] ? value : NULL);
    return 0;
}

int cmd_title(char *args)
{
    char title[LINE_SIZE];
    snprintf(title, sizeof(title), "%s", skip_spaces(args));
    trim_right(title);
    SetConsoleTitleA(title);
    return 0;
}

/* ==================== VER, DATE, TIME ==================== */

static void windows_version(char *text, int size)
{
    OSVERSIONINFOA version;
    memset(&version, 0, sizeof(version));
    version.dwOSVersionInfoSize = sizeof(version);
    GetVersionExA(&version);
    snprintf(text, size, "%lu.%lu.%lu", (unsigned long)version.dwMajorVersion,
             (unsigned long)version.dwMinorVersion,
             (unsigned long)(version.dwBuildNumber & 0xFFFF));
}

void print_banner(void)
{
    char version[64];
    windows_version(version, sizeof(version));
    outf("winexe32emu Command Prompt [Windows Version %s]\n"
         "Type HELP for the list of commands.\n\n", version);
}

int cmd_ver(char *args)
{
    char version[64];
    windows_version(version, sizeof(version));
    outf("\nWindows [Version %s] - winexe32emu Command Prompt\n", version);
    return 0;
}

static const char *const day_names[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};

int cmd_date(char *args)
{
    SYSTEMTIME t;
    char *p = skip_spaces(args);
    GetLocalTime(&t);
    if (is_option(p, "T")) {
        outf("%s %02d/%02d/%04d\n", day_names[t.wDayOfWeek % 7], t.wMonth, t.wDay, t.wYear);
        return 0;
    }
    if (*p) {
        errf("The date of the emulated computer cannot be changed.\n");
        return 1;
    }
    outf("The current date is: %s %02d/%02d/%04d\n", day_names[t.wDayOfWeek % 7], t.wMonth,
         t.wDay, t.wYear);
    return 0;
}

int cmd_time(char *args)
{
    SYSTEMTIME t;
    char *p = skip_spaces(args);
    GetLocalTime(&t);
    if (is_option(p, "T")) {
        int hour = t.wHour % 12;
        outf("%02d:%02d %s\n", hour ? hour : 12, t.wMinute, t.wHour < 12 ? "AM" : "PM");
        return 0;
    }
    if (*p) {
        errf("The time of the emulated computer cannot be changed.\n");
        return 1;
    }
    outf("The current time is: %2d:%02d:%02d.%02d\n", t.wHour, t.wMinute, t.wSecond,
         t.wMilliseconds / 10);
    return 0;
}

/* ==================== CLS ==================== */

int cmd_cls(char *args)
{
    CONSOLE_SCREEN_BUFFER_INFO info;
    COORD origin = {0, 0};
    DWORD written;
    if (!GetConsoleScreenBufferInfo(out_h, &info)) {
        /* Not a console (redirected): a form feed, like cmd writes */
        out("\f");
        return 0;
    }
    DWORD cells = (DWORD)info.dwSize.X * (DWORD)info.dwSize.Y;
    FillConsoleOutputCharacterA(out_h, ' ', cells, origin, &written);
    FillConsoleOutputAttribute(out_h, info.wAttributes, cells, origin, &written);
    SetConsoleCursorPosition(out_h, origin);
    screen_cleared = 1;
    return 0;
}

/* ==================== EXIT, START ==================== */

int cmd_exit(char *args)
{
    char token[64];
    char *p = args;
    int batch_only = 0, code = errorlevel;
    while (next_token(&p, token, sizeof(token))) {
        if (is_option(token, "B"))
            batch_only = 1;
        else
            code = atoi(token);
    }
    if (batch_only && current_batch) {
        errorlevel = code;
        stop_batch(current_batch);
        abort_line = 1;
        return code;
    }
    ExitProcess((UINT)code);
    return code;
}

int cmd_start(char *args)
{
    char title[256] = "", dir[PATH_SIZE] = "", token[PATH_SIZE];
    int wait = 0, shared = 0;
    WORD show = SW_SHOWNORMAL;
    char *p = skip_spaces(args);
    if (*p == '"') {
        /* The first quoted argument is the window title */
        char *close = strchr(p + 1, '"');
        if (close) {
            snprintf(title, sizeof(title), "%.*s", (int)(close - p - 1), p + 1);
            p = close + 1;
        }
    }
    for (;;) {
        p = skip_spaces(p);
        if (*p != '/')
            break;
        char *option = p;
        next_token(&p, token, sizeof(token));
        if (_strnicmp(token, "/D", 2) == 0) {
            if (token[2])
                snprintf(dir, sizeof(dir), "%s", token + 2);
            else
                next_token(&p, dir, sizeof(dir));
        } else if (is_option(token, "WAIT")) {
            wait = 1;
        } else if (is_option(token, "B")) {
            shared = 1;
        } else if (is_option(token, "MIN")) {
            show = SW_SHOWMINNOACTIVE;
        } else if (is_option(token, "MAX")) {
            show = SW_SHOWMAXIMIZED;
        } else if (!is_option(token, "I") && !is_option(token, "NORMAL") &&
                   !is_option(token, "LOW") && !is_option(token, "HIGH") &&
                   !is_option(token, "REALTIME") && !is_option(token, "ABOVENORMAL") &&
                   !is_option(token, "BELOWNORMAL") && !is_option(token, "SEPARATE") &&
                   !is_option(token, "SHARED")) {
            p = option;  /* Not ours: it belongs to the command */
            break;
        }
    }

    char command[LINE_SIZE], name[PATH_SIZE], path[PATH_SIZE], comspec[PATH_SIZE];
    if (!GetEnvironmentVariableA("COMSPEC", comspec, sizeof(comspec)))
        GetModuleFileNameA(NULL, comspec, sizeof(comspec));
    snprintf(command, sizeof(command), "%s", skip_spaces(p));
    trim_right(command);
    if (!command[0])
        snprintf(command, sizeof(command), "\"%s\"", comspec);
    char *rest = command;
    next_token(&rest, name, sizeof(name));
    int kind = find_program(name, path, sizeof(path));
    if (kind == 0) {
        /* A folder, a document or anything else the shell opens */
        char parameters[LINE_SIZE];
        snprintf(parameters, sizeof(parameters), "%s", skip_spaces(rest));
        if ((INT_PTR)ShellExecuteA(NULL, "open", name, parameters[0] ? parameters : NULL,
                                   dir[0] ? dir : NULL, show) > 32)
            return 0;
        errf("The system cannot find the file %s.\n", name);
        return 1;
    }
    char cmdline[LINE_SIZE];
    const char *program = path;
    if (kind == 2) {
        snprintf(cmdline, sizeof(cmdline), "\"%s\" /K \"%s\"%s", comspec, path, rest);
        program = comspec;
    } else {
        snprintf(cmdline, sizeof(cmdline), "%s", command);
    }
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = show;
    si.lpTitle = title[0] ? title : NULL;
    if (!CreateProcessA(program, cmdline, NULL, NULL, FALSE, shared ? 0 : CREATE_NEW_CONSOLE,
                        NULL, dir[0] ? dir : NULL, &si, &pi)) {
        print_error(GetLastError());
        return 1;
    }
    DWORD code = 0;
    if (wait) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        GetExitCodeProcess(pi.hProcess, &code);
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return (int)code;
}

/* ==================== SETLOCAL, ENDLOCAL ==================== */

#define LOCAL_DEPTH 32
static char *saved_environments[LOCAL_DEPTH];
static int local_depth;

/* A copy of the environment block (NAME=value strings, an empty one at the end) */
static char *copy_environment(void)
{
    char *block = GetEnvironmentStringsA();
    if (!block)
        return NULL;
    size_t size = 0;
    while (block[size] || block[size + 1])
        size++;
    size += 2;
    char *copy = malloc(size);
    if (copy)
        memcpy(copy, block, size);
    FreeEnvironmentStringsA(block);
    return copy;
}

static void restore_environment(const char *saved)
{
    char name[LINE_SIZE];
    char *current = copy_environment();
    if (current) {
        /* Remove the variables made since (the drive folders stay) */
        for (char *p = current; *p; p += strlen(p) + 1) {
            char *equals = strchr(p + 1, '=');
            if (*p == '=' || !equals)
                continue;
            snprintf(name, sizeof(name), "%.*s", (int)(equals - p), p);
            SetEnvironmentVariableA(name, NULL);
        }
        free(current);
    }
    for (const char *p = saved; *p; p += strlen(p) + 1) {
        const char *equals = strchr(p + 1, '=');
        if (*p == '=' || !equals)
            continue;
        snprintf(name, sizeof(name), "%.*s", (int)(equals - p), p);
        SetEnvironmentVariableA(name, equals + 1);
    }
}

int cmd_setlocal(char *args)
{
    if (local_depth >= LOCAL_DEPTH) {
        errf("Too many SETLOCAL levels.\n");
        return 1;
    }
    saved_environments[local_depth++] = copy_environment();
    return 0;
}

int cmd_endlocal(char *args)
{
    if (local_depth == 0)
        return 0;
    char *saved = saved_environments[--local_depth];
    if (saved) {
        restore_environment(saved);
        free(saved);
    }
    return 0;
}

int local_level(void)
{
    return local_depth;
}

void end_local_to(int level)
{
    while (local_depth > level)
        cmd_endlocal(NULL);
}
