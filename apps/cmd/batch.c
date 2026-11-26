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

/* Batch files (.BAT, .CMD) of the Command Prompt and the commands made for
   them: GOTO, CALL, IF, FOR and SHIFT. A batch file is read whole, then run
   line by line; a line with an open parenthesis goes on in the next lines. */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cmd.h"

#define MAX_BATCH_ARGS 64
#define MAX_BATCH_DEPTH 32

struct batch_file {
    char path[PATH_SIZE];
    char *data;              /* The file's text, cut into lines */
    char **lines;
    int count, pos;
    char *args[MAX_BATCH_ARGS];  /* %0 (the name as typed), %1... with their quotes */
    int arg_count, shift;
    char all_args[LINE_SIZE];    /* %* */
    int stopped;
    int local_level;             /* SETLOCAL levels to undo at the end */
    struct batch_file *parent;
};

struct batch_file *current_batch;
static int batch_depth;

void stop_batch(struct batch_file *batch)
{
    if (batch)
        batch->stopped = 1;
}

/* ==================== ARGUMENTS ==================== */

static void split_arguments(struct batch_file *b, const char *name, const char *args)
{
    char token[LINE_SIZE];
    b->args[0] = _strdup(name);
    b->arg_count = 1;
    snprintf(b->all_args, sizeof(b->all_args), "%s", skip_spaces(args));
    trim_right(b->all_args);
    /* Like cmd: separated by spaces, commas, semicolons and equals signs;
       the quotes stay part of the argument */
    const char *p = args;
    while (b->arg_count < MAX_BATCH_ARGS) {
        while (*p && strchr(" \t,;=", *p))
            p++;
        if (!*p)
            break;
        int length = 0, quoted = 0;
        while (*p && (quoted || !strchr(" \t,;=", *p))) {
            if (*p == '"')
                quoted = !quoted;
            if (length < (int)sizeof(token) - 1)
                token[length++] = *p;
            p++;
        }
        token[length] = '\0';
        b->args[b->arg_count++] = _strdup(token);
    }
}

int batch_argument(int index, char *value, int size)
{
    value[0] = '\0';
    if (!current_batch)
        return 0;
    int i = index + current_batch->shift;
    if (index == 0 && current_batch->shift == 0)
        i = 0;
    if (i >= current_batch->arg_count || !current_batch->args[i])
        return 0;
    snprintf(value, size, "%s", current_batch->args[i]);
    return 1;
}

int batch_all_arguments(char *value, int size)
{
    if (!current_batch)
        return 0;
    snprintf(value, size, "%s", current_batch->all_args);
    return 1;
}

int cmd_shift(char *args)
{
    if (current_batch && current_batch->shift < current_batch->arg_count)
        current_batch->shift++;
    return 0;
}

/* %~f %~d %~p %~n %~x %~z of a value (a file name): its full path, drive,
   folder, name, extension or size; no modifier just removes the quotes */
int apply_modifiers(const char *mods, const char *value, char *result, int size)
{
    char plain[PATH_SIZE], full[PATH_SIZE];
    snprintf(plain, sizeof(plain), "%s", value);
    strip_quotes(plain);
    if (!*mods) {
        snprintf(result, size, "%s", plain);
        return 1;
    }
    if (!plain[0]) {
        result[0] = '\0';
        return 1;
    }
    full_path(plain, full, sizeof(full));
    int used = 0;
    result[0] = '\0';
    if (strchr(mods, 'z')) {
        WIN32_FILE_ATTRIBUTE_DATA data;
        if (GetFileAttributesExA(full, GetFileExInfoStandard, &data))
            used += snprintf(result + used, size - used, "%lu",
                             (unsigned long)data.nFileSizeLow);
        if (!strpbrk(mods, "fdpnx"))
            return 1;
    }
    if (strchr(mods, 'f') && !strpbrk(mods, "dpnx")) {
        snprintf(result + used, size - used, "%s", full);
        return 1;
    }
    const char *slash = strrchr(full, '\\');
    const char *name = slash ? slash + 1 : full;
    const char *dot = strrchr(name, '.');
    if (!dot)
        dot = name + strlen(name);
    if (strchr(mods, 'd') && used < size)
        used += snprintf(result + used, size - used, "%.2s", full);
    if (strchr(mods, 'p') && used < size)
        used += snprintf(result + used, size - used, "%.*s", (int)(name - full - 2), full + 2);
    if (strchr(mods, 'n') && used < size)
        used += snprintf(result + used, size - used, "%.*s", (int)(dot - name), name);
    if (strchr(mods, 'x') && used < size)
        snprintf(result + used, size - used, "%s", dot);
    return 1;
}

/* ==================== RUNNING A BATCH FILE ==================== */

static int load_batch(struct batch_file *b, const char *path)
{
    HANDLE file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                              OPEN_EXISTING, 0, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return 0;
    DWORD size = GetFileSize(file, NULL), count = 0;
    if (size == INVALID_FILE_SIZE)
        size = 0;
    b->data = malloc(size + 1);
    if (!b->data || (size && (!ReadFile(file, b->data, size, &count, NULL)))) {
        CloseHandle(file);
        return 0;
    }
    CloseHandle(file);
    b->data[count] = '\0';
    int capacity = 1;
    for (DWORD i = 0; i < count; i++)
        capacity += b->data[i] == '\n';
    b->lines = malloc(capacity * sizeof(char *));
    if (!b->lines)
        return 0;
    b->count = 0;
    char *line = b->data;
    for (;;) {
        char *end = strchr(line, '\n');
        if (end)
            *end = '\0';
        size_t length = strlen(line);
        if (length && line[length - 1] == '\r')
            line[length - 1] = '\0';
        /* Ctrl+Z ends the text, like in MS-DOS batch files */
        char *eof = strchr(line, 0x1A);
        if (eof)
            *eof = '\0';
        b->lines[b->count++] = line;
        if (!end || eof)
            break;
        line = end + 1;
    }
    return 1;
}

/* The line after :label, or -1 */
static int find_label(struct batch_file *b, const char *label)
{
    size_t length = strlen(label);
    for (int i = 0; i < b->count; i++) {
        char *p = skip_spaces(b->lines[i]);
        if (*p != ':')
            continue;
        p++;
        if (_strnicmp(p, label, length) == 0 &&
                (p[length] == '\0' || strchr(" \t:+=,;", p[length])))
            return i + 1;
    }
    return -1;
}

int run_batch(const char *path, const char *name, const char *args, const char *label)
{
    struct batch_file *b;
    int saved_echo = echo_on;
    if (batch_depth >= MAX_BATCH_DEPTH) {
        errf("The batch files call each other too deeply.\n");
        return 1;
    }
    b = calloc(1, sizeof(*b));
    if (!b)
        return 1;
    snprintf(b->path, sizeof(b->path), "%s", path);
    if (!load_batch(b, path)) {
        print_error(GetLastError() ? GetLastError() : ERROR_FILE_NOT_FOUND);
        free(b->data);
        free(b);
        return 1;
    }
    split_arguments(b, name, args);
    if (label) {
        b->pos = find_label(b, label);
        if (b->pos < 0) {
            errf("The batch label %s cannot be found.\n", label);
            b->stopped = 1;
        }
    }
    b->parent = current_batch;
    b->local_level = local_level();
    current_batch = b;
    batch_depth++;

    char *line = malloc(LINE_SIZE), *expanded = malloc(LINE_SIZE);
    while (line && expanded && !b->stopped && b->pos < b->count) {
        snprintf(line, LINE_SIZE, "%s", b->lines[b->pos++]);
        /* A block goes on until its parentheses close */
        while (count_open_parens(line) > 0 && b->pos < b->count) {
            size_t used = strlen(line);
            snprintf(line + used, LINE_SIZE - used, " & %s", b->lines[b->pos++]);
        }
        expand_variables(line, expanded, LINE_SIZE, 1);
        char *p = skip_spaces(expanded);
        if (*p == ':' || !*p)
            continue;  /* A label (or a :: comment) */
        if (echo_on && *p != '@') {
            out("\n");
            print_prompt();
            outf("%s\n", p);
        }
        run_line(p);
        abort_line = 0;
    }
    free(line);
    free(expanded);

    end_local_to(b->local_level);
    current_batch = b->parent;
    batch_depth--;
    if (!b->parent)
        echo_on = saved_echo;  /* The prompt comes back after @echo off */
    for (int i = 0; i < b->arg_count; i++)
        free(b->args[i]);
    free(b->lines);
    free(b->data);
    free(b);
    return errorlevel;
}

/* ==================== GOTO, CALL ==================== */

int cmd_goto(char *args)
{
    char label[PATH_SIZE];
    char *p = args;
    if (!next_token(&p, label, sizeof(label))) {
        errf("No batch label specified to GOTO command.\n");
        return 1;
    }
    if (!current_batch)
        return 0;
    const char *name = label[0] == ':' ? label + 1 : label;
    abort_line = 1;
    if (_stricmp(name, "EOF") == 0) {
        current_batch->stopped = 1;
        return 0;
    }
    int pos = find_label(current_batch, name);
    if (pos < 0) {
        errf("The batch label %s cannot be found.\n", name);
        current_batch->stopped = 1;
        return 1;
    }
    current_batch->pos = pos;
    return 0;
}

int cmd_call(char *args)
{
    char *p = skip_spaces(args);
    if (*p == ':') {
        char label[PATH_SIZE];
        char *rest = p;
        next_token(&rest, label, sizeof(label));
        if (!current_batch) {
            errf("CALL :label works only in a batch file.\n");
            return 1;
        }
        return run_batch(current_batch->path, label, rest, label + 1);
    }
    if (!*p)
        return 0;
    calling_batch = 1;
    int status = run_line(p);
    calling_batch = 0;
    return status;
}

/* ==================== IF ==================== */

/* An IF operand: up to a space or "==" outside quotes, the quotes kept */
static void read_operand(char **cursor, char *operand, int size)
{
    char *p = skip_spaces(*cursor);
    int length = 0, quoted = 0;
    while (*p && (quoted || (*p != ' ' && *p != '\t' && !(p[0] == '=' && p[1] == '=')))) {
        if (*p == '"')
            quoted = !quoted;
        if (length < size - 1)
            operand[length++] = *p;
        p++;
    }
    operand[length] = '\0';
    *cursor = p;
}

static int is_number(const char *text, long *value)
{
    char *end;
    if (!*text)
        return 0;
    *value = strtol(text, &end, 0);
    return *end == '\0';
}

static int starts_word(const char *p, const char *word)
{
    size_t length = strlen(word);
    return _strnicmp(p, word, length) == 0 && (p[length] == ' ' || p[length] == '\t');
}

int cmd_if(char *args)
{
    char *p = skip_spaces(args);
    int negate = 0, ignore_case = 0, result;
    char left[LINE_SIZE], right[LINE_SIZE];
    if (starts_word(p, "/I")) {
        ignore_case = 1;
        p = skip_spaces(p + 2);
    }
    if (starts_word(p, "NOT")) {
        negate = 1;
        p = skip_spaces(p + 3);
    }
    if (starts_word(p, "EXIST")) {
        p += 5;
        next_token(&p, left, sizeof(left));
        WIN32_FIND_DATAA data;
        HANDLE find = FindFirstFileA(left, &data);
        /* A wildcard matches, or the name is a file or folder (C:\ too) */
        result = find != INVALID_HANDLE_VALUE ||
                 GetFileAttributesA(left) != INVALID_FILE_ATTRIBUTES;
        if (find != INVALID_HANDLE_VALUE)
            FindClose(find);
    } else if (starts_word(p, "ERRORLEVEL")) {
        p += 10;
        next_token(&p, left, sizeof(left));
        result = errorlevel >= atoi(left);
    } else if (starts_word(p, "DEFINED")) {
        p += 7;
        next_token(&p, left, sizeof(left));
        result = GetEnvironmentVariableA(left, right, sizeof(right)) > 0;
    } else if (starts_word(p, "CMDEXTVERSION")) {
        p += 13;
        next_token(&p, left, sizeof(left));
        result = 2 >= atoi(left);
    } else {
        read_operand(&p, left, sizeof(left));
        p = skip_spaces(p);
        char op[8] = "==";
        if (p[0] == '=' && p[1] == '=') {
            p += 2;
            while (*p == '=')
                p++;
        } else {
            int length = 0;
            while (isalpha((unsigned char)*p) && length < 7)
                op[length++] = (char)toupper((unsigned char)*p++);
            op[length] = '\0';
        }
        read_operand(&p, right, sizeof(right));
        if (!left[0] || !right[0]) {
            errf("The syntax of the command is incorrect.\n");
            return 1;
        }
        long a, b;
        int compare;
        if (strcmp(op, "==") != 0 && is_number(left, &a) && is_number(right, &b))
            compare = a < b ? -1 : a > b;
        else
            compare = ignore_case ? _stricmp(left, right) : strcmp(left, right);
        if (strcmp(op, "==") == 0 || strcmp(op, "EQU") == 0)
            result = compare == 0;
        else if (strcmp(op, "NEQ") == 0)
            result = compare != 0;
        else if (strcmp(op, "LSS") == 0)
            result = compare < 0;
        else if (strcmp(op, "LEQ") == 0)
            result = compare <= 0;
        else if (strcmp(op, "GTR") == 0)
            result = compare > 0;
        else if (strcmp(op, "GEQ") == 0)
            result = compare >= 0;
        else {
            errf("%s was unexpected at this time.\n", op);
            return 1;
        }
    }
    if (negate)
        result = !result;

    /* The command, and after a ( block ) maybe ELSE and another one */
    char *command = skip_spaces(p), *otherwise = NULL;
    if (!*command) {
        errf("The syntax of the command is incorrect.\n");
        return 1;
    }
    if (*command == '(') {
        int close = matching_paren(command, 0);
        if (close >= 0) {
            char *after = skip_spaces(command + close + 1);
            if (_strnicmp(after, "else", 4) == 0 &&
                    (after[4] == ' ' || after[4] == '\t' || after[4] == '(')) {
                otherwise = skip_spaces(after + 4);
                command[close + 1] = '\0';
            }
        }
    }
    if (result)
        return run_line(command);
    return otherwise ? run_line(otherwise) : 0;
}

/* ==================== FOR ==================== */

/* body with %v (and %~mods v) replaced by value */
static void substitute(const char *body, char var, const char *value, char *result, int size)
{
    int used = 0;
    for (const char *p = body; *p && used < size - 1;) {
        if (p[0] == '%' && p[1] == var) {
            used += snprintf(result + used, size - used, "%s", value);
            p += 2;
            continue;
        }
        if (p[0] == '%' && p[1] == '~') {
            /* The longest run of modifier letters that ends with the variable */
            int run = 0;
            while (isalpha((unsigned char)p[2 + run]))
                run++;
            int matched = 0;
            for (int k = run; k >= 1 && !matched; k--) {
                if (p[2 + k - 1] != var)
                    continue;
                char mods[32];
                int m = 0, ok = 1;
                for (int i = 0; i < k - 1; i++) {
                    char c = (char)tolower((unsigned char)p[2 + i]);
                    if (!strchr("fdpnxsatz", c) || m >= 31)
                        ok = 0;
                    else
                        mods[m++] = c;
                }
                mods[m] = '\0';
                if (!ok)
                    continue;
                char piece[PATH_SIZE];
                apply_modifiers(mods, value, piece, sizeof(piece));
                used += snprintf(result + used, size - used, "%s", piece);
                p += 2 + k;
                matched = 1;
            }
            if (matched)
                continue;
        }
        result[used++] = *p++;
    }
    if (used >= size)
        used = size - 1;
    result[used] = '\0';
}

static int run_body(const char *body, char var, const char *value)
{
    char *command = malloc(LINE_SIZE);
    int status = 0;
    if (!command)
        return 1;
    substitute(body, var, value, command, LINE_SIZE);
    if (echo_on && !current_batch) {
        /* Each run is shown at the prompt, like in cmd */
        out("\n");
        print_prompt();
        outf("%s\n", skip_spaces(command));
    }
    status = run_line(command);
    free(command);
    return status;
}

/* Run the body for the files (or folders) matching a wildcard item */
static int for_matches(const char *pattern, int dirs, const char *body, char var)
{
    WIN32_FIND_DATAA data;
    char folder[PATH_SIZE], path[PATH_SIZE];
    int status = 0;
    const char *slash = strrchr(pattern, '\\');
    const char *colon = strchr(pattern, ':');
    const char *end = slash ? slash + 1 : colon ? colon + 1 : pattern;
    snprintf(folder, sizeof(folder), "%.*s", (int)(end - pattern), pattern);
    HANDLE find = FindFirstFileA(pattern, &data);
    if (find == INVALID_HANDLE_VALUE)
        return 0;
    do {
        int is_dir = (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        if (is_dir != dirs || strcmp(data.cFileName, ".") == 0 ||
                strcmp(data.cFileName, "..") == 0)
            continue;
        snprintf(path, sizeof(path), "%s%s", folder, data.cFileName);
        status = run_body(body, var, path);
    } while (!abort_line && FindNextFileA(find, &data));
    FindClose(find);
    return status;
}

int cmd_for(char *args)
{
    char *p = skip_spaces(args);
    int dirs = 0, numbers = 0, status = 0;
    while (*p == '/') {
        char option = (char)toupper((unsigned char)p[1]);
        if (option == 'D')
            dirs = 1;
        else if (option == 'L')
            numbers = 1;
        else {
            errf("FOR /%c is not supported.\n", p[1]);
            return 1;
        }
        p = skip_spaces(p + 2);
    }
    if (p[0] != '%' || !p[1] || (p[2] != ' ' && p[2] != '\t')) {
        errf("The syntax of the command is incorrect.\n");
        return 1;
    }
    char var = p[1];
    p = skip_spaces(p + 2);
    if (!starts_word(p, "IN") && _strnicmp(p, "IN(", 3) != 0) {
        errf("The syntax of the command is incorrect.\n");
        return 1;
    }
    p = skip_spaces(p + 2);
    int close = *p == '(' ? matching_paren(p, 0) : -1;
    if (close < 0) {
        errf("The syntax of the command is incorrect.\n");
        return 1;
    }
    char set[LINE_SIZE];
    snprintf(set, sizeof(set), "%.*s", close - 1, p + 1);
    p = skip_spaces(p + close + 1);
    if (!starts_word(p, "DO")) {
        errf("The syntax of the command is incorrect.\n");
        return 1;
    }
    const char *body = skip_spaces(p + 2);

    if (numbers) {
        long values[3] = {0, 0, 0};
        char *cursor = set;
        for (int i = 0; i < 3; i++) {
            while (*cursor && strchr(" \t,;=", *cursor))
                cursor++;
            values[i] = strtol(cursor, &cursor, 0);
        }
        if (values[1] == 0)
            return 0;
        for (long v = values[0]; !abort_line &&
                (values[1] > 0 ? v <= values[2] : v >= values[2]); v += values[1]) {
            char text[32];
            snprintf(text, sizeof(text), "%ld", v);
            status = run_body(body, var, text);
        }
        return status;
    }

    /* The items of the set: words (quotes kept), wildcards for files */
    char *cursor = set;
    char item[PATH_SIZE];
    while (!abort_line) {
        while (*cursor && strchr(" \t,;=", *cursor))
            cursor++;
        if (!*cursor)
            break;
        int length = 0, quoted = 0;
        while (*cursor && (quoted || !strchr(" \t,;=", *cursor))) {
            if (*cursor == '"')
                quoted = !quoted;
            if (length < (int)sizeof(item) - 1)
                item[length++] = *cursor;
            cursor++;
        }
        item[length] = '\0';
        if (has_wildcard(item)) {
            strip_quotes(item);
            status = for_matches(item, dirs, body, var);
        } else if (!dirs) {
            status = run_body(body, var, item);
        }
    }
    return status;
}
