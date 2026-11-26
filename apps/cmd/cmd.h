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

/* Shared declarations of the Command Prompt (cmd.exe) source files */

#ifndef CMD_H
#define CMD_H

#include <windows.h>
#include <shellapi.h>

#define LINE_SIZE 8192
#define PATH_SIZE 1024

/* ---- cmd.c: output, input, parsing and running commands ---- */

/* Where the running command reads and writes: the console, or the files
   of its redirections (> >> < and the pipe's temporary files) */
extern HANDLE out_h, err_h, in_h;

extern int echo_on;      /* ECHO ON/OFF: prompt and batch lines are shown */
extern int errorlevel;   /* Exit code of the last program (IF ERRORLEVEL, %ERRORLEVEL%) */
/* GOTO, EXIT /B or a batch file run without CALL: skip the rest of the line */
extern int abort_line;
/* Set while CALL runs a command: a batch file it names returns to the caller
   instead of replacing the running one like a plain batch file name does */
extern int calling_batch;
extern int screen_cleared;  /* CLS ran: no empty line before the next prompt */

void out(const char *text);
void outf(const char *format, ...) __attribute__((format(printf, 1, 2)));
void errf(const char *format, ...) __attribute__((format(printf, 1, 2)));
void print_error(DWORD code);
int read_line(HANDLE handle, char *buffer, int size);
int ask_yes_no(const char *question, int allow_all);

char *skip_spaces(const char *text);
int next_token(char **cursor, char *token, int size);
int is_option(const char *token, const char *name);
int has_wildcard(const char *name);
void strip_quotes(char *text);
void trim_right(char *text);

int run_line(const char *line);
int run_external(const char *command, int must_wait);
int find_program(const char *name, char *path, int size);
int run_cmd_command(const char *name, char *args, int *status);
void show_command_help(const char *name);
void print_prompt(void);
void expand_variables(const char *line, char *result, int size, int in_batch);
void remember_current_directory(void);
int matching_paren(const char *text, int start);
int count_open_parens(const char *line);

/* ---- files.c: DIR, CD, drives, MD, RD, COPY, MOVE, DEL, REN, TYPE, VOL ---- */

int cmd_dir(char *args);
int cmd_cd(char *args);
int cmd_drive(char letter);
int cmd_md(char *args);
int cmd_rd(char *args);
int cmd_copy(char *args);
int cmd_move(char *args);
int cmd_del(char *args);
int cmd_ren(char *args);
int cmd_type(char *args);
int cmd_vol(char *args);
int cmd_pushd(char *args);
int cmd_popd(char *args);
void format_number(ULONGLONG value, char *text);
int full_path(const char *name, char *path, int size);

/* ---- builtins.c: the other internal commands ---- */

int cmd_echo(char *args);
int cmd_set(char *args);
int cmd_path(char *args);
int cmd_prompt(char *args);
int cmd_title(char *args);
int cmd_ver(char *args);
int cmd_date(char *args);
int cmd_time(char *args);
int cmd_cls(char *args);
int cmd_help(char *args);
int cmd_exit(char *args);
int cmd_start(char *args);
int cmd_pause(char *args);
int cmd_rem(char *args);
int cmd_setlocal(char *args);
int cmd_endlocal(char *args);
void print_banner(void);
int local_level(void);
void end_local_to(int level);

/* ---- batch.c: batch files and their commands ---- */

struct batch_file;
extern struct batch_file *current_batch;

void stop_batch(struct batch_file *batch);
int run_batch(const char *path, const char *name, const char *args, const char *label);
int batch_argument(int index, char *value, int size);
int batch_all_arguments(char *value, int size);
int cmd_goto(char *args);
int cmd_call(char *args);
int cmd_if(char *args);
int cmd_for(char *args);
int cmd_shift(char *args);
int apply_modifiers(const char *mods, const char *value, char *result, int size);

#endif
