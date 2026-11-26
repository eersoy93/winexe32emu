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

/* Notepad resource and command IDs */

#ifndef NOTEPAD_RESOURCE_H
#define NOTEPAD_RESOURCE_H

#define IDI_NOTEPAD  1
#define IDA_NOTEPAD  100
#define IDD_ENCODING 101
#define IDD_GOTO     102
#define IDD_ABOUT    103

/* File menu */
#define IDM_NEW          200
#define IDM_OPEN         201
#define IDM_OPEN_AS      202
#define IDM_REOPEN_AS    203
#define IDM_SAVE         204
#define IDM_SAVE_AS      205
#define IDM_EXIT         206

/* Edit menu */
#define IDM_UNDO         210
#define IDM_CUT          211
#define IDM_COPY         212
#define IDM_PASTE        213
#define IDM_DELETE       214
#define IDM_FIND         215
#define IDM_FIND_NEXT    216
#define IDM_REPLACE      217
#define IDM_GOTO         218
#define IDM_SELECT_ALL   219
#define IDM_TIME_DATE    220

/* Format and View menus */
#define IDM_WORD_WRAP    230
#define IDM_EOL_CRLF     231
#define IDM_EOL_LF       232
#define IDM_EOL_CR       233
#define IDM_ENCODING     234
#define IDM_STATUS_BAR   235

/* Help menu */
#define IDM_ABOUT        240

/* Controls */
#define IDC_EDIT          300
#define IDC_STATUS        301
#define IDC_ENCODING      310
#define IDC_EOL           311
#define IDC_EOL_LABEL     312
#define IDC_ENCODING_NOTE 313
#define IDC_LINE          320
#define IDC_ABOUT_TEXT    330

#endif
