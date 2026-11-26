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
Notepad's text codec: detects and converts the encoding and the line breaks
of a text file. Kept apart from the user interface so that a console test
program (tests/notepad_codec_test.c) can check it in the emulator.

The text in memory is UTF-16 with CR LF line breaks (what an EDIT control
wants); a file is bytes in one of the encodings below with CR LF, LF or CR
line breaks.
*/

#ifndef NOTEPAD_TEXTCODEC_H
#define NOTEPAD_TEXTCODEC_H

#include <windows.h>
#include <stddef.h>

/* Encodings that are not Windows code pages of MultiByteToWideChar: the
   numbers .NET uses for them (a Windows code page is never one of these) */
#define TC_ANSI    0      /* CP_ACP: the system's ANSI code page */
#define TC_UTF16LE 1200
#define TC_UTF16BE 1201
#define TC_UTF8    65001

typedef struct {
    UINT codepage;  /* TC_ANSI, TC_UTF8, TC_UTF16LE, TC_UTF16BE or a code page */
    BOOL bom;       /* With a byte order mark (UTF-8 and UTF-16 only) */
} TextEncoding;

/* Line break types */
#define TC_EOL_CRLF 0  /* Windows */
#define TC_EOL_LF   1  /* Unix */
#define TC_EOL_CR   2  /* Classic Mac OS */

/* A file read into memory */
typedef struct {
    WCHAR *text;           /* CR LF line breaks, NUL-terminated (malloc) */
    size_t length;         /* Characters, without the terminating NUL */
    TextEncoding encoding;
    int eol;               /* The most common line break of the file */
    BOOL mixed_eol;        /* The file has more than one kind of line break */
    BOOL invalid;          /* Bytes that are not valid in the encoding */
} TextDocument;

/* An encoding Notepad offers (tc_encodings) */
typedef struct {
    UINT codepage;
    BOOL bom;
    const WCHAR *name;
} TextEncodingInfo;

/* The encodings in the order Notepad lists them; the code pages the system
   does not support (IsValidCodePage) are skipped by the caller */
extern const TextEncodingInfo tc_encodings[];
extern const int tc_encoding_count;

/* Is data valid UTF-8? *non_ascii (may be NULL) tells whether it has any
   byte above 0x7F */
BOOL tc_is_utf8(const unsigned char *data, size_t size, BOOL *non_ascii);

/* UTF-16 without a byte order mark: TC_UTF16LE or TC_UTF16BE if the zero
   bytes look like the high bytes of Latin text, else 0 */
UINT tc_guess_utf16(const unsigned char *data, size_t size);

/* The encoding of a file: its byte order mark, UTF-16 by its zero bytes,
   valid UTF-8 (also plain ASCII), else the ANSI code page */
TextEncoding tc_detect(const unsigned char *data, size_t size);

/* Bytes of the byte order mark of enc at the start of data (0: none) */
size_t tc_bom_size(const unsigned char *data, size_t size, const TextEncoding *enc);

/* data (without its byte order mark) as UTF-16 (malloc, NUL-terminated);
   *invalid: bytes the encoding has no character for were replaced */
WCHAR *tc_decode(const unsigned char *data, size_t size, UINT codepage, size_t *length,
                 BOOL *invalid);

/* text in an encoding, with its byte order mark (malloc); *lossy:
   characters the encoding cannot represent were replaced */
unsigned char *tc_encode(const WCHAR *text, size_t length, const TextEncoding *enc,
                         size_t *size, BOOL *lossy);

/* Counts the CR LF, LF and CR line breaks of text into counts[3]; returns
   the most common one (TC_EOL_CRLF if there are none or on a tie) */
int tc_count_eol(const WCHAR *text, size_t length, size_t counts[3]);

/* text with every line break (CR LF, LF, CR) turned into eol (malloc) */
WCHAR *tc_convert_eol(const WCHAR *text, size_t length, int eol, size_t *out_length);

/* Reads a file's bytes: forced (NULL: detect) is its encoding; NUL
   characters become spaces (an EDIT control's text ends at a NUL) */
BOOL tc_load(const unsigned char *data, size_t size, const TextEncoding *forced,
             TextDocument *doc);

/* The bytes to save text (any line breaks) as, in enc with eol line breaks */
unsigned char *tc_save(const WCHAR *text, size_t length, const TextEncoding *enc, int eol,
                       size_t *size, BOOL *lossy);

/* Display name of an encoding ("UTF-8 with BOM", "Windows-1254 (ANSI)") */
void tc_encoding_name(const TextEncoding *enc, WCHAR *buffer, int size);

/* Display name of a line break type ("Windows (CRLF)") */
const WCHAR *tc_eol_name(int eol);

#endif
