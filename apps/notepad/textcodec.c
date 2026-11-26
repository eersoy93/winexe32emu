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
Notepad's text codec (see textcodec.h). UTF-8 and UTF-16 are converted here
(strictly, so that detection and data loss are exact); the other code pages
go through MultiByteToWideChar / WideCharToMultiByte.
*/

#include "textcodec.h"

#include <stdlib.h>
#include <string.h>

#define REPLACEMENT 0xFFFD

const TextEncodingInfo tc_encodings[] = {
    {TC_ANSI, FALSE, L"ANSI"},
    {TC_UTF8, FALSE, L"UTF-8"},
    {TC_UTF8, TRUE, L"UTF-8 with BOM"},
    {TC_UTF16LE, TRUE, L"UTF-16 LE"},
    {TC_UTF16BE, TRUE, L"UTF-16 BE"},
    {1250, FALSE, L"Central European (Windows-1250)"},
    {1251, FALSE, L"Cyrillic (Windows-1251)"},
    {1252, FALSE, L"Western European (Windows-1252)"},
    {1253, FALSE, L"Greek (Windows-1253)"},
    {1254, FALSE, L"Turkish (Windows-1254)"},
    {1255, FALSE, L"Hebrew (Windows-1255)"},
    {1256, FALSE, L"Arabic (Windows-1256)"},
    {1257, FALSE, L"Baltic (Windows-1257)"},
    {1258, FALSE, L"Vietnamese (Windows-1258)"},
    {874, FALSE, L"Thai (Windows-874)"},
    {437, FALSE, L"OEM United States (437)"},
    {737, FALSE, L"OEM Greek (737)"},
    {775, FALSE, L"OEM Baltic (775)"},
    {850, FALSE, L"OEM Multilingual Latin 1 (850)"},
    {852, FALSE, L"OEM Latin 2 (852)"},
    {855, FALSE, L"OEM Cyrillic (855)"},
    {857, FALSE, L"OEM Turkish (857)"},
    {860, FALSE, L"OEM Portuguese (860)"},
    {861, FALSE, L"OEM Icelandic (861)"},
    {862, FALSE, L"OEM Hebrew (862)"},
    {863, FALSE, L"OEM French Canadian (863)"},
    {865, FALSE, L"OEM Nordic (865)"},
    {866, FALSE, L"OEM Russian (866)"},
    {869, FALSE, L"OEM Modern Greek (869)"},
    {28591, FALSE, L"Western European (ISO-8859-1)"},
    {28592, FALSE, L"Central European (ISO-8859-2)"},
    {28593, FALSE, L"Latin 3 (ISO-8859-3)"},
    {28594, FALSE, L"Baltic (ISO-8859-4)"},
    {28595, FALSE, L"Cyrillic (ISO-8859-5)"},
    {28596, FALSE, L"Arabic (ISO-8859-6)"},
    {28597, FALSE, L"Greek (ISO-8859-7)"},
    {28598, FALSE, L"Hebrew (ISO-8859-8)"},
    {28599, FALSE, L"Turkish (ISO-8859-9)"},
    {28603, FALSE, L"Estonian (ISO-8859-13)"},
    {28605, FALSE, L"Latin 9 (ISO-8859-15)"},
    {20866, FALSE, L"Cyrillic (KOI8-R)"},
    {21866, FALSE, L"Cyrillic (KOI8-U)"},
    {10000, FALSE, L"Western European (Mac)"},
    {20127, FALSE, L"US-ASCII"},
    {932, FALSE, L"Japanese (Shift-JIS)"},
    {51932, FALSE, L"Japanese (EUC)"},
    {936, FALSE, L"Chinese Simplified (GBK)"},
    {54936, FALSE, L"Chinese Simplified (GB18030)"},
    {950, FALSE, L"Chinese Traditional (Big5)"},
    {949, FALSE, L"Korean (949)"},
    {51949, FALSE, L"Korean (EUC)"},
    {65000, FALSE, L"Unicode (UTF-7)"},
};

const int tc_encoding_count = sizeof(tc_encodings) / sizeof(tc_encodings[0]);

/* One UTF-8 sequence at data[0..size): its code point (or -1 if it is not
   a valid, shortest-form sequence) and its length in *used */
static long utf8_sequence(const unsigned char *data, size_t size, size_t *used)
{
    unsigned char first = data[0];
    size_t count, i;
    long point, minimum;

    *used = 1;
    if (first < 0x80)
        return first;
    if (first >= 0xC2 && first <= 0xDF) {
        count = 2;
        point = first & 0x1F;
        minimum = 0x80;
    } else if (first >= 0xE0 && first <= 0xEF) {
        count = 3;
        point = first & 0x0F;
        minimum = 0x800;
    } else if (first >= 0xF0 && first <= 0xF4) {
        count = 4;
        point = first & 0x07;
        minimum = 0x10000;
    } else {
        return -1;  /* A continuation byte, C0/C1 (overlong) or F5..FF */
    }
    if (count > size)
        return -1;
    for (i = 1; i < count; i++) {
        if ((data[i] & 0xC0) != 0x80)
            return -1;
        point = (point << 6) | (data[i] & 0x3F);
    }
    /* Overlong forms, UTF-16 surrogates and code points above U+10FFFF are
       not UTF-8 */
    if (point < minimum || (point >= 0xD800 && point <= 0xDFFF) || point > 0x10FFFF)
        return -1;
    *used = count;
    return point;
}

BOOL tc_is_utf8(const unsigned char *data, size_t size, BOOL *non_ascii)
{
    size_t pos = 0, used;
    BOOL high = FALSE;

    while (pos < size) {
        if (data[pos] < 0x80) {
            pos++;
            continue;
        }
        high = TRUE;
        if (utf8_sequence(data + pos, size - pos, &used) < 0) {
            if (non_ascii)
                *non_ascii = TRUE;
            return FALSE;
        }
        pos += used;
    }
    if (non_ascii)
        *non_ascii = high;
    return TRUE;
}

UINT tc_guess_utf16(const unsigned char *data, size_t size)
{
    size_t pairs = size / 2, i, zero_low = 0, zero_high = 0;

    /* Latin text in UTF-16 has a zero in most high bytes and almost no zero
       low bytes; an odd size cannot be UTF-16 */
    if (pairs == 0 || size % 2)
        return 0;
    for (i = 0; i < pairs; i++) {
        if (data[2 * i] == 0)
            zero_low++;
        if (data[2 * i + 1] == 0)
            zero_high++;
    }
    if (zero_high * 10 >= pairs * 4 && zero_low * 10 <= pairs)
        return TC_UTF16LE;
    if (zero_low * 10 >= pairs * 4 && zero_high * 10 <= pairs)
        return TC_UTF16BE;
    return 0;
}

TextEncoding tc_detect(const unsigned char *data, size_t size)
{
    TextEncoding enc = {TC_ANSI, FALSE};
    UINT utf16;

    if (size >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF) {
        enc.codepage = TC_UTF8;
        enc.bom = TRUE;
    } else if (size >= 2 && data[0] == 0xFF && data[1] == 0xFE) {
        enc.codepage = TC_UTF16LE;
        enc.bom = TRUE;
    } else if (size >= 2 && data[0] == 0xFE && data[1] == 0xFF) {
        enc.codepage = TC_UTF16BE;
        enc.bom = TRUE;
    } else if ((utf16 = tc_guess_utf16(data, size)) != 0) {
        enc.codepage = utf16;
    } else if (tc_is_utf8(data, size, NULL)) {
        /* Also plain ASCII: what is typed into it later is not lost then */
        enc.codepage = TC_UTF8;
    }
    return enc;
}

size_t tc_bom_size(const unsigned char *data, size_t size, const TextEncoding *enc)
{
    if (enc->codepage == TC_UTF8 && size >= 3 && data[0] == 0xEF && data[1] == 0xBB &&
            data[2] == 0xBF)
        return 3;
    if (enc->codepage == TC_UTF16LE && size >= 2 && data[0] == 0xFF && data[1] == 0xFE)
        return 2;
    if (enc->codepage == TC_UTF16BE && size >= 2 && data[0] == 0xFE && data[1] == 0xFF)
        return 2;
    return 0;
}

static UINT windows_codepage(UINT codepage)
{
    return codepage == TC_ANSI ? CP_ACP : codepage;
}

WCHAR *tc_decode(const unsigned char *data, size_t size, UINT codepage, size_t *length,
                 BOOL *invalid)
{
    WCHAR *text;
    size_t count = 0, pos = 0, used;
    long point;

    *invalid = FALSE;
    if (codepage == TC_UTF16LE || codepage == TC_UTF16BE) {
        text = malloc((size / 2 + 2) * sizeof(WCHAR));
        if (!text)
            return NULL;
        for (pos = 0; pos + 1 < size; pos += 2)
            text[count++] = codepage == TC_UTF16LE ? (WCHAR)(data[pos] | (data[pos + 1] << 8))
                                                   : (WCHAR)((data[pos] << 8) | data[pos + 1]);
        if (size % 2) {  /* A last half character */
            text[count++] = REPLACEMENT;
            *invalid = TRUE;
        }
    } else if (codepage == TC_UTF8) {
        /* At most one UTF-16 unit per byte (4 bytes give a surrogate pair) */
        text = malloc((size + 1) * sizeof(WCHAR));
        if (!text)
            return NULL;
        while (pos < size) {
            point = utf8_sequence(data + pos, size - pos, &used);
            pos += used;
            if (point < 0) {
                text[count++] = REPLACEMENT;
                *invalid = TRUE;
            } else if (point >= 0x10000) {
                point -= 0x10000;
                text[count++] = (WCHAR)(0xD800 + (point >> 10));
                text[count++] = (WCHAR)(0xDC00 + (point & 0x3FF));
            } else {
                text[count++] = (WCHAR)point;
            }
        }
    } else {
        UINT cp = windows_codepage(codepage);
        int needed = 0;

        if (size > 0x7FFFFFFF)
            return NULL;
        if (size) {
            /* First strictly, to know whether the bytes are valid; code pages
               that do not take MB_ERR_INVALID_CHARS are converted as they are */
            needed = MultiByteToWideChar(cp, MB_ERR_INVALID_CHARS, (const char *)data,
                                         (int)size, NULL, 0);
            if (needed == 0) {
                if (GetLastError() == ERROR_NO_UNICODE_TRANSLATION)
                    *invalid = TRUE;
                needed = MultiByteToWideChar(cp, 0, (const char *)data, (int)size, NULL, 0);
                if (needed == 0)
                    return NULL;
            }
        }
        text = malloc((needed + 1) * sizeof(WCHAR));
        if (!text)
            return NULL;
        if (needed)
            count = MultiByteToWideChar(cp, 0, (const char *)data, (int)size, text, needed);
    }
    text[count] = 0;
    *length = count;
    return text;
}

/* Code pages whose WideCharToMultiByte takes no flags */
static BOOL flagless_codepage(UINT cp)
{
    return cp == 42 || (cp >= 50220 && cp <= 50229) || cp == 52936 || cp == 54936 ||
           (cp >= 57002 && cp <= 57011) || cp == 65000 || cp == 65001;
}

static unsigned char *encode_codepage(const WCHAR *text, size_t length, UINT codepage,
                                      size_t *size, BOOL *lossy)
{
    UINT cp = windows_codepage(codepage);
    DWORD flags = flagless_codepage(cp) ? 0 : WC_NO_BEST_FIT_CHARS;
    BOOL used_default = FALSE;
    unsigned char *data;
    WCHAR *back;
    BOOL invalid;
    size_t back_length;
    int needed;

    if (length > 0x7FFFFFFF)
        return NULL;
    if (length == 0) {
        *size = 0;
        return malloc(1);
    }
    needed = WideCharToMultiByte(cp, flags, text, (int)length, NULL, 0, NULL, NULL);
    if (needed <= 0)
        return NULL;
    data = malloc(needed);
    if (!data)
        return NULL;
    WideCharToMultiByte(cp, flags, text, (int)length, (char *)data, needed, NULL,
                        flags ? &used_default : NULL);
    *size = needed;
    /* What did not survive is lost: decode the result and compare (this also
       catches the code pages that do not report the default character) */
    *lossy = used_default;
    back = tc_decode(data, needed, codepage, &back_length, &invalid);
    if (!back || back_length != length || memcmp(back, text, length * sizeof(WCHAR)))
        *lossy = TRUE;
    free(back);
    return data;
}

unsigned char *tc_encode(const WCHAR *text, size_t length, const TextEncoding *enc,
                         size_t *size, BOOL *lossy)
{
    unsigned char *data, *out;
    size_t i;

    *lossy = FALSE;
    if (enc->codepage == TC_UTF16LE || enc->codepage == TC_UTF16BE) {
        data = out = malloc(length * 2 + 2);
        if (!data)
            return NULL;
        if (enc->bom) {
            *out++ = enc->codepage == TC_UTF16LE ? 0xFF : 0xFE;
            *out++ = enc->codepage == TC_UTF16LE ? 0xFE : 0xFF;
        }
        for (i = 0; i < length; i++) {
            unsigned char low = (unsigned char)(text[i] & 0xFF), high = (unsigned char)(text[i] >> 8);
            *out++ = enc->codepage == TC_UTF16LE ? low : high;
            *out++ = enc->codepage == TC_UTF16LE ? high : low;
        }
    } else if (enc->codepage == TC_UTF8) {
        data = out = malloc(length * 3 + 3);
        if (!data)
            return NULL;
        if (enc->bom) {
            *out++ = 0xEF;
            *out++ = 0xBB;
            *out++ = 0xBF;
        }
        for (i = 0; i < length; i++) {
            unsigned long point = text[i];
            if (point >= 0xD800 && point <= 0xDBFF && i + 1 < length &&
                    text[i + 1] >= 0xDC00 && text[i + 1] <= 0xDFFF) {
                point = 0x10000 + ((point - 0xD800) << 10) + (text[i + 1] - 0xDC00);
                i++;
            } else if (point >= 0xD800 && point <= 0xDFFF) {
                point = REPLACEMENT;  /* A lone surrogate has no UTF-8 form */
                *lossy = TRUE;
            }
            if (point < 0x80) {
                *out++ = (unsigned char)point;
            } else if (point < 0x800) {
                *out++ = (unsigned char)(0xC0 | (point >> 6));
                *out++ = (unsigned char)(0x80 | (point & 0x3F));
            } else if (point < 0x10000) {
                *out++ = (unsigned char)(0xE0 | (point >> 12));
                *out++ = (unsigned char)(0x80 | ((point >> 6) & 0x3F));
                *out++ = (unsigned char)(0x80 | (point & 0x3F));
            } else {
                *out++ = (unsigned char)(0xF0 | (point >> 18));
                *out++ = (unsigned char)(0x80 | ((point >> 12) & 0x3F));
                *out++ = (unsigned char)(0x80 | ((point >> 6) & 0x3F));
                *out++ = (unsigned char)(0x80 | (point & 0x3F));
            }
        }
    } else {
        return encode_codepage(text, length, enc->codepage, size, lossy);
    }
    *size = out - data;
    return data;
}

int tc_count_eol(const WCHAR *text, size_t length, size_t counts[3])
{
    size_t i;

    counts[TC_EOL_CRLF] = counts[TC_EOL_LF] = counts[TC_EOL_CR] = 0;
    for (i = 0; i < length; i++) {
        if (text[i] == '\r' && i + 1 < length && text[i + 1] == '\n') {
            counts[TC_EOL_CRLF]++;
            i++;
        } else if (text[i] == '\r') {
            counts[TC_EOL_CR]++;
        } else if (text[i] == '\n') {
            counts[TC_EOL_LF]++;
        }
    }
    if (counts[TC_EOL_LF] > counts[TC_EOL_CRLF] && counts[TC_EOL_LF] >= counts[TC_EOL_CR])
        return TC_EOL_LF;
    if (counts[TC_EOL_CR] > counts[TC_EOL_CRLF] && counts[TC_EOL_CR] > counts[TC_EOL_LF])
        return TC_EOL_CR;
    return TC_EOL_CRLF;
}

WCHAR *tc_convert_eol(const WCHAR *text, size_t length, int eol, size_t *out_length)
{
    WCHAR *out = malloc((length * 2 + 1) * sizeof(WCHAR));
    size_t i, count = 0;

    if (!out)
        return NULL;
    for (i = 0; i < length; i++) {
        if (text[i] == '\r' || text[i] == '\n') {
            if (text[i] == '\r' && i + 1 < length && text[i + 1] == '\n')
                i++;
            if (eol != TC_EOL_LF)
                out[count++] = '\r';
            if (eol != TC_EOL_CR)
                out[count++] = '\n';
        } else {
            out[count++] = text[i];
        }
    }
    out[count] = 0;
    *out_length = count;
    return out;
}

BOOL tc_load(const unsigned char *data, size_t size, const TextEncoding *forced,
             TextDocument *doc)
{
    size_t bom, length, counts[3], i;
    WCHAR *decoded;

    memset(doc, 0, sizeof(*doc));
    doc->encoding = forced ? *forced : tc_detect(data, size);
    /* A chosen Unicode encoding has a byte order mark only if the file has */
    bom = tc_bom_size(data, size, &doc->encoding);
    doc->encoding.bom = bom != 0;
    decoded = tc_decode(data + bom, size - bom, doc->encoding.codepage, &length,
                        &doc->invalid);
    if (!decoded)
        return FALSE;
    doc->eol = tc_count_eol(decoded, length, counts);
    doc->mixed_eol = (counts[0] != 0) + (counts[1] != 0) + (counts[2] != 0) > 1;
    doc->text = tc_convert_eol(decoded, length, TC_EOL_CRLF, &doc->length);
    free(decoded);
    if (!doc->text)
        return FALSE;
    for (i = 0; i < doc->length; i++)
        if (doc->text[i] == 0)
            doc->text[i] = ' ';
    return TRUE;
}

unsigned char *tc_save(const WCHAR *text, size_t length, const TextEncoding *enc, int eol,
                       size_t *size, BOOL *lossy)
{
    size_t converted_length;
    WCHAR *converted = tc_convert_eol(text, length, eol, &converted_length);
    unsigned char *data;

    if (!converted)
        return NULL;
    data = tc_encode(converted, converted_length, enc, size, lossy);
    free(converted);
    return data;
}

/* text followed by number and ")" (no wsprintfW: the codec needs only
   kernel32, so the console test program links with it alone) */
static void name_with_number(WCHAR *name, const WCHAR *text, UINT number)
{
    WCHAR digits[12];
    int count = 0, length;

    lstrcpyW(name, text);
    do {
        digits[count++] = (WCHAR)('0' + number % 10);
        number /= 10;
    } while (number);
    length = lstrlenW(name);
    while (count)
        name[length++] = digits[--count];
    name[length++] = ')';
    name[length] = 0;
}

void tc_encoding_name(const TextEncoding *enc, WCHAR *buffer, int size)
{
    WCHAR name[96];
    int i;

    if (size <= 0)
        return;
    if (enc->codepage == TC_ANSI) {
        name_with_number(name, L"ANSI (code page ", GetACP());
    } else if (enc->codepage == TC_UTF8 || enc->codepage == TC_UTF16LE ||
               enc->codepage == TC_UTF16BE) {
        lstrcpyW(name, enc->codepage == TC_UTF8 ? L"UTF-8" :
                       enc->codepage == TC_UTF16LE ? L"UTF-16 LE" : L"UTF-16 BE");
        if (enc->codepage == TC_UTF8 && enc->bom)
            lstrcatW(name, L" with BOM");
        else if (enc->codepage != TC_UTF8 && !enc->bom)
            lstrcatW(name, L" without BOM");
    } else {
        name_with_number(name, L"Code page (", enc->codepage);
        for (i = 0; i < tc_encoding_count; i++) {
            if (tc_encodings[i].codepage == enc->codepage) {
                lstrcpynW(name, tc_encodings[i].name, 96);
                break;
            }
        }
    }
    lstrcpynW(buffer, name, size);
}

const WCHAR *tc_eol_name(int eol)
{
    return eol == TC_EOL_LF ? L"Unix (LF)" : eol == TC_EOL_CR ? L"Macintosh (CR)"
                                                             : L"Windows (CRLF)";
}
