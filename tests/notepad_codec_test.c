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
Notepad codec test - the encoding and line break detection and conversion of
apps/notepad/textcodec.c (compiled into this program), and through it the
emulator's code pages: MultiByteToWideChar, WideCharToMultiByte and
IsValidCodePage for the ANSI, OEM, ISO-8859, KOI8 and East Asian code pages.
The expected bytes are those of the published code page tables. Every
check prints PASS or FAIL; the exit code is the failure count.

Run with --codepage cp1254 too: the ANSI checks use GetACP().
*/

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../apps/notepad/textcodec.c"

static int failures = 0;

static void check(int ok, const char *name)
{
    printf("%s: %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok)
        failures++;
}

static int same_text(const WCHAR *a, size_t a_length, const WCHAR *b)
{
    return a_length == wcslen(b) && memcmp(a, b, a_length * sizeof(WCHAR)) == 0;
}

/* text encoded in codepage gives bytes (size), and the bytes decode back */
static void check_codepage(UINT codepage, const WCHAR *text, const char *bytes, size_t size,
                           const char *name)
{
    TextEncoding enc = {codepage, FALSE};
    size_t out_size = 0, length = 0;
    BOOL lossy = TRUE, invalid = TRUE;
    unsigned char *data;
    WCHAR *back;
    char label[96];

    if (!IsValidCodePage(codepage)) {
        snprintf(label, sizeof(label), "%s: IsValidCodePage(%u)", name, codepage);
        check(0, label);
        return;
    }
    data = tc_encode(text, wcslen(text), &enc, &out_size, &lossy);
    snprintf(label, sizeof(label), "%s: encode (%u)", name, codepage);
    check(data && out_size == size && memcmp(data, bytes, size) == 0 && !lossy, label);
    back = tc_decode((const unsigned char *)bytes, size, codepage, &length, &invalid);
    snprintf(label, sizeof(label), "%s: decode (%u)", name, codepage);
    check(back && same_text(back, length, text) && !invalid, label);
    free(data);
    free(back);
}

static void test_detection(void)
{
    const unsigned char overlong[] = {'a', 0xC0, 0x80};
    const unsigned char surrogate[] = {0xED, 0xA0, 0x80};
    const unsigned char truncated[] = {'a', 0xE2, 0x82};
    const unsigned char beyond[] = {0xF4, 0x90, 0x80, 0x80};
    const unsigned char valid[] = {'a', 0xC4, 0x9F, 0xE2, 0x82, 0xAC, 0xF0, 0x9F, 0x98, 0x80};
    const unsigned char utf16le[] = {'H', 0, 'i', 0, 0x1F, 0x01, '!', 0};
    const unsigned char utf16be[] = {0, 'H', 0, 'i', 0x01, 0x1F, 0, '!'};
    const unsigned char ansi[] = {'D', 0xFC, 'n', 'y', 'a'};
    const unsigned char bom8[] = {0xEF, 0xBB, 0xBF, 'x'};
    const unsigned char bom16le[] = {0xFF, 0xFE, 'x', 0};
    const unsigned char bom16be[] = {0xFE, 0xFF, 0, 'x'};
    BOOL high = FALSE;
    TextEncoding enc;

    check(tc_is_utf8(valid, sizeof(valid), &high) && high, "valid UTF-8 (2, 3, 4 bytes)");
    check(!tc_is_utf8(overlong, sizeof(overlong), NULL), "overlong UTF-8 is invalid");
    check(!tc_is_utf8(surrogate, sizeof(surrogate), NULL), "UTF-8 surrogate is invalid");
    check(!tc_is_utf8(truncated, sizeof(truncated), NULL), "truncated UTF-8 is invalid");
    check(!tc_is_utf8(beyond, sizeof(beyond), NULL), "UTF-8 above U+10FFFF is invalid");
    check(tc_is_utf8((const unsigned char *)"plain", 5, &high) && !high, "ASCII is UTF-8");
    check(tc_guess_utf16(utf16le, sizeof(utf16le)) == TC_UTF16LE, "UTF-16 LE without BOM");
    check(tc_guess_utf16(utf16be, sizeof(utf16be)) == TC_UTF16BE, "UTF-16 BE without BOM");
    check(tc_guess_utf16(ansi, sizeof(ansi)) == 0, "ANSI text is not UTF-16");
    enc = tc_detect(bom8, sizeof(bom8));
    check(enc.codepage == TC_UTF8 && enc.bom, "detect: UTF-8 BOM");
    enc = tc_detect(bom16le, sizeof(bom16le));
    check(enc.codepage == TC_UTF16LE && enc.bom, "detect: UTF-16 LE BOM");
    enc = tc_detect(bom16be, sizeof(bom16be));
    check(enc.codepage == TC_UTF16BE && enc.bom, "detect: UTF-16 BE BOM");
    enc = tc_detect(utf16le, sizeof(utf16le));
    check(enc.codepage == TC_UTF16LE && !enc.bom, "detect: UTF-16 LE by its zeros");
    enc = tc_detect(valid, sizeof(valid));
    check(enc.codepage == TC_UTF8 && !enc.bom, "detect: UTF-8 without BOM");
    enc = tc_detect(ansi, sizeof(ansi));
    check(enc.codepage == TC_ANSI, "detect: else ANSI");
    enc = tc_detect((const unsigned char *)"", 0);
    check(enc.codepage == TC_UTF8, "detect: an empty file is UTF-8");
}

static void test_unicode(void)
{
    const WCHAR *text = L"ağ€\xD83D\xDE00";
    const unsigned char utf8[] = {0xEF, 0xBB, 0xBF, 'a', 0xC4, 0x9F, 0xE2, 0x82, 0xAC,
                                  0xF0, 0x9F, 0x98, 0x80};
    const unsigned char utf16be[] = {0xFE, 0xFF, 0, 'a', 0x01, 0x1F, 0x20, 0xAC,
                                     0xD8, 0x3D, 0xDE, 0x00};
    const unsigned char bad[] = {'a', 0xFF, 'b'};
    TextEncoding enc = {TC_UTF8, TRUE};
    unsigned char *data;
    size_t size, length;
    BOOL lossy, invalid;
    WCHAR *back;

    data = tc_encode(text, wcslen(text), &enc, &size, &lossy);
    check(data && size == sizeof(utf8) && !memcmp(data, utf8, size) && !lossy,
          "UTF-8 with BOM, a surrogate pair is 4 bytes");
    free(data);
    enc.codepage = TC_UTF16BE;
    data = tc_encode(text, wcslen(text), &enc, &size, &lossy);
    check(data && size == sizeof(utf16be) && !memcmp(data, utf16be, size) && !lossy,
          "UTF-16 BE with BOM");
    free(data);
    back = tc_decode(utf8 + 3, sizeof(utf8) - 3, TC_UTF8, &length, &invalid);
    check(back && same_text(back, length, text) && !invalid, "UTF-8 decodes");
    free(back);
    back = tc_decode(utf16be + 2, sizeof(utf16be) - 2, TC_UTF16BE, &length, &invalid);
    check(back && same_text(back, length, text) && !invalid, "UTF-16 BE decodes");
    free(back);
    back = tc_decode(bad, sizeof(bad), TC_UTF8, &length, &invalid);
    check(back && same_text(back, length, L"a\xFFFD" L"b") && invalid,
          "invalid UTF-8 byte: U+FFFD, reported");
    free(back);
    enc.codepage = TC_UTF8;
    enc.bom = FALSE;
    data = tc_encode(L"x\xD800y", 3, &enc, &size, &lossy);
    check(data && lossy && size == 5, "lone surrogate in UTF-8 is lossy");
    free(data);
}

static void test_codepages(void)
{
    TextEncoding enc;
    unsigned char *data;
    size_t size, length;
    BOOL lossy, invalid;
    WCHAR *back;
    const unsigned char cp1252_gap[] = {'a', 0x81, 0x8D, 'b'};

    check_codepage(1254, L"ğüşıöçĞÜŞİÖ"
                   L"Ç", "\xf0\xfc\xfe\xfd\xf6\xe7\xd0\xdc\xde\xdd\xd6\xc7", 12,
                   "Turkish Windows-1254");
    check_codepage(1251, L"Жж", "\xc6\xe6", 2, "Cyrillic Windows-1251");
    check_codepage(20866, L"Привет",
                   "\xf0\xd2\xc9\xd7\xc5\xd4", 6, "KOI8-R");
    check_codepage(437, L"äöü½", "\x84\x94\x81\xab", 4, "OEM 437");
    check_codepage(857, L"ğış", "\xa7\x8d\x9f", 3, "OEM Turkish 857");
    check_codepage(28599, L"ğış", "\xf0\xfd\xfe", 3, "ISO-8859-9");
    check_codepage(28605, L"€Š", "\xa4\xa6", 2, "ISO-8859-15");
    check_codepage(932, L"こんにちは",
                   "\x82\xb1\x82\xf1\x82\xc9\x82\xbf\x82\xcd", 10, "Shift-JIS 932");
    check_codepage(936, L"中文", "\xd6\xd0\xce\xc4", 4, "GBK 936");
    check_codepage(949, L"한국어", "\xc7\xd1\xb1\xb9\xbe\xee", 6, "Korean 949");
    check_codepage(950, L"中文", "\xa4\xa4\xa4\xe5", 4, "Big5 950");
    check_codepage(51932, L"日本", "\xc6\xfc\xcb\xdc", 4, "EUC-JP 51932");
    check_codepage(54936, L"中\xD83D\xDE00", "\xd6\xd0\x94\x39\xfc\x36", 6,
                   "GB18030 54936 (a surrogate pair)");

    /* What a code page lacks is lost, and reported */
    enc.codepage = 1252;
    enc.bom = FALSE;
    data = tc_encode(L"aş", 2, &enc, &size, &lossy);
    check(data && size == 2 && lossy, "s-cedilla is lost in Windows-1252");
    free(data);
    enc.codepage = 932;
    data = tc_encode(L"ğ", 1, &enc, &size, &lossy);
    check(data && lossy, "g-breve is lost in Shift-JIS");
    free(data);

    /* The bytes Windows-1252 has no character for survive a round trip */
    back = tc_decode(cp1252_gap, sizeof(cp1252_gap), 1252, &length, &invalid);
    check(back && same_text(back, length, L"a\x0081\x008D" L"b"), "1252 0x81 is U+0081");
    enc.codepage = 1252;
    data = back ? tc_encode(back, length, &enc, &size, &lossy) : NULL;
    check(data && size == sizeof(cp1252_gap) && !memcmp(data, cp1252_gap, size) && !lossy,
          "1252 0x81 round-trips");
    free(data);
    free(back);

    /* An invalid double-byte sequence is reported */
    back = tc_decode((const unsigned char *)"a\x82", 2, 932, &length, &invalid);
    check(back && invalid, "Shift-JIS lead byte at the end is invalid");
    free(back);
}

static void test_ansi(void)
{
    UINT acp = GetACP();
    TextEncoding enc = {TC_ANSI, FALSE};
    unsigned char *data;
    size_t size;
    BOOL lossy;
    WCHAR name[96], expected[96];

    /* The ANSI encoding is the system's: Turkish letters exist in 1254 */
    data = tc_encode(L"ğ", 1, &enc, &size, &lossy);
    if (acp == 1254)
        check(data && size == 1 && data[0] == 0xF0 && !lossy, "ANSI (1254) has g-breve");
    else
        check(data && lossy, "ANSI (not 1254) lacks g-breve");
    free(data);
    tc_encoding_name(&enc, name, 96);
    name_with_number(expected, L"ANSI (code page ", acp);
    check(lstrcmpW(name, expected) == 0, "ANSI name has the code page");
}

static void test_line_breaks(void)
{
    const WCHAR *mixed = L"a\nb\nc\r\nd\re";
    size_t counts[3], length, size;
    WCHAR *text;
    TextDocument doc;
    TextEncoding enc = {TC_UTF8, FALSE};
    unsigned char *data;
    BOOL lossy;

    check(tc_count_eol(mixed, wcslen(mixed), counts) == TC_EOL_LF && counts[TC_EOL_LF] == 2 &&
          counts[TC_EOL_CRLF] == 1 && counts[TC_EOL_CR] == 1, "count: LF is the most common");
    check(tc_count_eol(L"a\rb\rc", 5, counts) == TC_EOL_CR, "count: CR");
    check(tc_count_eol(L"abc", 3, counts) == TC_EOL_CRLF, "count: none is Windows");
    text = tc_convert_eol(mixed, wcslen(mixed), TC_EOL_CRLF, &length);
    check(text && same_text(text, length, L"a\r\nb\r\nc\r\nd\r\ne"), "to CR LF");
    free(text);
    text = tc_convert_eol(mixed, wcslen(mixed), TC_EOL_CR, &length);
    check(text && same_text(text, length, L"a\rb\rc\rd\re"), "to CR");
    free(text);

    check(tc_load((const unsigned char *)"x\ny\r\nz\n", 7, NULL, &doc) &&
          same_text(doc.text, doc.length, L"x\r\ny\r\nz\r\n") && doc.eol == TC_EOL_LF &&
          doc.mixed_eol && doc.encoding.codepage == TC_UTF8, "load: mixed, shown with CR LF");
    free(doc.text);
    check(tc_load((const unsigned char *)"a\0b", 3, NULL, &doc) &&
          same_text(doc.text, doc.length, L"a b"), "load: NUL becomes a space");
    free(doc.text);
    enc.codepage = TC_UTF16LE;
    enc.bom = TRUE;
    check(tc_load((const unsigned char *)"a\0b\0", 4, &enc, &doc) && !doc.encoding.bom &&
          same_text(doc.text, doc.length, L"ab"), "load: chosen UTF-16 without its BOM");
    free(doc.text);
    enc.codepage = TC_UTF8;
    enc.bom = FALSE;
    data = tc_save(L"1\r\n2\r\n", 6, &enc, TC_EOL_LF, &size, &lossy);
    check(data && size == 4 && !memcmp(data, "1\n2\n", 4), "save: Unix line breaks");
    free(data);
}

int main(void)
{
    test_detection();
    test_unicode();
    test_codepages();
    test_ansi();
    test_line_breaks();
    printf("\n== %d failure(s) ==\n", failures);
    return failures;
}
