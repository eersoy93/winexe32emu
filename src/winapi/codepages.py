# Copyright 2025-2026 Erdem Ersoy (eersoy93)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""WinAPIHandler mixin: Windows code pages on Python's codecs: the code page
numbers of MultiByteToWideChar & co., GetCPInfoEx, EnumSystemCodePages.

Windows numbers its code pages differently from Python's codec names
(28591 is ISO-8859-1, 20866 KOI8-R, 54936 GB18030); the numbers whose
codec is "cpNNN" need no entry here."""

import codecs
import functools
import struct

from unicorn import UcError

# Windows code page -> Python codec (besides the "cpNNN" ones)
CODEPAGE_CODECS = {
    936: 'gbk', 1361: 'johab', 10000: 'mac_roman', 10006: 'mac_greek',
    10007: 'mac_cyrillic', 10029: 'mac_latin2', 10079: 'mac_iceland', 10081: 'mac_turkish',
    20127: 'ascii', 20866: 'koi8_r', 21866: 'koi8_u', 20932: 'euc_jp',
    28591: 'iso8859_1', 28592: 'iso8859_2', 28593: 'iso8859_3', 28594: 'iso8859_4',
    28595: 'iso8859_5', 28596: 'iso8859_6', 28597: 'iso8859_7', 28598: 'iso8859_8',
    28599: 'iso8859_9', 28603: 'iso8859_13', 28605: 'iso8859_15', 38598: 'iso8859_8',
    50220: 'iso2022_jp', 50221: 'iso2022_jp_ext', 50222: 'iso2022_jp_ext',
    50225: 'iso2022_kr', 51932: 'euc_jp', 51936: 'gb2312', 51949: 'euc_kr', 52936: 'hz',
    54936: 'gb18030', 65000: 'utf-7', 65001: 'utf-8',
}

# Names of GetCPInfoEx (CodePageName) for the common code pages
CODEPAGE_NAMES = {
    437: 'OEM - United States', 737: 'OEM - Greek 437G', 775: 'OEM - Baltic',
    850: 'OEM - Multilingual Latin I', 852: 'OEM - Latin II', 855: 'OEM - Cyrillic',
    857: 'OEM - Turkish', 860: 'OEM - Portuguese', 861: 'OEM - Icelandic',
    862: 'OEM - Hebrew', 863: 'OEM - Canadian French', 865: 'OEM - Nordic',
    866: 'OEM - Russian', 869: 'OEM - Modern Greek', 874: 'ANSI/OEM - Thai',
    932: 'ANSI/OEM - Japanese Shift-JIS', 936: 'ANSI/OEM - Simplified Chinese GBK',
    949: 'ANSI/OEM - Korean', 950: 'ANSI/OEM - Traditional Chinese Big5',
    1250: 'ANSI - Central Europe', 1251: 'ANSI - Cyrillic', 1252: 'ANSI - Latin I',
    1253: 'ANSI - Greek', 1254: 'ANSI - Turkish', 1255: 'ANSI - Hebrew',
    1256: 'ANSI - Arabic', 1257: 'ANSI - Baltic', 1258: 'ANSI/OEM - Viet Nam',
    10000: 'MAC - Roman', 20127: 'US-ASCII', 20866: 'Russian - KOI8-R',
    21866: 'Ukrainian - KOI8-U', 28591: 'ISO 8859-1 Latin I',
    28592: 'ISO 8859-2 Central Europe', 28593: 'ISO 8859-3 Latin 3',
    28594: 'ISO 8859-4 Baltic', 28595: 'ISO 8859-5 Cyrillic', 28596: 'ISO 8859-6 Arabic',
    28597: 'ISO 8859-7 Greek', 28598: 'ISO 8859-8 Hebrew: Visual Ordering',
    28599: 'ISO 8859-9 Latin 5', 28603: 'ISO 8859-13 Latin 7',
    28605: 'ISO 8859-15 Latin 9', 51932: 'EUC - Japanese', 51949: 'EUC - Korean',
    54936: 'GB18030 Simplified Chinese', 65000: 'Unicode (UTF-7)',
    65001: 'Unicode (UTF-8)',
}

# Lead byte ranges of the double-byte code pages (CPINFO.LeadByte)
LEAD_BYTES = {932: ((0x81, 0x9F), (0xE0, 0xFC)), 936: ((0x81, 0xFE),),
              949: ((0x81, 0xFE),), 950: ((0x81, 0xFE),),
              1361: ((0x84, 0xD3), (0xD8, 0xDE), (0xE0, 0xF9))}

# Codecs with more than one byte per character (normalized codec names)
MULTI_BYTE_CODECS = frozenset(
    codecs.lookup(name).name for name in (
        'utf-8', 'utf-7', 'cp932', 'shift_jis', 'gbk', 'gb2312', 'gb18030', 'hz', 'big5',
        'cp950', 'cp949', 'euc_kr', 'euc_jp', 'johab', 'iso2022_jp', 'iso2022_jp_ext',
        'iso2022_kr', 'euc_jis_2004', 'shift_jis_2004', 'big5hkscs'))

# Code pages EnumSystemCodePages lists (the ones with a codec)
ENUMERATED_CODEPAGES = (
    37, 437, 500, 720, 737, 775, 850, 852, 855, 857, 858, 860, 861, 862, 863, 864, 865, 866,
    869, 874, 875, 932, 936, 949, 950, 1026, 1140, 1250, 1251, 1252, 1253, 1254, 1255, 1256,
    1257, 1258, 1361, 10000, 10006, 10007, 10029, 10079, 10081, 20127, 20866, 20932, 21866,
    28591, 28592, 28593, 28594, 28595, 28596, 28597, 28598, 28599, 28603, 28605, 38598,
    50220, 50221, 50222, 50225, 51932, 51936, 51949, 52936, 54936, 65000, 65001)

KEEP_BYTE_ERRORS = 'winexe32emu-keep-byte'


def codec_for_codepage(code_page):
    """Python codec name of a Windows code page number, or None. CP_ACP and
    the other symbolic values are resolved by the caller."""
    name = CODEPAGE_CODECS.get(code_page)
    if name is None:
        if code_page in (1200, 1201, 12000, 12001):  # UTF-16/32: not for these APIs
            return None
        name = f'cp{code_page}'
    try:
        return codecs.lookup(name).name
    except LookupError:
        return None


def is_single_byte(codec):
    """Does the codec map each byte to one character?"""
    try:
        return codecs.lookup(codec).name not in MULTI_BYTE_CODECS
    except LookupError:
        return False


@functools.lru_cache(maxsize=64)
def undefined_bytes(codec):
    """Bytes a single-byte codec has no character for (0x81 of cp1252)"""
    result = set()
    for value in range(256):
        try:
            bytes([value]).decode(codec)
        except UnicodeDecodeError:
            result.add(value)
    return frozenset(result)


def _keep_byte(error):
    """Decoding error handler: a byte without a character in a single-byte
    code page is the character of the same value (Windows' cp1252 reads 0x81
    as U+0081); encode_codepage turns it back into that byte, so it
    round-trips"""
    if isinstance(error, UnicodeDecodeError):
        return ''.join(chr(b) for b in error.object[error.start:error.end]), error.end
    raise error


codecs.register_error(KEEP_BYTE_ERRORS, _keep_byte)


def decode_codepage(data, codec, strict=False):
    """Bytes of a code page as text; strict (MB_ERR_INVALID_CHARS): None
    when a multi-byte sequence is not valid"""
    if is_single_byte(codec):
        return data.decode(codec, errors=KEEP_BYTE_ERRORS)
    try:
        return data.decode(codec)
    except UnicodeDecodeError:
        return None if strict else data.decode(codec, errors='replace')


def encode_codepage(text, codec, default=b'?'):
    """(bytes, used_default) of text in a code page: the characters it
    cannot represent become default (WideCharToMultiByte's lpDefaultChar)"""
    # The characters U+0080..U+00FF decode_codepage made of undefined bytes
    kept = undefined_bytes(codec) if is_single_byte(codec) else frozenset()
    parts, used, pos = [], False, 0
    while pos < len(text):
        try:
            parts.append(text[pos:].encode(codec))
            break
        except UnicodeEncodeError as error:
            # Positions are relative to the slice that was encoded
            start, end = pos + error.start, pos + error.end
            parts.append(text[pos:start].encode(codec))
            for char in text[start:end]:
                if ord(char) in kept:
                    parts.append(bytes([ord(char)]))
                else:
                    parts.append(default)
                    used = True
            pos = end
    return b''.join(parts), used


def max_char_size(code_page):
    """CPINFO.MaxCharSize of a code page"""
    if code_page in (54936, 65001):
        return 4
    if code_page == 65000 or 50220 <= code_page <= 50229 or code_page == 52936:
        return 5
    codec = codec_for_codepage(code_page)
    return 1 if codec is None or is_single_byte(codec) else 2


class CodePagesMixin:
    """Code page information: GetCPInfoEx, EnumSystemCodePages, the CPINFO data"""

    def _resolve_codepage(self, code_page):
        """A code page number for CP_ACP (0), CP_OEMCP (1), CP_MACCP (2) and
        CP_THREAD_ACP (3); others unchanged"""
        if code_page in (0, 3):
            return self._ansi_codepage_number()
        if code_page == 1:
            return self.GetOEMCP([])
        if code_page == 2:
            return 10000
        return code_page

    def _cp_info(self, code_page):
        """(code page, MaxCharSize, CPINFO bytes without CodePage/name), or None
        for an unsupported code page"""
        number = self._resolve_codepage(code_page)
        if number != 65001 and codec_for_codepage(number) is None:
            return None
        lead = bytearray(12)
        for index, (first, last) in enumerate(LEAD_BYTES.get(number, ())):
            lead[2 * index], lead[2 * index + 1] = first, last
        size = max_char_size(number)
        return number, size, struct.pack('<I2s12s', size, b'?\x00', bytes(lead))

    def GetCPInfoExA(self, args, wide=False):
        """GetCPInfoExA/W(CodePage, dwFlags, lpCPInfoEx): CPINFO with the
        Unicode default character, the code page number and its name"""
        code_page, info_address = args[0], args[2]
        info = self._cp_info(code_page)
        if info is None or not info_address:
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0
        number, _, data = info
        name = f"{number}  ({CODEPAGE_NAMES.get(number, f'Code Page {number}')})"
        units = self._text_units(name, wide)[:259] + [0]
        data += struct.pack('<HI', ord('?'), number) + self._pack_units(units, wide)
        return 1 if self._mem_write(info_address, data) else 0

    def GetCPInfoExW(self, args):
        return self.GetCPInfoExA(args, wide=True)

    def EnumSystemCodePagesA(self, args, wide=False):
        """EnumSystemCodePagesA/W(lpCodePageEnumProc, dwFlags): each code page
        the emulator converts, as a decimal string, until the callback
        returns FALSE (CP_INSTALLED and CP_SUPPORTED list the same ones)"""
        proc, flags = args[0], args[1]
        if not proc or flags not in (1, 2):  # CP_INSTALLED, CP_SUPPORTED
            self._last_error = 1004 if proc else 87  # ERROR_INVALID_FLAGS
            return 0
        address = self.emu.heap_alloc(32)
        try:
            for number in ENUMERATED_CODEPAGES:
                if codec_for_codepage(number) is None:
                    continue
                self._write_units(address, self._text_units(str(number), wide), wide)
                if not self.emu.call_callback(proc, [address]):
                    break
        finally:
            self.emu.heap_free(address)
        return 1

    def EnumSystemCodePagesW(self, args):
        return self.EnumSystemCodePagesA(args, wide=True)

    def _read_long_text(self, address, wide):
        """A NUL-terminated string argument of any length (a window text is not
        cut at the 32K of the other string arguments: an edit control can
        hold megabytes)"""
        if not address:
            return ''
        try:
            return (self.read_wide_string(address, max_len=0x4000000) if wide else
                    self.read_string(address, max_len=0x8000000))
        except UcError:
            return ''
