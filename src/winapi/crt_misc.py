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

"""WinAPIHandler mixin: CRT strings, number conversion, paths, environment, process control,
non-local jumps, time, UCRT startup"""

import re
import struct
import math
import time

from unicorn import UcError
from unicorn.x86_const import UC_X86_REG_EBP, UC_X86_REG_EBX, UC_X86_REG_EDI, UC_X86_REG_ESI

from .. import config
from ..guest import ApiJump, QWordResult, X87Result
from ..logger import log


class CrtMiscMixin:
    """CRT strings, number conversion, paths, environment, process control,
    non-local jumps, time, UCRT startup"""

    # ---- Strings (narrow and wide share unit-based helpers) ----

    @staticmethod
    def _fold_unit(u):
        """Case-fold one code unit (per-character lower case, like _stricmp)."""
        lowered = chr(u).lower()
        return ord(lowered) if len(lowered) == 1 else u

    @staticmethod
    def _cmp_units(a, b):
        for x, y in zip(a, b, strict=False):
            if x != y:
                return -1 if x < y else 1
        if len(a) != len(b):
            return -1 if len(a) < len(b) else 1
        return 0

    def _str_compare(self, args, wide, n=None, fold=False):
        a = self._read_units(args[0], wide)
        b = self._read_units(args[1], wide)
        if n is not None:
            a, b = a[:n], b[:n]
        if fold:
            if not wide:
                # Narrow case folding is ASCII-only in the C locale
                a = [u + 32 if 0x41 <= u <= 0x5A else u for u in a]
                b = [u + 32 if 0x41 <= u <= 0x5A else u for u in b]
            else:
                a = [self._fold_unit(u) for u in a]
                b = [self._fold_unit(u) for u in b]
        return self._cmp_units(a, b) & 0xFFFFFFFF

    def _str_copy(self, args, wide, n=None):
        dest, src = args[0], args[1]
        units = self._read_units(src, wide)
        if n is None:
            self._write_units(dest, units, wide)
        else:
            units = units[:n]
            self._write_units(dest, units + [0] * (n - len(units)), wide, terminate=False)
        return dest

    def _str_cat(self, args, wide, n=None):
        dest = args[0]
        dest_len = len(self._read_units(dest, wide))
        units = self._read_units(args[1], wide)
        if n is not None:
            units = units[:n]
        self._write_units(dest + dest_len * (2 if wide else 1), units, wide)
        return dest

    def _str_find_unit(self, args, wide, last=False):
        s = args[0]
        units = self._read_units(s, wide) + [0]  # the terminator can be searched for
        c = args[1] & (0xFFFF if wide else 0xFF)
        if c not in units:
            return 0
        index = len(units) - 1 - units[::-1].index(c) if last else units.index(c)
        return s + index * (2 if wide else 1)

    def _str_span(self, args, wide, accept):
        units = self._read_units(args[0], wide)
        chars = set(self._read_units(args[1], wide))
        count = 0
        for u in units:
            if (u in chars) != accept:
                break
            count += 1
        return count

    def _str_map(self, s, wide, func):
        units = self._read_units(s, wide)
        text = self._units_text(units, wide)
        mapped = self._text_units(func(text), wide)
        if len(mapped) == len(units):
            self._write_units(s, mapped, wide)
        return s

    def _tokenize(self, s, delim_addr, wide, context=None):
        """strtok/wcstok/strtok_s: tokens are terminated in place."""
        unit = 2 if wide else 1
        if s == 0:
            s = self._read_u32(context) if context else self._strtok_next.get(unit, 0)
        delims = set(self._read_units(delim_addr, wide))
        units = self._read_units(s, wide) if s else []
        i = 0
        while i < len(units) and units[i] in delims:
            i += 1
        if i >= len(units):
            next_pos = 0
            token = 0
        else:
            j = i
            while j < len(units) and units[j] not in delims:
                j += 1
            token = s + i * unit
            if j < len(units):
                self._write_units(s + j * unit, [], wide)  # terminate the token
                next_pos = s + (j + 1) * unit
            else:
                next_pos = s + j * unit
        if context:
            self._mem_write(context, struct.pack('<I', next_pos))
        else:
            self._strtok_next[unit] = next_pos
        return token

    def strtok(self, args):
        """strtok emulation"""
        return self._tokenize(args[0], args[1], False)

    def strtok_s(self, args):
        """strtok_s emulation (context pointer instead of static state)"""
        return self._tokenize(args[0], args[1], False, context=args[2])

    def wcstok(self, args):
        """wcstok emulation (msvcrt two-argument form)"""
        return self._tokenize(args[0], args[1], True)

    def strerror(self, args):
        """strerror emulation"""
        message = self._ERRNO_MESSAGES.get(args[0], "Unknown error")
        buf = self._static_buffer('strerror', 96)
        self._write_units(buf, self._text_units(message, False), False)
        return buf

    def strcoll(self, args):
        return self._str_compare(args, False)

    def _stricoll(self, args):
        return self._str_compare(args, False, fold=True)

    def _strcmpi(self, args):
        return self._str_compare(args, False, fold=True)

    def strxfrm(self, args):
        """strxfrm emulation (C locale: plain copy)"""
        units = self._read_units(args[1], False)
        if args[0] and len(units) < args[2]:
            self._write_units(args[0], units, False)
        return len(units)

    def _strset(self, args):
        """_strset emulation"""
        n = len(self._read_units(args[0], False))
        self._write_units(args[0], [args[1] & 0xFF] * n, False)
        return args[0]

    def _strnset(self, args):
        """_strnset emulation"""
        n = min(len(self._read_units(args[0], False)), args[2])
        self._write_units(args[0], [args[1] & 0xFF] * n, False, terminate=False)
        return args[0]

    def strnlen(self, args):
        """strnlen emulation"""
        return len(self.read_cstring(args[0], args[1])) if args[0] else 0

    def _memicmp(self, args):
        """_memicmp emulation"""
        try:
            a = bytes(self.emu.uc.mem_read(args[0], args[2])).lower()
            b = bytes(self.emu.uc.mem_read(args[1], args[2])).lower()
        except UcError:
            return 0
        return self._cmp_units(a, b) & 0xFFFFFFFF

    def _memccpy(self, args):
        """_memccpy emulation - copy up to and including byte c"""
        dest, src, c, n = args[0], args[1], args[2] & 0xFF, args[3]
        try:
            data = bytes(self.emu.uc.mem_read(src, n))
        except UcError:
            return 0
        idx = data.find(bytes([c]))
        if idx != -1:
            data = data[:idx + 1]
        self._mem_write(dest, data)
        return dest + idx + 1 if idx != -1 else 0

    def memccpy(self, args):
        return self._memccpy(args)

    # Secure (_s) string functions: return 0 or an errno value
    def _secure_copy(self, dest, size, units, wide):
        if not dest or size == 0:
            return self.EINVAL
        if len(units) >= size:
            self._write_units(dest, [], wide)
            return self.ERANGE
        self._write_units(dest, units, wide)
        return 0

    def strcpy_s(self, args):
        """strcpy_s emulation"""
        return self._secure_copy(args[0], args[1], self._read_units(args[2], False), False)

    def wcscpy_s(self, args):
        """wcscpy_s emulation"""
        return self._secure_copy(args[0], args[1], self._read_units(args[2], True), True)

    def strcat_s(self, args):
        """strcat_s emulation"""
        units = self._read_units(args[0], False) + self._read_units(args[2], False)
        return self._secure_copy(args[0], args[1], units, False)

    def wcscat_s(self, args):
        """wcscat_s emulation"""
        units = self._read_units(args[0], True) + self._read_units(args[2], True)
        return self._secure_copy(args[0], args[1], units, True)

    def strncpy_s(self, args):
        """strncpy_s emulation (count may be _TRUNCATE)"""
        dest, size, count = args[0], args[1], args[3]
        units = self._read_units(args[2], False)
        if count == 0xFFFFFFFF:  # _TRUNCATE
            if len(units) >= size and dest and size:
                self._write_units(dest, units[:size - 1], False)
                return 80  # STRUNCATE
            return self._secure_copy(dest, size, units, False)
        return self._secure_copy(dest, size, units[:count], False)

    def strncat_s(self, args):
        """strncat_s emulation"""
        units = self._read_units(args[2], False)
        if args[3] != 0xFFFFFFFF:
            units = units[:args[3]]
        return self._secure_copy(args[0], args[1], self._read_units(args[0], False) + units, False)

    def memcpy_s(self, args):
        """memcpy_s emulation"""
        dest, size, src, count = args[0], args[1], args[2], args[3]
        if count > size:
            if dest and size:
                self._mem_write(dest, b'\x00' * size)
            return self.ERANGE
        self.memcpy([dest, src, count])
        return 0

    def memmove_s(self, args):
        """memmove_s emulation"""
        return self.memcpy_s(args)

    # Wide string functions
    def wcscpy(self, args):
        return self._str_copy(args, True)

    def wcsncpy(self, args):
        return self._str_copy(args, True, args[2])

    def wcscat(self, args):
        return self._str_cat(args, True)

    def wcsncat(self, args):
        return self._str_cat(args, True, args[2])

    def wcscmp(self, args):
        return self._str_compare(args, True)

    def wcsncmp(self, args):
        return self._str_compare(args, True, n=args[2])

    def _wcsicmp(self, args):
        return self._str_compare(args, True, fold=True)

    def _wcsnicmp(self, args):
        return self._str_compare(args, True, n=args[2], fold=True)

    def wcscoll(self, args):
        return self._str_compare(args, True)

    def _wcsicoll(self, args):
        return self._str_compare(args, True, fold=True)

    def wcschr(self, args):
        return self._str_find_unit(args, True)

    def wcsrchr(self, args):
        return self._str_find_unit(args, True, last=True)

    def wcsspn(self, args):
        return self._str_span(args, True, accept=True)

    def wcscspn(self, args):
        return self._str_span(args, True, accept=False)

    def wcspbrk(self, args):
        """wcspbrk emulation"""
        count = self._str_span(args, True, accept=False)
        return args[0] + 2 * count if count < len(self._read_units(args[0], True)) else 0

    def wcsstr(self, args):
        """wcsstr emulation"""
        hay = self._read_units(args[0], True)
        needle = self._read_units(args[1], True)
        for i in range(len(hay) - len(needle) + 1):
            if hay[i:i + len(needle)] == needle:
                return args[0] + 2 * i
        return 0

    def wcsnlen(self, args):
        return min(len(self._read_units(args[0], True)), args[1]) if args[0] else 0

    def _wcsdup(self, args):
        """_wcsdup emulation"""
        return self._alloc_units(self._read_units(args[0], True), True) if args[0] else 0

    def _wcslwr(self, args):
        return self._str_map(args[0], True, str.lower)

    def _wcsupr(self, args):
        return self._str_map(args[0], True, str.upper)

    def _wcsrev(self, args):
        units = self._read_units(args[0], True)
        self._write_units(args[0], units[::-1], True)
        return args[0]

    def towupper(self, args):
        """towupper emulation"""
        return self._case_unit(args[0] & 0xFFFF, str.upper)

    def towlower(self, args):
        """towlower emulation"""
        return self._case_unit(args[0] & 0xFFFF, str.lower)

    @staticmethod
    def _case_unit(u, func):
        mapped = func(chr(u))
        return ord(mapped) if len(mapped) == 1 and ord(mapped) <= 0xFFFF else u

    _WCTYPE_TESTS = {
        'iswalpha': str.isalpha,
        'iswdigit': lambda c: '0' <= c <= '9',
        'iswxdigit': lambda c: c in '0123456789abcdefABCDEF',
        'iswspace': lambda c: c in ' \t\n\v\f\r' or c.isspace(),
        'iswupper': str.isupper,
        'iswlower': str.islower,
        'iswalnum': str.isalnum,
        'iswcntrl': lambda c: ord(c) < 0x20 or 0x7F <= ord(c) < 0xA0,
        'iswprint': lambda c: c == ' ' or c.isprintable(),
        'iswgraph': lambda c: c.isprintable() and not c.isspace(),
        'iswpunct': lambda c: c.isprintable() and not c.isalnum() and not c.isspace(),
    }

    # CRT ctype mask bits (_UPPER, _LOWER, _DIGIT, _SPACE, _PUNCT, _CONTROL, _BLANK, _HEX, _ALPHA)
    _CTYPE_MASK_TESTS = (
        (0x0001, 'iswupper'), (0x0002, 'iswlower'), (0x0004, 'iswdigit'),
        (0x0008, 'iswspace'), (0x0010, 'iswpunct'), (0x0020, 'iswcntrl'),
        (0x0040, lambda c: c in ' \t'), (0x0080, 'iswxdigit'),
        (0x0100, 'iswalpha'),
    )

    def _wctype_mask(self, ch):
        c = chr(ch & 0xFFFF)
        mask = 0
        for bit, test in self._CTYPE_MASK_TESTS:
            if (self._WCTYPE_TESTS[test] if isinstance(test, str) else test)(c):
                mask |= bit
        return mask

    def iswctype(self, args):
        """iswctype emulation - test a wide character against a ctype mask"""
        return self._wctype_mask(args[0]) & (args[1] & 0xFFFF)

    def is_wctype(self, args):
        """is_wctype emulation (obsolete alias of iswctype)"""
        return self.iswctype(args)

    def _isctype(self, args):
        """_isctype emulation"""
        ch = args[0] & 0xFFFFFFFF
        if ch > 0xFF:
            return 0
        return self._wctype_mask(ch) & (args[1] & 0xFFFF)

    # Multibyte <-> wide conversion (ANSI code page)
    def mbstowcs(self, args):
        """mbstowcs emulation"""
        units = self._text_units(self.read_string(args[1]), True)
        if not args[0]:
            return len(units)
        count = min(len(units), args[2])
        self._write_units(args[0], units[:count], True, terminate=count < args[2])
        return count

    def wcstombs(self, args):
        """wcstombs emulation"""
        units = self._text_units(self.read_wide_string(args[1]), False)
        if not args[0]:
            return len(units)
        count = min(len(units), args[2])
        self._write_units(args[0], units[:count], False, terminate=count < args[2])
        return count

    def _decode_mb_char(self, addr, n):
        """(wide unit, byte length) of the multibyte char at addr, or None."""
        try:
            data = bytes(self.emu.uc.mem_read(addr, min(n, 4)))
        except UcError:
            return None
        if not data or data[0] == 0:
            return 0, 0
        for k in range(1, len(data) + 1):
            try:
                ch = data[:k].decode(config.ANSI_CODEPAGE)
            except UnicodeDecodeError:
                continue
            return (ord(ch) if ord(ch) <= 0xFFFF else 0xFFFD), k
        return None

    def mbtowc(self, args):
        """mbtowc emulation"""
        if not args[1]:
            return 0
        decoded = self._decode_mb_char(args[1], args[2])
        if decoded is None:
            self._store_errno(42)  # EILSEQ
            return 0xFFFFFFFF
        if args[0]:
            self._mem_write(args[0], struct.pack('<H', decoded[0]))
        return decoded[1]

    def mblen(self, args):
        """mblen emulation"""
        if not args[0]:
            return 0
        decoded = self._decode_mb_char(args[0], args[1])
        return 0xFFFFFFFF if decoded is None else decoded[1]

    def wctomb(self, args):
        """wctomb emulation"""
        if not args[0]:
            return 0
        data = chr(args[1] & 0xFFFF).encode(config.ANSI_CODEPAGE, errors='replace')
        self._mem_write(args[0], data)
        return len(data)

    # ---- Number conversion ----

    _FLOAT_RE = re.compile(
        r'[ \t\n\r\v\f]*([+-]?(?:0[xX](?:[0-9a-fA-F]+\.?[0-9a-fA-F]*|\.[0-9a-fA-F]+)'
        r'(?:[pP][+-]?\d+)?|(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?|'
        r'inf(?:inity)?|nan))', re.IGNORECASE)

    def _parse_c_double(self, text):
        """strtod parsing: returns (value, characters consumed)."""
        match = self._FLOAT_RE.match(text)
        if not match:
            return 0.0, 0
        token = match.group(1)
        unsigned = token.lstrip('+-')
        if unsigned[:2].lower() == '0x':
            value = float.fromhex(token)
        else:
            value = float(token)
        if math.isinf(value) and not unsigned[:1].lower() == 'i':
            self._store_errno(self.ERANGE)
        return value, match.end()

    def _string_arg_text(self, addr, wide):
        """String argument as text whose indices equal unit offsets."""
        return ''.join(map(chr, self._read_units(addr, wide)))

    def _strtod_common(self, args, wide):
        nptr, endptr = args[0], args[1]
        value, consumed = self._parse_c_double(self._string_arg_text(nptr, wide))
        if endptr:
            self._mem_write(endptr, struct.pack('<I', nptr + consumed * (2 if wide else 1)))
        return X87Result(value)

    def strtod(self, args):
        """strtod emulation"""
        return self._strtod_common(args, False)

    def wcstod(self, args):
        """wcstod emulation"""
        return self._strtod_common(args, True)

    def atof(self, args):
        """atof emulation"""
        return self._strtod_common([args[0], 0], False)

    def _wtof(self, args):
        """_wtof emulation"""
        return self._strtod_common([args[0], 0], True)

    def _strtoint_common(self, args, wide, bits, signed):
        """strtol-family core: clamps with ERANGE like the CRT."""
        nptr, endptr, base = args[0], args[1], args[2]
        value, consumed = self._parse_c_integer(self._string_arg_text(nptr, wide), base)
        if endptr:
            self._mem_write(endptr, struct.pack('<I', nptr + consumed * (2 if wide else 1)))
        if signed:
            lo, hi = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
        else:
            lo, hi = -((1 << bits) - 1), (1 << bits) - 1  # negation wraps for unsigned
        if value > hi or value < lo:
            self._store_errno(self.ERANGE)
            value = hi if value > hi else (lo if signed else hi)
        value &= (1 << bits) - 1
        return QWordResult(value) if bits == 64 else value

    def wcstol(self, args):
        return self._strtoint_common(args, True, 32, True)

    def wcstoul(self, args):
        return self._strtoint_common(args, True, 32, False)

    def _strtoi64(self, args):
        return self._strtoint_common(args, False, 64, True)

    def _strtoui64(self, args):
        return self._strtoint_common(args, False, 64, False)

    def strtoll(self, args):
        return self._strtoi64(args)

    def strtoull(self, args):
        return self._strtoui64(args)

    def _wcstoi64(self, args):
        return self._strtoint_common(args, True, 64, True)

    def _wcstoui64(self, args):
        return self._strtoint_common(args, True, 64, False)

    def _atoi64(self, args):
        """_atoi64 emulation"""
        value, _ = self._parse_c_integer(self._string_arg_text(args[0], False), 10)
        return QWordResult(value)

    def atoll(self, args):
        return self._atoi64(args)

    def _wtoi(self, args):
        """_wtoi emulation"""
        value, _ = self._parse_c_integer(self._string_arg_text(args[0], True), 10)
        return value & 0xFFFFFFFF

    def _wtol(self, args):
        return self._wtoi(args)

    def _wtoi64(self, args):
        value, _ = self._parse_c_integer(self._string_arg_text(args[0], True), 10)
        return QWordResult(value)

    @staticmethod
    def _int_to_units(value, radix, wide):
        digits = '0123456789abcdefghijklmnopqrstuvwxyz'
        if not 2 <= radix <= 36:
            radix = 10
        neg = value < 0
        v = -value if neg else value
        out = ''
        while True:
            out = digits[v % radix] + out
            v //= radix
            if not v:
                break
        return [ord(c) for c in ('-' + out if neg else out)]

    def _i64toa(self, args):
        """_i64toa emulation (value, buffer, radix)"""
        value = self._signed64(self._arg_qword(args, 0))
        radix = args[3]
        if radix != 10:
            value &= (1 << 64) - 1
        self._write_units(args[2], self._int_to_units(value, radix, False), False)
        return args[2]

    def _ui64toa(self, args):
        """_ui64toa emulation"""
        units = self._int_to_units(self._arg_qword(args, 0), args[3], False)
        self._write_units(args[2], units, False)
        return args[2]

    def _i64tow(self, args):
        value = self._signed64(self._arg_qword(args, 0))
        if args[3] != 10:
            value &= (1 << 64) - 1
        self._write_units(args[2], self._int_to_units(value, args[3], True), True)
        return args[2]

    def _itow(self, args):
        """_itow emulation"""
        value = self._signed32(args[0]) if args[2] == 10 else args[0]
        self._write_units(args[1], self._int_to_units(value, args[2], True), True)
        return args[1]

    def _ltow(self, args):
        return self._itow(args)

    def _ultow(self, args):
        self._write_units(args[1], self._int_to_units(args[0], args[2], True), True)
        return args[1]

    def _itoa_s(self, args):
        """_itoa_s emulation (value, buffer, size, radix)"""
        value = self._signed32(args[0]) if args[3] == 10 else args[0]
        units = self._int_to_units(value, args[3], False)
        return self._secure_copy(args[1], args[2], units, False)

    def _abs64(self, args):
        """_abs64 emulation"""
        return QWordResult(abs(self._signed64(self._arg_qword(args, 0))))

    def llabs(self, args):
        return self._abs64(args)

    def div(self, args):
        """div emulation - div_t {quot, rem} returned in EDX:EAX"""
        num, den = self._signed32(args[0]), self._signed32(args[1])
        if den == 0:
            log.error("div: integer division by zero")
            self.emu.crashed = True
            self.emu.stop_emulation = True
            return QWordResult(0)
        quot = abs(num) // abs(den) * (1 if (num < 0) == (den < 0) else -1)
        rem = num - quot * den
        return QWordResult((quot & 0xFFFFFFFF) | ((rem & 0xFFFFFFFF) << 32))

    def ldiv(self, args):
        return self.div(args)

    def _rotl(self, args):
        """_rotl emulation"""
        value, shift = args[0] & 0xFFFFFFFF, args[1] & 31
        return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF

    def _rotr(self, args):
        """_rotr emulation"""
        value, shift = args[0] & 0xFFFFFFFF, args[1] & 31
        return ((value >> shift) | (value << (32 - shift))) & 0xFFFFFFFF

    def _lrotl(self, args):
        return self._rotl(args)

    def _lrotr(self, args):
        return self._rotr(args)

    def _swab(self, args):
        """_swab emulation - swap adjacent bytes"""
        n = args[2] & ~1
        try:
            data = bytearray(self.emu.uc.mem_read(args[0], n))
        except UcError:
            return 0
        data[0::2], data[1::2] = data[1::2], data[0::2]
        self._mem_write(args[1], data)
        return 0

    # ---- Paths ----

    def _splitpath(self, args):
        """_splitpath emulation (path, drive, dir, fname, ext)"""
        path = self.read_string(args[0])
        drive = path[:2] if len(path) >= 2 and path[1] == ':' else ''
        rest = path[len(drive):]
        cut = max(rest.rfind('\\'), rest.rfind('/')) + 1
        directory, name = rest[:cut], rest[cut:]
        dot = name.rfind('.')
        fname, ext = (name[:dot], name[dot:]) if dot != -1 else (name, '')
        for addr, part in zip(args[1:5], (drive, directory, fname, ext), strict=True):
            if addr:
                self._write_units(addr, self._text_units(part, False), False)
        return 0

    def _makepath(self, args):
        """_makepath emulation (path, drive, dir, fname, ext)"""
        drive, directory, fname, ext = (self.read_string(a) if a else '' for a in args[1:5])
        if drive and not drive.endswith(':'):
            drive += ':'
        if directory and directory[-1] not in '\\/':
            directory += '\\'
        if ext and not ext.startswith('.'):
            ext = '.' + ext
        self._write_units(args[0], self._text_units(drive + directory + fname + ext, False), False)
        return 0

    def _fullpath(self, args):
        """_fullpath emulation - resolve against the current directory"""
        full = self.full_windows_path(self.read_string(args[1]), clamp=True)
        if full is None:
            self._store_errno(self.EINVAL)
            return 0
        units = self._text_units(full.rstrip('\\') if len(full) > 3 else full, False)
        if not args[0]:
            return self._alloc_units(units, False)
        if len(units) >= args[2]:
            self._store_errno(self.ERANGE)
            return 0
        self._write_units(args[0], units, False)
        return args[0]

    # ---- Environment ----

    def _getenv_common(self, name, wide):
        value = self.environment.get(name.upper())
        if value is None:
            return 0
        key = (name.upper(), wide)
        cached = self._getenv_cache.get(key)
        if cached and cached[0] == value:
            return cached[1]
        addr = self._alloc_units(self._text_units(value, wide), wide)
        self._getenv_cache[key] = (value, addr)
        return addr

    def getenv(self, args):
        """getenv emulation"""
        return self._getenv_common(self.read_string(args[0]), False)

    def _wgetenv(self, args):
        """_wgetenv emulation"""
        return self._getenv_common(self.read_wide_string(args[0]), True)

    def _putenv_common(self, text):
        name, sep, value = text.partition('=')
        if not sep or not name:
            self._store_errno(self.EINVAL)
            return 0xFFFFFFFF
        if value:
            self.environment[name.upper()] = value
        else:
            self.environment.pop(name.upper(), None)
        self._update_environ()
        return 0

    def _putenv(self, args):
        """_putenv emulation ("NAME=value", empty value removes)"""
        return self._putenv_common(self.read_string(args[0]))

    def putenv(self, args):
        return self._putenv(args)

    def _wputenv(self, args):
        return self._putenv_common(self.read_wide_string(args[0]))

    def _get_narrow_winmain_command_line(self, args):
        """UCRT: command line after the program name (WinMain lpCmdLine)"""
        return self._winmain_command_line(False)

    def _get_wide_winmain_command_line(self, args):
        return self._winmain_command_line(True)

    def _winmain_command_line(self, wide):
        key = 'winmain_cmdline_w' if wide else 'winmain_cmdline'
        if key not in self._crt_static:
            line = self.windows_command_line()
            if line.startswith('"'):
                end = line.find('"', 1)
                rest = line[end + 1:] if end != -1 else ''
            else:
                rest = line.partition(' ')[2]
            units = self._text_units(rest.lstrip(' \t'), wide)
            self._crt_static[key] = self._alloc_units(units, wide)
        return self._crt_static[key]

    # ---- Process control and signals ----

    SIGINT, SIGILL, SIGFPE, SIGSEGV, SIGTERM, SIGBREAK, SIGABRT = 2, 4, 8, 11, 15, 21, 22

    def _crt_terminate(self, code, message=None):
        if message:
            self._ensure_iob()
            self.std_streams[2].write(message.encode(config.ANSI_CODEPAGE, errors='replace'))
        self._set_exit_code(code)
        self.flush_std_streams()
        self.emu.stop_emulation = True
        return 0

    def system(self, args):
        """system emulation - there is no command processor"""
        if not args[0]:
            return 0
        log.warning(f"system(\"{self.read_string(args[0])}\") is not supported")
        self._store_errno(self.ENOENT)
        return 0xFFFFFFFF

    def abort(self, args):
        """abort emulation - raise(SIGABRT), then exit code 3"""
        handler = self._signal_handlers.get(self.SIGABRT, 0)
        if handler not in (0, 1):
            self._signal_handlers[self.SIGABRT] = 0
            self.emu.call_callback(handler, [self.SIGABRT])
        return self._crt_terminate(3, "\nabnormal program termination\n")

    def terminate(self, args):
        return self.abort(args)

    def _purecall(self, args):
        """_purecall emulation - a pure virtual function was called"""
        log.error("Pure virtual function call (_purecall)")
        return self._crt_terminate(3, "\nR6025 - pure virtual function call\n")

    def quick_exit(self, args):
        return self._exit(args)

    def _c_exit(self, args):
        """_c_exit emulation - flush without running exit handlers"""
        self.flush_std_streams()
        return 0

    def signal(self, args):
        """signal emulation - returns the previous handler"""
        sig, handler = args[0], args[1]
        if sig not in (self.SIGINT, self.SIGILL, self.SIGFPE, self.SIGSEGV,
                       self.SIGTERM, self.SIGBREAK, self.SIGABRT, 6):
            self._store_errno(self.EINVAL)
            return 0xFFFFFFFF  # SIG_ERR
        previous = self._signal_handlers.get(sig, 0)
        self._signal_handlers[sig] = handler
        return previous

    def _crt_raise(self, args):
        """raise emulation"""
        sig = args[0]
        handler = self._signal_handlers.get(sig, 0)
        if handler == 1:  # SIG_IGN
            return 0
        if handler == 0:  # SIG_DFL terminates the process
            return self._crt_terminate(3)
        self._signal_handlers[sig] = 0  # reset to SIG_DFL before the call
        self.emu.call_callback(handler, [sig])
        return 0

    def _sleep(self, args):
        """_sleep emulation"""
        return self.Sleep(args)

    # ---- Non-local jumps (MSVC _JUMP_BUFFER: Ebp Ebx Edi Esi Esp Eip ...) ----

    def _setjmp(self, args):
        """_setjmp emulation - save the caller's context; returns 0"""
        buf = args[0]
        esp = self.emu.api_call_esp
        ret_addr = self._read_u32(esp)
        uc = self.emu.uc
        context = struct.pack('<6I', uc.reg_read(UC_X86_REG_EBP), uc.reg_read(UC_X86_REG_EBX),
                              uc.reg_read(UC_X86_REG_EDI), uc.reg_read(UC_X86_REG_ESI),
                              esp + 4, ret_addr)
        self._mem_write(buf, context + b'\x00' * 40)
        return 0

    def _setjmp3(self, args):
        return self._setjmp(args)

    def setjmp(self, args):
        return self._setjmp(args)

    def longjmp(self, args):
        """longjmp emulation - resume after the matching setjmp"""
        buf, value = args[0], args[1]
        try:
            ebp, ebx, edi, esi, esp, eip = struct.unpack('<6I', self.emu.uc.mem_read(buf, 24))
        except UcError:
            ebp = ebx = edi = esi = esp = eip = 0
        if not eip:
            log.error("longjmp with an uninitialized jmp_buf")
            self.emu.crashed = True
            self.emu.stop_emulation = True
            return 0
        # (the registers are set where the jump lands, also outside a callback)
        return ApiJump(eip, esp, value or 1, ebp=ebp,
                       regs={'ebx': ebx, 'edi': edi, 'esi': esi})

    # ---- Time ----

    _DAY_NAMES = ('Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday')
    _MONTH_NAMES = ('January', 'February', 'March', 'April', 'May', 'June', 'July',
                    'August', 'September', 'October', 'November', 'December')

    @staticmethod
    def _struct_time_to_tm(st):
        """Python struct_time -> C struct tm fields."""
        return [st.tm_sec, st.tm_min, st.tm_hour, st.tm_mday, st.tm_mon - 1,
                st.tm_year - 1900, (st.tm_wday + 1) % 7, st.tm_yday - 1,
                max(st.tm_isdst, 0)]

    def _read_tm(self, addr):
        try:
            return list(struct.unpack('<9i', self.emu.uc.mem_read(addr, 36)))
        except UcError:
            return None

    def _time_to_tm(self, t, local, buffer_name='tm'):
        """Fill the static struct tm for time_t t (NULL for invalid times)."""
        if t < 0:
            self._store_errno(self.EINVAL)
            return 0
        try:
            st = time.localtime(t) if local else time.gmtime(t)
        except (OverflowError, OSError, ValueError):
            self._store_errno(self.EINVAL)
            return 0
        buf = self._static_buffer(buffer_name, 36)
        self._mem_write(buf, struct.pack('<9i', *self._struct_time_to_tm(st)))
        return buf

    def _read_time_arg(self, ptr, bits):
        """Read a time_t through a pointer (32- or 64-bit)."""
        if not ptr:
            return None
        try:
            if bits == 64:
                return struct.unpack('<q', self.emu.uc.mem_read(ptr, 8))[0]
            return struct.unpack('<i', self.emu.uc.mem_read(ptr, 4))[0]
        except UcError:
            return None

    def _tm_time_common(self, ptr, bits, local):
        t = self._read_time_arg(ptr, bits)
        if t is None:
            self._store_errno(self.EINVAL)
            return 0
        return self._time_to_tm(t, local)

    def localtime(self, args):
        """localtime emulation (32-bit time_t)"""
        return self._tm_time_common(args[0], 32, True)

    def _localtime32(self, args):
        return self._tm_time_common(args[0], 32, True)

    def _localtime64(self, args):
        return self._tm_time_common(args[0], 64, True)

    def gmtime(self, args):
        """gmtime emulation (32-bit time_t)"""
        return self._tm_time_common(args[0], 32, False)

    def _gmtime32(self, args):
        return self._tm_time_common(args[0], 32, False)

    def _gmtime64(self, args):
        return self._tm_time_common(args[0], 64, False)

    def _tm_s_common(self, args, bits, local):
        """localtime_s/gmtime_s style: (struct tm *dest, const time_t *t) -> errno"""
        t = self._read_time_arg(args[1], bits)
        if not args[0] or t is None:
            return self.EINVAL
        src = self._time_to_tm(t, local, buffer_name='tm_s')
        if not src:
            return self.EINVAL
        self.memcpy([args[0], src, 36])
        return 0

    def _localtime32_s(self, args):
        return self._tm_s_common(args, 32, True)

    def _localtime64_s(self, args):
        return self._tm_s_common(args, 64, True)

    def _gmtime32_s(self, args):
        return self._tm_s_common(args, 32, False)

    def _gmtime64_s(self, args):
        return self._tm_s_common(args, 64, False)

    def _mktime_common(self, tm_addr, bits, local):
        """mktime/_mkgmtime: normalize struct tm in place, return time_t."""
        fields = self._read_tm(tm_addr) if tm_addr else None
        fail = QWordResult(-1) if bits == 64 else 0xFFFFFFFF
        if fields is None:
            self._store_errno(self.EINVAL)
            return fail
        sec, minute, hour, mday, mon, year, _, _, isdst = fields
        year += 1900 + mon // 12
        mon %= 12
        try:
            import datetime
            base = datetime.datetime(year, mon + 1, 1)
            dt = base + datetime.timedelta(days=mday - 1, hours=hour, minutes=minute, seconds=sec)
            if local:
                t = int(time.mktime(dt.timetuple()[:8] + (isdst if isdst >= 0 else -1,)))
            else:
                import calendar
                t = calendar.timegm(dt.timetuple())
        except (OverflowError, ValueError, OSError):
            return fail
        if t < 0 or (bits == 32 and t > 0x7FFFFFFF):
            return fail
        st = time.localtime(t) if local else time.gmtime(t)
        self._mem_write(tm_addr, struct.pack('<9i', *self._struct_time_to_tm(st)))
        return QWordResult(t) if bits == 64 else t

    def mktime(self, args):
        """mktime emulation"""
        return self._mktime_common(args[0], 32, True)

    def _mktime32(self, args):
        return self._mktime_common(args[0], 32, True)

    def _mktime64(self, args):
        return self._mktime_common(args[0], 64, True)

    def _mkgmtime(self, args):
        return self._mktime_common(args[0], 32, False)

    def _mkgmtime32(self, args):
        return self._mktime_common(args[0], 32, False)

    def _mkgmtime64(self, args):
        return self._mktime_common(args[0], 64, False)

    def difftime(self, args):
        """difftime emulation (32-bit time_t)"""
        return X87Result(self._signed32(args[0]) - self._signed32(args[1]))

    def _difftime32(self, args):
        return self.difftime(args)

    def _difftime64(self, args):
        """_difftime64 emulation"""
        return X87Result(self._signed64(self._arg_qword(args, 0)) -
                         self._signed64(self._arg_qword(args, 2)))

    def _time_common(self, ptr, bits):
        t = int(time.time())
        if ptr:
            self._mem_write(ptr, struct.pack('<q' if bits == 64 else '<i', t))
        return QWordResult(t) if bits == 64 else t & 0xFFFFFFFF

    def _time32(self, args):
        return self._time_common(args[0], 32)

    def _time64(self, args):
        """_time64 emulation"""
        return self._time_common(args[0], 64)

    def _asctime_text(self, fields):
        sec, minute, hour, mday, mon, year, wday = fields[:7]
        return (f"{self._DAY_NAMES[wday % 7][:3]} {self._MONTH_NAMES[mon % 12][:3]} "
                f"{mday:02d} {hour:02d}:{minute:02d}:{sec:02d} {year + 1900}\n")

    def _asctime_store(self, fields, wide=False):
        if fields is None:
            self._store_errno(self.EINVAL)
            return 0
        buf = self._static_buffer('asctime_w' if wide else 'asctime', 64)
        self._write_units(buf, self._text_units(self._asctime_text(fields), wide), wide)
        return buf

    def asctime(self, args):
        """asctime emulation"""
        return self._asctime_store(self._read_tm(args[0]) if args[0] else None)

    def _ctime_common(self, ptr, bits, wide=False):
        t = self._read_time_arg(ptr, bits)
        tm = self._time_to_tm(t, True, buffer_name='ctime_tm') if t is not None else 0
        return self._asctime_store(self._read_tm(tm) if tm else None, wide)

    def ctime(self, args):
        """ctime emulation (32-bit time_t)"""
        return self._ctime_common(args[0], 32)

    def _ctime32(self, args):
        return self._ctime_common(args[0], 32)

    def _ctime64(self, args):
        return self._ctime_common(args[0], 64)

    def _wctime(self, args):
        return self._ctime_common(args[0], 32, wide=True)

    def _wctime64(self, args):
        return self._ctime_common(args[0], 64, wide=True)

    def _strftime_text(self, fmt, fields):
        """strftime for the "C" locale (supports the '#' flag)."""
        sec, minute, hour, mday, mon, year, wday, yday, isdst = fields
        year += 1900
        hour12 = hour % 12 or 12

        def week(first_day):  # %U (Sunday) / %W (Monday)
            offset = (wday - first_day) % 7
            return (yday + 7 - offset) // 7

        tz_name = time.tzname[1 if isdst > 0 else 0]
        tz_minutes = -(time.altzone if isdst > 0 else time.timezone) // 60
        out = []
        i = 0
        while i < len(fmt):
            ch = fmt[i]
            if ch != '%' or i + 1 >= len(fmt):
                out.append(ch)
                i += 1
                continue
            i += 1
            alt = fmt[i] == '#'
            if alt:
                i += 1
                if i >= len(fmt):
                    break
            spec = fmt[i]
            i += 1

            def num(value, width=2, alt=alt):
                return str(value) if alt else str(value).zfill(width)

            values = {
                'a': self._DAY_NAMES[wday % 7][:3], 'A': self._DAY_NAMES[wday % 7],
                'b': self._MONTH_NAMES[mon % 12][:3], 'h': self._MONTH_NAMES[mon % 12][:3],
                'B': self._MONTH_NAMES[mon % 12],
                'd': num(mday), 'e': f"{mday:2d}", 'H': num(hour), 'I': num(hour12),
                'j': num(yday + 1, 3), 'm': num(mon + 1), 'M': num(minute),
                'p': 'AM' if hour < 12 else 'PM', 'S': num(sec),
                'U': num(week(0)), 'W': num(week(1)), 'w': str(wday),
                'y': num(year % 100), 'Y': str(year), 'C': num(year // 100),
                'Z': tz_name,
                'z': (f"{'+' if tz_minutes >= 0 else '-'}"
                      f"{abs(tz_minutes) // 60:02d}{abs(tz_minutes) % 60:02d}"),
                'n': '\n', 't': '\t', '%': '%',
                'D': f"{mon + 1:02d}/{mday:02d}/{year % 100:02d}",
                'F': f"{year}-{mon + 1:02d}-{mday:02d}",
                'R': f"{hour:02d}:{minute:02d}", 'T': f"{hour:02d}:{minute:02d}:{sec:02d}",
                'r': f"{hour12:02d}:{minute:02d}:{sec:02d} {'AM' if hour < 12 else 'PM'}",
                'u': str(wday or 7),
            }
            if spec == 'c':
                out.append(f"{self._DAY_NAMES[wday % 7][:3]} {self._MONTH_NAMES[mon % 12][:3]} "
                           f"{mday:2d} {hour:02d}:{minute:02d}:{sec:02d} {year}"
                           if alt else
                           f"{mon + 1:02d}/{mday:02d}/{year % 100:02d} "
                           f"{hour:02d}:{minute:02d}:{sec:02d}")
            elif spec == 'x':
                out.append(f"{self._DAY_NAMES[wday % 7]}, {self._MONTH_NAMES[mon % 12]} "
                           f"{mday:02d}, {year}" if alt else values['D'])
            elif spec == 'X':
                out.append(values['T'])
            else:
                out.append(values.get(spec, ''))
        return ''.join(out)

    def _strftime_common(self, args, wide):
        buf, max_size, fmt_addr, tm_addr = args[0], args[1], args[2], args[3]
        fields = self._read_tm(tm_addr) if tm_addr else None
        if fields is None:
            self._store_errno(self.EINVAL)
            return 0
        text = self._strftime_text(self._read_text(fmt_addr, wide), fields)
        units = self._text_units(text, wide)
        if len(units) + 1 > max_size:
            if buf and max_size:
                self._write_units(buf, [], wide)
            self._store_errno(self.ERANGE)
            return 0
        self._write_units(buf, units, wide)
        return len(units)

    def strftime(self, args):
        """strftime emulation"""
        return self._strftime_common(args, False)

    def wcsftime(self, args):
        """wcsftime emulation"""
        return self._strftime_common(args, True)

    def _strdate(self, args):
        """_strdate emulation - "MM/DD/YY" """
        st = time.localtime()
        self._write_units(args[0], self._text_units(time.strftime('%m/%d/%y', st), False), False)
        return args[0]

    def _strtime(self, args):
        """_strtime emulation - "HH:MM:SS" """
        st = time.localtime()
        self._write_units(args[0], self._text_units(time.strftime('%H:%M:%S', st), False), False)
        return args[0]

    def _ftime_common(self, ptr, bits):
        now = time.time()
        st = time.localtime(now)
        tz = (time.altzone if st.tm_isdst > 0 else time.timezone) // 60
        fixed = struct.pack('<Hhh', int((now % 1) * 1000), tz, max(st.tm_isdst, 0))
        if bits == 64:
            data = struct.pack('<q', int(now)) + fixed + b'\x00\x00'
        else:
            data = struct.pack('<i', int(now)) + fixed + b'\x00\x00'
        if ptr:
            self._mem_write(ptr, data)
        return 0

    def _ftime(self, args):
        """_ftime emulation (struct _timeb with 32-bit time)"""
        return self._ftime_common(args[0], 32)

    def _ftime32(self, args):
        return self._ftime_common(args[0], 32)

    def _ftime64(self, args):
        return self._ftime_common(args[0], 64)

    def _tzset(self, args):
        return 0

    # ---- UCRT startup / runtime configuration ----

    def _set_app_type(self, args):
        return self.api__set_app_type(args)

    def _configure_narrow_argv(self, args):
        return 0

    def _configure_wide_argv(self, args):
        return 0

    def _initialize_narrow_environment(self, args):
        return 0

    def _initialize_wide_environment(self, args):
        return 0

    def _get_initial_narrow_environment(self, args):
        """UCRT: the initial char **environ"""
        return self._read_u32(self._ensure_env_ptr('_environ_ptr_addr'))

    def _get_initial_wide_environment(self, args):
        return self._read_u32(self._ensure_env_ptr('_wenviron_ptr_addr', wide=True))

    def _seh_filter_exe(self, args):
        return 0  # EXCEPTION_CONTINUE_SEARCH

    def _seh_filter_dll(self, args):
        return 0

    def _initialize_onexit_table(self, args):
        return 0

    def _register_onexit_function(self, args):
        """UCRT: register an exit handler (the table is kept internally)"""
        if args[1]:
            self.exit_handlers.append(args[1])
        return 0

    def _execute_onexit_table(self, args):
        return 0

    def _crt_atexit(self, args):
        return self.atexit(args)

    def _crt_at_quick_exit(self, args):
        return 0

    def _set_fmode(self, args):
        """_set_fmode emulation"""
        self._mem_write(self._ensure_fmode_addr(), struct.pack('<I', args[0]))
        return 0

    def _get_fmode(self, args):
        """_get_fmode emulation"""
        if args[0]:
            self._mem_write(args[0], struct.pack('<I', self._read_u32(self._ensure_fmode_addr())))
        return 0

    def _configthreadlocale(self, args):
        return 0

    def _set_new_mode(self, args):
        return 0

    def _register_thread_local_exe_atexit_callback(self, args):
        return 0

    def _set_invalid_parameter_handler(self, args):
        return 0

    def _set_abort_behavior(self, args):
        return 0

    def _invalid_parameter_noinfo(self, args):
        """Invalid parameter detected by a CRT function: fatal, like Windows"""
        return self._invoke_watson(args)

    def _invalid_parameter_noinfo_noreturn(self, args):
        return self._invoke_watson(args)

    def _get_errno(self, args):
        """_get_errno emulation"""
        if not args[0]:
            return self.EINVAL
        self._mem_write(args[0], struct.pack('<I', self._load_errno()))
        return 0

    def _set_errno(self, args):
        """_set_errno emulation"""
        self._store_errno(args[0])
        return 0


# ==================== PYGAME WINDOWS GUI ====================
