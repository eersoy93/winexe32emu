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

"""WinAPIHandler mixin: Basic CRT functions: strings, memory, printf, numbers, time"""

import re
import struct
import time

from unicorn import UcError

from .. import config
from ..logger import log


class CrtBasicMixin:
    """Basic CRT functions: strings, memory, printf, numbers, time"""

    # String functions
    def strlen(self, args):
        """strlen emulation"""
        s = args[0]
        data = self._read_until_null(s, 0x7FFFFFFF, 1) or b''
        log.debug(f"strlen(0x{s:08x}) -> {len(data)}")
        return len(data)

    def wcslen(self, args):
        """wcslen emulation"""
        # UTF-16 code units (a surrogate pair is 2) of a string of any length
        data = self._read_until_null(args[0], 0x8000000, 2) if args[0] else b''
        if data is None:
            self._string_access_violation(args[0])
            return 0
        return len(data) // 2

    def memset(self, args):
        """memset emulation"""
        dest = args[0]
        c = args[1] & 0xFF
        count = args[2]
        log.debug(f"memset(0x{dest:08x}, {c}, {count})")
        try:
            self.emu.uc.mem_write(dest, bytes([c]) * count)
        except UcError:
            pass
        return dest

    def memcpy(self, args):
        """memcpy emulation"""
        dest = args[0]
        src = args[1]
        count = args[2]
        log.debug(f"memcpy(0x{dest:08x}, 0x{src:08x}, {count})")
        try:
            # bytes(): unicorn's mem_write rejects the bytearray mem_read returns
            data = bytes(self.emu.uc.mem_read(src, count))
            self.emu.uc.mem_write(dest, data)
        except UcError as e:
            log.warning(f"memcpy(0x{dest:08x}, 0x{src:08x}, {count}) failed: {e}")
        return dest

    def memmove(self, args):
        """memmove emulation"""
        return self.memcpy(args)

    def memcmp(self, args):
        """memcmp emulation"""
        buf1 = args[0]
        buf2 = args[1]
        count = args[2]
        try:
            data1 = self.emu.uc.mem_read(buf1, count)
            data2 = self.emu.uc.mem_read(buf2, count)
            if data1 < data2:
                return -1
            elif data1 > data2:
                return 1
            return 0
        except UcError:
            return 0

    def strcpy(self, args):
        """strcpy emulation"""
        dest = args[0]
        src = args[1]
        data = self.read_cstring(src)
        try:
            self.emu.uc.mem_write(dest, data + b'\x00')
        except UcError:
            pass
        return dest

    def strncpy(self, args):
        """strncpy emulation"""
        dest = args[0]
        src = args[1]
        count = args[2]
        data = self.read_cstring(src, count)
        data += b'\x00' * (count - len(data))
        try:
            self.emu.uc.mem_write(dest, data)
        except UcError:
            pass
        return dest

    def strcmp(self, args):
        """strcmp emulation"""
        s1 = self.read_string(args[0])
        s2 = self.read_string(args[1])
        if s1 < s2:
            return -1
        elif s1 > s2:
            return 1
        return 0

    def _stricmp(self, args):
        """_stricmp emulation (case-insensitive)"""
        s1 = self.read_string(args[0]).lower()
        s2 = self.read_string(args[1]).lower()
        if s1 < s2:
            return -1
        elif s1 > s2:
            return 1
        return 0

    def strcat(self, args):
        """strcat emulation"""
        dest = args[0]
        src = args[1]
        dest_len = len(self.read_cstring(dest))
        data = self.read_cstring(src)
        try:
            self.emu.uc.mem_write(dest + dest_len, data + b'\x00')
        except UcError:
            pass
        return dest

    _FORMAT_SPEC_RE = re.compile(
        r'%([-+ #0]*)(\*|\d+)?(?:\.(\*|\d*))?'
        r'(hh|h|ll|l|L|I64|I32|I|j|z|t|w)?([diouxXcCsSpnfFeEgGaA%])')

    def _format_string(self, fmt, varargs, wide_fmt=False):
        """printf/wsprintf style formatting with 32-bit stack arguments.

        Supports flags (-+ #0), '*' width/precision, length modifiers
        (hh h l ll L I I32 I64 j z t w) and d i o u x X c C s S p n f F e E
        g G a A. 64-bit integers and doubles consume two stack slots.
        varargs is the argument list starting at the first value.
        wide_fmt selects the wprintf meaning of %s/%c (wide by default).
        """
        result = []
        arg_index = 0

        def next_arg():
            nonlocal arg_index
            value = varargs[arg_index] if arg_index < len(varargs) else 0
            arg_index += 1
            return value

        def next_qword():
            low = next_arg()
            return low | (next_arg() << 32)

        i = 0
        while i < len(fmt):
            ch = fmt[i]
            if ch != '%':
                result.append(ch)
                i += 1
                continue

            spec = self._FORMAT_SPEC_RE.match(fmt, i)
            if not spec:
                result.append(ch)
                i += 1
                continue
            i = spec.end()

            flags, width, precision, length, conv = spec.groups()
            if conv == '%':
                result.append('%')
                continue

            if width == '*':
                w = next_arg()
                w = w - 0x100000000 if w >= 0x80000000 else w
                if w < 0:
                    flags += '-'
                    w = -w
                width = str(w)
            if precision == '*':
                p = next_arg()
                precision = None if p >= 0x80000000 else str(p)
            elif precision == '':
                precision = '0'

            wide64 = length in ('ll', 'I64', 'j')

            if conv in 'diouxX':
                value = next_qword() if wide64 else next_arg()
                bits = 64 if wide64 else 32
                if length == 'hh':
                    bits = 8
                elif length == 'h':
                    bits = 16
                value &= (1 << bits) - 1
                if conv in 'di':
                    if value >= 1 << (bits - 1):
                        value -= 1 << bits
                    py_conv = 'd'
                else:
                    py_conv = conv
                py_flags = flags.replace('#', '') if conv in 'diu' else flags
                if conv == 'u':
                    py_conv = 'd'
                text = ('%' + py_flags + (width or '') +
                        ('.' + precision if precision is not None else '') +
                        py_conv) % value
                if conv == 'o' and '#' in flags:
                    text = text.replace('0o', '0', 1)
            elif conv in 'fFeEgGaA':
                value = struct.unpack('<d', struct.pack('<Q', next_qword()))[0]
                if conv in 'aA':
                    text = value.hex()
                    if conv == 'A':
                        text = text.upper()
                    text = ('%' + flags.replace('0', '').replace('#', '') +
                            (width or '') + 's') % text
                else:
                    text = ('%' + flags + (width or '') +
                            ('.' + precision if precision is not None else '') +
                            conv) % value
            elif conv == 'p':
                text = ('%' + flags.replace('#', '').replace('0', '') +
                        (width or '') + 's') % format(next_arg(), '08X')
            elif conv == 'n':
                next_arg()  # pointer to the count; not written
                continue
            elif conv in 'cC':
                value = next_arg()
                if self._wide_spec(conv, length, wide_fmt):
                    text = chr(value & 0xFFFF)
                else:
                    text = bytes([value & 0xFF]).decode(config.ANSI_CODEPAGE, errors='replace')
                text = ('%' + flags.replace('0', '') + (width or '') + 's') % text
            else:  # 's' / 'S'
                ptr = next_arg()
                wide = self._wide_spec(conv, length, wide_fmt)
                if not ptr:
                    text = "(null)"
                elif wide:
                    text = self.read_wide_string(ptr)
                else:
                    text = self.read_string(ptr)
                text = ('%' + flags.replace('0', '').replace('#', '') +
                        (width or '') +
                        ('.' + precision if precision is not None else '') +
                        's') % text

            result.append(text)

        return ''.join(result)

    @staticmethod
    def _wide_spec(conv, length, wide_fmt):
        """Whether a %c/%s style conversion refers to wide characters."""
        if length in ('l', 'w'):
            return True
        if length == 'h':
            return False
        return conv.isupper() != wide_fmt

    def wsprintfA(self, args, varargs=None):
        """wsprintfA emulation (user32, cdecl varargs)"""
        buf = args[0]
        fmt = self.read_string(args[1])
        text = self._format_string(fmt, args[2:] if varargs is None else varargs)
        data = text.encode(config.ANSI_CODEPAGE, errors='replace')[:1023]
        log.debug(f"wsprintfA(0x{buf:08x}, \"{fmt}\") -> \"{text}\"")
        try:
            self.emu.uc.mem_write(buf, data + b'\x00')
        except UcError:
            pass
        return len(data)

    def wvsprintfA(self, args):
        """wvsprintfA emulation (stdcall, arguments in a va_list)"""
        return self.wsprintfA(args, self._va_args(args[2]))

    def sprintf(self, args):
        """sprintf emulation"""
        buf = args[0]
        fmt = self.read_string(args[1])
        text = self._format_string(fmt, args[2:])
        data = text.encode(config.ANSI_CODEPAGE, errors='replace')
        log.debug(f"sprintf(0x{buf:08x}, \"{fmt}\") -> \"{text}\"")
        try:
            self.emu.uc.mem_write(buf, data + b'\x00')
        except UcError:
            pass
        return len(data)

    def _stdout_stream(self):
        self._ensure_iob()
        return self.std_streams[1]

    def printf(self, args):
        """printf emulation"""
        fmt = self.read_string(args[0])
        data = self._format_string(fmt, args[1:]).encode(config.ANSI_CODEPAGE, errors='replace')
        self._stdout_stream().write(data)
        return len(data)

    def puts(self, args):
        """puts emulation"""
        s = self.read_string(args[0])
        self._stdout_stream().write((s + "\n").encode(config.ANSI_CODEPAGE, errors='replace'))
        return len(s) + 1

    # Numeric / time CRT functions
    def rand(self, args):
        """rand emulation (MSVC-compatible LCG, returns 0..0x7FFF)"""
        self._rand_seed = (self._rand_seed * 214013 + 2531011) & 0xFFFFFFFF
        return (self._rand_seed >> 16) & 0x7FFF

    def srand(self, args):
        """srand emulation"""
        self._rand_seed = args[0] & 0xFFFFFFFF
        log.debug(f"srand({args[0]})")
        return 0

    def time(self, args):
        """time emulation - Unix timestamp (time_t as 32-bit)"""
        lpTime = args[0]
        t = int(time.time()) & 0xFFFFFFFF
        if lpTime:
            try:
                self.emu.uc.mem_write(lpTime, struct.pack("<I", t))
            except UcError:
                pass
        log.debug(f"time() -> {t}")
        return t

    def clock(self, args):
        """clock emulation - milliseconds since start (CLOCKS_PER_SEC=1000)"""
        return int((time.time() - self._clock_epoch) * 1000) & 0xFFFFFFFF

    def abs(self, args):
        """abs emulation"""
        v = args[0] - 0x100000000 if args[0] >= 0x80000000 else args[0]
        return (v if v >= 0 else -v) & 0xFFFFFFFF

    def labs(self, args):
        """labs emulation (long == int on win32)"""
        return self.abs(args)

    def atoi(self, args):
        """atoi emulation"""
        s = self.read_string(args[0]).strip()
        sign = 1
        if s[:1] in ('+', '-'):
            if s[0] == '-':
                sign = -1
            s = s[1:]
        digits = ''
        for ch in s:
            if not ch.isdigit():
                break
            digits += ch
        value = sign * int(digits) if digits else 0
        log.debug(f"atoi -> {value}")
        return value & 0xFFFFFFFF

    def atol(self, args):
        """atol emulation (long == int on win32)"""
        return self.atoi(args)
