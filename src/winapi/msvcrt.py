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

"""WinAPIHandler mixin: msvcrt: character classes, string functions, stdio, variables
(the "C" locale)"""

import os
import struct
import time
from functools import cmp_to_key

from unicorn import UcError

from .. import config
from ..guest import ConsoleStream, _ScanSource
from ..logger import log


class MsvcrtMixin:
    """msvcrt: character classes, string functions, stdio, variables (the "C" locale)"""

    # ---- Character classification / conversion (msvcrt) ----
    # These take an int (the character promoted to int) and return an int.

    def isalpha(self, args):
        """isalpha emulation"""
        c = args[0] & 0xFF
        return 1 if chr(c).isalpha() else 0

    def isdigit(self, args):
        """isdigit emulation"""
        c = args[0] & 0xFF
        return 1 if 0x30 <= c <= 0x39 else 0

    def isalnum(self, args):
        """isalnum emulation"""
        c = args[0] & 0xFF
        return 1 if chr(c).isalnum() else 0

    def isspace(self, args):
        """isspace emulation"""
        c = args[0] & 0xFF
        return 1 if c in (0x20, 0x09, 0x0A, 0x0B, 0x0C, 0x0D) else 0

    def isupper(self, args):
        """isupper emulation"""
        c = args[0] & 0xFF
        return 1 if 0x41 <= c <= 0x5A else 0

    def islower(self, args):
        """islower emulation"""
        c = args[0] & 0xFF
        return 1 if 0x61 <= c <= 0x7A else 0

    def isxdigit(self, args):
        """isxdigit emulation"""
        c = args[0] & 0xFF
        return 1 if chr(c) in "0123456789abcdefABCDEF" else 0

    def ispunct(self, args):
        """ispunct emulation"""
        c = args[0] & 0xFF
        return 1 if 0x21 <= c <= 0x7E and not chr(c).isalnum() else 0

    def iscntrl(self, args):
        """iscntrl emulation"""
        c = args[0] & 0xFF
        return 1 if c < 0x20 or c == 0x7F else 0

    def isprint(self, args):
        """isprint emulation"""
        c = args[0] & 0xFF
        return 1 if 0x20 <= c <= 0x7E else 0

    def isgraph(self, args):
        """isgraph emulation"""
        c = args[0] & 0xFF
        return 1 if 0x21 <= c <= 0x7E else 0

    def toupper(self, args):
        """toupper emulation"""
        c = args[0] & 0xFF
        return (c - 0x20) if 0x61 <= c <= 0x7A else c

    def tolower(self, args):
        """tolower emulation"""
        c = args[0] & 0xFF
        return (c + 0x20) if 0x41 <= c <= 0x5A else c

    # msvcrt exposes some ctype helpers with a leading underscore too
    def _toupper(self, args):
        return self.toupper(args)

    def _tolower(self, args):
        return self.tolower(args)

    # ---- Additional string functions (msvcrt) ----

    def strchr(self, args):
        """strchr emulation - pointer to first occurrence of a char (or NULL)"""
        s_addr = args[0]
        c = args[1] & 0xFF
        data = self.read_cstring(s_addr) + b'\x00'  # c may be the terminator
        idx = data.find(bytes([c]))
        return s_addr + idx if s_addr and idx != -1 else 0

    def strrchr(self, args):
        """strrchr emulation - pointer to last occurrence of a char (or NULL)"""
        s_addr = args[0]
        c = args[1] & 0xFF
        data = self.read_cstring(s_addr) + b'\x00'
        idx = data.rfind(bytes([c]))
        return s_addr + idx if s_addr and idx != -1 else 0

    def strstr(self, args):
        """strstr emulation - pointer to first occurrence of a substring"""
        hay_addr = args[0]
        needle = self.read_string(args[1])
        haystack = self.read_string(hay_addr)
        if needle == "":
            return hay_addr
        idx = haystack.find(needle)
        if idx == -1:
            return 0
        # byte offset (haystack is decoded, but ASCII examples map 1:1)
        return hay_addr + len(haystack[:idx].encode(config.ANSI_CODEPAGE, errors='replace'))

    def strncmp(self, args):
        """strncmp emulation"""
        n = args[2]
        if n == 0:
            return 0
        # Up to n bytes of each string (the terminator compares too); n may
        # be far bigger than the strings (strncmp(a, b, SIZE_MAX))
        limit = min(n, 0x10000)
        d1 = self.read_cstring(args[0], limit)[:limit] + b'\x00'
        d2 = self.read_cstring(args[1], limit)[:limit] + b'\x00'
        for a, b in zip(d1[:n], d2[:n], strict=False):
            if a != b:
                return 0xFFFFFFFF if a < b else 1
            if a == 0:
                break
        return 0

    def _strnicmp(self, args):
        """_strnicmp / strnicmp emulation (case-insensitive, n bytes)"""
        n = args[2]
        s1 = self.read_string(args[0], n).lower()
        s2 = self.read_string(args[1], n).lower()
        s1, s2 = s1[:n], s2[:n]
        if s1 < s2:
            return -1
        elif s1 > s2:
            return 1
        return 0

    def strnicmp(self, args):
        return self._strnicmp(args)

    def strncat(self, args):
        """strncat emulation - append at most n chars"""
        dest = args[0]
        src = args[1]
        n = args[2]
        dest_len = len(self.read_cstring(dest))
        data = self.read_cstring(src, n)
        try:
            self.emu.uc.mem_write(dest + dest_len, data + b'\x00')
        except UcError:
            pass
        return dest

    def strspn(self, args):
        """strspn emulation - length of prefix consisting of accept chars"""
        s = self.read_string(args[0])
        accept = set(self.read_string(args[1]))
        count = 0
        for ch in s:
            if ch not in accept:
                break
            count += 1
        return count

    def strcspn(self, args):
        """strcspn emulation - length of prefix with no reject chars"""
        s = self.read_string(args[0])
        reject = set(self.read_string(args[1]))
        count = 0
        for ch in s:
            if ch in reject:
                break
            count += 1
        return count

    def strpbrk(self, args):
        """strpbrk emulation - pointer to first char that is in accept"""
        s_addr = args[0]
        s = self.read_string(s_addr)
        accept = set(self.read_string(args[1]))
        for i, ch in enumerate(s):
            if ch in accept:
                return s_addr + i
        return 0

    def _strrev(self, args):
        """_strrev emulation - reverse a string in place"""
        s_addr = args[0]
        s = self.read_string(s_addr)
        data = s[::-1].encode(config.ANSI_CODEPAGE, errors='replace')
        if not self._mem_write(s_addr, data + b'\x00'):
            log.warning(f"String function: cannot write to 0x{s_addr:08x}")
        return s_addr

    def _strlwr(self, args):
        """_strlwr emulation - lowercase in place"""
        s_addr = args[0]
        s = self.read_string(s_addr)
        data = s.lower().encode(config.ANSI_CODEPAGE, errors='replace')
        if not self._mem_write(s_addr, data + b'\x00'):
            log.warning(f"String function: cannot write to 0x{s_addr:08x}")
        return s_addr

    def _strupr(self, args):
        """_strupr emulation - uppercase in place"""
        s_addr = args[0]
        s = self.read_string(s_addr)
        data = s.upper().encode(config.ANSI_CODEPAGE, errors='replace')
        if not self._mem_write(s_addr, data + b'\x00'):
            log.warning(f"String function: cannot write to 0x{s_addr:08x}")
        return s_addr

    def _strdup(self, args):
        """_strdup emulation - allocate a copy of the string"""
        if not args[0]:
            return 0
        data = self.read_cstring(args[0]) + b'\x00'
        addr = self.emu.heap_alloc(len(data))
        if addr:
            self.emu.uc.mem_write(addr, data)
        return addr

    def strdup(self, args):
        return self._strdup(args)

    def memchr(self, args):
        """memchr emulation - pointer to first occurrence of a byte"""
        s_addr = args[0]
        c = args[1] & 0xFF
        n = args[2]
        try:
            data = self.emu.uc.mem_read(s_addr, n)
        except UcError:
            log.warning(f"memchr: cannot read 0x{s_addr:08x} (+{n})")
            return 0
        idx = data.find(bytes([c]))
        return (s_addr + idx) if idx != -1 else 0

    def _parse_c_integer(self, text, base):
        """Shared strtol/strtoul helper. Returns (value, chars_consumed)."""
        i = 0
        n = len(text)
        while i < n and text[i] in ' \t\n\r\v\f':
            i += 1
        sign = 1
        if i < n and text[i] in '+-':
            if text[i] == '-':
                sign = -1
            i += 1
        # Determine/skip base prefix ("0x"; an octal number's 0 is a digit)
        hex_prefix = text[i:i + 1] == '0' and text[i + 1:i + 2] in ('x', 'X')
        if base == 0:
            base = 16 if hex_prefix else 8 if text[i:i + 1] == '0' else 10
        if base == 16 and hex_prefix:
            if text[i + 2:i + 3].lower() not in tuple('0123456789abcdef'):
                return 0, i + 1  # "0x" without hex digits: the number is the 0
            i += 2
        digits = ''
        while i < n:
            ch = text[i].lower()
            if ch.isdigit():
                d = ord(ch) - ord('0')
            elif 'a' <= ch <= 'z':
                d = ord(ch) - ord('a') + 10
            else:
                break
            if d >= base:
                break
            digits += ch
            i += 1
        if digits == '':
            # No conversion performed
            return 0, 0
        value = sign * int(digits, base)
        return value, i

    def strtol(self, args):
        """strtol emulation (nptr, endptr, base)"""
        nptr = args[0]
        endptr = args[1]
        base = args[2]
        text = self.read_string(nptr)
        value, consumed = self._parse_c_integer(text, base)
        if endptr and not self._mem_write(endptr,
                                          struct.pack('<I', (nptr + consumed) & 0xFFFFFFFF)):
            log.warning(f"strtol/strtoul: cannot write the end pointer to 0x{endptr:08x}")
        # Clamp to signed long range
        if value > 0x7FFFFFFF:
            value = 0x7FFFFFFF
        elif value < -0x80000000:
            value = -0x80000000
        return value & 0xFFFFFFFF

    def strtoul(self, args):
        """strtoul emulation (nptr, endptr, base)"""
        nptr = args[0]
        endptr = args[1]
        base = args[2]
        text = self.read_string(nptr)
        value, consumed = self._parse_c_integer(text, base)
        if endptr and not self._mem_write(endptr,
                                          struct.pack('<I', (nptr + consumed) & 0xFFFFFFFF)):
            log.warning(f"strtol/strtoul: cannot write the end pointer to 0x{endptr:08x}")
        return value & 0xFFFFFFFF

    def _itoa(self, args):
        """_itoa emulation (value, buffer, radix)"""
        value = args[0]
        buf = args[1]
        radix = args[2] if args[2] else 10
        if radix == 10 and value >= 0x80000000:
            value -= 0x100000000  # signed for base 10
        if value == 0:
            text = '0'
        else:
            neg = value < 0
            v = abs(value)
            digs = '0123456789abcdefghijklmnopqrstuvwxyz'
            out = ''
            while v:
                out = digs[v % radix] + out
                v //= radix
            text = ('-' + out) if neg else out
        data = text.encode(config.ANSI_CODEPAGE, errors='replace')
        if not self._mem_write(buf, data + b'\x00'):
            log.warning(f"Integer to string: cannot write to 0x{buf:08x}")
        return buf

    def itoa(self, args):
        return self._itoa(args)

    def _ltoa(self, args):
        return self._itoa(args)

    def _ultoa(self, args):
        """_ultoa emulation (unsigned value, buffer, radix)"""
        value = args[0] & 0xFFFFFFFF
        buf = args[1]
        radix = args[2] if args[2] else 10
        if value == 0:
            text = '0'
        else:
            digs = '0123456789abcdefghijklmnopqrstuvwxyz'
            out = ''
            v = value
            while v:
                out = digs[v % radix] + out
                v //= radix
            text = out
        data = text.encode(config.ANSI_CODEPAGE, errors='replace')
        if not self._mem_write(buf, data + b'\x00'):
            log.warning(f"Integer to string: cannot write to 0x{buf:08x}")
        return buf

    def qsort(self, args):
        """qsort emulation (base, num, size, compar).

        Sorts an array in place by repeatedly invoking the C comparison
        callback. Each comparison copies the two candidate elements into
        scratch buffers and calls compar(&a, &b) via the callback machinery.
        """
        base = args[0]
        num = args[1]
        size = args[2]
        compar = args[3]
        if num <= 1 or size == 0 or base == 0 or compar == 0:
            return 0
        log.debug(f"qsort(0x{base:08x}, {num}, {size}, 0x{compar:08x})")
        try:
            elements = [bytes(self.emu.uc.mem_read(base + i * size, size))
                        for i in range(num)]
        except UcError:
            log.warning(f"qsort: cannot read the array at 0x{base:08x}")
            return 0

        # Two scratch buffers for the comparator arguments
        buf_a = self.emu.heap_alloc(size)
        buf_b = self.emu.heap_alloc(size)

        def cmp(a, b):
            self.emu.uc.mem_write(buf_a, a)
            self.emu.uc.mem_write(buf_b, b)
            r = self.emu.call_callback(compar, [buf_a, buf_b])
            # Return value is a signed int
            if r >= 0x80000000:
                r -= 0x100000000
            return r

        # An exception the comparison function throws (GuestUnwind) goes on
        # to the program's handler
        try:
            elements.sort(key=cmp_to_key(cmp))
            self.emu.uc.mem_write(base, b''.join(elements))
        except UcError as e:
            log.warning(f"qsort failed: {e}")
        finally:
            self.emu.heap_free(buf_a)
            self.emu.heap_free(buf_b)
        return 0

    def bsearch(self, args):
        """bsearch emulation (key, base, num, size, compar)"""
        key = args[0]
        base = args[1]
        num = args[2]
        size = args[3]
        compar = args[4]
        if num == 0 or size == 0 or base == 0 or compar == 0:
            return 0
        lo, hi = 0, num - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            elem_addr = base + mid * size
            r = self.emu.call_callback(compar, [key, elem_addr])
            if r >= 0x80000000:
                r -= 0x100000000
            if r == 0:
                return elem_addr
            elif r < 0:
                hi = mid - 1
            else:
                lo = mid + 1
        return 0

    _SCAN_WS = frozenset(b' \t\n\r\v\f')

    def _scan(self, src, fmt, varargs, wide_src=False, wide_fmt=False, secure=False):
        """scanf-family engine.

        src is a _ScanSource yielding bytes (or UTF-16 units when wide_src),
        fmt is the format as a list of units. Supports %d %i %u %o %x %X %p
        %e %f %g %a %c %s %[set] %n %% with '*', widths and the length
        modifiers hh h l ll L I64 I32 j z t w. Secure (_s) variants take a
        buffer size after each %c/%s/%[ pointer. Returns the number of
        assigned fields, or EOF if input ended before the first conversion.
        """
        WS = self._SCAN_WS
        arg_index = 0
        assigned = 0
        converted = False
        eof_failure = False
        fi = 0
        n = len(fmt)

        def next_arg():
            nonlocal arg_index
            value = varargs[arg_index] if arg_index < len(varargs) else 0
            arg_index += 1
            return value

        def skip_ws():
            while src.peek() in WS:
                src.get()

        def store_int(ptr, value, size):
            if ptr:
                self._mem_write(ptr, (value & ((1 << (size * 8)) - 1)).to_bytes(size, 'little'))

        def store_text(ptr, units, as_wide, terminate, limit):
            if not ptr:
                return
            if as_wide == wide_src:
                text_units = list(units)
            elif as_wide:
                text = bytes(units).decode(config.ANSI_CODEPAGE, errors='replace')
                raw = text.encode('utf-16-le')
                text_units = list(struct.unpack(f'<{len(raw) // 2}H', raw))
            else:
                text = ''.join(chr(u) for u in units)
                text_units = list(text.encode(config.ANSI_CODEPAGE, errors='replace'))
            if terminate:
                text_units.append(0)
            if limit is not None and len(text_units) > limit:
                text_units = text_units[:limit]
            self._mem_write(ptr, self._pack_units(text_units, as_wide))

        while fi < n:
            fc = fmt[fi]
            if fc in WS:
                skip_ws()
                fi += 1
                continue
            if fc != 0x25:  # literal character
                if src.peek() == -1:
                    eof_failure = True
                    break
                if src.peek() != fc:
                    break
                src.get()
                fi += 1
                continue

            fi += 1
            if fi < n and fmt[fi] == 0x25:  # %%
                skip_ws()
                if src.peek() != 0x25:
                    eof_failure = src.peek() == -1
                    break
                src.get()
                fi += 1
                continue
            suppress = fi < n and fmt[fi] == 0x2A  # '*'
            if suppress:
                fi += 1
            width = 0
            while fi < n and 0x30 <= fmt[fi] <= 0x39:
                width = width * 10 + fmt[fi] - 0x30
                fi += 1
            spec = ''.join(chr(u) for u in fmt[fi:fi + 3])
            length = ''
            for candidate in ('I64', 'I32', 'hh', 'll', 'h', 'l', 'L', 'w', 'j', 'z', 't', 'I'):
                if spec.startswith(candidate):
                    length = candidate
                    break
            fi += len(length)
            if fi >= n:
                break
            conv = chr(fmt[fi])
            fi += 1

            scanset = None
            if conv == '[':
                negate = fi < n and fmt[fi] == 0x5E  # '^'
                if negate:
                    fi += 1
                members = set()
                first = True
                while fi < n and (first or fmt[fi] != 0x5D):
                    lo = fmt[fi]
                    if (fi + 2 < n and fmt[fi + 1] == 0x2D and fmt[fi + 2] != 0x5D):
                        members.update(range(lo, fmt[fi + 2] + 1))
                        fi += 3
                    else:
                        members.add(lo)
                        fi += 1
                    first = False
                fi += 1  # closing ']'
                scanset = (members, negate)

            maxw = width or None
            if conv not in 'c[n':
                skip_ws()

            if conv == 'n':
                if not suppress:
                    store_int(next_arg(), src.count, 8 if length in ('ll', 'I64', 'j') else
                              {'hh': 1, 'h': 2}.get(length, 4))
                continue

            if src.peek() == -1:
                eof_failure = True
                break

            if conv in 'diouxXp':
                base = {'d': 10, 'u': 10, 'o': 8, 'x': 16, 'X': 16, 'p': 16}.get(conv, 0)
                remaining = maxw if maxw else 1 << 30
                sign = 1
                digits = ''
                if remaining and src.peek() in (0x2B, 0x2D):
                    sign = -1 if src.get() == 0x2D else 1
                    remaining -= 1
                if remaining and src.peek() == 0x30 and base in (0, 16):
                    src.get()
                    remaining -= 1
                    digits = '0'
                    if remaining and src.peek() in (0x78, 0x58):  # 0x prefix
                        src.get()
                        remaining -= 1
                        base = 16
                    elif base == 0:
                        base = 8
                if base == 0:
                    base = 10
                while remaining:
                    c = src.peek()
                    ch = chr(c).lower() if 0 <= c < 0x80 else ''
                    if not ch or not ch.isalnum() or int(ch, 36) >= base:
                        break
                    digits += ch
                    src.get()
                    remaining -= 1
                if not digits:
                    break
                converted = True
                if not suppress:
                    size = 8 if length in ('ll', 'I64', 'j') else {'hh': 1, 'h': 2}.get(length, 4)
                    store_int(next_arg(), sign * int(digits, base), size)
                    assigned += 1
            elif conv in 'eEfFgGaA':
                remaining = maxw if maxw else 1 << 30
                token = ''
                seen_dot = seen_exp = seen_digit = False

                def take():
                    nonlocal token, remaining
                    token += chr(src.get())
                    remaining -= 1

                if remaining and src.peek() in (0x2B, 0x2D):
                    take()
                while remaining:
                    c = src.peek()
                    if 0x30 <= c <= 0x39:
                        seen_digit = True
                        take()
                    elif c == 0x2E and not seen_dot and not seen_exp:
                        seen_dot = True
                        take()
                    elif c in (0x65, 0x45) and seen_digit and not seen_exp:
                        seen_exp = True
                        take()
                        if remaining and src.peek() in (0x2B, 0x2D):
                            take()
                    else:
                        break
                if not seen_digit:
                    break
                try:
                    value = float(token.rstrip('eE+-') if token[-1:] in 'eE+-' else token)
                except ValueError:
                    break
                converted = True
                if not suppress:
                    ptr = next_arg()
                    if ptr:
                        fmt = '<d' if length in ('l', 'L') else '<f'
                        self._mem_write(ptr, struct.pack(fmt, value))
                    assigned += 1
            elif conv in 'cCsS[':
                as_wide = self._wide_spec(conv if conv != '[' else 's', length, wide_fmt)
                count = maxw if maxw else (1 if conv in 'cC' else 1 << 30)
                units = []
                while len(units) < count:
                    c = src.peek()
                    if c == -1:
                        break
                    if conv in 'sS' and c in WS:
                        break
                    if scanset and ((c in scanset[0]) == scanset[1]):
                        break
                    units.append(src.get())
                if not units:
                    break
                converted = True
                if not suppress:
                    ptr = next_arg()
                    limit = next_arg() if secure else None
                    store_text(ptr, units, as_wide, conv not in 'cC', limit)
                    assigned += 1
            else:
                break

        if eof_failure and not converted:
            return 0xFFFFFFFF  # EOF
        return assigned

    def _scan_string(self, src_addr, fmt_addr, varargs, wide=False, secure=False,
                     max_count=None):
        """sscanf/swscanf helper: scan a NUL-terminated (or counted) string."""
        data = self._read_units(src_addr, wide)
        if max_count is not None:
            data = data[:max_count]
        fmt = self._read_units(fmt_addr, wide)
        pos = 0

        def getc():
            nonlocal pos
            if pos >= len(data):
                return -1
            pos += 1
            return data[pos - 1]

        return self._scan(_ScanSource(getc), fmt, varargs, wide, wide, secure)

    def _scan_stream(self, stream_ptr, fmt_addr, varargs, wide_fmt=False, secure=False):
        """fscanf/scanf helper: scan bytes from a FILE*, pushing back lookahead."""
        fp = self._p_stream(stream_ptr)
        if fp is None:
            return 0xFFFFFFFF
        if isinstance(fp, ConsoleStream):
            self.flush_std_streams()

        def getc():
            try:
                b = fp.read(1)
            except OSError:
                return -1
            return b[0] if b else -1

        src = _ScanSource(getc)
        fmt = self._read_units(fmt_addr, wide_fmt)
        if wide_fmt:
            # Narrow input with a wide format: compare units as ANSI-range text
            fmt = list(''.join(chr(u) for u in fmt).encode(config.ANSI_CODEPAGE, errors='replace'))
        result = self._scan(src, fmt, varargs, False, wide_fmt, secure)
        pending = src.pending()
        if pending is not None:
            self._stream_unread(fp, pending)
        return result

    def _stream_unread(self, fp, byte):
        """Push one byte back onto a stream (scanf lookahead / ungetc)."""
        try:
            if isinstance(fp, ConsoleStream):
                fp.unread(bytes([byte]))
            else:
                fp.seek(-1, os.SEEK_CUR)
        except (OSError, ValueError):
            pass

    def sscanf(self, args):
        """sscanf emulation (see _scan for supported conversions)"""
        result = self._scan_string(args[0], args[1], args[2:])
        log.debug(f"sscanf(...) -> {self._signed32(result)}")
        return result

    # File functions
    def _alloc_file_ptr(self, fp, path):
        """Register a Python file object and hand back a fake FILE* pointer."""
        ptr = self.next_file_ptr
        self.next_file_ptr += 0x20
        self.file_streams[ptr] = {'fp': fp, 'path': path, 'fd': self.next_fd}
        self.next_fd += 1
        return ptr

    def fopen(self, args):
        """fopen emulation - opens a real file inside the drives/ sandbox"""
        filename = self.read_string(args[0])
        mode = self.read_string(args[1])
        log.debug(f"fopen(\"{filename}\", \"{mode}\")")

        device = self.open_device_stream(filename, mode)
        if device is False:
            self._store_errno(2)  # ENOENT
            return 0
        if device is not None:
            return self._alloc_file_ptr(device, None)

        path = self.resolve_drive_path(filename)
        if path is None or (self._crt_mode_writes(mode) and self._write_protected(path)):
            self._last_error = 13  # EACCES
            self._store_errno(13)
            return 0  # NULL

        try:
            fp = open(path, self._c_mode_to_python(mode))
        except OSError as e:
            log.debug(f"fopen(\"{filename}\") failed: {e}")
            self._last_error = 2  # ENOENT
            self._store_errno(self._oserror_errno(e))
            return 0

        return self._alloc_file_ptr(fp, path)

    def _p_stream(self, ptr):
        """Look up the Python file object for a FILE* pointer (or None)."""
        info = self.file_streams.get(ptr)
        return info['fp'] if info else None

    def fclose(self, args):
        """fclose emulation"""
        stream = args[0]
        log.debug(f"fclose(0x{stream:x})")
        info = self.file_streams.pop(stream, None)
        if info:
            try:
                info['fp'].close()
            except OSError:
                return 0xFFFFFFFF  # EOF
            return 0
        return 0xFFFFFFFF  # EOF

    def fread(self, args):
        """fread emulation - fread(ptr, size, nmemb, FILE*)"""
        ptr = args[0]
        size = args[1]
        nmemb = args[2]
        stream = args[3]
        log.debug(f"fread(0x{ptr:x}, {size}, {nmemb}, 0x{stream:x})")

        fp = self._p_stream(stream)
        if fp is None or size == 0:
            return 0
        try:
            data = fp.read(size * nmemb)
        except OSError as e:
            log.error(f"fread error: {e}")
            return 0
        if data:
            try:
                self.emu.uc.mem_write(ptr, data)
            except UcError as e:
                log.error(f"fread mem_write error: {e}")
                return 0
        return len(data) // size  # count of complete elements read

    def fwrite(self, args):
        """fwrite emulation - fwrite(ptr, size, nmemb, FILE*)"""
        ptr = args[0]
        size = args[1]
        nmemb = args[2]
        stream = args[3]
        log.debug(f"fwrite(0x{ptr:x}, {size}, {nmemb}, 0x{stream:x})")

        total = size * nmemb
        if total == 0:
            return 0

        # stdout / stderr FILE* come from __iob_func (heap range), not our
        # sandbox map - route those to the console like WriteFile does.
        fp = self._p_stream(stream)
        try:
            data = bytes(self.emu.uc.mem_read(ptr, total))
        except UcError as e:
            log.error(f"fwrite mem_read error: {e}")
            return 0

        if fp is None:
            text = data.decode(config.ANSI_CODEPAGE, errors='replace')
            log.program_output("STDOUT", text)
            self.console_output.append(text)
            self.console_write(text)
            return nmemb

        try:
            written = fp.write(data)
        except OSError as e:
            log.error(f"fwrite error: {e}")
            return 0
        if size == 0:
            return 0
        return (written if written is not None else total) // size

    def fseek(self, args):
        """fseek emulation - fseek(FILE*, offset, whence)"""
        stream = args[0]
        offset = args[1]
        whence = args[2]
        if offset & 0x80000000:
            offset -= 0x100000000
        log.debug(f"fseek(0x{stream:x}, {offset}, {whence})")
        fp = self._p_stream(stream)
        if fp is None:
            return 0xFFFFFFFF
        try:
            origin = {0: os.SEEK_SET, 1: os.SEEK_CUR, 2: os.SEEK_END}.get(whence, os.SEEK_SET)
            fp.seek(offset, origin)
            return 0
        except OSError:
            return 0xFFFFFFFF

    def ftell(self, args):
        """ftell emulation"""
        stream = args[0]
        fp = self._p_stream(stream)
        if fp is None:
            return 0xFFFFFFFF
        try:
            return fp.tell() & 0xFFFFFFFF
        except OSError:
            return 0xFFFFFFFF

    def rewind(self, args):
        """rewind emulation"""
        fp = self._p_stream(args[0])
        if fp is not None:
            try:
                fp.seek(0, os.SEEK_SET)
            except OSError:
                pass
        return 0

    def feof(self, args):
        """feof emulation - nonzero once a read has hit end-of-file"""
        stream = args[0]
        info = self.file_streams.get(stream)
        if not info:
            return 0
        fp = info['fp']
        try:
            cur = fp.tell()
            probe = fp.read(1)
            if probe == b'':
                return 1
            fp.seek(cur, os.SEEK_SET)
            return 0
        except OSError:
            return 0

    def fgetc(self, args):
        """fgetc emulation - returns the byte read, or EOF (-1)"""
        fp = self._p_stream(args[0])
        if fp is None:
            return 0xFFFFFFFF
        try:
            b = fp.read(1)
        except OSError:
            return 0xFFFFFFFF
        if not b:
            return 0xFFFFFFFF  # EOF
        return b[0]

    def fputc(self, args):
        """fputc emulation - fputc(c, FILE*)"""
        c = args[0] & 0xFF
        stream = args[1]
        fp = self._p_stream(stream)
        if fp is None:
            return 0xFFFFFFFF
        try:
            fp.write(bytes([c]))
        except OSError:
            return 0xFFFFFFFF
        return c

    def getc(self, args):
        """getc emulation - same as fgetc"""
        return self.fgetc(args)

    def putc(self, args):
        """putc emulation - same as fputc"""
        return self.fputc(args)

    def getchar(self, args):
        """getchar emulation - fgetc(stdin)"""
        self._ensure_iob()
        return self.fgetc([self._iob_addr])

    def putchar(self, args):
        """putchar emulation - fputc(c, stdout)"""
        c = args[0] & 0xFF
        self._stdout_stream().write(bytes([c]))
        return c

    def ungetc(self, args):
        """ungetc emulation - push one byte back onto an input stream"""
        c = args[0]
        stream = args[1]
        if c == 0xFFFFFFFF:
            return 0xFFFFFFFF  # ungetc(EOF) fails and leaves the stream alone
        c &= 0xFF
        fp = self._p_stream(stream)
        if fp is None:
            return 0xFFFFFFFF
        try:
            if isinstance(fp, ConsoleStream):
                fp.unread(bytes([c]))
                return c
            # Real file: step back over the byte that was just read. Pushing
            # back a different byte can't be represented, so report failure.
            fp.seek(-1, os.SEEK_CUR)
            if fp.read(1) != bytes([c]):
                return 0xFFFFFFFF
            fp.seek(-1, os.SEEK_CUR)
            return c
        except (OSError, ValueError):
            return 0xFFFFFFFF

    def setlocale(self, args):
        """setlocale emulation - only the "C" locale is available"""
        locale_ptr = args[1]
        requested = self.read_string(locale_ptr) if locale_ptr else None
        if requested not in (None, "", "C"):
            log.debug(f"setlocale: unsupported locale \"{requested}\"")
            return 0
        if self._c_locale_addr == 0:
            self._c_locale_addr = self.emu.heap_alloc(2)
            self.emu.uc.mem_write(self._c_locale_addr, b'C\x00')
        return self._c_locale_addr

    def fgets(self, args):
        """fgets emulation - fgets(buf, n, FILE*)"""
        buf = args[0]
        n = args[1]
        stream = args[2]
        fp = self._p_stream(stream)
        if fp is None or n <= 0:
            return 0
        out = bytearray()
        try:
            while len(out) < n - 1:
                ch = fp.read(1)
                if not ch:
                    break
                out += ch
                if ch == b'\n':
                    break
        except OSError:
            return 0
        if not out:
            return 0  # NULL at EOF with nothing read
        out += b'\x00'
        try:
            self.emu.uc.mem_write(buf, bytes(out))
        except UcError as e:
            log.error(f"fgets mem_write error: {e}")
            return 0
        return buf

    def fputs(self, args):
        """fputs emulation - fputs(str, FILE*)"""
        s = args[0]
        stream = args[1]
        text = self.read_string(s, max_len=4096)
        fp = self._p_stream(stream)
        if fp is None:
            # Treat unknown stream as stdout.
            log.program_output("STDOUT", text)
            self.console_output.append(text)
            self.console_write(text)
            return 0
        try:
            fp.write(text.encode(config.ANSI_CODEPAGE, errors='replace'))
        except OSError:
            return 0xFFFFFFFF  # EOF
        return 0

    def fflush(self, args):
        """fflush emulation"""
        fp = self._p_stream(args[0])
        if fp is not None:
            try:
                fp.flush()
            except OSError:
                return 0xFFFFFFFF
        return 0

    def api__iob_func(self, args):
        """__iob_func emulation - stdin/stdout/stderr file handles"""
        log.debug("__iob_func()")
        return self._ensure_iob()

    def api__acrt_iob_func(self, args):
        """__acrt_iob_func emulation - UCRT version"""
        index = args[0]
        log.debug(f"__acrt_iob_func({index})")
        return self._ensure_iob() + (index * self._FILE_SIZE)

    # ---- msvcrt.dll variables (the "C" locale) and their __p__ accessors ----

    def _crt_variable(self, name, data):
        """Address of a C runtime variable, allocated with its initial bytes once"""
        cells = self.__dict__.setdefault('_crt_variables', {})
        if name not in cells:
            address = self.emu.heap_alloc(max(len(data), 4))
            self._mem_write(address, data)
            cells[name] = address
        return cells[name]

    def _ctype_table(self, wide):
        """The "C" locale's character classification table (_UPPER, _LOWER,
        _DIGIT, ... like CT_CTYPE1): _pctype points to the entry of character
        0 with the EOF (-1) entry before it; _pwctype has 256 entries"""
        if wide:
            flags = [self._ctype1(chr(c)) for c in range(256)]
            return self._crt_variable('_pwctype table', struct.pack('<256H', *flags))
        flags = [self._ctype1(chr(c)) if c < 0x80 else 0 for c in range(256)]
        return self._crt_variable('_pctype table', struct.pack('<257H', 0, *flags)) + 2

    def _crt_pointer_variable(self, name, target):
        return self._crt_variable(name, struct.pack('<I', target))

    def _pgmptr_variable(self, wide):
        """_pgmptr/_wpgmptr: the program's full path"""
        name = '_wpgmptr' if wide else '_pgmptr'
        cells = self.__dict__.setdefault('_crt_variables', {})
        if name not in cells:
            units = self._text_units(self.windows_exe_path(), wide) + [0]
            text = self.emu.heap_alloc(len(units) * (2 if wide else 1))
            self._write_units(text, units, wide, terminate=False)
            self._crt_pointer_variable(name, text)
        return cells[name]

    def _tzname_variable(self):
        """_tzname: {standard name, daylight saving time name}"""
        cells = self.__dict__.setdefault('_crt_variables', {})
        if '_tzname' not in cells:
            names = []
            for text in time.tzname:
                data = text.encode(config.ANSI_CODEPAGE, errors='replace')[:63] + b'\x00'
                names.append(self.emu.heap_alloc(64))
                self._mem_write(names[-1], data)
            self._crt_variable('_tzname', struct.pack('<II', *names))
        return cells['_tzname']

    def _crt_variable_resolvers(self):
        """msvcrt variables: name -> function returning the variable's address"""
        version = self.GetVersion([])
        major, minor, build = version & 0xFF, (version >> 8) & 0xFF, version >> 16
        return {
            '_pctype': lambda: self._crt_pointer_variable('_pctype', self._ctype_table(False)),
            '_pwctype': lambda: self._crt_pointer_variable('_pwctype', self._ctype_table(True)),
            '__mb_cur_max': lambda: self._crt_variable('__mb_cur_max', struct.pack('<i', 1)),
            '_pgmptr': lambda: self._pgmptr_variable(False),
            '_wpgmptr': lambda: self._pgmptr_variable(True),
            '_timezone': lambda: self._crt_variable('_timezone', struct.pack('<i', time.timezone)),
            '_daylight': lambda: self._crt_variable('_daylight', struct.pack('<i', time.daylight)),
            '_tzname': self._tzname_variable,
            '_osver': lambda: self._crt_variable('_osver', struct.pack('<I', build)),
            '_winver': lambda: self._crt_variable('_winver',
                                                  struct.pack('<I', (major << 8) | minor)),
            '_winmajor': lambda: self._crt_variable('_winmajor', struct.pack('<I', major)),
            '_winminor': lambda: self._crt_variable('_winminor', struct.pack('<I', minor)),
        }

    def _crt_variable_api_map(self):
        """The __p__ accessors and helper functions of the msvcrt variables"""
        variables = self._crt_variable_resolvers()
        api = {f'__p_{name}': (lambda args, resolve=resolve: resolve())
               for name, resolve in variables.items()}
        api.update({
            '__p__iob': self.api__iob_func,
            '__pctype_func': lambda args: self._ctype_table(False),
            '__pwctype_func': lambda args: self._ctype_table(True),
            '___mb_cur_max_func': lambda args: 1,  # single-byte "C" locale
            '___lc_codepage_func': lambda args: 0,  # the "C" locale
            '___lc_collate_cp_func': lambda args: 0,
            '___lc_handle_func': lambda args: self._crt_variable('__lc_handle', b'\x00' * 24),
            '__lconv_init': self._crt_noop,
            '__doserrno': lambda args: self._crt_variable('_doserrno', b'\x00' * 4),
            '__threadid': lambda args: self.emu.current_thread.tid,
            '__threadhandle': lambda args: 0xFFFFFFFE,  # GetCurrentThread()
        })
        return api

    def _get_pgmptr(self, args):
        """_get_pgmptr(char **) emulation"""
        self._mem_write(args[0], struct.pack('<I', self._read_u32(self._pgmptr_variable(False))))
        return 0

    def _get_wpgmptr(self, args):
        self._mem_write(args[0], struct.pack('<I', self._read_u32(self._pgmptr_variable(True))))
        return 0

    def _assert_common(self, message, file, line):
        self._ensure_iob()
        text = f"Assertion failed: {message}, file {file}, line {line}\n"
        self.std_streams[2].write(text.encode(config.ANSI_CODEPAGE, errors='replace'))
        return self.abort([])

    def _assert(self, args):
        """_assert emulation - prints the failed assertion and aborts"""
        return self._assert_common(self.read_string(args[0]), self.read_string(args[1]),
                                   args[2])

    def _wassert(self, args):
        return self._assert_common(self.read_wide_string(args[0]),
                                   self.read_wide_string(args[1]), args[2])

    def _errno(self, args):
        """_errno emulation - address of the thread's errno variable"""
        if self._errno_addr == 0:
            self._errno_addr = self.emu.heap_alloc(4)
            self.emu.uc.mem_write(self._errno_addr, struct.pack('<I', 0))
        return self._errno_addr

    def localeconv(self, args):
        """localeconv emulation - struct lconv for the "C" locale"""
        if self._lconv_addr == 0:
            strings = self.emu.heap_alloc(4)
            self.emu.uc.mem_write(strings, b'.\x00\x00\x00')  # "." and ""
            point, empty = strings, strings + 1
            # decimal_point, then 9 empty strings, then 8 CHAR_MAX fields
            lconv = struct.pack('<10I', point, *([empty] * 9)) + bytes([127] * 8)
            self._lconv_addr = self.emu.heap_alloc(len(lconv))
            self.emu.uc.mem_write(self._lconv_addr, lconv)
        return self._lconv_addr

    def _get_osfhandle(self, args):
        """_get_osfhandle emulation"""
        fd = args[0]
        log.debug(f"_get_osfhandle({fd})")
        # stdin=0, stdout=1, stderr=2
        if fd == 0:
            return 0x10
        elif fd == 1:
            return 0x11
        elif fd == 2:
            return 0x12
        return 0xFFFFFFFF  # INVALID_HANDLE_VALUE

    def _ismbblead(self, args):
        """_ismbblead emulation - no multibyte lead bytes in the C locale"""
        return 0

    def _isatty(self, args):
        """_isatty emulation"""
        fd = args[0]
        log.debug(f"_isatty({fd})")
        return 1 if fd in [0, 1, 2] else 0

    def _setmode(self, args):
        """_setmode emulation"""
        fd = args[0]
        mode = args[1]
        log.debug(f"_setmode({fd}, 0x{mode:x})")
        return mode  # Previous mode

    # Memory functions
    def malloc(self, args):
        """malloc emulation"""
        size = args[0]
        addr = self.emu.heap_alloc_small(size)
        log.debug(f"malloc({size}) -> 0x{addr:08x}")
        return addr

    def calloc(self, args):
        """calloc emulation"""
        num = args[0]
        size = args[1]
        total = num * size
        if total > 0xFFFFFFFF:
            return 0
        addr = self.emu.heap_alloc(total)
        log.debug(f"calloc({num}, {size}) -> 0x{addr:08x}")
        return addr  # heap_alloc memory is already zeroed

    def realloc(self, args):
        """realloc emulation - preserves the old block's contents"""
        ptr = args[0]
        size = args[1]
        if ptr == 0:
            return self.malloc([size])
        if size == 0:
            self.free([ptr])
            return 0

        old_size = self.emu.heap_block_size(ptr)
        if old_size is not None and self.emu.heap_resize(ptr, size):
            log.debug(f"realloc(0x{ptr:08x}, {size}) -> 0x{ptr:08x} (in place)")
            return ptr

        addr = self.emu.heap_alloc(size)
        if addr == 0:
            return 0  # Old block stays valid, as in C
        copy_size = min(old_size, size) if old_size is not None else size
        try:
            self.emu.uc.mem_write(addr, bytes(self.emu.uc.mem_read(ptr, copy_size)))
        except UcError as e:
            log.error(f"realloc copy error: {e}")
        self.emu.heap_free(ptr)
        log.debug(f"realloc(0x{ptr:08x}, {size}) -> 0x{addr:08x}")
        return addr

    def free(self, args):
        """free emulation"""
        ptr = args[0]
        log.debug(f"free(0x{ptr:08x})")
        if ptr:
            self.emu.heap_free(ptr)
        return 0
