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

"""WinAPIHandler mixin: CRT formatted and character I/O, stream state, file system, conio"""

import os
import struct

from unicorn import *

from .. import config


class CrtStdioMixin:
    """CRT formatted and character I/O, stream state, file system, conio"""

    # ---- Formatted output ----

    def _stream_write(self, stream_ptr, data):
        """Write bytes to a FILE*; unknown streams go to stdout. Returns success."""
        fp = self._p_stream(stream_ptr)
        if fp is None:
            fp = self._stdout_stream()
        try:
            fp.write(data)
            return True
        except OSError:
            return False

    def _printf_text(self, fmt_addr, varargs, wide=False, wide_fmt=None):
        fmt = self._read_text(fmt_addr, wide)
        return self._format_string(fmt, varargs, wide if wide_fmt is None else wide_fmt)

    def _fprintf_common(self, stream_ptr, text):
        data = text.encode(config.ANSI_CODEPAGE, errors='replace')
        if not self._stream_write(stream_ptr, data):
            return 0xFFFFFFFF
        return len(text)

    def _store_formatted(self, buf, count, text, wide, mode):
        """Store printf output into a buffer.

        mode: 'unbounded' (sprintf), 'legacy' (_snprintf: -1 on truncation,
        no terminator when it exactly fills), 'c99' (snprintf: always
        terminated, returns the full length), 'secure' (sprintf_s: empty
        string and -1 when it does not fit).
        """
        units = self._text_units(text, wide)
        length = len(units)
        if mode == 'unbounded':
            self._write_units(buf, units, wide)
            return length
        if mode == 'c99':
            if buf and count:
                self._write_units(buf, units[:count - 1], wide)
            return length
        if mode == 'secure':
            if length >= count:
                if buf and count:
                    self._write_units(buf, [], wide)
                self._store_errno(self.ERANGE)
                return 0xFFFFFFFF
            self._write_units(buf, units, wide)
            return length
        # legacy
        if buf:
            self._write_units(buf, units[:count], wide, terminate=length < count)
        return length if length <= count else 0xFFFFFFFF

    def fprintf(self, args):
        """fprintf emulation"""
        return self._fprintf_common(args[0], self._printf_text(args[1], args[2:]))

    def vfprintf(self, args):
        """vfprintf emulation"""
        return self._fprintf_common(args[0], self._printf_text(args[1], self._va_args(args[2])))

    def vprintf(self, args):
        """vprintf emulation"""
        return self._fprintf_common(0, self._printf_text(args[0], self._va_args(args[1])))

    def vsprintf(self, args):
        """vsprintf emulation"""
        text = self._printf_text(args[1], self._va_args(args[2]))
        return self._store_formatted(args[0], 0, text, False, 'unbounded')

    def _snprintf(self, args):
        """_snprintf emulation (-1 when truncated)"""
        text = self._printf_text(args[2], args[3:])
        return self._store_formatted(args[0], args[1], text, False, 'legacy')

    def _vsnprintf(self, args):
        """_vsnprintf emulation"""
        text = self._printf_text(args[2], self._va_args(args[3]))
        return self._store_formatted(args[0], args[1], text, False, 'legacy')

    def snprintf(self, args):
        """snprintf emulation (C99: always terminated, returns full length)"""
        text = self._printf_text(args[2], args[3:])
        return self._store_formatted(args[0], args[1], text, False, 'c99')

    def vsnprintf(self, args):
        """vsnprintf emulation (C99)"""
        text = self._printf_text(args[2], self._va_args(args[3]))
        return self._store_formatted(args[0], args[1], text, False, 'c99')

    def sprintf_s(self, args):
        """sprintf_s emulation"""
        text = self._printf_text(args[2], args[3:])
        return self._store_formatted(args[0], args[1], text, False, 'secure')

    def vsprintf_s(self, args):
        """vsprintf_s emulation"""
        text = self._printf_text(args[2], self._va_args(args[3]))
        return self._store_formatted(args[0], args[1], text, False, 'secure')

    def _scprintf(self, args):
        """_scprintf emulation - length of the formatted text"""
        return len(self._printf_text(args[0], args[1:]))

    def _vscprintf(self, args):
        """_vscprintf emulation"""
        return len(self._printf_text(args[0], self._va_args(args[1])))

    def wprintf(self, args):
        """wprintf emulation"""
        return self._fprintf_common(0, self._printf_text(args[0], args[1:], wide=True))

    def vwprintf(self, args):
        """vwprintf emulation"""
        return self._fprintf_common(0, self._printf_text(args[0], self._va_args(args[1]), wide=True))

    def fwprintf(self, args):
        """fwprintf emulation"""
        return self._fprintf_common(args[0], self._printf_text(args[1], args[2:], wide=True))

    def vfwprintf(self, args):
        """vfwprintf emulation"""
        return self._fprintf_common(args[0], self._printf_text(args[1], self._va_args(args[2]), wide=True))

    def swprintf(self, args):
        """swprintf emulation (msvcrt legacy form without a count)"""
        text = self._printf_text(args[1], args[2:], wide=True)
        return self._store_formatted(args[0], 0, text, True, 'unbounded')

    def _swprintf(self, args):
        return self.swprintf(args)

    def vswprintf(self, args):
        """vswprintf emulation (msvcrt legacy form without a count)"""
        text = self._printf_text(args[1], self._va_args(args[2]), wide=True)
        return self._store_formatted(args[0], 0, text, True, 'unbounded')

    def _snwprintf(self, args):
        """_snwprintf emulation"""
        text = self._printf_text(args[2], args[3:], wide=True)
        return self._store_formatted(args[0], args[1], text, True, 'legacy')

    def _vsnwprintf(self, args):
        """_vsnwprintf emulation"""
        text = self._printf_text(args[2], self._va_args(args[3]), wide=True)
        return self._store_formatted(args[0], args[1], text, True, 'legacy')

    def swprintf_s(self, args):
        """swprintf_s emulation"""
        text = self._printf_text(args[2], args[3:], wide=True)
        return self._store_formatted(args[0], args[1], text, True, 'secure')

    def _scwprintf(self, args):
        """_scwprintf emulation"""
        return len(self._text_units(self._printf_text(args[0], args[1:], wide=True), True))

    # UCRT stdio entry points: (unsigned __int64 options, ..., _locale_t, va_list)
    _UCRT_STANDARD_SNPRINTF = 0x2
    _UCRT_LEGACY_WIDE_SPECIFIERS = 0x4
    _UCRT_SECURE_SCANF = 0x1

    def _ucrt_wide_fmt(self, options):
        return bool(options & self._UCRT_LEGACY_WIDE_SPECIFIERS)

    def api__stdio_common_vfprintf(self, args):
        """__stdio_common_vfprintf (UCRT)"""
        text = self._printf_text(args[3], self._va_args(args[5]))
        return self._fprintf_common(args[2], text)

    def api__stdio_common_vfwprintf(self, args):
        """__stdio_common_vfwprintf (UCRT)"""
        text = self._printf_text(args[3], self._va_args(args[5]), wide=True,
                                 wide_fmt=self._ucrt_wide_fmt(args[0]))
        return self._fprintf_common(args[2], text)

    def _ucrt_vsprintf(self, args, wide):
        options, buf, count = args[0], args[2], args[3]
        text = self._printf_text(args[4], self._va_args(args[6]), wide=wide,
                                 wide_fmt=self._ucrt_wide_fmt(options) if wide else False)
        if options & self._UCRT_STANDARD_SNPRINTF or (not buf and not count):
            return self._store_formatted(buf, count, text, wide, 'c99')
        if count == 0xFFFFFFFF:
            return self._store_formatted(buf, 0, text, wide, 'unbounded')
        return self._store_formatted(buf, count, text, wide, 'legacy')

    def api__stdio_common_vsprintf(self, args):
        """__stdio_common_vsprintf (UCRT)"""
        return self._ucrt_vsprintf(args, False)

    def api__stdio_common_vswprintf(self, args):
        """__stdio_common_vswprintf (UCRT)"""
        return self._ucrt_vsprintf(args, True)

    def api__stdio_common_vsprintf_s(self, args):
        """__stdio_common_vsprintf_s (UCRT)"""
        text = self._printf_text(args[4], self._va_args(args[6]))
        return self._store_formatted(args[2], args[3], text, False, 'secure')

    def api__stdio_common_vswprintf_s(self, args):
        """__stdio_common_vswprintf_s (UCRT)"""
        text = self._printf_text(args[4], self._va_args(args[6]), wide=True,
                                 wide_fmt=self._ucrt_wide_fmt(args[0]))
        return self._store_formatted(args[2], args[3], text, True, 'secure')

    def api__stdio_common_vsnprintf_s(self, args):
        """__stdio_common_vsnprintf_s (UCRT): (options, buf, size, max_count, fmt, locale, va)"""
        buf, size, max_count = args[2], args[3], args[4]
        text = self._printf_text(args[5], self._va_args(args[7]))
        full = self._text_units(text, False)
        units = full if max_count == 0xFFFFFFFF else full[:max_count]
        if len(units) < size:
            self._write_units(buf, units, False)
            return len(units) if len(units) == len(full) else 0xFFFFFFFF
        if max_count == 0xFFFFFFFF and size:  # _TRUNCATE
            self._write_units(buf, units[:size - 1], False)
            return 0xFFFFFFFF
        if buf and size:
            self._write_units(buf, [], False)
        self._store_errno(self.ERANGE)
        return 0xFFFFFFFF

    def api__stdio_common_vsscanf(self, args):
        """__stdio_common_vsscanf (UCRT): (options, buf, count, fmt, locale, va)"""
        count = None if args[3] == 0xFFFFFFFF else args[3]
        return self._scan_string(args[2], args[4], self._va_args(args[6]),
                                 secure=bool(args[0] & self._UCRT_SECURE_SCANF), max_count=count)

    def api__stdio_common_vswscanf(self, args):
        """__stdio_common_vswscanf (UCRT)"""
        count = None if args[3] == 0xFFFFFFFF else args[3]
        return self._scan_string(args[2], args[4], self._va_args(args[6]), wide=True,
                                 secure=bool(args[0] & self._UCRT_SECURE_SCANF), max_count=count)

    def api__stdio_common_vfscanf(self, args):
        """__stdio_common_vfscanf (UCRT): (options, stream, fmt, locale, va)"""
        return self._scan_stream(args[2], args[3], self._va_args(args[5]),
                                 secure=bool(args[0] & self._UCRT_SECURE_SCANF))

    # ---- Formatted input ----

    def _stdin_ptr(self):
        return self._ensure_iob()

    def scanf(self, args):
        """scanf emulation"""
        return self._scan_stream(self._stdin_ptr(), args[0], args[1:])

    def scanf_s(self, args):
        """scanf_s emulation"""
        return self._scan_stream(self._stdin_ptr(), args[0], args[1:], secure=True)

    def vscanf(self, args):
        """vscanf emulation"""
        return self._scan_stream(self._stdin_ptr(), args[0], self._va_args(args[1]))

    def fscanf(self, args):
        """fscanf emulation"""
        return self._scan_stream(args[0], args[1], args[2:])

    def fscanf_s(self, args):
        """fscanf_s emulation"""
        return self._scan_stream(args[0], args[1], args[2:], secure=True)

    def vfscanf(self, args):
        """vfscanf emulation"""
        return self._scan_stream(args[0], args[1], self._va_args(args[2]))

    def sscanf_s(self, args):
        """sscanf_s emulation"""
        return self._scan_string(args[0], args[1], args[2:], secure=True)

    def vsscanf(self, args):
        """vsscanf emulation"""
        return self._scan_string(args[0], args[1], self._va_args(args[2]))

    def swscanf(self, args):
        """swscanf emulation"""
        return self._scan_string(args[0], args[1], args[2:], wide=True)

    def wscanf(self, args):
        """wscanf emulation"""
        return self._scan_stream(self._stdin_ptr(), args[0], args[1:], wide_fmt=True)

    # ---- Character / line I/O ----

    def gets(self, args):
        """gets emulation - read a line from stdin without the newline"""
        buf = args[0]
        fp = self._p_stream(self._stdin_ptr())
        out = bytearray()
        self.flush_std_streams()
        while True:
            ch = fp.read(1)
            if not ch:
                if not out:
                    return 0
                break
            if ch == b'\n':
                break
            out += ch
        if out.endswith(b'\r'):
            out = out[:-1]
        self._mem_write(buf, bytes(out) + b'\x00')
        return buf

    def fputws(self, args):
        """fputws emulation"""
        text = self.read_wide_string(args[0])
        return 0 if self._stream_write(args[1], text.encode(config.ANSI_CODEPAGE, errors='replace')) else 0xFFFFFFFF

    def _putws(self, args):
        """_putws emulation"""
        text = self.read_wide_string(args[0]) + "\n"
        self._stdout_stream().write(text.encode(config.ANSI_CODEPAGE, errors='replace'))
        return 0

    def fputwc(self, args):
        """fputwc emulation"""
        ch = args[0] & 0xFFFF
        ok = self._stream_write(args[1], chr(ch).encode(config.ANSI_CODEPAGE, errors='replace'))
        return ch if ok else 0xFFFF  # WEOF

    def putwc(self, args):
        return self.fputwc(args)

    def putwchar(self, args):
        """putwchar emulation"""
        return self.fputwc([args[0], 0])

    def _fputchar(self, args):
        return self.putchar(args)

    def _fgetchar(self, args):
        return self.getchar(args)

    # ---- Stream state ----

    def ferror(self, args):
        """ferror emulation - I/O errors are reported by the calls themselves"""
        return 0

    def clearerr(self, args):
        """clearerr emulation"""
        return 0

    def _fileno(self, args):
        """_fileno emulation"""
        stream = args[0]
        if self._iob_addr and self._iob_addr <= stream < self._iob_addr + 3 * self._FILE_SIZE:
            return (stream - self._iob_addr) // self._FILE_SIZE
        info = self.file_streams.get(stream)
        if info and 'fd' in info:
            return info['fd']
        self._store_errno(self.EINVAL)
        return 0xFFFFFFFF

    def fileno(self, args):
        return self._fileno(args)

    def setvbuf(self, args):
        """setvbuf emulation - buffering is handled by the host"""
        return 0

    def setbuf(self, args):
        """setbuf emulation"""
        return 0

    def fgetpos(self, args):
        """fgetpos emulation (fpos_t is 64-bit)"""
        fp = self._p_stream(args[0])
        try:
            pos = fp.tell()
        except (OSError, AttributeError):
            self._store_errno(self.EINVAL)
            return 0xFFFFFFFF
        self._mem_write(args[1], struct.pack('<q', pos))
        return 0

    def fsetpos(self, args):
        """fsetpos emulation"""
        fp = self._p_stream(args[0])
        try:
            pos = struct.unpack('<q', self.emu.uc.mem_read(args[1], 8))[0]
            fp.seek(pos, os.SEEK_SET)
        except (OSError, AttributeError, UcError):
            self._store_errno(self.EINVAL)
            return 0xFFFFFFFF
        return 0

    def _wfopen(self, args):
        """_wfopen emulation - fopen with wide file name and mode"""
        filename = self.read_wide_string(args[0])
        mode = self.read_wide_string(args[1])
        path = self.resolve_drive_path(filename)
        if path is None or (self._crt_mode_writes(mode) and self._write_protected(path)):
            self._store_errno(self.EACCES)
            return 0
        try:
            fp = open(path, self._c_mode_to_python(mode))
        except OSError as e:
            self._store_errno(self._oserror_errno(e))
            return 0
        return self._alloc_file_ptr(fp, path)

    def fopen_s(self, args):
        """fopen_s emulation - returns errno, FILE* through the first argument"""
        stream = self.fopen(args[1:])
        if args[0]:
            self._mem_write(args[0], struct.pack('<I', stream))
        return 0 if stream else (self._load_errno() or self.ENOENT)

    def perror(self, args):
        """perror emulation - "<prefix>: <strerror(errno)>" on stderr"""
        prefix = self.read_string(args[0]) if args[0] else ''
        message = self._ERRNO_MESSAGES.get(self._load_errno(), "Unknown error")
        text = f"{prefix}: {message}\n" if prefix else f"{message}\n"
        self._ensure_iob()
        self.std_streams[2].write(text.encode(config.ANSI_CODEPAGE, errors='replace'))
        return 0

    # ---- File system (sandboxed in drives/) ----

    @staticmethod
    def _crt_mode_writes(mode):
        """Does an fopen mode ("w", "a", "r+"...) change the file?"""
        return any(c in (mode or '') for c in 'wa+')

    def _sandbox_op(self, name_addr, op, wide=False, writes=True):
        """Run op(host_path) for a program path; returns 0 or -1 with errno.
        An op that writes fails with EACCES on the read-only CD-ROM D:."""
        filename = self._read_text(name_addr, wide)
        path = self.resolve_drive_path(filename)
        if path is None or (writes and self._write_protected(path)):
            self._store_errno(self.EACCES)
            return 0xFFFFFFFF
        try:
            op(path)
        except OSError as e:
            self._store_errno(self._oserror_errno(e))
            return 0xFFFFFFFF
        return 0

    def remove(self, args):
        """remove emulation"""
        return self._sandbox_op(args[0], os.remove)

    def _unlink(self, args):
        return self.remove(args)

    def unlink(self, args):
        return self.remove(args)

    def _wremove(self, args):
        return self._sandbox_op(args[0], os.remove, wide=True)

    def rename(self, args):
        """rename emulation (fails if the target exists, like Windows)"""
        new_path = self.resolve_drive_path(self.read_string(args[1]))
        if new_path is None or self._write_protected(new_path):
            self._store_errno(self.EACCES)
            return 0xFFFFFFFF

        def do_rename(old_path):
            if os.path.exists(new_path):
                raise FileExistsError(__import__('errno').EEXIST, "exists")
            os.rename(old_path, new_path)
        return self._sandbox_op(args[0], do_rename)

    def _access(self, args):
        """_access emulation (mode 0 exists, 2 write, 4 read, 6 read/write)"""
        mode = args[1]

        def check(path):
            if not os.path.exists(path):
                raise FileNotFoundError(__import__('errno').ENOENT, "missing")
            if mode & 2 and (not os.access(path, os.W_OK) or self._write_protected(path)):
                raise PermissionError(__import__('errno').EACCES, "read-only")
        return self._sandbox_op(args[0], check, writes=False)

    def access(self, args):
        return self._access(args)

    def _mkdir(self, args):
        """_mkdir emulation"""
        return self._sandbox_op(args[0], os.mkdir)

    def _rmdir(self, args):
        """_rmdir emulation"""
        return self._sandbox_op(args[0], os.rmdir)

    def _getcwd(self, args):
        """_getcwd emulation - the emulated current directory"""
        buf, size = args[0], args[1]
        units = self._text_units(self.current_directory, False)
        if not buf:
            return self._alloc_units(units, False)
        if size < len(units) + 1:
            self._store_errno(self.ERANGE)
            return 0
        self._write_units(buf, units, False)
        return buf

    def _getdrive(self, args):
        """_getdrive emulation - drive C: is 3"""
        return 3

    # ---- Console I/O (conio) ----

    def _getch(self, args):
        """_getch emulation - next byte of console input (line buffered)"""
        self._ensure_iob()
        return self.fgetc([self._iob_addr])

    def _getche(self, args):
        return self._getch(args)

    def _kbhit(self, args):
        """_kbhit emulation - 1 if console input is already buffered"""
        self._ensure_iob()
        return 1 if self.std_streams[0].has_input() else 0

    def _putch(self, args):
        """_putch emulation"""
        return self.putchar(args)

    def _cputs(self, args):
        """_cputs emulation"""
        self._stdout_stream().write(self.read_cstring(args[0]))
        return 0

    def _cprintf(self, args):
        """_cprintf emulation"""
        return self._fprintf_common(0, self._printf_text(args[0], args[1:]))
