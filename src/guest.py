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

"""Helpers shared by the API emulation and the CPU emulator: console
streams, x87/QWORD results, API jumps, guest unwinding, scanf sources"""

import sys

from . import config
from .logger import log


class ConsoleStream:
    """File-like object backing the CRT stdin/stdout/stderr FILE* streams.

    Output is buffered per line so byte-at-a-time writers (fputc, used by
    MinGW's printf) produce readable log lines; multi-byte UTF-8 sequences
    split across writes are decoded correctly once the line is complete.
    """

    def __init__(self, handler, kind):
        self.handler = handler
        self.kind = kind  # 'stdin' | 'stdout' | 'stderr'
        self._out = bytearray()
        self._in = bytearray()

    def write(self, data):
        if self.kind == 'stdin':
            raise OSError("stdin is not writable")
        self._out += data
        if b'\n' in data:
            self.flush()
        return len(data)

    def _redirected(self):
        """The file the stream goes to when the process got its standard
        handles from cmd's redirection (> file, < file), else None"""
        redirected = getattr(self.handler, 'redirected_std_file', None)
        return redirected(self.kind) if redirected else None

    def flush(self):
        if not self._out:
            return
        target = self._redirected()
        if target is not None:
            # Text mode, like the C runtime writes a file: LF becomes CR LF
            data = bytes(self._out).replace(b'\r\n', b'\n').replace(b'\n', b'\r\n')
            self._out.clear()
            try:
                target.write(data)
                target.flush()
            except (OSError, ValueError) as e:
                log.warning(f"Writing the redirected {self.kind} failed: {e}")
            return
        text = self._out.decode(config.ANSI_CODEPAGE, errors='replace')
        self._out.clear()
        if self.kind == 'stderr':
            log.program_output("STDERR", text)
        else:
            log.program_output("STDOUT", text)
        self.handler.console_output.append(text)
        self.handler.console_write(text, self.kind)

    def _fill(self):
        """Read one more line of input. Returns False at EOF."""
        if self.kind != 'stdin':
            raise OSError("stream is not readable")
        # Make any pending prompt visible before blocking for input
        self.handler.flush_std_streams()
        source = self._redirected()
        if source is not None:
            try:
                line = source.readline()
            except (OSError, ValueError):
                line = b''
            if not line:
                return False
            self._in += line.replace(b'\r\n', b'\n')  # Text mode
            return True
        gui = self.handler.gui
        if gui:
            # No console (GUI program): stdin is at EOF
            line = self.handler.console_read_line()
            if line is None:
                return False
            self._in += (line + "\n").encode(config.ANSI_CODEPAGE, errors='replace')
            return True
        line = sys.stdin.buffer.readline()
        if not line:
            return False
        self._in += line
        return True

    def read(self, size=-1):
        if size is None or size < 0:
            while self._fill():
                pass
            size = len(self._in)
        while len(self._in) < size:
            # Line-oriented like a real console: return what is available
            # once at least one byte has been read.
            if self._in or not self._fill():
                break
        data = bytes(self._in[:size])
        del self._in[:size]
        return data

    def unread(self, data):
        """Push bytes back to the front of the input buffer (ungetc)."""
        if self.kind != 'stdin':
            raise OSError("stream is not readable")
        self._in[:0] = data

    def seek(self, offset, whence=0):
        raise OSError("console streams are not seekable")

    def tell(self):
        raise OSError("console streams are not seekable")

    def close(self):
        # Never close the host's real stdio
        self.flush()

    def has_input(self):
        """True if buffered input is available without blocking (_kbhit)."""
        return self.kind == 'stdin' and bool(self._in)


class X87Result:
    """API return value the caller expects in ST(0) (double functions)."""
    __slots__ = ('value',)

    def __init__(self, value):
        self.value = float(value)


class QWordResult:
    """64-bit API return value in EDX:EAX (also 8-byte structs like div_t)."""
    __slots__ = ('value',)

    def __init__(self, value):
        self.value = value & 0xFFFFFFFFFFFFFFFF


class ApiJump:
    """API result that transfers control elsewhere (longjmp, a catch block,
    an exception handler). regs: other registers to set ({'ebx': value, ...};
    ebx, ecx, edx, esi, edi, eflags)."""
    __slots__ = ('eip', 'esp', 'eax', 'ebp', 'regs')

    def __init__(self, eip, esp, eax, ebp=None, regs=None):
        self.eip = eip
        self.esp = esp
        self.eax = eax
        self.ebp = ebp
        self.regs = regs


class GuestUnwind(Exception):
    """A guest exception is caught in a frame outside the current callback:
    the nested emulation stops and the Python API handlers in between are
    left, until the API call of the frame's level resumes it there."""

    def __init__(self, jump):
        super().__init__("guest exception unwinding")
        self.jump = jump


class _ScanSource:
    """One-unit lookahead input for the scanf family (bytes or UTF-16 units)."""

    def __init__(self, getc):
        self._getc = getc
        self._la = None
        self.count = 0

    def peek(self):
        if self._la is None:
            self._la = self._getc()
        return self._la

    def get(self):
        c = self.peek()
        self._la = None
        if c != -1:
            self.count += 1
        return c

    def pending(self):
        """Lookahead unit that was read but not consumed (to push back)."""
        return self._la if self._la not in (None, -1) else None
