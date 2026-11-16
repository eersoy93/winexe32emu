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

"""Logging: the debug logger and the log file tee"""

import sys
import re
import threading

from colorama import init, Fore, Style


# Initialize Colorama
init(autoreset=True)


class LogFileTee:
    """Stands in for sys.stdout/sys.stderr (--logfile): writes go to the
    console as before and, without ANSI color codes, to the log file"""

    ANSI_ESCAPE = re.compile(r'\x1b\[[0-9;?]*[A-Za-z]')

    def __init__(self, stream, logfile, lock):
        self._stream = stream
        self._logfile = logfile
        self._lock = lock  # Shared by the stdout and stderr tees

    def write(self, text):
        result = self._stream.write(text)
        with self._lock:
            self._logfile.write(self.ANSI_ESCAPE.sub('', text))
        return result

    def flush(self):
        self._stream.flush()
        with self._lock:
            self._logfile.flush()

    def __getattr__(self, name):
        return getattr(self._stream, name)


class DebugLogger:
    """Logger for colored debug output"""

    DEBUG, INFO, WARNING = 0, 1, 2
    level = INFO
    _lock = threading.Lock()
    _at_line_start = True

    @classmethod
    def write(cls, text):
        """Write text in one piece (the emulation and GUI threads both print)"""
        if not text:
            return
        with cls._lock:
            sys.stdout.write(text)
            sys.stdout.flush()
            cls._at_line_start = text.endswith('\n')
            cls._output_tag = None

    _output_tag = None
    PROGRAM_OUTPUT_COLORS = {'STDOUT': Fore.YELLOW, 'STDERR': Fore.RED,
                             'CONSOLE': Fore.YELLOW}

    @classmethod
    def program_output(cls, tag, text):
        """Write a program's console output, tagging each line once ([STDOUT],
        [STDERR], ...): programs write lines in pieces and redraw progress
        indicators with backspaces, so the tag must not split a line"""
        if not text:
            return
        color = cls.PROGRAM_OUTPUT_COLORS.get(tag, Fore.YELLOW)
        prefix = f"{color}[{tag}]{Style.RESET_ALL} "
        out = []
        with cls._lock:
            if not cls._at_line_start and cls._output_tag != tag:
                out.append('\n')
                cls._at_line_start = True
            for piece in re.findall(r'[^\n]*\n|[^\n]+', text):
                if cls._at_line_start:
                    out.append(prefix)
                # A carriage return redraws the line from column 0: keep the tag
                out.append(re.sub(r'\r(?!\n|$)', lambda m: '\r' + prefix, piece))
                cls._at_line_start = piece.endswith('\n')
            cls._output_tag = tag
            sys.stdout.write(''.join(out))
            sys.stdout.flush()

    @classmethod
    def _line(cls, text):
        with cls._lock:
            # Program output may have left the cursor mid-line
            prefix = '' if cls._at_line_start else '\n'
            sys.stdout.write(f"{prefix}{text}\n")
            sys.stdout.flush()
            cls._at_line_start = True
            cls._output_tag = None

    @classmethod
    def info(cls, msg):
        if cls.level <= cls.INFO:
            cls._line(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} {msg}")

    @classmethod
    def success(cls, msg):
        if cls.level <= cls.INFO:
            cls._line(f"{Fore.GREEN}[OK]{Style.RESET_ALL} {msg}")

    @classmethod
    def warning(cls, msg):
        cls._line(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} {msg}")

    @classmethod
    def error(cls, msg):
        cls._line(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {msg}")

    @classmethod
    def debug(cls, msg):
        if cls.level <= cls.DEBUG:
            cls._line(f"{Fore.MAGENTA}[DEBUG]{Style.RESET_ALL} {msg}")

    @classmethod
    def header(cls, msg):
        if cls.level <= cls.INFO:
            bar = f"{Fore.WHITE}{Style.BRIGHT}{'='*60}"
            cls._line(f"\n{bar}\n{Fore.WHITE}{Style.BRIGHT}{msg}\n{bar}{Style.RESET_ALL}\n")


log = DebugLogger()
