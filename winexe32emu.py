#!/usr/bin/env python3
#
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

"""
Windows 32-bit EXE Emulator
PE file loading, analysis and CPU emulation module
Fake Windows GUI environment with Pygame
"""

import sys
import os
import io
import re
import shutil
import array
import struct
import math
import codecs
import pefile
import threading
import queue
import subprocess
import time
import datetime
import unicodedata
import fnmatch
import ntpath
import wave
from functools import cmp_to_key, wraps
from colorama import init, Fore, Style

# Version info
WINEXE32EMU_VERSION = "0.1.0"

# Default EXE directory (c_drive/)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
C_DRIVE_PATH = os.path.join(SCRIPT_DIR, "c_drive")

# Environment variables seen by the emulated program. The folders they name
# are created inside c_drive/ at startup.
DEFAULT_ENVIRONMENT = {
    'PATH': 'C:\\Windows\\System32;C:\\Windows',
    'TEMP': 'C:\\Windows\\Temp',
    'TMP': 'C:\\Windows\\Temp',
    'WINDIR': 'C:\\Windows',
    'SYSTEMROOT': 'C:\\Windows',
    'COMSPEC': 'C:\\Windows\\System32\\cmd.exe',
}
# Variables whose value is a file path; only its parent folder is created
ENVIRONMENT_FILE_VARIABLES = {'COMSPEC'}

# Emulated folder holding the example programs (c_drive/Windows/Examples/)
EXAMPLES_FOLDER = 'C:\\Windows\\Examples'

# Folders searched for a bare EXE name (command line) and listed in the
# Start menu, in this order
PROGRAM_FOLDERS = ('C:\\', EXAMPLES_FOLDER)

# Code page used for the "A" (ANSI) APIs and CRT narrow strings. UTF-8 by
# default because MinGW emits string literals as UTF-8; set via --codepage
# (e.g. cp1254, cp1252) to behave like a localized Windows.
ANSI_CODEPAGE = "utf-8"

from unicorn import *
from unicorn.x86_const import *
from capstone import *

# Pygame import (optional for GUI)
os.environ["PYGAME_HIDE_SUPPORT_PROMPT"] = "1"
try:
    import pygame
    PYGAME_AVAILABLE = True
except ImportError:
    PYGAME_AVAILABLE = False
    print("Pygame not found, GUI support disabled!")

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

    @classmethod
    def _line(cls, text):
        with cls._lock:
            # Program output may have left the cursor mid-line
            prefix = '' if cls._at_line_start else '\n'
            sys.stdout.write(f"{prefix}{text}\n")
            sys.stdout.flush()
            cls._at_line_start = True

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


class PELoader:
    """PE file loader and analyzer"""

    # Imports by ordinal that the emulator implements by name: (dll, ordinal) -> name
    KNOWN_ORDINALS = {('comctl32.dll', 17): 'InitCommonControls',
                      ('comctl32.dll', 6): 'CreateStatusWindowA'}

    def __init__(self, filepath):
        self.filepath = filepath
        self.pe = None
        self.image_base = 0
        self.entry_point = 0
        self.subsystem = 0
        self.sections = []
        self.imports = {}
        self.exports = []

    def load(self):
        """Load and analyze PE file"""
        log.header("Loading PE File")
        log.info(f"The PE file: {self.filepath}")

        try:
            self.pe = pefile.PE(self.filepath)
            log.success("the PE file opened successfully!")
        except FileNotFoundError:
            log.error(f"The PE file not found: {self.filepath}")
            return False
        except pefile.PEFormatError as e:
            log.error(f"Invalid PE format: {e}")
            return False

        # Check PE type
        if self.pe.FILE_HEADER.Machine != 0x14c:  # IMAGE_FILE_MACHINE_I386
            log.error(f"This emulator only supports 32-bit (i386) PE files!")
            log.error(f"The PE file type: 0x{self.pe.FILE_HEADER.Machine:04x}")
            return False

        log.success("32-bit PE file verified!")

        # Get basic info
        if not self._parse_headers():
            return False
        self._parse_sections()
        self._parse_imports()
        self._parse_exports()

        return True

    def _parse_headers(self):
        """Parse PE header information"""
        log.header("PE Header Information")

        self.image_base = self.pe.OPTIONAL_HEADER.ImageBase
        self.entry_point = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        entry_point_va = self.image_base + self.entry_point

        log.info(f"Image Base: 0x{self.image_base:08x}")
        log.info(f"Entry Point (RVA): 0x{self.entry_point:08x}")
        log.info(f"Entry Point (VA): 0x{entry_point_va:08x}")
        log.info(f"Section Count: {self.pe.FILE_HEADER.NumberOfSections}")
        log.info(f"Image Size: 0x{self.pe.OPTIONAL_HEADER.SizeOfImage:08x}")
        log.info(f"Header Size: 0x{self.pe.OPTIONAL_HEADER.SizeOfHeaders:08x}")

        # Subsystem
        subsystem = self.pe.OPTIONAL_HEADER.Subsystem
        self.subsystem = subsystem
        subsystem_names = {
            1: "Native",
            2: "Windows GUI",
            3: "Windows Console",
        }
        subsystem_name = subsystem_names.get(subsystem, f"Unknown")
        log.info(f"Subsystem: {subsystem_name} ({subsystem})")
        if subsystem_name == "Unknown":
            log.error(f"Unknown subsystem: {subsystem}")
            return False

        # Characteristics
        characteristics = self.pe.FILE_HEADER.Characteristics
        log.debug(f"Characteristics: 0x{characteristics:04x}")
        if characteristics & 0x0001:
            log.debug("  - RELOCS_STRIPPED")
        if characteristics & 0x0002:
            log.debug("  - EXECUTABLE_IMAGE")
        if characteristics & 0x0100:
            log.debug("  - 32BIT_MACHINE")
        if characteristics & 0x2000:
            log.debug("  - DLL")

        return True

    def _parse_sections(self):
        """Parse section information"""
        log.header("Sections")

        for section in self.pe.sections:
            name = section.Name.decode('utf-8').rstrip('\x00')
            va = section.VirtualAddress
            vs = section.Misc_VirtualSize
            raw_size = section.SizeOfRawData
            raw_offset = section.PointerToRawData
            characteristics = section.Characteristics

            section_info = {
                'name': name,
                'virtual_address': va,
                'virtual_size': vs,
                'raw_size': raw_size,
                'raw_offset': raw_offset,
                'characteristics': characteristics,
                'data': section.get_data()
            }
            self.sections.append(section_info)

            # Determine permissions
            permissions = []
            if characteristics & 0x20000000:
                permissions.append("X")
            if characteristics & 0x40000000:
                permissions.append("R")
            if characteristics & 0x80000000:
                permissions.append("W")
            permissions_str = "".join(permissions) if permissions else "---"

            log.info(f"Section: {Fore.YELLOW}{name:8s}{Style.RESET_ALL} | "
                    f"VA: 0x{va:08x} | Size: 0x{vs:08x} | "
                    f"Raw: 0x{raw_offset:08x} | Perms: {permissions_str}")

    def _parse_imports(self):
        """Parse import table"""
        log.header("Import Table")

        if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            log.warning("Import table not found!")
            return

        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8')
            self.imports[dll_name] = []

            log.info(f"DLL: {Fore.GREEN}{dll_name}{Style.RESET_ALL}")

            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode('utf-8')
                else:
                    func_name = self.KNOWN_ORDINALS.get(
                        (dll_name.lower(), imp.ordinal), f"Ordinal_{imp.ordinal}")

                self.imports[dll_name].append({
                    'name': func_name,
                    'address': imp.address,
                    'ordinal': imp.ordinal
                })

                log.debug(f"  - {func_name} @ 0x{imp.address:08x}")

    def _parse_exports(self):
        """Parse export table"""
        log.header("Export Table")

        if not hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            log.warning("Export table not found (normal for EXE)!")
            return

        for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                func_name = exp.name.decode('utf-8')
            else:
                func_name = f"Ordinal_{exp.ordinal}"

            self.exports.append({
                'name': func_name,
                'address': exp.address,
                'ordinal': exp.ordinal
            })

            log.info(f"Export: {func_name} @ 0x{exp.address:08x}")

    def has_relocations(self):
        """True if the image can be loaded at another base address"""
        return (hasattr(self.pe, 'DIRECTORY_ENTRY_BASERELOC') and
                not self.pe.FILE_HEADER.Characteristics & 0x0001)  # RELOCS_STRIPPED

    def rebase(self, new_base):
        """Apply base relocations so the image runs at new_base"""
        delta = new_base - self.image_base
        self.pe.relocate_image(new_base)
        self.image_base = new_base
        for section, info in zip(self.pe.sections, self.sections):
            info['data'] = bytes(section.get_data())
        for functions in self.imports.values():
            for func in functions:
                func['address'] += delta

    def get_section_by_rva(self, rva):
        """Find section by RVA address"""
        for section in self.sections:
            start = section['virtual_address']
            end = start + section['virtual_size']
            if start <= rva < end:
                return section
        return None

    def rva_to_offset(self, rva):
        """Convert RVA to file offset"""
        section = self.get_section_by_rva(rva)
        if section:
            return rva - section['virtual_address'] + section['raw_offset']
        return None

    def get_data_at_rva(self, rva, size):
        """Read data at RVA address"""
        section = self.get_section_by_rva(rva)
        if section:
            offset = rva - section['virtual_address']
            return section['data'][offset:offset+size]
        return None

    def print_summary(self):
        """PE file summary"""
        log.header("PE File Summary")
        log.success(f"Total {len(self.sections)} sections loaded!")
        log.success(f"Imports from {len(self.imports)} DLLs!")

        total_imports = sum(len(funcs) for funcs in self.imports.values())
        log.success(f"Total {total_imports} functions imported!")
        log.success(f"Total {len(self.exports)} exports!")
        log.info(f"Entry point: 0x{self.image_base + self.entry_point:08x}")

    def is_console_program(self):
        """True for IMAGE_SUBSYSTEM_WINDOWS_CUI EXEs (they start with a console)"""
        return self.subsystem == 3


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

    def flush(self):
        if not self._out:
            return
        text = self._out.decode(ANSI_CODEPAGE, errors='replace')
        self._out.clear()
        if self.kind == 'stderr':
            log.write(f"{Fore.RED}[STDERR]{Style.RESET_ALL} {text}")
        else:
            log.write(f"{Fore.YELLOW}[STDOUT]{Style.RESET_ALL} {text}")
        self.handler.console_output.append(text)
        self.handler.console_write(text, self.kind)

    def _fill(self):
        """Read one more line of input. Returns False at EOF."""
        if self.kind != 'stdin':
            raise OSError("stream is not readable")
        # Make any pending prompt visible before blocking for input
        self.handler.flush_std_streams()
        gui = self.handler.gui
        if gui:
            # No console (GUI program): stdin is at EOF
            line = self.handler.console_read_line()
            if line is None:
                return False
            self._in += (line + "\n").encode(ANSI_CODEPAGE, errors='replace')
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
    """API result that transfers control elsewhere (longjmp)."""
    __slots__ = ('eip', 'esp', 'eax')

    def __init__(self, eip, esp, eax):
        self.eip = eip
        self.esp = esp
        self.eax = eax


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


def resolve_c_drive_path(filename):
    """Map a Windows-style filename into the c_drive/ sandbox.

    The emulated program may only ever touch files inside c_drive/.
    Any path that would escape that directory (via "..", an absolute
    path, or a drive letter pointing elsewhere) is rejected and this
    returns None. On success it returns the absolute host path, which is
    guaranteed to live under C_DRIVE_PATH.
    """
    if not filename:
        return None

    # Make sure the sandbox root exists so real I/O can happen.
    try:
        os.makedirs(C_DRIVE_PATH, exist_ok=True)
    except OSError as e:
        log.error(f"Cannot create c_drive/ sandbox: {e}")
        return None

    # Normalise Windows path syntax to a relative POSIX-ish path.
    name = filename.replace('\\', '/')

    # Strip a drive-letter prefix ("C:/...", "c:foo"). Everything is
    # treated as living on the emulated C: drive regardless of letter.
    if len(name) >= 2 and name[1] == ':':
        name = name[2:]

    # Drop UNC / leading-slash roots so they are taken relative to the
    # sandbox instead of the host filesystem root.
    name = name.lstrip('/')

    if not name:
        return None

    # Resolve against the sandbox root and confirm containment. Using
    # realpath collapses any "..", symlinks, etc. before the check so a
    # crafted name cannot climb out of c_drive/.
    root = os.path.realpath(C_DRIVE_PATH)
    candidate = os.path.realpath(os.path.join(root, name))

    if candidate != root and not candidate.startswith(root + os.sep):
        log.warning(f"Blocked sandbox escape attempt: \"{filename}\"")
        return None

    return candidate


def environment_folders(environment):
    """Windows folders named by environment variables (deduplicated)."""
    folders = []
    for name, value in environment.items():
        for entry in value.split(';'):
            entry = entry.strip()
            if len(entry) < 2 or entry[1] != ':':
                continue  # only absolute drive paths name folders
            if name.upper() in ENVIRONMENT_FILE_VARIABLES:
                entry = entry.replace('/', '\\').rsplit('\\', 1)[0]
            if entry.lower() not in (f.lower() for f in folders):
                folders.append(entry)
    return folders


def create_environment_folders(environment=DEFAULT_ENVIRONMENT):
    """Create the folders named by the environment (C:\\Windows, ...) and the
    examples folder (C:\\Windows\\Examples) in c_drive/."""
    for folder in environment_folders(environment) + [EXAMPLES_FOLDER]:
        path = resolve_c_drive_path(folder)
        if path is None:
            continue
        try:
            os.makedirs(path, exist_ok=True)
            log.debug(f"Environment folder ready: {folder} -> {path}")
        except OSError as e:
            log.warning(f"Cannot create environment folder {folder}: {e}")


# Startup scripts: c_drive/ folders, and the examples compiled into C:\Windows\Examples
CREATE_C_DRIVE_SCRIPT = os.path.join(SCRIPT_DIR, "scripts", "create_c_drive_environment.sh")
COMPILE_EXAMPLES_SCRIPT = os.path.join(SCRIPT_DIR, "scripts", "compile_examples.sh")
REMOVE_C_DRIVE_SCRIPT = os.path.join(SCRIPT_DIR, "scripts", "remove_c_drive_environment.sh")


def run_setup_script(script, title):
    """Run a startup shell script; failures are reported, not fatal."""
    if not os.path.isfile(script):
        log.warning(f"Script not found: {script}")
        return
    log.header(title)
    try:
        result = subprocess.run(['sh', script], cwd=SCRIPT_DIR,
                                capture_output=True, text=True, timeout=600)
    except (OSError, subprocess.TimeoutExpired) as e:
        log.warning(f"{os.path.basename(script)} failed: {e}")
        return
    for line in (result.stdout + result.stderr).splitlines():
        if line.startswith('OK:'):
            log.info(line)
        elif line.strip():
            log.warning(line)


def _program_folder_host_path(folder):
    """Host directory of an emulated program folder (C:\\ is c_drive/ itself)."""
    if folder.rstrip('\\/') in ('C:', 'c:'):
        return os.path.realpath(C_DRIVE_PATH)
    return resolve_c_drive_path(folder)


def _folder_programs(directory):
    """Names of the EXE files directly inside a host directory, sorted."""
    try:
        return sorted((f for f in os.listdir(directory)
                       if f.lower().endswith('.exe')
                       and os.path.isfile(os.path.join(directory, f))),
                      key=str.lower)
    except (OSError, TypeError):
        return []


def _program_subfolders(directory):
    """Names of the folders directly inside a host directory, sorted."""
    try:
        return sorted((d for d in os.listdir(directory)
                       if os.path.isdir(os.path.join(directory, d))), key=str.lower)
    except (OSError, TypeError):
        return []


def find_program(name):
    """Host path of the EXE to run, or None if it does not exist.

    A Windows path (C:\\Windows\\Examples\\gdi_example\\gdi_example.exe, ...)
    is resolved inside c_drive/; a bare file name is searched in
    PROGRAM_FOLDERS (C:\\ first, then C:\\Windows\\Examples) and in their
    subfolders (each example lives in its own folder).
    """
    if not name:
        return None
    if any(sep in name for sep in '\\/:'):
        path = resolve_c_drive_path(name)
        return path if path and os.path.isfile(path) else None
    for folder in PROGRAM_FOLDERS:
        directory = _program_folder_host_path(folder)
        if not directory:
            continue
        for sub in [''] + _program_subfolders(directory):
            path = os.path.join(directory, sub, name)
            if os.path.isfile(path):
                return path
    return None


def list_programs():
    """Windows paths of the EXE files in each PROGRAM_FOLDERS entry and its
    subfolders (for the Start menu): {folder: [paths]}."""
    programs = {}
    for folder in PROGRAM_FOLDERS:
        directory = _program_folder_host_path(folder)
        prefix = folder.rstrip('\\') + '\\'
        paths = [prefix + f for f in _folder_programs(directory)]
        if directory:
            for sub in _program_subfolders(directory):
                paths += [f"{prefix}{sub}\\{f}"
                          for f in _folder_programs(os.path.join(directory, sub))]
        programs[folder] = sorted(paths, key=lambda p: p.rsplit('\\', 1)[-1].lower())
    return programs


class SoundPlayer:
    """Audio output for Beep, MessageBeep and PlaySound (pygame.mixer).

    Without pygame or an audio device every sound is silent; callers still
    keep the right timing (e.g. Beep blocks for its duration).
    """

    _lock = threading.Lock()
    _format = None        # None: not tried yet, False: no audio, else mixer format
    _play_sound = None    # Sound started by PlaySound (only one at a time)
    _play_owner = None    # Process (WinAPIHandler) that started _play_sound

    # Sample packing per mixer sample size: (array typecode, scale, offset)
    _SAMPLE_FORMATS = {-16: ('h', 32767, 0), 16: ('H', 32767, 32768),
                       -8: ('b', 127, 0), 8: ('B', 127, 128),
                       32: ('f', 1.0, 0), -32: ('f', 1.0, 0)}

    @classmethod
    def _mixer(cls):
        """Initialize pygame.mixer once; returns (rate, size, channels) or False."""
        with cls._lock:
            if cls._format is None:
                cls._format = False
                if PYGAME_AVAILABLE:
                    try:
                        if not pygame.mixer.get_init():
                            pygame.mixer.init(frequency=44100, size=-16, channels=1)
                        cls._format = pygame.mixer.get_init() or False
                    except pygame.error as e:
                        log.warning(f"No audio device, sounds are silent: {e}")
            return cls._format

    @classmethod
    def available(cls):
        return bool(cls._mixer())

    @classmethod
    def tone(cls, frequency, duration_ms, volume=0.2):
        """Start a square-wave tone (PC speaker style); returns the Sound or None"""
        fmt = cls._mixer()
        if not fmt or frequency <= 0 or duration_ms <= 0:
            return None
        rate, size, channels = fmt
        packing = cls._SAMPLE_FORMATS.get(size)
        if packing is None:
            return None
        typecode, scale, offset = packing
        count = int(rate * duration_ms / 1000)
        half_period = rate / (2.0 * frequency)
        amplitude = volume * scale
        values = [amplitude if int(i / half_period) % 2 == 0 else -amplitude
                  for i in range(count)]
        # Short linear fade in/out avoids clicks at the edges
        fade = min(count // 2, max(1, rate // 500))
        for i in range(fade):
            k = i / fade
            values[i] *= k
            values[count - 1 - i] *= k
        values = [v + offset for v in values]
        if typecode != 'f':
            values = [int(v) for v in values]
        if channels > 1:
            values = [v for v in values for _ in range(channels)]
        samples = array.array(typecode, values)
        try:
            sound = pygame.mixer.Sound(buffer=samples.tobytes())
            sound.play()
            return sound
        except pygame.error as e:
            log.debug(f"Tone playback failed: {e}")
            return None

    @classmethod
    def play(cls, source, loop=False, owner=None):
        """Play a WAV file path or file-like object as the PlaySound sound.

        Returns the length in seconds, or None if it cannot be decoded.
        """
        if not cls._mixer():
            return 0.0
        try:
            sound = pygame.mixer.Sound(file=source)
        except (pygame.error, OSError) as e:
            log.debug(f"Cannot play sound: {e}")
            return None
        cls.stop()
        cls._play_sound, cls._play_owner = sound, owner
        sound.play(loops=-1 if loop else 0)
        return sound.get_length()

    @classmethod
    def play_tone(cls, frequency, duration_ms, owner=None):
        """Play a tone as the PlaySound sound (system sound aliases)"""
        cls.stop()
        cls._play_sound, cls._play_owner = cls.tone(frequency, duration_ms), owner

    @classmethod
    def playing(cls):
        """True while the PlaySound sound is still playing"""
        sound = cls._play_sound
        return bool(sound and sound.get_num_channels())

    @classmethod
    def stop(cls):
        """Stop the PlaySound sound"""
        sound, cls._play_sound = cls._play_sound, None
        cls._play_owner = None
        if sound is not None:
            try:
                sound.stop()
            except pygame.error:
                pass

    @classmethod
    def stop_owned_by(cls, owner):
        """Stop the PlaySound sound if the given process started it"""
        if cls._play_sound is not None and cls._play_owner is owner:
            cls.stop()

class WinAPIHandler:
    """Windows API emulation"""

    # Imports from these DLLs use cdecl (caller cleans the stack)
    CDECL_DLL_PREFIXES = ('msvcr', 'msvcp', 'crtdll', 'ucrtbase', 'api-ms-win-crt-')

    # Variadic functions exported by stdcall DLLs are cdecl
    CDECL_FUNCTIONS = {'wsprintfA', 'wsprintfW'}

    # Argument counts (DWORDs) for emulated stdcall APIs. The callee must pop
    # these from the stack before returning, exactly like the real DLLs do.
    STDCALL_ARG_COUNTS = {
        # kernel32
        'GetModuleHandleA': 1, 'GetModuleHandleW': 1, 'GetProcAddress': 2,
        'ExitProcess': 1, 'GetCommandLineA': 0, 'GetCommandLineW': 0,
        'SetUnhandledExceptionFilter': 1, 'AllocConsole': 0, 'FreeConsole': 0,
        'GetStdHandle': 1, 'GetFileType': 1, 'SetHandleCount': 1, 'WriteFile': 5, 'WriteConsoleA': 5, 'WriteConsoleW': 5,
        'MultiByteToWideChar': 6, 'WideCharToMultiByte': 8,
        'GetLastError': 0, 'SetLastError': 1, 'VirtualAlloc': 4,
        'VirtualFree': 3, 'HeapCreate': 3, 'HeapAlloc': 3, 'HeapFree': 3,
        'GetProcessHeap': 0, 'GetCurrentProcess': 0, 'GetCurrentProcessId': 0,
        'GetCurrentThreadId': 0, 'GetTickCount': 0, 'MulDiv': 3,
        'GetLocalTime': 1, 'GetSystemTime': 1, 'Beep': 2,
        'QueryPerformanceCounter': 1, 'GetSystemTimeAsFileTime': 1,
        'IsDebuggerPresent': 0, 'GetVersion': 0, 'GetVersionExA': 1,
        'GetVersionExW': 1, 'SetErrorMode': 1, 'GetModuleFileNameA': 3,
        'GetModuleFileNameW': 3, 'LoadLibraryA': 1, 'LoadLibraryW': 1,
        'LoadLibraryExA': 3, 'LoadLibraryExW': 3, 'FreeLibrary': 1,
        'GetSystemDirectoryA': 2, 'GetSystemDirectoryW': 2,
        'GetWindowsDirectoryA': 2, 'GetWindowsDirectoryW': 2,
        'GetTempPathA': 2, 'lstrlenA': 1, 'lstrlenW': 1, 'IsDBCSLeadByteEx': 2,
        'GetStartupInfoA': 1, 'GetStartupInfoW': 1, 'lstrcpyA': 2,
        'lstrcpynA': 3, 'lstrcatA': 2, 'lstrcmpA': 2, 'lstrcmpiA': 2,
        'GlobalAlloc': 2, 'GlobalFree': 1, 'GlobalLock': 1, 'GlobalUnlock': 1,
        'LocalAlloc': 2, 'LocalFree': 1, 'CloseHandle': 1, 'Sleep': 1,
        'GetFileAttributesA': 1, 'CreateFileA': 7, 'CreateFileW': 7,
        'GetFileSize': 2, 'SetFilePointer': 4, 'DeleteFileA': 1,
        'CreateDirectoryA': 2, 'RemoveDirectoryA': 1,
        'ReadFile': 5, 'ReadConsoleA': 5, 'GetEnvironmentVariableA': 3,
        'ExpandEnvironmentStringsA': 3, 'InitializeCriticalSection': 1,
        'InitializeCriticalSectionAndSpinCount': 2, 'EnterCriticalSection': 1,
        'TryEnterCriticalSection': 1, 'LeaveCriticalSection': 1,
        'DeleteCriticalSection': 1, 'GetFileAttributesW': 1, 'DeleteFileW': 1,
        'CreateDirectoryW': 2, 'RemoveDirectoryW': 1, 'CopyFileA': 3,
        'CopyFileW': 3, 'MoveFileA': 2, 'MoveFileW': 2,
        'GetCurrentDirectoryA': 2, 'GetCurrentDirectoryW': 2,
        'GetComputerNameA': 2, 'GetComputerNameW': 2, 'GetSystemInfo': 1,
        'GlobalMemoryStatus': 1, 'QueryPerformanceFrequency': 1,
        'GetTickCount64': 0, 'GetACP': 0, 'GetOEMCP': 0, 'GetUserDefaultLangID': 0,
        'GetDiskFreeSpaceA': 5,
        'LocalFileTimeToFileTime': 2, 'SetFileTime': 4,
        'SetConsoleTitleA': 1, 'SetConsoleTitleW': 1,
        'FindFirstFileA': 2, 'FindFirstFileW': 2, 'FindNextFileA': 2,
        'FindNextFileW': 2, 'FindClose': 1, 'SetCurrentDirectoryA': 1,
        'SetCurrentDirectoryW': 1, 'GetFullPathNameA': 4, 'GetTempFileNameA': 4,
        'FlushFileBuffers': 1, 'SetEndOfFile': 1, 'lstrcpyW': 2, 'lstrcatW': 2,
        'lstrcmpW': 2, 'lstrcmpiW': 2, 'SetEnvironmentVariableA': 2,
        'SetEnvironmentVariableW': 2, 'GetEnvironmentVariableW': 3,
        'GetPrivateProfileStringA': 6, 'WritePrivateProfileStringA': 4,
        'HeapReAlloc': 4, 'HeapDestroy': 1, 'GetEnvironmentStrings': 0,
        'GetEnvironmentStringsA': 0, 'GetEnvironmentStringsW': 0,
        'FreeEnvironmentStringsA': 1, 'FreeEnvironmentStringsW': 1, 'GetCPInfo': 2,
        'GetStringTypeA': 5, 'GetStringTypeW': 4, 'LCMapStringA': 6, 'LCMapStringW': 6,
        'RtlUnwind': 4, 'UnhandledExceptionFilter': 1, 'TerminateProcess': 2,
        'FindResourceA': 3, 'LoadResource': 2, 'LockResource': 1, 'FreeResource': 1,
        'SizeofResource': 2,
        'CreateProcessA': 10, 'GetExitCodeProcess': 2, 'WaitForSingleObject': 2,
        'HeapSize': 3, 'SetVolumeLabelA': 2, 'SetLocalTime': 1,
        'GetVolumeInformationA': 8, 'GetLogicalDrives': 0,
        'FileTimeToSystemTime': 2, 'SystemTimeToFileTime': 2,
        'FileTimeToLocalFileTime': 2, 'GetDriveTypeA': 1,
        'SetFileAttributesA': 2, 'CompareStringA': 6, 'RaiseException': 4,
        # user32
        'GetSystemMetrics': 1, 'MessageBoxA': 4, 'MessageBoxW': 4,
        'LoadCursorA': 2, 'LoadCursorW': 2, 'LoadIconA': 2, 'LoadIconW': 2,
        'RegisterClassA': 1, 'RegisterClassExA': 1, 'CreateWindowExA': 12,
        'RegisterClassW': 1, 'RegisterClassExW': 1, 'CreateWindowExW': 12,
        'SetWindowTextW': 2, 'GetWindowTextW': 3, 'SendMessageW': 4,
        'PostMessageW': 4, 'GetMessageW': 4, 'DispatchMessageW': 1,
        'DefWindowProcW': 4,
        'ShowWindow': 2, 'UpdateWindow': 1, 'DestroyWindow': 1,
        'SetWindowTextA': 2, 'GetWindowTextA': 3, 'GetClientRect': 2,
        'GetWindowRect': 2, 'SetRect': 5, 'SetRectEmpty': 1, 'CopyRect': 2,
        'OffsetRect': 3, 'InflateRect': 3, 'PtInRect': 3, 'EqualRect': 2,
        'IsRectEmpty': 1, 'IntersectRect': 3, 'UnionRect': 3,
        'MoveWindow': 6, 'SetWindowPos': 7, 'EnableWindow': 2,
        'GetDlgItem': 2, 'GetDlgItemTextA': 4, 'SetDlgItemTextA': 3,
        'GetDlgItemInt': 4, 'SetDlgItemInt': 4, 'GetDlgCtrlID': 1,
        'GetWindowLongA': 2, 'SetWindowLongA': 3, 'GetWindowLongW': 2,
        'SetWindowLongW': 3, 'CheckDlgButton': 3, 'IsDlgButtonChecked': 2,
        'SetFocus': 1, 'GetFocus': 0, 'GetAsyncKeyState': 1, 'GetKeyState': 1,
        'GetCursorPos': 1, 'SetCursorPos': 2, 'ScreenToClient': 2,
        'ClientToScreen': 2, 'SetCapture': 1, 'ReleaseCapture': 0,
        'GetCapture': 0, 'GetParent': 1, 'IsWindow': 1, 'IsWindowVisible': 1,
        'IsWindowEnabled': 1, 'MessageBeep': 1, 'SetScrollPos': 4,
        'GetScrollPos': 2, 'SetScrollRange': 5, 'GetScrollRange': 4,
        'SetScrollInfo': 4, 'GetScrollInfo': 3, 'SendMessageA': 4,
        'PostMessageA': 4, 'PostQuitMessage': 1, 'SetTimer': 4, 'KillTimer': 2,
        'GetMessageA': 4, 'PeekMessageA': 5, 'PeekMessageW': 5,
        'TranslateMessage': 1, 'DispatchMessageA': 1, 'DefWindowProcA': 4,
        'BeginPaint': 2, 'EndPaint': 2, 'InvalidateRect': 3, 'ValidateRect': 2,
        'FillRect': 3, 'FrameRect': 3, 'GetDC': 1, 'ReleaseDC': 2,
        'DrawTextA': 5, 'DrawTextW': 5, 'CreateMenu': 0, 'CreatePopupMenu': 0,
        'AppendMenuA': 4, 'SetMenu': 2, 'DrawMenuBar': 1, 'DestroyMenu': 1,
        'GetSysColor': 1, 'GetSysColorBrush': 1, 'GetDesktopWindow': 0,
        'GetForegroundWindow': 0, 'GetActiveWindow': 0, 'GetDoubleClickTime': 0,
        'CharUpperA': 1, 'CharLowerA': 1, 'IsCharAlphaA': 1,
        'IsCharAlphaNumericA': 1, 'CharUpperW': 1, 'CharLowerW': 1,
        'CharNextA': 1, 'CharPrevA': 2, 'IsCharUpperA': 1, 'IsCharLowerA': 1,
        'wvsprintfA': 3, 'FindWindowA': 2, 'GetClassNameA': 3,
        'GetWindowTextLengthA': 1, 'BringWindowToTop': 1,
        'SetForegroundWindow': 1, 'AdjustWindowRect': 3, 'AdjustWindowRectEx': 4, 'LoadStringA': 4,
        'LoadBitmapA': 2, 'IsIconic': 1, 'OpenIcon': 1,
        'GetWindow': 2, 'CharToOemBuffA': 3, 'OemToCharBuffA': 3,
        'SetKeyboardState': 1, 'GetKeyboardState': 1, 'IsDialogMessageA': 2,
        'ChangeDisplaySettingsA': 2, 'EnumDisplaySettingsA': 3, 'SetCursor': 1,
        'EndDialog': 2, 'RegisterWindowMessageA': 1, 'SystemParametersInfoA': 4,
        'LoadKeyboardLayoutA': 2, 'CreateCursor': 7, 'DestroyIcon': 1,
        'DestroyCursor': 1, 'IsZoomed': 1, 'ShowCursor': 1, 'DialogBoxParamA': 5,
        'GetWindowPlacement': 2, 'SetWindowPlacement': 2,
        # gdi32
        'GetDeviceCaps': 2, 'TextOutA': 5, 'TextOutW': 5, 'SetTextColor': 2,
        'SetBkColor': 2, 'SetBkMode': 2, 'CreatePen': 3, 'CreateSolidBrush': 1,
        'CreateHatchBrush': 2, 'GetStockObject': 1, 'SelectObject': 2,
        'DeleteObject': 1, 'MoveToEx': 4, 'LineTo': 3, 'Rectangle': 5,
        'Ellipse': 5, 'SetPixel': 4, 'GetPixel': 3, 'Polygon': 3,
        'Polyline': 3, 'RoundRect': 7, 'Arc': 9, 'Pie': 9, 'Chord': 9,
        'PatBlt': 6, 'CreateFontA': 14, 'CreateFontIndirectA': 1,
        'GetTextExtentPoint32A': 4, 'CreateCompatibleDC': 1,
        'CreateCompatibleBitmap': 3, 'DeleteDC': 1, 'BitBlt': 9,
        'StretchBlt': 11, 'SetTextAlign': 2, 'GetTextColor': 1, 'GetBkColor': 1,
        'CreatePenIndirect': 1, 'CreateBrushIndirect': 1, 'GetTextMetricsA': 2,
        'SetROP2': 2, 'GetObjectA': 3, 'CreateBitmap': 5,
        'CreatePalette': 1, 'SelectPalette': 3, 'RealizePalette': 1,
        'StretchDIBits': 13, 'SetStretchBltMode': 2, 'GetDIBits': 7,
        'CreateDCA': 4, 'EnumFontFamiliesA': 4,
        # advapi32
        'RegOpenKeyExA': 5, 'RegOpenKeyExW': 5, 'RegQueryValueExA': 6,
        'RegQueryValueExW': 6, 'RegCloseKey': 1, 'RegSetValueExA': 6,
        'RegSetValueExW': 6, 'RegCreateKeyExA': 9, 'RegCreateKeyExW': 9,
        'GetUserNameA': 2, 'GetUserNameW': 2, 'RegDeleteValueA': 2,
        'RegDeleteKeyA': 2, 'RegEnumKeyExA': 8, 'RegEnumValueA': 8,
        # winmm
        'timeGetTime': 0, 'timeBeginPeriod': 1, 'timeEndPeriod': 1,
        'PlaySoundA': 3, 'PlaySoundW': 3, 'sndPlaySoundA': 2, 'sndPlaySoundW': 2,
        'waveOutOpen': 6, 'waveOutWrite': 3, 'waveOutPrepareHeader': 3,
        'waveOutUnprepareHeader': 3, 'waveOutReset': 1, 'waveOutPause': 1,
        'waveOutRestart': 1, 'waveOutClose': 1, 'waveOutGetPosition': 3,
        'joyGetPos': 2, 'joyGetDevCapsA': 3, 'mciSendCommandA': 4,
        # msacm32
        'acmStreamOpen': 8, 'acmFormatSuggest': 5, 'acmStreamClose': 2,
        'acmStreamSize': 4, 'acmStreamPrepareHeader': 3, 'acmStreamConvert': 3,
        'acmStreamUnprepareHeader': 3,
        # ole32
        'OleInitialize': 1, 'OleUninitialize': 0, 'CoInitialize': 1,
        'CoUninitialize': 0,
        # comdlg32
        'GetOpenFileNameA': 1, 'GetSaveFileNameA': 1, 'FindTextA': 1,
        # shell32
        'ExtractIconA': 3,
        # comctl32
        'InitCommonControls': 0, 'CreateStatusWindowA': 4,
    }

    # Windows message constants
    WM_CREATE = 0x0001
    WM_DESTROY = 0x0002
    WM_PAINT = 0x000F
    WM_CLOSE = 0x0010
    WM_QUIT = 0x0012
    WM_SHOWWINDOW = 0x0018
    WM_KEYDOWN = 0x0100
    WM_KEYUP = 0x0101
    WM_CHAR = 0x0102
    WM_COMMAND = 0x0111
    WM_DRAWITEM = 0x002B
    WM_TIMER = 0x0113
    WM_MOUSEMOVE = 0x0200
    WM_LBUTTONDOWN = 0x0201
    WM_LBUTTONUP = 0x0202
    WM_RBUTTONDOWN = 0x0204
    WM_RBUTTONUP = 0x0205

    # Mouse key state flags (wParam for mouse messages)
    MK_LBUTTON = 0x0001
    MK_RBUTTON = 0x0002

    # Button notification codes (high word of WM_COMMAND wParam)
    BN_CLICKED = 0

    # Control notification codes (high word of WM_COMMAND wParam)
    LBN_SELCHANGE = 1
    CBN_SELCHANGE = 1

    # Button control messages
    BM_GETCHECK = 0x00F0
    BM_SETCHECK = 0x00F1
    # BS_CHECKBOX, BS_AUTOCHECKBOX, BS_RADIOBUTTON, BS_3STATE, BS_AUTO3STATE,
    # BS_AUTORADIOBUTTON
    CHECK_BUTTON_STYLES = (0x2, 0x3, 0x4, 0x5, 0x6, 0x9)

    # Listbox control messages
    LB_ADDSTRING = 0x0180
    LB_INSERTSTRING = 0x0181
    LB_DELETESTRING = 0x0182
    LB_RESETCONTENT = 0x0184
    LB_SETCURSEL = 0x0186
    LB_GETCURSEL = 0x0188
    LB_GETTEXT = 0x0189
    LB_GETTEXTLEN = 0x018A
    LB_GETCOUNT = 0x018B
    LB_ERR = 0xFFFFFFFF  # -1 as unsigned

    # Combobox control messages
    CB_ADDSTRING = 0x0143
    CB_DELETESTRING = 0x0144
    CB_GETCOUNT = 0x0146
    CB_GETCURSEL = 0x0147
    CB_GETLBTEXT = 0x0148
    CB_GETLBTEXTLEN = 0x0149
    CB_RESETCONTENT = 0x014B
    CB_SETCURSEL = 0x014E
    CB_ERR = 0xFFFFFFFF

    # PeekMessage removal flags
    PM_NOREMOVE = 0x0000
    PM_REMOVE = 0x0001

    # Scrollbar messages and notification codes
    WM_HSCROLL = 0x0114
    WM_VSCROLL = 0x0115
    SB_LINEUP = 0        # Also SB_LINELEFT
    SB_LINEDOWN = 1      # Also SB_LINERIGHT
    SB_PAGEUP = 2        # Also SB_PAGELEFT
    SB_PAGEDOWN = 3      # Also SB_PAGERIGHT
    SB_THUMBPOSITION = 4
    SB_THUMBTRACK = 5
    SB_ENDSCROLL = 8

    # Scrollbar selectors (nBar) and control style
    SB_HORZ = 0
    SB_VERT = 1
    SB_CTL = 2
    SBS_VERT = 0x0001

    # Scrollbar control messages (SBM_*)
    SBM_SETPOS = 0x00E0
    SBM_GETPOS = 0x00E1
    SBM_SETRANGE = 0x00E2
    SBM_GETRANGE = 0x00E3

    def __init__(self, emulator, gui=None):
        self.emu = emulator
        self.gui = gui  # PseudoWindowsGUI reference
        self.handles = {}
        self.module_handles = {}  # lowercase DLL name -> fake HMODULE
        self.virtual_allocs = {}  # VirtualAlloc base -> reserved size
        self.mapped_virtual_allocs = set()  # Bases mapped at a requested address
        self.next_handle = 0x1000
        self.console_output = []
        # Own console: has_console follows AllocConsole/FreeConsole, console is
        # the GUI console window (FakeConsole) when the GUI is running
        self.has_console = False
        self.console = None
        # msvcrt FILE* streams: fake FILE pointer -> {'fp': python file, 'path': str}
        self.file_streams = {}
        self.next_file_ptr = 0x0F000000  # dedicated range for fake FILE* pointers
        self._last_error = 0  # GetLastError/SetLastError storage
        self.registered_classes = {}  # Registered window classes
        self.atoms = {}  # RegisterClass atoms
        self.next_atom = 0xC000

        # Message queue system
        self.message_queue = []
        self.message_lock = threading.Lock()  # Guards message_queue (GUI thread is producer)
        self.painted_windows = set()  # Windows that received WM_PAINT
        self.dirty_controls = {}  # Owner-draw controls waiting for WM_DRAWITEM (ordered)
        self._drawitem_buf = 0
        self.quit_requested = False
        # True once the emulated process is gone (ExitProcess or emulation end).
        # After that no window can consume messages, so the GUI must stop
        # treating windows as live app windows (e.g. X click posts WM_CLOSE).
        self.process_exited = False

        # GDI object/DC state (all touched only on the emulation thread)
        self.gdi_objects = {}  # handle -> {'type': 'pen'|'brush', 'color': (r,g,b), 'width': int}
        self._bits_cache = {}  # (width, height, bpp, bits) -> RGB of CreateBitmap
        self._dib_cache = {}   # GetDIBits request + display list -> (bits, data refs)
        self.dc_map = {}       # hdc -> hwnd the DC draws into
        self.dc_state = {}     # hdc -> {'pen','brush','pos','text_color','bk_mode','bk_color'}
        self._stock_objects = {}  # GetStockObject index -> handle
        self._sys_color_brushes = {}  # GetSysColorBrush index -> handle

        # Timers: (hwnd, timer_id) -> {'elapse': sec, 'callback': addr, 'next_fire': time}
        self.timers = {}
        self.next_timer_id = 1

        # Menus: hmenu -> list of items
        # item = {'flags': int, 'id': int, 'text': str, 'submenu': hmenu or 0}
        self.menus = {}

        # GetWindowLong/SetWindowLong storage: hwnd -> {index: value}
        self.window_longs = {}

        # Mouse capture (SetCapture/ReleaseCapture) - hwnd or 0
        self.capture_hwnd = 0

        # Dialogs (DialogBoxParam, common dialogs): hwnd -> {'proc', 'handler',
        # 'owner', 'result', 'ended'}
        self.dialogs = {}

        # Cursor (SetCursor/ShowCursor) and keyboard toggle state (SetKeyboardState)
        self.current_cursor = 0
        self.cursor_count = 0
        self.keyboard_toggles = bytearray(256)

        # Multimedia: wave output devices, ACM streams, MCI devices (by handle/id)
        self.wave_outs = {}
        self.acm_streams = {}
        self.mci_devices = {}
        self.next_mci_id = 1

        # MSVCRT rand() state (MSVC-compatible LCG) and clock() epoch
        self._rand_seed = 1
        self._clock_epoch = time.time()

        # Process environment (GetEnvironmentVariable, getenv, _putenv);
        # keys are upper-case since Windows names are case-insensitive
        self.environment = dict(DEFAULT_ENVIRONMENT)

        # Current directory (SetCurrentDirectory); relative paths resolve against it.
        # Programs start in their EXE's folder, like when launched from Explorer.
        exe_dir = self.windows_exe_path().rsplit('\\', 1)[0]
        self.current_directory = exe_dir if len(exe_dir) > 2 else "C:\\"

        # (type, name) -> (RVA, size) of the EXE's resources, built on first use
        self._resource_index = None

        # In-memory registry: predefined HKEY -> key node, open HKEY -> key node
        self.registry_roots = {}
        self.registry_handles = {}
        self._init_registry()

        # Additional CRT state (strtok, getenv strings, signals, time buffers)
        self.next_fd = 3  # CRT file descriptors handed out by fopen
        self._strtok_next = {}  # unit size -> next strtok/wcstok position
        self._getenv_cache = {}  # (name, wide) -> (value, heap address)
        self._signal_handlers = {}
        self._crt_static = {}  # name -> static CRT buffer (strerror, asctime...)

        # MSVCRT global variable memory addresses (lazy init)
        self._fmode_addr = 0
        self._commode_addr = 0
        self._acmdln_addr = 0
        self._wcmdln_addr = 0
        self._environ_addr = 0
        self._wenviron_addr = 0
        self._argc = 0
        self._argv_addr = 0
        self.exit_handlers = []
        self.exit_code = None
        self._exit_handlers_ran = False
        self._wargv_addr = 0
        self._environ_ptr_addr = 0
        self._wenviron_ptr_addr = 0
        self._initenv_addr = 0
        self._winitenv_addr = 0

        # CRT stdio: _iob[3] FILE structs backed by ConsoleStream objects
        self._iob_addr = 0
        self.std_streams = []
        self._errno_addr = 0
        self._lconv_addr = 0
        self._c_locale_addr = 0

        # API name mapping (for functions starting with double underscore)
        self._api_map = {
            '__p__fmode': self.api__p__fmode,
            '__p__commode': self.api__p__commode,
            '__p__acmdln': self.api__p__acmdln,
            '__p__wcmdln': self.api__p__wcmdln,
            '__set_app_type': self.api__set_app_type,
            '__getmainargs': self.api__getmainargs,
            '__wgetmainargs': self.api__wgetmainargs,
            '__p___argc': self.api__p___argc,
            '__p___argv': self.api__p___argv,
            '__p___wargv': self.api__p___wargv,
            '__CxxFrameHandler3': self.api__CxxFrameHandler3,
            '__dllonexit': self.api__dllonexit,
            '__security_init_cookie': self.api__security_init_cookie,
            '__security_check_cookie': self.api__security_check_cookie,
            '__iob_func': self.api__iob_func,
            '__acrt_iob_func': self.api__acrt_iob_func,
        }
        self._api_map.update(self._crt_extra_api_map())

    def get_api_handler(self, func_name):
        """Find API handler"""
        # First search in mapping
        if func_name in self._api_map:
            return self._api_map[func_name]
        # Then search as normal attribute
        return getattr(self, func_name, None)

    def stack_cleanup_bytes(self, dll_name, func_name):
        """Bytes of arguments the callee pops on return (stdcall).

        Returns 0 for cdecl functions and None when the function is stdcall
        but its argument count is unknown.
        """
        dll = dll_name.lower()
        if dll.startswith(self.CDECL_DLL_PREFIXES) or func_name in self.CDECL_FUNCTIONS:
            return 0
        argc = self.STDCALL_ARG_COUNTS.get(func_name)
        return None if argc is None else argc * 4

    # MSVCRT FILE layout: _ptr, _cnt, _base, _flag, _file, _charbuf, _bufsiz, _tmpfname
    _FILE_SIZE = 0x20
    _IOREAD = 0x0001
    _IOWRT = 0x0002

    def _ensure_iob(self):
        """Allocate the CRT _iob[3] array and bind stdin/stdout/stderr to it."""
        if self._iob_addr:
            return self._iob_addr
        self._iob_addr = self.emu.heap_alloc(self._FILE_SIZE * 3)
        for fd, kind in enumerate(('stdin', 'stdout', 'stderr')):
            ptr = self._iob_addr + fd * self._FILE_SIZE
            flag = self._IOREAD if fd == 0 else self._IOWRT
            file_struct = struct.pack('<IIIIIIII', 0, 0, 0, flag, fd, 0, 0, 0)
            self.emu.uc.mem_write(ptr, file_struct)
            stream = ConsoleStream(self, kind)
            self.std_streams.append(stream)
            self.file_streams[ptr] = {'fp': stream, 'path': kind}
        return self._iob_addr

    def flush_std_streams(self):
        """Flush buffered console output (called at exit and before input)."""
        for stream in self.std_streams:
            if stream.kind != 'stdin':
                stream.flush()

    def _ensure_env_ptr(self, attr, wide=False):
        """Allocate a pointer variable that points to an empty environment block."""
        if getattr(self, attr) == 0:
            env_block_attr = '_wenviron_addr' if wide else '_environ_addr'
            if getattr(self, env_block_attr) == 0:
                block = self.emu.heap_alloc(8)
                self.emu.uc.mem_write(block, struct.pack('<I', 0))
                setattr(self, env_block_attr, block)
            var = self.emu.heap_alloc(4)
            self.emu.uc.mem_write(var, struct.pack('<I', getattr(self, env_block_attr)))
            setattr(self, attr, var)
        return getattr(self, attr)

    def windows_exe_path(self):
        """Path of the main EXE as the program sees it (C:\\...)."""
        rel = os.path.relpath(os.path.realpath(self.emu.pe_loader.filepath),
                              os.path.realpath(C_DRIVE_PATH))
        if rel.startswith('..'):
            rel = os.path.basename(self.emu.pe_loader.filepath)
        return "C:\\" + rel.replace('/', '\\')

    def windows_command_line(self):
        command_line = getattr(self.emu, 'command_line', None)
        if command_line:
            return command_line
        path = self.windows_exe_path()
        return f'"{path}"' if ' ' in path else path

    # ==================== CONSOLE ====================

    def alloc_console(self):
        """Give the process its own console (window). False if it already has one."""
        if self.has_console:
            return False
        self.has_console = True
        if self.gui and self.gui.running:
            self.console = self.gui.create_console(self.windows_exe_path(), self)
        return True

    def free_console(self):
        """Detach from the console; its window closes. False if there was none."""
        if not self.has_console:
            return False
        self.flush_std_streams()
        self.has_console = False
        console, self.console = self.console, None
        if console is not None and self.gui:
            self.gui.close_console(console)
        return True

    def console_write(self, text, stream='stdout'):
        """Show program output in the process's GUI console, if it has one"""
        console = self.console
        if console is not None and self.gui and self.gui.running:
            self.gui.console_write(console, text, stream)

    def console_read_line(self):
        """Read a line typed into the GUI console; None without a console or when cancelled"""
        console = self.console
        if console is None or not self.gui:
            return None
        return self.gui.request_console_input(console)

    def request_termination(self):
        """Stop the process from another thread (console closed, emulator shutdown)"""
        self.emu.stop_emulation = True
        # Also breaks guest loops that make no API calls
        self.emu.uc.emu_stop()
        self.quit_requested = True
        console = self.console
        if console is not None and self.gui:
            self.gui.cancel_console_input(console)

    def _set_exit_code(self, code):
        if self.exit_code is None:
            self.exit_code = code & 0xFFFFFFFF

    def run_exit_handlers(self):
        """Run atexit/_onexit handlers in LIFO order (once)."""
        if self._exit_handlers_ran:
            return
        self._exit_handlers_ran = True
        while self.exit_handlers and not self.emu.stop_emulation:
            func = self.exit_handlers.pop()
            log.debug(f"Running exit handler 0x{func:08x}")
            self.emu.call_callback(func, [])

    def resolve_data_import(self, dll_name, name):
        """Address of an exported CRT *variable*, or None if not a data import.

        Data imports must point at real memory: the program dereferences the
        IAT entry directly instead of calling through it.
        """
        if not dll_name.lower().startswith(self.CDECL_DLL_PREFIXES):
            return None
        resolvers = {
            '_iob': self._ensure_iob,
            '_fmode': self._ensure_fmode_addr,
            '_commode': self._ensure_commode_addr,
            '_acmdln': lambda: self.api__p__acmdln([]),
            '_wcmdln': lambda: self.api__p__wcmdln([]),
            '__argc': lambda: self.api__p___argc([]),
            '__argv': lambda: self.api__p___argv([]),
            '__wargv': lambda: self.api__p___wargv([]),
            '_environ': lambda: self._ensure_env_ptr('_environ_ptr_addr'),
            '__initenv': lambda: self._ensure_env_ptr('_initenv_addr'),
            '_wenviron': lambda: self._ensure_env_ptr('_wenviron_ptr_addr', wide=True),
            '__winitenv': lambda: self._ensure_env_ptr('_winitenv_addr', wide=True),
        }
        resolver = resolvers.get(name)
        return resolver() if resolver else None
        
    def get_next_handle(self):
        """Create new handle"""
        handle = self.next_handle
        self.next_handle += 4
        return handle
    
    def _read_until_null(self, address, max_bytes, unit):
        """Read up to max_bytes from emulated memory, stopping at a NUL unit.

        Reads page by page so a short string that ends just before an
        unmapped page is still returned. Returns None if nothing is readable.
        """
        data = bytearray()
        addr = address
        while len(data) < max_bytes:
            chunk = min(max_bytes - len(data), 0x1000 - (addr & 0xFFF))
            try:
                block = self.emu.uc.mem_read(addr, chunk)
            except UcError:
                if not data:
                    return None
                break
            start = len(data)
            data += block
            addr += chunk
            # Re-scan from an aligned position so a terminator split across
            # chunks (wide strings) is found too
            pos = start - (start % unit)
            while True:
                pos = data.find(b'\x00' * unit, pos)
                if pos == -1:
                    break
                if pos % unit == 0:
                    return bytes(data[:pos])
                pos += 1
        return bytes(data[:max_bytes - (max_bytes % unit)])

    def _string_access_violation(self, address):
        """An API read a string through an unmapped pointer: fatal, like on Windows."""
        log.error(f"Access violation: READ @ 0x{address:08x} (string argument)")
        self.emu.crashed = True
        self.emu.stop_emulation = True

    def read_cstring(self, address, max_len=0x10000):
        """Raw bytes of a NUL-terminated ANSI string (b'' for NULL or unreadable)."""
        if not address:
            return b''
        data = self._read_until_null(address, max_len, 1)
        if data is None:
            self._string_access_violation(address)
            return b''
        return data

    def read_string(self, address, max_len=0x10000):
        """Read null-terminated ANSI string from memory"""
        return self.read_cstring(address, max_len).decode(ANSI_CODEPAGE, errors='replace')
    
    def read_wide_string(self, address, max_len=0x8000):
        """Read wide string (UTF-16) from memory"""
        if not address:
            return ''
        data = self._read_until_null(address, max_len * 2, 2)
        if data is None:
            self._string_access_violation(address)
            return ''
        return data.decode('utf-16-le', errors='replace')

    def _read_text(self, address, wide):
        """Read an ANSI or UTF-16 string argument (A/W API variants)"""
        return self.read_wide_string(address) if wide else self.read_string(address)

    # ==================== SANDBOXED FILE SYSTEM ====================

    def resolve_c_drive_path(self, filename):
        """Map a Windows-style filename into the c_drive/ sandbox (see the
        module-level resolve_c_drive_path); relative names are taken
        relative to the current directory."""
        full = self.full_windows_path(filename)
        if full is None:
            if filename:
                log.warning(f"Blocked sandbox escape attempt: \"{filename}\"")
            return None
        if full == "C:\\":
            os.makedirs(C_DRIVE_PATH, exist_ok=True)
            return os.path.realpath(C_DRIVE_PATH)
        return resolve_c_drive_path(full)

    def full_windows_path(self, filename, clamp=False):
        """Absolute, normalized "C:\\..." form of filename.

        A ".." above the root returns None, or stays at the root with clamp
        (like GetFullPathName). Every drive letter is the emulated C: drive.
        """
        if not filename:
            return None
        name = filename.replace('/', '\\')
        if len(name) >= 2 and name[1] == ':':
            name = name[2:]
        if not name.startswith('\\'):
            # "name" and "C:name" are relative to the current directory
            name = self.current_directory[2:] + '\\' + name
        parts = []
        for part in name.split('\\'):
            if part in ('', '.'):
                continue
            if part == '..':
                if not parts and not clamp:
                    return None
                if parts:
                    parts.pop()
            else:
                parts.append(part)
        result = "C:\\" + '\\'.join(parts)
        if parts and filename.endswith(('\\', '/')) and clamp:
            result += '\\'
        return result

    def _c_mode_to_python(self, mode):
        """Translate a C fopen()/CreateFile mode string to a Python one.

        Always binary so no host newline translation corrupts data; the
        emulated program sees the exact bytes it wrote.
        """
        mode = (mode or "").lower()
        base = 'r'
        if 'a' in mode:
            base = 'a'
        elif 'w' in mode:
            base = 'w'
        elif 'r' in mode:
            base = 'r'
        if '+' in mode:
            base += '+'
        return base + 'b'

    def post_window_message(self, hwnd, message, wParam, lParam):
        """Thread-safe: enqueue a window message (called from the GUI thread).

        The emulation thread consumes these in GetMessageA. Only plain Python
        data is touched here; Unicorn memory is written later on the emu thread.
        """
        msg = {
            'hwnd': hwnd & 0xFFFFFFFF,
            'message': message & 0xFFFFFFFF,
            'wParam': wParam & 0xFFFFFFFF,
            'lParam': lParam & 0xFFFFFFFF,
        }
        with self.message_lock:
            # Coalesce mouse moves like Windows does: replace a still-pending
            # WM_MOUSEMOVE for the same window instead of flooding the queue
            if (message == self.WM_MOUSEMOVE and self.message_queue and
                    self.message_queue[-1]['message'] == self.WM_MOUSEMOVE and
                    self.message_queue[-1]['hwnd'] == msg['hwnd']):
                self.message_queue[-1] = msg
                return
            self.message_queue.append(msg)

    # KERNEL32.DLL functions
    def GetModuleHandleA(self, args):
        """GetModuleHandleA emulation"""
        lpModuleName = args[0]
        if lpModuleName == 0:
            log.debug(f"GetModuleHandleA(NULL) -> 0x{self.emu.pe_loader.image_base:08x}")
            return self.emu.pe_loader.image_base
        
        module_name = self.read_string(lpModuleName)
        log.debug(f"GetModuleHandleA(\"{module_name}\")")
        return self._module_handle(module_name, load=False)
    
    def GetModuleHandleW(self, args):
        """GetModuleHandleW emulation"""
        lpModuleName = args[0]
        if lpModuleName == 0:
            return self.emu.pe_loader.image_base
        
        module_name = self.read_wide_string(lpModuleName)
        log.debug(f"GetModuleHandleW(\"{module_name}\")")
        return self._module_handle(module_name, load=False)

    # DLLs whose APIs the emulator implements (always "loaded")
    EMULATED_DLLS = {'kernel32.dll', 'user32.dll', 'gdi32.dll', 'msvcrt.dll',
                     'advapi32.dll', 'ole32.dll', 'ntdll.dll', 'winmm.dll'}

    def _module_handle(self, name, load):
        """Fake HMODULE for a DLL name; 0 if not loaded and load is False"""
        key = name.replace('/', '\\').rsplit('\\', 1)[-1].lower()
        if '.' not in key:
            key += '.dll'
        if key == os.path.basename(self.emu.pe_loader.filepath).lower():
            return self.emu.pe_loader.image_base
        handle = self.module_handles.get(key)
        if handle is None:
            known = self.EMULATED_DLLS | {d.lower() for d in self.emu.pe_loader.imports}
            if not load and key not in known:
                self._last_error = 126  # ERROR_MOD_NOT_FOUND
                return 0
            handle = self.get_next_handle()
            self.handles[handle] = {'type': 'module', 'name': key}
            self.module_handles[key] = handle
        return handle

    def is_emulated(self, dll_name, func_name):
        """True if calls to dll_name!func_name can be emulated safely"""
        return (self.get_api_handler(func_name) is not None and
                self.stack_cleanup_bytes(dll_name, func_name) is not None)
    
    def GetProcAddress(self, args):
        """GetProcAddress emulation - returns a hook stub for emulated APIs"""
        hModule = args[0]
        lpProcName = args[1]
        
        info = self.handles.get(hModule)
        if lpProcName < 0x10000:
            log.debug(f"GetProcAddress(0x{hModule:08x}, Ordinal_{lpProcName}) -> not supported")
            addr = 0
        elif not info or info.get('type') != 'module':
            log.debug(f"GetProcAddress(0x{hModule:08x}) -> unknown module")
            addr = 0
        else:
            proc_name = self.read_string(lpProcName)
            addr = self.emu.get_api_stub(info['name'], proc_name)
            log.debug(f"GetProcAddress(\"{info['name']}\", \"{proc_name}\") -> 0x{addr:08x}")
        if not addr:
            self._last_error = 127  # ERROR_PROC_NOT_FOUND
        return addr
    
    def ExitProcess(self, args):
        """ExitProcess emulation"""
        exit_code = args[0]
        log.success(f"ExitProcess({exit_code}) called - Terminating program...")
        self._set_exit_code(exit_code)
        self.process_exited = True
        self.emu.stop_emulation = True
        return 0
    
    def GetCommandLineA(self, args):
        """GetCommandLineA emulation"""
        log.debug("GetCommandLineA()")
        # Return memory address allocated for command line
        return self.emu.cmdline_addr
    
    def GetCommandLineW(self, args):
        """GetCommandLineW emulation"""
        log.debug("GetCommandLineW()")
        return self.emu.cmdline_wide_addr
    
    def SetUnhandledExceptionFilter(self, args):
        """SetUnhandledExceptionFilter emulation - no previous filter"""
        log.debug(f"SetUnhandledExceptionFilter(0x{args[0]:08x})")
        return 0

    def LoadCursorA(self, args):
        """LoadCursorA emulation - opaque cursor handle"""
        log.debug(f"LoadCursorA(0x{args[0]:x}, 0x{args[1]:x})")
        return self.get_next_handle()

    def LoadCursorW(self, args):
        """LoadCursorW emulation"""
        return self.LoadCursorA(args)

    def LoadIconA(self, args):
        """LoadIconA emulation - opaque icon handle"""
        log.debug(f"LoadIconA(0x{args[0]:x}, 0x{args[1]:x})")
        return self.get_next_handle()

    def LoadIconW(self, args):
        """LoadIconW emulation"""
        return self.LoadIconA(args)

    # ---------- Resources of the loaded EXE ----------

    def _resource_key(self, value):
        """Resource name/type: integer ID (MAKEINTRESOURCE or "#123") or upper-case name"""
        if value < 0x10000:
            return value
        name = self.read_string(value)
        if name.startswith('#') and name[1:].isdigit():
            return int(name[1:])
        return name.upper()

    def _find_resource(self, res_type, name):
        """(address, size) of a resource of the EXE (first language), or None"""
        if self._resource_index is None:
            self._resource_index = {}
            root = getattr(self.emu.pe_loader.pe, 'DIRECTORY_ENTRY_RESOURCE', None)
            for type_entry in (root.entries if root else []):
                tkey = str(type_entry.name).upper() if type_entry.name else type_entry.id
                for name_entry in getattr(type_entry, 'directory', None).entries:
                    nkey = str(name_entry.name).upper() if name_entry.name else name_entry.id
                    languages = getattr(name_entry, 'directory', None)
                    if languages and languages.entries:
                        data = languages.entries[0].data.struct
                        self._resource_index[(tkey, nkey)] = (data.OffsetToData, data.Size)
        found = self._resource_index.get((res_type, name))
        if found is None:
            return None
        return (self.emu.pe_loader.image_base + found[0], found[1])

    def _is_own_module(self, hModule):
        return hModule in (0, self.emu.pe_loader.image_base)

    def FindResourceA(self, args):
        """FindResourceA emulation (resources of the EXE only)"""
        hModule, lpName, lpType = args[0], args[1], args[2]
        name, res_type = self._resource_key(lpName), self._resource_key(lpType)
        resource = self._find_resource(res_type, name) if self._is_own_module(hModule) else None
        log.debug(f"FindResourceA({name!r}, type {res_type!r}) -> {resource}")
        if resource is None:
            self._last_error = 1814  # ERROR_RESOURCE_NAME_NOT_FOUND
            return 0
        handle = self.get_next_handle()
        self.handles[handle] = {'type': 'resource', 'addr': resource[0], 'size': resource[1]}
        return handle

    def LoadResource(self, args):
        """LoadResource emulation - resources are already mapped with the image"""
        info = self.handles.get(args[1])
        if not info or info.get('type') != 'resource':
            self._last_error = 6  # ERROR_INVALID_HANDLE
            return 0
        return info['addr']

    def LockResource(self, args):
        """LockResource emulation - the HGLOBAL is the data address"""
        return args[0]

    def FreeResource(self, args):
        """FreeResource emulation (obsolete, always FALSE)"""
        return 0

    def SizeofResource(self, args):
        """SizeofResource emulation"""
        info = self.handles.get(args[1])
        return info['size'] if info and info.get('type') == 'resource' else 0

    def LoadStringA(self, args):
        """LoadStringA emulation - RT_STRING blocks hold 16 counted UTF-16 strings"""
        hInstance, uID, lpBuffer, cchBufferMax = args[0], args[1] & 0xFFFF, args[2], args[3]
        text = None
        resource = self._find_resource(6, uID // 16 + 1) if self._is_own_module(hInstance) \
            else None
        if resource:
            try:
                block = bytes(self.emu.uc.mem_read(*resource))
                pos = 0
                for _ in range(uID % 16):
                    pos += 2 + 2 * struct.unpack_from('<H', block, pos)[0]
                length = struct.unpack_from('<H', block, pos)[0]
                if length:
                    text = block[pos + 2:pos + 2 + 2 * length].decode('utf-16-le', errors='replace')
            except (UcError, struct.error):
                text = None
        log.debug(f"LoadStringA({uID}) -> {text!r}")
        if not lpBuffer or cchBufferMax == 0:
            return 0
        if text is None:
            self._last_error = 1814  # ERROR_RESOURCE_NAME_NOT_FOUND
            self.emu.uc.mem_write(lpBuffer, b'\x00')
            return 0
        data = text.encode(ANSI_CODEPAGE, errors='replace')[:cchBufferMax - 1]
        self.emu.uc.mem_write(lpBuffer, data + b'\x00')
        return len(data)

    def AllocConsole(self, args):
        """AllocConsole emulation - opens the process's console window"""
        log.debug("AllocConsole()")
        if not self.alloc_console():
            self._last_error = 5  # ERROR_ACCESS_DENIED: already has a console
            return 0
        return 1
    
    def FreeConsole(self, args):
        """FreeConsole emulation"""
        log.debug("FreeConsole()")
        if not self.free_console():
            self._last_error = 6  # ERROR_INVALID_HANDLE
            return 0
        return 1
    
    def GetStdHandle(self, args):
        """GetStdHandle emulation"""
        nStdHandle = args[0]
        handle_names = {
            0xFFFFFFF6: "STD_INPUT_HANDLE",
            0xFFFFFFF5: "STD_OUTPUT_HANDLE",
            0xFFFFFFF4: "STD_ERROR_HANDLE",
        }
        # Convert signed values for 32-bit
        if nStdHandle > 0x80000000:
            nStdHandle = nStdHandle - 0x100000000
        
        name = handle_names.get(nStdHandle & 0xFFFFFFFF, f"Unknown({nStdHandle})")
        log.debug(f"GetStdHandle({name})")
        
        # Return fixed handle values
        if (nStdHandle & 0xFFFFFFFF) == 0xFFFFFFF6:
            return 0x10
        elif (nStdHandle & 0xFFFFFFFF) == 0xFFFFFFF5:
            return 0x11
        elif (nStdHandle & 0xFFFFFFFF) == 0xFFFFFFF4:
            return 0x12
        return 0

    def GetFileType(self, args):
        """GetFileType emulation - std handles are the console, CreateFile handles disk files"""
        hFile = args[0]
        if hFile in (0x10, 0x11, 0x12):
            result = 2  # FILE_TYPE_CHAR
        elif self.handles.get(hFile, {}).get('type') == 'file':
            result = 1  # FILE_TYPE_DISK
        else:
            self._last_error = 6  # ERROR_INVALID_HANDLE
            result = 0  # FILE_TYPE_UNKNOWN
        log.debug(f"GetFileType(0x{hFile:x}) -> {result}")
        if result:
            self._last_error = 0  # NO_ERROR distinguishes a real FILE_TYPE_UNKNOWN
        return result

    def SetHandleCount(self, args):
        """SetHandleCount emulation - Win32 has no handle limit, returns the request"""
        return args[0]
    
    def WriteFile(self, args):
        """WriteFile emulation"""
        hFile = args[0]
        lpBuffer = args[1]
        nNumberOfBytesToWrite = args[2]
        lpNumberOfBytesWritten = args[3]
        
        try:
            data = self.emu.uc.mem_read(lpBuffer, nNumberOfBytesToWrite)
            bytes_written = nNumberOfBytesToWrite

            if hFile in [0x11]:  # stdout
                text = data.decode(ANSI_CODEPAGE, errors='replace')
                log.write(f"{Fore.YELLOW}[STDOUT]{Style.RESET_ALL} {text}")
                self.console_output.append(text)
                self.console_write(text)
            elif hFile in [0x12]:  # stderr
                text = data.decode(ANSI_CODEPAGE, errors='replace')
                log.write(f"{Fore.RED}[STDERR]{Style.RESET_ALL} {text}")
                self.console_output.append(text)
                self.console_write(text, 'stderr')
            else:
                # Real file handle (opened via CreateFile, inside c_drive/)
                info = self.handles.get(hFile)
                if info and info.get('fp'):
                    written = info['fp'].write(bytes(data))
                    bytes_written = written if written is not None else nNumberOfBytesToWrite
                else:
                    # Unknown handle: report failure so callers notice.
                    if lpNumberOfBytesWritten != 0:
                        self.emu.uc.mem_write(lpNumberOfBytesWritten, struct.pack('<I', 0))
                    log.warning(f"WriteFile to unknown handle 0x{hFile:x}")
                    return 0

            # Write bytes written count to memory
            if lpNumberOfBytesWritten != 0:
                self.emu.uc.mem_write(lpNumberOfBytesWritten,
                                      struct.pack('<I', bytes_written & 0xFFFFFFFF))

            log.debug(f"WriteFile(0x{hFile:x}, {nNumberOfBytesToWrite} bytes)")
            return 1  # Success
        except Exception as e:
            log.error(f"WriteFile error: {e}")
            return 0
    
    def WriteConsoleA(self, args, wide=False):
        """WriteConsoleA/W emulation"""
        hConsoleOutput = args[0]
        lpBuffer = args[1]
        nNumberOfCharsToWrite = args[2]
        lpNumberOfCharsWritten = args[3]
        
        try:
            if wide:
                data = self.emu.uc.mem_read(lpBuffer, nNumberOfCharsToWrite * 2)
                text = data.decode('utf-16-le', errors='replace')
            else:
                data = self.emu.uc.mem_read(lpBuffer, nNumberOfCharsToWrite)
                text = data.decode(ANSI_CODEPAGE, errors='replace')
            log.write(f"{Fore.YELLOW}[CONSOLE]{Style.RESET_ALL} {text}")
            self.console_output.append(text)
            self.console_write(text)
            
            if lpNumberOfCharsWritten != 0:
                self.emu.uc.mem_write(lpNumberOfCharsWritten,
                                      struct.pack('<I', nNumberOfCharsToWrite))
            return 1
        except UcError as e:
            log.error(f"WriteConsoleA error: {e}")
            return 0

    def WriteConsoleW(self, args):
        return self.WriteConsoleA(args, wide=True)

    @staticmethod
    def _codepage_name(code_page):
        """Python codec for a Windows code page number, or None if unsupported"""
        if code_page in (0, 1, 3):  # CP_ACP, CP_OEMCP, CP_THREAD_ACP
            return ANSI_CODEPAGE
        if code_page == 65001:
            return 'utf-8'
        try:
            return codecs.lookup(f'cp{code_page}').name
        except LookupError:
            return None

    def MultiByteToWideChar(self, args):
        """MultiByteToWideChar emulation"""
        CodePage, dwFlags, lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar = args[:6]
        codec = self._codepage_name(CodePage)
        if codec is None or not lpMultiByteStr or cbMultiByte == 0:
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0
        if cbMultiByte == 0xFFFFFFFF:
            data = self.read_cstring(lpMultiByteStr) + b'\x00'
        else:
            data = bytes(self.emu.uc.mem_read(lpMultiByteStr, cbMultiByte))
        out = data.decode(codec, errors='replace').encode('utf-16-le')
        count = len(out) // 2
        if cchWideChar == 0:
            return count
        if count > cchWideChar:
            self._last_error = 122  # ERROR_INSUFFICIENT_BUFFER
            return 0
        self.emu.uc.mem_write(lpWideCharStr, out)
        return count

    def WideCharToMultiByte(self, args):
        """WideCharToMultiByte emulation"""
        (CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr,
         cbMultiByte, lpDefaultChar, lpUsedDefaultChar) = args[:8]
        codec = self._codepage_name(CodePage)
        if codec is None or not lpWideCharStr or cchWideChar == 0:
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0
        if cchWideChar == 0xFFFFFFFF:
            text = self.read_wide_string(lpWideCharStr) + '\x00'
        else:
            text = bytes(self.emu.uc.mem_read(lpWideCharStr, cchWideChar * 2)).decode(
                'utf-16-le', errors='replace')
        try:
            out = text.encode(codec)
            used_default = 0
        except UnicodeEncodeError:
            out = text.encode(codec, errors='replace')
            used_default = 1
        if lpUsedDefaultChar:
            self.emu.uc.mem_write(lpUsedDefaultChar, struct.pack('<I', used_default))
        if cbMultiByte == 0:
            return len(out)
        if len(out) > cbMultiByte:
            self._last_error = 122  # ERROR_INSUFFICIENT_BUFFER
            return 0
        self.emu.uc.mem_write(lpMultiByteStr, out)
        return len(out)
    
    def GetLastError(self, args):
        """GetLastError emulation"""
        log.debug(f"GetLastError() -> {self._last_error}")
        return self._last_error & 0xFFFFFFFF

    def SetLastError(self, args):
        """SetLastError emulation"""
        dwErrCode = args[0]
        log.debug(f"SetLastError({dwErrCode})")
        self._last_error = dwErrCode
        return 0
    
    def VirtualAlloc(self, args):
        """VirtualAlloc emulation"""
        lpAddress = args[0]
        dwSize = args[1]
        flAllocationType = args[2]
        flProtect = args[3]
        
        log.debug(f"VirtualAlloc(0x{lpAddress:08x}, 0x{dwSize:x}, 0x{flAllocationType:x}, 0x{flProtect:x})")

        if dwSize == 0:
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0
        if lpAddress:
            # Committing pages of an existing reservation (memory is always backed)
            for base, size in self.virtual_allocs.items():
                if base <= lpAddress and lpAddress + dwSize <= base + size:
                    return lpAddress & ~0xFFF
            addr = self._map_virtual_at(lpAddress, dwSize)
            if not addr:
                self._last_error = 487  # ERROR_INVALID_ADDRESS
            return addr

        size = self.emu._align_size(dwSize, 0x1000)
        addr = self.emu.heap_alloc(size, alignment=0x10000)  # allocation granularity
        if addr:
            self.virtual_allocs[addr] = size
        else:
            self._last_error = 8  # ERROR_NOT_ENOUGH_MEMORY
        return addr

    def _map_virtual_at(self, address, size):
        """Map a new region at a requested address (rounded down to the 64K
        allocation granularity) if it is free; returns its base or 0"""
        emu = self.emu
        base = address & ~0xFFFF
        size = emu._align_size(address + size - base, 0x1000)
        end = base + size
        if base < 0x10000 or end > 0x80000000:
            return 0
        used = [(start, last + 1) for start, last, _ in emu.uc.mem_regions()]
        if any(base < stop and end > start for start, stop in used + emu._reserved_regions()):
            return 0
        try:
            emu.uc.mem_map(base, size, UC_PROT_ALL)
        except UcError:
            return 0
        emu.mapped_regions.append((base, end))
        self.virtual_allocs[base] = size
        self.mapped_virtual_allocs.add(base)
        return base
    
    def VirtualFree(self, args):
        """VirtualFree emulation"""
        lpAddress = args[0]
        dwSize = args[1]
        dwFreeType = args[2]
        log.debug(f"VirtualFree(0x{lpAddress:08x}, 0x{dwSize:x}, 0x{dwFreeType:x})")
        if dwFreeType & 0x8000:  # MEM_RELEASE
            size = self.virtual_allocs.pop(lpAddress, None)
            if size is None:
                self._last_error = 487  # ERROR_INVALID_ADDRESS
                return 0
            if lpAddress in self.mapped_virtual_allocs:
                self.mapped_virtual_allocs.discard(lpAddress)
                self.emu.uc.mem_unmap(lpAddress, size)
                self.emu.mapped_regions.remove((lpAddress, lpAddress + size))
            else:
                self.emu.heap_free(lpAddress)
        return 1
    
    def HeapCreate(self, args):
        """HeapCreate emulation"""
        log.debug("HeapCreate()")
        return self.get_next_handle()
    
    def HeapAlloc(self, args):
        """HeapAlloc emulation"""
        hHeap = args[0]
        dwFlags = args[1]
        dwBytes = args[2]
        
        addr = self.emu.heap_alloc(dwBytes)
        log.debug(f"HeapAlloc(0x{hHeap:x}, 0x{dwFlags:x}, 0x{dwBytes:x}) -> 0x{addr:08x}")
        return addr
    
    def HeapFree(self, args):
        """HeapFree emulation"""
        lpMem = args[2]
        log.debug(f"HeapFree(0x{lpMem:08x})")
        return 1 if not lpMem or self.emu.heap_free(lpMem) else 0

    def HeapReAlloc(self, args):
        """HeapReAlloc emulation"""
        dwFlags, lpMem, dwBytes = args[1], args[2], args[3]
        log.debug(f"HeapReAlloc(0x{lpMem:08x}, 0x{dwBytes:x}, flags=0x{dwFlags:x})")
        if not lpMem:
            return 0
        old_size = self.emu.heap_block_size(lpMem)
        if old_size is not None and self.emu.heap_resize_last(lpMem, dwBytes):
            addr = lpMem
        elif dwFlags & 0x10:  # HEAP_REALLOC_IN_PLACE_ONLY
            self._last_error = 8  # ERROR_NOT_ENOUGH_MEMORY
            return 0
        else:
            addr = self.emu.heap_alloc(dwBytes)
            if not addr:
                self._last_error = 8
                return 0
            copy_size = min(old_size, dwBytes) if old_size is not None else dwBytes
            self.emu.uc.mem_write(addr, bytes(self.emu.uc.mem_read(lpMem, copy_size)))
            self.emu.heap_free(lpMem)
        if dwFlags & 0x08 and old_size is not None and dwBytes > old_size:  # HEAP_ZERO_MEMORY
            self.emu.uc.mem_write(addr + old_size, b'\x00' * (dwBytes - old_size))
        return addr

    def HeapDestroy(self, args):
        """HeapDestroy emulation - HeapCreate heaps share the process heap"""
        return 1

    def _environment_block(self, wide):
        """Heap copy of the environment block: NAME=value\\0 ... \\0"""
        units = []
        for name, value in sorted(self.environment.items()):
            units += self._text_units(f"{name}={value}", wide) + [0]
        return self._alloc_units(units, wide)

    def GetEnvironmentStrings(self, args):
        """GetEnvironmentStrings(A) emulation"""
        return self._environment_block(False)

    def GetEnvironmentStringsA(self, args):
        return self._environment_block(False)

    def GetEnvironmentStringsW(self, args):
        """GetEnvironmentStringsW emulation"""
        return self._environment_block(True)

    def FreeEnvironmentStringsA(self, args):
        """FreeEnvironmentStringsA/W emulation"""
        if args[0]:
            self.emu.heap_free(args[0])
        return 1

    def FreeEnvironmentStringsW(self, args):
        return self.FreeEnvironmentStringsA(args)

    def GetCPInfo(self, args):
        """GetCPInfo emulation - single-byte code pages, UTF-8 up to 4 bytes"""
        codepage, lpCPInfo = args[0], args[1]
        ansi = self._ansi_codepage_number()
        if codepage in (0, 3):  # CP_ACP, CP_THREAD_ACP
            codepage = ansi
        elif codepage == 1:  # CP_OEMCP
            codepage = self.GetOEMCP([])
        max_size = 4 if codepage == 65001 else 1
        data = struct.pack('<I2s12s', max_size, b'?\x00', b'')
        return 1 if self._mem_write(lpCPInfo, data) else 0

    @staticmethod
    def _ctype1(ch):
        """CT_CTYPE1 flags of one character (None: not a character)"""
        if ch is None:
            return 0
        flags = 0
        if ch.isupper():
            flags |= 0x001  # C1_UPPER
        if ch.islower():
            flags |= 0x002  # C1_LOWER
        if ch in '0123456789':
            flags |= 0x004  # C1_DIGIT
        if ch in ' \t\n\v\f\r' or (ch.isspace() and ord(ch) > 0x7F):
            flags |= 0x008  # C1_SPACE
        if ch.isprintable() and not ch.isalnum() and not ch.isspace():
            flags |= 0x010  # C1_PUNCT
        if ord(ch) < 0x20 or ord(ch) == 0x7F:
            flags |= 0x020  # C1_CNTRL
        if ch in ' \t':
            flags |= 0x040  # C1_BLANK
        if ch in '0123456789abcdefABCDEF':
            flags |= 0x080  # C1_XDIGIT
        if ch.isalpha():
            flags |= 0x100  # C1_ALPHA
        return flags

    def _counted_units(self, address, count, wide):
        """cchSrc code units (-1: up to and including the terminator)"""
        if count == 0xFFFFFFFF:
            return self._read_units(address, wide) + [0]
        try:
            data = bytes(self.emu.uc.mem_read(address, count * (2 if wide else 1)))
        except UcError:
            return None
        return list(struct.unpack(f'<{count}H', data)) if wide else list(data)

    def _string_type_common(self, info_type, address, count, lpCharType, wide):
        units = self._counted_units(address, count, wide)
        if units is None or not lpCharType:
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0
        if info_type == 1:  # CT_CTYPE1
            types = [self._ctype1(chr(u) if wide else self._ansi_char(u)) for u in units]
        else:  # CT_CTYPE2 / CT_CTYPE3: no type information
            types = [0] * len(units)
        return 1 if self._mem_write(lpCharType, struct.pack(f'<{len(types)}H', *types)) else 0

    def GetStringTypeA(self, args):
        """GetStringTypeA emulation (Locale, dwInfoType, lpSrcStr, cchSrc, lpCharType)"""
        return self._string_type_common(args[1], args[2], args[3], args[4], False)

    def GetStringTypeW(self, args):
        """GetStringTypeW emulation (dwInfoType, lpSrcStr, cchSrc, lpCharType)"""
        return self._string_type_common(args[0], args[1], args[2], args[3], True)

    def LCMapStringA(self, args, wide=False):
        """LCMapStringA/W emulation - case mapping; sort keys are the code units"""
        flags, lpSrcStr, cchSrc, lpDestStr, cchDest = args[1], args[2], args[3], args[4], args[5]
        units = self._counted_units(lpSrcStr, cchSrc, wide)
        if units is None:
            self._last_error = 87
            return 0
        if flags & 0x400:  # LCMAP_SORTKEY: bytes, compared like strcmp
            key = bytes(self._pack_units(units, wide)).rstrip(b'\x00') + b'\x00'
            if cchDest:
                if cchDest < len(key):
                    self._last_error = 122  # ERROR_INSUFFICIENT_BUFFER
                    return 0
                self._mem_write(lpDestStr, key)
            return len(key)
        if flags & 0x300:  # LCMAP_LOWERCASE / LCMAP_UPPERCASE
            convert = str.lower if flags & 0x100 else str.upper
            if wide:
                mapped = [ord(convert(chr(u))) if len(convert(chr(u))) == 1 else u for u in units]
            else:
                mapped = []
                for u in units:
                    ch = self._ansi_char(u)
                    out = convert(ch).encode(ANSI_CODEPAGE, errors='replace') if ch else b''
                    mapped.append(out[0] if len(out) == 1 else u)
            units = mapped
        if cchDest:
            if cchDest < len(units):
                self._last_error = 122
                return 0
            self._write_units(lpDestStr, units, wide, terminate=False)
        return len(units)

    def LCMapStringW(self, args):
        return self.LCMapStringA(args, wide=True)

    def RtlUnwind(self, args):
        """RtlUnwind emulation - drops SEH records above TargetFrame (handlers are not called)"""
        target_frame, return_value = args[0], args[3]
        if target_frame:
            self._mem_write(self.emu.teb_addr, struct.pack('<I', target_frame))
        return return_value

    def UnhandledExceptionFilter(self, args):
        """UnhandledExceptionFilter emulation - EXCEPTION_EXECUTE_HANDLER (terminate)"""
        return 1

    def TerminateProcess(self, args):
        """TerminateProcess emulation - only the current process can be terminated"""
        hProcess, exit_code = args[0], args[1]
        if hProcess != 0xFFFFFFFF:
            self._last_error = 5  # ERROR_ACCESS_DENIED
            return 0
        return self.ExitProcess([exit_code])

    # ---------- Child processes ----------

    # Set by main(): (windows_path, command_line, current_directory) -> CPUEmulator or None
    process_starter = None
    _next_process_id = 0x1000

    def _process_image_path(self, app, cmdline):
        """Windows path of the EXE CreateProcess should start, or None"""
        if app:
            name = app
        else:
            cmdline = cmdline.lstrip()
            if cmdline.startswith('"'):
                name = cmdline[1:].split('"', 1)[0]
            else:
                name = cmdline.split(None, 1)[0] if cmdline.strip() else ''
        if not name:
            return None
        candidates = [name] if name.lower().endswith('.exe') else [name, name + '.exe']
        folders = [None]
        if not any(sep in name for sep in '\\/:'):
            exe_dir = self.windows_exe_path().rsplit('\\', 1)[0]
            folders = [exe_dir, self.current_directory, "C:\\Windows\\System32",
                       "C:\\Windows"]
        for folder in folders:
            for candidate in candidates:
                full = self.full_windows_path(
                    candidate if folder is None else folder.rstrip('\\') + '\\' + candidate)
                path = self.resolve_c_drive_path(full) if full else None
                if path and os.path.isfile(path):
                    return full
        if folders != [None]:
            for candidate in candidates:
                path = find_program(candidate)
                if path:
                    rel = os.path.relpath(path, os.path.realpath(C_DRIVE_PATH))
                    return "C:\\" + rel.replace('/', '\\')
        return None

    def CreateProcessA(self, args):
        """CreateProcessA emulation - emulates the EXE in its own thread"""
        lpApplicationName, lpCommandLine = args[0], args[1]
        lpCurrentDirectory, lpProcessInformation = args[7], args[9]
        app = self.read_string(lpApplicationName) if lpApplicationName else ''
        cmdline = self.read_string(lpCommandLine) if lpCommandLine else ''
        log.info(f"CreateProcessA(\"{app}\", \"{cmdline}\")")
        path = self._process_image_path(app, cmdline)
        starter = WinAPIHandler.process_starter
        if path is None or starter is None:
            self._last_error = 2  # ERROR_FILE_NOT_FOUND
            return 0
        current = self.current_directory
        if lpCurrentDirectory:
            current = self.full_windows_path(self.read_string(lpCurrentDirectory),
                                             clamp=True).rstrip('\\') or current
            if len(current) == 2:
                current += '\\'
        if not cmdline.strip():
            cmdline = f'"{path}"' if ' ' in path else path
        child = starter(path, cmdline, current)
        if child is None:
            self._last_error = 193  # ERROR_BAD_EXE_FORMAT
            return 0
        WinAPIHandler._next_process_id += 4
        pid = WinAPIHandler._next_process_id
        hProcess = self.get_next_handle()
        hThread = self.get_next_handle()
        self.handles[hProcess] = {'type': 'process', 'emulator': child}
        self.handles[hThread] = {'type': 'thread', 'emulator': child}
        if lpProcessInformation:
            self._mem_write(lpProcessInformation,
                            struct.pack('<4I', hProcess, hThread, pid, pid + 1))
        return 1

    @staticmethod
    def _child_running(child):
        thread = getattr(child, 'thread', None)
        return thread is not None and thread.is_alive()

    def GetExitCodeProcess(self, args):
        """GetExitCodeProcess emulation - STILL_ACTIVE (259) while it runs"""
        hProcess, lpExitCode = args[0], args[1]
        if hProcess == 0xFFFFFFFF:
            code = 259
        else:
            info = self.handles.get(hProcess)
            if not info or info.get('type') != 'process':
                self._last_error = 6  # ERROR_INVALID_HANDLE
                return 0
            child = info['emulator']
            if self._child_running(child):
                code = 259
            elif child.crashed:
                code = 0xC0000005
            else:
                code = child.api_handler.exit_code or 0
        return 1 if self._mem_write(lpExitCode, struct.pack('<I', code)) else 0

    def WaitForSingleObject(self, args):
        """WaitForSingleObject emulation - processes/threads are signaled when
        they end; other objects are always signaled"""
        handle, timeout = args[0], args[1]
        info = self.handles.get(handle)
        if info is None:
            self._last_error = 6  # ERROR_INVALID_HANDLE
            return 0xFFFFFFFF  # WAIT_FAILED
        if info.get('type') not in ('process', 'thread'):
            return 0  # WAIT_OBJECT_0
        child = info['emulator']
        deadline = None if timeout == 0xFFFFFFFF else time.time() + timeout / 1000.0
        while self._child_running(child):
            if self.emu.stop_emulation:
                return 0xFFFFFFFF
            if deadline is not None and time.time() >= deadline:
                return 0x102  # WAIT_TIMEOUT
            time.sleep(0.02)
        return 0

    def RaiseException(self, args):
        """RaiseException emulation - no SEH support, so the exception is fatal
        (debugger notifications are ignored)"""
        code, flags = args[0], args[1]
        if code in (0x406D1388, 0x40010006, 0x4001000A):  # thread name, debug string
            return 0
        log.error(f"Unhandled exception 0x{code:08x} (RaiseException, flags 0x{flags:x}); "
                  f"exception handling is not emulated")
        self.emu.crashed = True
        self.emu.stop_emulation = True
        return 0

    def HeapSize(self, args):
        """HeapSize emulation - usable size of a heap block"""
        size = self.emu.heap_block_size(args[2]) if args[2] else None
        return 0xFFFFFFFF if size is None else size

    # ---------- Drives and volumes (only C: exists) ----------

    volume_label = ''

    def _drive_root_ok(self, address):
        """True if a root path argument (NULL: current drive) names drive C:"""
        if not address:
            return True
        root = self.read_string(address)
        return not (len(root) >= 2 and root[1] == ':' and root[0].upper() != 'C')

    def GetLogicalDrives(self, args):
        """GetLogicalDrives emulation - only C:"""
        return 1 << 2

    def GetDriveTypeA(self, args):
        """GetDriveTypeA emulation - C: is a fixed disk"""
        return 3 if self._drive_root_ok(args[0]) else 1  # DRIVE_FIXED / DRIVE_NO_ROOT_DIR

    def GetVolumeInformationA(self, args):
        """GetVolumeInformationA emulation - a FAT32 volume"""
        if not self._drive_root_ok(args[0]):
            self._last_error = 3  # ERROR_PATH_NOT_FOUND
            return 0
        (lpName, nNameSize, lpSerial, lpMaxComponent, lpFlags,
         lpFsName, nFsNameSize) = args[1:8]
        for buf, size, text in ((lpName, nNameSize, WinAPIHandler.volume_label),
                                (lpFsName, nFsNameSize, 'FAT32')):
            if buf:
                data = text.encode(ANSI_CODEPAGE, errors='replace')
                if size <= len(data):
                    self._last_error = 24  # ERROR_BAD_LENGTH
                    return 0
                self._mem_write(buf, data + b'\x00')
        for ptr, value in ((lpSerial, 0x1E3A5C07), (lpMaxComponent, 255),
                           (lpFlags, 0x6)):  # CASE_PRESERVED_NAMES | UNICODE_ON_DISK
            if ptr:
                self._mem_write(ptr, struct.pack('<I', value))
        return 1

    def SetVolumeLabelA(self, args):
        """SetVolumeLabelA emulation - kept for this session"""
        if not self._drive_root_ok(args[0]):
            self._last_error = 3
            return 0
        label = self.read_string(args[1]) if args[1] else ''
        WinAPIHandler.volume_label = label[:11].upper()
        return 1

    def SetFileAttributesA(self, args):
        """SetFileAttributesA emulation - only the read-only flag maps to the host"""
        filename = self.read_string(args[0])
        attributes = args[1]
        path = self.resolve_c_drive_path(filename)
        if path is None or not os.path.exists(path):
            self._last_error = 2  # ERROR_FILE_NOT_FOUND
            return 0
        if not os.path.isdir(path):
            try:
                mode = os.stat(path).st_mode
                if attributes & 1:  # FILE_ATTRIBUTE_READONLY
                    mode &= ~0o222
                else:
                    mode |= 0o200
                os.chmod(path, mode)
            except OSError:
                self._last_error = 5  # ERROR_ACCESS_DENIED
                return 0
        return 1

    # ---------- Time conversions ----------

    def _read_filetime(self, address):
        try:
            return struct.unpack('<Q', self.emu.uc.mem_read(address, 8))[0]
        except UcError:
            return None

    def FileTimeToSystemTime(self, args):
        """FileTimeToSystemTime emulation"""
        ft = self._read_filetime(args[0])
        if ft is None or ft >= 0x8000000000000000:
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0
        try:
            when = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ft // 10)
        except OverflowError:
            self._last_error = 87
            return 0
        data = struct.pack('<8H', when.year, when.month, (when.weekday() + 1) % 7,
                           when.day, when.hour, when.minute, when.second,
                           when.microsecond // 1000)
        return 1 if self._mem_write(args[1], data) else 0

    def SystemTimeToFileTime(self, args):
        """SystemTimeToFileTime emulation"""
        try:
            year, month, _, day, hour, minute, second, ms = struct.unpack(
                '<8H', self.emu.uc.mem_read(args[0], 16))
            when = datetime.datetime(year, month, day, hour, minute, second, ms * 1000)
        except (UcError, ValueError):
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0
        if year < 1601 or ms > 999:
            self._last_error = 87
            return 0
        delta = when - datetime.datetime(1601, 1, 1)
        ft = (delta.days * 86400 + delta.seconds) * 10000000 + delta.microseconds * 10
        return 1 if self._mem_write(args[1], struct.pack('<Q', ft)) else 0

    def FileTimeToLocalFileTime(self, args):
        """FileTimeToLocalFileTime emulation - UTC FILETIME -> local FILETIME"""
        utc = self._read_filetime(args[0])
        if utc is None:
            self._last_error = 998  # ERROR_NOACCESS
            return 0
        seconds = (utc - self.UNIX_EPOCH_FILETIME) // 10000000
        offset = time.localtime(max(0, min(seconds, 0x7FFFFFFF))).tm_gmtoff
        local = (utc + offset * 10000000) & 0xFFFFFFFFFFFFFFFF
        return 1 if self._mem_write(args[1], struct.pack('<Q', local)) else 0

    def SetLocalTime(self, args):
        """SetLocalTime emulation - the host clock can't be changed"""
        self._last_error = 1314  # ERROR_PRIVILEGE_NOT_HELD
        return 0

    def CompareStringA(self, args):
        """CompareStringA emulation - CSTR_LESS_THAN/EQUAL/GREATER_THAN (1/2/3)"""
        flags = args[1]
        texts = []
        for address, count in ((args[2], args[3]), (args[4], args[5])):
            if count != 0xFFFFFFFF and count >= 0x80000000:
                self._last_error = 87  # ERROR_INVALID_PARAMETER
                return 0
            units = self._counted_units(address, count, False) if address else None
            if units is None:
                self._last_error = 87
                return 0
            if 0 in units:
                units = units[:units.index(0)]
            text = bytes(units).decode(ANSI_CODEPAGE, errors='replace')
            if flags & 1:  # NORM_IGNORECASE
                text = text.lower()
            if flags & 4:  # NORM_IGNORESYMBOLS
                text = ''.join(ch for ch in text if ch.isalnum() or ch.isspace())
            if flags & 2:  # NORM_IGNORENONSPACE
                text = ''.join(ch for ch in unicodedata.normalize('NFD', text)
                               if not unicodedata.combining(ch))
            texts.append(text)
        # Linguistic order: case-insensitive first, case only breaks ties
        key1 = (texts[0].lower(), texts[0].swapcase())
        key2 = (texts[1].lower(), texts[1].swapcase())
        return 1 if key1 < key2 else 3 if key1 > key2 else 2
    
    def GetProcessHeap(self, args):
        """GetProcessHeap emulation"""
        log.debug("GetProcessHeap()")
        return self.emu.process_heap
    
    def GetCurrentProcess(self, args):
        """GetCurrentProcess emulation"""
        log.debug("GetCurrentProcess()")
        return 0xFFFFFFFF  # Pseudo handle
    
    def GetCurrentProcessId(self, args):
        """GetCurrentProcessId emulation"""
        log.debug("GetCurrentProcessId()")
        return 1234  # Fixed PID
    
    def GetCurrentThreadId(self, args):
        """GetCurrentThreadId emulation"""
        log.debug("GetCurrentThreadId()")
        return 5678  # Fixed TID
    
    def GetTickCount(self, args):
        """GetTickCount emulation"""
        import time
        ticks = int(time.time() * 1000) & 0xFFFFFFFF
        log.debug(f"GetTickCount() -> {ticks}")
        return ticks

    def MulDiv(self, args):
        """MulDiv emulation - (a * b) / c with rounding to nearest"""
        n, num, den = self._read_signed_args(args, 0, 3)
        if den == 0:
            return 0xFFFFFFFF  # -1
        prod = n * num
        sign = 1 if (prod >= 0) == (den > 0) else -1
        # Builtin abs: the CRT abs() emulation shadows it on the class only
        pa, da = (prod if prod >= 0 else -prod), (den if den >= 0 else -den)
        result = sign * ((pa + da // 2) // da)
        log.debug(f"MulDiv({n}, {num}, {den}) -> {result}")
        return result & 0xFFFFFFFF

    def _write_systemtime(self, address, tm):
        """Write a SYSTEMTIME structure (8 WORDs) to memory"""
        ms = int((time.time() % 1) * 1000)
        data = struct.pack("<8H", tm.tm_year, tm.tm_mon, (tm.tm_wday + 1) % 7,
                           tm.tm_mday, tm.tm_hour, tm.tm_min,
                           min(tm.tm_sec, 59), ms)
        try:
            self.emu.uc.mem_write(address, data)
            return True
        except UcError:
            return False

    def GetLocalTime(self, args):
        """GetLocalTime emulation"""
        lpSystemTime = args[0]
        log.debug("GetLocalTime()")
        if lpSystemTime:
            self._write_systemtime(lpSystemTime, time.localtime())
        return 0

    def GetSystemTime(self, args):
        """GetSystemTime emulation (UTC)"""
        lpSystemTime = args[0]
        log.debug("GetSystemTime()")
        if lpSystemTime:
            self._write_systemtime(lpSystemTime, time.gmtime())
        return 0

    def Beep(self, args):
        """Beep emulation - plays a square-wave tone and blocks for its duration"""
        frequency, duration = args[0], args[1]
        log.debug(f"Beep({frequency} Hz, {duration} ms)")
        if not 0x25 <= frequency <= 0x7FFF:
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0
        SoundPlayer.tone(frequency, min(duration, 10000))
        self._wait_ms(duration)
        return 1

    def QueryPerformanceCounter(self, args):
        """QueryPerformanceCounter emulation"""
        lpPerformanceCount = args[0]
        import time
        count = int(time.time() * 1000000)
        
        if lpPerformanceCount != 0:
            self.emu.uc.mem_write(lpPerformanceCount, struct.pack('<Q', count))
        
        log.debug(f"QueryPerformanceCounter()")
        return 1
    
    def GetSystemTimeAsFileTime(self, args):
        """GetSystemTimeAsFileTime emulation"""
        lpSystemTimeAsFileTime = args[0]
        import time
        # Windows FILETIME: 100-nanosecond intervals since January 1, 1601
        # Unix time: seconds since January 1, 1970
        # Difference: 11644473600 seconds
        filetime = int((time.time() + 11644473600) * 10000000)
        
        if lpSystemTimeAsFileTime != 0:
            self.emu.uc.mem_write(lpSystemTimeAsFileTime, struct.pack('<Q', filetime))
        
        log.debug("GetSystemTimeAsFileTime()")
        return 0

    # FILETIME of the Unix epoch (100 ns units since 1601-01-01)
    UNIX_EPOCH_FILETIME = 116444736000000000

    def LocalFileTimeToFileTime(self, args):
        """LocalFileTimeToFileTime emulation - local FILETIME -> UTC FILETIME"""
        lpLocalFileTime, lpFileTime = args[0], args[1]
        try:
            local = struct.unpack('<Q', self.emu.uc.mem_read(lpLocalFileTime, 8))[0]
            seconds = (local - self.UNIX_EPOCH_FILETIME) // 10000000
            # UTC offset in effect at that local time (DST aware)
            offset = time.localtime(max(0, min(seconds, 0x7FFFFFFF))).tm_gmtoff
            utc = (local - offset * 10000000) & 0xFFFFFFFFFFFFFFFF
            self.emu.uc.mem_write(lpFileTime, struct.pack('<Q', utc))
        except UcError:
            self._last_error = 998  # ERROR_NOACCESS
            return 0
        return 1

    def SetFileTime(self, args):
        """SetFileTime emulation - last access/write times of the host file
        (the creation time can't be set on the host)"""
        hFile, lpLastAccess, lpLastWrite = args[0], args[2], args[3]
        info = self.handles.get(hFile)
        if not info or info.get('type') != 'file' or not info.get('path'):
            self._last_error = 6  # ERROR_INVALID_HANDLE
            return 0
        path = info['path']
        try:
            if info.get('fp'):
                info['fp'].flush()  # Pending writes would bump the new time
            st = os.stat(path)
            times = [st.st_atime_ns, st.st_mtime_ns]
            for i, ptr in enumerate((lpLastAccess, lpLastWrite)):
                if ptr:
                    ft = struct.unpack('<Q', self.emu.uc.mem_read(ptr, 8))[0]
                    if ft:
                        times[i] = (ft - self.UNIX_EPOCH_FILETIME) * 100
            os.utime(path, ns=tuple(times))
        except (OSError, ValueError, UcError):
            self._last_error = 5  # ERROR_ACCESS_DENIED
            return 0
        return 1
    
    def IsDebuggerPresent(self, args):
        """IsDebuggerPresent emulation"""
        log.debug("IsDebuggerPresent() -> 0")
        return 0  # No debugger
    
    def GetVersion(self, args):
        """GetVersion emulation - Returns Windows Vista SP2"""
        log.debug("GetVersion()")
        # Windows Vista SP2: Major=6, Minor=0, Build=6002
        # Format: 0xMMMMBBBB where M=minor|major, B=build
        # Low word: Major (low byte) | Minor (high byte) = 0x0006
        # High word: Build number = 6002 = 0x1772
        return 0x17720006  # Build 6002, Version 6.0
    
    def GetVersionExA(self, args):
        """GetVersionExA emulation - Windows Vista SP2"""
        lpVersionInfo = args[0]
        log.debug(f"GetVersionExA(0x{lpVersionInfo:08x})")
        
        # Fill OSVERSIONINFOA or OSVERSIONINFOEXA structure
        try:
            # Read dwOSVersionInfoSize
            size = struct.unpack('<I', self.emu.uc.mem_read(lpVersionInfo, 4))[0]
            
            # Windows Vista SP2 info
            # OSVERSIONINFOA: 148 bytes
            # OSVERSIONINFOEXA: 156 bytes
            if size >= 156:
                # OSVERSIONINFOEXA
                version_info = struct.pack('<IIIII',
                    156,   # dwOSVersionInfoSize
                    6,     # dwMajorVersion (Vista)
                    0,     # dwMinorVersion
                    6002,  # dwBuildNumber (SP2)
                    2,     # dwPlatformId (VER_PLATFORM_WIN32_NT)
                )
                # szCSDVersion[128] - "Service Pack 2"
                csd_version = b'Service Pack 2' + b'\x00' * (128 - 14)
                # OSVERSIONINFOEXA additional fields
                ex_fields = struct.pack('<HHBBBB',
                    2,     # wServicePackMajor
                    0,     # wServicePackMinor
                    0,     # wSuiteMask
                    1,     # wProductType (VER_NT_WORKSTATION)
                    0,     # wReserved
                    0,     # padding
                )
                self.emu.uc.mem_write(lpVersionInfo, version_info + csd_version + ex_fields)
            else:
                # OSVERSIONINFOA
                version_info = struct.pack('<IIIII',
                    148,   # dwOSVersionInfoSize
                    6,     # dwMajorVersion (Vista)
                    0,     # dwMinorVersion
                    6002,  # dwBuildNumber (SP2)
                    2,     # dwPlatformId (VER_PLATFORM_WIN32_NT)
                )
                # szCSDVersion[128] - "Service Pack 2"
                csd_version = b'Service Pack 2' + b'\x00' * (128 - 14)
                self.emu.uc.mem_write(lpVersionInfo, version_info + csd_version)
            return 1
        except Exception as e:
            log.error(f"GetVersionExA error: {e}")
            return 0
    
    def GetVersionExW(self, args):
        """GetVersionExW emulation - Windows Vista SP2 (Unicode)"""
        lpVersionInfo = args[0]
        log.debug(f"GetVersionExW(0x{lpVersionInfo:08x})")
        
        try:
            # Read dwOSVersionInfoSize
            size = struct.unpack('<I', self.emu.uc.mem_read(lpVersionInfo, 4))[0]
            
            # Windows Vista SP2 info
            # OSVERSIONINFOW: 276 bytes (128 WCHAR = 256 bytes for szCSDVersion)
            # OSVERSIONINFOEXW: 284 bytes
            if size >= 284:
                # OSVERSIONINFOEXW
                version_info = struct.pack('<IIIII',
                    284,   # dwOSVersionInfoSize
                    6,     # dwMajorVersion (Vista)
                    0,     # dwMinorVersion
                    6002,  # dwBuildNumber (SP2)
                    2,     # dwPlatformId (VER_PLATFORM_WIN32_NT)
                )
                # szCSDVersion[128] WCHAR - "Service Pack 2"
                csd_version = 'Service Pack 2'.encode('utf-16-le') + b'\x00' * (256 - 28)
                # OSVERSIONINFOEXW additional fields
                ex_fields = struct.pack('<HHBBBB',
                    2,     # wServicePackMajor
                    0,     # wServicePackMinor
                    0,     # wSuiteMask
                    1,     # wProductType (VER_NT_WORKSTATION)
                    0,     # wReserved
                    0,     # padding
                )
                self.emu.uc.mem_write(lpVersionInfo, version_info + csd_version + ex_fields)
            else:
                # OSVERSIONINFOW
                version_info = struct.pack('<IIIII',
                    276,   # dwOSVersionInfoSize
                    6,     # dwMajorVersion (Vista)
                    0,     # dwMinorVersion
                    6002,  # dwBuildNumber (SP2)
                    2,     # dwPlatformId (VER_PLATFORM_WIN32_NT)
                )
                # szCSDVersion[128] WCHAR
                csd_version = 'Service Pack 2'.encode('utf-16-le') + b'\x00' * (256 - 28)
                self.emu.uc.mem_write(lpVersionInfo, version_info + csd_version)
            return 1
        except Exception as e:
            log.error(f"GetVersionExW error: {e}")
            return 0

    # ==================== ADDITIONAL APIs ====================
    
    def SetErrorMode(self, args):
        """SetErrorMode emulation"""
        uMode = args[0]
        log.debug(f"SetErrorMode(0x{uMode:x})")
        return 0  # Previous mode
    
    def GetModuleFileNameA(self, args):
        """GetModuleFileNameA emulation"""
        hModule = args[0]
        lpFilename = args[1]
        nSize = args[2]
        
        filepath = self.windows_exe_path()
        data = filepath.encode(ANSI_CODEPAGE, errors='replace')
        if nSize == 0:
            return 0
        if len(data) >= nSize:
            # Truncated: Windows XP+ semantics (no room for full name)
            data = data[:nSize - 1]
            self.emu.uc.mem_write(lpFilename, data + b'\x00')
            self._last_error = 122  # ERROR_INSUFFICIENT_BUFFER
            return nSize
        self.emu.uc.mem_write(lpFilename, data + b'\x00')

        log.debug(f"GetModuleFileNameA(0x{hModule:x}) -> \"{filepath}\"")
        return len(data)
    
    def GetModuleFileNameW(self, args):
        """GetModuleFileNameW emulation"""
        hModule = args[0]
        lpFilename = args[1]
        nSize = args[2]
        
        filepath = self.windows_exe_path()
        if nSize == 0:
            return 0
        if len(filepath) >= nSize:
            self.emu.uc.mem_write(lpFilename, filepath[:nSize - 1].encode('utf-16-le') + b'\x00\x00')
            self._last_error = 122  # ERROR_INSUFFICIENT_BUFFER
            return nSize
        self.emu.uc.mem_write(lpFilename, filepath.encode('utf-16-le') + b'\x00\x00')

        log.debug(f"GetModuleFileNameW(0x{hModule:x}) -> \"{filepath}\"")
        return len(filepath)
    
    def LoadLibraryA(self, args):
        """LoadLibraryA emulation"""
        lib_name = self.read_string(args[0])
        log.debug(f"LoadLibraryA(\"{lib_name}\")")
        return self._module_handle(lib_name, load=True)
    
    def LoadLibraryW(self, args):
        """LoadLibraryW emulation"""
        lib_name = self.read_wide_string(args[0])
        log.debug(f"LoadLibraryW(\"{lib_name}\")")
        return self._module_handle(lib_name, load=True)
    
    def LoadLibraryExA(self, args):
        """LoadLibraryExA emulation"""
        lib_name = self.read_string(args[0])
        log.debug(f"LoadLibraryExA(\"{lib_name}\", 0x{args[2]:x})")
        return self._module_handle(lib_name, load=True)
    
    def LoadLibraryExW(self, args):
        """LoadLibraryExW emulation"""
        lib_name = self.read_wide_string(args[0])
        log.debug(f"LoadLibraryExW(\"{lib_name}\", 0x{args[2]:x})")
        return self._module_handle(lib_name, load=True)
    
    def FreeLibrary(self, args):
        """FreeLibrary emulation - module handles stay valid (no refcounting)"""
        hLibModule = args[0]
        log.debug(f"FreeLibrary(0x{hLibModule:x})")
        return 1
    
    def GetSystemDirectoryA(self, args):
        """GetSystemDirectoryA emulation"""
        lpBuffer = args[0]
        uSize = args[1]
        
        sys_dir = "C:\\Windows\\System32"
        if len(sys_dir) < uSize:
            self.emu.uc.mem_write(lpBuffer, sys_dir.encode(ANSI_CODEPAGE, errors='replace') + b'\x00')
        
        log.debug(f"GetSystemDirectoryA() -> \"{sys_dir}\"")
        return len(sys_dir)
    
    def GetWindowsDirectoryA(self, args):
        """GetWindowsDirectoryA emulation"""
        lpBuffer = args[0]
        uSize = args[1]
        
        win_dir = "C:\\Windows"
        if len(win_dir) < uSize:
            self.emu.uc.mem_write(lpBuffer, win_dir.encode(ANSI_CODEPAGE, errors='replace') + b'\x00')
        
        log.debug(f"GetWindowsDirectoryA() -> \"{win_dir}\"")
        return len(win_dir)
    
    def GetTempPathA(self, args):
        """GetTempPathA emulation"""
        nBufferLength = args[0]
        lpBuffer = args[1]
        
        temp_path = "C:\\Windows\\Temp\\"
        if len(temp_path) < nBufferLength:
            self.emu.uc.mem_write(lpBuffer, temp_path.encode(ANSI_CODEPAGE, errors='replace') + b'\x00')
        
        log.debug(f"GetTempPathA() -> \"{temp_path}\"")
        return len(temp_path)
    
    def lstrlenA(self, args):
        """lstrlenA emulation"""
        lpString = args[0]
        
        if lpString == 0:
            return 0
        
        s = self.read_string(lpString)
        log.debug(f"lstrlenA(\"{s[:32]}...\") -> {len(s)}")
        return len(s)
    
    def lstrlenW(self, args):
        """lstrlenW emulation"""
        lpString = args[0]
        
        if lpString == 0:
            return 0
        
        s = self.read_wide_string(lpString)
        log.debug(f"lstrlenW() -> {len(s)}")
        return len(s)
    
    def IsDBCSLeadByteEx(self, args):
        """IsDBCSLeadByteEx emulation - supported code pages have no DBCS lead bytes"""
        return 0

    def GetStartupInfoA(self, args):
        """GetStartupInfoA emulation"""
        lpStartupInfo = args[0]
        log.debug(f"GetStartupInfoA(0x{lpStartupInfo:08x})")
        
        # Fill STARTUPINFOA structure (68 bytes)
        try:
            startup_info = struct.pack('<IIIIIIIIIIIIHHIIII',
                68,   # cb (structure size)
                0,    # lpReserved
                0,    # lpDesktop
                0,    # lpTitle
                0,    # dwX
                0,    # dwY
                800,  # dwXSize
                600,  # dwYSize
                80,   # dwXCountChars
                25,   # dwYCountChars
                0,    # dwFillAttribute
                0,    # dwFlags
                1,    # wShowWindow (SW_SHOWNORMAL)
                0,    # cbReserved2
                0,    # lpReserved2
                0,    # hStdInput
                0,    # hStdOutput
                0,    # hStdError
            )
            self.emu.uc.mem_write(lpStartupInfo, startup_info)
        except UcError:
            pass
        return 0
    
    def GetStartupInfoW(self, args):
        """GetStartupInfoW emulation"""
        return self.GetStartupInfoA(args)
    
    def GetSystemDirectoryW(self, args):
        """GetSystemDirectoryW emulation"""
        lpBuffer = args[0]
        uSize = args[1]
        
        sys_dir = "C:\\Windows\\System32"
        if len(sys_dir) < uSize:
            self.emu.uc.mem_write(lpBuffer, sys_dir.encode('utf-16-le') + b'\x00\x00')
        
        log.debug(f"GetSystemDirectoryW() -> \"{sys_dir}\"")
        return len(sys_dir)
    
    def GetWindowsDirectoryW(self, args):
        """GetWindowsDirectoryW emulation"""
        lpBuffer = args[0]
        uSize = args[1]
        
        win_dir = "C:\\Windows"
        if len(win_dir) < uSize:
            self.emu.uc.mem_write(lpBuffer, win_dir.encode('utf-16-le') + b'\x00\x00')
        
        log.debug(f"GetWindowsDirectoryW() -> \"{win_dir}\"")
        return len(win_dir)

    def lstrcpyA(self, args, wide=False):
        """lstrcpyA/W emulation"""
        lpString1 = args[0]
        lpString2 = args[1]
        
        units = self._read_units(lpString2, wide)
        self._write_units(lpString1, units, wide)
        
        log.debug(f"lstrcpy{'W' if wide else 'A'}(0x{lpString1:08x}, "
                  f"\"{self._units_text(units[:32], wide)}\")")
        return lpString1

    def lstrcpyW(self, args):
        return self.lstrcpyA(args, wide=True)
    
    def lstrcpynA(self, args):
        """lstrcpynA emulation"""
        lpString1 = args[0]
        lpString2 = args[1]
        iMaxLength = args[2]
        
        if iMaxLength == 0 or iMaxLength >= 0x80000000:
            return lpString1
        src = self.read_cstring(lpString2, iMaxLength - 1)
        self.emu.uc.mem_write(lpString1, src + b'\x00')
        
        log.debug(f"lstrcpynA(0x{lpString1:08x}, {src[:32]!r}, {iMaxLength})")
        return lpString1
    
    def lstrcatA(self, args, wide=False):
        """lstrcatA/W emulation"""
        lpString1 = args[0]
        lpString2 = args[1]
        
        dst = self._read_units(lpString1, wide)
        src = self._read_units(lpString2, wide)
        self._write_units(lpString1 + len(dst) * (2 if wide else 1), src, wide)
        
        log.debug(f"lstrcat{'W' if wide else 'A'}() -> "
                  f"\"{self._units_text((dst + src)[:32], wide)}\"")
        return lpString1

    def lstrcatW(self, args):
        return self.lstrcatA(args, wide=True)
    
    def lstrcmpA(self, args, wide=False, ignore_case=False):
        """lstrcmpA/W and lstrcmpiA/W emulation"""
        s1 = self._read_text(args[0], wide)
        s2 = self._read_text(args[1], wide)
        if ignore_case:
            s1, s2 = s1.lower(), s2.lower()
        
        result = (s1 > s2) - (s1 < s2)
        
        log.debug(f"lstrcmp{'i' if ignore_case else ''}{'W' if wide else 'A'}"
                  f"(\"{s1[:16]}\", \"{s2[:16]}\") -> {result}")
        return result & 0xFFFFFFFF

    def lstrcmpW(self, args):
        return self.lstrcmpA(args, wide=True)
    
    def lstrcmpiA(self, args):
        """lstrcmpiA emulation (case-insensitive)"""
        return self.lstrcmpA(args, ignore_case=True)

    def lstrcmpiW(self, args):
        return self.lstrcmpA(args, wide=True, ignore_case=True)
    
    def GlobalAlloc(self, args):
        """GlobalAlloc emulation"""
        uFlags = args[0]
        dwBytes = args[1]
        
        addr = self.emu.heap_alloc(dwBytes)
        
        # Zero memory if GMEM_ZEROINIT (0x0040) flag is set
        if addr and uFlags & 0x0040:
            self.emu.uc.mem_write(addr, b'\x00' * dwBytes)
        
        log.debug(f"GlobalAlloc(0x{uFlags:x}, {dwBytes}) -> 0x{addr:08x}")
        return addr
    
    def GlobalFree(self, args):
        """GlobalFree emulation"""
        hMem = args[0]
        log.debug(f"GlobalFree(0x{hMem:08x})")
        # NULL on success, the handle on failure
        return 0 if not hMem or self.emu.heap_free(hMem) else hMem
    
    def GlobalLock(self, args):
        """GlobalLock emulation"""
        hMem = args[0]
        log.debug(f"GlobalLock(0x{hMem:08x})")
        return hMem  # Return same address
    
    def GlobalUnlock(self, args):
        """GlobalUnlock emulation"""
        hMem = args[0]
        log.debug(f"GlobalUnlock(0x{hMem:08x})")
        return 1
    
    def LocalAlloc(self, args):
        """LocalAlloc emulation"""
        return self.GlobalAlloc(args)
    
    def LocalFree(self, args):
        """LocalFree emulation"""
        return self.GlobalFree(args)
    
    def CloseHandle(self, args):
        """CloseHandle emulation"""
        hObject = args[0]
        log.debug(f"CloseHandle(0x{hObject:x})")

        if hObject in self.handles:
            info = self.handles[hObject]
            fp = info.get('fp')
            if fp:
                try:
                    fp.close()
                except OSError as e:
                    log.error(f"CloseHandle close error: {e}")
            del self.handles[hObject]
        return 1
    
    def Sleep(self, args):
        """Sleep emulation - real wait so game loops pace correctly"""
        dwMilliseconds = args[0]
        log.debug(f"Sleep({dwMilliseconds}ms)")
        self._wait_ms(dwMilliseconds)
        return 0

    def _wait_ms(self, milliseconds, until=None):
        """Block for up to 10 s (or until until() is False), in short chunks
        so a stop request is not delayed"""
        end = time.time() + min(milliseconds, 10000) / 1000.0
        while not self.emu.stop_emulation:
            self._audio_pump()
            remaining = end - time.time()
            if remaining <= 0 or (until is not None and not until()):
                break
            time.sleep(min(0.05, remaining))
    
    # Critical sections: the emulated process is single-threaded, so these
    # never contend and need no real locking.
    def InitializeCriticalSection(self, args):
        """InitializeCriticalSection emulation"""
        try:
            self.emu.uc.mem_write(args[0], b'\x00' * 24)  # sizeof(CRITICAL_SECTION)
        except UcError:
            pass
        return 0

    def InitializeCriticalSectionAndSpinCount(self, args):
        """InitializeCriticalSectionAndSpinCount emulation"""
        self.InitializeCriticalSection(args)
        return 1

    def EnterCriticalSection(self, args):
        """EnterCriticalSection emulation"""
        return 0

    def TryEnterCriticalSection(self, args):
        """TryEnterCriticalSection emulation - always acquires"""
        return 1

    def LeaveCriticalSection(self, args):
        """LeaveCriticalSection emulation"""
        return 0

    def DeleteCriticalSection(self, args):
        """DeleteCriticalSection emulation"""
        return 0

    def GetFileAttributesA(self, args, wide=False):
        """GetFileAttributesA/W emulation (sandboxed to c_drive/)"""
        filename = self._read_text(args[0], wide)
        log.debug(f"GetFileAttributes{'W' if wide else 'A'}(\"{filename}\")")

        path = self.resolve_c_drive_path(filename)
        if path is None or not os.path.exists(path):
            return 0xFFFFFFFF  # INVALID_FILE_ATTRIBUTES
        if os.path.isdir(path):
            return 0x10  # FILE_ATTRIBUTE_DIRECTORY
        if not os.access(path, os.W_OK):
            return 0x01  # FILE_ATTRIBUTE_READONLY
        return 0x80  # FILE_ATTRIBUTE_NORMAL

    def CreateFileA(self, args):
        """CreateFileA emulation - opens a real file inside the c_drive/ sandbox"""
        filename = self.read_string(args[0])
        dwDesiredAccess = args[1]
        dwCreationDisposition = args[4]
        log.debug(f"CreateFileA(\"{filename}\", access=0x{dwDesiredAccess:x}, "
                  f"disp={dwCreationDisposition})")
        return self._create_file_common(filename, dwDesiredAccess, dwCreationDisposition)

    def CreateFileW(self, args):
        """CreateFileW emulation - wide-char CreateFile"""
        filename = self.read_wide_string(args[0])
        dwDesiredAccess = args[1]
        dwCreationDisposition = args[4]
        log.debug(f"CreateFileW(\"{filename}\", access=0x{dwDesiredAccess:x}, "
                  f"disp={dwCreationDisposition})")
        return self._create_file_common(filename, dwDesiredAccess, dwCreationDisposition)

    def _create_file_common(self, filename, dwDesiredAccess, dwCreationDisposition):
        """Shared CreateFile opener used by the A/W variants.

        Honours the sandbox: names that escape c_drive/ get
        INVALID_HANDLE_VALUE and ERROR_ACCESS_DENIED.
        """
        INVALID_HANDLE_VALUE = 0xFFFFFFFF
        path = self.resolve_c_drive_path(filename)
        if path is None:
            self._last_error = 5  # ERROR_ACCESS_DENIED
            return INVALID_HANDLE_VALUE

        GENERIC_WRITE = 0x40000000
        want_write = bool(dwDesiredAccess & GENERIC_WRITE)
        exists = os.path.exists(path)

        # CreationDisposition: CREATE_NEW=1, CREATE_ALWAYS=2, OPEN_EXISTING=3,
        # OPEN_ALWAYS=4, TRUNCATE_EXISTING=5
        try:
            if dwCreationDisposition == 1:      # CREATE_NEW
                if exists:
                    self._last_error = 80  # ERROR_FILE_EXISTS
                    return INVALID_HANDLE_VALUE
                fp = open(path, 'w+b')
            elif dwCreationDisposition == 2:    # CREATE_ALWAYS
                fp = open(path, 'w+b')
            elif dwCreationDisposition == 3:    # OPEN_EXISTING
                if not exists:
                    self._last_error = 2  # ERROR_FILE_NOT_FOUND
                    return INVALID_HANDLE_VALUE
                fp = open(path, 'r+b' if want_write else 'rb')
            elif dwCreationDisposition == 4:    # OPEN_ALWAYS
                fp = open(path, 'r+b') if exists else open(path, 'w+b')
            elif dwCreationDisposition == 5:    # TRUNCATE_EXISTING
                if not exists:
                    self._last_error = 2
                    return INVALID_HANDLE_VALUE
                fp = open(path, 'w+b')
            else:
                fp = open(path, 'r+b' if want_write else 'rb')
        except OSError as e:
            log.error(f"CreateFile(\"{filename}\") failed: {e}")
            self._last_error = 2
            return INVALID_HANDLE_VALUE

        handle = self.get_next_handle()
        self.handles[handle] = {'type': 'file', 'name': filename,
                                'fp': fp, 'path': path}
        self._last_error = 0
        return handle

    def GetFileSize(self, args):
        """GetFileSize emulation"""
        hFile = args[0]
        lpFileSizeHigh = args[1]

        log.debug(f"GetFileSize(0x{hFile:x})")

        size = 0
        info = self.handles.get(hFile)
        if info and info.get('fp'):
            try:
                fp = info['fp']
                cur = fp.tell()
                fp.seek(0, os.SEEK_END)
                size = fp.tell()
                fp.seek(cur, os.SEEK_SET)
            except OSError:
                size = 0

        if lpFileSizeHigh != 0:
            self.emu.uc.mem_write(lpFileSizeHigh,
                                  struct.pack('<I', (size >> 32) & 0xFFFFFFFF))

        return size & 0xFFFFFFFF

    def SetFilePointer(self, args):
        """SetFilePointer emulation"""
        hFile = args[0]
        lDistanceToMove = args[1]
        # args[2] lpDistanceToMoveHigh (ignored, 32-bit offsets only)
        dwMoveMethod = args[3]  # FILE_BEGIN=0, FILE_CURRENT=1, FILE_END=2

        # Interpret distance as signed 32-bit.
        if lDistanceToMove & 0x80000000:
            lDistanceToMove -= 0x100000000

        log.debug(f"SetFilePointer(0x{hFile:x}, {lDistanceToMove}, method={dwMoveMethod})")

        info = self.handles.get(hFile)
        if not info or not info.get('fp'):
            return 0xFFFFFFFF  # INVALID_SET_FILE_POINTER

        whence = {0: os.SEEK_SET, 1: os.SEEK_CUR, 2: os.SEEK_END}.get(dwMoveMethod, os.SEEK_SET)
        try:
            info['fp'].seek(lDistanceToMove, whence)
            return info['fp'].tell() & 0xFFFFFFFF
        except OSError:
            return 0xFFFFFFFF

    def DeleteFileA(self, args, wide=False):
        """DeleteFileA/W emulation (sandboxed)"""
        filename = self._read_text(args[0], wide)
        log.debug(f"DeleteFileA(\"{filename}\")")
        path = self.resolve_c_drive_path(filename)
        if path is None or not os.path.isfile(path):
            self._last_error = 2
            return 0  # FALSE
        try:
            os.remove(path)
            return 1
        except OSError as e:
            log.error(f"DeleteFileA(\"{filename}\") failed: {e}")
            self._last_error = 5
            return 0

    def CreateDirectoryA(self, args, wide=False):
        """CreateDirectoryA/W emulation (sandboxed)"""
        dirname = self._read_text(args[0], wide)
        log.debug(f"CreateDirectoryA(\"{dirname}\")")
        path = self.resolve_c_drive_path(dirname)
        if path is None:
            self._last_error = 5  # ERROR_ACCESS_DENIED
            return 0
        try:
            os.mkdir(path)
            return 1
        except FileExistsError:
            self._last_error = 183  # ERROR_ALREADY_EXISTS
        except FileNotFoundError:
            self._last_error = 3  # ERROR_PATH_NOT_FOUND
        except OSError as e:
            log.error(f"CreateDirectoryA(\"{dirname}\") failed: {e}")
            self._last_error = 5
        return 0

    def RemoveDirectoryA(self, args, wide=False):
        """RemoveDirectoryA/W emulation (sandboxed, directory must be empty)"""
        dirname = self._read_text(args[0], wide)
        log.debug(f"RemoveDirectoryA(\"{dirname}\")")
        path = self.resolve_c_drive_path(dirname)
        if path is None or not os.path.isdir(path):
            self._last_error = 3 if path else 5
            return 0
        try:
            os.rmdir(path)
            return 1
        except OSError:
            self._last_error = 145  # ERROR_DIR_NOT_EMPTY
            return 0

    def GetFileAttributesW(self, args):
        return self.GetFileAttributesA(args, wide=True)

    def DeleteFileW(self, args):
        return self.DeleteFileA(args, wide=True)

    def CreateDirectoryW(self, args):
        return self.CreateDirectoryA(args, wide=True)

    def RemoveDirectoryW(self, args):
        return self.RemoveDirectoryA(args, wide=True)

    def CopyFileA(self, args, wide=False):
        """CopyFileA/W emulation (sandboxed)"""
        src = self._read_text(args[0], wide)
        dst = self._read_text(args[1], wide)
        fail_if_exists = args[2]
        log.debug(f"CopyFile(\"{src}\", \"{dst}\", {fail_if_exists})")
        src_path = self.resolve_c_drive_path(src)
        dst_path = self.resolve_c_drive_path(dst)
        if src_path is None or dst_path is None:
            self._last_error = 5  # ERROR_ACCESS_DENIED
            return 0
        if not os.path.isfile(src_path):
            self._last_error = 2  # ERROR_FILE_NOT_FOUND
            return 0
        if os.path.isdir(dst_path):
            self._last_error = 5
            return 0
        if fail_if_exists and os.path.exists(dst_path):
            self._last_error = 80  # ERROR_FILE_EXISTS
            return 0
        try:
            shutil.copyfile(src_path, dst_path)
        except FileNotFoundError:
            self._last_error = 3  # ERROR_PATH_NOT_FOUND
            return 0
        except OSError as e:
            log.error(f"CopyFile(\"{src}\", \"{dst}\") failed: {e}")
            self._last_error = 5
            return 0
        return 1

    def CopyFileW(self, args):
        return self.CopyFileA(args, wide=True)

    def MoveFileA(self, args, wide=False):
        """MoveFileA/W emulation (sandboxed; files and directories)"""
        src = self._read_text(args[0], wide)
        dst = self._read_text(args[1], wide)
        log.debug(f"MoveFile(\"{src}\", \"{dst}\")")
        src_path = self.resolve_c_drive_path(src)
        dst_path = self.resolve_c_drive_path(dst)
        if src_path is None or dst_path is None:
            self._last_error = 5  # ERROR_ACCESS_DENIED
            return 0
        if not os.path.exists(src_path):
            self._last_error = 2  # ERROR_FILE_NOT_FOUND
            return 0
        if os.path.exists(dst_path):
            self._last_error = 183  # ERROR_ALREADY_EXISTS
            return 0
        try:
            os.rename(src_path, dst_path)
        except FileNotFoundError:
            self._last_error = 3  # ERROR_PATH_NOT_FOUND
            return 0
        except OSError as e:
            log.error(f"MoveFile(\"{src}\", \"{dst}\") failed: {e}")
            self._last_error = 5
            return 0
        return 1

    def MoveFileW(self, args):
        return self.MoveFileA(args, wide=True)

    def GetCurrentDirectoryA(self, args, wide=False):
        """GetCurrentDirectoryA/W emulation"""
        nBufferLength, lpBuffer = args[0], args[1]
        cwd = self.current_directory
        log.debug(f"GetCurrentDirectory() -> \"{cwd}\"")
        size = len(self._text_units(cwd, wide))
        if not lpBuffer or nBufferLength <= size:
            return size + 1  # required size including the terminator
        self._write_text(lpBuffer, cwd, wide)
        return size

    def GetCurrentDirectoryW(self, args):
        return self.GetCurrentDirectoryA(args, wide=True)

    def SetCurrentDirectoryA(self, args, wide=False):
        """SetCurrentDirectoryA/W emulation (the directory must exist in c_drive/)"""
        name = self._read_text(args[0], wide)
        log.debug(f"SetCurrentDirectory(\"{name}\")")
        full = self.full_windows_path(name)
        path = self.resolve_c_drive_path(name)
        if full is None or path is None:
            self._last_error = 5  # ERROR_ACCESS_DENIED
            return 0
        if not os.path.isdir(path):
            self._last_error = 2 if not os.path.exists(path) else 267  # ERROR_DIRECTORY
            return 0
        self.current_directory = full
        return 1

    def SetCurrentDirectoryW(self, args):
        return self.SetCurrentDirectoryA(args, wide=True)

    def GetFullPathNameA(self, args):
        """GetFullPathNameA emulation - resolves against the current directory"""
        name = self.read_string(args[0])
        nBufferLength, lpBuffer, lpFilePart = args[1], args[2], args[3]
        full = self.full_windows_path(name, clamp=True)
        log.debug(f"GetFullPathNameA(\"{name}\") -> \"{full}\"")
        if full is None:
            self._last_error = 123  # ERROR_INVALID_NAME
            return 0
        data = full.encode(ANSI_CODEPAGE, errors='replace')
        if not lpBuffer or nBufferLength <= len(data):
            return len(data) + 1
        self.emu.uc.mem_write(lpBuffer, data + b'\x00')
        if lpFilePart:
            # Last component, or NULL when the path ends with a separator
            sep = data.rfind(b'\\')
            part = lpBuffer + sep + 1 if sep + 1 < len(data) else 0
            self.emu.uc.mem_write(lpFilePart, struct.pack('<I', part))
        return len(data)

    def GetDiskFreeSpaceA(self, args):
        """GetDiskFreeSpaceA emulation - space of the host disk holding c_drive/"""
        root = self.read_string(args[0]) if args[0] else "C:\\"
        log.debug(f"GetDiskFreeSpaceA(\"{root}\")")
        if root[1:2] == ':' and root[0].upper() != 'C':
            self._last_error = 3  # ERROR_PATH_NOT_FOUND
            return 0
        usage = shutil.disk_usage(C_DRIVE_PATH)
        sectors, sector_size = 8, 512
        cluster = sectors * sector_size
        # Old programs compute bytes in 32 bits: report at most 2 GB like Windows 9x
        limit = 0x7FFFFFFF // cluster
        values = (sectors, sector_size, min(usage.free // cluster, limit),
                  min(usage.total // cluster, limit))
        for ptr, value in zip(args[1:5], values):
            if ptr:
                self.emu.uc.mem_write(ptr, struct.pack('<I', value))
        return 1

    def GetTempFileNameA(self, args):
        """GetTempFileNameA emulation - <path>\\<pre><hex>.TMP (created if uUnique is 0)"""
        path_name = self.read_string(args[0])
        prefix = self.read_string(args[1])[:3]
        uUnique = args[2] & 0xFFFF
        lpTempFileName = args[3]
        log.debug(f"GetTempFileNameA(\"{path_name}\", \"{prefix}\", {uUnique})")

        directory = self.resolve_c_drive_path(path_name)
        if directory is None or not os.path.isdir(directory):
            self._last_error = 267  # ERROR_DIRECTORY
            return 0
        base = path_name.rstrip('\\/') + '\\' + prefix

        if uUnique:
            name = f"{base}{uUnique:X}.TMP"
        else:
            # Probe numbers from the tick count until an unused name is found
            start = (int(time.time() * 1000) & 0xFFFF) or 1
            for i in range(0xFFFF):
                uUnique = (start + i - 1) % 0xFFFF + 1
                name = f"{base}{uUnique:X}.TMP"
                path = self.resolve_c_drive_path(name)
                if path is None:
                    break
                try:
                    with open(path, 'xb'):
                        pass
                    break
                except FileExistsError:
                    continue
                except OSError:
                    path = None
                    break
            else:
                path = None
            if path is None:
                self._last_error = 80  # ERROR_FILE_EXISTS
                return 0

        data = name.encode(ANSI_CODEPAGE, errors='replace')
        if len(data) >= 260:  # MAX_PATH
            self._last_error = 206  # ERROR_FILENAME_EXCED_RANGE
            return 0
        self.emu.uc.mem_write(lpTempFileName, data + b'\x00')
        return uUnique

    def _file_handle_fp(self, hFile):
        """Python file object of a CreateFile handle, or None (sets ERROR_INVALID_HANDLE)"""
        info = self.handles.get(hFile)
        if info and info.get('fp'):
            return info['fp']
        self._last_error = 6  # ERROR_INVALID_HANDLE
        return None

    def FlushFileBuffers(self, args):
        """FlushFileBuffers emulation"""
        fp = self._file_handle_fp(args[0])
        if fp is None:
            return 0
        try:
            fp.flush()
        except OSError:
            self._last_error = 5
            return 0
        return 1

    def SetEndOfFile(self, args):
        """SetEndOfFile emulation - truncate or extend the file at the file pointer"""
        fp = self._file_handle_fp(args[0])
        if fp is None:
            return 0
        try:
            fp.truncate(fp.tell())
        except (OSError, io.UnsupportedOperation):
            self._last_error = 5  # ERROR_ACCESS_DENIED (opened read-only)
            return 0
        return 1

    # ---------- FindFirstFile / FindNextFile ----------

    @staticmethod
    def _wildcard_regex(pattern):
        """Compile a Windows wildcard (* and ?) into a case-insensitive regex"""
        if pattern == '*.*':
            pattern = '*'  # Matches names without an extension too
        regex = ''.join('.*' if c == '*' else '.' if c == '?' else re.escape(c)
                        for c in pattern)
        return re.compile(regex + r'\Z', re.IGNORECASE | re.DOTALL)

    @staticmethod
    def _filetime(timestamp):
        """FILETIME (100 ns units since 1601) of a Unix timestamp"""
        return int((timestamp + 11644473600) * 10000000)

    def _find_entry(self, path, name):
        """(name, attributes, size, mtime) of one directory entry"""
        try:
            st = os.stat(path)
        except OSError:
            return None
        if os.path.isdir(path):
            return (name, 0x10, 0, st.st_mtime)  # FILE_ATTRIBUTE_DIRECTORY
        return (name, 0x80, st.st_size, st.st_mtime)  # FILE_ATTRIBUTE_NORMAL

    def _write_find_data(self, address, entry, wide):
        """Fill a WIN32_FIND_DATAA/W structure"""
        name, attributes, size, mtime = entry
        ft = self._filetime(mtime)
        header = struct.pack('<I3QIIII', attributes, ft, ft, ft,
                             size >> 32, size & 0xFFFFFFFF, 0, 0)
        name_size, alt_size = (520, 28) if wide else (260, 14)
        if wide:
            raw = name.encode('utf-16-le')[:name_size - 2]
        else:
            raw = name.encode(ANSI_CODEPAGE, errors='replace')[:name_size - 1]
        names = raw.ljust(name_size, b'\x00') + b'\x00' * alt_size
        self.emu.uc.mem_write(address, header + names)

    def FindFirstFileA(self, args, wide=False):
        """FindFirstFileA/W emulation - lists a c_drive/ directory"""
        INVALID_HANDLE_VALUE = 0xFFFFFFFF
        spec = self._read_text(args[0], wide)
        lpFindFileData = args[1]
        log.debug(f"FindFirstFile{'W' if wide else 'A'}(\"{spec}\")")

        full = self.full_windows_path(spec)
        if full is None or full == "C:\\":
            self._last_error = 5 if full is None else 2
            return INVALID_HANDLE_VALUE
        folder, _, pattern = full.rpartition('\\')
        folder_path = self.resolve_c_drive_path(folder + '\\')
        if folder_path is None:
            self._last_error = 5  # ERROR_ACCESS_DENIED
            return INVALID_HANDLE_VALUE
        if not os.path.isdir(folder_path):
            self._last_error = 3  # ERROR_PATH_NOT_FOUND
            return INVALID_HANDLE_VALUE

        regex = self._wildcard_regex(pattern)
        try:
            names = sorted(os.listdir(folder_path), key=str.lower)
        except OSError:
            self._last_error = 5
            return INVALID_HANDLE_VALUE
        if folder != "C:":
            names = ['.', '..'] + names  # Every directory but the root has them
        entries = []
        for name in names:
            if regex.match(name):
                entry = self._find_entry(os.path.join(folder_path, name), name)
                if entry:
                    entries.append(entry)
        if not entries:
            self._last_error = 2  # ERROR_FILE_NOT_FOUND
            return INVALID_HANDLE_VALUE

        self._write_find_data(lpFindFileData, entries[0], wide)
        handle = self.get_next_handle()
        self.handles[handle] = {'type': 'find', 'entries': entries, 'index': 1}
        self._last_error = 0
        return handle

    def FindFirstFileW(self, args):
        return self.FindFirstFileA(args, wide=True)

    def FindNextFileA(self, args, wide=False):
        """FindNextFileA/W emulation"""
        info = self.handles.get(args[0])
        if not info or info.get('type') != 'find':
            self._last_error = 6  # ERROR_INVALID_HANDLE
            return 0
        if info['index'] >= len(info['entries']):
            self._last_error = 18  # ERROR_NO_MORE_FILES
            return 0
        self._write_find_data(args[1], info['entries'][info['index']], wide)
        info['index'] += 1
        return 1

    def FindNextFileW(self, args):
        return self.FindNextFileA(args, wide=True)

    def FindClose(self, args):
        """FindClose emulation"""
        info = self.handles.get(args[0])
        if not info or info.get('type') != 'find':
            self._last_error = 6
            return 0
        del self.handles[args[0]]
        return 1

    def _write_text(self, address, text, wide):
        """Write a NUL-terminated ANSI or UTF-16 string"""
        if wide:
            data = text.encode('utf-16-le') + b'\x00\x00'
        else:
            data = text.encode(ANSI_CODEPAGE, errors='replace') + b'\x00'
        self.emu.uc.mem_write(address, data)

    def _get_name_common(self, name, lpBuffer, lpnSize, wide, size_includes_nul,
                         error_code):
        """Shared GetComputerName/GetUserName logic (size is in/out in *lpnSize)"""
        try:
            size = struct.unpack('<I', self.emu.uc.mem_read(lpnSize, 4))[0]
        except UcError:
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0
        if not lpBuffer or size <= len(name):
            self.emu.uc.mem_write(lpnSize, struct.pack('<I', len(name) + 1))
            self._last_error = error_code
            return 0
        self._write_text(lpBuffer, name, wide)
        written = len(name) + (1 if size_includes_nul else 0)
        self.emu.uc.mem_write(lpnSize, struct.pack('<I', written))
        return 1

    COMPUTER_NAME = "WINEXE32EMU"
    USER_NAME = "User"

    def GetComputerNameA(self, args, wide=False):
        """GetComputerNameA/W emulation"""
        log.debug(f"GetComputerName() -> \"{self.COMPUTER_NAME}\"")
        # ERROR_BUFFER_OVERFLOW; the returned size excludes the terminator
        return self._get_name_common(self.COMPUTER_NAME, args[0], args[1], wide, False, 111)

    def GetComputerNameW(self, args):
        return self.GetComputerNameA(args, wide=True)

    def GetUserNameA(self, args, wide=False):
        """GetUserNameA/W emulation (advapi32)"""
        log.debug(f"GetUserName() -> \"{self.USER_NAME}\"")
        # ERROR_INSUFFICIENT_BUFFER; the returned size includes the terminator
        return self._get_name_common(self.USER_NAME, args[0], args[1], wide, True, 122)

    def GetUserNameW(self, args):
        return self.GetUserNameA(args, wide=True)

    def GetSystemInfo(self, args):
        """GetSystemInfo emulation - one x86 processor, 4 KiB pages"""
        lpSystemInfo = args[0]
        log.debug(f"GetSystemInfo(0x{lpSystemInfo:08x})")
        data = struct.pack('<HHIIIIIIIHH',
                           0,           # wProcessorArchitecture (INTEL)
                           0,           # wReserved
                           0x1000,      # dwPageSize
                           0x00010000,  # lpMinimumApplicationAddress
                           0x7FFEFFFF,  # lpMaximumApplicationAddress
                           1,           # dwActiveProcessorMask
                           1,           # dwNumberOfProcessors
                           586,         # dwProcessorType (PROCESSOR_INTEL_PENTIUM)
                           0x10000,     # dwAllocationGranularity
                           6,           # wProcessorLevel
                           0)           # wProcessorRevision
        try:
            self.emu.uc.mem_write(lpSystemInfo, data)
        except UcError:
            pass
        return 0

    def GlobalMemoryStatus(self, args):
        """GlobalMemoryStatus emulation - physical memory is the emulated heap"""
        lpBuffer = args[0]
        total = self.emu.HEAP_SIZE
        avail = max(0, self.emu.HEAP_BASE + total - self.emu.heap_current)
        load = 100 - avail * 100 // total if total else 0
        log.debug(f"GlobalMemoryStatus() -> {avail}/{total} bytes free")
        data = struct.pack('<8I', 32, load, total, avail, total, avail,
                           0x7FFE0000, 0x7FFE0000 - (total - avail))
        try:
            self.emu.uc.mem_write(lpBuffer, data)
        except UcError:
            pass
        return 0

    def QueryPerformanceFrequency(self, args):
        """QueryPerformanceFrequency emulation (the counter ticks in microseconds)"""
        lpFrequency = args[0]
        log.debug("QueryPerformanceFrequency() -> 1000000")
        if not lpFrequency:
            return 0
        self.emu.uc.mem_write(lpFrequency, struct.pack('<Q', 1000000))
        return 1

    def GetTickCount64(self, args):
        """GetTickCount64 emulation"""
        return QWordResult(int(time.time() * 1000))

    # ANSI code page -> OEM (console) code page of the same Windows locale
    OEM_CODEPAGES = {1250: 852, 1251: 866, 1252: 850, 1253: 737, 1254: 857,
                     1255: 862, 1256: 720, 1257: 775}

    @staticmethod
    def _ansi_codepage_number():
        """Windows number of ANSI_CODEPAGE (e.g. 1254 for cp1254, 65001 for UTF-8)"""
        if ANSI_CODEPAGE.replace('_', '-') == 'utf-8':
            return 65001
        match = re.fullmatch(r'cp(\d+)', ANSI_CODEPAGE)
        return int(match.group(1)) if match else 1252

    def GetACP(self, args):
        """GetACP emulation - the code page chosen with --codepage"""
        return self._ansi_codepage_number()

    def GetOEMCP(self, args):
        """GetOEMCP emulation"""
        return self.OEM_CODEPAGES.get(self._ansi_codepage_number(), 437)

    def GetUserDefaultLangID(self, args):
        """GetUserDefaultLangID emulation - English (United States)"""
        return 0x0409

    def InitCommonControls(self, args):
        """InitCommonControls emulation (comctl32 ordinal 17) - nothing to register"""
        return 0

    def SetConsoleTitleA(self, args, wide=False):
        """SetConsoleTitleA/W emulation - renames the GUI console window"""
        title = self._read_text(args[0], wide)
        log.debug(f"SetConsoleTitle(\"{title}\")")
        console = self.console
        if console is not None and self.gui:
            with self.gui.lock:
                if console.hwnd in self.gui.windows:
                    self.gui.windows[console.hwnd].title = title
        return 1

    def SetConsoleTitleW(self, args):
        return self.SetConsoleTitleA(args, wide=True)

    def ReadFile(self, args):
        """ReadFile emulation - reads from a real sandboxed file"""
        hFile = args[0]
        lpBuffer = args[1]
        nNumberOfBytesToRead = args[2]
        lpNumberOfBytesRead = args[3]

        log.debug(f"ReadFile(0x{hFile:x}, {nNumberOfBytesToRead} bytes)")

        data = b''
        info = self.handles.get(hFile)
        if info and info.get('fp'):
            try:
                data = info['fp'].read(nNumberOfBytesToRead)
            except OSError as e:
                log.error(f"ReadFile error: {e}")
                return 0

        if data:
            try:
                self.emu.uc.mem_write(lpBuffer, data)
            except Exception as e:
                log.error(f"ReadFile mem_write error: {e}")
                return 0

        if lpNumberOfBytesRead != 0:
            self.emu.uc.mem_write(lpNumberOfBytesRead, struct.pack('<I', len(data)))

        return 1
    
    def ReadConsoleA(self, args):
        """ReadConsoleA emulation - Read user input from console"""
        hConsoleInput = args[0]
        lpBuffer = args[1]
        nNumberOfCharsToRead = args[2]
        lpNumberOfCharsRead = args[3]
        # pInputControl = args[4]  # optional, usually NULL
        
        log.debug(f"ReadConsoleA(0x{hConsoleInput:x}, max {nNumberOfCharsToRead} chars)")
        
        if self.gui:
            if self.console is None:
                self._last_error = 6  # ERROR_INVALID_HANDLE: no console
                return 0
            user_input = self.console_read_line()
            if user_input is None:
                user_input = ""
            data = (user_input + "\r\n").encode(ANSI_CODEPAGE, errors='replace')
        else:
            try:
                line = sys.stdin.buffer.readline()
            except (OSError, ValueError):
                line = b""
            if line.endswith(b"\n") and not line.endswith(b"\r\n"):
                line = line[:-1] + b"\r\n"
            data = line

        # ANSI console reads count bytes, not Unicode characters
        data = data[:nNumberOfCharsToRead]
        if data:
            self.emu.uc.mem_write(lpBuffer, data)
        if lpNumberOfCharsRead != 0:
            self.emu.uc.mem_write(lpNumberOfCharsRead, struct.pack('<I', len(data)))
        log.debug(f"ReadConsoleA: {data!r} ({len(data)} bytes)")
        return 1

    def GetEnvironmentVariableA(self, args, wide=False):
        """GetEnvironmentVariableA/W emulation"""
        lpName = args[0]
        lpBuffer = args[1]
        nSize = args[2]
        
        name = self._read_text(lpName, wide)
        log.debug(f"GetEnvironmentVariable{'W' if wide else 'A'}(\"{name}\")")
        
        value = self.environment.get(name.upper())
        if value is None:
            self._last_error = 203  # ERROR_ENVVAR_NOT_FOUND
            return 0
        units = self._text_units(value, wide)
        if not lpBuffer or nSize <= len(units):
            return len(units) + 1  # required size including the terminator
        self._write_units(lpBuffer, units, wide)
        return len(units)

    def GetEnvironmentVariableW(self, args):
        return self.GetEnvironmentVariableA(args, wide=True)

    def SetEnvironmentVariableA(self, args, wide=False):
        """SetEnvironmentVariableA/W emulation (NULL value removes the variable)"""
        name = self._read_text(args[0], wide)
        value = self._read_text(args[1], wide) if args[1] else None
        log.debug(f"SetEnvironmentVariable{'W' if wide else 'A'}(\"{name}\", {value!r})")
        if not name or '=' in name:
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0
        if value is None:
            if self.environment.pop(name.upper(), None) is None:
                self._last_error = 203  # ERROR_ENVVAR_NOT_FOUND
                return 0
        else:
            self.environment[name.upper()] = value
        return 1

    def SetEnvironmentVariableW(self, args):
        return self.SetEnvironmentVariableA(args, wide=True)

    # ---------- INI files (GetPrivateProfileString / WritePrivateProfileString) ----------

    def _profile_path(self, filename):
        """Host path of an INI file; a bare name lives in the Windows directory"""
        if '\\' not in filename and '/' not in filename:
            filename = "C:\\Windows\\" + filename
        return self.resolve_c_drive_path(filename)

    @staticmethod
    def _ini_section_name(line):
        """Section name of a "[name]" line, else None"""
        line = line.strip()
        if line.startswith('[') and ']' in line:
            return line[1:line.index(']')].strip()
        return None

    @staticmethod
    def _ini_key_value(line):
        """(key, value) of a "key=value" line, else None"""
        if line.lstrip().startswith(';') or '=' not in line:
            return None
        key, _, value = line.partition('=')
        return key.strip(), value.strip()

    def _ini_read_lines(self, path):
        try:
            with open(path, 'rb') as fp:
                return fp.read().decode(ANSI_CODEPAGE, errors='replace').splitlines()
        except OSError:
            return None

    def _ini_section_range(self, lines, section):
        """(header index, end index) of a section (case-insensitive), or None"""
        start = None
        for i, line in enumerate(lines):
            name = self._ini_section_name(line)
            if name is None:
                continue
            if start is not None:
                return (start, i)
            if name.lower() == section.lower():
                start = i
        return None if start is None else (start, len(lines))

    def GetPrivateProfileStringA(self, args):
        """GetPrivateProfileStringA emulation (INI files inside c_drive/)"""
        lpAppName, lpKeyName, lpDefault = args[0], args[1], args[2]
        lpReturnedString, nSize, lpFileName = args[3], args[4], args[5]
        section = self.read_string(lpAppName) if lpAppName else None
        key = self.read_string(lpKeyName) if lpKeyName else None
        default = self.read_string(lpDefault).rstrip(' ') if lpDefault else ''
        filename = self.read_string(lpFileName)
        log.debug(f"GetPrivateProfileStringA({section!r}, {key!r}, {default!r}, \"{filename}\")")

        if not lpReturnedString or nSize == 0:
            return 0
        path = self._profile_path(filename)
        lines = (self._ini_read_lines(path) if path else None) or []

        if section is None or key is None:
            # Name lists: every name NUL-terminated, the list ends with an extra NUL
            if section is None:
                names = [n for n in map(self._ini_section_name, lines) if n is not None]
            else:
                bounds = self._ini_section_range(lines, section)
                names = []
                if bounds:
                    for line in lines[bounds[0] + 1:bounds[1]]:
                        pair = self._ini_key_value(line)
                        if pair:
                            names.append(pair[0])
            data = b''.join(n.encode(ANSI_CODEPAGE, errors='replace') + b'\x00' for n in names)
            if len(data) + 1 > nSize:
                # Truncated: the last name still ends with two NULs
                data = data[:max(0, nSize - 2)]
                self.emu.uc.mem_write(lpReturnedString, (data + b'\x00\x00')[:nSize])
                return len(data)
            self.emu.uc.mem_write(lpReturnedString, data + b'\x00')
            return len(data)

        value = None
        bounds = self._ini_section_range(lines, section)
        if bounds:
            for line in lines[bounds[0] + 1:bounds[1]]:
                pair = self._ini_key_value(line)
                if pair and pair[0].lower() == key.lower():
                    value = pair[1]
                    break
        if value is None:
            value = default
        elif len(value) >= 2 and value[0] == value[-1] and value[0] in '"\'':
            value = value[1:-1]

        data = value.encode(ANSI_CODEPAGE, errors='replace')[:nSize - 1]
        self.emu.uc.mem_write(lpReturnedString, data + b'\x00')
        return len(data)

    def WritePrivateProfileStringA(self, args):
        """WritePrivateProfileStringA emulation (NULL key deletes the section,
        NULL string deletes the key)"""
        lpAppName, lpKeyName, lpString, lpFileName = args[0], args[1], args[2], args[3]
        if not lpAppName:
            return 0  # Only flushes the (nonexistent) cache
        section = self.read_string(lpAppName)
        key = self.read_string(lpKeyName) if lpKeyName else None
        value = self.read_string(lpString) if lpString else None
        filename = self.read_string(lpFileName)
        log.debug(f"WritePrivateProfileStringA({section!r}, {key!r}, {value!r}, \"{filename}\")")

        path = self._profile_path(filename)
        if path is None:
            self._last_error = 5  # ERROR_ACCESS_DENIED
            return 0
        lines = self._ini_read_lines(path) or []
        bounds = self._ini_section_range(lines, section)

        if key is None:
            if bounds:
                del lines[bounds[0]:bounds[1]]
        elif bounds:
            index = None
            for i in range(bounds[0] + 1, bounds[1]):
                pair = self._ini_key_value(lines[i])
                if pair and pair[0].lower() == key.lower():
                    index = i
                    break
            if value is None:
                if index is not None:
                    del lines[index]
            elif index is not None:
                lines[index] = f"{key}={value}"
            else:
                # Append after the section's last non-blank line
                end = bounds[1]
                while end > bounds[0] + 1 and not lines[end - 1].strip():
                    end -= 1
                lines.insert(end, f"{key}={value}")
        elif value is not None:
            lines += [f"[{section}]", f"{key}={value}"]

        try:
            with open(path, 'wb') as fp:
                fp.write(''.join(line + '\r\n' for line in lines)
                         .encode(ANSI_CODEPAGE, errors='replace'))
        except OSError as e:
            log.error(f"WritePrivateProfileStringA(\"{filename}\") failed: {e}")
            self._last_error = 3  # ERROR_PATH_NOT_FOUND
            return 0
        return 1
    
    def ExpandEnvironmentStringsA(self, args):
        """ExpandEnvironmentStringsA emulation"""
        lpSrc = args[0]
        lpDst = args[1]
        nSize = args[2]
        
        src = self.read_string(lpSrc)
        log.debug(f"ExpandEnvironmentStringsA(\"{src[:32]}...\")")
        
        # Simple variable expansion
        result = src
        result = result.replace('%WINDIR%', 'C:\\Windows')
        result = result.replace('%SYSTEMROOT%', 'C:\\Windows')
        result = result.replace('%TEMP%', 'C:\\Windows\\Temp')
        result = result.replace('%TMP%', 'C:\\Windows\\Temp')
        
        if lpDst != 0 and len(result) < nSize:
            self.emu.uc.mem_write(lpDst, result.encode(ANSI_CODEPAGE, errors='replace') + b'\x00')
        
        return len(result) + 1
    
    # USER32.DLL APIs
    def _screen_size(self):
        """Size of the fake desktop (fixed 1920x1080 without the GUI)"""
        if self.gui:
            return self.gui.width, self.gui.height
        return 1920, 1080

    def GetSystemMetrics(self, args):
        """GetSystemMetrics emulation"""
        nIndex = args[0]
        width, height = self._screen_size()
        
        metrics = {
            0: width,  # SM_CXSCREEN
            1: height, # SM_CYSCREEN
            2: 20,     # SM_CXVSCROLL
            3: 20,     # SM_CYHSCROLL
            4: 25,     # SM_CYCAPTION
            5: 1,      # SM_CXBORDER
            6: 1,      # SM_CYBORDER
            16: width,  # SM_CXFULLSCREEN
            17: height - 30 - 25,  # SM_CYFULLSCREEN: minus taskbar and caption
            80: 1,     # SM_CMONITORS
        }
        
        result = metrics.get(nIndex, 0)
        log.debug(f"GetSystemMetrics({nIndex}) -> {result}")
        return result
    
    def MessageBoxA(self, args):
        """MessageBoxA emulation"""
        hWnd = args[0]
        lpText = args[1]
        lpCaption = args[2]
        uType = args[3]
        
        text = self.read_string(lpText) if lpText else ""
        caption = self.read_string(lpCaption) if lpCaption else ""
        
        log.info(f"{Fore.YELLOW}[MESSAGEBOX]{Style.RESET_ALL} {caption}: {text}")
        
        # Show MessageBox if GUI exists
        if self.gui and self.gui.running:
            return self.gui.show_messagebox(caption, text, uType)
        
        return 1  # IDOK
    
    def MessageBoxW(self, args):
        """MessageBoxW emulation (Unicode)"""
        hWnd = args[0]
        lpText = args[1]
        lpCaption = args[2]
        uType = args[3]
        
        text = self.read_wide_string(lpText) if lpText else ""
        caption = self.read_wide_string(lpCaption) if lpCaption else ""
        
        log.info(f"{Fore.YELLOW}[MESSAGEBOX]{Style.RESET_ALL} {caption}: {text}")
        
        if self.gui and self.gui.running:
            return self.gui.show_messagebox(caption, text, uType)
        
        return 1  # IDOK
    
    def RegisterClassA(self, args, wide=False):
        """RegisterClassA/W emulation"""
        lpWndClass = args[0]
        
        # Read WNDCLASS structure
        try:
            wndclass_data = self.emu.uc.mem_read(lpWndClass, 40)
            style = struct.unpack("<I", wndclass_data[0:4])[0]
            lpfnWndProc = struct.unpack("<I", wndclass_data[4:8])[0]
            hInstance = struct.unpack("<I", wndclass_data[16:20])[0]
            hbrBackground = struct.unpack("<I", wndclass_data[28:32])[0]
            lpszClassName = struct.unpack("<I", wndclass_data[36:40])[0]
            
            class_name = self._read_text(lpszClassName, wide)
            
            atom = self.next_atom
            self.next_atom += 1
            
            self.registered_classes[class_name] = {
                'atom': atom,
                'style': style,
                'wndproc': lpfnWndProc,
                'hInstance': hInstance,
                'background': hbrBackground,
            }
            self.atoms[atom] = class_name
            
            log.debug(f"RegisterClassA('{class_name}') -> 0x{atom:x}")
            return atom
        except UcError:
            return 0

    def RegisterClassW(self, args):
        return self.RegisterClassA(args, wide=True)
    
    def RegisterClassExA(self, args, wide=False):
        """RegisterClassExA/W emulation"""
        lpwcx = args[0]
        
        try:
            # Read WNDCLASSEX structure
            wcex_data = self.emu.uc.mem_read(lpwcx, 48)
            cbSize = struct.unpack("<I", wcex_data[0:4])[0]
            style = struct.unpack("<I", wcex_data[4:8])[0]
            lpfnWndProc = struct.unpack("<I", wcex_data[8:12])[0]
            hInstance = struct.unpack("<I", wcex_data[20:24])[0]
            hbrBackground = struct.unpack("<I", wcex_data[32:36])[0]
            lpszClassName = struct.unpack("<I", wcex_data[40:44])[0]
            
            class_name = self._read_text(lpszClassName, wide)
            
            atom = self.next_atom
            self.next_atom += 1
            
            self.registered_classes[class_name] = {
                'atom': atom,
                'style': style,
                'wndproc': lpfnWndProc,
                'hInstance': hInstance,
                'background': hbrBackground,
            }
            self.atoms[atom] = class_name
            
            log.debug(f"RegisterClassExA('{class_name}') -> 0x{atom:x}")
            return atom
        except UcError:
            return 0

    def RegisterClassExW(self, args):
        return self.RegisterClassExA(args, wide=True)
    
    def CreateWindowExA(self, args, wide=False):
        """CreateWindowExA/W emulation"""
        dwExStyle = args[0]
        lpClassName = args[1]
        lpWindowName = args[2]
        dwStyle = args[3]
        CW_USEDEFAULT = -0x80000000
        x, y, nWidth, nHeight = self._read_signed_args(args, 4, 4)
        x = x if x != CW_USEDEFAULT else 100
        y = y if y != CW_USEDEFAULT else 100
        nWidth = nWidth if nWidth != CW_USEDEFAULT else 400
        nHeight = nHeight if nHeight != CW_USEDEFAULT else 300
        hWndParent = args[8]
        hMenu = args[9]
        hInstance = args[10]
        lpParam = args[11]
        
        # Class name can be atom or string
        if lpClassName < 0x10000:
            class_name = self.atoms.get(lpClassName, f"ATOM_{lpClassName}")
        else:
            class_name = self._read_text(lpClassName, wide)
        
        window_name = self._read_text(lpWindowName, wide)
        
        log.info(f"{Fore.GREEN}CreateWindowExA{Style.RESET_ALL}('{class_name}', '{window_name}', "
                f"pos=({x},{y}), size=({nWidth},{nHeight}))")
        
        # Create real window if GUI exists
        if self.gui and self.gui.running:
            # Create control for top-level controls
            if class_name.upper() == "MSCTLS_STATUSBAR32" and hWndParent in self.gui.windows:
                hwnd = self._create_status_bar(hWndParent, window_name, dwStyle, hMenu)
            elif class_name.upper() in ["BUTTON", "EDIT", "STATIC", "LISTBOX", "COMBOBOX",
                                        "SCROLLBAR"]:
                # BUTTON with a checkbox or radio button style is drawn and
                # clicked as a checkbox
                control_class = class_name
                if (class_name.upper() == "BUTTON" and
                        (dwStyle & 0xF) in self.CHECK_BUTTON_STYLES):
                    control_class = "CHECKBOX"
                # For child controls hMenu carries the control ID (used by WM_COMMAND)
                hwnd = self.gui.create_control(hWndParent, control_class, window_name,
                                               x, y, nWidth, nHeight, dwStyle,
                                               control_id=hMenu)
                self.dirty_controls[hwnd] = True
            else:
                parent = hWndParent if dwStyle & self.WS_CHILD else 0
                hwnd = self.gui.create_window(window_name, x, y, nWidth, nHeight, dwStyle,
                                              owner=self, parent=parent)

            # Save class_name to window (for finding WndProc)
            if hwnd in self.gui.windows:
                self.gui.windows[hwnd].class_name = class_name
                # The client area is erased with the class background brush
                wndclass = self.registered_classes.get(class_name)
                if wndclass and wndclass.get('background'):
                    color = self._brush_color(wndclass['background'])
                    if color is not None:
                        self.gui.windows[hwnd].bg_color = color

            # Real Windows sends WM_CREATE to the WndProc synchronously, before
            # CreateWindowEx returns. Apps often create their child controls here.
            # Controls have no app WndProc, so this only fires for app windows.
            wndproc = self._find_wndproc_for_hwnd(hwnd)
            if wndproc:
                cs_addr = self._build_createstruct(
                    lpParam, hInstance, hMenu, hWndParent,
                    nHeight, nWidth, y, x, dwStyle, lpWindowName, lpClassName, dwExStyle)
                self.emu.call_wndproc(wndproc, hwnd, self.WM_CREATE, 0, cs_addr)
                if dwStyle & (self.WS_CHILD | self.WS_POPUP):
                    self._send_size(hwnd)  # Overlapped windows get it from ShowWindow
            # WS_VISIBLE windows are shown without an explicit ShowWindow call
            win = self.gui.windows.get(hwnd)
            if (dwStyle & self.WS_VISIBLE and isinstance(win, FakeWindow)
                    and not win.visible):
                self.gui.show_window(hwnd, True)
                if win.size_state is None:
                    self._send_size(hwnd)
        else:
            hwnd = self.get_next_handle()

        return hwnd

    def CreateWindowExW(self, args):
        return self.CreateWindowExA(args, wide=True)

    WS_CHILD = 0x40000000
    WS_POPUP = 0x80000000
    WS_VISIBLE = 0x10000000
    WM_SIZE = 0x0005
    WM_ACTIVATE = 0x0006

    def _send_size(self, hwnd):
        """Send WM_SIZE now if the window's client size or state changed
        (window creation, MoveWindow, SetWindowPos)"""
        if not self.gui or hwnd not in self.gui.windows:
            return
        win = self.gui.windows[hwnd]
        state = self.gui.size_state(win)
        if state == win.size_state:
            return
        win.size_state = state
        wndproc = self._find_wndproc_for_hwnd(hwnd)
        if wndproc:
            kind, width, height = state
            self.emu.call_wndproc(wndproc, hwnd, self.WM_SIZE, kind,
                                  ((height & 0xFFFF) << 16) | (width & 0xFFFF))

    def _build_createstruct(self, lpCreateParams, hInstance, hMenu, hwndParent,
                            cy, cx, y, x, style, lpszName, lpszClass, dwExStyle):
        """Allocate and fill a CREATESTRUCTA, return its address (for WM_CREATE)."""
        addr = self.emu.heap_alloc(48)
        data = struct.pack("<IIIIiiiiIIII",
                           lpCreateParams & 0xFFFFFFFF,
                           hInstance & 0xFFFFFFFF,
                           hMenu & 0xFFFFFFFF,
                           hwndParent & 0xFFFFFFFF,
                           cy, cx, y, x,
                           style & 0xFFFFFFFF,
                           lpszName & 0xFFFFFFFF,
                           lpszClass & 0xFFFFFFFF,
                           dwExStyle & 0xFFFFFFFF)
        self.emu.uc.mem_write(addr, data)
        return addr
    
    def ShowWindow(self, args):
        """ShowWindow emulation"""
        hWnd = args[0]
        nCmdShow = args[1]
        
        show_names = {0: "SW_HIDE", 1: "SW_SHOWNORMAL", 2: "SW_SHOWMINIMIZED",
                     3: "SW_SHOWMAXIMIZED", 4: "SW_SHOWNOACTIVATE", 5: "SW_SHOW"}
        show_name = show_names.get(nCmdShow, f"SW_{nCmdShow}")
        
        log.debug(f"ShowWindow(0x{hWnd:x}, {show_name})")
        
        if self.gui and self.gui.running:
            show = nCmdShow in [1, 3, 5, 6, 7, 8, 9, 10]
            self.gui.show_window(hWnd, show)
            win = self.gui.windows.get(hWnd)
            if win is not None and win.parent is None and nCmdShow in (3, 9):
                with self.gui.lock:
                    if nCmdShow == 3 and not win.maximized:  # SW_SHOWMAXIMIZED
                        win.minimized = False
                        win.maximize(self.gui.width, self.gui.height, 30)
                    elif nCmdShow == 9:  # SW_RESTORE
                        win.restore()
                self._send_size(hWnd)
            elif show and win is not None and win.size_state is None:
                self._send_size(hWnd)
        
        return 1
    
    def UpdateWindow(self, args):
        """UpdateWindow emulation"""
        hWnd = args[0]
        log.debug(f"UpdateWindow(0x{hWnd:x})")
        return 1
    
    def DestroyWindow(self, args):
        """DestroyWindow emulation"""
        hWnd = args[0]
        log.debug(f"DestroyWindow(0x{hWnd:x})")

        if self.gui and hWnd in self.gui.controls:
            self.gui.destroy_control(hWnd)
        elif self.gui and hWnd in self.gui.windows:
            self.gui._close_window(hWnd, notify_app=False)
            # Deliver WM_DESTROY via the queue: a synchronous call here would
            # nest emu_start inside an already-running callback
            if self._find_wndproc_for_hwnd(hWnd):
                self.post_window_message(hWnd, self.WM_DESTROY, 0, 0)

        return 1
    
    def SetWindowTextA(self, args, wide=False):
        """SetWindowTextA/W emulation"""
        hWnd = args[0]
        lpString = args[1]
        
        text = self._read_text(lpString, wide)
        log.debug(f"SetWindowTextA(0x{hWnd:x}, '{text}')")
        
        if self.gui:
            self.gui.set_window_text(hWnd, text)
        
        return 1

    def SetWindowTextW(self, args):
        return self.SetWindowTextA(args, wide=True)
    
    def GetWindowTextA(self, args, wide=False):
        """GetWindowTextA/W emulation"""
        hWnd = args[0]
        lpString = args[1]
        nMaxCount = args[2]
        
        text = ""
        if self.gui:
            text = self.gui.get_window_text(hWnd)

        # Always null-terminate the buffer (like real Windows), even when
        # the text is empty - the caller's buffer is uninitialized memory
        if lpString and nMaxCount > 0:
            if wide:
                text_bytes = text.encode('utf-16-le')[:(nMaxCount - 1) * 2]
                self.emu.uc.mem_write(lpString, text_bytes + b'\x00\x00')
                copied = len(text_bytes) // 2
            else:
                text_bytes = text.encode(ANSI_CODEPAGE, errors='replace')[:nMaxCount - 1]
                self.emu.uc.mem_write(lpString, text_bytes + b'\x00')
                copied = len(text_bytes)
        else:
            copied = 0

        log.debug(f"GetWindowTextA(0x{hWnd:x}) -> '{text}'")
        return copied

    def GetWindowTextW(self, args):
        return self.GetWindowTextA(args, wide=True)
    
    def GetClientRect(self, args):
        """GetClientRect emulation"""
        hWnd = args[0]
        lpRect = args[1]
        
        # Default rectangle
        left, top, right, bottom = 0, 0, 400, 300

        if self.gui and hWnd in self.gui.windows:
            win = self.gui.windows[hWnd]
            right, bottom = self.gui.client_size(win)
        elif self.gui and hWnd in self.gui.controls:
            control = self.gui.controls[hWnd]
            if control.class_name == 'STATUSBAR':
                self.gui.layout_statusbar(control)
            right, bottom = control.width, control.height
        
        if lpRect:
            rect_data = struct.pack("<iiii", left, top, right, bottom)
            self.emu.uc.mem_write(lpRect, rect_data)
        
        log.debug(f"GetClientRect(0x{hWnd:x}) -> ({left}, {top}, {right}, {bottom})")
        return 1
    
    def GetWindowRect(self, args):
        """GetWindowRect emulation"""
        hWnd = args[0]
        lpRect = args[1]
        
        left, top, right, bottom = 100, 100, 500, 400
        
        if self.gui and hWnd in self.gui.windows:
            win = self.gui.windows[hWnd]
            left, top = win.x, win.y
            right = win.x + win.width
            bottom = win.y + win.height
        elif self.gui and hWnd in self.gui.controls:
            control = self.gui.controls[hWnd]
            parent = self.gui.windows.get(control.parent_hwnd)
            if control.class_name == 'STATUSBAR':
                self.gui.layout_statusbar(control)
            ox, oy = self.gui.client_origin(parent) if parent else (0, 0)
            left, top = ox + control.x, oy + control.y
            right, bottom = left + control.width, top + control.height
        
        if lpRect:
            rect_data = struct.pack("<iiii", left, top, right, bottom)
            self.emu.uc.mem_write(lpRect, rect_data)
        
        log.debug(f"GetWindowRect(0x{hWnd:x}) -> ({left}, {top}, {right}, {bottom})")
        return 1

    # ---------- RECT utility APIs (user32) ----------

    def _read_rect(self, address):
        """Read a RECT from memory -> (left, top, right, bottom) or None"""
        try:
            return struct.unpack("<iiii", self.emu.uc.mem_read(address, 16))
        except UcError:
            return None

    def _write_rect(self, address, left, top, right, bottom):
        """Write a RECT to memory"""
        try:
            self.emu.uc.mem_write(address, struct.pack("<iiii", left, top,
                                                       right, bottom))
            return True
        except UcError:
            return False

    def SetRect(self, args):
        """SetRect emulation"""
        lprc = args[0]
        left, top, right, bottom = self._read_signed_args(args, 1, 4)
        if not lprc:
            return 0
        return 1 if self._write_rect(lprc, left, top, right, bottom) else 0

    def SetRectEmpty(self, args):
        """SetRectEmpty emulation"""
        lprc = args[0]
        if not lprc:
            return 0
        return 1 if self._write_rect(lprc, 0, 0, 0, 0) else 0

    def CopyRect(self, args):
        """CopyRect emulation"""
        lprcDst, lprcSrc = args[0], args[1]
        rect = self._read_rect(lprcSrc) if lprcSrc else None
        if not lprcDst or rect is None:
            return 0
        return 1 if self._write_rect(lprcDst, *rect) else 0

    def OffsetRect(self, args):
        """OffsetRect emulation"""
        lprc = args[0]
        dx, dy = self._read_signed_args(args, 1, 2)
        rect = self._read_rect(lprc) if lprc else None
        if rect is None:
            return 0
        left, top, right, bottom = rect
        return 1 if self._write_rect(lprc, left + dx, top + dy,
                                     right + dx, bottom + dy) else 0

    def InflateRect(self, args):
        """InflateRect emulation"""
        lprc = args[0]
        dx, dy = self._read_signed_args(args, 1, 2)
        rect = self._read_rect(lprc) if lprc else None
        if rect is None:
            return 0
        left, top, right, bottom = rect
        return 1 if self._write_rect(lprc, left - dx, top - dy,
                                     right + dx, bottom + dy) else 0

    def PtInRect(self, args):
        """PtInRect emulation (POINT is passed by value: two stack dwords)"""
        lprc = args[0]
        x, y = self._read_signed_args(args, 1, 2)
        rect = self._read_rect(lprc) if lprc else None
        if rect is None:
            return 0
        left, top, right, bottom = rect
        return 1 if (left <= x < right and top <= y < bottom) else 0

    def EqualRect(self, args):
        """EqualRect emulation"""
        r1 = self._read_rect(args[0]) if args[0] else None
        r2 = self._read_rect(args[1]) if args[1] else None
        if r1 is None or r2 is None:
            return 0
        return 1 if r1 == r2 else 0

    def IsRectEmpty(self, args):
        """IsRectEmpty emulation"""
        rect = self._read_rect(args[0]) if args[0] else None
        if rect is None:
            return 1
        left, top, right, bottom = rect
        return 1 if (right <= left or bottom <= top) else 0

    def IntersectRect(self, args):
        """IntersectRect emulation"""
        lprcDst = args[0]
        r1 = self._read_rect(args[1]) if args[1] else None
        r2 = self._read_rect(args[2]) if args[2] else None
        if not lprcDst or r1 is None or r2 is None:
            return 0
        left, top = max(r1[0], r2[0]), max(r1[1], r2[1])
        right, bottom = min(r1[2], r2[2]), min(r1[3], r2[3])
        if right <= left or bottom <= top:
            self._write_rect(lprcDst, 0, 0, 0, 0)
            return 0
        self._write_rect(lprcDst, left, top, right, bottom)
        return 1

    def UnionRect(self, args):
        """UnionRect emulation"""
        lprcDst = args[0]
        r1 = self._read_rect(args[1]) if args[1] else None
        r2 = self._read_rect(args[2]) if args[2] else None
        if not lprcDst or r1 is None or r2 is None:
            return 0
        empty1 = r1[2] <= r1[0] or r1[3] <= r1[1]
        empty2 = r2[2] <= r2[0] or r2[3] <= r2[1]
        if empty1 and empty2:
            self._write_rect(lprcDst, 0, 0, 0, 0)
            return 0
        if empty1:
            self._write_rect(lprcDst, *r2)
        elif empty2:
            self._write_rect(lprcDst, *r1)
        else:
            self._write_rect(lprcDst, min(r1[0], r2[0]), min(r1[1], r2[1]),
                             max(r1[2], r2[2]), max(r1[3], r2[3]))
        return 1

    def MoveWindow(self, args):
        """MoveWindow emulation"""
        hWnd = args[0]
        X = args[1]
        Y = args[2]
        nWidth = args[3]
        nHeight = args[4]
        bRepaint = args[5]
        
        log.debug(f"MoveWindow(0x{hWnd:x}, {X}, {Y}, {nWidth}, {nHeight})")
        
        if self.gui and hWnd in self.gui.windows:
            win = self.gui.windows[hWnd]
            win.x, win.y = X, Y
            win.width, win.height = nWidth, nHeight
            self._send_size(hWnd)
        elif self.gui and hWnd in self.gui.controls:
            control = self.gui.controls[hWnd]
            (control.x, control.y, control.width,
             control.height) = self._read_signed_args(args, 1, 4)
        
        return 1
    
    def SetWindowPos(self, args):
        """SetWindowPos emulation"""
        hWnd = args[0]
        hWndInsertAfter = args[1]
        X = args[2]
        Y = args[3]
        cx = args[4]
        cy = args[5]
        uFlags = args[6]
        
        log.debug(f"SetWindowPos(0x{hWnd:x}, {X}, {Y}, {cx}, {cy})")
        
        if self.gui and hWnd in self.gui.windows:
            win = self.gui.windows[hWnd]
            X, Y, cx, cy = self._read_signed_args(args, 2, 4)
            with self.gui.lock:
                if not (uFlags & 0x0002):  # SWP_NOMOVE
                    win.x, win.y = X, Y
                if not (uFlags & 0x0001):  # SWP_NOSIZE
                    win.width, win.height = cx, cy
                if (not uFlags & 0x0004 and win.parent is None  # SWP_NOZORDER
                        and hWnd in self.gui.z_order):
                    after = hWndInsertAfter if hWndInsertAfter < 0x80000000 else hWndInsertAfter - 0x100000000
                    if after in (0, -1):  # HWND_TOP, HWND_TOPMOST
                        self.gui.z_order.remove(hWnd)
                        self.gui.z_order.append(hWnd)
                    elif after == 1:  # HWND_BOTTOM
                        self.gui.z_order.remove(hWnd)
                        self.gui.z_order.insert(0, hWnd)
                if uFlags & 0x0040:  # SWP_SHOWWINDOW
                    self.gui.show_window(hWnd, True)
                elif uFlags & 0x0080:  # SWP_HIDEWINDOW
                    self.gui.show_window(hWnd, False)
            self._send_size(hWnd)
        elif self.gui and hWnd in self.gui.controls:
            control = self.gui.controls[hWnd]
            X, Y, cx, cy = self._read_signed_args(args, 2, 4)
            if not (uFlags & 0x0002):  # SWP_NOMOVE
                control.x, control.y = X, Y
            if not (uFlags & 0x0001):  # SWP_NOSIZE
                control.width, control.height = cx, cy
            if uFlags & 0x0040:  # SWP_SHOWWINDOW
                control.visible = True
            elif uFlags & 0x0080:  # SWP_HIDEWINDOW
                control.visible = False
        
        return 1
    
    def EnableWindow(self, args):
        """EnableWindow emulation"""
        hWnd = args[0]
        bEnable = args[1]
        log.debug(f"EnableWindow(0x{hWnd:x}, {bEnable})")
        
        if self.gui and hWnd in self.gui.windows:
            self.gui.windows[hWnd].enabled = bool(bEnable)
        elif self.gui and hWnd in self.gui.controls:
            self.gui.controls[hWnd].enabled = bool(bEnable)
        
        return 1
    
    def GetDlgItem(self, args):
        """GetDlgItem emulation"""
        hDlg = args[0]
        nIDDlgItem = args[1]
        log.debug(f"GetDlgItem(0x{hDlg:x}, {nIDDlgItem})")

        # Find the child control with this control id
        if self.gui and hDlg in self.gui.windows:
            for control in self.gui.windows[hDlg].controls:
                if control.control_id == nIDDlgItem:
                    return control.hwnd

        # Fallback: return dialog item ID as handle
        return 0x20000 + nIDDlgItem

    def GetDlgItemTextA(self, args):
        """GetDlgItemTextA emulation"""
        hDlg = args[0]
        nIDDlgItem = args[1]
        lpString = args[2]
        cchMax = args[3]
        hwnd = self.GetDlgItem([hDlg, nIDDlgItem])
        return self.GetWindowTextA([hwnd, lpString, cchMax])

    def SetDlgItemTextA(self, args):
        """SetDlgItemTextA emulation"""
        hDlg = args[0]
        nIDDlgItem = args[1]
        lpString = args[2]
        hwnd = self.GetDlgItem([hDlg, nIDDlgItem])
        return self.SetWindowTextA([hwnd, lpString])

    def GetDlgItemInt(self, args):
        """GetDlgItemInt emulation - read a control's text and parse an integer.

        Signature: UINT GetDlgItemInt(hDlg, nIDDlgItem, lpTranslated, bSigned)
        """
        hDlg = args[0]
        nIDDlgItem = args[1]
        lpTranslated = args[2]
        bSigned = args[3]

        text = ""
        hwnd = self.GetDlgItem([hDlg, nIDDlgItem])
        if self.gui:
            text = self.gui.get_window_text(hwnd)
        text = text.strip()

        # Parse the leading integer, exactly like the Win32 implementation
        sign = 1
        idx = 0
        if bSigned and idx < len(text) and text[idx] in '+-':
            if text[idx] == '-':
                sign = -1
            idx += 1
        elif not bSigned and idx < len(text) and text[idx] == '+':
            idx += 1
        digits = ''
        while idx < len(text) and text[idx].isdigit():
            digits += text[idx]
            idx += 1

        success = 1 if digits else 0
        value = (sign * int(digits)) if digits else 0

        if bSigned:
            # Clamp to INT range
            if value > 0x7FFFFFFF or value < -0x80000000:
                success = 0
                value = 0
        else:
            if value > 0xFFFFFFFF:
                success = 0
                value = 0

        if lpTranslated:
            try:
                self.emu.uc.mem_write(lpTranslated, struct.pack('<I', success))
            except Exception:
                pass

        log.debug(f"GetDlgItemInt(0x{hDlg:x}, {nIDDlgItem}) -> {value} (ok={success})")
        return value & 0xFFFFFFFF

    def SetDlgItemInt(self, args):
        """SetDlgItemInt emulation - set a control's text from an integer.

        Signature: BOOL SetDlgItemInt(hDlg, nIDDlgItem, uValue, bSigned)
        """
        hDlg = args[0]
        nIDDlgItem = args[1]
        uValue = args[2]
        bSigned = args[3]

        if bSigned and uValue >= 0x80000000:
            value = uValue - 0x100000000
        else:
            value = uValue
        text = str(value)

        hwnd = self.GetDlgItem([hDlg, nIDDlgItem])
        log.debug(f"SetDlgItemInt(0x{hDlg:x}, {nIDDlgItem}, {text})")
        if self.gui:
            self.gui.set_window_text(hwnd, text)
        return 1

    def GetDlgCtrlID(self, args):
        """GetDlgCtrlID emulation - return a control's ID"""
        hwndCtl = args[0]
        if self.gui and hwndCtl in self.gui.controls:
            return self.gui.controls[hwndCtl].control_id
        return 0

    def _window_long(self, hWnd, nIndex, new_value=None, set_value=False):
        """Shared GetWindowLong/SetWindowLong backend.

        Handles the common negative GWL_* indices against real window state
        and keeps every other index (including positive extra-bytes offsets)
        in a per-handle dictionary.
        """
        GWL_WNDPROC = -4
        GWL_STYLE = -16
        GWL_EXSTYLE = -20
        GWL_USERDATA = -21   # GWLP_USERDATA on 32-bit

        win = self.gui.windows.get(hWnd) if self.gui else None
        store = self.window_longs.setdefault(hWnd, {})

        if nIndex == GWL_WNDPROC:
            old = win.wndproc if win else store.get(nIndex, 0)
            if set_value:
                if win:
                    win.wndproc = new_value
                store[nIndex] = new_value
            return old & 0xFFFFFFFF
        if nIndex == GWL_STYLE:
            if win is None:
                old = store.get(nIndex, 0)
            else:
                # WS_MINIMIZE / WS_MAXIMIZE reflect the window state
                old = (win.style | (0x20000000 if win.minimized else 0)
                       | (0x01000000 if win.maximized else 0))
            if set_value:
                if win:
                    win.style = new_value
                    # Dropping WS_MINIMIZE / WS_MAXIMIZE leaves that state
                    if not new_value & 0x20000000:
                        win.minimized = False
                    if not new_value & 0x01000000:
                        win.maximized = False
                store[nIndex] = new_value
            return old & 0xFFFFFFFF
        if nIndex in (GWL_EXSTYLE, GWL_USERDATA):
            old = store.get(nIndex, 0)
            if set_value:
                store[nIndex] = new_value
            return old & 0xFFFFFFFF

        # Generic slot (extra window bytes, etc.)
        old = store.get(nIndex, 0)
        if set_value:
            store[nIndex] = new_value
        return old & 0xFFFFFFFF

    def GetWindowLongA(self, args):
        """GetWindowLongA emulation"""
        hWnd = args[0]
        nIndex = args[1] if args[1] < 0x80000000 else args[1] - 0x100000000
        value = self._window_long(hWnd, nIndex)
        log.debug(f"GetWindowLongA(0x{hWnd:x}, {nIndex}) -> 0x{value:08x}")
        return value

    def SetWindowLongA(self, args):
        """SetWindowLongA emulation - returns the previous value"""
        hWnd = args[0]
        nIndex = args[1] if args[1] < 0x80000000 else args[1] - 0x100000000
        dwNewLong = args[2]
        old = self._window_long(hWnd, nIndex, dwNewLong, set_value=True)
        log.debug(f"SetWindowLongA(0x{hWnd:x}, {nIndex}, 0x{dwNewLong:08x}) -> 0x{old:08x}")
        return old

    # Wide variants share the same backend
    def GetWindowLongW(self, args):
        return self.GetWindowLongA(args)

    def SetWindowLongW(self, args):
        return self.SetWindowLongA(args)

    def CheckDlgButton(self, args):
        """CheckDlgButton emulation - set a checkbox's state by control id"""
        hDlg = args[0]
        nIDButton = args[1]
        uCheck = args[2]
        hwnd = self.GetDlgItem([hDlg, nIDButton])
        if self.gui and hwnd in self.gui.controls:
            self.gui.controls[hwnd].checked = bool(uCheck)
            return 1
        return 0

    def IsDlgButtonChecked(self, args):
        """IsDlgButtonChecked emulation"""
        hDlg = args[0]
        nIDButton = args[1]
        hwnd = self.GetDlgItem([hDlg, nIDButton])
        if self.gui and hwnd in self.gui.controls:
            return 1 if self.gui.controls[hwnd].checked else 0
        return 0

    def SetFocus(self, args):
        """SetFocus emulation - give keyboard focus to a control"""
        hWnd = args[0]
        log.debug(f"SetFocus(0x{hWnd:x})")
        prev = 0
        if self.gui:
            prev = self.gui.focused_control or 0
            if hWnd in self.gui.controls:
                self.gui.focused_control = hWnd
            else:
                self.gui.focused_control = None
        return prev

    def GetFocus(self, args):
        """GetFocus emulation"""
        return (self.gui.focused_control or 0) if self.gui else 0

    def GetAsyncKeyState(self, args):
        """GetAsyncKeyState emulation - poll key state (game loops)"""
        vKey = args[0]
        if self.gui and self.gui.key_states.get(vKey):
            return 0x8000  # Key is currently down (bit 15)
        return 0

    def GetKeyState(self, args):
        """GetKeyState emulation (same as GetAsyncKeyState in the emulator)"""
        return self.GetAsyncKeyState(args)

    def GetCursorPos(self, args):
        """GetCursorPos emulation - cursor position in fake-desktop coordinates"""
        lpPoint = args[0]
        x, y = self.gui.mouse_pos if self.gui else (0, 0)
        if lpPoint:
            try:
                self.emu.uc.mem_write(lpPoint, struct.pack("<ii", x, y))
            except UcError:
                return 0
        log.debug(f"GetCursorPos() -> ({x}, {y})")
        return 1

    def SetCursorPos(self, args):
        """SetCursorPos emulation (accepted but not applied to the real mouse)"""
        x, y = self._read_signed_args(args, 0, 2)
        log.debug(f"SetCursorPos({x}, {y})")
        return 1

    def ScreenToClient(self, args):
        """ScreenToClient emulation"""
        hWnd = args[0]
        lpPoint = args[1]
        if not lpPoint:
            return 0
        try:
            x, y = struct.unpack("<ii", self.emu.uc.mem_read(lpPoint, 8))
        except UcError:
            return 0
        if self.gui and hWnd in self.gui.windows:
            ox, oy = self.gui.client_origin(self.gui.windows[hWnd])
            x, y = x - ox, y - oy
        try:
            self.emu.uc.mem_write(lpPoint, struct.pack("<ii", x, y))
        except UcError:
            return 0
        return 1

    def ClientToScreen(self, args):
        """ClientToScreen emulation"""
        hWnd = args[0]
        lpPoint = args[1]
        if not lpPoint:
            return 0
        try:
            x, y = struct.unpack("<ii", self.emu.uc.mem_read(lpPoint, 8))
        except UcError:
            return 0
        if self.gui and hWnd in self.gui.windows:
            ox, oy = self.gui.client_origin(self.gui.windows[hWnd])
            x, y = x + ox, y + oy
        try:
            self.emu.uc.mem_write(lpPoint, struct.pack("<ii", x, y))
        except UcError:
            return 0
        return 1

    def SetCapture(self, args):
        """SetCapture emulation - route mouse input to one window"""
        hWnd = args[0]
        prev = self.capture_hwnd
        self.capture_hwnd = hWnd
        log.debug(f"SetCapture(0x{hWnd:x})")
        return prev

    def ReleaseCapture(self, args):
        """ReleaseCapture emulation"""
        log.debug("ReleaseCapture()")
        self.capture_hwnd = 0
        return 1

    def GetCapture(self, args):
        """GetCapture emulation"""
        return self.capture_hwnd

    def GetParent(self, args):
        """GetParent emulation"""
        hWnd = args[0]
        if self.gui and hWnd in self.gui.controls:
            return self.gui.controls[hWnd].parent_hwnd or 0
        return 0

    def IsWindow(self, args):
        """IsWindow emulation"""
        hWnd = args[0]
        if self.gui and (hWnd in self.gui.windows or hWnd in self.gui.controls):
            return 1
        return 0

    def IsWindowVisible(self, args):
        """IsWindowVisible emulation"""
        hWnd = args[0]
        if self.gui:
            if hWnd in self.gui.windows:
                win = self.gui.windows[hWnd]
                return 1 if (win.visible and not win.minimized) else 0
            if hWnd in self.gui.controls:
                return 1 if self.gui.controls[hWnd].visible else 0
        return 0

    def IsWindowEnabled(self, args):
        """IsWindowEnabled emulation"""
        hWnd = args[0]
        if self.gui:
            if hWnd in self.gui.windows:
                return 1 if self.gui.windows[hWnd].enabled else 0
            if hWnd in self.gui.controls:
                return 1 if self.gui.controls[hWnd].enabled else 0
        return 0

    # MessageBeep/PlaySound system sounds as (frequency Hz, duration ms)
    SYSTEM_SOUND_TONES = {
        0xFFFFFFFF: (750, 150),   # simple beep (PC speaker)
        0x00: (800, 150),         # MB_OK / SystemDefault
        0x10: (400, 300),         # MB_ICONHAND / SystemHand
        0x20: (600, 150),         # MB_ICONQUESTION / SystemQuestion
        0x30: (900, 200),         # MB_ICONEXCLAMATION / SystemExclamation
        0x40: (1000, 150),        # MB_ICONASTERISK / SystemAsterisk
    }

    def MessageBeep(self, args):
        """MessageBeep emulation - plays a system tone asynchronously"""
        uType = args[0]
        log.debug(f"MessageBeep(0x{uType:x})")
        key = uType if uType == 0xFFFFFFFF else uType & 0xF0
        SoundPlayer.tone(*self.SYSTEM_SOUND_TONES.get(key, self.SYSTEM_SOUND_TONES[0]))
        return 1

    # Classic Windows colors for GetSysColor, as (r, g, b)
    SYS_COLORS = {
        0: (212, 208, 200),   # COLOR_SCROLLBAR
        1: (58, 110, 165),    # COLOR_BACKGROUND (desktop)
        2: (0, 0, 128),       # COLOR_ACTIVECAPTION
        3: (128, 128, 128),   # COLOR_INACTIVECAPTION
        4: (212, 208, 200),   # COLOR_MENU
        5: (255, 255, 255),   # COLOR_WINDOW
        6: (0, 0, 0),         # COLOR_WINDOWFRAME
        7: (0, 0, 0),         # COLOR_MENUTEXT
        8: (0, 0, 0),         # COLOR_WINDOWTEXT
        9: (255, 255, 255),   # COLOR_CAPTIONTEXT
        10: (212, 208, 200),  # COLOR_ACTIVEBORDER
        11: (212, 208, 200),  # COLOR_INACTIVEBORDER
        12: (128, 128, 128),  # COLOR_APPWORKSPACE
        13: (0, 0, 128),      # COLOR_HIGHLIGHT
        14: (255, 255, 255),  # COLOR_HIGHLIGHTTEXT
        15: (212, 208, 200),  # COLOR_BTNFACE
        16: (128, 128, 128),  # COLOR_BTNSHADOW
        17: (128, 128, 128),  # COLOR_GRAYTEXT
        18: (0, 0, 0),        # COLOR_BTNTEXT
        19: (192, 192, 192),  # COLOR_INACTIVECAPTIONTEXT
        20: (255, 255, 255),  # COLOR_BTNHIGHLIGHT
        21: (64, 64, 64),     # COLOR_3DDKSHADOW
        22: (212, 208, 200),  # COLOR_3DLIGHT
        23: (0, 0, 0),        # COLOR_INFOTEXT
        24: (255, 255, 225),  # COLOR_INFOBK
    }

    def GetSysColor(self, args):
        """GetSysColor emulation - classic Windows color scheme (COLORREF)"""
        r, g, b = self.SYS_COLORS.get(args[0], (0, 0, 0))
        return r | (g << 8) | (b << 16)

    def GetSysColorBrush(self, args):
        """GetSysColorBrush emulation - one cached solid brush per color index"""
        nIndex = args[0]
        if nIndex not in self.SYS_COLORS:
            return 0
        cache = self._sys_color_brushes
        if nIndex not in cache:
            cache[nIndex] = self.CreateSolidBrush([self.GetSysColor([nIndex])])
        return cache[nIndex]

    DESKTOP_HWND = 0x00010010

    def GetDesktopWindow(self, args):
        """GetDesktopWindow emulation - fixed pseudo handle"""
        return self.DESKTOP_HWND

    def GetForegroundWindow(self, args):
        """GetForegroundWindow emulation - the active window of the fake desktop"""
        if self.gui and self.gui.active_window in self.gui.windows:
            return self.gui.active_window
        return 0

    def GetActiveWindow(self, args):
        """GetActiveWindow emulation"""
        return self.GetForegroundWindow(args)

    def GetDoubleClickTime(self, args):
        """GetDoubleClickTime emulation - Windows default (500 ms)"""
        return 500

    # Window class names Windows reports for the built-in control classes
    CONTROL_CLASS_NAMES = {'BUTTON': 'Button', 'CHECKBOX': 'Button', 'EDIT': 'Edit',
                           'STATIC': 'Static', 'LISTBOX': 'ListBox',
                           'COMBOBOX': 'ComboBox', 'SCROLLBAR': 'ScrollBar'}

    def _window_class_name(self, hwnd):
        """Class name of a window or control, or None for an invalid handle"""
        if not self.gui:
            return None
        if hwnd in self.gui.windows:
            if hwnd in self.gui.consoles:
                return "ConsoleWindowClass"
            return getattr(self.gui.windows[hwnd], 'class_name', None) or "#32770"
        if hwnd in self.gui.controls:
            name = self.gui.controls[hwnd].class_name
            return self.CONTROL_CLASS_NAMES.get(name, name)
        return None

    def FindWindowA(self, args):
        """FindWindowA emulation - top-level windows by class and/or title"""
        lpClassName, lpWindowName = args[0], args[1]
        if lpClassName and lpClassName < 0x10000:
            class_name = self.atoms.get(lpClassName)
            if class_name is None:
                return 0
        else:
            class_name = self.read_string(lpClassName) if lpClassName else None
        title = self.read_string(lpWindowName) if lpWindowName else None
        log.debug(f"FindWindowA({class_name!r}, {title!r})")
        if not self.gui:
            return 0
        with self.gui.lock:
            # Topmost first, then hidden windows
            order = list(reversed(self.gui.z_order))
            order += [h for h in self.gui.windows if h not in order]
            for hwnd in order:
                win = self.gui.windows.get(hwnd)
                if win is None or win.parent:
                    continue
                if class_name is not None and \
                        (self._window_class_name(hwnd) or '').lower() != class_name.lower():
                    continue
                if title is not None and win.title.lower() != title.lower():
                    continue
                return hwnd
        self._last_error = 2  # ERROR_FILE_NOT_FOUND
        return 0

    def GetClassNameA(self, args):
        """GetClassNameA emulation"""
        hWnd, lpClassName, nMaxCount = args[0], args[1], args[2]
        name = self._window_class_name(hWnd)
        log.debug(f"GetClassNameA(0x{hWnd:x}) -> {name!r}")
        if name is None:
            self._last_error = 1400  # ERROR_INVALID_WINDOW_HANDLE
            return 0
        if not lpClassName or nMaxCount == 0 or nMaxCount >= 0x80000000:
            return 0
        data = name.encode(ANSI_CODEPAGE, errors='replace')[:nMaxCount - 1]
        self.emu.uc.mem_write(lpClassName, data + b'\x00')
        return len(data)

    def GetWindowTextLengthA(self, args):
        """GetWindowTextLengthA emulation - length in ANSI bytes"""
        text = self.gui.get_window_text(args[0]) if self.gui else ""
        return len(text.encode(ANSI_CODEPAGE, errors='replace'))

    def BringWindowToTop(self, args):
        """BringWindowToTop emulation - raise and activate a top-level window"""
        hWnd = args[0]
        log.debug(f"BringWindowToTop(0x{hWnd:x})")
        if not self.gui:
            return 0
        with self.gui.lock:
            if hWnd not in self.gui.windows:
                self._last_error = 1400  # ERROR_INVALID_WINDOW_HANDLE
                return 0
            if hWnd in self.gui.z_order:
                self.gui.z_order.remove(hWnd)
                self.gui.z_order.append(hWnd)
            if self.gui.windows[hWnd].visible:
                self.gui.active_window = hWnd
        return 1

    def SetForegroundWindow(self, args):
        """SetForegroundWindow emulation"""
        return self.BringWindowToTop(args)

    def IsIconic(self, args):
        """IsIconic emulation - is the window minimized?"""
        win = self.gui.windows.get(args[0]) if self.gui else None
        return 1 if win and win.minimized else 0

    def OpenIcon(self, args):
        """OpenIcon emulation - restore a minimized window and activate it"""
        hWnd = args[0]
        if not self.gui or hWnd not in self.gui.windows:
            self._last_error = 1400  # ERROR_INVALID_WINDOW_HANDLE
            return 0
        with self.gui.lock:
            win = self.gui.windows[hWnd]
            if win.minimized:
                win.restore()
        return self.BringWindowToTop([hWnd])

    def IsZoomed(self, args):
        """IsZoomed emulation - is the window maximized?"""
        win = self.gui.windows.get(args[0]) if self.gui else None
        return 1 if win and win.maximized and not win.minimized else 0

    def GetWindowPlacement(self, args):
        """GetWindowPlacement emulation (WINDOWPLACEMENT, 44 bytes)"""
        hWnd, lpwndpl = args[0], args[1]
        win = self.gui.windows.get(hWnd) if self.gui else None
        if win is None or not lpwndpl:
            self._last_error = 1400  # ERROR_INVALID_WINDOW_HANDLE
            return 0
        show = 2 if win.minimized else 3 if win.maximized else 1
        if win.maximized:
            normal = (win.restore_x, win.restore_y, win.restore_x + win.restore_width,
                      win.restore_y + win.restore_height)
        else:
            normal = (win.x, win.y, win.x + win.width, win.y + win.height)
        data = struct.pack('<III4i4i', 44, 0, show, -1, -1, -1, -1, *normal)
        return 1 if self._mem_write(lpwndpl, data) else 0

    def SetWindowPlacement(self, args):
        """SetWindowPlacement emulation - normal rectangle and show state"""
        hWnd, lpwndpl = args[0], args[1]
        win = self.gui.windows.get(hWnd) if self.gui else None
        try:
            fields = struct.unpack('<III4i4i', self.emu.uc.mem_read(lpwndpl, 44))
        except UcError:
            fields = None
        if win is None or fields is None:
            self._last_error = 1400
            return 0
        show = fields[2]
        left, top, right, bottom = fields[7:11]
        with self.gui.lock:
            if win.maximized:
                win.restore_x, win.restore_y = left, top
                win.restore_width, win.restore_height = right - left, bottom - top
            else:
                win.x, win.y, win.width, win.height = left, top, right - left, bottom - top
            if show == 0:  # SW_HIDE
                self.gui.show_window(hWnd, False)
            else:
                if show in (2, 6, 7):  # SW_SHOWMINIMIZED, SW_MINIMIZE, SW_SHOWMINNOACTIVE
                    win.minimize()
                elif show == 3:  # SW_SHOWMAXIMIZED
                    win.minimized = False
                    win.maximize(self.gui.width, self.gui.height, 30)
                else:
                    win.restore()
                    if win.maximized:
                        win.restore()
                if not win.visible:
                    self.gui.show_window(hWnd, True)
        self._send_size(hWnd)
        return 1

    # GetWindow commands
    GW_HWNDFIRST, GW_HWNDLAST, GW_HWNDNEXT, GW_HWNDPREV, GW_OWNER, GW_CHILD = range(6)

    def _child_handles(self, hwnd):
        """Child controls and child windows of a window, top of the Z order first"""
        win = self.gui.windows.get(hwnd)
        if win is None:
            return []
        return [c.hwnd for c in win.controls] + list(win.children)

    def GetWindow(self, args):
        """GetWindow emulation - walks siblings, children and owners"""
        hWnd, uCmd = args[0], args[1]
        if not self.gui:
            return 0
        with self.gui.lock:
            if uCmd == self.GW_CHILD:
                children = self._child_handles(hWnd)
                return children[0] if children else 0
            if uCmd == self.GW_OWNER:
                dialog = self.dialogs.get(hWnd)
                return dialog['owner'] if dialog else 0
            control = self.gui.controls.get(hWnd)
            win = self.gui.windows.get(hWnd)
            if control is not None:
                siblings = self._child_handles(control.parent_hwnd)
            elif win is not None and win.parent:
                siblings = self._child_handles(win.parent)
            elif win is not None:
                siblings = [h for h in reversed(self.gui.z_order) if h in self.gui.windows]
            else:
                self._last_error = 1400  # ERROR_INVALID_WINDOW_HANDLE
                return 0
        if not siblings:
            return 0
        if uCmd == self.GW_HWNDFIRST:
            return siblings[0]
        if uCmd == self.GW_HWNDLAST:
            return siblings[-1]
        if hWnd not in siblings:
            return 0
        index = siblings.index(hWnd) + (1 if uCmd == self.GW_HWNDNEXT else -1)
        if uCmd in (self.GW_HWNDNEXT, self.GW_HWNDPREV) and 0 <= index < len(siblings):
            return siblings[index]
        return 0

    # ---------- Cursors, icons ----------

    def SetCursor(self, args):
        """SetCursor emulation - returns the previous cursor"""
        previous, self.current_cursor = self.current_cursor, args[0]
        return previous

    def ShowCursor(self, args):
        """ShowCursor emulation - display counter (the cursor shows while >= 0)"""
        self.cursor_count += 1 if args[0] else -1
        return self.cursor_count & 0xFFFFFFFF

    def CreateCursor(self, args):
        """CreateCursor emulation - opaque cursor handle"""
        return self.get_next_handle()

    def DestroyCursor(self, args):
        """DestroyCursor emulation"""
        return 1

    def DestroyIcon(self, args):
        """DestroyIcon emulation"""
        return 1

    def ExtractIconA(self, args):
        """ExtractIconA emulation - icon count (nIconIndex -1) or an opaque icon handle"""
        filename = self.read_string(args[1])
        index = args[2]
        path = self.resolve_c_drive_path(filename)
        if path is None or not os.path.isfile(path):
            return 0
        count = 0
        try:
            pe = pefile.PE(path, fast_load=True)
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
            for entry in getattr(pe, 'DIRECTORY_ENTRY_RESOURCE', None).entries:
                if entry.id == 14:  # RT_GROUP_ICON
                    count = len(entry.directory.entries)
            pe.close()
        except (pefile.PEFormatError, AttributeError, OSError):
            return 1 if filename.lower().endswith('.ico') else 0  # Not an EXE/DLL
        if index == 0xFFFFFFFF:
            return count
        return self.get_next_handle() if index < count else 0

    # ---------- Keyboard ----------

    def GetKeyboardState(self, args):
        """GetKeyboardState emulation - 256 key bytes (0x80: down, 0x01: toggled)"""
        state = bytearray(self.keyboard_toggles)
        if self.gui:
            for vk, down in list(self.gui.key_states.items()):
                if down and 0 <= vk < 256:
                    state[vk] |= 0x80
        return 1 if self._mem_write(args[0], bytes(state)) else 0

    def SetKeyboardState(self, args):
        """SetKeyboardState emulation - only the toggle bits are kept"""
        try:
            data = self.emu.uc.mem_read(args[0], 256)
        except UcError:
            self._last_error = 998  # ERROR_NOACCESS
            return 0
        self.keyboard_toggles = bytearray(b & 1 for b in data)
        return 1

    def LoadKeyboardLayoutA(self, args):
        """LoadKeyboardLayoutA emulation - HKL of a KLID like "0000041F" """
        klid = self.read_string(args[0]).strip()
        try:
            layout = int(klid, 16)
        except ValueError:
            return 0
        lang = layout & 0xFFFF
        return ((layout >> 16 or lang) << 16 | lang) if lang else 0

    def _oem_table(self, to_oem):
        """bytes.translate table between the ANSI and the OEM code page"""
        oem = f"cp{self.OEM_CODEPAGES.get(self._ansi_codepage_number(), 437)}"
        src, dst = (ANSI_CODEPAGE, oem) if to_oem else (oem, ANSI_CODEPAGE)
        table = bytearray(range(128))
        for b in range(128, 256):
            ch = bytes([b]).decode(src, errors='replace')
            out = ch.encode(dst, errors='replace') if ch != '\ufffd' else b'?'
            table.append(out[0] if len(out) == 1 else 0x3F)
        return bytes(table)

    def _convert_oem_buffer(self, args, to_oem):
        src, dst, length = args[0], args[1], args[2]
        try:
            data = bytes(self.emu.uc.mem_read(src, length)) if length else b''
        except UcError:
            return 0
        return 1 if self._mem_write(dst, data.translate(self._oem_table(to_oem))) else 0

    def CharToOemBuffA(self, args):
        """CharToOemBuffA emulation - ANSI -> OEM code page"""
        return self._convert_oem_buffer(args, True)

    def OemToCharBuffA(self, args):
        """OemToCharBuffA emulation - OEM -> ANSI code page"""
        return self._convert_oem_buffer(args, False)

    # ---------- System settings, display modes ----------

    # Registered window messages are system-wide: name (upper case) -> id
    registered_messages = {}

    def RegisterWindowMessageA(self, args):
        """RegisterWindowMessageA emulation - ids from 0xC000, case-insensitive"""
        name = self.read_string(args[0]).upper()
        if not name:
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0
        messages = WinAPIHandler.registered_messages
        if name not in messages:
            messages[name] = 0xC000 + len(messages)
        return messages[name]

    @staticmethod
    def _logfont(height=-11, weight=400, face="MS Sans Serif"):
        """LOGFONTA bytes (60)"""
        return (struct.pack('<5i8B', height, 0, 0, 0, weight, 0, 0, 0, 0, 0, 0, 0, 0)
                + face.encode('ascii').ljust(32, b'\x00'))

    def SystemParametersInfoA(self, args):
        """SystemParametersInfoA emulation - common SPI_GET* queries; SPI_SET* are accepted"""
        action, ui_param, pv_param = args[0], args[1], args[2]
        width, height = self._screen_size()
        dword_values = {
            0x01: 1,     # SPI_GETBEEP
            0x0A: 31,    # SPI_GETKEYBOARDSPEED
            0x0E: 0,     # SPI_GETSCREENSAVETIMEOUT
            0x10: 0,     # SPI_GETSCREENSAVEACTIVE
            0x16: 1,     # SPI_GETKEYBOARDDELAY
            0x23: 1,     # SPI_GETFASTTASKSWITCH
            0x26: 0,     # SPI_GETDRAGFULLWINDOWS
            0x38: 0,     # SPI_GETSHOWSOUNDS
            0x4A: 0,     # SPI_GETFONTSMOOTHING
            0x53: 0,     # SPI_GETLOWPOWERACTIVE
            0x54: 0,     # SPI_GETPOWEROFFACTIVE
            0x5F: 0,     # SPI_GETMOUSETRAILS
            0x68: 3,     # SPI_GETWHEELSCROLLLINES
        }
        if action in dword_values:
            data = struct.pack('<I', dword_values[action])
        elif action == 0x03:  # SPI_GETMOUSE: threshold1, threshold2, acceleration
            data = struct.pack('<3i', 6, 10, 1)
        elif action == 0x30:  # SPI_GETWORKAREA: the desktop above the taskbar
            data = struct.pack('<4i', 0, 0, width, height - 30)
        elif action == 0x1F:  # SPI_GETICONTITLELOGFONT
            data = self._logfont()
        elif action == 0x29:  # SPI_GETNONCLIENTMETRICS
            data = (struct.pack('<6i', 340, 1, 16, 16, 18, 18) + self._logfont(weight=700)
                    + struct.pack('<2i', 12, 15) + self._logfont()
                    + struct.pack('<2i', 18, 18) + self._logfont()
                    + self._logfont() + self._logfont())
        elif action in (0x02, 0x0B, 0x0F, 0x11, 0x17, 0x2F, 0x55, 0x56, 0x69):
            return 1  # SPI_SET* (beep, keyboard, screen saver, work area, power...)
        else:
            log.debug(f"SystemParametersInfoA(0x{action:x}) not supported")
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0
        if not pv_param:
            self._last_error = 87
            return 0
        return 1 if self._mem_write(pv_param, data) else 0

    DISPLAY_MODES = [(640, 480), (800, 600), (1024, 768), (1280, 1024)]

    def _desktop_size(self):
        """Display mode of the fake desktop at startup (the registry mode)"""
        if self.gui:
            return self.gui.desktop_width, self.gui.desktop_height
        return self._screen_size()

    def _display_modes(self):
        width, height = self._desktop_size()
        sizes = [(w, h) for w, h in self.DISPLAY_MODES if w <= width and h <= height]
        if (width, height) not in sizes:
            sizes.append((width, height))
        return [(w, h, bpp) for w, h in sizes for bpp in (8, 16, 32)]

    def EnumDisplaySettingsA(self, args):
        """EnumDisplaySettingsA emulation - the startup mode and smaller standard ones"""
        mode_num, lpDevMode = args[1], args[2]
        if mode_num == 0xFFFFFFFF:  # ENUM_CURRENT_SETTINGS
            width, height = self._screen_size()
            mode = (width, height, 32)
        elif mode_num == 0xFFFFFFFE:  # ENUM_REGISTRY_SETTINGS
            width, height = self._desktop_size()
            mode = (width, height, 32)
        else:
            modes = self._display_modes()
            if mode_num >= len(modes):
                return 0
            mode = modes[mode_num]
        try:
            self.emu.uc.mem_write(lpDevMode, b'DISPLAY'.ljust(32, b'\x00')
                                  + struct.pack('<HHHHI', 0x0401, 0, 156, 0, 0x7C0000))
            self.emu.uc.mem_write(lpDevMode + 104, struct.pack('<5I', mode[2], mode[0],
                                                               mode[1], 0, 60))
        except UcError:
            return 0
        return 1

    WM_DISPLAYCHANGE = 0x007E

    def ChangeDisplaySettingsA(self, args):
        """ChangeDisplaySettingsA emulation - an enumerated mode changes the fake
        desktop resolution (the color depth stays 32 bpp); NULL restores the
        startup mode"""
        lpDevMode, dwFlags = args[0], args[1]
        if not lpDevMode:
            if not dwFlags & 0x2:  # CDS_TEST
                self._set_display_mode(*self._desktop_size(), owner=None)
            return 0  # DISP_CHANGE_SUCCESSFUL (back to the registry mode)
        try:
            fields = struct.unpack('<I', self.emu.uc.mem_read(lpDevMode + 40, 4))[0]
            bpp, width, height = struct.unpack('<3I', self.emu.uc.mem_read(lpDevMode + 104, 12))
        except UcError:
            return 0xFFFFFFFB  # DISP_CHANGE_BADPARAM
        screen_w, screen_h = self._screen_size()
        width = width if fields & 0x80000 else screen_w    # DM_PELSWIDTH
        height = height if fields & 0x100000 else screen_h  # DM_PELSHEIGHT
        sizes = {(w, h) for w, h, _ in self._display_modes()}
        if ((fields & 0x40000 and bpp not in (1, 4, 8, 15, 16, 24, 32)) or
                (width, height) not in sizes):
            return 0xFFFFFFFE  # DISP_CHANGE_BADMODE
        if not dwFlags & 0x2:  # CDS_TEST only checks the mode
            # CDS_FULLSCREEN modes end with the program
            owner = self if dwFlags & 0x4 else None
            self._set_display_mode(width, height, owner)
        return 0

    def _set_display_mode(self, width, height, owner):
        """Resize the fake desktop and tell the top-level windows (WM_DISPLAYCHANGE)"""
        if not self.gui:
            return
        changed = (width, height) != self._screen_size()
        self.gui.set_display_mode(width, height, owner)
        if not changed:
            return
        lparam = ((height & 0xFFFF) << 16) | (width & 0xFFFF)
        for hwnd, win in list(self.gui.windows.items()):
            if win.parent is None and win.owner is self and self._find_wndproc_for_hwnd(hwnd):
                self.post_window_message(hwnd, self.WM_DISPLAYCHANGE, 32, lparam)

    # ---------- Dialog boxes ----------

    DIALOG_CLASS_ATOMS = {0x80: 'BUTTON', 0x81: 'EDIT', 0x82: 'STATIC',
                          0x83: 'LISTBOX', 0x84: 'SCROLLBAR', 0x85: 'COMBOBOX'}
    WM_INITDIALOG = 0x0110
    DS_SETFONT = 0x40
    DS_CENTER = 0x800

    @staticmethod
    def _parse_dialog_template(data):
        """DLGTEMPLATE / DLGTEMPLATEEX -> dict with the dialog and its items"""
        pos = 0

        def sz_or_ord():
            nonlocal pos
            first = struct.unpack_from('<H', data, pos)[0]
            if first == 0:
                pos += 2
                return ''
            if first == 0xFFFF:
                pos += 4
                return struct.unpack_from('<H', data, pos - 2)[0]
            end = pos
            while struct.unpack_from('<H', data, end)[0]:
                end += 2
            text = data[pos:end].decode('utf-16-le', errors='replace')
            pos = end + 2
            return text

        extended = struct.unpack_from('<HH', data, 0) == (1, 0xFFFF)
        if extended:
            ex_style, style = struct.unpack_from('<II', data, 8)
            pos = 16
        else:
            style, ex_style = struct.unpack_from('<II', data, 0)
            pos = 8
        count, x, y, cx, cy = struct.unpack_from('<Hhhhh', data, pos)
        pos += 10
        dialog = {'style': style, 'ex_style': ex_style, 'x': x, 'y': y, 'cx': cx, 'cy': cy,
                  'menu': sz_or_ord(), 'class': sz_or_ord(), 'title': sz_or_ord(),
                  'font': None, 'items': []}
        if style & WinAPIHandler.DS_SETFONT:
            size = struct.unpack_from('<H', data, pos)[0]
            pos += 6 if extended else 2  # weight, italic, charset
            dialog['font'] = (sz_or_ord(), size)
        for _ in range(count):
            pos = (pos + 3) & ~3
            if extended:
                _, iex, istyle, ix, iy, icx, icy, iid = struct.unpack_from('<IIIhhhhI', data, pos)
                pos += 24
            else:
                istyle, iex, ix, iy, icx, icy, iid = struct.unpack_from('<IIhhhhH', data, pos)
                pos += 18
            item = {'style': istyle, 'ex_style': iex, 'x': ix, 'y': iy, 'cx': icx,
                    'cy': icy, 'id': iid, 'class': sz_or_ord(), 'text': sz_or_ord()}
            pos += 2 + struct.unpack_from('<H', data, pos)[0]  # Creation data
            dialog['items'].append(item)
        return dialog

    def _create_dialog(self, template, owner, proc=0, handler=None):
        """Create a dialog window and its controls from a parsed template.
        Dialog units are converted for an 8 pt dialog font."""
        size = template['font'][1] if template['font'] else 8
        bx, by = 1.5 * size / 8, 1.625 * size / 8
        client_w, client_h = round(template['cx'] * bx), round(template['cy'] * by)
        border, caption = PseudoWindowsGUI.frame_size(template['style'], dialog=True)
        width, height = client_w + 2 * border, client_h + 2 * border + caption
        owner_win = self.gui.windows.get(owner)
        screen_w, screen_h = self._screen_size()
        if template['style'] & self.DS_CENTER or owner_win is None:
            if owner_win is not None and owner_win.visible and not owner_win.minimized:
                x = owner_win.x + (owner_win.width - width) // 2
                y = owner_win.y + (owner_win.height - height) // 2
            else:
                x, y = (screen_w - width) // 2, (screen_h - 30 - height) // 2
        else:
            ox, oy = self.gui.client_origin(owner_win)
            x, y = ox + round(template['x'] * bx), oy + round(template['y'] * by)
        x = max(0, min(x, screen_w - width))
        y = max(0, min(y, screen_h - 30 - height))
        title = template['title'] if isinstance(template['title'], str) else ''
        hwnd = self.gui.create_window(title, x, y, width, height,
                                      template['style'] & ~self.WS_VISIBLE, owner=self)
        win = self.gui.windows[hwnd]
        win.class_name = '#32770'
        win.is_dialog = True
        self.dialogs[hwnd] = {'proc': proc, 'handler': handler, 'owner': owner,
                              'result': 0, 'ended': False}
        for item in template['items']:
            cls = item['class']
            cls = self.DIALOG_CLASS_ATOMS.get(cls, 'STATIC') if isinstance(cls, int) else cls
            text = item['text'] if isinstance(item['text'], str) else ''
            style = item['style']
            if cls.upper() == 'BUTTON' and (style & 0xF) in self.CHECK_BUTTON_STYLES:
                cls = 'CHECKBOX'
            elif cls.upper() == 'MSCTLS_STATUSBAR32':
                cls = 'STATUSBAR'
            chwnd = self.gui.create_control(
                hwnd, cls, text, round(item['x'] * bx), round(item['y'] * by),
                round(item['cx'] * bx), round(item['cy'] * by), style,
                control_id=item['id'] & 0xFFFF)
            self.dirty_controls[chwnd] = True
            control = self.gui.controls[chwnd]
            control.visible = bool(style & self.WS_VISIBLE)
            control.enabled = not style & 0x08000000  # WS_DISABLED
        return hwnd

    def _dialog_of(self, hwnd):
        """The dialog hwnd belongs to (itself or the parent of a control), or 0"""
        if hwnd in self.dialogs:
            return hwnd
        control = self.gui.controls.get(hwnd) if self.gui else None
        if control is not None and control.parent_hwnd in self.dialogs:
            return control.parent_hwnd
        return 0

    def _dialog_button(self, dlg, control_id=None):
        """Button of a dialog by id, or its default push button (control_id None)"""
        win = self.gui.windows.get(dlg)
        for control in (win.controls if win else []):
            if control.class_name != 'BUTTON' or not control.visible:
                continue
            if control_id is None and (control.style & 0xF) == 1:
                return control
            if control_id is not None and control.control_id == control_id:
                return control
        return None

    def _dialog_message(self, dlg, message, wParam, lParam):
        """Deliver a message to a dialog's procedure (or internal handler)"""
        dialog = self.dialogs.get(dlg)
        if dialog is None:
            return 0
        if dialog['handler']:
            return dialog['handler'](message, wParam, lParam) or 0
        result = self.emu.call_wndproc(dialog['proc'], dlg, message, wParam, lParam)
        if message == self.WM_CLOSE and not result and dlg in self.dialogs:
            # DefDlgProc: closing a dialog clicks its Cancel button
            cancel = self._dialog_button(dlg, 2)
            self.emu.call_wndproc(dialog['proc'], dlg, self.WM_COMMAND, 2,
                                  cancel.hwnd if cancel else 0)
        return result

    def _owner_draw_type(self, control):
        """ODT_* type of an owner-draw control, or 0"""
        if control.class_name == 'STATIC' and (control.style & 0x1F) == 0xD:  # SS_OWNERDRAW
            return 5  # ODT_STATIC
        if control.class_name == 'BUTTON' and (control.style & 0xF) == 0xB:  # BS_OWNERDRAW
            return 4  # ODT_BUTTON
        return 0

    def _paint_control(self, hwnd):
        """WM_PAINT of an owner-draw control: send WM_DRAWITEM to its parent"""
        control = self.gui.controls.get(hwnd)
        kind = self._owner_draw_type(control) if control else 0
        if not kind:
            return 0
        if not self._drawitem_buf:
            self._drawitem_buf = self.emu.heap_alloc(48)
        hdc = self._create_dc(hwnd)
        self.gui.clear_drawings(hwnd)
        # CtlType, CtlID, itemID, itemAction (ODA_DRAWENTIRE), itemState, hwndItem, hDC,
        # rcItem, itemData
        self.emu.uc.mem_write(self._drawitem_buf, struct.pack(
            '<7I4iI', kind, control.control_id, 0, 1, 0, hwnd, hdc,
            0, 0, control.width, control.height, 0))
        parent = control.parent_hwnd
        try:
            if self._dialog_of(parent):
                self._dialog_message(parent, self.WM_DRAWITEM, control.control_id,
                                     self._drawitem_buf)
            else:
                wndproc = self._find_wndproc_for_hwnd(parent)
                if wndproc:
                    self.emu.call_wndproc(wndproc, parent, self.WM_DRAWITEM,
                                          control.control_id, self._drawitem_buf)
        finally:
            self._delete_dc(hdc)
        return 0

    def _dispatch(self, hwnd, message, wParam, lParam):
        """DispatchMessage for a message already read from the queue"""
        if message == self.WM_PAINT and hwnd in self.gui.controls:
            return self._paint_control(hwnd)
        if message == self.WM_TIMER and lParam:
            tick = int(time.time() * 1000) & 0xFFFFFFFF
            return self.emu.call_callback(lParam, [hwnd, message, wParam, tick])
        dlg = self._dialog_of(hwnd)
        if dlg:
            if message == self.WM_KEYDOWN and wParam in (0x0D, 0x1B):
                # Enter: default button, Escape: Cancel
                button = (self._dialog_button(dlg) if wParam == 0x0D
                          else self._dialog_button(dlg, 2))
                control_id = button.control_id if button else (1 if wParam == 0x0D else 2)
                return self._dialog_message(dlg, self.WM_COMMAND, control_id,
                                            button.hwnd if button else 0)
            if message == self.WM_KEYDOWN and wParam == 0x09:  # Tab: next edit control
                win = self.gui.windows.get(dlg)
                edits = [c.hwnd for c in (win.controls if win else [])
                         if c.class_name == 'EDIT' and c.visible and c.enabled]
                if edits:
                    current = self.gui.focused_control
                    index = edits.index(current) + 1 if current in edits else 0
                    self.gui.focused_control = edits[index % len(edits)]
                return 0
            return self._dialog_message(dlg, message, wParam, lParam)
        wndproc = self._find_wndproc_for_hwnd(hwnd)
        return self.emu.call_wndproc(wndproc, hwnd, message, wParam, lParam) if wndproc else 0

    def _close_dialog(self, dlg):
        """Destroy a dialog window and reactivate its owner"""
        dialog = self.dialogs.pop(dlg, None)
        self.painted_windows.discard(dlg)
        self.gui._remove_window(dlg)
        owner = self.gui.windows.get(dialog['owner']) if dialog else None
        if owner is not None:
            owner.enabled = True
            if owner.visible and not owner.parent:
                self.BringWindowToTop([owner.hwnd])

    def _run_modal_dialog(self, dlg):
        """Message loop of a modal dialog; returns its EndDialog result"""
        dialog = self.dialogs[dlg]
        owner = self.gui.windows.get(dialog['owner'])
        if owner is not None:
            owner.enabled = False
        result = 0xFFFFFFFF
        try:
            while not dialog['ended']:
                if (self.emu.stop_emulation or self.quit_requested or
                        not self.gui.running or dlg not in self.gui.windows):
                    break
                msg = self._next_message(True)
                if msg is None:
                    self._audio_pump()
                    time.sleep(0.01)
                    continue
                if msg[1] == self.WM_QUIT:
                    self.quit_requested = True
                    break
                self._dispatch(*msg)
            else:
                result = dialog['result']
        finally:
            self._close_dialog(dlg)
        return result

    def _show_dialog(self, dlg, init_param):
        """Show a new dialog, send WM_INITDIALOG and focus its first edit control"""
        win = self.gui.windows[dlg]
        edits = [c for c in win.controls if c.class_name == 'EDIT' and c.visible and c.enabled]
        first = next((c for c in win.controls
                      if c.visible and c.enabled and c.style & 0x00010000), None)  # WS_TABSTOP
        set_focus = self._dialog_message(dlg, self.WM_INITDIALOG,
                                         first.hwnd if first else 0, init_param)
        if dlg not in self.gui.windows:
            return
        if set_focus and edits and self.gui.focused_control not in [c.hwnd for c in edits]:
            self.gui.focused_control = edits[0].hwnd
        self.gui.show_window(dlg, True)

    def DialogBoxParamA(self, args):
        """DialogBoxParamA emulation - modal dialog from an RT_DIALOG resource"""
        hInstance, lpTemplateName, hWndParent, lpDialogFunc, dwInitParam = args[:5]
        key = self._resource_key(lpTemplateName)
        found = self._find_resource(5, key) if self._is_own_module(hInstance) else None
        log.info(f"DialogBoxParamA({key!r})")
        if found is None:
            self._last_error = 1814  # ERROR_RESOURCE_NAME_NOT_FOUND
            return 0xFFFFFFFF
        if not self.gui or not self.gui.running:
            return 0xFFFFFFFF
        try:
            template = self._parse_dialog_template(bytes(self.emu.uc.mem_read(*found)))
        except (struct.error, UcError) as e:
            log.error(f"DialogBoxParamA: bad dialog template ({e})")
            return 0xFFFFFFFF
        owner = hWndParent
        control = self.gui.controls.get(owner)
        if control is not None:
            owner = control.parent_hwnd
        dlg = self._create_dialog(template, owner, proc=lpDialogFunc)
        self._show_dialog(dlg, dwInitParam)
        return self._run_modal_dialog(dlg)

    def EndDialog(self, args):
        """EndDialog emulation - the modal loop ends with nResult"""
        dialog = self.dialogs.get(args[0])
        if dialog is None:
            self._last_error = 1400  # ERROR_INVALID_WINDOW_HANDLE
            return 0
        dialog['ended'] = True
        dialog['result'] = args[1]
        if self.gui and args[0] in self.gui.windows:
            self.gui.windows[args[0]].visible = False
        return 1

    def IsDialogMessageA(self, args):
        """IsDialogMessageA emulation - processes messages for a dialog's window"""
        hDlg, lpMsg = args[0], args[1]
        if hDlg not in self.dialogs:
            return 0
        try:
            hwnd, message, wParam, lParam = struct.unpack('<4I', self.emu.uc.mem_read(lpMsg, 16))
        except UcError:
            return 0
        if self._dialog_of(hwnd) != hDlg:
            return 0
        self._dispatch(hwnd, message, wParam, lParam)
        return 1

    # ---------- Common dialogs (comdlg32) ----------

    @staticmethod
    def _dialog_item(cls, text, x, y, cx, cy, control_id, style=0):
        return {'class': cls, 'text': text, 'x': x, 'y': y, 'cx': cx, 'cy': cy,
                'id': control_id, 'style': 0x50000000 | style, 'ex_style': 0}

    @staticmethod
    def _dialog_template(title, cx, cy, items):
        return {'style': 0x80C80000 | 0x800, 'ex_style': 0, 'x': 0, 'y': 0, 'cx': cx,
                'cy': cy, 'menu': '', 'class': '', 'title': title, 'font': None,
                'items': items}

    def _dialog_control(self, dlg, control_id):
        win = self.gui.windows.get(dlg)
        return next((c for c in (win.controls if win else [])
                     if c.control_id == control_id), None)

    def _owner_window(self, hwnd):
        """Top-level window owning hwnd (a control's parent), or 0"""
        control = self.gui.controls.get(hwnd) if self.gui else None
        return control.parent_hwnd if control is not None else hwnd

    def _file_dialog(self, lpofn, save):
        """GetOpenFileNameA / GetSaveFileNameA: a modal file browser"""
        try:
            (hwndOwner, _, lpstrFilter, _, _, nFilterIndex, lpstrFile, nMaxFile,
             lpstrFileTitle, nMaxFileTitle, lpstrInitialDir, lpstrTitle,
             flags) = struct.unpack('<13I', self.emu.uc.mem_read(lpofn + 4, 52))
            lpstrDefExt = struct.unpack('<I', self.emu.uc.mem_read(lpofn + 60, 4))[0]
            filters = []
            if lpstrFilter:
                parts, address = [], lpstrFilter
                while len(parts) < 256:
                    raw = bytes(self.read_cstring(address))
                    if not raw:
                        break
                    parts.append(raw.decode(ANSI_CODEPAGE, errors='replace'))
                    address += len(raw) + 1
                filters = list(zip(parts[0::2], parts[1::2]))
        except UcError:
            return 0
        if not self.gui or not self.gui.running:
            return 0
        initial = self.read_string(lpstrFile) if lpstrFile else ''
        default_ext = self.read_string(lpstrDefExt) if lpstrDefExt else ''
        title = (self.read_string(lpstrTitle) if lpstrTitle else
                 ('Save As' if save else 'Open'))
        index = nFilterIndex if 0 < nFilterIndex <= len(filters) else 1
        patterns = (filters[index - 1][1].split(';') if filters else ['*.*'])
        start_dir = self.read_string(lpstrInitialDir) if lpstrInitialDir else ''
        if '\\' in initial or ':' in initial:
            start_dir, initial = ntpath.split(initial)
        directory = self.full_windows_path(start_dir or self.current_directory, clamp=True)
        host = self.resolve_c_drive_path(directory) if directory else None
        if host is None or not os.path.isdir(host):
            directory = self.current_directory
        log.info(f"{'GetSaveFileNameA' if save else 'GetOpenFileNameA'}"
                 f"(\"{title}\", dir=\"{directory}\", filter={patterns})")

        ID_PATH, ID_LIST, ID_EDIT = 1088, 1120, 1152
        template = self._dialog_template(title, 220, 170, [
            self._dialog_item('STATIC', '', 7, 6, 206, 10, ID_PATH),
            self._dialog_item('LISTBOX', '', 7, 20, 206, 104, ID_LIST, 0x00810001),
            self._dialog_item('STATIC', 'File name:', 7, 134, 40, 10, 0xFFFF),
            self._dialog_item('EDIT', initial if '*' not in initial and '?' not in initial
                              else '', 48, 132, 165, 12, ID_EDIT, 0x00810080),
            self._dialog_item('BUTTON', 'Save' if save else 'Open', 106, 150, 50, 14, 1,
                              0x00010001),
            self._dialog_item('BUTTON', 'Cancel', 163, 150, 50, 14, 2, 0x00010000)])
        state = {'dir': directory, 'patterns': patterns, 'result': None}

        def fill():
            host_dir = self.resolve_c_drive_path(state['dir'])
            try:
                entries = sorted(os.listdir(host_dir), key=str.lower)
            except (OSError, TypeError):
                entries = []
            dirs = [e for e in entries if os.path.isdir(os.path.join(host_dir, e))]
            files = [e for e in entries if os.path.isfile(os.path.join(host_dir, e)) and
                     any(fnmatch.fnmatch(e.lower(), p.strip().lower().replace('*.*', '*'))
                         for p in state['patterns'])]
            items = ([] if state['dir'].rstrip('\\').endswith(':') else ['[..]'])
            items += [f'[{d}]' for d in dirs] + files
            listbox = self._dialog_control(dlg, ID_LIST)
            listbox.items, listbox.sel_index, listbox.top_index = items, -1, 0
            self._dialog_control(dlg, ID_PATH).text = state['dir']

        def navigate(name):
            target = self.full_windows_path(ntpath.join(state['dir'], name), clamp=True)
            host_dir = self.resolve_c_drive_path(target) if target else None
            if host_dir is None or not os.path.isdir(host_dir):
                return False
            state['dir'] = target
            fill()
            return True

        def accept():
            name = self._dialog_control(dlg, ID_EDIT).text.strip().strip('"')
            if not name:
                return
            if '*' in name or '?' in name:
                state['patterns'] = name.split(';')
                self._dialog_control(dlg, ID_EDIT).text = ''
                fill()
                return
            if navigate(name):
                self._dialog_control(dlg, ID_EDIT).text = ''
                return
            full = self.full_windows_path(ntpath.join(state['dir'], name), clamp=True)
            if full is None:
                return
            path = self.resolve_c_drive_path(full)
            if not ntpath.splitext(full)[1] and default_ext and \
                    not (path and os.path.isfile(path)):
                full += '.' + default_ext
                path = self.resolve_c_drive_path(full)
            if path is None or (flags & 0x1000 and not os.path.isfile(path)):  # OFN_FILEMUSTEXIST
                SoundPlayer.tone(440, 150)
                return
            state['result'] = full
            self.EndDialog([dlg, 1])

        def handler(message, wParam, lParam):
            if message == self.WM_INITDIALOG:
                fill()
                return 1
            if message == self.WM_CLOSE:
                self.EndDialog([dlg, 0])
            elif message == self.WM_COMMAND:
                control_id, code = wParam & 0xFFFF, wParam >> 16
                if control_id == ID_LIST and code == self.LBN_SELCHANGE:
                    listbox = self._dialog_control(dlg, ID_LIST)
                    if 0 <= listbox.sel_index < len(listbox.items):
                        item = listbox.items[listbox.sel_index]
                        if item.startswith('[') and item.endswith(']'):
                            navigate(item[1:-1])
                        else:
                            self._dialog_control(dlg, ID_EDIT).text = item
                elif control_id == 1:
                    accept()
                elif control_id == 2:
                    self.EndDialog([dlg, 0])
            return 0

        dlg = self._create_dialog(template, self._owner_window(hwndOwner), handler=handler)
        self._show_dialog(dlg, 0)
        if self._run_modal_dialog(dlg) != 1 or not state['result']:
            self._last_error = 0
            return 0
        full = state['result']
        data = full.encode(ANSI_CODEPAGE, errors='replace')
        if len(data) + 1 > nMaxFile:
            if nMaxFile >= 2:
                self._mem_write(lpstrFile, struct.pack('<H', min(len(data) + 1, 0xFFFF)))
            self._last_error = 0x3003  # FNERR_BUFFERTOOSMALL
            return 0
        self._mem_write(lpstrFile, data + b'\x00')
        offset = data.rfind(b'\\') + 1
        dot = data.rfind(b'.')
        extension = dot + 1 if dot >= offset else len(data)
        self._mem_write(lpofn + 56, struct.pack('<HH', offset, extension))
        if lpstrFileTitle and nMaxFileTitle:
            self._mem_write(lpstrFileTitle, data[offset:][:nMaxFileTitle - 1] + b'\x00')
        self._mem_write(lpofn + 24, struct.pack('<I', index))
        if not flags & 0x8:  # OFN_NOCHANGEDIR
            self.current_directory = ntpath.dirname(full) if offset > 3 else full[:3]
        return 1

    def GetOpenFileNameA(self, args):
        """GetOpenFileNameA emulation"""
        return self._file_dialog(args[0], save=False)

    def GetSaveFileNameA(self, args):
        """GetSaveFileNameA emulation"""
        return self._file_dialog(args[0], save=True)

    FR_DOWN, FR_MATCHCASE, FR_FINDNEXT, FR_DIALOGTERM = 0x1, 0x4, 0x8, 0x40
    FR_HIDEMATCHCASE = 0x8000

    def FindTextA(self, args):
        """FindTextA emulation - modeless Find dialog; the owner gets the
        "commdlg_FindReplace" registered message"""
        lpfr = args[0]
        try:
            hwndOwner, _, flags, lpstrFindWhat, _, length = struct.unpack(
                '<IIIIIH', self.emu.uc.mem_read(lpfr + 4, 22))
        except UcError:
            return 0
        if not self.gui or not self.gui.running or not lpstrFindWhat or not length:
            return 0
        messages = WinAPIHandler.registered_messages
        find_message = messages.setdefault('COMMDLG_FINDREPLACE', 0xC000 + len(messages))
        ID_EDIT, ID_CASE = 1152, 1041
        items = [self._dialog_item('STATIC', 'Find what:', 6, 9, 40, 10, 0xFFFF),
                 self._dialog_item('EDIT', self.read_string(lpstrFindWhat), 48, 7, 128, 12,
                                   ID_EDIT, 0x00810080),
                 self._dialog_item('BUTTON', 'Find Next', 182, 5, 50, 14, 1, 0x00010001),
                 self._dialog_item('BUTTON', 'Cancel', 182, 23, 50, 14, 2, 0x00010000)]
        if not flags & self.FR_HIDEMATCHCASE:
            items.append(self._dialog_item('BUTTON', 'Match case', 6, 28, 64, 12, ID_CASE,
                                           0x00010003))
        owner = self._owner_window(hwndOwner)

        def notify(new_flags):
            try:
                current = struct.unpack('<I', self.emu.uc.mem_read(lpfr + 12, 4))[0]
            except UcError:
                return
            current = (current & ~(self.FR_FINDNEXT | self.FR_DIALOGTERM | self.FR_MATCHCASE)
                       | new_flags)
            self._mem_write(lpfr + 12, struct.pack('<I', current))
            self._dispatch(owner, find_message, 0, lpfr)

        def handler(message, wParam, lParam):
            if message == self.WM_INITDIALOG:
                case = self._dialog_control(dlg, ID_CASE)
                if case is not None:
                    case.checked = bool(flags & self.FR_MATCHCASE)
                return 1
            command = wParam & 0xFFFF if message == self.WM_COMMAND else None
            if command == 1:
                text = self._dialog_control(dlg, ID_EDIT).text
                if text:
                    data = text.encode(ANSI_CODEPAGE, errors='replace')[:length - 1]
                    self._mem_write(lpstrFindWhat, data + b'\x00')
                    case = self._dialog_control(dlg, ID_CASE)
                    notify(self.FR_FINDNEXT |
                           (self.FR_MATCHCASE if case is not None and case.checked else 0))
            elif command == 2 or message == self.WM_CLOSE:
                self._close_dialog(dlg)
                notify(self.FR_DIALOGTERM)
            return 0

        dlg = self._create_dialog(self._dialog_template('Find', 238, 44, items), owner,
                                  handler=handler)
        self._show_dialog(dlg, 0)
        return dlg

    # ---------- Status bar (comctl32) ----------

    SB_SETTEXTA, SB_GETTEXTA, SB_GETTEXTLENGTHA, SB_SETPARTS = 0x401, 0x402, 0x403, 0x404
    SB_GETPARTS, SB_SETMINHEIGHT, SB_SIMPLE, SB_GETRECT = 0x406, 0x408, 0x409, 0x40A

    def _create_status_bar(self, parent, text, style, control_id):
        hwnd = self.gui.create_control(parent, 'STATUSBAR', text, 0, 0, 0,
                                       PseudoWindowsGUI.STATUSBAR_H, style,
                                       control_id=control_id)
        control = self.gui.controls[hwnd]
        control.visible = bool(style & self.WS_VISIBLE)
        self.gui.layout_statusbar(control)
        return hwnd

    def CreateStatusWindowA(self, args):
        """CreateStatusWindowA emulation (comctl32 ordinal 6) - status bar at the
        bottom of the parent's client area"""
        style, lpszText, hwndParent, wID = args[0], args[1], args[2], args[3]
        text = self.read_string(lpszText) if lpszText else ''
        log.debug(f"CreateStatusWindowA(0x{hwndParent:x}, \"{text}\")")
        if not self.gui or hwndParent not in self.gui.windows:
            return self.get_next_handle() if not self.gui else 0
        return self._create_status_bar(hwndParent, text, style, wID & 0xFFFF)

    def _status_bar_message(self, control, Msg, wParam, lParam, wide):
        """Status bar messages (SB_*); None if Msg is not one of them"""
        if Msg == self.WM_SIZE:
            self.gui.layout_statusbar(control)
            return 0
        if Msg == self.SB_SETTEXTA:
            part = wParam & 0xFF
            text = self._read_text(lParam, wide) if lParam else ''
            if part == 0:
                control.text = text
            else:
                texts = dict(control.part_texts)  # The GUI thread may be drawing the old one
                texts[part] = text
                control.part_texts = texts
            return 1
        if Msg in (self.SB_GETTEXTA, self.SB_GETTEXTLENGTHA):
            part = wParam & 0xFF
            text = control.text if part == 0 else control.part_texts.get(part, '')
            if Msg == self.SB_GETTEXTA and lParam:
                self._write_units(lParam, self._text_units(text, wide), wide)
            return len(text)
        if Msg == self.SB_SETPARTS:
            count = min(wParam, 256)
            try:
                edges = list(struct.unpack(f'<{count}i', self.emu.uc.mem_read(lParam, 4 * count)))
            except UcError:
                return 0
            control.parts = edges or [-1]
            return 1
        if Msg == self.SB_GETPARTS:
            if lParam and wParam:
                edges = control.parts[:wParam]
                self._mem_write(lParam, struct.pack(f'<{len(edges)}i', *edges))
            return len(control.parts)
        if Msg == self.SB_SIMPLE:
            control.simple = bool(wParam)
            return 0
        if Msg == self.SB_SETMINHEIGHT:
            return 0
        if Msg == self.SB_GETRECT:
            if wParam >= len(control.parts) or not lParam:
                return 0
            left = 0 if wParam == 0 else control.parts[wParam - 1]
            right = control.parts[wParam]
            right = control.width if right < 0 else right
            self._write_rect(lParam, left, 2, right, control.height - 2)
            return 1
        return None

    def AdjustWindowRect(self, args):
        """AdjustWindowRect emulation - client rect -> window rect.

        Uses the fake desktop's frame for the style (overlapped and WS_CAPTION
        windows have a border and a title bar), so it matches GetClientRect for
        the created window.
        """
        lpRect, dwStyle, bMenu = args[0], args[1], args[2]
        rect = self._read_rect(lpRect) if lpRect else None
        if rect is None:
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0
        left, top, right, bottom = rect
        border, caption = PseudoWindowsGUI.frame_size(dwStyle)
        caption += PseudoWindowsGUI.MENU_H if bMenu else 0
        return 1 if self._write_rect(lpRect, left - border, top - border - caption,
                                     right + border, bottom + border) else 0

    def AdjustWindowRectEx(self, args):
        """AdjustWindowRectEx emulation (the extended style has no extra frame here)"""
        return self.AdjustWindowRect(args[:3])

    def _ansi_char(self, value):
        """Decode one ANSI code unit; None if it is not a character on its own"""
        try:
            return bytes([value & 0xFF]).decode(ANSI_CODEPAGE)
        except UnicodeDecodeError:
            return None

    def _char_case_common(self, lpsz, upper, wide=False):
        """CharUpper/CharLower A/W: a single char (HIWORD 0) or an in-place string"""
        convert = str.upper if upper else str.lower
        if lpsz < 0x10000:
            if wide:
                converted = convert(chr(lpsz))
                return ord(converted) if len(converted) == 1 and ord(converted) < 0x10000 else lpsz
            ch = self._ansi_char(lpsz)
            if ch is None:
                return lpsz
            converted = convert(ch).encode(ANSI_CODEPAGE, errors='replace')
            return converted[0] if len(converted) == 1 else lpsz
        if wide:
            units = self._read_units(lpsz, True)
            text = self._units_text(units, True)
            data = self._text_units(convert(text), True)
            if len(data) == len(units):
                self._write_units(lpsz, data, True, terminate=False)
            return lpsz
        raw = self.read_cstring(lpsz)
        text = raw.decode(ANSI_CODEPAGE, errors='surrogateescape')
        data = convert(text).encode(ANSI_CODEPAGE, errors='surrogateescape')
        if len(data) == len(raw):  # never change the buffer length in place
            self.emu.uc.mem_write(lpsz, data)
        return lpsz

    def CharUpperA(self, args):
        """CharUpperA emulation"""
        return self._char_case_common(args[0], True)

    def CharLowerA(self, args):
        """CharLowerA emulation"""
        return self._char_case_common(args[0], False)

    def CharUpperW(self, args):
        """CharUpperW emulation"""
        return self._char_case_common(args[0], True, wide=True)

    def CharLowerW(self, args):
        """CharLowerW emulation"""
        return self._char_case_common(args[0], False, wide=True)

    def _ansi_char_length(self, address):
        """Bytes of the ANSI character at address (0 at the terminator).

        Only UTF-8 has multi-byte characters among the supported code pages.
        """
        try:
            data = bytes(self.emu.uc.mem_read(address, 1))
        except UcError:
            return 0
        if data == b'\x00':
            return 0
        if ANSI_CODEPAGE.replace('_', '-') != 'utf-8':
            return 1
        lead = data[0]
        size = 2 if 0xC2 <= lead <= 0xDF else 3 if 0xE0 <= lead <= 0xEF else \
            4 if 0xF0 <= lead <= 0xF4 else 1
        if size > 1:
            try:
                data = bytes(self.emu.uc.mem_read(address, size))
                data.decode('utf-8')
            except (UcError, UnicodeDecodeError):
                return 1
        return size

    def CharNextA(self, args):
        """CharNextA emulation - stays on the terminator"""
        lpsz = args[0]
        return lpsz + self._ansi_char_length(lpsz) if lpsz else 0

    def CharPrevA(self, args):
        """CharPrevA emulation - never moves before lpszStart"""
        start, current = args[0], args[1]
        if current <= start:
            return start
        # Step back over UTF-8 continuation bytes to the character that ends at current
        for back in range(min(4, current - start), 1, -1):
            if self._ansi_char_length(current - back) == back:
                return current - back
        return current - 1

    def IsCharUpperA(self, args):
        """IsCharUpperA emulation"""
        ch = self._ansi_char(args[0])
        return 1 if ch and ch.isupper() else 0

    def IsCharLowerA(self, args):
        """IsCharLowerA emulation"""
        ch = self._ansi_char(args[0])
        return 1 if ch and ch.islower() else 0

    def CharUpperA(self, args):
        """CharUpperA emulation"""
        return self._char_case_common(args[0], True)

    def CharLowerA(self, args):
        """CharLowerA emulation"""
        return self._char_case_common(args[0], False)

    def IsCharAlphaA(self, args):
        """IsCharAlphaA emulation"""
        ch = self._ansi_char(args[0])
        return 1 if ch and ch.isalpha() else 0

    def IsCharAlphaNumericA(self, args):
        """IsCharAlphaNumericA emulation"""
        ch = self._ansi_char(args[0])
        return 1 if ch and ch.isalnum() else 0

    # ---------- winmm ----------

    def timeGetTime(self, args):
        """timeGetTime emulation - milliseconds, like GetTickCount"""
        self._audio_pump()
        return int(time.time() * 1000) & 0xFFFFFFFF

    def timeBeginPeriod(self, args):
        """timeBeginPeriod emulation - TIMERR_NOERROR"""
        return 0

    def timeEndPeriod(self, args):
        """timeEndPeriod emulation - TIMERR_NOERROR"""
        return 0

    # ---------- PCM / ADPCM sample conversion ----------

    @staticmethod
    def _read_waveformat(uc, address):
        """WAVEFORMATEX -> dict (tag, channels, rate, avg, align, bits, extra) or None"""
        try:
            tag, channels, rate, avg, align, bits = struct.unpack(
                '<HHIIHH', uc.mem_read(address, 16))
            extra = b''
            if tag != 1:
                cb_size = struct.unpack('<H', uc.mem_read(address + 16, 2))[0]
                extra = bytes(uc.mem_read(address + 18, min(cb_size, 1024))) if cb_size else b''
        except UcError:
            return None
        return {'tag': tag, 'channels': channels, 'rate': rate, 'avg': avg,
                'align': align, 'bits': bits, 'extra': extra}

    @staticmethod
    def _pcm_samples(data, bits):
        """PCM bytes (8-bit unsigned or 16-bit signed) -> array of 16-bit samples"""
        if bits == 8:
            return array.array('h', ((b - 128) << 8 for b in data))
        samples = array.array('h')
        samples.frombytes(bytes(data[:len(data) & ~1]))
        if sys.byteorder != 'little':
            samples.byteswap()
        return samples

    @staticmethod
    def _convert_samples(samples, channels, rate, dst_channels, dst_rate, dst_bits):
        """Interleaved 16-bit samples -> PCM bytes in another layout (nearest
        neighbour resampling, stereo is mixed down by averaging)"""
        if channels == 2 and dst_channels == 1:
            samples = array.array('h', ((a + b) >> 1 for a, b in
                                        zip(samples[0::2], samples[1::2])))
        elif channels == 1 and dst_channels == 2:
            stereo = array.array('h', bytes(4 * len(samples)))
            stereo[0::2] = samples
            stereo[1::2] = samples
            samples = stereo
        if rate != dst_rate and rate > 0:
            frames = len(samples) // dst_channels
            count = frames * dst_rate // rate
            if dst_channels == 1:
                samples = array.array('h', (samples[i * rate // dst_rate]
                                            for i in range(count)))
            else:
                resampled = array.array('h', bytes(4 * count))
                for c in range(dst_channels):
                    channel = samples[c::dst_channels]
                    resampled[c::dst_channels] = array.array(
                        'h', (channel[i * rate // dst_rate] for i in range(count)))
                samples = resampled
        if dst_bits == 8:
            return bytes(((v >> 8) + 128) & 0xFF for v in samples)
        if sys.byteorder != 'little':
            samples = array.array('h', samples)
            samples.byteswap()
        return samples.tobytes()

    MS_ADPCM_ADAPT = (230, 230, 230, 230, 307, 409, 512, 614,
                      768, 614, 512, 409, 307, 230, 230, 230)
    MS_ADPCM_COEFS = ((256, 0), (512, -256), (0, 0), (192, 64),
                      (240, 0), (460, -208), (392, -232))
    IMA_INDEX = (-1, -1, -1, -1, 2, 4, 6, 8, -1, -1, -1, -1, 2, 4, 6, 8)
    IMA_STEPS = (
        7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 19, 21, 23, 25, 28, 31, 34, 37, 41, 45,
        50, 55, 60, 66, 73, 80, 88, 97, 107, 118, 130, 143, 157, 173, 190, 209, 230,
        253, 279, 307, 337, 371, 408, 449, 494, 544, 598, 658, 724, 796, 876, 963,
        1060, 1166, 1282, 1411, 1552, 1707, 1878, 2066, 2272, 2499, 2749, 3024, 3327,
        3660, 4026, 4428, 4871, 5358, 5894, 6484, 7132, 7845, 8630, 9493, 10442, 11487,
        12635, 13899, 15289, 16818, 18500, 20350, 22385, 24623, 27086, 29794, 32767)

    @classmethod
    def _decode_ms_adpcm(cls, data, fmt):
        """Microsoft ADPCM blocks -> interleaved 16-bit samples"""
        channels, align = fmt['channels'], fmt['align']
        coefs = list(cls.MS_ADPCM_COEFS)
        extra = fmt['extra']
        if len(extra) >= 4:
            count = struct.unpack_from('<H', extra, 2)[0]
            if len(extra) >= 4 + 4 * count:
                coefs = [struct.unpack_from('<hh', extra, 4 + 4 * i) for i in range(count)]
        out = array.array('h')
        for start in range(0, len(data), align):
            block = data[start:start + align]
            if len(block) < 7 * channels:
                break
            pos = 0
            predictors = list(block[pos:pos + channels])
            pos += channels
            delta = list(struct.unpack_from(f'<{channels}h', block, pos))
            pos += 2 * channels
            s1 = list(struct.unpack_from(f'<{channels}h', block, pos))
            pos += 2 * channels
            s2 = list(struct.unpack_from(f'<{channels}h', block, pos))
            pos += 2 * channels
            out.extend(s2)
            out.extend(s1)
            c1 = [coefs[p][0] if p < len(coefs) else 0 for p in predictors]
            c2 = [coefs[p][1] if p < len(coefs) else 0 for p in predictors]
            ch = 0
            for byte in block[pos:]:
                for nibble in (byte >> 4, byte & 0x0F):
                    signed = nibble - 16 if nibble >= 8 else nibble
                    sample = ((s1[ch] * c1[ch] + s2[ch] * c2[ch]) >> 8) + signed * delta[ch]
                    sample = max(-32768, min(32767, sample))
                    s2[ch], s1[ch] = s1[ch], sample
                    delta[ch] = max(16, (cls.MS_ADPCM_ADAPT[nibble] * delta[ch]) >> 8)
                    out.append(sample)
                    ch = (ch + 1) % channels
        return out

    @classmethod
    def _decode_ima_adpcm(cls, data, fmt):
        """IMA (DVI) ADPCM blocks -> interleaved 16-bit samples"""
        channels, align = fmt['channels'], fmt['align']
        out = array.array('h')
        for start in range(0, len(data), align):
            block = data[start:start + align]
            if len(block) < 4 * channels:
                break
            predictor, index = [], []
            for c in range(channels):
                sample, idx = struct.unpack_from('<hB', block, 4 * c)
                predictor.append(sample)
                index.append(min(88, idx))
            body = block[4 * channels:]
            chunks = len(body) // (4 * channels)
            decoded = [[] for _ in range(channels)]
            for chunk in range(chunks):
                for c in range(channels):
                    base = (chunk * channels + c) * 4
                    for byte in body[base:base + 4]:
                        for nibble in (byte & 0x0F, byte >> 4):
                            step = cls.IMA_STEPS[index[c]]
                            diff = step >> 3
                            if nibble & 4:
                                diff += step
                            if nibble & 2:
                                diff += step >> 1
                            if nibble & 1:
                                diff += step >> 2
                            if nibble & 8:
                                diff = -diff
                            predictor[c] = max(-32768, min(32767, predictor[c] + diff))
                            index[c] = max(0, min(88, index[c] + cls.IMA_INDEX[nibble]))
                            decoded[c].append(predictor[c])
            first = [struct.unpack_from('<h', block, 4 * c)[0] for c in range(channels)]
            out.extend(first)
            for i in range(len(decoded[0])):
                out.extend(decoded[c][i] for c in range(channels))
        return out

    def _decode_audio(self, data, fmt):
        """Audio bytes in a supported WAVEFORMAT -> interleaved 16-bit samples, or None"""
        if fmt['tag'] == 1 and fmt['bits'] in (8, 16):
            return self._pcm_samples(data, fmt['bits'])
        if fmt['tag'] == 2 and fmt['align']:
            return self._decode_ms_adpcm(data, fmt)
        if fmt['tag'] == 0x11 and fmt['align']:
            return self._decode_ima_adpcm(data, fmt)
        return None

    # ---------- Wave output (waveOut*) ----------

    WOM_OPEN, WOM_CLOSE, WOM_DONE = 0x3BB, 0x3BC, 0x3BD
    WHDR_DONE, WHDR_PREPARED, WHDR_INQUEUE = 0x01, 0x02, 0x10

    def _wave_callback(self, hwo, dev, message, param1=0):
        """Notify the waveOut client (window, thread or callback function)"""
        kind, callback = dev['callback_type'], dev['callback']
        if not callback and kind != 0x20000:
            return
        if kind == 0x10000:      # CALLBACK_WINDOW
            self.post_window_message(callback, message, hwo, param1)
        elif kind == 0x20000:    # CALLBACK_THREAD
            self.post_window_message(0, message, hwo, param1)
        elif kind == 0x30000:    # CALLBACK_FUNCTION
            self.emu.call_callback(callback, [hwo, message, dev['instance'], param1, 0])

    def _wave_done(self, hwo, dev, pwh):
        """Hand a played buffer back to the application"""
        try:
            flags = struct.unpack('<I', self.emu.uc.mem_read(pwh + 16, 4))[0]
            flags = (flags | self.WHDR_DONE) & ~self.WHDR_INQUEUE
            self.emu.uc.mem_write(pwh + 16, struct.pack('<I', flags))
        except UcError:
            return
        self._wave_callback(hwo, dev, self.WOM_DONE, pwh)

    def _wave_feed(self, dev):
        """Keep the device's mixer channel supplied with converted buffers"""
        channel = dev['channel']
        while dev['pending'] and channel is not None:
            try:
                if not channel.get_busy():
                    channel.play(dev['pending'].pop(0))
                elif channel.get_queue() is None:
                    channel.queue(dev['pending'].pop(0))
                else:
                    break
            except pygame.error:
                dev['pending'].clear()

    def _audio_pump(self):
        """Advance wave output and MCI playback: completes played buffers
        (WOM_DONE) and reports finished MCI plays (MM_MCINOTIFY)"""
        if getattr(self, '_audio_pumping', False):
            return
        self._audio_pumping = True
        try:
            now = time.time()
            for hwo, dev in list(self.wave_outs.items()):
                self._wave_feed(dev)
                if dev['paused_at'] is not None:
                    continue
                while dev['queue'] and dev['queue'][0]['end'] <= now:
                    entry = dev['queue'].pop(0)
                    dev['done_bytes'] += entry['length']
                    self._wave_done(hwo, dev, entry['hdr'])
            for device_id, device in list(self.mci_devices.items()):
                if device['mode'] == 526 and self._mci_finished(device):
                    device['mode'] = 525
                    device['offset'] = device['length']
                    self._mci_notify(device_id, device, 1)  # MCI_NOTIFY_SUCCESSFUL
        finally:
            self._audio_pumping = False

    def waveOutOpen(self, args):
        """waveOutOpen emulation - PCM output through the pygame mixer"""
        phwo, device_id, pwfx, dwCallback, dwInstance, fdwOpen = args[:6]
        fmt = self._read_waveformat(self.emu.uc, pwfx)
        if fmt is None:
            return 11  # MMSYSERR_INVALPARAM
        log.info(f"waveOutOpen(format {fmt['tag']}, {fmt['channels']} ch, "
                 f"{fmt['rate']} Hz, {fmt['bits']} bit)")
        if device_id not in (0, 0xFFFFFFFF, 0xFFFF):
            return 2  # MMSYSERR_BADDEVICEID
        if (fmt['tag'] != 1 or fmt['bits'] not in (8, 16) or fmt['channels'] not in (1, 2)
                or not fmt['rate'] or not fmt['align']):
            return 32  # WAVERR_BADFORMAT
        if fdwOpen & 0x1:  # WAVE_FORMAT_QUERY
            return 0
        channel = None
        if SoundPlayer.available():
            try:
                channel = pygame.mixer.find_channel()
            except pygame.error:
                channel = None
        hwo = self.get_next_handle()
        dev = {'format': fmt, 'callback': dwCallback, 'instance': dwInstance,
               'callback_type': fdwOpen & 0x70000, 'queue': [], 'pending': [],
               'channel': channel, 'paused_at': None, 'done_bytes': 0}
        self.wave_outs[hwo] = dev
        if phwo and not self._mem_write(phwo, struct.pack('<I', hwo)):
            del self.wave_outs[hwo]
            return 11
        self._wave_callback(hwo, dev, self.WOM_OPEN)
        return 0

    def _wave_header_flags(self, pwh):
        try:
            return struct.unpack('<I', self.emu.uc.mem_read(pwh + 16, 4))[0]
        except UcError:
            return None

    def waveOutPrepareHeader(self, args):
        """waveOutPrepareHeader emulation"""
        if args[0] not in self.wave_outs:
            return 5  # MMSYSERR_INVALHANDLE
        flags = self._wave_header_flags(args[1])
        if flags is None:
            return 11
        self._mem_write(args[1] + 16, struct.pack('<I', flags | self.WHDR_PREPARED))
        return 0

    def waveOutUnprepareHeader(self, args):
        """waveOutUnprepareHeader emulation"""
        if args[0] not in self.wave_outs:
            return 5
        flags = self._wave_header_flags(args[1])
        if flags is None:
            return 11
        if flags & self.WHDR_INQUEUE:
            return 33  # WAVERR_STILLPLAYING
        self._mem_write(args[1] + 16, struct.pack('<I', flags & ~self.WHDR_PREPARED))
        return 0

    def waveOutWrite(self, args):
        """waveOutWrite emulation - queue a buffer; it is done after its play time"""
        hwo, pwh = args[0], args[1]
        dev = self.wave_outs.get(hwo)
        if dev is None:
            return 5
        try:
            lpData, length = struct.unpack('<II', self.emu.uc.mem_read(pwh, 8))
            flags = struct.unpack('<I', self.emu.uc.mem_read(pwh + 16, 4))[0]
            data = bytes(self.emu.uc.mem_read(lpData, length)) if length else b''
        except UcError:
            return 11
        if not flags & self.WHDR_PREPARED:
            return 34  # WAVERR_UNPREPARED
        self._mem_write(pwh + 16, struct.pack(
            '<I', (flags | self.WHDR_INQUEUE) & ~self.WHDR_DONE))
        fmt = dev['format']
        now = dev['paused_at'] if dev['paused_at'] is not None else time.time()
        start = max(now, dev['queue'][-1]['end']) if dev['queue'] else now
        duration = length / (fmt['avg'] or fmt['rate'] * fmt['align'])
        dev['queue'].append({'hdr': pwh, 'start': start, 'end': start + duration,
                             'length': length})
        mixer = SoundPlayer._mixer() if dev['channel'] is not None else None
        if mixer and mixer[1] == -16 and data:
            pcm = self._convert_samples(self._pcm_samples(data, fmt['bits']),
                                        fmt['channels'], fmt['rate'],
                                        mixer[2], mixer[0], 16)
            try:
                dev['pending'].append(pygame.mixer.Sound(buffer=pcm))
            except pygame.error as e:
                log.debug(f"waveOutWrite: cannot play buffer: {e}")
            if dev['paused_at'] is None:
                self._wave_feed(dev)
        return 0

    def _wave_stop_channel(self, dev):
        dev['pending'].clear()
        if dev['channel'] is not None:
            try:
                dev['channel'].stop()
            except pygame.error:
                pass

    def waveOutReset(self, args):
        """waveOutReset emulation - stop and return all buffers"""
        hwo = args[0]
        dev = self.wave_outs.get(hwo)
        if dev is None:
            return 5
        self._wave_stop_channel(dev)
        queue, dev['queue'] = dev['queue'], []
        dev['done_bytes'] = 0
        if dev['paused_at'] is not None:
            dev['paused_at'] = time.time()
        for entry in queue:
            self._wave_done(hwo, dev, entry['hdr'])
        return 0

    def waveOutPause(self, args):
        """waveOutPause emulation"""
        dev = self.wave_outs.get(args[0])
        if dev is None:
            return 5
        if dev['paused_at'] is None:
            dev['paused_at'] = time.time()
            if dev['channel'] is not None:
                dev['channel'].pause()
        return 0

    def waveOutRestart(self, args):
        """waveOutRestart emulation - continue after waveOutPause"""
        dev = self.wave_outs.get(args[0])
        if dev is None:
            return 5
        if dev['paused_at'] is not None:
            shift = time.time() - dev['paused_at']
            for entry in dev['queue']:
                entry['start'] += shift
                entry['end'] += shift
            dev['paused_at'] = None
            if dev['channel'] is not None:
                dev['channel'].unpause()
            self._wave_feed(dev)
        return 0

    def waveOutClose(self, args):
        """waveOutClose emulation"""
        hwo = args[0]
        dev = self.wave_outs.get(hwo)
        if dev is None:
            return 5
        self._audio_pump()
        if dev['queue']:
            return 33  # WAVERR_STILLPLAYING
        self._wave_stop_channel(dev)
        del self.wave_outs[hwo]
        self._wave_callback(hwo, dev, self.WOM_CLOSE)
        return 0

    def waveOutGetPosition(self, args):
        """waveOutGetPosition emulation - bytes, samples or milliseconds played"""
        hwo, pmmt = args[0], args[1]
        dev = self.wave_outs.get(hwo)
        if dev is None:
            return 5
        fmt = dev['format']
        played = dev['done_bytes']
        if dev['queue']:
            entry = dev['queue'][0]
            now = dev['paused_at'] if dev['paused_at'] is not None else time.time()
            span = entry['end'] - entry['start']
            fraction = min(1.0, max(0.0, (now - entry['start']) / span)) if span > 0 else 1.0
            played += int(entry['length'] * fraction) // fmt['align'] * fmt['align']
        try:
            kind = struct.unpack('<I', self.emu.uc.mem_read(pmmt, 4))[0]
        except UcError:
            return 11
        if kind == 2:     # TIME_SAMPLES
            value = played // fmt['align']
        elif kind == 1:   # TIME_MS
            value = played * 1000 // (fmt['avg'] or 1)
        else:
            kind, value = 4, played  # TIME_BYTES
        self._mem_write(pmmt, struct.pack('<II', kind, value & 0xFFFFFFFF))
        return 0

    # ---------- Audio compression manager (msacm32) ----------

    def acmFormatSuggest(self, args):
        """acmFormatSuggest emulation - always suggests 16-bit PCM"""
        pwfxSrc, pwfxDst, cbwfxDst, fdwSuggest = args[1], args[2], args[3], args[4]
        src = self._read_waveformat(self.emu.uc, pwfxSrc)
        if src is None or cbwfxDst < 16:
            return 11  # MMSYSERR_INVALPARAM
        dst = self._read_waveformat(self.emu.uc, pwfxDst) or {}
        channels = dst.get('channels') if fdwSuggest & 0x20000 else src['channels']
        rate = dst.get('rate') if fdwSuggest & 0x40000 else src['rate']
        bits = dst.get('bits') if fdwSuggest & 0x80000 else 16
        if (fdwSuggest & 0x10000 and dst.get('tag') != 1) or bits not in (8, 16) \
                or channels not in (1, 2) or src['channels'] not in (1, 2):
            return 512  # ACMERR_NOTPOSSIBLE
        align = channels * bits // 8
        data = struct.pack('<HHIIHH', 1, channels, rate, rate * align, align, bits)
        if cbwfxDst >= 18:
            data += b'\x00\x00'
        return 0 if self._mem_write(pwfxDst, data) else 11

    def acmStreamOpen(self, args):
        """acmStreamOpen emulation - PCM, MS ADPCM and IMA ADPCM to PCM"""
        phas, _, pwfxSrc, pwfxDst, _, _, _, fdwOpen = args[:8]
        src = self._read_waveformat(self.emu.uc, pwfxSrc)
        dst = self._read_waveformat(self.emu.uc, pwfxDst)
        if src is None or dst is None:
            return 11
        log.info(f"acmStreamOpen(src tag {src['tag']}, {src['channels']} ch, {src['rate']} Hz, "
                 f"{src['bits']} bit -> dst tag {dst['tag']}, {dst['channels']} ch, "
                 f"{dst['rate']} Hz, {dst['bits']} bit)")
        if (src['tag'] not in (1, 2, 0x11) or dst['tag'] != 1 or dst['bits'] not in (8, 16)
                or src['channels'] not in (1, 2) or dst['channels'] not in (1, 2)
                or (src['tag'] == 1 and src['bits'] not in (8, 16))
                or not src['align'] or not dst['align'] or not src['rate']):
            return 512  # ACMERR_NOTPOSSIBLE
        if fdwOpen & 0x1:  # ACM_STREAMOPENF_QUERY
            return 0
        has = self.get_next_handle()
        self.acm_streams[has] = {'src': src, 'dst': dst}
        if phas and not self._mem_write(phas, struct.pack('<I', has)):
            del self.acm_streams[has]
            return 11
        return 0

    def acmStreamClose(self, args):
        """acmStreamClose emulation"""
        return 0 if self.acm_streams.pop(args[0], None) is not None else 5

    def acmStreamSize(self, args):
        """acmStreamSize emulation - output size for an input size or vice versa"""
        stream = self.acm_streams.get(args[0])
        if stream is None:
            return 5
        cb, pdwOutput, flags = args[1], args[2], args[3]
        src, dst = stream['src'], stream['dst']

        def samples_per_block(fmt):
            if fmt['tag'] == 1:
                return 1
            if len(fmt['extra']) >= 2:
                return struct.unpack_from('<H', fmt['extra'])[0] or 1
            return 1

        src_frames = samples_per_block(src)
        if flags & 0x0F == 1:  # ACM_STREAMSIZEF_DESTINATION
            frames = cb // dst['align'] * src['rate'] // dst['rate']
            size = -(-frames // src_frames) * src['align']
        else:                  # ACM_STREAMSIZEF_SOURCE
            frames = -(-cb // src['align']) * src_frames
            size = -(-frames * dst['rate'] // src['rate']) * dst['align']
        return 0 if self._mem_write(pdwOutput, struct.pack('<I', size)) else 11

    def _acm_header_status(self, pash, set_flags=0, clear_flags=0):
        try:
            status = struct.unpack('<I', self.emu.uc.mem_read(pash + 4, 4))[0]
        except UcError:
            return None
        status = (status | set_flags) & ~clear_flags
        self._mem_write(pash + 4, struct.pack('<I', status))
        return status

    def acmStreamPrepareHeader(self, args):
        """acmStreamPrepareHeader emulation"""
        if args[0] not in self.acm_streams:
            return 5
        return 0 if self._acm_header_status(args[1], 0x20000) is not None else 11

    def acmStreamUnprepareHeader(self, args):
        """acmStreamUnprepareHeader emulation"""
        if args[0] not in self.acm_streams:
            return 5
        return 0 if self._acm_header_status(args[1], 0, 0x20000) is not None else 11

    def acmStreamConvert(self, args):
        """acmStreamConvert emulation - decodes/converts a whole source buffer"""
        stream = self.acm_streams.get(args[0])
        if stream is None:
            return 5
        pash = args[1]
        src, dst = stream['src'], stream['dst']
        try:
            (pbSrc, cbSrc, _, _, pbDst, cbDst) = struct.unpack(
                '<IIIIII', self.emu.uc.mem_read(pash + 12, 24))
            data = bytes(self.emu.uc.mem_read(pbSrc, cbSrc)) if cbSrc else b''
        except UcError:
            return 11
        if src['tag'] == 1:
            data = data[:len(data) // src['align'] * src['align']]
        samples = self._decode_audio(data, src)
        out = self._convert_samples(samples, src['channels'], src['rate'], dst['channels'],
                                    dst['rate'], dst['bits']) if samples else b''
        out = out[:cbDst // dst['align'] * dst['align']]
        if out and not self._mem_write(pbDst, out):
            return 11
        self._mem_write(pash + 20, struct.pack('<I', len(data)))
        self._mem_write(pash + 36, struct.pack('<I', len(out)))
        self._acm_header_status(pash, 0x10000)  # ACMSTREAMHEADER_STATUSF_DONE
        return 0

    # ---------- Joystick ----------

    def joyGetPos(self, args):
        """joyGetPos emulation - no joystick is connected"""
        return 167  # JOYERR_UNPLUGGED

    def joyGetDevCapsA(self, args):
        """joyGetDevCapsA emulation - no joystick driver"""
        return 165  # JOYERR_PARMS

    # ---------- Media control interface (mciSendCommandA) ----------

    MM_MCINOTIFY = 0x3B9
    MCI_DEVICE_TYPES = {0x201: 'animation', 0x202: 'cdaudio', 0x203: 'dat',
                        0x204: 'digitalvideo', 0x205: 'other', 0x206: 'overlay',
                        0x207: 'scanner', 0x208: 'sequencer', 0x209: 'vcr',
                        0x20A: 'waveaudio', 0x20B: 'mmmovie'}

    def _mci_notify(self, device_id, device, code):
        """Post MM_MCINOTIFY for a pending notification (MCI_NOTIFY_*)"""
        hwnd, device['notify'] = device.get('notify'), None
        if hwnd:
            self.post_window_message(hwnd, self.MM_MCINOTIFY, code, device_id)

    def _mci_position(self, device):
        """Current position of an MCI device (milliseconds)"""
        if device['mode'] == 526:
            position = device['offset'] + (time.time() - device['started']) * 1000
            return int(min(position, device['length'])) if device['length'] else int(position)
        return int(device['offset'])

    def _mci_finished(self, device):
        """True when a playing device reached its end (or its MCI_TO point)"""
        if device.get('to') is not None and self._mci_position(device) >= device['to']:
            self._mci_stop_music(device)
            return True
        if device['music']:
            try:
                return SoundPlayer.available() and not pygame.mixer.music.get_busy()
            except pygame.error:
                return True
        return bool(device['length']) and self._mci_position(device) >= device['length']

    def _mci_stop_music(self, device):
        if device['music'] and getattr(WinAPIHandler, '_mci_music_owner', None) is device:
            try:
                pygame.mixer.music.stop()
            except pygame.error:
                pass
            WinAPIHandler._mci_music_owner = None

    @staticmethod
    def _media_length_ms(path):
        """Length of a WAV file (ms); 0 when unknown"""
        try:
            with wave.open(path, 'rb') as wav:
                return wav.getnframes() * 1000 // max(1, wav.getframerate())
        except (wave.Error, OSError, EOFError):
            pass
        if PYGAME_AVAILABLE and SoundPlayer.available():
            try:
                return int(pygame.mixer.Sound(path).get_length() * 1000)
            except (pygame.error, OSError):
                pass
        return 0

    def _mci_open(self, flags, params):
        try:
            _, _, lpType, lpElement, lpAlias = struct.unpack(
                '<5I', self.emu.uc.mem_read(params, 20))
        except UcError:
            return 11
        dev_type = ''
        if flags & 0x2000:  # MCI_OPEN_TYPE
            if flags & 0x1000:  # MCI_OPEN_TYPE_ID
                dev_type = self.MCI_DEVICE_TYPES.get(lpType & 0xFFFF, '')
            elif lpType:
                dev_type = self.read_string(lpType).lower()
        element = self.read_string(lpElement) if flags & 0x200 and lpElement else ''
        alias = self.read_string(lpAlias) if flags & 0x400 and lpAlias else ''
        if not dev_type and element:
            ext = os.path.splitext(element)[1].lower()
            dev_type = {'.wav': 'waveaudio', '.mid': 'sequencer', '.rmi': 'sequencer',
                        '.avi': 'avivideo'}.get(ext, '')
        log.info(f"mciSendCommandA(MCI_OPEN, type={dev_type!r}, element={element!r})")
        if dev_type not in ('waveaudio', 'sequencer'):
            return 263  # MCIERR_INVALID_DEVICE_NAME
        path = None
        if element:
            path = self.resolve_c_drive_path(element)
            if path is None or not os.path.isfile(path):
                return 275  # MCIERR_FILE_NOT_FOUND
        device_id = self.next_mci_id
        self.next_mci_id += 1
        self.mci_devices[device_id] = {
            'type': dev_type, 'path': path, 'alias': alias, 'mode': 525,
            'offset': 0, 'started': 0, 'to': None, 'notify': None,
            'length': self._media_length_ms(path) if path else 0,
            'music': False, 'time_format': 0}
        self._mem_write(params + 4, struct.pack('<I', device_id))
        return 0

    def _mci_play(self, device_id, device, flags, params):
        try:
            _, start, end = struct.unpack('<3I', self.emu.uc.mem_read(params, 12))
        except UcError:
            start = end = 0
        if not device['path']:
            return 263
        if device.get('notify'):
            self._mci_notify(device_id, device, 2)  # MCI_NOTIFY_SUPERSEDED
        if flags & 0x4:  # MCI_FROM
            device['offset'] = start
        elif device['length'] and device['offset'] >= device['length']:
            device['offset'] = 0
        device['to'] = end if flags & 0x8 else None
        device['music'] = False
        if SoundPlayer.available():
            owner = getattr(WinAPIHandler, '_mci_music_owner', None)
            if owner is not None and owner is not device:
                owner['offset'] = int(owner['offset'])
                owner['mode'] = 525
            try:
                pygame.mixer.music.load(device['path'])
                try:
                    pygame.mixer.music.play(start=device['offset'] / 1000.0)
                except pygame.error:
                    pygame.mixer.music.play()
                device['music'] = True
                WinAPIHandler._mci_music_owner = device
            except pygame.error as e:
                log.warning(f"MCI: cannot play {device['path']}: {e}")
        device['mode'] = 526
        device['started'] = time.time()
        return 0

    def mciSendCommandA(self, args):
        """mciSendCommandA emulation - waveaudio/sequencer files via the pygame mixer"""
        device_id, message, flags, params = args[:4]
        notify_hwnd = 0
        if flags & 0x1 and params:  # MCI_NOTIFY
            try:
                notify_hwnd = struct.unpack('<I', self.emu.uc.mem_read(params, 4))[0]
            except UcError:
                pass
        if message == 0x803:  # MCI_OPEN
            result = self._mci_open(flags, params)
            if result == 0 and notify_hwnd:
                opened = struct.unpack('<I', self.emu.uc.mem_read(params + 4, 4))[0]
                self.post_window_message(notify_hwnd, self.MM_MCINOTIFY, 1, opened)
            return result
        if message == 0x804 and device_id == 0xFFFF:  # MCI_CLOSE, MCI_ALL_DEVICE_ID
            for open_id in list(self.mci_devices):
                self.mciSendCommandA([open_id, message, 0, 0])
            return 0
        device = self.mci_devices.get(device_id)
        if device is None:
            return 257  # MCIERR_INVALID_DEVICE_ID
        log.debug(f"mciSendCommandA({device_id}, 0x{message:x}, flags=0x{flags:x})")
        result = 0
        if message == 0x804:  # MCI_CLOSE
            self._mci_stop_music(device)
            if device.get('notify'):
                self._mci_notify(device_id, device, 4)  # MCI_NOTIFY_ABORTED
            del self.mci_devices[device_id]
        elif message == 0x806:  # MCI_PLAY
            result = self._mci_play(device_id, device, flags, params)
            if result == 0 and notify_hwnd:
                device['notify'] = notify_hwnd
                notify_hwnd = 0  # Posted when the play ends
        elif message in (0x808, 0x809):  # MCI_STOP, MCI_PAUSE
            if device['mode'] == 526:
                device['offset'] = self._mci_position(device)
                if device['music'] and message == 0x809:
                    pygame.mixer.music.pause()
                else:
                    self._mci_stop_music(device)
                device['mode'] = 529 if message == 0x809 else 525
                if device.get('notify'):
                    self._mci_notify(device_id, device, 4)
        elif message == 0x855:  # MCI_RESUME
            if device['mode'] == 529:
                if device['music'] and getattr(WinAPIHandler, '_mci_music_owner', None) is device:
                    pygame.mixer.music.unpause()
                device['mode'] = 526
                device['started'] = time.time()
        elif message == 0x807:  # MCI_SEEK
            self._mci_stop_music(device)
            if flags & 0x100:    # MCI_SEEK_TO_START
                device['offset'] = 0
            elif flags & 0x200:  # MCI_SEEK_TO_END
                device['offset'] = device['length']
            elif flags & 0x8:    # MCI_TO
                device['offset'] = struct.unpack('<I', self.emu.uc.mem_read(params + 4, 4))[0]
            device['mode'] = 525
        elif message == 0x80D:  # MCI_SET
            if flags & 0x400:  # MCI_SET_TIME_FORMAT
                device['time_format'] = struct.unpack(
                    '<I', self.emu.uc.mem_read(params + 4, 4))[0]
        elif message == 0x814:  # MCI_STATUS
            if not flags & 0x100:  # MCI_STATUS_ITEM
                return 273  # MCIERR_MISSING_PARAMETER
            item = struct.unpack('<I', self.emu.uc.mem_read(params + 8, 4))[0]
            self._audio_pump()
            values = {1: device['length'], 2: self._mci_position(device), 3: 1,
                      4: device['mode'], 5: 1, 6: device['time_format'], 7: 1, 8: 1}
            if item not in values:
                return 290  # MCIERR_BAD_CONSTANT
            self._mem_write(params + 4, struct.pack('<I', values[item] & 0xFFFFFFFF))
        else:
            log.warning(f"mciSendCommandA: command 0x{message:x} is not supported")
            return 274  # MCIERR_UNSUPPORTED_FUNCTION
        if notify_hwnd:
            self.post_window_message(notify_hwnd, self.MM_MCINOTIFY, 1, device_id)
        return result

    SND_ASYNC = 0x0001
    SND_NODEFAULT = 0x0002
    SND_MEMORY = 0x0004
    SND_LOOP = 0x0008
    SND_NOSTOP = 0x0010
    SND_PURGE = 0x0040
    SND_ALIAS = 0x00010000
    SND_FILENAME = 0x00020000
    SND_RESOURCE = 0x00040004

    # PlaySound system sound aliases -> MessageBeep sound type
    SOUND_ALIASES = {
        'systemdefault': 0x00, '.default': 0x00, 'systemasterisk': 0x40,
        'systemexclamation': 0x30, 'systemhand': 0x10, 'systemquestion': 0x20,
        'systemstart': 0x40, 'systemexit': 0x40,
    }

    def _read_wav_memory(self, address):
        """Read a RIFF/WAVE image from emulated memory (SND_MEMORY)"""
        try:
            header = bytes(self.emu.uc.mem_read(address, 8))
            if header[:4] != b'RIFF':
                return None
            size = struct.unpack('<I', header[4:8])[0] + 8
            return bytes(self.emu.uc.mem_read(address, min(size, 64 * 1024 * 1024)))
        except UcError:
            return None

    def _play_sound_common(self, pszSound, flags, wide):
        """Shared PlaySound/sndPlaySound logic; returns TRUE/FALSE"""
        if not pszSound or (flags & self.SND_PURGE):
            log.debug("PlaySound(NULL) - stop")
            SoundPlayer.stop_owned_by(self)
            return 1
        if (flags & self.SND_NOSTOP) and SoundPlayer.playing():
            return 0
        loop = bool(flags & self.SND_LOOP) and bool(flags & self.SND_ASYNC)

        length = None
        if (flags & self.SND_RESOURCE) == self.SND_RESOURCE:
            log.debug("PlaySound(SND_RESOURCE) - resources are not supported")
        elif flags & self.SND_MEMORY:
            data = self._read_wav_memory(pszSound)
            log.debug(f"PlaySound(memory 0x{pszSound:08x}, 0x{flags:x})")
            if data is not None:
                length = SoundPlayer.play(io.BytesIO(data), loop, owner=self)
        else:
            name = self._read_text(pszSound, wide)
            log.debug(f"PlaySound(\"{name}\", 0x{flags:x})")
            alias = self.SOUND_ALIASES.get(name.lower())
            if alias is not None and not (flags & self.SND_FILENAME):
                frequency, duration = self.SYSTEM_SOUND_TONES[alias]
                SoundPlayer.play_tone(frequency, duration, owner=self)
                length = duration / 1000.0
            elif not (flags & self.SND_ALIAS):
                path = self.resolve_c_drive_path(name)
                if path is None or not os.path.isfile(path):
                    # Windows also tries the name with a .wav extension
                    path = self.resolve_c_drive_path(name + '.wav')
                if path is not None and os.path.isfile(path):
                    length = SoundPlayer.play(path, loop, owner=self)

        if length is None:
            if not (flags & self.SND_NODEFAULT):
                SoundPlayer.tone(*self.SYSTEM_SOUND_TONES[0])
            return 0
        if not (flags & self.SND_ASYNC):
            # SND_SYNC: return once the sound has finished
            self._wait_ms(int(length * 1000),
                          until=SoundPlayer.playing if SoundPlayer.available() else None)
        return 1

    def PlaySoundA(self, args, wide=False):
        """PlaySoundA/W emulation (winmm) - WAV files in c_drive/, memory
        images and system sound aliases"""
        return self._play_sound_common(args[0], args[2], wide)

    def PlaySoundW(self, args):
        return self.PlaySoundA(args, wide=True)

    def sndPlaySoundA(self, args, wide=False):
        """sndPlaySoundA/W emulation (winmm) - alias or file name"""
        flags = args[1] & (self.SND_ASYNC | self.SND_NODEFAULT | self.SND_MEMORY |
                           self.SND_LOOP | self.SND_NOSTOP)
        return self._play_sound_common(args[0], flags, wide)

    def sndPlaySoundW(self, args):
        return self.sndPlaySoundA(args, wide=True)

    # ---------- Scrollbar APIs (user32) ----------

    def _scrollbar_control(self, hwnd, nBar):
        """Resolve a scrollbar target to its FakeControl (SB_CTL only).

        Standard window scrollbars (SB_HORZ/SB_VERT on a window handle) are
        not emulated; only SCROLLBAR controls carry scroll state.
        """
        if self.gui and hwnd in self.gui.controls:
            control = self.gui.controls[hwnd]
            if control.class_name == "SCROLLBAR":
                return control
        if nBar != self.SB_CTL:
            log.debug(f"Standard window scrollbar (nBar={nBar}) not emulated")
        return None

    @staticmethod
    def scroll_pos_max(control):
        """Highest legal scroll position (Windows: max - page + 1 if page set)"""
        if control.scroll_page > 0:
            return max(control.scroll_min,
                       control.scroll_max - control.scroll_page + 1)
        return control.scroll_max

    def _clamp_scroll_pos(self, control, pos):
        return max(control.scroll_min, min(pos, self.scroll_pos_max(control)))

    def SetScrollPos(self, args):
        """SetScrollPos emulation"""
        hWnd, nBar = args[0], args[1]
        nPos = args[2] - 0x100000000 if args[2] >= 0x80000000 else args[2]
        control = self._scrollbar_control(hWnd, nBar)
        if not control:
            return 0
        prev = control.scroll_pos
        control.scroll_pos = self._clamp_scroll_pos(control, nPos)
        log.debug(f"SetScrollPos(0x{hWnd:x}, {nPos}) -> prev {prev}")
        return prev & 0xFFFFFFFF

    def GetScrollPos(self, args):
        """GetScrollPos emulation"""
        control = self._scrollbar_control(args[0], args[1])
        return (control.scroll_pos & 0xFFFFFFFF) if control else 0

    def SetScrollRange(self, args):
        """SetScrollRange emulation"""
        hWnd, nBar = args[0], args[1]
        nMin, nMax = self._read_signed_args(args, 2, 2)
        control = self._scrollbar_control(hWnd, nBar)
        if not control:
            return 0
        control.scroll_min = min(nMin, nMax)
        control.scroll_max = max(nMin, nMax)
        control.scroll_pos = self._clamp_scroll_pos(control, control.scroll_pos)
        log.debug(f"SetScrollRange(0x{hWnd:x}, {nMin}..{nMax})")
        return 1

    def GetScrollRange(self, args):
        """GetScrollRange emulation"""
        control = self._scrollbar_control(args[0], args[1])
        lpMin, lpMax = args[2], args[3]
        if not control:
            return 0
        try:
            if lpMin:
                self.emu.uc.mem_write(lpMin, struct.pack("<i", control.scroll_min))
            if lpMax:
                self.emu.uc.mem_write(lpMax, struct.pack("<i", control.scroll_max))
        except UcError:
            return 0
        return 1

    # SCROLLINFO fMask flags
    SIF_RANGE = 0x0001
    SIF_PAGE = 0x0002
    SIF_POS = 0x0004
    SIF_TRACKPOS = 0x0010

    def SetScrollInfo(self, args):
        """SetScrollInfo emulation"""
        hWnd, nBar, lpsi = args[0], args[1], args[2]
        control = self._scrollbar_control(hWnd, nBar)
        if not control or not lpsi:
            return 0
        try:
            # SCROLLINFO: cbSize, fMask, nMin, nMax, nPage, nPos, nTrackPos
            data = self.emu.uc.mem_read(lpsi, 28)
            _, fMask, nMin, nMax, nPage, nPos, _ = struct.unpack("<IIiiIii", data)
        except UcError:
            return 0
        if fMask & self.SIF_RANGE:
            control.scroll_min = min(nMin, nMax)
            control.scroll_max = max(nMin, nMax)
        if fMask & self.SIF_PAGE:
            control.scroll_page = nPage
        if fMask & self.SIF_POS:
            control.scroll_pos = nPos
        control.scroll_pos = self._clamp_scroll_pos(control, control.scroll_pos)
        log.debug(f"SetScrollInfo(0x{hWnd:x}, mask=0x{fMask:x}) -> pos {control.scroll_pos}")
        return control.scroll_pos & 0xFFFFFFFF

    def GetScrollInfo(self, args):
        """GetScrollInfo emulation"""
        hWnd, nBar, lpsi = args[0], args[1], args[2]
        control = self._scrollbar_control(hWnd, nBar)
        if not control or not lpsi:
            return 0
        try:
            # Preserve the caller's cbSize and fMask, fill everything else
            head = self.emu.uc.mem_read(lpsi, 8)
            data = head + struct.pack("<iiIii", control.scroll_min,
                                      control.scroll_max, control.scroll_page,
                                      control.scroll_pos, control.scroll_pos)
            self.emu.uc.mem_write(lpsi, bytes(data))
        except UcError:
            return 0
        return 1

    def SendMessageA(self, args, wide=False):
        """SendMessageA/W emulation"""
        hWnd = args[0]
        Msg = args[1]
        wParam = args[2]
        lParam = args[3]

        msg_names = {
            0x0001: "WM_CREATE", 0x0002: "WM_DESTROY", 0x000F: "WM_PAINT",
            0x0010: "WM_CLOSE", 0x0012: "WM_QUIT", 0x0100: "WM_KEYDOWN",
            0x0111: "WM_COMMAND", 0x000C: "WM_SETTEXT", 0x000D: "WM_GETTEXT",
        }
        msg_name = msg_names.get(Msg, f"0x{Msg:04x}")

        log.debug(f"SendMessageA(0x{hWnd:x}, {msg_name}, 0x{wParam:x}, 0x{lParam:x})")

        # Text messages are handled directly (also work for controls)
        WM_SETTEXT, WM_GETTEXT, WM_GETTEXTLENGTH = 0x000C, 0x000D, 0x000E
        if Msg == WM_SETTEXT:
            return self.SetWindowTextA([hWnd, lParam], wide)
        if Msg == WM_GETTEXT:
            return self.GetWindowTextA([hWnd, lParam, wParam], wide)
        if Msg == WM_GETTEXTLENGTH:
            text = self.gui.get_window_text(hWnd) if self.gui else ""
            return len(text)

        # Control messages (LISTBOX, COMBOBOX, checkbox BUTTON)
        if self.gui and hWnd in self.gui.controls:
            return self._control_message(self.gui.controls[hWnd], Msg, wParam, lParam, wide)

        # Other messages: deliver synchronously to the window's WndProc
        wndproc = self._find_wndproc_for_hwnd(hWnd)
        if wndproc:
            return self.emu.call_wndproc(wndproc, hWnd, Msg, wParam, lParam)
        return 0

    def SendMessageW(self, args):
        return self.SendMessageA(args, wide=True)

    def _control_message(self, control, Msg, wParam, lParam, wide=False):
        """Handle a message sent to a child control (emulation thread).

        Item lists are swapped in as new list objects so the GUI thread can
        keep painting the snapshot it already holds.
        """
        items = control.items

        if control.class_name == 'STATUSBAR':
            result = self._status_bar_message(control, Msg, wParam, lParam, wide)
            if result is not None:
                return result

        WM_SETFONT, WM_GETFONT = 0x0030, 0x0031
        if Msg == WM_SETFONT:
            font = self.gdi_objects.get(wParam)
            control.font_handle = wParam
            control.font = font if font and font['type'] == 'font' else None
            return 0
        if Msg == WM_GETFONT:
            return control.font_handle

        # ----- Checkbox / button messages -----
        if Msg == self.BM_GETCHECK:
            return 1 if control.checked else 0
        if Msg == self.BM_SETCHECK:
            control.checked = bool(wParam)
            return 0

        # ----- Listbox messages -----
        if Msg == self.LB_ADDSTRING:
            control.items = items + [self._read_text(lParam, wide)]
            return len(control.items) - 1
        if Msg == self.LB_INSERTSTRING:
            index = len(items) if wParam >= len(items) else wParam
            control.items = items[:index] + [self._read_text(lParam, wide)] + items[index:]
            return index
        if Msg == self.LB_DELETESTRING:
            if wParam >= len(items):
                return self.LB_ERR
            control.items = items[:wParam] + items[wParam + 1:]
            if control.sel_index >= len(control.items):
                control.sel_index = -1
            return len(control.items)
        if Msg == self.LB_RESETCONTENT:
            control.items = []
            control.sel_index = -1
            return 0
        if Msg == self.LB_GETCOUNT:
            return len(items)
        if Msg == self.LB_GETCURSEL:
            return control.sel_index if control.sel_index >= 0 else self.LB_ERR
        if Msg == self.LB_SETCURSEL:
            if wParam == 0xFFFFFFFF:
                control.sel_index = -1
                return self.LB_ERR
            if wParam < len(items):
                control.sel_index = wParam
                return wParam
            return self.LB_ERR
        if Msg == self.LB_GETTEXT:
            if wParam >= len(items):
                return self.LB_ERR
            text = items[wParam]
            if lParam:
                if wide:
                    self.emu.uc.mem_write(lParam, text.encode('utf-16-le') + b'\x00\x00')
                else:
                    self.emu.uc.mem_write(lParam, text.encode(ANSI_CODEPAGE, errors='replace') + b'\x00')
            return len(text)
        if Msg == self.LB_GETTEXTLEN:
            return len(items[wParam]) if wParam < len(items) else self.LB_ERR

        # ----- Combobox messages (same item list as listbox) -----
        combo_to_list = {
            self.CB_ADDSTRING: self.LB_ADDSTRING,
            self.CB_DELETESTRING: self.LB_DELETESTRING,
            self.CB_RESETCONTENT: self.LB_RESETCONTENT,
            self.CB_GETCOUNT: self.LB_GETCOUNT,
            self.CB_GETCURSEL: self.LB_GETCURSEL,
            self.CB_SETCURSEL: self.LB_SETCURSEL,
            self.CB_GETLBTEXT: self.LB_GETTEXT,
            self.CB_GETLBTEXTLEN: self.LB_GETTEXTLEN,
        }
        if Msg in combo_to_list:
            return self._control_message(control, combo_to_list[Msg], wParam, lParam, wide)

        # ----- Scrollbar messages -----
        if Msg == self.SBM_SETPOS:
            pos = wParam - 0x100000000 if wParam >= 0x80000000 else wParam
            prev = control.scroll_pos
            control.scroll_pos = self._clamp_scroll_pos(control, pos)
            return prev & 0xFFFFFFFF
        if Msg == self.SBM_GETPOS:
            return control.scroll_pos & 0xFFFFFFFF
        if Msg == self.SBM_SETRANGE:
            nmin = wParam - 0x100000000 if wParam >= 0x80000000 else wParam
            nmax = lParam - 0x100000000 if lParam >= 0x80000000 else lParam
            control.scroll_min = min(nmin, nmax)
            control.scroll_max = max(nmin, nmax)
            control.scroll_pos = self._clamp_scroll_pos(control, control.scroll_pos)
            return 0
        if Msg == self.SBM_GETRANGE:
            try:
                if wParam:
                    self.emu.uc.mem_write(wParam, struct.pack("<i", control.scroll_min))
                if lParam:
                    self.emu.uc.mem_write(lParam, struct.pack("<i", control.scroll_max))
            except UcError:
                pass
            return 0

        log.debug(f"Unhandled control message 0x{Msg:04x} for {control.class_name}")
        return 0
    
    def PostMessageA(self, args):
        """PostMessageA emulation - queue a message for the message loop"""
        hWnd = args[0]
        Msg = args[1]
        wParam = args[2]
        lParam = args[3]
        log.debug(f"PostMessageA(0x{hWnd:x}, 0x{Msg:x}, 0x{wParam:x}, 0x{lParam:x})")
        if Msg == self.WM_QUIT:
            self.quit_requested = True
        else:
            self.post_window_message(hWnd, Msg, wParam, lParam)
        return 1

    def PostMessageW(self, args):
        return self.PostMessageA(args)

    def PostQuitMessage(self, args):
        """PostQuitMessage emulation - request message loop exit"""
        nExitCode = args[0]
        log.debug(f"PostQuitMessage({nExitCode})")
        # The blocking GetMessageA relies on this to break the loop
        self.quit_requested = True
        return 0

    def SetTimer(self, args):
        """SetTimer emulation"""
        hWnd = args[0]
        nIDEvent = args[1]
        uElapse = args[2]
        lpTimerFunc = args[3]

        # Window-less timers get a fresh id (like real Windows)
        if hWnd == 0 or nIDEvent == 0:
            nIDEvent = self.next_timer_id
            self.next_timer_id += 1

        elapse = max(uElapse, 10) / 1000.0  # USER_TIMER_MINIMUM ~ 10ms
        self.timers[(hWnd, nIDEvent)] = {
            'elapse': elapse,
            'callback': lpTimerFunc,
            'next_fire': time.time() + elapse,
        }

        log.debug(f"SetTimer(0x{hWnd:x}, id={nIDEvent}, {uElapse}ms) -> {nIDEvent}")
        return nIDEvent

    def KillTimer(self, args):
        """KillTimer emulation"""
        hWnd = args[0]
        nIDEvent = args[1]
        log.debug(f"KillTimer(0x{hWnd:x}, id={nIDEvent})")
        return 1 if self.timers.pop((hWnd, nIDEvent), None) else 0

    def _pop_due_timer(self, matches=lambda hwnd, message: True):
        """Return (hwnd, id, callback) of a due timer and schedule its next fire"""
        now = time.time()
        for (hwnd, timer_id), timer in self.timers.items():
            if now >= timer['next_fire'] and matches(hwnd, self.WM_TIMER):
                # Keep the period on its grid so polling delays don't slow the timer
                timer['next_fire'] += timer['elapse']
                if timer['next_fire'] <= now:
                    timer['next_fire'] = now + timer['elapse']
                return (hwnd, timer_id, timer['callback'])
        return None

    def _write_msg(self, lpMsg, hwnd, message, wParam, lParam):
        """Fill a MSG structure in emulated memory"""
        if lpMsg:
            msg_data = struct.pack("<IIIIIii", hwnd, message, wParam, lParam, 0, 0, 0)
            self.emu.uc.mem_write(lpMsg, msg_data)

    def _next_message(self, remove=True, hwnd_filter=0, msg_min=0, msg_max=0):
        """Single non-blocking scan for a pending message.

        Returns (hwnd, message, wParam, lParam) or None. Priority mirrors
        GetMessageA: synthesized WM_PAINT, then the input queue, then timers.
        hwnd_filter/msg_min/msg_max follow GetMessage's hWnd and filter range.
        """
        def matches(hwnd, message):
            if hwnd_filter == 0xFFFFFFFF:  # (HWND)-1: thread messages only
                if hwnd != 0:
                    return False
            elif hwnd_filter and hwnd != hwnd_filter:
                return False
            return (msg_min == 0 and msg_max == 0) or msg_min <= message <= msg_max

        self._audio_pump()

        # Send WM_PAINT for visible windows not yet painted
        windows = []
        if self.gui:
            with self.gui.lock:
                windows = list(self.gui.windows.items())
        for hwnd, window in windows:
            if (hwnd not in self.painted_windows and window.visible
                    and window.owner is self and matches(hwnd, self.WM_PAINT)):
                if remove:
                    self.painted_windows.add(hwnd)
                return (hwnd, self.WM_PAINT, 0, 0)

        # Owner-draw controls paint after their (painted, visible) parent
        for hwnd in list(self.dirty_controls):
            control = self.gui.controls.get(hwnd) if self.gui else None
            if control is None or not self._owner_draw_type(control):
                self.dirty_controls.pop(hwnd, None)
                continue
            parent = self.gui.windows.get(control.parent_hwnd)
            if (parent is not None and parent.visible and control.visible
                    and control.parent_hwnd in self.painted_windows
                    and matches(hwnd, self.WM_PAINT)):
                if remove:
                    del self.dirty_controls[hwnd]
                return (hwnd, self.WM_PAINT, 0, 0)

        # Queued message (input forwarded from the GUI thread)
        with self.message_lock:
            for index, msg in enumerate(self.message_queue):
                if matches(msg['hwnd'], msg['message']):
                    if remove:
                        del self.message_queue[index]
                    return (msg['hwnd'], msg['message'], msg['wParam'], msg['lParam'])

        # Fire due timers (lowest priority, like real WM_TIMER)
        if remove:
            due = self._pop_due_timer(matches)
            if due is not None:
                timer_hwnd, timer_id, callback = due
                return (timer_hwnd, self.WM_TIMER, timer_id, callback)

        return None

    def GetMessageA(self, args):
        """GetMessageA emulation - For message loop"""
        lpMsg = args[0]
        hWnd = args[1]
        wMsgFilterMin = args[2]
        wMsgFilterMax = args[3]

        log.debug(f"GetMessageA() - Message loop")

        # Block until a message is available, the app quits, or the GUI closes.
        # This runs on the emulation thread; the GUI thread feeds message_queue.
        while True:
            if self.quit_requested:
                self._write_msg(lpMsg, 0, self.WM_QUIT, 0, 0)
                return 0

            msg = self._next_message(True, hWnd, wMsgFilterMin, wMsgFilterMax)
            if msg is not None:
                hwnd, message, wParam, lParam = msg
                self._write_msg(lpMsg, hwnd, message, wParam, lParam)
                if message == self.WM_QUIT:
                    return 0
                return 1

            # GUI window closed -> end the message loop
            if self.gui and not self.gui.running:
                self._write_msg(lpMsg, 0, self.WM_QUIT, 0, 0)
                return 0

            # No GUI at all -> nothing can ever arrive, terminate
            if not self.gui:
                self.quit_requested = True
                self._write_msg(lpMsg, 0, self.WM_QUIT, 0, 0)
                return 0

            # Idle: wait for the GUI thread to post input (does not burn instructions)
            time.sleep(0.01)

    def GetMessageW(self, args):
        return self.GetMessageA(args)

    def PeekMessageA(self, args):
        """PeekMessageA emulation - non-blocking message check (game loops)"""
        lpMsg = args[0]
        hWnd = args[1]
        wMsgFilterMin = args[2]
        wMsgFilterMax = args[3]
        wRemoveMsg = args[4]

        remove = bool(wRemoveMsg & self.PM_REMOVE)

        # Quit pending or GUI gone: report WM_QUIT (PeekMessage returns TRUE)
        if self.quit_requested or (self.gui and not self.gui.running) or not self.gui:
            self._write_msg(lpMsg, 0, self.WM_QUIT, 0, 0)
            return 1

        msg = self._next_message(remove, hWnd, wMsgFilterMin, wMsgFilterMax)
        if msg is None:
            return 0

        hwnd, message, wParam, lParam = msg
        self._write_msg(lpMsg, hwnd, message, wParam, lParam)
        log.debug(f"PeekMessageA() -> msg=0x{message:04x} hwnd=0x{hwnd:x}")
        return 1

    def PeekMessageW(self, args):
        """PeekMessageW emulation (same as PeekMessageA in the emulator)"""
        return self.PeekMessageA(args)
    
    def TranslateMessage(self, args):
        """TranslateMessage emulation"""
        lpMsg = args[0]
        log.debug(f"TranslateMessage()")
        return 1
    
    def DispatchMessageA(self, args):
        """DispatchMessageA emulation - Call WndProc"""
        lpMsg = args[0]
        log.debug(f"DispatchMessageA()")
        
        # Read MSG structure: hwnd, message, wParam, lParam, time, pt.x, pt.y
        try:
            msg_data = self.emu.uc.mem_read(lpMsg, 28)
            hwnd, message, wParam, lParam, time_val, pt_x, pt_y = struct.unpack("<IIIIIii", msg_data)
            
            log.debug(f"DispatchMessageA: hwnd=0x{hwnd:x}, msg=0x{message:x}")

            if message == self.WM_PAINT and self.gui and hwnd in self.gui.controls:
                return self._paint_control(hwnd)

            # Dialog windows: keyboard navigation and the dialog procedure
            if self._dialog_of(hwnd) and not (message == self.WM_TIMER and lParam):
                return self._dispatch(hwnd, message, wParam, lParam)

            # WM_TIMER with a TimerProc: call the callback instead of the WndProc
            if message == self.WM_TIMER and lParam:
                tick = int(time.time() * 1000) & 0xFFFFFFFF
                return self.emu.call_callback(lParam, [hwnd, message, wParam, tick])

            # Find WndProc for this hwnd
            wndproc = self._find_wndproc_for_hwnd(hwnd)
            
            if wndproc and wndproc != 0:
                log.debug(f"Calling WndProc: 0x{wndproc:x}(hwnd=0x{hwnd:x}, msg=0x{message:x}, wParam=0x{wParam:x}, lParam=0x{lParam:x})")
                
                # Call WndProc callback
                result = self.emu.call_wndproc(wndproc, hwnd, message, wParam, lParam)
                
                log.debug(f"WndProc returned: 0x{result:x}")
                return result
            else:
                log.debug(f"WndProc not found, hwnd=0x{hwnd:x}")
                
        except UcError as e:
            log.warning(f"DispatchMessageA error: {e}")
        
        return 0

    def DispatchMessageW(self, args):
        return self.DispatchMessageA(args)
    
    def _find_wndproc_for_hwnd(self, hwnd):
        """Find WndProc address for a specific hwnd"""
        # Get window class from GUI (only this process's own windows, no consoles)
        if self.gui and hwnd in self.gui.windows:
            window = self.gui.windows[hwnd]
            if window.owner is not self or hwnd in self.gui.consoles:
                return 0
            dialog = self.dialogs.get(hwnd)
            if dialog is not None:
                return dialog['proc']
            # Find WndProc from window class name
            class_name = getattr(window, 'class_name', None)
            if class_name and class_name in self.registered_classes:
                return self.registered_classes[class_name].get('wndproc', 0)
            # No WndProc if no class_name (internal window)
            if not class_name:
                return 0
        
        return 0
    
    def DefWindowProcA(self, args):
        """DefWindowProcA emulation"""
        hWnd = args[0]
        Msg = args[1]
        wParam = args[2]
        lParam = args[3]
        log.debug(f"DefWindowProcA(0x{hWnd:x}, 0x{Msg:x})")

        # Default WM_CLOSE handling: destroy the window (like real Windows)
        if Msg == self.WM_CLOSE:
            self.DestroyWindow([hWnd])

        return 0

    def DefWindowProcW(self, args):
        return self.DefWindowProcA(args)
    
    # ==================== DEVICE CONTEXT HELPERS ====================

    @staticmethod
    def _colorref_to_rgb(colorref):
        """Convert a Win32 COLORREF (0x00BBGGRR) to an (r, g, b) tuple"""
        return (colorref & 0xFF, (colorref >> 8) & 0xFF, (colorref >> 16) & 0xFF)

    def _create_dc(self, hwnd, memory=False):
        """Create a DC handle bound to a window (or an off-screen memory DC)"""
        hdc = self.get_next_handle()
        self.dc_map[hdc] = hwnd
        self.dc_state[hdc] = {
            'pen': 0,          # 0 = default black pen, width 1
            'brush': 0,        # 0 = default white brush
            'font': 0,         # 0 = default GUI font
            'pos': (0, 0),     # Current position (MoveToEx/LineTo)
            'text_color': (0, 0, 0),
            'bk_mode': 2,      # OPAQUE
            'bk_color': (255, 255, 255),
            'memory': memory,  # Memory DCs keep their own display list
            'shapes': [] if memory else None,
            'bitmap': 0,       # Selected bitmap (memory DCs)
        }
        return hdc

    def _delete_dc(self, hdc):
        """Release a DC handle"""
        self._store_bitmap_shapes(self.dc_state.get(hdc))
        self.dc_map.pop(hdc, None)
        self.dc_state.pop(hdc, None)

    def _store_bitmap_shapes(self, state):
        """Keep a memory DC's drawing with its selected bitmap (it outlives the selection)"""
        if state and state.get('memory') and state.get('bitmap'):
            bmp = self.gdi_objects.get(state['bitmap'])
            if bmp and bmp['type'] == 'bitmap':
                bmp['shapes'] = state['shapes']

    def _dc_hwnd(self, hdc):
        """Window a DC belongs to (fall back to the active window)"""
        hwnd = self.dc_map.get(hdc, 0)
        if not hwnd and self.gui:
            active = self.gui.active_window
            if self.gui.window_owner(active) is self:
                hwnd = active
        return hwnd

    def _dc_pen(self, hdc):
        """Current pen of a DC -> (color, width) or None for PS_NULL"""
        state = self.dc_state.get(hdc)
        if state and state['pen']:
            pen = self.gdi_objects.get(state['pen'])
            if pen and pen['type'] == 'pen':
                if pen.get('style', 0) == 5:  # PS_NULL
                    return None
                return (pen['color'], max(1, pen['width']))
        return ((0, 0, 0), 1)  # Default: black pen, width 1

    def _dc_brush(self, hdc):
        """Current brush color of a DC, or None for NULL_BRUSH"""
        state = self.dc_state.get(hdc)
        if state and state['brush']:
            brush = self.gdi_objects.get(state['brush'])
            if brush and brush['type'] == 'brush':
                return brush['color']  # None for NULL_BRUSH
        return (255, 255, 255)  # Default: white brush

    def _dc_font(self, hdc):
        """Current font dict of a DC, or None for the default GUI font"""
        state = self.dc_state.get(hdc)
        if state and state.get('font'):
            font = self.gdi_objects.get(state['font'])
            if font and font['type'] == 'font':
                return font
        return None

    def _memdc_size(self, hdc):
        """Bitmap size of a memory DC -> (w, h) or None"""
        state = self.dc_state.get(hdc)
        if state:
            bmp = self.gdi_objects.get(state.get('bitmap', 0))
            if bmp and bmp['type'] == 'bitmap':
                return (bmp['width'], bmp['height'])
        return None

    def _add_shape(self, hdc, shape):
        """Append a GDI shape to the display list of the DC's window.

        Memory DCs collect shapes in their own list until BitBlt copies them.
        An opaque rect covering the whole bitmap restarts the list, so a
        game loop that fills the background every frame doesn't grow it.
        """
        state = self.dc_state.get(hdc)
        if state and state.get('memory'):
            size = self._memdc_size(hdc)
            if size and PseudoWindowsGUI.covers_area(shape, *size):
                state['shapes'] = [shape]
                return
            shapes = PseudoWindowsGUI.add_to_display_list(state['shapes'], shape)
            if len(shapes) > PseudoWindowsGUI.MAX_SHAPES:
                shapes = shapes[-(PseudoWindowsGUI.MAX_SHAPES // 2):]
            state['shapes'] = shapes
            return

        hwnd = self._dc_hwnd(hdc)
        if self.gui and hwnd:
            self.gui.add_shape(hwnd, shape)

    def _add_text(self, hdc, text, x, y):
        """Append a text item to the DC's display list (window or memory DC)"""
        state = self.dc_state.get(hdc, {})
        shape = {
            'type': 'text',
            'pos': (x, y),
            'text': text,
            'color': state.get('text_color') or (0, 0, 0),
            'font': self._dc_font(hdc),
            # OPAQUE background mode fills the text cell with the background color
            'bk': state.get('bk_color') if state.get('bk_mode', 2) == 2 else None,
        }
        self._add_shape(hdc, shape)

    def BeginPaint(self, args):
        """BeginPaint emulation"""
        hWnd = args[0]
        lpPaint = args[1]

        log.debug(f"BeginPaint(0x{hWnd:x})")

        hdc = self._create_dc(hWnd)

        # Painting starts fresh: clear the window's retained display lists
        if self.gui:
            self.gui.clear_drawings(hWnd)

        # Fill PAINTSTRUCT structure
        if lpPaint:
            # Client area size
            right, bottom = 400, 300
            if self.gui and hWnd in self.gui.windows:
                win = self.gui.windows[hWnd]
                right, bottom = self.gui.client_size(win)
            # hdc, fErase, rcPaint(4 int), fRestore, fIncUpdate, rgbReserved[32]
            paint_data = struct.pack("<II", hdc, 0)  # First 8 bytes
            paint_data += struct.pack("<iiii", 0, 0, right, bottom)  # rcPaint
            paint_data += b'\x00' * (64 - len(paint_data))  # Rest
            self.emu.uc.mem_write(lpPaint, paint_data[:64])

        return hdc

    def EndPaint(self, args):
        """EndPaint emulation"""
        hWnd = args[0]
        lpPaint = args[1]
        log.debug(f"EndPaint(0x{hWnd:x})")
        # Free the DC allocated by BeginPaint
        if lpPaint:
            try:
                hdc = struct.unpack("<I", self.emu.uc.mem_read(lpPaint, 4))[0]
                self._delete_dc(hdc)
            except UcError:
                pass
        return 1

    def InvalidateRect(self, args):
        """InvalidateRect emulation - request a repaint via WM_PAINT"""
        hWnd = args[0]
        lpRect = args[1]
        bErase = args[2]
        log.debug(f"InvalidateRect(0x{hWnd:x})")
        # GetMessageA re-synthesizes WM_PAINT for windows not in painted_windows
        self.painted_windows.discard(hWnd)
        if self.gui and hWnd in self.gui.controls:
            self.dirty_controls[hWnd] = True
        return 1

    def FillRect(self, args):
        """FillRect emulation"""
        hdc = args[0]
        lprc = args[1]
        hbr = args[2]

        if not lprc:
            log.debug(f"FillRect(0x{hdc:x})")
            return 1

        try:
            rect_data = self.emu.uc.mem_read(lprc, 16)
            left, top, right, bottom = struct.unpack("<iiii", rect_data)
        except UcError:
            log.debug(f"FillRect(0x{hdc:x})")
            return 1

        log.debug(f"FillRect(0x{hdc:x}, rect=({left},{top},{right},{bottom}), brush=0x{hbr:x})")

        # Resolve the brush: GDI handle, or a system color index + 1 (e.g. COLOR_WINDOW+1)
        color = self._brush_color(hbr)

        if color is not None:
            self._add_shape(hdc, {'type': 'rect', 'rect': (left, top, right, bottom),
                                  'fill': color, 'pen': None})
        return 1

    def GetDC(self, args):
        """GetDC emulation"""
        hWnd = args[0]
        log.debug(f"GetDC(0x{hWnd:x})")
        return self._create_dc(hWnd)

    def ReleaseDC(self, args):
        """ReleaseDC emulation"""
        hWnd = args[0]
        hDC = args[1]
        log.debug(f"ReleaseDC(0x{hWnd:x}, 0x{hDC:x})")
        self._delete_dc(hDC)
        return 1

    # GDI32.DLL APIs
    def GetDeviceCaps(self, args):
        """GetDeviceCaps emulation"""
        hdc = args[0]
        index = args[1]
        width, height = self._screen_size()
        
        caps = {
            4: 320,     # HORZSIZE (mm)
            6: 240,     # VERTSIZE (mm)
            8: width,   # HORZRES
            10: height, # VERTRES
            12: 32,     # BITSPIXEL
            14: 1,      # PLANES
            24: -1,     # NUMCOLORS (more than 256 colors)
            88: 96,     # LOGPIXELSX
            90: 96,     # LOGPIXELSY
            117: height, # DESKTOPVERTRES
            118: width,  # DESKTOPHORZRES
        }
        
        result = caps.get(index, 0)
        log.debug(f"GetDeviceCaps(0x{hdc:x}, {index}) -> {result}")
        return result & 0xFFFFFFFF
    
    def TextOutA(self, args):
        """TextOutA emulation - Draw text"""
        hdc = args[0]
        x = args[1]
        y = args[2]
        lpString = args[3]
        c = args[4]
        
        text = self.read_string(lpString) if lpString else ""
        if c > 0 and len(text) > c:
            text = text[:c]

        log.debug(f"TextOutA(0x{hdc:x}, {x}, {y}, \"{text}\")")

        if self.gui:
            self._add_text(hdc, text, *self._aligned_text_pos(hdc, text, x, y))

        return 1
    
    def TextOutW(self, args):
        """TextOutW emulation - Draw Unicode text"""
        hdc = args[0]
        x = args[1]
        y = args[2]
        lpString = args[3]
        c = args[4]
        
        text = self.read_wide_string(lpString) if lpString else ""
        if c > 0 and len(text) > c:
            text = text[:c]

        log.debug(f"TextOutW(0x{hdc:x}, {x}, {y}, \"{text}\")")

        if self.gui:
            self._add_text(hdc, text, *self._aligned_text_pos(hdc, text, x, y))

        return 1
    
    def DrawTextA(self, args):
        """DrawTextA emulation"""
        hdc = args[0]
        lpchText = args[1]
        cchText = args[2]
        lprc = args[3]
        format_flags = args[4]
        
        text = self.read_string(lpchText) if lpchText else ""
        if cchText > 0 and len(text) > cchText:
            text = text[:cchText]
        
        # Read RECT structure
        x, y, width, height = 0, 0, 400, 300
        if lprc:
            try:
                rect_data = self.emu.uc.mem_read(lprc, 16)
                left, top, right, bottom = struct.unpack("<iiii", rect_data)
                x, y = left, top
                width, height = right - left, bottom - top
            except UcError:
                pass
        
        log.debug(f"DrawTextA(0x{hdc:x}, \"{text}\", rect=({x},{y},{width},{height}))")
        
        # DT_CENTER (0x01) ve DT_VCENTER (0x04) flag'leri
        DT_CENTER = 0x01
        DT_VCENTER = 0x04
        
        draw_x = x
        draw_y = y
        
        # Calculate centering (approximate)
        if format_flags & DT_CENTER:
            draw_x = x + (width - len(text) * 8) // 2  # 8 pixel estimated character width
        if format_flags & DT_VCENTER:
            draw_y = y + (height - 16) // 2  # 16 pixel estimated height
        
        if self.gui:
            state = self.dc_state.get(hdc, {})
            if state.get('memory') or self._dc_hwnd(hdc) not in self.gui.consoles:
                self._add_text(hdc, text, draw_x, draw_y)

        return height  # Text height
    
    def DrawTextW(self, args):
        """DrawTextW emulation"""
        hdc = args[0]
        lpchText = args[1]
        cchText = args[2]
        lprc = args[3]
        format_flags = args[4]
        
        text = self.read_wide_string(lpchText) if lpchText else ""
        if cchText > 0 and len(text) > cchText:
            text = text[:cchText]

        x, y = 0, 0
        if lprc:
            try:
                rect_data = self.emu.uc.mem_read(lprc, 16)
                left, top, right, bottom = struct.unpack("<iiii", rect_data)
                x, y = left, top
            except UcError:
                pass

        log.debug(f"DrawTextW(0x{hdc:x}, \"{text}\")")

        if self.gui:
            self._add_text(hdc, text, x, y)

        return 20  # Text height
    
    def SetTextColor(self, args):
        """SetTextColor emulation"""
        hdc = args[0]
        color = args[1]
        log.debug(f"SetTextColor(0x{hdc:x}, 0x{color:06x})")
        state = self.dc_state.get(hdc)
        prev = 0
        if state:
            r, g, b = state['text_color']
            prev = r | (g << 8) | (b << 16)
            state['text_color'] = self._colorref_to_rgb(color)
        return prev  # Previous color

    def SetBkColor(self, args):
        """SetBkColor emulation"""
        hdc = args[0]
        color = args[1]
        log.debug(f"SetBkColor(0x{hdc:x}, 0x{color:06x})")
        state = self.dc_state.get(hdc)
        prev = 0xFFFFFF
        if state:
            r, g, b = state['bk_color']
            prev = r | (g << 8) | (b << 16)
            state['bk_color'] = self._colorref_to_rgb(color)
        return prev  # Previous color

    def SetBkMode(self, args):
        """SetBkMode emulation"""
        hdc = args[0]
        mode = args[1]  # TRANSPARENT=1, OPAQUE=2
        log.debug(f"SetBkMode(0x{hdc:x}, {mode})")
        state = self.dc_state.get(hdc)
        prev = 2
        if state:
            prev = state['bk_mode']
            state['bk_mode'] = mode
        return prev  # Previous mode

    CLR_INVALID = 0xFFFFFFFF
    GDI_ERROR = 0xFFFFFFFF

    def _dc_colorref(self, hdc, key):
        """A DC color as COLORREF, or CLR_INVALID for an unknown DC"""
        state = self.dc_state.get(hdc)
        if not state:
            return self.CLR_INVALID
        r, g, b = state[key]
        return r | (g << 8) | (b << 16)

    def GetTextColor(self, args):
        """GetTextColor emulation"""
        return self._dc_colorref(args[0], 'text_color')

    def GetBkColor(self, args):
        """GetBkColor emulation"""
        return self._dc_colorref(args[0], 'bk_color')

    # SetTextAlign flags
    TA_UPDATECP = 0x01
    TA_RIGHT = 0x02
    TA_CENTER = 0x06
    TA_BOTTOM = 0x08
    TA_BASELINE = 0x18

    def SetTextAlign(self, args):
        """SetTextAlign emulation - honoured by TextOut (TA_UPDATECP is ignored)"""
        hdc, align = args[0], args[1]
        log.debug(f"SetTextAlign(0x{hdc:x}, 0x{align:x})")
        state = self.dc_state.get(hdc)
        if not state:
            return self.GDI_ERROR
        prev = state.get('text_align', 0)  # TA_LEFT | TA_TOP
        state['text_align'] = align
        return prev

    def _aligned_text_pos(self, hdc, text, x, y):
        """Top-left position of TextOut text for the DC's text alignment"""
        align = self.dc_state.get(hdc, {}).get('text_align', 0)
        if not align & ~self.TA_UPDATECP:
            return x, y
        width, height = self._text_extent(hdc, text)
        if align & self.TA_CENTER == self.TA_CENTER:
            x -= width // 2
        elif align & self.TA_RIGHT:
            x -= width
        if align & self.TA_BASELINE == self.TA_BASELINE:
            y -= self._text_ascent(height)
        elif align & self.TA_BOTTOM:
            y -= height
        return x, y

    @staticmethod
    def _text_ascent(height):
        return (height * 4 + 2) // 5

    def GetTextMetricsA(self, args):
        """GetTextMetricsA emulation - metrics of the estimated GUI font"""
        hdc, lptm = args[0], args[1]
        if hdc not in self.dc_state or not lptm:
            return 0
        font = self._dc_font(hdc) or {}
        ave_width, height = self._text_extent(hdc, 'x')
        ascent = self._text_ascent(height)
        data = struct.pack('<11i9B',
                           height, ascent, height - ascent,
                           0,                       # tmInternalLeading
                           0,                       # tmExternalLeading
                           ave_width, ave_width * 2,
                           700 if font.get('bold') else 400,
                           0, 96, 96,               # overhang, digitized aspect
                           0x20, 0xFF, 0x1F, 0x20,  # first/last/default/break char
                           1 if font.get('italic') else 0,
                           1 if font.get('underline') else 0,
                           0,                       # tmStruckOut
                           0x22,                    # VARIABLE_PITCH | FF_SWISS
                           0)                       # ANSI_CHARSET
        return 1 if self._mem_write(lptm, data + b'\x00' * 3) else 0

    def SetROP2(self, args):
        """SetROP2 emulation - the mix mode is stored, drawing always copies the pen"""
        hdc, rop2 = args[0], args[1]
        state = self.dc_state.get(hdc)
        if not state or not 1 <= rop2 <= 16:
            return 0
        prev = state.get('rop2', 13)  # R2_COPYPEN
        state['rop2'] = rop2
        return prev

    # ==================== GDI DRAWING APIs ====================

    def CreatePen(self, args):
        """CreatePen emulation"""
        style = args[0]   # PS_SOLID=0 ... PS_NULL=5
        width = args[1]
        colorref = args[2]

        handle = self.get_next_handle()
        self.gdi_objects[handle] = {
            'type': 'pen',
            'style': style,
            'color': self._colorref_to_rgb(colorref),
            'width': max(1, width),
        }
        log.debug(f"CreatePen(style={style}, width={width}, color=0x{colorref:06x}) -> 0x{handle:x}")
        return handle

    def CreateSolidBrush(self, args):
        """CreateSolidBrush emulation"""
        colorref = args[0]
        handle = self.get_next_handle()
        self.gdi_objects[handle] = {
            'type': 'brush',
            'color': self._colorref_to_rgb(colorref),
            'width': 0,
        }
        log.debug(f"CreateSolidBrush(0x{colorref:06x}) -> 0x{handle:x}")
        return handle

    def CreatePalette(self, args):
        """CreatePalette emulation (LOGPALETTE: version, count, PALETTEENTRY[])"""
        try:
            _, count = struct.unpack('<HH', self.emu.uc.mem_read(args[0], 4))
            raw = bytes(self.emu.uc.mem_read(args[0] + 4, count * 4)) if count else b''
        except UcError:
            return 0
        if not count:
            return 0
        handle = self.get_next_handle()
        self.gdi_objects[handle] = {
            'type': 'palette',
            'entries': [tuple(raw[i:i + 4]) for i in range(0, len(raw), 4)],
        }
        log.debug(f"CreatePalette({count} entries) -> 0x{handle:x}")
        return handle

    def SelectPalette(self, args):
        """SelectPalette emulation - returns the previously selected palette"""
        hdc, hpal = args[0], args[1]
        state = self.dc_state.get(hdc)
        obj = self.gdi_objects.get(hpal)
        if state is None or obj is None:
            return 0
        prev = state.get('palette') or self.GetStockObject([15])  # DEFAULT_PALETTE
        state['palette'] = hpal
        log.debug(f"SelectPalette(0x{hdc:x}, 0x{hpal:x}) -> 0x{prev:x}")
        return prev

    def RealizePalette(self, args):
        """RealizePalette emulation - true-color display, nothing to remap"""
        return 0

    def CreatePenIndirect(self, args):
        """CreatePenIndirect emulation (LOGPEN: style, POINT width, color)"""
        try:
            style, width, _, color = struct.unpack('<IiiI', self.emu.uc.mem_read(args[0], 16))
        except UcError:
            return 0
        return self.CreatePen([style, max(0, width), color])

    def CreateBrushIndirect(self, args):
        """CreateBrushIndirect emulation (LOGBRUSH: style, color, hatch)"""
        try:
            style, color, hatch = struct.unpack('<III', self.emu.uc.mem_read(args[0], 12))
        except UcError:
            return 0
        if style == 1:  # BS_NULL / BS_HOLLOW
            return self.GetStockObject([5])  # NULL_BRUSH
        if style == 2:  # BS_HATCHED
            return self.CreateHatchBrush([hatch, color])
        return self.CreateSolidBrush([color])

    # Stock fonts: index -> (face, pixel height)
    STOCK_FONTS = {
        10: ('courier new', 16),    # OEM_FIXED_FONT
        11: ('courier new', 16),    # ANSI_FIXED_FONT
        12: ('ms sans serif', 16),  # ANSI_VAR_FONT
        16: ('courier new', 16),    # SYSTEM_FIXED_FONT
        17: ('ms sans serif', 16),  # DEFAULT_GUI_FONT
    }

    def GetStockObject(self, args):
        """GetStockObject emulation"""
        index = args[0]

        # Cache: the same index always returns the same handle
        if index in self._stock_objects:
            return self._stock_objects[index]

        stock = {
            0: ('brush', (255, 255, 255)),   # WHITE_BRUSH
            1: ('brush', (192, 192, 192)),   # LTGRAY_BRUSH
            2: ('brush', (128, 128, 128)),   # GRAY_BRUSH
            3: ('brush', (64, 64, 64)),      # DKGRAY_BRUSH
            4: ('brush', (0, 0, 0)),         # BLACK_BRUSH
            5: ('brush', None),              # NULL_BRUSH (draws nothing)
            6: ('pen', (255, 255, 255)),     # WHITE_PEN
            7: ('pen', (0, 0, 0)),           # BLACK_PEN
            8: ('pen', None),                # NULL_PEN
        }

        handle = self.get_next_handle()
        if index in stock:
            obj_type, color = stock[index]
            obj = {'type': obj_type, 'color': color, 'width': 1}
            if color is None and obj_type == 'pen':
                obj['style'] = 5  # PS_NULL
            self.gdi_objects[handle] = obj
        elif index in self.STOCK_FONTS:
            face, height = self.STOCK_FONTS[index]
            self.gdi_objects[handle] = {'type': 'font', 'height': height, 'bold': False,
                                        'italic': False, 'underline': False, 'face': face}
        else:
            # Fonts and other stock objects: return a generic handle
            self.gdi_objects[handle] = {'type': 'other', 'color': (0, 0, 0), 'width': 0}

        self._stock_objects[index] = handle
        log.debug(f"GetStockObject({index}) -> 0x{handle:x}")
        return handle

    def SelectObject(self, args):
        """SelectObject emulation"""
        hdc = args[0]
        hobj = args[1]

        state = self.dc_state.get(hdc)
        obj = self.gdi_objects.get(hobj)
        prev = 0

        if state and obj:
            kind = obj['type']
            # Selecting a DC default stock object restores the built-in default (0)
            default_kind = next((k for k, h in self._dc_default_objects().items()
                                 if h == hobj), None)
            if default_kind:
                kind = default_kind
            if kind in ('pen', 'brush', 'font', 'bitmap'):
                prev = state.get(kind, 0) or self._dc_default_objects()[kind]
                if kind == 'bitmap' and state.get('memory'):
                    self._store_bitmap_shapes(state)
                    state['shapes'] = list(obj.get('shapes', [])) if not default_kind else []
                state[kind] = 0 if default_kind else hobj

        log.debug(f"SelectObject(0x{hdc:x}, 0x{hobj:x}) -> 0x{prev:x}")
        return prev

    def _dc_default_objects(self):
        """Stock handles standing for a fresh DC's defaults (returned by SelectObject)"""
        if 'bitmap' not in self._stock_objects:
            handle = self.get_next_handle()
            self.gdi_objects[handle] = {'type': 'bitmap', 'width': 1, 'height': 1}
            self._stock_objects['bitmap'] = handle  # 1x1 default bitmap of memory DCs
        return {'pen': self.GetStockObject([7]),     # BLACK_PEN
                'brush': self.GetStockObject([0]),   # WHITE_BRUSH
                'font': self.GetStockObject([13]),   # SYSTEM_FONT
                'bitmap': self._stock_objects['bitmap']}

    def DeleteObject(self, args):
        """DeleteObject emulation"""
        hobj = args[0]
        log.debug(f"DeleteObject(0x{hobj:x})")
        # Keep stock objects alive (deleting them is a no-op in Windows too)
        if hobj in self._stock_objects.values():
            return 1
        # Windows refuses to delete an object that is selected into a DC
        for state in self.dc_state.values():
            if hobj in (state.get('pen'), state.get('brush'), state.get('font'),
                        state.get('bitmap'), state.get('palette')):
                return 0
        return 1 if self.gdi_objects.pop(hobj, None) else 0

    def MoveToEx(self, args):
        """MoveToEx emulation - set current position"""
        hdc = args[0]
        x = args[1] if args[1] < 0x80000000 else args[1] - 0x100000000
        y = args[2] if args[2] < 0x80000000 else args[2] - 0x100000000
        lpPoint = args[3]

        state = self.dc_state.get(hdc)
        if state:
            if lpPoint:
                old_x, old_y = state['pos']
                self.emu.uc.mem_write(lpPoint, struct.pack("<ii", old_x, old_y))
            state['pos'] = (x, y)

        log.debug(f"MoveToEx(0x{hdc:x}, {x}, {y})")
        return 1

    def LineTo(self, args):
        """LineTo emulation - draw line from current position"""
        hdc = args[0]
        x = args[1] if args[1] < 0x80000000 else args[1] - 0x100000000
        y = args[2] if args[2] < 0x80000000 else args[2] - 0x100000000

        state = self.dc_state.get(hdc)
        if state:
            pen = self._dc_pen(hdc)
            if pen:
                self._add_shape(hdc, {'type': 'line', 'from': state['pos'],
                                      'to': (x, y), 'pen': pen})
            state['pos'] = (x, y)

        log.debug(f"LineTo(0x{hdc:x}, {x}, {y})")
        return 1

    def Rectangle(self, args):
        """Rectangle emulation - draw rectangle with current pen and brush"""
        hdc = args[0]
        left, top, right, bottom = (v if v < 0x80000000 else v - 0x100000000
                                    for v in args[1:5])

        self._add_shape(hdc, {'type': 'rect', 'rect': (left, top, right, bottom),
                              'fill': self._dc_brush(hdc), 'pen': self._dc_pen(hdc)})

        log.debug(f"Rectangle(0x{hdc:x}, {left}, {top}, {right}, {bottom})")
        return 1

    def Ellipse(self, args):
        """Ellipse emulation - draw ellipse with current pen and brush"""
        hdc = args[0]
        left, top, right, bottom = (v if v < 0x80000000 else v - 0x100000000
                                    for v in args[1:5])

        self._add_shape(hdc, {'type': 'ellipse', 'rect': (left, top, right, bottom),
                              'fill': self._dc_brush(hdc), 'pen': self._dc_pen(hdc)})

        log.debug(f"Ellipse(0x{hdc:x}, {left}, {top}, {right}, {bottom})")
        return 1

    def SetPixel(self, args):
        """SetPixel emulation"""
        hdc = args[0]
        x = args[1] if args[1] < 0x80000000 else args[1] - 0x100000000
        y = args[2] if args[2] < 0x80000000 else args[2] - 0x100000000
        colorref = args[3]

        color = self._colorref_to_rgb(colorref)
        self._add_shape(hdc, {'type': 'pixel', 'pos': (x, y), 'color': color})
        return colorref

    @staticmethod
    def _rgb_to_colorref(rgb):
        """Convert an (r, g, b) tuple to a Win32 COLORREF (0x00BBGGRR)"""
        r, g, b = rgb
        return (b << 16) | (g << 8) | r

    @staticmethod
    def _point_near_segment(px, py, x1, y1, x2, y2, radius):
        """Is (px, py) within radius of the segment (x1,y1)-(x2,y2)?"""
        dx, dy = x2 - x1, y2 - y1
        length_sq = dx * dx + dy * dy
        if length_sq == 0:
            ex, ey = px - x1, py - y1
        else:
            t = max(0.0, min(1.0, ((px - x1) * dx + (py - y1) * dy) / length_sq))
            ex, ey = px - (x1 + t * dx), py - (y1 + t * dy)
        return ex * ex + ey * ey <= radius * radius

    @staticmethod
    def _point_in_polygon(px, py, points):
        """Ray-casting point-in-polygon test"""
        inside = False
        n = len(points)
        for i in range(n):
            x1, y1 = points[i]
            x2, y2 = points[(i + 1) % n]
            if (y1 > py) != (y2 > py):
                x_cross = x1 + (py - y1) * (x2 - x1) / (y2 - y1)
                if px < x_cross:
                    inside = not inside
        return inside

    def _shape_color_at(self, shapes, x, y):
        """Color of the topmost display-list shape covering (x, y), or None"""
        for shape in reversed(shapes):
            stype = shape['type']
            if stype == 'pixel':
                if shape['pos'] == (x, y):
                    return shape['color']
            elif stype in ('rect', 'roundrect'):
                left, top, right, bottom = shape['rect']
                if left <= x < right and top <= y < bottom:
                    pen = shape.get('pen')
                    fill = shape.get('fill')
                    on_border = (x < left + 1 or x >= right - 1 or
                                 y < top + 1 or y >= bottom - 1)
                    if pen and on_border:
                        return pen[0] if isinstance(pen, tuple) else pen
                    if fill is not None:
                        return fill
            elif stype == 'ellipse':
                left, top, right, bottom = shape['rect']
                rx, ry = (right - left) / 2.0, (bottom - top) / 2.0
                if rx > 0 and ry > 0:
                    nx = (x - (left + rx)) / rx
                    ny = (y - (top + ry)) / ry
                    if nx * nx + ny * ny <= 1.0 and shape.get('fill') is not None:
                        return shape['fill']
            elif stype == 'polygon':
                if (shape.get('fill') is not None and len(shape['points']) >= 3 and
                        self._point_in_polygon(x, y, shape['points'])):
                    return shape['fill']
            elif stype == 'line':
                pen = shape.get('pen')
                if pen:
                    color, width = pen
                    x1, y1 = shape['from']
                    x2, y2 = shape['to']
                    if self._point_near_segment(x, y, x1, y1, x2, y2,
                                                max(1, width) / 2.0 + 0.5):
                        return color
            elif stype == 'polyline':
                pen = shape.get('pen')
                if pen:
                    color, width = pen
                    pts = shape['points']
                    for i in range(len(pts) - 1):
                        if self._point_near_segment(x, y, pts[i][0], pts[i][1],
                                                    pts[i + 1][0], pts[i + 1][1],
                                                    max(1, width) / 2.0 + 0.5):
                            return color
            elif stype == 'image':
                (left, top), (w, h) = shape['pos'], shape['dim']
                if (shape.get('rop') == self.SRCCOPY and shape['size'] == (w, h) and
                        left <= x < left + w and top <= y < top + h):
                    i = ((y - top) * w + (x - left)) * 3
                    return tuple(shape['data'][i:i + 3])
            # arc/text: no reliable hit test, skip
        return None

    def GetPixel(self, args):
        """GetPixel emulation - resolved from the DC's display list"""
        hdc = args[0]
        x, y = self._read_signed_args(args, 1, 2)

        state = self.dc_state.get(hdc)
        if state and state.get('memory'):
            shapes = state['shapes']
            background = (255, 255, 255)
        else:
            hwnd = self._dc_hwnd(hdc)
            if not self.gui or hwnd not in self.gui.windows:
                return 0xFFFFFFFF  # CLR_INVALID
            shapes = self.gui.windows[hwnd].drawn_shapes
            background = self.gui.windows[hwnd].bg_color

        color = self._shape_color_at(shapes, x, y)
        if color is None:
            color = background
        colorref = self._rgb_to_colorref(color)
        log.debug(f"GetPixel(0x{hdc:x}, {x}, {y}) -> 0x{colorref:06x}")
        return colorref

    @staticmethod
    def _read_signed_args(args, start, count):
        """Interpret stack dwords as signed 32-bit integers"""
        return [v - 0x100000000 if v >= 0x80000000 else v
                for v in args[start:start + count]]

    def _read_points(self, address, count):
        """Read an array of POINT structures -> [(x, y), ...]"""
        points = []
        try:
            data = self.emu.uc.mem_read(address, count * 8)
            for i in range(count):
                x, y = struct.unpack_from("<ii", data, i * 8)
                points.append((x, y))
        except UcError:
            pass
        return points

    def Polygon(self, args):
        """Polygon emulation - filled polygon with current pen and brush"""
        hdc = args[0]
        points = self._read_points(args[1], args[2])
        log.debug(f"Polygon(0x{hdc:x}, {len(points)} points)")
        if len(points) >= 3:
            self._add_shape(hdc, {'type': 'polygon', 'points': points,
                                  'fill': self._dc_brush(hdc), 'pen': self._dc_pen(hdc)})
        return 1

    def Polyline(self, args):
        """Polyline emulation - connected line segments with current pen"""
        hdc = args[0]
        points = self._read_points(args[1], args[2])
        log.debug(f"Polyline(0x{hdc:x}, {len(points)} points)")
        pen = self._dc_pen(hdc)
        if len(points) >= 2 and pen:
            self._add_shape(hdc, {'type': 'polyline', 'points': points, 'pen': pen})
        return 1

    def RoundRect(self, args):
        """RoundRect emulation - rectangle with rounded corners"""
        hdc = args[0]
        left, top, right, bottom, ew, eh = self._read_signed_args(args, 1, 6)
        log.debug(f"RoundRect(0x{hdc:x}, {left}, {top}, {right}, {bottom})")
        radius = max(0, min(ew, eh) // 2)
        self._add_shape(hdc, {'type': 'roundrect', 'rect': (left, top, right, bottom),
                              'radius': radius, 'fill': self._dc_brush(hdc),
                              'pen': self._dc_pen(hdc)})
        return 1

    @staticmethod
    def _arc_angles(left, top, right, bottom, x1, y1, x2, y2):
        """GDI arc endpoints -> (start, end) angles in math orientation (radians)"""
        import math
        cx, cy = (left + right) / 2.0, (top + bottom) / 2.0
        # Screen y grows downward; math orientation flips it
        start = math.atan2(cy - y1, x1 - cx)
        end = math.atan2(cy - y2, x2 - cx)
        return start, end

    def Arc(self, args):
        """Arc emulation - elliptic arc drawn counterclockwise"""
        hdc = args[0]
        left, top, right, bottom, x1, y1, x2, y2 = self._read_signed_args(args, 1, 8)
        log.debug(f"Arc(0x{hdc:x}, {left}, {top}, {right}, {bottom})")
        pen = self._dc_pen(hdc)
        if pen:
            start, end = self._arc_angles(left, top, right, bottom, x1, y1, x2, y2)
            self._add_shape(hdc, {'type': 'arc', 'rect': (left, top, right, bottom),
                                  'start': start, 'end': end, 'pen': pen})
        return 1

    def Pie(self, args):
        """Pie emulation - filled pie slice (approximated with a polygon)"""
        import math
        hdc = args[0]
        left, top, right, bottom, x1, y1, x2, y2 = self._read_signed_args(args, 1, 8)
        log.debug(f"Pie(0x{hdc:x}, {left}, {top}, {right}, {bottom})")

        start, end = self._arc_angles(left, top, right, bottom, x1, y1, x2, y2)
        if end <= start:
            end += 2 * math.pi

        # Sample the arc into polygon points (plus the center)
        cx, cy = (left + right) / 2.0, (top + bottom) / 2.0
        rx, ry = abs(right - left) / 2.0, abs(bottom - top) / 2.0
        steps = max(8, int((end - start) * 16))
        points = [(int(cx), int(cy))]
        for i in range(steps + 1):
            a = start + (end - start) * i / steps
            points.append((int(cx + rx * math.cos(a)), int(cy - ry * math.sin(a))))

        self._add_shape(hdc, {'type': 'polygon', 'points': points,
                              'fill': self._dc_brush(hdc), 'pen': self._dc_pen(hdc)})
        return 1

    def Chord(self, args):
        """Chord emulation - arc closed by its secant (approximated polygon)"""
        import math
        hdc = args[0]
        left, top, right, bottom, x1, y1, x2, y2 = self._read_signed_args(args, 1, 8)
        log.debug(f"Chord(0x{hdc:x}, {left}, {top}, {right}, {bottom})")

        start, end = self._arc_angles(left, top, right, bottom, x1, y1, x2, y2)
        if end <= start:
            end += 2 * math.pi

        cx, cy = (left + right) / 2.0, (top + bottom) / 2.0
        rx, ry = abs(right - left) / 2.0, abs(bottom - top) / 2.0
        steps = max(8, int((end - start) * 16))
        points = []
        for i in range(steps + 1):
            a = start + (end - start) * i / steps
            points.append((int(cx + rx * math.cos(a)), int(cy - ry * math.sin(a))))

        self._add_shape(hdc, {'type': 'polygon', 'points': points,
                              'fill': self._dc_brush(hdc), 'pen': self._dc_pen(hdc)})
        return 1

    def _brush_color(self, hbr):
        """Resolve a brush handle (or COLOR_* + 1 index) to an RGB color"""
        brush = self.gdi_objects.get(hbr)
        if brush and brush['type'] == 'brush':
            return brush['color']
        if hbr < 32:
            # COLOR_* + 1 stands for that system color
            return self.SYS_COLORS.get(hbr - 1, PseudoWindowsGUI.COLOR_WINDOW_BG)
        return None

    def FrameRect(self, args):
        """FrameRect emulation - one-pixel border drawn with a brush"""
        hdc = args[0]
        lprc = args[1]
        hbr = args[2]

        rect = self._read_rect(lprc) if lprc else None
        color = self._brush_color(hbr)
        if rect is None or color is None:
            return 0

        left, top, right, bottom = rect
        log.debug(f"FrameRect(0x{hdc:x}, ({left},{top},{right},{bottom}))")
        self._add_shape(hdc, {'type': 'rect', 'rect': rect,
                              'fill': None, 'pen': (color, 1)})
        return 1

    def PatBlt(self, args):
        """PatBlt emulation - BLACKNESS/WHITENESS/PATCOPY fills"""
        hdc = args[0]
        x, y, w, h = self._read_signed_args(args, 1, 4)
        rop = args[5]

        if rop == 0x00000042:        # BLACKNESS
            color = (0, 0, 0)
        elif rop == 0x00FF0062:      # WHITENESS
            color = (255, 255, 255)
        else:                        # PATCOPY and others: current brush
            color = self._dc_brush(hdc)

        log.debug(f"PatBlt(0x{hdc:x}, {x}, {y}, {w}, {h}, rop=0x{rop:08x})")
        if color is not None and w > 0 and h > 0:
            self._add_shape(hdc, {'type': 'rect', 'rect': (x, y, x + w, y + h),
                                  'fill': color, 'pen': None})
        return 1

    def CreateHatchBrush(self, args):
        """CreateHatchBrush emulation (hatch pattern approximated as solid)"""
        iHatch = args[0]
        colorref = args[1]
        handle = self.get_next_handle()
        self.gdi_objects[handle] = {
            'type': 'brush',
            'color': self._colorref_to_rgb(colorref),
            'width': 0,
        }
        log.debug(f"CreateHatchBrush({iHatch}, 0x{colorref:06x}) -> 0x{handle:x}")
        return handle

    def CreateFontA(self, args):
        """CreateFontA emulation"""
        height = args[0] - 0x100000000 if args[0] >= 0x80000000 else args[0]
        weight = args[4]
        italic = args[5]
        underline = args[6]
        face = self.read_string(args[13]) if args[13] else ""

        handle = self.get_next_handle()
        self.gdi_objects[handle] = {
            'type': 'font',
            'height': abs(height) or 13,
            'bold': weight >= 600,
            'italic': bool(italic),
            'underline': bool(underline),
            'face': face,
        }
        log.debug(f"CreateFontA(height={height}, weight={weight}, '{face}') -> 0x{handle:x}")
        return handle

    def CreateFontIndirectA(self, args):
        """CreateFontIndirectA emulation - font from a LOGFONT structure"""
        lplf = args[0]
        try:
            data = self.emu.uc.mem_read(lplf, 60)
            height = struct.unpack_from("<i", data, 0)[0]
            weight = struct.unpack_from("<i", data, 16)[0]
            italic, underline = data[20], data[21]
            face = data[28:60].split(b'\x00')[0].decode(ANSI_CODEPAGE, errors='replace')
        except UcError:
            return 0

        handle = self.get_next_handle()
        self.gdi_objects[handle] = {
            'type': 'font',
            'height': abs(height) or 13,
            'bold': weight >= 600,
            'italic': bool(italic),
            'underline': bool(underline),
            'face': face,
        }
        log.debug(f"CreateFontIndirectA(height={height}, '{face}') -> 0x{handle:x}")
        return handle

    def GetTextExtentPoint32A(self, args):
        """GetTextExtentPoint32A emulation - measure a string"""
        hdc = args[0]
        text = self.read_string(args[1]) if args[1] else ""
        c = args[2]
        lpSize = args[3]
        if c > 0 and len(text) > c:
            text = text[:c]

        width, height = self._text_extent(hdc, text)
        if lpSize:
            self.emu.uc.mem_write(lpSize, struct.pack("<ii", width, height))
        return 1

    def _text_extent(self, hdc, text):
        """Rough (width, height) of text; the GUI font is close to 8x16 per character"""
        font = self._dc_font(hdc)
        if font:
            return int(len(text) * font['height'] * 0.55), font['height']
        return len(text) * 8, 16

    # ==================== MEMORY DC / DOUBLE BUFFERING ====================

    def CreateCompatibleDC(self, args):
        """CreateCompatibleDC emulation - off-screen memory DC"""
        hdc = args[0]
        mem_dc = self._create_dc(0, memory=True)
        log.debug(f"CreateCompatibleDC(0x{hdc:x}) -> 0x{mem_dc:x}")
        return mem_dc

    def CreateCompatibleBitmap(self, args):
        """CreateCompatibleBitmap emulation"""
        hdc = args[0]
        width = args[1]
        height = args[2]
        handle = self.get_next_handle()
        self.gdi_objects[handle] = {'type': 'bitmap', 'width': width, 'height': height,
                                    'bpp': 32, 'shapes': []}
        log.debug(f"CreateCompatibleBitmap(0x{hdc:x}, {width}, {height}) -> 0x{handle:x}")
        return handle

    def DeleteDC(self, args):
        """DeleteDC emulation - free a memory DC"""
        hdc = args[0]
        log.debug(f"DeleteDC(0x{hdc:x})")
        self._delete_dc(hdc)
        return 1

    @staticmethod
    def _translate_shape(shape, dx, dy):
        """Copy of a display list entry shifted by (dx, dy)"""
        moved = dict(shape)
        if 'rect' in moved:
            l, t, r, b = moved['rect']
            moved['rect'] = (l + dx, t + dy, r + dx, b + dy)
        if 'pos' in moved:
            x, y = moved['pos']
            moved['pos'] = (x + dx, y + dy)
        if 'from' in moved:
            x, y = moved['from']
            moved['from'] = (x + dx, y + dy)
        if 'to' in moved:
            x, y = moved['to']
            moved['to'] = (x + dx, y + dy)
        if 'points' in moved:
            moved['points'] = [(x + dx, y + dy) for x, y in moved['points']]
        return moved

    def BitBlt(self, args):
        """BitBlt emulation - copy a memory DC's display list to the target.

        A blit that covers the whole client area replaces the window's
        display list, so per-frame game rendering doesn't accumulate shapes.
        """
        hdcDest = args[0]
        x, y, cx, cy = self._read_signed_args(args, 1, 4)
        hdcSrc = args[5]
        sx, sy = self._read_signed_args(args, 6, 2)
        rop = args[8]

        log.debug(f"BitBlt(0x{hdcDest:x}, {x}, {y}, {cx}, {cy}, src=0x{hdcSrc:x}, rop=0x{rop:08x})")

        if rop in (self.BLACKNESS, self.WHITENESS, self.PATCOPY):
            return self.PatBlt([hdcDest, x, y, cx, cy, rop])

        src_state = self.dc_state.get(hdcSrc)
        if not src_state or not src_state.get('memory'):
            return 1  # Only memory DC sources carry shapes

        dx, dy = x - sx, y - sy
        shapes = []
        for shape in src_state['shapes']:
            if shape['type'] == 'image':
                shape = self._crop_image(shape, sx, sy, cx, cy, rop)
                if shape is None:
                    continue
            else:
                box = PseudoWindowsGUI.shape_bbox(shape)
                if box and (box[2] <= sx or box[0] >= sx + cx or
                            box[3] <= sy or box[1] >= sy + cy):
                    continue  # Outside the copied area
                if shape['type'] == 'rect':
                    l, t, r, b = box
                    shape = dict(shape, rect=(max(l, sx), max(t, sy),
                                              min(r, sx + cx), min(b, sy + cy)))
            shapes.append(self._translate_shape(shape, dx, dy))

        # Shapes under a later one covering the whole copied area are invisible
        for i in range(len(shapes) - 1, 0, -1):
            if PseudoWindowsGUI.covers_rect(shapes[i], (x, y, x + cx, y + cy)):
                shapes = shapes[i:]
                break

        dest_state = self.dc_state.get(hdcDest)
        if dest_state and dest_state.get('memory'):
            bmp = self.gdi_objects.get(dest_state.get('bitmap', 0))
            if bmp and bmp.get('bpp') == 1:
                shapes = [self._to_monochrome(s, src_state['bk_color']) for s in shapes]
            for shape in shapes:
                self._add_shape(hdcDest, shape)
            return 1

        hwnd = self._dc_hwnd(hdcDest)
        if not self.gui or not hwnd or hwnd not in self.gui.windows:
            return 1

        window = self.gui.windows[hwnd]
        client_w, client_h = self.gui.client_size(window)
        if x <= 0 and y <= 0 and x + cx >= client_w and y + cy >= client_h:
            # Full-area blit: swap in a fresh list (GUI thread iterates snapshots)
            window.drawn_shapes = shapes
        else:
            for shape in shapes:
                self.gui.add_shape(hwnd, shape)
        return 1

    # Raster operations
    SRCCOPY = 0x00CC0020
    SRCPAINT = 0x00EE0086
    SRCAND = 0x008800C6
    SRCINVERT = 0x00660046
    NOTSRCCOPY = 0x00330008
    PATCOPY = 0x00F00021
    BLACKNESS = 0x00000042
    WHITENESS = 0x00FF0062

    def _crop_image(self, shape, sx, sy, cx, cy, rop):
        """Part of an image shape inside the source rect (sx, sy, cx, cy), or None.

        A non-SRCCOPY blit replaces the raster operation the image is drawn with.
        """
        x, y = shape['pos']
        w, h = shape['dim']
        if shape['size'] != shape['dim']:
            cropped = dict(shape)  # Stretched images are not cropped
        else:
            left, top = max(x, sx), max(y, sy)
            right, bottom = min(x + w, sx + cx), min(y + h, sy + cy)
            if right <= left or bottom <= top:
                return None
            if (left, top, right, bottom) == (x, y, x + w, y + h):
                cropped = dict(shape)
            else:
                row = w * 3
                start = (left - x) * 3
                end = (right - x) * 3
                data = b''.join(shape['data'][r * row + start:r * row + end]
                                for r in range(top - y, bottom - y))
                cropped = dict(shape, pos=(left, top), dim=(right - left, bottom - top),
                               size=(right - left, bottom - top), data=data)
        if rop != self.SRCCOPY:
            cropped['rop'] = rop
        cropped.pop('_surface', None)
        return cropped

    def _to_monochrome(self, shape, bk_color):
        """Shape blitted into a monochrome bitmap: the background color becomes
        white, every other color black (how masks are built from sprites)"""
        def mono(color):
            return (255, 255, 255) if color == bk_color else (0, 0, 0)
        shape = dict(shape)
        shape.pop('_surface', None)
        if shape['type'] == 'image':
            bk = bytes(bk_color)
            data = shape['data']
            shape['data'] = b''.join(b'\xff\xff\xff' if data[i:i + 3] == bk else b'\x00\x00\x00'
                                     for i in range(0, len(data), 3))
        for key in ('fill', 'color'):
            if shape.get(key) is not None:
                shape[key] = mono(shape[key])
        return shape

    def _new_bitmap(self, width, height, bpp, rgb=None):
        """Create a bitmap GDI object; rgb (top-down RGB bytes) becomes its picture"""
        handle = self.get_next_handle()
        shapes = []
        if rgb is not None and width > 0 and height > 0:
            shapes.append({'type': 'image', 'pos': (0, 0), 'dim': (width, height),
                           'size': (width, height), 'data': rgb, 'rop': self.SRCCOPY})
        self.gdi_objects[handle] = {'type': 'bitmap', 'width': width, 'height': height,
                                    'bpp': bpp, 'shapes': shapes}
        return handle

    @staticmethod
    def _decode_dib(data):
        """(width, height, top-down RGB bytes) of a packed DIB (BITMAPINFOHEADER,
        color table, bits), or None for unsupported formats"""
        if len(data) < 40:
            return None
        (hdr_size, width, height, _, bpp, compression, _, _, _,
         clr_used, _) = struct.unpack_from('<IiiHHIIiiII', data)
        if hdr_size < 40 or width <= 0 or height == 0 or compression not in (0, 3) or \
                bpp not in (1, 4, 8, 16, 24, 32):
            return None
        bottom_up = height > 0
        height = abs(height)
        offset = hdr_size
        masks = None
        if compression == 3:  # BI_BITFIELDS
            if bpp not in (16, 32):
                return None
            masks = struct.unpack_from('<III', data, offset)
            offset += 12
        elif bpp == 16:
            masks = (0x7C00, 0x03E0, 0x001F)  # 5-5-5
        palette = []
        if bpp <= 8:
            count = clr_used or (1 << bpp)
            for i in range(count):
                b, g, r = data[offset + 4 * i:offset + 4 * i + 3]
                palette.append(bytes((r, g, b)))
            offset += 4 * count
        stride = ((width * bpp + 31) // 32) * 4
        if len(data) < offset + stride * height:
            return None

        def channel(value, mask):
            if not mask:
                return 0
            shift = (mask & -mask).bit_length() - 1
            top = mask >> shift
            return ((value & mask) >> shift) * 255 // top

        if bpp <= 8:
            # Indexed: unpack pixels to one index byte each, then map every
            # channel through a 256-entry translate table
            padded = palette + [b'\x00\x00\x00'] * (256 - len(palette))
            tables = [bytes(p[c] for p in padded[:256]) for c in range(3)]
            per_byte = 8 // bpp
            mask = (1 << bpp) - 1
            unpack = [bytes((b >> (8 - bpp * (k + 1))) & mask for b in range(256))
                      for k in range(per_byte)] if bpp < 8 else None

        rows = []
        for r in range(height):
            src_row = (height - 1 - r) if bottom_up else r
            line = data[offset + src_row * stride:offset + (src_row + 1) * stride]
            if bpp == 24:
                out = bytearray(width * 3)
                out[0::3] = line[2:width * 3:3]
                out[1::3] = line[1:width * 3:3]
                out[2::3] = line[0:width * 3:3]
            elif bpp == 32 and masks is None:
                out = bytearray(width * 3)
                out[0::3] = line[2:width * 4:4]
                out[1::3] = line[1:width * 4:4]
                out[2::3] = line[0:width * 4:4]
            elif bpp in (16, 32):
                fmt = '<H' if bpp == 16 else '<I'
                step = bpp // 8
                out = bytearray()
                for i in range(width):
                    value = struct.unpack_from(fmt, line, i * step)[0]
                    out += bytes(channel(value, m) for m in masks)
            else:
                line = bytes(line)
                if unpack is None:
                    indices = line[:width]
                else:
                    expanded = bytearray(len(line) * per_byte)
                    for k in range(per_byte):
                        expanded[k::per_byte] = line.translate(unpack[k])
                    indices = bytes(expanded[:width])
                out = bytearray(width * 3)
                for c in range(3):
                    out[c::3] = indices.translate(tables[c])
            rows.append(bytes(out))
        return width, height, b''.join(rows)

    def LoadBitmapA(self, args):
        """LoadBitmapA emulation - a bitmap resource of the program"""
        hInstance, lpBitmapName = args[0], args[1]
        name = self._resource_key(lpBitmapName)
        if not hInstance:
            log.warning(f"LoadBitmapA: system bitmap {name} is not available")
            return 0
        resource = self._find_resource(2, name)  # RT_BITMAP
        decoded = None
        if resource:
            try:
                decoded = self._decode_dib(bytes(self.emu.uc.mem_read(*resource)))
            except UcError:
                decoded = None
        if decoded is None:
            log.warning(f"LoadBitmapA({name!r}): bitmap not found or unsupported")
            self._last_error = 1814  # ERROR_RESOURCE_NAME_NOT_FOUND
            return 0
        width, height, rgb = decoded
        handle = self._new_bitmap(width, height, 32, rgb)
        log.debug(f"LoadBitmapA({name!r}) -> 0x{handle:x} ({width}x{height})")
        return handle

    BITS_CACHE_SIZE = 8
    DIB_CACHE_SIZE = 64        # Entries of at most DIB_CACHE_MAX_BYTES each
    DIB_CACHE_MAX_BYTES = 65536

    # b'0'/b'1' bit characters -> black/white channel bytes
    _BIT_TO_GRAY = bytes.maketrans(b'01', b'\x00\xff')
    # Palette index bytes -> hex digit characters (for 4 bpp packing)
    _INDEX_TO_HEX = bytes.maketrans(bytes(range(16)), b'0123456789abcdef')

    def CreateBitmap(self, args):
        """CreateBitmap emulation - monochrome (1 bpp) or 24/32 bpp bits"""
        width, height = self._read_signed_args(args, 0, 2)
        planes, bit_count, lpBits = args[2], args[3], args[4]
        bpp = planes * bit_count
        if width <= 0 or height <= 0:
            return 0
        rgb = None
        if lpBits and bpp in (1, 24, 32):
            stride = ((width * bpp + 15) // 16) * 2  # DDB rows are WORD aligned
            try:
                bits = bytes(self.emu.uc.mem_read(lpBits, stride * height))
            except UcError:
                return 0
            # Shared picture for equal bits, so GetDIBits' cache can recognize it
            key = (width, height, bpp, bits)
            rgb = self._bits_cache.get(key)
            if rgb is not None:
                handle = self._new_bitmap(width, height, 1 if bpp == 1 else 32, rgb)
                log.debug(f"CreateBitmap({width}, {height}, {bpp} bpp) -> 0x{handle:x}")
                return handle
            out = bytearray(width * height * 3)
            if bpp == 1:
                digits = format(int.from_bytes(bits, 'big'), f'0{len(bits) * 8}b')
                if stride * 8 != width:
                    digits = ''.join(digits[r * stride * 8:r * stride * 8 + width]
                                     for r in range(height))
                gray = digits.encode().translate(self._BIT_TO_GRAY)
                out[0::3] = out[1::3] = out[2::3] = gray
            else:
                row = width * 3
                step = bpp // 8
                end = width * step
                for r in range(height):
                    line = bits[r * stride:(r + 1) * stride]
                    base = r * row
                    out[base:base + row:3] = line[2:end:step]
                    out[base + 1:base + row:3] = line[1:end:step]
                    out[base + 2:base + row:3] = line[0:end:step]
            rgb = bytes(out)
            if len(self._bits_cache) >= self.BITS_CACHE_SIZE:
                del self._bits_cache[next(iter(self._bits_cache))]
            self._bits_cache[key] = rgb
        handle = self._new_bitmap(width, height, 1 if bpp == 1 else 32, rgb)
        log.debug(f"CreateBitmap({width}, {height}, {bpp} bpp) -> 0x{handle:x}")
        return handle

    def GetObjectA(self, args):
        """GetObjectA emulation - BITMAP, LOGPEN, LOGBRUSH and LOGFONTA"""
        hObject, cbBuffer, lpvObject = args[0], args[1], args[2]
        obj = self.gdi_objects.get(hObject)
        if obj is None:
            return 0
        kind = obj['type']
        if kind == 'bitmap':
            bpp = obj.get('bpp', 32)
            width, height = obj['width'], obj['height']
            data = struct.pack('<iiiiHHI', 0, width, height,
                               ((width * bpp + 15) // 16) * 2, 1, bpp, 0)
        elif kind == 'pen':
            r, g, b = obj['color']
            data = struct.pack('<IiiI', obj.get('style', 0), obj['width'], 0,
                               r | (g << 8) | (b << 16))
        elif kind == 'brush':
            color = obj.get('color')
            if color is None:
                data = struct.pack('<III', 1, 0, 0)  # BS_NULL
            else:
                r, g, b = color
                data = struct.pack('<III', 0, r | (g << 8) | (b << 16), 0)
        elif kind == 'font':
            face = obj.get('face', '').encode(ANSI_CODEPAGE, errors='replace')[:31]
            data = struct.pack('<iiiii8B32s', -obj['height'], 0, 0, 0,
                               700 if obj.get('bold') else 400,
                               1 if obj.get('italic') else 0,
                               1 if obj.get('underline') else 0, 0, 0, 0, 0, 0, 0, face)
        elif kind == 'palette':
            data = struct.pack('<H', len(obj['entries']))
        else:
            return 0
        if not lpvObject:
            return len(data)
        data = data[:cbBuffer]
        return len(data) if self._mem_write(lpvObject, data) else 0

    @staticmethod
    def _scale_shape(shape, sx_src, sy_src, xd, yd, scale_x, scale_y):
        """Copy of a display list entry mapped through a StretchBlt transform"""
        def tx(x):
            return int(round(xd + (x - sx_src) * scale_x))

        def ty(y):
            return int(round(yd + (y - sy_src) * scale_y))

        scaled = dict(shape)
        if 'rect' in scaled:
            l, t, r, b = scaled['rect']
            x1, x2 = tx(l), tx(r)
            y1, y2 = ty(t), ty(b)
            # Normalize so mirrored blits keep left < right, top < bottom
            scaled['rect'] = (min(x1, x2), min(y1, y2), max(x1, x2), max(y1, y2))
        if 'pos' in scaled:
            x, y = scaled['pos']
            scaled['pos'] = (tx(x), ty(y))
        if 'from' in scaled:
            x, y = scaled['from']
            scaled['from'] = (tx(x), ty(y))
        if 'to' in scaled:
            x, y = scaled['to']
            scaled['to'] = (tx(x), ty(y))
        if 'points' in scaled:
            scaled['points'] = [(tx(x), ty(y)) for x, y in scaled['points']]
        if 'radius' in scaled:
            scale_avg = (abs(scale_x) + abs(scale_y)) / 2.0
            scaled['radius'] = max(0, int(round(scaled['radius'] * scale_avg)))
        if scaled['type'] == 'image':
            w, h = scaled['size']
            x, y = scaled['pos']
            x2, y2 = tx(shape['pos'][0] + w), ty(shape['pos'][1] + h)
            scaled['pos'] = (min(x, x2), min(y, y2))
            scaled['size'] = (abs(x2 - x), abs(y2 - y))
            scaled.pop('_surface', None)
        return scaled

    def StretchBlt(self, args):
        """StretchBlt emulation - copy a memory DC's display list scaled.

        Like BitBlt, but the source rectangle is mapped onto the destination
        rectangle; shape coordinates are transformed accordingly (pen widths
        and font sizes are kept as-is).
        """
        hdcDest = args[0]
        xd, yd, wd, hd = self._read_signed_args(args, 1, 4)
        hdcSrc = args[5]
        xs, ys, ws, hs = self._read_signed_args(args, 6, 4)
        rop = args[10]

        log.debug(f"StretchBlt(0x{hdcDest:x}, dst=({xd},{yd},{wd},{hd}), "
                  f"src=0x{hdcSrc:x} ({xs},{ys},{ws},{hs}), rop=0x{rop:08x})")

        if ws == 0 or hs == 0:
            return 0

        src_state = self.dc_state.get(hdcSrc)
        if not src_state or not src_state.get('memory'):
            return 1  # Only memory DC sources carry shapes

        scale_x = wd / ws
        scale_y = hd / hs
        shapes = []
        for shape in src_state['shapes']:
            if shape['type'] == 'image':
                shape = self._crop_image(shape, min(xs, xs + ws), min(ys, ys + hs),
                                         abs(ws), abs(hs), rop)
                if shape is None:
                    continue
            shapes.append(self._scale_shape(shape, xs, ys, xd, yd, scale_x, scale_y))

        dest_state = self.dc_state.get(hdcDest)
        if dest_state and dest_state.get('memory'):
            dest_state['shapes'].extend(shapes)
            return 1

        hwnd = self._dc_hwnd(hdcDest)
        if not self.gui or not hwnd or hwnd not in self.gui.windows:
            return 1

        window = self.gui.windows[hwnd]
        client_w, client_h = self.gui.client_size(window)
        if xd <= 0 and yd <= 0 and xd + wd >= client_w and yd + hd >= client_h:
            # Full-area blit: swap in a fresh list (GUI thread iterates snapshots)
            window.drawn_shapes = shapes
        else:
            window.drawn_shapes = window.drawn_shapes + shapes
        return 1

    # ---------- Device independent bitmaps ----------

    def _dc_palette_colors(self, hdc):
        """RGB entries of the palette selected into a DC (DIB_PAL_COLORS)"""
        state = self.dc_state.get(hdc) or {}
        palette = self.gdi_objects.get(state.get('palette', 0))
        if palette and palette['type'] == 'palette':
            return [entry[:3] for entry in palette['entries']]
        return []

    def _read_dib(self, hdc, lpbmi, lpBits, usage):
        """(width, height, top-down RGB, bottom_up) of a DIB given as BITMAPINFO
        and bits, or None for unsupported formats"""
        try:
            header = bytes(self.emu.uc.mem_read(lpbmi, 40))
            (hdr_size, width, height, _, bpp, compression, _, _, _,
             clr_used, _) = struct.unpack('<IiiHHIIiiII', header)
            if bpp <= 8:
                count = clr_used or (1 << bpp)
                if usage == 1:  # DIB_PAL_COLORS: WORD indices into the DC's palette
                    indices = struct.unpack(f'<{count}H',
                                            self.emu.uc.mem_read(lpbmi + hdr_size, 2 * count))
                    colors = self._dc_palette_colors(hdc)
                    table = b''.join(bytes((b, g, r, 0)) for r, g, b in
                                     (colors[i] if i < len(colors) else (0, 0, 0)
                                      for i in indices))
                else:
                    table = bytes(self.emu.uc.mem_read(lpbmi + hdr_size, 4 * count))
            elif compression == 3:  # BI_BITFIELDS (masks in V4/V5 headers too)
                count = 0
                table = bytes(self.emu.uc.mem_read(lpbmi + 40, 12))
            else:
                count, table = 0, b''
            stride = ((abs(width) * bpp + 31) // 32) * 4
            bits = bytes(self.emu.uc.mem_read(lpBits, stride * abs(height)))
        except (UcError, struct.error, OverflowError):
            return None
        packed = struct.pack('<IiiHHIIiiII', 40, width, height, 1, bpp, compression,
                             0, 0, 0, count, 0) + table + bits
        decoded = self._decode_dib(packed)
        if decoded is None:
            log.warning(f"Unsupported DIB: {width}x{height}, {bpp} bpp, "
                        f"compression {compression}")
            return None
        return decoded + (height > 0,)

    @staticmethod
    def _flip_rgb(data, width, height, flip_x, flip_y):
        """Mirror top-down RGB pixel data horizontally and/or vertically"""
        row = width * 3
        rows = [data[r * row:(r + 1) * row] for r in range(height)]
        if flip_y:
            rows.reverse()
        if flip_x:
            flipped = []
            for line in rows:
                reverse = line[::-1]  # Pixels reversed, channels as B, G, R
                out = bytearray(row)
                out[0::3], out[1::3], out[2::3] = reverse[2::3], reverse[1::3], reverse[0::3]
                flipped.append(bytes(out))
            rows = flipped
        return b''.join(rows)

    def StretchDIBits(self, args):
        """StretchDIBits emulation - a DIB (or part of it) scaled onto a DC"""
        hdc = args[0]
        xd, yd, wd, hd, xs, ys, ws, hs = self._read_signed_args(args, 1, 8)
        lpBits, lpbmi, usage, rop = args[9], args[10], args[11], args[12]
        log.debug(f"StretchDIBits(0x{hdc:x}, dst=({xd},{yd},{wd},{hd}), "
                  f"src=({xs},{ys},{ws},{hs}), rop=0x{rop:08x})")
        if rop in (self.BLACKNESS, self.WHITENESS, self.PATCOPY):
            self.PatBlt([hdc, xd, yd, wd, hd, rop])
            return abs(hs)
        if not wd or not hd or not ws or not hs or not lpBits or not lpbmi:
            return 0
        decoded = self._read_dib(hdc, lpbmi, lpBits, usage)
        if decoded is None:
            return 0
        width, height, rgb, bottom_up = decoded

        # Source rectangle in top-down image rows (ySrc counts from the bottom
        # of a bottom-up DIB)
        left, src_w = min(xs, xs + ws), abs(ws)
        low, src_h = min(ys, ys + hs), abs(hs)
        top = height - (low + src_h) if bottom_up else low
        scale_x, scale_y = abs(wd) / src_w, abs(hd) / src_h
        dst_x, dst_y = min(xd, xd + wd), min(yd, yd + hd)
        flip_x, flip_y = (ws < 0) != (wd < 0), (hs < 0) != (hd < 0)

        # Clip the source rectangle to the image
        c_left, c_top = max(left, 0), max(top, 0)
        c_right, c_bottom = min(left + src_w, width), min(top + src_h, height)
        if c_right <= c_left or c_bottom <= c_top:
            return 0
        if flip_x:
            dst_x += round((left + src_w - c_right) * scale_x)
        else:
            dst_x += round((c_left - left) * scale_x)
        if flip_y:
            dst_y += round((top + src_h - c_bottom) * scale_y)
        else:
            dst_y += round((c_top - top) * scale_y)
        cw, ch = c_right - c_left, c_bottom - c_top
        if (cw, ch) != (width, height):
            row = width * 3
            rgb = b''.join(rgb[r * row + c_left * 3:r * row + c_right * 3]
                           for r in range(c_top, c_bottom))
        if flip_x or flip_y:
            rgb = self._flip_rgb(rgb, cw, ch, flip_x, flip_y)
        size = (max(1, round(cw * scale_x)), max(1, round(ch * scale_y)))
        self._add_shape(hdc, {'type': 'image', 'pos': (dst_x, dst_y), 'dim': (cw, ch),
                              'size': size, 'data': rgb, 'rop': rop})
        return abs(hs)

    def SetStretchBltMode(self, args):
        """SetStretchBltMode emulation - returns the previous mode"""
        state = self.dc_state.get(args[0])
        if state is None or not 1 <= args[1] <= 4:
            return 0
        previous = state.get('stretch_mode', 1)  # BLACKONWHITE
        state['stretch_mode'] = args[1]
        return previous

    def _bitmap_shapes(self, hbm, bmp):
        """Display list of a bitmap; when selected, the DC has the live drawing"""
        for state in self.dc_state.values():
            if state.get('memory') and state.get('bitmap') == hbm:
                return state['shapes']
        return bmp['shapes']

    @staticmethod
    def _shapes_key(shapes):
        """(hashable key, image data objects) of a display list. Image data is
        keyed by identity, so the caller must keep the data objects alive."""
        parts, refs = [], []
        for shape in shapes:
            items = []
            for name, value in shape.items():
                if name == '_surface':
                    continue
                if name == 'data':
                    refs.append(value)
                    value = id(value)
                items.append((name, value))
            parts.append(repr(items))
        return '\n'.join(parts), refs

    def _bitmap_rgb(self, hbm):
        """Top-down RGB pixels of a bitmap object, rendered from its display list"""
        bmp = self.gdi_objects.get(hbm)
        if not bmp or bmp['type'] != 'bitmap':
            return None
        width, height = bmp['width'], bmp['height']
        shapes = self._bitmap_shapes(hbm, bmp)
        if (len(shapes) == 1 and shapes[0]['type'] == 'image' and shapes[0]['pos'] == (0, 0)
                and shapes[0]['dim'] == shapes[0]['size'] == (width, height)
                and shapes[0].get('rop') == self.SRCCOPY):
            return shapes[0]['data']
        if not PYGAME_AVAILABLE or not self.gui:
            return None
        surface = pygame.Surface((width, height))
        surface.fill((255, 255, 255) if bmp.get('bpp') == 1 else (0, 0, 0))
        for shape in shapes:
            self.gui._draw_shape(shape, 0, 0, target=surface)
        to_bytes = getattr(pygame.image, 'tobytes', None) or pygame.image.tostring
        return to_bytes(surface, 'RGB')

    def GetDIBits(self, args):
        """GetDIBits emulation - bitmap info (lpvBits NULL) or 24/32 bpp pixels"""
        hdc, hbm, start, lines, lpvBits, lpbmi, usage = args[:7]
        bmp = self.gdi_objects.get(hbm)
        if not bmp or bmp['type'] != 'bitmap' or not lpbmi:
            return 0
        width, height = bmp['width'], bmp['height']
        try:
            hdr_size, _, req_height, _, bpp = struct.unpack(
                '<IiiHH', self.emu.uc.mem_read(lpbmi, 16))
        except UcError:
            return 0
        if not lpvBits:
            if bpp == 0:
                bpp = 1 if bmp.get('bpp') == 1 else 32
                stride = ((width * bpp + 31) // 32) * 4
                header = struct.pack('<IiiHHIIiiII', max(hdr_size, 40), width, height, 1,
                                     bpp, 0, stride * height, 0, 0, 0, 0)
                if not self._mem_write(lpbmi, header):
                    return 0
            return height
        if bpp not in (1, 4, 8, 24, 32):
            log.warning(f"GetDIBits: {bpp} bpp output is not supported")
            return 0
        stride = ((width * bpp + 31) // 32) * 4
        step = bpp // 8
        bottom_up = req_height >= 0
        lines = min(lines, max(0, height - start))
        out = bytearray(stride * lines)
        palette = None
        if bpp <= 8:
            if bpp == 1:
                palette = [(0, 0, 0), (255, 255, 255)]
            elif bpp == 4:
                palette = [(0, 0, 0), (128, 0, 0), (0, 128, 0), (128, 128, 0), (0, 0, 128),
                           (128, 0, 128), (0, 128, 128), (192, 192, 192), (128, 128, 128),
                           (255, 0, 0), (0, 255, 0), (255, 255, 0), (0, 0, 255),
                           (255, 0, 255), (0, 255, 255), (255, 255, 255)]
            else:
                palette = self._dc_palette_colors(hdc)[:256] or [
                    (r * 255 // 7, g * 255 // 7, b * 255 // 3)
                    for r in range(8) for g in range(8) for b in range(4)]
            if usage == 1:  # DIB_PAL_COLORS
                table = struct.pack(f'<{len(palette)}H', *range(len(palette)))
            else:
                table = b''.join(bytes((b, g, r, 0)) for r, g, b in palette)
            self._mem_write(lpbmi + hdr_size, table)
            self._mem_write(lpbmi + 32, struct.pack('<I', len(palette)))  # biClrUsed

        # Programs often re-read the same picture (e.g. text drawn into a bitmap)
        shapes_key, refs = self._shapes_key(self._bitmap_shapes(hbm, bmp))
        key = (width, height, bmp.get('bpp'), bpp, bottom_up, start, lines,
               tuple(map(tuple, palette)) if palette else None, shapes_key)
        cached = self._dib_cache.get(key)
        if cached is not None:
            return lines if self._mem_write(lpvBits, cached[0]) else 0
        rgb = self._bitmap_rgb(hbm)
        if rgb is None:
            return 0
        if palette is not None:
            class Nearest(dict):
                def __missing__(cache, color):
                    index = min(range(len(palette)), key=lambda i: sum(
                        (a - b) ** 2 for a, b in zip(palette[i], color)))
                    cache[color] = index
                    return index
            index_of = Nearest().__getitem__
            reds = rgb[0::3]
            if reds == rgb[1::3] == rgb[2::3]:
                # Gray image (e.g. monochrome bitmaps): map the levels with one table
                gray = bytearray(256)
                for level in set(reds):
                    gray[level] = index_of((level, level, level))
                indices = reds.translate(gray)
            else:
                indices = bytes(map(index_of, zip(reds, rgb[1::3], rgb[2::3])))
            row_bytes = (width * bpp + 7) // 8

            def pack(row_indices, nbytes):
                if bpp == 8:
                    return row_indices
                digits = row_indices.translate(self._INDEX_TO_HEX).ljust(
                    nbytes * 8 // bpp, b'0')
                if bpp == 1:
                    return int(digits, 2).to_bytes(nbytes, 'big')
                return bytes.fromhex(digits.decode())

            packed = None
            if width * bpp % 8 == 0:
                packed = pack(indices, row_bytes * height)
        for i in range(lines):
            scan = start + i  # Scan lines count from the bottom of a bottom-up DIB
            src_row = height - 1 - scan if bottom_up else scan
            base = i * stride
            if palette is not None:
                if packed is not None:
                    row = packed[src_row * row_bytes:(src_row + 1) * row_bytes]
                else:
                    row = pack(indices[src_row * width:(src_row + 1) * width], row_bytes)
                out[base:base + row_bytes] = row
                continue
            line = rgb[src_row * width * 3:(src_row + 1) * width * 3]
            out[base + 2:base + width * step:step] = line[0::3]
            out[base + 1:base + width * step:step] = line[1::3]
            out[base:base + width * step:step] = line[2::3]
        if len(out) <= self.DIB_CACHE_MAX_BYTES:
            if len(self._dib_cache) >= self.DIB_CACHE_SIZE:
                del self._dib_cache[next(iter(self._dib_cache))]
            self._dib_cache[key] = (bytes(out), refs)
        return lines if self._mem_write(lpvBits, out) else 0

    def CreateDCA(self, args):
        """CreateDCA emulation - "DISPLAY" gives a screen DC"""
        driver = self.read_string(args[0]).upper() if args[0] else ''
        device = self.read_string(args[1]).upper() if args[1] else ''
        if driver.strip('\\.') == 'DISPLAY' or device.strip('\\.') == 'DISPLAY1':
            return self._create_dc(0)
        log.warning(f"CreateDCA({driver!r}, {device!r}): only the display is available")
        return 0

    FONT_FAMILIES = [('Arial', 0x22, 4), ('Courier New', 0x31, 4),
                     ('Times New Roman', 0x12, 4), ('MS Sans Serif', 0x22, 1),
                     ('System', 0x22, 1)]

    def EnumFontFamiliesA(self, args):
        """EnumFontFamiliesA emulation - a fixed set of common font families"""
        hdc, lpszFamily, lpProc, lParam = args[:4]
        family = self.read_string(lpszFamily) if lpszFamily else None
        fonts = [f for f in self.FONT_FAMILIES
                 if family is None or f[0].lower() == family.lower()]
        if not fonts:
            return 1
        buffer = self.emu.heap_alloc(156 + 72)
        if not buffer:
            return 0
        result = 1
        try:
            for name, pitch_family, font_type in fonts:
                face = name.encode('ascii')
                logfont = (struct.pack('<5i8B', -13, 0, 0, 0, 400, 0, 0, 0, 0, 0, 0,
                                       2 if font_type == 4 else 0, pitch_family)
                           + face.ljust(32, b'\x00'))
                enum_logfont = logfont + face.ljust(64, b'\x00') + b'Regular'.ljust(32, b'\x00')
                metrics = (struct.pack('<11i9B', 13, 10, 3, 0, 0, 6, 12, 400, 0, 96, 96,
                                       0x20, 0xFF, 0x1F, 0x20, 0, 0, 0, pitch_family, 0)
                           + b'\x00' * 3 + struct.pack('<4I', 0x40 if font_type == 4 else 0,
                                                       2048 if font_type == 4 else 0, 16, 6))
                self._mem_write(buffer, enum_logfont + metrics)
                result = self.emu.call_callback(lpProc, [buffer, buffer + 156, font_type,
                                                         lParam])
                if not result:
                    break
        finally:
            self.emu.heap_free(buffer)
        return result

    def ValidateRect(self, args):
        """ValidateRect emulation - mark the window as painted"""
        hWnd = args[0]
        self.painted_windows.add(hWnd)
        return 1

    # ==================== MENU APIs ====================

    MF_SEPARATOR = 0x0800
    MF_POPUP = 0x0010

    def CreateMenu(self, args):
        """CreateMenu emulation"""
        handle = self.get_next_handle()
        self.menus[handle] = []
        log.debug(f"CreateMenu() -> 0x{handle:x}")
        return handle

    def CreatePopupMenu(self, args):
        """CreatePopupMenu emulation"""
        handle = self.get_next_handle()
        self.menus[handle] = []
        log.debug(f"CreatePopupMenu() -> 0x{handle:x}")
        return handle

    def AppendMenuA(self, args):
        """AppendMenuA emulation"""
        hMenu = args[0]
        uFlags = args[1]
        uIDNewItem = args[2]
        lpNewItem = args[3]

        if hMenu not in self.menus:
            return 0

        text = ""
        if not (uFlags & self.MF_SEPARATOR) and lpNewItem:
            text = self.read_string(lpNewItem)

        self.menus[hMenu].append({
            'flags': uFlags,
            'id': uIDNewItem,
            'text': text,
            'submenu': uIDNewItem if (uFlags & self.MF_POPUP) else 0,
        })

        log.debug(f"AppendMenuA(0x{hMenu:x}, flags=0x{uFlags:x}, id=0x{uIDNewItem:x}, '{text}')")
        return 1

    def _build_menu_tree(self, hmenu):
        """Convert menu handles into the plain structure the GUI renders"""
        tree = []
        for item in self.menus.get(hmenu, []):
            if item['flags'] & self.MF_POPUP:
                subitems = []
                for sub in self.menus.get(item['submenu'], []):
                    if sub['flags'] & self.MF_SEPARATOR:
                        subitems.append({'separator': True})
                    else:
                        subitems.append({'text': sub['text'], 'id': sub['id']})
                tree.append({'text': item['text'], 'id': 0, 'items': subitems})
            elif item['flags'] & self.MF_SEPARATOR:
                continue  # Separators make no sense at the top level
            else:
                tree.append({'text': item['text'], 'id': item['id'], 'items': None})
        return tree

    def SetMenu(self, args):
        """SetMenu emulation - attach a menu bar to a window"""
        hWnd = args[0]
        hMenu = args[1]

        log.debug(f"SetMenu(0x{hWnd:x}, 0x{hMenu:x})")

        if self.gui and hWnd in self.gui.windows:
            window = self.gui.windows[hWnd]
            window.menu = self._build_menu_tree(hMenu) if hMenu else None
        return 1

    def DrawMenuBar(self, args):
        """DrawMenuBar emulation - menu bar is redrawn every frame anyway"""
        return 1

    def DestroyMenu(self, args):
        """DestroyMenu emulation"""
        hMenu = args[0]
        return 1 if self.menus.pop(hMenu, None) is not None else 0

    # ADVAPI32.DLL APIs - in-memory registry (per process, not persisted)

    # Predefined keys (HKEY_CLASSES_ROOT ... HKEY_CURRENT_CONFIG)
    REGISTRY_ROOTS = {0x80000000: 'HKEY_CLASSES_ROOT', 0x80000001: 'HKEY_CURRENT_USER',
                      0x80000002: 'HKEY_LOCAL_MACHINE', 0x80000003: 'HKEY_USERS',
                      0x80000005: 'HKEY_CURRENT_CONFIG'}
    REG_STRING_TYPES = (1, 2, 7)  # REG_SZ, REG_EXPAND_SZ, REG_MULTI_SZ

    ERROR_SUCCESS = 0
    ERROR_FILE_NOT_FOUND = 2
    ERROR_ACCESS_DENIED = 5
    ERROR_INVALID_HANDLE = 6
    ERROR_INVALID_PARAMETER = 87
    ERROR_MORE_DATA = 234
    ERROR_NO_MORE_ITEMS = 259
    ERROR_KEY_DELETED = 1018

    @staticmethod
    def _new_registry_key(name):
        return {'name': name, 'keys': {}, 'values': {}, 'deleted': False,
                'time': int((time.time() + 11644473600) * 10000000)}

    def _init_registry(self):
        for hkey, name in self.REGISTRY_ROOTS.items():
            self.registry_roots[hkey] = self._new_registry_key(name)
        for hkey, name in ((0x80000001, 'Software'), (0x80000002, 'SOFTWARE')):
            self.registry_roots[hkey]['keys'][name.lower()] = self._new_registry_key(name)

    def _registry_key(self, hkey):
        """(key node, error code) of an open or predefined HKEY"""
        node = self.registry_roots.get(hkey) or self.registry_handles.get(hkey)
        if node is None:
            return None, self.ERROR_INVALID_HANDLE
        if node['deleted']:
            return None, self.ERROR_KEY_DELETED
        return node, self.ERROR_SUCCESS

    @staticmethod
    def _registry_path(subkey):
        return [part for part in subkey.split('\\') if part]

    def _registry_open_common(self, hKey, subkey, phkResult, create, lpdwDisposition=0):
        node, error = self._registry_key(hKey)
        if node is None:
            return error
        disposition = 2  # REG_OPENED_EXISTING_KEY
        for part in self._registry_path(subkey):
            child = node['keys'].get(part.lower())
            if child is None:
                if not create:
                    return self.ERROR_FILE_NOT_FOUND
                child = self._new_registry_key(part)
                node['keys'][part.lower()] = child
                disposition = 1  # REG_CREATED_NEW_KEY
            node = child
        if not phkResult:
            return self.ERROR_INVALID_PARAMETER
        handle = self.get_next_handle()
        self.registry_handles[handle] = node
        self.emu.uc.mem_write(phkResult, struct.pack('<I', handle))
        if lpdwDisposition:
            self.emu.uc.mem_write(lpdwDisposition, struct.pack('<I', disposition))
        return self.ERROR_SUCCESS

    def RegOpenKeyExA(self, args, wide=False):
        """RegOpenKeyExA/W emulation"""
        hKey, lpSubKey, phkResult = args[0], args[1], args[4]
        subkey = self._read_text(lpSubKey, wide) if lpSubKey else ""
        result = self._registry_open_common(hKey, subkey, phkResult, create=False)
        log.debug(f"RegOpenKeyEx{'W' if wide else 'A'}(0x{hKey:x}, \"{subkey}\") -> {result}")
        return result

    def RegOpenKeyExW(self, args):
        return self.RegOpenKeyExA(args, wide=True)

    def RegCreateKeyExA(self, args, wide=False):
        """RegCreateKeyExA/W emulation"""
        hKey, lpSubKey, phkResult, lpdwDisposition = args[0], args[1], args[7], args[8]
        subkey = self._read_text(lpSubKey, wide) if lpSubKey else ""
        result = self._registry_open_common(hKey, subkey, phkResult, True, lpdwDisposition)
        log.debug(f"RegCreateKeyEx{'W' if wide else 'A'}(0x{hKey:x}, \"{subkey}\") -> {result}")
        return result

    def RegCreateKeyExW(self, args):
        return self.RegCreateKeyExA(args, wide=True)

    def RegCloseKey(self, args):
        """RegCloseKey emulation"""
        hKey = args[0]
        log.debug(f"RegCloseKey(0x{hKey:x})")
        if hKey in self.registry_roots or self.registry_handles.pop(hKey, None) is not None:
            return self.ERROR_SUCCESS
        return self.ERROR_INVALID_HANDLE

    def RegSetValueExA(self, args, wide=False):
        """RegSetValueExA/W emulation"""
        hKey, lpValueName, dwType, lpData, cbData = args[0], args[1], args[3], args[4], args[5]
        name = self._read_text(lpValueName, wide) if lpValueName else ""
        log.debug(f"RegSetValueEx{'W' if wide else 'A'}(0x{hKey:x}, \"{name}\", type={dwType})")
        node, error = self._registry_key(hKey)
        if node is None:
            return error
        try:
            data = bytes(self.emu.uc.mem_read(lpData, cbData)) if cbData else b''
        except UcError:
            return self.ERROR_INVALID_PARAMETER
        if dwType in self.REG_STRING_TYPES:
            # Strings are kept as text so the A and W APIs can both read them
            data = data.decode('utf-16-le' if wide else ANSI_CODEPAGE, errors='replace')
        node['values'][name.lower()] = {'name': name, 'type': dwType, 'data': data}
        node['time'] = int((time.time() + 11644473600) * 10000000)
        return self.ERROR_SUCCESS

    def RegSetValueExW(self, args):
        return self.RegSetValueExA(args, wide=True)

    def _registry_value_bytes(self, value, wide):
        data = value['data']
        if isinstance(data, str):
            return data.encode('utf-16-le') if wide else \
                data.encode(ANSI_CODEPAGE, errors='replace')
        return data

    def _registry_store_data(self, value, wide, lpType, lpData, lpcbData):
        """Copy a value's type and data out (RegQueryValueEx/RegEnumValue)"""
        data = self._registry_value_bytes(value, wide)
        if lpType:
            self.emu.uc.mem_write(lpType, struct.pack('<I', value['type']))
        if not lpcbData:
            return self.ERROR_INVALID_PARAMETER if lpData else self.ERROR_SUCCESS
        size = self._read_u32(lpcbData)
        self.emu.uc.mem_write(lpcbData, struct.pack('<I', len(data)))
        if lpData:
            if size < len(data):
                return self.ERROR_MORE_DATA
            self.emu.uc.mem_write(lpData, data)
        return self.ERROR_SUCCESS

    def RegQueryValueExA(self, args, wide=False):
        """RegQueryValueExA/W emulation"""
        hKey, lpValueName = args[0], args[1]
        lpType, lpData, lpcbData = args[3], args[4], args[5]
        name = self._read_text(lpValueName, wide) if lpValueName else ""
        node, error = self._registry_key(hKey)
        if node is not None:
            value = node['values'].get(name.lower())
            error = self.ERROR_FILE_NOT_FOUND if value is None else \
                self._registry_store_data(value, wide, lpType, lpData, lpcbData)
        log.debug(f"RegQueryValueEx{'W' if wide else 'A'}(0x{hKey:x}, \"{name}\") -> {error}")
        return error

    def RegQueryValueExW(self, args):
        return self.RegQueryValueExA(args, wide=True)

    def RegDeleteValueA(self, args):
        """RegDeleteValueA emulation"""
        hKey = args[0]
        name = self.read_string(args[1]) if args[1] else ""
        log.debug(f"RegDeleteValueA(0x{hKey:x}, \"{name}\")")
        node, error = self._registry_key(hKey)
        if node is None:
            return error
        if node['values'].pop(name.lower(), None) is None:
            return self.ERROR_FILE_NOT_FOUND
        return self.ERROR_SUCCESS

    def RegDeleteKeyA(self, args):
        """RegDeleteKeyA emulation - the key must have no subkeys"""
        hKey = args[0]
        subkey = self.read_string(args[1]) if args[1] else ""
        log.debug(f"RegDeleteKeyA(0x{hKey:x}, \"{subkey}\")")
        node, error = self._registry_key(hKey)
        if node is None:
            return error
        path = self._registry_path(subkey)
        if not path:
            return self.ERROR_ACCESS_DENIED
        for part in path[:-1]:
            node = node['keys'].get(part.lower())
            if node is None:
                return self.ERROR_FILE_NOT_FOUND
        target = node['keys'].get(path[-1].lower())
        if target is None:
            return self.ERROR_FILE_NOT_FOUND
        if target['keys']:
            return self.ERROR_ACCESS_DENIED
        del node['keys'][path[-1].lower()]
        target['deleted'] = True  # Open handles to it now fail
        return self.ERROR_SUCCESS

    def _registry_store_name(self, name, lpName, lpcchName):
        """Copy an ANSI key/value name; *lpcchName is in/out (chars)"""
        data = name.encode(ANSI_CODEPAGE, errors='replace')
        if not lpName or not lpcchName:
            return self.ERROR_INVALID_PARAMETER
        if self._read_u32(lpcchName) <= len(data):
            return self.ERROR_MORE_DATA
        self.emu.uc.mem_write(lpName, data + b'\x00')
        self.emu.uc.mem_write(lpcchName, struct.pack('<I', len(data)))
        return self.ERROR_SUCCESS

    def RegEnumKeyExA(self, args):
        """RegEnumKeyExA emulation - subkeys in alphabetical order"""
        hKey, dwIndex, lpName, lpcchName = args[0], args[1], args[2], args[3]
        lpClass, lpcchClass, lpftLastWriteTime = args[5], args[6], args[7]
        node, error = self._registry_key(hKey)
        if node is None:
            return error
        keys = sorted(node['keys'].values(), key=lambda k: k['name'].lower())
        if dwIndex >= len(keys):
            return self.ERROR_NO_MORE_ITEMS
        key = keys[dwIndex]
        error = self._registry_store_name(key['name'], lpName, lpcchName)
        if error:
            return error
        if lpClass:
            self.emu.uc.mem_write(lpClass, b'\x00')
        if lpcchClass:
            self.emu.uc.mem_write(lpcchClass, struct.pack('<I', 0))
        if lpftLastWriteTime:
            self.emu.uc.mem_write(lpftLastWriteTime, struct.pack('<Q', key['time']))
        return self.ERROR_SUCCESS

    def RegEnumValueA(self, args):
        """RegEnumValueA emulation - values in creation order"""
        hKey, dwIndex, lpValueName, lpcchValueName = args[0], args[1], args[2], args[3]
        lpType, lpData, lpcbData = args[5], args[6], args[7]
        node, error = self._registry_key(hKey)
        if node is None:
            return error
        values = list(node['values'].values())
        if dwIndex >= len(values):
            return self.ERROR_NO_MORE_ITEMS
        value = values[dwIndex]
        error = self._registry_store_name(value['name'], lpValueName, lpcchValueName)
        if error:
            return error
        return self._registry_store_data(value, False, lpType, lpData, lpcbData)
    
    # OLE32.DLL APIs
    def OleInitialize(self, args):
        """OleInitialize emulation"""
        log.debug("OleInitialize()")
        return 0  # S_OK
    
    def OleUninitialize(self, args):
        """OleUninitialize emulation"""
        log.debug("OleUninitialize()")
        return 0
    
    def CoInitialize(self, args):
        """CoInitialize emulation"""
        log.debug("CoInitialize()")
        return 0  # S_OK
    
    def CoUninitialize(self, args):
        """CoUninitialize emulation"""
        log.debug("CoUninitialize()")
        return 0
    
    # MSVCRT.DLL APIs
    def _ensure_fmode_addr(self):
        """Allocate memory for _fmode variable"""
        if self._fmode_addr == 0:
            self._fmode_addr = self.emu.heap_alloc(4)
            self.emu.uc.mem_write(self._fmode_addr, struct.pack('<I', 0x4000))  # _O_TEXT
        return self._fmode_addr
    
    def _ensure_commode_addr(self):
        """Allocate memory for _commode variable"""
        if self._commode_addr == 0:
            self._commode_addr = self.emu.heap_alloc(4)
            self.emu.uc.mem_write(self._commode_addr, struct.pack('<I', 0))  # Default commit mode
        return self._commode_addr
    
    def api__p__fmode(self, args):
        """__p__fmode emulation - Returns address of _fmode variable"""
        addr = self._ensure_fmode_addr()
        log.debug(f"__p__fmode() -> 0x{addr:08x}")
        return addr

    def api__p__acmdln(self, args):
        """__p__acmdln emulation - pointer to the ANSI command line pointer"""
        if self._acmdln_addr == 0:
            self._acmdln_addr = self.emu.heap_alloc(4)
            self.emu.uc.mem_write(self._acmdln_addr,
                                  struct.pack('<I', self.emu.cmdline_addr))
        log.debug(f"__p__acmdln() -> 0x{self._acmdln_addr:08x}")
        return self._acmdln_addr

    def api__p__wcmdln(self, args):
        """__p__wcmdln emulation - pointer to the wide command line pointer"""
        if self._wcmdln_addr == 0:
            self._wcmdln_addr = self.emu.heap_alloc(4)
            self.emu.uc.mem_write(self._wcmdln_addr,
                                  struct.pack('<I', self.emu.cmdline_wide_addr))
        log.debug(f"__p__wcmdln() -> 0x{self._wcmdln_addr:08x}")
        return self._wcmdln_addr

    def api__p__commode(self, args):
        """__p__commode emulation - Returns address of _commode variable"""
        addr = self._ensure_commode_addr()
        log.debug(f"__p__commode() -> 0x{addr:08x}")
        return addr
    
    def api__set_app_type(self, args):
        """__set_app_type emulation"""
        app_type = args[0]
        log.debug(f"__set_app_type({app_type})")
        return 0
    
    def _controlfp(self, args):
        """_controlfp emulation - floating point control word"""
        new_val = args[0]
        mask = args[1]
        log.debug(f"_controlfp(0x{new_val:x}, 0x{mask:x})")
        # Return default FPU control word
        return 0x9001F  # Default x86 FPU control word
    
    def _initterm(self, args):
        """_initterm emulation - Run C++ static initializer table"""
        pfbegin = args[0]
        pfend = args[1]
        log.debug(f"_initterm(0x{pfbegin:08x}, 0x{pfend:08x})")
        
        self._run_initializers(pfbegin, pfend, stop_on_error=False)
        return 0

    def _run_initializers(self, pfbegin, pfend, stop_on_error):
        current = pfbegin
        while current < pfend and not self.emu.stop_emulation:
            try:
                func_ptr = struct.unpack('<I', self.emu.uc.mem_read(current, 4))[0]
            except UcError:
                break
            current += 4
            if func_ptr in (0, 0xFFFFFFFF):
                continue
            log.debug(f"  _initterm: calling 0x{func_ptr:08x}")
            result = self.emu.call_callback(func_ptr, [])
            if stop_on_error and result != 0:
                return result
        return 0

    def _initterm_e(self, args):
        """_initterm_e emulation - stops at the first initializer returning non-zero"""
        log.debug(f"_initterm_e(0x{args[0]:08x}, 0x{args[1]:08x})")
        return self._run_initializers(args[0], args[1], stop_on_error=True)
    
    def api__getmainargs(self, args):
        """__getmainargs emulation - Returns argc, argv, environ"""
        p_argc = args[0]
        p_argv = args[1]
        p_env = args[2]
        do_wildcard = args[3]
        # startinfo = args[4]  # Optional
        
        log.debug(f"__getmainargs(0x{p_argc:08x}, 0x{p_argv:08x}, 0x{p_env:08x}, {do_wildcard})")
        
        # argc = 1
        self.emu.uc.mem_write(p_argc, struct.pack('<I', 1))
        
        # Allocate memory for argv
        if self._argv_addr == 0:
            self._argv_addr = self.emu.heap_alloc(16)  # argv array
            argv0_addr = self.emu.heap_alloc(256)  # argv[0] string
            
            # argv[0] = program name
            prog_name = self.windows_exe_path().encode(ANSI_CODEPAGE, errors='replace')
            self.emu.uc.mem_write(argv0_addr, prog_name[:255] + b'\x00')
            
            # argv[0] pointer, argv[1] = NULL
            self.emu.uc.mem_write(self._argv_addr, struct.pack('<II', argv0_addr, 0))
        
        self.emu.uc.mem_write(p_argv, struct.pack('<I', self._argv_addr))
        
        # Allocate memory for environ
        if self._environ_addr == 0:
            self._environ_addr = self.emu.heap_alloc(8)
            self.emu.uc.mem_write(self._environ_addr, struct.pack('<I', 0))  # NULL terminated
        
        self.emu.uc.mem_write(p_env, struct.pack('<I', self._environ_addr))
        
        return 0
    
    def api__wgetmainargs(self, args):
        """__wgetmainargs emulation - wide char version"""
        p_argc = args[0]
        p_argv = args[1]
        p_env = args[2]
        do_wildcard = args[3]
        
        log.debug(f"__wgetmainargs(0x{p_argc:08x}, 0x{p_argv:08x}, 0x{p_env:08x}, {do_wildcard})")
        
        # argc = 1
        self.emu.uc.mem_write(p_argc, struct.pack('<I', 1))
        
        # Allocate memory for wargv
        if self._wargv_addr == 0:
            self._wargv_addr = self.emu.heap_alloc(16)  # wargv array
            wargv0_addr = self.emu.heap_alloc(512)  # wargv[0] string
            
            # wargv[0] = program name (wide)
            prog_name = self.windows_exe_path()[:255]
            self.emu.uc.mem_write(wargv0_addr, prog_name.encode('utf-16-le') + b'\x00\x00')
            
            # wargv[0] pointer, wargv[1] = NULL
            self.emu.uc.mem_write(self._wargv_addr, struct.pack('<II', wargv0_addr, 0))
        
        self.emu.uc.mem_write(p_argv, struct.pack('<I', self._wargv_addr))
        
        # Allocate memory for wenviron
        if self._wenviron_addr == 0:
            self._wenviron_addr = self.emu.heap_alloc(8)
            self.emu.uc.mem_write(self._wenviron_addr, struct.pack('<I', 0))  # NULL terminated
        
        self.emu.uc.mem_write(p_env, struct.pack('<I', self._wenviron_addr))
        
        return 0
    
    def api__p___argc(self, args):
        """__p___argc emulation"""
        if self._argc == 0:
            self._argc = self.emu.heap_alloc(4)
            self.emu.uc.mem_write(self._argc, struct.pack('<I', 1))
        log.debug(f"__p___argc() -> 0x{self._argc:08x}")
        return self._argc
    
    def api__p___argv(self, args):
        """__p___argv emulation"""
        # Allocate memory for argv
        if self._argv_addr == 0:
            self._argv_addr = self.emu.heap_alloc(16)
            argv0_addr = self.emu.heap_alloc(256)
            prog_name = self.windows_exe_path().encode(ANSI_CODEPAGE, errors='replace')
            self.emu.uc.mem_write(argv0_addr, prog_name[:255] + b'\x00')
            self.emu.uc.mem_write(self._argv_addr, struct.pack('<II', argv0_addr, 0))
        
        # Return address of argv pointer
        argv_ptr_addr = self.emu.heap_alloc(4)
        self.emu.uc.mem_write(argv_ptr_addr, struct.pack('<I', self._argv_addr))
        log.debug(f"__p___argv() -> 0x{argv_ptr_addr:08x}")
        return argv_ptr_addr
    
    def api__p___wargv(self, args):
        """__p___wargv emulation"""
        if self._wargv_addr == 0:
            self._wargv_addr = self.emu.heap_alloc(16)
            wargv0_addr = self.emu.heap_alloc(512)
            prog_name = self.windows_exe_path()[:255]
            self.emu.uc.mem_write(wargv0_addr, prog_name.encode('utf-16-le') + b'\x00\x00')
            self.emu.uc.mem_write(self._wargv_addr, struct.pack('<II', wargv0_addr, 0))
        
        wargv_ptr_addr = self.emu.heap_alloc(4)
        self.emu.uc.mem_write(wargv_ptr_addr, struct.pack('<I', self._wargv_addr))
        log.debug(f"__p___wargv() -> 0x{wargv_ptr_addr:08x}")
        return wargv_ptr_addr
    
    def _amsg_exit(self, args):
        """_amsg_exit emulation - runtime error message and exit"""
        errnum = args[0]
        log.error(f"_amsg_exit({errnum}) - Runtime error!")
        self._set_exit_code(255)
        self.flush_std_streams()
        self.emu.stop_emulation = True
        return 0
    
    def _cexit(self, args):
        """_cexit emulation - run exit handlers without terminating"""
        log.debug("_cexit()")
        self.run_exit_handlers()
        self.flush_std_streams()
        return 0
    
    def _exit(self, args):
        """_exit emulation - terminate without running exit handlers"""
        code = args[0]
        log.debug(f"_exit({code})")
        self._set_exit_code(code)
        self.flush_std_streams()
        self.emu.stop_emulation = True
        return 0
    
    def exit(self, args):
        """exit emulation - run atexit handlers, flush, terminate"""
        code = args[0]
        log.debug(f"exit({code})")
        self.run_exit_handlers()
        self._set_exit_code(code)
        self.flush_std_streams()
        self.emu.stop_emulation = True
        return 0
    
    def _XcptFilter(self, args):
        """_XcptFilter emulation - exception filter"""
        log.debug("_XcptFilter()")
        return 1  # EXCEPTION_EXECUTE_HANDLER
    
    def _except_handler3(self, args):
        """_except_handler3 emulation - SEH handler"""
        log.debug("_except_handler3()")
        return 0
    
    def api__CxxFrameHandler3(self, args):
        """__CxxFrameHandler3 emulation - C++ exception handler"""
        log.debug("__CxxFrameHandler3()")
        return 0
    
    def _CxxThrowException(self, args):
        """_CxxThrowException emulation - no SEH support, so the exception is fatal"""
        log.error("Unhandled C++ exception (_CxxThrowException); "
                  "exception handling is not emulated")
        self.emu.crashed = True
        self.emu.stop_emulation = True
        return 0
    
    def _onexit(self, args):
        """_onexit emulation - atexit registration"""
        func = args[0]
        log.debug(f"_onexit(0x{func:08x})")
        if func:
            self.exit_handlers.append(func)
        return func  # Success
    
    def atexit(self, args):
        """atexit emulation"""
        func = args[0]
        log.debug(f"atexit(0x{func:08x})")
        if func:
            self.exit_handlers.append(func)
        return 0  # Success
    
    def _lock(self, args):
        """_lock emulation - critical section"""
        locknum = args[0]
        log.debug(f"_lock({locknum})")
        return 0
    
    def _unlock(self, args):
        """_unlock emulation"""
        locknum = args[0]
        log.debug(f"_unlock({locknum})")
        return 0
    
    def _encoded_null(self, args):
        """_encoded_null emulation"""
        return 0
    
    def _decode_pointer(self, args):
        """_decode_pointer emulation"""
        ptr = args[0]
        return ptr  # No encoding, return directly
    
    def _encode_pointer(self, args):
        """_encode_pointer emulation"""
        ptr = args[0]
        return ptr  # No encoding, return directly
    
    def _crt_debugger_hook(self, args):
        """_crt_debugger_hook emulation"""
        log.debug("_crt_debugger_hook()")
        return 0
    
    def api__dllonexit(self, args):
        """__dllonexit emulation"""
        func = args[0]
        log.debug(f"__dllonexit(0x{func:08x})")
        if func:
            self.exit_handlers.append(func)
        return func
    
    def _invoke_watson(self, args):
        """_invoke_watson emulation - security error handler"""
        log.error("_invoke_watson() - Security violation detected!")
        self.emu.stop_emulation = True
        return 0
    
    def api__security_init_cookie(self, args):
        """__security_init_cookie emulation - stack cookie initialization"""
        log.debug("__security_init_cookie()")
        return 0
    
    def api__security_check_cookie(self, args):
        """__security_check_cookie emulation"""
        cookie = args[0]
        log.debug(f"__security_check_cookie(0x{cookie:08x})")
        return 0
    
    # String functions
    def strlen(self, args):
        """strlen emulation"""
        s = args[0]
        data = self._read_until_null(s, 0x7FFFFFFF, 1) or b''
        log.debug(f"strlen(0x{s:08x}) -> {len(data)}")
        return len(data)
    
    def wcslen(self, args):
        """wcslen emulation"""
        s = args[0]
        string = self.read_wide_string(s)
        log.debug(f"wcslen() -> {len(string)}")
        return len(string)
    
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
                    text = bytes([value & 0xFF]).decode(ANSI_CODEPAGE, errors='replace')
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
        data = text.encode(ANSI_CODEPAGE, errors='replace')[:1023]
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
        data = text.encode(ANSI_CODEPAGE, errors='replace')
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
        data = self._format_string(fmt, args[1:]).encode(ANSI_CODEPAGE, errors='replace')
        self._stdout_stream().write(data)
        return len(data)
    
    def puts(self, args):
        """puts emulation"""
        s = self.read_string(args[0])
        self._stdout_stream().write((s + "\n").encode(ANSI_CODEPAGE, errors='replace'))
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
        try:
            data = self.emu.uc.mem_read(s_addr, 4096)
        except Exception:
            return 0
        end = data.find(b'\x00')
        limit = len(data) if end == -1 else end + 1  # include terminator (c may be 0)
        for i in range(limit):
            if data[i] == c:
                return s_addr + i
        return 0

    def strrchr(self, args):
        """strrchr emulation - pointer to last occurrence of a char (or NULL)"""
        s_addr = args[0]
        c = args[1] & 0xFF
        try:
            data = self.emu.uc.mem_read(s_addr, 4096)
        except Exception:
            return 0
        end = data.find(b'\x00')
        limit = len(data) if end == -1 else end + 1
        found = -1
        for i in range(limit):
            if data[i] == c:
                found = i
        return (s_addr + found) if found != -1 else 0

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
        return hay_addr + len(haystack[:idx].encode(ANSI_CODEPAGE, errors='replace'))

    def strncmp(self, args):
        """strncmp emulation"""
        n = args[2]
        try:
            d1 = bytes(self.emu.uc.mem_read(args[0], n))
            d2 = bytes(self.emu.uc.mem_read(args[1], n))
        except Exception:
            return 0
        # Compare up to n bytes, stopping at a shared null terminator
        for i in range(n):
            a, b = d1[i], d2[i]
            if a != b:
                return -1 if a < b else 1
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
        try:
            self.emu.uc.mem_write(s_addr, s[::-1].encode(ANSI_CODEPAGE, errors='replace') + b'\x00')
        except Exception:
            pass
        return s_addr

    def _strlwr(self, args):
        """_strlwr emulation - lowercase in place"""
        s_addr = args[0]
        s = self.read_string(s_addr)
        try:
            self.emu.uc.mem_write(s_addr, s.lower().encode(ANSI_CODEPAGE, errors='replace') + b'\x00')
        except Exception:
            pass
        return s_addr

    def _strupr(self, args):
        """_strupr emulation - uppercase in place"""
        s_addr = args[0]
        s = self.read_string(s_addr)
        try:
            self.emu.uc.mem_write(s_addr, s.upper().encode(ANSI_CODEPAGE, errors='replace') + b'\x00')
        except Exception:
            pass
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
        except Exception:
            return 0
        idx = data.find(bytes([c]))
        return (s_addr + idx) if idx != -1 else 0

    def _parse_c_integer(self, text, base):
        """Shared strtol/strtoul helper. Returns (value, chars_consumed)."""
        i = 0
        n = len(text)
        while i < n and text[i] in ' \t\n\r\v\f':
            i += 1
        start = i
        sign = 1
        if i < n and text[i] in '+-':
            if text[i] == '-':
                sign = -1
            i += 1
        # Determine/skip base prefix
        if base == 0:
            if i < n and text[i] == '0':
                if i + 1 < n and text[i + 1] in 'xX':
                    base = 16
                    i += 2
                else:
                    base = 8
                    i += 1
            else:
                base = 10
        elif base == 16 and i + 1 < n and text[i] == '0' and text[i + 1] in 'xX':
            i += 2
        digits_start = i
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
        if endptr:
            try:
                self.emu.uc.mem_write(endptr, struct.pack('<I', (nptr + consumed) & 0xFFFFFFFF))
            except Exception:
                pass
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
        if endptr:
            try:
                self.emu.uc.mem_write(endptr, struct.pack('<I', (nptr + consumed) & 0xFFFFFFFF))
            except Exception:
                pass
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
        try:
            self.emu.uc.mem_write(buf, text.encode(ANSI_CODEPAGE, errors='replace') + b'\x00')
        except Exception:
            pass
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
        try:
            self.emu.uc.mem_write(buf, text.encode(ANSI_CODEPAGE, errors='replace') + b'\x00')
        except Exception:
            pass
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
        except Exception:
            return 0

        # Two scratch buffers for the comparator arguments
        buf_a = self.emu.heap_alloc(size)
        buf_b = self.emu.heap_alloc(size)

        def cmp(a, b):
            try:
                self.emu.uc.mem_write(buf_a, a)
                self.emu.uc.mem_write(buf_b, b)
            except Exception:
                return 0
            r = self.emu.call_callback(compar, [buf_a, buf_b])
            # Return value is a signed int
            if r >= 0x80000000:
                r -= 0x100000000
            return r

        try:
            elements.sort(key=cmp_to_key(cmp))
            self.emu.uc.mem_write(base, b''.join(elements))
        except Exception as e:
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
                raw = bytes(units).decode(ANSI_CODEPAGE, errors='replace').encode('utf-16-le')
                text_units = list(struct.unpack(f'<{len(raw) // 2}H', raw))
            else:
                text = ''.join(chr(u) for u in units)
                text_units = list(text.encode(ANSI_CODEPAGE, errors='replace'))
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
                        self._mem_write(ptr, struct.pack('<d' if length in ('l', 'L') else '<f', value))
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
            fmt = list(''.join(chr(u) for u in fmt).encode(ANSI_CODEPAGE, errors='replace'))
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
        """fopen emulation - opens a real file inside the c_drive/ sandbox"""
        filename = self.read_string(args[0])
        mode = self.read_string(args[1])
        log.debug(f"fopen(\"{filename}\", \"{mode}\")")

        path = self.resolve_c_drive_path(filename)
        if path is None:
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
            except Exception as e:
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
        except Exception as e:
            log.error(f"fwrite mem_read error: {e}")
            return 0

        if fp is None:
            text = data.decode(ANSI_CODEPAGE, errors='replace')
            log.write(f"{Fore.YELLOW}[STDOUT]{Style.RESET_ALL} {text}")
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
            fp.seek(offset, {0: os.SEEK_SET, 1: os.SEEK_CUR, 2: os.SEEK_END}.get(whence, os.SEEK_SET))
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
        except Exception as e:
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
            log.write(f"{Fore.YELLOW}[STDOUT]{Style.RESET_ALL} {text}")
            self.console_output.append(text)
            self.console_write(text)
            return 0
        try:
            fp.write(text.encode(ANSI_CODEPAGE, errors='replace'))
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
        addr = self.emu.heap_alloc(size)
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
        if old_size is not None and self.emu.heap_resize_last(ptr, size):
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

    # ==================== ADDITIONAL CRT APIs ====================

    # CRT errno values used by the emulated functions
    EDOM = 33
    ERANGE = 34
    EINVAL = 22
    ENOENT = 2
    EEXIST = 17
    EACCES = 13

    _ERRNO_MESSAGES = {
        0: "No error", 1: "Operation not permitted", 2: "No such file or directory",
        3: "No such process", 4: "Interrupted function call", 5: "Input/output error",
        6: "No such device or address", 7: "Arg list too long", 8: "Exec format error",
        9: "Bad file descriptor", 10: "No child processes",
        11: "Resource temporarily unavailable", 12: "Not enough space",
        13: "Permission denied", 14: "Bad address", 16: "Resource device",
        17: "File exists", 18: "Improper link", 19: "No such device",
        20: "Not a directory", 21: "Is a directory", 22: "Invalid argument",
        23: "Too many open files in system", 24: "Too many open files",
        25: "Inappropriate I/O control operation", 27: "File too large",
        28: "No space left on device", 29: "Invalid seek", 30: "Read-only file system",
        31: "Too many links", 32: "Broken pipe", 33: "Domain error",
        34: "Result too large", 36: "Resource deadlock avoided", 38: "Filename too long",
        39: "No locks available", 40: "Function not implemented",
        41: "Directory not empty", 42: "Illegal byte sequence",
    }

    # Helpers taking their arguments in x87 registers: name -> ST(i) count.
    # Their stubs spill ST(0..n-1) to X87_ARGS_ADDR before the hooked RET.
    X87_ARG_FUNCTIONS = {
        '_CIsin': 1, '_CIcos': 1, '_CItan': 1, '_CIasin': 1, '_CIacos': 1,
        '_CIatan': 1, '_CIsinh': 1, '_CIcosh': 1, '_CItanh': 1, '_CIexp': 1,
        '_CIlog': 1, '_CIlog10': 1, '_CIsqrt': 1, '_CIpow': 2, '_CIatan2': 2,
        '_CIfmod': 2, '_ftol': 1, '_ftol2': 1, '_ftol2_sse': 1,
    }

    def native_prologue(self, func_name):
        """Machine code run in an API stub before the hooked RET."""
        count = self.X87_ARG_FUNCTIONS.get(func_name)
        if count:
            base = self.emu.X87_ARGS_ADDR
            # fstp qword ptr [slot i] for ST(0), then ST(1)...
            return b''.join(b'\xDD\x1D' + struct.pack('<I', base + 8 * i)
                            for i in range(count))
        if func_name == '_fpreset':
            return b'\xDB\xE3'  # fninit
        return b''

    def _x87_args(self, count):
        """x87 register arguments spilled by the stub, in source order."""
        data = bytes(self.emu.uc.mem_read(self.emu.X87_ARGS_ADDR, 8 * count))
        values = list(struct.unpack(f'<{count}d', data))
        return values[::-1]  # slot 0 held ST(0), the last operand

    @staticmethod
    def _signed32(value):
        value &= 0xFFFFFFFF
        return value - 0x100000000 if value & 0x80000000 else value

    @staticmethod
    def _signed64(value):
        value &= 0xFFFFFFFFFFFFFFFF
        return value - (1 << 64) if value >> 63 else value

    @staticmethod
    def _arg_double(args, index):
        """A double passed in two stack slots starting at args[index]."""
        return struct.unpack('<d', struct.pack('<II', args[index], args[index + 1]))[0]

    @staticmethod
    def _arg_qword(args, index):
        return args[index] | (args[index + 1] << 32)

    def _mem_write(self, addr, data):
        try:
            self.emu.uc.mem_write(addr, bytes(data))
            return True
        except UcError:
            return False

    def _read_u32(self, addr):
        try:
            return struct.unpack('<I', self.emu.uc.mem_read(addr, 4))[0]
        except UcError:
            return 0

    def _read_units(self, addr, wide):
        """NUL-terminated string as a list of code units (bytes or UTF-16)."""
        if not addr:
            return []
        if wide:
            data = self._read_until_null(addr, 0x10000, 2)
            if data is None:
                self._string_access_violation(addr)
                return []
            return list(struct.unpack(f'<{len(data) // 2}H', data))
        return list(self.read_cstring(addr))

    @staticmethod
    def _pack_units(units, wide):
        if wide:
            return struct.pack(f'<{len(units)}H', *(u & 0xFFFF for u in units))
        return bytes(u & 0xFF for u in units)

    def _write_units(self, addr, units, wide, terminate=True):
        units = list(units) + ([0] if terminate else [])
        return self._mem_write(addr, self._pack_units(units, wide))

    @staticmethod
    def _text_units(text, wide):
        """Encode Python text to code units (ANSI bytes or UTF-16)."""
        if wide:
            raw = text.encode('utf-16-le', errors='surrogatepass')
            return list(struct.unpack(f'<{len(raw) // 2}H', raw))
        return list(text.encode(ANSI_CODEPAGE, errors='replace'))

    @staticmethod
    def _units_text(units, wide):
        if wide:
            return struct.pack(f'<{len(units)}H', *units).decode('utf-16-le', errors='replace')
        return bytes(units).decode(ANSI_CODEPAGE, errors='replace')

    def _alloc_units(self, units, wide):
        """Heap copy of a string (with terminator); returns its address."""
        data = self._pack_units(list(units) + [0], wide)
        addr = self.emu.heap_alloc(len(data))
        if addr:
            self._mem_write(addr, data)
        return addr

    def _static_buffer(self, name, size):
        """Per-function static buffer (like the CRT's internal ones)."""
        addr = self._crt_static.get(name)
        if not addr:
            addr = self.emu.heap_alloc(size)
            self._crt_static[name] = addr
        return addr

    def _store_errno(self, value):
        self._mem_write(self._errno([]), struct.pack('<I', value & 0xFFFFFFFF))

    def _load_errno(self):
        return self._read_u32(self._errno([]))

    def _oserror_errno(self, error):
        """Map a host OSError to the CRT errno value."""
        mapping = {
            getattr(__import__('errno'), name): value
            for name, value in (('ENOENT', 2), ('EACCES', 13), ('EPERM', 13),
                                ('EEXIST', 17), ('ENOTDIR', 20), ('EISDIR', 13),
                                ('ENOTEMPTY', 41), ('EINVAL', 22))
        }
        return mapping.get(error.errno, self.EACCES)

    def _va_args(self, va_list, count=32):
        """Read up to count DWORD arguments from a va_list pointer."""
        values = []
        for i in range(count):
            try:
                values.append(struct.unpack('<I', self.emu.uc.mem_read(va_list + 4 * i, 4))[0])
            except UcError:
                break
        return values + [0] * (count - len(values))

    def _crt_extra_api_map(self):
        """Handlers whose names start with '__' or are generated from tables."""
        api = {
            '__setusermatherr': self._crt_noop,
            '__p__environ': lambda args: self._ensure_env_ptr('_environ_ptr_addr'),
            '__p__wenviron': lambda args: self._ensure_env_ptr('_wenviron_ptr_addr', wide=True),
            '__stdio_common_vfprintf': self.api__stdio_common_vfprintf,
            '__stdio_common_vfwprintf': self.api__stdio_common_vfwprintf,
            '__stdio_common_vsprintf': self.api__stdio_common_vsprintf,
            '__stdio_common_vswprintf': self.api__stdio_common_vswprintf,
            '__stdio_common_vsprintf_s': self.api__stdio_common_vsprintf_s,
            '__stdio_common_vswprintf_s': self.api__stdio_common_vswprintf_s,
            '__stdio_common_vsnprintf_s': self.api__stdio_common_vsnprintf_s,
            '__stdio_common_vsscanf': self.api__stdio_common_vsscanf,
            '__stdio_common_vswscanf': self.api__stdio_common_vswscanf,
            '__stdio_common_vfscanf': self.api__stdio_common_vfscanf,
            'raise': self._crt_raise,  # Python keyword
        }
        # Double math functions: cdecl versions take stack arguments, the
        # MSVC _CI* intrinsics take them in x87 registers
        for name, (func, argc) in self._MATH_FUNCTIONS.items():
            api[name] = self._make_math_handler(name, func, argc, x87=False)
            ci_name = '_CI' + name
            if ci_name in self.X87_ARG_FUNCTIONS:
                api[ci_name] = self._make_math_handler(ci_name, func, argc, x87=True)
        api['_hypot'] = api['hypot']
        # Wide character classification (wctype) functions
        for name, test in self._WCTYPE_TESTS.items():
            api[name] = (lambda t: lambda args: 1 if t(chr(args[0] & 0xFFFF)) else 0)(test)
        return api

    def _crt_noop(self, args):
        return 0

    # ---- Math (double results are returned in ST(0)) ----

    @staticmethod
    def _c_floor(x):
        return float(math.floor(x)) if math.isfinite(x) else x

    @staticmethod
    def _c_ceil(x):
        return float(math.ceil(x)) if math.isfinite(x) else x

    class _MathRange(Exception):
        """Range error with a defined C result (e.g. log(0) == -HUGE_VAL)."""
        def __init__(self, value):
            super().__init__(value)
            self.value = value

    @staticmethod
    def _c_log(x, log_func=math.log):
        if x == 0:
            raise WinAPIHandler._MathRange(-math.inf)
        return log_func(x)

    @staticmethod
    def _c_pow(x, y):
        odd_int = float(y).is_integer() and int(y) % 2 == 1
        if x == 0 and y < 0:
            raise WinAPIHandler._MathRange(math.copysign(math.inf, x) if odd_int else math.inf)
        try:
            return math.pow(x, y)
        except OverflowError:
            raise WinAPIHandler._MathRange(-math.inf if x < 0 and odd_int else math.inf)

    _MATH_FUNCTIONS = {
        'sin': (math.sin, 1), 'cos': (math.cos, 1), 'tan': (math.tan, 1),
        'asin': (math.asin, 1), 'acos': (math.acos, 1), 'atan': (math.atan, 1),
        'sinh': (math.sinh, 1), 'cosh': (math.cosh, 1), 'tanh': (math.tanh, 1),
        'exp': (math.exp, 1), 'sqrt': (math.sqrt, 1), 'fabs': (math.fabs, 1),
        'log': (lambda x: WinAPIHandler._c_log(x), 1),
        'log10': (lambda x: WinAPIHandler._c_log(x, math.log10), 1),
        'floor': (lambda x: WinAPIHandler._c_floor(x), 1),
        'ceil': (lambda x: WinAPIHandler._c_ceil(x), 1),
        'atan2': (math.atan2, 2), 'fmod': (math.fmod, 2), 'hypot': (math.hypot, 2),
        'pow': (lambda x, y: WinAPIHandler._c_pow(x, y), 2),
        '_copysign': (math.copysign, 2),
    }

    def _math_call(self, func, values):
        """Run a math function with C error semantics (errno, NaN, HUGE_VAL)."""
        try:
            return func(*values)
        except ValueError:
            self._store_errno(self.EDOM)
            return math.nan
        except WinAPIHandler._MathRange as e:
            self._store_errno(self.ERANGE)
            return e.value
        except OverflowError:
            self._store_errno(self.ERANGE)
            if func is math.sinh:
                return math.copysign(math.inf, values[0])
            return math.inf

    def _make_math_handler(self, name, func, argc, x87):
        def handler(args):
            if x87:
                values = self._x87_args(argc)
            else:
                values = [self._arg_double(args, 2 * i) for i in range(argc)]
            result = self._math_call(func, values)
            log.debug(f"{name}{tuple(values)} -> {result}")
            return X87Result(result)
        return handler

    def ldexp(self, args):
        """ldexp emulation (x * 2^exp)"""
        x = self._arg_double(args, 0)
        try:
            return X87Result(math.ldexp(x, self._signed32(args[2])))
        except OverflowError:
            self._store_errno(self.ERANGE)
            return X87Result(math.copysign(math.inf, x))

    def frexp(self, args):
        """frexp emulation (mantissa, *exp)"""
        x = self._arg_double(args, 0)
        mantissa, exponent = math.frexp(x) if math.isfinite(x) else (x, 0)
        if args[2]:
            self._mem_write(args[2], struct.pack('<i', exponent))
        return X87Result(mantissa)

    def modf(self, args):
        """modf emulation (fractional part, *integer part)"""
        x = self._arg_double(args, 0)
        if math.isinf(x):
            frac, whole = math.copysign(0.0, x), x
        else:
            frac, whole = math.modf(x)
        if args[2]:
            self._mem_write(args[2], struct.pack('<d', whole))
        return X87Result(frac)

    def _chgsign(self, args):
        """_chgsign emulation"""
        return X87Result(-self._arg_double(args, 0))

    def _isnan(self, args):
        """_isnan emulation"""
        return 1 if math.isnan(self._arg_double(args, 0)) else 0

    def _finite(self, args):
        """_finite emulation"""
        return 1 if math.isfinite(self._arg_double(args, 0)) else 0

    def _ftol_common(self):
        value = self._x87_args(1)[0]
        if not math.isfinite(value) or not -(1 << 63) <= value < (1 << 63):
            return QWordResult(1 << 63)  # integer indefinite
        return QWordResult(int(value))  # truncation toward zero

    def _ftol(self, args):
        """_ftol emulation - ST(0) truncated to a 64-bit integer in EDX:EAX"""
        return self._ftol_common()

    def _ftol2(self, args):
        return self._ftol_common()

    def _ftol2_sse(self, args):
        return self._ftol_common()

    def _fpreset(self, args):
        """_fpreset emulation (the stub already executed FNINIT)"""
        return 0

    def _clearfp(self, args):
        """_clearfp emulation - no exception flags are tracked"""
        return 0

    def _statusfp(self, args):
        """_statusfp emulation"""
        return 0

    def _controlfp_s(self, args):
        """_controlfp_s emulation"""
        if args[0]:
            self._mem_write(args[0], struct.pack('<I', 0x9001F))
        return 0

    def _control87(self, args):
        return self._controlfp(args)

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
        data = text.encode(ANSI_CODEPAGE, errors='replace')
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
        return 0 if self._stream_write(args[1], text.encode(ANSI_CODEPAGE, errors='replace')) else 0xFFFFFFFF

    def _putws(self, args):
        """_putws emulation"""
        text = self.read_wide_string(args[0]) + "\n"
        self._stdout_stream().write(text.encode(ANSI_CODEPAGE, errors='replace'))
        return 0

    def fputwc(self, args):
        """fputwc emulation"""
        ch = args[0] & 0xFFFF
        ok = self._stream_write(args[1], chr(ch).encode(ANSI_CODEPAGE, errors='replace'))
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
        path = self.resolve_c_drive_path(filename)
        if path is None:
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
        self.std_streams[2].write(text.encode(ANSI_CODEPAGE, errors='replace'))
        return 0

    # ---- File system (sandboxed in c_drive/) ----

    def _sandbox_op(self, name_addr, op, wide=False):
        """Run op(host_path) for a program path; returns 0 or -1 with errno."""
        filename = self._read_text(name_addr, wide)
        path = self.resolve_c_drive_path(filename)
        if path is None:
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
        new_path = self.resolve_c_drive_path(self.read_string(args[1]))
        if new_path is None:
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
            if mode & 2 and not os.access(path, os.W_OK):
                raise PermissionError(__import__('errno').EACCES, "read-only")
        return self._sandbox_op(args[0], check)

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

    # ---- Strings (narrow and wide share unit-based helpers) ----

    @staticmethod
    def _fold_unit(u):
        """Case-fold one code unit (per-character lower case, like _stricmp)."""
        lowered = chr(u).lower()
        return ord(lowered) if len(lowered) == 1 else u

    @staticmethod
    def _cmp_units(a, b):
        for x, y in zip(a, b):
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
                ch = data[:k].decode(ANSI_CODEPAGE)
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
        data = chr(args[1] & 0xFFFF).encode(ANSI_CODEPAGE, errors='replace')
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
        self._write_units(args[2], self._int_to_units(self._arg_qword(args, 0), args[3], False), False)
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
        for addr, part in zip(args[1:5], (drive, directory, fname, ext)):
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
            self._crt_static[key] = self._alloc_units(self._text_units(rest.lstrip(' \t'), wide), wide)
        return self._crt_static[key]

    # ---- Process control and signals ----

    SIGINT, SIGILL, SIGFPE, SIGSEGV, SIGTERM, SIGBREAK, SIGABRT = 2, 4, 8, 11, 15, 21, 22

    def _crt_terminate(self, code, message=None):
        if message:
            self._ensure_iob()
            self.std_streams[2].write(message.encode(ANSI_CODEPAGE, errors='replace'))
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
        uc = self.emu.uc
        uc.reg_write(UC_X86_REG_EBP, ebp)
        uc.reg_write(UC_X86_REG_EBX, ebx)
        uc.reg_write(UC_X86_REG_EDI, edi)
        uc.reg_write(UC_X86_REG_ESI, esi)
        return ApiJump(eip, esp, value or 1)

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

            def num(value, width=2):
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
                'z': f"{'+' if tz_minutes >= 0 else '-'}{abs(tz_minutes) // 60:02d}{abs(tz_minutes) % 60:02d}",
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
        return 0

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

def gui_locked(method):
    """Run a PseudoWindowsGUI method while holding its lock (shared with the GUI thread)"""
    @wraps(method)
    def wrapper(self, *args, **kwargs):
        with self.lock:
            return method(self, *args, **kwargs)
    return wrapper


class FakeWindow:
    """Fake Windows window"""
    
    def __init__(self, hwnd, title, x, y, width, height, style=0):
        self.hwnd = hwnd
        self.title = title
        self.x = x
        self.y = y
        self.width = width
        self.height = height
        self.style = style
        self.visible = False
        self.enabled = True
        self.parent = None
        self.children = []
        self.size_state = None  # (SIZE_* kind, client w, h) last told to the app (WM_SIZE)
        self.controls = []  # Buttons, text boxes, etc.
        self.wndproc = 0
        self.owner = None  # WinAPIHandler of the process that created it (None: emulator's own)
        self.bg_color = (212, 208, 200)  # Classic Windows gray (COLOR_BTNFACE)
        self.text = title

        # Retained drawing list (GDI display list, redrawn every frame):
        # Rectangle/Ellipse/LineTo/SetPixel/Polygon/TextOut... items
        self.drawn_shapes = []

        # Menu bar: list of {'text', 'id', 'items': [...]} or None
        self.menu = None

        # Window state
        self.minimized = False
        self.maximized = False
        self.is_dialog = False  # True if Dialog/MessageBox (only close button)
        
        # Original dimensions for restore
        self.restore_x = x
        self.restore_y = y
        self.restore_width = width
        self.restore_height = height
        
    def contains_point(self, px, py):
        """Is point inside window?"""
        if self.minimized:
            return False
        return (self.x <= px <= self.x + self.width and 
                self.y <= py <= self.y + self.height)
    
    def get_title_bar_rect(self):
        """Title bar rectangle"""
        return (self.x, self.y, self.width, 25)
    
    def minimize(self):
        """Minimize window"""
        if not self.minimized:
            self.minimized = True
    
    def restore(self):
        """Restore window"""
        if self.minimized:
            self.minimized = False
        elif self.maximized:
            self.x = self.restore_x
            self.y = self.restore_y
            self.width = self.restore_width
            self.height = self.restore_height
            self.maximized = False
    
    def maximize(self, screen_width, screen_height, taskbar_height=30):
        """Maximize window"""
        if not self.maximized:
            # Save original dimensions
            self.restore_x = self.x
            self.restore_y = self.y
            self.restore_width = self.width
            self.restore_height = self.height
            
            # Go fullscreen (except taskbar)
            self.x = 0
            self.y = 0
            self.width = screen_width
            self.height = screen_height - taskbar_height
            self.maximized = True
        else:
            # Restore
            self.restore()


class FakeControl:
    """Fake Windows control (Button, Edit, Static, etc.)"""
    
    def __init__(self, hwnd, class_name, text, x, y, width, height, style=0):
        self.hwnd = hwnd
        self.class_name = class_name.upper()
        self.text = text
        self.x = x
        self.y = y
        self.width = width
        self.height = height
        self.style = style
        self.visible = True
        self.enabled = True
        self.parent_hwnd = 0
        self.control_id = 0  # Control ID (hMenu in CreateWindowEx) for WM_COMMAND
        self.checked = False  # For Checkbox/Radio
        self.drawn_shapes = []  # GDI drawing on the control's DC (owner-draw)
        self.items = []       # For Listbox/Combobox (LB_ADDSTRING, CB_ADDSTRING)
        self.sel_index = -1   # Selected item index (-1 = none)
        self.top_index = 0    # First visible LISTBOX item (mouse wheel scrolling)
        # Scrollbar state (SCROLLBAR class)
        self.scroll_min = 0
        self.scroll_max = 100
        self.scroll_pos = 0
        self.scroll_page = 0  # 0 = no page size set (SetScrollInfo SIF_PAGE)
        self.font = None      # GDI font dict set by WM_SETFONT (None: GUI font)
        self.font_handle = 0
        # Status bar (STATUSBAR class): pane right edges (-1: to the end),
        # texts of panes 1+ (pane 0 is self.text; 255 is the simple-mode text)
        self.parts = [-1]
        self.part_texts = {}
        self.simple = False

    def contains_point(self, px, py, parent_x=0, parent_y=0):
        """Is point inside control?"""
        abs_x = parent_x + self.x
        abs_y = parent_y + self.y
        return (abs_x <= px <= abs_x + self.width and 
                abs_y <= py <= abs_y + self.height)


class FakeConsole:
    """Console of one process: its output lines and a pending line read"""

    MAX_LINES = 100

    def __init__(self, hwnd):
        self.hwnd = hwnd  # Console window
        self.lines = []  # Each line: [(text, color), ...]
        self.line_open = False  # Last line not ended by LF yet (output continues it)
        self.scroll = 0
        self.input = ""  # Line being typed
        self.input_active = False  # A ReadConsole/stdin read is waiting
        self.input_result = None
        self.input_ready = threading.Event()
        self.cancelled = False  # Process ending or console closed: reads return None


class _ProcessRouter:
    """GUI-side stand-in for a WinAPIHandler while several programs run at once.

    Window messages go to the process owning the target window; other
    attributes (message constants, scroll_pos_max) come from WinAPIHandler.
    """

    def __init__(self, gui):
        self._gui = gui

    def __getattr__(self, name):
        return getattr(WinAPIHandler, name)

    def post_window_message(self, hwnd, message, wParam, lParam):
        owner = self._gui.window_owner(hwnd)
        if owner is not None and not owner.process_exited:
            owner.post_window_message(hwnd, message, wParam, lParam)

    @property
    def capture_hwnd(self):
        for process in list(self._gui.processes):
            if process.capture_hwnd:
                return process.capture_hwnd
        return 0

class PseudoWindowsGUI:
    """Pygame-based fake Windows GUI environment"""
    
    # Windows colors
    COLOR_DESKTOP = (58, 110, 165)  # #3a6ea5, Windows 2000 blue
    COLOR_WINDOW_BG = (212, 208, 200)  # Classic Windows gray (COLOR_BTNFACE)
    COLOR_TITLE_BAR = (0, 0, 128)  # Classic blue
    COLOR_TITLE_BAR_INACTIVE = (128, 128, 128)
    COLOR_TITLE_TEXT = (255, 255, 255)
    COLOR_BUTTON = (212, 208, 200)
    COLOR_BUTTON_BORDER_LIGHT = (255, 255, 255)
    COLOR_BUTTON_BORDER_DARK = (64, 64, 64)
    COLOR_TEXT = (0, 0, 0)
    COLOR_EDIT_BG = (255, 255, 255)
    COLOR_TASKBAR = (192, 192, 192)

    # Resize settings
    RESIZE_BORDER = 6      # Edge grab margin (pixels)
    MIN_WINDOW_WIDTH = 120
    MIN_WINDOW_HEIGHT = 80

    # Window chrome geometry (client area origin = x+BORDER, y+BORDER+TITLE_BAR_H)
    BORDER = 3
    TITLE_BAR_H = 25
    MENU_H = 20  # Menu bar height (only when the window has a menu)
    LISTBOX_ITEM_H = 18  # Row height in LISTBOX and COMBOBOX dropdowns

    # Window styles deciding the frame of a top-level window
    WS_POPUP = 0x80000000
    WS_CAPTION = 0x00C00000
    WS_BORDER = 0x00800000
    WS_DLGFRAME = 0x00400000
    WS_THICKFRAME = 0x00040000
    DS_MODALFRAME = 0x80

    def __init__(self, width=1024, height=768):
        self.width = width
        self.height = height
        # Display mode set at startup (the registry mode); ChangeDisplaySettings
        # changes width/height, the GUI thread then resizes the screen
        self.desktop_width = width
        self.desktop_height = height
        self.pending_mode = None
        self.display_mode_owner = None  # Process that changed the display mode
        self.screen = None
        self.running = False
        self.clock = None
        # Running programs (WinAPIHandler each); winapi routes messages to them
        self.processes = []
        self.winapi = _ProcessRouter(self)
        
        # Window management
        self.windows = {}  # hwnd -> FakeWindow
        self.controls = {}  # hwnd -> FakeControl
        self.next_hwnd = 0x10000
        self.active_window = None
        self.notified_active = None  # Window last told it is active (WM_ACTIVATE)
        self.z_order = []  # Window ordering (topmost is at end)

        # Keyboard focus (EDIT controls)
        self.focused_control = None  # hwnd of the focused control

        # Open dropdown menu: (window_hwnd, top_level_item_index) or None
        self.open_menu = None

        # Open combobox dropdown: control hwnd or None
        self.open_combo = None

        # Start menu: open flag, rows (C:\ programs, then an Examples submenu
        # listing C:\Windows\Examples), and the callback that runs one (set by main)
        self.start_menu_open = False
        self.start_menu_rows = []
        self.start_menu_examples = []
        self.start_submenu_open = False
        self.show_examples = True  # False with --no-examples: no Examples submenu
        self.launcher = None

        # Keyboard state for GetAsyncKeyState (vk -> bool, GUI thread writes)
        self.key_states = {}

        # Last mouse position for GetCursorPos (GUI thread writes)
        self.mouse_pos = (0, 0)

        # Font
        self.font = None
        self.font_small = None
        self.font_bold = None
        self._font_cache = {}  # (face, size, bold, italic) -> pygame Font
        
        # Event queue
        self.event_queue = queue.Queue()
        self.message_queue = queue.Queue()
        
        # MessageBox queue
        self.messagebox_queue = queue.Queue()
        # Guards windows/controls/z_order and display lists across threads
        self.lock = threading.RLock()
        self.messagebox_result = None
        
        # Thread
        self.gui_thread = None
        self.ready = threading.Event()  # Set once the GUI loop is running
        self.consoles_opened = 0  # Cascades the console windows
        
        # Console windows of the programs: hwnd -> FakeConsole
        self.consoles = {}
        self.font_console = None  # Monospace font
        self.console_cursor_visible = True  # Input cursor blinking
        self.console_cursor_timer = 0
        
        # Window dragging
        self.dragging_window = None  # Dragged window hwnd
        self.drag_offset_x = 0
        self.drag_offset_y = 0

        # Scrollbar thumb dragging: (control hwnd, grab offset in thumb) or None
        self.dragging_scrollbar = None

        # Window resizing
        self.resizing_window = None  # Resized window hwnd
        self.resize_edge = None      # Active edge: 'left','right','top','bottom' + corners
        self.resize_start_mouse = (0, 0)  # Mouse pos when resize began
        self.resize_start_rect = (0, 0, 0, 0)  # Window (x, y, w, h) when resize began
        self.current_cursor = None   # Currently set system cursor (avoid redundant sets)

    def start(self):
        """Start GUI thread"""
        if not PYGAME_AVAILABLE:
            log.warning("Pygame not available, GUI could not start!")
            return False
        
        self.gui_thread = threading.Thread(target=self._gui_loop, daemon=True)
        self.gui_thread.start()
        
        # Wait until the screen exists; programs started next need it
        # (e.g. a console program opens its console window at once)
        self.ready.wait(timeout=30)
        return self.running
    
    def stop(self):
        """Stop GUI"""
        self.running = False
        if self.gui_thread:
            self.gui_thread.join(timeout=1.0)
    
    def _gui_loop(self):
        """Main GUI loop"""
        pygame.init()
        pygame.display.set_caption(
            f"Windows 32-bit EXE Emulator v{WINEXE32EMU_VERSION} - Fake Desktop")
        
        self.screen = pygame.display.set_mode((self.width, self.height), pygame.SCALED)
        self.clock = pygame.time.Clock()
        
        # Load fonts
        pygame.font.init()
        self.font = pygame.font.SysFont('arial', 14)
        self.font_small = pygame.font.SysFont('arial', 11)
        self.font_bold = pygame.font.SysFont('arial', 14, bold=True)
        self.font_console = pygame.font.SysFont('consolas,courier,monospace', 12)
        
        self.running = True
        self.ready.set()
        
        while self.running:
            # Window state is shared with the emulation thread
            with self.lock:
                if self.pending_mode is not None:
                    # Display surfaces belong to this thread (ChangeDisplaySettings)
                    self.screen = pygame.display.set_mode(self.pending_mode, pygame.SCALED)
                    self.pending_mode = None
                self._process_frame()
                self._post_size_changes()
                self._post_activation_changes()
            
            pygame.display.flip()
            self.clock.tick(60)
        
        pygame.quit()

    def _process_frame(self):
        """Handle pending input events and redraw the screen"""
        # Process Pygame events
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                self.running = False
            elif event.type == pygame.MOUSEBUTTONDOWN:
                self._handle_mouse_click(event.pos, event.button)
            elif event.type == pygame.MOUSEBUTTONUP:
                # Release drag / resize; forward release to app if neither
                was_interacting = (self.dragging_window is not None or
                                   self.resizing_window is not None or
                                   self.dragging_scrollbar is not None)
                if self.dragging_scrollbar is not None:
                    self._end_scrollbar_drag()
                self.dragging_window = None
                self.resizing_window = None
                self.resize_edge = None
                if not was_interacting:
                    self._forward_mouse_up(event.pos, event.button)
            elif event.type == pygame.MOUSEMOTION:
                self.mouse_pos = event.pos
                # Scrollbar thumb dragging grabs the mouse first
                if self.dragging_scrollbar is not None:
                    self._drag_scrollbar_to(event.pos)
                # Window resizing (takes priority over dragging)
                elif self.resizing_window and self.resizing_window in self.windows:
                    self._resize_window_to(self.windows[self.resizing_window], event.pos)
                # Window dragging
                elif self.dragging_window and self.dragging_window in self.windows:
                    win = self.windows[self.dragging_window]
                    win.x = event.pos[0] - self.drag_offset_x
                    win.y = event.pos[1] - self.drag_offset_y
                    # Keep within screen boundaries
                    win.x = max(0, min(win.x, self.width - 50))
                    win.y = max(0, min(win.y, self.height - 60))
                else:
                    # Update mouse cursor based on hovered edge
                    self._update_resize_cursor(event.pos)
                    # Forward WM_MOUSEMOVE to the app window
                    self._forward_mouse_move(event.pos, event.buttons)
            elif event.type == pygame.KEYDOWN:
                vk = self._pygame_key_to_vk(event)
                if vk is not None:
                    self.key_states[vk] = True
                self._handle_key_press(event)
            elif event.type == pygame.KEYUP:
                vk = self._pygame_key_to_vk(event)
                if vk is not None:
                    self.key_states[vk] = False
                    self._forward_key_up(vk)
        
        # MessageBox check
        self._check_messagebox()
        
        # Cursor blinking (when a console waits for input)
        if any(c.input_active for c in self.consoles.values()):
            self.console_cursor_timer += 1
            if self.console_cursor_timer >= 30:  # ~0.5 seconds
                self.console_cursor_timer = 0
                self.console_cursor_visible = not self.console_cursor_visible
        
        # Draw screen
        self._draw()
    
    def _draw(self):
        """Draw screen"""
        # Desktop background
        self.screen.fill(self.COLOR_DESKTOP)
        
        # Taskbar
        self._draw_taskbar()
        
        # Draw windows (according to z-order)
        for hwnd in self.z_order:
            if hwnd in self.windows:
                if hwnd in self.consoles:
                    self._draw_console_window(self.windows[hwnd], self.consoles[hwnd])
                else:
                    self._draw_window(self.windows[hwnd])

        # Open dropdown menu is drawn over all windows
        self._draw_open_menu()

        # Open combobox dropdown is drawn over all windows too
        self._draw_open_combo()

        # Start menu is the topmost layer
        self._draw_start_menu()

    # ==================== START MENU ====================

    START_ITEM_H = 22
    START_SEP_H = 8
    START_MENU_W = 200
    START_STRIP_W = 22

    def _start_button_rect(self):
        return pygame.Rect(2, self.height - 28, 60, 26)

    def _fill_start_menu(self):
        """Read the Start menu rows: C:\\ programs, then the Examples submenu"""
        programs = list_programs()
        self.start_menu_examples = (programs.get(EXAMPLES_FOLDER, [])
                                    if self.show_examples else [])
        rows = [('program', path) for path in programs.get('C:\\', [])]
        if self.start_menu_examples:
            if rows:
                rows.append(('separator', None))
            rows.append(('examples', None))
        self.start_menu_rows = rows or [('empty', None)]
        self.start_submenu_open = False

    def _start_menu_rects(self):
        """Start menu rect and one rect per row"""
        heights = [self.START_SEP_H if kind == 'separator' else self.START_ITEM_H
                   for kind, _ in self.start_menu_rows]
        menu_h = sum(heights) + 6
        menu = pygame.Rect(0, self.height - 30 - menu_h, self.START_MENU_W, menu_h)
        rects = []
        y = menu.y + 3
        for h in heights:
            rects.append(pygame.Rect(menu.x + self.START_STRIP_W + 2, y,
                                     menu.width - self.START_STRIP_W - 5, h))
            y += h
        return menu, rects

    def _start_submenu_rects(self, examples_rect):
        """Examples submenu rect (right of its row) and its item rects"""
        count = len(self.start_menu_examples)
        sub_h = count * self.START_ITEM_H + 6
        top = max(0, min(examples_rect.y - 3, self.height - 30 - sub_h))
        sub = pygame.Rect(examples_rect.right + 2, top, self.START_MENU_W, sub_h)
        rects = [pygame.Rect(sub.x + 3, sub.y + 3 + i * self.START_ITEM_H,
                             sub.width - 6, self.START_ITEM_H)
                 for i in range(count)]
        return sub, rects

    def _examples_row_rect(self, rects):
        for (kind, _), rect in zip(self.start_menu_rows, rects):
            if kind == 'examples':
                return rect
        return None

    def _draw_menu_panel(self, rect):
        """Raised 3D panel behind a menu"""
        pygame.draw.rect(self.screen, self.COLOR_BUTTON, rect)
        pygame.draw.line(self.screen, self.COLOR_BUTTON_BORDER_LIGHT, rect.topleft, rect.topright)
        pygame.draw.line(self.screen, self.COLOR_BUTTON_BORDER_LIGHT, rect.topleft, rect.bottomleft)
        pygame.draw.line(self.screen, self.COLOR_BUTTON_BORDER_DARK,
                         (rect.right - 1, rect.top), (rect.right - 1, rect.bottom))
        pygame.draw.line(self.screen, self.COLOR_BUTTON_BORDER_DARK,
                         (rect.left, rect.bottom - 1), (rect.right - 1, rect.bottom - 1))

    def _draw_menu_row(self, rect, label, highlighted):
        if highlighted:
            pygame.draw.rect(self.screen, self.COLOR_TITLE_BAR, rect)
        color = self.COLOR_TITLE_TEXT if highlighted else self.COLOR_TEXT
        text = self.font.render(label, True, color)
        self.screen.blit(text, (rect.x + 6, rect.y + (rect.height - text.get_height()) // 2))
        return color

    @staticmethod
    def _program_label(path):
        return os.path.splitext(path.rsplit('\\', 1)[-1])[0]

    def _draw_start_menu(self):
        """Draw the Start menu: C:\\ programs and an Examples submenu (C:\\Windows\\Examples)"""
        if not self.start_menu_open:
            return
        menu, rects = self._start_menu_rects()
        self._draw_menu_panel(menu)
        strip = pygame.Rect(menu.x + 3, menu.y + 3, self.START_STRIP_W - 3, menu.height - 6)
        pygame.draw.rect(self.screen, self.COLOR_TITLE_BAR, strip)

        mouse_pos = pygame.mouse.get_pos()
        examples_rect = self._examples_row_rect(rects)
        sub, sub_rects = (self._start_submenu_rects(examples_rect) if examples_rect
                          else (None, []))

        # Hovering a row opens the Examples submenu or closes it
        if not (sub and self.start_submenu_open and sub.collidepoint(mouse_pos)):
            for (kind, _), rect in zip(self.start_menu_rows, rects):
                if rect.collidepoint(mouse_pos) and kind != 'separator':
                    self.start_submenu_open = (kind == 'examples')

        for (kind, path), rect in zip(self.start_menu_rows, rects):
            if kind == 'separator':
                y = rect.centery
                pygame.draw.line(self.screen, self.COLOR_BUTTON_BORDER_DARK,
                                 (rect.x + 2, y - 1), (rect.right - 2, y - 1))
                pygame.draw.line(self.screen, self.COLOR_BUTTON_BORDER_LIGHT,
                                 (rect.x + 2, y), (rect.right - 2, y))
            elif kind == 'empty':
                text = self.font.render("(no programs found)", True, (128, 128, 128))
                self.screen.blit(text, (rect.x + 6, rect.y + 3))
            elif kind == 'examples':
                color = self._draw_menu_row(rect, "Examples", self.start_submenu_open)
                # Submenu arrow
                ax, ay = rect.right - 12, rect.centery
                pygame.draw.polygon(self.screen, color,
                                    [(ax, ay - 4), (ax + 4, ay), (ax, ay + 4)])
            else:
                self._draw_menu_row(rect, self._program_label(path),
                                    rect.collidepoint(mouse_pos))

        if sub and self.start_submenu_open:
            self._draw_menu_panel(sub)
            for path, rect in zip(self.start_menu_examples, sub_rects):
                self._draw_menu_row(rect, self._program_label(path),
                                    rect.collidepoint(mouse_pos))

    def _handle_start_menu_click(self, pos, button):
        """Start button toggles the menu; returns True if the click was consumed"""
        if self._fullscreen_window() is not None:
            return False  # A full-screen window covers the taskbar
        if self._start_button_rect().collidepoint(pos):
            self.start_menu_open = not self.start_menu_open
            if self.start_menu_open:
                self.open_menu = None
                self.open_combo = None
                self._fill_start_menu()
            return True
        if not self.start_menu_open:
            return False

        menu, rects = self._start_menu_rects()
        examples_rect = self._examples_row_rect(rects)
        if examples_rect and self.start_submenu_open:
            sub, sub_rects = self._start_submenu_rects(examples_rect)
            if sub.collidepoint(pos):
                for path, rect in zip(self.start_menu_examples, sub_rects):
                    if button == 1 and rect.collidepoint(pos) and self.launcher:
                        self.start_menu_open = False
                        self.launcher(path)
                return True
        if examples_rect and examples_rect.collidepoint(pos):
            self.start_submenu_open = True
            return True

        self.start_menu_open = False
        if not menu.collidepoint(pos):
            return False
        for (kind, path), rect in zip(self.start_menu_rows, rects):
            if kind == 'program' and button == 1 and rect.collidepoint(pos) and self.launcher:
                self.launcher(path)
        return True

    @gui_locked
    def register_process(self, process):
        """A program starts: its windows get input from now on"""
        self.processes.append(process)

    @gui_locked
    def unregister_process(self, process):
        """A program ended: close its windows; its console stays to show the output"""
        if process in self.processes:
            self.processes.remove(process)
        if self.display_mode_owner is process:
            # Like Windows, a CDS_FULLSCREEN mode ends with its program
            self.set_display_mode(self.desktop_width, self.desktop_height)
        for hwnd, win in list(self.windows.items()):
            if win.owner is not process:
                continue
            console = self.consoles.get(hwnd)
            if console is None:
                self._remove_window(hwnd)
                continue
            self.cancel_console_input(console)
            win.owner = None
            win.title += " [finished]"

    def window_owner(self, hwnd):
        """Process (WinAPIHandler) owning a window or control, or None"""
        win = self.windows.get(hwnd)
        if win is None:
            control = self.controls.get(hwnd)
            win = self.windows.get(control.parent_hwnd) if control else None
        return win.owner if win else None

    @gui_locked
    def _remove_window(self, hwnd):
        """Delete a window and its controls, dropping every reference to them"""
        if self.windows.pop(hwnd, None) is None:
            return
        for chwnd in [h for h, c in self.controls.items() if c.parent_hwnd == hwnd]:
            del self.controls[chwnd]
            if self.focused_control == chwnd:
                self.focused_control = None
            if self.open_combo == chwnd:
                self.open_combo = None
            if self.dragging_scrollbar and self.dragging_scrollbar[0] == chwnd:
                self.dragging_scrollbar = None
        if hwnd in self.z_order:
            self.z_order.remove(hwnd)
        if self.active_window == hwnd:
            self.active_window = self.z_order[-1] if self.z_order else None
        if self.open_menu and self.open_menu[0] == hwnd:
            self.open_menu = None
        if self.dragging_window == hwnd:
            self.dragging_window = None
        if self.resizing_window == hwnd:
            self.resizing_window = None
    
    def _draw_taskbar(self):
        """Draw taskbar"""
        taskbar_height = 30
        taskbar_rect = pygame.Rect(0, self.height - taskbar_height, self.width, taskbar_height)
        
        # Taskbar background
        pygame.draw.rect(self.screen, self.COLOR_TASKBAR, taskbar_rect)
        pygame.draw.line(self.screen, (255, 255, 255), (0, self.height - taskbar_height), 
                        (self.width, self.height - taskbar_height))
        
        # Start button
        self._draw_button_3d(self._start_button_rect(), "Start",
                             pressed=self.start_menu_open)
        
        # System tray area (right side)
        tray_width = 80
        tray_rect = pygame.Rect(self.width - tray_width, self.height - taskbar_height + 2, 
                               tray_width - 4, taskbar_height - 4)
        # Sunken effect for tray
        pygame.draw.rect(self.screen, (192, 192, 192), tray_rect)
        pygame.draw.line(self.screen, (128, 128, 128), 
                        (tray_rect.x, tray_rect.y), (tray_rect.x + tray_rect.width, tray_rect.y))
        pygame.draw.line(self.screen, (128, 128, 128), 
                        (tray_rect.x, tray_rect.y), (tray_rect.x, tray_rect.y + tray_rect.height))
        pygame.draw.line(self.screen, (255, 255, 255), 
                        (tray_rect.x + tray_rect.width, tray_rect.y), 
                        (tray_rect.x + tray_rect.width, tray_rect.y + tray_rect.height))
        pygame.draw.line(self.screen, (255, 255, 255), 
                        (tray_rect.x, tray_rect.y + tray_rect.height), 
                        (tray_rect.x + tray_rect.width, tray_rect.y + tray_rect.height))
        
        # Saat
        current_time = time.strftime("%H:%M")
        time_text = self.font_small.render(current_time, True, self.COLOR_TEXT)
        self.screen.blit(time_text, (self.width - 45, self.height - taskbar_height + 8))
        
        # Open windows (excluding dialogs)
        x_offset = 70
        max_btn_width = 140
        
        # First count visible windows (excluding dialogs)
        visible_windows = [(hwnd, self.windows[hwnd]) for hwnd in self.z_order 
                          if hwnd in self.windows and self.windows[hwnd].visible 
                          and not self.windows[hwnd].is_dialog]
        
        # Adjust button width
        available_width = self.width - tray_width - 80  # Leave room for Start button and tray
        if visible_windows:
            btn_width = min(max_btn_width, available_width // len(visible_windows) - 5)
            btn_width = max(60, btn_width)  # Minimum 60px
        else:
            btn_width = max_btn_width
        
        for hwnd, win in visible_windows:
            btn_rect = pygame.Rect(x_offset, self.height - taskbar_height + 2, btn_width, taskbar_height - 4)
            
            is_active = (hwnd == self.active_window) and not win.minimized
            is_minimized = win.minimized
            
            # Minimized windows should not appear pressed
            # Active window should appear pressed
            self._draw_taskbar_button(btn_rect, win.title, is_active, is_minimized)
            
            x_offset += btn_width + 5
    
    def _draw_taskbar_button(self, rect, title, is_active, is_minimized):
        """Draw taskbar button"""
        # Background
        if is_active:
            # Active: pressed appearance
            pygame.draw.rect(self.screen, (192, 192, 192), rect)
            pygame.draw.line(self.screen, self.COLOR_BUTTON_BORDER_DARK, 
                           (rect.x, rect.y), (rect.x + rect.width - 1, rect.y))
            pygame.draw.line(self.screen, self.COLOR_BUTTON_BORDER_DARK, 
                           (rect.x, rect.y), (rect.x, rect.y + rect.height - 1))
            pygame.draw.line(self.screen, self.COLOR_BUTTON_BORDER_LIGHT, 
                           (rect.x + rect.width - 1, rect.y), 
                           (rect.x + rect.width - 1, rect.y + rect.height - 1))
            pygame.draw.line(self.screen, self.COLOR_BUTTON_BORDER_LIGHT, 
                           (rect.x, rect.y + rect.height - 1), 
                           (rect.x + rect.width - 1, rect.y + rect.height - 1))
        else:
            # Normal: raised appearance
            pygame.draw.rect(self.screen, self.COLOR_BUTTON, rect)
            pygame.draw.line(self.screen, self.COLOR_BUTTON_BORDER_LIGHT, 
                           (rect.x, rect.y), (rect.x + rect.width - 1, rect.y))
            pygame.draw.line(self.screen, self.COLOR_BUTTON_BORDER_LIGHT, 
                           (rect.x, rect.y), (rect.x, rect.y + rect.height - 1))
            pygame.draw.line(self.screen, self.COLOR_BUTTON_BORDER_DARK, 
                           (rect.x + rect.width - 1, rect.y), 
                           (rect.x + rect.width - 1, rect.y + rect.height - 1))
            pygame.draw.line(self.screen, self.COLOR_BUTTON_BORDER_DARK, 
                           (rect.x, rect.y + rect.height - 1), 
                           (rect.x + rect.width - 1, rect.y + rect.height - 1))
        
        # Text
        max_chars = (rect.width - 10) // 7  # Approximate character count
        display_title = title[:max_chars] if len(title) > max_chars else title
        text_color = self.COLOR_TEXT
        text_surface = self.font_small.render(display_title, True, text_color)
        text_x = rect.x + 5
        text_y = rect.y + (rect.height - text_surface.get_height()) // 2
        self.screen.blit(text_surface, (text_x, text_y))
    
    def _draw_window(self, window):
        """Draw window"""
        if not window.visible or window.minimized:
            return
        
        is_active = (window.hwnd == self.active_window)
        border, caption = self.window_frame(window)

        if border:
            # Window shadow
            shadow_rect = pygame.Rect(window.x + 3, window.y + 3, window.width, window.height)
            pygame.draw.rect(self.screen, (64, 64, 64), shadow_rect)

            # Window frame
            frame_rect = pygame.Rect(window.x, window.y, window.width, window.height)
            pygame.draw.rect(self.screen, self.COLOR_WINDOW_BG, frame_rect)
            pygame.draw.rect(self.screen, self.COLOR_BUTTON_BORDER_DARK, frame_rect, 1)

        if border > 1:
            # 3D edge effect
            pygame.draw.line(self.screen, (255, 255, 255),
                            (window.x, window.y), (window.x + window.width - 1, window.y))
            pygame.draw.line(self.screen, (255, 255, 255),
                            (window.x, window.y), (window.x, window.y + window.height - 1))
            pygame.draw.line(self.screen, (64, 64, 64),
                            (window.x + window.width - 1, window.y),
                            (window.x + window.width - 1, window.y + window.height - 1))
            pygame.draw.line(self.screen, (64, 64, 64),
                            (window.x, window.y + window.height - 1),
                            (window.x + window.width - 1, window.y + window.height - 1))

        if caption:
            self._draw_title_bar(window, is_active)

        # Menu bar (between title bar and client area)
        if window.menu:
            self._draw_menu_bar(window)

        # Content area
        client_x, client_y = self.client_origin(window)
        client_w, client_h = self.client_size(window)
        content_rect = pygame.Rect(client_x, client_y, client_w, client_h)
        pygame.draw.rect(self.screen, window.bg_color, content_rect)

        # Clip client-area drawing to the window (GDI shapes may overflow)
        self.screen.set_clip(content_rect)

        # Render GDI shapes and texts (Rectangle, Ellipse, TextOut, ...)
        for shape in window.drawn_shapes:
            self._draw_shape(shape, client_x, client_y)

        # Draw controls
        for control in window.controls:
            self._draw_control(control, client_x, client_y)

        self._draw_child_windows(window)

        self.screen.set_clip(None)

    def _draw_title_bar(self, window, is_active):
        """Draw a window's caption: title and the caption buttons"""
        title_color = self.COLOR_TITLE_BAR if is_active else self.COLOR_TITLE_BAR_INACTIVE
        title_rect = pygame.Rect(window.x + 3, window.y + 3, window.width - 6, 22)
        pygame.draw.rect(self.screen, title_color, title_rect)
        
        # Title text, cut with "..." before the caption buttons
        buttons_w = 18 * (1 if window.is_dialog else 3) + 5
        max_title_w = window.width - 8 - buttons_w - 6
        title = window.title
        if self.font_bold.size(title)[0] > max_title_w:
            while title and self.font_bold.size(title + "...")[0] > max_title_w:
                title = title[:-1]
            title += "..."
        title_text = self.font_bold.render(title, True, self.COLOR_TITLE_TEXT)
        self.screen.blit(title_text, (window.x + 8, window.y + 6))
        
        # Window buttons (Minimize, Maximize, Close)
        btn_size = 16
        btn_y = window.y + 5
        
        # Close button (X) - special for red hover effect
        close_rect = pygame.Rect(window.x + window.width - btn_size - 5, btn_y, btn_size, btn_size)
        self._draw_window_button(close_rect, "×", "close")
        
        # Show minimize and maximize buttons if not a dialog
        if not window.is_dialog:
            # Maximize/Restore butonu
            max_rect = pygame.Rect(window.x + window.width - btn_size * 2 - 7, btn_y, btn_size, btn_size)
            max_symbol = "❐" if window.maximized else "□"  # Restore vs Maximize
            self._draw_window_button(max_rect, max_symbol, "max")
            
            # Minimize butonu
            min_rect = pygame.Rect(window.x + window.width - btn_size * 3 - 9, btn_y, btn_size, btn_size)
            self._draw_window_button(min_rect, "─", "min")

    def _draw_shape(self, shape, ox, oy, target=None):
        """Render one GDI display list entry at client origin (ox, oy) on target
        (default: the screen)"""
        screen = self.screen if target is None else target
        stype = shape['type']

        if stype == 'line':
            color, width = shape['pen']
            x1, y1 = shape['from']
            x2, y2 = shape['to']
            pygame.draw.line(screen, color, (ox + x1, oy + y1), (ox + x2, oy + y2), width)

        elif stype in ('rect', 'ellipse'):
            left, top, right, bottom = shape['rect']
            rect = pygame.Rect(ox + left, oy + top, right - left, bottom - top)
            draw_func = pygame.draw.rect if stype == 'rect' else pygame.draw.ellipse
            if shape.get('fill') is not None:
                draw_func(screen, shape['fill'], rect)
            if shape.get('pen') is not None:
                color, width = shape['pen']
                draw_func(screen, color, rect, width)

        elif stype == 'roundrect':
            left, top, right, bottom = shape['rect']
            rect = pygame.Rect(ox + left, oy + top, right - left, bottom - top)
            radius = shape.get('radius', 0)
            if shape.get('fill') is not None:
                pygame.draw.rect(screen, shape['fill'], rect, border_radius=radius)
            if shape.get('pen') is not None:
                color, width = shape['pen']
                pygame.draw.rect(screen, color, rect, width, border_radius=radius)

        elif stype == 'polygon':
            points = [(ox + x, oy + y) for x, y in shape['points']]
            if len(points) >= 3:
                if shape.get('fill') is not None:
                    pygame.draw.polygon(screen, shape['fill'], points)
                if shape.get('pen') is not None:
                    color, width = shape['pen']
                    pygame.draw.polygon(screen, color, points, width)

        elif stype == 'polyline':
            points = [(ox + x, oy + y) for x, y in shape['points']]
            if len(points) >= 2 and shape.get('pen') is not None:
                color, width = shape['pen']
                pygame.draw.lines(screen, color, False, points, width)

        elif stype == 'arc':
            left, top, right, bottom = shape['rect']
            rect = pygame.Rect(ox + left, oy + top, right - left, bottom - top)
            if shape.get('pen') is not None:
                color, width = shape['pen']
                pygame.draw.arc(screen, color, rect,
                                shape['start'], shape['end'], width)

        elif stype == 'text':
            x, y = shape['pos']
            font = self._get_render_font(shape.get('font'))
            surface = font.render(shape['text'], True, shape.get('color') or self.COLOR_TEXT,
                                  shape.get('bk'))
            screen.blit(surface, (ox + x, oy + y))
            if shape.get('font') and shape['font'].get('underline'):
                line_y = oy + y + surface.get_height() - 2
                pygame.draw.line(screen, shape.get('color') or self.COLOR_TEXT,
                                 (ox + x, line_y), (ox + x + surface.get_width(), line_y))

        elif stype == 'pixel':
            x, y = shape['pos']
            rect = pygame.Rect(ox + x, oy + y, 1, 1)
            pygame.draw.rect(screen, shape['color'], rect)

        elif stype == 'image':
            x, y = shape['pos']
            if shape['size'][0] > 0 and shape['size'][1] > 0:
                screen.blit(self._image_surface(shape), (ox + x, oy + y))

    def _image_surface(self, shape):
        """Pygame surface of an image shape, cached in the shape.

        Raster operations are approximated with transparency: SRCAND leaves
        white pixels out (mask), SRCPAINT/SRCINVERT leave black pixels out.
        """
        rop = shape.get('rop')
        key = (shape['size'], rop)
        cached = shape.get('_surface')
        if cached and cached[0] == key:
            return cached[1]
        data = shape['data']
        if rop == WinAPIHandler.NOTSRCCOPY:
            data = bytes(255 - b for b in data)
        from_bytes = getattr(pygame.image, 'frombytes', None) or pygame.image.fromstring
        surface = from_bytes(data, shape['dim'], 'RGB')
        if shape['size'] != shape['dim']:
            surface = pygame.transform.scale(surface, shape['size'])
        if rop == WinAPIHandler.SRCAND:
            surface.set_colorkey((255, 255, 255))
        elif rop in (WinAPIHandler.SRCPAINT, WinAPIHandler.SRCINVERT):
            surface.set_colorkey((0, 0, 0))
        shape['_surface'] = (key, surface)
        return surface

    def _get_render_font(self, font_dict):
        """Pygame font for a GDI font dict (cached); None -> default GUI font."""
        if not font_dict:
            return self.font
        # GDI height is in pixels; pygame SysFont sizes are close to points
        size = max(8, int(font_dict.get('height', 13) * 0.75))
        face = (font_dict.get('face') or 'arial').lower()
        bold = font_dict.get('bold', False)
        italic = font_dict.get('italic', False)
        key = (face, size, bold, italic)
        if key not in self._font_cache:
            self._font_cache[key] = pygame.font.SysFont(f"{face},arial", size,
                                                        bold=bold, italic=italic)
        return self._font_cache[key]

    def _draw_menu_bar(self, window):
        """Draw a window's menu bar and highlight the open item"""
        bar = self._menu_bar_rect(window)
        pygame.draw.rect(self.screen, self.COLOR_WINDOW_BG, bar)
        pygame.draw.line(self.screen, (128, 128, 128),
                         (bar.x, bar.bottom - 1), (bar.right - 1, bar.bottom - 1))

        item_rects = self._menu_item_rects(window)
        for i, (item, rect) in enumerate(zip(window.menu, item_rects)):
            is_open = (self.open_menu == (window.hwnd, i))
            if is_open:
                pygame.draw.rect(self.screen, self.COLOR_TITLE_BAR, rect)
            color = self.COLOR_TITLE_TEXT if is_open else self.COLOR_TEXT
            text = self.font.render(item['text'], True, color)
            self.screen.blit(text, (rect.x + 8, rect.y + (rect.height - text.get_height()) // 2))

    def _draw_open_menu(self):
        """Draw the open dropdown menu on top of everything"""
        if not self.open_menu:
            return
        hwnd, index = self.open_menu
        win = self.windows.get(hwnd)
        if not win or not win.visible or win.minimized or not win.menu:
            self.open_menu = None
            return

        drop, item_rects = self._menu_dropdown_rects(win, index)
        if drop is None:
            self.open_menu = None
            return

        # Dropdown frame with shadow
        shadow = pygame.Rect(drop.x + 3, drop.y + 3, drop.width, drop.height)
        pygame.draw.rect(self.screen, (64, 64, 64), shadow)
        pygame.draw.rect(self.screen, self.COLOR_WINDOW_BG, drop)
        pygame.draw.rect(self.screen, (128, 128, 128), drop, 1)

        mouse_pos = pygame.mouse.get_pos()
        items = win.menu[index].get('items') or []
        for sub, rect in zip(items, item_rects):
            if sub.get('separator'):
                mid_y = rect.y + rect.height // 2
                pygame.draw.line(self.screen, (128, 128, 128),
                                 (rect.x + 2, mid_y), (rect.right - 2, mid_y))
                continue
            hovered = rect.collidepoint(mouse_pos)
            if hovered:
                pygame.draw.rect(self.screen, self.COLOR_TITLE_BAR, rect)
            color = self.COLOR_TITLE_TEXT if hovered else self.COLOR_TEXT
            text = self.font.render(sub['text'], True, color)
            self.screen.blit(text, (rect.x + 16, rect.y + (rect.height - text.get_height()) // 2))
    
    def _combo_dropdown_rects(self, control):
        """Dropdown rect and item rects of an open combobox (screen coords)."""
        win = self.windows.get(control.parent_hwnd)
        if not win or not win.visible or win.minimized:
            return None, []
        ox, oy = self.client_origin(win)
        box_h = min(control.height, 24)
        item_h = self.LISTBOX_ITEM_H
        count = max(1, len(control.items))
        drop = pygame.Rect(ox + control.x, oy + control.y + box_h,
                           control.width, count * item_h + 2)
        rects = [pygame.Rect(drop.x + 1, drop.y + 1 + i * item_h,
                             drop.width - 2, item_h)
                 for i in range(len(control.items))]
        return drop, rects

    def _draw_open_combo(self):
        """Draw the open combobox dropdown on top of everything"""
        if not self.open_combo:
            return
        control = self.controls.get(self.open_combo)
        if not control or not control.visible:
            self.open_combo = None
            return

        drop, item_rects = self._combo_dropdown_rects(control)
        if drop is None:
            self.open_combo = None
            return

        shadow = pygame.Rect(drop.x + 3, drop.y + 3, drop.width, drop.height)
        pygame.draw.rect(self.screen, (64, 64, 64), shadow)
        pygame.draw.rect(self.screen, self.COLOR_EDIT_BG, drop)
        pygame.draw.rect(self.screen, (128, 128, 128), drop, 1)

        mouse_pos = pygame.mouse.get_pos()
        for i, (item, rect) in enumerate(zip(control.items, item_rects)):
            hovered = rect.collidepoint(mouse_pos)
            selected = (i == control.sel_index)
            if hovered or selected:
                pygame.draw.rect(self.screen, self.COLOR_TITLE_BAR, rect)
            color = self.COLOR_TITLE_TEXT if (hovered or selected) else self.COLOR_TEXT
            text = self.font.render(item, True, color)
            self.screen.blit(text, (rect.x + 3, rect.y + 1))

    def _draw_control(self, control, parent_x, parent_y):
        """Draw control in its WM_SETFONT font"""
        if not control.visible:
            return
        if control.class_name == "STATUSBAR":
            self.layout_statusbar(control)
        gui_font = self.font
        if control.font:
            self.font = self._get_render_font(control.font)
        try:
            self._draw_control_body(control, parent_x + control.x, parent_y + control.y)
        finally:
            self.font = gui_font
        if control.drawn_shapes:
            abs_x, abs_y = parent_x + control.x, parent_y + control.y
            prev_clip = self.screen.get_clip()
            rect = pygame.Rect(abs_x, abs_y, control.width, control.height)
            self.screen.set_clip(rect.clip(prev_clip) if prev_clip else rect)
            for shape in control.drawn_shapes:
                self._draw_shape(shape, abs_x, abs_y)
            self.screen.set_clip(prev_clip)

    def _wrap_text(self, text, width):
        """Split text into lines that fit width pixels (word wrap)"""
        lines = []
        for paragraph in text.split('\n'):
            line = ''
            for word in paragraph.split(' '):
                candidate = f"{line} {word}" if line else word
                if line and self.font.size(candidate)[0] > width:
                    lines.append(line)
                    line = word
                else:
                    line = candidate
            lines.append(line)
        return lines

    SS_NOPREFIX = 0x80

    def _draw_static(self, control, rect):
        """Draw a STATIC control by its SS_* type"""
        kind = control.style & 0x1F
        dark, light = (128, 128, 128), (255, 255, 255)
        x, y, w, h = rect
        if kind == 0x10:    # SS_ETCHEDHORZ
            pygame.draw.line(self.screen, dark, (x, y), (x + w - 1, y))
            pygame.draw.line(self.screen, light, (x, y + 1), (x + w - 1, y + 1))
        elif kind == 0x11:  # SS_ETCHEDVERT
            pygame.draw.line(self.screen, dark, (x, y), (x, y + h - 1))
            pygame.draw.line(self.screen, light, (x + 1, y), (x + 1, y + h - 1))
        elif kind == 0x12:  # SS_ETCHEDFRAME
            pygame.draw.rect(self.screen, light, (x + 1, y + 1, w - 1, h - 1), 1)
            pygame.draw.rect(self.screen, dark, (x, y, w - 1, h - 1), 1)
        elif kind in (4, 5, 6):  # SS_BLACKRECT, SS_GRAYRECT, SS_WHITERECT
            pygame.draw.rect(self.screen, ((0, 0, 0), dark, light)[kind - 4], rect)
        elif kind in (7, 8, 9):  # SS_BLACKFRAME, SS_GRAYFRAME, SS_WHITEFRAME
            pygame.draw.rect(self.screen, ((0, 0, 0), dark, light)[kind - 7], rect, 1)
        elif kind in (0, 1, 2, 0xB, 0xC):  # Text: left, center, right, simple, no wrap
            text = control.text
            if not control.style & self.SS_NOPREFIX:
                text = re.sub(r'&(.)', r'\1', text)
            lines = self._wrap_text(text, w) if kind <= 2 else text.split('\n')
            prev_clip = self.screen.get_clip()
            self.screen.set_clip(rect.clip(prev_clip) if prev_clip else rect)
            line_y = y
            for line in lines:
                surface = self.font.render(line, True, self.COLOR_TEXT)
                if kind == 1:
                    line_x = x + (w - surface.get_width()) // 2
                elif kind == 2:
                    line_x = x + w - surface.get_width()
                else:
                    line_x = x
                self.screen.blit(surface, (line_x, line_y))
                line_y += self.font.get_linesize()
                if line_y >= y + h:
                    break
            self.screen.set_clip(prev_clip)

    STATUSBAR_H = 20

    def layout_statusbar(self, control):
        """Dock a status bar to the bottom (CCS_TOP: top) of its parent's client area"""
        if control.style & 0x0C:  # CCS_NORESIZE, CCS_NOPARENTALIGN
            return
        win = self.windows.get(control.parent_hwnd)
        if win is None:
            return
        width, height = self.client_size(win)
        top = 0 if control.style & 0x3 == 1 else height - self.STATUSBAR_H
        control.x, control.y = 0, top
        control.width, control.height = width, self.STATUSBAR_H

    def _draw_statusbar(self, control, abs_x, abs_y):
        """Status bar: sunken panes with their texts"""
        rect = pygame.Rect(abs_x, abs_y, control.width, control.height)
        pygame.draw.rect(self.screen, self.COLOR_BUTTON, rect)
        dark, light = (128, 128, 128), (255, 255, 255)
        if control.simple:
            panes = [(-1, control.part_texts.get(255, ''))]
        else:
            panes = [(edge, control.text if i == 0 else control.part_texts.get(i, ''))
                     for i, edge in enumerate(control.parts)]
        prev_clip = self.screen.get_clip()
        left = abs_x + 2
        for edge, text in panes:
            right = rect.right - 2 if edge < 0 else min(abs_x + edge, rect.right - 2)
            pane = pygame.Rect(left, abs_y + 2, max(0, right - left - 2), control.height - 3)
            if pane.width > 0:
                pygame.draw.line(self.screen, dark, pane.topleft, (pane.right - 1, pane.top))
                pygame.draw.line(self.screen, dark, pane.topleft, (pane.left, pane.bottom - 1))
                pygame.draw.line(self.screen, light, (pane.left, pane.bottom - 1),
                                 (pane.right - 1, pane.bottom - 1))
                pygame.draw.line(self.screen, light, (pane.right - 1, pane.top),
                                 (pane.right - 1, pane.bottom - 1))
                self.screen.set_clip(pane.clip(prev_clip) if prev_clip else pane)
                surface = self.font.render(text.replace('\t', ' '), True, self.COLOR_TEXT)
                self.screen.blit(surface, (pane.x + 3,
                                           pane.y + (pane.height - surface.get_height()) // 2))
                self.screen.set_clip(prev_clip)
            left = right

    def _draw_control_body(self, control, abs_x, abs_y):
        if control.class_name == "STATUSBAR":
            self._draw_statusbar(control, abs_x, abs_y)
        elif control.class_name == "BUTTON":
            rect = pygame.Rect(abs_x, abs_y, control.width, control.height)
            if (control.style & 0xF) == 7:  # BS_GROUPBOX
                self._draw_group_box(control, rect)
            elif (control.style & 0xF) == 1:  # BS_DEFPUSHBUTTON: black outer frame
                self._draw_button_3d(rect.inflate(-2, -2), control.text)
                pygame.draw.rect(self.screen, (0, 0, 0), rect, 1)
            else:
                self._draw_button_3d(rect, control.text)
            
        elif control.class_name == "STATIC":
            self._draw_static(control, pygame.Rect(abs_x, abs_y, control.width, control.height))
            
        elif control.class_name == "EDIT":
            rect = pygame.Rect(abs_x, abs_y, control.width, control.height)
            pygame.draw.rect(self.screen, self.COLOR_EDIT_BG, rect)
            border_color = (0, 0, 128) if control.hwnd == self.focused_control else (128, 128, 128)
            pygame.draw.rect(self.screen, border_color, rect, 1)
            # Sunken effect
            pygame.draw.line(self.screen, (64, 64, 64), (abs_x, abs_y), (abs_x + control.width, abs_y))
            pygame.draw.line(self.screen, (64, 64, 64), (abs_x, abs_y), (abs_x, abs_y + control.height))

            # Show the tail of the text if it is wider than the control
            text_str = control.text
            max_text_w = control.width - 8
            while text_str and self.font.size(text_str)[0] > max_text_w:
                text_str = text_str[1:]

            prev_clip = self.screen.get_clip()
            self.screen.set_clip(rect)
            text = self.font.render(text_str, True, self.COLOR_TEXT)
            text_y = abs_y + (control.height - text.get_height()) // 2
            self.screen.blit(text, (abs_x + 4, text_y))

            # Blinking caret when focused
            if control.hwnd == self.focused_control and (pygame.time.get_ticks() // 500) % 2 == 0:
                caret_x = abs_x + 4 + text.get_width() + 1
                pygame.draw.line(self.screen, self.COLOR_TEXT,
                                 (caret_x, abs_y + 3), (caret_x, abs_y + control.height - 4))
            self.screen.set_clip(prev_clip)
            
        elif control.class_name == "LISTBOX":
            rect = pygame.Rect(abs_x, abs_y, control.width, control.height)
            pygame.draw.rect(self.screen, self.COLOR_EDIT_BG, rect)
            pygame.draw.rect(self.screen, (128, 128, 128), rect, 1)

            # Items with the selected one highlighted
            prev_clip = self.screen.get_clip()
            self.screen.set_clip(rect)
            item_h = self.LISTBOX_ITEM_H
            top = min(control.top_index, max(0, len(control.items) - 1))
            for i, item in enumerate(control.items[top:], top):
                item_rect = pygame.Rect(abs_x + 1, abs_y + 1 + (i - top) * item_h,
                                        control.width - 2, item_h)
                if item_rect.top > rect.bottom:
                    break
                selected = (i == control.sel_index)
                if selected:
                    pygame.draw.rect(self.screen, self.COLOR_TITLE_BAR, item_rect)
                color = self.COLOR_TITLE_TEXT if selected else self.COLOR_TEXT
                text = self.font.render(item, True, color)
                self.screen.blit(text, (item_rect.x + 3, item_rect.y + 1))
            self.screen.set_clip(prev_clip)

        elif control.class_name == "COMBOBOX":
            box_h = min(control.height, 24)
            rect = pygame.Rect(abs_x, abs_y, control.width, box_h)
            pygame.draw.rect(self.screen, self.COLOR_EDIT_BG, rect)
            pygame.draw.rect(self.screen, (128, 128, 128), rect, 1)

            # Selected item text
            sel_text = ""
            if 0 <= control.sel_index < len(control.items):
                sel_text = control.items[control.sel_index]
            if sel_text:
                prev_clip = self.screen.get_clip()
                self.screen.set_clip(rect)
                text = self.font.render(sel_text, True, self.COLOR_TEXT)
                self.screen.blit(text, (abs_x + 4, abs_y + (box_h - text.get_height()) // 2))
                self.screen.set_clip(prev_clip)

            # Dropdown arrow
            arrow_rect = pygame.Rect(abs_x + control.width - 18, abs_y + 1, 17, box_h - 2)
            self._draw_button_3d(arrow_rect, "", small=True, arrow='down')
            
        elif control.class_name in ["CHECKBOX", "BS_CHECKBOX"]:
            if (control.style & 0xF) in (0x4, 0x9):  # Radio button
                center = (abs_x + 6, abs_y + 8)
                pygame.draw.circle(self.screen, self.COLOR_EDIT_BG, center, 6)
                pygame.draw.circle(self.screen, (128, 128, 128), center, 6, 1)
                if control.checked:
                    pygame.draw.circle(self.screen, self.COLOR_TEXT, center, 2)
                text = self.font.render(control.text, True, self.COLOR_TEXT)
                self.screen.blit(text, (abs_x + 18, abs_y))
                return
            # Checkbox box
            box_rect = pygame.Rect(abs_x, abs_y + 2, 13, 13)
            pygame.draw.rect(self.screen, self.COLOR_EDIT_BG, box_rect)
            pygame.draw.rect(self.screen, (128, 128, 128), box_rect, 1)
            if control.checked:
                pygame.draw.line(self.screen, self.COLOR_TEXT, 
                               (abs_x + 2, abs_y + 8), (abs_x + 5, abs_y + 11), 2)
                pygame.draw.line(self.screen, self.COLOR_TEXT, 
                               (abs_x + 5, abs_y + 11), (abs_x + 11, abs_y + 4), 2)
            # Label
            text = self.font.render(control.text, True, self.COLOR_TEXT)
            self.screen.blit(text, (abs_x + 18, abs_y))
            
        elif control.class_name == "PROGRESSBAR":
            rect = pygame.Rect(abs_x, abs_y, control.width, control.height)
            pygame.draw.rect(self.screen, self.COLOR_EDIT_BG, rect)
            pygame.draw.rect(self.screen, (128, 128, 128), rect, 1)
            # Progress fill (example 50%)
            fill_width = int(control.width * 0.5)
            fill_rect = pygame.Rect(abs_x + 1, abs_y + 1, fill_width - 2, control.height - 2)
            pygame.draw.rect(self.screen, (0, 128, 0), fill_rect)

        elif control.class_name == "SCROLLBAR":
            m = self._scrollbar_metrics(control, abs_x, abs_y)

            # Track (classic dotted-gray look approximated with a light gray)
            pygame.draw.rect(self.screen, (224, 224, 224), m['track'])
            pygame.draw.rect(self.screen, (128, 128, 128),
                             pygame.Rect(abs_x, abs_y, control.width, control.height), 1)

            # Arrow buttons
            if m['vertical']:
                self._draw_button_3d(m['up'], "", small=True, arrow='up')
                self._draw_button_3d(m['down'], "", small=True, arrow='down')
            else:
                self._draw_button_3d(m['up'], "", small=True, arrow='left')
                self._draw_button_3d(m['down'], "", small=True, arrow='right')

            # Thumb (pressed look while dragging)
            dragging = (self.dragging_scrollbar is not None and
                        self.dragging_scrollbar[0] == control.hwnd)
            self._draw_button_3d(m['thumb'], "", pressed=dragging)
    
    def _draw_group_box(self, control, rect):
        """BS_GROUPBOX: etched frame with the caption on its top edge"""
        text = self.font.render(control.text, True, self.COLOR_TEXT) if control.text else None
        top = rect.y + (text.get_height() // 2 if text else 0)
        frame = pygame.Rect(rect.x, top, rect.width - 1, rect.bottom - top - 1)
        pygame.draw.rect(self.screen, self.COLOR_BUTTON_BORDER_DARK, frame, 1)
        pygame.draw.rect(self.screen, self.COLOR_BUTTON_BORDER_LIGHT, frame.move(1, 1), 1)
        if text:
            label = pygame.Rect(rect.x + 8, rect.y, text.get_width() + 4, text.get_height())
            pygame.draw.rect(self.screen, self.COLOR_BUTTON, label)
            self.screen.blit(text, (label.x + 2, label.y))

    def _draw_button_3d(self, rect, text, pressed=False, small=False, arrow=None):
        """Draw 3D-style button.

        When ``arrow`` is one of 'up'/'down'/'left'/'right', a filled triangle
        is drawn instead of ``text``. Triangles render crisply at any size and
        don't depend on the system font carrying Unicode arrow glyphs.
        """
        pygame.draw.rect(self.screen, self.COLOR_BUTTON, rect)
        
        if not pressed:
            # Raised effect
            pygame.draw.line(self.screen, self.COLOR_BUTTON_BORDER_LIGHT, 
                           (rect.x, rect.y), (rect.x + rect.width - 1, rect.y))
            pygame.draw.line(self.screen, self.COLOR_BUTTON_BORDER_LIGHT, 
                           (rect.x, rect.y), (rect.x, rect.y + rect.height - 1))
            pygame.draw.line(self.screen, self.COLOR_BUTTON_BORDER_DARK, 
                           (rect.x + rect.width - 1, rect.y), 
                           (rect.x + rect.width - 1, rect.y + rect.height - 1))
            pygame.draw.line(self.screen, self.COLOR_BUTTON_BORDER_DARK, 
                           (rect.x, rect.y + rect.height - 1), 
                           (rect.x + rect.width - 1, rect.y + rect.height - 1))
        else:
            # Sunken effect
            pygame.draw.line(self.screen, self.COLOR_BUTTON_BORDER_DARK, 
                           (rect.x, rect.y), (rect.x + rect.width - 1, rect.y))
            pygame.draw.line(self.screen, self.COLOR_BUTTON_BORDER_DARK, 
                           (rect.x, rect.y), (rect.x, rect.y + rect.height - 1))
        
        if arrow:
            self._draw_arrow(rect, arrow, pressed=pressed)
            return

        # Text
        font = self.font_small if small else self.font
        text_surface = font.render(text, True, self.COLOR_TEXT)
        text_rect = text_surface.get_rect(center=rect.center)
        self.screen.blit(text_surface, text_rect)

    def _draw_arrow(self, rect, direction, pressed=False):
        """Draw a small filled triangle centered in ``rect``.

        ``direction`` is 'up', 'down', 'left' or 'right'. Used for scrollbar
        arrow buttons and the combo-box dropdown, replacing font glyphs that
        render poorly (or not at all) at small sizes on some systems.
        """
        cx, cy = rect.center
        if pressed:
            cx += 1
            cy += 1
        dw, dh = 3, 2  # triangle half-base / depth -> 7px base, 4px tall
        if direction == 'down':
            points = [(cx - dw, cy - dh), (cx + dw, cy - dh), (cx, cy + dh)]
        elif direction == 'up':
            points = [(cx - dw, cy + dh), (cx + dw, cy + dh), (cx, cy - dh)]
        elif direction == 'right':
            points = [(cx - dh, cy - dw), (cx - dh, cy + dw), (cx + dh, cy)]
        else:  # 'left'
            points = [(cx + dh, cy - dw), (cx + dh, cy + dw), (cx - dh, cy)]
        pygame.draw.polygon(self.screen, self.COLOR_TEXT, points)

    def _draw_window_button(self, rect, symbol, btn_type):
        """Draw window control button (minimize, maximize, close)"""
        # Background
        pygame.draw.rect(self.screen, self.COLOR_BUTTON, rect)
        
        # 3D borders
        pygame.draw.line(self.screen, self.COLOR_BUTTON_BORDER_LIGHT, 
                       (rect.x, rect.y), (rect.x + rect.width - 1, rect.y))
        pygame.draw.line(self.screen, self.COLOR_BUTTON_BORDER_LIGHT, 
                       (rect.x, rect.y), (rect.x, rect.y + rect.height - 1))
        pygame.draw.line(self.screen, self.COLOR_BUTTON_BORDER_DARK, 
                       (rect.x + rect.width - 1, rect.y), 
                       (rect.x + rect.width - 1, rect.y + rect.height - 1))
        pygame.draw.line(self.screen, self.COLOR_BUTTON_BORDER_DARK, 
                       (rect.x, rect.y + rect.height - 1), 
                       (rect.x + rect.width - 1, rect.y + rect.height - 1))
        
        # Draw symbol
        center_x = rect.x + rect.width // 2
        center_y = rect.y + rect.height // 2
        
        if btn_type == "close":
            # X mark
            pygame.draw.line(self.screen, (0, 0, 0), 
                           (rect.x + 4, rect.y + 4), (rect.x + rect.width - 5, rect.y + rect.height - 5), 2)
            pygame.draw.line(self.screen, (0, 0, 0), 
                           (rect.x + rect.width - 5, rect.y + 4), (rect.x + 4, rect.y + rect.height - 5), 2)
        elif btn_type == "max":
            # Square (maximize) or double square (restore)
            if symbol == "❐":  # Restore
                # Two overlapping squares
                pygame.draw.rect(self.screen, (0, 0, 0), 
                               pygame.Rect(rect.x + 5, rect.y + 3, 8, 8), 1)
                pygame.draw.rect(self.screen, self.COLOR_BUTTON, 
                               pygame.Rect(rect.x + 3, rect.y + 5, 8, 8))
                pygame.draw.rect(self.screen, (0, 0, 0), 
                               pygame.Rect(rect.x + 3, rect.y + 5, 8, 8), 1)
            else:  # Maximize
                pygame.draw.rect(self.screen, (0, 0, 0), 
                               pygame.Rect(rect.x + 3, rect.y + 3, 10, 10), 1)
                pygame.draw.line(self.screen, (0, 0, 0), 
                               (rect.x + 3, rect.y + 5), (rect.x + 12, rect.y + 5), 1)
        elif btn_type == "min":
            # Underline (minimize)
            pygame.draw.line(self.screen, (0, 0, 0), 
                           (rect.x + 4, rect.y + rect.height - 5), 
                           (rect.x + rect.width - 5, rect.y + rect.height - 5), 2)
    
    def _get_resize_edge(self, win, x, y):
        """Return which edge/corner the point is on, or None.

        Returns one of: 'left','right','top','bottom','topleft','topright',
        'bottomleft','bottomright'. Resizing is disabled for maximized,
        minimized and dialog (MessageBox) windows.
        """
        if win.maximized or win.minimized or win.is_dialog:
            return None
        if win.parent is None and not self.window_frame(win)[0]:
            return None  # No frame to grab

        m = self.RESIZE_BORDER

        # Point must be near the window rectangle (inner border band)
        if not (win.x - m <= x <= win.x + win.width + m and
                win.y - m <= y <= win.y + win.height + m):
            return None

        left = abs(x - win.x) <= m
        right = abs(x - (win.x + win.width)) <= m
        top = abs(y - win.y) <= m
        bottom = abs(y - (win.y + win.height)) <= m

        edge = ""
        if top:
            edge += "top"
        elif bottom:
            edge += "bottom"
        if left:
            edge += "left"
        elif right:
            edge += "right"

        return edge or None

    def _resize_window_to(self, win, pos):
        """Resize a window while the user drags an edge/corner."""
        mx, my = pos
        edge = self.resize_edge
        sx, sy = self.resize_start_mouse
        ox, oy, ow, oh = self.resize_start_rect

        dx = mx - sx
        dy = my - sy

        new_x, new_y, new_w, new_h = ox, oy, ow, oh

        if "left" in edge:
            new_x = ox + dx
            new_w = ow - dx
        elif "right" in edge:
            new_w = ow + dx

        if "top" in edge:
            new_y = oy + dy
            new_h = oh - dy
        elif "bottom" in edge:
            new_h = oh + dy

        # Enforce minimum size, keeping the opposite edge anchored
        if new_w < self.MIN_WINDOW_WIDTH:
            if "left" in edge:
                new_x -= (self.MIN_WINDOW_WIDTH - new_w)
            new_w = self.MIN_WINDOW_WIDTH
        if new_h < self.MIN_WINDOW_HEIGHT:
            if "top" in edge:
                new_y -= (self.MIN_WINDOW_HEIGHT - new_h)
            new_h = self.MIN_WINDOW_HEIGHT

        # Keep the title bar reachable on screen
        new_y = max(0, new_y)

        win.x, win.y, win.width, win.height = new_x, new_y, new_w, new_h

    def _update_resize_cursor(self, pos):
        """Set the mouse cursor to a resize arrow when hovering an edge."""
        x, y = pos
        edge = None

        # Find the topmost window under the cursor
        for hwnd in reversed(self.z_order):
            win = self.windows.get(hwnd)
            if win and win.visible and not win.minimized and win.contains_point(x, y):
                edge = self._get_resize_edge(win, x, y)
                break

        cursor_map = {
            "left": pygame.SYSTEM_CURSOR_SIZEWE,
            "right": pygame.SYSTEM_CURSOR_SIZEWE,
            "top": pygame.SYSTEM_CURSOR_SIZENS,
            "bottom": pygame.SYSTEM_CURSOR_SIZENS,
            "topleft": pygame.SYSTEM_CURSOR_SIZENWSE,
            "bottomright": pygame.SYSTEM_CURSOR_SIZENWSE,
            "topright": pygame.SYSTEM_CURSOR_SIZENESW,
            "bottomleft": pygame.SYSTEM_CURSOR_SIZENESW,
        }
        cursor = cursor_map.get(edge, pygame.SYSTEM_CURSOR_ARROW)

        if cursor != self.current_cursor:
            try:
                pygame.mouse.set_cursor(cursor)
                self.current_cursor = cursor
            except Exception:
                pass

    def _is_app_window(self, hwnd):
        """True if hwnd is an emulated application window with a WndProc.

        Once the owning process has exited, its windows are dead: nothing
        consumes their messages, so they are treated as plain windows again
        (X click hides directly, input is no longer forwarded).
        """
        win = self.windows.get(hwnd)
        owner = win.owner if win else None
        if owner is None or owner.process_exited or hwnd in self.consoles:
            return False
        return bool(owner._find_wndproc_for_hwnd(hwnd)) or hwnd in owner.dialogs

    def client_origin(self, win):
        """Screen coordinates of a window's client area origin."""
        if win.parent in self.windows:
            px, py = self.client_origin(self.windows[win.parent])
            border = self._child_border(win)
            return (px + win.x + border, py + win.y + border)
        border, caption = self.window_frame(win)
        top = win.y + border + caption
        if win.menu:
            top += self.MENU_H
        return (win.x + border, top)

    def client_size(self, win):
        """Client area size (width, height) of a window."""
        if win.parent in self.windows:
            border = self._child_border(win)
            return (max(0, win.width - 2 * border), max(0, win.height - 2 * border))
        border, caption = self.window_frame(win)
        height = win.height - 2 * border - caption
        if win.menu:
            height -= self.MENU_H
        return (max(0, win.width - 2 * border), max(0, height))

    @classmethod
    def frame_size(cls, style, dialog=False):
        """(border, caption height) of a top-level window with this style.
        Overlapped windows always have a caption; pop-ups only with WS_CAPTION."""
        if not style & cls.WS_POPUP or style & cls.WS_CAPTION == cls.WS_CAPTION:
            return cls.BORDER, cls.TITLE_BAR_H
        if style & (cls.WS_DLGFRAME | cls.WS_THICKFRAME) or (dialog and
                                                             style & cls.DS_MODALFRAME):
            return cls.BORDER, 0
        if style & cls.WS_BORDER:
            return 1, 0
        return 0, 0

    def window_frame(self, win):
        """(border, caption height) of a top-level window"""
        return self.frame_size(win.style, win.is_dialog)

    def _fullscreen_window(self):
        """The topmost visible window if it covers the whole screen, else None"""
        for hwnd in reversed(self.z_order):
            win = self.windows.get(hwnd)
            if win is None or not win.visible or win.minimized:
                continue
            if (win.x <= 0 and win.y <= 0 and win.x + win.width >= self.width
                    and win.y + win.height >= self.height):
                return hwnd
            return None
        return None

    @gui_locked
    def set_display_mode(self, width, height, owner=None):
        """Change the fake desktop resolution (ChangeDisplaySettings); the GUI
        thread resizes the screen on its next frame"""
        self.display_mode_owner = owner
        if (width, height) == (self.width, self.height):
            return
        self.width, self.height = width, height
        self.pending_mode = (width, height)
        self.start_menu_open = False
        self.start_submenu_open = False
        for win in self.windows.values():
            if win.maximized and win.parent is None:
                win.x, win.y, win.width, win.height = 0, 0, width, height - 30
        log.info(f"Display mode changed to {width}x{height}")

    @staticmethod
    def _child_border(win):
        """Frame width of a child window: 1 with WS_BORDER, else none"""
        return 1 if win.style & 0x00800000 else 0

    def size_state(self, win):
        """(SIZE_RESTORED/MINIMIZED/MAXIMIZED, client width, client height) for WM_SIZE"""
        width, height = self.client_size(win)
        return (1 if win.minimized else 2 if win.maximized else 0, width, height)

    def _post_size_changes(self):
        """Post WM_SIZE for windows the user resized, maximized or minimized"""
        for hwnd, win in list(self.windows.items()):
            if win.size_state is None:
                continue  # The app has not been told a size yet
            state = self.size_state(win)
            if state != win.size_state:
                win.size_state = state
                if self._is_app_window(hwnd):
                    kind, width, height = state
                    win.owner.post_window_message(hwnd, win.owner.WM_SIZE, kind,
                                                  ((height & 0xFFFF) << 16) | (width & 0xFFFF))

    def _post_activation_changes(self):
        """Post WM_ACTIVATE when the active (not minimized) window changes"""
        active = self.active_window
        if active not in self.windows or self.windows[active].minimized:
            active = None
        previous = self.notified_active
        if active == previous:
            return
        self.notified_active = active
        if previous is not None and self._is_app_window(previous):
            owner = self.windows[previous].owner
            owner.post_window_message(previous, owner.WM_ACTIVATE, 0, active or 0)  # WA_INACTIVE
        if active is not None and self._is_app_window(active):
            owner = self.windows[active].owner
            owner.post_window_message(active, owner.WM_ACTIVATE, 1, previous or 0)  # WA_ACTIVE

    def _draw_child_windows(self, window):
        """Draw the visible child windows of window (inside its client area)"""
        parent_clip = self.screen.get_clip()
        for hwnd in window.children:
            child = self.windows.get(hwnd)
            if child is None or not child.visible:
                continue
            cx, cy = self.client_origin(child)
            cw, ch = self.client_size(child)
            border = self._child_border(child)
            frame = pygame.Rect(cx - border, cy - border, cw + 2 * border, ch + 2 * border)
            self.screen.set_clip(frame.clip(parent_clip))
            if border:
                pygame.draw.rect(self.screen, (0, 0, 0), frame, border)
            content = pygame.Rect(cx, cy, cw, ch)
            pygame.draw.rect(self.screen, child.bg_color, content)
            self.screen.set_clip(content.clip(parent_clip))
            for shape in child.drawn_shapes:
                self._draw_shape(shape, cx, cy)
            for control in child.controls:
                self._draw_control(control, cx, cy)
            self._draw_child_windows(child)
        self.screen.set_clip(parent_clip)

    def _client_point(self, win, x, y):
        """Convert screen coordinates to a window's client coordinates."""
        ox, oy = self.client_origin(win)
        return (x - ox, y - oy)

    # Upper bound for a retained display list (oldest shapes are dropped)
    MAX_SHAPES = 20000

    @staticmethod
    def covers_area(shape, width, height):
        """True if shape is an opaque rect hiding everything in a width x height area"""
        return PseudoWindowsGUI.covers_rect(shape, (0, 0, width, height))

    @staticmethod
    def covers_rect(shape, area):
        """True if shape opaquely hides everything in area (left, top, right, bottom)"""
        if shape['type'] == 'image':
            if shape.get('rop') not in (0x00CC0020, 0x00330008):  # SRCCOPY, NOTSRCCOPY
                return False
            (left, top), (w, h) = shape['pos'], shape['size']
            right, bottom = left + w, top + h
        elif shape['type'] != 'rect' or shape.get('fill') is None:
            return False
        else:
            left, top, right, bottom = shape['rect']
        return left <= area[0] and top <= area[1] and right >= area[2] and bottom >= area[3]

    @gui_locked
    def add_shape(self, hwnd, shape):
        """Append a GDI shape to a window's display list (emu thread)."""
        win = self.windows.get(hwnd)
        if win is None:
            control = self.controls.get(hwnd)
            if control is not None:
                if self.covers_area(shape, control.width, control.height):
                    control.drawn_shapes = [shape]
                else:
                    control.drawn_shapes = self.add_to_display_list(
                        control.drawn_shapes, shape)[-self.MAX_SHAPES:]
            return
        # New list objects keep the GUI thread's current snapshot intact
        if self.covers_area(shape, *self.client_size(win)):
            win.drawn_shapes = [shape]
            return
        shapes = self.add_to_display_list(win.drawn_shapes, shape)
        if len(shapes) > self.FLATTEN_SHAPES:
            flat = self._flatten_shapes(win, shapes)
            if flat is not None:
                shapes = [flat]
        if len(shapes) > self.MAX_SHAPES:
            shapes = shapes[-(self.MAX_SHAPES // 2):]
        win.drawn_shapes = shapes

    # Longer window display lists are rasterized into one image shape, so
    # partially overlapping game updates don't slow every frame down
    FLATTEN_SHAPES = 256

    def _flatten_shapes(self, win, shapes):
        """Client-area image shape showing shapes over the window background, or None"""
        width, height = self.client_size(win)
        if width <= 0 or height <= 0:
            return None
        surface = pygame.Surface((width, height))
        surface.fill(win.bg_color)
        for shape in shapes:
            self._draw_shape(shape, 0, 0, surface)
        to_bytes = getattr(pygame.image, 'tobytes', None) or pygame.image.tostring
        rop = WinAPIHandler.SRCCOPY
        return {'type': 'image', 'pos': (0, 0), 'dim': (width, height),
                'size': (width, height), 'data': to_bytes(surface, 'RGB'), 'rop': rop,
                '_surface': (((width, height), rop), surface)}

    # Only this many recent entries are checked for being hidden by a new shape
    HIDDEN_SCAN = 1024

    @staticmethod
    def shape_bbox(shape):
        """(left, top, right, bottom) a display list entry can paint, or None"""
        stype = shape['type']
        if 'rect' in shape:
            l, t, r, b = shape['rect']
            return (min(l, r), min(t, b), max(l, r), max(t, b))
        if stype == 'image':
            (x, y), (w, h) = shape['pos'], shape['size']
            return (x, y, x + w, y + h)
        if stype == 'pixel':
            x, y = shape['pos']
            return (x, y, x + 1, y + 1)
        if stype == 'text':
            x, y = shape['pos']
            height = (shape.get('font') or {}).get('height', 16)
            return (x, y, x + len(shape['text']) * height, y + height * 2)
        points = shape.get('points') or [p for p in (shape.get('from'), shape.get('to')) if p]
        if not points:
            return None
        pad = (shape['pen'][1] if shape.get('pen') else 1) + 1
        xs, ys = [p[0] for p in points], [p[1] for p in points]
        return (min(xs) - pad, min(ys) - pad, max(xs) + pad, max(ys) + pad)

    @classmethod
    def add_to_display_list(cls, shapes, shape):
        """shapes plus shape, without recent entries the new shape fully hides
        (keeps redraw-in-place game loops from growing the list)"""
        cover = None
        if shape['type'] == 'rect' and shape.get('fill') is not None:
            cover = cls.shape_bbox(shape)
        elif shape['type'] == 'image' and shape.get('rop') in (0x00CC0020, 0x00330008):
            cover = cls.shape_bbox(shape)
        same_text = shape['type'] == 'text' and shape.get('bk') is not None
        if cover is None and not same_text:
            shapes.append(shape)  # Cheap path: most shapes hide nothing
            return shapes

        def hidden(old):
            if same_text:
                return old['type'] == 'text' and old['pos'] == shape['pos'] and \
                    len(old['text']) <= len(shape['text']) and old.get('font') == shape.get('font')
            box = cls.shape_bbox(old)
            return box is not None and box[0] >= cover[0] and box[1] >= cover[1] and \
                box[2] <= cover[2] and box[3] <= cover[3]

        split = max(0, len(shapes) - cls.HIDDEN_SCAN)
        return shapes[:split] + [s for s in shapes[split:] if not hidden(s)] + [shape]

    @gui_locked
    def clear_drawings(self, hwnd):
        """Reset a window's display list (start of a paint cycle).

        A new empty list is assigned instead of clearing in place, so the GUI
        thread can safely keep iterating a snapshot it already picked up.
        """
        if hwnd in self.windows:
            self.windows[hwnd].drawn_shapes = []
        elif hwnd in self.controls:
            self.controls[hwnd].drawn_shapes = []

    # ==================== MENU BAR ====================

    def _menu_bar_rect(self, win):
        """Screen rect of a window's menu bar strip (or None)."""
        if not win.menu:
            return None
        border, caption = self.window_frame(win)
        return pygame.Rect(win.x + border,
                           win.y + border + max(0, caption - 3),
                           win.width - 2 * border,
                           self.MENU_H)

    def _menu_item_rects(self, win):
        """Screen rects of the top-level menu items (computed, not cached)."""
        bar = self._menu_bar_rect(win)
        if bar is None:
            return []
        rects = []
        x = bar.x + 4
        for item in win.menu:
            text_w = self.font.size(item['text'])[0]
            width = text_w + 16
            rects.append(pygame.Rect(x, bar.y, width, bar.height))
            x += width
        return rects

    def _menu_dropdown_rects(self, win, index):
        """Dropdown rect and item rects of an open top-level menu."""
        item_rects = self._menu_item_rects(win)
        if index >= len(item_rects):
            return None, []
        top_rect = item_rects[index]
        items = win.menu[index].get('items') or []

        width = 100
        for sub in items:
            if sub.get('text'):
                width = max(width, self.font.size(sub['text'])[0] + 32)

        item_h = 20
        sep_h = 7
        height = sum(sep_h if sub.get('separator') else item_h for sub in items) + 4

        drop = pygame.Rect(top_rect.x, top_rect.bottom, width, height)
        rects = []
        y = drop.y + 2
        for sub in items:
            h = sep_h if sub.get('separator') else item_h
            rects.append(pygame.Rect(drop.x + 2, y, width - 4, h))
            y += h
        return drop, rects

    @staticmethod
    def _make_lparam(cx, cy):
        """Pack client x/y into an lParam (LOWORD=x, HIWORD=y)."""
        return ((cy & 0xFFFF) << 16) | (cx & 0xFFFF)

    def _post_control_command(self, win, control, notify_code):
        """Notify a window's WndProc about a control event via WM_COMMAND."""
        parent_hwnd = control.parent_hwnd or win.hwnd
        wParam = ((notify_code & 0xFFFF) << 16) | (control.control_id & 0xFFFF)
        self.winapi.post_window_message(parent_hwnd, self.winapi.WM_COMMAND,
                                        wParam, control.hwnd)

    # ==================== SCROLLBAR CONTROLS ====================

    SCROLL_BTN = 16       # Arrow button length (pixels)
    SCROLL_MIN_THUMB = 12  # Minimum thumb length

    def _scrollbar_metrics(self, control, abs_x, abs_y):
        """Geometry of a scrollbar control at its absolute screen position.

        Returns a dict with 'vertical', arrow rects 'up'/'down', 'track' and
        'thumb' rects, plus 'track_len' and 'thumb_len' along the scroll axis.
        """
        vertical = bool(control.style & 0x0001)  # SBS_VERT
        length = control.height if vertical else control.width
        btn = min(self.SCROLL_BTN, max(0, length // 2))
        track_len = max(1, length - 2 * btn)

        span = 1
        pos_max = control.scroll_max
        if self.winapi:
            pos_max = self.winapi.scroll_pos_max(control)
        span = max(1, pos_max - control.scroll_min)

        # Thumb length: proportional when a page size is set
        if control.scroll_page > 0:
            content = max(1, control.scroll_max - control.scroll_min + 1)
            thumb_len = int(track_len * control.scroll_page / content)
        else:
            thumb_len = self.SCROLL_MIN_THUMB
        thumb_len = max(self.SCROLL_MIN_THUMB, min(thumb_len, track_len))

        frac = (control.scroll_pos - control.scroll_min) / span
        frac = max(0.0, min(1.0, frac))
        thumb_off = int((track_len - thumb_len) * frac)

        if vertical:
            up = pygame.Rect(abs_x, abs_y, control.width, btn)
            down = pygame.Rect(abs_x, abs_y + control.height - btn,
                               control.width, btn)
            track = pygame.Rect(abs_x, abs_y + btn, control.width, track_len)
            thumb = pygame.Rect(abs_x, abs_y + btn + thumb_off,
                                control.width, thumb_len)
        else:
            up = pygame.Rect(abs_x, abs_y, btn, control.height)
            down = pygame.Rect(abs_x + control.width - btn, abs_y,
                               btn, control.height)
            track = pygame.Rect(abs_x + btn, abs_y, track_len, control.height)
            thumb = pygame.Rect(abs_x + btn + thumb_off, abs_y,
                                thumb_len, control.height)

        return {'vertical': vertical, 'up': up, 'down': down, 'track': track,
                'thumb': thumb, 'track_len': track_len, 'thumb_len': thumb_len,
                'span': span, 'pos_max': pos_max}

    def _scrollbar_abs_pos(self, control):
        """Absolute screen position of a scrollbar control, or None"""
        win = self.windows.get(control.parent_hwnd)
        if not win or not win.visible or win.minimized:
            return None
        content_x, content_y = self.client_origin(win)
        return (content_x + control.x, content_y + control.y)

    def _post_scroll(self, control, code, pos):
        """Post WM_VSCROLL/WM_HSCROLL for a scrollbar control to its parent."""
        if not self.winapi or not control.parent_hwnd:
            return
        vertical = bool(control.style & 0x0001)
        msg = self.winapi.WM_VSCROLL if vertical else self.winapi.WM_HSCROLL
        wparam = (code & 0xFFFF) | ((pos & 0xFFFF) << 16)
        self.winapi.post_window_message(control.parent_hwnd, msg,
                                        wparam, control.hwnd)

    def _scroll_by(self, control, delta, code):
        """Move a scrollbar by delta positions and notify the parent."""
        pos_max = self.winapi.scroll_pos_max(control) if self.winapi \
            else control.scroll_max
        new_pos = max(control.scroll_min, min(control.scroll_pos + delta, pos_max))
        control.scroll_pos = new_pos
        self._post_scroll(control, code, new_pos)

    def _handle_scrollbar_click(self, control, x, y, abs_x, abs_y):
        """Handle a left click inside a scrollbar control."""
        winapi = self.winapi
        if not winapi:
            return
        m = self._scrollbar_metrics(control, abs_x, abs_y)
        page = control.scroll_page if control.scroll_page > 0 else 10

        if m['up'].collidepoint(x, y):
            self._scroll_by(control, -1, winapi.SB_LINEUP)
        elif m['down'].collidepoint(x, y):
            self._scroll_by(control, 1, winapi.SB_LINEDOWN)
        elif m['thumb'].collidepoint(x, y):
            grab = (y - m['thumb'].y) if m['vertical'] else (x - m['thumb'].x)
            self.dragging_scrollbar = (control.hwnd, grab)
        elif m['track'].collidepoint(x, y):
            before = (y < m['thumb'].y) if m['vertical'] else (x < m['thumb'].x)
            if before:
                self._scroll_by(control, -page, winapi.SB_PAGEUP)
            else:
                self._scroll_by(control, page, winapi.SB_PAGEDOWN)

    def _drag_scrollbar_to(self, pos):
        """Track a scrollbar thumb drag (SB_THUMBTRACK)."""
        hwnd, grab = self.dragging_scrollbar
        control = self.controls.get(hwnd)
        if not control or not self.winapi:
            self.dragging_scrollbar = None
            return
        abs_pos = self._scrollbar_abs_pos(control)
        if abs_pos is None:
            self.dragging_scrollbar = None
            return
        m = self._scrollbar_metrics(control, abs_pos[0], abs_pos[1])
        slide = m['track_len'] - m['thumb_len']
        if slide <= 0:
            return
        coord = pos[1] if m['vertical'] else pos[0]
        track_start = m['track'].y if m['vertical'] else m['track'].x
        frac = (coord - grab - track_start) / slide
        frac = max(0.0, min(1.0, frac))
        new_pos = control.scroll_min + int(round(frac * m['span']))
        if new_pos != control.scroll_pos:
            control.scroll_pos = new_pos
            self._post_scroll(control, self.winapi.SB_THUMBTRACK, new_pos)

    def _end_scrollbar_drag(self):
        """Finish a thumb drag: SB_THUMBPOSITION then SB_ENDSCROLL."""
        hwnd, _ = self.dragging_scrollbar
        self.dragging_scrollbar = None
        control = self.controls.get(hwnd)
        if control and self.winapi:
            self._post_scroll(control, self.winapi.SB_THUMBPOSITION,
                              control.scroll_pos)
            self._post_scroll(control, self.winapi.SB_ENDSCROLL, 0)

    def _post_button_command(self, win, control):
        """Notify a window's WndProc that one of its buttons was clicked."""
        self._post_control_command(win, control, self.winapi.BN_CLICKED)

    def _check_auto_radio(self, win, control):
        """Check a BS_AUTORADIOBUTTON and uncheck the other radio buttons of its
        group (controls from a WS_GROUP control up to the next one)"""
        WS_GROUP = 0x00020000
        controls = win.controls
        index = controls.index(control)
        first = index
        while first > 0 and not controls[first].style & WS_GROUP:
            first -= 1
        last = index + 1
        while last < len(controls) and not controls[last].style & WS_GROUP:
            last += 1
        for other in controls[first:last]:
            if other.class_name == "CHECKBOX" and (other.style & 0xF) == 0x9:
                other.checked = other is control

    def _handle_combo_click(self, pos, button):
        """Handle clicks while a combobox dropdown is open.

        Returns True if the click was consumed by the dropdown.
        """
        control = self.controls.get(self.open_combo)
        if not control:
            self.open_combo = None
            return False

        drop, item_rects = self._combo_dropdown_rects(control)
        if drop is not None and drop.collidepoint(pos):
            if button == 1:
                for i, rect in enumerate(item_rects):
                    if rect.collidepoint(pos):
                        control.sel_index = i
                        self.open_combo = None
                        win = self.windows.get(control.parent_hwnd)
                        if win and self.winapi:
                            self._post_control_command(win, control,
                                                       self.winapi.CBN_SELCHANGE)
                        return True
            return True  # Click inside dropdown chrome: swallow

        # Click elsewhere: close the dropdown, then process the click normally
        self.open_combo = None
        return False

    def _capture_target(self):
        """Window that currently captures the mouse (SetCapture), or None."""
        if not self.winapi:
            return None
        cap = self.winapi.capture_hwnd
        if cap and cap in self.windows and self._is_app_window(cap):
            return self.windows[cap]
        return None

    def _forward_mouse_move(self, pos, buttons):
        """Forward WM_MOUSEMOVE to the captured or hovered app window."""
        if not self.winapi:
            return
        x, y = pos
        wparam = 0
        if buttons[0]:
            wparam |= self.winapi.MK_LBUTTON
        if buttons[2]:
            wparam |= self.winapi.MK_RBUTTON

        # Mouse capture: every move goes to the capturing window
        win = self._capture_target()
        if win is None:
            # Otherwise: topmost visible app window under the cursor
            for hwnd in reversed(self.z_order):
                w = self.windows.get(hwnd)
                if w and w.visible and not w.minimized and w.contains_point(x, y):
                    if w.is_dialog or not self._is_app_window(hwnd):
                        return
                    if y < self.client_origin(w)[1]:
                        return  # title bar / menu bar / chrome
                    win = w
                    break
        if win is None:
            return
        cx, cy = self._client_point(win, x, y)
        self.winapi.post_window_message(win.hwnd, self.winapi.WM_MOUSEMOVE,
                                        wparam, self._make_lparam(cx, cy))

    def _forward_mouse_up(self, pos, button):
        """Forward a mouse-button release to the app window under the cursor."""
        if not self.winapi:
            return
        x, y = pos

        # Mouse capture: the release always goes to the capturing window
        win = self._capture_target()
        if win is not None:
            cx, cy = self._client_point(win, x, y)
            lparam = self._make_lparam(cx, cy)
            if button == 1:
                self.winapi.post_window_message(win.hwnd, self.winapi.WM_LBUTTONUP,
                                                0, lparam)
            elif button == 3:
                self.winapi.post_window_message(win.hwnd, self.winapi.WM_RBUTTONUP,
                                                0, lparam)
            return

        for hwnd in reversed(self.z_order):
            win = self.windows.get(hwnd)
            if win and win.visible and not win.minimized and win.contains_point(x, y):
                if win.is_dialog or not self._is_app_window(hwnd):
                    return
                if y < self.client_origin(win)[1]:
                    return  # title bar / menu bar / chrome, not client area
                cx, cy = self._client_point(win, x, y)
                lparam = self._make_lparam(cx, cy)
                if button == 1:
                    self.winapi.post_window_message(hwnd, self.winapi.WM_LBUTTONUP, 0, lparam)
                elif button == 3:
                    self.winapi.post_window_message(hwnd, self.winapi.WM_RBUTTONUP, 0, lparam)
                return

    def _handle_menu_click(self, pos, button):
        """Handle clicks while a dropdown menu is open.

        Returns True if the click was consumed by the menu system.
        """
        hwnd, index = self.open_menu
        win = self.windows.get(hwnd)
        if not win or not win.visible or win.minimized or not win.menu:
            self.open_menu = None
            return False

        drop, item_rects = self._menu_dropdown_rects(win, index)
        if drop is not None and drop.collidepoint(pos):
            if button == 1:
                items = win.menu[index].get('items') or []
                for sub, rect in zip(items, item_rects):
                    if not sub.get('separator') and rect.collidepoint(pos):
                        self.open_menu = None
                        if self.winapi:
                            # Menu WM_COMMAND: HIWORD(wParam)=0, LOWORD=menu id
                            self.winapi.post_window_message(
                                hwnd, self.winapi.WM_COMMAND, sub['id'] & 0xFFFF, 0)
                        return True
            return True  # Click inside dropdown chrome: swallow

        # Clicking another top-level item switches the open dropdown
        for i, rect in enumerate(self._menu_item_rects(win)):
            if rect.collidepoint(pos):
                self._activate_menu_item(win, i)
                return True

        # Click elsewhere: close the menu, then process the click normally
        self.open_menu = None
        return False

    def _activate_menu_item(self, win, index):
        """Open a dropdown or fire a plain top-level menu item"""
        item = win.menu[index]
        if item.get('items'):
            # Toggle dropdown
            if self.open_menu == (win.hwnd, index):
                self.open_menu = None
            else:
                self.open_menu = (win.hwnd, index)
        else:
            self.open_menu = None
            if self.winapi:
                self.winapi.post_window_message(
                    win.hwnd, self.winapi.WM_COMMAND, item['id'] & 0xFFFF, 0)

    def _handle_mouse_click(self, pos, button):
        """Handle mouse click"""
        x, y = pos

        # The Start menu grabs clicks first
        if self._handle_start_menu_click(pos, button):
            return

        # An open dropdown menu grabs clicks first
        if self.open_menu and self._handle_menu_click(pos, button):
            return

        # An open combobox dropdown grabs clicks next
        if self.open_combo and self._handle_combo_click(pos, button):
            return

        # Click on taskbar windows (a full-screen window covers the taskbar)
        taskbar_y = self.height - 30
        if y >= taskbar_y and self._fullscreen_window() is None:
            # System tray area (right side) - ignore click
            tray_width = 80
            if x >= self.width - tray_width:
                return
            
            # Visible windows (excluding dialogs)
            visible_windows = [(hwnd, self.windows[hwnd]) for hwnd in self.z_order 
                              if hwnd in self.windows and self.windows[hwnd].visible 
                              and not self.windows[hwnd].is_dialog]
            
            if not visible_windows:
                return
            
            # Calculate button width
            max_btn_width = 140
            available_width = self.width - tray_width - 80
            btn_width = min(max_btn_width, available_width // len(visible_windows) - 5)
            btn_width = max(60, btn_width)
            
            # Which button was clicked?
            btn_x = 70
            for hwnd, win in visible_windows:
                if btn_x <= x <= btn_x + btn_width:
                    if win.minimized:
                        # If minimized, restore
                        win.restore()
                    elif hwnd == self.active_window:
                        # If already active, minimize
                        win.minimize()
                        # Activate next visible window
                        for h in reversed(self.z_order):
                            if h in self.windows and self.windows[h].visible and not self.windows[h].minimized and not self.windows[h].is_dialog:
                                self.active_window = h
                                break
                        return
                    
                    # Make window active and bring to front
                    self.active_window = hwnd
                    self.z_order.remove(hwnd)
                    self.z_order.append(hwnd)
                    return
                btn_x += btn_width + 5
            return
        
        # Check windows in reverse order (topmost first)
        for hwnd in reversed(self.z_order):
            if hwnd in self.windows:
                win = self.windows[hwnd]
                if win.visible and not win.minimized and win.contains_point(x, y):
                    # Make window active and bring to front
                    self.active_window = hwnd
                    self.z_order.remove(hwnd)
                    self.z_order.append(hwnd)
                    border, caption = self.window_frame(win)
                    
                    # Title bar buttons (right to left: close, max, min)
                    btn_size = 16
                    btn_y_start = win.y + 5
                    btn_y_end = win.y + 5 + btn_size
                    
                    # Close butonu (X)
                    close_x = win.x + win.width - btn_size - 5
                    if (caption and close_x <= x <= close_x + btn_size
                            and btn_y_start <= y <= btn_y_end):
                        self._close_window(hwnd)
                        return
                    
                    # Minimize and maximize buttons if not a dialog
                    if caption and not win.is_dialog:
                        # Maximize butonu (□)
                        max_x = win.x + win.width - btn_size * 2 - 7
                        if max_x <= x <= max_x + btn_size and btn_y_start <= y <= btn_y_end:
                            win.maximize(self.width, self.height, 30)
                            return
                        
                        # Minimize butonu (_)
                        min_x = win.x + win.width - btn_size * 3 - 9
                        if min_x <= x <= min_x + btn_size and btn_y_start <= y <= btn_y_end:
                            win.minimize()
                            # Activate next visible window
                            for h in reversed(self.z_order):
                                if h in self.windows and self.windows[h].visible and not self.windows[h].minimized:
                                    self.active_window = h
                                    break
                            return
                    
                    # Edge/corner resizing (left button only)
                    if button == 1:
                        edge = self._get_resize_edge(win, x, y)
                        if edge:
                            self.resizing_window = hwnd
                            self.resize_edge = edge
                            self.resize_start_mouse = (x, y)
                            self.resize_start_rect = (win.x, win.y, win.width, win.height)
                            return

                    # Title bar click (start dragging) - if not maximized
                    if (caption and win.y + border <= y <= win.y + caption
                            and not win.maximized):
                        self.dragging_window = hwnd
                        self.drag_offset_x = x - win.x
                        self.drag_offset_y = y - win.y
                        return

                    # Menu bar click
                    if win.menu and button == 1:
                        for i, rect in enumerate(self._menu_item_rects(win)):
                            if rect.collidepoint(x, y):
                                self._activate_menu_item(win, i)
                                return
                        bar = self._menu_bar_rect(win)
                        if bar and bar.collidepoint(x, y):
                            return  # Empty menu bar area: swallow the click

                    # Click on controls in content area
                    content_x, content_y = self.client_origin(win)
                    for control in win.controls:
                        if not (control.visible and control.enabled):
                            continue
                        ctrl_x = content_x + control.x
                        ctrl_y = content_y + control.y
                        # A combobox only occupies its closed box; the
                        # CreateWindow height includes the dropdown area
                        ctrl_h = control.height
                        if control.class_name == "COMBOBOX":
                            ctrl_h = min(control.height, 24)
                        if not (ctrl_x <= x <= ctrl_x + control.width and
                                ctrl_y <= y <= ctrl_y + ctrl_h):
                            continue

                        if control.class_name == "BUTTON":
                            if (control.style & 0xF) == 7:
                                continue  # A group box lets clicks through to its buttons
                            # Clicking a button takes focus away from edits
                            self.focused_control = None
                            # If dialog window (MessageBox) - OK/Cancel button closes it
                            if win.is_dialog and not self._is_app_window(hwnd):
                                self._close_window(hwnd)
                                return
                            # Normal window - notify WndProc with WM_COMMAND
                            if button == 1 and self.winapi:
                                self._post_button_command(win, control)
                            return
                        elif control.class_name == "EDIT":
                            # Give keyboard focus to the edit control
                            if button == 1:
                                self.focused_control = control.hwnd
                            return
                        elif control.class_name == "CHECKBOX":
                            if button == 1:
                                self.focused_control = None
                                # BS_AUTOCHECKBOX (0x3) toggles by itself
                                if (control.style & 0xF) == 0x3:
                                    control.checked = not control.checked
                                elif (control.style & 0xF) == 0x9:  # BS_AUTORADIOBUTTON
                                    self._check_auto_radio(win, control)
                                if self.winapi:
                                    self._post_button_command(win, control)
                            return
                        elif control.class_name == "LISTBOX":
                            if button in (4, 5):  # Mouse wheel
                                rows = max(1, (control.height - 2) // self.LISTBOX_ITEM_H)
                                step = 3 if button == 5 else -3
                                control.top_index = max(0, min(control.top_index + step,
                                                               len(control.items) - rows))
                            elif button == 1:
                                self.focused_control = None
                                index = ((y - ctrl_y - 1) // self.LISTBOX_ITEM_H
                                         + control.top_index)
                                if 0 <= index < len(control.items):
                                    control.sel_index = index
                                    if self.winapi:
                                        self._post_control_command(
                                            win, control, self.winapi.LBN_SELCHANGE)
                            return
                        elif control.class_name == "COMBOBOX":
                            if button == 1:
                                self.focused_control = None
                                # Toggle the dropdown list
                                if self.open_combo == control.hwnd:
                                    self.open_combo = None
                                else:
                                    self.open_combo = control.hwnd
                            return
                        elif control.class_name == "SCROLLBAR":
                            if button == 1:
                                self.focused_control = None
                                self._handle_scrollbar_click(control, x, y,
                                                             ctrl_x, ctrl_y)
                            return
                        # Other control types: swallow the click
                        return

                    # Clicking empty client area clears edit focus
                    if button == 1:
                        self.focused_control = None

                    # No control hit -> forward raw mouse click to the WndProc
                    if (not win.is_dialog and y >= content_y and
                            self._is_app_window(hwnd)):
                        cx, cy = self._client_point(win, x, y)
                        lparam = self._make_lparam(cx, cy)
                        if button == 1:
                            self.winapi.post_window_message(
                                hwnd, self.winapi.WM_LBUTTONDOWN,
                                self.winapi.MK_LBUTTON, lparam)
                        elif button == 3:
                            self.winapi.post_window_message(
                                hwnd, self.winapi.WM_RBUTTONDOWN,
                                self.winapi.MK_RBUTTON, lparam)

                    break
    
    def _pygame_key_to_vk(self, event):
        """Map a Pygame key to a Windows virtual-key code, or None."""
        key = event.key
        if pygame.K_a <= key <= pygame.K_z:
            return key - 32            # 'a' (0x61) -> VK 'A' (0x41)
        if pygame.K_0 <= key <= pygame.K_9:
            return key                 # '0' (0x30) -> VK 0x30
        if pygame.K_F1 <= key <= pygame.K_F12:
            return 0x70 + (key - pygame.K_F1)
        special = {
            pygame.K_ESCAPE: 0x1B, pygame.K_RETURN: 0x0D, pygame.K_KP_ENTER: 0x0D,
            pygame.K_SPACE: 0x20, pygame.K_TAB: 0x09, pygame.K_BACKSPACE: 0x08,
            pygame.K_DELETE: 0x2E, pygame.K_LEFT: 0x25, pygame.K_UP: 0x26,
            pygame.K_RIGHT: 0x27, pygame.K_DOWN: 0x28, pygame.K_HOME: 0x24,
            pygame.K_END: 0x23, pygame.K_PAGEUP: 0x21, pygame.K_PAGEDOWN: 0x22,
            pygame.K_LSHIFT: 0x10, pygame.K_RSHIFT: 0x10,
            pygame.K_LCTRL: 0x11, pygame.K_RCTRL: 0x11,
            pygame.K_LALT: 0x12, pygame.K_RALT: 0x12,
        }
        return special.get(key)

    def _forward_key_up(self, vk):
        """Forward a key release (WM_KEYUP) to the active application window."""
        if not self.winapi:
            return
        hwnd = self.active_window
        if hwnd and self._is_app_window(hwnd):
            self.winapi.post_window_message(hwnd, self.winapi.WM_KEYUP, vk, 1)

    def _forward_key_to_window(self, event):
        """Forward a keystroke to the active application window's WndProc."""
        if not self.winapi:
            return
        hwnd = self.active_window
        if not hwnd or not self._is_app_window(hwnd):
            return
        vk = self._pygame_key_to_vk(event)
        if vk is not None:
            self.winapi.post_window_message(hwnd, self.winapi.WM_KEYDOWN, vk, 1)
        # Synthesize WM_CHAR for printable input (TranslateMessage behavior)
        if event.unicode and len(event.unicode) == 1 and event.unicode.isprintable():
            self.winapi.post_window_message(hwnd, self.winapi.WM_CHAR, ord(event.unicode), 1)

    def _handle_key_press(self, event):
        """Handle keyboard key press"""
        # The active console window takes the line its program is waiting for
        console = self.consoles.get(self.active_window)
        if console is not None and console.input_active:
            if event.key in (pygame.K_RETURN, pygame.K_KP_ENTER):
                # Enter - input completed; it stays on screen like in a real console
                line = console.input
                console.input = ""
                self.console_write(console, line + "\n", "stdin")
                console.input_result = line
                console.input_active = False
                console.input_ready.set()  # Send signal to waiting thread
            elif event.key == pygame.K_BACKSPACE:
                # Backspace - delete last character
                console.input = console.input[:-1]
            elif event.key == pygame.K_ESCAPE:
                # ESC - clear the line being typed
                console.input = ""
            else:
                # Printable character
                if event.unicode and event.unicode.isprintable():
                    console.input += event.unicode
            return

        # A focused EDIT control consumes keystrokes
        if self._handle_edit_key(event):
            return

        # Otherwise forward the keystroke to the active application window
        self._forward_key_to_window(event)

    def _handle_edit_key(self, event):
        """Type into the focused EDIT control. Returns True if consumed."""
        control = self.controls.get(self.focused_control)
        if not control or control.class_name != "EDIT":
            return False
        # Only edit when the parent window is visible and active
        win = self.windows.get(control.parent_hwnd)
        if not win or not win.visible or win.minimized or win.hwnd != self.active_window:
            return False
        if not (control.visible and control.enabled):
            return False

        if event.key == pygame.K_BACKSPACE:
            control.text = control.text[:-1]
        elif event.key in (pygame.K_RETURN, pygame.K_KP_ENTER, pygame.K_ESCAPE, pygame.K_TAB):
            if win.owner is not None and control.parent_hwnd in win.owner.dialogs:
                return False  # The dialog handles them (default button, Cancel, next edit)
            self.focused_control = None
        elif event.unicode and event.unicode.isprintable():
            control.text += event.unicode
        return True

    def _check_messagebox(self):
        """Check MessageBox requests"""
        try:
            msg = self.messagebox_queue.get_nowait()
            self._show_messagebox(msg['caption'], msg['text'], msg['type'])
        except queue.Empty:
            pass
    
    def _show_messagebox(self, caption, text, msg_type):
        """Show MessageBox"""
        # Create MessageBox window
        width = max(300, len(text) * 8 + 50)
        height = 120
        x = (self.width - width) // 2
        y = (self.height - height) // 2
        
        hwnd = self.create_window(caption, x, y, width, height)
        win = self.windows[hwnd]
        win.is_dialog = True  # Show only close button
        
        # Text
        text_ctrl = FakeControl(self.get_next_hwnd(), "STATIC", text, 20, 20, width - 40, 30)
        win.controls.append(text_ctrl)
        
        # OK button
        ok_btn = FakeControl(self.get_next_hwnd(), "BUTTON", "OK", (width - 80) // 2, height - 60, 80, 25)
        win.controls.append(ok_btn)
        
        self.show_window(hwnd)
    
    @gui_locked
    def _close_window(self, hwnd, notify_app=True):
        """Close window.

        App windows with a WndProc get WM_CLOSE posted so the app decides
        (DestroyWindow / PostQuitMessage). Other windows are hidden directly.
        DestroyWindow calls this with notify_app=False to avoid a loop.
        """
        if hwnd not in self.windows:
            return

        console = self.consoles.get(hwnd)
        if console is not None:
            # Closing a console ends the program attached to it (like Windows)
            owner = self.windows[hwnd].owner
            if owner is not None:
                owner.request_termination()
            self.close_console(console)
            return

        if notify_app and self._is_app_window(hwnd):
            self.winapi.post_window_message(hwnd, self.winapi.WM_CLOSE, 0, 0)
            return

        self.windows[hwnd].visible = False
        if hwnd in self.z_order:
            self.z_order.remove(hwnd)
        if self.active_window == hwnd:
            self.active_window = self.z_order[-1] if self.z_order else None
        if self.open_menu and self.open_menu[0] == hwnd:
            self.open_menu = None
    
    @gui_locked
    def get_next_hwnd(self):
        """Get new HWND"""
        hwnd = self.next_hwnd
        self.next_hwnd += 4
        return hwnd
    
    @gui_locked
    def create_window(self, title, x, y, width, height, style=0, owner=None, parent=0):
        """Create new window (a child window if parent is a window handle)"""
        hwnd = self.get_next_hwnd()
        window = FakeWindow(hwnd, title, x, y, width, height, style)
        window.owner = owner
        self.windows[hwnd] = window
        if parent in self.windows:
            # Child windows are drawn inside their parent, not on the desktop
            window.parent = parent
            self.windows[parent].children.append(hwnd)
        else:
            self.z_order.append(hwnd)
        
        log.debug(f"GUI: Window created - HWND=0x{hwnd:08x}, '{title}'")
        return hwnd
    
    @gui_locked
    def create_control(self, parent_hwnd, class_name, text, x, y, width, height, style=0, control_id=0):
        """Create new control"""
        hwnd = self.get_next_hwnd()
        control = FakeControl(hwnd, class_name, text, x, y, width, height, style)
        control.parent_hwnd = parent_hwnd
        control.control_id = control_id

        self.controls[hwnd] = control
        
        if parent_hwnd in self.windows:
            self.windows[parent_hwnd].controls.append(control)
        
        log.debug(f"GUI: Control created - HWND=0x{hwnd:08x}, {class_name}, '{text}'")
        return hwnd

    @gui_locked
    def destroy_control(self, hwnd):
        """Remove a child control (DestroyWindow)"""
        control = self.controls.pop(hwnd, None)
        if control is None:
            return
        parent = self.windows.get(control.parent_hwnd)
        if parent is not None:
            parent.controls = [c for c in parent.controls if c.hwnd != hwnd]
        if self.focused_control == hwnd:
            self.focused_control = None
        if self.open_combo == hwnd:
            self.open_combo = None
    
    @gui_locked
    def show_window(self, hwnd, show=True):
        """Show/hide window"""
        if hwnd in self.windows:
            self.windows[hwnd].visible = show
            if show and not self.windows[hwnd].parent:
                self.active_window = hwnd
                if hwnd not in self.z_order:
                    self.z_order.append(hwnd)
        elif hwnd in self.controls:
            self.controls[hwnd].visible = show
    
    @gui_locked
    def set_window_text(self, hwnd, text):
        """Set window/control text"""
        if hwnd in self.windows:
            self.windows[hwnd].title = text
            self.windows[hwnd].text = text
        elif hwnd in self.controls:
            self.controls[hwnd].text = text
    
    def get_window_text(self, hwnd):
        """Get window/control text"""
        if hwnd in self.windows:
            return self.windows[hwnd].text
        elif hwnd in self.controls:
            return self.controls[hwnd].text
        return ""
    
    def show_messagebox(self, caption, text, msg_type=0):
        """Show MessageBox (thread-safe)"""
        self.messagebox_queue.put({
            'caption': caption,
            'text': text,
            'type': msg_type
        })
        return 1  # IDOK
    
    # ==================== CONSOLE WINDOW ====================
    
    @gui_locked
    def create_console(self, title, owner):
        """Open a console window for a process (called on its emulation thread)"""
        offset = 24 * (self.consoles_opened % 8)  # Cascade, so none hides another
        self.consoles_opened += 1
        hwnd = self.create_window(title, 50 + offset, 400 - offset, 600, 280, owner=owner)
        self.windows[hwnd].bg_color = (12, 12, 12)  # Black background
        console = FakeConsole(hwnd)
        self.consoles[hwnd] = console
        self.show_window(hwnd)
        return console

    @gui_locked
    def cancel_console_input(self, console):
        """Unblock a pending read for good (process ending or console closing)"""
        console.cancelled = True
        console.input_active = False
        console.input_result = None
        console.input_ready.set()

    @gui_locked
    def close_console(self, console):
        """Close a console window"""
        self.cancel_console_input(console)
        self.consoles.pop(console.hwnd, None)
        self._remove_window(console.hwnd)
    
    def _draw_console_window(self, window, console):
        """Draw console window"""
        if not window.visible or window.minimized:
            return
        
        is_active = (window.hwnd == self.active_window)
        
        # Window shadow
        shadow_rect = pygame.Rect(window.x + 3, window.y + 3, window.width, window.height)
        pygame.draw.rect(self.screen, (64, 64, 64), shadow_rect)
        
        # Window frame
        frame_rect = pygame.Rect(window.x, window.y, window.width, window.height)
        pygame.draw.rect(self.screen, (12, 12, 12), frame_rect)  # Black background
        pygame.draw.rect(self.screen, self.COLOR_BUTTON_BORDER_DARK, frame_rect, 1)
        
        # 3D edge effect
        pygame.draw.line(self.screen, (64, 64, 64), 
                        (window.x, window.y), (window.x + window.width - 1, window.y))
        pygame.draw.line(self.screen, (64, 64, 64), 
                        (window.x, window.y), (window.x, window.y + window.height - 1))
        
        # Title bar
        title_color = self.COLOR_TITLE_BAR if is_active else self.COLOR_TITLE_BAR_INACTIVE
        title_rect = pygame.Rect(window.x + 3, window.y + 3, window.width - 6, 22)
        pygame.draw.rect(self.screen, title_color, title_rect)
        
        # Title text
        title_text = self.font_bold.render(window.title[:50], True, self.COLOR_TITLE_TEXT)
        self.screen.blit(title_text, (window.x + 8, window.y + 6))
        
        # Window buttons
        btn_size = 16
        btn_y = window.y + 5
        
        # Close butonu (X)
        close_rect = pygame.Rect(window.x + window.width - btn_size - 5, btn_y, btn_size, btn_size)
        self._draw_window_button(close_rect, "×", "close")
        
        # Maximize butonu
        max_rect = pygame.Rect(window.x + window.width - btn_size * 2 - 7, btn_y, btn_size, btn_size)
        max_symbol = "❐" if window.maximized else "□"
        self._draw_window_button(max_rect, max_symbol, "max")
        
        # Minimize butonu
        min_rect = pygame.Rect(window.x + window.width - btn_size * 3 - 9, btn_y, btn_size, btn_size)
        self._draw_window_button(min_rect, "─", "min")
        
        # Content area (console output, the line being typed continues it)
        content_x = window.x + 5
        content_y = window.y + 30
        content_width = window.width - 10
        content_height = window.height - 35
        
        # Content background
        content_rect = pygame.Rect(content_x, content_y, content_width, content_height)
        pygame.draw.rect(self.screen, (12, 12, 12), content_rect)

        rows = list(console.lines)
        if console.input_active:
            typed = (console.input, self.CONSOLE_COLORS['stdin'])
            if console.line_open and rows:
                rows[-1] = rows[-1] + [typed]
            else:
                rows.append([typed])

        # Draw the last rows that fit (scrolled back by console.scroll)
        line_height = 14
        max_visible_lines = max(1, (content_height - 4) // line_height)
        end_line = max(0, len(rows) - console.scroll)
        start_line = max(0, end_line - max_visible_lines)

        self.screen.set_clip(content_rect)
        y_offset = content_y + 2
        x = content_x + 3
        for row in rows[start_line:end_line]:
            x = content_x + 3
            for text, color in row:
                if text:
                    surface = self.font_console.render(text, True, color)
                    self.screen.blit(surface, (x, y_offset))
                    x += surface.get_width()
            y_offset += line_height

        # Blinking block cursor after the typed text
        if console.input_active and self.console_cursor_visible and console.scroll == 0:
            cursor_h = self.font_console.get_height()
            pygame.draw.rect(self.screen, self.CONSOLE_COLORS['stdin'],
                             (x, y_offset - line_height + cursor_h - 3, 8, 2))
        self.screen.set_clip(None)

    # Console text colors per stream
    CONSOLE_COLORS = {'stdout': (192, 192, 192), 'stderr': (255, 64, 64),
                      'stdin': (192, 192, 192)}

    @gui_locked
    def console_write(self, console, text, stream="stdout"):
        """Write to a process's console (thread-safe); text without a final LF
        leaves the line open, so later output (or typed input) continues it"""
        color = self.CONSOLE_COLORS.get(stream, self.CONSOLE_COLORS['stdout'])
        
        # CR has no glyph; console lines are split on LF only
        text = text.replace('\r\n', '\n').replace('\r', '')

        for i, part in enumerate(text.split('\n')):
            if i > 0:
                # LF: end the open line, or add an empty one at a line start
                if not console.line_open:
                    console.lines.append([])
                console.line_open = False
            if part:
                if console.line_open:
                    console.lines[-1].append((part, color))
                else:
                    console.lines.append([(part, color)])
                    console.line_open = True
        
        # Check maximum line count
        del console.lines[:-FakeConsole.MAX_LINES]
    
    def request_console_input(self, console):
        """
        Read a line typed into a console - called from the emulation thread,
        blocks until the GUI thread delivers it. None if the read is cancelled.
        """
        with self.lock:
            if console.cancelled or console.hwnd not in self.consoles:
                return None
            console.input = ""
            console.input_result = None
            console.input_ready.clear()
            console.input_active = True
            self.console_cursor_visible = True
            self.console_cursor_timer = 0
            # Bring the console to the front so typing goes to it
            win = self.windows[console.hwnd]
            win.minimized = False
            if console.hwnd in self.z_order:
                self.z_order.remove(console.hwnd)
            self.z_order.append(console.hwnd)
            self.active_window = console.hwnd
        
        console.input_ready.wait()  # Blocking wait
        return console.input_result


class CPUEmulator:
    """Unicorn-based x86 CPU emulator"""
    
    # Memory layout constants
    STACK_BASE = 0x7FF00000
    STACK_SIZE = 0x00100000  # 1MB stack
    HEAP_BASE = 0x10000000
    HEAP_SIZE = 128 * 1024 * 1024  # 128 MiB heap
    API_HOOK_BASE = 0x70000000  # API stub addresses
    API_HOOK_SIZE = 0x100000
    CALLBACK_RETURN_ADDR = 0x6FFF0000
    PROCESS_EXIT_ADDR = CALLBACK_RETURN_ADDR + 0x10  # return address of the entry point
    # Double-returning APIs return through "fld qword [X87_RESULT_ADDR]; ret"
    X87_RETURN_STUB = CALLBACK_RETURN_ADDR + 0x20
    X87_RESULT_ADDR = CALLBACK_RETURN_ADDR + 0x100
    # x87-register-argument APIs (_CIsin, _ftol...) spill ST(i) here
    X87_ARGS_ADDR = CALLBACK_RETURN_ADDR + 0x110
    
    def __init__(self, pe_loader, gui=None):
        self.pe_loader = pe_loader
        self.gui = gui  # PseudoWindowsGUI reference
        self.uc = None
        self.cs = None
        self.stop_emulation = False
        self.instruction_count = 0
        self.block_insn_counts = {}  # (address, size) -> instructions in block
        self.max_instructions = 0  # Maximum instruction limit (0 = unlimited)
        
        # Memory management
        self.heap_current = self.HEAP_BASE
        self.heap_blocks = {}  # addr -> requested size (for realloc)
        self.heap_free_bins = {}  # aligned size -> set of free block addrs
        self.heap_free_ends = {}  # free block end addr -> start addr
        self.mapped_regions = []
        
        # API hook system
        self.api_hooks = {}
        self.api_handler = None
        self.crashed = False
        self.next_hook_addr = self.API_HOOK_BASE
        self.dynamic_stubs = {}  # (dll, name) -> stub addr from GetProcAddress
        
        # Callback system
        self.callback_stack = []  # Stack for nested callback support
        self.callback_return_addr = self.CALLBACK_RETURN_ADDR
        self.api_call_esp = 0  # ESP at the current API stub (setjmp needs it)
        self.pending_callback = None  # Pending callback info
        
        # Console input system
        self.pending_console_read = None  # Pending ReadConsoleA request
        self.stop_for_input = False  # Paused for input?
        
        # Special memory addresses
        self.cmdline_addr = 0
        self.cmdline_wide_addr = 0
        self.peb_addr = 0
        self.teb_addr = 0
        self.process_heap = 0
        
    def initialize(self):
        """Initialize emulator"""
        log.header("Initializing CPU Emulator")
        
        # Create Unicorn emulator (32-bit x86)
        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        
        # Create Capstone disassembler
        self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
        self.cs.detail = True
        
        log.success("Unicorn and Capstone initialized")
        
        # Create API handler (with GUI reference)
        self.api_handler = WinAPIHandler(self, self.gui)
        
        # Setup memory
        if not self._setup_memory():
            return False
        
        # Setup stack
        self._setup_stack()
        
        # Create PEB/TEB structures
        self._setup_peb_teb()
        
        # Setup callback return hook region
        self._setup_callback_return_hook()
        
        # Setup import hooks
        self._setup_import_hooks()
        
        # Register hooks
        self._setup_hooks()
        
        return True
    
    def _align_address(self, addr, alignment=0x1000):
        """Align address"""
        return addr & ~(alignment - 1)
    
    def _align_size(self, size, alignment=0x1000):
        """Align size"""
        return (size + alignment - 1) & ~(alignment - 1)
    
    def _map_memory(self, address, size, perms=UC_PROT_ALL):
        """Map memory region"""
        aligned_addr = self._align_address(address)
        aligned_size = self._align_size(size + (address - aligned_addr))
        
        # Check for overlap
        for start, end in self.mapped_regions:
            if aligned_addr < end and aligned_addr + aligned_size > start:
                # Already mapped, skip
                return
        
        try:
            self.uc.mem_map(aligned_addr, aligned_size, perms)
            self.mapped_regions.append((aligned_addr, aligned_addr + aligned_size))
            log.debug(f"Memory mapped: 0x{aligned_addr:08x} - 0x{aligned_addr + aligned_size:08x}")
        except UcError as e:
            log.warning(f"Memory map error: {e}")
    
    def _reserved_regions(self):
        """Address ranges the emulator itself uses (start, end)"""
        return [(0, 0x10000),
                (self.HEAP_BASE, self.HEAP_BASE + self.HEAP_SIZE),
                (self.CALLBACK_RETURN_ADDR, self.API_HOOK_BASE + self.API_HOOK_SIZE),
                (self.STACK_BASE, self.STACK_BASE + self.STACK_SIZE)]

    def _choose_image_base(self, size):
        """Preferred ImageBase if free, else the first free 64K-aligned address"""
        def is_free(base):
            return (base + size <= 0x80000000 and
                    all(base + size <= start or base >= end
                        for start, end in self._reserved_regions()))

        preferred = self.pe_loader.image_base
        if is_free(preferred):
            return preferred
        for base in range(0x00400000, 0x80000000, 0x10000):
            if is_free(base):
                return base
        return None

    def _setup_memory(self):
        """Load PE file into memory. Returns False on failure."""
        log.header("Memory Configuration")
        
        image_size = self._align_size(self.pe_loader.pe.OPTIONAL_HEADER.SizeOfImage)
        image_base = self._choose_image_base(image_size)
        if image_base is None:
            log.error("No free address range for the image")
            return False
        if image_base != self.pe_loader.image_base:
            if not self.pe_loader.has_relocations():
                log.error(f"ImageBase 0x{self.pe_loader.image_base:08x} overlaps emulator "
                          f"memory and the image has no relocations")
                return False
            log.warning(f"ImageBase 0x{self.pe_loader.image_base:08x} overlaps emulator "
                        f"memory, relocating to 0x{image_base:08x}")
            self.pe_loader.rebase(image_base)
        
        # Allocate memory for main image
        self._map_memory(image_base, image_size)
        
        # Write PE header
        header_size = self.pe_loader.pe.OPTIONAL_HEADER.SizeOfHeaders
        pe_data = self.pe_loader.pe.get_memory_mapped_image()
        self.uc.mem_write(image_base, pe_data[:header_size])
        log.info(f"PE Header loaded: 0x{image_base:08x}")
        
        # Load sections
        for section in self.pe_loader.sections:
            va = image_base + section['virtual_address']
            data = section['data']
            
            if len(data) > 0:
                self.uc.mem_write(va, data)
                log.info(f"Section '{section['name']}' loaded: 0x{va:08x}")
        
        # Allocate memory for stack
        self._map_memory(self.STACK_BASE, self.STACK_SIZE)
        log.info(f"Stack allocated: 0x{self.STACK_BASE:08x} - 0x{self.STACK_BASE + self.STACK_SIZE:08x}")
        
        # Allocate memory for heap - larger and aligned
        try:
            self.uc.mem_map(self.HEAP_BASE, self.HEAP_SIZE, UC_PROT_ALL)
            self.mapped_regions.append((self.HEAP_BASE, self.HEAP_BASE + self.HEAP_SIZE))
            log.info(f"Heap allocated: 0x{self.HEAP_BASE:08x} - 0x{self.HEAP_BASE + self.HEAP_SIZE:08x}")
        except UcError as e:
            log.error(f"Heap allocation error: {e}")
            return False
        
        # API hook region
        self._map_memory(self.API_HOOK_BASE, self.API_HOOK_SIZE)
        log.info(f"API Hook region: 0x{self.API_HOOK_BASE:08x}")
        return True
    
    def _setup_stack(self):
        """Configure stack"""
        # Set ESP to middle of stack
        esp = self.STACK_BASE + self.STACK_SIZE - 0x1000
        self.uc.reg_write(UC_X86_REG_ESP, esp)
        self.uc.reg_write(UC_X86_REG_EBP, esp)
        # Returning from the entry point ends the process with EAX as exit code
        self.uc.mem_write(esp, struct.pack('<I', self.PROCESS_EXIT_ADDR))
        
        log.info(f"Stack pointer: ESP = 0x{esp:08x}")
        
        # Allocate memory for command line
        cmdline = self.api_handler.windows_command_line()
        cmdline_bytes = cmdline.encode(ANSI_CODEPAGE, errors='replace') + b'\x00'
        self.cmdline_addr = self.heap_alloc(len(cmdline_bytes))
        self.uc.mem_write(self.cmdline_addr, cmdline_bytes)

        cmdline_wide = cmdline.encode('utf-16-le') + b'\x00\x00'
        self.cmdline_wide_addr = self.heap_alloc(len(cmdline_wide))
        self.uc.mem_write(self.cmdline_wide_addr, cmdline_wide)
    
    def _setup_peb_teb(self):
        """Create PEB and TEB structures"""
        # Memory for TEB
        self.teb_addr = self.heap_alloc(0x1000)
        # Memory for PEB
        self.peb_addr = self.heap_alloc(0x1000)
        
        # TEB structure (simplified)
        # Offset 0x00: SEH chain
        # Offset 0x04: Stack base
        # Offset 0x08: Stack limit
        # Offset 0x18: TEB self pointer
        # Offset 0x30: PEB pointer
        teb_data = b'\x00' * 0x1000
        teb_data = bytearray(teb_data)
        
        # SEH chain end marker, StackBase, StackLimit
        struct.pack_into('<III', teb_data, 0x00, 0xFFFFFFFF,
                         self.STACK_BASE + self.STACK_SIZE, self.STACK_BASE)
        # TEB self pointer (FS:[0x18])
        struct.pack_into('<I', teb_data, 0x18, self.teb_addr)
        # PEB pointer (FS:[0x30])
        struct.pack_into('<I', teb_data, 0x30, self.peb_addr)
        # ProcessId (FS:[0x20])
        struct.pack_into('<I', teb_data, 0x20, 1234)
        # ThreadId (FS:[0x24])
        struct.pack_into('<I', teb_data, 0x24, 5678)
        
        self.uc.mem_write(self.teb_addr, bytes(teb_data))
        
        # PEB structure (simplified)
        # Offset 0x02: BeingDebugged
        # Offset 0x08: ImageBaseAddress
        # Offset 0x0C: Ldr
        peb_data = b'\x00' * 0x1000
        peb_data = bytearray(peb_data)
        
        # ImageBaseAddress
        struct.pack_into('<I', peb_data, 0x08, self.pe_loader.image_base)
        # BeingDebugged = 0
        peb_data[0x02] = 0
        # ProcessHeap: a real (zeroed) block so heap header reads don't fault
        self.process_heap = self.heap_alloc(0x1000)
        struct.pack_into('<I', peb_data, 0x18, self.process_heap)
        # OSMajorVersion, OSMinorVersion, OSBuildNumber, OSPlatformId (matches GetVersion)
        struct.pack_into('<IIHHI', peb_data, 0xA4, 6, 0, 6002, 0, 2)
        
        self.uc.mem_write(self.peb_addr, bytes(peb_data))
        
        # Set FS segment to TEB
        # Create GDT entry
        gdt_addr = self.heap_alloc(0x1000)
        
        # GDT entry format: base, limit, access, flags
        def create_gdt_entry(base, limit, access, flags):
            entry = bytearray(8)
            # Limit (bits 0-15)
            entry[0] = limit & 0xFF
            entry[1] = (limit >> 8) & 0xFF
            # Base (bits 0-15)
            entry[2] = base & 0xFF
            entry[3] = (base >> 8) & 0xFF
            # Base (bits 16-23)
            entry[4] = (base >> 16) & 0xFF
            # Access
            entry[5] = access
            # Limit (bits 16-19) + Flags
            entry[6] = ((limit >> 16) & 0x0F) | (flags << 4)
            # Base (bits 24-31)
            entry[7] = (base >> 24) & 0xFF
            return bytes(entry)
        
        # Null descriptor
        null_entry = b'\x00' * 8
        # Code segment (CS)
        code_entry = create_gdt_entry(0, 0xFFFFF, 0x9B, 0x0C)
        # Data segment (DS, ES, SS)
        data_entry = create_gdt_entry(0, 0xFFFFF, 0x93, 0x0C)
        # FS segment (TEB)
        fs_entry = create_gdt_entry(self.teb_addr, 0xFFF, 0x93, 0x00)
        
        gdt = null_entry + code_entry + data_entry + fs_entry
        self.uc.mem_write(gdt_addr, gdt)
        
        # Set GDTR
        self.uc.reg_write(UC_X86_REG_GDTR, (0, gdt_addr, len(gdt) - 1, 0))
        
        # Set segment registers
        self.uc.reg_write(UC_X86_REG_CS, 0x08)  # Code segment
        self.uc.reg_write(UC_X86_REG_DS, 0x10)  # Data segment
        self.uc.reg_write(UC_X86_REG_ES, 0x10)
        self.uc.reg_write(UC_X86_REG_SS, 0x10)
        self.uc.reg_write(UC_X86_REG_FS, 0x18)  # TEB segment
        self.uc.reg_write(UC_X86_REG_GS, 0x00)
        
        log.info(f"TEB configured: 0x{self.teb_addr:08x}")
        log.info(f"PEB configured: 0x{self.peb_addr:08x}")
    
    def heap_alloc(self, size, alignment=16):
        """Allocate zeroed heap memory, reusing freed blocks. Returns 0 when exhausted."""
        span = self._align_size(max(size, 1), 16)
        free_bin = self.heap_free_bins.get(span) if alignment <= 16 else None
        if free_bin:
            addr = free_bin.pop()
            del self.heap_free_ends[addr + span]
            self.uc.mem_write(addr, b'\x00' * span)
        else:
            addr = self._align_size(self.heap_current, alignment)
            if addr + span > self.HEAP_BASE + self.HEAP_SIZE:
                log.error(f"Heap exhausted: cannot allocate {size} bytes "
                          f"(increase with -m/--memory)")
                return 0
            if addr != self.heap_current:
                # The alignment gap becomes a free block for later small allocations
                self.heap_free_bins.setdefault(addr - self.heap_current, set()).add(self.heap_current)
                self.heap_free_ends[addr] = self.heap_current
            self.heap_current = addr + span
        self.heap_blocks[addr] = size
        return addr

    def heap_free(self, addr):
        """Release a heap_alloc() block. Returns False if addr is not a live block."""
        size = self.heap_blocks.pop(addr, None)
        if size is None:
            return False
        end = addr + self._align_size(max(size, 1), 16)
        if end != self.heap_current:
            self.heap_free_bins.setdefault(end - addr, set()).add(addr)
            self.heap_free_ends[end] = addr
            return True
        # Top block: shrink the bump area, folding in free blocks below it.
        # Memory above heap_current is kept zeroed.
        top = addr
        while top in self.heap_free_ends:
            start = self.heap_free_ends.pop(top)
            self.heap_free_bins[top - start].discard(start)
            top = start
        self.heap_current = top
        self.uc.mem_write(top, b'\x00' * (end - top))
        return True

    def heap_block_size(self, addr):
        """Requested size of a heap_alloc() block, or None if unknown."""
        return self.heap_blocks.get(addr)

    def heap_resize_last(self, addr, new_size):
        """Grow/shrink the most recent block in place. Returns True on success."""
        old_size = self.heap_blocks.get(addr)
        if old_size is None:
            return False
        if addr + self._align_size(max(old_size, 1), 16) != self.heap_current:
            return False
        new_end = addr + self._align_size(max(new_size, 1), 16)
        if new_end > self.HEAP_BASE + self.HEAP_SIZE:
            return False
        if new_end < self.heap_current:
            self.uc.mem_write(new_end, b'\x00' * (self.heap_current - new_end))
        self.heap_current = new_end
        self.heap_blocks[addr] = new_size
        return True
    
    def _setup_import_hooks(self):
        """Setup hooks for import functions"""
        log.header("Setting Up API Hooks")
        
        # Create hook address for each import
        for dll_name, functions in self.pe_loader.imports.items():
            log.info(f"DLL hook: {dll_name}")
            
            for func_info in functions:
                func_name = func_info['name']
                iat_addr = func_info['address']

                # CRT variables (e.g. _iob) are dereferenced, not called:
                # point the IAT entry at real memory instead of a hook stub.
                data_addr = self.api_handler.resolve_data_import(dll_name, func_name)
                if data_addr:
                    self.uc.mem_write(iat_addr, struct.pack('<I', data_addr))
                    log.debug(f"  Data: {func_name} -> 0x{data_addr:08x}")
                    continue
                
                hook_addr = self._create_api_stub(dll_name, func_name)
                if not hook_addr:
                    break
                
                # Write hook address to IAT
                self.uc.mem_write(iat_addr, struct.pack('<I', hook_addr))
                log.debug(f"  Hook: {func_name} -> 0x{hook_addr:08x}")

    def _create_api_stub(self, dll_name, func_name):
        """Write a RET stub that _hook_code intercepts; returns its address (0 if full)

        Some CRT helpers take their arguments in x87 registers; their stub
        starts with native code that spills them to memory before the RET.
        """
        prologue = self.api_handler.native_prologue(func_name)
        entry = self.next_hook_addr
        hook_addr = entry + len(prologue)
        if hook_addr >= self.API_HOOK_BASE + self.API_HOOK_SIZE:
            log.error(f"API stub region full, cannot hook {func_name}")
            return 0
        self.next_hook_addr = (hook_addr + 4) & ~3
        self.uc.mem_write(entry, prologue + b'\xC3')  # RET
        self.api_hooks[hook_addr] = {'dll': dll_name, 'name': func_name}
        return entry

    def get_api_stub(self, dll_name, func_name):
        """Stub address for GetProcAddress, or 0 if the API is not emulated"""
        if not self.api_handler.is_emulated(dll_name, func_name):
            return 0
        key = (dll_name.lower(), func_name)
        if key not in self.dynamic_stubs:
            self.dynamic_stubs[key] = self._create_api_stub(dll_name, func_name)
        return self.dynamic_stubs[key]
    
    def _setup_callback_return_hook(self):
        """Setup callback return hook region"""
        # Allocate special memory region for callback return address
        # When execution reaches this address, we know callback has finished
        try:
            self.uc.mem_map(self.callback_return_addr, 0x1000, UC_PROT_ALL)
            # Write RET instruction (0xC3) - will be hooked
            self.uc.mem_write(self.callback_return_addr, b'\xC3')
            # fld qword ptr [X87_RESULT_ADDR]; ret
            self.uc.mem_write(self.X87_RETURN_STUB,
                              b'\xDD\x05' + struct.pack('<I', self.X87_RESULT_ADDR) + b'\xC3')
            log.debug(f"Callback return hook: 0x{self.callback_return_addr:08x}")
        except UcError as e:
            log.warning(f"Could not setup callback return hook: {e}")
    
    def call_callback(self, callback_addr, args, return_handler=None):
        """
        Call callback function (WndProc, EnumWindowsProc, etc.)
        
        Args:
            callback_addr: Address of callback function
            args: Callback arguments (list)
            return_handler: Function to call when callback finishes (optional)
        
        Returns:
            Callback return value (EAX)
        """
        if callback_addr == 0:
            log.warning("Callback address is 0, skipping call")
            return 0
        
        # Save current state
        saved_esp = self.uc.reg_read(UC_X86_REG_ESP)
        saved_eip = self.uc.reg_read(UC_X86_REG_EIP)
        saved_eax = self.uc.reg_read(UC_X86_REG_EAX)
        saved_ebx = self.uc.reg_read(UC_X86_REG_EBX)
        saved_ecx = self.uc.reg_read(UC_X86_REG_ECX)
        saved_edx = self.uc.reg_read(UC_X86_REG_EDX)
        saved_esi = self.uc.reg_read(UC_X86_REG_ESI)
        saved_edi = self.uc.reg_read(UC_X86_REG_EDI)
        saved_ebp = self.uc.reg_read(UC_X86_REG_EBP)
        
        # Add callback info to stack
        callback_info = {
            'addr': callback_addr,
            'args': args,
            'return_handler': return_handler,
            'saved_state': {
                'esp': saved_esp,
                'eip': saved_eip,
                'eax': saved_eax,
                'ebx': saved_ebx,
                'ecx': saved_ecx,
                'edx': saved_edx,
                'esi': saved_esi,
                'edi': saved_edi,
                'ebp': saved_ebp,
            }
        }
        self.callback_stack.append(callback_info)
        
        # Push arguments to stack (right to left - cdecl/stdcall)
        esp = saved_esp
        
        # Push arguments in reverse order
        for arg in reversed(args):
            esp -= 4
            self.uc.mem_write(esp, struct.pack("<I", arg & 0xFFFFFFFF))
        
        # Push callback_return_addr as return address
        esp -= 4
        self.uc.mem_write(esp, struct.pack("<I", self.callback_return_addr))
        
        # Update ESP
        self.uc.reg_write(UC_X86_REG_ESP, esp)
        
        log.debug(f"Calling callback: 0x{callback_addr:08x} args={[hex(a) for a in args]}")
        
        # Run callback. Unicorn's instruction budget is shared with the outer
        # emu_start (nested runs clobber it), so pass 0 (unlimited) here and
        # let the Python-side max_instructions check in _hook_code limit
        # everything uniformly.
        try:
            self.uc.emu_start(callback_addr, self.callback_return_addr, 0, 0)
        except UcError as e:
            log.error(f"Callback error: {e}")
        
        # Get return value
        result = self.uc.reg_read(UC_X86_REG_EAX)
        
        # Pop callback info from stack
        if self.callback_stack:
            completed_callback = self.callback_stack.pop()
            
            # Call return handler if exists
            if completed_callback.get('return_handler'):
                completed_callback['return_handler'](result)
        
        # Restore state (except EAX - return value)
        self.uc.reg_write(UC_X86_REG_ESP, saved_esp)
        self.uc.reg_write(UC_X86_REG_EIP, saved_eip)
        self.uc.reg_write(UC_X86_REG_EBX, saved_ebx)
        self.uc.reg_write(UC_X86_REG_ECX, saved_ecx)
        self.uc.reg_write(UC_X86_REG_EDX, saved_edx)
        self.uc.reg_write(UC_X86_REG_ESI, saved_esi)
        self.uc.reg_write(UC_X86_REG_EDI, saved_edi)
        self.uc.reg_write(UC_X86_REG_EBP, saved_ebp)
        
        log.debug(f"Callback completed: 0x{callback_addr:08x} -> 0x{result:08x}")
        
        return result
    
    def call_wndproc(self, wndproc_addr, hwnd, msg, wParam, lParam):
        """
        Call WndProc callback
        
        Args:
            wndproc_addr: Address of WndProc function
            hwnd: Window handle
            msg: Message code (WM_PAINT, etc.)
            wParam: wParam value
            lParam: lParam value
        
        Returns:
            WndProc return value
        """
        return self.call_callback(wndproc_addr, [hwnd, msg, wParam, lParam])
    
    def _setup_hooks(self):
        """Register Unicorn hooks"""
        # Per-instruction hooks only on API stubs and the callback return
        # address; hooking every instruction makes emulation very slow.
        self.uc.hook_add(UC_HOOK_CODE, self._hook_code,
                         begin=self.API_HOOK_BASE,
                         end=self.API_HOOK_BASE + self.API_HOOK_SIZE - 1)
        self.uc.hook_add(UC_HOOK_CODE, self._hook_code,
                         begin=self.callback_return_addr,
                         end=self.callback_return_addr)

        # Memory access error hook
        self.uc.hook_add(UC_HOOK_MEM_UNMAPPED, self._hook_mem_invalid)
        
        # Interrupt hook
        self.uc.hook_add(UC_HOOK_INTR, self._hook_interrupt)

    def _hook_block(self, uc, address, size, user_data):
        """Hook called at the start of each basic block"""
        key = (address, size)
        count = self.block_insn_counts.get(key)
        if count is None or self.instruction_count < 50:
            insns = list(self.cs.disasm_lite(bytes(uc.mem_read(address, size)), address))
            count = max(len(insns), 1)
            self.block_insn_counts[key] = count
            for insn_addr, _, mnemonic, op_str in insns[:max(0, 50 - self.instruction_count)]:
                log.debug(f"0x{insn_addr:08x}: {mnemonic:8s} {op_str}")
        self.instruction_count += count

        # Limit check (max_instructions <= 0 means unlimited)
        if self.max_instructions > 0 and self.instruction_count > self.max_instructions:
            log.warning(f"Maximum instruction limit reached ({self.max_instructions})! Stopping emulation...")
            self.stop_emulation = True

        if self.stop_emulation:
            uc.emu_stop()
    
    def _hook_code(self, uc, address, size, user_data):
        """Hook for API stubs and the callback return address"""
        if self.stop_emulation or address == self.callback_return_addr:
            uc.emu_stop()
            return
        
        hook_info = self.api_hooks.get(address)
        if hook_info:
            self._handle_api_call(hook_info)
            if self.stop_emulation:
                uc.emu_stop()
    
    def _handle_api_call(self, hook_info):
        """Handle API call"""
        dll_name = hook_info['dll'].lower()
        func_name = hook_info['name']
        
        log.debug(f"API Call: {dll_name}!{func_name}")
        
        # Read arguments from stack
        esp = self.uc.reg_read(UC_X86_REG_ESP)
        
        # Return address
        ret_addr = struct.unpack('<I', self.uc.mem_read(esp, 4))[0]
        
        # Up to 32 argument slots (varargs functions such as printf may use
        # many); slots beyond the top of the stack read as zero.
        try:
            args = list(struct.unpack('<32I', self.uc.mem_read(esp + 4, 128)))
        except UcError:
            args = []
            for i in range(32):
                try:
                    args.append(struct.unpack('<I', self.uc.mem_read(esp + 4 + i * 4, 4))[0])
                except UcError:
                    args.append(0)
        
        # Find and call handler
        handler = self.api_handler.get_api_handler(func_name)
        self.api_call_esp = esp
        
        if handler:
            try:
                result = handler(args)
            except Exception as e:
                log.error(f"Emulator error in {dll_name}!{func_name}: "
                          f"{type(e).__name__}: {e}")
                if DebugLogger.level <= DebugLogger.DEBUG:
                    import traceback
                    traceback.print_exc()
                result = 0
        else:
            log.warning(f"Unemulated API: {func_name}")
            result = 0

        if isinstance(result, ApiJump):
            self.uc.reg_write(UC_X86_REG_EAX, result.eax & 0xFFFFFFFF)
            self.uc.reg_write(UC_X86_REG_ESP, result.esp)
            self.uc.reg_write(UC_X86_REG_EIP, result.eip)
            return

        x87_result = isinstance(result, X87Result)
        if x87_result:
            self.uc.mem_write(self.X87_RESULT_ADDR, struct.pack('<d', result.value))
            result = 0
        elif isinstance(result, QWordResult):
            self.uc.reg_write(UC_X86_REG_EDX, result.value >> 32)
            result = result.value
        
        # Write result to EAX
        self.uc.reg_write(UC_X86_REG_EAX, result & 0xFFFFFFFF)
        
        # Return to caller. stdcall APIs (kernel32, user32, gdi32, ...) pop
        # their own arguments; cdecl CRT functions leave them to the caller.
        cleanup = self.api_handler.stack_cleanup_bytes(dll_name, func_name)
        if cleanup is None:
            # Unknown stdcall argument count: continuing would corrupt ESP
            log.error(f"Unemulated stdcall API {dll_name}!{func_name}: "
                      f"argument count unknown, stopping emulation")
            self.crashed = True
            self.stop_emulation = True
            cleanup = 0
        if x87_result and cleanup == 0:
            # Leave the return address on the stack: the stub loads ST(0) and RETs
            self.uc.reg_write(UC_X86_REG_EIP, self.X87_RETURN_STUB)
            self.uc.reg_write(UC_X86_REG_ESP, esp)
            return
        self.uc.reg_write(UC_X86_REG_EIP, ret_addr)
        self.uc.reg_write(UC_X86_REG_ESP, esp + 4 + cleanup)
    
    def _hook_mem_invalid(self, uc, access, address, size, value, user_data):
        """Invalid memory access hook"""
        access_types = {
            UC_MEM_READ_UNMAPPED: "READ",
            UC_MEM_WRITE_UNMAPPED: "WRITE", 
            UC_MEM_FETCH_UNMAPPED: "FETCH",
        }
        access_type = access_types.get(access, f"Unknown({access})")
        eip = uc.reg_read(UC_X86_REG_EIP)

        # Like Windows, an access to unmapped memory is fatal (there is no
        # SEH support to hand it to the program). Mapping memory on demand
        # would silently turn NULL-pointer bugs into reads of zeros.
        log.error(f"Access violation: {access_type} @ 0x{address:08x}, "
                  f"size={size}, EIP=0x{eip:08x}")
        self.crashed = True
        self.stop_emulation = True
        return False
    
    def _hook_interrupt(self, uc, intno, user_data):
        """Interrupt hook"""
        log.debug(f"Interrupt: {intno}")
        
        if intno == 0x80:
            # Linux syscall (not used in Windows but catch anyway)
            log.warning("Linux system call detected (INT 0x80)")
        elif intno == 0x2E:
            # Windows syscall
            eax = uc.reg_read(UC_X86_REG_EAX)
            log.warning(f"Windows system call: EAX=0x{eax:08x}")
    
    def run(self, max_instructions=None):
        """Start emulation"""
        if max_instructions is not None:
            self.max_instructions = max_instructions

        # Instruction counting costs a Python call per basic block: only for the
        # instruction limit and the verbose start-up disassembly
        count_instructions = (self.max_instructions > 0 or
                              DebugLogger.level <= DebugLogger.DEBUG)
        if count_instructions:
            self.uc.hook_add(UC_HOOK_BLOCK, self._hook_block)

        log.header("Starting Emulation")

        entry_point = self.pe_loader.image_base + self.pe_loader.entry_point
        log.info(f"Entry point: 0x{entry_point:08x}")
        log.info(f"Maximum instructions: "
                 f"{self.max_instructions if self.max_instructions > 0 else 'unlimited'}")

        # Let the GUI route window messages to this process
        if self.gui:
            self.gui.register_process(self.api_handler)
        # Like Windows, only console (CUI) programs start with a console
        if self.pe_loader.is_console_program():
            self.api_handler.alloc_console()

        try:
            # The instruction limit is enforced in _hook_code. Passing a count
            # to Unicorn would break nested emu_start calls (callbacks,
            # _initterm, atexit) and can crash the process.
            self.uc.emu_start(entry_point, self.PROCESS_EXIT_ADDR, 0, 0)

            if (not self.crashed and
                    self.uc.reg_read(UC_X86_REG_EIP) == self.PROCESS_EXIT_ADDR):
                self.api_handler._set_exit_code(self.uc.reg_read(UC_X86_REG_EAX))

        except UcError as e:
            eip = self.uc.reg_read(UC_X86_REG_EIP)
            esp = self.uc.reg_read(UC_X86_REG_ESP)
            log.error(f"Emulation error: {e}")
            log.error(f"EIP: 0x{eip:08x}, ESP: 0x{esp:08x}")
            self.crashed = True
        finally:
            # However the emulation ended (ExitProcess, error, instruction
            # limit), the process is gone and can't consume messages anymore
            if self.api_handler:
                self.api_handler.process_exited = True
                self.api_handler.flush_std_streams()
                if self.gui:
                    self.gui.unregister_process(self.api_handler)

        log.header("Emulation Completed")
        if count_instructions:
            log.info(f"Total instruction count: {self.instruction_count}")
        
        # Show register state
        self._print_registers()
    
    def _print_registers(self):
        """Print register values"""
        log.header("Register State")
        
        regs = [
            ("EAX", UC_X86_REG_EAX), ("EBX", UC_X86_REG_EBX),
            ("ECX", UC_X86_REG_ECX), ("EDX", UC_X86_REG_EDX),
            ("ESI", UC_X86_REG_ESI), ("EDI", UC_X86_REG_EDI),
            ("EBP", UC_X86_REG_EBP), ("ESP", UC_X86_REG_ESP),
            ("EIP", UC_X86_REG_EIP), ("EFLAGS", UC_X86_REG_EFLAGS),
        ]
        
        for i in range(0, len(regs), 2):
            name1, reg1 = regs[i]
            val1 = self.uc.reg_read(reg1)
            
            if i + 1 < len(regs):
                name2, reg2 = regs[i + 1]
                val2 = self.uc.reg_read(reg2)
                log.info(f"{name1}: 0x{val1:08x}    {name2}: 0x{val2:08x}")
            else:
                log.info(f"{name1}: 0x{val1:08x}")
    
    def disassemble(self, address, count=10):
        """Disassemble starting from specified address"""
        log.header(f"Disassembly @ 0x{address:08x}")
        
        try:
            code = self.uc.mem_read(address, count * 15)  # Each instruction max 15 bytes
            
            disasm_count = 0
            for insn in self.cs.disasm(bytes(code), address):
                bytes_str = ' '.join(f'{b:02x}' for b in insn.bytes)
                log.info(f"0x{insn.address:08x}: {bytes_str:24s} {insn.mnemonic:8s} {insn.op_str}")
                disasm_count += 1
                if disasm_count >= count:
                    break
        except Exception as e:
            log.error(f"Disassembly error: {e}!")


def main():
    """Main function"""
    import argparse
    parser = argparse.ArgumentParser(
        description="Windows 32-bit EXE Emulator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="EXE files are searched in c_drive/ (C:\\) and then in c_drive/Windows/Examples/ "
               "(C:\\Windows\\Examples).\nExample: python3 winexe32emu.py gdi_example.exe"
    )
    parser.add_argument("exe", nargs="?",
                        help="PE file to run: a name in C:\\ or C:\\Windows\\Examples, or a "
                             "Windows path inside c_drive/; optional with the GUI, "
                             "programs can also be started from the Start menu")
    parser.add_argument("-n", "--max-instructions", type=int, default=0,
                        help="Maximum instructions to execute "
                             "(default: 0 = unlimited)")
    parser.add_argument("-m", "--memory", type=int, default=128,
                        help="Heap memory amount in MiB (default: 128)")
    parser.add_argument("--no-gui", action="store_true",
                        help="Run without GUI")
    parser.add_argument("--codepage", default="utf-8",
                        help="ANSI code page for 'A' APIs and CRT strings "
                             "(default: utf-8; e.g. cp1254, cp1252)")
    parser.add_argument("--clean", action="store_true",
                        help="Only delete c_drive/ (scripts/remove_c_drive_environment.sh "
                             "--all, asks for confirmation) and exit")
    parser.add_argument("--no-examples", action="store_true",
                        help="Don't compile the examples (compile_examples.sh) and "
                             "don't show the Examples submenu in the Start menu")
    parser.add_argument("--no-create-environment", "--no_create_environment",
                        action="store_true",
                        help="Don't run create_c_drive_environment.sh at startup")
    parser.add_argument("--logfile", metavar="FILE",
                        help="Also write the console output to FILE (without colors)")
    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument("-v", "--verbose", action="store_true",
                           help="Show debug output (every API call, disassembly)")
    verbosity.add_argument("-q", "--quiet", action="store_true",
                           help="Show only program output, warnings and errors")

    args = parser.parse_args()

    if args.logfile:
        try:
            logfile = open(args.logfile, 'w', encoding='utf-8', errors='replace',
                           buffering=1)
        except OSError as e:
            log.error(f"Cannot open log file {args.logfile}: {e}")
            sys.exit(1)
        lock = threading.Lock()
        sys.stdout = LogFileTee(sys.stdout, logfile, lock)
        sys.stderr = LogFileTee(sys.stderr, logfile, lock)

    print(f"{Fore.CYAN}{Style.BRIGHT}╔══════════════════════════════════════════════════════════╗")
    print(f"{Fore.CYAN}{Style.BRIGHT}║                                                          ║")
    print(f"{Fore.CYAN}{Style.BRIGHT}║{f'Windows 32-bit EXE Emulator v{WINEXE32EMU_VERSION}':^58}║")
    print(f"{Fore.CYAN}{Style.BRIGHT}║                                                          ║")
    print(f"{Fore.CYAN}{Style.BRIGHT}╚══════════════════════════════════════════════════════════╝")
    print(f"{Style.RESET_ALL}")

    if args.verbose:
        DebugLogger.level = DebugLogger.DEBUG
    elif args.quiet:
        DebugLogger.level = DebugLogger.WARNING

    global ANSI_CODEPAGE
    try:
        ANSI_CODEPAGE = codecs.lookup(args.codepage).name
    except LookupError:
        log.error(f"Unknown code page: {args.codepage}")
        sys.exit(1)

    if args.clean:
        # Interactive: the script asks before deleting everything in c_drive/
        try:
            result = subprocess.run(['sh', REMOVE_C_DRIVE_SCRIPT, '--all'], cwd=SCRIPT_DIR)
        except OSError as e:
            log.error(f"Cannot run {REMOVE_C_DRIVE_SCRIPT}: {e}")
            sys.exit(1)
        sys.exit(result.returncode)

    use_gui = not args.no_gui

    if not args.no_create_environment:
        run_setup_script(CREATE_C_DRIVE_SCRIPT, "Creating C Drive Environment")
    if not args.no_examples:
        run_setup_script(COMPILE_EXAMPLES_SCRIPT, "Compiling Examples")
    create_environment_folders()

    if args.exe is None and not (use_gui and PYGAME_AVAILABLE):
        log.error("An EXE name is required when the GUI is not available")
        sys.exit(1)
    if args.exe is not None and find_program(args.exe) is None:
        log.error(f"File not found in emulation C drive: {args.exe}")
        sys.exit(1)

    max_instr = args.max_instructions
    heap_size_mib = args.memory
    # The heap must end below the callback/API stub/stack regions
    max_heap_mib = (CPUEmulator.CALLBACK_RETURN_ADDR - CPUEmulator.HEAP_BASE) // (1024 * 1024)
    if not 1 <= heap_size_mib <= max_heap_mib:
        log.error(f"Heap size must be between 1 and {max_heap_mib} MiB")
        sys.exit(1)

    # Update heap size
    CPUEmulator.HEAP_SIZE = heap_size_mib * 1024 * 1024
    log.info(f"Heap size: {heap_size_mib} MiB ({CPUEmulator.HEAP_SIZE} bytes)")

    # Start GUI (optional)
    gui = None
    if use_gui and PYGAME_AVAILABLE:
        log.header("Starting Pygame GUI")
        gui = PseudoWindowsGUI(1024, 768)
        gui.show_examples = not args.no_examples
        if gui.start():
            log.success("Pygame GUI window opened!")
        else:
            log.warning("Failed to start GUI, continuing without GUI...")
            gui = None
    elif use_gui and not PYGAME_AVAILABLE:
        log.warning("Pygame not installed, continuing without GUI...")

    # Started programs: [(CPUEmulator, emulation thread)]; they run side by side
    programs = []

    def load_program(name, command_line=None, current_directory=None):
        """Load an EXE from the emulated C drive and emulate it in a new thread.
        Returns the CPUEmulator, or None on failure."""
        exe_path = find_program(name)
        if exe_path is None:
            log.error(f"File not found in emulation C drive: {name}")
            return None
        log.info(f"Loading EXE from emulation C drive: {exe_path}")
        loader = PELoader(exe_path)
        if not loader.load():
            log.error("Failed to load PE file!")
            return None
        loader.print_summary()

        emulator = CPUEmulator(loader, gui)
        emulator.command_line = command_line
        if not emulator.initialize():
            log.error("Failed to initialize CPU emulator!")
            return None
        if current_directory:
            emulator.api_handler.current_directory = current_directory
        emulator.disassemble(loader.image_base + loader.entry_point, 20)

        def run_emulation():
            try:
                emulator.run(max_instr)
            except Exception as e:
                log.error(f"Emulation error: {e}")
                emulator.crashed = True
            finally:
                # Sounds do not outlive their process
                SoundPlayer.stop_owned_by(emulator.api_handler)
                log.success("Emulation completed!")

        # Separate thread so the GUI stays responsive
        thread = threading.Thread(target=run_emulation, daemon=True)
        emulator.thread = thread
        programs.append((emulator, thread))
        thread.start()
        return emulator

    # CreateProcessA starts child programs the same way
    WinAPIHandler.process_starter = staticmethod(load_program)

    def launch(name):
        """Start menu: run the EXE at Windows path name next to the running programs"""
        # Loading takes a while: keep it off the GUI thread
        threading.Thread(target=load_program, args=(name,), daemon=True).start()

    if gui:
        gui.launcher = launch
        log.info("GUI window is open, close the window to exit!")

    if args.exe is not None and not load_program(args.exe):
        if gui:
            gui.stop()
        sys.exit(1)
    
    # Wait while GUI is open
    try:
        if gui:
            while gui.running:
                time.sleep(0.1)
            gui.stop()
        else:
            # If no GUI, wait for emulation to finish
            programs[0][1].join()
    except KeyboardInterrupt:
        log.warning("Stopped by user (Ctrl+C)!")
        if gui:
            gui.running = False
            gui.stop()
        sys.exit(130)

    # Exit code of the program named on the command line (Start menu ones don't count)
    if args.exe is None:
        return
    emulator, emu_thread = programs[0]

    # Propagate the guest's exit code (like a real process would)
    if emu_thread.is_alive():
        return
    if emulator.crashed:
        sys.exit(1)
    exit_code = emulator.api_handler.exit_code if emulator.api_handler else None
    if exit_code:
        sys.exit(exit_code & 0xFF)


if __name__ == "__main__":
    main()
