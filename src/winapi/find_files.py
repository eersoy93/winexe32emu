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

"""WinAPIHandler mixin: FindFirstFile / FindNextFile, computer and user names, tokens, system info"""

import sys
import os
import re
import struct
import time

from unicorn import *

from .. import config
from ..config import USER_NAME
from ..guest import QWordResult
from ..logger import log


class FindFilesMixin:
    """FindFirstFile / FindNextFile, computer and user names, tokens, system info"""

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
        read_only = 0x01 if self._host_read_only(path) else 0  # FILE_ATTRIBUTE_READONLY
        if os.path.isdir(path):
            return (name, 0x10 | read_only, 0, st.st_mtime)  # FILE_ATTRIBUTE_DIRECTORY
        return (name, read_only or 0x80, st.st_size, st.st_mtime)  # FILE_ATTRIBUTE_NORMAL

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
            raw = name.encode(config.ANSI_CODEPAGE, errors='replace')[:name_size - 1]
        names = raw.ljust(name_size, b'\x00') + b'\x00' * alt_size
        self.emu.uc.mem_write(address, header + names)

    def FindFirstFileA(self, args, wide=False):
        """FindFirstFileA/W emulation - lists a directory of a drive (drives/)"""
        INVALID_HANDLE_VALUE = 0xFFFFFFFF
        spec = self._read_text(args[0], wide)
        lpFindFileData = args[1]
        log.debug(f"FindFirstFile{'W' if wide else 'A'}(\"{spec}\")")

        full = self.full_windows_path(spec)
        if full is None or len(full) == 3:  # A drive root itself ("C:\\")
            self._last_error = 5 if full is None else 2
            return INVALID_HANDLE_VALUE
        folder, _, pattern = full.rpartition('\\')
        folder_path = self.resolve_drive_path(folder + '\\')
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
        if len(folder) > 2:  # Not a drive root ("C:")
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
            data = text.encode(config.ANSI_CODEPAGE, errors='replace') + b'\x00'
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
    USER_NAME = USER_NAME

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

    # Privilege names -> LUIDs (LookupPrivilegeValue)
    PRIVILEGE_LUIDS = {
        'secreatetokenprivilege': 2, 'seassignprimarytokenprivilege': 3,
        'selockmemoryprivilege': 4, 'seincreasequotaprivilege': 5,
        'semachineaccountprivilege': 6, 'setcbprivilege': 7, 'sesecurityprivilege': 8,
        'setakeownershipprivilege': 9, 'seloaddriverprivilege': 10,
        'sesystemprofileprivilege': 11, 'sesystemtimeprivilege': 12,
        'seprofilesingleprocessprivilege': 13, 'seincreasebasepriorityprivilege': 14,
        'secreatepagefileprivilege': 15, 'secreatepermanentprivilege': 16,
        'sebackupprivilege': 17, 'serestoreprivilege': 18, 'seshutdownprivilege': 19,
        'sedebugprivilege': 20, 'seauditprivilege': 21,
        'sesystemenvironmentprivilege': 22, 'sechangenotifyprivilege': 23,
        'seremoteshutdownprivilege': 24, 'seundockprivilege': 25,
    }

    def OpenProcessToken(self, args):
        """OpenProcessToken emulation - an access token of the (administrator) user"""
        ProcessHandle, DesiredAccess, TokenHandle = args[0], args[1], args[2]
        log.debug(f"OpenProcessToken(0x{ProcessHandle:x}, 0x{DesiredAccess:x})")
        handle = self.get_next_handle()
        self.handles[handle] = {'type': 'token', 'access': DesiredAccess}
        if not self._mem_write(TokenHandle, struct.pack('<I', handle)):
            del self.handles[handle]
            self._last_error = 998  # ERROR_NOACCESS
            return 0
        return 1

    def LookupPrivilegeValueA(self, args, wide=False):
        """LookupPrivilegeValueA/W emulation - LUID of a privilege name"""
        name = self._read_text(args[1], wide) if args[1] else ''
        luid = self.PRIVILEGE_LUIDS.get(name.lower())
        log.debug(f"LookupPrivilegeValue(\"{name}\") -> {luid}")
        if luid is None:
            self._last_error = 1313  # ERROR_NO_SUCH_PRIVILEGE
            return 0
        if not self._mem_write(args[2], struct.pack('<Ii', luid, 0)):
            self._last_error = 998  # ERROR_NOACCESS
            return 0
        return 1

    def LookupPrivilegeValueW(self, args):
        return self.LookupPrivilegeValueA(args, wide=True)

    def AdjustTokenPrivileges(self, args):
        """AdjustTokenPrivileges emulation - the user holds every privilege"""
        TokenHandle, _, _, BufferLength, PreviousState, ReturnLength = args[:6]
        info = self.handles.get(TokenHandle)
        if not info or info.get('type') != 'token':
            self._last_error = 6  # ERROR_INVALID_HANDLE
            return 0
        if PreviousState and BufferLength >= 4:
            self._mem_write(PreviousState, struct.pack('<I', 0))  # PrivilegeCount
        if ReturnLength:
            self._mem_write(ReturnLength, struct.pack('<I', 4))
        # Callers check GetLastError() for ERROR_NOT_ALL_ASSIGNED
        self._last_error = 0
        return 1

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

    def _memory_status(self):
        """(total, available) "physical" memory: the emulated heap and the
        budget of the big VirtualAlloc regions"""
        total = self.emu.HEAP_SIZE + self.BIG_REGION_BUDGET
        avail = max(0, self.emu.HEAP_BASE + self.emu.HEAP_SIZE - self.emu.heap_current)
        avail += max(0, self.BIG_REGION_BUDGET - self._big_region_usage())
        return total, avail

    def GlobalMemoryStatus(self, args):
        """GlobalMemoryStatus emulation - physical memory is the emulated heap
        plus the room for big VirtualAlloc blocks"""
        lpBuffer = args[0]
        total, avail = self._memory_status()
        load = 100 - avail * 100 // total if total else 0
        log.debug(f"GlobalMemoryStatus() -> {avail}/{total} bytes free")
        data = struct.pack('<8I', 32, load, total, avail, total, avail,
                           0x7FFE0000, 0x7FFE0000 - (total - avail))
        try:
            self.emu.uc.mem_write(lpBuffer, data)
        except UcError:
            pass
        return 0

    def GlobalMemoryStatusEx(self, args):
        """GlobalMemoryStatusEx emulation (MEMORYSTATUSEX)"""
        total, avail = self._memory_status()
        load = 100 - avail * 100 // total if total else 0
        data = struct.pack('<II7Q', 64, load, total, avail, total, avail, 0x7FFE0000,
                           0x7FFE0000 - (total - avail), 0)
        return 1 if self._mem_write(args[0], data) else 0

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
        if config.ANSI_CODEPAGE.replace('_', '-') == 'utf-8':
            return 65001
        match = re.fullmatch(r'cp(\d+)', config.ANSI_CODEPAGE)
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
    
    def ReadConsoleA(self, args, wide=False):
        """ReadConsoleA/W emulation - Read user input from console"""
        hConsoleInput = args[0]
        lpBuffer = args[1]
        nNumberOfCharsToRead = args[2]
        lpNumberOfCharsRead = args[3]
        # pInputControl = args[4]  # optional, usually NULL

        log.debug(f"ReadConsole{'W' if wide else 'A'}(0x{hConsoleInput:x}, "
                  f"max {nNumberOfCharsToRead} chars)")

        if self.gui:
            if self.console is None:
                self._last_error = 6  # ERROR_INVALID_HANDLE: no console
                return 0
            user_input = self.console_read_line()
            if user_input is None:
                user_input = ""
            text = user_input + "\r\n"
            data = None if wide else text.encode(config.ANSI_CODEPAGE, errors='replace')
        else:
            try:
                line = sys.stdin.buffer.readline()
            except (OSError, ValueError):
                line = b""
            if line.endswith(b"\n") and not line.endswith(b"\r\n"):
                line = line[:-1] + b"\r\n"
            data = line
            if wide:
                text = line.decode(sys.stdin.encoding or 'utf-8', errors='replace')

        if wide:
            # Wide console reads count UTF-16 code units
            units = self._text_units(text, True)[:nNumberOfCharsToRead]
            if units:
                self._write_units(lpBuffer, units, True, terminate=False)
            count = len(units)
        else:
            # ANSI console reads count bytes, not Unicode characters
            data = data[:nNumberOfCharsToRead]
            if data:
                self.emu.uc.mem_write(lpBuffer, data)
            count = len(data)
        if lpNumberOfCharsRead != 0:
            self.emu.uc.mem_write(lpNumberOfCharsRead, struct.pack('<I', count))
        log.debug(f"ReadConsole: {count} chars")
        return 1

    def ReadConsoleW(self, args):
        return self.ReadConsoleA(args, wide=True)

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
