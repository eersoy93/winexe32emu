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

"""WinAPIHandler mixin: Drives and volumes (only C:), file attributes and copies, time conversions"""

import os
import shutil
import struct
import mmap
import ctypes
import time
import datetime
import unicodedata

from unicorn import *

from .. import config, winapi
from ..config import C_DRIVE_PATH
from ..logger import log
from ..paths import strip_win32_path_prefix
from ..sound import SoundPlayer


class DrivesTimeMixin:
    """Drives and volumes (only C:), file attributes and copies, time conversions"""

    # ---------- Drives and volumes (only C: exists) ----------

    volume_label = ''

    def _drive_root_ok(self, address, wide=False):
        """True if a root path argument (NULL: current drive) names drive C:"""
        if not address:
            return True
        root = strip_win32_path_prefix(self._read_text(address, wide))
        return root is not None and not (len(root) >= 2 and root[1] == ':'
                                         and root[0].upper() != 'C')

    def GetLogicalDriveStringsA(self, args, wide=False):
        """GetLogicalDriveStringsA/W emulation - only C:\\"""
        size, buffer = args[0], args[1]
        data = "C:\\\x00\x00"
        if size < len(data) or not buffer:
            return len(data)
        self._mem_write(buffer, data.encode('utf-16-le' if wide else 'ascii'))
        return len(data) - 1

    def GetLogicalDriveStringsW(self, args):
        return self.GetLogicalDriveStringsA(args, wide=True)

    def GetDriveTypeW(self, args):
        return 3 if self._drive_root_ok(args[0], True) else 1

    def GetVolumeInformationW(self, args):
        """GetVolumeInformationW emulation - a FAT32 volume"""
        if not self._drive_root_ok(args[0], True):
            self._last_error = 3  # ERROR_PATH_NOT_FOUND
            return 0
        (lpName, nNameSize, lpSerial, lpMaxComponent, lpFlags,
         lpFsName, nFsNameSize) = args[1:8]
        for buf, size, text in ((lpName, nNameSize, winapi.WinAPIHandler.volume_label),
                                (lpFsName, nFsNameSize, 'FAT32')):
            if buf:
                if size <= len(text):
                    self._last_error = 24  # ERROR_BAD_LENGTH
                    return 0
                self._write_text(buf, text, True)
        for ptr, value in ((lpSerial, 0x1E3A5C07), (lpMaxComponent, 255),
                           (lpFlags, 0x6)):  # CASE_PRESERVED_NAMES | UNICODE_ON_DISK
            if ptr:
                self._mem_write(ptr, struct.pack('<I', value))
        return 1

    def GetDiskFreeSpaceW(self, args):
        """GetDiskFreeSpaceW emulation"""
        if not self._drive_root_ok(args[0], True):
            self._last_error = 3  # ERROR_PATH_NOT_FOUND
            return 0
        usage = shutil.disk_usage(C_DRIVE_PATH)
        sectors, sector_size = 8, 512
        cluster = sectors * sector_size
        values = (sectors, sector_size, min(usage.free // cluster, 0xFFFFFFFF),
                  min(usage.total // cluster, 0xFFFFFFFF))
        for ptr, value in zip(args[1:5], values):
            if ptr:
                self._mem_write(ptr, struct.pack('<I', value))
        return 1

    def GetDiskFreeSpaceExA(self, args, wide=False):
        """GetDiskFreeSpaceExA/W emulation - space of the host disk holding c_drive/"""
        if args[0]:
            path = self.resolve_c_drive_path(self._read_text(args[0], wide))
            if path is None or not os.path.exists(path):
                self._last_error = 3  # ERROR_PATH_NOT_FOUND
                return 0
        usage = shutil.disk_usage(C_DRIVE_PATH)
        for ptr, value in zip(args[1:4], (usage.free, usage.total, usage.free)):
            if ptr:
                self._mem_write(ptr, struct.pack('<Q', value))
        return 1

    def GetDiskFreeSpaceExW(self, args):
        return self.GetDiskFreeSpaceExA(args, wide=True)

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
        for buf, size, text in ((lpName, nNameSize, winapi.WinAPIHandler.volume_label),
                                (lpFsName, nFsNameSize, 'FAT32')):
            if buf:
                data = text.encode(config.ANSI_CODEPAGE, errors='replace')
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
        winapi.WinAPIHandler.volume_label = label[:11].upper()
        return 1

    def SetFileAttributesA(self, args, wide=False):
        """SetFileAttributesA/W emulation - only the read-only flag maps to the host"""
        filename = self._read_text(args[0], wide)
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

    def SetFileAttributesW(self, args):
        return self.SetFileAttributesA(args, wide=True)

    def GetFileInformationByHandle(self, args):
        """GetFileInformationByHandle emulation (BY_HANDLE_FILE_INFORMATION)"""
        info = self.handles.get(args[0])
        if not info or info.get('type') != 'file' or not info.get('path'):
            self._last_error = 6  # ERROR_INVALID_HANDLE
            return 0
        try:
            if info.get('fp'):
                info['fp'].flush()
            st = os.stat(info['path'])
        except OSError:
            self._last_error = 5
            return 0
        attributes = 0x10 if os.path.isdir(info['path']) else 0x20  # DIRECTORY / ARCHIVE
        if not os.access(info['path'], os.W_OK):
            attributes |= 0x1  # READONLY
        size = 0 if attributes & 0x10 else st.st_size
        data = struct.pack('<I3QIIIIII', attributes, self._filetime(st.st_ctime),
                           self._filetime(st.st_atime), self._filetime(st.st_mtime),
                           0x1E3A5C07, size >> 32, size & 0xFFFFFFFF, st.st_nlink,
                           (st.st_ino >> 32) & 0xFFFFFFFF, st.st_ino & 0xFFFFFFFF)
        return 1 if self._mem_write(args[1], data) else 0

    def GetCompressedFileSizeA(self, args, wide=False):
        """GetCompressedFileSizeA/W emulation - the file size"""
        path = self.resolve_c_drive_path(self._read_text(args[0], wide))
        if path is None or not os.path.isfile(path):
            self._last_error = 2  # ERROR_FILE_NOT_FOUND
            return 0xFFFFFFFF
        size = os.path.getsize(path)
        if args[1]:
            self._mem_write(args[1], struct.pack('<I', size >> 32))
        self._last_error = 0
        return size & 0xFFFFFFFF

    def GetCompressedFileSizeW(self, args):
        return self.GetCompressedFileSizeA(args, wide=True)

    def CopyFileExW(self, args):
        """CopyFileExW emulation (no progress callbacks)"""
        fail_if_exists = 1 if args[5] & 0x1 else 0  # COPY_FILE_FAIL_IF_EXISTS
        return self.CopyFileA([args[0], args[1], fail_if_exists], wide=True)

    def MoveFileWithProgressW(self, args):
        """MoveFileWithProgressW emulation (no progress callbacks)"""
        return self.MoveFileExA([args[0], args[1], args[4]], wide=True)

    def CreateHardLinkA(self, args, wide=False):
        """CreateHardLinkA/W emulation (sandboxed)"""
        new = self.resolve_c_drive_path(self._read_text(args[0], wide))
        existing = self.resolve_c_drive_path(self._read_text(args[1], wide))
        if new is None or existing is None:
            self._last_error = 5  # ERROR_ACCESS_DENIED
            return 0
        try:
            os.link(existing, new)
        except FileExistsError:
            self._last_error = 183  # ERROR_ALREADY_EXISTS
            return 0
        except OSError:
            self._last_error = 2
            return 0
        return 1

    def CreateHardLinkW(self, args):
        return self.CreateHardLinkA(args, wide=True)

    def DeviceIoControl(self, args):
        """DeviceIoControl emulation - no device control codes are supported"""
        self._last_error = 50  # ERROR_NOT_SUPPORTED
        return 0

    def FindFirstChangeNotificationA(self, args, wide=False):
        """FindFirstChangeNotificationA/W emulation - a handle that is signaled
        when the folder's listing changes (checked at FindNextChangeNotification)"""
        path = self.resolve_c_drive_path(self._read_text(args[0], wide))
        if path is None or not os.path.isdir(path):
            self._last_error = 3  # ERROR_PATH_NOT_FOUND
            return 0xFFFFFFFF
        handle = self.get_next_handle()
        self.handles[handle] = {'type': 'change_notification', 'path': path,
                                'signaled': False, 'snapshot': self._dir_snapshot(path)}
        return handle

    def FindFirstChangeNotificationW(self, args):
        return self.FindFirstChangeNotificationA(args, wide=True)

    @staticmethod
    def _dir_snapshot(path):
        try:
            with os.scandir(path) as entries:
                return sorted((e.name, e.stat().st_mtime_ns, e.stat().st_size)
                              for e in entries)
        except OSError:
            return None

    def _check_change_notification(self, info):
        snapshot = self._dir_snapshot(info['path'])
        if snapshot != info['snapshot']:
            info['snapshot'] = snapshot
            info['signaled'] = True

    def FindNextChangeNotification(self, args):
        """FindNextChangeNotification emulation - re-arm the handle"""
        info = self.handles.get(args[0])
        if not info or info.get('type') != 'change_notification':
            self._last_error = 6  # ERROR_INVALID_HANDLE
            return 0
        info['signaled'] = False
        return 1

    def FindCloseChangeNotification(self, args):
        """FindCloseChangeNotification emulation"""
        info = self.handles.pop(args[0], None)
        return 1 if info else 0

    def OpenProcess(self, args):
        """OpenProcess emulation - other processes can't be opened"""
        self._last_error = 87  # ERROR_INVALID_PARAMETER
        return 0

    def CreateToolhelp32Snapshot(self, args):
        """CreateToolhelp32Snapshot emulation - an empty snapshot"""
        handle = self.get_next_handle()
        self.handles[handle] = {'type': 'snapshot'}
        return handle

    def Process32FirstW(self, args):
        """Process32FirstW emulation - no processes are listed"""
        self._last_error = 18  # ERROR_NO_MORE_FILES
        return 0

    def Process32NextW(self, args):
        self._last_error = 18  # ERROR_NO_MORE_FILES
        return 0

    def CreateFileMappingA(self, args, wide=False):
        """CreateFileMappingA/W emulation - host memory that every process (and
        thread) mapping it shares; a file's contents are copied in"""
        hFile, size_high, size_low, lpName = args[0], args[3], args[4], args[5]
        size = (size_high << 32) | size_low
        file_info = self.handles.get(hFile) if hFile != 0xFFFFFFFF else None
        if file_info is not None and file_info.get('fp') and size == 0:
            fp = file_info['fp']
            current = fp.tell()
            size = fp.seek(0, os.SEEK_END)
            fp.seek(current, os.SEEK_SET)
        if size == 0 or size > 0x10000000:
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0

        def create():
            span = self.emu._align_size(size, 0x10000)
            buf = mmap.mmap(-1, span)
            if file_info is not None and file_info.get('fp'):
                fp = file_info['fp']
                current = fp.tell()
                fp.seek(0)
                buf[:size] = fp.read(size).ljust(size, b'\x00')
                fp.seek(current, os.SEEK_SET)
            return {'size': size, 'span': span, 'buf': buf,
                    'ptr': ctypes.addressof(ctypes.c_char.from_buffer(buf))}
        return self._named_object(lpName, 'mapping', wide, create)

    def CreateFileMappingW(self, args):
        return self.CreateFileMappingA(args, wide=True)

    def MapViewOfFile(self, args):
        """MapViewOfFile emulation - the mapping's memory, mapped once per process"""
        info = self.handles.get(args[0])
        if not info or info.get('type') != 'mapping':
            self._last_error = 6  # ERROR_INVALID_HANDLE
            return 0
        offset = (args[2] << 32) | args[3]
        if offset >= info['size']:
            self._last_error = 87
            return 0
        base = self.mapping_views.get(id(info))
        if base is None:
            base = self.emu._free_image_base(0, info['span'])
            if base is None:
                self._last_error = 8  # ERROR_NOT_ENOUGH_MEMORY
                return 0
            self.emu.map_foreign(base, info['span'], info['buf'], info['ptr'])
            self.mapping_views[id(info)] = base
        return base + offset

    def MapViewOfFileEx(self, args):
        return self.MapViewOfFile(args[:5])

    def UnmapViewOfFile(self, args):
        return 1

    def GlobalSize(self, args):
        """GlobalSize emulation - size of a GlobalAlloc block"""
        size = self.emu.heap_block_size(args[0]) if args[0] else None
        if size is None:
            self._last_error = 6  # ERROR_INVALID_HANDLE
            return 0
        return size

    def GetProcessTimes(self, args):
        """GetProcessTimes emulation - creation time and the CPU time used so far"""
        if args[0] not in (0xFFFFFFFF,) and args[0] not in self.handles:
            self._last_error = 6  # ERROR_INVALID_HANDLE
            return 0
        start = getattr(self, '_process_start', None)
        if start is None:
            start = self._process_start = time.time()
        user = int(time.process_time() * 10000000)
        for ptr, value in ((args[1], self._filetime(start)), (args[2], 0), (args[3], 0),
                           (args[4], user)):
            if ptr:
                self._mem_write(ptr, struct.pack('<Q', value))
        return 1

    def SetProcessAffinityMask(self, args):
        return 1

    def SetFileApisToOEM(self, args):
        return 0

    def SetFileApisToANSI(self, args):
        return 0

    def AreFileApisANSI(self, args):
        return 1

    def _is_console_handle(self, handle):
        return handle in (0x10, 0x11, 0x12) and self.has_console

    def GetConsoleMode(self, args):
        """GetConsoleMode emulation - only for the process's own console"""
        if not self._is_console_handle(args[0]):
            self._last_error = 6  # ERROR_INVALID_HANDLE
            return 0
        mode = 0x7 if args[0] == 0x10 else 0x3  # Processed/line/echo input, processed output
        return 1 if self._mem_write(args[1], struct.pack('<I', mode)) else 0

    def SetConsoleMode(self, args):
        if not self._is_console_handle(args[0]):
            self._last_error = 6
            return 0
        return 1

    def GetConsoleScreenBufferInfo(self, args):
        """GetConsoleScreenBufferInfo emulation - an 80 x 25 console"""
        if not self._is_console_handle(args[0]) or args[0] == 0x10:
            self._last_error = 6  # ERROR_INVALID_HANDLE
            return 0
        data = struct.pack('<hhhhH4hhh', 80, 300, 0, 0, 0x07, 0, 0, 79, 24, 80, 25)
        return 1 if self._mem_write(args[1], data) else 0

    def SetConsoleCtrlHandler(self, args):
        return 1

    def GetSystemDefaultLangID(self, args):
        return 0x0409  # English (United States)

    def GetSystemDefaultLCID(self, args):
        return 0x0409

    def GetUserDefaultLCID(self, args):
        return 0x0409

    def IsProcessorFeaturePresent(self, args):
        """IsProcessorFeaturePresent emulation - the emulated CPU has SSE/SSE2"""
        # PF_FLOATING_POINT_EMULATED (1) no; PF_COMPARE_EXCHANGE_DOUBLE (2),
        # PF_MMX (3), PF_XMMI (6), PF_RDTSC (8), PF_PAE (9), PF_XMMI64 (10)
        return 1 if args[0] in (2, 3, 6, 8, 10) else 0

    # ---------- Time conversions ----------

    def FileTimeToDosDateTime(self, args):
        """FileTimeToDosDateTime emulation"""
        ft = self._read_filetime(args[0])
        if ft is None or ft >= 0x8000000000000000:
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0
        when = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ft // 10)
        if not 1980 <= when.year <= 2107:
            self._last_error = 87
            return 0
        dos_date = ((when.year - 1980) << 9) | (when.month << 5) | when.day
        dos_time = (when.hour << 11) | (when.minute << 5) | (when.second // 2)
        if args[1]:
            self._mem_write(args[1], struct.pack('<H', dos_date))
        if args[2]:
            self._mem_write(args[2], struct.pack('<H', dos_time))
        return 1

    def DosDateTimeToFileTime(self, args):
        """DosDateTimeToFileTime emulation"""
        dos_date, dos_time = args[0] & 0xFFFF, args[1] & 0xFFFF
        try:
            when = datetime.datetime(1980 + (dos_date >> 9), (dos_date >> 5) & 0xF,
                                     dos_date & 0x1F, dos_time >> 11, (dos_time >> 5) & 0x3F,
                                     min((dos_time & 0x1F) * 2, 59))
        except ValueError:
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0
        delta = when - datetime.datetime(1601, 1, 1)
        ft = (delta.days * 86400 + delta.seconds) * 10000000
        return 1 if self._mem_write(args[2], struct.pack('<Q', ft)) else 0

    def CompareFileTime(self, args):
        """CompareFileTime emulation: -1, 0 or 1"""
        first, second = self._read_filetime(args[0]), self._read_filetime(args[1])
        if first is None or second is None:
            return 0
        return 0xFFFFFFFF if first < second else 1 if first > second else 0

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

    def CompareStringA(self, args, wide=False):
        """CompareStringA/W emulation - CSTR_LESS_THAN/EQUAL/GREATER_THAN (1/2/3)"""
        flags = args[1]
        texts = []
        for address, count in ((args[2], args[3]), (args[4], args[5])):
            if count != 0xFFFFFFFF and count >= 0x80000000:
                self._last_error = 87  # ERROR_INVALID_PARAMETER
                return 0
            units = self._counted_units(address, count, wide) if address else None
            if units is None:
                self._last_error = 87
                return 0
            if 0 in units:
                units = units[:units.index(0)]
            text = self._units_text(units, wide)
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
        return self.emu.current_thread.tid
    
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
        
        log.debug("QueryPerformanceCounter()")
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
