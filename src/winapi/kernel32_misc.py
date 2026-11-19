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

"""WinAPIHandler mixin: Additional kernel32 APIs: libraries, system folders, lstr*
strings, global memory"""

import os
import io
import shutil
import struct
import time

from unicorn import UcError

from .. import config, winapi
from ..config import DRIVES
from ..logger import log
from ..paths import drive_path_error


class Kernel32MiscMixin:
    """Additional kernel32 APIs: libraries, system folders, lstr* strings, global memory"""

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

        # The EXE, a loaded DLL or an emulated system DLL (other handles: the EXE)
        filepath = self._module_path(hModule) or self.windows_exe_path()
        data = filepath.encode(config.ANSI_CODEPAGE, errors='replace')
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

        # The EXE, a loaded DLL or an emulated system DLL (other handles: the EXE)
        filepath = self._module_path(hModule) or self.windows_exe_path()
        if nSize == 0:
            return 0
        if len(filepath) >= nSize:
            data = filepath[:nSize - 1].encode('utf-16-le')
            self.emu.uc.mem_write(lpFilename, data + b'\x00\x00')
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
        """FreeLibrary emulation - a real DLL is unloaded with its last
        reference (DllMain(DLL_PROCESS_DETACH)); the emulated system DLLs
        stay loaded"""
        hLibModule = args[0]
        log.debug(f"FreeLibrary(0x{hLibModule:x})")
        if self.emu.release_dll(hLibModule):
            return 1
        info = self.handles.get(hLibModule)
        if (hLibModule == self.emu.pe_loader.image_base or
                (info and info.get('type') == 'module') or
                self._system_module_name(hLibModule)):
            return 1
        self._last_error = 126  # ERROR_MOD_NOT_FOUND
        return 0

    def FreeLibraryAndExitThread(self, args):
        """FreeLibraryAndExitThread(module, exit code)"""
        self.FreeLibrary(args[:1])
        return self.ExitThread(args[1:])

    def DisableThreadLibraryCalls(self, args):
        """DisableThreadLibraryCalls(module) - no DLL_THREAD_ATTACH/DETACH"""
        module = self.emu.find_dll(args[0])
        if module is not None:
            module['thread_calls'] = False
        return 1

    def GetSystemDirectoryA(self, args):
        """GetSystemDirectoryA emulation: the length, or the needed size
        (with the terminator) when the buffer is too small"""
        log.debug("GetSystemDirectoryA()")
        return self._return_text(args[0], args[1], "C:\\Windows\\System32", False)

    def GetWindowsDirectoryA(self, args):
        """GetWindowsDirectoryA emulation (see GetSystemDirectoryA)"""
        log.debug("GetWindowsDirectoryA()")
        return self._return_text(args[0], args[1], "C:\\Windows", False)

    def GetTempPathW(self, args):
        """GetTempPathW emulation"""
        return self._return_text(args[1], args[0], "C:\\Windows\\Temp\\", True)

    def _return_text(self, buffer, size, text, wide):
        """Copy text into a caller buffer of size characters: its length, or
        the needed size (with the terminator) if it does not fit"""
        length = len(self._text_units(text, wide))
        if not buffer or size <= length:
            return length + 1
        self._write_text(buffer, text, wide)
        return length

    def GetTempPathA(self, args):
        """GetTempPathA emulation (see GetSystemDirectoryA)"""
        log.debug("GetTempPathA()")
        return self._return_text(args[1], args[0], "C:\\Windows\\Temp\\", False)

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
        """GetSystemDirectoryW emulation (see GetSystemDirectoryA)"""
        log.debug("GetSystemDirectoryW()")
        return self._return_text(args[0], args[1], "C:\\Windows\\System32", True)

    def GetWindowsDirectoryW(self, args):
        """GetWindowsDirectoryW emulation (see GetSystemDirectoryA)"""
        log.debug("GetWindowsDirectoryW()")
        return self._return_text(args[0], args[1], "C:\\Windows", True)

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
            if info.get('shared'):
                # DuplicateHandle: other handles still use the object
                info['shared'] -= 1
                del self.handles[hObject]
                return 1
            if 'refs' in info:
                # The last handle of a named object destroys its name
                info['refs'] -= 1
                name = info.get('object_name')
                if info['refs'] <= 0 and name and \
                        winapi.WinAPIHandler.named_kernel_objects.get(name) is info:
                    del winapi.WinAPIHandler.named_kernel_objects[name]
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
            self.emu.idle_wait(min(0.05, remaining))

    # Critical sections: owner thread and recursion count by address
    def InitializeCriticalSection(self, args):
        """InitializeCriticalSection emulation"""
        try:
            self.emu.uc.mem_write(args[0], b'\x00' * 24)  # sizeof(CRITICAL_SECTION)
        except UcError:
            pass
        self.critical_sections.pop(args[0], None)
        return 0

    def InitializeCriticalSectionAndSpinCount(self, args):
        """InitializeCriticalSectionAndSpinCount emulation"""
        self.InitializeCriticalSection(args)
        return 1

    def InitializeCriticalSectionEx(self, args):
        self.InitializeCriticalSection(args)
        return 1

    def _try_enter_cs(self, address):
        tid = self.emu.current_thread.tid
        owner = self.critical_sections.get(address)
        if owner is None or not self._thread_alive(owner[0]):
            self.critical_sections[address] = [tid, 1]
            return True
        if owner[0] == tid:
            owner[1] += 1
            return True
        return False

    def EnterCriticalSection(self, args):
        """EnterCriticalSection emulation - waits while another thread owns it"""
        self.emu.wait_until(lambda: self._try_enter_cs(args[0]))
        return 0

    def TryEnterCriticalSection(self, args):
        """TryEnterCriticalSection emulation"""
        return 1 if self._try_enter_cs(args[0]) else 0

    def LeaveCriticalSection(self, args):
        """LeaveCriticalSection emulation"""
        owner = self.critical_sections.get(args[0])
        if owner is not None and owner[0] == self.emu.current_thread.tid:
            owner[1] -= 1
            if owner[1] <= 0:
                del self.critical_sections[args[0]]
                self.emu.wake_threads()
        return 0

    def DeleteCriticalSection(self, args):
        """DeleteCriticalSection emulation"""
        self.critical_sections.pop(args[0], None)
        return 0

    def GetFileAttributesA(self, args, wide=False):
        """GetFileAttributesA/W emulation (sandboxed to drives/)"""
        filename = self._read_text(args[0], wide)
        log.debug(f"GetFileAttributes{'W' if wide else 'A'}(\"{filename}\")")

        path = self.resolve_drive_path(filename)
        if path is None or not os.path.exists(path):
            return 0xFFFFFFFF  # INVALID_FILE_ATTRIBUTES
        read_only = 0x01 if self._host_read_only(path) else 0  # FILE_ATTRIBUTE_READONLY
        if os.path.isdir(path):
            return 0x10 | read_only  # FILE_ATTRIBUTE_DIRECTORY
        return read_only or 0x80  # FILE_ATTRIBUTE_NORMAL

    def CreateFileA(self, args):
        """CreateFileA emulation - opens a real file inside the drives/ sandbox"""
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

        Honours the sandbox: names that escape their drive's folder get
        INVALID_HANDLE_VALUE and ERROR_ACCESS_DENIED, like changes on the
        read-only CD-ROM D:.
        """
        INVALID_HANDLE_VALUE = 0xFFFFFFFF
        GENERIC_WRITE = 0x40000000
        want_write = bool(dwDesiredAccess & (GENERIC_WRITE | 0x2 | 0x4 | 0x100))
        device = self.open_device(filename, want_write)
        if device is not None:
            return device
        path = self.resolve_drive_path(filename)
        if path is None:
            full = self.full_windows_path(filename)
            self._last_error = drive_path_error(full) if full else 5  # ERROR_ACCESS_DENIED
            return INVALID_HANDLE_VALUE

        exists = os.path.exists(path)
        if os.path.isdir(path):
            # Directories open only with FILE_FLAG_BACKUP_SEMANTICS (no data)
            if dwCreationDisposition in (1, 2, 5):
                self._last_error = 5 if dwCreationDisposition != 1 else 80
                return INVALID_HANDLE_VALUE
            handle = self.get_next_handle()
            self.handles[handle] = {'type': 'file', 'name': filename, 'fp': None,
                                    'path': path, 'directory': True}
            self._last_error = 0
            return handle

        # CreationDisposition: CREATE_NEW=1, CREATE_ALWAYS=2, OPEN_EXISTING=3,
        # OPEN_ALWAYS=4, TRUNCATE_EXISTING=5
        if (want_write or dwCreationDisposition in (1, 2, 5) or
                (dwCreationDisposition == 4 and not exists)):
            if dwCreationDisposition in (3, 5) and not exists:
                pass  # ERROR_FILE_NOT_FOUND below
            elif self._write_protected(path):
                return INVALID_HANDLE_VALUE
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
        """SetFilePointer emulation (64-bit with lpDistanceToMoveHigh)"""
        hFile = args[0]
        lDistanceToMove = args[1]
        lpDistanceToMoveHigh = args[2]
        dwMoveMethod = args[3]  # FILE_BEGIN=0, FILE_CURRENT=1, FILE_END=2

        if lpDistanceToMoveHigh:
            high = struct.unpack('<I', self.emu.uc.mem_read(lpDistanceToMoveHigh, 4))[0]
            distance = (high << 32) | lDistanceToMove
            if distance & (1 << 63):
                distance -= 1 << 64
        else:
            # Interpret distance as signed 32-bit.
            distance = lDistanceToMove - 0x100000000 if lDistanceToMove & 0x80000000 \
                else lDistanceToMove

        log.debug(f"SetFilePointer(0x{hFile:x}, {distance}, method={dwMoveMethod})")

        info = self.handles.get(hFile)
        if not info or not info.get('fp'):
            self._last_error = 6  # ERROR_INVALID_HANDLE
            return 0xFFFFFFFF  # INVALID_SET_FILE_POINTER

        fp = info['fp']
        try:
            if dwMoveMethod == 1:
                position = fp.tell() + distance
            elif dwMoveMethod == 2:
                position = fp.seek(0, os.SEEK_END) + distance
            else:
                position = distance
            if position < 0:
                self._last_error = 131  # ERROR_NEGATIVE_SEEK
                return 0xFFFFFFFF
            fp.seek(position, os.SEEK_SET)
        except OSError:
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0xFFFFFFFF
        if lpDistanceToMoveHigh:
            self.emu.uc.mem_write(lpDistanceToMoveHigh, struct.pack('<I', position >> 32))
        self._last_error = 0
        return position & 0xFFFFFFFF

    def SetFilePointerEx(self, args):
        """SetFilePointerEx emulation"""
        hFile, low, high, lpNew, method = args[:5]
        info = self.handles.get(hFile)
        if not info or not info.get('fp'):
            self._last_error = 6  # ERROR_INVALID_HANDLE
            return 0
        distance = (high << 32) | low
        if distance & (1 << 63):
            distance -= 1 << 64
        fp = info['fp']
        try:
            base = {1: fp.tell(), 2: fp.seek(0, os.SEEK_END)}.get(method, 0)
            if base + distance < 0:
                self._last_error = 131  # ERROR_NEGATIVE_SEEK
                return 0
            position = fp.seek(base + distance, os.SEEK_SET)
        except OSError:
            self._last_error = 87
            return 0
        if lpNew:
            self._mem_write(lpNew, struct.pack('<Q', position))
        return 1

    def GetFileSizeEx(self, args):
        """GetFileSizeEx emulation"""
        info = self.handles.get(args[0])
        if not info or not info.get('fp'):
            self._last_error = 6  # ERROR_INVALID_HANDLE
            return 0
        fp = info['fp']
        current = fp.tell()
        size = fp.seek(0, os.SEEK_END)
        fp.seek(current, os.SEEK_SET)
        return 1 if self._mem_write(args[1], struct.pack('<Q', size)) else 0

    def DeleteFileA(self, args, wide=False):
        """DeleteFileA/W emulation (sandboxed)"""
        filename = self._read_text(args[0], wide)
        log.debug(f"DeleteFileA(\"{filename}\")")
        path = self.resolve_drive_path(filename)
        if path is None or not os.path.isfile(path):
            self._last_error = 2
            return 0  # FALSE
        if self._write_protected(path):
            return 0
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
        path = self.resolve_drive_path(dirname)
        if path is None:
            self._last_error = 5  # ERROR_ACCESS_DENIED
            return 0
        if os.path.exists(path):
            self._last_error = 183  # ERROR_ALREADY_EXISTS
            return 0
        if self._write_protected(path):
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
        path = self.resolve_drive_path(dirname)
        if path is None or not os.path.isdir(path):
            self._last_error = 3 if path else 5
            return 0
        if self._write_protected(path):
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
        src_path = self.resolve_drive_path(src)
        dst_path = self.resolve_drive_path(dst)
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
        if self._write_protected(dst_path):
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
        src_path = self.resolve_drive_path(src)
        dst_path = self.resolve_drive_path(dst)
        if src_path is None or dst_path is None:
            self._last_error = 5  # ERROR_ACCESS_DENIED
            return 0
        if not os.path.exists(src_path):
            self._last_error = 2  # ERROR_FILE_NOT_FOUND
            return 0
        if os.path.exists(dst_path):
            self._last_error = 183  # ERROR_ALREADY_EXISTS
            return 0
        if self._write_protected(src_path, dst_path):
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

    MOVEFILE_REPLACE_EXISTING = 0x1
    MOVEFILE_DELAY_UNTIL_REBOOT = 0x4

    def MoveFileExA(self, args, wide=False):
        """MoveFileExA/W emulation. MOVEFILE_DELAY_UNTIL_REBOOT operations are
        kept until ExitWindowsEx restarts the (emulated) system."""
        lpExisting, lpNew, flags = args[0], args[1], args[2]
        src = self._read_text(lpExisting, wide)
        dst = self._read_text(lpNew, wide) if lpNew else None
        log.debug(f"MoveFileEx(\"{src}\", \"{dst}\", 0x{flags:x})")
        src_path = self.resolve_drive_path(src)
        dst_path = self.resolve_drive_path(dst) if dst else None
        if src_path is None or (dst is not None and dst_path is None):
            self._last_error = 5  # ERROR_ACCESS_DENIED
            return 0
        if self._write_protected(src_path, dst_path):
            return 0
        if flags & self.MOVEFILE_DELAY_UNTIL_REBOOT:
            self.pending_file_operations.append((src_path, dst_path, flags))
            log.info(f"MoveFileEx: \"{src}\" -> \"{dst or '(delete)'}\" after restart")
            return 1
        if dst is None:
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0
        if not os.path.exists(src_path):
            self._last_error = 2  # ERROR_FILE_NOT_FOUND
            return 0
        if os.path.exists(dst_path):
            if (not flags & self.MOVEFILE_REPLACE_EXISTING or os.path.isdir(dst_path)
                    or os.path.isdir(src_path)):
                self._last_error = 183  # ERROR_ALREADY_EXISTS
                return 0
        try:
            if os.path.isdir(src_path):
                os.rename(src_path, dst_path)
            else:
                shutil.move(src_path, dst_path)
        except FileNotFoundError:
            self._last_error = 3  # ERROR_PATH_NOT_FOUND
            return 0
        except OSError as e:
            log.error(f"MoveFileEx(\"{src}\", \"{dst}\") failed: {e}")
            self._last_error = 5
            return 0
        return 1

    def MoveFileExW(self, args):
        return self.MoveFileExA(args, wide=True)

    def _run_pending_file_operations(self):
        """Do the MOVEFILE_DELAY_UNTIL_REBOOT renames/deletions (system restart)"""
        operations, self.pending_file_operations = self.pending_file_operations, []
        for src_path, dst_path, flags in operations:
            try:
                if dst_path is None:
                    if os.path.isdir(src_path):
                        os.rmdir(src_path)
                    elif os.path.exists(src_path):
                        os.remove(src_path)
                elif os.path.exists(src_path):
                    if os.path.isfile(dst_path) and flags & self.MOVEFILE_REPLACE_EXISTING:
                        os.replace(src_path, dst_path)
                    elif not os.path.exists(dst_path):
                        os.rename(src_path, dst_path)
            except OSError as e:
                log.warning(f"Pending file operation on {src_path} failed: {e}")

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
        """SetCurrentDirectoryA/W emulation (the directory must exist on a drive)"""
        name = self._read_text(args[0], wide)
        log.debug(f"SetCurrentDirectory(\"{name}\")")
        full = self.full_windows_path(name)
        path = self.resolve_drive_path(name)
        if full is None or path is None:
            self._last_error = 5  # ERROR_ACCESS_DENIED
            return 0
        if not os.path.isdir(path):
            self._last_error = 2 if not os.path.exists(path) else 267  # ERROR_DIRECTORY
            return 0
        self.current_directory = full
        self.emu.update_process_current_directory(full)
        return 1

    def SetCurrentDirectoryW(self, args):
        return self.SetCurrentDirectoryA(args, wide=True)

    def GetFullPathNameA(self, args, wide=False):
        """GetFullPathNameA/W emulation - resolves against the current directory"""
        name = self._read_text(args[0], wide)
        nBufferLength, lpBuffer, lpFilePart = args[1], args[2], args[3]
        full = self.full_windows_path(name, clamp=True)
        log.debug(f"GetFullPathName{'W' if wide else 'A'}(\"{name}\") -> \"{full}\"")
        if full is None:
            self._last_error = 123  # ERROR_INVALID_NAME
            return 0
        return self._write_path_out(full, nBufferLength, lpBuffer, lpFilePart, wide)

    def _write_path_out(self, full, nBufferLength, lpBuffer, lpFilePart, wide):
        """Copy a full path into a caller buffer like GetFullPathName: its
        length, or the needed size (with the terminator) if it does not fit;
        lpFilePart gets the address of its last component"""
        units = self._text_units(full, wide)  # lengths are in TCHARs
        if not lpBuffer or nBufferLength <= len(units):
            return len(units) + 1
        self._write_units(lpBuffer, units, wide)
        if lpFilePart:
            # Last component, or NULL when the path ends with a separator
            sep = len(units) - 1 - units[::-1].index(0x5C) if 0x5C in units else -1
            part = lpBuffer + (sep + 1) * (2 if wide else 1) if sep + 1 < len(units) else 0
            self.emu.uc.mem_write(lpFilePart, struct.pack('<I', part))
        return len(units)

    def GetFullPathNameW(self, args):
        return self.GetFullPathNameA(args, wide=True)

    def _search_path_dirs(self):
        """SearchPath's default order: the program's folder, the current
        folder, System32, the Windows folder, then the PATH folders"""
        exe_dir = self.windows_exe_path().rsplit('\\', 1)[0]
        dirs = [exe_dir, self.current_directory, "C:\\Windows\\System32", "C:\\Windows"]
        path = self.environment.get('PATH', '')
        return dirs + [d for d in path.split(';') if d]

    def SearchPathA(self, args, wide=False):
        """SearchPathA/W emulation - finds a file in the sandbox"""
        lpPath, lpFileName, lpExtension, nBufferLength, lpBuffer, lpFilePart = args[:6]
        name = self._read_text(lpFileName, wide) if lpFileName else ''
        if not name:
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0
        candidates = [name]
        if lpExtension and '.' not in name.replace('/', '\\').rsplit('\\', 1)[-1]:
            candidates.insert(0, name + self._read_text(lpExtension, wide))
        if name[1:2] == ':' or name.startswith(('\\', '/')):
            dirs = ['']
        elif lpPath:
            dirs = [d for d in self._read_text(lpPath, wide).split(';') if d]
        else:
            dirs = self._search_path_dirs()
        for folder in dirs:
            for candidate in candidates:
                full = self.full_windows_path(
                    candidate if not folder else folder.rstrip('\\/') + '\\' + candidate)
                host = self.resolve_drive_path(full) if full else None
                if host and os.path.exists(host):
                    log.debug(f"SearchPath(\"{name}\") -> \"{full}\"")
                    return self._write_path_out(full, nBufferLength, lpBuffer, lpFilePart,
                                                wide)
        log.debug(f"SearchPath(\"{name}\") -> not found")
        self._last_error = 2  # ERROR_FILE_NOT_FOUND
        return 0

    def SearchPathW(self, args):
        return self.SearchPathA(args, wide=True)

    def GetShortPathNameA(self, args, wide=False):
        """GetShortPathNameA/W emulation - the sandbox has no 8.3 names (like an
        NTFS volume with short names turned off): the path itself, if it exists"""
        lpszLongPath, lpszShortPath, cchBuffer = args[0], args[1], args[2]
        name = self._read_text(lpszLongPath, wide) if lpszLongPath else ''
        full = self.full_windows_path(name) if name else None
        host = self.resolve_drive_path(full) if full else None
        if not host or not os.path.exists(host):
            self._last_error = 2 if full else 123  # FILE_NOT_FOUND / INVALID_NAME
            return 0
        log.debug(f"GetShortPathName(\"{name}\")")
        return self._return_text(lpszShortPath, cchBuffer, name, wide)

    def GetShortPathNameW(self, args):
        return self.GetShortPathNameA(args, wide=True)

    def GetLongPathNameA(self, args, wide=False):
        """GetLongPathNameA/W emulation (see GetShortPathName)"""
        return self.GetShortPathNameA(args, wide)

    def GetLongPathNameW(self, args):
        return self.GetShortPathNameA(args, wide=True)

    def GetDiskFreeSpaceA(self, args):
        """GetDiskFreeSpaceA emulation (see GetDiskFreeSpaceW)"""
        letter = self._drive_letter(args[0])
        if letter is None:
            self._last_error = 3  # ERROR_PATH_NOT_FOUND
            return 0
        # Old programs compute bytes in 32 bits: report at most 2 GB like Windows 9x
        sector_size, sectors = self.DRIVE_GEOMETRY[DRIVES[letter][0]]
        return self._disk_free_space(letter, args[1:5],
                                     limit=0x7FFFFFFF // (sector_size * sectors))

    def GetTempFileNameA(self, args):
        """GetTempFileNameA emulation - <path>\\<pre><hex>.TMP (created if uUnique is 0)"""
        path_name = self.read_string(args[0])
        prefix = self.read_string(args[1])[:3]
        uUnique = args[2] & 0xFFFF
        lpTempFileName = args[3]
        log.debug(f"GetTempFileNameA(\"{path_name}\", \"{prefix}\", {uUnique})")

        directory = self.resolve_drive_path(path_name)
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
                path = self.resolve_drive_path(name)
                if path is None or self._write_protected(path):
                    path = None
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

        data = name.encode(config.ANSI_CODEPAGE, errors='replace')
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
