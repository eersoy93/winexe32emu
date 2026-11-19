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

"""WinAPIHandler mixin: kernel32 atom tables, version checks, system
information, file and handle extras, local/global memory extras, the
16-bit file functions, console extras, power and ntdll helpers"""

import os
import struct
import threading
import time

from unicorn import UC_PROT_EXEC, UC_PROT_READ, UC_PROT_WRITE, UcError

from .. import winapi
from ..guest import QWordResult


class Kernel32ExtraMixin:
    """kernel32 atoms, version checks, system information and other extras"""

    # ---------- Atom tables ----------

    # The global atom table is shared by the emulated programs (like the
    # system's); each process has its own local one
    _global_atoms = {}
    _global_atoms_lock = threading.Lock()

    def _atom_table(self, global_table):
        if global_table:
            return winapi.WinAPIHandler._global_atoms
        return self.__dict__.setdefault('_local_atoms', {})

    def _atom_name_arg(self, address, wide):
        """(name, integer atom) of an atom name argument: MAKEINTATOM or "#123" """
        if address < 0x10000:
            return None, address
        name = self._read_text(address, wide)
        if name.startswith('#') and name[1:].isdigit():
            return None, int(name[1:])
        return name, None

    def _add_atom(self, address, wide, global_table):
        name, number = self._atom_name_arg(address, wide)
        if number is not None:
            if not 0 < number < 0xC000:
                self._last_error = 87  # ERROR_INVALID_PARAMETER
                return 0
            return number
        if not name or len(name) > 255:
            self._last_error = 87
            return 0
        with winapi.WinAPIHandler._global_atoms_lock:
            table = self._atom_table(global_table)
            for atom, entry in table.items():
                if entry['name'].lower() == name.lower():
                    entry['refs'] += 1
                    return atom
            atom = next((a for a in range(0xC000, 0x10000) if a not in table), 0)
            if atom:
                table[atom] = {'name': name, 'refs': 1}
            else:
                self._last_error = 8  # ERROR_NOT_ENOUGH_MEMORY
            return atom

    def _find_atom(self, address, wide, global_table):
        name, number = self._atom_name_arg(address, wide)
        if number is not None:
            return number if 0 < number < 0xC000 else 0
        with winapi.WinAPIHandler._global_atoms_lock:
            for atom, entry in self._atom_table(global_table).items():
                if entry['name'].lower() == (name or '').lower():
                    return atom
        self._last_error = 2  # ERROR_FILE_NOT_FOUND
        return 0

    def _delete_atom(self, atom, global_table):
        """0 on success, the atom on failure"""
        if atom < 0xC000:
            return 0
        with winapi.WinAPIHandler._global_atoms_lock:
            table = self._atom_table(global_table)
            entry = table.get(atom)
            if entry is None:
                self._last_error = 6  # ERROR_INVALID_HANDLE
                return atom
            entry['refs'] -= 1
            if entry['refs'] <= 0:
                del table[atom]
        return 0

    def _atom_name(self, atom, buffer, size, wide, global_table):
        if atom < 0xC000:
            name = f'#{atom}' if atom else None
        else:
            with winapi.WinAPIHandler._global_atoms_lock:
                entry = self._atom_table(global_table).get(atom)
            name = entry['name'] if entry else None
        if name is None:
            self._last_error = 6
            return 0
        if not buffer or size == 0:
            self._last_error = 122  # ERROR_INSUFFICIENT_BUFFER
            return 0
        units = self._text_units(name, wide)[:size - 1]
        self._write_units(buffer, units, wide)
        return len(units)

    def AddAtomA(self, args, wide=False):
        return self._add_atom(args[0], wide, False)

    def AddAtomW(self, args):
        return self.AddAtomA(args, wide=True)

    def FindAtomA(self, args, wide=False):
        return self._find_atom(args[0], wide, False)

    def FindAtomW(self, args):
        return self.FindAtomA(args, wide=True)

    def DeleteAtom(self, args):
        return self._delete_atom(args[0] & 0xFFFF, False)

    def GetAtomNameA(self, args, wide=False):
        return self._atom_name(args[0] & 0xFFFF, args[1], args[2], wide, False)

    def GetAtomNameW(self, args):
        return self.GetAtomNameA(args, wide=True)

    def InitAtomTable(self, args):
        return 1

    def GlobalAddAtomA(self, args, wide=False):
        return self._add_atom(args[0], wide, True)

    def GlobalAddAtomW(self, args):
        return self.GlobalAddAtomA(args, wide=True)

    def GlobalFindAtomA(self, args, wide=False):
        return self._find_atom(args[0], wide, True)

    def GlobalFindAtomW(self, args):
        return self.GlobalFindAtomA(args, wide=True)

    def GlobalDeleteAtom(self, args):
        return self._delete_atom(args[0] & 0xFFFF, True)

    def GlobalGetAtomNameA(self, args, wide=False):
        return self._atom_name(args[0] & 0xFFFF, args[1], args[2], wide, True)

    def GlobalGetAtomNameW(self, args):
        return self.GlobalGetAtomNameA(args, wide=True)

    # ---------- Versions (Windows Vista SP2, like GetVersionEx) ----------

    OS_VERSION = (6, 0, 6002, 2)  # major, minor, build, platform (VER_PLATFORM_WIN32_NT)
    OS_SERVICE_PACK = (2, 0)
    OS_SUITE_MASK = 0x0100  # VER_SUITE_SINGLEUSERTS
    OS_PRODUCT_TYPE = 1  # VER_NT_WORKSTATION

    def VerSetConditionMask(self, args):
        """VerSetConditionMask(ULONGLONG mask, type bits, condition)"""
        mask, type_mask, condition = self._arg_qword(args, 0), args[2], args[3] & 0x7
        if type_mask and condition:
            for index in range(8):
                if type_mask & (1 << index):
                    mask = (mask & ~(0x7 << (index * 3))) | (condition << (index * 3))
        return QWordResult(mask)

    @staticmethod
    def _version_test(value, wanted, condition):
        if condition == 1:
            return value == wanted
        if condition == 2:
            return value > wanted
        if condition == 3:
            return value >= wanted
        if condition == 4:
            return value < wanted
        if condition == 5:
            return value <= wanted
        return False

    def VerifyVersionInfoA(self, args, wide=False):
        """VerifyVersionInfoA/W(OSVERSIONINFOEX, type mask, ULONGLONG conditions)"""
        info, type_mask = args[0], args[1]
        conditions = self._arg_qword(args, 2)
        if not type_mask or not conditions:
            self._last_error = 160  # ERROR_BAD_ARGUMENTS
            return 0
        try:
            major, minor, build, platform = struct.unpack('<4I',
                                                          self.emu.uc.mem_read(info + 4, 16))
            tail = info + (276 if wide else 148)
            sp_major, sp_minor, suite, product = struct.unpack(
                '<HHHB', self.emu.uc.mem_read(tail, 7))
        except UcError:
            self._last_error = 998
            return 0

        def condition(bit):
            return (conditions >> (3 * (bit.bit_length() - 1))) & 0x7

        ok = True
        # Major, minor and service pack versions compare as one version number
        levels = [(0x2, self.OS_VERSION[0], major), (0x1, self.OS_VERSION[1], minor),
                  (0x20, self.OS_SERVICE_PACK[0], sp_major),
                  (0x10, self.OS_SERVICE_PACK[1], sp_minor)]
        levels = [level for level in levels if type_mask & level[0]]
        if levels:
            mine = tuple(level[1] for level in levels)
            wanted = tuple(level[2] for level in levels)
            ok = self._version_test(mine, wanted, condition(levels[0][0]))
        if ok and type_mask & 0x4:  # VER_BUILDNUMBER
            ok = self._version_test(self.OS_VERSION[2], build, condition(0x4))
        if ok and type_mask & 0x8:  # VER_PLATFORMID
            ok = self._version_test(self.OS_VERSION[3], platform, condition(0x8))
        if ok and type_mask & 0x80:  # VER_PRODUCT_TYPE
            ok = self._version_test(self.OS_PRODUCT_TYPE, product, condition(0x80))
        if ok and type_mask & 0x40:  # VER_SUITENAME: VER_AND (6) or VER_OR (7)
            if condition(0x40) == 7:
                ok = bool(self.OS_SUITE_MASK & suite)
            else:
                ok = self.OS_SUITE_MASK & suite == suite
        if not ok:
            self._last_error = 1150  # ERROR_OLD_WIN_VERSION
            return 0
        return 1

    def VerifyVersionInfoW(self, args):
        return self.VerifyVersionInfoA(args, wide=True)

    def GetProductInfo(self, args):
        """GetProductInfo(major, minor, sp major, sp minor, &type) - Ultimate"""
        return 1 if self._mem_write(args[4], struct.pack('<I', 1)) else 0

    def RtlGetVersion(self, args):
        """RtlGetVersion(RTL_OSVERSIONINFOW or EXW) - STATUS_SUCCESS"""
        size = self._read_u32(args[0])
        major, minor, build, platform = self.OS_VERSION
        data = struct.pack('<4I', major, minor, build, platform)
        data += 'Service Pack 2'.encode('utf-16-le').ljust(256, b'\x00')
        if size >= 284:  # RTL_OSVERSIONINFOEXW
            data += struct.pack('<HHHBB', *self.OS_SERVICE_PACK, self.OS_SUITE_MASK,
                                self.OS_PRODUCT_TYPE, 0)
        self._mem_write(args[0] + 4, data)
        return 0

    def RtlGetNtVersionNumbers(self, args):
        """RtlGetNtVersionNumbers(&major, &minor, &build)"""
        values = (self.OS_VERSION[0], self.OS_VERSION[1], self.OS_VERSION[2] | 0xF0000000)
        for address, value in zip(args[:3], values, strict=True):
            if address:
                self._mem_write(address, struct.pack('<I', value))
        return 0

    # The emulated Windows is 32-bit: there is no WOW64 (no 64-bit system,
    # no SysWOW64 folder, no file system or registry redirection)

    def IsWow64Process(self, args):
        """IsWow64Process - a 32-bit Windows: FALSE"""
        return 1 if self._mem_write(args[1], struct.pack('<I', 0)) else 0

    def IsWow64Process2(self, args):
        """IsWow64Process2(process, &process machine, &native machine)"""
        self._mem_write(args[1], struct.pack('<H', 0))  # IMAGE_FILE_MACHINE_UNKNOWN
        if args[2]:
            self._mem_write(args[2], struct.pack('<H', 0x14C))  # IMAGE_FILE_MACHINE_I386
        return 1

    def GetSystemWow64DirectoryA(self, args):
        """GetSystemWow64DirectoryA/W - there is none on 32-bit Windows"""
        self._last_error = 120  # ERROR_CALL_NOT_IMPLEMENTED
        return 0

    GetSystemWow64DirectoryW = GetSystemWow64DirectoryA

    def Wow64DisableWow64FsRedirection(self, args):
        """Wow64Disable/RevertWow64FsRedirection - FALSE on 32-bit Windows"""
        self._last_error = 1  # ERROR_INVALID_FUNCTION
        return 0

    Wow64RevertWow64FsRedirection = Wow64EnableWow64FsRedirection = \
        Wow64DisableWow64FsRedirection

    def GetSystemWindowsDirectoryA(self, args, wide=False):
        """GetSystemWindowsDirectoryA/W(buffer, size)"""
        return self._return_text(args[0], args[1], "C:\\Windows", wide)

    def GetSystemWindowsDirectoryW(self, args):
        return self.GetSystemWindowsDirectoryA(args, wide=True)

    def GetComputerNameExA(self, args, wide=False):
        """GetComputerNameExA/W(format, buffer, &size) - no DNS domain"""
        name_format = args[0]
        if name_format > 7:
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0
        name = '' if name_format in (2, 6) else self.COMPUTER_NAME  # ComputerNameDnsDomain
        if name_format in (1, 3, 5, 7):
            name = name.lower()  # DNS names
        # ERROR_MORE_DATA; the returned size excludes the terminator
        return self._get_name_common(name, args[1], args[2], wide, False, 234)

    def GetComputerNameExW(self, args):
        return self.GetComputerNameExA(args, wide=True)

    def GetUserDefaultUILanguage(self, args):
        return self.GetSystemDefaultLangID(args)

    def GetSystemDefaultUILanguage(self, args):
        return self.GetSystemDefaultLangID(args)

    def GetThreadLocale(self, args):
        return self.__dict__.get('_thread_locales', {}).get(self.emu.current_thread.tid,
                                                            self.GetUserDefaultLCID(args))

    def SetThreadLocale(self, args):
        self.__dict__.setdefault('_thread_locales', {})[self.emu.current_thread.tid] = args[0]
        return 1

    def GetThreadUILanguage(self, args):
        return self.GetUserDefaultUILanguage(args)

    def SetThreadUILanguage(self, args):
        return args[0] & 0xFFFF or self.GetUserDefaultUILanguage(args)

    # ---------- Processors and power ----------

    def GetCurrentProcessorNumber(self, args):
        return 0

    def GetActiveProcessorCount(self, args):
        return 1

    def GetMaximumProcessorCount(self, args):
        return 1

    def GetActiveProcessorGroupCount(self, args):
        return 1

    def GetLogicalProcessorInformation(self, args):
        """GetLogicalProcessorInformation(buffer, &size) - one core in one package"""
        # SYSTEM_LOGICAL_PROCESSOR_INFORMATION: mask, relationship, 16-byte union
        data = struct.pack('<II16s', 1, 0, b'\x00') + \
            struct.pack('<II16s', 1, 3, b'\x00')  # RelationProcessorCore, ..Package
        size = self._read_u32(args[1])
        self._mem_write(args[1], struct.pack('<I', len(data)))
        if not args[0] or size < len(data):
            self._last_error = 122  # ERROR_INSUFFICIENT_BUFFER
            return 0
        return 1 if self._mem_write(args[0], data) else 0

    def GetSystemTimes(self, args):
        """GetSystemTimes(&idle, &kernel, &user)"""
        start = getattr(self, '_process_start', None)
        if start is None:
            start = self._process_start = time.time()
        user = int(time.process_time() * 10000000)
        elapsed = int((time.time() - start) * 10000000)
        idle = max(0, elapsed - user)
        for address, value in zip(args[:3], (idle, idle, user), strict=True):
            if address:
                self._mem_write(address, struct.pack('<Q', value))
        return 1

    def GetThreadTimes(self, args):
        """GetThreadTimes(thread, &creation, &exit, &kernel, &user)"""
        if self._thread_info(args[0]) is None:
            self._last_error = 6  # ERROR_INVALID_HANDLE
            return 0
        return self.GetProcessTimes([0xFFFFFFFF] + list(args[1:5]))

    def GetProcessWorkingSetSize(self, args):
        """GetProcessWorkingSetSize(process, &minimum, &maximum) - Windows' defaults"""
        self._mem_write(args[1], struct.pack('<I', 204800))
        self._mem_write(args[2], struct.pack('<I', 1413120))
        return 1

    def GetProcessWorkingSetSizeEx(self, args):
        if args[3]:
            self._mem_write(args[3], struct.pack('<I', 0))
        return self.GetProcessWorkingSetSize(args)

    def SetProcessWorkingSetSize(self, args):
        return 1

    def SetProcessWorkingSetSizeEx(self, args):
        return 1

    def GetSystemPowerStatus(self, args):
        """GetSystemPowerStatus - on AC power, no battery"""
        return 1 if self._mem_write(args[0], struct.pack('<BBBBII', 1, 128, 255, 0,
                                                          0xFFFFFFFF, 0xFFFFFFFF)) else 0

    def SetThreadExecutionState(self, args):
        """SetThreadExecutionState - the previous state"""
        previous = self.__dict__.get('_execution_state', 0x80000000)  # ES_CONTINUOUS
        if args[0] & 0x80000000:
            self.__dict__['_execution_state'] = args[0]
        return previous

    # ---------- Files ----------

    def _file_attribute_data(self, path):
        """WIN32_FILE_ATTRIBUTE_DATA of a host path (None if it doesn't exist)"""
        try:
            st = os.stat(path)
        except OSError:
            return None
        attributes = 0x10 if os.path.isdir(path) else 0x20  # DIRECTORY / ARCHIVE
        if self._host_read_only(path):
            attributes |= 0x1  # READONLY
        size = 0 if attributes & 0x10 else st.st_size
        return struct.pack('<I3QII', attributes, self._filetime(st.st_ctime),
                           self._filetime(st.st_atime), self._filetime(st.st_mtime),
                           size >> 32, size & 0xFFFFFFFF)

    def GetFileAttributesExA(self, args, wide=False):
        """GetFileAttributesExA/W(name, GetFileExInfoStandard, data)"""
        if args[1] != 0:
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0
        path = self.resolve_drive_path(self._read_text(args[0], wide))
        data = self._file_attribute_data(path) if path is not None else None
        if data is None:
            self._last_error = 2 if path is not None else 5
            return 0
        return 1 if self._mem_write(args[2], data) else 0

    def GetFileAttributesExW(self, args):
        return self.GetFileAttributesExA(args, wide=True)

    def GetFileTime(self, args):
        """GetFileTime(file, &creation, &last access, &last write)"""
        info = self.handles.get(args[0])
        if not info or info.get('type') != 'file' or not info.get('path'):
            self._last_error = 6  # ERROR_INVALID_HANDLE
            return 0
        if info.get('fp'):
            info['fp'].flush()
        data = self._file_attribute_data(info['path'])
        if data is None:
            self._last_error = 5
            return 0
        times = struct.unpack('<3Q', data[4:28])
        for address, value in zip(args[1:4], times, strict=True):
            if address:
                self._mem_write(address, struct.pack('<Q', value))
        return 1

    def CreateDirectoryExA(self, args, wide=False):
        """CreateDirectoryExA/W(template, new directory, security)"""
        return self.CreateDirectoryA([args[1], args[2]], wide)

    def CreateDirectoryExW(self, args):
        return self.CreateDirectoryExA(args, wide=True)

    def _file_lock(self, handle):
        info = self.handles.get(handle)
        if not info or info.get('type') != 'file':
            self._last_error = 6  # ERROR_INVALID_HANDLE
            return 0
        return 1

    def LockFile(self, args):
        """LockFile/UnlockFile(Ex) - one process uses a file at a time: success"""
        return self._file_lock(args[0])

    UnlockFile = LockFileEx = UnlockFileEx = LockFile

    # ---------- Handles ----------

    def DuplicateHandle(self, args):
        """DuplicateHandle(source process, handle, target process, &target,
        access, inherit, options) - both handles share the object"""
        handle, target_addr, options = args[1], args[3], args[6]
        if handle == 0xFFFFFFFE:  # GetCurrentThread()
            info = {'type': 'thread', 'thread': self.emu.current_thread}
        elif handle == 0xFFFFFFFF:  # GetCurrentProcess()
            info = {'type': 'process', 'current': True}
        else:
            info = self.handles.get(handle)
            if info is None:
                self._last_error = 6  # ERROR_INVALID_HANDLE
                return 0
            if 'refs' in info:
                info['refs'] += 1
            else:
                info['shared'] = info.get('shared', 0) + 1
        new = self.get_next_handle()
        self.handles[new] = info
        if target_addr:
            self._mem_write(target_addr, struct.pack('<I', new))
        if options & 1 and handle in self.handles:  # DUPLICATE_CLOSE_SOURCE
            self.CloseHandle([handle])
        return 1

    def GetHandleInformation(self, args):
        """GetHandleInformation(handle, &flags)"""
        if args[0] not in self.handles and args[0] not in (0x10, 0x11, 0x12):
            self._last_error = 6
            return 0
        flags = self.handles.get(args[0], {}).get('handle_flags', 0)
        return 1 if self._mem_write(args[1], struct.pack('<I', flags)) else 0

    def SetHandleInformation(self, args):
        """SetHandleInformation(handle, mask, flags)"""
        info = self.handles.get(args[0])
        if info is None:
            if args[0] in (0x10, 0x11, 0x12):
                return 1
            self._last_error = 6
            return 0
        info['handle_flags'] = (info.get('handle_flags', 0) & ~args[1]) | (args[2] & args[1])
        return 1

    def GetProcessId(self, args):
        """GetProcessId(process)"""
        if args[0] == 0xFFFFFFFF:
            return self.GetCurrentProcessId(args)
        info = self.handles.get(args[0])
        if not info or info.get('type') != 'process':
            self._last_error = 6
            return 0
        if info.get('current'):
            return self.GetCurrentProcessId(args)
        child = info.get('emulator')
        handler = getattr(child, 'api_handler', None) if child is not None else None
        return handler.GetCurrentProcessId([]) if handler else 0

    def GetThreadId(self, args):
        """GetThreadId(thread)"""
        thread = self._thread_info(args[0])
        if thread is None:
            self._last_error = 6
            return 0
        return thread.tid

    def GetProcessIdOfThread(self, args):
        if self._thread_info(args[0]) is None:
            self._last_error = 6
            return 0
        return self.GetCurrentProcessId(args)

    def GetProcessVersion(self, args):
        """GetProcessVersion(pid) - the EXE's subsystem version"""
        try:
            header = self.emu.pe_loader.pe.OPTIONAL_HEADER
            return (header.MajorSubsystemVersion << 16) | header.MinorSubsystemVersion
        except AttributeError:
            return 0x00040000

    # ---------- Memory ----------

    def LocalReAlloc(self, args):
        """LocalReAlloc/GlobalReAlloc(memory, size, flags)"""
        memory, size, flags = args[0], args[1], args[2]
        if flags & 0x80:  # LMEM_MODIFY / GMEM_MODIFY: only the flags change
            return memory
        old_size = self.emu.heap_block_size(memory) if memory else None
        if old_size is None:
            self._last_error = 6  # ERROR_INVALID_HANDLE
            return 0
        if self.emu.heap_resize_last(memory, size):
            new = memory
        elif not flags & 0x2:  # LMEM_MOVEABLE: may not move without it
            if size <= old_size:
                return memory
            self._last_error = 8  # ERROR_NOT_ENOUGH_MEMORY
            return 0
        else:
            new = self.emu.heap_alloc(size)
            if not new:
                self._last_error = 8
                return 0
            self._mem_write(new, self.emu.uc.mem_read(memory, min(old_size, size)))
            self.emu.heap_free(memory)
        if flags & 0x40 and size > old_size:  # LMEM_ZEROINIT
            self._mem_write(new + old_size, b'\x00' * (size - old_size))
        return new

    def GlobalReAlloc(self, args):
        """GlobalReAlloc(memory, size, flags) - GMEM_* flags are the LMEM_* ones"""
        return self.LocalReAlloc(args)

    def LocalSize(self, args):
        return self.GlobalSize(args)

    def LocalLock(self, args):
        return self.GlobalLock(args)

    def LocalUnlock(self, args):
        """LocalUnlock/GlobalUnlock - FALSE: the block is not locked any more"""
        self._last_error = 0
        return 0

    def LocalFlags(self, args):
        if not args[0] or self.emu.heap_block_size(args[0]) is None:
            self._last_error = 6
            return 0x8000  # LMEM_INVALID_HANDLE
        return 0

    def GlobalFlags(self, args):
        return self.LocalFlags(args)

    def LocalHandle(self, args):
        return args[0]

    def GlobalHandle(self, args):
        return args[0]

    def LocalCompact(self, args):
        return self._memory_status()[1]

    def GlobalCompact(self, args):
        return self._memory_status()[1]

    def LocalShrink(self, args):
        return self._memory_status()[1]

    def GlobalWire(self, args):
        return args[0]

    def GlobalUnWire(self, args):
        return 1

    def GlobalFix(self, args):
        return 0

    def GlobalUnfix(self, args):
        return 0

    def HeapValidate(self, args):
        """HeapValidate(heap, flags, block) - TRUE for the whole heap or a block of it"""
        return 1 if not args[2] or self.emu.heap_block_size(args[2]) is not None else 0

    def HeapCompact(self, args):
        return self._memory_status()[1]

    def HeapLock(self, args):
        return 1

    def HeapUnlock(self, args):
        return 1

    def HeapWalk(self, args):
        self._last_error = 259  # ERROR_NO_MORE_ITEMS
        return 0

    def HeapSetInformation(self, args):
        return 1

    def HeapQueryInformation(self, args):
        """HeapQueryInformation(heap, class, info, size, &needed) - the
        low-fragmentation heap (HeapCompatibilityInformation)"""
        if args[1] != 0:
            self._last_error = 87
            return 0
        if args[4]:
            self._mem_write(args[4], struct.pack('<I', 4))
        if args[3] < 4:
            self._last_error = 24  # ERROR_BAD_LENGTH
            return 0
        return 1 if self._mem_write(args[2], struct.pack('<I', 2)) else 0

    def GetProcessHeaps(self, args):
        """GetProcessHeaps(count, heaps[]) - the process heap"""
        if args[0] >= 1 and args[1]:
            self._mem_write(args[1], struct.pack('<I', self.emu.process_heap))
        return 1

    def _range_access(self, address, size, write=False, execute=False):
        """Can a guest range be read (written, run)? False for unmapped pages"""
        if size == 0:
            return True
        end = address + size
        if not address or end > 0x100000000:
            return False
        needed = UC_PROT_READ | (UC_PROT_WRITE if write else 0) | \
            (UC_PROT_EXEC if execute else 0)
        position = address
        for begin, last, perms in sorted(self.emu.uc.mem_regions()):
            if last < position:
                continue
            if begin > position or perms & needed != needed:
                return False
            position = last + 1
            if position >= end:
                return True
        return False

    def IsBadReadPtr(self, args):
        return 0 if self._range_access(args[0], args[1]) else 1

    def IsBadWritePtr(self, args):
        return 0 if self._range_access(args[0], args[1], write=True) else 1

    def IsBadCodePtr(self, args):
        return 0 if self._range_access(args[0], 1) else 1

    def IsBadHugeReadPtr(self, args):
        return self.IsBadReadPtr(args)

    def IsBadHugeWritePtr(self, args):
        return self.IsBadWritePtr(args)

    def IsBadStringPtrA(self, args, wide=False):
        """IsBadStringPtrA/W(string, max characters)"""
        if not args[0]:
            return 1
        unit = 2 if wide else 1
        data = self._read_until_null(args[0], min(args[1], 0x100000) * unit, unit)
        return 1 if data is None else 0

    def IsBadStringPtrW(self, args):
        return self.IsBadStringPtrA(args, wide=True)

    def VirtualLock(self, args):
        return 1

    def VirtualUnlock(self, args):
        return 1

    def FlushInstructionCache(self, args):
        return 1

    def SleepEx(self, args):
        """SleepEx(ms, alertable) - no APCs are queued: 0"""
        return self.Sleep(args)

    def lstrcpynW(self, args):
        """lstrcpynW(dest, src, count) - at most count-1 characters and a NUL"""
        if args[2] > 0:
            self._write_units(args[0], self._read_units(args[1], True)[:args[2] - 1], True)
        return args[0]

    # ---------- 16-bit file functions (HFILE) ----------

    HFILE_ERROR = 0xFFFFFFFF

    def _open_hfile(self, address, access, disposition):
        name = self.read_string(address)
        handle = self._create_file_common(name, access, disposition)
        return self.HFILE_ERROR if handle == 0xFFFFFFFF else handle

    @staticmethod
    def _of_access(mode):
        return {0: 0x80000000, 1: 0x40000000, 2: 0xC0000000}.get(mode & 3, 0x80000000)

    def _lopen(self, args):
        """_lopen(path, OF_READ/OF_WRITE/OF_READWRITE | sharing)"""
        return self._open_hfile(args[0], self._of_access(args[1]), 3)

    def _lcreat(self, args):
        """_lcreat(path, attributes) - created or truncated, read/write"""
        return self._open_hfile(args[0], 0xC0000000, 2)

    def _hfile_io(self, handle, buffer, count, write):
        counter = self.emu.heap_alloc(4)
        try:
            api = self.WriteFile if write else self.ReadFile
            if not api([handle, buffer, count, counter, 0]):
                return self.HFILE_ERROR
            return self._read_u32(counter)
        finally:
            self.emu.heap_free(counter)

    def _lread(self, args):
        return self._hfile_io(args[0], args[1], args[2], False)

    def _hread(self, args):
        return self._lread(args)

    def _lwrite(self, args):
        """_lwrite(file, buffer, count) - a count of 0 truncates at the position"""
        if args[2] == 0:
            return 0 if self.SetEndOfFile([args[0]]) else self.HFILE_ERROR
        return self._hfile_io(args[0], args[1], args[2], True)

    def _hwrite(self, args):
        return self._lwrite(args)

    def _llseek(self, args):
        """_llseek(file, offset, origin) - the new position"""
        return self.SetFilePointer([args[0], args[1], 0, args[2]])

    def _lclose(self, args):
        if args[0] not in self.handles:
            return self.HFILE_ERROR
        self.CloseHandle([args[0]])
        return 0

    def OpenFile(self, args):
        """OpenFile(path, OFSTRUCT, style) - OF_EXIST, OF_DELETE, OF_PARSE,
        OF_CREATE and the access modes"""
        address, ofs, style = args[0], args[1], args[2]
        name = self.read_string(address)
        full = self.full_windows_path(name) or name
        path = self.resolve_drive_path(full)

        def report(error):
            data = struct.pack('<BBHHH', 136, 1, error, 0, 0)
            data += full.encode('ascii', errors='replace')[:127].ljust(128, b'\x00')
            self._mem_write(ofs, data)

        if style & 0x100:  # OF_PARSE
            report(0)
            return 0
        if path is None:
            report(5)
            self._last_error = 5
            return self.HFILE_ERROR
        if style & 0x200:  # OF_DELETE
            ok = self.DeleteFileA([address])
            report(0 if ok else self._last_error)
            return 1 if ok else self.HFILE_ERROR
        if style & 0x1000:  # OF_CREATE
            handle = self._open_hfile(address, 0xC0000000, 2)
        else:
            handle = self._open_hfile(address, self._of_access(style), 3)
        if handle == self.HFILE_ERROR:
            report(self._last_error)
            return self.HFILE_ERROR
        report(0)
        if style & 0x4000:  # OF_EXIST: only tests, the file is closed
            self.CloseHandle([handle])
            return 1
        return handle

    # ---------- Console extras ----------

    def _console_output_handle(self, handle):
        if not self._is_console_handle(handle) or handle == 0x10:
            self._last_error = 6  # ERROR_INVALID_HANDLE
            return False
        return True

    def GetConsoleWindow(self, args):
        console = self.console
        return console.hwnd if console is not None else 0

    def SetConsoleTextAttribute(self, args):
        """SetConsoleTextAttribute - the console shows one color: accepted"""
        if not self._console_output_handle(args[0]):
            return 0
        self.__dict__['_console_attribute'] = args[1] & 0xFFFF
        return 1

    def SetConsoleCursorPosition(self, args):
        return 1 if self._console_output_handle(args[0]) else 0

    def GetConsoleCursorInfo(self, args):
        """GetConsoleCursorInfo(console, &CONSOLE_CURSOR_INFO) - 25%, visible"""
        if not self._console_output_handle(args[0]):
            return 0
        return 1 if self._mem_write(args[1], struct.pack('<II', 25, 1)) else 0

    def SetConsoleCursorInfo(self, args):
        return 1 if self._console_output_handle(args[0]) else 0

    def FillConsoleOutputCharacterA(self, args):
        """FillConsoleOutputCharacterA/W, FillConsoleOutputAttribute(console,
        value, count, COORD, &written)"""
        if not self._console_output_handle(args[0]):
            return 0
        if args[4]:
            self._mem_write(args[4], struct.pack('<I', args[2]))
        return 1

    FillConsoleOutputCharacterW = FillConsoleOutputAttribute = FillConsoleOutputCharacterA

    def GetConsoleTitleA(self, args, wide=False):
        """GetConsoleTitleA/W(buffer, size) - the console window's title"""
        if not self.has_console:
            self._last_error = 6
            return 0
        title = self.windows_exe_path()
        console = self.console
        if console is not None and self.gui:
            win = self.gui.windows.get(console.hwnd)
            if win is not None:
                title = win.title
        if not args[0] or not args[1]:
            return 0
        units = self._text_units(title, wide)[:args[1] - 1]
        self._write_units(args[0], units, wide)
        return len(units)

    def GetConsoleTitleW(self, args):
        return self.GetConsoleTitleA(args, wide=True)

    def SetConsoleCP(self, args):
        return 1 if self.IsValidCodePage(args) else 0

    def SetConsoleOutputCP(self, args):
        return self.SetConsoleCP(args)

    def FlushConsoleInputBuffer(self, args):
        return 1 if self._is_console_handle(args[0]) else 0

    def GetNumberOfConsoleInputEvents(self, args):
        if not self._is_console_handle(args[0]):
            self._last_error = 6
            return 0
        return 1 if self._mem_write(args[1], struct.pack('<I', 0)) else 0

    def SetConsoleScreenBufferSize(self, args):
        return 1 if self._console_output_handle(args[0]) else 0

    def SetConsoleWindowInfo(self, args):
        return 1 if self._console_output_handle(args[0]) else 0

    def GetLargestConsoleWindowSize(self, args):
        """GetLargestConsoleWindowSize - a COORD (80 x 50) in EAX"""
        if not self._console_output_handle(args[0]):
            return 0
        return 80 | (50 << 16)

    def GenerateConsoleCtrlEvent(self, args):
        return 1

    def AttachConsole(self, args):
        """AttachConsole - no other process has a console to share"""
        self._last_error = 5 if self.has_console else 6
        return 0

    # ---------- ntdll ----------

    def RtlZeroMemory(self, args):
        if args[1]:
            self._mem_write(args[0], b'\x00' * args[1])
        return 0

    def RtlFillMemory(self, args):
        """RtlFillMemory(destination, length, byte)"""
        if args[1]:
            self._mem_write(args[0], bytes([args[2] & 0xFF]) * args[1])
        return 0

    def RtlMoveMemory(self, args):
        """RtlMoveMemory/RtlCopyMemory(destination, source, length)"""
        if args[2]:
            self._mem_write(args[0], self.emu.uc.mem_read(args[1], args[2]))
        return 0

    RtlCopyMemory = RtlMoveMemory

    def RtlCompareMemory(self, args):
        """RtlCompareMemory(a, b, length) - the length of the equal prefix"""
        first = bytes(self.emu.uc.mem_read(args[0], args[2])) if args[2] else b''
        second = bytes(self.emu.uc.mem_read(args[1], args[2])) if args[2] else b''
        for i, (x, y) in enumerate(zip(first, second, strict=False)):
            if x != y:
                return i
        return args[2]

    # NTSTATUS -> Win32 error (RtlNtStatusToDosError)
    NTSTATUS_ERRORS = {
        0x00000000: 0, 0x00000103: 997, 0x80000005: 234, 0x8000001A: 259,
        0xC0000001: 31, 0xC0000002: 1, 0xC0000005: 998, 0xC0000008: 6, 0xC000000D: 87,
        0xC000000F: 2, 0xC0000011: 38, 0xC0000017: 8, 0xC0000022: 5, 0xC0000023: 122,
        0xC0000033: 123, 0xC0000034: 2, 0xC0000035: 183, 0xC000003A: 3, 0xC0000043: 32,
        0xC0000054: 33, 0xC000007F: 112, 0xC00000BA: 5, 0xC00000BB: 50, 0xC0000101: 145,
        0xC0000120: 995, 0xC0000135: 126, 0xC0000139: 127, 0xC0000225: 1168,
    }

    def RtlNtStatusToDosError(self, args):
        status = args[0]
        if status in self.NTSTATUS_ERRORS:
            return self.NTSTATUS_ERRORS[status]
        if status & 0xFFFF0000 == 0x80070000 or status & 0xFFFF0000 == 0xC0070000:
            return status & 0xFFFF  # HRESULT_FROM_WIN32 / NTSTATUS_FROM_WIN32
        return 317  # ERROR_MR_MID_NOT_FOUND

    def RtlGetLastWin32Error(self, args):
        return self._last_error

    def RtlSetLastWin32Error(self, args):
        self._last_error = args[0]
        return 0

    def _init_counted_string(self, address, source, wide):
        """UNICODE_STRING/ANSI_STRING {Length, MaximumLength, Buffer}"""
        unit = 2 if wide else 1
        length = len(self._read_units(source, wide)) * unit if source else 0
        maximum = length + unit if source else 0
        self._mem_write(address, struct.pack('<HHI', length & 0xFFFF, maximum & 0xFFFF, source))
        return 0

    def RtlInitUnicodeString(self, args):
        return self._init_counted_string(args[0], args[1], True)

    def RtlInitAnsiString(self, args):
        return self._init_counted_string(args[0], args[1], False)

    def RtlInitString(self, args):
        return self._init_counted_string(args[0], args[1], False)

    def NtClose(self, args):
        """NtClose - STATUS_SUCCESS or STATUS_INVALID_HANDLE"""
        if args[0] not in self.handles:
            return 0xC0000008
        self.CloseHandle(args)
        return 0

    def NtQuerySystemTime(self, args):
        self.GetSystemTimeAsFileTime(args)
        return 0

    def RtlRandom(self, args):
        """RtlRandom(&seed) - the next value of the seed's generator"""
        seed = self._read_u32(args[0])
        seed = (seed * 0x7FFFFFED + 0x7FFFFFC3) % 0x7FFFFFFF
        self._mem_write(args[0], struct.pack('<I', seed))
        return seed

    RtlRandomEx = RtlRandom

    def RtlUniform(self, args):
        return self.RtlRandom(args)

    def NtYieldExecution(self, args):
        self.SwitchToThread(args)
        return 0

    def NtDelayExecution(self, args):
        """NtDelayExecution(alertable, &interval) - negative: relative 100 ns units"""
        interval = struct.unpack('<q', self.emu.uc.mem_read(args[1], 8))[0]
        if interval < 0:
            self.Sleep([min(-interval // 10000, 0xFFFFFFFF)])
        return 0
