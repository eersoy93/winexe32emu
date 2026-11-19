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

"""WinAPIHandler mixin: Vista+ kernel32 APIs (used by the Visual C++ 2015+ runtime)"""

import os
import struct

from unicorn import UcError

from ..logger import log


class Kernel32VistaMixin:
    """Vista+ kernel32 APIs (used by the Visual C++ 2015+ runtime)"""

    # ---------- Vista+ kernel32 APIs (used by the Visual C++ 2015+ runtime) ----------

    def EncodePointer(self, args):
        """EncodePointer emulation - pointers are kept as they are"""
        return args[0]

    def DecodePointer(self, args):
        return args[0]

    def EncodeSystemPointer(self, args):
        return args[0]

    def DecodeSystemPointer(self, args):
        return args[0]

    # Fiber local storage: there are no fibers, so FLS slots are TLS slots

    def FlsAlloc(self, args):
        """FlsAlloc emulation - a TLS slot; the callback runs at FlsFree"""
        index = self.TlsAlloc(args)
        if index != 0xFFFFFFFF and args[0]:
            self.fls_callbacks[index] = args[0]
        return index

    def FlsFree(self, args):
        """FlsFree emulation - the callback gets the calling thread's value"""
        callback = self.fls_callbacks.pop(args[0], None)
        value = self.TlsGetValue(args) if args[0] in self.tls_used else 0
        if not self.TlsFree(args):
            return 0
        if callback and value:
            self.emu.call_callback(callback, [value])
        return 1

    def FlsGetValue(self, args):
        return self.TlsGetValue(args)

    def FlsSetValue(self, args):
        return self.TlsSetValue(args)

    # Interlocked singly linked lists: SLIST_HEADER is {Next, Depth, Sequence}

    def _slist_header(self, head):
        try:
            return struct.unpack('<IHH', self.emu.uc.mem_read(head, 8))
        except UcError:
            return None

    def InitializeSListHead(self, args):
        self._mem_write(args[0], b'\x00' * 8)
        return 0

    def InterlockedPushEntrySList(self, args):
        """InterlockedPushEntrySList emulation - the previous first entry"""
        head, entry = args[0], args[1]
        header = self._slist_header(head)
        if header is None:
            return 0
        first, depth, sequence = header
        self._mem_write(entry, struct.pack('<I', first))
        self._mem_write(head, struct.pack('<IHH', entry, (depth + 1) & 0xFFFF,
                                          (sequence + 1) & 0xFFFF))
        return first

    def InterlockedPopEntrySList(self, args):
        """InterlockedPopEntrySList emulation - the removed entry (NULL if empty)"""
        header = self._slist_header(args[0])
        if header is None or not header[0]:
            return 0
        first, depth, sequence = header
        self._mem_write(args[0], struct.pack('<IHH', self._read_u32(first),
                                             max(depth - 1, 0), (sequence + 1) & 0xFFFF))
        return first

    def InterlockedFlushSList(self, args):
        """InterlockedFlushSList emulation - the whole list (NULL if empty)"""
        header = self._slist_header(args[0])
        if header is None:
            return 0
        self._mem_write(args[0], struct.pack('<IHH', 0, 0, (header[2] + 1) & 0xFFFF))
        return header[0]

    def QueryDepthSList(self, args):
        header = self._slist_header(args[0])
        return header[1] if header else 0

    # Slim reader/writer locks and condition variables (the guest threads run
    # one at a time, so the state is kept here; waiting lets the others run)

    def _try_srw(self, address, shared):
        lock = self.srw_locks.setdefault(address, {'owner': None, 'shared': 0})
        if lock['owner'] is not None and not self._thread_alive(lock['owner']):
            lock['owner'] = None
        if lock['owner'] is not None:
            return False
        if shared:
            lock['shared'] += 1
            return True
        if lock['shared']:
            return False
        lock['owner'] = self.emu.current_thread.tid
        return True

    def InitializeSRWLock(self, args):
        self.srw_locks.pop(args[0], None)
        self._mem_write(args[0], b'\x00' * 4)
        return 0

    def AcquireSRWLockExclusive(self, args):
        """AcquireSRWLockExclusive emulation - waits while others hold the lock"""
        self.emu.wait_until(lambda: self._try_srw(args[0], False))
        return 0

    def AcquireSRWLockShared(self, args):
        """AcquireSRWLockShared emulation - waits while a writer holds the lock"""
        self.emu.wait_until(lambda: self._try_srw(args[0], True))
        return 0

    def TryAcquireSRWLockExclusive(self, args):
        return 1 if self._try_srw(args[0], False) else 0

    def TryAcquireSRWLockShared(self, args):
        return 1 if self._try_srw(args[0], True) else 0

    def ReleaseSRWLockExclusive(self, args):
        lock = self.srw_locks.get(args[0])
        if lock is not None and lock['owner'] == self.emu.current_thread.tid:
            lock['owner'] = None
            self.emu.wake_threads()
        return 0

    def ReleaseSRWLockShared(self, args):
        lock = self.srw_locks.get(args[0])
        if lock is not None and lock['shared'] > 0:
            lock['shared'] -= 1
            if not lock['shared']:
                self.emu.wake_threads()
        return 0

    def InitializeConditionVariable(self, args):
        self.condition_variables.pop(args[0], None)
        self._mem_write(args[0], b'\x00' * 4)
        return 0

    def _sleep_condition_variable(self, cv, release, reacquire, timeout):
        """Release a lock, wait for a wake-up (or the timeout), take the lock back"""
        token = {'woken': False}
        waiters = self.condition_variables.setdefault(cv, [])
        waiters.append(token)
        state = release()
        woken = self.emu.wait_until(lambda: token['woken'], timeout)
        if not woken:
            waiters[:] = [t for t in waiters if t is not token]
        reacquire(state)
        if not woken:
            self._last_error = 1460  # ERROR_TIMEOUT
            return 0
        return 1

    def SleepConditionVariableCS(self, args):
        """SleepConditionVariableCS emulation (cv, critical section, timeout)"""
        cv, cs, timeout = args[0], args[1], args[2]
        tid = self.emu.current_thread.tid

        def release():
            owner = self.critical_sections.pop(cs, None)
            self.emu.wake_threads()
            return owner[1] if owner is not None and owner[0] == tid else 1

        def reacquire(count):
            if self.emu.wait_until(lambda: self._try_enter_cs(cs)):
                self.critical_sections[cs][1] = count
        return self._sleep_condition_variable(cv, release, reacquire, timeout)

    def SleepConditionVariableSRW(self, args):
        """SleepConditionVariableSRW emulation (cv, SRW lock, timeout, flags)"""
        cv, srw, timeout, shared = args[0], args[1], args[2], bool(args[3] & 1)

        def release():
            if shared:
                self.ReleaseSRWLockShared([srw])
            else:
                self.ReleaseSRWLockExclusive([srw])

        def reacquire(_):
            self.emu.wait_until(lambda: self._try_srw(srw, shared))
        return self._sleep_condition_variable(cv, release, reacquire, timeout)

    def WakeConditionVariable(self, args):
        waiters = self.condition_variables.get(args[0])
        if waiters:
            waiters.pop(0)['woken'] = True
            self.emu.wake_threads()
        return 0

    def WakeAllConditionVariable(self, args):
        waiters = self.condition_variables.get(args[0])
        if waiters:
            for token in waiters:
                token['woken'] = True
            waiters.clear()
            self.emu.wake_threads()
        return 0

    # INIT_ONCE: 0 = not run, 1 = running, (context & ~3) | 2 = done

    def InitOnceInitialize(self, args):
        self._mem_write(args[0], b'\x00' * 4)
        return 0

    def InitOnceExecuteOnce(self, args):
        """InitOnceExecuteOnce emulation - runs InitFn once (other threads wait)"""
        init_once, init_fn, parameter, lpContext = args[:4]
        self.emu.wait_until(lambda: self._read_u32(init_once) & 3 != 1)
        state = self._read_u32(init_once)
        if state & 3 == 2:
            if lpContext:
                self._mem_write(lpContext, struct.pack('<I', state & ~3))
            return 1
        self._mem_write(init_once, struct.pack('<I', 1))
        cell = self.emu.heap_alloc(4)
        self._mem_write(cell, b'\x00' * 4)
        ok = False
        try:
            ok = self.emu.call_callback(init_fn, [init_once, parameter, cell]) != 0
        finally:
            value = self._read_u32(cell)
            self.emu.heap_free(cell)
            self._mem_write(init_once, struct.pack('<I', (value & ~3) | 2 if ok else 0))
            self.emu.wake_threads()
        if not ok:
            return 0
        if lpContext:
            self._mem_write(lpContext, struct.pack('<I', value))
        return 1

    # Memory: page protections are enforced (CPUEmulator.protect_range);
    # page_protections remembers them for VirtualQuery. Protection 0 marks
    # reserved, not committed pages.

    PAGE_EXECUTE_READWRITE = 0x40

    def _memory_region(self, address):
        """(start, end) of the mapped memory region holding address, or None"""
        for start, end, _ in self.emu.uc.mem_regions():
            if start <= address <= end:
                return start, end + 1
        return None

    def _image_ranges(self):
        """[(base, end)] of the EXE and the loaded DLLs"""
        pe = self.emu.pe_loader
        ranges = [(pe.image_base, pe.image_base + pe.pe.OPTIONAL_HEADER.SizeOfImage)]
        ranges += [(m['base'], m['base'] + m['size']) for m in self.emu.dlls.values()]
        ranges += [(m['base'], m['base'] + m['size'])
                   for m in self.emu.system_modules.values()]
        return ranges

    def _module_at(self, address):
        """HMODULE of the EXE or DLL image holding address, or 0"""
        for start, end in self._image_ranges():
            if start <= address < end:
                return start
        return 0

    def _page_protection(self, page):
        for start, end, protection in reversed(self.page_protections):
            if start <= page < end:
                return protection
        return self.PAGE_EXECUTE_READWRITE

    def record_protection(self, start, end, protection):
        """Remember the protection of the pages [start, end) for VirtualQuery
        (ranges it covers are forgotten, others are cut around it)"""
        kept = []
        for r_start, r_end, r_prot in self.page_protections:
            if r_end <= start or r_start >= end:
                kept.append((r_start, r_end, r_prot))
                continue
            if r_start < start:
                kept.append((r_start, start, r_prot))
            if r_end > end:
                kept.append((end, r_end, r_prot))
        if protection != self.PAGE_EXECUTE_READWRITE:
            kept.append((start, end, protection))
        self.page_protections = kept

    def set_protection(self, start, end, protection):
        """Enforce and remember a page protection; False if not all mapped"""
        if not self.emu.protect_range(start, end, protection):
            return False
        self.record_protection(start, end, protection)
        return True

    @staticmethod
    def valid_protection(protection):
        """Exactly one PAGE_* access value, with PAGE_GUARD, PAGE_NOCACHE or
        PAGE_WRITECOMBINE at most"""
        base = protection & 0xFF
        return (base in (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80) and
                not protection & ~0x7FF)

    def VirtualProtect(self, args):
        """VirtualProtect emulation - enforced on the pages (an access they
        forbid is an access violation); returns the old protection"""
        address, size, protection, lpflOldProtect = args[:4]
        if not lpflOldProtect:
            self._last_error = 998  # ERROR_NOACCESS
            return 0
        if not self.valid_protection(protection):
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0
        start = address & ~0xFFF
        end = (address + size + 0xFFF) & ~0xFFF
        if (not size or self._memory_region(address) is None or
                any(self._page_protection(page) == 0 for page in range(start, end, 0x1000))):
            self._last_error = 487  # ERROR_INVALID_ADDRESS (or not committed)
            return 0
        old = self._page_protection(start)
        if not self.set_protection(start, end, protection):
            self._last_error = 487
            return 0
        self._mem_write(lpflOldProtect, struct.pack('<I', old))
        return 1

    def VirtualProtectEx(self, args):
        if args[0] != 0xFFFFFFFF:  # only the own process
            self._last_error = 5  # ERROR_ACCESS_DENIED
            return 0
        return self.VirtualProtect(args[1:])

    def VirtualQuery(self, args):
        """VirtualQuery emulation - fills MEMORY_BASIC_INFORMATION (28 bytes)"""
        address, lpBuffer, length = args[:3]
        if length < 28:
            self._last_error = 24  # ERROR_BAD_LENGTH
            return 0
        if address >= 0x7FFF0000:
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0
        page = address & ~0xFFF
        region = self._memory_region(address)
        if region is None:
            following = [start for start, _, _ in self.emu.uc.mem_regions() if start > page]
            end = min(following + [0x7FFF0000])
            # MEM_FREE, PAGE_NOACCESS
            info = (page, 0, 0, end - page, 0x10000, 0x01, 0)
        else:
            start, end = region
            allocation_base, kind = start, 0x20000  # MEM_PRIVATE
            for base, size in self.virtual_allocs.items():
                if base <= address < base + size:
                    allocation_base, end = base, min(end, base + size)
                    break
            image = self._module_at(address)
            if image:
                allocation_base, kind = image, 0x1000000  # MEM_IMAGE
            # The region ends where the protection changes
            for r_start, r_end, _ in self.page_protections:
                for edge in (r_start, r_end):
                    if page < edge < end:
                        end = edge
            protection = self._page_protection(page)
            state = 0x1000 if protection else 0x2000  # MEM_COMMIT / MEM_RESERVE
            info = (page, allocation_base, self.PAGE_EXECUTE_READWRITE, end - page,
                    state, protection, kind)
        if not self._mem_write(lpBuffer, struct.pack('<7I', *info)):
            self._last_error = 998  # ERROR_NOACCESS
            return 0
        return 28

    def VirtualQueryEx(self, args):
        if args[0] != 0xFFFFFFFF:
            self._last_error = 5
            return 0
        return self.VirtualQuery(args[1:])

    def SetThreadStackGuarantee(self, args):
        """SetThreadStackGuarantee emulation - the previous guarantee is 0"""
        if args[0]:
            self._mem_write(args[0], b'\x00' * 4)
        return 1

    def GetNativeSystemInfo(self, args):
        """GetNativeSystemInfo emulation - a 32-bit Windows (same as GetSystemInfo)"""
        return self.GetSystemInfo(args)

    def GetSystemTimePreciseAsFileTime(self, args):
        return self.GetSystemTimeAsFileTime(args)

    # Modules

    def GetModuleHandleExA(self, args, wide=False):
        """GetModuleHandleExA/W emulation (flags, name or address, phModule)"""
        flags, name, phModule = args[:3]
        if not phModule:
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0
        if flags & 4:  # GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
            module = self._module_at(name)
        elif name:
            module = (self.GetModuleHandleW if wide else self.GetModuleHandleA)([name])
        else:
            module = self.emu.pe_loader.image_base
        self._mem_write(phModule, struct.pack('<I', module))
        if not module:
            self._last_error = 126  # ERROR_MOD_NOT_FOUND
            return 0
        return 1

    def GetModuleHandleExW(self, args):
        return self.GetModuleHandleExA(args, wide=True)

    def RtlPcToFileHeader(self, args):
        """RtlPcToFileHeader emulation - image base of the module holding PcValue"""
        base = self._module_at(args[0])
        self._mem_write(args[1], struct.pack('<I', base))
        return base

    def RtlCaptureContext(self, args):
        """RtlCaptureContext emulation - the caller's registers (CONTEXT_FULL),
        EIP/ESP as after the return"""
        esp = self.emu.api_call_esp
        self._write_context(args[0], self.capture_context(eip=self._read_u32(esp),
                                                          esp=esp + 8))
        return 0

    # Vectored exception handlers run before the SEH frames (dispatch_exception)

    def AddVectoredExceptionHandler(self, args):
        """AddVectoredExceptionHandler(First, Handler) emulation"""
        handle = self.get_next_handle()
        if args[0]:  # called first
            self.vectored_handlers = {handle: args[1], **self.vectored_handlers}
        else:
            self.vectored_handlers[handle] = args[1]
        log.debug(f"AddVectoredExceptionHandler(0x{args[1]:08x}) -> 0x{handle:x}")
        return handle

    def RemoveVectoredExceptionHandler(self, args):
        return 1 if self.vectored_handlers.pop(args[0], None) is not None else 0

    # Console and misc

    def SetStdHandle(self, args):
        """SetStdHandle emulation - GetStdHandle returns the new handle"""
        if args[0] not in (0xFFFFFFF6, 0xFFFFFFF5, 0xFFFFFFF4):
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0
        self.std_handles[args[0]] = args[1]
        return 1

    def GetConsoleCP(self, args):
        """GetConsoleCP emulation - the emulated console uses the ANSI code page"""
        return self._ansi_codepage_number()

    def GetConsoleOutputCP(self, args):
        return self._ansi_codepage_number()

    def IsValidCodePage(self, args):
        """IsValidCodePage emulation - code pages Python has a codec for"""
        if args[0] in (0, 1, 2, 3, 42):  # CP_ACP & co. are not code pages
            return 0
        return 1 if self._codepage_name(args[0]) else 0

    def OutputDebugStringA(self, args, wide=False):
        """OutputDebugStringA/W emulation - shown in the debug log"""
        log.debug(f"OutputDebugString: {self._read_text(args[0], wide).rstrip()}")
        return 0

    def OutputDebugStringW(self, args):
        return self.OutputDebugStringA(args, wide=True)

    def FindFirstFileExA(self, args, wide=False):
        """FindFirstFileExA/W emulation - FindFirstFile (the search limits are hints)"""
        return self.FindFirstFileA([args[0], args[2]], wide=wide)

    def FindFirstFileExW(self, args):
        return self.FindFirstFileExA(args, wide=True)

    def CreateSemaphoreExW(self, args):
        return self.CreateSemaphoreA(args[:4], wide=True)

    def CreateMutexExW(self, args):
        # CREATE_MUTEX_INITIAL_OWNER (1) in dwFlags
        return self.CreateMutexA([args[0], args[2] & 1, args[1]], wide=True)

    def SystemFunction036(self, args):
        """SystemFunction036 (RtlGenRandom) emulation - host random bytes"""
        return 1 if self._mem_write(args[0], os.urandom(args[1])) else 0
