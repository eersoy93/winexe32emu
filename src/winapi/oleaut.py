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

"""WinAPIHandler mixin: OLEAUT32 BSTR and VARIANT; waits, events, mutexes, semaphores"""

import struct

from unicorn import *

from .. import winapi
from ..logger import log


class OleAutMixin:
    """OLEAUT32 BSTR and VARIANT; waits, events, mutexes, semaphores"""

    # ---------- OLEAUT32: BSTR and VARIANT ----------

    def _alloc_bstr(self, data):
        """BSTR holding raw bytes: length prefix, data, wide NUL"""
        block = self.emu.heap_alloc(4 + len(data) + 2)
        if not block:
            return 0
        self.emu.uc.mem_write(block, struct.pack('<I', len(data)) + data + b'\x00\x00')
        return block + 4

    def SysAllocString(self, args):
        """SysAllocString emulation"""
        if not args[0]:
            return 0
        return self._alloc_bstr(self.read_wide_string(args[0]).encode('utf-16-le'))

    def SysAllocStringLen(self, args):
        """SysAllocStringLen emulation (pch may be NULL: uninitialized)"""
        pch, length = args[0], args[1]
        if length >= 0x10000000:
            return 0
        data = bytes(self.emu.uc.mem_read(pch, length * 2)) if pch and length else b'\x00' * (length * 2)
        return self._alloc_bstr(data)

    def SysAllocStringByteLen(self, args):
        """SysAllocStringByteLen emulation"""
        psz, length = args[0], args[1]
        if length >= 0x10000000:
            return 0
        data = bytes(self.emu.uc.mem_read(psz, length)) if psz and length else b'\x00' * length
        bstr = self._alloc_bstr(data)
        if bstr:
            self.emu.uc.mem_write(bstr + length, b'\x00')
        return bstr

    def SysReAllocString(self, args):
        """SysReAllocString emulation"""
        new = self.SysAllocString([args[1]])
        if not new and args[1]:
            return 0
        self.SysFreeString([struct.unpack('<I', self.emu.uc.mem_read(args[0], 4))[0]])
        self.emu.uc.mem_write(args[0], struct.pack('<I', new))
        return 1

    def SysReAllocStringLen(self, args):
        """SysReAllocStringLen emulation"""
        new = self.SysAllocStringLen([args[1], args[2]])
        if not new:
            return 0
        self.SysFreeString([struct.unpack('<I', self.emu.uc.mem_read(args[0], 4))[0]])
        self.emu.uc.mem_write(args[0], struct.pack('<I', new))
        return 1

    def SysFreeString(self, args):
        """SysFreeString emulation"""
        if args[0]:
            self.emu.heap_free(args[0] - 4)
        return 0

    def SysStringByteLen(self, args):
        """SysStringByteLen emulation"""
        if not args[0]:
            return 0
        return struct.unpack('<I', self.emu.uc.mem_read(args[0] - 4, 4))[0]

    def SysStringLen(self, args):
        """SysStringLen emulation"""
        return self.SysStringByteLen(args) // 2

    VT_BSTR, VT_DISPATCH, VT_UNKNOWN, VT_BYREF = 8, 9, 13, 0x4000

    def _com_call(self, interface, index, *call_args):
        """Call method index of a COM interface pointer (stdcall, this first)"""
        vtable = struct.unpack('<I', self.emu.uc.mem_read(interface, 4))[0]
        method = struct.unpack('<I', self.emu.uc.mem_read(vtable + 4 * index, 4))[0]
        return self.emu.call_callback(method, [interface, *call_args])

    def VariantInit(self, args):
        """VariantInit emulation - VT_EMPTY"""
        self._mem_write(args[0], b'\x00' * 16)
        return 0

    def VariantClear(self, args):
        """VariantClear emulation - frees a BSTR, releases an interface"""
        if not args[0]:
            return 0x80070057  # E_INVALIDARG
        vt, _, _, _, value = struct.unpack('<HHHHI', self.emu.uc.mem_read(args[0], 12))
        if not vt & self.VT_BYREF:
            if vt == self.VT_BSTR:
                self.SysFreeString([value])
            elif vt in (self.VT_DISPATCH, self.VT_UNKNOWN) and value:
                self._com_call(value, 2)  # Release
        self.emu.uc.mem_write(args[0], b'\x00' * 16)
        return 0

    def VariantCopy(self, args):
        """VariantCopy emulation - copies BSTRs, AddRefs interfaces"""
        dest, src = args[0], args[1]
        if dest == src:
            return 0
        data = bytes(self.emu.uc.mem_read(src, 16))
        self.VariantClear([dest])
        vt, value = struct.unpack_from('<H', data)[0], struct.unpack_from('<I', data, 8)[0]
        if not vt & self.VT_BYREF:
            if vt == self.VT_BSTR and value:
                copy = self._alloc_bstr(bytes(self.emu.uc.mem_read(
                    value, self.SysStringByteLen([value]))))
                if not copy:
                    return 0x8007000E  # E_OUTOFMEMORY
                data = data[:8] + struct.pack('<I', copy) + data[12:]
            elif vt in (self.VT_DISPATCH, self.VT_UNKNOWN) and value:
                self._com_call(value, 1)  # AddRef
        self.emu.uc.mem_write(dest, data)
        return 0

    def _thread_alive(self, tid):
        thread = self.emu.threads.get(tid)
        return thread is not None and not thread.exited

    def _wait_objects(self, handles, wait_all, timeout):
        """WaitForSingleObject/WaitForMultipleObjects core: WAIT_OBJECT_0 + i,
        WAIT_TIMEOUT or WAIT_FAILED"""
        infos = []
        for handle in handles:
            if handle == 0xFFFFFFFF:  # GetCurrentProcess(): never signaled
                infos.append({'type': 'event', 'manual': True, 'signaled': False})
                continue
            info = self.handles.get(handle)
            if info is None:
                self._last_error = 6  # ERROR_INVALID_HANDLE
                return 0xFFFFFFFF
            infos.append(info)
        result = []

        def ready():
            if wait_all:
                if all(self._object_signaled(info, False) for info in infos):
                    for info in infos:
                        self._object_signaled(info, True)
                    result.append(0)
                    return True
                return False
            for index, info in enumerate(infos):
                if self._object_signaled(info, True):
                    result.append(index)
                    return True
            return False

        if self.emu.wait_until(ready, timeout):
            return result[0]
        if self.emu.stop_emulation:
            return 0xFFFFFFFF
        return 0x102  # WAIT_TIMEOUT

    def WaitForSingleObject(self, args):
        """WaitForSingleObject emulation - other threads run while waiting"""
        handle, timeout = args[0], args[1]
        log.debug(f"WaitForSingleObject(0x{handle:x}, {timeout})")
        return self._wait_objects([handle], False, timeout)

    def WaitForSingleObjectEx(self, args):
        return self._wait_objects([args[0]], False, args[1])

    def WaitForMultipleObjects(self, args):
        """WaitForMultipleObjects emulation"""
        count, lpHandles, wait_all, timeout = args[:4]
        if not 0 < count <= 64:
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0xFFFFFFFF
        handles = struct.unpack(f'<{count}I', self.emu.uc.mem_read(lpHandles, 4 * count))
        log.debug(f"WaitForMultipleObjects({[hex(h) for h in handles]}, all={wait_all}, {timeout})")
        return self._wait_objects(handles, bool(wait_all), timeout)

    def WaitForMultipleObjectsEx(self, args):
        return self.WaitForMultipleObjects(args)

    # Named kernel objects are shared by all emulated programs (like the
    # session namespace of Windows): name -> object info (the same dict is in
    # the handle tables of every process that opened it)
    named_kernel_objects = {}

    def _named_object(self, lpName, kind, wide, create):
        """Handle of a new or existing named kernel object; create() makes new info"""
        name = self._read_text(lpName, wide) if lpName else ''
        key = name.split('\\', 1)[1] if name.lower().startswith(('global\\', 'local\\')) \
            else name
        if name:
            info = winapi.WinAPIHandler.named_kernel_objects.get(key)
            if info is not None:
                if info.get('type') != kind:
                    self._last_error = 6  # ERROR_INVALID_HANDLE
                    return 0
                handle = self.get_next_handle()
                self.handles[handle] = info
                info['refs'] = info.get('refs', 0) + 1
                self._last_error = 183  # ERROR_ALREADY_EXISTS
                return handle
        info = create()
        info['type'] = kind
        info['refs'] = 1
        if name:
            info['object_name'] = key
            winapi.WinAPIHandler.named_kernel_objects[key] = info
        handle = self.get_next_handle()
        self.handles[handle] = info
        self._last_error = 0
        return handle

    def _open_named_object(self, lpName, kind, wide):
        """OpenEvent/OpenMutex/OpenSemaphore/OpenFileMapping: handle or 0"""
        name = self._read_text(lpName, wide) if lpName else ''
        key = name.split('\\', 1)[1] if name.lower().startswith(('global\\', 'local\\')) \
            else name
        info = winapi.WinAPIHandler.named_kernel_objects.get(key)
        if info is None:
            self._last_error = 2  # ERROR_FILE_NOT_FOUND
            return 0
        if info.get('type') != kind:
            self._last_error = 6  # ERROR_INVALID_HANDLE
            return 0
        handle = self.get_next_handle()
        self.handles[handle] = info
        info['refs'] = info.get('refs', 0) + 1
        self._last_error = 0
        return handle

    def OpenEventA(self, args, wide=False):
        return self._open_named_object(args[2], 'event', wide)

    def OpenEventW(self, args):
        return self.OpenEventA(args, wide=True)

    def OpenMutexA(self, args, wide=False):
        return self._open_named_object(args[2], 'mutex', wide)

    def OpenMutexW(self, args):
        return self.OpenMutexA(args, wide=True)

    def OpenSemaphoreA(self, args, wide=False):
        return self._open_named_object(args[2], 'semaphore', wide)

    def OpenSemaphoreW(self, args):
        return self.OpenSemaphoreA(args, wide=True)

    def OpenFileMappingA(self, args, wide=False):
        return self._open_named_object(args[2], 'mapping', wide)

    def OpenFileMappingW(self, args):
        return self.OpenFileMappingA(args, wide=True)

    def CreateEventA(self, args, wide=False):
        """CreateEventA/W emulation"""
        manual, initial, lpName = args[1], args[2], args[3]
        handle = self._named_object(lpName, 'event', wide, lambda: {
            'manual': bool(manual), 'signaled': bool(initial)})
        log.debug(f"CreateEvent(manual={manual}, initial={initial}) -> 0x{handle:x}")
        return handle

    def CreateEventW(self, args):
        return self.CreateEventA(args, wide=True)

    def CreateEventExW(self, args):
        flags = args[2]
        return self.CreateEventA([0, flags & 1, flags & 2, args[1]], wide=True)

    def _event(self, handle):
        info = self.handles.get(handle)
        if not info or info.get('type') != 'event':
            self._last_error = 6  # ERROR_INVALID_HANDLE
            return None
        return info

    def SetEvent(self, args):
        """SetEvent emulation"""
        info = self._event(args[0])
        if info is None:
            return 0
        info['signaled'] = True
        self.emu.wake_threads()
        return 1

    def ResetEvent(self, args):
        """ResetEvent emulation"""
        info = self._event(args[0])
        if info is None:
            return 0
        info['signaled'] = False
        return 1

    def PulseEvent(self, args):
        """PulseEvent emulation - wakes the waiting threads (approximation:
        they get the signal at their next check)"""
        info = self._event(args[0])
        if info is None:
            return 0
        info['signaled'] = True
        self.emu.wake_threads()
        self.emu.idle_wait(0.001)
        info['signaled'] = False
        return 1

    def CreateSemaphoreA(self, args, wide=False):
        """CreateSemaphoreA/W emulation"""
        initial, maximum, lpName = args[1], args[2], args[3]
        if maximum <= 0 or maximum >= 0x80000000 or initial > maximum:
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0
        return self._named_object(lpName, 'semaphore', wide, lambda: {
            'count': initial, 'max': maximum})

    def CreateSemaphoreW(self, args):
        return self.CreateSemaphoreA(args, wide=True)

    def ReleaseSemaphore(self, args):
        """ReleaseSemaphore emulation"""
        handle, release, lpPrevious = args[0], args[1], args[2]
        info = self.handles.get(handle)
        if not info or info.get('type') != 'semaphore':
            self._last_error = 6  # ERROR_INVALID_HANDLE
            return 0
        if info['count'] + release > info['max']:
            self._last_error = 298  # ERROR_TOO_MANY_POSTS
            return 0
        if lpPrevious:
            self._mem_write(lpPrevious, struct.pack('<I', info['count']))
        info['count'] += release
        self.emu.wake_threads()
        return 1

    def CreateMutexA(self, args, wide=False):
        """CreateMutexA/W emulation"""
        initial_owner, lpName = args[1], args[2]
        tid = self.emu.current_thread.tid
        return self._named_object(lpName, 'mutex', wide, lambda: {
            'owner': tid if initial_owner else 0, 'count': 1 if initial_owner else 0})

    def CreateMutexW(self, args):
        return self.CreateMutexA(args, wide=True)

    def ReleaseMutex(self, args):
        """ReleaseMutex emulation"""
        info = self.handles.get(args[0])
        if not info or info.get('type') != 'mutex':
            self._last_error = 6  # ERROR_INVALID_HANDLE
            return 0
        if info['owner'] != self.emu.current_thread.tid:
            self._last_error = 288  # ERROR_NOT_OWNER
            return 0
        info['count'] -= 1
        if info['count'] <= 0:
            info['owner'], info['count'] = 0, 0
            self.emu.wake_threads()
        return 1

    def _start_thread(self, start, param, stack_size, flags, lpThreadId):
        """Create a guest thread; returns its handle or 0"""
        thread = self.emu.create_thread(start, param, stack_size,
                                        suspended=bool(flags & 0x4))  # CREATE_SUSPENDED
        if thread is None:
            self._last_error = 8  # ERROR_NOT_ENOUGH_MEMORY
            return 0
        handle = self.get_next_handle()
        thread.handle = handle
        self.handles[handle] = {'type': 'thread', 'thread': thread}
        if lpThreadId:
            self._mem_write(lpThreadId, struct.pack('<I', thread.tid))
        log.debug(f"Thread created: start 0x{start:08x} -> handle 0x{handle:x}, id {thread.tid}")
        return handle

    def CreateThread(self, args):
        """CreateThread emulation"""
        return self._start_thread(args[2], args[3], args[1], args[4], args[5])

    def _beginthreadex(self, args):
        """_beginthreadex emulation (cdecl)"""
        return self._start_thread(args[2], args[3], args[1], args[4], args[5])

    def _thread_info(self, handle):
        if handle == 0xFFFFFFFE:  # GetCurrentThread()
            return self.emu.current_thread
        info = self.handles.get(handle)
        if info and info.get('type') == 'thread' and 'thread' in info:
            return info['thread']
        return None

    def ResumeThread(self, args):
        """ResumeThread emulation - previous suspend count"""
        thread = self._thread_info(args[0])
        if thread is None:
            self._last_error = 6  # ERROR_INVALID_HANDLE
            return 0xFFFFFFFF
        previous = thread.suspend_count
        if previous:
            thread.suspend_count -= 1
            self.emu.wake_threads()
        return previous

    def SuspendThread(self, args):
        """SuspendThread emulation - only not yet started threads can be held"""
        thread = self._thread_info(args[0])
        if thread is None:
            self._last_error = 6  # ERROR_INVALID_HANDLE
            return 0xFFFFFFFF
        previous = thread.suspend_count
        thread.suspend_count += 1
        return previous

    def GetExitCodeThread(self, args):
        """GetExitCodeThread emulation - STILL_ACTIVE (259) while it runs"""
        thread = self._thread_info(args[0])
        if thread is None:
            info = self.handles.get(args[0])
            if info and info.get('type') == 'thread' and 'emulator' in info:
                return self.GetExitCodeProcess(args)
            self._last_error = 6  # ERROR_INVALID_HANDLE
            return 0
        code = thread.exit_code if thread.exited else 259
        return 1 if self._mem_write(args[1], struct.pack('<I', code & 0xFFFFFFFF)) else 0

    def ExitThread(self, args):
        """ExitThread emulation (the main thread ends the process)"""
        if not self.emu.exit_current_thread(args[0]):
            return self.ExitProcess(args)
        return 0

    def _endthreadex(self, args):
        """_endthreadex emulation"""
        return self.ExitThread(args)

    def _endthread(self, args):
        """_endthread emulation"""
        return self.ExitThread([0])

    def GetCurrentThread(self, args):
        """GetCurrentThread emulation - the pseudo handle"""
        return 0xFFFFFFFE

    def SetThreadPriority(self, args):
        return 1

    def GetThreadPriority(self, args):
        return 0

    def SetThreadAffinityMask(self, args):
        """SetThreadAffinityMask emulation - previous mask (one processor)"""
        return 1 if args[1] & 1 else 0

    def GetProcessAffinityMask(self, args):
        """GetProcessAffinityMask emulation - one processor"""
        self._mem_write(args[1], struct.pack('<I', 1))
        self._mem_write(args[2], struct.pack('<I', 1))
        return 1

    def SetPriorityClass(self, args):
        return 1

    def GetPriorityClass(self, args):
        return 0x20  # NORMAL_PRIORITY_CLASS

    # Thread local storage: slot values live in each thread's TEB (TlsSlots)
    TLS_SLOTS = 64
    TEB_TLS_SLOTS = 0xE10

    def TlsAlloc(self, args):
        """TlsAlloc emulation - a free slot index (TLS_OUT_OF_INDEXES if none)"""
        for index in range(self.TLS_SLOTS):
            if index not in self.tls_used:
                self.tls_used.add(index)
                for thread in list(self.emu.threads.values()):
                    teb = thread.teb or self.emu.teb_addr
                    self._mem_write(teb + self.TEB_TLS_SLOTS + 4 * index, b'\x00' * 4)
                return index
        self._last_error = 8  # ERROR_NOT_ENOUGH_MEMORY
        return 0xFFFFFFFF

    def TlsFree(self, args):
        if args[0] not in self.tls_used:
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0
        self.tls_used.discard(args[0])
        return 1

    def _tls_slot(self, index):
        if index not in self.tls_used:
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0
        thread = self.emu.current_thread
        return (thread.teb or self.emu.teb_addr) + self.TEB_TLS_SLOTS + 4 * index

    def TlsGetValue(self, args):
        """TlsGetValue emulation - the calling thread's value"""
        slot = self._tls_slot(args[0])
        if not slot:
            return 0
        self._last_error = 0
        return self._read_u32(slot)

    def TlsSetValue(self, args):
        """TlsSetValue emulation"""
        slot = self._tls_slot(args[0])
        if not slot:
            return 0
        self._mem_write(slot, struct.pack('<I', args[1]))
        return 1

    def SwitchToThread(self, args):
        """SwitchToThread emulation - let another thread run"""
        self.emu.idle_wait(0.0005)
        return 1

    def InterlockedIncrement(self, args):
        """InterlockedIncrement emulation (threads never run at the same time)"""
        value = (struct.unpack('<I', self.emu.uc.mem_read(args[0], 4))[0] + 1) & 0xFFFFFFFF
        self.emu.uc.mem_write(args[0], struct.pack('<I', value))
        return value

    def InterlockedDecrement(self, args):
        """InterlockedDecrement emulation"""
        value = (struct.unpack('<I', self.emu.uc.mem_read(args[0], 4))[0] - 1) & 0xFFFFFFFF
        self.emu.uc.mem_write(args[0], struct.pack('<I', value))
        return value

    def InterlockedExchange(self, args):
        """InterlockedExchange emulation - previous value"""
        previous = struct.unpack('<I', self.emu.uc.mem_read(args[0], 4))[0]
        self.emu.uc.mem_write(args[0], struct.pack('<I', args[1]))
        return previous

    def InterlockedExchangeAdd(self, args):
        """InterlockedExchangeAdd emulation - previous value"""
        previous = struct.unpack('<I', self.emu.uc.mem_read(args[0], 4))[0]
        self.emu.uc.mem_write(args[0], struct.pack('<I', (previous + args[1]) & 0xFFFFFFFF))
        return previous

    def InterlockedCompareExchange(self, args):
        """InterlockedCompareExchange emulation - previous value"""
        previous = struct.unpack('<I', self.emu.uc.mem_read(args[0], 4))[0]
        if previous == args[2]:
            self.emu.uc.mem_write(args[0], struct.pack('<I', args[1]))
        return previous

    def RaiseException(self, args):
        """RaiseException emulation - dispatched to the program's exception
        handlers (debugger notifications are ignored: there is no debugger)"""
        code, flags, count, lpArguments = args[:4]
        if code in (0x406D1388, 0x40010006, 0x4001000A):  # thread name, debug string
            return 0
        count = min(count, 15)
        try:
            params = list(struct.unpack(f'<{count}I', self.emu.uc.mem_read(lpArguments, 4 * count))
                          ) if count and lpArguments else []
        except UcError:
            params = []
        if (code == self.CXX_EXCEPTION and len(params) > 2 and not params[1] and
                not params[2]):
            # "throw;" of a static C++ runtime: rethrow the exception being handled
            params = self._cxx_rethrow_params() or params
        log.debug(f"RaiseException(0x{code:08x}, flags 0x{flags:x}, {params})")
        return self.raise_guest_exception(code, flags & self.EXCEPTION_NONCONTINUABLE,
                                          params, 16)

    def HeapSize(self, args):
        """HeapSize emulation - usable size of a heap block"""
        size = self.emu.heap_block_size(args[2]) if args[2] else None
        return 0xFFFFFFFF if size is None else size
