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

"""WinAPIHandler mixin: ILockBytes (CreateILockBytesOnHGlobal) and the
compound files kept in one (StgCreateDocfileOnILockBytes & co)"""

import struct

from unicorn import UcError

from ..logger import log
from . import compound_file
from .com import ComMixin

ComMixin.COM_INTERFACES.update({
    # ReadAt, WriteAt, SetSize, LockRegion: ULARGE_INTEGERs take two DWORDs
    'lock_bytes': [
        ('QueryInterface', 3), ('AddRef', 1), ('Release', 1), ('ReadAt', 6),
        ('WriteAt', 6), ('Flush', 1), ('SetSize', 3), ('LockRegion', 6),
        ('UnlockRegion', 6), ('Stat', 3)],
})


class OleLockBytesMixin:
    """ILockBytes on global memory and docfiles on ILockBytes"""

    IID_ILOCKBYTES = '0000000a-0000-0000-c000-000000000046'

    def CreateILockBytesOnHGlobal(self, args):
        """CreateILockBytesOnHGlobal(hGlobal, fDeleteOnRelease, pplkbyt) - an
        ILockBytes whose bytes are kept in the global memory block"""
        handle, delete, out = args[:3]
        if not out:
            return self.E_INVALIDARG
        entry = compound_file.Entry('', False)
        if handle:
            size = self._hglobal_size(handle)
            if size is None:
                return self.E_INVALIDARG
            entry.data = bytearray(self.emu.uc.mem_read(self._hglobal_pointer(handle), size)) \
                if size else bytearray()
        else:
            handle = self.GlobalAlloc([0x2, 1])  # GMEM_MOVEABLE
            if not handle:
                return 0x8007000E  # E_OUTOFMEMORY
        pointers = self._com_new_object(
            [((self.IID_ILOCKBYTES, self.IID_IUNKNOWN),
              self._com_vtable('ILockBytes', 'lock_bytes'))],
            {'kind': 'lock_bytes', 'entry': entry,
             'info': {'hglobal': handle, 'hglobal_delete': bool(delete)}})
        return self._return_object(pointers[self.IID_ILOCKBYTES], out)

    def GetHGlobalFromILockBytes(self, args):
        """GetHGlobalFromILockBytes(plkbyt, phglobal)"""
        state = self._com_state(args[0], 'lock_bytes')
        if state is None:
            return self.E_INVALIDARG
        self._sync_hglobal(state)
        return self.S_OK if self._mem_write(args[1], struct.pack('<I', state['info']['hglobal'])) \
            else self.E_INVALIDARG

    def _com_lock_bytes(self, method, wide, args):
        """ILockBytes methods of the global memory one"""
        state = self.com_objects.get(args[0])
        if method == 'Release' and state is not None and state['refs'] == 1 and \
                state['info']['hglobal_delete'] and state['info']['hglobal']:
            self.GlobalFree([state['info']['hglobal']])
            state['info']['hglobal'] = 0
        result = self._com_unknown(method, args)
        if result is not None:
            return result
        data = state['entry'].data
        if method in ('ReadAt', 'WriteAt'):
            offset = args[1] | (args[2] << 32)
            buffer, count, done = args[3], args[4], args[5]
            if method == 'ReadAt':
                chunk = bytes(data[offset:offset + count])
                if chunk:
                    self._mem_write(buffer, chunk)
                moved = len(chunk)
            else:
                chunk = bytes(self.emu.uc.mem_read(buffer, count)) if count else b''
                if offset > len(data):
                    data.extend(b'\x00' * (offset - len(data)))
                data[offset:offset + len(chunk)] = chunk
                moved = len(chunk)
                if not self._sync_hglobal(state):
                    return 0x80030008  # STG_E_MEDIUMFULL
            if done:
                self._mem_write(done, struct.pack('<I', moved))
            return self.S_OK
        if method == 'SetSize':
            size = args[1] | (args[2] << 32)
            if size < len(data):
                del data[size:]
            else:
                data.extend(b'\x00' * (size - len(data)))
            return self.S_OK if self._sync_hglobal(state) else 0x80030008
        if method == 'Stat':
            # STATSTG: no name, STGTY_LOCKBYTES, the size
            statstg = struct.pack('<IIQ', 0, 3, len(data)) + b'\x00' * 52
            return self.S_OK if self._mem_write(args[1], statstg) else self.STG_E_INVALIDPOINTER
        if method in ('Flush', 'LockRegion', 'UnlockRegion'):
            return self.S_OK
        return self.E_NOTIMPL

    # ---------- Reading and writing any ILockBytes ----------

    def _lockbytes_read_all(self, pointer):
        """(HRESULT, bytes) of all of an ILockBytes (the program's or ours)"""
        state = self._com_state(pointer, 'lock_bytes')
        if state is not None:
            return self.S_OK, bytes(state['entry'].data)
        statstg = self.emu.heap_alloc(80)
        try:
            self._mem_write(statstg, b'\x00' * 80)
            result = self._guest_method(pointer, 9, [statstg, 1])  # Stat, STATFLAG_NONAME
            if result & 0x80000000:
                return result, b''
            size = struct.unpack('<Q', self.emu.uc.mem_read(statstg + 8, 8))[0]
        finally:
            self.emu.heap_free(statstg)
        if not size:
            return self.S_OK, b''
        memory = self.emu.heap_alloc(size + 4)
        try:
            result = self._guest_method(pointer, 3, [0, 0, memory, size, memory + size])
            done = self._read_u32(memory + size) if not result & 0x80000000 else 0
            return result, bytes(self.emu.uc.mem_read(memory, done)) if done else b''
        finally:
            self.emu.heap_free(memory)

    def _lockbytes_write_all(self, pointer, data):
        """Replace the bytes of an ILockBytes; an HRESULT"""
        state = self._com_state(pointer, 'lock_bytes')
        if state is not None:
            state['entry'].data[:] = data
            return self.S_OK if self._sync_hglobal(state) else 0x80030008
        memory = self.emu.heap_alloc(len(data) + 4)
        try:
            self._mem_write(memory, data)
            result = self._guest_method(pointer, 4, [0, 0, memory, len(data),
                                                     memory + len(data)])  # WriteAt
            if not result & 0x80000000:
                result = self._guest_method(pointer, 6, [len(data), 0])  # SetSize
            return result
        finally:
            self.emu.heap_free(memory)

    def _new_lockbytes_docfile(self, pointer, root, mode, dirty):
        info = {'path': None, 'host': None, 'root': root, 'lockbytes': pointer,
                'delete': False, 'transacted': bool(mode & self.STGM_TRANSACTED),
                'opens': 0, 'dirty': dirty}
        # The docfile holds a reference until its last IStorage is released
        if self._com_state(pointer, 'lock_bytes') is None:
            self._guest_method(pointer, 1, [])  # AddRef
        else:
            self._com_unknown('AddRef', [pointer])
        return info

    def _release_lockbytes(self, pointer):
        if self._com_state(pointer, 'lock_bytes') is None:
            self._guest_method(pointer, 2, [])  # Release
        else:
            self._com_lock_bytes('Release', False, [pointer])

    def StgCreateDocfileOnILockBytes(self, args):
        """StgCreateDocfileOnILockBytes(plkbyt, grfMode, reserved, ppstgOpen)"""
        pointer, mode, _, out = args[:4]
        if not out or not pointer:
            return self.STG_E_INVALIDPOINTER
        self._mem_write(out, b'\x00' * 4)
        root = compound_file.Entry('Root Entry', True)
        root.ctime = root.mtime = self._filetime_now()
        info = self._new_lockbytes_docfile(pointer, root, mode, True)
        if not self._save_docfile(info):
            return self.STG_E_WRITEFAULT
        writable = bool(mode & (self.STGM_WRITE | self.STGM_READWRITE))
        log.debug(f"StgCreateDocfileOnILockBytes(0x{pointer:x}, 0x{mode:x})")
        return self._return_object(self._new_storage_object(root, info, writable, top=True), out)

    def StgOpenStorageOnILockBytes(self, args):
        """StgOpenStorageOnILockBytes(plkbyt, pstgPriority, grfMode, snbExclude,
        reserved, ppstgOpen)"""
        pointer, _, mode, _, _, out = args[:6]
        if not out or not pointer:
            return self.STG_E_INVALIDPOINTER
        self._mem_write(out, b'\x00' * 4)
        result, data = self._lockbytes_read_all(pointer)
        if result & 0x80000000:
            return result
        if not compound_file.is_compound_file(data):
            return self.STG_E_FILEALREADYEXISTS
        try:
            root = compound_file.load(data)
        except (compound_file.CompoundFileError, struct.error, IndexError, UcError) as e:
            log.debug(f"StgOpenStorageOnILockBytes: {e}")
            return self.STG_E_DOCFILECORRUPT
        info = self._new_lockbytes_docfile(pointer, root, mode, False)
        writable = bool(mode & (self.STGM_WRITE | self.STGM_READWRITE))
        return self._return_object(self._new_storage_object(root, info, writable, top=True), out)

    def StgIsStorageILockBytes(self, args):
        """StgIsStorageILockBytes(plkbyt) - S_OK for a compound file, else S_FALSE"""
        result, data = self._lockbytes_read_all(args[0]) if args[0] else (self.E_INVALIDARG, b'')
        if result & 0x80000000:
            return result
        return self.S_OK if compound_file.is_compound_file(data) else self.S_FALSE
