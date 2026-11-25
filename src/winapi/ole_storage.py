# Copyright 2026 Erdem Ersoy (eersoy93)
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

"""WinAPIHandler mixin: OLE structured storage - compound files (docfiles)
as IStorage and IStream objects, streams on global memory, and the ole32
helpers that read and write class IDs, user types and conversion flags"""

import os
import struct
import time

from unicorn import UcError

from ..logger import log
from . import compound_file


class OleStorageMixin:
    """StgCreateDocfile, StgOpenStorage, IStorage, IStream, IEnumSTATSTG,
    CreateStreamOnHGlobal, ReadClassStg & co, OleSave"""

    IID_ISTORAGE = '0000000b-0000-0000-c000-000000000046'
    IID_ISTREAM = '0000000c-0000-0000-c000-000000000046'
    IID_ISEQUENTIALSTREAM = '0c733a30-2a1c-11ce-ade5-00aa0044773a'
    IID_IENUMSTATSTG = '0000000d-0000-0000-c000-000000000046'

    STG_E_INVALIDFUNCTION = 0x80030001
    STG_E_FILENOTFOUND = 0x80030002
    STG_E_PATHNOTFOUND = 0x80030003
    STG_E_ACCESSDENIED = 0x80030005
    STG_E_INVALIDPOINTER = 0x80030009
    STG_E_WRITEFAULT = 0x8003001D
    STG_E_FILEALREADYEXISTS = 0x80030050
    STG_E_INVALIDPARAMETER = 0x80030057
    STG_E_INVALIDNAME = 0x800300FC
    STG_E_DOCFILECORRUPT = 0x80030109

    STGM_WRITE, STGM_READWRITE = 0x1, 0x2
    STGM_CREATE, STGM_TRANSACTED, STGM_CONVERT = 0x1000, 0x10000, 0x20000
    STGM_DELETEONRELEASE = 0x04000000
    STGTY_STORAGE, STGTY_STREAM = 1, 2

    COM_INTERFACES_STORAGE = {
        'storage': [
            ('QueryInterface', 3), ('AddRef', 1), ('Release', 1), ('CreateStream', 6),
            ('OpenStream', 6), ('CreateStorage', 6), ('OpenStorage', 7), ('CopyTo', 5),
            ('MoveElementTo', 5), ('Commit', 2), ('Revert', 1), ('EnumElements', 5),
            ('DestroyElement', 2), ('RenameElement', 3), ('SetElementTimes', 5),
            ('SetClass', 2), ('SetStateBits', 3), ('Stat', 3)],
        # Seek, SetSize, CopyTo, LockRegion: 64-bit arguments take two DWORDs
        'stream': [
            ('QueryInterface', 3), ('AddRef', 1), ('Release', 1), ('Read', 4), ('Write', 4),
            ('Seek', 5), ('SetSize', 3), ('CopyTo', 6), ('Commit', 2), ('Revert', 1),
            ('LockRegion', 6), ('UnlockRegion', 6), ('Stat', 3), ('Clone', 2)],
        'enum_statstg': [
            ('QueryInterface', 3), ('AddRef', 1), ('Release', 1), ('Next', 4), ('Skip', 2),
            ('Reset', 1), ('Clone', 2)],
    }

    def _storage_interfaces(self):
        for kind, methods in self.COM_INTERFACES_STORAGE.items():
            self.COM_INTERFACES.setdefault(kind, methods)

    # ---------- Calls into the program's own COM objects ----------

    def _guest_method(self, pointer, index, args):
        """Call method index of the vtable of a COM object of the program"""
        try:
            vtable = self._read_u32(pointer)
            function = self._read_u32(vtable + 4 * index)
        except UcError:
            return self.E_POINTER
        return self.emu.call_callback(function, [pointer] + list(args)) & 0xFFFFFFFF

    def _com_state(self, pointer, kind):
        """The state of an emulated COM object of a kind, None for others"""
        state = self.com_objects.get(pointer)
        return state if state is not None and state.get('kind') == kind else None

    # ---------- Docfiles: the open compound files ----------

    def _docfile_name(self, name):
        """(Windows path, host path, error) of a docfile name"""
        full = self.full_windows_path(name) if name else None
        host = self.resolve_drive_path(full) if full else None
        if host is None:
            return None, None, self.STG_E_INVALIDNAME
        if not os.path.isdir(os.path.dirname(host)):
            return full, host, self.STG_E_PATHNOTFOUND
        return full, host, 0

    def _save_docfile(self, info):
        """Write a docfile's tree to its file; False if it cannot be written"""
        if info.get('lockbytes'):  # A docfile on an ILockBytes (OleLockBytesMixin)
            if self._lockbytes_write_all(info['lockbytes'],
                                         compound_file.save(info['root'])) & 0x80000000:
                return False
            info['dirty'] = False
            return True
        if info['host'] is None or info['delete']:
            return True
        try:
            data = compound_file.save(info['root'])
            with open(info['host'], 'wb') as f:
                f.write(data)
        except OSError as e:
            log.debug(f"Cannot write the docfile {info['path']}: {e}")
            return False
        info['dirty'] = False
        return True

    def _new_storage_object(self, entry, info, writable, top=False):
        """An IStorage of an entry of the docfile info; returns its pointer"""
        self._storage_interfaces()
        if top:
            info['opens'] += 1
        pointers = self._com_new_object(
            [((self.IID_ISTORAGE, self.IID_IUNKNOWN), self._com_vtable('IStorage', 'storage',
                                                                       wide=True))],
            {'kind': 'storage', 'entry': entry, 'info': info, 'writable': writable,
             'top': top})
        return pointers[self.IID_IUNKNOWN]

    def _new_stream_object(self, entry, info, writable, position=0, hglobal=False):
        """An IStream of a stream entry (hglobal: on global memory, whose block
        is info['hglobal']); returns its pointer"""
        self._storage_interfaces()
        pointers = self._com_new_object(
            [((self.IID_ISTREAM, self.IID_ISEQUENTIALSTREAM, self.IID_IUNKNOWN),
              self._com_vtable('IStream', 'stream', wide=True))],
            {'kind': 'stream', 'entry': entry, 'info': info, 'writable': writable,
             'pos': position, 'hglobal': hglobal})
        return pointers[self.IID_IUNKNOWN]

    def _return_object(self, pointer, out):
        if not self._mem_write(out, struct.pack('<I', pointer)):
            self._com_unknown('Release', [pointer])
            return self.STG_E_INVALIDPOINTER
        return self.S_OK

    @staticmethod
    def _filetime_now():
        return int(time.time() * 10_000_000) + 116444736000000000

    def StgCreateDocfile(self, args):
        """StgCreateDocfile(pwcsName, grfMode, reserved, ppstgOpen) - a new
        compound file; without a name a temporary one (kept in memory)"""
        name_ptr, mode, _, out = args[:4]
        if not out:
            return self.STG_E_INVALIDPOINTER
        self._mem_write(out, b'\x00' * 4)
        writable = bool(mode & (self.STGM_WRITE | self.STGM_READWRITE))
        if name_ptr:
            full, host, error = self._docfile_name(self.read_wide_string(name_ptr))
            if error:
                return error
            if self._write_protected(host):
                return self.STG_E_ACCESSDENIED
            if os.path.exists(host) and not mode & (self.STGM_CREATE | self.STGM_CONVERT):
                return self.STG_E_FILEALREADYEXISTS
            delete = bool(mode & self.STGM_DELETEONRELEASE)
        else:
            self._temp_docfiles = getattr(self, '_temp_docfiles', 0) + 1
            full, host, delete = f'C:\\Windows\\Temp\\~DF{self._temp_docfiles:04X}.tmp', None, True
        root = compound_file.Entry('Root Entry', True)
        root.ctime = root.mtime = self._filetime_now()
        info = {'path': full, 'host': host, 'root': root, 'delete': delete,
                'transacted': bool(mode & self.STGM_TRANSACTED), 'opens': 0, 'dirty': True}
        if host is not None and not delete and not self._save_docfile(info):
            return self.STG_E_ACCESSDENIED
        log.debug(f"StgCreateDocfile({full!r}, 0x{mode:x})")
        return self._return_object(self._new_storage_object(root, info, writable, top=True), out)

    def StgOpenStorage(self, args):
        """StgOpenStorage(pwcsName, pstgPriority, grfMode, snbExclude,
        reserved, ppstgOpen)"""
        name_ptr, priority, mode, _, _, out = args[:6]
        if not out:
            return self.STG_E_INVALIDPOINTER
        self._mem_write(out, b'\x00' * 4)
        writable = bool(mode & (self.STGM_WRITE | self.STGM_READWRITE))
        if not name_ptr:
            state = self._com_state(priority, 'storage')
            if state is None:
                return self.STG_E_INVALIDNAME
            info = state['info']
            return self._return_object(
                self._new_storage_object(info['root'], info, writable, top=True), out)
        full, host, error = self._docfile_name(self.read_wide_string(name_ptr))
        if error:
            return error if error != self.STG_E_PATHNOTFOUND else self.STG_E_FILENOTFOUND
        if not os.path.isfile(host):
            return self.STG_E_FILENOTFOUND
        if writable and self._host_read_only(host):
            return self.STG_E_ACCESSDENIED
        try:
            with open(host, 'rb') as f:
                data = f.read()
        except OSError:
            return self.STG_E_ACCESSDENIED
        if not compound_file.is_compound_file(data):
            return self.STG_E_FILEALREADYEXISTS  # What Windows says for other files
        try:
            root = compound_file.load(data)
        except (compound_file.CompoundFileError, struct.error, IndexError) as e:
            log.debug(f"StgOpenStorage({full!r}): {e}")
            return self.STG_E_DOCFILECORRUPT
        info = {'path': full, 'host': host, 'root': root,
                'delete': bool(mode & self.STGM_DELETEONRELEASE),
                'transacted': bool(mode & self.STGM_TRANSACTED), 'opens': 0, 'dirty': False}
        log.debug(f"StgOpenStorage({full!r}, 0x{mode:x})")
        return self._return_object(self._new_storage_object(root, info, writable, top=True), out)

    def StgIsStorageFile(self, args):
        """StgIsStorageFile(pwcsName) - S_OK for a compound file, else S_FALSE"""
        _, host, error = self._docfile_name(self.read_wide_string(args[0]) if args[0] else '')
        try:
            with open(host, 'rb') as f:
                header = f.read(8)
        except (OSError, TypeError):
            return self.STG_E_FILENOTFOUND
        return self.S_OK if compound_file.is_compound_file(header) else self.S_FALSE

    # ---------- IStorage ----------

    @staticmethod
    def _valid_element_name(name):
        return 0 < len(name) <= 31 and not any(c in name for c in '/\\:!')

    def _write_statstg(self, address, entry, flag, mode=0, name=None):
        """Fill a STATSTG; the name (unless STATFLAG_NONAME) is CoTaskMemAlloc'd"""
        name_ptr = 0
        if not flag & 1:
            name_ptr = self._alloc_units(self._text_units(name or entry.name, True), True)
        size = 0 if entry.storage else len(entry.data)
        kind = self.STGTY_STORAGE if entry.storage else self.STGTY_STREAM
        times = (entry.mtime, entry.ctime, 0) if entry.storage else (0, 0, 0)
        data = struct.pack('<IIQQQQII16sII', name_ptr, kind, size, *times, mode, 0,
                           entry.clsid, entry.state_bits, 0)
        return self._mem_write(address, data)

    def _com_storage(self, method, wide, args):
        """IStorage methods of a docfile storage"""
        state = self.com_objects.get(args[0])
        if method == 'Release' and state is not None and state['refs'] == 1 and state['top']:
            self._close_docfile(state['info'])
        result = self._com_unknown(method, args)
        if result is not None:
            return result
        if state is None:
            return self.STG_E_INVALIDPOINTER
        entry, info = state['entry'], state['info']

        def name_arg(index):
            return self.read_wide_string(args[index]) if args[index] else ''

        def must_write():
            if not state['writable']:
                return self.STG_E_ACCESSDENIED
            info['dirty'] = True
            entry.mtime = self._filetime_now()
            return 0

        if method in ('CreateStream', 'CreateStorage'):
            name, mode, out = name_arg(1), args[2], args[5]
            if not out:
                return self.STG_E_INVALIDPOINTER
            self._mem_write(out, b'\x00' * 4)
            if not self._valid_element_name(name):
                return self.STG_E_INVALIDNAME
            error = must_write()
            if error:
                return error
            existing = entry.child(name)
            if existing is not None and not mode & self.STGM_CREATE:
                return self.STG_E_FILEALREADYEXISTS
            child = entry.add(compound_file.Entry(name, method == 'CreateStorage'))
            if child.storage:
                child.ctime = child.mtime = self._filetime_now()
                return self._return_object(self._new_storage_object(child, info, True), out)
            return self._return_object(self._new_stream_object(child, info, True), out)
        if method in ('OpenStream', 'OpenStorage'):
            name = name_arg(1)
            mode, out = (args[3], args[5]) if method == 'OpenStream' else (args[3], args[6])
            if not out:
                return self.STG_E_INVALIDPOINTER
            self._mem_write(out, b'\x00' * 4)
            child = entry.child(name)
            if child is None or child.storage != (method == 'OpenStorage'):
                return self.STG_E_FILENOTFOUND
            writable = bool(mode & (self.STGM_WRITE | self.STGM_READWRITE))
            if writable and not state['writable']:
                return self.STG_E_ACCESSDENIED
            if child.storage:
                return self._return_object(self._new_storage_object(child, info, writable), out)
            return self._return_object(self._new_stream_object(child, info, writable), out)
        if method == 'CopyTo':
            excluded = set()
            if args[3]:  # SNB: NULL-terminated array of names
                pointer = args[3]
                while True:
                    item = self._read_u32(pointer)
                    if not item:
                        break
                    excluded.add(self.read_wide_string(item).upper())
                    pointer += 4
            dest = self._com_state(args[4], 'storage')
            if dest is None:
                return self.STG_E_INVALIDFUNCTION  # A storage of the program itself
            if not dest['writable']:
                return self.STG_E_ACCESSDENIED
            for child in entry.children.values():
                if child.name.upper() not in excluded:
                    dest['entry'].add(child.copy())
            dest['entry'].clsid = entry.clsid
            dest['info']['dirty'] = True
            return self.S_OK
        if method == 'MoveElementTo':
            name, new_name, flags = name_arg(1), name_arg(3), args[4]
            child = entry.child(name)
            dest = self._com_state(args[2], 'storage')
            if child is None:
                return self.STG_E_FILENOTFOUND
            if dest is None:
                return self.STG_E_INVALIDFUNCTION
            if not dest['writable'] or (flags == 0 and not state['writable']):
                return self.STG_E_ACCESSDENIED
            moved = child.copy()
            moved.name = new_name or child.name
            dest['entry'].add(moved)
            dest['info']['dirty'] = True
            if flags == 0:  # STGMOVE_MOVE
                del entry.children[child.name.upper()]
                info['dirty'] = True
            return self.S_OK
        if method == 'Commit':
            if state['top'] and state['writable'] and (info['dirty'] or not info['transacted']):
                return self.S_OK if self._save_docfile(info) else self.STG_E_WRITEFAULT
            return self.S_OK
        if method == 'Revert':
            if state['top'] and info['transacted'] and info['host'] and \
                    os.path.isfile(info['host']):
                try:
                    with open(info['host'], 'rb') as f:
                        fresh = compound_file.load(f.read())
                except (OSError, compound_file.CompoundFileError, struct.error):
                    return self.S_OK
                entry.children, entry.clsid = fresh.children, fresh.clsid
                info['dirty'] = False
            return self.S_OK
        if method == 'EnumElements':
            out = args[4]
            if not out:
                return self.STG_E_INVALIDPOINTER
            pointers = self._com_new_object(
                [((self.IID_IENUMSTATSTG, self.IID_IUNKNOWN),
                  self._com_vtable('IEnumSTATSTG', 'enum_statstg', wide=True))],
                {'kind': 'enum_statstg', 'items': list(entry.children.values()), 'index': 0})
            return self._return_object(pointers[self.IID_IUNKNOWN], out)
        if method == 'DestroyElement':
            name = name_arg(1)
            if entry.child(name) is None:
                return self.STG_E_FILENOTFOUND
            error = must_write()
            if error:
                return error
            del entry.children[name.upper()]
            return self.S_OK
        if method == 'RenameElement':
            old, new = name_arg(1), name_arg(2)
            child = entry.child(old)
            if child is None:
                return self.STG_E_FILENOTFOUND
            if not self._valid_element_name(new):
                return self.STG_E_INVALIDNAME
            if entry.child(new) is not None:
                return self.STG_E_FILEALREADYEXISTS
            error = must_write()
            if error:
                return error
            del entry.children[old.upper()]
            child.name = new
            entry.add(child)
            return self.S_OK
        if method == 'SetElementTimes':
            child = entry.child(name_arg(1)) if args[1] else entry
            if child is None:
                return self.STG_E_FILENOTFOUND
            for pointer, attribute in ((args[2], 'ctime'), (args[4], 'mtime')):
                if pointer and child.storage:
                    setattr(child, attribute, struct.unpack('<Q', self.emu.uc.mem_read(pointer,
                                                                                    8))[0])
            info['dirty'] = True
            return self.S_OK
        if method == 'SetClass':
            error = must_write()
            if error:
                return error
            entry.clsid = bytes(self.emu.uc.mem_read(args[1], 16))
            return self.S_OK
        if method == 'SetStateBits':
            error = must_write()
            if error:
                return error
            entry.state_bits = (entry.state_bits & ~args[2]) | (args[1] & args[2])
            return self.S_OK
        if method == 'Stat':
            mode = self.STGM_READWRITE if state['writable'] else 0
            name = info['path'] if state['top'] else entry.name
            return self.S_OK if self._write_statstg(args[1], entry, args[2], mode, name) \
                else self.STG_E_INVALIDPOINTER
        return self.E_NOTIMPL

    def _close_docfile(self, info):
        """The last IStorage of a docfile's root was released"""
        info['opens'] -= 1
        if info['opens'] > 0:
            return
        if info['delete'] and info['host']:
            try:
                os.remove(info['host'])
            except OSError:
                pass
        elif not info['transacted'] and info['dirty']:
            self._save_docfile(info)
        if info.get('lockbytes'):  # The docfile's reference to its ILockBytes
            self._release_lockbytes(info.pop('lockbytes'))

    # ---------- IEnumSTATSTG ----------

    def _com_enum_statstg(self, method, wide, args):
        result = self._com_unknown(method, args)
        if result is not None:
            return result
        state = self.com_objects.get(args[0])
        if state is None:
            return self.E_POINTER
        if method == 'Next':
            count, out, fetched = args[1], args[2], args[3]
            items = state['items'][state['index']:state['index'] + count]
            for i, item in enumerate(items):
                self._write_statstg(out + 72 * i, item, 0)
            state['index'] += len(items)
            if fetched:
                self._mem_write(fetched, struct.pack('<I', len(items)))
            return self.S_OK if len(items) == count else self.S_FALSE
        if method == 'Skip':
            state['index'] = min(len(state['items']), state['index'] + args[1])
            return self.S_OK if state['index'] < len(state['items']) else self.S_FALSE
        if method == 'Reset':
            state['index'] = 0
            return self.S_OK
        if method == 'Clone':
            pointers = self._com_new_object(
                [((self.IID_IENUMSTATSTG, self.IID_IUNKNOWN),
                  self._com_vtable('IEnumSTATSTG', 'enum_statstg', wide=True))],
                {'kind': 'enum_statstg', 'items': state['items'], 'index': state['index']})
            return self._return_object(pointers[self.IID_IUNKNOWN], args[1])
        return self.E_NOTIMPL

    # ---------- IStream ----------

    def _sync_hglobal(self, state):
        """A stream on global memory: the block (shared by the stream's clones
        in info['hglobal']) holds the stream's bytes"""
        info = state['info']
        data = state['entry'].data
        handle = info['hglobal']
        size = self._hglobal_size(handle) if handle else None
        if size is None or size < len(data):
            # (a moveable block keeps its handle)
            new = self.GlobalReAlloc([handle, max(len(data), 1), 0x2]) if handle else \
                self.GlobalAlloc([0x2, max(len(data), 1)])
            if not new:
                return False
            info['hglobal'] = new
        return self._mem_write(self._hglobal_pointer(info['hglobal']), bytes(data)) if data \
            else True

    def _com_stream(self, method, wide, args):
        """IStream methods: a docfile stream or a stream on global memory"""
        state = self.com_objects.get(args[0])
        if method == 'Release' and state is not None and state['refs'] == 1 and \
                state['hglobal']:
            # The last stream on a global memory block frees it if asked to
            info = state['info']
            info['streams'] -= 1
            if not info['streams'] and info['hglobal_delete']:
                self.GlobalFree([info['hglobal']])
        result = self._com_unknown(method, args)
        if result is not None:
            return result
        if state is None:
            return self.STG_E_INVALIDPOINTER
        data = state['entry'].data
        if method == 'Read':
            buffer, count, done = args[1], args[2], args[3]
            chunk = bytes(data[state['pos']:state['pos'] + count])
            if chunk and not self._mem_write(buffer, chunk):
                return self.STG_E_INVALIDPOINTER
            state['pos'] += len(chunk)
            if done:
                self._mem_write(done, struct.pack('<I', len(chunk)))
            return self.S_OK
        if method == 'Write':
            buffer, count, done = args[1], args[2], args[3]
            if not state['writable']:
                return self.STG_E_ACCESSDENIED
            try:
                chunk = bytes(self.emu.uc.mem_read(buffer, count)) if count else b''
            except UcError:
                return self.STG_E_INVALIDPOINTER
            position = state['pos']
            if position > len(data):
                data.extend(b'\x00' * (position - len(data)))
            data[position:position + len(chunk)] = chunk
            state['pos'] = position + len(chunk)
            if state['info'] is not None:
                state['info']['dirty'] = True
            if state['hglobal'] and not self._sync_hglobal(state):
                return 0x80030008  # STG_E_MEDIUMFULL
            if done:
                self._mem_write(done, struct.pack('<I', len(chunk)))
            return self.S_OK
        if method == 'Seek':
            move = struct.unpack('<q', struct.pack('<II', args[1], args[2]))[0]
            origin, out = args[3], args[4]
            base = {0: 0, 1: state['pos'], 2: len(data)}.get(origin)
            if base is None:
                return self.STG_E_INVALIDFUNCTION
            if base + move < 0:
                return self.STG_E_INVALIDFUNCTION
            state['pos'] = base + move
            if out:
                self._mem_write(out, struct.pack('<Q', state['pos']))
            return self.S_OK
        if method == 'SetSize':
            size = args[1] | (args[2] << 32)
            if not state['writable']:
                return self.STG_E_ACCESSDENIED
            if size > 0x7FFFFFFF:
                return 0x80030008  # STG_E_MEDIUMFULL
            if size < len(data):
                del data[size:]
            else:
                data.extend(b'\x00' * (size - len(data)))
            if state['info'] is not None:
                state['info']['dirty'] = True
            if state['hglobal']:
                self._sync_hglobal(state)
            return self.S_OK
        if method == 'CopyTo':
            dest, count = args[1], args[2] | (args[3] << 32)
            chunk = bytes(data[state['pos']:state['pos'] + count])
            state['pos'] += len(chunk)
            written = len(chunk)
            target = self._com_state(dest, 'stream')
            if target is not None:
                if not target['writable']:
                    return self.STG_E_ACCESSDENIED
                target_data, position = target['entry'].data, target['pos']
                if position > len(target_data):
                    target_data.extend(b'\x00' * (position - len(target_data)))
                target_data[position:position + len(chunk)] = chunk
                target['pos'] += len(chunk)
                if target['info'] is not None:
                    target['info']['dirty'] = True
                if target['hglobal']:
                    self._sync_hglobal(target)
            elif chunk:
                buffer = self.emu.heap_alloc(len(chunk) + 4)
                if not buffer:
                    return 0x80030008
                try:
                    self._mem_write(buffer, chunk)
                    result = self._guest_method(dest, 4, [buffer, len(chunk), buffer + len(chunk)])
                    written = self._read_u32(buffer + len(chunk)) if result == 0 else 0
                finally:
                    self.emu.heap_free(buffer)
                if result:
                    return result
            if args[4]:
                self._mem_write(args[4], struct.pack('<Q', len(chunk)))
            if args[5]:
                self._mem_write(args[5], struct.pack('<Q', written))
            return self.S_OK
        if method in ('Commit', 'Revert'):
            return self.S_OK
        if method in ('LockRegion', 'UnlockRegion'):
            return self.STG_E_INVALIDFUNCTION  # Like the streams of Windows' docfiles
        if method == 'Stat':
            mode = self.STGM_READWRITE if state['writable'] else 0
            return self.S_OK if self._write_statstg(args[1], state['entry'], args[2], mode) \
                else self.STG_E_INVALIDPOINTER
        if method == 'Clone':
            if state['hglobal']:
                state['info']['streams'] += 1
            clone = self._new_stream_object(state['entry'], state['info'], state['writable'],
                                            state['pos'], state['hglobal'])
            return self._return_object(clone, args[1])
        return self.E_NOTIMPL

    # ---------- Streams on global memory ----------

    def CreateStreamOnHGlobal(self, args):
        """CreateStreamOnHGlobal(hGlobal, fDeleteOnRelease, ppstm) - a stream
        whose bytes are kept in the global memory block (a new one if NULL)"""
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
        info = {'hglobal': handle, 'hglobal_delete': bool(delete), 'streams': 1}
        pointer = self._new_stream_object(entry, info, True, hglobal=True)
        return self._return_object(pointer, out)

    def GetHGlobalFromStream(self, args):
        """GetHGlobalFromStream(pstm, phglobal)"""
        state = self._com_state(args[0], 'stream')
        if state is None or not state['hglobal']:
            return self.E_INVALIDARG
        self._sync_hglobal(state)
        return self.S_OK if self._mem_write(args[1], struct.pack('<I', state['info']['hglobal'])) \
            else self.E_INVALIDARG

    # ---------- Class IDs, user types and conversion flags ----------

    def _stream_write_bytes(self, stream, data):
        """Write bytes to an IStream (emulated or the program's own)"""
        state = self._com_state(stream, 'stream')
        if state is not None:
            if not state['writable']:
                return self.STG_E_ACCESSDENIED
            buffer = state['entry'].data
            position = state['pos']
            if position > len(buffer):
                buffer.extend(b'\x00' * (position - len(buffer)))
            buffer[position:position + len(data)] = data
            state['pos'] += len(data)
            if state['info'] is not None:
                state['info']['dirty'] = True
            if state['hglobal']:
                self._sync_hglobal(state)
            return self.S_OK
        memory = self.emu.heap_alloc(len(data) + 4)
        if not memory:
            return 0x8007000E
        try:
            self._mem_write(memory, data)
            result = self._guest_method(stream, 4, [memory, len(data), memory + len(data)])
            if result == 0 and self._read_u32(memory + len(data)) != len(data):
                result = 0x80030008  # STG_E_MEDIUMFULL
        finally:
            self.emu.heap_free(memory)
        return result

    def _stream_read_bytes(self, stream, count):
        """(HRESULT, bytes) read from an IStream"""
        state = self._com_state(stream, 'stream')
        if state is not None:
            chunk = bytes(state['entry'].data[state['pos']:state['pos'] + count])
            state['pos'] += len(chunk)
            return self.S_OK, chunk
        memory = self.emu.heap_alloc(count + 4)
        if not memory:
            return 0x8007000E, b''
        try:
            result = self._guest_method(stream, 3, [memory, count, memory + count])
            done = self._read_u32(memory + count) if result in (0, 1) else 0
            return result, bytes(self.emu.uc.mem_read(memory, done)) if done else b''
        finally:
            self.emu.heap_free(memory)

    def WriteClassStm(self, args):
        """WriteClassStm(pStm, rclsid)"""
        if not args[0] or not args[1]:
            return self.E_INVALIDARG
        return self._stream_write_bytes(args[0], bytes(self.emu.uc.mem_read(args[1], 16)))

    def ReadClassStm(self, args):
        """ReadClassStm(pStm, pclsid)"""
        if not args[0] or not args[1]:
            return self.E_INVALIDARG
        result, data = self._stream_read_bytes(args[0], 16)
        if result not in (0, 1):
            return result
        if len(data) < 16:
            return 0x80030026  # STG_E_READFAULT
        self._mem_write(args[1], data)
        return self.S_OK

    def _storage_entry(self, pointer):
        state = self._com_state(pointer, 'storage')
        return (state['entry'], state) if state is not None else (None, None)

    def WriteClassStg(self, args):
        """WriteClassStg(pStg, rclsid) - IStorage::SetClass"""
        if not args[0]:
            return self.E_INVALIDARG
        if self._com_state(args[0], 'storage') is not None:
            return self._com_storage('SetClass', True, [args[0], args[1]])
        return self._guest_method(args[0], 15, [args[1]])  # IStorage::SetClass

    def ReadClassStg(self, args):
        """ReadClassStg(pStg, pclsid) - the storage's CLSID (IStorage::Stat)"""
        if not args[0] or not args[1]:
            return self.E_INVALIDARG
        entry, _ = self._storage_entry(args[0])
        if entry is not None:
            self._mem_write(args[1], entry.clsid)
            return self.S_OK
        statstg = self.emu.heap_alloc(72)
        try:
            result = self._guest_method(args[0], 17, [statstg, 1])  # STATFLAG_NONAME
            clsid = bytes(self.emu.uc.mem_read(statstg + 48, 16)) if result == 0 else b'\x00' * 16
        finally:
            self.emu.heap_free(statstg)
        self._mem_write(args[1], clsid)
        return result

    # The \1CompObj stream: the user type and clipboard format of an object
    COMPOBJ_STREAM = '\x01CompObj'
    COMPOBJ_UNICODE_MARKER = 0x71B239F4

    def _clipboard_format_name(self, fmt):
        return type(self).clipboard_format_names.get(fmt) if fmt >= 0xC000 else None

    def WriteFmtUserTypeStg(self, args):
        """WriteFmtUserTypeStg(pstg, cf, lpszUserType) - the \\1CompObj stream"""
        entry, state = self._storage_entry(args[0])
        if entry is None:
            return self.E_INVALIDARG
        if not state['writable']:
            return self.STG_E_ACCESSDENIED
        fmt, user_type = args[1], self.read_wide_string(args[2]) if args[2] else ''

        def ansi(text):
            raw = text.encode('cp1252', errors='replace') + b'\x00' if text else b''
            return struct.pack('<I', len(raw)) + raw

        def unicode(text):
            raw = text.encode('utf-16-le') + b'\x00\x00' if text else b''
            return struct.pack('<I', len(raw) // 2) + raw

        name = self._clipboard_format_name(fmt)
        if not fmt:
            ansi_format = unicode_format = struct.pack('<I', 0)
        elif name:
            ansi_format, unicode_format = ansi(name), unicode(name)
        else:
            ansi_format = unicode_format = struct.pack('<II', 0xFFFFFFFE, fmt)
        data = (struct.pack('<HHI', 0xFFFE, 1, 0x0A03) + struct.pack('<I', 0xFFFFFFFF) +
                entry.clsid + ansi(user_type) + ansi_format + ansi('') +
                struct.pack('<I', self.COMPOBJ_UNICODE_MARKER) + unicode(user_type) +
                unicode_format + unicode(''))
        stream = entry.add(compound_file.Entry(self.COMPOBJ_STREAM, False))
        stream.data = bytearray(data)
        state['info']['dirty'] = True
        return self.S_OK

    def ReadFmtUserTypeStg(self, args):
        """ReadFmtUserTypeStg(pstg, pcf, lplpszUserType)"""
        entry, _ = self._storage_entry(args[0])
        if entry is None:
            return self.E_INVALIDARG
        stream = entry.child(self.COMPOBJ_STREAM)
        if stream is None or stream.storage:
            return self.STG_E_FILENOTFOUND
        data = bytes(stream.data)
        try:
            position = 28

            def ansi_string():
                nonlocal position
                length = struct.unpack_from('<I', data, position)[0]
                text = data[position + 4:position + 4 + length].split(b'\x00')[0]
                position += 4 + length
                return text.decode('cp1252', errors='replace')

            user_type = ansi_string()
            marker = struct.unpack_from('<I', data, position)[0]
            if marker in (0xFFFFFFFF, 0xFFFFFFFE):
                fmt = struct.unpack_from('<I', data, position + 4)[0]
                position += 8
            elif marker == 0:
                fmt = 0
                position += 4
            else:
                name = ansi_string()
                fmt = type(self).clipboard_formats.get(name.lower())
                if fmt is None:
                    buffer = self._alloc_units(self._text_units(name, False), False)
                    fmt = self.RegisterClipboardFormatA([buffer])
                    self.emu.heap_free(buffer)
        except struct.error:
            return 0x80030026  # STG_E_READFAULT
        if args[1]:
            self._mem_write(args[1], struct.pack('<I', fmt))
        if args[2]:
            text = self._alloc_units(self._text_units(user_type, True), True) if user_type else 0
            self._mem_write(args[2], struct.pack('<I', text))
        return self.S_OK

    # The \1Ole stream: OLE's flags of an embedded object
    OLE_STREAM = '\x01Ole'
    OLESTREAM_CONVERT = 0x4

    def GetConvertStg(self, args):
        """GetConvertStg(pStg) - S_OK if the object is marked to be converted"""
        entry, _ = self._storage_entry(args[0])
        if entry is None:
            return self.E_INVALIDARG
        stream = entry.child(self.OLE_STREAM)
        if stream is None or stream.storage or len(stream.data) < 8:
            return self.S_FALSE
        flags = struct.unpack_from('<I', stream.data, 4)[0]
        return self.S_OK if flags & self.OLESTREAM_CONVERT else self.S_FALSE

    def SetConvertStg(self, args):
        """SetConvertStg(pStg, fConvert)"""
        entry, state = self._storage_entry(args[0])
        if entry is None:
            return self.E_INVALIDARG
        if not state['writable']:
            return self.STG_E_ACCESSDENIED
        stream = entry.child(self.OLE_STREAM)
        if stream is None or stream.storage:
            stream = entry.add(compound_file.Entry(self.OLE_STREAM, False))
            stream.data = bytearray(struct.pack('<IIIII', 0x02000001, 0, 0, 0, 0))
        if len(stream.data) < 8:
            stream.data.extend(b'\x00' * (8 - len(stream.data)))
        flags = struct.unpack_from('<I', stream.data, 4)[0]
        flags = flags | self.OLESTREAM_CONVERT if args[1] else flags & ~self.OLESTREAM_CONVERT
        struct.pack_into('<I', stream.data, 4, flags)
        state['info']['dirty'] = True
        return self.S_OK

    # ---------- Saving the program's objects ----------

    def OleSave(self, args):
        """OleSave(pPS, pStg, fSameAsLoad): IPersistStorage::GetClassID,
        WriteClassStg, IPersistStorage::Save, IStorage::Commit"""
        persist, storage, same = args[:3]
        clsid = self.emu.heap_alloc(16)
        try:
            result = self._guest_method(persist, 3, [clsid])  # GetClassID
            if result == 0:
                result = self.WriteClassStg([storage, clsid])
        finally:
            self.emu.heap_free(clsid)
        if result:
            return result
        result = self._guest_method(persist, 7, [storage, same])  # IPersistStorage::Save
        if result:
            return result
        if self._com_state(storage, 'storage') is not None:
            return self._com_storage('Commit', True, [storage, 0])
        return self._guest_method(storage, 9, [0])  # IStorage::Commit

    def OleSaveToStream(self, args):
        """OleSaveToStream(pPStm, pStm): the CLSID, then IPersistStream::Save"""
        persist, stream = args[:2]
        if not stream:
            return self.E_INVALIDARG
        clsid = self.emu.heap_alloc(16)
        try:
            self._mem_write(clsid, b'\x00' * 16)
            result = self._guest_method(persist, 3, [clsid]) if persist else 0  # GetClassID
            if result == 0:
                result = self.WriteClassStm([stream, clsid])
        finally:
            self.emu.heap_free(clsid)
        if result or not persist:
            return result
        return self._guest_method(persist, 6, [stream, 1])  # IPersistStream::Save(pStm, TRUE)
