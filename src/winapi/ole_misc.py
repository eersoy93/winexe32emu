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

"""WinAPIHandler mixin: more of ole32 - the OLE clipboard, advise holders,
bind contexts, the running object table, file, item and composite
monikers, class registration queries, and the embedding functions of a
computer without OLE servers"""

import os
import struct

from unicorn import UcError

from .. import winapi
from ..logger import log
from .registry import registry_locked


class OleMiscMixin:
    """The OLE clipboard, IDataAdviseHolder, IOleAdviseHolder, IBindCtx,
    IRunningObjectTable, IMoniker, OleReg*, OleCreate*"""

    IID_IDATAOBJECT = '0000010e-0000-0000-c000-000000000046'
    IID_IENUMFORMATETC = '00000103-0000-0000-c000-000000000046'
    IID_IENUMOLEVERB = '00000104-0000-0000-c000-000000000046'
    IID_IDATAADVISEHOLDER = '00000110-0000-0000-c000-000000000046'
    IID_IOLEADVISEHOLDER = '00000111-0000-0000-c000-000000000046'
    IID_IBINDCTX = '0000000e-0000-0000-c000-000000000046'
    IID_IRUNNINGOBJECTTABLE = '00000010-0000-0000-c000-000000000046'
    IID_IMONIKER = '0000000f-0000-0000-c000-000000000046'
    IID_IPERSISTSTREAM = '00000109-0000-0000-c000-000000000046'
    IID_IRUNNABLEOBJECT = '00000126-0000-0000-c000-000000000046'
    IID_IOLEITEMCONTAINER = '0000011c-0000-0000-c000-000000000046'
    CLSID_FILEMONIKER = '00000303-0000-0000-c000-000000000046'
    CLSID_ITEMMONIKER = '00000304-0000-0000-c000-000000000046'
    CLSID_COMPOSITEMONIKER = '00000309-0000-0000-c000-000000000046'

    DV_E_FORMATETC = 0x80040064
    OLE_E_ADVISENOTSUPPORTED = 0x80040003
    OLE_E_NOCONNECTION = 0x80040004
    DATA_S_SAMEFORMATETC = 0x00040130
    OLEOBJ_E_NOVERBS = 0x80040180
    REGDB_E_KEYMISSING = 0x80040155
    MK_E_UNAVAILABLE = 0x800401E3
    MK_E_NOOBJECT = 0x800401E5
    MK_E_NOINVERSE = 0x800401EC
    MK_E_NOSTORAGE = 0x800401ED
    MK_E_NOPREFIX = 0x800401EE
    MK_E_NEEDGENERIC = 0x800401E2
    MK_E_SYNTAX = 0x800401E4
    MK_E_NOTBOUND = 0x800401E8
    MK_S_REDUCED_TO_SELF = 0x000401E2
    MK_S_MONIKERALREADYREGISTERED = 0x000401E7
    TYMED_NULL, TYMED_HGLOBAL, TYMED_FILE, TYMED_ISTREAM, TYMED_ISTORAGE = 0, 1, 2, 4, 8
    TYMED_GDI, TYMED_MFPICT, TYMED_ENHMF = 16, 32, 64

    COM_INTERFACES_OLE = {
        'data_object': [
            ('QueryInterface', 3), ('AddRef', 1), ('Release', 1), ('GetData', 3),
            ('GetDataHere', 3), ('QueryGetData', 2), ('GetCanonicalFormatEtc', 3),
            ('SetData', 4), ('EnumFormatEtc', 3), ('DAdvise', 5), ('DUnadvise', 2),
            ('EnumDAdvise', 2)],
        # IEnumFORMATETC, IEnumOLEVERB: fixed-size items made on demand
        'enum_items': [
            ('QueryInterface', 3), ('AddRef', 1), ('Release', 1), ('Next', 4), ('Skip', 2),
            ('Reset', 1), ('Clone', 2)],
        'data_advise_holder': [
            ('QueryInterface', 3), ('AddRef', 1), ('Release', 1), ('Advise', 6),
            ('Unadvise', 2), ('EnumAdvise', 2), ('SendOnDataChange', 4)],
        'ole_advise_holder': [
            ('QueryInterface', 3), ('AddRef', 1), ('Release', 1), ('Advise', 3),
            ('Unadvise', 2), ('EnumAdvise', 2), ('SendOnRename', 2), ('SendOnSave', 1),
            ('SendOnClose', 1)],
        'bind_ctx': [
            ('QueryInterface', 3), ('AddRef', 1), ('Release', 1), ('RegisterObjectBound', 2),
            ('RevokeObjectBound', 2), ('ReleaseBoundObjects', 1), ('SetBindOptions', 2),
            ('GetBindOptions', 2), ('GetRunningObjectTable', 2), ('RegisterObjectParam', 3),
            ('GetObjectParam', 3), ('EnumObjectParam', 2), ('RevokeObjectParam', 2)],
        'running_object_table': [
            ('QueryInterface', 3), ('AddRef', 1), ('Release', 1), ('Register', 5),
            ('Revoke', 2), ('IsRunning', 2), ('GetObject', 3), ('NoteChangeTime', 3),
            ('GetTimeOfLastChange', 3), ('EnumRunning', 2)],
        # IMoniker (IPersistStream's methods first)
        'moniker': [
            ('QueryInterface', 3), ('AddRef', 1), ('Release', 1), ('GetClassID', 2),
            ('IsDirty', 1), ('Load', 2), ('Save', 3), ('GetSizeMax', 2), ('BindToObject', 5),
            ('BindToStorage', 5), ('Reduce', 5), ('ComposeWith', 4), ('Enum', 3),
            ('IsEqual', 2), ('Hash', 2), ('IsRunning', 4), ('GetTimeOfLastChange', 4),
            ('Inverse', 2), ('CommonPrefixWith', 3), ('RelativePathTo', 3),
            ('GetDisplayName', 4), ('ParseDisplayName', 6), ('IsSystemMoniker', 2)],
    }

    def _ole_interfaces(self):
        for kind, methods in self.COM_INTERFACES_OLE.items():
            self.COM_INTERFACES.setdefault(kind, methods)

    def _new_ole_object(self, kind, interface, iids, state):
        """A new emulated COM object; returns its IUnknown pointer"""
        self._ole_interfaces()
        state['kind'] = kind
        pointers = self._com_new_object(
            [(tuple(iids) + (self.IID_IUNKNOWN,), self._com_vtable(interface, kind, wide=True))],
            state)
        return pointers[self.IID_IUNKNOWN]

    # ---------- The program's COM objects ----------

    def _guest_query(self, pointer, iid):
        """QueryInterface of any COM object: the interface pointer or 0"""
        if not pointer:
            return 0
        memory = self.emu.heap_alloc(20)
        try:
            self._mem_write(memory, self._guid_bytes(iid) + b'\x00' * 4)
            if pointer in self.com_objects:
                result = self._com_unknown('QueryInterface', [pointer, memory, memory + 16])
            else:
                result = self._guest_method(pointer, 0, [memory, memory + 16])
            return self._read_u32(memory + 16) if result == 0 else 0
        finally:
            self.emu.heap_free(memory)

    def _add_ref(self, pointer):
        if pointer in self.com_objects:
            return self._com_unknown('AddRef', [pointer])
        return self._guest_method(pointer, 1, [])

    def _release(self, pointer):
        if not pointer:
            return 0
        if pointer in self.com_objects:
            return self._com_unknown('Release', [pointer])
        return self._guest_method(pointer, 2, [])

    def _release_stgmedium(self, medium):
        """ReleaseStgMedium: free what a STGMEDIUM holds (or Release its
        pUnkForRelease, which owns it)"""
        try:
            tymed, handle, owner = struct.unpack('<III', self.emu.uc.mem_read(medium, 12))
        except UcError:
            return
        if owner:
            self._release(owner)
        elif tymed == self.TYMED_HGLOBAL and handle:
            self.GlobalFree([handle])
        elif tymed == self.TYMED_FILE and handle:
            name = self.read_wide_string(handle)
            host = self.resolve_drive_path(name) if name else None
            if host and not self._write_protected(host):
                try:
                    os.remove(host)
                except OSError:
                    pass
            self.CoTaskMemFree([handle])
        elif tymed in (self.TYMED_ISTREAM, self.TYMED_ISTORAGE) and handle:
            self._release(handle)
        elif tymed == self.TYMED_GDI and handle:
            self.DeleteObject([handle])
        elif tymed == self.TYMED_MFPICT and handle:
            try:
                metafile = struct.unpack('<I', self.emu.uc.mem_read(handle + 12, 4))[0]
                self.DeleteMetaFile([metafile])
            except UcError:
                pass
            self.GlobalFree([handle])
        self._mem_write(medium, struct.pack('<III', self.TYMED_NULL, 0, 0))

    # ---------- Simple queries ----------

    def OleBuildVersion(self, args):
        """OleBuildVersion - OLE 2.3 (rmm 23), build 700"""
        return (23 << 16) | 700

    def CoIsOle1Class(self, args):
        """CoIsOle1Class(rclsid) - no OLE 1 classes are registered"""
        return 0

    def CoDisconnectObject(self, args):
        """CoDisconnectObject(pUnk, dwReserved) - no other process holds
        references to the program's objects"""
        return self.S_OK

    def OleQueryCreateFromData(self, args):
        """OleQueryCreateFromData(pSrcDataObject) - no OLE server can embed the data"""
        return self.S_FALSE

    def OleQueryLinkFromData(self, args):
        return self.S_FALSE

    def _class_key(self, clsid_ptr):
        clsid = self._read_guid(clsid_ptr)
        return f'CLSID\\{{{clsid.upper()}}}' if clsid else None

    @registry_locked
    def CoGetTreatAsClass(self, args):
        """CoGetTreatAsClass(clsidOld, pClsidNew) - HKEY_CLASSES_ROOT\\CLSID\\
        {old}\\TreatAs, else the old class with S_FALSE"""
        key = self._class_key(args[0])
        if key is None or not args[1]:
            return self.E_INVALIDARG
        text = self._registry_default_text(key + '\\TreatAs').strip('{}').lower()
        if len(text) != 36:
            self._mem_write(args[1], bytes(self.emu.uc.mem_read(args[0], 16)))
            return self.S_FALSE
        self._mem_write(args[1], self._guid_bytes(text))
        return self.S_OK

    @registry_locked
    def CoTreatAsClass(self, args):
        """CoTreatAsClass(clsidOld, clsidNew) - set HKEY_CLASSES_ROOT\\CLSID\\
        {old}\\TreatAs; a NULL (or the same) new class removes it"""
        key = self._class_key(args[0])
        if key is None:
            return self.E_INVALIDARG
        old = self._read_guid(args[0])
        new = self._read_guid(args[1]) if args[1] else ''
        node, _ = self._registry_walk(self.HKEY_CLASSES_ROOT, key, create=True)
        if node is None:
            return 0x80040151  # REGDB_E_WRITEREGDB
        if not new or new in (old, self.ZERO_GUID):
            treat = node['keys'].pop('treatas', None)
            if treat is not None:
                self._mark_deleted(treat)
            self._save_registry()
            return self.S_OK
        treat, _ = self._registry_walk(self.HKEY_CLASSES_ROOT, key + '\\TreatAs', create=True)
        treat['values'][''] = {'name': '', 'type': 1, 'data': f'{{{new.upper()}}}\x00'}
        self._save_registry()
        return self.S_OK

    @registry_locked
    def OleRegGetMiscStatus(self, args):
        """OleRegGetMiscStatus(clsid, dwAspect, pdwStatus) - the class's
        MiscStatus (for the aspect, else its default), 0 if it has none"""
        key = self._class_key(args[0])
        if not args[2]:
            return self.E_INVALIDARG
        self._mem_write(args[2], b'\x00' * 4)
        node, _ = self._registry_walk(self.HKEY_CLASSES_ROOT, key) if key else (None, 0)
        if node is None:
            return self.REGDB_E_CLASSNOTREG
        text = self._registry_default_text(f'{key}\\MiscStatus\\{args[1]}') or \
            self._registry_default_text(f'{key}\\MiscStatus')
        try:
            status = int(text) if text else 0
        except ValueError:
            status = 0
        self._mem_write(args[2], struct.pack('<I', status & 0xFFFFFFFF))
        return self.S_OK

    def _registry_subkey_values(self, key):
        """[(subkey name, default text)] of HKEY_CLASSES_ROOT\\key, or None"""
        node, _ = self._registry_walk(self.HKEY_CLASSES_ROOT, key)
        if node is None:
            return None
        items = []
        for child in node['keys'].values():
            value = child['values'].get('')
            data = value.get('data') if value else ''
            items.append((child['name'], data.rstrip('\x00') if isinstance(data, str) else ''))
        return items

    def _new_enum_items(self, interface, iid, items, size):
        """An enumerator of fixed-size items: items are callables writing
        one item at an address"""
        return self._new_ole_object('enum_items', interface, (iid,),
                                    {'items': items, 'index': 0, 'size': size,
                                     'interface': interface, 'iid': iid})

    def _com_enum_items(self, method, wide, args):
        result = self._com_unknown(method, args)
        if result is not None:
            return result
        state = self.com_objects.get(args[0])
        if state is None:
            return self.E_POINTER
        if method == 'Next':
            count, out, fetched = args[1], args[2], args[3]
            items = state['items'][state['index']:state['index'] + count]
            for i, write in enumerate(items):
                write(out + state['size'] * i)
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
            clone = self._new_enum_items(state['interface'], state['iid'], state['items'],
                                         state['size'])
            self.com_objects[clone]['index'] = state['index']
            return self._return_object(clone, args[1])
        return self.E_NOTIMPL

    @registry_locked
    def OleRegEnumVerbs(self, args):
        """OleRegEnumVerbs(clsid, ppenum) - the class's Verb subkeys
        ("name,menu flags,attributes") as OLEVERBs"""
        key = self._class_key(args[0])
        if not args[1]:
            return self.E_INVALIDARG
        self._mem_write(args[1], b'\x00' * 4)
        if key is None or self._registry_walk(self.HKEY_CLASSES_ROOT, key)[0] is None:
            return self.REGDB_E_CLASSNOTREG
        verbs = self._registry_subkey_values(key + '\\Verb')
        if not verbs:
            return self.OLEOBJ_E_NOVERBS
        items = []
        for number, text in sorted(verbs, key=lambda v: int(v[0]) if v[0].lstrip('-').isdigit()
                                   else 0):
            parts = text.split(',')
            name = parts[0]
            flags = int(parts[1]) if len(parts) > 1 and parts[1].strip().isdigit() else 0
            attributes = int(parts[2]) if len(parts) > 2 and parts[2].strip().isdigit() else 0
            verb = int(number) if number.lstrip('-').isdigit() else 0

            def write(address, verb=verb, name=name, flags=flags, attributes=attributes):
                text_ptr = self._alloc_units(self._text_units(name, True), True)
                self._mem_write(address, struct.pack('<iIII', verb, text_ptr, flags, attributes))
            items.append(write)
        enum = self._new_enum_items('IEnumOLEVERB', self.IID_IENUMOLEVERB, items, 16)
        return self._return_object(enum, args[1])

    def _formatetc_writer(self, fmt, aspect=1, tymed=1):
        def write(address):
            self._mem_write(address, struct.pack('<IIIiI', fmt, 0, aspect, -1, tymed))
        return write

    @registry_locked
    def OleRegEnumFormatEtc(self, args):
        """OleRegEnumFormatEtc(clsid, dwDirection, ppenum) - the class's
        DataFormats\\GetSet subkeys ("format,aspect,tymed,direction")"""
        key = self._class_key(args[0])
        if not args[2]:
            return self.E_INVALIDARG
        self._mem_write(args[2], b'\x00' * 4)
        formats = self._registry_subkey_values(f'{key}\\DataFormats\\GetSet') if key else None
        if not formats:
            return self.REGDB_E_KEYMISSING
        items = []
        for _, text in formats:
            parts = [p.strip() for p in text.split(',')]
            if len(parts) < 4:
                continue
            fmt = int(parts[0]) if parts[0].isdigit() else \
                type(self).clipboard_formats.get(parts[0].lower(), 0)
            try:
                aspect, tymed, direction = int(parts[1]), int(parts[2]), int(parts[3])
            except ValueError:
                continue
            if fmt and direction & args[1]:
                items.append(self._formatetc_writer(fmt, aspect, tymed))
        enum = self._new_enum_items('IEnumFORMATETC', self.IID_IENUMFORMATETC, items, 20)
        return self._return_object(enum, args[2])

    # ---------- Running objects ----------

    def OleRun(self, args):
        """OleRun(pUnknown) - IRunnableObject::Run if the object has it"""
        runnable = self._guest_query(args[0], self.IID_IRUNNABLEOBJECT)
        if not runnable:
            return self.S_OK
        result = self._guest_method(runnable, 4, [0])  # Run(pbc)
        self._release(runnable)
        return result

    def OleIsRunning(self, args):
        """OleIsRunning(pObject) - IRunnableObject::IsRunning, else TRUE"""
        runnable = self._guest_query(args[0], self.IID_IRUNNABLEOBJECT)
        if not runnable:
            return 1
        result = self._guest_method(runnable, 5, [])  # IsRunning
        self._release(runnable)
        return 1 if result else 0

    @registry_locked
    def _class_user_type(self, clsid_ptr):
        key = self._class_key(clsid_ptr)
        return self._registry_default_text(key) if key else ''

    def OleGetIconOfClass(self, args):
        """OleGetIconOfClass(rclsid, lpszLabel, fUseTypeAsLabel) - a
        METAFILEPICT (HGLOBAL) of the application icon with the label under it"""
        if args[1]:
            label = self.read_wide_string(args[1])
        elif args[2]:
            label = self._class_user_type(args[0]) or 'Document'
        else:
            label = ''
        hdc = self.CreateMetaFileA([0])
        if not hdc:
            return 0
        self._draw_icon(hdc, 0, 0, self.LoadIconA([0, 32512]))  # IDI_APPLICATION
        if label:
            text = self._alloc_units(self._text_units(label, False), False)
            self.TextOutA([hdc, 0, 34, text, len(label)])
            self.emu.heap_free(text)
        metafile = self.CloseMetaFile([hdc])
        width = max(32, self._text_extent(0, label)[0]) if label else 32
        block = self.GlobalAlloc([0x2, 16])
        if not block:
            return 0
        # MM_ANISOTROPIC, the size in 0.01 mm (96 pixels per inch)
        self._mem_write(block, struct.pack('<IiiI', 8, width * 2540 // 96,
                                           (52 if label else 32) * 2540 // 96, metafile))
        return block

    # ---------- OLE servers: there are none ----------

    def _no_ole_server(self, name, out):
        if out:
            self._mem_write(out, b'\x00' * 4)
        log.debug(f"{name}: no OLE server can create the object")
        return self.REGDB_E_CLASSNOTREG

    def OleCreate(self, args):
        """OleCreate(rclsid, riid, renderopt, pFormatEtc, pClientSite, pStg, ppvObj)"""
        return self._no_ole_server('OleCreate', args[6])

    def OleCreateFromFile(self, args):
        """OleCreateFromFile(rclsid, lpszFileName, riid, renderopt, lpFormatEtc,
        pClientSite, pStg, ppvObj)"""
        return self._no_ole_server('OleCreateFromFile', args[7])

    def OleCreateLink(self, args):
        return self._no_ole_server('OleCreateLink', args[6])

    def OleCreateLinkToFile(self, args):
        return self._no_ole_server('OleCreateLinkToFile', args[6])

    def OleCreateFromData(self, args):
        """OleCreateFromData(pSrcDataObj, riid, renderopt, pFormatEtc, pClientSite,
        pStg, ppvObj) - the data names no object an OLE server could embed"""
        if args[6]:
            self._mem_write(args[6], b'\x00' * 4)
        return self.DV_E_FORMATETC

    def OleCreateLinkFromData(self, args):
        if args[6]:
            self._mem_write(args[6], b'\x00' * 4)
        return self.DV_E_FORMATETC

    def OleLoad(self, args):
        """OleLoad(pStg, riid, pClientSite, ppvObj) - the storage's class has
        no OLE server"""
        return self._no_ole_server('OleLoad', args[3])

    def OleCreateDefaultHandler(self, args):
        """OleCreateDefaultHandler(clsid, pUnkOuter, riid, lplpObj)"""
        if args[3]:
            self._mem_write(args[3], b'\x00' * 4)
        return self.E_NOTIMPL

    def CreateDataCache(self, args):
        """CreateDataCache(pUnkOuter, rclsid, iid, ppv)"""
        if args[3]:
            self._mem_write(args[3], b'\x00' * 4)
        return self.E_NOTIMPL

    CONVERT10_E_OLESTREAM_FMT = 0x800401C2

    def OleConvertOLESTREAMToIStorage(self, args):
        """OleConvertOLESTREAMToIStorage(lpolestream, pstg, ptd) - OLE 1
        objects are not converted"""
        return self.CONVERT10_E_OLESTREAM_FMT

    def OleConvertIStorageToOLESTREAM(self, args):
        return self.CONVERT10_E_OLESTREAM_FMT

    # ---------- In-place activation menus and accelerators ----------

    def OleCreateMenuDescriptor(self, args):
        """OleCreateMenuDescriptor(hmenuCombined, lpMenuWidths) - an HOLEMENU"""
        block = self.GlobalAlloc([0x40, 28])  # GPTR
        if not block:
            return 0
        widths = bytes(self.emu.uc.mem_read(args[1], 24)) if args[1] else b'\x00' * 24
        self._mem_write(block, struct.pack('<I', args[0]) + widths)
        return block

    def OleDestroyMenuDescriptor(self, args):
        if args[0]:
            self.GlobalFree([args[0]])
        return self.S_OK

    def OleSetMenuDescriptor(self, args):
        """OleSetMenuDescriptor(holemenu, hwndFrame, hwndActiveObject, lpFrame,
        lpActiveObj) - no in-place object's menus to route"""
        return self.S_OK

    def OleTranslateAccelerator(self, args):
        """OleTranslateAccelerator(lpFrame, lpFrameInfo, lpmsg) - no in-place
        object is active, so the frame's accelerators are not involved"""
        return self.S_FALSE

    # ---------- OleDuplicateData ----------

    CF_BITMAP, CF_METAFILEPICT, CF_PALETTE, CF_ENHMETAFILE = 2, 3, 9, 14

    def OleDuplicateData(self, args):
        """OleDuplicateData(hSrc, cfFormat, uiFlags) - a copy of a clipboard
        format's handle"""
        handle, fmt = args[:2]
        if not handle:
            return 0
        if fmt in (self.CF_BITMAP, self.CF_PALETTE):
            obj = self.gdi_objects.get(handle)
            if obj is None:
                return 0
            copy = self.get_next_handle()
            self.gdi_objects[copy] = dict(obj, shapes=list(obj.get('shapes', [])))
            return copy
        size = self.emu.heap_block_size(handle)
        if size is None:
            return 0
        copy = self.GlobalAlloc([0x2, size])
        if not copy:
            return 0
        self._mem_write(copy, bytes(self.emu.uc.mem_read(handle, size)))
        if fmt == self.CF_METAFILEPICT and size >= 16:
            metafile = self._read_u32(handle + 12)
            meta = self.gdi_objects.get(metafile)
            if meta is not None and meta['type'] == 'metafile':
                duplicate = self.get_next_handle()
                self.gdi_objects[duplicate] = dict(meta)
                self._mem_write(copy + 12, struct.pack('<I', duplicate))
        return copy

    # ---------- The OLE clipboard ----------

    def _ole_clipboard_object(self):
        """The data object of OleSetClipboard, if it still owns the clipboard"""
        current = getattr(self, '_ole_clipboard', None)
        if current and current[1] is winapi.WinAPIHandler.clipboard_data:
            return current[0]
        return 0

    def _render_data_object(self, data_object):
        """Copy the HGLOBAL formats of a data object to the Win32 clipboard"""
        enum_ptr = self.emu.heap_alloc(4 + 20 + 12 + 4)
        if not enum_ptr:
            return
        formatetc, medium, fetched = enum_ptr + 4, enum_ptr + 24, enum_ptr + 36
        try:
            if self._guest_method(data_object, 8, [1, enum_ptr]):  # EnumFormatEtc(GET)
                return
            enum = self._read_u32(enum_ptr)
            for _ in range(256):
                if self._guest_method(enum, 3, [1, formatetc, fetched]) or \
                        not self._read_u32(fetched):
                    break
                fmt, _, _, _, tymed = struct.unpack('<IIIiI', self.emu.uc.mem_read(formatetc,
                                                                                20))
                if not tymed & self.TYMED_HGLOBAL:
                    continue
                self._mem_write(formatetc + 16, struct.pack('<I', self.TYMED_HGLOBAL))
                self._mem_write(medium, b'\x00' * 12)
                if self._guest_method(data_object, 3, [formatetc, medium]):  # GetData
                    continue
                tymed, handle, _ = struct.unpack('<III', self.emu.uc.mem_read(medium, 12))
                size = self.emu.heap_block_size(handle) if tymed == self.TYMED_HGLOBAL else None
                if size is not None:
                    winapi.WinAPIHandler.clipboard_data[fmt & 0xFFFF] = bytes(
                        self.emu.uc.mem_read(handle, size))
                self._release_stgmedium(medium)
            self._release(enum)
        finally:
            self.emu.heap_free(enum_ptr)

    def OleSetClipboard(self, args):
        """OleSetClipboard(pDataObj) - the object's HGLOBAL formats are put on
        the clipboard at once (no delayed rendering); NULL empties it"""
        previous = self._ole_clipboard_object()
        self._ole_clipboard = None
        if previous:
            self._release(previous)
        winapi.WinAPIHandler.clipboard_data = {}
        if args[0]:
            self._add_ref(args[0])
            self._render_data_object(args[0])
            self._ole_clipboard = (args[0], winapi.WinAPIHandler.clipboard_data)
        return self.S_OK

    def OleFlushClipboard(self, args):
        """OleFlushClipboard - the formats are already on the clipboard"""
        previous = self._ole_clipboard_object()
        self._ole_clipboard = None
        if previous:
            self._release(previous)
        return self.S_OK

    def OleIsCurrentClipboard(self, args):
        return self.S_OK if args[0] and args[0] == self._ole_clipboard_object() \
            else self.S_FALSE

    def OleGetClipboard(self, args):
        """OleGetClipboard(ppDataObj) - the program's own data object, or one
        reading the Win32 clipboard"""
        if not args[0]:
            return self.E_INVALIDARG
        current = self._ole_clipboard_object()
        if current:
            self._add_ref(current)
            self._mem_write(args[0], struct.pack('<I', current))
            return self.S_OK
        pointer = self._new_ole_object('data_object', 'IDataObject', (self.IID_IDATAOBJECT,), {})
        return self._return_object(pointer, args[0])

    def _com_data_object(self, method, wide, args):
        """IDataObject of the Win32 clipboard: its HGLOBAL formats"""
        result = self._com_unknown(method, args)
        if result is not None:
            return result
        clipboard = winapi.WinAPIHandler.clipboard_data
        if method in ('GetData', 'QueryGetData'):
            try:
                fmt, _, _, _, tymed = struct.unpack('<IIIiI', self.emu.uc.mem_read(args[1], 20))
            except UcError:
                return self.E_INVALIDARG
            fmt &= 0xFFFF
            if fmt not in clipboard or not tymed & self.TYMED_HGLOBAL:
                return self.DV_E_FORMATETC
            if method == 'QueryGetData':
                return self.S_OK
            data = clipboard[fmt]
            handle = self.GlobalAlloc([0x2, max(len(data), 1)])
            if not handle:
                return 0x8007000E  # E_OUTOFMEMORY
            self._mem_write(handle, data)
            self._mem_write(args[2], struct.pack('<III', self.TYMED_HGLOBAL, handle, 0))
            return self.S_OK
        if method == 'GetDataHere':
            return self.E_NOTIMPL
        if method == 'GetCanonicalFormatEtc':
            if args[2]:
                self._mem_write(args[2], bytes(self.emu.uc.mem_read(args[1], 20)))
                self._mem_write(args[2] + 4, b'\x00' * 4)  # ptd
            return self.DATA_S_SAMEFORMATETC
        if method == 'SetData':
            return self.E_NOTIMPL
        if method == 'EnumFormatEtc':
            if args[1] != 1:  # DATADIR_GET
                return self.E_NOTIMPL
            items = [self._formatetc_writer(fmt) for fmt in sorted(clipboard)]
            enum = self._new_enum_items('IEnumFORMATETC', self.IID_IENUMFORMATETC, items, 20)
            return self._return_object(enum, args[2])
        if method in ('DAdvise', 'EnumDAdvise'):
            return self.OLE_E_ADVISENOTSUPPORTED
        if method == 'DUnadvise':
            return self.OLE_E_NOCONNECTION
        return self.E_NOTIMPL

    # ---------- Advise holders ----------

    def CreateDataAdviseHolder(self, args):
        """CreateDataAdviseHolder(ppDAHolder)"""
        if not args[0]:
            return self.E_INVALIDARG
        pointer = self._new_ole_object('data_advise_holder', 'IDataAdviseHolder',
                                       (self.IID_IDATAADVISEHOLDER,),
                                       {'sinks': {}, 'next': 1})
        return self._return_object(pointer, args[0])

    def CreateOleAdviseHolder(self, args):
        """CreateOleAdviseHolder(ppOAHolder)"""
        if not args[0]:
            return self.E_INVALIDARG
        pointer = self._new_ole_object('ole_advise_holder', 'IOleAdviseHolder',
                                       (self.IID_IOLEADVISEHOLDER,),
                                       {'sinks': {}, 'next': 1})
        return self._return_object(pointer, args[0])

    def _advise_holder_release(self, state):
        for sink in list(state['sinks'].values()):
            self._release(sink[0] if isinstance(sink, tuple) else sink)
        state['sinks'].clear()

    def _send_data_change(self, sink, formatetc, advf, data_object):
        """IAdviseSink::OnDataChange with the data (unless ADVF_NODATA)"""
        memory = self.emu.heap_alloc(20 + 12)
        if not memory:
            return
        try:
            self._mem_write(memory, formatetc + b'\x00' * 12)
            got = False
            if not advf & 0x1 and data_object:  # ADVF_NODATA
                got = self._guest_method(data_object, 3, [memory, memory + 20]) == 0
            self._guest_method(sink, 3, [memory, memory + 20])  # OnDataChange
            if got:
                self._release_stgmedium(memory + 20)
        finally:
            self.emu.heap_free(memory)

    def _com_data_advise_holder(self, method, wide, args):
        state = self.com_objects.get(args[0])
        if method == 'Release' and state is not None and state['refs'] == 1:
            self._advise_holder_release(state)
        result = self._com_unknown(method, args)
        if result is not None:
            return result
        if method == 'Advise':
            data_object, formatetc_ptr, advf, sink, out = args[1:6]
            if not sink or not formatetc_ptr:
                return self.E_INVALIDARG
            formatetc = bytes(self.emu.uc.mem_read(formatetc_ptr, 20))
            self._add_ref(sink)
            connection = state['next']
            state['next'] += 1
            state['sinks'][connection] = (sink, formatetc, advf)
            if out:
                self._mem_write(out, struct.pack('<I', connection))
            if advf & 0x2:  # ADVF_PRIMEFIRST
                self._send_data_change(sink, formatetc, advf, data_object)
            return self.S_OK
        if method == 'Unadvise':
            sink = state['sinks'].pop(args[1], None)
            if sink is None:
                return self.OLE_E_NOCONNECTION
            self._release(sink[0])
            return self.S_OK
        if method == 'EnumAdvise':
            if args[1]:
                self._mem_write(args[1], b'\x00' * 4)
            return self.E_NOTIMPL
        if method == 'SendOnDataChange':
            data_object, _, advf = args[1:4]
            for connection, (sink, formatetc, sink_advf) in list(state['sinks'].items()):
                self._send_data_change(sink, formatetc, sink_advf | advf, data_object)
                if sink_advf & 0x4:  # ADVF_ONLYONCE
                    state['sinks'].pop(connection, None)
                    self._release(sink)
            return self.S_OK
        return self.E_NOTIMPL

    def _com_ole_advise_holder(self, method, wide, args):
        state = self.com_objects.get(args[0])
        if method == 'Release' and state is not None and state['refs'] == 1:
            self._advise_holder_release(state)
        result = self._com_unknown(method, args)
        if result is not None:
            return result
        if method == 'Advise':
            sink, out = args[1], args[2]
            if not sink:
                return self.E_INVALIDARG
            self._add_ref(sink)
            connection = state['next']
            state['next'] += 1
            state['sinks'][connection] = sink
            if out:
                self._mem_write(out, struct.pack('<I', connection))
            return self.S_OK
        if method == 'Unadvise':
            sink = state['sinks'].pop(args[1], None)
            if sink is None:
                return self.OLE_E_NOCONNECTION
            self._release(sink)
            return self.S_OK
        if method == 'EnumAdvise':
            if args[1]:
                self._mem_write(args[1], b'\x00' * 4)
            return self.E_NOTIMPL
        # IAdviseSink::OnRename (5), OnSave (6), OnClose (7)
        index, call_args = {'SendOnRename': (5, [args[1]] if len(args) > 1 else [0]),
                            'SendOnSave': (6, []), 'SendOnClose': (7, [])}.get(method,
                                                                             (None, None))
        if index is None:
            return self.E_NOTIMPL
        for sink in list(state['sinks'].values()):
            self._guest_method(sink, index, call_args)
        return self.S_OK

    # ---------- Bind contexts and the running object table ----------

    def CreateBindCtx(self, args):
        """CreateBindCtx(reserved, ppbc)"""
        if not args[1]:
            return self.E_INVALIDARG
        pointer = self._new_ole_object(
            'bind_ctx', 'IBindCtx', (self.IID_IBINDCTX,),
            {'bound': [], 'params': {},
             # BIND_OPTS: cbStruct, grfFlags, grfMode (STGM_READWRITE), deadline
             'options': struct.pack('<IIII', 16, 0, 0x2, 0)})
        return self._return_object(pointer, args[1])

    def _com_bind_ctx(self, method, wide, args):
        state = self.com_objects.get(args[0])
        if method == 'Release' and state is not None and state['refs'] == 1:
            for pointer in state['bound'] + list(state['params'].values()):
                self._release(pointer)
        result = self._com_unknown(method, args)
        if result is not None:
            return result
        if method == 'RegisterObjectBound':
            if args[1]:
                self._add_ref(args[1])
                state['bound'].append(args[1])
            return self.S_OK
        if method == 'RevokeObjectBound':
            if args[1] in state['bound']:
                state['bound'].remove(args[1])
                self._release(args[1])
                return self.S_OK
            return self.MK_E_NOTBOUND
        if method == 'ReleaseBoundObjects':
            for pointer in state['bound']:
                self._release(pointer)
            state['bound'] = []
            return self.S_OK
        if method == 'SetBindOptions':
            size = min(self._read_u32(args[1]), 64)
            state['options'] = bytes(self.emu.uc.mem_read(args[1], size))
            return self.S_OK
        if method == 'GetBindOptions':
            size = self._read_u32(args[1])
            data = state['options'][:size]
            self._mem_write(args[1] + 4, data[4:])
            return self.S_OK
        if method == 'GetRunningObjectTable':
            return self.GetRunningObjectTable([0, args[1]])
        if method == 'RegisterObjectParam':
            key = self.read_wide_string(args[1])
            old = state['params'].pop(key, None)
            if old:
                self._release(old)
            if args[2]:
                self._add_ref(args[2])
                state['params'][key] = args[2]
            return self.S_OK
        if method == 'GetObjectParam':
            pointer = state['params'].get(self.read_wide_string(args[1]), 0)
            if pointer:
                self._add_ref(pointer)
            self._mem_write(args[2], struct.pack('<I', pointer))
            return self.S_OK if pointer else self.E_FAIL
        if method == 'RevokeObjectParam':
            pointer = state['params'].pop(self.read_wide_string(args[1]), None)
            if pointer is None:
                return self.S_FALSE
            self._release(pointer)
            return self.S_OK
        if method == 'EnumObjectParam':
            self._mem_write(args[1], b'\x00' * 4)
            return self.E_NOTIMPL
        return self.E_NOTIMPL

    def GetRunningObjectTable(self, args):
        """GetRunningObjectTable(reserved, pprot) - the process's table"""
        if not args[1]:
            return self.E_INVALIDARG
        table = getattr(self, '_running_object_table', 0)
        if not table:
            table = self._new_ole_object('running_object_table', 'IRunningObjectTable',
                                         (self.IID_IRUNNINGOBJECTTABLE,),
                                         {'entries': {}, 'next': 1})
            self.com_objects[table]['refs'] = 0x10000  # Lives as long as the process
            self._running_object_table = table
        else:
            self._com_unknown('AddRef', [table])
        self._mem_write(args[1], struct.pack('<I', table))
        return self.S_OK

    def _moniker_name(self, moniker):
        """The display name of a moniker (upper case, for comparisons)"""
        state = self._com_state(moniker, 'moniker')
        if state is not None:
            return self._moniker_display(state['parts']).upper()
        memory = self.emu.heap_alloc(4)
        try:
            self._mem_write(memory, b'\x00' * 4)
            if self._guest_method(moniker, 20, [0, 0, memory]):  # GetDisplayName
                return f'#{moniker:08x}'
            text_ptr = self._read_u32(memory)
            name = self.read_wide_string(text_ptr)
            self.CoTaskMemFree([text_ptr])
            return name.upper()
        finally:
            self.emu.heap_free(memory)

    def _running_object(self, name):
        table = getattr(self, '_running_object_table', 0)
        if not table:
            return None
        for entry in self.com_objects[table]['entries'].values():
            if entry['name'] == name:
                return entry
        return None

    def _com_running_object_table(self, method, wide, args):
        result = self._com_unknown(method, args)
        if result is not None:
            return result
        state = self.com_objects.get(args[0])
        if method == 'Register':
            unknown, moniker, out = args[2], args[3], args[4]
            if not unknown or not moniker:
                return self.E_INVALIDARG
            name = self._moniker_name(moniker)
            already = self._running_object(name) is not None
            self._add_ref(unknown)
            cookie = state['next']
            state['next'] += 1
            state['entries'][cookie] = {'name': name, 'object': unknown,
                                        'time': self._filetime_now()}
            if out:
                self._mem_write(out, struct.pack('<I', cookie))
            return self.MK_S_MONIKERALREADYREGISTERED if already else self.S_OK
        if method == 'Revoke':
            entry = state['entries'].pop(args[1], None)
            if entry is None:
                return self.E_INVALIDARG
            self._release(entry['object'])
            return self.S_OK
        if method == 'IsRunning':
            return self.S_OK if self._running_object(self._moniker_name(args[1])) \
                else self.S_FALSE
        if method == 'GetObject':
            entry = self._running_object(self._moniker_name(args[1]))
            self._mem_write(args[2], struct.pack('<I', entry['object'] if entry else 0))
            if entry is None:
                return self.MK_E_UNAVAILABLE
            self._add_ref(entry['object'])
            return self.S_OK
        if method == 'NoteChangeTime':
            entry = state['entries'].get(args[1])
            if entry is None:
                return self.E_INVALIDARG
            entry['time'] = struct.unpack('<Q', self.emu.uc.mem_read(args[2], 8))[0]
            return self.S_OK
        if method == 'GetTimeOfLastChange':
            entry = self._running_object(self._moniker_name(args[1]))
            if entry is None:
                return self.MK_E_UNAVAILABLE
            self._mem_write(args[2], struct.pack('<Q', entry['time']))
            return self.S_OK
        if method == 'EnumRunning':
            self._mem_write(args[1], b'\x00' * 4)
            return self.E_NOTIMPL
        return self.E_NOTIMPL

    # ---------- File, item and composite monikers ----------

    @staticmethod
    def _moniker_display(parts):
        return ''.join(part[1] if part[0] == 'file' else part[1] + part[2] for part in parts)

    def _new_moniker(self, parts):
        return self._new_ole_object('moniker', 'IMoniker',
                                    (self.IID_IMONIKER, self.IID_IPERSISTSTREAM,
                                     self.IID_IPERSIST), {'parts': list(parts)})

    def CreateFileMoniker(self, args):
        """CreateFileMoniker(lpszPathName, ppmk)"""
        if not args[0] or not args[1]:
            return self.E_INVALIDARG
        return self._return_object(self._new_moniker([('file', self.read_wide_string(args[0]))]),
                                   args[1])

    def CreateItemMoniker(self, args):
        """CreateItemMoniker(lpszDelim, lpszItem, ppmk)"""
        if not args[2]:
            return self.E_INVALIDARG
        delimiter = self.read_wide_string(args[0]) if args[0] else ''
        item = self.read_wide_string(args[1]) if args[1] else ''
        return self._return_object(self._new_moniker([('item', delimiter, item)]), args[2])

    def CreateGenericComposite(self, args):
        """CreateGenericComposite(pmkFirst, pmkRest, ppmkComposite)"""
        first, rest, out = args[:3]
        if not out:
            return self.E_INVALIDARG
        if not first or not rest:
            single = first or rest
            if single:
                self._add_ref(single)
            self._mem_write(out, struct.pack('<I', single))
            return self.S_OK if single else self.E_INVALIDARG
        left, right = self._com_state(first, 'moniker'), self._com_state(rest, 'moniker')
        if left is None or right is None:
            self._mem_write(out, b'\x00' * 4)
            log.debug("CreateGenericComposite: a moniker of the program is not supported")
            return self.E_NOTIMPL
        return self._return_object(self._new_moniker(left['parts'] + right['parts']), out)

    def MkParseDisplayName(self, args):
        """MkParseDisplayName(pbc, szUserName, pchEaten, ppmk): "path!item!item"
        as a file moniker composed with item monikers"""
        name = self.read_wide_string(args[1]) if args[1] else ''
        if args[3]:
            self._mem_write(args[3], b'\x00' * 4)
        if not name or not args[3]:
            if args[2]:
                self._mem_write(args[2], b'\x00' * 4)
            return self.MK_E_SYNTAX
        pieces = name.split('!')
        parts = [('file', pieces[0])] if pieces[0] else []
        parts += [('item', '!', item) for item in pieces[1:]]
        if args[2]:
            self._mem_write(args[2], struct.pack('<I', len(name)))
        return self._return_object(self._new_moniker(parts), args[3])

    def _write_task_string(self, out, text):
        pointer = self._alloc_units(self._text_units(text, True), True)
        return self.S_OK if pointer and self._mem_write(out, struct.pack('<I', pointer)) \
            else 0x8007000E

    def _moniker_bytes(self, parts):
        """The persistent data of a moniker (as Windows writes it)"""
        def ansi(text):
            raw = text.encode('cp1252', errors='replace') + b'\x00'
            return struct.pack('<I', len(raw)) + raw
        if len(parts) > 1:
            data = struct.pack('<I', len(parts))
            for part in parts:
                clsid = self.CLSID_FILEMONIKER if part[0] == 'file' else self.CLSID_ITEMMONIKER
                data += self._guid_bytes(clsid) + self._moniker_bytes([part])
            return data
        part = parts[0]
        if part[0] == 'file':
            unicode = part[1].encode('utf-16-le')
            extra = b'' if part[1].isascii() else \
                struct.pack('<IIH', len(unicode) + 6, len(unicode), 3) + unicode
            return (struct.pack('<H', 0) + ansi(part[1]) + struct.pack('<HH', 0xFFFF, 0xDEAD) +
                    b'\x00' * 20 + struct.pack('<I', len(extra)) + extra)
        return ansi(part[1]) + ansi(part[2])

    def _parse_moniker_bytes(self, clsid, data):
        """(parts, bytes used) of persistent moniker data, or None"""
        def ansi(position):
            length = struct.unpack_from('<I', data, position)[0]
            text = data[position + 4:position + 4 + length].split(b'\x00')[0]
            return text.decode('cp1252', errors='replace'), position + 4 + length
        try:
            if clsid == self.CLSID_FILEMONIKER:
                path, position = ansi(2)
                position += 4 + 20
                extra = struct.unpack_from('<I', data, position)[0]
                if extra >= 6:
                    size = struct.unpack_from('<I', data, position + 4)[0]
                    path = data[position + 10:position + 10 + size].decode('utf-16-le')
                return [('file', path)], position + 4 + extra
            if clsid == self.CLSID_ITEMMONIKER:
                delimiter, position = ansi(0)
                item, position = ansi(position)
                return [('item', delimiter, item)], position
            if clsid == self.CLSID_COMPOSITEMONIKER:
                count = struct.unpack_from('<I', data, 0)[0]
                parts, position = [], 4
                for _ in range(min(count, 64)):
                    inner = self._read_guid_bytes(data[position:position + 16])
                    parsed = self._parse_moniker_bytes(inner, data[position + 16:])
                    if parsed is None:
                        return None
                    parts += parsed[0]
                    position += 16 + parsed[1]
                return parts, position
        except (struct.error, UnicodeDecodeError):
            return None
        return None

    @staticmethod
    def _read_guid_bytes(raw):
        data1, data2, data3, data4 = struct.unpack('<IHH8s', raw)
        return f'{data1:08x}-{data2:04x}-{data3:04x}-{data4[:2].hex()}-{data4[2:].hex()}'

    def _bind_moniker(self, parts, riid, out, bind_ctx):
        """IMoniker::BindToObject: a running object (the running object table),
        or an item of the object its left part binds to (IOleItemContainer)"""
        entry = self._running_object(self._moniker_display(parts).upper())
        if entry is not None:
            return self._com_unknown('QueryInterface', [entry['object'], riid, out]) \
                if entry['object'] in self.com_objects else \
                self._guest_method(entry['object'], 0, [riid, out])
        if len(parts) > 1 and parts[-1][0] == 'item':
            memory = self.emu.heap_alloc(20)
            try:
                self._mem_write(memory, self._guid_bytes(self.IID_IOLEITEMCONTAINER) +
                                b'\x00' * 4)
                result = self._bind_moniker(parts[:-1], memory, memory + 16, bind_ctx)
                if result:
                    return result
                container = self._read_u32(memory + 16)
            finally:
                self.emu.heap_free(memory)
            item = self._alloc_units(self._text_units(parts[-1][2], True), True)
            try:
                result = self._guest_method(container, 6, [item, 1, bind_ctx, riid, out])
            finally:
                self.emu.heap_free(item)
                self._release(container)
            return result
        return self.MK_E_NOOBJECT  # No OLE server can open the file

    def _com_moniker(self, method, wide, args):
        result = self._com_unknown(method, args)
        if result is not None:
            return result
        state = self.com_objects.get(args[0])
        parts = state['parts']
        name = self._moniker_display(parts)
        if method == 'GetClassID':
            clsid = self.CLSID_COMPOSITEMONIKER if len(parts) > 1 else \
                self.CLSID_FILEMONIKER if parts[0][0] == 'file' else self.CLSID_ITEMMONIKER
            self._mem_write(args[1], self._guid_bytes(clsid))
            return self.S_OK
        if method == 'IsDirty':
            return self.S_FALSE
        if method == 'Save':
            return self._stream_write_bytes(args[1], self._moniker_bytes(parts))
        if method == 'GetSizeMax':
            self._mem_write(args[1], struct.pack('<Q', len(self._moniker_bytes(parts)) + 256))
            return self.S_OK
        if method == 'Load':
            clsid = self.CLSID_COMPOSITEMONIKER if len(parts) > 1 else \
                self.CLSID_FILEMONIKER if parts[0][0] == 'file' else self.CLSID_ITEMMONIKER
            stream = self._com_state(args[1], 'stream')
            if stream is None:
                return self.E_NOTIMPL
            parsed = self._parse_moniker_bytes(clsid, bytes(stream['entry'].data[stream['pos']:]))
            if parsed is None:
                return 0x80030026  # STG_E_READFAULT
            state['parts'], used = parsed
            stream['pos'] += used
            return self.S_OK
        if method == 'BindToObject':
            if args[4]:
                self._mem_write(args[4], b'\x00' * 4)
            return self._bind_moniker(parts, args[3], args[4], args[1])
        if method == 'BindToStorage':
            if args[4]:
                self._mem_write(args[4], b'\x00' * 4)
            if len(parts) == 1 and parts[0][0] == 'file' and \
                    self._read_guid(args[3]) == self.IID_ISTORAGE:
                text = self._alloc_units(self._text_units(parts[0][1], True), True)
                try:
                    result = self.StgOpenStorage([text, 0, 0x12, 0, 0, args[4]])
                    if result:
                        result = self.StgOpenStorage([text, 0, 0x10, 0, 0, args[4]])
                finally:
                    self.emu.heap_free(text)
                return result
            return self.MK_E_NOSTORAGE
        if method == 'Reduce':
            if args[3]:
                self._mem_write(args[3], b'\x00' * 4)
            self._com_unknown('AddRef', [args[0]])
            self._mem_write(args[4], struct.pack('<I', args[0]))
            return self.MK_S_REDUCED_TO_SELF
        if method == 'ComposeWith':
            right = self._com_state(args[1], 'moniker')
            if right is None:
                self._mem_write(args[3], b'\x00' * 4)
                return self.MK_E_NEEDGENERIC
            return self._return_object(self._new_moniker(parts + right['parts']), args[3])
        if method == 'Enum':
            self._mem_write(args[2], b'\x00' * 4)
            return self.S_OK if len(parts) == 1 else self.E_NOTIMPL
        if method == 'IsEqual':
            other = self._com_state(args[1], 'moniker')
            return self.S_OK if other is not None and \
                self._moniker_display(other['parts']).upper() == name.upper() else self.S_FALSE
        if method == 'Hash':
            value = 0
            for char in name.upper():
                value = (value * 31 + ord(char)) & 0xFFFFFFFF
            self._mem_write(args[1], struct.pack('<I', value))
            return self.S_OK
        if method == 'IsRunning':
            return self.S_OK if self._running_object(name.upper()) else self.S_FALSE
        if method == 'GetTimeOfLastChange':
            entry = self._running_object(name.upper())
            if entry is not None:
                self._mem_write(args[3], struct.pack('<Q', entry['time']))
                return self.S_OK
            host = self.resolve_drive_path(parts[0][1]) if parts[0][0] == 'file' else None
            if host and os.path.exists(host):
                self._mem_write(args[3], struct.pack('<Q', self._filetime(os.path.getmtime(host))))
                return self.S_OK
            return self.MK_E_UNAVAILABLE
        if method == 'Inverse':
            self._mem_write(args[1], b'\x00' * 4)
            return self.MK_E_NOINVERSE
        if method == 'CommonPrefixWith':
            self._mem_write(args[2], b'\x00' * 4)
            return self.MK_E_NOPREFIX
        if method == 'RelativePathTo':
            self._mem_write(args[2], b'\x00' * 4)
            return self.E_NOTIMPL
        if method == 'GetDisplayName':
            return self._write_task_string(args[3], name)
        if method == 'ParseDisplayName':
            text = self.read_wide_string(args[3]) if args[3] else ''
            if not text.startswith('!'):
                self._mem_write(args[5], b'\x00' * 4)
                return self.MK_E_SYNTAX
            items = [('item', '!', item) for item in text[1:].split('!')]
            self._mem_write(args[4], struct.pack('<I', len(text)))
            return self._return_object(self._new_moniker(items), args[5])
        if method == 'IsSystemMoniker':
            kind = 1 if len(parts) > 1 else 2 if parts[0][0] == 'file' else 4  # MKSYS_*
            self._mem_write(args[1], struct.pack('<I', kind))
            return self.S_OK
        return self.E_NOTIMPL

