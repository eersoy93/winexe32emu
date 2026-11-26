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

"""WinAPIHandler mixin: the type information of type libraries (ITypeLib
with its types, ITypeInfo), read by typelib_reader"""

import os
import struct

from unicorn import UcError

from ..logger import log
from .com import ComMixin
from .typelib import type_library_data
from . import typelib_reader as tlr

ComMixin.COM_INTERFACES.update({
    'type_info': [
        ('QueryInterface', 3), ('AddRef', 1), ('Release', 1), ('GetTypeAttr', 2),
        ('GetTypeComp', 2), ('GetFuncDesc', 3), ('GetVarDesc', 3), ('GetNames', 5),
        ('GetRefTypeOfImplType', 3), ('GetImplTypeFlags', 3), ('GetIDsOfNames', 4),
        ('Invoke', 8), ('GetDocumentation', 6), ('GetDllEntry', 6), ('GetRefTypeInfo', 3),
        ('AddressOfMember', 4), ('CreateInstance', 4), ('GetMops', 3),
        ('GetContainingTypeLib', 3), ('ReleaseTypeAttr', 2), ('ReleaseFuncDesc', 2),
        ('ReleaseVarDesc', 2)],
})

IID_ITYPEINFO = '00020401-0000-0000-c000-000000000046'
IID_STDOLE = '00020430-0000-0000-c000-000000000046'
MEMBERID_NIL = 0xFFFFFFFF
ID_DEFAULTINST = 0xFFFFFFFE  # AddressOfMember: the default instance of a coclass
DISP_E_UNKNOWNNAME = 0x80020006
TYPE_E_ELEMENTNOTFOUND = 0x8002802B
TYPE_E_CANTLOADLIBRARY = 0x80029C4A
E_NOTIMPL = 0x80004001
VT_PTR, VT_SAFEARRAY, VT_CARRAY, VT_USERDEFINED = 26, 27, 28, 29


def _stdole_library():
    """OLE Automation (stdole32.tlb) as far as other libraries refer to it:
    GUID, DISPPARAMS, EXCEPINFO, IUnknown, IDispatch, IEnumVARIANT"""
    lib = tlr.TypeLibrary()
    lib.guid, lib.major, lib.minor, lib.name = IID_STDOLE, 2, 0, 'stdole'
    lib.doc = 'OLE Automation'

    def func(name, memid, ovft, params, ret=('vt', 25)):
        f = tlr.FuncInfo()
        f.name, f.memid, f.ovft, f.ret = name, memid, ovft, ret
        f.params = [(n, td, flags, None) for n, td, flags in params]
        return f

    def record(index, name, guid, size):
        t = tlr.TypeInfo(index)
        t.name, t.guid, t.typekind, t.size_instance = name, guid, tlr.TKIND_RECORD, size
        return t

    void_ptr = ('ptr', ('vt', 24))
    unknown = tlr.TypeInfo(3)
    unknown.name, unknown.guid = 'IUnknown', '00000000-0000-0000-c000-000000000046'
    unknown.flags, unknown.size_vft = 0x10, 12  # TYPEFLAG_FHIDDEN
    unknown.funcs = [
        func('QueryInterface', 0x60000000, 0, [
            ('riid', ('ptr', ('user', ('stdole', 0))), 1), ('ppvObj', ('ptr', void_ptr), 2)]),
        func('AddRef', 0x60000001, 4, [], ('vt', 19)),
        func('Release', 0x60000002, 8, [], ('vt', 19))]
    dispatch = tlr.TypeInfo(4)
    dispatch.name, dispatch.guid = 'IDispatch', '00020400-0000-0000-c000-000000000046'
    dispatch.flags, dispatch.size_vft = 0x10, 28
    dispatch.impls = [(('stdole', 3), 0)]
    dispatch.funcs = [
        func('GetTypeInfoCount', 0x60010000, 12, [('pctinfo', ('ptr', ('vt', 23)), 2)]),
        func('GetTypeInfo', 0x60010001, 16, [
            ('itinfo', ('vt', 23), 1), ('lcid', ('vt', 19), 1),
            ('pptinfo', ('ptr', void_ptr), 2)]),
        func('GetIDsOfNames', 0x60010002, 20, [
            ('riid', ('ptr', ('user', ('stdole', 0))), 1),
            ('rgszNames', ('ptr', ('ptr', ('vt', 17))), 1),
            ('cNames', ('vt', 23), 1), ('lcid', ('vt', 19), 1),
            ('rgdispid', ('ptr', ('vt', 3)), 2)]),
        func('Invoke', 0x60010003, 24, [
            ('dispidMember', ('vt', 3), 1), ('riid', ('ptr', ('user', ('stdole', 0))), 1),
            ('lcid', ('vt', 19), 1), ('wFlags', ('vt', 18), 1),
            ('pdispparams', ('ptr', ('user', ('stdole', 1))), 1),
            ('pvarResult', ('ptr', ('vt', 12)), 2),
            ('pexcepinfo', ('ptr', ('user', ('stdole', 2))), 2),
            ('puArgErr', ('ptr', ('vt', 23)), 2)])]
    enum = tlr.TypeInfo(5)
    enum.name, enum.guid = 'IEnumVARIANT', '00020404-0000-0000-c000-000000000046'
    enum.flags, enum.size_vft = 0x10, 28
    enum.impls = [(('stdole', 3), 0)]
    lib.types = [record(0, 'GUID', '00000000-0000-0000-0000-000000000000', 16),
                 record(1, 'DISPPARAMS', '00000000-0000-0000-0000-000000000000', 16),
                 record(2, 'EXCEPINFO', '00000000-0000-0000-0000-000000000000', 32),
                 unknown, dispatch, enum]
    # Internal references of the built-in library: ('stdole', index)
    for index in range(len(lib.types)):
        lib.refs[('stdole', index)] = ('internal', index)
    return lib


class TypeInfoMixin:
    """ITypeLib type information and ITypeInfo objects"""

    # ---------- Libraries ----------

    STDOLE_FILES = {1: 'stdole32.tlb', 2: 'stdole2.tlb'}

    def _builtin_typelib_path(self, guid, major):
        """The file a library that comes with the emulated oleaut32 is in
        (OLE Automation), when the registry does not name one; '' if none"""
        if guid != IID_STDOLE:
            return ''
        return f"C:\\Windows\\System32\\{self.STDOLE_FILES.get(major, 'stdole2.tlb')}"

    def _builtin_typelib(self, name):
        """The built-in TypeLibrary of a file name LoadTypeLib cannot find, or None"""
        base = name.replace('/', '\\').rsplit('\\', 1)[-1].lower()
        if base not in self.STDOLE_FILES.values():
            return None
        cache = self.__dict__.setdefault('_builtin_typelibs', {})
        if base not in cache:
            model = _stdole_library()
            model.major = 1 if base == 'stdole32.tlb' else 2
            cache[base] = model
        return cache[base]

    def _typelib_model(self, state):
        """The parsed library (TypeLibrary) of an ITypeLib object, or None"""
        if 'model' not in state:
            state['model'] = self._typelib_model_of_file(state.get('file', ''))
        return state['model']

    def _typelib_model_of_file(self, name):
        cache = self.__dict__.setdefault('_typelib_models', {})
        candidates = [(name, None)]
        head, _, tail = name.rpartition('\\')
        if head and tail.isdigit():
            candidates.append((head, int(tail)))
        for candidate, index in candidates:
            full = self.full_windows_path(candidate)
            host = self.resolve_drive_path(full) if full else None
            if not host or not os.path.isfile(host):
                continue
            key = (host.lower(), index)
            if key not in cache:
                try:
                    cache[key] = tlr.read_type_library(type_library_data(host, index) or b'')
                except tlr.TypeLibraryError as e:
                    log.debug(f"Type library \"{candidate}\" not read: {e}")
                    cache[key] = None
            return cache[key]
        return None

    def _typelib_by_guid(self, guid, major, minor, lcid):
        """The TypeLibrary registered for a library (stdole is built in)"""
        cache = self.__dict__.setdefault('_typelib_by_guid', {})
        key = (guid, major)
        if key in cache:
            return cache[key]
        model = None
        cell = self.emu.heap_alloc(16)
        try:
            self._mem_write(cell, self._guid_bytes(guid))
            if self.QueryPathOfRegTypeLib([cell, major, minor, lcid, cell + 12]) == self.S_OK:
                bstr = struct.unpack('<I', self.emu.uc.mem_read(cell + 12, 4))[0]
                path = self.read_wide_string(bstr)
                self.emu.heap_free(bstr - 4)
                model = self._typelib_model_of_file(path)
        finally:
            self.emu.heap_free(cell)
        if model is None and guid == IID_STDOLE:
            model = _stdole_library()
        cache[key] = model
        return model

    def _new_typelib_object(self, model, name=''):
        """An ITypeLib object of a parsed library; its interface pointer"""
        attributes = {'guid': model.guid, 'lcid': model.lcid, 'syskind': model.syskind,
                      'major': model.major, 'minor': model.minor, 'flags': model.flags,
                      'name': model.name, 'doc': model.doc}
        pointers = self._com_new_object(
            [((self.IID_ITYPELIB, self.IID_IUNKNOWN), self._com_vtable('ITypeLib', 'type_lib'))],
            {'file': name, 'attr': None, 'library': attributes, 'model': model})
        return pointers[self.IID_ITYPELIB]

    def _new_typeinfo_object(self, model, info, view=None):
        """An ITypeInfo object of a type (view 'interface': the vtable
        interface of a dual dispinterface)"""
        cache = self.__dict__.setdefault('_typeinfo_objects', {})
        key = (id(model), info.index, view)
        pointer = cache.get(key)
        state = self.com_objects.get(pointer) if pointer else None
        if state is not None and state.get('type') is info:
            state['refs'] += 1
            return pointer
        pointers = self._com_new_object(
            [((IID_ITYPEINFO, self.IID_IUNKNOWN), self._com_vtable('ITypeInfo', 'type_info'))],
            {'lib': model, 'type': info, 'view': view, 'allocations': {}})
        pointer = pointers[IID_ITYPEINFO]
        cache[key] = pointer
        return pointer

    def _write_pointer(self, address, value):
        return bool(address) and self._mem_write(address, struct.pack('<I', value & 0xFFFFFFFF))

    def _write_bstr(self, address, text):
        if address:
            bstr = self._alloc_bstr(text.encode('utf-16-le')) if text is not None else 0
            self._write_pointer(address, bstr)

    def _typelib_model_method(self, method, state, args):
        """ITypeLib methods that need the library's types; None: not handled"""
        model = self._typelib_model(state)
        if model is None:
            return None
        if method == 'GetTypeInfoCount':
            return len(model.types)
        if method in ('GetTypeInfo', 'GetTypeInfoType'):
            index, out = args[1], args[2]
            if index >= len(model.types):
                return TYPE_E_ELEMENTNOTFOUND
            if method == 'GetTypeInfoType':
                return self.S_OK if self._mem_write(out, struct.pack(
                    '<I', model.types[index].typekind)) else self.E_POINTER
            return self.S_OK if self._write_pointer(
                out, self._new_typeinfo_object(model, model.types[index])) else self.E_POINTER
        if method == 'GetTypeInfoOfGuid':
            guid, out = self._read_guid(args[1]), args[2]
            self._write_pointer(out, 0)
            info = next((t for t in model.types if t.guid == guid), None)
            log.debug(f"ITypeLib::GetTypeInfoOfGuid({{{guid}}}) -> "
                      f"{info.name if info else 'not found'}")
            if info is None:
                return TYPE_E_ELEMENTNOTFOUND
            return self.S_OK if self._write_pointer(
                out, self._new_typeinfo_object(model, info)) else self.E_POINTER
        if method == 'GetDocumentation':
            index = args[1]
            if index == 0xFFFFFFFF:
                name, doc, context = model.name, model.doc, model.helpcontext
            elif index < len(model.types):
                info = model.types[index]
                name, doc, context = info.name, info.doc, info.helpcontext
            else:
                return TYPE_E_ELEMENTNOTFOUND
            self._write_bstr(args[2], name)
            self._write_bstr(args[3], doc)
            if args[4]:
                self._mem_write(args[4], struct.pack('<I', context))
            self._write_bstr(args[5], model.helpfile)
            return self.S_OK
        if method in ('IsName', 'FindName'):
            return self._typelib_find_name(model, method, args)
        if method == 'GetTypeComp':
            return self.S_OK if self._write_pointer(
                args[1], self._new_typecomp_object(model)) else self.E_POINTER
        return None

    def _typelib_find_name(self, model, method, args):
        """ITypeLib::IsName(name, hash, pfName) / FindName(name, hash,
        ppTInfo, rgMemId, pcFound)"""
        name = self.read_wide_string(args[1]) if args[1] else ''
        lower = name.lower()
        found = []  # (exact name, type, memid)
        for info in model.types:
            if info.name.lower() == lower:
                found.append((info.name, info, MEMBERID_NIL))
            for member in info.funcs + info.vars:
                if member.name.lower() == lower:
                    found.append((member.name, info, member.memid))
                    break
        if method == 'IsName':
            if found:  # The library's spelling goes back into the buffer
                self._mem_write(args[1], found[0][0].encode('utf-16-le') + b'\x00\x00')
            return self.S_OK if self._mem_write(
                args[3], struct.pack('<i', -1 if found else 0)) else self.E_POINTER
        try:
            room = struct.unpack('<H', self.emu.uc.mem_read(args[5], 2))[0]
        except UcError:
            return self.E_POINTER
        found = found[:room]
        for number, (_, info, memid) in enumerate(found):
            self._write_pointer(args[3] + 4 * number, self._new_typeinfo_object(model, info))
            self._mem_write(args[4] + 4 * number, struct.pack('<I', memid))
        self._mem_write(args[5], struct.pack('<H', len(found)))
        return self.S_OK

    # ---------- ITypeInfo ----------

    def _ti_funcs(self, state):
        return state['type'].funcs

    def _ti_kind(self, state):
        info = state['type']
        if state['view'] == 'interface':
            return tlr.TKIND_INTERFACE
        return info.typekind

    def _ti_impls(self, state):
        """[(href, flags)] of a type: a dual dispinterface derives from IDispatch"""
        info = state['type']
        return info.impls

    def _ti_alloc(self, state, size):
        block = self.emu.heap_alloc(max(size, 4))
        state['allocations'][block] = []
        return block

    def _ti_sub_alloc(self, state, owner, size):
        block = self.emu.heap_alloc(max(size, 4))
        state['allocations'][owner].append(block)
        return block

    def _ti_free(self, state, block):
        for sub in state['allocations'].pop(block, []):
            self.emu.heap_free(sub)
        if block:
            self.emu.heap_free(block)

    def _ti_href(self, model, href):
        """A typedesc reference as a 32-bit HREFTYPE"""
        if isinstance(href, tuple):  # Built-in stdole: its index
            return href[1] * 4 + 4
        return href

    def _ti_typedesc(self, state, owner, td, model):
        """(union DWORD, VARTYPE) of a TYPEDESC; nested ones are allocated"""
        kind = td[0]
        if kind == 'vt':
            return 0, td[1]
        if kind == 'user':
            return self._ti_href(model, td[1]), VT_USERDEFINED
        if kind in ('ptr', 'safearray'):
            inner = self._ti_sub_alloc(state, owner, 8)
            value, vt = self._ti_typedesc(state, owner, td[1], model)
            self._mem_write(inner, struct.pack('<IHH', value, vt, 0))
            return inner, VT_PTR if kind == 'ptr' else VT_SAFEARRAY
        if kind == 'carray':
            bounds = td[2]
            array = self._ti_sub_alloc(state, owner, 12 + 8 * len(bounds))
            value, vt = self._ti_typedesc(state, owner, td[1], model)
            data = struct.pack('<IHHH', value, vt, 0, len(bounds)) + b'\x00\x00'
            for elements, lower in bounds:
                data += struct.pack('<Ii', elements, lower)
            self._mem_write(array, data)
            return array, VT_CARRAY
        return 0, 0

    def _ti_variant(self, state, owner, value):
        """A VARIANT of a constant's (VT_xxx, value)"""
        variant = self._ti_sub_alloc(state, owner, 16)
        vt, data = value
        if vt == 8:
            bstr = self._alloc_bstr(data.encode('utf-16-le')) if data is not None else 0
            if bstr:
                state['allocations'][owner].append(bstr - 4)
            payload = struct.pack('<I', bstr)
        else:
            vt = 3  # VT_I4
            payload = struct.pack('<i', data)
        self._mem_write(variant, struct.pack('<HHHH', vt, 0, 0, 0) + payload + b'\x00' * 4)
        return variant

    def _ti_type_attr(self, state):
        model, info = state['lib'], state['type']
        kind = self._ti_kind(state)
        flags = info.flags
        size_vft = info.size_vft
        if kind == tlr.TKIND_DISPATCH:
            size_vft = 28
            flags |= 0x1000  # TYPEFLAG_FDISPATCHABLE
        elif state['view'] == 'interface':
            flags |= 0x1000
        impls = len(self._ti_impls(state))
        block = self._ti_alloc(state, 76)
        alias_value, alias_vt = (self._ti_typedesc(state, block, info.alias, model)
                                 if info.alias else (0, 0))
        data = (self._guid_bytes(info.guid) +
                struct.pack('<IIIIIIIHHHHHHHH', model.lcid, 0, MEMBERID_NIL, MEMBERID_NIL, 0,
                            info.size_instance, kind, len(info.funcs), len(info.vars), impls,
                            size_vft, info.alignment, flags, info.major, info.minor) +
                struct.pack('<IHHIHH', alias_value, alias_vt, 0, 0, 0, 0))
        self._mem_write(block, data)
        return block

    def _ti_elemdesc(self, state, owner, td, flags, model):
        value, vt = self._ti_typedesc(state, owner, td, model)
        return struct.pack('<IHHIHH', value, vt, 0, 0, flags, 0)

    def _ti_func_desc(self, state, func):
        model = state['lib']
        block = self._ti_alloc(state, 52)
        params = b''.join(self._ti_elemdesc(state, block, td, flags, model)
                          for _, td, flags, _ in func.params)
        array = 0
        if params:
            array = self._ti_sub_alloc(state, block, len(params))
            self._mem_write(array, params)
        kind = func.funckind
        if self._ti_kind(state) == tlr.TKIND_DISPATCH and kind == tlr.FUNC_PUREVIRTUAL:
            kind = tlr.FUNC_DISPATCH
        data = struct.pack('<IIIIIIhhhh', func.memid, 0, array, kind, func.invkind,
                           func.callconv, len(func.params), func.opt, func.ovft, 0)
        data += self._ti_elemdesc(state, block, func.ret, func.ret_flags, model)
        data += struct.pack('<HH', func.flags, 0)
        self._mem_write(block, data)
        return block

    def _ti_var_desc(self, state, var):
        model = state['lib']
        block = self._ti_alloc(state, 36)
        union = var.offset
        if var.varkind == tlr.VAR_CONST and var.value is not None:
            union = self._ti_variant(state, block, var.value)
        data = struct.pack('<III', var.memid, 0, union)
        data += self._ti_elemdesc(state, block, var.type, 0, model)
        data += struct.pack('<HHI', var.flags, 0, var.varkind)
        self._mem_write(block, data)
        return block

    def _ti_member(self, state, memid):
        info = state['type']
        for member in info.funcs + info.vars:
            if member.memid == memid:
                return member
        return None

    def _ti_resolve(self, state, href):
        """(model, TypeInfo, view) an HREFTYPE of this type's library refers to"""
        model = state['lib']
        if href & 3 == 1:  # The vtable interface of a dual dispinterface
            index = href >> 2
            if index < len(model.types):
                return model, model.types[index], 'interface'
            return None
        target = model.refs.get(href)
        if target is None:
            target = next((t for k, t in model.refs.items()
                           if isinstance(k, tuple) and self._ti_href(model, k) == href), None)
        if target is None:
            return None
        if target[0] == 'internal':
            index = target[1]
            return (model, model.types[index], None) if index < len(model.types) else None
        guid, major, minor, lcid, _ = target[1]
        other = self._typelib_by_guid(guid, major, minor, lcid)
        if other is None or target[2] >= len(other.types):
            log.debug(f"ITypeInfo: library {{{guid}}} {major}.{minor} not available")
            return None
        return other, other.types[target[2]], None

    def _com_type_info(self, method, wide, args):
        """ITypeInfo methods"""
        result = self._com_unknown(method, args)
        if result is not None:
            return result
        state = self.com_objects[args[0]]
        model, info = state['lib'], state['type']
        if method == 'GetTypeAttr':
            return self.S_OK if self._write_pointer(args[1], self._ti_type_attr(state)) \
                else self.E_POINTER
        if method in ('ReleaseTypeAttr', 'ReleaseFuncDesc', 'ReleaseVarDesc'):
            if args[1] in state['allocations']:
                self._ti_free(state, args[1])
            return 0
        if method == 'GetFuncDesc':
            funcs = self._ti_funcs(state)
            if args[1] >= len(funcs):
                return TYPE_E_ELEMENTNOTFOUND
            return self.S_OK if self._write_pointer(
                args[2], self._ti_func_desc(state, funcs[args[1]])) else self.E_POINTER
        if method == 'GetVarDesc':
            if args[1] >= len(info.vars):
                return TYPE_E_ELEMENTNOTFOUND
            return self.S_OK if self._write_pointer(
                args[2], self._ti_var_desc(state, info.vars[args[1]])) else self.E_POINTER
        if method == 'GetNames':
            memid, names, room, out = args[1:5]
            member = self._ti_member(state, memid)
            texts = []
            if member is not None:
                texts = [member.name]
                for param in getattr(member, 'params', []):
                    if not param[0]:
                        break  # The value of a property put has no name
                    texts.append(param[0])
            texts = texts[:room]
            for number, text in enumerate(texts):
                self._write_bstr(names + 4 * number, text)
            self._mem_write(out, struct.pack('<I', len(texts)))
            return self.S_OK if member is not None else TYPE_E_ELEMENTNOTFOUND
        if method == 'GetRefTypeOfImplType':
            index = args[1]
            if index == 0xFFFFFFFF:
                if info.dual_interface and state['view'] is None:
                    return self.S_OK if self._mem_write(args[2], struct.pack(
                        '<I', info.index * 4 + 1)) else self.E_POINTER
                return TYPE_E_ELEMENTNOTFOUND
            impls = self._ti_impls(state)
            if index >= len(impls):
                return TYPE_E_ELEMENTNOTFOUND
            return self.S_OK if self._mem_write(args[2], struct.pack(
                '<I', self._ti_href(model, impls[index][0]))) else self.E_POINTER
        if method == 'GetImplTypeFlags':
            impls = self._ti_impls(state)
            if args[1] >= len(impls):
                return TYPE_E_ELEMENTNOTFOUND
            return self.S_OK if self._mem_write(args[2], struct.pack(
                '<I', impls[args[1]][1])) else self.E_POINTER
        if method == 'GetIDsOfNames':
            return self._ti_ids_of_names(state, args[1], args[2], args[3])
        if method == 'GetDocumentation':
            memid = args[1]
            if memid == MEMBERID_NIL:
                name, doc, context = info.name, info.doc, info.helpcontext
            else:
                member = self._ti_member(state, memid)
                if member is None:
                    return TYPE_E_ELEMENTNOTFOUND
                name, doc, context = member.name, member.doc, member.helpcontext
            self._write_bstr(args[2], name)
            self._write_bstr(args[3], doc)
            if args[4]:
                self._mem_write(args[4], struct.pack('<I', context))
            self._write_bstr(args[5], model.helpfile)
            return self.S_OK
        if method == 'GetRefTypeInfo':
            self._write_pointer(args[2], 0)
            target = self._ti_resolve(state, args[1])
            if target is None:
                log.debug(f"ITypeInfo::GetRefTypeInfo({info.name}, 0x{args[1]:x}): not found")
                return TYPE_E_ELEMENTNOTFOUND
            other, other_info, view = target
            return self.S_OK if self._write_pointer(
                args[2], self._new_typeinfo_object(other, other_info, view)) \
                else self.E_POINTER
        if method == 'GetContainingTypeLib':
            if args[1]:
                self._write_pointer(args[1], self._new_typelib_object(model))
            if args[2]:
                self._mem_write(args[2], struct.pack('<I', info.index))
            return self.S_OK
        if method == 'Invoke':
            return self._ti_invoke(state, args)
        if method == 'GetTypeComp':
            return self.S_OK if self._write_pointer(
                args[1], self._new_typecomp_object(model, info, state['view'])) \
                else self.E_POINTER
        if method == 'GetMops':
            self._write_pointer(args[2], 0)
            return self.S_OK
        if method == 'GetDllEntry':
            return TYPE_E_ELEMENTNOTFOUND
        if method == 'AddressOfMember' and args[1] == ID_DEFAULTINST:
            # The default instance cell of a coclass: the host stores its
            # application object there, VBA finds it there (Access 95)
            cells = self.__dict__.setdefault('_typeinfo_default_instances', {})
            key = (model.guid, info.index)
            if key not in cells:
                cells[key] = self.emu.heap_alloc(4)
                self._mem_write(cells[key], b'\x00' * 4)
            return self.S_OK if self._write_pointer(args[3], cells[key]) else self.E_POINTER
        log.warning(f"ITypeInfo::{method} ({info.name}, "
                    f"{', '.join(hex(a) for a in args[1:])}) is not emulated")
        if method in ('GetTypeComp', 'AddressOfMember'):
            self._write_pointer(args[2] if method == 'AddressOfMember' else args[1], 0)
        return E_NOTIMPL

    def _ti_ids_of_names(self, state, names, count, out):
        """ITypeInfo::GetIDsOfNames: the member's DISPID, then its parameters' numbers"""
        texts = []
        for number in range(count):
            pointer = struct.unpack('<I', self.emu.uc.mem_read(names + 4 * number, 4))[0]
            texts.append(self.read_wide_string(pointer) if pointer else '')
        ids = [-1] * count
        result = self.S_OK
        member = None
        if texts:
            lower = texts[0].lower()
            member = next((m for m in state['type'].funcs + state['type'].vars
                           if m.name.lower() == lower), None)
            if member is None:
                # Like Windows, the interfaces it derives from have names too
                member = self._inherited_member(state['lib'], state['type'], state['view'],
                                                texts[0])
        log.debug(f"ITypeInfo::GetIDsOfNames({state['type'].name}, {texts}) -> "
                  f"{member.memid if member is not None else 'unknown'}")
        if member is None:
            result = DISP_E_UNKNOWNNAME
        else:
            ids[0] = member.memid
            params = [p[0].lower() for p in getattr(member, 'params', [])]
            for number, text in enumerate(texts[1:], 1):
                if text.lower() in params:
                    ids[number] = params.index(text.lower())
                else:
                    result = DISP_E_UNKNOWNNAME
        self._mem_write(out, struct.pack(f'<{count}i', *ids))
        return result

    # ---------- ITypeInfo::Invoke ----------

    DISPID_PROPERTYPUT = 0xFFFFFFFD
    DISP_E_MEMBERNOTFOUND, DISP_E_PARAMNOTOPTIONAL = 0x80020003, 0x8002000F
    DISP_E_BADPARAMCOUNT, DISP_E_EXCEPTION = 0x8002000E, 0x80020009
    DISP_E_PARAMNOTFOUND_TI = 0x80020004

    def _ti_value_vt(self, state, td, depth=0):
        """The VARTYPE a parameter of type td is passed as (by value):
        enums are I4, interface pointers VT_DISPATCH / VT_UNKNOWN; None for
        a reference (a pointer to a value)"""
        if depth > 8:
            return 3
        kind = td[0]
        if kind == 'vt':
            return td[1]
        if kind == 'safearray':
            return 0x2000 | (self._ti_value_vt(state, td[1], depth + 1) or 12)
        if kind == 'user':
            target = self._ti_resolve(state, self._ti_href(state['lib'], td[1]))
            if target is None:
                return 3
            other_model, info, _ = target
            if info.typekind == tlr.TKIND_ALIAS and info.alias is not None:
                other = {'lib': other_model, 'type': info, 'view': None}
                return self._ti_value_vt(other, info.alias, depth + 1)
            if info.typekind in (tlr.TKIND_DISPATCH, tlr.TKIND_INTERFACE, tlr.TKIND_COCLASS):
                return 'object'
            if info.typekind == tlr.TKIND_RECORD:
                return 'record'
            return 3  # An enum (or a module): a long
        if kind == 'ptr':
            inner = self._ti_value_vt(state, td[1], depth + 1)
            if inner == 'object':  # A pointer to an interface is the object itself
                return 9 if self._ti_dispatch_target(state, td[1]) else 13
            return None
        return 3

    def _ti_dispatch_target(self, state, td):
        target = self._ti_resolve(state, self._ti_href(state['lib'], td[1])) \
            if td[0] == 'user' else None
        return target is not None and target[1].typekind in (tlr.TKIND_DISPATCH,
                                                              tlr.TKIND_COCLASS)

    def _ti_dwords_of(self, vt, variant):
        """The argument DWORDs of a VARIANT of type vt"""
        raw = bytes(self.emu.uc.mem_read(variant + 8, 8))
        if vt in (5, 6, 7, 20, 21):  # R8, CY, DATE, I8, UI8
            return list(struct.unpack('<II', raw))
        if vt == 12:  # VARIANT by value
            return list(struct.unpack('<IIII', bytes(self.emu.uc.mem_read(variant, 16))))
        value = struct.unpack('<I', raw[:4])[0]
        if vt in (2, 11, 18):  # I2, BOOL, UI2: sign or zero extended
            value &= 0xFFFF
            if vt != 18 and value & 0x8000:
                value |= 0xFFFF0000
        elif vt in (16, 17):  # I1, UI1
            value &= 0xFF
            if vt == 16 and value & 0x80:
                value |= 0xFFFFFF00
        return [value]

    def _ti_invoke(self, state, args):
        """ITypeInfo::Invoke(pvInstance, memid, wFlags, pDispParams,
        pVarResult, pExcepInfo, puArgErr): converts the arguments to the
        parameter types and calls the vtable function of the instance"""
        _, instance, memid, flags, params, result_out, excep, arg_err = args[:8]
        info = state['type']
        func = next((f for f in info.funcs if f.memid == memid and f.invkind & flags), None)
        if func is None:
            log.debug(f"ITypeInfo::Invoke({info.name}, 0x{memid:x}, {flags}): no member")
            return self.DISP_E_MEMBERNOTFOUND
        if func.funckind == tlr.FUNC_DISPATCH or not instance:
            return self.DISP_E_MEMBERNOTFOUND
        rgvarg, named, count, count_named = struct.unpack(
            '<IIII', self.emu.uc.mem_read(params, 16)) if params else (0, 0, 0, 0)
        named_ids = list(struct.unpack(f'<{count_named}I', self.emu.uc.mem_read(
            named, 4 * count_named))) if count_named else []
        real = [i for i, p in enumerate(func.params) if not p[2] & (tlr.PARAMFLAG_FRETVAL |
                                                                    tlr.PARAMFLAG_FLCID)]
        given = {}
        positional = count - count_named
        for number in range(positional):
            if number < len(real):
                given[real[number]] = rgvarg + 16 * (count - 1 - number)
        for number, dispid in enumerate(named_ids):
            if dispid == self.DISPID_PROPERTYPUT and real:
                given[real[-1]] = rgvarg + 16 * number
            elif dispid < len(func.params):
                given[dispid] = rgvarg + 16 * number
        if positional > len(real):
            return self.DISP_E_BADPARAMCOUNT
        temps = []  # VARIANTs to clear afterwards
        dwords = [instance]
        retval = None
        try:
            for index, (_name, td, pflags, _default) in enumerate(func.params):
                if pflags & tlr.PARAMFLAG_FLCID:
                    dwords.append(0x409)
                    continue
                temp = self.emu.heap_alloc(16)
                self._mem_write(temp, b'\x00' * 16)
                temps.append(temp)
                if pflags & tlr.PARAMFLAG_FRETVAL:
                    retval = (temp, td)
                    dwords.append(temp + (0 if td[0] == 'ptr' and td[1] == ('vt', 12) else 8))
                    continue
                vt = self._ti_value_vt(state, td)
                source = given.get(index)
                if source is None:
                    if not pflags & tlr.PARAMFLAG_FOPT and vt != 12 and \
                            not (vt is None and td[1] == ('vt', 12)):
                        if arg_err:
                            self._mem_write(arg_err, struct.pack('<I', index))
                        return self.DISP_E_PARAMNOTOPTIONAL
                    # A missing optional argument: VT_ERROR DISP_E_PARAMNOTFOUND
                    self._mem_write(temp, struct.pack('<HHHHI', 10, 0, 0, 0,
                                                      self.DISP_E_PARAMNOTFOUND_TI))
                    if vt == 12:
                        dwords.extend(self._ti_dwords_of(12, temp))
                    elif vt is None:
                        dwords.append(temp if td[1] == ('vt', 12) else 0)
                    else:
                        dwords.extend([0] * len(self._ti_dwords_of(vt, temp)))
                    continue
                source_vt = struct.unpack('<H', self.emu.uc.mem_read(source, 2))[0]
                if vt is None:  # By reference
                    inner = td[1]
                    if source_vt & 0x4000:  # VT_BYREF: the caller's storage
                        dwords.append(struct.unpack('<I', self.emu.uc.mem_read(source + 8, 4))[0])
                    elif inner == ('vt', 12):
                        dwords.append(source)
                    else:
                        inner_vt = self._ti_value_vt(state, inner)
                        if isinstance(inner_vt, int) and self.VariantChangeType(
                                [temp, source, 0, inner_vt]) & 0x80000000:
                            return 0x80020005  # DISP_E_TYPEMISMATCH
                        dwords.append(temp + 8)
                    continue
                if vt == 12:
                    if source_vt & 0x4000:
                        self.VariantCopyInd([temp, source])
                        dwords.extend(self._ti_dwords_of(12, temp))
                    else:
                        dwords.extend(self._ti_dwords_of(12, source))
                    continue
                if vt in ('record',):
                    dwords.append(struct.unpack('<I', self.emu.uc.mem_read(source + 8, 4))[0])
                    continue
                result = self.VariantChangeType([temp, source, 0, vt])
                if result & 0x80000000:
                    if arg_err:
                        self._mem_write(arg_err, struct.pack('<I', index))
                    return result
                dwords.extend(self._ti_dwords_of(vt, temp))
            vtable = struct.unpack('<I', self.emu.uc.mem_read(instance, 4))[0]
            function = struct.unpack('<I', self.emu.uc.mem_read(vtable + func.ovft, 4))[0]
            log.debug(f"ITypeInfo::Invoke({info.name}.{func.name}) -> 0x{function:x}")
            returned = self.emu.call_callback(function, dwords) & 0xFFFFFFFF
            if func.ret == ('vt', 25):  # HRESULT
                if returned & 0x80000000:
                    if excep:
                        self._ti_fill_excepinfo(excep, returned)
                        return self.DISP_E_EXCEPTION
                    return returned
            elif func.ret != ('vt', 24) and result_out:
                ret_vt = self._ti_value_vt(state, func.ret)
                if isinstance(ret_vt, int):
                    self._mem_write(result_out, struct.pack('<HHHHII', ret_vt, 0, 0, 0,
                                                            returned, 0))
            if retval is not None and result_out:
                temp, td = retval
                inner = td[1] if td[0] == 'ptr' else td
                self.VariantClear([result_out])
                if inner == ('vt', 12):
                    self._mem_write(result_out, bytes(self.emu.uc.mem_read(temp, 16)))
                else:
                    inner_vt = self._ti_value_vt(state, inner)
                    if not isinstance(inner_vt, int):
                        inner_vt = 3
                    self._mem_write(temp, struct.pack('<H', inner_vt))
                    self._mem_write(result_out, bytes(self.emu.uc.mem_read(temp, 16)))
                temps.remove(temp)  # The result owns the value now
                self.emu.heap_free(temp)
            return self.S_OK
        finally:
            for temp in temps:
                if retval is None or temp != retval[0]:
                    self.VariantClear([temp])
                self.emu.heap_free(temp)

    def _ti_fill_excepinfo(self, excep, hresult):
        """EXCEPINFO of a failed call: the thread's error information, if any"""
        source = description = helpfile = 0
        context = 0
        cell = self.emu.heap_alloc(4)
        try:
            if self.GetErrorInfo([0, cell]) == 0:
                error = struct.unpack('<I', self.emu.uc.mem_read(cell, 4))[0]
                for index, slot in ((4, 'source'), (5, 'description'), (6, 'helpfile')):
                    self._com_call(error, index, cell)
                    value = struct.unpack('<I', self.emu.uc.mem_read(cell, 4))[0]
                    if slot == 'source':
                        source = value
                    elif slot == 'description':
                        description = value
                    else:
                        helpfile = value
                self._com_call(error, 7, cell)
                context = struct.unpack('<I', self.emu.uc.mem_read(cell, 4))[0]
                self._com_call(error, 2)  # Release
        finally:
            self.emu.heap_free(cell)
        self._mem_write(excep, struct.pack('<HHIIIIIII', 0, 0, source, description, helpfile,
                                           context, 0, 0, hresult))
