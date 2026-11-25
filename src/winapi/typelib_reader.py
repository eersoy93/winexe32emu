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

"""Type library reader: the type information of SLTG (OLE 2.0 era, Office 95)
and MSFT type libraries, for the emulated ITypeLib / ITypeInfo objects.

Type descriptions are tuples: ('vt', VT_xxx), ('ptr', td), ('user', href),
('safearray', td), ('carray', td, [(elements, lower bound)...]).
A reference (href) is the key of TypeLibrary.refs: ('internal', index) or
('external', import key, index); imports are (guid, major, minor, lcid, file).
"""

import struct

from .typelib import guid_text

VT_PTR, VT_SAFEARRAY, VT_CARRAY, VT_USERDEFINED = 26, 27, 28, 29
TKIND_ENUM, TKIND_RECORD, TKIND_MODULE, TKIND_INTERFACE = 0, 1, 2, 3
TKIND_DISPATCH, TKIND_COCLASS, TKIND_ALIAS, TKIND_UNION = 4, 5, 6, 7
TYPEFLAG_FDUAL = 0x40
PARAMFLAG_FIN, PARAMFLAG_FOUT, PARAMFLAG_FLCID = 0x1, 0x2, 0x4
PARAMFLAG_FRETVAL, PARAMFLAG_FOPT, PARAMFLAG_FHASDEFAULT = 0x8, 0x10, 0x20
FUNC_PUREVIRTUAL, FUNC_STATIC, FUNC_DISPATCH = 1, 3, 4
VAR_PERINSTANCE, VAR_STATIC, VAR_CONST, VAR_DISPATCH = 0, 1, 2, 3
VARFLAG_FREADONLY = 0x1


class TypeLibraryError(Exception):
    """The data is not a type library this reader understands"""


class FuncInfo:
    """One function (FUNCDESC and its names)"""

    def __init__(self):
        self.memid = 0
        self.funckind = FUNC_PUREVIRTUAL
        self.invkind = 1
        self.callconv = 4  # CC_STDCALL
        self.params = []  # [(name, typedesc, flags, default VARIANT or None)]
        self.ret = ('vt', 24)  # VT_VOID
        self.ret_flags = 0
        self.opt = 0
        self.ovft = 0
        self.flags = 0
        self.name = ''
        self.doc = ''
        self.helpcontext = 0
        self.dll_entry = None  # (dll, name or ordinal) of a module function


class VarInfo:
    """One variable or constant (VARDESC and its name)"""

    def __init__(self):
        self.memid = 0
        self.name = ''
        self.type = ('vt', 3)
        self.varkind = VAR_PERINSTANCE
        self.offset = 0
        self.value = None  # (VT_xxx, Python value) of a constant
        self.flags = 0
        self.doc = ''
        self.helpcontext = 0


class TypeInfo:
    """One type (TYPEATTR and its members)"""

    def __init__(self, index):
        self.index = index
        self.name = ''
        self.doc = ''
        self.helpcontext = 0
        self.guid = '00000000-0000-0000-0000-000000000000'
        self.typekind = TKIND_INTERFACE
        self.flags = 0
        self.major = self.minor = 0
        self.size_instance = 4
        self.alignment = 4
        self.size_vft = 0
        self.funcs = []
        self.vars = []
        self.impls = []  # [(href, IMPLTYPEFLAGS)]
        self.alias = None  # typedesc of a TKIND_ALIAS
        # A dual interface is a dispinterface whose vtable interface is this
        self.dual_interface = None


class TypeLibrary:
    """A parsed type library"""

    def __init__(self):
        self.guid = '00000000-0000-0000-0000-000000000000'
        self.lcid = 0
        self.syskind = 1
        self.major = self.minor = 0
        self.flags = 0
        self.name = ''
        self.doc = ''
        self.helpfile = ''
        self.helpcontext = 0
        self.types = []
        self.refs = {}  # href -> ('internal', index) / ('external', import, index)

    def find(self, name):
        """The type of this name (any case), or None"""
        lower = name.lower()
        return next((t for t in self.types if t.name.lower() == lower), None)


# ---------- SLTG ----------

def _u16(data, offset):
    return struct.unpack_from('<H', data, offset)[0]


def _u32(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


def _cstring(data, offset):
    end = data.find(b'\x00', offset)
    if end < 0:
        end = len(data)
    return data[offset:end].decode('latin-1')


class _SltgReader:
    """The SLTG format (see Wine's typelib.c): a directory of blocks, one per
    type, the library block last; names are NUL-terminated strings in a name
    table after the library block"""

    def __init__(self, data):
        self.data = data
        self.lib = TypeLibrary()
        self.imports = {}  # name table offset -> import key

    def name(self, offset):
        if offset in (0xFFFF, 0xFFFE) or self.names + offset >= len(self.data):
            return ''
        return _cstring(self.data, self.names + offset)

    def read(self):
        data = self.data
        if data[:4] != b'SLTG':
            raise TypeLibraryError('not SLTG')
        blocks, _, _, first = struct.unpack_from('<HHHH', data, 4)
        entries = [struct.unpack_from('<IHH', data, 0x24 + 8 * i) for i in range(blocks - 1)]
        magic = 0x24 + 8 * (blocks - 1)
        if data[magic + 1:magic + 8] != b'CompObj':
            raise TypeLibraryError('no CompObj magic')
        first_block = magic + 13 + 11 * (blocks - 2) + 9
        # The blocks in file order follow the "next" links from first_blk
        order, start, chain = first - 1, first_block, []
        while True:
            length, index_string, following = entries[order]
            chain.append((start, length, _cstring(data, magic + index_string)))
            if following == 0:
                break
            start += length
            order = following - 1
        lib_block = chain[-1][0]
        type_blocks = chain[:-1]
        offset = lib_block + self.read_lib_block(lib_block) + 0x40
        count = blocks - 2
        other = []
        for _ in range(count):
            extra = 0
            length = _u16(data, offset + 2)
            index_name = ''
            if length != 0xFFFF:
                index_name = data[offset + 4:offset + 4 + length].decode('latin-1')
                extra += length
            length = _u16(data, offset + 4 + extra)
            if length != 0xFFFF:
                extra += length
            name_offset = _u16(data, offset + extra + 8)
            more = _u16(data, offset + 10 + extra)
            extra += more
            helpcontext = _u32(data, offset + 14 + extra)
            guid = guid_text(data[offset + 20 + extra:offset + 36 + extra])
            other.append((index_name, name_offset, helpcontext, guid))
            offset += extra + 36
        table = _u32(data, offset + 2)
        names = lib_block + table
        if _u16(data, names) == 0x0200:
            names += 0x20
        self.names = names + 0x216 + 2
        self.lib.name = self.name(_u16(data, lib_block + 4))
        for index, (start, _length, _index_string) in enumerate(type_blocks):
            if index >= len(other):
                break
            info = TypeInfo(index)
            index_name, name_offset, helpcontext, guid = other[index]
            info.name = self.name(name_offset)
            info.helpcontext = helpcontext
            info.guid = guid
            self.read_type(info, start)
            self.lib.types.append(info)
        return self.lib

    def read_lib_block(self, start):
        data, lib = self.data, self.lib
        if _u16(data, start) != 0x51CC:
            raise TypeLibraryError('no library block')
        offset = start + 6
        length = _u16(data, offset)
        if length != 0xFFFF:
            offset += length
        offset += 2
        for attribute in ('doc', 'helpfile'):
            length = _u16(data, offset)
            if length != 0xFFFF:
                setattr(lib, attribute, data[offset + 2:offset + 2 + length].decode('latin-1'))
                offset += length
            offset += 2
        lib.helpcontext, lib.syskind, lcid = struct.unpack_from('<IHH', data, offset)
        lib.lcid = lcid & 0x3FF if (lcid >> 10) == 0 else 0  # SUBLANG_NEUTRAL only
        offset += 12  # Help context, SYSKIND, LCID, a DWORD
        lib.flags, lib.major, lib.minor = struct.unpack_from('<HHH', data, offset)
        lib.guid = guid_text(data[offset + 6:offset + 22])
        return offset + 22 - start

    def read_type(self, info, start):
        data = self.data
        if _u16(data, start) != 0x0501:
            raise TypeLibraryError('bad type block')
        href_table, _, elem_table = struct.unpack_from('<III', data, start + 2)
        info.major, info.minor = struct.unpack_from('<HH', data, start + 0x12)
        flags1, flags2, _, typekind = struct.unpack_from('<BBBB', data, start + 0x1A)
        info.typekind = typekind
        info.flags = (flags1 >> 3) | (flags2 << 5)
        member = start + elem_table
        extra = _u32(data, member + 5)
        block = member + 9
        tail = block + extra
        (cfuncs, cvars, _, _, funcs_off, vars_off, _, _, _, _, alias_vt, _, _, _, simple,
         _, size_instance, alignment, _, _, size_vft) = struct.unpack_from('<21H', data, tail)
        info.size_instance, info.alignment, info.size_vft = size_instance, alignment, size_vft
        refs = self.read_refs(start + href_table) if href_table != 0xFFFFFFFF else []
        if typekind == TKIND_ALIAS:
            if simple:
                info.alias = ('vt', alias_vt)
            else:
                info.alias = self.read_type_desc(block + alias_vt, block, refs)[0]
            return
        if typekind in (TKIND_INTERFACE, TKIND_COCLASS) and _u16(data, block) == 0x004A:
            self.read_impls(info, block, refs)
        if vars_off != 0xFFFF and typekind != TKIND_INTERFACE:
            self.read_vars(info, block, block + vars_off, cvars, refs)
        if funcs_off != 0xFFFF and typekind not in (TKIND_ENUM, TKIND_RECORD,
                                                    TKIND_COCLASS):
            self.read_funcs(info, block, block + funcs_off, cfuncs, refs)
        if info.flags & TYPEFLAG_FDUAL and typekind == TKIND_INTERFACE:
            info.typekind = TKIND_DISPATCH
            info.dual_interface = True

    def read_refs(self, start):
        """The type's reference table: its index -> href of the library"""
        data, lib = self.data, self.lib
        if data[start] != 0xDF:
            return []
        number = _u32(data, start + 0x44)
        offset = start + 0x4F + number
        table = []
        for _ in range(number >> 3):
            length = _u16(data, offset)
            text = data[offset + 2:offset + 2 + length].decode('latin-1') \
                if length != 0xFFFF else ''
            offset += 2 + (length if length != 0xFFFF else 0)
            target = None
            if text.startswith('*\\R') and '*#' in text:
                lib_part, _, type_part = text[3:].partition('*#')
                try:
                    lib_offset, type_number = int(lib_part, 16), int(type_part, 16)
                except ValueError:
                    lib_offset, type_number = 0xFFFF, 0
                if lib_offset == 0xFFFF:
                    target = ('internal', type_number)
                else:
                    target = ('external', self.read_import(lib_offset), type_number)
            href = (len(lib.refs) + 1) * 4
            lib.refs[href] = target
            table.append(href)
        return table

    def read_import(self, offset):
        """An imported library named in the name table: "*\\G{guid}#maj.min#lcid#file#name" """
        if offset in self.imports:
            return self.imports[offset]
        text = _cstring(self.data, self.names + offset)
        guid = text[4:40].lower()
        fields = text[41:].split('#')
        try:
            major, _, minor = fields[1].partition('.')
            key = (guid, int(major, 16), int(minor or '0', 16), int(fields[2], 16), fields[3])
        except (IndexError, ValueError):
            key = (guid, 0, 0, 0, '')
        self.imports[offset] = key
        return key

    @staticmethod
    def ref(refs, number):
        return refs[number] if 0 <= number < len(refs) else 0

    def read_type_desc(self, offset, block, refs):
        """(typedesc, offset after it) of the WORDs at offset"""
        data = self.data
        wrappers = []
        while True:
            word = _u16(data, offset)
            if word & 0xE00 == 0xE00:
                wrappers.append(('ptr',))
            vt = word & 0x3F
            offset += 2
            if vt == VT_PTR:
                wrappers.append(('ptr',))
                continue
            if vt == VT_SAFEARRAY:
                offset += 2
                wrappers.append(('safearray',))
                continue
            if vt == VT_CARRAY:
                array = block + _u16(data, offset)
                offset += 2
                dims = _u16(data, array)
                bounds = [struct.unpack_from('<Ii', data, array + 16 + 8 * i) for i in range(dims)]
                wrappers.append(('carray', bounds))
                continue
            if vt == VT_USERDEFINED:
                td = ('user', self.ref(refs, _u16(data, offset) // 4))
                offset += 2
            else:
                td = ('vt', vt)
            break
        for wrapper in reversed(wrappers):
            td = (wrapper[0], td) + tuple(wrapper[1:])
        return td, offset

    def read_elem(self, offset, block, refs):
        """(typedesc, PARAMFLAGS, offset after it) of an element description"""
        word = _u16(self.data, offset)
        if word & 0xC000 == 0xC000:
            flags = 0
        elif word & 0x8000:
            flags = PARAMFLAG_FIN | PARAMFLAG_FOUT
        elif word & 0x4000:
            flags = PARAMFLAG_FOUT
        else:
            flags = PARAMFLAG_FIN
        if word & 0x2000:
            flags |= PARAMFLAG_FLCID
        if word & 0x80:
            flags |= PARAMFLAG_FRETVAL
        td, after = self.read_type_desc(offset, block, refs)
        return td, flags, after

    def read_impls(self, info, block, refs):
        data, offset = self.data, block
        for _ in range(64):
            following, _, impl_flags, _, _, ref = struct.unpack_from('<HHBBHH', data, offset + 2)
            info.impls.append((self.ref(refs, ref), impl_flags))
            if following == 0xFFFF:
                break
            offset = block + following

    def read_funcs(self, info, block, first, count, refs):
        data, offset = self.data, first
        for _ in range(count):
            magic, inv, following, name, dispid = struct.unpack_from('<BBHHI', data, offset)
            helpcontext, helpstring, arg_off, nacc, retopt, rettype, vtblpos = \
                struct.unpack_from('<HHHBBHH', data, offset + 10)
            kind = {0x4C: FUNC_PUREVIRTUAL, 0xCB: FUNC_DISPATCH,
                    0x8B: FUNC_STATIC}.get(magic & ~0x20)
            if kind is not None:
                func = FuncInfo()
                func.funckind = kind
                func.name = self.name(name)
                func.memid = dispid
                func.invkind = inv >> 4
                func.callconv = nacc & 7
                func.opt = (retopt & 0x7E) >> 1
                func.ovft = (vtblpos & ~1)
                func.helpcontext = helpcontext
                if magic & 0x20:
                    func.flags = _u16(data, offset + 22)
                ret_at = offset + 18 if retopt & 0x80 else block + rettype
                func.ret, func.ret_flags, _ = self.read_elem(ret_at, block, refs)
                count_params = nacc >> 3
                arg = block + arg_off
                for number in range(count_params):
                    name_word = _u16(data, arg)
                    param_name = None
                    have_offset = False
                    if name_word == 0xFFFF:
                        pass
                    elif name_word == 0xFFFE:
                        have_offset = True
                    else:
                        position = self.names + name_word
                        previous = data[position - 1]
                        if previous and not (previous < 0x80 and chr(previous).isalnum()):
                            have_offset = True
                            param_name = _cstring(data, position)
                        else:
                            param_name = _cstring(data, position - 1)
                    arg += 2
                    if have_offset:
                        td, flags, _ = self.read_elem(block + _u16(data, arg), block, refs)
                        arg += 2
                    else:
                        td, flags, arg = self.read_elem(arg, block, refs)
                    if count_params - number <= func.opt:
                        flags |= PARAMFLAG_FOPT
                    func.params.append((param_name or func.name, td, flags, None))
                info.funcs.append(func)
            if following == 0xFFFF:
                break
            offset = block + following

    def read_vars(self, info, block, first, count, refs):
        data, offset = self.data, first
        previous = ''
        for _ in range(count):
            magic, flags, following, name, byte_offs, type_word, memid = struct.unpack_from(
                '<BBHHHHI', data, offset)
            if magic not in (0x0A, 0x2A):
                break
            var = VarInfo()
            var.memid = memid
            var.name = previous if name == 0xFFFE else self.name(name)
            type_at = offset + 8 if flags & 0x02 else block + type_word
            var.type, _, _ = self.read_elem(type_at, block, refs)
            if flags & 0x40:
                var.varkind = VAR_DISPATCH
            elif flags & 0x10:
                var.varkind = VAR_CONST
                vt = var.type[1] if var.type[0] == 'vt' else 3
                if flags & 0x08:
                    var.value = (22, struct.unpack('<h', struct.pack('<H', byte_offs))[0]
                                 if byte_offs & 0x8000 else byte_offs)  # VT_INT
                elif vt in (8, 30, 31):  # VT_BSTR, VT_LPSTR, VT_LPWSTR
                    length = _u16(data, block + byte_offs)
                    text = None if length == 0xFFFF else \
                        data[block + byte_offs + 2:block + byte_offs + 2 + length].decode('latin-1')
                    var.value = (8, text)
                else:
                    var.value = (22, struct.unpack_from('<i', data, block + byte_offs)[0])
            else:
                var.varkind = VAR_PERINSTANCE
                var.offset = byte_offs
            if magic == 0x2A:
                var.flags = _u16(data, offset + 18)
            if flags & 0x80:
                var.flags |= VARFLAG_FREADONLY
            previous = var.name
            info.vars.append(var)
            if following == 0xFFFF:
                break
            offset = block + following


def read_type_library(data):
    """TypeLibrary of SLTG or MSFT type library data; TypeLibraryError if
    it is neither (or damaged)"""
    try:
        if data[:4] == b'SLTG':
            return _SltgReader(data).read()
        if data[:4] == b'MSFT':
            return _MsftReader(data).read()
    except (struct.error, IndexError, ValueError) as e:
        raise TypeLibraryError(str(e)) from e
    raise TypeLibraryError('unknown format')


class _MsftReader:
    """MSFT type libraries are not read yet"""

    def __init__(self, data):
        self.data = data

    def read(self):
        raise TypeLibraryError('MSFT')
