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
#
# There is no published description of the SLTG format. This reader was
# worked out for this project by comparing the bytes of the type libraries
# that ship with Office 95 (Binder, DAO, VBA, Excel, Access, PowerPoint,
# Schedule+, the OLE controls) with what their documentation says about the
# objects in them: member names, parameter lists, optional parameters,
# constant values. Fields whose meaning could not be told that way are
# skipped, and kinds of data none of those libraries has (structures,
# unions, fixed-size arrays) are not read.
#
# The file: a directory of named blocks, one per type plus the library block,
# chained in file order. The library block lists the types (name, GUID,
# kind...), then holds the word tree of the help strings and the name table.
# A type block has a header, the types it refers to, its member records
# (implemented interfaces, variables, functions) and a summary at its end.

_SLTG_MAGIC = b'SLTG'
_LIBRARY_MAGIC = b'\xcc\x51'
_TYPE_MAGIC = 0x0501
_NONE16 = 0xFFFF
_NONE32 = 0xFFFFFFFF
_SUMMARY_SIZE = 54  # The fixed part at the end of a type block
_REF_TABLE = 0x44  # Offset of the reference table in the reference section
_DLL_HEADER = 0x15  # Bytes before the DLL entries of a module
_FUNC_HEADER = 22
_VAR_HEADER = 18

VT_I2, VT_I4, VT_BSTR, VT_BOOL = 2, 3, 8, 11
VT_LPSTR = 30
_SIGNED_16 = (VT_I2, VT_BOOL)
_UNSIGNED = (17, 18, 19, 23)  # VT_UI1, VT_UI2, VT_UI4, VT_UINT

# The low byte of a member record's first word: record flags
_MEMBER_HAS_FLAGS = 0x20  # A flags word follows the header
# Bits 6-7 of a function record's first byte tell how it is called
_FUNC_KINDS = {0: 0, 1: FUNC_PUREVIRTUAL, 2: FUNC_STATIC, 3: FUNC_DISPATCH}
# The high byte of a variable record's first word
_VAR_INLINE_TYPE, _VAR_INLINE_VALUE, _VAR_CONST = 0x02, 0x08, 0x10
_VAR_DISPATCH, _VAR_READONLY = 0x40, 0x80
# The WORD of a function record with its calling convention (3 bits), number
# of parameters (6 bits) and number of optional parameters (6 bits)
_FUNC_INLINE_RESULT = 0x8000  # The result is a type word, not an offset
# A type word: VARTYPE in the low 6 bits, then these
_TYPE_RETVAL = 0x0080  # The [retval] parameter (and its function's result)
_TYPE_POINTER = 0x0E00  # A pointer to the type
_TYPE_LCID = 0x2000


def _word(data, offset):
    return struct.unpack_from('<H', data, offset)[0]


def _dword(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


def _text(data):
    return data.decode('latin-1')


def _counted_text(data, offset):
    """(text or None, next offset) of a string with a WORD length before it
    (0xFFFF: no string)"""
    length = _word(data, offset)
    offset += 2
    if length == _NONE16:
        return None, offset
    return _text(data[offset:offset + length]), offset + length


def _zero_text(data, offset):
    end = data.find(b'\x00', offset)
    return _text(data[offset:end if end >= 0 else len(data)])


class _WordTree:
    """The help strings of a library are sequences of words, each word coded
    by its path in a binary tree (frequent words have short paths). A node of
    the tree is 3 bytes with the top bit set, the rest being the offset of the
    subtree a 0 bit leads to (a 1 bit leads to the node that follows); a leaf
    is a byte below 0x80 and the NUL-terminated word. The empty word ends a
    string."""

    MAX_WORDS = 4096  # Damaged data must not loop forever

    def __init__(self, data, start, size):
        self.data, self.start, self.size = data, start, size

    def decode(self, coded, offset=0):
        if not self.size or offset >= len(coded):
            return ''
        data, bit, words = self.data, offset * 8, []
        while len(words) < self.MAX_WORDS:
            node = self.start
            while data[node] & 0x80:
                if bit >> 3 >= len(coded):
                    return ' '.join(words)
                if coded[bit >> 3] >> (7 - (bit & 7)) & 1:
                    node += 3
                else:
                    node = self.start + (int.from_bytes(data[node:node + 3], 'big') & 0x7FFFFF)
                bit += 1
            word = _zero_text(data, node + 1)
            if not word:
                break
            words.append(word)
        return ' '.join(words)


class _SltgReader:
    """Reads SLTG type library data into a TypeLibrary"""

    def __init__(self, data):
        self.data = data
        self.lib = TypeLibrary()
        self.names = 0  # Offset of the name table
        self.tree = _WordTree(data, 0, 0)
        self.externals = {}  # (import, index) -> href

    # ----- The file and the library block -----

    def read(self):
        data = self.data
        if data[:4] != _SLTG_MAGIC:
            raise TypeLibraryError('not SLTG')
        entries, gap, names_size, first = struct.unpack_from('<HHHH', data, 4)
        directory = [struct.unpack_from('<IHH', data, 0x24 + 8 * i) for i in range(entries - 1)]
        names = 0x24 + 8 * len(directory)
        # The blocks follow the block names, in the order of the chain
        blocks, position, number = {}, names + names_size + gap, first
        last = None
        while number:
            if number > len(directory) or len(blocks) > len(directory):
                raise TypeLibraryError('bad block chain')
            size, name, number = directory[number - 1]
            last = _zero_text(data, names + name)
            blocks[last] = (position, size)
            position += size
        if last is None:
            raise TypeLibraryError('no blocks')
        entries = self.read_library(blocks[last][0])
        for info, block_name in entries:
            if block_name in blocks:
                self.read_type(info, *blocks[block_name])
        return self.lib

    def name(self, offset):
        """A name of the name table (8 bytes of hash data come before it)"""
        if offset >= 0xFFFE or self.names + offset + 8 >= len(self.data):
            return ''
        return _zero_text(self.data, self.names + offset + 8)

    def read_library(self, start):
        """Reads the library block; returns [(TypeInfo, its block's name)]"""
        data, lib = self.data, self.lib
        if data[start:start + 2] != _LIBRARY_MAGIC:
            raise TypeLibraryError('no library block')
        name = _word(data, start + 4)
        _, offset = _counted_text(data, start + 6)
        doc, offset = _counted_text(data, offset)
        helpfile, offset = _counted_text(data, offset)
        (lib.helpcontext, lib.syskind, lib.lcid, _, _, lib.flags, lib.major,
         lib.minor) = struct.unpack_from('<IHHHHHHH', data, offset)
        lib.guid = guid_text(data[offset + 18:offset + 34])
        lib.doc, lib.helpfile = doc or '', helpfile or ''
        offset += 34 + 0x40  # 32 hash buckets of the type names
        count = _word(data, offset)
        offset += 2
        entries = []
        for index in range(count):
            block_name, offset = _counted_text(data, offset)
            _, offset = _counted_text(data, offset)
            info = TypeInfo(index)
            _, type_name, doc_size = struct.unpack_from('<HHH', data, offset)
            offset += 6
            coded = data[offset:offset + doc_size]
            offset += doc_size
            _, info.helpcontext, _ = struct.unpack_from('<HIH', data, offset)
            info.guid = guid_text(data[offset + 8:offset + 24])
            info.typekind = _word(data, offset + 24)
            offset += 26
            entries.append((info, block_name, type_name, coded))
        # The word tree, the hash table of the names and the name table
        tree_size = _word(data, offset + 6)
        self.tree = _WordTree(data, offset + 10, tree_size)
        offset = self._skip_chunk(offset + 10 + tree_size) + 2
        self.names = offset + 7
        lib.name = self.name(name)
        for info, _, type_name, coded in entries:
            info.name = self.name(type_name)
            info.doc = self.tree.decode(coded)
            lib.types.append(info)
        return [(info, block_name) for info, block_name, _, _ in entries]

    def _skip_chunk(self, offset):
        """The offset after a chunk: WORD, the byte 1, DWORD size, the data"""
        if self.data[offset + 2] != 1:
            raise TypeLibraryError('bad chunk')
        return offset + 7 + _dword(self.data, offset + 3)

    # ----- A type block -----

    def read_type(self, info, start, size):
        data = self.data
        if _word(data, start) != _TYPE_MAGIC:
            raise TypeLibraryError('bad type block')
        refs_at, dll_at, members_at = struct.unpack_from('<III', data, start + 2)
        info.flags = _word(data, start + 26) >> 3
        # A dual interface is listed as a dispinterface in the library block
        # and as an interface here
        if info.typekind == TKIND_DISPATCH and data[start + 29] == TKIND_INTERFACE:
            info.dual_interface = info
        refs = self.read_refs(start + refs_at, start + members_at) if refs_at != _NONE32 else []
        members = start + members_at + 9
        members_size = _dword(data, start + members_at + 5)
        block = data[members:members + members_size]
        summary = members + members_size
        if summary + _SUMMARY_SIZE > start + size:
            raise TypeLibraryError('bad type block size')
        (funcs, variables, impls, _, first_func, first_var, first_impl, _, _, _, default,
         _) = struct.unpack_from('<12H', data, summary)
        base_context, _, info.size_instance, info.alignment = struct.unpack_from(
            '<IIHH', data, summary + 24)
        info.size_vft = _word(data, summary + 40)
        table_at = _word(data, summary + 52)
        context = (block, refs, base_context)
        if info.typekind == TKIND_ALIAS:
            # A descriptor before the member table, or else just a type word
            info.alias = (self.read_type_desc(block, default, refs) if default < table_at
                          else self.word_type(default))
            return
        dll_entries = start + dll_at + _DLL_HEADER if dll_at != _NONE32 else None
        for offset in self._chain(block, first_impl, impls):
            flags = _word(block, offset + 6) & 0x7FFF
            desc = self.read_type_desc(block, _word(block, offset + 8), refs)
            if desc[0] == 'user':
                # The base of a dual interface is noted as the vtable interface
                # of another one; which view of it is used is left to the view
                # of the deriving type, so only the type is kept
                info.impls.append((desc[1] & ~3, flags))
        for offset in self._chain(block, first_var, variables):
            info.vars.append(self.read_var(context, offset))
        for offset in self._chain(block, first_func, funcs):
            info.funcs.append(self.read_func(context, offset, dll_entries))

    @staticmethod
    def _chain(block, offset, count):
        """Offsets of the member records linked from offset (the second WORD
        of a record is the offset of the next one)"""
        while count > 0 and offset != _NONE16:
            yield offset
            offset = _word(block, offset + 2)
            count -= 1

    def member_help(self, context, record, at):
        """(help context, help string) of a member: the WORDs at record + at"""
        block, _, base = context
        code, doc = struct.unpack_from('<HH', block, record + at)
        if code >= 0xFFFE:
            helpcontext = 0
        elif not code & 1:  # The offset of the whole number
            helpcontext = _dword(block, code)
        else:  # A distance from the type's base help context
            distance = code >> 2
            helpcontext = (base - distance if code & 2 else base + distance) & _NONE32
        return helpcontext, self.tree.decode(block, doc) if doc != _NONE16 else ''

    # ----- References to other types -----

    def read_refs(self, start, end):
        """The hrefs of the types a type block refers to, by their number"""
        data = self.data
        size = _dword(data, start + _REF_TABLE)
        offset = self._skip_chunk(start + _REF_TABLE + 4 + size)
        refs = []
        for _ in range(size // 8):
            text, offset = _counted_text(data, offset)
            if offset > end:
                raise TypeLibraryError('bad reference')
            refs.append(self.read_ref(text or ''))
        return refs

    def read_ref(self, text):
        """(href, True if it is a type of this library) of a reference
        "*\\R<library>*#<type index>", both numbers hexadecimal: <library> is
        ffff for this library or the name table offset of the description of
        another one"""
        lib = self.lib
        try:
            library, index = text.split('*')[1:3]
            library, index = int(library[2:], 16), int(index[1:], 16)
        except (ValueError, IndexError):
            return None, False
        if library == 0xFFFF:
            lib.refs[index * 4] = ('internal', index)
            return index * 4, True
        key = (self.read_import(library), index)
        if key not in self.externals:
            # After the hrefs of this library's own types
            href = (len(lib.types) + len(self.externals)) * 4
            self.externals[key] = href
            lib.refs[href] = ('external',) + key
        return self.externals[key], False

    def read_import(self, offset):
        """(guid, major, minor, lcid, file) of another library, from its
        description "*\\G{guid}#major.minor#lcid#file#" in the name table"""
        fields = self.name(offset).split('#')
        guid = fields[0][3:].strip('{}').lower()
        major = minor = lcid = 0
        try:
            major, _, minor = fields[1].partition('.')
            major, minor = int(major, 16), int(minor or '0', 16)
            lcid = int(fields[2], 16)
        except (ValueError, IndexError):
            pass
        return guid, major, minor, lcid, fields[3] if len(fields) > 3 else ''

    @staticmethod
    def href_of(refs, number):
        """The href of a reference number of a type block: 4 * its place in
        the reference table, plus 1 for the vtable interface of a dual
        interface of this library"""
        if number >> 2 >= len(refs) or refs[number >> 2][0] is None:
            return 0
        href, internal = refs[number >> 2]
        return href + 1 if number & 1 and internal else href

    # ----- Types -----

    @staticmethod
    def word_type(word):
        """The type of a type word that needs no more data"""
        desc = ('vt', word & 0x3F)
        return ('ptr', desc) if word & _TYPE_POINTER == _TYPE_POINTER else desc

    def read_type_desc(self, block, offset, refs, depth=0):
        """The type described at an offset of the member data: a type word,
        followed by the pointed type (VT_PTR), by a WORD and the element type
        (VT_SAFEARRAY) or by a reference number (VT_USERDEFINED)"""
        word = _word(block, offset)
        vt = word & 0x3F
        if depth > 16:
            raise TypeLibraryError('type too deep')
        if vt == VT_PTR:
            desc = ('ptr', self.read_type_desc(block, offset + 2, refs, depth + 1))
        elif vt == VT_SAFEARRAY:
            desc = ('safearray', self.read_type_desc(block, offset + 4, refs, depth + 1))
        elif vt == VT_USERDEFINED:
            desc = ('user', self.href_of(refs, _word(block, offset + 2)))
        else:
            desc = ('vt', vt)
        return ('ptr', desc) if word & _TYPE_POINTER == _TYPE_POINTER else desc

    @staticmethod
    def param_flags(word):
        """PARAMFLAG_xxx of a parameter's (or a result's) type word: its top
        two bits count in, out, in/out, nothing"""
        flags = ((word >> 14) + 1) & 3
        if word & _TYPE_LCID:
            flags |= PARAMFLAG_FLCID
        if word & _TYPE_RETVAL:
            flags |= PARAMFLAG_FRETVAL
        return flags

    # ----- Members -----

    def read_func(self, context, offset, dll_entries):
        block, refs, _ = context
        func = FuncInfo()
        (kind, _, name, func.memid, _, _, params_at, counts, result,
         place) = struct.unpack_from('<HHHIHHHHHH', block, offset)
        func.name = self.name(name)
        func.invkind = kind >> 12
        func.funckind = _FUNC_KINDS[kind >> 6 & 3]
        func.helpcontext, func.doc = self.member_help(context, offset, 10)
        func.callconv = counts & 7
        func.opt = counts >> 9 & 0x3F
        if counts & _FUNC_INLINE_RESULT:
            func.ret = ('vt', result & 0x3F)
            func.ret_flags = self.param_flags(result)
        else:
            func.ret = self.read_type_desc(block, result, refs)
            func.ret_flags = self.param_flags(_word(block, result))
        if kind & _MEMBER_HAS_FLAGS:
            func.flags = _word(block, offset + _FUNC_HEADER)
        if func.funckind == FUNC_STATIC:
            if dll_entries is not None:
                func.dll_entry = self.read_dll_entry(dll_entries + place)
        elif place != _NONE16:
            func.ovft = place
        for number in range(counts >> 3 & 0x3F if params_at != _NONE16 else 0):
            # The name's lowest bit: the type is the type word itself, not
            # the offset of a longer description
            name, word = struct.unpack_from('<HH', block, params_at + 4 * number)
            if name & 1:
                desc = self.word_type(word)
            else:
                desc = self.read_type_desc(block, word, refs)
                word = _word(block, word)
            func.params.append((self.name(name & ~1), desc, self.param_flags(word), None))
        self.mark_optional(func)
        return func

    @staticmethod
    def mark_optional(func):
        """Sets PARAMFLAG_FOPT on the optional parameters: the last ones before
        the [lcid] and [retval] parameters"""
        last = len(func.params)
        while last and func.params[last - 1][2] & (PARAMFLAG_FLCID | PARAMFLAG_FRETVAL):
            last -= 1
        for number in range(max(last - func.opt, 0), last):
            name, desc, flags, default = func.params[number]
            func.params[number] = (name, desc, flags | PARAMFLAG_FOPT, default)

    def read_dll_entry(self, offset):
        """(DLL, ordinal) of a module function; only entries by ordinal are
        known"""
        by_ordinal, dll, ordinal = struct.unpack_from('<HHH', self.data, offset)
        return (self.name(dll & ~1), ordinal) if by_ordinal == 1 else None

    def read_var(self, context, offset):
        block, refs, _ = context
        var = VarInfo()
        kind, _, name, place, type_word, var.memid = struct.unpack_from('<HHHHHI', block, offset)
        kind_flags = kind >> 8
        var.name = self.name(name)
        var.helpcontext, var.doc = self.member_help(context, offset, 14)
        var.type = (self.word_type(type_word) if kind_flags & _VAR_INLINE_TYPE
                    else self.read_type_desc(block, type_word, refs))
        if kind_flags & _VAR_READONLY:
            var.flags |= VARFLAG_FREADONLY
        if kind & _MEMBER_HAS_FLAGS:
            var.flags |= _word(block, offset + _VAR_HEADER)
        if kind_flags & _VAR_CONST:
            var.varkind = VAR_CONST
            var.value = self.read_value(block, var.type, place, kind_flags & _VAR_INLINE_VALUE)
        elif kind_flags & _VAR_DISPATCH:
            var.varkind = VAR_DISPATCH
        else:
            var.offset = place
        return var

    @staticmethod
    def read_value(block, desc, place, inline):
        """(VT_xxx, value) of a constant: a 16-bit value in the record itself,
        or the offset of a number or of a counted string"""
        vt = desc[1] if desc[0] == 'vt' else VT_I4
        if vt in (VT_BSTR, VT_LPSTR):
            return (VT_BSTR, None if inline else _counted_text(block, place)[0])
        if inline:
            signed = vt not in _UNSIGNED
            return vt, struct.unpack('<h' if signed else '<H', struct.pack('<H', place))[0]
        if vt in _SIGNED_16:
            return vt, struct.unpack_from('<h', block, place)[0]
        return vt, struct.unpack_from('<I' if vt in _UNSIGNED else '<i', block, place)[0]


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
