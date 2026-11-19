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

"""Library attributes (TLIBATTR: GUID, LCID, SYSKIND, version, flags; and the
name) of type libraries: .TLB/.OLB files in the MSFT format, the older SLTG
format, and the TYPELIB resources of DLLs and EXEs"""

import struct

try:
    import pefile
except ImportError:  # pragma: no cover - pefile is a requirement
    pefile = None

MSFT_MAGIC = b'MSFT'
SLTG_MAGIC = b'SLTG'
SLTG_LIBBLK_MAGIC = b'\xcc\x51'


def guid_text(data):
    """16 GUID bytes -> lower-case "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" """
    data1, data2, data3 = struct.unpack_from('<IHH', data)
    rest = data[8:16]
    return f'{data1:08x}-{data2:04x}-{data3:04x}-{rest[:2].hex()}-{rest[2:].hex()}'


def _msft_attributes(data):
    (posguid, lcid, _, varflags, version, flags, typeinfos) = struct.unpack_from(
        '<iIIIIII', data, 8)
    name_offset = struct.unpack_from('<i', data, 56)[0]
    offset = 0x54 + (4 if varflags & 0x100 else 0) + 4 * typeinfos
    # Segment directory: 16-byte entries; the 6th is the GUID table, the 8th
    # the name table (a name: 12-byte header, 1-byte length, the characters)
    guid_table = struct.unpack_from('<i', data, offset + 5 * 16)[0]
    name_table = struct.unpack_from('<i', data, offset + 7 * 16)[0]
    guid = guid_text(data[guid_table + posguid:guid_table + posguid + 16])
    name = ''
    if name_offset >= 0:
        start = name_table + name_offset
        length = data[start + 8]
        name = data[start + 12:start + 12 + length].decode('latin-1')
    return {'guid': guid, 'lcid': lcid, 'syskind': varflags & 0xF,
            'major': version & 0xFFFF, 'minor': version >> 16, 'flags': flags & 0xFFFF,
            'name': name}


def _sltg_string(data, offset):
    """(text, next offset) of an SLTG string: WORD length (0xFFFF: none), bytes"""
    length = struct.unpack_from('<H', data, offset)[0]
    if length == 0xFFFF:
        return '', offset + 2
    return data[offset + 2:offset + 2 + length].decode('latin-1'), offset + 2 + length


def _sltg_attributes(data):
    """The library block: magic 0x51CC, WORD, the strings (name, doc string,
    help file...), help context, SYSKIND, LCID, a DWORD, flags, version, GUID"""
    start = data.find(SLTG_LIBBLK_MAGIC)
    while start >= 0:
        try:
            offset = start + 4
            strings = []
            for _ in range(4):
                text, offset = _sltg_string(data, offset)
                strings.append(text)
            _, syskind, lcid, _, flags, major, minor = struct.unpack_from(
                '<IHHIHHH', data, offset)
            guid_bytes = data[offset + 18:offset + 34]
            if syskind <= 3 and len(guid_bytes) == 16:
                return {'guid': guid_text(guid_bytes), 'lcid': lcid, 'syskind': syskind,
                        'major': major, 'minor': minor, 'flags': flags,
                        'name': strings[0] or strings[1], 'doc': strings[2]}
        except struct.error:
            pass
        start = data.find(SLTG_LIBBLK_MAGIC, start + 1)
    return None


def type_library_attributes(data):
    """Attributes of type library data (MSFT or SLTG), None if not one"""
    if not data:
        return None
    try:
        if data[:4] == MSFT_MAGIC:
            return _msft_attributes(data)
        if data[:4] == SLTG_MAGIC:
            return _sltg_attributes(data)
    except (struct.error, IndexError, UnicodeDecodeError):
        pass
    return None


def type_library_data(host_path, index=None):
    """Type library data of a file: the file itself, or a TYPELIB resource of a
    PE file (the one numbered index, else the first)"""
    try:
        with open(host_path, 'rb') as f:
            data = f.read()
    except OSError:
        return None
    if data[:2] != b'MZ' or pefile is None:
        return data
    try:
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
        for type_entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if str(type_entry.name or '').upper() != 'TYPELIB':
                continue
            entries = type_entry.directory.entries
            chosen = next((e for e in entries if index is not None and e.id == index),
                          entries[0] if entries else None)
            if chosen is None:
                return None
            item = chosen.directory.entries[0].data.struct
            return pe.get_data(item.OffsetToData, item.Size)
    except (pefile.PEFormatError, AttributeError):
        pass
    return None
