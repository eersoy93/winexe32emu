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

"""Placeholder files of the emulated system DLLs in C:\\Windows\\System32.

The APIs of kernel32.dll, comctl32.dll... are emulated in Python, so there
is no DLL file behind them. Setup programs still look for those files and
read their version resource (an old COMCTL32.DLL makes Red Alert 2's Setup
ask for an update and a reboot). Each placeholder is a resource-only PE
file written by this module: no code, only a version resource naming the
emulator. They are never loaded: WinAPIHandler keeps emulating these DLLs.
"""

import os
import struct

from .config import WINEXE32EMU_VERSION
from .logger import log
from .paths import resolve_drive_path

SYSTEM_FOLDER = 'C:\\Windows\\System32'

# Version of the DLLs of the Windows the emulator reports (GetVersionEx:
# 6.0, build 6002)
SYSTEM_FILE_VERSION = (6, 0, 6002, 18005)
# DLLs whose version does not follow the Windows version (the values of
# that Windows, from Microsoft's public file lists)
SPECIAL_FILE_VERSIONS = {
    'comctl32.dll': (5, 82, 6002, 18005),
    'msvcrt.dll': (7, 0, 6002, 18005),
}
# Emulated DLLs that are not files of System32
NOT_SYSTEM_FOLDER_FILES = frozenset(['vcruntime140.dll', 'ucrtbase.dll'])

RT_VERSION = 16
LANG_ENGLISH_US = 0x0409
CODEPAGE_UNICODE = 1200
SECTION_ALIGNMENT = 0x1000
FILE_ALIGNMENT = 0x200
RESOURCE_RVA = SECTION_ALIGNMENT


def _align(data, boundary=4):
    return data + b'\x00' * (-len(data) % boundary)


def _version_node(key, value=b'', text=False, children=()):
    """A node of a version resource: lengths, type, key, value and children,
    each part aligned to 32 bits"""
    node = b'\x00' * 6 + key.encode('utf-16-le') + b'\x00\x00'
    if value:
        node = _align(node) + value
    for child in children:
        node = _align(node) + child
    value_length = len(value) // 2 if text else len(value)
    return struct.pack('<HHH', len(node), value_length, 1 if text else 0) + node[6:]


def build_version_resource(file_name, version, description):
    """VS_VERSIONINFO block of a DLL (the format of the Win32 version
    resource: VS_FIXEDFILEINFO, StringFileInfo and VarFileInfo)"""
    major, minor, build, revision = version
    fixed = struct.pack('<13I', 0xFEEF04BD, 0x00010000,
                        (major << 16) | minor, (build << 16) | revision,
                        (major << 16) | minor, (build << 16) | revision,
                        0x3F, 0,          # dwFileFlagsMask, dwFileFlags
                        0x00040004,       # VOS_NT_WINDOWS32
                        2, 0,             # VFT_DLL, no subtype
                        0, 0)
    version_text = '.'.join(map(str, version))
    strings = [
        ('CompanyName', 'winexe32emu'),
        ('FileDescription', description),
        ('FileVersion', version_text),
        ('InternalName', file_name.rsplit('.', 1)[0]),
        ('OriginalFilename', file_name),
        ('ProductName', f'winexe32emu {WINEXE32EMU_VERSION}'),
        ('ProductVersion', version_text),
    ]
    table = _version_node(
        f'{LANG_ENGLISH_US:04X}{CODEPAGE_UNICODE:04X}',
        children=[_version_node(name, (value + '\x00').encode('utf-16-le'), text=True)
                  for name, value in strings])
    translation = _version_node('Translation',
                                struct.pack('<HH', LANG_ENGLISH_US, CODEPAGE_UNICODE))
    return _version_node('VS_VERSION_INFO', fixed, children=[
        _version_node('StringFileInfo', children=[table]),
        _version_node('VarFileInfo', children=[translation])])


def _resource_section(version_block):
    """A resource directory with one entry: RT_VERSION, ID 1, English (US)"""
    def directory(entry_id, offset, is_directory):
        return (struct.pack('<IIHHHH', 0, 0, 0, 0, 0, 1) +
                struct.pack('<II', entry_id, offset | (0x80000000 if is_directory else 0)))
    data_offset = 3 * 24 + 16
    return _align(directory(RT_VERSION, 24, True) + directory(1, 48, True) +
                  directory(LANG_ENGLISH_US, 72, False) +
                  struct.pack('<IIII', RESOURCE_RVA + data_offset, len(version_block), 0, 0) +
                  version_block)


def build_placeholder_dll(file_name, version, description=None):
    """Bytes of a resource-only 32-bit DLL that holds just a version resource"""
    description = description or f'{file_name} (emulated by winexe32emu)'
    resources = _resource_section(build_version_resource(file_name, version, description))
    raw_size = len(_align(resources, FILE_ALIGNMENT))
    virtual_size = len(_align(resources, SECTION_ALIGNMENT))
    dos_header = b'MZ' + b'\x00' * 58 + struct.pack('<I', 0x40)
    coff = struct.pack('<HHIIIHH', 0x014C, 1, 0, 0, 0, 224,
                       0x2102)  # EXECUTABLE_IMAGE | 32BIT_MACHINE | DLL
    optional = struct.pack(
        '<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII',
        0x010B, 6, 0,                 # PE32, linker version
        0, raw_size, 0,               # code, initialized and uninitialized data sizes
        0, 0, RESOURCE_RVA,           # no entry point, code base, data base
        0x10000000, SECTION_ALIGNMENT, FILE_ALIGNMENT,
        4, 0, version[0], version[1], 4, 0,   # OS, image and subsystem versions
        0, RESOURCE_RVA + virtual_size, FILE_ALIGNMENT, 0,
        2, 0,                         # Windows GUI subsystem, DLL characteristics
        0x100000, 0x1000, 0x100000, 0x1000,   # stack and heap sizes
        0, 16)                        # loader flags, data directory count
    directories = [(0, 0)] * 16
    directories[2] = (RESOURCE_RVA, len(resources))  # IMAGE_DIRECTORY_ENTRY_RESOURCE
    optional += b''.join(struct.pack('<II', *d) for d in directories)
    section = (b'.rsrc\x00\x00\x00' +
               struct.pack('<IIIIIIHHI', len(resources), RESOURCE_RVA, raw_size,
                           FILE_ALIGNMENT, 0, 0, 0, 0,
                           0x40000040))  # INITIALIZED_DATA | MEM_READ
    headers = dos_header + b'PE\x00\x00' + coff + optional + section
    return _align(headers, FILE_ALIGNMENT) + _align(resources, FILE_ALIGNMENT)


def system_file_version(file_name):
    """Version of the placeholder of an emulated DLL"""
    return SPECIAL_FILE_VERSIONS.get(file_name.lower(), SYSTEM_FILE_VERSION)


def create_system_files(dll_names):
    """Write the placeholder of each emulated DLL into C:\\Windows\\System32
    (at each start, like the files of a Windows installation). A file that is
    already there stays: a setup program may have installed a real DLL."""
    for name in sorted(dll_names):
        if name in NOT_SYSTEM_FOLDER_FILES:
            continue
        path = resolve_drive_path(f'{SYSTEM_FOLDER}\\{name}')
        if path is None or os.path.lexists(path):
            continue
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'wb') as f:
                f.write(build_placeholder_dll(name, system_file_version(name)))
        except OSError as e:
            log.warning(f"Cannot create system file {name}: {e}")
