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

"""The fonts in a font file (AddFontResource): the faces of a .FON (raster
fonts in an NE executable) or of a TrueType .TTF/.TTC file"""

import struct
from collections import namedtuple

RASTER_FONTTYPE, TRUETYPE_FONTTYPE = 1, 4

# One font of a file: its face name, LOGFONT lfPitchAndFamily, EnumFonts
# FontType, pixel height (0: scalable) and weight
FontFace = namedtuple('FontFace', 'name pitch_family font_type height weight')


def font_file_faces(host_path):
    """The fonts of a font file ([] if it has none the emulator can read)"""
    try:
        with open(host_path, 'rb') as f:
            data = f.read()
    except OSError:
        return []
    try:
        if data[:2] == b'MZ':
            return _ne_font_faces(data)
        if data[:4] in (b'\x00\x01\x00\x00', b'true', b'OTTO'):
            return _truetype_faces(data, 0)
        if data[:4] == b'ttcf':
            count = struct.unpack_from('>I', data, 8)[0]
            faces = []
            for i in range(min(count, 64)):
                faces += _truetype_faces(data, struct.unpack_from('>I', data, 12 + 4 * i)[0])
            return faces
    except (struct.error, IndexError):
        pass
    return []


def _ne_font_faces(data):
    """The RT_FONT resources (Windows 2.x/3.x .FNT) of an NE file"""
    ne = struct.unpack_from('<I', data, 0x3C)[0]
    if data[ne:ne + 2] != b'NE':
        return []
    table = ne + struct.unpack_from('<H', data, ne + 0x24)[0]
    shift = struct.unpack_from('<H', data, table)[0]
    pos = table + 2
    faces = []
    while True:
        type_id, count = struct.unpack_from('<HH', data, pos)
        pos += 8
        if type_id == 0:
            break
        for _ in range(count):
            offset = struct.unpack_from('<H', data, pos)[0] << shift
            pos += 12
            if type_id != 0x8008:  # RT_FONT
                continue
            face_offset = struct.unpack_from('<I', data, offset + 0x69)[0]
            name = data[offset + face_offset:offset + face_offset + 64].split(b'\x00')[0]
            faces.append(FontFace(name.decode('cp1252', errors='replace'),
                                  data[offset + 0x5A],  # dfPitchAndFamily
                                  RASTER_FONTTYPE,
                                  struct.unpack_from('<H', data, offset + 0x58)[0],  # dfPixHeight
                                  struct.unpack_from('<H', data, offset + 0x53)[0]))  # dfWeight
    return faces


def _truetype_faces(data, start):
    """The family name (name ID 1) of the TrueType font at start"""
    num_tables = struct.unpack_from('>H', data, start + 4)[0]
    for i in range(num_tables):
        tag, _, offset, _ = struct.unpack_from('>4sIII', data, start + 12 + 16 * i)
        if tag != b'name':
            continue
        _, count, strings = struct.unpack_from('>HHH', data, offset)
        names = {}
        for j in range(count):
            platform, _, language, name_id, length, str_offset = struct.unpack_from(
                '>6H', data, offset + 6 + 12 * j)
            if name_id != 1:
                continue
            raw = data[offset + strings + str_offset:offset + strings + str_offset + length]
            if platform == 3:
                names[(0, language != 0x409)] = raw.decode('utf-16-be', errors='replace')
            elif platform == 1:
                names[(1, language != 0)] = raw.decode('mac_roman', errors='replace')
        if names:
            # 0x22: VARIABLE_PITCH | FF_SWISS, a guess the name table can't tell
            return [FontFace(names[min(names)], 0x22, TRUETYPE_FONTTYPE, 0, 400)]
    return []
