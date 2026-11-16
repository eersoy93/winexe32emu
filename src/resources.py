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

"""Shell links, icons and the standard cursors"""

import io
import struct
import math

import pefile

from . import config
from .config import PYGAME_AVAILABLE

if PYGAME_AVAILABLE:
    import pygame


def parse_shell_link(data):
    """Fields of a shell link (.lnk, MS-SHLLINK) file: 'path' (local target),
    'description', 'relative', 'workdir', 'arguments', 'icon', 'icon_index',
    'show' and 'hotkey'; None if data is not a shell link"""
    def cstring(offset, wide=False):
        unit = 2 if wide else 1
        end = offset
        while data[end:end + unit] != b'\x00' * unit:
            if end + unit > len(data):
                raise IndexError("unterminated string")
            end += unit
        return data[offset:end].decode('utf-16-le' if wide else config.ANSI_CODEPAGE,
                                       errors='replace')

    try:
        if struct.unpack_from('<I', data, 0)[0] != 0x4C:
            return None
        flags = struct.unpack_from('<I', data, 20)[0]
        icon_index, show, hotkey = struct.unpack_from('<iIH', data, 56)
        pos = 0x4C
        if flags & 0x1:  # HasLinkTargetIDList
            pos += 2 + struct.unpack_from('<H', data, pos)[0]
        link = {'path': '', 'description': '', 'relative': '', 'workdir': '',
                'arguments': '', 'icon': '', 'icon_index': icon_index, 'show': show,
                'hotkey': hotkey}
        if flags & 0x2:  # HasLinkInfo
            size, header_size, info_flags = struct.unpack_from('<III', data, pos)
            base_offset, _, suffix_offset = struct.unpack_from('<III', data, pos + 16)
            if info_flags & 1:  # VolumeIDAndLocalBasePath
                if header_size >= 0x24:
                    unicode_base = struct.unpack_from('<I', data, pos + 28)[0]
                    link['path'] = cstring(pos + unicode_base, wide=True)
                else:
                    link['path'] = cstring(pos + base_offset)
                link['path'] += cstring(pos + suffix_offset)
            pos += size
        for flag, field in ((0x4, 'description'), (0x8, 'relative'), (0x10, 'workdir'),
                            (0x20, 'arguments'), (0x40, 'icon')):
            if flags & flag:
                count = struct.unpack_from('<H', data, pos)[0]
                unit = 2 if flags & 0x80 else 1
                raw = data[pos + 2:pos + 2 + count * unit]
                link[field] = raw.decode('utf-16-le' if unit == 2 else config.ANSI_CODEPAGE,
                                         errors='replace')
                pos += 2 + count * unit
    except (struct.error, IndexError):
        return None
    return link


def _icon_image_rgba(data):
    """(width, height, RGBA bytes) of an RT_ICON image (a DIB with the AND mask
    under it, or PNG), or None if it can't be decoded"""
    if data[:8] == b'\x89PNG\r\n\x1a\n':
        if not PYGAME_AVAILABLE:
            return None
        try:
            surface = pygame.image.load(io.BytesIO(data), 'icon.png')
        except pygame.error:
            return None
        return (*surface.get_size(), pygame.image.tobytes(surface, 'RGBA'))
    if len(data) < 40:
        return None
    hdr_size, width, double_height, _, bpp, compression = struct.unpack_from('<IiiHHI', data)
    height = abs(double_height) // 2
    if width <= 0 or height <= 0 or compression != 0:
        return None
    # The header's height covers the image and the mask: decode only the image
    header = bytearray(data)
    struct.pack_into('<i', header, 8, height)
    decoded = winapi.WinAPIHandler._decode_dib(bytes(header))
    if decoded is None:
        return None
    rgb = decoded[2]
    colors = 0
    if bpp <= 8:
        colors = struct.unpack_from('<I', data, 32)[0] or (1 << bpp)
    xor_offset = hdr_size + 4 * colors
    xor_stride = ((width * bpp + 31) // 32) * 4
    and_offset = xor_offset + xor_stride * height
    and_stride = ((width + 31) // 32) * 4

    alpha = bytearray(width * height)
    if bpp == 32:
        for r in range(height):
            start = xor_offset + (height - 1 - r) * xor_stride
            alpha[r * width:(r + 1) * width] = data[start + 3:start + width * 4:4]
    if not any(alpha):
        # No alpha channel: the AND mask tells the transparent pixels (bit set)
        if len(data) < and_offset + and_stride * height:
            alpha = bytearray(b'\xff' * (width * height))
        else:
            for r in range(height):
                line = data[and_offset + (height - 1 - r) * and_stride:]
                for c in range(width):
                    if not (line[c >> 3] >> (7 - (c & 7))) & 1:
                        alpha[r * width + c] = 255
    rgba = bytearray(width * height * 4)
    for c in range(3):
        rgba[c::4] = rgb[c::3]
    rgba[3::4] = alpha
    return width, height, bytes(rgba)


# Built-in standard cursors (IDC_*) of the fake desktop, drawn like the classic
# Windows ones: 'X' black, 'O' white, '.' transparent
_ARROW_CURSOR = (
    "X...........", "XX..........", "XOX.........", "XOOX........", "XOOOX.......",
    "XOOOOX......", "XOOOOOX.....", "XOOOOOOX....", "XOOOOOOOX...", "XOOOOOOOOX..",
    "XOOOOOOOOOX.", "XOOOOOOXXXXX", "XOOOXOOX....", "XOOXXOOX....", "XOX..XOOX...",
    "XX...XOOX...", "X.....XOOX..", "......XOOX..", ".......XX...")
_HOURGLASS = (
    "XXXXXXXXXXXXX", "XOOOOOOOOOOOX", "XXXXXXXXXXXXX", ".XOOOOOOOOOX.", ".XOOOOOOOOOX.",
    ".XOXOXOXOXOX.", ".XOOXOXOXOOX.", "..XOOXOXOOX..", "...XOOXOOX...", "....XOOOX....",
    ".....XOX.....", ".....XOX.....", "....XOOOX....", "...XOOXOOX...", "..XOOOOOOOX..",
    ".XOOOOXOOOOX.", ".XOOOXOXOOOX.", ".XOOXOXOXOOX.", ".XOXOXOXOXOX.", "XXXXXXXXXXXXX",
    "XOOOOOOOOOOOX", "XXXXXXXXXXXXX")
_SMALL_HOURGLASS = (
    "XXXXXXX", "XOOOOOX", ".XOXOX.", "..XOX..", "..XOX..", ".XOOOX.", "XOXOXOX", "XXXXXXX")
_QUESTION_MARK = (
    ".XXXXX.", "XOOOOOX", "XOXXXOX", "XXX.XOX", "..XXOOX", "..XOOX.", "..XOX..",
    "..XXX..", "..XOX..", "..XXX..")
_IBEAM_CURSOR = (
    "OOOO.OOOO", "OXXXOXXXO", "OOOOXOOOO") + ("...OXO...",) * 11 + (
    "OOOOXOOOO", "OXXXOXXXO", "OOOO.OOOO")
_HAND_CURSOR = (
    ".....XX.........", "....XOOX........", "....XOOX........", "....XOOX........",
    "....XOOX........", "....XOOXXX......", "....XOOXOOXXX...", "....XOOXOOXOOXX.",
    ".XX.XOOXOOXOOXOX", "XOOXXOOOOOOOOXOX", "XOOOXOOOOOOOOOOX", ".XOOXOOOOOOOOOOX",
    "..XOOOOOOOOOOOOX", "..XOOOOOOOOOOOX.", "...XOOOOOOOOOOX.", "...XOOOOOOOOOX..",
    "....XOOOOOOOOX..", "....XOOOOOOOOX..", "....XXXXXXXXXX..")
_UPARROW_CURSOR = (
    ".....X.....", "....XOX....", "...XOOOX...", "..XOOOOOX..", ".XOOOOOOOX.",
    "XOOOOOOOOOX", "XXXXOOOXXXX") + ("...XOOOX...",) * 10 + ("...XXXXX...",)


def _cursor_core_art(core, width, height, outline='X', fill='O'):
    """Art rows of a shape: core pixels in fill, their 8 neighbors in outline"""
    grid = [['.'] * width for _ in range(height)]
    for x, y in core:
        for dx in (-1, 0, 1):
            for dy in (-1, 0, 1):
                if 0 <= x + dx < width and 0 <= y + dy < height:
                    grid[y + dy][x + dx] = outline
    for x, y in core:
        grid[y][x] = fill
    return tuple(''.join(row) for row in grid)


def _size_ns_core(cx, top, length, head=5):
    """Core of a vertical double-headed arrow centered on column cx"""
    core = set()
    for i in range(head):  # Arrowheads
        for x in range(cx - i, cx + i + 1):
            core.add((x, top + i))
            core.add((x, top + length - 1 - i))
    core.update((cx, y) for y in range(top, top + length))
    return core


def _overlay_art(*layers):
    """Art of layers [(rows, (x, y))] drawn in order; '.' lets lower ones show"""
    width = max(x + len(rows[0]) for rows, (x, y) in layers)
    height = max(y + len(rows) for rows, (x, y) in layers)
    grid = [['.'] * width for _ in range(height)]
    for rows, (ox, oy) in layers:
        for y, row in enumerate(rows):
            for x, char in enumerate(row):
                if char != '.':
                    grid[oy + y][ox + x] = char
    return tuple(''.join(row) for row in grid)


def _standard_cursor_art():
    """IDC_* -> (art rows, hotspot)"""
    ns = _size_ns_core(5, 1, 19)
    nwse = ({(x, y) for x in range(1, 7) for y in range(1, 7) if x + y <= 7} |
            {(x, y) for x in range(9, 15) for y in range(9, 15) if x + y >= 23} |
            {(i, i) for i in range(1, 15)})
    cross = ({(x, 9) for x in range(1, 18)} | {(9, y) for y in range(1, 18)})
    no_core = set()
    for y in range(20):
        for x in range(20):
            dist = math.hypot(x - 9.5, y - 9.5)
            if 6.0 <= dist <= 8.6 or (dist < 8.6 and abs(x - y) <= 1):
                no_core.add((x, y))
    size_all = (_size_ns_core(11, 1, 21, head=4) |
                {(y, x) for x, y in _size_ns_core(11, 1, 21, head=4)})
    arts = {
        32512: (_ARROW_CURSOR, (0, 0)),                                        # IDC_ARROW
        32513: (_IBEAM_CURSOR, (4, 8)),                                        # IDC_IBEAM
        32514: (_HOURGLASS, (6, 11)),                                          # IDC_WAIT
        32515: (_cursor_core_art(cross, 19, 19, 'O', 'X'), (9, 9)),            # IDC_CROSS
        32516: (_UPARROW_CURSOR, (5, 0)),                                      # IDC_UPARROW
        32642: (_cursor_core_art(nwse, 16, 16), (8, 8)),                       # IDC_SIZENWSE
        32643: (_cursor_core_art({(15 - x, y) for x, y in nwse}, 16, 16), (7, 8)),
        32644: (_cursor_core_art({(y, x) for x, y in ns}, 21, 11), (10, 5)),  # IDC_SIZEWE
        32645: (_cursor_core_art(ns, 11, 21), (5, 10)),                       # IDC_SIZENS
        32646: (_cursor_core_art(size_all, 23, 23), (11, 11)),                # IDC_SIZEALL
        32648: (_cursor_core_art(no_core, 20, 20, 'O', 'X'), (10, 10)),       # IDC_NO
        32649: (_HAND_CURSOR, (5, 0)),                                         # IDC_HAND
        32650: (_overlay_art((_ARROW_CURSOR, (0, 0)), (_SMALL_HOURGLASS, (11, 11))),
                (0, 0)),                                                       # IDC_APPSTARTING
        32651: (_overlay_art((_ARROW_CURSOR, (0, 0)), (_QUESTION_MARK, (12, 9))),
                (0, 0)),                                                       # IDC_HELP
    }
    arts[32640] = arts[32646]  # IDC_SIZE
    arts[32641] = arts[32512]  # IDC_ICON
    return arts


_standard_cursors = {}


def standard_cursor_image(cursor_id):
    """Cursor dict ({'hotspot', 'size', 'rgba'}) of a built-in standard cursor
    (the arrow for unknown IDC_* values)"""
    image = _standard_cursors.get(cursor_id)
    if image is None:
        arts = _standard_cursor_art()
        rows, hotspot = arts.get(cursor_id, arts[32512])
        width, height = len(rows[0]), len(rows)
        colors = {'X': b'\x00\x00\x00\xff', 'O': b'\xff\xff\xff\xff', '.': b'\x00\x00\x00\x00'}
        rgba = b''.join(colors[char] for row in rows for char in row.ljust(width, '.'))
        image = {'hotspot': hotspot, 'size': (width, height), 'rgba': rgba}
        _standard_cursors[cursor_id] = image
    return image


def read_exe_icon(host_path, size=32):
    """(width, height, RGBA bytes) of the EXE's main icon (its first icon group),
    the image closest to size x size with the most colors; None if it has none"""
    try:
        pe = pefile.PE(host_path, fast_load=True)
    except (pefile.PEFormatError, OSError):
        return None
    try:
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
        root = getattr(pe, 'DIRECTORY_ENTRY_RESOURCE', None)
        entries = {entry.id: entry for entry in (root.entries if root else [])}
        if 14 not in entries or 3 not in entries:  # RT_GROUP_ICON, RT_ICON
            return None

        def first_language_data(name_entry):
            languages = getattr(name_entry, 'directory', None)
            if not languages or not languages.entries:
                return None
            struct_ = languages.entries[0].data.struct
            return pe.get_data(struct_.OffsetToData, struct_.Size)

        group = first_language_data(entries[14].directory.entries[0])
        if not group or len(group) < 6:
            return None
        count = struct.unpack_from('<H', group, 4)[0]
        images = []
        for i in range(count):
            if len(group) < 6 + 14 * (i + 1):
                break
            w, _, _, _, _, bits, _, icon_id = struct.unpack_from('<BBBBHHIH', group, 6 + 14 * i)
            images.append((abs((w or 256) - size), -bits, icon_id))
        icons = {entry.id: entry for entry in entries[3].directory.entries}
        for _, _, icon_id in sorted(images):
            data = first_language_data(icons[icon_id]) if icon_id in icons else None
            decoded = _icon_image_rgba(data) if data else None
            if decoded:
                return decoded
        return None
    except (pefile.PEFormatError, AttributeError, IndexError, struct.error):
        return None
    finally:
        pe.close()


# Last: winapi (through gui) imports this module too
from . import winapi
