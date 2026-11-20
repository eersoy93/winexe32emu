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

"""Unit tests of the parts Microsoft Word 95 needs that work without an
emulated program: compound files, OS/2 bitmap headers, raster font files,
the logical -> device mapping of DCs, moveable memory handles, item ID
lists, window menus, character sets and the OBM_* system bitmaps.

Run from the repository root:
    python3 -m unittest discover -s tests/python -v
"""

import os
import struct
import sys
import tempfile
import types
import unittest

from unicorn import Uc, UC_ARCH_X86, UC_MODE_32

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
from src.winapi import WinAPIHandler, compound_file  # noqa: E402
from src.winapi.font_files import RASTER_FONTTYPE, font_file_faces  # noqa: E402
from src.winapi.memory_dc import core_dib_to_info  # noqa: E402


def tree(entry, path=''):
    """{path: (kind, data)} of a compound file tree, for comparisons"""
    out = {}
    for child in entry.children.values():
        key = f'{path}/{child.name}'
        out[key] = ('storage', child.clsid, child.state_bits) if child.storage else \
            ('stream', bytes(child.data))
        if child.storage:
            out.update(tree(child, key))
    return out


class CompoundFileTest(unittest.TestCase):
    def sample(self):
        root = compound_file.Entry('Root Entry', True, b'\x01' * 16)
        for i in range(20):
            root.add(compound_file.Entry(f'Stream{i}', False)).data = \
                bytearray(bytes([i]) * (i * 400))
        storage = root.add(compound_file.Entry('ObjectPool', True, b'\x02' * 16))
        storage.state_bits = 5
        storage.add(compound_file.Entry('\x01CompObj', False)).data = bytearray(b'x' * 5000)
        root.add(compound_file.Entry('WordDocument', False)).data = bytearray(range(256)) * 300
        return root

    def test_round_trip(self):
        root = self.sample()
        again = compound_file.load(compound_file.save(root))
        self.assertEqual(tree(again), tree(root))
        self.assertEqual(again.clsid, root.clsid)

    def test_directory_is_a_red_black_tree(self):
        data = compound_file.save(self.sample())
        first_dir = struct.unpack_from('<I', data, 0x30)[0]
        fat = []
        for sector in struct.unpack_from('<109I', data, 0x4C)[:struct.unpack_from('<I', data,
                                                                                   0x2C)[0]]:
            fat += struct.unpack_from('<128I', data, 512 * (sector + 1))
        raw, sector = b'', first_dir
        while sector != compound_file.ENDOFCHAIN:
            raw += data[512 * (sector + 1):512 * (sector + 2)]
            sector = fat[sector]
        entries = [raw[i:i + 128] for i in range(0, len(raw), 128)]

        def key(index):
            size = struct.unpack_from('<H', entries[index], 64)[0]
            name = entries[index][:size - 2].decode('utf-16-le')
            return len(name), name.upper()

        def black_height(index):
            if index == compound_file.NOSTREAM:
                return 1
            left, right = struct.unpack_from('<II', entries[index], 68)
            red = entries[index][67] == 0
            for child in (left, right):
                if child != compound_file.NOSTREAM:
                    self.assertFalse(red and entries[child][67] == 0, 'red node with red child')
            if left != compound_file.NOSTREAM:
                self.assertLess(key(left), key(index))
            if right != compound_file.NOSTREAM:
                self.assertGreater(key(right), key(index))
            heights = black_height(left), black_height(right)
            self.assertEqual(heights[0], heights[1])
            return heights[0] + (0 if red else 1)

        for entry in entries:
            if entry[66] in (compound_file.STGTY_STORAGE, compound_file.STGTY_ROOT):
                black_height(struct.unpack_from('<I', entry, 76)[0])

    def test_not_a_compound_file(self):
        with self.assertRaises(compound_file.CompoundFileError):
            compound_file.load(b'MZ' + b'\x00' * 1000)


class OldFormatTest(unittest.TestCase):
    def test_core_header_becomes_info_header(self):
        # 2x1 pixels, 1 bpp, colors black and white (RGBTRIPLEs)
        core = struct.pack('<IHHHH', 12, 2, 1, 1, 1) + b'\x00\x00\x00\xff\xff\xff' + \
            b'\x40\x00\x00\x00'
        info = core_dib_to_info(core)
        size, width, height, _, bpp, _, _, _, _, colors, _ = struct.unpack_from('<IiiHHIIiiII',
                                                                                info)
        self.assertEqual((size, width, height, bpp, colors), (40, 2, 1, 1, 2))
        self.assertEqual(info[40:48], b'\x00\x00\x00\x00\xff\xff\xff\x00')
        decoded = WinAPIHandler._decode_dib(core)
        self.assertEqual(decoded[2], b'\x00\x00\x00\xff\xff\xff')

    def test_raster_font_faces(self):
        # A minimal NE file with one RT_FONT resource named "Test Face"
        fnt = bytearray(0x80)
        struct.pack_into('<H', fnt, 0x53, 700)  # dfWeight
        struct.pack_into('<H', fnt, 0x58, 13)  # dfPixHeight
        fnt[0x5A] = 0x21  # dfPitchAndFamily
        struct.pack_into('<I', fnt, 0x69, len(fnt))  # dfFace
        fnt += b'Test Face\x00'
        ne_offset, table_offset = 0x40, 0x40
        resources = struct.pack('<H', 0) + struct.pack('<HHI', 0x8008, 1, 0) + \
            struct.pack('<HHHHI', 0x100, len(fnt), 0, 0, 0) + struct.pack('<H', 0)
        header = bytearray(b'MZ' + b'\x00' * 0x3A + struct.pack('<I', ne_offset))
        ne = bytearray(b'NE' + b'\x00' * 0x3E)
        struct.pack_into('<H', ne, 0x24, table_offset)
        data = bytes(header + ne + resources).ljust(0x100, b'\x00') + bytes(fnt)
        with tempfile.NamedTemporaryFile(suffix='.fon', delete=False) as f:
            f.write(data)
        try:
            faces = font_file_faces(f.name)
        finally:
            os.remove(f.name)
        self.assertEqual([(x.name, x.font_type, x.height, x.weight, x.pitch_family)
                          for x in faces], [('Test Face', RASTER_FONTTYPE, 13, 700, 0x21)])


class MappingTest(unittest.TestCase):
    def handler(self, **state):
        handler = WinAPIHandler.__new__(WinAPIHandler)
        handler.dc_state = {1: dict(state)}
        return handler

    def test_text_mode_is_pixels(self):
        handler = self.handler()
        self.assertIsNone(handler._dc_mapping(1))
        self.assertEqual(handler._lp_to_dp(1, 10, 20), (10, 20))

    def test_origins(self):
        handler = self.handler(window_org=(100, 50), viewport_org=(10, 10))
        self.assertEqual(handler._lp_to_dp(1, 100, 50), (10, 10))
        self.assertEqual(handler._dp_to_lp(1, 10, 10), (100, 50))

    def test_anisotropic_and_isotropic(self):
        state = dict(map_mode=8, window_ext=(1000, 1000), viewport_ext=(100, -50))
        self.assertEqual(self.handler(**state)._lp_to_dp(1, 500, 500), (50, -25))
        state['map_mode'] = 7  # The smaller scale on both axes, signs kept
        self.assertEqual(self.handler(**state)._lp_to_dp(1, 500, 500), (25, -25))

    def test_fixed_modes_grow_upwards(self):
        # MM_LOENGLISH: 0.01 inch per unit, 96 pixels per inch
        self.assertEqual(self.handler(map_mode=4)._lp_to_dp(1, 100, 100), (96, -96))


class FakeEmulator:
    """Just enough of CPUEmulator for the handlers: memory and a heap"""
    BASE = 0x100000

    def __init__(self):
        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        self.uc.mem_map(self.BASE, 0x100000)
        self.next = self.BASE
        self.blocks = {}
        self.current_thread = types.SimpleNamespace(last_error=0)

    def heap_alloc(self, size, alignment=16):
        address = self.next
        self.next += (max(size, 1) + 15) & ~15
        self.blocks[address] = size
        return address

    def heap_free(self, address):
        return self.blocks.pop(address, None) is not None

    def heap_block_size(self, address):
        return self.blocks.get(address)

    def heap_resize(self, address, size):
        return False


def handler_with_memory():
    handler = WinAPIHandler.__new__(WinAPIHandler)
    handler.emu = FakeEmulator()
    handler.moveable_handles = {}
    handler.moveable_by_pointer = {}
    handler.pidls = {}
    handler.dc_state = {}
    return handler


class MoveableMemoryTest(unittest.TestCase):
    GMEM_MOVEABLE, GHND = 0x2, 0x42

    def setUp(self):
        self.handler = handler_with_memory()
        self.uc = self.handler.emu.uc

    def dword(self, address):
        return struct.unpack('<I', self.uc.mem_read(address, 4))[0]

    def test_handle_points_to_its_block(self):
        # The Office 95 spelling checker reads a block through its handle
        h = self.handler.GlobalAlloc([self.GHND, 100])
        pointer = self.handler.GlobalLock([h])
        self.assertNotEqual(h, pointer)
        self.assertEqual(self.dword(h), pointer)
        self.assertEqual(bytes(self.uc.mem_read(pointer, 100)), b'\x00' * 100)
        self.assertEqual(self.handler.GlobalSize([h]), 100)
        self.assertEqual(self.handler.GlobalHandle([pointer]), h)
        self.assertEqual(self.handler.LocalFlags([h]), 1)  # Lock count
        self.assertEqual(self.handler.GlobalUnlock([h]), 0)
        self.assertEqual(self.handler.GlobalFree([h]), 0)
        self.assertNotIn(pointer, self.handler.emu.blocks)

    def test_realloc_keeps_the_handle(self):
        h = self.handler.LocalAlloc([self.GMEM_MOVEABLE, 8])
        old = self.handler.LocalLock([h])
        self.uc.mem_write(old, b'abcdefgh')
        self.assertEqual(self.handler.LocalReAlloc([h, 64, self.GMEM_MOVEABLE]), h)
        new = self.dword(h)
        self.assertNotEqual(new, old)
        self.assertEqual(bytes(self.uc.mem_read(new, 8)), b'abcdefgh')
        self.assertEqual(self.handler.LocalSize([h]), 64)

    def test_discarded_block(self):
        h = self.handler.GlobalAlloc([self.GMEM_MOVEABLE, 0])
        self.assertEqual(self.dword(h), 0)
        self.assertEqual(self.handler.GlobalLock([h]), 0)
        self.assertEqual(self.handler.GlobalFlags([h]) & 0x4000, 0x4000)  # GMEM_DISCARDED
        self.assertEqual(self.handler.GlobalReAlloc([h, 16, self.GMEM_MOVEABLE]), h)
        self.assertNotEqual(self.handler.GlobalLock([h]), 0)

    def test_fixed_block_is_its_handle(self):
        h = self.handler.GlobalAlloc([0x40, 32])
        self.assertEqual(self.handler.GlobalLock([h]), h)
        self.assertEqual(self.handler.GlobalHandle([h]), h)
        self.assertEqual(self.handler._hglobal_pointer(h), h)


class ShellItemIdListTest(unittest.TestCase):
    def test_copied_and_combined_lists(self):
        handler = handler_with_memory()
        pidl = handler._make_pidl('C:\\Users')
        self.assertEqual(handler._pidl_path(pidl), 'C:\\Users')
        # A copy the program made (not in handler.pidls), with a parent item in front
        item = bytes(handler.emu.uc.mem_read(pidl, struct.unpack(
            '<H', handler.emu.uc.mem_read(pidl, 2))[0]))
        child = handler._make_pidl('C:\\Users\\Public')
        child_item = bytes(handler.emu.uc.mem_read(child, len(item) + 14))
        copy = handler.emu.heap_alloc(256)
        handler.emu.uc.mem_write(copy, item + child_item[:struct.unpack('<H', child_item[:2])[0]]
                                 + b'\x00\x00')
        self.assertEqual(handler._pidl_path(copy), 'C:\\Users\\Public')

    def test_desktop_is_the_empty_list(self):
        handler = handler_with_memory()
        empty = handler.emu.heap_alloc(2)
        handler.emu.uc.mem_write(empty, b'\x00\x00')
        self.assertEqual(handler._pidl_path(empty), '')
        self.assertEqual(handler._pidl_path(handler._make_empty_pidl()), '')
        junk = handler.emu.heap_alloc(16)
        handler.emu.uc.mem_write(junk, struct.pack('<H', 8) + b'abcdef' + b'\x00\x00')
        self.assertIsNone(handler._pidl_path(junk))


class WindowMenuTest(unittest.TestCase):
    def test_child_window_menu_has_switch_to(self):
        # Word 6/95 turn "Switch To..." into "Next Window" in their document
        # windows' menus and fail to start without it
        handler = WinAPIHandler.__new__(WinAPIHandler)
        items = handler._standard_system_menu(child=True)
        self.assertEqual(sum(1 for item in items if item['flags'] & handler.MF_SEPARATOR), 2)
        self.assertEqual(items[-1]['id'], 0xF130)  # SC_TASKLIST
        self.assertNotIn(0xF130, [item['id'] for item in handler._standard_system_menu()])

    def test_backspace_starts_the_shortcut(self):
        self.assertEqual(WinAPIHandler._menu_label('Undo Typing\bCtrl+Z'),
                         ('Undo Typing', 'Ctrl+Z'))
        self.assertEqual(WinAPIHandler._menu_label('&Find...\t\bCtrl+F'), ('Find...', 'Ctrl+F'))


class CharsetAndBitmapTest(unittest.TestCase):
    def test_translate_charset_info(self):
        handler = handler_with_memory()
        out = handler.emu.heap_alloc(32)
        self.assertEqual(handler.TranslateCharsetInfo([162, out, 1]), 1)  # TCI_SRCCHARSET
        charset, codepage = struct.unpack('<II', handler.emu.uc.mem_read(out, 8))
        self.assertEqual((charset, codepage), (162, 1254))
        self.assertEqual(handler.TranslateCharsetInfo([1251, out, 2]), 1)  # TCI_SRCCODEPAGE
        self.assertEqual(struct.unpack('<I', handler.emu.uc.mem_read(out, 4))[0], 204)
        self.assertEqual(handler.TranslateCharsetInfo([99, out, 1]), 0)

    def test_system_bitmaps(self):
        handler = WinAPIHandler.__new__(WinAPIHandler)
        for name, size in ((32738, (7, 4)), (32759, (52, 39)), (32753, (16, 16))):
            width, height, rgb = handler._system_bitmap(name)
            self.assertEqual((width, height), size)
            self.assertEqual(len(rgb), width * height * 3)
        self.assertIsNone(handler._system_bitmap(1))


if __name__ == '__main__':
    unittest.main()
