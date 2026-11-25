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

"""Unit tests of the parts Microsoft Office Binder 95 needs that work
without an emulated program: RLE compressed bitmaps, the display aspect
ratio, bitmap menu items and the failure of OLE object creation.

Run from the repository root:
    python3 -m unittest discover -s tests/python -v
"""

import os
import struct
import sys
import types
import unittest

from unicorn import Uc, UC_ARCH_X86, UC_MODE_32

os.environ.setdefault('SDL_VIDEODRIVER', 'dummy')
os.environ.setdefault('SDL_AUDIODRIVER', 'dummy')

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
from src.config import PYGAME_AVAILABLE  # noqa: E402
from src.winapi import WinAPIHandler  # noqa: E402
from src.winapi.memory_dc import decompress_rle  # noqa: E402

if PYGAME_AVAILABLE:
    from src.gui import PseudoWindowsGUI  # noqa: E402


def packed_dib(width, height, bpp, compression, palette, bits):
    """BITMAPINFOHEADER + color table + bits"""
    header = struct.pack('<IiiHHIIiiII', 40, width, height, 1, bpp, compression, len(bits),
                         0, 0, len(palette), 0)
    table = b''.join(bytes((b, g, r, 0)) for r, g, b in palette)
    return header + table + bits


class RleBitmapTest(unittest.TestCase):
    PALETTE = [(0, 0, 0), (255, 0, 0), (0, 255, 0), (0, 0, 255)]

    def test_rle8(self):
        # Bottom row: 3 x red, then absolute run green, blue, red; top row:
        # a delta of 2 pixels, then one blue; end of bitmap
        bits = bytes([3, 1, 0, 3, 2, 3, 1, 0, 0, 0, 0, 2, 2, 0, 1, 3, 0, 1])
        width, height, rgb = WinAPIHandler._decode_dib(
            packed_dib(6, 2, 8, 1, self.PALETTE, bits))
        self.assertEqual((width, height), (6, 2))
        pixels = [tuple(rgb[i:i + 3]) for i in range(0, len(rgb), 3)]
        red, green, blue, black = (255, 0, 0), (0, 255, 0), (0, 0, 255), (0, 0, 0)
        self.assertEqual(pixels[:6], [black, black, blue, black, black, black])  # Top row
        self.assertEqual(pixels[6:], [red, red, red, green, blue, red])

    def test_rle4(self):
        # 5 pixels alternating 1, 2; absolute run of 3 pixels 3, 1, 2 (padded)
        bits = bytes([5, 0x12, 0, 3, 0x31, 0x20, 0, 1])
        out = decompress_rle(bits, 8, 1, 4)
        self.assertEqual(out[:4], bytes([0x12, 0x12, 0x13, 0x12]))
        width, height, rgb = WinAPIHandler._decode_dib(
            packed_dib(8, 1, 4, 2, self.PALETTE, bits))
        self.assertEqual((width, height), (8, 1))
        self.assertEqual(tuple(rgb[15:18]), (0, 0, 255))  # Pixel 5: index 3

    def test_rle_needs_its_depth(self):
        self.assertIsNone(WinAPIHandler._decode_dib(
            packed_dib(4, 1, 4, 1, self.PALETTE, bytes([4, 1, 0, 1]))))


class DisplayCapsTest(unittest.TestCase):
    def test_aspect_ratio_is_square(self):
        # Binder divides by ASPECTX / ASPECTY in its progress indicator
        handler = WinAPIHandler.__new__(WinAPIHandler)
        handler.gui = None
        caps = {index: handler.GetDeviceCaps([0, index]) for index in (40, 42, 44)}
        self.assertEqual(caps, {40: 36, 42: 36, 44: 51})


class BitmapMenuItemTest(unittest.TestCase):
    MF_BITMAP, MF_STRING = 0x4, 0x0

    def handler(self):
        handler = WinAPIHandler.__new__(WinAPIHandler)
        handler.menus = {0x100: []}
        handler.gdi_objects = {0x2000: {'type': 'bitmap', 'width': 20, 'height': 18,
                                        'shapes': []}}
        handler.gui = None
        handler._menus_changed = lambda: None
        return handler

    def test_append_and_modify_keep_the_bitmap(self):
        handler = self.handler()
        handler.AppendMenuA([0x100, self.MF_BITMAP, 1011, 0x2000])
        tree = handler._build_menu_tree(0x100)
        self.assertIs(tree[0]['bitmap'], handler.gdi_objects[0x2000])
        # ModifyMenu to text and back (Binder swaps its pane button this way)
        handler.ModifyMenuW([0x100, 1011, self.MF_STRING, 1011, 0])
        self.assertNotIn('bitmap', handler._build_menu_tree(0x100)[0])
        handler.ModifyMenuW([0x100, 1011, self.MF_BITMAP, 1011, 0x2000])
        self.assertEqual(handler._build_menu_tree(0x100)[0]['bitmap']['width'], 20)

    def test_unknown_bitmap_handle(self):
        handler = self.handler()
        handler.AppendMenuA([0x100, self.MF_BITMAP, 5, 0x3])  # HBMMENU_* value
        self.assertNotIn('bitmap', handler._build_menu_tree(0x100)[0])


class OleServerFailureTest(unittest.TestCase):
    CLSID_WORD_DOCUMENT = '00020900-0000-0000-c000-000000000046'

    def handler(self, keys):
        handler = WinAPIHandler.__new__(WinAPIHandler)
        handler.emu = types.SimpleNamespace(uc=Uc(UC_ARCH_X86, UC_MODE_32))
        handler.emu.uc.mem_map(0x100000, 0x1000)
        handler._guid_out = 0x100100
        handler._registry_walk = lambda root, key, create=False: \
            ({'keys': {}, 'values': {}} if key.lower() in keys else None, 0)
        return handler

    def guid(self, handler, text):
        handler.emu.uc.mem_write(0x100000, handler._guid_bytes(text))
        return 0x100000

    def test_registered_server_fails_to_start(self):
        key = f'clsid\\{{{self.CLSID_WORD_DOCUMENT}}}\\localserver32'
        handler = self.handler({key})
        clsid = self.guid(handler, self.CLSID_WORD_DOCUMENT)
        handler.emu.uc.mem_write(handler._guid_out, b'\xff' * 4)
        result = handler.OleCreate([clsid, 0, 0, 0, 0, 0, handler._guid_out])
        self.assertEqual(result, 0x80080005)  # CO_E_SERVER_EXEC_FAILURE
        self.assertEqual(bytes(handler.emu.uc.mem_read(handler._guid_out, 4)), b'\x00' * 4)

    def test_unknown_class_is_not_registered(self):
        handler = self.handler(set())
        clsid = self.guid(handler, self.CLSID_WORD_DOCUMENT)
        result = handler.OleCreate([clsid, 0, 0, 0, 0, 0, handler._guid_out])
        self.assertEqual(result, 0x80040154)  # REGDB_E_CLASSNOTREG


@unittest.skipUnless(PYGAME_AVAILABLE, "Pygame is not installed")
class ActivationTest(unittest.TestCase):
    def test_closed_dialog_activates_its_owner_not_a_hidden_window(self):
        gui = PseudoWindowsGUI(800, 600)
        frame = gui.create_window('Binder', 0, 0, 400, 300)
        gui.show_window(frame)
        hidden = gui.create_window('', 0, 0, 10, 10)  # Shown once, then hidden
        gui.show_window(hidden)
        gui.show_window(hidden, False)
        dialog = gui.create_window('Add Section', 50, 50, 200, 100)
        gui.windows[dialog].owner_hwnd = frame
        gui.show_window(dialog)
        self.assertEqual(gui.active_window, dialog)
        gui._remove_window(dialog)
        self.assertEqual(gui.active_window, frame)


if __name__ == '__main__':
    unittest.main()
