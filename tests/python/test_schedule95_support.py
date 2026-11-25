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

"""Unit tests of the parts Microsoft Schedule+ 7.0 needs that work without
an emulated program: byte-range file locks, monochrome pattern brushes,
tab expansion (TabbedTextOut), FindResourceW/FindResourceEx, the printer
dialogs of a computer without a printer and GetPixel outside a bitmap.

Run from the repository root:
    python3 -m unittest discover -s tests/python -v
"""

import os
import struct
import sys
import types
import unittest

from unicorn import Uc, UC_ARCH_X86, UC_MODE_32

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
from src.winapi import WinAPIHandler  # noqa: E402


class FakeEmulator:
    """Just enough of CPUEmulator for the handlers: memory and a thread"""
    BASE = 0x100000

    def __init__(self):
        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        self.uc.mem_map(self.BASE, 0x10000)
        self.current_thread = types.SimpleNamespace(last_error=0)


def bare_handler():
    handler = WinAPIHandler.__new__(WinAPIHandler)
    handler.emu = FakeEmulator()
    handler.handles = {}
    handler.dc_state = {}
    handler.gdi_objects = {}
    handler.gui = None
    return handler


class FileLockTest(unittest.TestCase):
    ERROR_LOCK_VIOLATION, ERROR_NOT_LOCKED = 33, 158

    def setUp(self):
        self.handler = bare_handler()
        for handle in (0x10, 0x14):
            self.handler.handles[handle] = {'type': 'file', 'path': '/tmp/x/USER.SCD'}
        self.handler.handles[0x18] = {'type': 'file', 'path': '/tmp/x/OTHER.SCD'}

    def error(self):
        return self.handler.emu.current_thread.last_error

    def test_locking_a_locked_byte_fails(self):
        # Schedule+ locks byte 0 twice with one handle and expects the second to fail
        lock = self.handler.LockFile
        self.assertEqual(lock([0x10, 0, 0, 1, 0]), 1)
        self.assertEqual(lock([0x10, 0, 0, 1, 0]), 0)
        self.assertEqual(self.error(), self.ERROR_LOCK_VIOLATION)
        self.assertEqual(lock([0x14, 0, 0, 4, 0]), 0)  # Another handle of the file
        self.assertEqual(lock([0x18, 0, 0, 1, 0]), 1)  # Another file
        self.assertEqual(lock([0x10, 1, 0, 1, 0]), 1)  # The next byte

    def test_unlock_needs_the_locked_range(self):
        self.assertEqual(self.handler.LockFile([0x10, 0x80, 0, 0x40, 0]), 1)
        self.assertEqual(self.handler.UnlockFile([0x10, 0x80, 0, 1, 0]), 0)
        self.assertEqual(self.error(), self.ERROR_NOT_LOCKED)
        self.assertEqual(self.handler.UnlockFile([0x10, 0x80, 0, 0x40, 0]), 1)
        self.assertEqual(self.handler.UnlockFile([0x10, 0x80, 0, 0x40, 0]), 0)
        self.assertEqual(self.handler.LockFile([0x14, 0x80, 0, 1, 0]), 1)

    def test_locks_go_away_with_the_handle(self):
        self.assertEqual(self.handler.LockFile([0x10, 0, 0, 1, 0]), 1)
        del self.handler.handles[0x10]
        self.assertEqual(self.handler.LockFile([0x14, 0, 0, 1, 0]), 1)

    def test_shared_locks_overlap(self):
        overlapped = FakeEmulator.BASE
        self.handler.emu.uc.mem_write(overlapped, b'\x00' * 8 + struct.pack('<II', 10, 0))
        lock_ex = self.handler.LockFileEx
        self.assertEqual(lock_ex([0x10, 0, 0, 5, 0, overlapped]), 1)
        self.assertEqual(lock_ex([0x14, 0, 0, 5, 0, overlapped]), 1)
        self.assertEqual(lock_ex([0x14, 2, 0, 5, 0, overlapped]), 0)  # Exclusive
        self.assertEqual(self.handler.UnlockFileEx([0x10, 0, 5, 0, overlapped]), 1)

    def test_bad_handle(self):
        self.assertEqual(self.handler.LockFile([0x99, 0, 0, 1, 0]), 0)
        self.assertEqual(self.error(), 6)


class PatternBrushTest(unittest.TestCase):
    def setUp(self):
        self.handler = bare_handler()
        self.handler.dc_state[0x50] = {'text_color': (255, 255, 0), 'bk_color': (255, 255, 255)}

    def test_monochrome_pattern_takes_the_dc_colors(self):
        # Schedule+ paints its appointment book with an all-0 8x8 pattern and
        # the text color yellow
        handler = self.handler
        handler.gdi_objects[0x60] = {'type': 'brush', 'color': (0, 0, 0), 'mono': 0.0}
        handler.gdi_objects[0x64] = {'type': 'brush', 'color': (255, 255, 255), 'mono': 1.0}
        self.assertEqual(handler._brush_color(0x60, 0x50), (255, 255, 0))
        self.assertEqual(handler._brush_color(0x64, 0x50), (255, 255, 255))
        self.assertEqual(handler._brush_color(0x60), (0, 0, 0))  # No DC: as made

    def test_logbrush_pattern_style(self):
        handler = self.handler
        calls = []
        handler.CreatePatternBrush = lambda args: calls.append(args) or 0x70
        address = FakeEmulator.BASE
        handler.emu.uc.mem_write(address, struct.pack('<III', 3, 0, 0x1234))  # BS_PATTERN
        self.assertEqual(handler.CreateBrushIndirect([address]), 0x70)
        self.assertEqual(calls, [[0x1234]])


class TabbedTextTest(unittest.TestCase):
    def setUp(self):
        self.handler = bare_handler()
        # 8 pixels per character, 16 high
        self.handler._text_extent = lambda hdc, text: (8 * len(text), 16)
        self.stops = FakeEmulator.BASE + 0x100

    def extent(self, text, stops=()):
        uc = self.handler.emu.uc
        string = FakeEmulator.BASE
        uc.mem_write(string, text.encode('ascii') + b'\x00')
        uc.mem_write(self.stops, struct.pack(f'<{len(stops)}i', *stops) if stops else b'')
        value = self.handler.GetTabbedTextExtentA([0x50, string, len(text), len(stops),
                                                   self.stops if stops else 0])
        return value & 0xFFFF, value >> 16

    def test_default_stops_every_eight_characters(self):
        self.assertEqual(self.extent('ab\tc'), (64 + 8, 16))

    def test_one_value_is_the_interval(self):
        self.assertEqual(self.extent('a\tb\tc', [20]), (40 + 8, 16))

    def test_stop_positions(self):
        self.assertEqual(self.extent('a\tb\tc', [30, 100]), (100 + 8, 16))
        # Right-aligned stops (negative) are taken as left ones
        self.assertEqual(self.extent('a\tb', [-50]), (50 + 8, 16))

    def test_count_limits_the_text(self):
        uc = self.handler.emu.uc
        uc.mem_write(FakeEmulator.BASE, b'abcdef\x00')
        value = self.handler.GetTabbedTextExtentA([0x50, FakeEmulator.BASE, 3, 0, 0])
        self.assertEqual(value & 0xFFFF, 24)


class ResourceAndDialogTest(unittest.TestCase):
    def test_find_resource_w_and_ex(self):
        handler = bare_handler()
        found = []
        handler._find_resource = lambda res_type, name, module=0: found.append(
            (res_type, name, module))
        name = FakeEmulator.BASE
        handler.emu.uc.mem_write(name, 'dialog'.encode('utf-16-le') + b'\x00\x00')
        handler.FindResourceW([0x400000, name, 5])
        handler.FindResourceExA([0x400000, 6, 7, 0x409])  # Type first, then the name
        self.assertEqual(found, [(5, 'DIALOG', 0x400000), (6, 7, 0x400000)])

    def test_no_printer(self):
        handler = bare_handler()
        self.assertEqual(handler.PrintDlgA([FakeEmulator.BASE]), 0)
        self.assertEqual(handler.CommDlgExtendedError([]), 0x1008)  # PDERR_NODEFAULTPRN
        self.assertEqual(handler.PageSetupDlgW([FakeEmulator.BASE]), 0)

    def test_get_pixel_outside_the_bitmap(self):
        handler = bare_handler()
        handler.gdi_objects[0x80] = {'type': 'bitmap', 'width': 35, 'height': 13}
        handler.dc_state[0x90] = {'memory': True, 'bitmap': 0x80, 'shapes': [
            {'type': 'rect', 'rect': (0, 0, 35, 13), 'fill': (0, 0, 0), 'pen': None}]}
        self.assertEqual(handler.GetPixel([0x90, 3, 3]), 0)
        self.assertEqual(handler.GetPixel([0x90, 3, 14]), 0xFFFFFFFF)  # CLR_INVALID


if __name__ == '__main__':
    unittest.main()
