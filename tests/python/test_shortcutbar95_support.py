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

"""Unit tests of the parts the Microsoft Office 95 Shortcut Bar (MSOFFICE.EXE),
its MSOW.EXE dialogs, Find Fast and FastBoot need that work without an
emulated program: application desktop toolbars, TB_SETROWS, check groups,
tooltips, the tab control, DIB section bits, toolhelp snapshots and the FPU
state of new threads.

Run from the repository root:
    python3 -m unittest discover -s tests/python -v
"""

import os
import struct
import sys
import types
import unittest

from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
from unicorn.x86_const import UC_X86_REG_FPCW, UC_X86_REG_MXCSR

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
from src import windows  # noqa: E402
from src.cpu import CPUEmulator  # noqa: E402
from src.winapi import WinAPIHandler  # noqa: E402


class FakeEmulator:
    """Just enough of CPUEmulator for the handlers: memory and a heap"""
    BASE = 0x100000

    def __init__(self):
        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        self.uc.mem_map(self.BASE, 0x100000)
        self.next = self.BASE
        self.current_thread = types.SimpleNamespace(last_error=0, tid=1)
        self.process_id = 0x404

    def heap_alloc(self, size, alignment=16):
        address = self.next
        self.next += (max(size, 1) + 15) & ~15
        return address

    def heap_free(self, address):
        return True


def handler_with_memory():
    handler = WinAPIHandler.__new__(WinAPIHandler)
    handler.emu = FakeEmulator()
    handler.gui = None
    handler.handles = {}
    handler.dc_state = {}
    handler.gdi_objects = {}
    handler.imagelists = {}
    handler.timers = {}
    handler.next_handle = 0x1000
    return handler


class AppBarTest(unittest.TestCase):
    """SHAppBarMessage: the Shortcut Bar docks at the right edge of the
    1920x1080 desktop (no GUI), above the 30 pixel taskbar"""
    ABM_NEW, ABM_REMOVE, ABM_QUERYPOS, ABM_SETPOS = 0, 1, 2, 3
    ABE_RIGHT = 2

    def setUp(self):
        self.handler = handler_with_memory()
        self.data = self.handler.emu.heap_alloc(36)
        windows.APPBARS.clear()

    def tearDown(self):
        windows.APPBARS.clear()

    def message(self, message, hwnd, edge=0, rect=(0, 0, 0, 0), callback=0x401):
        self.handler.emu.uc.mem_write(self.data, struct.pack('<4I4iI', 36, hwnd, callback,
                                                             edge, *rect, 0))
        result = self.handler.SHAppBarMessage([message, self.data])
        return result, struct.unpack('<4i', self.handler.emu.uc.mem_read(self.data + 16, 16))

    def test_docked_bar_leaves_the_taskbar_and_the_work_area(self):
        self.assertEqual(self.message(self.ABM_NEW, 0x10004)[0], 1)
        self.assertEqual(self.message(self.ABM_NEW, 0x10004)[0], 0)  # Already registered
        result, rect = self.message(self.ABM_QUERYPOS, 0x10004, self.ABE_RIGHT,
                                    (1887, 0, 1920, 1080))
        self.assertEqual((result, rect), (1, (1887, 0, 1920, 1050)))
        self.message(self.ABM_SETPOS, 0x10004, self.ABE_RIGHT, (1887, 0, 1920, 1080))
        self.assertEqual(self.handler._work_area(), (0, 0, 1887, 1050))
        # A second bar on the same edge goes inside the first one
        self.message(self.ABM_NEW, 0x20004)
        _, rect = self.message(self.ABM_QUERYPOS, 0x20004, self.ABE_RIGHT, (1900, 0, 1920, 1080))
        self.assertEqual(rect, (1867, 0, 1887, 1050))
        self.message(self.ABM_REMOVE, 0x20004)
        self.message(self.ABM_REMOVE, 0x10004)
        self.assertEqual(self.handler._work_area(), (0, 0, 1920, 1050))

    def test_maximized_window_fills_the_work_area(self):
        windows.APPBARS[0x10004] = windows.AppBar(None, 0)
        windows.APPBARS[0x10004].edge, windows.APPBARS[0x10004].rect = 1, (0, 0, 800, 40)
        win = windows.FakeWindow(1, 'x', 10, 10, 100, 100)
        win.maximize(800, 600, 30)
        self.assertEqual((win.x, win.y, win.width, win.height), (0, 40, 800, 530))


def toolbar(buttons, style=0x40):
    """A FakeWindow of ToolbarWindow32 with (id, style, state) buttons"""
    win = windows.FakeWindow(0x2000, '', 0, 0, 100, 30, style)
    win.native = 'TOOLBAR'
    win.nstate = {'buttons': [{'bitmap': 0 if kind & 1 else i, 'id': command, 'state': state,
                               'style': kind, 'data': 0, 'string': -1, 'text': None}
                              for i, (command, kind, state) in enumerate(buttons)],
                  'bitmaps': [], 'imagelist': 0, 'bitmap_size': (16, 16), 'button_size': None,
                  'strings': [], 'pressed': -1, 'ex_style': 0, 'notify': 0, 'struct_size': 20,
                  'max_text_rows': 1}
    return win


class ToolbarTest(unittest.TestCase):
    def test_set_rows_wraps_and_sizes_the_toolbar(self):
        # The Office Shortcut Bar asks for 10000 rows: one button a row; a
        # separator alone in its row is a gap of its width; hidden buttons
        # take no room
        handler = handler_with_memory()
        win = toolbar([(1, 0, 4), (0, 1, 0), (2, 0, 4), (3, 0, 0xC), (4, 0, 4)])
        rect = handler.emu.heap_alloc(16)
        handler._toolbar_message(win, 0x427, 0x12710, rect)
        layout = handler._tb_layout(win)
        self.assertEqual(layout[0], (0, 0, 23, 23))
        self.assertEqual(layout[1], (0, 23, 23, 31))
        self.assertEqual(layout[2], (0, 31, 23, 54))
        self.assertEqual(layout[4], (0, 54, 23, 77))
        self.assertEqual(struct.unpack('<4i', handler.emu.uc.mem_read(rect, 16)),
                         (0, 0, 23, 77))
        self.assertEqual((win.width, win.height), (23, 77))

    def test_check_group_stays_checked(self):
        win = toolbar([(1, 6, 5), (2, 6, 4), (3, 2, 4)])
        WinAPIHandler._tb_click_check(win, 0)
        self.assertEqual([b['state'] & 1 for b in win.nstate['buttons']], [1, 0, 0])
        WinAPIHandler._tb_click_check(win, 1)
        self.assertEqual([b['state'] & 1 for b in win.nstate['buttons']], [0, 1, 0])
        WinAPIHandler._tb_click_check(win, 2)  # BTNS_CHECK toggles
        WinAPIHandler._tb_click_check(win, 2)
        self.assertEqual(win.nstate['buttons'][2]['state'] & 1, 0)


class TooltipTest(unittest.TestCase):
    def test_rectangle_tool_before_the_whole_window_tool(self):
        handler = handler_with_memory()
        tip = windows.FakeWindow(0x3000, '', 0, 0, 0, 0)
        tip.native = 'TOOLTIPS'
        info = handler.emu.heap_alloc(44)
        for flags, uid, rect in ((0x1, 0x2000, (0, 0, 0, 0)), (0, 7, (10, 0, 20, 10))):
            handler.emu.uc.mem_write(info, struct.pack('<4I4i3I', 44, flags, 0x2000, uid,
                                                       *rect, 0, 0xFFFFFFFF, 0))
            self.assertEqual(handler._tooltip_message(tip, 0x404, 0, info), 1)
        st = tip.nstate
        self.assertEqual(handler._tt_tool_at(st, 0x2000, 15, 5)['id'], 7)
        self.assertEqual(handler._tt_tool_at(st, 0x2000, 50, 5)['id'], 0x2000)
        self.assertIsNone(handler._tt_tool_at(st, 0x2004, 15, 5))
        self.assertEqual(handler._tooltip_message(tip, 0x40D, 0, 0), 2)  # TTM_GETTOOLCOUNT


class TabControlTest(unittest.TestCase):
    def test_items_selection_and_display_rect(self):
        handler = handler_with_memory()
        handler._native_text_width = lambda text: 6 * len(text)
        win = windows.FakeWindow(0x4000, '', 0, 0, 300, 200, 0x50010000)
        win.native = 'TAB'
        text = handler.emu.heap_alloc(32)
        item = handler.emu.heap_alloc(28)
        for i, name in enumerate(('General', 'Letters && Faxes')):
            handler.emu.uc.mem_write(text, name.encode() + b'\x00')
            handler.emu.uc.mem_write(item, struct.pack('<5Iii', 0x9, 0, 0, text, 0, -1, i + 10))
            self.assertEqual(handler._tab_message(win, 0x1307, i, item), i)  # TCM_INSERTITEM
        self.assertEqual(handler._tab_message(win, 0x1304, 0, 0), 2)  # TCM_GETITEMCOUNT
        self.assertEqual(handler._tab_message(win, 0x130B, 0, 0), 0)  # TCM_GETCURSEL
        self.assertEqual(handler._tab_message(win, 0x130C, 1, 0), 0)  # TCM_SETCURSEL
        self.assertEqual(handler._tab_message(win, 0x130B, 0, 0), 1)
        self.assertEqual(handler.tab_label('Letters && Faxes'), 'Letters & Faxes')
        rect = handler.emu.heap_alloc(16)
        handler.emu.uc.mem_write(rect, struct.pack('<4i', 0, 0, 300, 200))
        handler._tab_message(win, 0x1328, 0, rect)  # TCM_ADJUSTRECT
        self.assertEqual(struct.unpack('<4i', handler.emu.uc.mem_read(rect, 16)),
                         (4, 2 + handler.TAB_ROW_H + 4, 296, 196))


class DibSectionBitsTest(unittest.TestCase):
    def test_four_bpp_bottom_up_nearest_color(self):
        # The Shortcut Bar saves its button bitmaps (Office.tbb) from a 4 bpp
        # DIB section it drew on with BitBlt
        palette = [(0, 0, 0), (128, 0, 0), (0, 128, 0), (255, 255, 255)]
        header = struct.pack('<IiiHHIIiiII', 40, 3, 2, 1, 4, 0, 0, 0, 0, 4, 0) + \
            b''.join(bytes((b, g, r, 0)) for r, g, b in palette)
        rgb = bytes((255, 255, 255, 120, 0, 0, 0, 0, 0,     # top row
                     0, 130, 0, 0, 0, 0, 250, 250, 250))    # bottom row
        bits = WinAPIHandler._encode_dib_bits(header, 3, 2, rgb)
        self.assertEqual(bits, bytes((0x20, 0x30, 0, 0, 0x31, 0x00, 0, 0)))

    def test_twenty_four_bpp_top_down(self):
        header = struct.pack('<IiiHHIIiiII', 40, 1, -2, 1, 24, 0, 0, 0, 0, 0, 0)
        bits = WinAPIHandler._encode_dib_bits(header, 1, 2, bytes((1, 2, 3, 4, 5, 6)))
        self.assertEqual(bits, bytes((3, 2, 1, 0, 6, 5, 4, 0)))


class SmallApiTest(unittest.TestCase):
    def test_gdi_batch_limit(self):
        handler = handler_with_memory()
        self.assertEqual(handler.GdiSetBatchLimit([1]), 20)
        self.assertEqual(handler.GdiGetBatchLimit([]), 1)
        self.assertEqual(handler.GdiSetBatchLimit([0]), 1)
        self.assertEqual(handler.GdiGetBatchLimit([]), 20)

    def test_toolhelp_lists_this_process(self):
        handler = handler_with_memory()
        handler.windows_exe_path = lambda: 'C:\\MSOffice\\Office\\MSOFFICE.EXE'
        handler.emu.pe_loader = types.SimpleNamespace(image_base=0x400000, pe=None)
        handler.emu.dlls = {}
        handler.emu.threads = {1: None}
        snapshot = handler.CreateToolhelp32Snapshot([0xA, 0])  # PROCESS | MODULE
        entry = handler.emu.heap_alloc(548)
        handler.emu.uc.mem_write(entry, struct.pack('<I', 296))
        self.assertEqual(handler.Process32First([snapshot, entry]), 1)
        data = bytes(handler.emu.uc.mem_read(entry, 296))
        self.assertEqual(struct.unpack_from('<I', data, 8)[0], 0x404)
        self.assertTrue(data[36:].startswith(b'C:\\MSOffice\\Office\\MSOFFICE.EXE\x00'))
        self.assertEqual(handler.Process32Next([snapshot, entry]), 0)
        handler.emu.uc.mem_write(entry, struct.pack('<I', 548))
        self.assertEqual(handler.Module32First([snapshot, entry]), 1)
        data = bytes(handler.emu.uc.mem_read(entry, 548))
        self.assertEqual(struct.unpack_from('<I', data, 20)[0], 0x400000)
        self.assertTrue(data[32:].startswith(b'MSOFFICE.EXE\x00'))
        self.assertEqual(handler.Module32Next([snapshot, entry]), 0)


class ThreadFpuStateTest(unittest.TestCase):
    def test_new_thread_masks_floating_point_exceptions(self):
        # Unicorn starts with control word 0: every exception unmasked, and
        # Find Fast's indexing thread died of STATUS_FLOAT_INEXACT_RESULT
        uc = Uc(UC_ARCH_X86, UC_MODE_32)
        uc.mem_map(0x100000, 0x10000)
        fake = types.SimpleNamespace(heap_alloc=lambda size: 0x100000)
        CPUEmulator._setup_segments(fake, uc, 0x101000)
        self.assertEqual(uc.reg_read(UC_X86_REG_FPCW), 0x027F)
        self.assertEqual(uc.reg_read(UC_X86_REG_MXCSR), 0x1F80)


if __name__ == '__main__':
    unittest.main()
