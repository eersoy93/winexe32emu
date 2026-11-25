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

"""Unit tests of the parts Microsoft PowerPoint 95 needs that work without an
emulated program: the desktop window handle, TA_UPDATECP text, messages
posted to threads, the paint order of overlapping child windows and a few
small GDI and spooler calls.

Run from the repository root:
    python3 -m unittest discover -s tests/python -v
"""

import os
import struct
import sys
import threading
import types
import unittest

from unicorn import Uc, UC_ARCH_X86, UC_MODE_32

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
from src.gui import PseudoWindowsGUI  # noqa: E402
from src.windows import FakeWindow  # noqa: E402
from src.winapi import WinAPIHandler  # noqa: E402


class FakeEmulator:
    """Just enough of CPUEmulator for the handlers: memory, a heap, threads"""
    BASE = 0x100000

    def __init__(self):
        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        self.uc.mem_map(self.BASE, 0x100000)
        self.next = self.BASE
        self.current_thread = types.SimpleNamespace(last_error=0, tid=1000)
        self.threads = {1000: None, 1004: None}

    def heap_alloc(self, size, alignment=16):
        address = self.next
        self.next += (max(size, 1) + 15) & ~15
        return address


def handler_with_memory():
    handler = WinAPIHandler.__new__(WinAPIHandler)
    handler.emu = FakeEmulator()
    handler.dc_state = {}
    handler.gui = None
    return handler


class DesktopWindowTest(unittest.TestCase):
    def test_no_window_gets_the_desktop_handle(self):
        # PowerPoint 95 kept Tip of the Day inside GetWindowRect(GetDesktopWindow()),
        # the rectangle of its frame's fifth child window, 0x10010 too
        gui = PseudoWindowsGUI.__new__(PseudoWindowsGUI)
        gui.lock = threading.RLock()
        gui.next_hwnd = 0x10000
        handles = [gui.get_next_hwnd() for _ in range(8)]
        self.assertNotIn(WinAPIHandler.DESKTOP_HWND, handles)
        self.assertEqual(len(set(handles)), 8)

    def test_desktop_rectangles_are_the_screen(self):
        handler = handler_with_memory()
        handler.gui = types.SimpleNamespace(width=1024, height=768, windows={}, controls={})
        handler.combo_edits = {}
        rect = handler.emu.heap_alloc(16)
        self.assertEqual(handler.GetWindowRect([WinAPIHandler.DESKTOP_HWND, rect]), 1)
        self.assertEqual(struct.unpack('<4i', handler.emu.uc.mem_read(rect, 16)),
                         (0, 0, 1024, 768))
        self.assertEqual(handler.GetClientRect([WinAPIHandler.DESKTOP_HWND, rect]), 1)
        self.assertEqual(struct.unpack('<4i', handler.emu.uc.mem_read(rect, 16)),
                         (0, 0, 1024, 768))


class UpdateCurrentPositionTest(unittest.TestCase):
    TA_UPDATECP, TA_BASELINE, TA_RIGHT = 0x1, 0x18, 0x2

    def handler(self, align):
        handler = handler_with_memory()
        handler.dc_state = {1: {'text_align': align, 'pos': (10, 50)}}
        handler._text_extent = lambda hdc, text: (10 * len(text), 20)
        handler._text_ascent = lambda height: 16
        return handler

    def test_text_goes_at_the_current_position_and_moves_it(self):
        # PowerPoint 95's outline view: TextOut(hdc, 0, 0) with TA_UPDATECP
        handler = self.handler(self.TA_UPDATECP | self.TA_BASELINE)
        self.assertEqual(handler._aligned_text_pos(1, 'abc', 0, 0), (10, 34))
        self.assertEqual(handler.dc_state[1]['pos'], (40, 50))
        self.assertEqual(handler._aligned_text_pos(1, 'de', 0, 0), (40, 34))
        self.assertEqual(handler.dc_state[1]['pos'], (60, 50))

    def test_right_aligned_text_moves_it_left(self):
        handler = self.handler(self.TA_UPDATECP | self.TA_RIGHT)
        self.assertEqual(handler._aligned_text_pos(1, 'abc', 0, 0), (-20, 50))
        self.assertEqual(handler.dc_state[1]['pos'], (-20, 50))

    def test_without_it_the_position_stays(self):
        handler = self.handler(0)
        self.assertEqual(handler._aligned_text_pos(1, 'abc', 5, 6), (5, 6))
        self.assertEqual(handler.dc_state[1]['pos'], (10, 50))

    def test_get_current_position(self):
        handler = self.handler(0)
        point = handler.emu.heap_alloc(8)
        self.assertEqual(handler.GetCurrentPositionEx([1, point]), 1)
        self.assertEqual(struct.unpack('<2i', handler.emu.uc.mem_read(point, 8)), (10, 50))


class ThreadMessageTest(unittest.TestCase):
    def setUp(self):
        handler = handler_with_memory()
        handler.message_queue = []
        handler.message_lock = threading.Lock()
        self.handler = handler

    def test_posted_to_its_thread_only(self):
        # Office 95's file search thread took the File Open dialog's
        # messages from the main thread's queue and crashed on them
        handler = self.handler
        self.assertEqual(handler.PostThreadMessageA([1004, 0x464, 1, 2]), 1)
        self.assertEqual(handler.message_queue[-1]['thread'], 1004)
        self.assertEqual(handler.PostThreadMessageA([1234, 0x464, 1, 2]), 0)

    def test_window_less_post_message_is_the_callers(self):
        self.handler.PostMessageA([0, 0x401, 0, 0])
        self.assertEqual(self.handler.message_queue[-1]['thread'], 1000)
        self.handler.PostMessageA([0x10004, 0x401, 0, 0])
        self.assertNotIn('thread', self.handler.message_queue[-1])

    def test_quit_for_another_thread_is_queued(self):
        self.handler.quit_requested = False
        self.handler.PostThreadMessageA([1004, 0x0012, 0, 0])  # WM_QUIT
        self.assertFalse(self.handler.quit_requested)
        self.assertEqual(self.handler.message_queue[-1]['message'], 0x0012)


class ChildPaintOrderTest(unittest.TestCase):
    def test_overlapping_children_without_clip_siblings(self):
        # Tip of the Day: a white box (top) and the tip's text (below it),
        # neither WS_CLIPSIBLINGS: Windows paints them top down, the text shows
        gui = PseudoWindowsGUI.__new__(PseudoWindowsGUI)
        parent = FakeWindow(1, '', 0, 0, 100, 100)
        gui.windows = {1: parent}
        for hwnd, style in ((2, 0x50000000), (3, 0x50000000), (4, 0x54000000),
                            (5, 0x54000000)):
            gui.windows[hwnd] = FakeWindow(hwnd, '', 0, 0, 10, 10, style)
        parent.children = [2, 3, 4, 5]  # Z order, the top one first
        # Clipped ones bottom up first, then the others top down
        self.assertEqual(gui._child_paint_order(parent), [5, 4, 2, 3])


class SmallApiTest(unittest.TestCase):
    def test_truetype_is_enabled(self):
        handler = handler_with_memory()
        status = handler.emu.heap_alloc(6)
        self.assertEqual(handler.GetRasterizerCaps([status, 6]), 1)
        self.assertEqual(struct.unpack('<3h', handler.emu.uc.mem_read(status, 6)), (6, 3, 0))

    def test_no_printers(self):
        handler = handler_with_memory()
        needed, returned = handler.emu.heap_alloc(4), handler.emu.heap_alloc(4)
        handler.emu.uc.mem_write(needed, b'\xff' * 4)
        handler.emu.uc.mem_write(returned, b'\xff' * 4)
        self.assertEqual(handler.EnumPrintersA([2, 0, 2, 0, 0, needed, returned]), 1)
        self.assertEqual(bytes(handler.emu.uc.mem_read(needed, 4)), b'\x00' * 4)
        self.assertEqual(bytes(handler.emu.uc.mem_read(returned, 4)), b'\x00' * 4)

    def test_text_justification_is_kept(self):
        handler = handler_with_memory()
        handler.dc_state = {1: {}}
        self.assertEqual(handler.SetTextJustification([1, 12, 3]), 1)
        self.assertEqual(handler.dc_state[1]['justification'], (12, 3))
        self.assertEqual(handler.SetTextJustification([2, 12, 3]), 0)


if __name__ == '__main__':
    unittest.main()
