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

"""Unit tests of the parts Microsoft Excel 95 needs that work without an
emulated program: raster operations on the pixels of memory bitmaps, drawing
clipped to a DC's clip region, update rectangles and key scan codes.

Run from the repository root:
    python3 -m unittest discover -s tests/python -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
from src.gui import PseudoWindowsGUI  # noqa: E402
from src.gui.keyboard import key_lparam  # noqa: E402
from src.winapi import WinAPIHandler  # noqa: E402

SRCAND, SRCPAINT, SRCINVERT, DSTINVERT = 0x008800C6, 0x00EE0086, 0x00660046, 0x00550009
PATCOPY, PATINVERT = 0x00F00021, 0x005A0049


class Rop3BytesTest(unittest.TestCase):
    """Excel builds its toolbar buttons from a picture and a mask with these"""

    def test_source_operations(self):
        rop = WinAPIHandler.rop3_bytes
        source, dest = bytes([0x0F, 0xF0, 0xFF]), bytes([0x3C, 0x3C, 0x00])
        self.assertEqual(rop(SRCAND, None, source, dest), bytes([0x0C, 0x30, 0x00]))
        self.assertEqual(rop(SRCPAINT, None, source, dest), bytes([0x3F, 0xFC, 0xFF]))
        self.assertEqual(rop(SRCINVERT, None, source, dest), bytes([0x33, 0xCC, 0xFF]))

    def test_pattern_and_destination_operations(self):
        rop = WinAPIHandler.rop3_bytes
        pattern, dest = bytes([0xAA, 0x55]), bytes([0x0F, 0x0F])
        self.assertEqual(rop(DSTINVERT, pattern, None, dest), bytes([0xF0, 0xF0]))
        self.assertEqual(rop(PATCOPY, pattern, None, dest), pattern)
        self.assertEqual(rop(PATINVERT, pattern, None, dest), bytes([0xA5, 0x5A]))

    def test_crop(self):
        rgb = bytes(range(2 * 3 * 3))  # 3 pixels wide, 2 rows
        self.assertEqual(WinAPIHandler._crop_rgb(rgb, 3, 1, 0, 2, 2),
                         rgb[3:9] + rgb[12:18])


def handler_with_dc(**state):
    handler = WinAPIHandler.__new__(WinAPIHandler)
    handler.dc_state = {1: dict(state)}
    return handler


class ClipTest(unittest.TestCase):
    """Drawing is clipped to the clip region and to a partial WM_PAINT"""

    FILL = {'type': 'rect', 'rect': (0, 0, 100, 100), 'fill': (1, 2, 3), 'pen': None}

    def test_no_clip_region(self):
        handler = handler_with_dc()
        self.assertIsNone(handler._draw_clip(1))
        self.assertEqual(handler._clip_shape(1, self.FILL), [self.FILL])

    def test_update_rectangle_inside_the_clip_region(self):
        handler = handler_with_dc(clip=[(0, 0, 50, 50), (80, 80, 90, 90)], vis=(40, 40, 85, 85))
        self.assertEqual(handler._draw_clip(1), [(40, 40, 50, 50), (80, 80, 85, 85)])

    def test_plain_rectangles_are_cut(self):
        handler = handler_with_dc(clip=[(10, 10, 20, 20), (200, 0, 210, 10)])
        self.assertEqual(handler._clip_shape(1, self.FILL),
                         [dict(self.FILL, rect=(10, 10, 20, 20))])
        invert = {'type': 'invert', 'rect': (15, 0, 30, 30)}
        self.assertEqual(handler._clip_shape(1, invert),
                         [{'type': 'invert', 'rect': (15, 10, 20, 20)}])

    def test_other_shapes_get_a_region(self):
        handler = handler_with_dc(clip=[(10, 10, 20, 20)])
        line = {'type': 'line', 'from': (0, 15), 'to': (100, 15), 'pen': ((0, 0, 0), 1)}
        self.assertEqual(handler._clip_shape(1, line), [dict(line, region=((10, 10, 20, 20),))])
        inside = {'type': 'pixel', 'pos': (12, 12), 'color': (0, 0, 0)}
        self.assertEqual(handler._clip_shape(1, inside), [inside])
        outside = {'type': 'pixel', 'pos': (50, 50), 'color': (0, 0, 0)}
        self.assertEqual(handler._clip_shape(1, outside), [])

    def test_regions_are_intersected(self):
        handler = handler_with_dc(clip=[(0, 0, 15, 15)])
        line = {'type': 'line', 'from': (0, 12), 'to': (100, 12), 'pen': ((0, 0, 0), 1),
                'region': ((10, 10, 20, 20),)}
        self.assertEqual(handler._clip_shape(1, line)[0]['region'], ((10, 10, 15, 15),))

    def test_clipped_shapes_hide_nothing(self):
        clipped = dict(self.FILL, region=((0, 0, 5, 5),))
        self.assertFalse(PseudoWindowsGUI.covers_rect(clipped, (0, 0, 100, 100)))
        self.assertTrue(PseudoWindowsGUI.covers_rect(self.FILL, (0, 0, 100, 100)))
        old = {'type': 'pixel', 'pos': (50, 50), 'color': (0, 0, 0)}
        self.assertEqual(PseudoWindowsGUI.add_to_display_list([old], clipped), [old, clipped])

    def test_regions_move_with_a_blit(self):
        line = {'type': 'line', 'from': (0, 0), 'to': (5, 5), 'pen': ((0, 0, 0), 1),
                'region': ((1, 2, 3, 4),)}
        moved = WinAPIHandler._translate_shape(line, 10, 20)
        self.assertEqual(moved['region'], ((11, 22, 13, 24),))


class UpdateRectangleTest(unittest.TestCase):
    """InvalidateRect with a rectangle repaints only that part"""

    def handler(self):
        handler = WinAPIHandler.__new__(WinAPIHandler)
        handler.gui = None
        handler.painted_windows = {7}
        handler.paint_pending = set()
        handler.update_rects = {}
        handler.dirty_controls = {}
        return handler

    def test_invalid_rectangles_add_up(self):
        handler = self.handler()
        handler.gui = type('Gui', (), {'windows': {7: object()}, 'controls': {},
                                       'client_size': staticmethod(lambda win: (100, 100))})()
        handler._invalidate(7, (10, 10, 20, 20))
        self.assertNotIn(7, handler.painted_windows)
        self.assertEqual(handler.update_rects[7], (10, 10, 20, 20))
        handler._invalidate(7, (50, 5, 300, 15))  # Cut to the client area
        self.assertEqual(handler.update_rects[7], (10, 5, 100, 20))
        handler._invalidate(7)  # The whole window
        self.assertNotIn(7, handler.update_rects)
        handler._invalidate(7, (1, 1, 2, 2))  # ... stays whole
        self.assertNotIn(7, handler.update_rects)

    def test_nothing_outside_the_window(self):
        handler = self.handler()
        handler.gui = type('Gui', (), {'windows': {7: object()}, 'controls': {},
                                       'client_size': staticmethod(lambda win: (100, 100))})()
        handler._invalidate(7, (200, 200, 300, 300))
        self.assertIn(7, handler.painted_windows)


class KeyScanCodeTest(unittest.TestCase):
    def test_scan_codes(self):
        self.assertEqual(key_lparam(0x41), 0x001E0001)  # A
        self.assertEqual(key_lparam(0x0D, 0xC0000001), 0xC01C0001)  # Enter, released
        self.assertEqual(key_lparam(0x26), 0x01480001)  # Up: an extended key
        self.assertEqual(key_lparam(None), 1)


if __name__ == '__main__':
    unittest.main()
