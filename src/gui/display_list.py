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

"""PseudoWindowsGUI mixin: Display lists: the shapes programs draw with GDI, kept per window and
control"""


from .. import winapi
from ..config import PYGAME_AVAILABLE
from ..windows import gui_locked

if PYGAME_AVAILABLE:
    import pygame


class DisplayListMixin:
    """Display lists: the shapes programs draw with GDI, kept per window and control"""

    # Upper bound for a retained display list (oldest shapes are dropped)
    MAX_SHAPES = 20000

    @staticmethod
    def covers_area(shape, width, height):
        """True if shape is an opaque rect hiding everything in a width x height area"""
        return DisplayListMixin.covers_rect(shape, (0, 0, width, height))

    @staticmethod
    def covers_rect(shape, area):
        """True if shape opaquely hides everything in area (left, top, right, bottom)"""
        if shape.get('region'):
            return False  # Clipped: only a part of it is drawn
        if shape['type'] == 'image':
            if shape.get('rop') not in (0x00CC0020, 0x00330008) or \
                    shape.get('colorkey') is not None:  # Only opaque SRCCOPY, NOTSRCCOPY
                return False
            (left, top), (w, h) = shape['pos'], shape['size']
            right, bottom = left + w, top + h
        elif shape['type'] != 'rect' or shape.get('fill') is None:
            return False
        else:
            left, top, right, bottom = shape['rect']
        return left <= area[0] and top <= area[1] and right >= area[2] and bottom >= area[3]

    @gui_locked
    def add_shape(self, hwnd, shape):
        """Append a GDI shape to a window's display list (emu thread)."""
        win = self.windows.get(hwnd)
        if win is None:
            control = self.controls.get(hwnd)
            if control is not None:
                if self.covers_area(shape, control.width, control.height):
                    control.drawn_shapes = [shape]
                else:
                    control.drawn_shapes = self.add_to_display_list(
                        control.drawn_shapes, shape)[-self.MAX_SHAPES:]
            return
        # New list objects keep the GUI thread's current snapshot intact
        if self.covers_area(shape, *self.client_size(win)):
            win.drawn_shapes = [shape]
            return
        shapes = self.add_to_display_list(win.drawn_shapes, shape)
        if len(shapes) > self.FLATTEN_SHAPES:
            flat = self._flatten_shapes(win, shapes)
            if flat is not None:
                shapes = [flat]
        if len(shapes) > self.MAX_SHAPES:
            shapes = shapes[-(self.MAX_SHAPES // 2):]
        win.drawn_shapes = shapes

    # Longer window display lists are rasterized into one image shape, so
    # partially overlapping game updates don't slow every frame down
    FLATTEN_SHAPES = 256

    def _flatten_shapes(self, win, shapes):
        """Client-area image shape showing shapes over the window background, or None"""
        width, height = self.client_size(win)
        if width <= 0 or height <= 0:
            return None
        surface = pygame.Surface((width, height))
        surface.fill(win.dialog_brush or win.bg_color)
        for shape in shapes:
            self._draw_shape(shape, 0, 0, surface)
        to_bytes = getattr(pygame.image, 'tobytes', None) or pygame.image.tostring
        rop = winapi.WinAPIHandler.SRCCOPY
        return {'type': 'image', 'pos': (0, 0), 'dim': (width, height),
                'size': (width, height), 'data': to_bytes(surface, 'RGB'), 'rop': rop,
                '_surface': (((width, height), rop), surface)}

    # Only this many recent entries are checked for being hidden by a new shape
    HIDDEN_SCAN = 1024

    @staticmethod
    def shape_bbox(shape):
        """(left, top, right, bottom) a display list entry can paint, or None"""
        stype = shape['type']
        if 'rect' in shape:
            left, top, right, bottom = shape['rect']
            return (min(left, right), min(top, bottom), max(left, right), max(top, bottom))
        if stype in ('image', 'icon'):
            (x, y), (w, h) = shape['pos'], shape['size']
            return (x, y, x + w, y + h)
        if stype == 'pixel':
            x, y = shape['pos']
            return (x, y, x + 1, y + 1)
        if stype == 'text':
            x, y = shape['pos']
            height = (shape.get('font') or {}).get('height', 16)
            return (x, y, x + len(shape['text']) * height, y + height * 2)
        points = shape.get('points') or [p for p in (shape.get('from'), shape.get('to')) if p]
        if not points:
            return None
        pad = (shape['pen'][1] if shape.get('pen') else 1) + 1
        xs, ys = [p[0] for p in points], [p[1] for p in points]
        return (min(xs) - pad, min(ys) - pad, max(xs) + pad, max(ys) + pad)

    @classmethod
    def add_to_display_list(cls, shapes, shape):
        """shapes plus shape, without recent entries the new shape fully hides
        (keeps redraw-in-place game loops from growing the list)"""
        if shape['type'] == 'invert' and shapes and shapes[-1]['type'] == 'invert' and \
                shapes[-1]['rect'] == shape['rect'] and shapes[-1].get('mask') == shape.get('mask'):
            # Inverting the same area twice (a blinking caret) changes nothing
            return shapes[:-1]
        if shape.get('region'):
            shapes.append(shape)  # Clipped to a region: what it hides is not known
            return shapes
        cover = None
        if shape['type'] == 'rect' and shape.get('fill') is not None:
            cover = cls.shape_bbox(shape)
        elif shape['type'] == 'image' and shape.get('rop') in (0x00CC0020, 0x00330008) and \
                shape.get('colorkey') is None:  # An opaque copy
            cover = cls.shape_bbox(shape)
        # An opaque text hides an older one at its place (unless it is clipped:
        # a progress bar draws its percentage twice, each in a part of the bar)
        same_text = shape['type'] == 'text' and shape.get('bk') is not None and \
            not shape.get('clip')
        if cover is None and not same_text:
            shapes.append(shape)  # Cheap path: most shapes hide nothing
            return shapes

        def hidden(old):
            if same_text:
                return old['type'] == 'text' and old['pos'] == shape['pos'] and \
                    len(old['text']) <= len(shape['text']) and old.get('font') == shape.get('font')
            box = cls.shape_bbox(old)
            return box is not None and box[0] >= cover[0] and box[1] >= cover[1] and \
                box[2] <= cover[2] and box[3] <= cover[3]

        split = max(0, len(shapes) - cls.HIDDEN_SCAN)
        return shapes[:split] + [s for s in shapes[split:] if not hidden(s)] + [shape]

    @gui_locked
    def clear_drawings(self, hwnd):
        """Reset a window's display list (start of a paint cycle).

        A new empty list is assigned instead of clearing in place, so the GUI
        thread can safely keep iterating a snapshot it already picked up.
        """
        if hwnd in self.windows:
            self.windows[hwnd].drawn_shapes = []
        elif hwnd in self.controls:
            self.controls[hwnd].drawn_shapes = []
