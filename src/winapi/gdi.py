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

"""WinAPIHandler mixin: GDI drawing APIs: pens, brushes, palettes, shapes, fonts"""

import ntpath
import os
import struct

from unicorn import UcError

from .. import config, gui
from ..logger import log
from .font_files import font_file_faces


class GdiMixin:
    """GDI drawing APIs: pens, brushes, palettes, shapes, fonts"""

    # ==================== GDI DRAWING APIs ====================

    def CreatePen(self, args):
        """CreatePen emulation"""
        style = args[0]   # PS_SOLID=0 ... PS_NULL=5
        width = args[1]
        colorref = args[2]

        handle = self.get_next_handle()
        self.gdi_objects[handle] = {
            'type': 'pen',
            'style': style,
            'color': self._colorref_to_rgb(colorref),
            'width': max(1, width),
        }
        log.debug(f"CreatePen(style={style}, width={width}, color=0x{colorref:06x}) "
                  f"-> 0x{handle:x}")
        return handle

    def CreateSolidBrush(self, args):
        """CreateSolidBrush emulation"""
        colorref = args[0]
        handle = self.get_next_handle()
        self.gdi_objects[handle] = {
            'type': 'brush',
            'color': self._colorref_to_rgb(colorref),
            'width': 0,
        }
        log.debug(f"CreateSolidBrush(0x{colorref:06x}) -> 0x{handle:x}")
        return handle

    def CreatePalette(self, args):
        """CreatePalette emulation (LOGPALETTE: version, count, PALETTEENTRY[])"""
        try:
            _, count = struct.unpack('<HH', self.emu.uc.mem_read(args[0], 4))
            raw = bytes(self.emu.uc.mem_read(args[0] + 4, count * 4)) if count else b''
        except UcError:
            return 0
        if not count:
            return 0
        handle = self.get_next_handle()
        self.gdi_objects[handle] = {
            'type': 'palette',
            'entries': [tuple(raw[i:i + 4]) for i in range(0, len(raw), 4)],
        }
        log.debug(f"CreatePalette({count} entries) -> 0x{handle:x}")
        return handle

    def SelectPalette(self, args):
        """SelectPalette emulation - returns the previously selected palette"""
        hdc, hpal = args[0], args[1]
        state = self.dc_state.get(hdc)
        obj = self.gdi_objects.get(hpal)
        if state is None or obj is None:
            return 0
        prev = state.get('palette') or self.GetStockObject([15])  # DEFAULT_PALETTE
        state['palette'] = hpal
        log.debug(f"SelectPalette(0x{hdc:x}, 0x{hpal:x}) -> 0x{prev:x}")
        return prev

    def RealizePalette(self, args):
        """RealizePalette emulation - true-color display, nothing to remap"""
        return 0

    def CreatePenIndirect(self, args):
        """CreatePenIndirect emulation (LOGPEN: style, POINT width, color)"""
        try:
            style, width, _, color = struct.unpack('<IiiI', self.emu.uc.mem_read(args[0], 16))
        except UcError:
            return 0
        return self.CreatePen([style, max(0, width), color])

    def CreateBrushIndirect(self, args):
        """CreateBrushIndirect emulation (LOGBRUSH: style, color, hatch)"""
        try:
            style, color, hatch = struct.unpack('<III', self.emu.uc.mem_read(args[0], 12))
        except UcError:
            return 0
        if style == 1:  # BS_NULL / BS_HOLLOW
            return self.GetStockObject([5])  # NULL_BRUSH
        if style == 2:  # BS_HATCHED
            return self.CreateHatchBrush([hatch, color])
        return self.CreateSolidBrush([color])

    # Stock fonts: index -> (face, pixel height)
    STOCK_FONTS = {
        10: ('courier new', 16, False),    # OEM_FIXED_FONT
        11: ('courier new', 16, False),    # ANSI_FIXED_FONT
        12: ('ms sans serif', 16, False),  # ANSI_VAR_FONT
        13: ('system', 16, True),          # SYSTEM_FONT
        14: ('system', 16, True),          # DEVICE_DEFAULT_FONT
        16: ('courier new', 16, False),    # SYSTEM_FIXED_FONT
        17: ('ms sans serif', 16, False),  # DEFAULT_GUI_FONT
    }
    # DEFAULT_PALETTE: the 20 static colors of a palette display
    DEFAULT_PALETTE_COLORS = [
        (0, 0, 0), (128, 0, 0), (0, 128, 0), (128, 128, 0), (0, 0, 128), (128, 0, 128),
        (0, 128, 128), (192, 192, 192), (192, 220, 192), (166, 202, 240),
        (255, 251, 240), (160, 160, 164), (128, 128, 128), (255, 0, 0), (0, 255, 0),
        (255, 255, 0), (0, 0, 255), (255, 0, 255), (0, 255, 255), (255, 255, 255)]

    def GetStockObject(self, args):
        """GetStockObject emulation"""
        index = args[0]

        # Cache: the same index always returns the same handle
        if index in self._stock_objects:
            return self._stock_objects[index]

        stock = {
            0: ('brush', (255, 255, 255)),   # WHITE_BRUSH
            1: ('brush', (192, 192, 192)),   # LTGRAY_BRUSH
            2: ('brush', (128, 128, 128)),   # GRAY_BRUSH
            3: ('brush', (64, 64, 64)),      # DKGRAY_BRUSH
            4: ('brush', (0, 0, 0)),         # BLACK_BRUSH
            5: ('brush', None),              # NULL_BRUSH (draws nothing)
            6: ('pen', (255, 255, 255)),     # WHITE_PEN
            7: ('pen', (0, 0, 0)),           # BLACK_PEN
            8: ('pen', None),                # NULL_PEN
        }

        handle = self.get_next_handle()
        if index in stock:
            obj_type, color = stock[index]
            obj = {'type': obj_type, 'color': color, 'width': 1}
            if color is None and obj_type == 'pen':
                obj['style'] = 5  # PS_NULL
            self.gdi_objects[handle] = obj
        elif index in self.STOCK_FONTS:
            face, height, bold = self.STOCK_FONTS[index]
            self.gdi_objects[handle] = {'type': 'font', 'height': height, 'bold': bold,
                                        'italic': False, 'underline': False, 'face': face}
        elif index == 15:  # DEFAULT_PALETTE
            self.gdi_objects[handle] = {'type': 'palette', 'entries': [
                (r, g, b, 0) for r, g, b in self.DEFAULT_PALETTE_COLORS]}
        else:
            # Other stock objects (DC_BRUSH, DC_PEN): a generic handle
            self.gdi_objects[handle] = {'type': 'other', 'color': (0, 0, 0), 'width': 0}

        self._stock_objects[index] = handle
        log.debug(f"GetStockObject({index}) -> 0x{handle:x}")
        return handle

    def SelectObject(self, args):
        """SelectObject emulation"""
        hdc = args[0]
        hobj = args[1]

        state = self.dc_state.get(hdc)
        obj = self.gdi_objects.get(hobj)
        prev = 0

        if state and obj:
            kind = obj['type']
            # Selecting a DC default stock object restores the built-in default (0)
            default_kind = next((k for k, h in self._dc_default_objects().items()
                                 if h == hobj), None)
            if default_kind:
                kind = default_kind
            if kind in ('pen', 'brush', 'font', 'bitmap'):
                prev = state.get(kind, 0) or self._dc_default_objects()[kind]
                if kind == 'bitmap' and state.get('memory'):
                    self._store_bitmap_shapes(state)
                    state['shapes'] = list(obj.get('shapes', [])) if not default_kind else []
                state[kind] = 0 if default_kind else hobj

        log.debug(f"SelectObject(0x{hdc:x}, 0x{hobj:x}) -> 0x{prev:x}")
        return prev

    def _dc_default_objects(self):
        """Stock handles standing for a fresh DC's defaults (returned by SelectObject)"""
        if 'bitmap' not in self._stock_objects:
            handle = self.get_next_handle()
            self.gdi_objects[handle] = {'type': 'bitmap', 'width': 1, 'height': 1}
            self._stock_objects['bitmap'] = handle  # 1x1 default bitmap of memory DCs
        return {'pen': self.GetStockObject([7]),     # BLACK_PEN
                'brush': self.GetStockObject([0]),   # WHITE_BRUSH
                'font': self.GetStockObject([13]),   # SYSTEM_FONT
                'bitmap': self._stock_objects['bitmap']}

    def DeleteObject(self, args):
        """DeleteObject emulation"""
        hobj = args[0]
        log.debug(f"DeleteObject(0x{hobj:x})")
        # Keep stock objects alive (deleting them is a no-op in Windows too)
        if hobj in self._stock_objects.values():
            return 1
        # Windows refuses to delete an object that is selected into a DC
        for state in self.dc_state.values():
            if hobj in (state.get('pen'), state.get('brush'), state.get('font'),
                        state.get('bitmap'), state.get('palette')):
                return 0
        obj = self.gdi_objects.pop(hobj, None)
        if obj and obj.get('dib'):
            self.emu.heap_free(obj['dib']['bits'])  # A DIB section's pixels
        return 1 if obj else 0

    def MoveToEx(self, args):
        """MoveToEx emulation - set current position"""
        hdc = args[0]
        x = args[1] if args[1] < 0x80000000 else args[1] - 0x100000000
        y = args[2] if args[2] < 0x80000000 else args[2] - 0x100000000
        lpPoint = args[3]

        state = self.dc_state.get(hdc)
        if state:
            if lpPoint:
                old_x, old_y = state['pos']
                self.emu.uc.mem_write(lpPoint, struct.pack("<ii", old_x, old_y))
            state['pos'] = (x, y)

        log.debug(f"MoveToEx(0x{hdc:x}, {x}, {y})")
        return 1

    def LineTo(self, args):
        """LineTo emulation - draw line from current position"""
        hdc = args[0]
        x = args[1] if args[1] < 0x80000000 else args[1] - 0x100000000
        y = args[2] if args[2] < 0x80000000 else args[2] - 0x100000000

        state = self.dc_state.get(hdc)
        if state:
            pen = self._dc_pen(hdc)
            if pen:
                self._add_shape(hdc, {'type': 'line', 'from': state['pos'],
                                      'to': (x, y), 'pen': pen})
            state['pos'] = (x, y)

        log.debug(f"LineTo(0x{hdc:x}, {x}, {y})")
        return 1

    def Rectangle(self, args):
        """Rectangle emulation - draw rectangle with current pen and brush"""
        hdc = args[0]
        left, top, right, bottom = (v if v < 0x80000000 else v - 0x100000000
                                    for v in args[1:5])

        self._add_shape(hdc, {'type': 'rect', 'rect': (left, top, right, bottom),
                              'fill': self._dc_brush(hdc), 'pen': self._dc_pen(hdc)})

        log.debug(f"Rectangle(0x{hdc:x}, {left}, {top}, {right}, {bottom})")
        return 1

    def Ellipse(self, args):
        """Ellipse emulation - draw ellipse with current pen and brush"""
        hdc = args[0]
        left, top, right, bottom = (v if v < 0x80000000 else v - 0x100000000
                                    for v in args[1:5])

        self._add_shape(hdc, {'type': 'ellipse', 'rect': (left, top, right, bottom),
                              'fill': self._dc_brush(hdc), 'pen': self._dc_pen(hdc)})

        log.debug(f"Ellipse(0x{hdc:x}, {left}, {top}, {right}, {bottom})")
        return 1

    def SetPixel(self, args):
        """SetPixel emulation"""
        hdc = args[0]
        x = args[1] if args[1] < 0x80000000 else args[1] - 0x100000000
        y = args[2] if args[2] < 0x80000000 else args[2] - 0x100000000
        colorref = args[3]

        color = self._colorref_to_rgb(colorref)
        self._add_shape(hdc, {'type': 'pixel', 'pos': (x, y), 'color': color})
        return colorref

    @staticmethod
    def _rgb_to_colorref(rgb):
        """Convert an (r, g, b) tuple to a Win32 COLORREF (0x00BBGGRR)"""
        r, g, b = rgb
        return (b << 16) | (g << 8) | r

    @staticmethod
    def _point_near_segment(px, py, x1, y1, x2, y2, radius):
        """Is (px, py) within radius of the segment (x1,y1)-(x2,y2)?"""
        dx, dy = x2 - x1, y2 - y1
        length_sq = dx * dx + dy * dy
        if length_sq == 0:
            ex, ey = px - x1, py - y1
        else:
            t = max(0.0, min(1.0, ((px - x1) * dx + (py - y1) * dy) / length_sq))
            ex, ey = px - (x1 + t * dx), py - (y1 + t * dy)
        return ex * ex + ey * ey <= radius * radius

    @staticmethod
    def _point_in_polygon(px, py, points):
        """Ray-casting point-in-polygon test"""
        inside = False
        n = len(points)
        for i in range(n):
            x1, y1 = points[i]
            x2, y2 = points[(i + 1) % n]
            if (y1 > py) != (y2 > py):
                x_cross = x1 + (py - y1) * (x2 - x1) / (y2 - y1)
                if px < x_cross:
                    inside = not inside
        return inside

    def _shape_color_at(self, shapes, x, y):
        """Color of the topmost display-list shape covering (x, y), or None"""
        for shape in reversed(shapes):
            stype = shape['type']
            if stype == 'pixel':
                if shape['pos'] == (x, y):
                    return shape['color']
            elif stype in ('rect', 'roundrect'):
                left, top, right, bottom = shape['rect']
                if left <= x < right and top <= y < bottom:
                    pen = shape.get('pen')
                    fill = shape.get('fill')
                    on_border = (x < left + 1 or x >= right - 1 or
                                 y < top + 1 or y >= bottom - 1)
                    if pen and on_border:
                        return pen[0] if isinstance(pen, tuple) else pen
                    if fill is not None:
                        return fill
            elif stype == 'ellipse':
                left, top, right, bottom = shape['rect']
                rx, ry = (right - left) / 2.0, (bottom - top) / 2.0
                if rx > 0 and ry > 0:
                    nx = (x - (left + rx)) / rx
                    ny = (y - (top + ry)) / ry
                    if nx * nx + ny * ny <= 1.0 and shape.get('fill') is not None:
                        return shape['fill']
            elif stype == 'polygon':
                if (shape.get('fill') is not None and len(shape['points']) >= 3 and
                        self._point_in_polygon(x, y, shape['points'])):
                    return shape['fill']
            elif stype == 'line':
                pen = shape.get('pen')
                if pen:
                    color, width = pen
                    x1, y1 = shape['from']
                    x2, y2 = shape['to']
                    if self._point_near_segment(x, y, x1, y1, x2, y2,
                                                max(1, width) / 2.0 + 0.5):
                        return color
            elif stype == 'polyline':
                pen = shape.get('pen')
                if pen:
                    color, width = pen
                    pts = shape['points']
                    for i in range(len(pts) - 1):
                        if self._point_near_segment(x, y, pts[i][0], pts[i][1],
                                                    pts[i + 1][0], pts[i + 1][1],
                                                    max(1, width) / 2.0 + 0.5):
                            return color
            elif stype == 'image':
                (left, top), (w, h) = shape['pos'], shape['dim']
                if (shape.get('rop') == self.SRCCOPY and shape['size'] == (w, h) and
                        left <= x < left + w and top <= y < top + h):
                    i = ((y - top) * w + (x - left)) * 3
                    return tuple(shape['data'][i:i + 3])
            # arc/text: no reliable hit test, skip
        return None

    def GetPixel(self, args):
        """GetPixel emulation - resolved from the DC's display list"""
        hdc = args[0]
        x, y = self._read_signed_args(args, 1, 2)

        state = self.dc_state.get(hdc)
        if state and state.get('memory'):
            shapes = state['shapes']
            background = (255, 255, 255)
        else:
            hwnd = self._dc_hwnd(hdc)
            if not self.gui or hwnd not in self.gui.windows:
                return 0xFFFFFFFF  # CLR_INVALID
            shapes = self.gui.windows[hwnd].drawn_shapes
            background = self.gui.windows[hwnd].bg_color

        color = self._shape_color_at(shapes, x, y)
        if color is None:
            color = background
        colorref = self._rgb_to_colorref(color)
        log.debug(f"GetPixel(0x{hdc:x}, {x}, {y}) -> 0x{colorref:06x}")
        return colorref

    @staticmethod
    def _read_signed_args(args, start, count):
        """Interpret stack dwords as signed 32-bit integers"""
        return [v - 0x100000000 if v >= 0x80000000 else v
                for v in args[start:start + count]]

    def _read_points(self, address, count):
        """Read an array of POINT structures -> [(x, y), ...]"""
        points = []
        try:
            data = self.emu.uc.mem_read(address, count * 8)
            for i in range(count):
                x, y = struct.unpack_from("<ii", data, i * 8)
                points.append((x, y))
        except UcError:
            pass
        return points

    def Polygon(self, args):
        """Polygon emulation - filled polygon with current pen and brush"""
        hdc = args[0]
        points = self._read_points(args[1], args[2])
        log.debug(f"Polygon(0x{hdc:x}, {len(points)} points)")
        if len(points) >= 3:
            self._add_shape(hdc, {'type': 'polygon', 'points': points,
                                  'fill': self._dc_brush(hdc), 'pen': self._dc_pen(hdc)})
        return 1

    def Polyline(self, args):
        """Polyline emulation - connected line segments with current pen"""
        hdc = args[0]
        points = self._read_points(args[1], args[2])
        log.debug(f"Polyline(0x{hdc:x}, {len(points)} points)")
        pen = self._dc_pen(hdc)
        if len(points) >= 2 and pen:
            self._add_shape(hdc, {'type': 'polyline', 'points': points, 'pen': pen})
        return 1

    def RoundRect(self, args):
        """RoundRect emulation - rectangle with rounded corners"""
        hdc = args[0]
        left, top, right, bottom, ew, eh = self._read_signed_args(args, 1, 6)
        log.debug(f"RoundRect(0x{hdc:x}, {left}, {top}, {right}, {bottom})")
        radius = max(0, min(ew, eh) // 2)
        self._add_shape(hdc, {'type': 'roundrect', 'rect': (left, top, right, bottom),
                              'radius': radius, 'fill': self._dc_brush(hdc),
                              'pen': self._dc_pen(hdc)})
        return 1

    @staticmethod
    def _arc_angles(left, top, right, bottom, x1, y1, x2, y2):
        """GDI arc endpoints -> (start, end) angles in math orientation (radians)"""
        import math
        cx, cy = (left + right) / 2.0, (top + bottom) / 2.0
        # Screen y grows downward; math orientation flips it
        start = math.atan2(cy - y1, x1 - cx)
        end = math.atan2(cy - y2, x2 - cx)
        return start, end

    def Arc(self, args):
        """Arc emulation - elliptic arc drawn counterclockwise"""
        hdc = args[0]
        left, top, right, bottom, x1, y1, x2, y2 = self._read_signed_args(args, 1, 8)
        log.debug(f"Arc(0x{hdc:x}, {left}, {top}, {right}, {bottom})")
        pen = self._dc_pen(hdc)
        if pen:
            start, end = self._arc_angles(left, top, right, bottom, x1, y1, x2, y2)
            self._add_shape(hdc, {'type': 'arc', 'rect': (left, top, right, bottom),
                                  'start': start, 'end': end, 'pen': pen})
        return 1

    def Pie(self, args):
        """Pie emulation - filled pie slice (approximated with a polygon)"""
        import math
        hdc = args[0]
        left, top, right, bottom, x1, y1, x2, y2 = self._read_signed_args(args, 1, 8)
        log.debug(f"Pie(0x{hdc:x}, {left}, {top}, {right}, {bottom})")

        start, end = self._arc_angles(left, top, right, bottom, x1, y1, x2, y2)
        if end <= start:
            end += 2 * math.pi

        # Sample the arc into polygon points (plus the center)
        cx, cy = (left + right) / 2.0, (top + bottom) / 2.0
        rx, ry = abs(right - left) / 2.0, abs(bottom - top) / 2.0
        steps = max(8, int((end - start) * 16))
        points = [(int(cx), int(cy))]
        for i in range(steps + 1):
            a = start + (end - start) * i / steps
            points.append((int(cx + rx * math.cos(a)), int(cy - ry * math.sin(a))))

        self._add_shape(hdc, {'type': 'polygon', 'points': points,
                              'fill': self._dc_brush(hdc), 'pen': self._dc_pen(hdc)})
        return 1

    def Chord(self, args):
        """Chord emulation - arc closed by its secant (approximated polygon)"""
        import math
        hdc = args[0]
        left, top, right, bottom, x1, y1, x2, y2 = self._read_signed_args(args, 1, 8)
        log.debug(f"Chord(0x{hdc:x}, {left}, {top}, {right}, {bottom})")

        start, end = self._arc_angles(left, top, right, bottom, x1, y1, x2, y2)
        if end <= start:
            end += 2 * math.pi

        cx, cy = (left + right) / 2.0, (top + bottom) / 2.0
        rx, ry = abs(right - left) / 2.0, abs(bottom - top) / 2.0
        steps = max(8, int((end - start) * 16))
        points = []
        for i in range(steps + 1):
            a = start + (end - start) * i / steps
            points.append((int(cx + rx * math.cos(a)), int(cy - ry * math.sin(a))))

        self._add_shape(hdc, {'type': 'polygon', 'points': points,
                              'fill': self._dc_brush(hdc), 'pen': self._dc_pen(hdc)})
        return 1

    def _brush_color(self, hbr):
        """Resolve a brush handle (or COLOR_* + 1 index) to an RGB color"""
        brush = self.gdi_objects.get(hbr)
        if brush and brush['type'] == 'brush':
            return brush['color']
        if hbr < 32:
            # COLOR_* + 1 stands for that system color
            return self.SYS_COLORS.get(hbr - 1, gui.PseudoWindowsGUI.COLOR_WINDOW_BG)
        return None

    def FrameRect(self, args):
        """FrameRect emulation - one-pixel border drawn with a brush"""
        hdc = args[0]
        lprc = args[1]
        hbr = args[2]

        rect = self._read_rect(lprc) if lprc else None
        color = self._brush_color(hbr)
        if rect is None or color is None:
            return 0

        left, top, right, bottom = rect
        log.debug(f"FrameRect(0x{hdc:x}, ({left},{top},{right},{bottom}))")
        self._add_shape(hdc, {'type': 'rect', 'rect': rect,
                              'fill': None, 'pen': (color, 1)})
        return 1

    def DrawFocusRect(self, args):
        """DrawFocusRect emulation - the focus rectangle (drawn solid, not with
        XOR: owner-drawn items repaint their background before drawing it)"""
        hdc, lprc = args[0], args[1]
        rect = self._read_rect(lprc) if lprc else None
        if rect is None:
            return 0
        self._add_shape(hdc, {'type': 'rect', 'rect': rect, 'fill': None,
                              'pen': ((0, 0, 0), 1)})
        return 1

    # ---------- Regions (unions of rectangles) ----------

    NULLREGION, SIMPLEREGION, COMPLEXREGION = 1, 2, 3
    RGN_AND, RGN_OR, RGN_XOR, RGN_DIFF, RGN_COPY = 1, 2, 3, 4, 5

    def _new_region(self, rects):
        handle = self.get_next_handle()
        self.gdi_objects[handle] = {'type': 'region', 'rects': rects}
        return handle

    def _region_kind(self, rects):
        return (self.NULLREGION if not rects else
                self.SIMPLEREGION if len(rects) == 1 else self.COMPLEXREGION)

    @staticmethod
    def _combine_rects(first, second, test):
        """Rectangles covering the points p for which test(p in first, p in
        second) holds (row bands merged like Windows' region data)"""
        xs = sorted({v for r in first + second for v in (r[0], r[2])})
        ys = sorted({v for r in first + second for v in (r[1], r[3])})

        def inside(rects, x, y):
            return any(r[0] <= x < r[2] and r[1] <= y < r[3] for r in rects)
        bands = []
        for top, bottom in zip(ys, ys[1:], strict=False):
            row = []
            for left, right in zip(xs, xs[1:], strict=False):
                if test(inside(first, left, top), inside(second, left, top)):
                    if row and row[-1][2] == left:
                        row[-1] = (row[-1][0], top, right, bottom)
                    else:
                        row.append((left, top, right, bottom))
            if bands and [(r[0], r[2]) for r in bands[-1]] == [(r[0], r[2]) for r in row] \
                    and bands[-1] and bands[-1][0][3] == top:
                bands[-1] = [(r[0], r[1], r[2], bottom) for r in bands[-1]]
            elif row:
                bands.append(row)
        return [r for band in bands for r in band]

    def CreateRectRgn(self, args):
        """CreateRectRgn emulation"""
        left, top, right, bottom = self._read_signed_args(args, 0, 4)
        left, right = min(left, right), max(left, right)
        top, bottom = min(top, bottom), max(top, bottom)
        rects = [(left, top, right, bottom)] if left < right and top < bottom else []
        return self._new_region(rects)

    def CreateRectRgnIndirect(self, args):
        """CreateRectRgnIndirect emulation"""
        rect = self._read_rect(args[0]) if args[0] else None
        if rect is None:
            return 0
        return self.CreateRectRgn([v & 0xFFFFFFFF for v in rect])

    def CombineRgn(self, args):
        """CombineRgn emulation - returns the kind of the new region"""
        dest, src1, src2, mode = args[:4]
        regions = [self.gdi_objects.get(h) for h in (dest, src1, src2)]
        if regions[0] is None or regions[0]['type'] != 'region' or \
                regions[1] is None or regions[1]['type'] != 'region':
            return 0  # ERROR
        first = list(regions[1]['rects'])
        if mode == self.RGN_COPY:
            rects = first
        else:
            if regions[2] is None or regions[2]['type'] != 'region':
                return 0
            second = list(regions[2]['rects'])
            test = {self.RGN_AND: lambda a, b: a and b, self.RGN_OR: lambda a, b: a or b,
                    self.RGN_XOR: lambda a, b: a != b,
                    self.RGN_DIFF: lambda a, b: a and not b}.get(mode)
            if test is None:
                return 0
            rects = self._combine_rects(first, second, test)
        regions[0]['rects'] = rects
        return self._region_kind(rects)

    def GetRgnBox(self, args):
        """GetRgnBox emulation - the bounding rectangle; returns the kind"""
        region = self.gdi_objects.get(args[0])
        if region is None or region['type'] != 'region':
            return 0
        rects = region['rects']
        box = (min(r[0] for r in rects), min(r[1] for r in rects),
               max(r[2] for r in rects), max(r[3] for r in rects)) if rects else (0, 0, 0, 0)
        if args[1]:
            self._mem_write(args[1], struct.pack('<4i', *box))
        return self._region_kind(rects)

    # ---------- Clipping regions of DCs (kept for their queries; drawing is
    # not clipped to them) ----------

    def _dc_bounds(self, hdc):
        """The whole drawing surface of a DC: a memory DC's bitmap, a window's
        client area or the screen"""
        state = self.dc_state.get(hdc, {})
        if state.get('memory'):
            bmp = self.gdi_objects.get(state.get('bitmap')) or {}
            return (0, 0, bmp.get('width', 1), bmp.get('height', 1))
        hwnd = self.dc_map.get(hdc)
        if self.gui and hwnd in self.gui.windows:
            return (0, 0) + tuple(self.gui.client_size(self.gui.windows[hwnd]))
        if self.gui and hwnd in self.gui.controls:
            control = self.gui.controls[hwnd]
            return (0, 0, control.width, control.height)
        return (0, 0) + tuple(self._screen_size())

    def _dc_clip(self, hdc):
        """Clip rectangles of a DC (its whole surface if it has no clip region)"""
        clip = self.dc_state[hdc].get('clip')
        return list(clip) if clip is not None else [self._dc_bounds(hdc)]

    def _rect_clip(self, args, test):
        hdc = args[0]
        if hdc not in self.dc_state:
            return 0  # ERROR
        left, top, right, bottom = self._read_signed_args(args, 1, 4)
        rect = [(left, top, right, bottom)] if left < right and top < bottom else []
        clip = self._combine_rects(self._dc_clip(hdc), rect, test)
        self.dc_state[hdc]['clip'] = clip
        return self._region_kind(clip)

    def IntersectClipRect(self, args):
        """IntersectClipRect(hdc, left, top, right, bottom) - returns the region kind"""
        return self._rect_clip(args, lambda a, b: a and b)

    def ExcludeClipRect(self, args):
        """ExcludeClipRect(hdc, left, top, right, bottom) - returns the region kind"""
        return self._rect_clip(args, lambda a, b: a and not b)

    def SelectClipRgn(self, args):
        """SelectClipRgn(hdc, hrgn) - a copy of the region; NULL removes the clipping"""
        hdc, hrgn = args[0], args[1]
        if hdc not in self.dc_state:
            return 0
        if not hrgn:
            self.dc_state[hdc]['clip'] = None
            return self.SIMPLEREGION
        region = self.gdi_objects.get(hrgn)
        if region is None or region['type'] != 'region':
            return 0
        self.dc_state[hdc]['clip'] = list(region['rects'])
        return self._region_kind(region['rects'])

    def GetClipBox(self, args):
        """GetClipBox(hdc, lprect) - bounding rectangle of the visible area"""
        hdc = args[0]
        if hdc not in self.dc_state:
            return 0
        rects = self._dc_clip(hdc)
        box = (min(r[0] for r in rects), min(r[1] for r in rects),
               max(r[2] for r in rects), max(r[3] for r in rects)) if rects else (0, 0, 0, 0)
        if args[1]:
            self._mem_write(args[1], struct.pack('<4i', *box))
        return self._region_kind(rects)

    def SetWindowRgn(self, args):
        """SetWindowRgn emulation - the system owns the region afterwards (it is
        kept with the window; drawing is not clipped to it)"""
        hwnd, hrgn = args[0], args[1]
        if not self.gui or (hwnd not in self.gui.windows and hwnd not in self.gui.controls):
            self._last_error = 1400  # ERROR_INVALID_WINDOW_HANDLE
            return 0
        target = self.gui.windows.get(hwnd) or self.gui.controls.get(hwnd)
        region = self.gdi_objects.pop(hrgn, None) if hrgn else None
        target.region = list(region['rects']) if region and region['type'] == 'region' \
            else None
        return 1

    def PatBlt(self, args):
        """PatBlt emulation - BLACKNESS/WHITENESS/PATCOPY fills"""
        hdc = args[0]
        x, y, w, h = self._read_signed_args(args, 1, 4)
        rop = args[5]

        log.debug(f"PatBlt(0x{hdc:x}, {x}, {y}, {w}, {h}, rop=0x{rop:08x})")
        if rop == 0x00000042:        # BLACKNESS
            color = (0, 0, 0)
        elif rop == 0x00FF0062:      # WHITENESS
            color = (255, 255, 255)
        else:
            color = self._dc_brush(hdc)
            # DSTINVERT, PATINVERT with a white brush etc.: what they do to
            # the destination (a text selection, a dragged splitter bar)
            pattern = 1 if color is not None and sum(color) >= 384 else 0
            effect = self.rop3_effect(rop, pattern, 0)
            if effect == 'keep':
                return 1
            if effect == 'invert':
                if w > 0 and h > 0:
                    self._add_shape(hdc, {'type': 'invert', 'rect': (x, y, x + w, y + h)})
                return 1
            # PATCOPY and the others: the current brush
        if color is not None and w > 0 and h > 0:
            self._add_shape(hdc, {'type': 'rect', 'rect': (x, y, x + w, y + h),
                                  'fill': color, 'pen': None})
        return 1

    def CreateHatchBrush(self, args):
        """CreateHatchBrush emulation (hatch pattern approximated as solid)"""
        iHatch = args[0]
        colorref = args[1]
        handle = self.get_next_handle()
        self.gdi_objects[handle] = {
            'type': 'brush',
            'color': self._colorref_to_rgb(colorref),
            'width': 0,
        }
        log.debug(f"CreateHatchBrush({iHatch}, 0x{colorref:06x}) -> 0x{handle:x}")
        return handle

    # DC state that SaveDC does not copy: the drawing of memory DCs, the kind
    # of DC and the stack of saved states itself
    _UNSAVED_DC_KEYS = ('shapes', 'memory', 'saved')

    def SaveDC(self, args):
        """SaveDC(hdc) emulation - pushes the DC's state (objects, colors,
        modes, position); returns the new save level, 0 on error"""
        state = self.dc_state.get(args[0])
        if state is None:
            return 0
        saved = {k: v for k, v in state.items() if k not in self._UNSAVED_DC_KEYS}
        state.setdefault('saved', []).append(saved)
        return len(state['saved'])

    def RestoreDC(self, args):
        """RestoreDC(hdc, nSavedDC) emulation - a positive level, or a negative
        one counted back from the latest save (-1: the latest)"""
        hdc, level = args[0], self._signed32(args[1])
        state = self.dc_state.get(hdc)
        stack = state.get('saved', []) if state else []
        if level < 0:
            level += len(stack) + 1
        if not 1 <= level <= len(stack):
            return 0
        saved = stack[level - 1]
        del stack[level - 1:]
        bitmap = saved.pop('bitmap', None)
        state.update(saved)
        if bitmap is not None and bitmap != state.get('bitmap'):
            self.SelectObject([hdc, bitmap or self._dc_default_objects()['bitmap']])
        return 1

    # Font files added with AddFontResource (lower-case Windows paths), shared
    # by the emulated programs. The fonts are not loaded: text is drawn with
    # the fake desktop's own fonts.
    font_resources = {}
    # The fonts in each added file: {lower-case Windows path: [FontFace]}
    font_resource_faces = {}

    def added_font_faces(self):
        """The fonts of the font files added with AddFontResource"""
        return [face for faces in type(self).font_resource_faces.values() for face in faces]

    def AddFontResourceA(self, args, wide=False):
        """AddFontResourceA/W(lpFileName) - the number of fonts added, 0 if
        the file does not exist"""
        name = self._read_text(args[0], wide) if args[0] else ''
        path = self.full_windows_path(name) if name else None
        host = self.resolve_drive_path(path) if path else None
        if host is None or not os.path.isfile(host):
            # A bare file name is looked up in the Fonts folder
            path = 'C:\\Windows\\Fonts\\' + ntpath.basename(name) if name else None
            host = self.resolve_drive_path(path) if path else None
            if host is None or not os.path.isfile(host):
                log.debug(f"AddFontResource(\"{name}\"): no such file")
                return 0
        counts = type(self).font_resources
        counts[path.lower()] = counts.get(path.lower(), 0) + 1
        faces = type(self).font_resource_faces
        if path.lower() not in faces:
            faces[path.lower()] = font_file_faces(host)
        log.debug(f"AddFontResource(\"{name}\") -> \"{path}\": "
                  f"{sorted({face.name for face in faces[path.lower()]})}")
        return len(faces[path.lower()]) or 1  # The number of fonts added

    def AddFontResourceW(self, args):
        return self.AddFontResourceA(args, wide=True)

    def AddFontResourceExA(self, args):
        """AddFontResourceExA(name, fl, pdv) - private fonts are added like the others"""
        return self.AddFontResourceA(args)

    def AddFontResourceExW(self, args):
        return self.AddFontResourceA(args, wide=True)

    def RemoveFontResourceA(self, args, wide=False):
        """RemoveFontResourceA/W(lpFileName) - 0 if the font was not added"""
        name = self._read_text(args[0], wide) if args[0] else ''
        counts = type(self).font_resources
        for path in (self.full_windows_path(name) if name else None,
                     'C:\\Windows\\Fonts\\' + ntpath.basename(name) if name else None):
            if path and counts.get(path.lower()):
                counts[path.lower()] -= 1
                if not counts[path.lower()]:
                    del counts[path.lower()]
                    type(self).font_resource_faces.pop(path.lower(), None)
                return 1
        return 0

    def RemoveFontResourceW(self, args):
        return self.RemoveFontResourceA(args, wide=True)

    def RemoveFontResourceExA(self, args):
        return self.RemoveFontResourceA(args)

    def RemoveFontResourceExW(self, args):
        return self.RemoveFontResourceA(args, wide=True)

    def CreateScalableFontResourceA(self, args, wide=False):
        """CreateScalableFontResourceA/W(fdwHidden, lpszFontRes, lpszFontFile,
        lpszCurrentPath) - writes the font resource (.FOT) file, which here
        only names the TrueType file"""
        fot = self._read_text(args[1], wide) if args[1] else ''
        ttf = self._read_text(args[2], wide) if args[2] else ''
        host = self.resolve_drive_path(fot) if fot else None
        if host is None or self._write_protected(host):
            self._last_error = 5  # ERROR_ACCESS_DENIED
            return 0
        if os.path.exists(host):
            self._last_error = 80  # ERROR_FILE_EXISTS
            return 0
        try:
            with open(host, 'wb') as f:
                f.write(b'FONTRES:' + ttf.encode(config.ANSI_CODEPAGE, errors='replace'))
        except OSError:
            self._last_error = 3  # ERROR_PATH_NOT_FOUND
            return 0
        return 1

    def CreateScalableFontResourceW(self, args):
        return self.CreateScalableFontResourceA(args, wide=True)

    # ---------- Mapping modes (the transforms: GdiExtraMixin._dc_mapping) ----------

    MM_TEXT = 1

    def SetMapMode(self, args):
        """SetMapMode(hdc, mode) - the previous mode"""
        state = self.dc_state.get(args[0])
        if state is None or not 1 <= args[1] <= 8:
            return 0
        previous = state.get('map_mode', self.MM_TEXT)
        state['map_mode'] = args[1]
        return previous

    def GetMapMode(self, args):
        state = self.dc_state.get(args[0])
        return state.get('map_mode', self.MM_TEXT) if state is not None else 0

    def DPtoLP(self, args):
        """DPtoLP(hdc, lppt, c) - device -> logical coordinates"""
        return self._convert_points(args, self._dp_to_lp)

    def LPtoDP(self, args):
        return self._convert_points(args, self._lp_to_dp)

    def GetNearestColor(self, args):
        """GetNearestColor(hdc, color) emulation - the display has 32 bits per
        pixel, so every RGB color is shown as it is; a palette index or
        palette-relative COLORREF gives its RGB value"""
        return args[1] & 0x00FFFFFF

    def CreatePatternBrush(self, args):
        """CreatePatternBrush(hbm) emulation - brushes are solid: the pattern is
        approximated by the average color of the bitmap (gray, like the
        common 8x8 dither patterns, if it cannot be read)"""
        hbm = args[0]
        bmp = self.gdi_objects.get(hbm)
        if not bmp or bmp['type'] != 'bitmap':
            return 0
        color = (128, 128, 128)
        try:
            pixels = self._bitmap_rgb(hbm)
        except (UcError, ValueError, TypeError):
            pixels = None
        if pixels:
            count = len(pixels) // 3
            if count:
                color = tuple(sum(pixels[i::3]) // count for i in range(3))
        handle = self.get_next_handle()
        self.gdi_objects[handle] = {'type': 'brush', 'color': color, 'width': 0}
        log.debug(f"CreatePatternBrush(0x{hbm:x}) -> 0x{handle:x}, color {color}")
        return handle

    def CreateFontA(self, args):
        """CreateFontA emulation"""
        height = args[0] - 0x100000000 if args[0] >= 0x80000000 else args[0]
        weight = args[4]
        italic = args[5]
        underline = args[6]
        face = self.read_string(args[13]) if args[13] else ""

        handle = self.get_next_handle()
        self.gdi_objects[handle] = {
            'type': 'font',
            'height': abs(height) or 13,
            'cell': height >= 0,  # Negative: character (em) height, else cell height
            'bold': weight >= 600,
            'italic': bool(italic),
            'underline': bool(underline),
            'face': face,
        }
        log.debug(f"CreateFontA(height={height}, weight={weight}, '{face}') -> 0x{handle:x}")
        return handle

    def CreateFontIndirectA(self, args, wide=False):
        """CreateFontIndirectA/W emulation - font from a LOGFONT structure"""
        lplf = args[0]
        try:
            data = bytes(self.emu.uc.mem_read(lplf, 92 if wide else 60))
            height = struct.unpack_from("<i", data, 0)[0]
            weight = struct.unpack_from("<i", data, 16)[0]
            italic, underline = data[20], data[21]
            if wide:
                face = data[28:92].decode('utf-16-le', errors='replace').split('\x00')[0]
            else:
                face = data[28:60].split(b'\x00')[0].decode(config.ANSI_CODEPAGE, errors='replace')
        except UcError:
            return 0

        handle = self.get_next_handle()
        self.gdi_objects[handle] = {
            'type': 'font',
            'height': abs(height) or 13,
            'cell': height >= 0,  # Negative: character (em) height, else cell height
            'bold': weight >= 600,
            'italic': bool(italic),
            'underline': bool(underline),
            'face': face,
        }
        log.debug(f"CreateFontIndirectA(height={height}, '{face}') -> 0x{handle:x}")
        return handle

    def CreateFontIndirectW(self, args):
        return self.CreateFontIndirectA(args, wide=True)

    def GetTextExtentPoint32A(self, args, wide=False):
        """GetTextExtentPoint32A/W emulation - measure a string"""
        hdc = args[0]
        text = self._read_text(args[1], wide) if args[1] else ""
        c = args[2]
        lpSize = args[3]
        if c > 0 and len(text) > c:
            text = text[:c]

        width, height = self._text_extent(hdc, text)
        if lpSize:
            self.emu.uc.mem_write(lpSize, struct.pack("<ii", width, height))
        return 1

    def GetTextExtentPoint32W(self, args):
        return self.GetTextExtentPoint32A(args, wide=True)

    def GetTextExtentPointA(self, args):
        """GetTextExtentPointA - the Win16-era name; in Win32 it is the same as
        GetTextExtentPoint32A"""
        return self.GetTextExtentPoint32A(args)

    def GetTextExtentPointW(self, args):
        return self.GetTextExtentPoint32A(args, wide=True)

    def _char_widths(self, hdc, first, last, wide):
        """Advance widths of the characters first..last in the DC's font (None
        for a bad range); an ANSI code that is no character measures like "?"."""
        if last < first or last - first >= 0x10000 or (not wide and last > 0xFF):
            return None
        widths = []
        for code in range(first, last + 1):
            ch = chr(code) if wide else self._ansi_char(code)
            widths.append(self._text_extent(hdc, ch if ch else '?')[0])
        return widths

    def GetCharWidthA(self, args, wide=False):
        """GetCharWidth(32)A/W(hdc, iFirst, iLast, lpBuffer): an INT width per
        character"""
        hdc, first, last, buffer = args[:4]
        widths = self._char_widths(hdc, first, last, wide)
        if widths is None or not buffer:
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0
        return 1 if self._mem_write(buffer, struct.pack(f'<{len(widths)}i', *widths)) else 0

    def GetCharWidthW(self, args):
        return self.GetCharWidthA(args, wide=True)

    GetCharWidth32A = GetCharWidthA
    GetCharWidth32W = GetCharWidthW

    def GetCharABCWidthsA(self, args, wide=False):
        """GetCharABCWidthsA/W(hdc, uFirst, uLast, lpABC): the fonts are drawn
        without overhangs, so A and C are 0 and B is the advance width"""
        hdc, first, last, buffer = args[:4]
        widths = self._char_widths(hdc, first, last, wide)
        if widths is None or not buffer:
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0
        data = b''.join(struct.pack('<iIi', 0, w, 0) for w in widths)
        return 1 if self._mem_write(buffer, data) else 0

    def GetCharABCWidthsW(self, args):
        return self.GetCharABCWidthsA(args, wide=True)

    def _text_extent(self, hdc, text):
        """(width, height) of text in the DC's font, measured with the font the
        GUI draws it with; without the GUI the font is close to 8x16 per character"""
        font = self._dc_font(hdc)
        if self.gui and self.gui.font is not None:
            with self.gui.lock:
                render_font = self.gui._get_render_font(font)
                width = render_font.size(text)[0]
                if font and not font.get('cell', True):
                    return width, render_font.get_height()
            return width, font['height'] if font else 16
        if font:
            return int(len(text) * font['height'] * 0.55), font['height']
        return len(text) * 8, 16
