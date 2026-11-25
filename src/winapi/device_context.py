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

"""WinAPIHandler mixin: Device context helpers, painting and text output"""

import struct

from unicorn import UcError

from .. import gui
from ..logger import log
from .font_files import TRUETYPE_FONTTYPE


class DeviceContextMixin:
    """Device context helpers, painting and text output"""

    # ==================== DEVICE CONTEXT HELPERS ====================

    @staticmethod
    def _colorref_to_rgb(colorref):
        """Convert a Win32 COLORREF (0x00BBGGRR) to an (r, g, b) tuple"""
        return (colorref & 0xFF, (colorref >> 8) & 0xFF, (colorref >> 16) & 0xFF)

    def _create_dc(self, hwnd, memory=False):
        """Create a DC handle bound to a window (or an off-screen memory DC)"""
        hdc = self.get_next_handle()
        self.dc_map[hdc] = hwnd
        self.dc_state[hdc] = {
            'pen': 0,          # 0 = default black pen, width 1
            'brush': 0,        # 0 = default white brush
            'font': 0,         # 0 = default GUI font
            'pos': (0, 0),     # Current position (MoveToEx/LineTo)
            'text_color': (0, 0, 0),
            'bk_mode': 2,      # OPAQUE
            'bk_color': (255, 255, 255),
            'memory': memory,  # Memory DCs keep their own display list
            'shapes': [] if memory else None,
            'bitmap': 0,       # Selected bitmap (memory DCs)
        }
        return hdc

    def _delete_dc(self, hdc):
        """Release a DC handle"""
        self._store_bitmap_shapes(self.dc_state.get(hdc))
        self.dc_map.pop(hdc, None)
        self.dc_state.pop(hdc, None)

    def _store_bitmap_shapes(self, state):
        """Keep a memory DC's drawing with its selected bitmap (it outlives the selection)"""
        if state and state.get('memory') and state.get('bitmap'):
            bmp = self.gdi_objects.get(state['bitmap'])
            if bmp and bmp['type'] == 'bitmap':
                bmp['shapes'] = state['shapes']

    def _dc_hwnd(self, hdc):
        """Window a DC belongs to (fall back to the active window)"""
        hwnd = self.dc_map.get(hdc, 0)
        if not hwnd and self.gui:
            active = self.gui.active_window
            if self.gui.window_owner(active) is self:
                hwnd = active
        return hwnd

    def _dc_pen(self, hdc):
        """Current pen of a DC -> (color, width) or None for PS_NULL"""
        state = self.dc_state.get(hdc)
        if state and state['pen']:
            pen = self.gdi_objects.get(state['pen'])
            if pen and pen['type'] == 'pen':
                if pen.get('style', 0) == 5:  # PS_NULL
                    return None
                return (pen['color'], max(1, pen['width']))
        return ((0, 0, 0), 1)  # Default: black pen, width 1

    # On/off pixel runs of the styled cosmetic pens: PS_DASH, PS_DOT,
    # PS_DASHDOT, PS_DASHDOTDOT
    PEN_DASHES = {1: (18, 6), 2: (3, 3), 3: (9, 6, 3, 6), 4: (9, 3, 3, 3, 3, 3)}

    def _with_pen_style(self, hdc, shape):
        """shape with the 'dash' pattern of the DC's pen if it is a styled
        one-pixel pen (PowerPoint 95's dotted placeholder outlines)"""
        state = self.dc_state.get(hdc)
        pen = self.gdi_objects.get(state['pen']) if state and state.get('pen') else None
        if pen and pen['type'] == 'pen' and pen.get('width', 1) <= 1:
            dash = self.PEN_DASHES.get(pen.get('style', 0) & 0xF)
            if dash:
                shape['dash'] = dash
        return shape

    def _dc_brush(self, hdc):
        """Current brush color of a DC, or None for NULL_BRUSH"""
        state = self.dc_state.get(hdc)
        if state and state['brush']:
            brush = self.gdi_objects.get(state['brush'])
            if brush and brush['type'] == 'brush':
                return self._brush_color(state['brush'], hdc)  # None for NULL_BRUSH
        return (255, 255, 255)  # Default: white brush

    def _dc_font(self, hdc):
        """Current font dict of a DC, or None for the default GUI font"""
        state = self.dc_state.get(hdc)
        if state and state.get('font'):
            font = self.gdi_objects.get(state['font'])
            if font and font['type'] == 'font':
                return font
        return None

    def _memdc_size(self, hdc):
        """Bitmap size of a memory DC -> (w, h) or None"""
        state = self.dc_state.get(hdc)
        if state:
            bmp = self.gdi_objects.get(state.get('bitmap', 0))
            if bmp and bmp['type'] == 'bitmap':
                return (bmp['width'], bmp['height'])
        return None

    @staticmethod
    def _rect_and(a, b):
        """Intersection of two (left, top, right, bottom) rectangles, or None"""
        left, top = max(a[0], b[0]), max(a[1], b[1])
        right, bottom = min(a[2], b[2]), min(a[3], b[3])
        return (left, top, right, bottom) if left < right and top < bottom else None

    def _draw_clip(self, hdc):
        """Device rectangles the drawing on a DC is clipped to: its clip region
        (SelectClipRgn...) inside the update rectangle of a partial WM_PAINT
        ('vis'); None if nothing clips it"""
        state = self.dc_state.get(hdc)
        if not state:
            return None
        clip, vis = state.get('clip'), state.get('vis')
        if clip is None:
            return None if vis is None else [vis]
        if vis is None:
            return list(clip)
        return [part for part in (self._rect_and(rect, vis) for rect in clip) if part]

    def _clip_shape(self, hdc, shape):
        """The display list entries of a shape (in device coordinates) drawn on
        a DC: the shape itself, parts of it, the shape with the 'region' it
        is drawn in, or nothing if the DC's clipping hides it"""
        rects = self._draw_clip(hdc)
        if rects is None:
            return [shape]
        if shape.get('region'):
            rects = [part for part in (self._rect_and(a, b) for a in rects
                                       for b in shape['region']) if part]
        if not rects:
            return []
        stype = shape['type']
        if not shape.get('region') and (
                (stype == 'invert' and shape.get('mask') is None) or
                (stype == 'rect' and shape.get('pen') is None and
                 shape.get('fill') is not None)):
            # Plain rectangles are cut instead
            left, top, right, bottom = shape['rect']
            box = (min(left, right), min(top, bottom), max(left, right), max(top, bottom))
            return [dict(shape, rect=part) for part in
                    (self._rect_and(box, rect) for rect in rects) if part]
        box = gui.PseudoWindowsGUI.shape_bbox(shape)
        if box is not None:
            rects = [rect for rect in rects if self._rect_and(box, rect)]
            if not rects:
                return []
            if not shape.get('region') and any(
                    rect[0] <= box[0] and rect[1] <= box[1] and rect[2] >= box[2] and
                    rect[3] >= box[3] for rect in rects):
                return [shape]  # Wholly inside
        return [dict(shape, region=tuple(rects))]

    def _add_shape(self, hdc, shape, mapped=False):
        """Append a GDI shape, clipped to the DC's clip region, to the display
        list of the DC's window or memory bitmap (see _append_shape)"""
        if not mapped:
            shape = self._map_shape(hdc, shape)
        for part in self._clip_shape(hdc, shape):
            self._append_shape(hdc, part)

    def _append_shape(self, hdc, shape, mapped=True):
        """Append a GDI shape to the display list of the DC's window.

        The shape is in the DC's logical coordinates (its window and viewport
        origins and extents), unless mapped says it is in device ones.
        Memory DCs collect shapes in their own list until BitBlt copies them.
        An opaque rect covering the whole bitmap restarts the list, so a
        game loop that fills the background every frame doesn't grow it.
        """
        if not mapped:
            shape = self._map_shape(hdc, shape)
        state = self.dc_state.get(hdc)
        if state and state.get('memory'):
            size = self._memdc_size(hdc)
            if size and gui.PseudoWindowsGUI.covers_area(shape, *size):
                state['shapes'] = [shape]
                return
            shapes = gui.PseudoWindowsGUI.add_to_display_list(state['shapes'], shape)
            if len(shapes) > gui.PseudoWindowsGUI.MAX_SHAPES:
                shapes = shapes[-(gui.PseudoWindowsGUI.MAX_SHAPES // 2):]
            state['shapes'] = shapes
            return

        hwnd = self._dc_hwnd(hdc)
        if self.gui and hwnd:
            self.gui.add_shape(hwnd, shape)

    def _add_text(self, hdc, text, x, y, clip=None, dx=None):
        """Append a text item to the DC's display list (window or memory DC);
        clip (left, top, right, bottom) cuts it off outside a rectangle, dx
        (ExtTextOut's lpDx) gives the distance from each character to the next"""
        state = self.dc_state.get(hdc, {})
        shape = {
            'type': 'text',
            'pos': (x, y),
            'text': text,
            'color': state.get('text_color') or (0, 0, 0),
            'font': self._dc_font(hdc),
            # OPAQUE background mode fills the text cell with the background color
            'bk': state.get('bk_color') if state.get('bk_mode', 2) == 2 else None,
        }
        if clip is not None:
            shape['clip'] = clip
        if dx:
            shape['dx'] = dx
        self._add_shape(hdc, shape)

    WM_ERASEBKGND = 0x0014

    def BeginPaint(self, args):
        """BeginPaint emulation"""
        hWnd = args[0]
        lpPaint = args[1]

        log.debug(f"BeginPaint(0x{hWnd:x})")
        self.paint_pending.discard(hWnd)  # BeginPaint validates the update region
        update = self.update_rects.pop(hWnd, None)

        hdc = self._own_dc(hWnd) or self._create_dc(hWnd)
        win = self.gui.windows.get(hWnd) if self.gui else None
        if win is None:
            update = None
        self.dc_state[hdc].pop('vis', None)

        if update is None:
            # Painting starts fresh: clear the window's retained display lists
            if self.gui:
                self.gui.clear_drawings(hWnd)
        else:
            # Only a part is painted: the DC draws nothing outside it, and
            # the class brush (the window's background) erases it
            if not win.transparent:
                self.gui.add_shape(hWnd, {'type': 'rect', 'rect': update, 'pen': None,
                                          'fill': win.dialog_brush or win.bg_color})
            self.dc_state[hdc]['vis'] = update

        # Like Windows, the window procedure erases the background first
        # (Word's dialogs paint their gray face there); fErase tells WM_PAINT
        # whether it is still to do. The whole window is painted again (its
        # drawings were cleared), so it is erased every time.
        erase = 0
        if self.gui and hWnd in self.gui.windows and hWnd not in self.gui.consoles:
            erase = 0 if self.SendMessageA([hWnd, self.WM_ERASEBKGND, hdc, 0]) else 1

        # Fill PAINTSTRUCT structure
        if lpPaint:
            # Client area size
            right, bottom = 400, 300
            if self.gui and hWnd in self.gui.windows:
                win = self.gui.windows[hWnd]
                right, bottom = self.gui.client_size(win)
            # hdc, fErase, rcPaint(4 int), fRestore, fIncUpdate, rgbReserved[32]
            paint_data = struct.pack("<II", hdc, erase)  # First 8 bytes
            paint_data += struct.pack("<iiii", *(update or (0, 0, right, bottom)))  # rcPaint
            paint_data += b'\x00' * (64 - len(paint_data))  # Rest
            self.emu.uc.mem_write(lpPaint, paint_data[:64])

        return hdc

    def EndPaint(self, args):
        """EndPaint emulation"""
        hWnd = args[0]
        lpPaint = args[1]
        log.debug(f"EndPaint(0x{hWnd:x})")
        # Free the DC allocated by BeginPaint
        if lpPaint:
            try:
                hdc = struct.unpack("<I", self.emu.uc.mem_read(lpPaint, 4))[0]
                if self.own_dcs.get(hWnd) == hdc:
                    self.dc_state[hdc].pop('vis', None)  # The private DC lives on
                else:
                    self._delete_dc(hdc)
            except UcError:
                pass
        return 1

    def InvalidateRect(self, args):
        """InvalidateRect emulation - request a repaint via WM_PAINT: of the
        rectangle, or of the whole client area (lpRect NULL)"""
        hWnd = args[0]
        lpRect = args[1]
        log.debug(f"InvalidateRect(0x{hWnd:x})")
        rect = None
        if lpRect and self.gui and hWnd in self.gui.windows:
            rect = self._read_rect(lpRect)
        self._invalidate(hWnd, rect)
        return 1

    def _invalidate(self, hwnd, rect=None):
        """Add rect (client coordinates; None: the whole client area) to a
        window's update region. GetMessage synthesizes WM_PAINT for windows
        not in painted_windows."""
        win = self.gui.windows.get(hwnd) if self.gui else None
        if rect is not None and win is not None:
            rect = self._rect_and(rect, (0, 0) + tuple(self.gui.client_size(win)))
            if rect is None:
                return  # Nothing of it is in the window
        valid = hwnd in self.painted_windows and hwnd not in self.paint_pending
        if rect is None or win is None:
            self.update_rects.pop(hwnd, None)
        elif valid:
            self.update_rects[hwnd] = rect
        elif hwnd in self.update_rects:
            old = self.update_rects[hwnd]
            self.update_rects[hwnd] = (min(old[0], rect[0]), min(old[1], rect[1]),
                                       max(old[2], rect[2]), max(old[3], rect[3]))
        self.painted_windows.discard(hwnd)
        if self.gui and hwnd in self.gui.controls:
            self.dirty_controls[hwnd] = True

    def _invalidate_area(self, hwnd, rect, skip=0):
        """Invalidate rect (client coordinates of hwnd) in the visible window
        hwnd and in its child windows (not in skip): what a hidden or moved
        child window uncovered"""
        win = self.gui.windows.get(hwnd) if self.gui else None
        if win is None or not win.visible:
            return
        rect = self._rect_and(rect, (0, 0) + tuple(self.gui.client_size(win)))
        if rect is None:
            return
        if win.owner is self and hwnd not in self.dialogs:
            self._invalidate(hwnd, rect)
        for child in list(win.children):
            child_win = self.gui.windows.get(child)
            if child == skip or child_win is None:
                continue
            border, caption = self.gui.child_frame(child_win)
            x, y = child_win.x + border, child_win.y + border + caption
            self._invalidate_area(child, (rect[0] - x, rect[1] - y, rect[2] - x, rect[3] - y))

    def FillRect(self, args):
        """FillRect emulation"""
        hdc = args[0]
        lprc = args[1]
        hbr = args[2]

        if not lprc:
            log.debug(f"FillRect(0x{hdc:x})")
            return 1

        try:
            rect_data = self.emu.uc.mem_read(lprc, 16)
            left, top, right, bottom = struct.unpack("<iiii", rect_data)
        except UcError:
            log.debug(f"FillRect(0x{hdc:x})")
            return 1

        log.debug(f"FillRect(0x{hdc:x}, rect=({left},{top},{right},{bottom}), brush=0x{hbr:x})")

        # Resolve the brush: GDI handle, or a system color index + 1 (e.g. COLOR_WINDOW+1)
        color = self._brush_color(hbr, hdc)

        if color is not None:
            self._add_shape(hdc, {'type': 'rect', 'rect': (left, top, right, bottom),
                                  'fill': color, 'pen': None})
        return 1

    CS_OWNDC = 0x0020

    def _own_dc(self, hwnd):
        """The private DC of a window whose class has CS_OWNDC (it is made on
        first use and keeps its state: Excel 95 gets it once and selects its
        fonts and clip regions into it for good), or 0"""
        hdc = self.own_dcs.get(hwnd)
        if hdc is not None and hdc in self.dc_state:
            return hdc
        if not self.gui or hwnd not in self.gui.windows:
            return 0
        info = self.registered_classes.get(self._window_class_name(hwnd))
        if not info or not info['style'] & self.CS_OWNDC:
            return 0
        hdc = self.own_dcs[hwnd] = self._create_dc(hwnd)
        return hdc

    def _forget_window(self, hwnd):
        """Paint state of a destroyed window"""
        self.painted_windows.discard(hwnd)
        self.update_rects.pop(hwnd, None)
        hdc = self.own_dcs.pop(hwnd, None)
        if hdc is not None:
            self._delete_dc(hdc)

    def GetDC(self, args):
        """GetDC emulation"""
        hWnd = args[0]
        log.debug(f"GetDC(0x{hWnd:x})")
        return self._own_dc(hWnd) or self._create_dc(hWnd)

    def ReleaseDC(self, args):
        """ReleaseDC emulation"""
        hWnd = args[0]
        hDC = args[1]
        log.debug(f"ReleaseDC(0x{hWnd:x}, 0x{hDC:x})")
        if self.own_dcs.get(self.dc_map.get(hDC)) == hDC:
            return 1  # A private DC is never released
        self._delete_dc(hDC)
        return 1

    # GDI32.DLL APIs
    def GetDeviceCaps(self, args):
        """GetDeviceCaps emulation"""
        hdc = args[0]
        index = args[1]
        width, height = self._screen_size()

        caps = {
            2: 1,       # TECHNOLOGY: DT_RASDISPLAY
            4: 320,     # HORZSIZE (mm)
            6: 240,     # VERTSIZE (mm)
            8: width,   # HORZRES
            10: height, # VERTRES
            12: 32,     # BITSPIXEL
            14: 1,      # PLANES
            24: -1,     # NUMCOLORS (more than 256 colors)
            36: 1,      # CLIPCAPS: CP_RECTANGLE
            40: 36,     # ASPECTX (square pixels, like a VGA display)
            42: 36,     # ASPECTY
            44: 51,     # ASPECTXY (hypotenuse)
            # RASTERCAPS: RC_BITBLT, RC_BITMAP64, RC_GDI20_OUTPUT, RC_DI_BITMAP,
            # RC_DIBTODEV, RC_BIGFONT, RC_STRETCHBLT, RC_FLOODFILL, RC_STRETCHDIB,
            # RC_OP_DX_OUTPUT (a true color display: no RC_PALETTE)
            38: 0x7E99,
            88: 96,     # LOGPIXELSX
            90: 96,     # LOGPIXELSY
            117: height, # DESKTOPVERTRES
            118: width,  # DESKTOPHORZRES
        }

        result = caps.get(index, 0)
        log.debug(f"GetDeviceCaps(0x{hdc:x}, {index}) -> {result}")
        return result & 0xFFFFFFFF

    def TextOutA(self, args):
        """TextOutA emulation - Draw text"""
        hdc = args[0]
        x = args[1]
        y = args[2]
        lpString = args[3]
        c = args[4]

        text = self.read_string(lpString) if lpString else ""
        if c > 0 and len(text) > c:
            text = text[:c]

        log.debug(f"TextOutA(0x{hdc:x}, {x}, {y}, \"{text}\")")

        if self.gui:
            self._add_text(hdc, text, *self._aligned_text_pos(hdc, text, x, y))

        return 1

    def TextOutW(self, args):
        """TextOutW emulation - Draw Unicode text"""
        hdc = args[0]
        x = args[1]
        y = args[2]
        lpString = args[3]
        c = args[4]

        text = self.read_wide_string(lpString) if lpString else ""
        if c > 0 and len(text) > c:
            text = text[:c]

        log.debug(f"TextOutW(0x{hdc:x}, {x}, {y}, \"{text}\")")

        if self.gui:
            self._add_text(hdc, text, *self._aligned_text_pos(hdc, text, x, y))

        return 1

    def _tabbed_text(self, hdc, text, n_tabs, lp_tabs, origin, x, y=None):
        """Lay out (and with y, draw) text with its tabs expanded: tab stops at
        the n_tabs pixel positions of lp_tabs from origin (right or centered
        stops, negative values, are taken as left ones), every lp_tabs[0]
        pixels for one value, else every 8 average character widths.
        Returns MAKELONG(width, height) like TabbedTextOut."""
        stops = []
        if n_tabs > 0 and lp_tabs:
            count = min(n_tabs, 1024)
            try:
                stops = [abs(v) for v in struct.unpack(
                    f'<{count}i', bytes(self.emu.uc.mem_read(lp_tabs, 4 * count)))]
            except UcError:
                stops = []
        interval = 0
        if len(stops) == 1:
            interval, stops = stops[0], []
        elif not stops:
            interval = 8 * max(1, self._text_extent(hdc, 'x')[0])
        height = self._text_extent(hdc, text.replace('\t', '') or ' ')[1]
        pos = x
        for index, piece in enumerate(text.split('\t')):
            if index:
                column = pos - origin
                stop = next((s for s in stops if s > column), None)
                if stop is None:
                    stop = ((column // interval + 1) * interval if interval > 0
                            else column + self._text_extent(hdc, ' ')[0])
                pos = origin + stop
            if piece:
                if y is not None and self.gui:
                    self._add_text(hdc, piece, pos, y)
                pos += self._text_extent(hdc, piece)[0]
        return ((height & 0xFFFF) << 16) | ((pos - x) & 0xFFFF)

    @staticmethod
    def _int32(value):
        value &= 0xFFFFFFFF
        return value - 0x100000000 if value & 0x80000000 else value

    def TabbedTextOutA(self, args, wide=False):
        """TabbedTextOutA/W(hdc, x, y, string, count, tab count, &tab stops,
        tab origin) - TextOut that expands the tabs"""
        hdc, x, y, lp_string, count = args[0], self._int32(args[1]), \
            self._int32(args[2]), args[3], self._int32(args[4])
        text = (self.read_wide_string(lp_string) if wide else
                self.read_string(lp_string)) if lp_string else ""
        if count >= 0:
            text = text[:count]
        log.debug(f"TabbedTextOut(0x{hdc:x}, {x}, {y}, \"{text}\")")
        return self._tabbed_text(hdc, text, self._int32(args[5]), args[6],
                                 self._int32(args[7]), x, y)

    def TabbedTextOutW(self, args):
        return self.TabbedTextOutA(args, wide=True)

    def GetTabbedTextExtentA(self, args, wide=False):
        """GetTabbedTextExtentA/W(hdc, string, count, tab count, &tab stops):
        MAKELONG(width, height) of the text with its tabs expanded"""
        hdc, lp_string, count = args[0], args[1], self._int32(args[2])
        text = (self.read_wide_string(lp_string) if wide else
                self.read_string(lp_string)) if lp_string else ""
        if count >= 0:
            text = text[:count]
        return self._tabbed_text(hdc, text, self._int32(args[3]), args[4], 0, 0)

    def GetTabbedTextExtentW(self, args):
        return self.GetTabbedTextExtentA(args, wide=True)

    ETO_OPAQUE = 0x2
    ETO_CLIPPED = 0x4
    ETO_PDY = 0x2000

    def ExtTextOutA(self, args, wide=False):
        """ExtTextOutA/W(hdc, x, y, options, lprect, lpString, c, lpDx) - TextOut
        that can first fill a rectangle with the background color (ETO_OPAQUE)
        and keep the text inside it (ETO_CLIPPED); lpDx places the characters
        (Word lays its lines out with the widths of its formatting device and
        draws each character where that layout put it)"""
        hdc, options, lprect, lpString, c = args[0], args[3], args[4], args[5], args[6]
        x, y = self._signed32(args[1]), self._signed32(args[2])
        text = self._read_text(lpString, wide)[:c] if lpString and c else ''
        log.debug(f"ExtTextOut{'W' if wide else 'A'}(0x{hdc:x}, {x}, {y}, \"{text}\")")
        rect = None
        if options & (self.ETO_OPAQUE | self.ETO_CLIPPED) and lprect:
            try:
                rect = struct.unpack('<iiii', self.emu.uc.mem_read(lprect, 16))
            except UcError:
                rect = None
        if options & self.ETO_OPAQUE and rect:
            state = self.dc_state.get(hdc)
            if state is not None:
                self._add_shape(hdc, {'type': 'rect', 'rect': rect,
                                      'fill': state.get('bk_color', (255, 255, 255)),
                                      'pen': None})
        if self.gui and text:
            clip = rect if options & self.ETO_CLIPPED else None
            dx = self._read_text_dx(args[7], len(text), options & self.ETO_PDY)
            self._add_text(hdc, text, *self._aligned_text_pos(hdc, text, x, y, dx), clip=clip,
                           dx=dx)
        return 1

    def _read_text_dx(self, address, count, pairs):
        """ExtTextOut's lpDx: the x advance of each of count characters (with
        ETO_PDY the array has an x, y pair each), or None"""
        if not address or not count:
            return None
        try:
            values = struct.unpack(f'<{count * (2 if pairs else 1)}i',
                                   self.emu.uc.mem_read(address, 4 * count * (2 if pairs else 1)))
        except UcError:
            return None
        return list(values[0::2] if pairs else values)

    def ExtTextOutW(self, args):
        return self.ExtTextOutA(args, wide=True)

    DT_CENTER, DT_RIGHT, DT_VCENTER, DT_BOTTOM = 0x1, 0x2, 0x4, 0x8
    DT_WORDBREAK, DT_SINGLELINE, DT_EXPANDTABS, DT_NOCLIP = 0x10, 0x20, 0x40, 0x100
    DT_CALCRECT, DT_NOPREFIX = 0x400, 0x800
    DT_HIDEPREFIX, DT_PREFIXONLY = 0x100000, 0x200000

    @staticmethod
    def _strip_prefixes(text):
        """(text, index of the underlined character or -1): an & marks the next
        character (a mnemonic), && is a literal &"""
        out = []
        underline = -1
        i = 0
        while i < len(text):
            ch = text[i]
            if ch == '&' and i + 1 < len(text):
                i += 1
                if text[i] != '&':
                    underline = len(out)
                out.append(text[i])
            elif ch != '&':
                out.append(ch)
            i += 1
        return ''.join(out), underline

    def _text_lines(self, hdc, text, width, flags):
        """[(start, end)] character ranges of the lines DrawText shows: the text
        breaks at newlines (unless DT_SINGLELINE) and, with DT_WORDBREAK,
        between words where a line gets wider than width"""
        if flags & self.DT_SINGLELINE:
            return [(0, len(text))]
        lines = []
        start = 0
        for paragraph in text.split('\n'):
            end = start + len(paragraph)
            if paragraph.endswith('\r'):
                end -= 1  # CR LF
            if not flags & self.DT_WORDBREAK:
                lines.append((start, end))
            else:
                line_start = start
                while True:
                    # The longest run of words from line_start that fits
                    pos, fit = line_start, None
                    while pos < end:
                        space = text.find(' ', pos, end)
                        word_end = end if space < 0 else space
                        if self._text_extent(hdc, text[line_start:word_end])[0] > width and \
                                fit is not None:
                            break
                        fit = word_end
                        pos = word_end + 1
                        if space < 0:
                            break
                    if fit is None or fit >= end:
                        lines.append((line_start, end))
                        break
                    lines.append((line_start, fit))
                    line_start = fit
                    while line_start < end and text[line_start] == ' ':
                        line_start += 1
                    if line_start >= end:
                        break
            start += len(paragraph) + 1
        return lines

    def _draw_text(self, hdc, text, lprc, flags):
        """DrawText A/W: the text in the rectangle (or its size with DT_CALCRECT);
        returns the height of the text"""
        rect = self._read_rect(lprc) if lprc else None
        if rect is None:
            return 0
        left, top, right, bottom = rect
        log.debug(f"DrawText(0x{hdc:x}, \"{text}\", rect=({left},{top},{right},{bottom}), "
                  f"flags=0x{flags:x})")
        underline = -1
        if not flags & self.DT_NOPREFIX:
            text, underline = self._strip_prefixes(text)
        if flags & self.DT_EXPANDTABS:
            text = text.replace('\t', ' ' * 8)
        if flags & self.DT_SINGLELINE:
            text = text.replace('\r', ' ').replace('\n', ' ')
        line_h = self._text_extent(hdc, 'Xg')[1]
        lines = self._text_lines(hdc, text, right - left, flags)
        widths = [self._text_extent(hdc, text[s:e])[0] for s, e in lines]
        height = line_h * len(lines)

        if flags & self.DT_CALCRECT:
            # The rectangle bounds the text: its widest line and its last line
            self._write_rect(lprc, left, top, left + max(widths, default=0), top + height)
            return height

        y = top
        if flags & self.DT_SINGLELINE:
            if flags & self.DT_VCENTER:
                y = top + (bottom - top - line_h) // 2
            elif flags & self.DT_BOTTOM:
                y = bottom - line_h
        state = self.dc_state.get(hdc, {})
        drawn = self.gui and (state.get('memory') or self._dc_hwnd(hdc) not in self.gui.consoles)
        for (start, end), width in zip(lines, widths, strict=True):
            if flags & self.DT_CENTER:
                x = left + (right - left - width) // 2
            elif flags & self.DT_RIGHT:
                x = right - width
            else:
                x = left
            if drawn and not flags & self.DT_PREFIXONLY:
                self._add_text(hdc, text[start:end], x, y)
            if drawn and start <= underline < end and not flags & self.DT_HIDEPREFIX:
                # The mnemonic's underline, below the baseline
                ux = x + self._text_extent(hdc, text[start:underline])[0]
                uw = self._text_extent(hdc, text[underline])[0]
                uy = y + self._text_ascent(line_h) + 1
                self._add_shape(hdc, {'type': 'line', 'from': (ux, uy),
                                      'to': (ux + max(uw, 1) - 1, uy),
                                      'pen': (state.get('text_color') or (0, 0, 0), 1)})
            y += line_h
        return (y - top) if flags & (self.DT_VCENTER | self.DT_BOTTOM) else height

    def DrawTextA(self, args):
        """DrawTextA emulation"""
        hdc, lpchText, cchText, lprc, flags = args[:5]
        text = self.read_string(lpchText) if lpchText else ""
        if 0 <= cchText < 0x80000000 and len(text) > cchText:
            text = text[:cchText]
        return self._draw_text(hdc, text, lprc, flags)

    def DrawTextW(self, args):
        """DrawTextW emulation"""
        hdc, lpchText, cchText, lprc, flags = args[:5]
        text = self.read_wide_string(lpchText) if lpchText else ""
        if 0 <= cchText < 0x80000000 and len(text) > cchText:
            text = text[:cchText]
        return self._draw_text(hdc, text, lprc, flags)

    def SetTextColor(self, args):
        """SetTextColor emulation"""
        hdc = args[0]
        color = args[1]
        log.debug(f"SetTextColor(0x{hdc:x}, 0x{color:06x})")
        state = self.dc_state.get(hdc)
        prev = 0
        if state:
            r, g, b = state['text_color']
            prev = r | (g << 8) | (b << 16)
            state['text_color'] = self._colorref_to_rgb(color)
        return prev  # Previous color

    def SetBkColor(self, args):
        """SetBkColor emulation"""
        hdc = args[0]
        color = args[1]
        log.debug(f"SetBkColor(0x{hdc:x}, 0x{color:06x})")
        state = self.dc_state.get(hdc)
        prev = 0xFFFFFF
        if state:
            r, g, b = state['bk_color']
            prev = r | (g << 8) | (b << 16)
            state['bk_color'] = self._colorref_to_rgb(color)
        return prev  # Previous color

    def SetBkMode(self, args):
        """SetBkMode emulation"""
        hdc = args[0]
        mode = args[1]  # TRANSPARENT=1, OPAQUE=2
        log.debug(f"SetBkMode(0x{hdc:x}, {mode})")
        state = self.dc_state.get(hdc)
        prev = 2
        if state:
            prev = state['bk_mode']
            state['bk_mode'] = mode
        return prev  # Previous mode

    CLR_INVALID = 0xFFFFFFFF
    GDI_ERROR = 0xFFFFFFFF

    def _dc_colorref(self, hdc, key):
        """A DC color as COLORREF, or CLR_INVALID for an unknown DC"""
        state = self.dc_state.get(hdc)
        if not state:
            return self.CLR_INVALID
        r, g, b = state[key]
        return r | (g << 8) | (b << 16)

    def GetTextColor(self, args):
        """GetTextColor emulation"""
        return self._dc_colorref(args[0], 'text_color')

    def GetBkColor(self, args):
        """GetBkColor emulation"""
        return self._dc_colorref(args[0], 'bk_color')

    # SetTextAlign flags
    TA_UPDATECP = 0x01
    TA_RIGHT = 0x02
    TA_CENTER = 0x06
    TA_BOTTOM = 0x08
    TA_BASELINE = 0x18

    def SetTextAlign(self, args):
        """SetTextAlign emulation - honoured by TextOut and ExtTextOut"""
        hdc, align = args[0], args[1]
        log.debug(f"SetTextAlign(0x{hdc:x}, 0x{align:x})")
        state = self.dc_state.get(hdc)
        if not state:
            return self.GDI_ERROR
        prev = state.get('text_align', 0)  # TA_LEFT | TA_TOP
        state['text_align'] = align
        return prev

    def _aligned_text_pos(self, hdc, text, x, y, dx=None):
        """Top-left position of TextOut text for the DC's text alignment (dx:
        the advances of its characters, if given). With TA_UPDATECP the text
        goes at the current position (MoveToEx), not at x, y, and moves it
        past the text (PowerPoint 95 draws its outline view this way)."""
        state = self.dc_state.get(hdc, {})
        align = state.get('text_align', 0)
        if not align:  # TA_LEFT | TA_TOP | TA_NOUPDATECP
            return x, y
        width, height = self._text_extent(hdc, text)
        if dx:
            width = sum(dx)
        if align & self.TA_UPDATECP and 'pos' in state:
            x, y = state['pos']
            if align & self.TA_CENTER != self.TA_CENTER:
                state['pos'] = (x - width if align & self.TA_RIGHT else x + width, y)
        if align & self.TA_CENTER == self.TA_CENTER:
            x -= width // 2
        elif align & self.TA_RIGHT:
            x -= width
        if align & self.TA_BASELINE == self.TA_BASELINE:
            y -= self._text_ascent(height)
        elif align & self.TA_BOTTOM:
            y -= height
        return x, y

    @staticmethod
    def _text_ascent(height):
        return (height * 4 + 2) // 5

    def GetTextMetricsA(self, args):
        """GetTextMetricsA emulation - metrics of the estimated GUI font"""
        hdc, lptm = args[0], args[1]
        if hdc not in self.dc_state or not lptm:
            return 0
        font = self._dc_font(hdc) or {}
        ave_width, height = self._text_extent(hdc, 'x')
        ascent, leading = self._text_ascent(height), 0
        if self.gui and self.gui.font is not None and font:
            # The drawn font's own metrics: the cell is taller than the
            # character (em) height by the internal leading. Word picks the
            # screen font from tmHeight - tmInternalLeading of the font on
            # its formatting DC, so a leading of 0 made its text too big.
            with self.gui.lock:
                render_font = self.gui._get_render_font(font)
                em = getattr(render_font, 'point_size', None)
                if render_font.get_height() == height:
                    ascent = min(height, render_font.get_ascent())
                if em and 0 < em <= height:
                    leading = height - em
        data = struct.pack('<11i9B',
                           height, ascent, height - ascent,
                           leading,                 # tmInternalLeading
                           0,                       # tmExternalLeading
                           ave_width, ave_width * 2,
                           700 if font.get('bold') else 400,
                           0, 96, 96,               # overhang, digitized aspect
                           0x20, 0xFF, 0x1F, 0x20,  # first/last/default/break char
                           1 if font.get('italic') else 0,
                           1 if font.get('underline') else 0,
                           0,                       # tmStruckOut
                           self._tm_pitch_and_family(font),
                           0)                       # ANSI_CHARSET
        return 1 if self._mem_write(lptm, data + b'\x00' * 3) else 0

    # Faces drawn with fixed-pitch (monospaced) fonts
    FIXED_PITCH_FACES = ('courier', 'courier new', 'fixedsys', 'terminal', 'lucida console',
                         'consolas', 'system fixed')

    def _tm_pitch_and_family(self, font):
        """TEXTMETRIC's tmPitchAndFamily of a font dict: the family, and
        TMPF_FIXED_PITCH (0x01), which is set for a *variable*-pitch font
        (without it Word laid every character out as wide as an "x"),
        TMPF_VECTOR | TMPF_TRUETYPE (0x06) for a TrueType face"""
        face = (font.get('face') or '').lower()
        known = {f.name.lower(): f for f in self.FONT_FAMILIES + self.added_font_faces()}
        info = known.get(face)
        family = info.pitch_family & 0xF0 if info else 0x20  # FF_SWISS
        if face in self.FIXED_PITCH_FACES:
            family = 0x30  # FF_MODERN
            pitch = 0
        else:
            pitch = 1
        if info is not None and info.font_type == TRUETYPE_FONTTYPE:
            pitch |= 0x06
        return family | pitch

    def SetROP2(self, args):
        """SetROP2 emulation - the mix mode is stored, drawing always copies the pen"""
        hdc, rop2 = args[0], args[1]
        state = self.dc_state.get(hdc)
        if not state or not 1 <= rop2 <= 16:
            return 0
        prev = state.get('rop2', 13)  # R2_COPYPEN
        state['rop2'] = rop2
        return prev
