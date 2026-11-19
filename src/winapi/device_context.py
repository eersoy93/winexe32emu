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

    def _dc_brush(self, hdc):
        """Current brush color of a DC, or None for NULL_BRUSH"""
        state = self.dc_state.get(hdc)
        if state and state['brush']:
            brush = self.gdi_objects.get(state['brush'])
            if brush and brush['type'] == 'brush':
                return brush['color']  # None for NULL_BRUSH
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

    def _add_shape(self, hdc, shape):
        """Append a GDI shape to the display list of the DC's window.

        Memory DCs collect shapes in their own list until BitBlt copies them.
        An opaque rect covering the whole bitmap restarts the list, so a
        game loop that fills the background every frame doesn't grow it.
        """
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

    def _add_text(self, hdc, text, x, y):
        """Append a text item to the DC's display list (window or memory DC)"""
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
        self._add_shape(hdc, shape)

    def BeginPaint(self, args):
        """BeginPaint emulation"""
        hWnd = args[0]
        lpPaint = args[1]

        log.debug(f"BeginPaint(0x{hWnd:x})")

        hdc = self._create_dc(hWnd)

        # Painting starts fresh: clear the window's retained display lists
        if self.gui:
            self.gui.clear_drawings(hWnd)

        # Fill PAINTSTRUCT structure
        if lpPaint:
            # Client area size
            right, bottom = 400, 300
            if self.gui and hWnd in self.gui.windows:
                win = self.gui.windows[hWnd]
                right, bottom = self.gui.client_size(win)
            # hdc, fErase, rcPaint(4 int), fRestore, fIncUpdate, rgbReserved[32]
            paint_data = struct.pack("<II", hdc, 0)  # First 8 bytes
            paint_data += struct.pack("<iiii", 0, 0, right, bottom)  # rcPaint
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
                self._delete_dc(hdc)
            except UcError:
                pass
        return 1

    def InvalidateRect(self, args):
        """InvalidateRect emulation - request a repaint via WM_PAINT"""
        hWnd = args[0]
        lpRect = args[1]
        bErase = args[2]
        log.debug(f"InvalidateRect(0x{hWnd:x})")
        # GetMessageA re-synthesizes WM_PAINT for windows not in painted_windows
        self.painted_windows.discard(hWnd)
        if self.gui and hWnd in self.gui.controls:
            self.dirty_controls[hWnd] = True
        return 1

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
        color = self._brush_color(hbr)

        if color is not None:
            self._add_shape(hdc, {'type': 'rect', 'rect': (left, top, right, bottom),
                                  'fill': color, 'pen': None})
        return 1

    def GetDC(self, args):
        """GetDC emulation"""
        hWnd = args[0]
        log.debug(f"GetDC(0x{hWnd:x})")
        return self._create_dc(hWnd)

    def ReleaseDC(self, args):
        """ReleaseDC emulation"""
        hWnd = args[0]
        hDC = args[1]
        log.debug(f"ReleaseDC(0x{hWnd:x}, 0x{hDC:x})")
        self._delete_dc(hDC)
        return 1

    # GDI32.DLL APIs
    def GetDeviceCaps(self, args):
        """GetDeviceCaps emulation"""
        hdc = args[0]
        index = args[1]
        width, height = self._screen_size()

        caps = {
            4: 320,     # HORZSIZE (mm)
            6: 240,     # VERTSIZE (mm)
            8: width,   # HORZRES
            10: height, # VERTRES
            12: 32,     # BITSPIXEL
            14: 1,      # PLANES
            24: -1,     # NUMCOLORS (more than 256 colors)
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

    def DrawTextA(self, args):
        """DrawTextA emulation"""
        hdc = args[0]
        lpchText = args[1]
        cchText = args[2]
        lprc = args[3]
        format_flags = args[4]

        text = self.read_string(lpchText) if lpchText else ""
        if cchText > 0 and len(text) > cchText:
            text = text[:cchText]

        # Read RECT structure
        x, y, width, height = 0, 0, 400, 300
        if lprc:
            try:
                rect_data = self.emu.uc.mem_read(lprc, 16)
                left, top, right, bottom = struct.unpack("<iiii", rect_data)
                x, y = left, top
                width, height = right - left, bottom - top
            except UcError:
                pass

        log.debug(f"DrawTextA(0x{hdc:x}, \"{text}\", rect=({x},{y},{width},{height}))")

        # DT_CENTER (0x01) ve DT_VCENTER (0x04) flag'leri
        DT_CENTER = 0x01
        DT_VCENTER = 0x04

        draw_x = x
        draw_y = y
        text_w, text_h = self._text_extent(hdc, text)

        if format_flags & DT_CENTER:
            draw_x = x + (width - text_w) // 2
        elif format_flags & 0x02:  # DT_RIGHT
            draw_x = x + width - text_w
        if format_flags & DT_VCENTER:
            draw_y = y + (height - text_h) // 2
        elif format_flags & 0x08:  # DT_BOTTOM
            draw_y = y + height - text_h

        if self.gui:
            state = self.dc_state.get(hdc, {})
            if state.get('memory') or self._dc_hwnd(hdc) not in self.gui.consoles:
                self._add_text(hdc, text, draw_x, draw_y)

        return height  # Text height

    def DrawTextW(self, args):
        """DrawTextW emulation"""
        hdc = args[0]
        lpchText = args[1]
        cchText = args[2]
        lprc = args[3]
        format_flags = args[4]

        text = self.read_wide_string(lpchText) if lpchText else ""
        if cchText > 0 and len(text) > cchText:
            text = text[:cchText]

        x, y = 0, 0
        if lprc:
            try:
                rect_data = self.emu.uc.mem_read(lprc, 16)
                left, top, right, bottom = struct.unpack("<iiii", rect_data)
                x, y = left, top
            except UcError:
                pass

        log.debug(f"DrawTextW(0x{hdc:x}, \"{text}\")")

        if self.gui:
            self._add_text(hdc, text, x, y)

        return 20  # Text height

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
        """SetTextAlign emulation - honoured by TextOut (TA_UPDATECP is ignored)"""
        hdc, align = args[0], args[1]
        log.debug(f"SetTextAlign(0x{hdc:x}, 0x{align:x})")
        state = self.dc_state.get(hdc)
        if not state:
            return self.GDI_ERROR
        prev = state.get('text_align', 0)  # TA_LEFT | TA_TOP
        state['text_align'] = align
        return prev

    def _aligned_text_pos(self, hdc, text, x, y):
        """Top-left position of TextOut text for the DC's text alignment"""
        align = self.dc_state.get(hdc, {}).get('text_align', 0)
        if not align & ~self.TA_UPDATECP:
            return x, y
        width, height = self._text_extent(hdc, text)
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
        ascent = self._text_ascent(height)
        data = struct.pack('<11i9B',
                           height, ascent, height - ascent,
                           0,                       # tmInternalLeading
                           0,                       # tmExternalLeading
                           ave_width, ave_width * 2,
                           700 if font.get('bold') else 400,
                           0, 96, 96,               # overhang, digitized aspect
                           0x20, 0xFF, 0x1F, 0x20,  # first/last/default/break char
                           1 if font.get('italic') else 0,
                           1 if font.get('underline') else 0,
                           0,                       # tmStruckOut
                           0x22,                    # VARIABLE_PITCH | FF_SWISS
                           0)                       # ANSI_CHARSET
        return 1 if self._mem_write(lptm, data + b'\x00' * 3) else 0

    def SetROP2(self, args):
        """SetROP2 emulation - the mix mode is stored, drawing always copies the pen"""
        hdc, rop2 = args[0], args[1]
        state = self.dc_state.get(hdc)
        if not state or not 1 <= rop2 <= 16:
            return 0
        prev = state.get('rop2', 13)  # R2_COPYPEN
        state['rop2'] = rop2
        return prev
