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

"""WinAPIHandler mixin: Status bar (comctl32), AdjustWindowRect, character case and classes"""

import struct

from unicorn import UcError

from .. import config, gui
from ..logger import log


class StatusBarMixin:
    """Status bar (comctl32), AdjustWindowRect, character case and classes"""

    # ---------- Status bar (comctl32) ----------

    SB_SETTEXTA, SB_GETTEXTA, SB_GETTEXTLENGTHA, SB_SETPARTS = 0x401, 0x402, 0x403, 0x404
    SB_GETPARTS, SB_SETMINHEIGHT, SB_SIMPLE, SB_GETRECT = 0x406, 0x408, 0x409, 0x40A

    def _create_status_bar(self, parent, text, style, control_id):
        hwnd = self.gui.create_control(parent, 'STATUSBAR', text, 0, 0, 0,
                                       gui.PseudoWindowsGUI.STATUSBAR_H, style,
                                       control_id=control_id)
        control = self.gui.controls[hwnd]
        control.visible = bool(style & self.WS_VISIBLE)
        self.gui.layout_statusbar(control)
        return hwnd

    def CreateStatusWindowA(self, args):
        """CreateStatusWindowA emulation (comctl32 ordinal 6) - status bar at the
        bottom of the parent's client area"""
        style, lpszText, hwndParent, wID = args[0], args[1], args[2], args[3]
        text = self.read_string(lpszText) if lpszText else ''
        log.debug(f"CreateStatusWindowA(0x{hwndParent:x}, \"{text}\")")
        if not self.gui or hwndParent not in self.gui.windows:
            return self.get_next_handle() if not self.gui else 0
        return self._create_status_bar(hwndParent, text, style, wID & 0xFFFF)

    def _status_bar_message(self, control, Msg, wParam, lParam, wide):
        """Status bar messages (SB_*); None if Msg is not one of them"""
        wide_msgs = {0x40B: self.SB_SETTEXTA, 0x40D: self.SB_GETTEXTA,
                     0x40C: self.SB_GETTEXTLENGTHA}  # SB_SETTEXTW, SB_GETTEXTW, ...
        if Msg in wide_msgs:
            Msg, wide = wide_msgs[Msg], True
        if Msg == self.WM_SIZE:
            self.gui.layout_statusbar(control)
            return 0
        if Msg == self.SB_SETTEXTA:
            part = wParam & 0xFF
            text = self._read_text(lParam, wide) if lParam else ''
            if part == 0:
                control.text = text
            else:
                texts = dict(control.part_texts)  # The GUI thread may be drawing the old one
                texts[part] = text
                control.part_texts = texts
            return 1
        if Msg in (self.SB_GETTEXTA, self.SB_GETTEXTLENGTHA):
            part = wParam & 0xFF
            text = control.text if part == 0 else control.part_texts.get(part, '')
            if Msg == self.SB_GETTEXTA and lParam:
                self._write_units(lParam, self._text_units(text, wide), wide)
            return len(text)
        if Msg == self.SB_SETPARTS:
            count = min(wParam, 256)
            try:
                edges = list(struct.unpack(f'<{count}i', self.emu.uc.mem_read(lParam, 4 * count)))
            except UcError:
                return 0
            control.parts = edges or [-1]
            return 1
        if Msg == self.SB_GETPARTS:
            if lParam and wParam:
                edges = control.parts[:wParam]
                self._mem_write(lParam, struct.pack(f'<{len(edges)}i', *edges))
            return len(control.parts)
        if Msg == self.SB_SIMPLE:
            control.simple = bool(wParam)
            return 0
        if Msg == self.SB_SETMINHEIGHT:
            return 0
        if Msg == self.SB_GETRECT:
            if wParam >= len(control.parts) or not lParam:
                return 0
            left = 0 if wParam == 0 else control.parts[wParam - 1]
            right = control.parts[wParam]
            right = control.width if right < 0 else right
            self._write_rect(lParam, left, 2, right, control.height - 2)
            return 1
        return None

    def AdjustWindowRect(self, args):
        """AdjustWindowRect emulation - client rect -> window rect.

        Uses the fake desktop's frame for the style (overlapped and WS_CAPTION
        windows have a border and a title bar), so it matches GetClientRect for
        the created window.
        """
        lpRect, dwStyle, bMenu = args[0], args[1], args[2]
        rect = self._read_rect(lpRect) if lpRect else None
        if rect is None:
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0
        left, top, right, bottom = rect
        if dwStyle & self.WS_CHILD:
            border, caption = gui.PseudoWindowsGUI.child_frame_size(dwStyle)
        else:
            border, caption = gui.PseudoWindowsGUI.frame_size(dwStyle)
        caption += gui.PseudoWindowsGUI.MENU_H if bMenu else 0
        return 1 if self._write_rect(lpRect, left - border, top - border - caption,
                                     right + border, bottom + border) else 0

    def AdjustWindowRectEx(self, args):
        """AdjustWindowRectEx emulation (the extended style has no extra frame here)"""
        return self.AdjustWindowRect(args[:3])

    def _ansi_char(self, value):
        """Decode one ANSI code unit; None if it is not a character on its own"""
        try:
            return bytes([value & 0xFF]).decode(config.ANSI_CODEPAGE)
        except UnicodeDecodeError:
            return None

    @staticmethod
    def _ansi_case(ch, convert):
        """ch in the other case, or unchanged if that case is not one character
        of the ANSI code page (cp1252 "ƒ" -> "Ƒ", "µ" -> "Μ", "ß" -> "SS")"""
        converted = convert(ch)
        if converted == ch or len(converted) != 1:
            return ch
        try:
            if len(converted.encode(config.ANSI_CODEPAGE)) == len(ch.encode(config.ANSI_CODEPAGE)):
                return converted
        except UnicodeEncodeError:
            pass
        return ch

    def _char_case_common(self, lpsz, upper, wide=False):
        """CharUpper/CharLower A/W: a single char (HIWORD 0) or an in-place string"""
        convert = str.upper if upper else str.lower
        if lpsz < 0x10000:
            if wide:
                converted = convert(chr(lpsz))
                return ord(converted) if len(converted) == 1 and ord(converted) < 0x10000 else lpsz
            ch = self._ansi_char(lpsz)
            if ch is None:
                return lpsz
            converted = self._ansi_case(ch, convert).encode(config.ANSI_CODEPAGE)
            return converted[0] if len(converted) == 1 else lpsz
        if wide:
            units = self._read_units(lpsz, True)
            text = self._units_text(units, True)
            data = self._text_units(convert(text), True)
            if len(data) == len(units):
                self._write_units(lpsz, data, True, terminate=False)
            return lpsz
        raw = self.read_cstring(lpsz)
        text = raw.decode(config.ANSI_CODEPAGE, errors='surrogateescape')
        data = ''.join(self._ansi_case(ch, convert) for ch in text).encode(
            config.ANSI_CODEPAGE, errors='surrogateescape')
        if len(data) == len(raw):  # never change the buffer length in place
            self.emu.uc.mem_write(lpsz, data)
        return lpsz

    def CharUpperA(self, args):
        """CharUpperA emulation"""
        return self._char_case_common(args[0], True)

    def CharLowerA(self, args):
        """CharLowerA emulation"""
        return self._char_case_common(args[0], False)

    def CharUpperW(self, args):
        """CharUpperW emulation"""
        return self._char_case_common(args[0], True, wide=True)

    def CharLowerW(self, args):
        """CharLowerW emulation"""
        return self._char_case_common(args[0], False, wide=True)

    def _ansi_char_length(self, address):
        """Bytes of the ANSI character at address (0 at the terminator).

        Only UTF-8 has multi-byte characters among the supported code pages.
        """
        try:
            data = bytes(self.emu.uc.mem_read(address, 1))
        except UcError:
            return 0
        if data == b'\x00':
            return 0
        if config.ANSI_CODEPAGE.replace('_', '-') != 'utf-8':
            return 1
        lead = data[0]
        size = 2 if 0xC2 <= lead <= 0xDF else 3 if 0xE0 <= lead <= 0xEF else \
            4 if 0xF0 <= lead <= 0xF4 else 1
        if size > 1:
            try:
                data = bytes(self.emu.uc.mem_read(address, size))
                data.decode('utf-8')
            except (UcError, UnicodeDecodeError):
                return 1
        return size

    def CharNextA(self, args):
        """CharNextA emulation - stays on the terminator"""
        lpsz = args[0]
        return lpsz + self._ansi_char_length(lpsz) if lpsz else 0

    def CharPrevA(self, args):
        """CharPrevA emulation - never moves before lpszStart"""
        start, current = args[0], args[1]
        if current <= start:
            return start
        # Step back over UTF-8 continuation bytes to the character that ends at current
        for back in range(min(4, current - start), 1, -1):
            if self._ansi_char_length(current - back) == back:
                return current - back
        return current - 1

    def CharPrevExA(self, args):
        """CharPrevExA emulation (the ANSI code page)"""
        return self.CharPrevA([args[1], args[2]])

    def CharNextExA(self, args):
        """CharNextExA emulation (the ANSI code page)"""
        return self.CharNextA([args[1]])

    def IsCharUpperA(self, args):
        """IsCharUpperA emulation"""
        ch = self._ansi_char(args[0])
        return 1 if ch and ch.isupper() else 0

    def IsCharLowerA(self, args):
        """IsCharLowerA emulation"""
        ch = self._ansi_char(args[0])
        return 1 if ch and ch.islower() else 0

    def IsCharAlphaA(self, args):
        """IsCharAlphaA emulation"""
        ch = self._ansi_char(args[0])
        return 1 if ch and ch.isalpha() else 0

    def IsCharAlphaNumericA(self, args):
        """IsCharAlphaNumericA emulation"""
        ch = self._ansi_char(args[0])
        return 1 if ch and ch.isalnum() else 0
