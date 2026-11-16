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

"""WinAPIHandler mixin: Scrollbar APIs (user32)"""

import struct

from unicorn import *

from ..logger import log


class ScrollbarsMixin:
    """Scrollbar APIs (user32)"""

    # ---------- Scrollbar APIs (user32) ----------

    def _scrollbar_control(self, hwnd, nBar):
        """Resolve a scrollbar target to its FakeControl (SB_CTL only).

        Standard window scrollbars (SB_HORZ/SB_VERT on a window handle) are
        not emulated; only SCROLLBAR controls carry scroll state.
        """
        if self.gui and hwnd in self.gui.controls:
            control = self.gui.controls[hwnd]
            if control.class_name == "SCROLLBAR":
                return control
        if nBar != self.SB_CTL:
            log.debug(f"Standard window scrollbar (nBar={nBar}) not emulated")
        return None

    @staticmethod
    def scroll_pos_max(control):
        """Highest legal scroll position (Windows: max - page + 1 if page set)"""
        if control.scroll_page > 0:
            return max(control.scroll_min,
                       control.scroll_max - control.scroll_page + 1)
        return control.scroll_max

    def _clamp_scroll_pos(self, control, pos):
        return max(control.scroll_min, min(pos, self.scroll_pos_max(control)))

    def SetScrollPos(self, args):
        """SetScrollPos emulation"""
        hWnd, nBar = args[0], args[1]
        nPos = args[2] - 0x100000000 if args[2] >= 0x80000000 else args[2]
        control = self._scrollbar_control(hWnd, nBar)
        if not control:
            return 0
        prev = control.scroll_pos
        control.scroll_pos = self._clamp_scroll_pos(control, nPos)
        log.debug(f"SetScrollPos(0x{hWnd:x}, {nPos}) -> prev {prev}")
        return prev & 0xFFFFFFFF

    def GetScrollPos(self, args):
        """GetScrollPos emulation"""
        control = self._scrollbar_control(args[0], args[1])
        return (control.scroll_pos & 0xFFFFFFFF) if control else 0

    def SetScrollRange(self, args):
        """SetScrollRange emulation"""
        hWnd, nBar = args[0], args[1]
        nMin, nMax = self._read_signed_args(args, 2, 2)
        control = self._scrollbar_control(hWnd, nBar)
        if not control:
            return 0
        control.scroll_min = min(nMin, nMax)
        control.scroll_max = max(nMin, nMax)
        control.scroll_pos = self._clamp_scroll_pos(control, control.scroll_pos)
        log.debug(f"SetScrollRange(0x{hWnd:x}, {nMin}..{nMax})")
        return 1

    def GetScrollRange(self, args):
        """GetScrollRange emulation"""
        control = self._scrollbar_control(args[0], args[1])
        lpMin, lpMax = args[2], args[3]
        if not control:
            return 0
        try:
            if lpMin:
                self.emu.uc.mem_write(lpMin, struct.pack("<i", control.scroll_min))
            if lpMax:
                self.emu.uc.mem_write(lpMax, struct.pack("<i", control.scroll_max))
        except UcError:
            return 0
        return 1

    # SCROLLINFO fMask flags
    SIF_RANGE = 0x0001
    SIF_PAGE = 0x0002
    SIF_POS = 0x0004
    SIF_TRACKPOS = 0x0010

    def SetScrollInfo(self, args):
        """SetScrollInfo emulation"""
        hWnd, nBar, lpsi = args[0], args[1], args[2]
        control = self._scrollbar_control(hWnd, nBar)
        if not control or not lpsi:
            return 0
        try:
            # SCROLLINFO: cbSize, fMask, nMin, nMax, nPage, nPos, nTrackPos
            data = self.emu.uc.mem_read(lpsi, 28)
            _, fMask, nMin, nMax, nPage, nPos, _ = struct.unpack("<IIiiIii", data)
        except UcError:
            return 0
        if fMask & self.SIF_RANGE:
            control.scroll_min = min(nMin, nMax)
            control.scroll_max = max(nMin, nMax)
        if fMask & self.SIF_PAGE:
            control.scroll_page = nPage
        if fMask & self.SIF_POS:
            control.scroll_pos = nPos
        control.scroll_pos = self._clamp_scroll_pos(control, control.scroll_pos)
        log.debug(f"SetScrollInfo(0x{hWnd:x}, mask=0x{fMask:x}) -> pos {control.scroll_pos}")
        return control.scroll_pos & 0xFFFFFFFF

    def GetScrollInfo(self, args):
        """GetScrollInfo emulation"""
        hWnd, nBar, lpsi = args[0], args[1], args[2]
        control = self._scrollbar_control(hWnd, nBar)
        if not control or not lpsi:
            return 0
        try:
            # Preserve the caller's cbSize and fMask, fill everything else
            head = self.emu.uc.mem_read(lpsi, 8)
            data = head + struct.pack("<iiIii", control.scroll_min,
                                      control.scroll_max, control.scroll_page,
                                      control.scroll_pos, control.scroll_pos)
            self.emu.uc.mem_write(lpsi, bytes(data))
        except UcError:
            return 0
        return 1
