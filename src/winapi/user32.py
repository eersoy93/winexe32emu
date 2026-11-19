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

"""WinAPIHandler mixin: USER32: RECT utilities, window positions, dialog items, window
longs, system colors"""

import struct

from unicorn import UcError

from .. import config
from ..logger import log
from ..sound import SoundPlayer


class User32Mixin:
    """USER32: RECT utilities, window positions, dialog items, window longs, system colors"""

    # ---------- RECT utility APIs (user32) ----------

    def _read_rect(self, address):
        """Read a RECT from memory -> (left, top, right, bottom) or None"""
        try:
            return struct.unpack("<iiii", self.emu.uc.mem_read(address, 16))
        except UcError:
            return None

    def _write_rect(self, address, left, top, right, bottom):
        """Write a RECT to memory"""
        try:
            self.emu.uc.mem_write(address, struct.pack("<iiii", left, top,
                                                       right, bottom))
            return True
        except UcError:
            return False

    def SetRect(self, args):
        """SetRect emulation"""
        lprc = args[0]
        left, top, right, bottom = self._read_signed_args(args, 1, 4)
        if not lprc:
            return 0
        return 1 if self._write_rect(lprc, left, top, right, bottom) else 0

    def SetRectEmpty(self, args):
        """SetRectEmpty emulation"""
        lprc = args[0]
        if not lprc:
            return 0
        return 1 if self._write_rect(lprc, 0, 0, 0, 0) else 0

    def CopyRect(self, args):
        """CopyRect emulation"""
        lprcDst, lprcSrc = args[0], args[1]
        rect = self._read_rect(lprcSrc) if lprcSrc else None
        if not lprcDst or rect is None:
            return 0
        return 1 if self._write_rect(lprcDst, *rect) else 0

    def OffsetRect(self, args):
        """OffsetRect emulation"""
        lprc = args[0]
        dx, dy = self._read_signed_args(args, 1, 2)
        rect = self._read_rect(lprc) if lprc else None
        if rect is None:
            return 0
        left, top, right, bottom = rect
        return 1 if self._write_rect(lprc, left + dx, top + dy,
                                     right + dx, bottom + dy) else 0

    def InflateRect(self, args):
        """InflateRect emulation"""
        lprc = args[0]
        dx, dy = self._read_signed_args(args, 1, 2)
        rect = self._read_rect(lprc) if lprc else None
        if rect is None:
            return 0
        left, top, right, bottom = rect
        return 1 if self._write_rect(lprc, left - dx, top - dy,
                                     right + dx, bottom + dy) else 0

    def PtInRect(self, args):
        """PtInRect emulation (POINT is passed by value: two stack dwords)"""
        lprc = args[0]
        x, y = self._read_signed_args(args, 1, 2)
        rect = self._read_rect(lprc) if lprc else None
        if rect is None:
            return 0
        left, top, right, bottom = rect
        return 1 if (left <= x < right and top <= y < bottom) else 0

    def EqualRect(self, args):
        """EqualRect emulation"""
        r1 = self._read_rect(args[0]) if args[0] else None
        r2 = self._read_rect(args[1]) if args[1] else None
        if r1 is None or r2 is None:
            return 0
        return 1 if r1 == r2 else 0

    def IsRectEmpty(self, args):
        """IsRectEmpty emulation"""
        rect = self._read_rect(args[0]) if args[0] else None
        if rect is None:
            return 1
        left, top, right, bottom = rect
        return 1 if (right <= left or bottom <= top) else 0

    def IntersectRect(self, args):
        """IntersectRect emulation"""
        lprcDst = args[0]
        r1 = self._read_rect(args[1]) if args[1] else None
        r2 = self._read_rect(args[2]) if args[2] else None
        if not lprcDst or r1 is None or r2 is None:
            return 0
        left, top = max(r1[0], r2[0]), max(r1[1], r2[1])
        right, bottom = min(r1[2], r2[2]), min(r1[3], r2[3])
        if right <= left or bottom <= top:
            self._write_rect(lprcDst, 0, 0, 0, 0)
            return 0
        self._write_rect(lprcDst, left, top, right, bottom)
        return 1

    def UnionRect(self, args):
        """UnionRect emulation"""
        lprcDst = args[0]
        r1 = self._read_rect(args[1]) if args[1] else None
        r2 = self._read_rect(args[2]) if args[2] else None
        if not lprcDst or r1 is None or r2 is None:
            return 0
        empty1 = r1[2] <= r1[0] or r1[3] <= r1[1]
        empty2 = r2[2] <= r2[0] or r2[3] <= r2[1]
        if empty1 and empty2:
            self._write_rect(lprcDst, 0, 0, 0, 0)
            return 0
        if empty1:
            self._write_rect(lprcDst, *r2)
        elif empty2:
            self._write_rect(lprcDst, *r1)
        else:
            self._write_rect(lprcDst, min(r1[0], r2[0]), min(r1[1], r2[1]),
                             max(r1[2], r2[2]), max(r1[3], r2[3]))
        return 1

    def MoveWindow(self, args):
        """MoveWindow emulation"""
        hWnd = args[0]
        X = args[1]
        Y = args[2]
        nWidth = args[3]
        nHeight = args[4]
        bRepaint = args[5]

        log.debug(f"MoveWindow(0x{hWnd:x}, {X}, {Y}, {nWidth}, {nHeight})")

        if self.gui and hWnd in self.gui.windows:
            win = self.gui.windows[hWnd]
            X, Y, nWidth, nHeight = self._read_signed_args(args, 1, 4)
            win.x, win.y = X, Y
            win.width, win.height = max(nWidth, 0), max(nHeight, 0)
            self._native_moved(win)
            self._send_size(hWnd)
        elif self.gui and hWnd in self.gui.controls:
            control = self.gui.controls[hWnd]
            (control.x, control.y, control.width,
             control.height) = self._read_signed_args(args, 1, 4)

        return 1

    def _native_moved(self, win):
        """Emulated controls that size themselves: a rebar's height follows its
        bands, a combobox shows only its edit box"""
        if win.native == 'REBAR':
            self._rebar_resize(win, notify=False)
        elif win.native == 'COMBOBOXEX':
            win.nstate['drop_height'] = max(win.height, 100)
            win.height = self.COMBOBOX_BOX_H
            self._comboboxex_layout(win)
        elif win.native == 'TOOLBAR' and not win.style & 0x4 and win.parent:  # CCS_NORESIZE
            self._tb_autosize(win)
        elif win.native == 'LISTVIEW':
            win.nstate['dirty'] = True

    def SetWindowPos(self, args):
        """SetWindowPos emulation"""
        hWnd = args[0]
        hWndInsertAfter = args[1]
        X = args[2]
        Y = args[3]
        cx = args[4]
        cy = args[5]
        uFlags = args[6]

        log.debug(f"SetWindowPos(0x{hWnd:x}, {X}, {Y}, {cx}, {cy})")

        if self.gui and hWnd in self.gui.windows:
            win = self.gui.windows[hWnd]
            X, Y, cx, cy = self._read_signed_args(args, 2, 4)
            with self.gui.lock:
                if not (uFlags & 0x0002):  # SWP_NOMOVE
                    win.x, win.y = X, Y
                if not (uFlags & 0x0001):  # SWP_NOSIZE
                    win.width, win.height = cx, cy
                if (not uFlags & 0x0004 and win.parent is None  # SWP_NOZORDER
                        and hWnd in self.gui.z_order):
                    after = (hWndInsertAfter if hWndInsertAfter < 0x80000000 else
                             hWndInsertAfter - 0x100000000)
                    if after in (0, -1):  # HWND_TOP, HWND_TOPMOST
                        self.gui.z_order.remove(hWnd)
                        self.gui.z_order.append(hWnd)
                    elif after == 1:  # HWND_BOTTOM
                        self.gui.z_order.remove(hWnd)
                        self.gui.z_order.insert(0, hWnd)
                if uFlags & 0x0040:  # SWP_SHOWWINDOW
                    self.gui.show_window(hWnd, True)
                elif uFlags & 0x0080:  # SWP_HIDEWINDOW
                    self.gui.show_window(hWnd, False)
                if (not uFlags & 0x0010 and win.parent is None  # SWP_NOACTIVATE
                        and win.visible and not win.minimized):
                    self.gui.active_window = hWnd
            self._native_moved(win)
            self._send_size(hWnd)
        elif self.gui and hWnd in self.gui.controls:
            control = self.gui.controls[hWnd]
            X, Y, cx, cy = self._read_signed_args(args, 2, 4)
            if not (uFlags & 0x0002):  # SWP_NOMOVE
                control.x, control.y = X, Y
            if not (uFlags & 0x0001):  # SWP_NOSIZE
                control.width, control.height = cx, cy
            if uFlags & 0x0040:  # SWP_SHOWWINDOW
                control.visible = True
            elif uFlags & 0x0080:  # SWP_HIDEWINDOW
                control.visible = False

        return 1

    def EnableWindow(self, args):
        """EnableWindow emulation"""
        hWnd = args[0]
        bEnable = args[1]
        log.debug(f"EnableWindow(0x{hWnd:x}, {bEnable})")

        if self.gui and hWnd in self.gui.windows:
            self.gui.windows[hWnd].enabled = bool(bEnable)
        elif self.gui and hWnd in self.gui.controls:
            self.gui.controls[hWnd].enabled = bool(bEnable)

        return 1

    def GetDlgItem(self, args):
        """GetDlgItem emulation"""
        hDlg = args[0]
        nIDDlgItem = args[1]
        log.debug(f"GetDlgItem(0x{hDlg:x}, {nIDDlgItem})")

        # Find the child control with this control id
        if self.gui and hDlg in self.gui.windows:
            for control in self.gui.windows[hDlg].controls:
                if control.control_id == nIDDlgItem:
                    return control.hwnd
            for child in self.gui.windows[hDlg].children:
                win = self.gui.windows.get(child)
                if win is not None and win.control_id == nIDDlgItem:
                    return child
            # No such control: NULL, which programs rely on to stop loops
            # over consecutive control IDs
            self._last_error = 1421  # ERROR_CONTROL_ID_NOT_FOUND
            return 0

        # Without the fake desktop there are no controls: the ID stands for one
        return 0x20000 + nIDDlgItem

    def GetDlgItemTextA(self, args, wide=False):
        """GetDlgItemTextA/W emulation"""
        hDlg = args[0]
        nIDDlgItem = args[1]
        lpString = args[2]
        cchMax = args[3]
        hwnd = self.GetDlgItem([hDlg, nIDDlgItem])
        return self.GetWindowTextA([hwnd, lpString, cchMax], wide)

    def GetDlgItemTextW(self, args):
        return self.GetDlgItemTextA(args, wide=True)

    def SetDlgItemTextA(self, args, wide=False):
        """SetDlgItemTextA/W emulation"""
        hDlg = args[0]
        nIDDlgItem = args[1]
        lpString = args[2]
        hwnd = self.GetDlgItem([hDlg, nIDDlgItem])
        return self.SetWindowTextA([hwnd, lpString], wide)

    def SetDlgItemTextW(self, args):
        return self.SetDlgItemTextA(args, wide=True)

    def GetDlgItemInt(self, args):
        """GetDlgItemInt emulation - read a control's text and parse an integer.

        Signature: UINT GetDlgItemInt(hDlg, nIDDlgItem, lpTranslated, bSigned)
        """
        hDlg = args[0]
        nIDDlgItem = args[1]
        lpTranslated = args[2]
        bSigned = args[3]

        text = ""
        hwnd = self.GetDlgItem([hDlg, nIDDlgItem])
        if self.gui:
            text = self.gui.get_window_text(hwnd)
        text = text.strip()

        # Parse the leading integer, exactly like the Win32 implementation
        sign = 1
        idx = 0
        if bSigned and idx < len(text) and text[idx] in '+-':
            if text[idx] == '-':
                sign = -1
            idx += 1
        elif not bSigned and idx < len(text) and text[idx] == '+':
            idx += 1
        digits = ''
        while idx < len(text) and text[idx].isdigit():
            digits += text[idx]
            idx += 1

        success = 1 if digits else 0
        value = (sign * int(digits)) if digits else 0

        if bSigned:
            # Clamp to INT range
            if value > 0x7FFFFFFF or value < -0x80000000:
                success = 0
                value = 0
        else:
            if value > 0xFFFFFFFF:
                success = 0
                value = 0

        if lpTranslated and not self._mem_write(lpTranslated, struct.pack('<I', success)):
            log.warning(f"GetDlgItemInt: cannot write to 0x{lpTranslated:08x}")

        log.debug(f"GetDlgItemInt(0x{hDlg:x}, {nIDDlgItem}) -> {value} (ok={success})")
        return value & 0xFFFFFFFF

    def SetDlgItemInt(self, args):
        """SetDlgItemInt emulation - set a control's text from an integer.

        Signature: BOOL SetDlgItemInt(hDlg, nIDDlgItem, uValue, bSigned)
        """
        hDlg = args[0]
        nIDDlgItem = args[1]
        uValue = args[2]
        bSigned = args[3]

        if bSigned and uValue >= 0x80000000:
            value = uValue - 0x100000000
        else:
            value = uValue
        text = str(value)

        hwnd = self.GetDlgItem([hDlg, nIDDlgItem])
        log.debug(f"SetDlgItemInt(0x{hDlg:x}, {nIDDlgItem}, {text})")
        if self.gui:
            self.gui.set_window_text(hwnd, text)
        return 1

    def GetDlgCtrlID(self, args):
        """GetDlgCtrlID emulation - return a control's ID"""
        hwndCtl = args[0]
        if self.gui and hwndCtl in self.gui.controls:
            return self.gui.controls[hwndCtl].control_id
        if self.gui and hwndCtl in self.gui.windows:
            return self.gui.windows[hwndCtl].control_id
        return 0

    def _window_long(self, hWnd, nIndex, new_value=None, set_value=False):
        """Shared GetWindowLong/SetWindowLong backend.

        Handles the common negative GWL_* indices against real window state
        and keeps every other index (including positive extra-bytes offsets)
        in a per-handle dictionary.
        """
        GWL_WNDPROC = -4
        GWL_STYLE = -16
        GWL_EXSTYLE = -20
        GWL_USERDATA = -21   # GWLP_USERDATA on 32-bit

        win = self.gui.windows.get(hWnd) if self.gui else None
        store = self.window_longs.setdefault(hWnd, {})

        if nIndex == GWL_WNDPROC:
            if win:
                old = win.wndproc or self._find_wndproc_for_hwnd(hWnd)
            elif self.gui and hWnd in self.gui.controls:
                old = store.get(nIndex) or self._native_stub()
            else:
                old = store.get(nIndex, 0)
            if set_value:
                if win:
                    win.wndproc = new_value
                store[nIndex] = new_value
            return old & 0xFFFFFFFF
        DWL_DLGPROC = 4
        dialog = self.dialogs.get(hWnd)
        if nIndex == DWL_DLGPROC and dialog is not None and not dialog['handler']:
            # The dialog procedure (subclassing a dialog replaces it)
            old = dialog['proc']
            if set_value:
                dialog['proc'] = new_value
            return old & 0xFFFFFFFF
        if nIndex == -12:  # GWL_ID
            if win is not None:
                old = win.control_id
                if set_value:
                    win.control_id = new_value
            elif self.gui and hWnd in self.gui.controls:
                old = self.gui.controls[hWnd].control_id
                if set_value:
                    self.gui.controls[hWnd].control_id = new_value
            else:
                old = store.get(nIndex, 0)
            return old & 0xFFFFFFFF
        if nIndex == -8 and not set_value:  # GWL_HWNDPARENT
            return self._parent_of(hWnd) & 0xFFFFFFFF
        if nIndex == -6 and not set_value:  # GWL_HINSTANCE: the module that created it
            return (store.get(nIndex) or self.emu.pe_loader.image_base) & 0xFFFFFFFF
        if nIndex == GWL_STYLE:
            control = self.gui.controls.get(hWnd) if self.gui and win is None else None
            if control is not None:
                old = control.style
                if set_value:
                    control.style = new_value
                return old & 0xFFFFFFFF
            if win is None:
                old = store.get(nIndex, 0)
            else:
                # WS_MINIMIZE / WS_MAXIMIZE reflect the window state
                old = (win.style | (0x20000000 if win.minimized else 0)
                       | (0x01000000 if win.maximized else 0))
            if set_value:
                if win:
                    win.style = new_value
                    # Dropping WS_MINIMIZE / WS_MAXIMIZE leaves that state
                    if not new_value & 0x20000000:
                        win.minimized = False
                    if not new_value & 0x01000000:
                        win.maximized = False
                store[nIndex] = new_value
                if win is not None and win.native == 'LISTVIEW':
                    win.nstate['dirty'] = True
            return old & 0xFFFFFFFF
        if nIndex in (GWL_EXSTYLE, GWL_USERDATA):
            old = store.get(nIndex, 0)
            if set_value:
                store[nIndex] = new_value
            return old & 0xFFFFFFFF

        # Generic slot (extra window bytes, etc.)
        old = store.get(nIndex, 0)
        if set_value:
            store[nIndex] = new_value
        return old & 0xFFFFFFFF

    def GetWindowLongA(self, args):
        """GetWindowLongA emulation"""
        hWnd = args[0]
        nIndex = args[1] if args[1] < 0x80000000 else args[1] - 0x100000000
        value = self._window_long(hWnd, nIndex)
        log.debug(f"GetWindowLongA(0x{hWnd:x}, {nIndex}) -> 0x{value:08x}")
        return value

    def SetWindowLongA(self, args):
        """SetWindowLongA emulation - returns the previous value"""
        hWnd = args[0]
        nIndex = args[1] if args[1] < 0x80000000 else args[1] - 0x100000000
        dwNewLong = args[2]
        old = self._window_long(hWnd, nIndex, dwNewLong, set_value=True)
        log.debug(f"SetWindowLongA(0x{hWnd:x}, {nIndex}, 0x{dwNewLong:08x}) -> 0x{old:08x}")
        return old

    # Wide variants share the same backend
    def GetWindowLongW(self, args):
        return self.GetWindowLongA(args)

    def SetWindowLongW(self, args):
        return self.SetWindowLongA(args)

    def CheckDlgButton(self, args):
        """CheckDlgButton emulation - set a checkbox's state by control id"""
        hDlg = args[0]
        nIDButton = args[1]
        uCheck = args[2]
        hwnd = self.GetDlgItem([hDlg, nIDButton])
        if self.gui and hwnd in self.gui.controls:
            self.gui.controls[hwnd].checked = bool(uCheck)
            return 1
        return 0

    def IsDlgButtonChecked(self, args):
        """IsDlgButtonChecked emulation"""
        hDlg = args[0]
        nIDButton = args[1]
        hwnd = self.GetDlgItem([hDlg, nIDButton])
        if self.gui and hwnd in self.gui.controls:
            return 1 if self.gui.controls[hwnd].checked else 0
        return 0

    def SetFocus(self, args):
        """SetFocus emulation - give keyboard focus to a control, or to a
        top-level window, which is activated then"""
        hWnd = args[0]
        log.debug(f"SetFocus(0x{hWnd:x})")
        prev = 0
        if self.gui:
            prev = self.GetFocus([])
            win = self.gui.windows.get(hWnd)
            if hWnd in self.gui.controls:
                self.gui.focused_control = hWnd
                self.gui.focused_window = None
            else:
                self.gui.focused_control = None
                if win is not None and win.parent:
                    self.gui.focused_window = hWnd
                    top = self.gui.top_level_of(hWnd)
                    top_win = self.gui.windows.get(top)
                    if top_win is not None and top_win.visible and top_win.parent is None \
                            and self.gui.active_window != top:
                        self.BringWindowToTop([top])
                else:
                    self.gui.focused_window = None
                    if win is not None and win.parent is None and win.visible:
                        self.BringWindowToTop([hWnd])
            if prev != hWnd:
                # Like Windows: the old focus gets WM_KILLFOCUS, the new one WM_SETFOCUS
                if prev and (prev in self.gui.windows or prev in self.gui.controls):
                    self._send(prev, self.WM_KILLFOCUS, hWnd, 0)
                if win is not None and win.parent and hWnd in self.gui.windows:
                    self._send(hWnd, self.WM_SETFOCUS, prev, 0)
        return prev

    def GetFocus(self, args):
        """GetFocus emulation - the focused control, else the active window
        (0 if the focus belongs to another program)"""
        if not self.gui:
            return 0
        hwnd = self.gui.focused_control
        if not hwnd:
            focus = self.gui.focused_window
            if focus in self.gui.windows and self.gui.top_level_of(focus) == \
                    self.gui.active_window:
                hwnd = focus
        hwnd = hwnd or self.gui.active_window or 0
        return hwnd if hwnd and self.gui.window_owner(hwnd) is self else 0

    def GetAsyncKeyState(self, args):
        """GetAsyncKeyState emulation - poll key state (game loops)"""
        vKey = args[0]
        if self.gui and self.gui.key_states.get(vKey):
            return 0x8000  # Key is currently down (bit 15)
        return 0

    def GetKeyState(self, args):
        """GetKeyState emulation (same as GetAsyncKeyState in the emulator)"""
        return self.GetAsyncKeyState(args)

    def GetCursorPos(self, args):
        """GetCursorPos emulation - cursor position in fake-desktop coordinates"""
        lpPoint = args[0]
        x, y = self.gui.mouse_pos if self.gui else (0, 0)
        if lpPoint:
            try:
                self.emu.uc.mem_write(lpPoint, struct.pack("<ii", x, y))
            except UcError:
                return 0
        log.debug(f"GetCursorPos() -> ({x}, {y})")
        return 1

    def SetCursorPos(self, args):
        """SetCursorPos emulation (accepted but not applied to the real mouse)"""
        x, y = self._read_signed_args(args, 0, 2)
        log.debug(f"SetCursorPos({x}, {y})")
        return 1

    def _client_origin_of(self, hwnd):
        """Screen position of a window's or control's client area, or None"""
        if not self.gui:
            return None
        if hwnd in self.gui.windows:
            return self.gui.client_origin(self.gui.windows[hwnd])
        if hwnd in self.gui.controls:
            return self.gui.control_origin(self.gui.controls[hwnd])
        return None

    def ScreenToClient(self, args):
        """ScreenToClient emulation"""
        hWnd = args[0]
        lpPoint = args[1]
        if not lpPoint:
            return 0
        try:
            x, y = struct.unpack("<ii", self.emu.uc.mem_read(lpPoint, 8))
        except UcError:
            return 0
        origin = self._client_origin_of(hWnd)
        if origin is not None:
            x, y = x - origin[0], y - origin[1]
        try:
            self.emu.uc.mem_write(lpPoint, struct.pack("<ii", x, y))
        except UcError:
            return 0
        return 1

    def ClientToScreen(self, args):
        """ClientToScreen emulation"""
        hWnd = args[0]
        lpPoint = args[1]
        if not lpPoint:
            return 0
        try:
            x, y = struct.unpack("<ii", self.emu.uc.mem_read(lpPoint, 8))
        except UcError:
            return 0
        origin = self._client_origin_of(hWnd)
        if origin is not None:
            x, y = x + origin[0], y + origin[1]
        try:
            self.emu.uc.mem_write(lpPoint, struct.pack("<ii", x, y))
        except UcError:
            return 0
        return 1

    def MapWindowPoints(self, args):
        """MapWindowPoints emulation - points (or a RECT: 2 points) from the
        client area of one window to another's (NULL: the screen); returns
        the offset, x in the low word and y in the high word"""
        hWndFrom, hWndTo, lpPoints, cPoints = args[:4]
        if not self.gui:
            return 0
        origins = []
        for hwnd in (hWndFrom, hWndTo):
            origin = (0, 0) if hwnd in (0, self.DESKTOP_HWND) else self._client_origin_of(hwnd)
            if origin is None:
                self._last_error = 1400  # ERROR_INVALID_WINDOW_HANDLE
                return 0
            origins.append(origin)
        dx, dy = origins[0][0] - origins[1][0], origins[0][1] - origins[1][1]
        if lpPoints and cPoints:
            try:
                count = min(cPoints, 0x10000)
                values = struct.unpack(f"<{2 * count}i", self.emu.uc.mem_read(lpPoints, 8 * count))
                moved = [v + (dx if i % 2 == 0 else dy) for i, v in enumerate(values)]
                self.emu.uc.mem_write(lpPoints, struct.pack(f"<{2 * count}i", *moved))
            except UcError:
                return 0
        self._last_error = 0
        return ((dy & 0xFFFF) << 16) | (dx & 0xFFFF)

    def SetCapture(self, args):
        """SetCapture emulation - route mouse input to one window"""
        hWnd = args[0]
        prev = self.capture_hwnd
        self.capture_hwnd = hWnd
        log.debug(f"SetCapture(0x{hWnd:x})")
        return prev

    def ReleaseCapture(self, args):
        """ReleaseCapture emulation"""
        log.debug("ReleaseCapture()")
        self.capture_hwnd = 0
        return 1

    def GetCapture(self, args):
        """GetCapture emulation"""
        return self.capture_hwnd

    def GetParent(self, args):
        """GetParent emulation - parent of a child window or control, owner of a
        WS_POPUP dialog; like Windows, NULL for an overlapped (owned) window"""
        hWnd = args[0]
        if not self.gui:
            return 0
        if hWnd in self.gui.controls:
            return self.gui.controls[hWnd].parent_hwnd or 0
        win = self.gui.windows.get(hWnd)
        if win is not None and win.parent:
            return win.parent
        dialog = self.dialogs.get(hWnd)
        if dialog is None or win is None or not win.style & self.WS_POPUP:
            return 0
        return dialog['owner'] or 0

    def SetParent(self, args):
        """SetParent emulation - previous parent"""
        hWnd, parent = args[0], args[1]
        previous = self.GetParent([hWnd])
        if self.gui and parent in self.gui.windows:
            self.gui.reparent(hWnd, parent)
        return previous

    def IsWindow(self, args):
        """IsWindow emulation"""
        hWnd = args[0]
        if self.gui and (hWnd in self.gui.windows or hWnd in self.gui.controls):
            return 1
        return 0

    def IsWindowVisible(self, args):
        """IsWindowVisible emulation"""
        hWnd = args[0]
        if self.gui:
            if hWnd in self.gui.windows:
                win = self.gui.windows[hWnd]
                return 1 if (win.visible and not win.minimized) else 0
            if hWnd in self.gui.controls:
                return 1 if self.gui.controls[hWnd].visible else 0
        return 0

    def IsWindowEnabled(self, args):
        """IsWindowEnabled emulation"""
        hWnd = args[0]
        if self.gui:
            if hWnd in self.gui.windows:
                return 1 if self.gui.windows[hWnd].enabled else 0
            if hWnd in self.gui.controls:
                return 1 if self.gui.controls[hWnd].enabled else 0
        return 0

    # MessageBeep/PlaySound system sounds as (frequency Hz, duration ms)
    SYSTEM_SOUND_TONES = {
        0xFFFFFFFF: (750, 150),   # simple beep (PC speaker)
        0x00: (800, 150),         # MB_OK / SystemDefault
        0x10: (400, 300),         # MB_ICONHAND / SystemHand
        0x20: (600, 150),         # MB_ICONQUESTION / SystemQuestion
        0x30: (900, 200),         # MB_ICONEXCLAMATION / SystemExclamation
        0x40: (1000, 150),        # MB_ICONASTERISK / SystemAsterisk
    }

    def MessageBeep(self, args):
        """MessageBeep emulation - plays a system tone asynchronously"""
        uType = args[0]
        log.debug(f"MessageBeep(0x{uType:x})")
        key = uType if uType == 0xFFFFFFFF else uType & 0xF0
        SoundPlayer.tone(*self.SYSTEM_SOUND_TONES.get(key, self.SYSTEM_SOUND_TONES[0]))
        return 1

    # Classic Windows colors for GetSysColor, as (r, g, b)
    SYS_COLORS = {
        0: (212, 208, 200),   # COLOR_SCROLLBAR
        1: (58, 110, 165),    # COLOR_BACKGROUND (desktop)
        2: (0, 0, 128),       # COLOR_ACTIVECAPTION
        3: (128, 128, 128),   # COLOR_INACTIVECAPTION
        4: (212, 208, 200),   # COLOR_MENU
        5: (255, 255, 255),   # COLOR_WINDOW
        6: (0, 0, 0),         # COLOR_WINDOWFRAME
        7: (0, 0, 0),         # COLOR_MENUTEXT
        8: (0, 0, 0),         # COLOR_WINDOWTEXT
        9: (255, 255, 255),   # COLOR_CAPTIONTEXT
        10: (212, 208, 200),  # COLOR_ACTIVEBORDER
        11: (212, 208, 200),  # COLOR_INACTIVEBORDER
        12: (128, 128, 128),  # COLOR_APPWORKSPACE
        13: (0, 0, 128),      # COLOR_HIGHLIGHT
        14: (255, 255, 255),  # COLOR_HIGHLIGHTTEXT
        15: (212, 208, 200),  # COLOR_BTNFACE
        16: (128, 128, 128),  # COLOR_BTNSHADOW
        17: (128, 128, 128),  # COLOR_GRAYTEXT
        18: (0, 0, 0),        # COLOR_BTNTEXT
        19: (192, 192, 192),  # COLOR_INACTIVECAPTIONTEXT
        20: (255, 255, 255),  # COLOR_BTNHIGHLIGHT
        21: (64, 64, 64),     # COLOR_3DDKSHADOW
        22: (212, 208, 200),  # COLOR_3DLIGHT
        23: (0, 0, 0),        # COLOR_INFOTEXT
        24: (255, 255, 225),  # COLOR_INFOBK
    }

    def GetSysColor(self, args):
        """GetSysColor emulation - classic Windows color scheme (COLORREF)"""
        r, g, b = self.SYS_COLORS.get(args[0], (0, 0, 0))
        return r | (g << 8) | (b << 16)

    def GetSysColorBrush(self, args):
        """GetSysColorBrush emulation - one cached solid brush per color index"""
        nIndex = args[0]
        if nIndex not in self.SYS_COLORS:
            return 0
        cache = self._sys_color_brushes
        if nIndex not in cache:
            cache[nIndex] = self.CreateSolidBrush([self.GetSysColor([nIndex])])
        return cache[nIndex]

    DESKTOP_HWND = 0x00010010

    def GetDesktopWindow(self, args):
        """GetDesktopWindow emulation - fixed pseudo handle"""
        return self.DESKTOP_HWND

    def GetForegroundWindow(self, args):
        """GetForegroundWindow emulation - the active window of the fake desktop"""
        if self.gui and self.gui.active_window in self.gui.windows:
            return self.gui.active_window
        return 0

    def GetActiveWindow(self, args):
        """GetActiveWindow emulation"""
        return self.GetForegroundWindow(args)

    def GetDoubleClickTime(self, args):
        """GetDoubleClickTime emulation - Windows default (500 ms)"""
        return 500

    # Window class names Windows reports for the built-in control classes
    CONTROL_CLASS_NAMES = {'BUTTON': 'Button', 'CHECKBOX': 'Button', 'EDIT': 'Edit',
                           'STATIC': 'Static', 'LISTBOX': 'ListBox',
                           'COMBOBOX': 'ComboBox', 'SCROLLBAR': 'ScrollBar'}

    def _window_class_name(self, hwnd):
        """Class name of a window or control, or None for an invalid handle"""
        if not self.gui:
            return None
        if hwnd in self.gui.windows:
            if hwnd in self.gui.consoles:
                return "ConsoleWindowClass"
            return getattr(self.gui.windows[hwnd], 'class_name', None) or "#32770"
        if hwnd in self.gui.controls:
            name = self.gui.controls[hwnd].class_name
            return self.CONTROL_CLASS_NAMES.get(name, name)
        return None

    def FindWindowA(self, args):
        """FindWindowA emulation - top-level windows by class and/or title"""
        lpClassName, lpWindowName = args[0], args[1]
        if lpClassName and lpClassName < 0x10000:
            class_name = self.atoms.get(lpClassName)
            if class_name is None:
                return 0
        else:
            class_name = self.read_string(lpClassName) if lpClassName else None
        title = self.read_string(lpWindowName) if lpWindowName else None
        log.debug(f"FindWindowA({class_name!r}, {title!r})")
        if not self.gui:
            return 0
        with self.gui.lock:
            # Topmost first, then hidden windows
            order = list(reversed(self.gui.z_order))
            order += [h for h in self.gui.windows if h not in order]
            for hwnd in order:
                win = self.gui.windows.get(hwnd)
                if win is None or win.parent:
                    continue
                if class_name is not None and \
                        (self._window_class_name(hwnd) or '').lower() != class_name.lower():
                    continue
                if title is not None and win.title.lower() != title.lower():
                    continue
                return hwnd
        self._last_error = 2  # ERROR_FILE_NOT_FOUND
        return 0

    def GetClassNameA(self, args):
        """GetClassNameA emulation"""
        hWnd, lpClassName, nMaxCount = args[0], args[1], args[2]
        name = self._window_class_name(hWnd)
        log.debug(f"GetClassNameA(0x{hWnd:x}) -> {name!r}")
        if name is None:
            self._last_error = 1400  # ERROR_INVALID_WINDOW_HANDLE
            return 0
        if not lpClassName or nMaxCount == 0 or nMaxCount >= 0x80000000:
            return 0
        data = name.encode(config.ANSI_CODEPAGE, errors='replace')[:nMaxCount - 1]
        self.emu.uc.mem_write(lpClassName, data + b'\x00')
        return len(data)

    def GetWindowTextLengthA(self, args):
        """GetWindowTextLengthA emulation - length in ANSI bytes"""
        self._last_error = 0
        return len(self._window_text(args[0]).encode(config.ANSI_CODEPAGE, errors='replace'))

    def BringWindowToTop(self, args):
        """BringWindowToTop emulation - raise and activate a top-level window"""
        hWnd = args[0]
        log.debug(f"BringWindowToTop(0x{hWnd:x})")
        if not self.gui:
            return 0
        with self.gui.lock:
            if hWnd not in self.gui.windows:
                self._last_error = 1400  # ERROR_INVALID_WINDOW_HANDLE
                return 0
            if hWnd in self.gui.z_order:
                self.gui.z_order.remove(hWnd)
                self.gui.z_order.append(hWnd)
            if self.gui.windows[hWnd].visible:
                self.gui.active_window = hWnd
        return 1

    def SetForegroundWindow(self, args):
        """SetForegroundWindow emulation"""
        return self.BringWindowToTop(args)

    def IsIconic(self, args):
        """IsIconic emulation - is the window minimized?"""
        win = self.gui.windows.get(args[0]) if self.gui else None
        return 1 if win and win.minimized else 0

    def OpenIcon(self, args):
        """OpenIcon emulation - restore a minimized window and activate it"""
        hWnd = args[0]
        if not self.gui or hWnd not in self.gui.windows:
            self._last_error = 1400  # ERROR_INVALID_WINDOW_HANDLE
            return 0
        with self.gui.lock:
            win = self.gui.windows[hWnd]
            if win.minimized:
                win.restore()
        return self.BringWindowToTop([hWnd])

    def IsZoomed(self, args):
        """IsZoomed emulation - is the window maximized?"""
        win = self.gui.windows.get(args[0]) if self.gui else None
        return 1 if win and win.maximized and not win.minimized else 0

    def GetWindowPlacement(self, args):
        """GetWindowPlacement emulation (WINDOWPLACEMENT, 44 bytes)"""
        hWnd, lpwndpl = args[0], args[1]
        win = self.gui.windows.get(hWnd) if self.gui else None
        if win is None or not lpwndpl:
            self._last_error = 1400  # ERROR_INVALID_WINDOW_HANDLE
            return 0
        show = 2 if win.minimized else 3 if win.maximized else 1
        if win.maximized:
            normal = (win.restore_x, win.restore_y, win.restore_x + win.restore_width,
                      win.restore_y + win.restore_height)
        else:
            normal = (win.x, win.y, win.x + win.width, win.y + win.height)
        data = struct.pack('<III4i4i', 44, 0, show, -1, -1, -1, -1, *normal)
        return 1 if self._mem_write(lpwndpl, data) else 0

    def SetWindowPlacement(self, args):
        """SetWindowPlacement emulation - normal rectangle and show state"""
        hWnd, lpwndpl = args[0], args[1]
        win = self.gui.windows.get(hWnd) if self.gui else None
        try:
            fields = struct.unpack('<III4i4i', self.emu.uc.mem_read(lpwndpl, 44))
        except UcError:
            fields = None
        if win is None or fields is None:
            self._last_error = 1400
            return 0
        show = fields[2]
        left, top, right, bottom = fields[7:11]
        with self.gui.lock:
            if win.maximized:
                win.restore_x, win.restore_y = left, top
                win.restore_width, win.restore_height = right - left, bottom - top
            else:
                win.x, win.y, win.width, win.height = left, top, right - left, bottom - top
            if show == 0:  # SW_HIDE
                self.gui.show_window(hWnd, False)
            else:
                if show in (2, 6, 7):  # SW_SHOWMINIMIZED, SW_MINIMIZE, SW_SHOWMINNOACTIVE
                    win.minimize()
                elif show == 3:  # SW_SHOWMAXIMIZED
                    win.minimized = False
                    win.maximize(self.gui.width, self.gui.height, 30)
                else:
                    win.restore()
                    if win.maximized:
                        win.restore()
                if not win.visible:
                    self.gui.show_window(hWnd, True)
        self._send_size(hWnd)
        return 1

    # GetWindow commands
    GW_HWNDFIRST, GW_HWNDLAST, GW_HWNDNEXT, GW_HWNDPREV, GW_OWNER, GW_CHILD = range(6)

    def _child_handles(self, hwnd):
        """Child controls and child windows of a window, top of the Z order first"""
        win = self.gui.windows.get(hwnd)
        if win is None:
            return []
        return [c.hwnd for c in win.controls] + list(win.children)

    def GetWindow(self, args):
        """GetWindow emulation - walks siblings, children and owners"""
        hWnd, uCmd = args[0], args[1]
        if not self.gui:
            return 0
        with self.gui.lock:
            if uCmd == self.GW_CHILD:
                children = self._child_handles(hWnd)
                return children[0] if children else 0
            if uCmd == self.GW_OWNER:
                dialog = self.dialogs.get(hWnd)
                return dialog['owner'] if dialog else 0
            control = self.gui.controls.get(hWnd)
            win = self.gui.windows.get(hWnd)
            if control is not None:
                siblings = self._child_handles(control.parent_hwnd)
            elif win is not None and win.parent:
                siblings = self._child_handles(win.parent)
            elif win is not None:
                siblings = [h for h in reversed(self.gui.z_order) if h in self.gui.windows]
            else:
                self._last_error = 1400  # ERROR_INVALID_WINDOW_HANDLE
                return 0
        if not siblings:
            return 0
        if uCmd == self.GW_HWNDFIRST:
            return siblings[0]
        if uCmd == self.GW_HWNDLAST:
            return siblings[-1]
        if hWnd not in siblings:
            return 0
        index = siblings.index(hWnd) + (1 if uCmd == self.GW_HWNDNEXT else -1)
        if uCmd in (self.GW_HWNDNEXT, self.GW_HWNDPREV) and 0 <= index < len(siblings):
            return siblings[index]
        return 0
