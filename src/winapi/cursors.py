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

"""WinAPIHandler mixin: Cursors and icons"""

import os
import struct

import pefile
from unicorn import UcError

from .. import resources
from ..logger import log


class CursorsMixin:
    """Cursors and icons"""

    # ---------- Cursors, icons ----------

    IDC_ARROW = 32512
    IDC_SIZEWE = 32644
    # Standard cursors (LoadCursor with hInstance NULL): IDC_ARROW, IDC_IBEAM,
    # IDC_WAIT, IDC_CROSS, IDC_UPARROW, IDC_SIZE, IDC_ICON, IDC_SIZENWSE,
    # IDC_SIZENESW, IDC_SIZEWE, IDC_SIZENS, IDC_SIZEALL, IDC_NO, IDC_HAND,
    # IDC_APPSTARTING, IDC_HELP
    SYSTEM_CURSOR_IDS = (32512, 32513, 32514, 32515, 32516, 32640, 32641, 32642, 32643,
                         32644, 32645, 32646, 32648, 32649, 32650, 32651)

    def _system_cursor(self, cursor_id):
        """Shared handle of a standard cursor (always the same one, like Windows),
        or 0 if cursor_id is not one"""
        if cursor_id not in self.SYSTEM_CURSOR_IDS:
            return 0
        handle = self._system_cursors.get(cursor_id)
        if handle is None:
            handle = self.get_next_handle()
            self._system_cursors[cursor_id] = handle
            self.cursors[handle] = {'system': cursor_id}
        return handle

    def _new_cursor(self, hotspot, width, height, rgba):
        handle = self.get_next_handle()
        self.cursors[handle] = {'hotspot': hotspot, 'size': (width, height), 'rgba': rgba}
        return handle

    def _load_resource_cursor(self, key, hModule=0):
        """Cursor from an RT_GROUP_CURSOR resource of the EXE (its 32x32 image,
        else the first one), or 0"""
        group = self._find_resource(12, key, hModule)  # RT_GROUP_CURSOR
        if group is None:
            return 0
        try:
            data = bytes(self.emu.uc.mem_read(*group))
            count = struct.unpack_from('<H', data, 4)[0]
            # CURSORDIR entries: width, height (x2), planes, bit count, size, RT_CURSOR id
            entries = [struct.unpack_from('<HHHHIH', data, 6 + 14 * i) for i in range(count)]
        except (struct.error, UcError):
            return 0
        if not entries:
            return 0
        entry = max(entries, key=lambda e: (e[0] == 32, e[3]))
        found = self._find_resource(1, entry[5], hModule)  # RT_CURSOR
        if found is None:
            return 0
        try:
            data = bytes(self.emu.uc.mem_read(*found))
            hotspot = struct.unpack_from('<HH', data, 0)
            bpp = struct.unpack_from('<H', data, 4 + 14)[0]
        except (struct.error, UcError):
            return 0
        image = resources._icon_image_rgba(data[4:])
        if image is None:
            return 0
        width, height, rgba = image
        if bpp == 1:
            # Monochrome: masked pixels with a set XOR bit invert the screen;
            # they are drawn black (outlines stay visible)
            rgba = bytearray(rgba)
            for i in range(0, len(rgba), 4):
                if not rgba[i + 3] and rgba[i]:
                    rgba[i:i + 4] = b'\x00\x00\x00\xff'
            rgba = bytes(rgba)
        return self._new_cursor(hotspot, width, height, rgba)

    def SetCursor(self, args):
        """SetCursor emulation - returns the previous cursor"""
        previous, self.current_cursor = self.current_cursor, args[0]
        return previous or 0

    def GetCursor(self, args):
        """GetCursor emulation"""
        return self.current_cursor or 0

    def ShowCursor(self, args):
        """ShowCursor emulation - display counter (the cursor shows while >= 0)"""
        self.cursor_count += 1 if args[0] else -1
        return self.cursor_count & 0xFFFFFFFF

    def CreateCursor(self, args):
        """CreateCursor emulation - a monochrome cursor from an AND and an XOR
        bit plane (rows padded to 16 bits)"""
        x_hot, y_hot = self._read_signed_args(args, 1, 2)
        width, height = self._read_signed_args(args, 3, 2)
        and_plane, xor_plane = args[5], args[6]
        if not 0 < width <= 256 or not 0 < height <= 256:
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0
        stride = (width + 15) // 16 * 2
        try:
            and_bits = bytes(self.emu.uc.mem_read(and_plane, stride * height))
            xor_bits = bytes(self.emu.uc.mem_read(xor_plane, stride * height))
        except UcError:
            self._last_error = 998  # ERROR_NOACCESS
            return 0
        rgba = bytearray(width * height * 4)
        for y in range(height):
            for x in range(width):
                index, bit = y * stride + (x >> 3), 0x80 >> (x & 7)
                masked, xor = and_bits[index] & bit, xor_bits[index] & bit
                if not masked or xor:
                    # Black, white, or an inverted pixel (drawn black)
                    value = 255 if xor and not masked else 0
                    rgba[(y * width + x) * 4:(y * width + x + 1) * 4] = bytes(
                        (value, value, value, 255))
        log.debug(f"CreateCursor({width}x{height}, hotspot ({x_hot},{y_hot}))")
        return self._new_cursor((x_hot, y_hot), width, height, bytes(rgba))

    def DestroyCursor(self, args):
        """DestroyCursor emulation (the standard cursors are shared and kept)"""
        cursor = self.cursors.get(args[0])
        if cursor is None:
            self._last_error = 6  # ERROR_INVALID_HANDLE
            return 0
        if 'system' not in cursor:
            del self.cursors[args[0]]
        return 1

    def _class_cursor(self, hwnd):
        """hCursor of a window's class (0 if it has none); the emulated common
        controls' classes have the arrow"""
        win = self.gui.windows.get(hwnd) if self.gui else None
        wndclass = self.registered_classes.get(getattr(win, 'class_name', None) or '')
        if wndclass:
            return wndclass.get('cursor', 0)
        return self._system_cursor(self.IDC_ARROW) if getattr(win, 'native', None) else 0

    def displayed_cursor(self, hwnd):
        """Cursor shown over the client area of hwnd (called by the GUI thread):
        a cursor dict, or None if hidden (ShowCursor counter, SetCursor(NULL))"""
        if self.cursor_count < 0:
            return None
        handle = self.current_cursor
        if handle is None:
            handle = self._class_cursor(hwnd) or self._system_cursor(self.IDC_ARROW)
        return self.cursors.get(handle) if handle else None

    WM_SETCURSOR = 0x0020
    HTCLIENT = 1

    def _default_set_cursor(self, hwnd, wParam, lParam):
        """DefWindowProc's WM_SETCURSOR: a child window asks its parent first,
        then the client area gets the class cursor, the rest the arrow. A parent
        asked about a child's client area (wParam is the child) leaves it to the
        child, like Windows: the child's class cursor wins, not the parent's"""
        win = self.gui.windows.get(hwnd) if self.gui else None
        if win is not None and win.parent:
            parent_proc = self._find_wndproc_for_hwnd(win.parent)
            if parent_proc and self.emu.call_wndproc(parent_proc, win.parent,
                                                     self.WM_SETCURSOR, wParam, lParam):
                return 1
        if lParam & 0xFFFF == self.HTCLIENT:
            if wParam and wParam != hwnd:
                return 0
            cursor = self._class_cursor(hwnd)
            if cursor:
                self.current_cursor = cursor
        else:
            self.current_cursor = self._system_cursor(self.IDC_ARROW)
        return 0

    def _deliver_set_cursor(self):
        """Send the pending WM_SETCURSOR messages (posted by the GUI thread when
        the mouse moves over a window); they are sent, never returned by
        GetMessage/PeekMessage"""
        with self.message_lock:
            pending = [m for m in self.message_queue if m['message'] == self.WM_SETCURSOR]
            if not pending:
                return
            self.message_queue[:] = [m for m in self.message_queue
                                     if m['message'] != self.WM_SETCURSOR]
        for msg in pending:
            hwnd = msg['hwnd']
            if not self.gui or hwnd not in self.gui.windows:
                continue
            if hwnd in self.dialogs:  # DefDlgProc: the dialog class cursor
                self.current_cursor = self._system_cursor(self.IDC_ARROW)
                continue
            wndproc = self._find_wndproc_for_hwnd(hwnd)
            if wndproc:
                self.emu.call_wndproc(wndproc, hwnd, self.WM_SETCURSOR, hwnd, msg['lParam'])
            else:
                self._default_set_cursor(hwnd, hwnd, msg['lParam'])

    def DestroyIcon(self, args):
        """DestroyIcon emulation"""
        return 1

    def ExtractIconA(self, args):
        """ExtractIconA emulation - icon count (nIconIndex -1) or an opaque icon handle"""
        filename = self.read_string(args[1])
        index = args[2]
        path = self.resolve_drive_path(filename)
        if path is None or not os.path.isfile(path):
            return 0
        count = 0
        try:
            pe = pefile.PE(path, fast_load=True)
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
            for entry in getattr(pe, 'DIRECTORY_ENTRY_RESOURCE', None).entries:
                if entry.id == 14:  # RT_GROUP_ICON
                    count = len(entry.directory.entries)
            pe.close()
        except (pefile.PEFormatError, AttributeError, OSError):
            return 1 if filename.lower().endswith('.ico') else 0  # Not an EXE/DLL
        if index == 0xFFFFFFFF:
            return count
        return self.get_next_handle() if index < count else 0
