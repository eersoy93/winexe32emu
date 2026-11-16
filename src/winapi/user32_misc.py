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

"""WinAPIHandler mixin: Strings, bitmaps, dialog units, monitors, window classes; the clipboard"""

import struct

from unicorn import *

from .. import config, winapi


class User32MiscMixin:
    """Strings, bitmaps, dialog units, monitors, window classes; the clipboard"""

    # ---------- Strings, bitmaps, dialog units, monitors ----------

    def LoadStringW(self, args):
        """LoadStringW emulation (cchBufferMax 0: a pointer to the resource string)"""
        hInstance, uID, lpBuffer, cchBufferMax = args[0], args[1] & 0xFFFF, args[2], args[3]
        resource = self._find_resource(6, uID // 16 + 1) if self._is_own_module(hInstance) \
            else None
        text, address = None, 0
        if resource:
            try:
                block = bytes(self.emu.uc.mem_read(*resource))
                pos = 0
                for _ in range(uID % 16):
                    pos += 2 + 2 * struct.unpack_from('<H', block, pos)[0]
                length = struct.unpack_from('<H', block, pos)[0]
                if length:
                    text = block[pos + 2:pos + 2 + 2 * length].decode('utf-16-le', 'replace')
                    address = resource[0] + pos + 2
            except (UcError, struct.error):
                text = None
        if not lpBuffer:
            return 0
        if cchBufferMax == 0:
            self._mem_write(lpBuffer, struct.pack('<I', address))
            return len(text) if text else 0
        if text is None:
            self._last_error = 1814  # ERROR_RESOURCE_NAME_NOT_FOUND
            self._mem_write(lpBuffer, b'\x00\x00')
            return 0
        return self._copy_text_out(lpBuffer, cchBufferMax, text)

    def LoadBitmapW(self, args):
        """LoadBitmapW emulation"""
        name = args[1]
        if name >= 0x10000:
            text = self.read_wide_string(name)
            name = int(text[1:]) if text.startswith('#') and text[1:].isdigit() else name
            if name >= 0x10000:
                temp = self.emu.heap_alloc(len(text) + 1)
                self._mem_write(temp, text.encode(config.ANSI_CODEPAGE, 'replace') + b'\x00')
                result = self.LoadBitmapA([args[0], temp])
                self.emu.heap_free(temp)
                return result
        return self.LoadBitmapA([args[0], name])

    def GetDialogBaseUnits(self, args):
        """GetDialogBaseUnits emulation (system font: 8 x 16)"""
        return (16 << 16) | 8

    def MapDialogRect(self, args):
        """MapDialogRect emulation - dialog units -> pixels (8 pt dialog font,
        like the emulator's dialog templates)"""
        rect = self._read_rect(args[1])
        if rect is None:
            return 0
        left, top, right, bottom = rect
        self._mem_write(args[1], struct.pack('<iiii', round(left * 1.5), round(top * 1.625),
                                             round(right * 1.5), round(bottom * 1.625)))
        return 1

    MONITOR_HANDLE = 0x00010001

    def MonitorFromWindow(self, args):
        return self.MONITOR_HANDLE

    def MonitorFromPoint(self, args):
        return self.MONITOR_HANDLE

    def MonitorFromRect(self, args):
        return self.MONITOR_HANDLE

    def GetMonitorInfoA(self, args, wide=False):
        """GetMonitorInfoA/W emulation - the fake desktop (work area without the taskbar)"""
        if args[0] != self.MONITOR_HANDLE or not args[1]:
            return 0
        size = struct.unpack('<I', self.emu.uc.mem_read(args[1], 4))[0]
        width, height = self._screen_size()
        data = struct.pack('<4i4iI', 0, 0, width, height, 0, 0, width, height - 30, 1)
        self._mem_write(args[1] + 4, data)
        if size >= 72:
            name = '\\\\.\\DISPLAY1'
            if wide:
                self._mem_write(args[1] + 40, name.encode('utf-16-le') + b'\x00\x00')
            else:
                self._mem_write(args[1] + 40, name.encode('ascii') + b'\x00')
        return 1

    def GetMonitorInfoW(self, args):
        return self.GetMonitorInfoA(args, wide=True)

    def SystemParametersInfoW(self, args):
        """SystemParametersInfoW emulation (as the A version; string results are
        not supported)"""
        return self.SystemParametersInfoA(args)

    def _window_text(self, hwnd):
        """Text of a window or control (a ComboBoxEx: its edit field)"""
        if not self.gui:
            return ""
        combo = self._native_window(hwnd, 'COMBOBOXEX')
        if combo is not None:
            return self._comboboxex_edit_text(combo)
        return self.gui.get_window_text(hwnd)

    def GetWindowTextLengthW(self, args):
        self._last_error = 0
        return len(self._window_text(args[0]))

    def MapVirtualKeyA(self, args):
        """MapVirtualKeyA/W emulation: VK <-> scan code for the common keys"""
        code, map_type = args[0], args[1]
        table = {0x1B: 0x01, 0x08: 0x0E, 0x09: 0x0F, 0x0D: 0x1C, 0x11: 0x1D, 0x10: 0x2A,
                 0x12: 0x38, 0x20: 0x39, 0x14: 0x3A, 0x70: 0x3B, 0x71: 0x3C, 0x72: 0x3D,
                 0x73: 0x3E, 0x74: 0x3F, 0x75: 0x40, 0x76: 0x41, 0x77: 0x42, 0x78: 0x43,
                 0x79: 0x44, 0x24: 0x47, 0x26: 0x48, 0x21: 0x49, 0x25: 0x4B, 0x27: 0x4D,
                 0x23: 0x4F, 0x28: 0x50, 0x22: 0x51, 0x2D: 0x52, 0x2E: 0x53, 0x6A: 0x37,
                 0x6D: 0x4A, 0x6B: 0x4E}
        row = '1234567890'
        for i, ch in enumerate(row):
            table[ord(ch)] = 0x02 + i
        for scan, letters in ((0x10, 'QWERTYUIOP'), (0x1E, 'ASDFGHJKL'), (0x2C, 'ZXCVBNM')):
            for i, ch in enumerate(letters):
                table[ord(ch)] = scan + i
        if map_type in (0, 2):  # MAPVK_VK_TO_VSC, MAPVK_VK_TO_CHAR
            if map_type == 2:
                return code if 0x30 <= code <= 0x5A or code == 0x20 else 0
            return table.get(code, 0)
        if map_type in (1, 3):  # MAPVK_VSC_TO_VK(_EX)
            for vk, scan in table.items():
                if scan == code:
                    return vk
        return 0

    def MapVirtualKeyW(self, args):
        return self.MapVirtualKeyA(args)

    def SendDlgItemMessageA(self, args, wide=False):
        """SendDlgItemMessageA/W emulation"""
        hwnd = self.GetDlgItem([args[0], args[1]])
        return self.SendMessageA([hwnd, args[2], args[3], args[4]], wide)

    def SendDlgItemMessageW(self, args):
        return self.SendDlgItemMessageA(args, wide=True)

    def CheckRadioButton(self, args):
        """CheckRadioButton emulation"""
        dlg, first, last, check = args[:4]
        for control_id in range(first, last + 1):
            self.CheckDlgButton([dlg, control_id, 1 if control_id == check else 0])
        return 1

    SYSTEM_CLASSES = ('BUTTON', 'EDIT', 'STATIC', 'LISTBOX', 'COMBOBOX', 'SCROLLBAR',
                      'MSCTLS_PROGRESS32', 'MSCTLS_STATUSBAR32', 'SYSLISTVIEW32',
                      'TOOLBARWINDOW32', 'REBARWINDOW32', 'COMBOBOXEX32', 'SYSHEADER32',
                      'TOOLTIPS_CLASS32', '#32770')

    def GetClassInfoA(self, args, wide=False, ex=False):
        """GetClassInfoA/W(Ex) emulation"""
        lpClassName, lpWndClass = args[1], args[2]
        if lpClassName < 0x10000:
            name = self.atoms.get(lpClassName)
        else:
            name = self._read_text(lpClassName, wide)
        wndclass = self.registered_classes.get(name) if name else None
        if wndclass is None:
            match = next((n for n in self.registered_classes if name and n.lower() == name.lower()),
                         None)
            wndclass = self.registered_classes.get(match) if match else None
        if wndclass is not None:
            fields = (wndclass['style'], wndclass['wndproc'], 0, 0, wndclass['hInstance'], 0,
                      wndclass['cursor'], wndclass['background'], 0, lpClassName)
            atom = wndclass['atom']
        elif name and name.upper() in self.SYSTEM_CLASSES:
            fields = (0x8, self._native_stub(), 0, 0, 0, 0, self._system_cursor(self.IDC_ARROW),
                      0, 0, lpClassName)
            atom = 0xC000 + self.SYSTEM_CLASSES.index(name.upper())
        else:
            self._last_error = 1411  # ERROR_CLASS_DOES_NOT_EXIST
            return 0
        if ex:
            self._mem_write(lpWndClass + 4, struct.pack('<10I', *fields))
        else:
            self._mem_write(lpWndClass, struct.pack('<10I', *fields))
        return atom

    def GetClassInfoW(self, args):
        return self.GetClassInfoA(args, wide=True)

    def GetClassInfoExW(self, args):
        return self.GetClassInfoA(args, wide=True, ex=True)

    def GetClassInfoExA(self, args):
        return self.GetClassInfoA(args, ex=True)

    def GetClassNameW(self, args):
        """GetClassNameW emulation"""
        name = self._window_class_name(args[0])
        if name is None:
            self._last_error = 1400  # ERROR_INVALID_WINDOW_HANDLE
            return 0
        return self._copy_text_out(args[1], args[2], name)

    def _window_at(self, x, y, root=None, client=False):
        """Deepest visible window (or control) at a screen point"""
        if not self.gui:
            return 0
        with self.gui.lock:
            if root is None:
                for hwnd in reversed(self.gui.z_order):
                    win = self.gui.windows.get(hwnd)
                    if win and win.visible and not win.minimized and win.contains_point(x, y):
                        root = hwnd
                        break
                else:
                    return self.DESKTOP_HWND
            return self.gui.child_at(root, x, y)

    def WindowFromPoint(self, args):
        x, y = self._read_signed_args(args, 0, 2)
        return self._window_at(x, y)

    def ChildWindowFromPointEx(self, args):
        """ChildWindowFromPointEx emulation - a direct child at a client point"""
        hwnd = args[0]
        x, y = self._read_signed_args(args, 1, 2)
        win = self.gui.windows.get(hwnd) if self.gui else None
        if win is None:
            return 0
        ox, oy = self.gui.client_origin(win)
        sx, sy = ox + x, oy + y
        for child in reversed(win.children):
            cwin = self.gui.windows.get(child)
            if cwin is None or (not cwin.visible and args[3] & 0x1):  # CWP_SKIPINVISIBLE
                continue
            cx, cy = self.gui.client_origin(cwin)
            border = self.gui._child_border(cwin)
            if cx - border <= sx < cx - border + cwin.width and \
                    cy - border <= sy < cy - border + cwin.height:
                return child
        for control in win.controls:
            if (control.visible or not args[3] & 0x1) and \
                    control.x <= x < control.x + control.width and \
                    control.y <= y < control.y + control.height:
                return control.hwnd
        cw, ch = self.gui.client_size(win)
        return hwnd if 0 <= x < cw and 0 <= y < ch else 0

    def ChildWindowFromPoint(self, args):
        return self.ChildWindowFromPointEx(args[:3] + [0])

    # ---------- Clipboard (shared by the emulated programs) ----------

    clipboard_data = {}
    clipboard_formats = {}

    def RegisterClipboardFormatA(self, args, wide=False):
        name = self._read_text(args[0], wide)
        formats = winapi.WinAPIHandler.clipboard_formats
        if name.lower() not in formats:
            formats[name.lower()] = 0xC100 + len(formats)
        return formats[name.lower()]

    def RegisterClipboardFormatW(self, args):
        return self.RegisterClipboardFormatA(args, wide=True)

    def OpenClipboard(self, args):
        self.clipboard_open = True
        return 1

    def CloseClipboard(self, args):
        self.clipboard_open = False
        return 1

    def EmptyClipboard(self, args):
        winapi.WinAPIHandler.clipboard_data = {}
        return 1

    def SetClipboardData(self, args):
        """SetClipboardData emulation - copies the global memory block"""
        fmt, handle = args[0], args[1]
        size = self.emu.heap_block_size(handle) if handle else None
        if size is None:
            return 0
        winapi.WinAPIHandler.clipboard_data[fmt] = bytes(self.emu.uc.mem_read(handle, size))
        return handle

    def GetClipboardData(self, args):
        data = winapi.WinAPIHandler.clipboard_data.get(args[0])
        if data is None:
            return 0
        block = self.emu.heap_alloc(len(data))
        self._mem_write(block, data)
        return block

    def IsClipboardFormatAvailable(self, args):
        return 1 if args[0] in winapi.WinAPIHandler.clipboard_data else 0
