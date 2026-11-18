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

from .. import config, resources, winapi
from ..logger import log


class User32MiscMixin:
    """Strings, bitmaps, dialog units, monitors, window classes; the clipboard"""

    # ---------- Strings, bitmaps, dialog units, monitors ----------

    def LoadStringW(self, args):
        """LoadStringW emulation (cchBufferMax 0: a pointer to the resource string)"""
        hInstance, uID, lpBuffer, cchBufferMax = args[0], args[1] & 0xFFFF, args[2], args[3]
        resource = self._find_resource(6, uID // 16 + 1, hInstance)
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

    IMAGE_BITMAP, IMAGE_ICON, IMAGE_CURSOR = 0, 1, 2
    LR_LOADFROMFILE = 0x10

    def _load_image_file(self, path, image_type):
        """LoadImage(LR_LOADFROMFILE): a .bmp bitmap or a .ico icon"""
        host = self.resolve_drive_path(path)
        try:
            with open(host, 'rb') as f:
                data = f.read()
        except (OSError, TypeError):
            self._last_error = 2  # ERROR_FILE_NOT_FOUND
            return 0
        if image_type == self.IMAGE_BITMAP:
            decoded = self._decode_dib(data[14:]) if data[:2] == b'BM' else None
            if decoded is None:
                self._last_error = 13  # ERROR_INVALID_DATA
                return 0
            return self._new_bitmap(decoded[0], decoded[1], 32, decoded[2])
        if image_type == self.IMAGE_ICON:
            image = None
            try:
                count = struct.unpack_from('<H', data, 4)[0]
                if count:
                    size, offset = struct.unpack_from('<II', data, 6 + 8)
                    image = resources._icon_image_rgba(data[offset:offset + size])
            except struct.error:
                image = None
            if image is None:
                self._last_error = 13  # ERROR_INVALID_DATA
                return 0
            handle = self.get_next_handle()
            self.icons[handle] = image
            return handle
        self._last_error = 120  # ERROR_CALL_NOT_IMPLEMENTED (.cur files)
        return 0

    def _stretch_bitmap(self, handle, cx, cy):
        """Stretch a new bitmap to cx x cy (LoadImage; 0 keeps that side)"""
        bmp = self.gdi_objects[handle]
        width, height = cx or bmp['width'], cy or bmp['height']
        if (width, height) == (bmp['width'], bmp['height']):
            return
        sx, sy = width / bmp['width'], height / bmp['height']
        for shape in bmp['shapes']:
            x, y = shape['pos']
            shape['pos'] = (round(x * sx), round(y * sy))
            shape['size'] = (round(shape['size'][0] * sx), round(shape['size'][1] * sy))
        bmp['width'], bmp['height'] = width, height

    def LoadImageA(self, args, wide=False):
        """LoadImageA/W emulation - a bitmap, icon or cursor of the program's
        resources (or a system one with hInst NULL), or one of a file"""
        hInst, name, image_type, cx, cy, fuLoad = args[:6]
        log_name = (self._read_text(name, wide) if name >= 0x10000 else name)
        log.debug(f"LoadImage(0x{hInst:x}, {log_name!r}, {image_type}, "
                  f"{cx}, 0x{fuLoad:x})")
        if fuLoad & self.LR_LOADFROMFILE:
            handle = self._load_image_file(self._read_text(name, wide), image_type)
        elif image_type == self.IMAGE_BITMAP:
            handle = (self.LoadBitmapW if wide else self.LoadBitmapA)([hInst, name])
        else:
            handle = None
        if handle is not None:
            if handle and image_type == self.IMAGE_BITMAP:
                self._stretch_bitmap(handle, cx, cy)
            return handle
        if image_type == self.IMAGE_CURSOR:
            return self.LoadCursorA([hInst, name], wide)
        if image_type == self.IMAGE_ICON:
            if not hInst or not self._is_own_module(hInst) or not cx:
                return self.LoadIconA([hInst, name], wide)
            image = self._load_icon_image(self._resource_name_key(name, wide), cx, hInst)
            if image is None:
                self._last_error = 1813  # ERROR_RESOURCE_TYPE_NOT_FOUND
                return 0
            handle = self.get_next_handle()
            self.icons[handle] = image
            return handle
        self._last_error = 87  # ERROR_INVALID_PARAMETER
        return 0

    def LoadImageW(self, args):
        """LoadImageW emulation"""
        return self.LoadImageA(args, wide=True)

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

    # GCL_* index -> class field (registered_classes entry key)
    CLASS_LONG_FIELDS = {-8: 'menu', -10: 'background', -12: 'cursor', -14: 'icon',
                         -16: 'hInstance', -24: 'wndproc', -26: 'style', -34: 'icon_small'}

    def _class_entry(self, hwnd):
        """Class data of a window (a dict changed by SetClassLong), or None"""
        name = self._window_class_name(hwnd) if self.gui else None
        if name is None:
            return None
        wndclass = self.registered_classes.get(name)
        if wndclass is None:
            # The system classes: SetClassLong changes them for this process
            wndclass = self.system_class_data.setdefault(name.upper(), {'style': 0x8})
        return wndclass

    def _class_long(self, args, set_value=False):
        hwnd, index = args[0], args[1] - (1 << 32 if args[1] & 0x80000000 else 0)
        wndclass = self._class_entry(hwnd)
        if wndclass is None:
            self._last_error = 1400  # ERROR_INVALID_WINDOW_HANDLE
            return 0
        if index == -32:  # GCW_ATOM
            return wndclass.get('atom', 0)
        field = self.CLASS_LONG_FIELDS.get(index, index)
        old = wndclass.get(field, 0)
        if isinstance(old, str):
            old = 0  # A menu name string is not handed back
        if set_value:
            wndclass[field] = args[2]
        self._last_error = 0
        return old & 0xFFFFFFFF

    def GetClassLongA(self, args):
        """GetClassLongA/W emulation"""
        return self._class_long(args)

    def GetClassLongW(self, args):
        return self._class_long(args)

    def SetClassLongA(self, args):
        """SetClassLongA/W emulation - changes the window's class; returns the
        previous value"""
        log.debug(f"SetClassLong(0x{args[0]:x}, {args[1]:#x}, 0x{args[2]:x})")
        return self._class_long(args, set_value=True)

    def SetClassLongW(self, args):
        return self.SetClassLongA(args)

    SC_SIZE, SC_MOVE, SC_MINIMIZE, SC_MAXIMIZE = 0xF000, 0xF010, 0xF020, 0xF030
    SC_CLOSE, SC_RESTORE = 0xF060, 0xF120

    def GetSystemMenu(self, args):
        """GetSystemMenu emulation - the window menu of a window (its copy
        bRevert TRUE resets to the standard one)"""
        hwnd, bRevert = args[0], args[1]
        if not self.gui or hwnd not in self.gui.windows:
            self._last_error = 1400  # ERROR_INVALID_WINDOW_HANDLE
            return 0
        handle = self.system_menus.get(hwnd)
        if bRevert:
            if handle:
                self.menus[handle] = self._standard_system_menu()
            return 0
        if handle is None:
            handle = self.get_next_handle()
            self.menus[handle] = self._standard_system_menu()
            self.system_menus[hwnd] = handle
        return handle

    def _standard_system_menu(self):
        items = [('&Restore', self.SC_RESTORE), ('&Move', self.SC_MOVE),
                 ('&Size', self.SC_SIZE), ('Mi&nimize', self.SC_MINIMIZE),
                 ('Ma&ximize', self.SC_MAXIMIZE), (None, 0), ('&Close\tAlt+F4', self.SC_CLOSE)]
        return [{'flags': self.MF_SEPARATOR if text is None else 0, 'id': cmd,
                 'text': text or '', 'submenu': 0} for text, cmd in items]

    def GetMessagePos(self, args):
        """GetMessagePos emulation - cursor position of the last message
        retrieved (screen coordinates, x in the low word)"""
        x, y = self.last_message_pos
        return ((y & 0xFFFF) << 16) | (x & 0xFFFF)

    def MessageBoxIndirectA(self, args, wide=False):
        """MessageBoxIndirectA/W emulation (MSGBOXPARAMS)"""
        try:
            (_, _, _, lpszText, lpszCaption, dwStyle) = struct.unpack(
                '<6I', self.emu.uc.mem_read(args[0], 24))
        except UcError:
            return 0
        text = self._read_text(lpszText, wide) if lpszText else ""
        caption = self._read_text(lpszCaption, wide) if lpszCaption else "Error"
        return self._message_box(text, caption, dwStyle)

    def MessageBoxIndirectW(self, args):
        return self.MessageBoxIndirectA(args, wide=True)

    HWND_BROADCAST = 0xFFFF

    def SendMessageTimeoutA(self, args, wide=False):
        """SendMessageTimeoutA/W emulation - messages are delivered at once (no
        window of the emulator hangs); broadcasts reach the top-level windows
        of this process"""
        hwnd, msg, wParam, lParam, _, _, lpdwResult = args[:7]
        if hwnd == self.HWND_BROADCAST:
            targets = [h for h, w in list(self.gui.windows.items())
                       if not w.parent and w.owner is self] if self.gui else []
            for target in targets:
                self.SendMessageA([target, msg, wParam, lParam], wide)
            result = 0
        elif self.gui and (hwnd in self.gui.windows or hwnd in self.gui.controls):
            result = self.SendMessageA([hwnd, msg, wParam, lParam], wide)
        else:
            self._last_error = 1400  # ERROR_INVALID_WINDOW_HANDLE
            return 0
        if lpdwResult:
            self._mem_write(lpdwResult, struct.pack('<I', result & 0xFFFFFFFF))
        return 1

    def SendMessageTimeoutW(self, args):
        return self.SendMessageTimeoutA(args, wide=True)

    def FindWindowExA(self, args, wide=False):
        """FindWindowExA/W emulation - a child of hwndParent (the desktop's
        top-level windows if NULL) after hwndChildAfter, by class and/or title"""
        hwndParent, hwndChildAfter, lpszClass, lpszWindow = args[:4]
        if lpszClass and lpszClass < 0x10000:
            class_name = self.atoms.get(lpszClass)
            if class_name is None:
                self._last_error = 1411  # ERROR_CLASS_DOES_NOT_EXIST
                return 0
        else:
            class_name = self._read_text(lpszClass, wide) if lpszClass else None
        title = self._read_text(lpszWindow, wide) if lpszWindow else None
        if not self.gui:
            return 0
        with self.gui.lock:
            if hwndParent in (0, self.GetDesktopWindow([])):
                order = list(reversed(self.gui.z_order))
                order += [h for h in self.gui.windows if h not in order]
                candidates = [h for h in order
                              if h in self.gui.windows and not self.gui.windows[h].parent]
            else:
                candidates = self._child_handles(hwndParent)
            if hwndChildAfter:
                if hwndChildAfter not in candidates:
                    return 0
                candidates = candidates[candidates.index(hwndChildAfter) + 1:]
            for hwnd in candidates:
                if class_name is not None and \
                        (self._window_class_name(hwnd) or '').lower() != class_name.lower():
                    continue
                if title is not None and self._window_text(hwnd) != title:
                    continue
                log.debug(f"FindWindowEx({class_name!r}, {title!r}) -> 0x{hwnd:x}")
                return hwnd
        self._last_error = 0
        return 0

    def FindWindowExW(self, args):
        return self.FindWindowExA(args, wide=True)

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
