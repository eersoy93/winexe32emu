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

"""WinAPIHandler mixin: Common controls (native child windows) and image lists"""

import struct

from unicorn import UcError


class ControlsMixin:
    """Common controls (native child windows) and image lists"""

    # ==================== COMMON CONTROLS (native child windows) ====================
    #
    # SysListView32, ToolbarWindow32, ReBarWindow32 and ComboBoxEx32 are child
    # windows (FakeWindow) whose window procedure is the emulator's own
    # NativeWndProc stub, so programs can subclass them (SetWindowLong
    # GWL_WNDPROC + CallWindowProc) like real controls. Their state lives in
    # win.nstate; the GUI thread draws it, the emulation thread changes it.

    NATIVE_CLASSES = {'SYSLISTVIEW32': 'LISTVIEW', 'TOOLBARWINDOW32': 'TOOLBAR',
                      'REBARWINDOW32': 'REBAR', 'COMBOBOXEX32': 'COMBOBOXEX',
                      'SYSHEADER32': 'HEADER', 'TOOLTIPS_CLASS32': 'TOOLTIPS',
                      'MSCTLS_TRACKBAR32': 'TRACKBAR', 'MSCTLS_UPDOWN32': 'UPDOWN',
                      'SYSTREEVIEW32': 'TREEVIEW', 'SYSTABCONTROL32': 'TAB'}
    WM_NOTIFY = 0x004E
    WM_SETFONT = 0x0030
    WM_GETFONT = 0x0031
    WM_LBUTTONDBLCLK = 0x0203
    WM_MOUSEWHEEL = 0x020A
    WM_SETFOCUS = 0x0007
    WM_KILLFOCUS = 0x0008
    WM_CONTEXTMENU = 0x007B

    def _native_stub(self):
        """Address of the NativeWndProc stub (window procedure of the emulated controls)"""
        stub = getattr(self, '_native_wndproc_addr', 0)
        if not stub:
            stub = self.emu.get_api_stub('user32.dll', 'NativeWndProc')
            self._native_wndproc_addr = stub
        return stub

    def NativeWndProc(self, args):
        """Window procedure of the emulated controls (reached through CallWindowProc
        or a dispatched message)"""
        return self._native_message(args[0], args[1], args[2], args[3])

    def _native_window(self, hwnd, kind=None):
        win = self.gui.windows.get(hwnd) if self.gui else None
        if win is None or win.native is None or (kind and win.native != kind):
            return None
        return win

    def _call_proc(self, proc, hwnd, msg, wParam, lParam):
        """Call a window procedure; the emulator's own one directly"""
        if not proc:
            return 0
        if proc == self._native_stub():
            return self._native_message(hwnd, msg, wParam, lParam)
        return self.emu.call_wndproc(proc, hwnd, msg, wParam, lParam)

    def _send(self, hwnd, msg, wParam=0, lParam=0):
        """SendMessageW from emulator code (goes through subclassed procedures)"""
        return self.SendMessageA([hwnd, msg, wParam & 0xFFFFFFFF, lParam & 0xFFFFFFFF], True)

    def _control_subclass(self, hwnd):
        """Program window procedure that subclasses a FakeControl, or 0"""
        proc = self.window_longs.get(hwnd, {}).get(-4, 0)
        return proc if proc and proc != self._native_stub() else 0

    def CallWindowProcA(self, args):
        """CallWindowProcA/W emulation"""
        return self._call_proc(args[0], args[1], args[2], args[3], args[4])

    def CallWindowProcW(self, args):
        return self.CallWindowProcA(args)

    def _parent_of(self, hwnd):
        if not self.gui:
            return 0
        if hwnd in self.gui.controls:
            return self.gui.controls[hwnd].parent_hwnd
        win = self.gui.windows.get(hwnd)
        if win is None:
            return 0
        if win.native in ('TOOLBAR', 'COMBOBOXEX') and win.nstate.get('notify'):
            return win.nstate['notify']
        return win.parent or 0

    def _notify(self, win, code, payload=b''):
        """Send WM_NOTIFY with NMHDR + payload to the control's parent; returns
        (result, buffer address) - the caller frees the buffer"""
        parent = self._parent_of(win.hwnd)
        size = 12 + len(payload)
        buf = self.emu.heap_alloc(max(size, 64))
        self.emu.uc.mem_write(buf, struct.pack('<IIi', win.hwnd, win.control_id & 0xFFFFFFFF,
                                               code) + payload)
        result = self._send(parent, self.WM_NOTIFY, win.control_id, buf) if parent else 0
        return result, buf

    def _notify_simple(self, win, code, payload=b''):
        result, buf = self._notify(win, code, payload)
        self.emu.heap_free(buf)
        return result

    def _create_native(self, kind, class_name, title, x, y, width, height, style, ex_style,
                       parent, control_id):
        """Create an emulated common control window"""
        if kind == 'TOOLTIPS' or not style & self.WS_CHILD:
            parent = 0
        hwnd = self.gui.create_window(title, x, y, max(width, 0), max(height, 0), style,
                                      owner=self, parent=parent)
        win = self.gui.windows[hwnd]
        win.class_name = class_name
        win.native = kind
        win.ex_style = ex_style
        win.control_id = control_id if style & self.WS_CHILD else 0
        win.wndproc = self._native_stub()
        state = {'font': 0}
        if kind == 'LISTVIEW':
            win.bg_color = (255, 255, 255)
            state.update(columns=[], items=[], top=0, focus=-1, mark=-1, imagelists={},
                         ex_style=0, redraw=True, header=0, dirty=True, hscroll=0)
            header = self.gui.create_window('', 0, 0, 0, 0, self.WS_CHILD, owner=self,
                                            parent=0)
            hwin = self.gui.windows[header]
            hwin.class_name, hwin.native, hwin.wndproc = 'SysHeader32', 'HEADER', win.wndproc
            hwin.nstate = {'listview': hwnd, 'font': 0}
            hwin.parent_listview = hwnd
            state['header'] = header
        elif kind == 'TOOLBAR':
            state.update(buttons=[], bitmaps=[], imagelist=0, bitmap_size=(16, 15),
                         button_size=None, strings=[], pressed=-1, ex_style=0,
                         notify=parent, struct_size=20, max_text_rows=1)
        elif kind == 'TREEVIEW':
            win.bg_color = (255, 255, 255)
            state.update(self._tv_new_state())
        elif kind == 'REBAR':
            state.update(bands=[], notify=parent)
        elif kind == 'COMBOBOXEX':
            state.update(items=[], sel=-1, imagelist=0, drop_height=max(height, 100),
                         dropped=False, edit=0, notify=parent)
            win.height = self.COMBOBOX_BOX_H
            if style & 0x3 == 0x2:  # CBS_DROPDOWN: an edit control to type into
                edit = self.gui.create_control(hwnd, 'EDIT', '', 22, 2, max(width - 42, 10),
                                               self.COMBOBOX_BOX_H - 4, 0x50000080,
                                               control_id=1001)
                state['edit'] = edit
        win.nstate = state
        if kind == 'TOOLTIPS':
            win.visible = False
        return hwnd

    COMBOBOX_BOX_H = 22

    def _native_message(self, hwnd, msg, wParam, lParam):
        """Default processing of a message by an emulated control"""
        if self.gui and hwnd in self.gui.controls:
            return self._control_default(hwnd, msg, wParam, lParam)
        win = self.gui.windows.get(hwnd) if self.gui else None
        if win is None or win.native is None:
            return self.DefWindowProcA([hwnd, msg, wParam, lParam])
        if msg == self.WM_SETFONT:
            win.nstate['font'] = wParam
            edit = win.nstate.get('edit')
            if edit in self.gui.controls:
                self._control_message(self.gui.controls[edit], msg, wParam, lParam)
            return 0
        if msg == self.WM_GETFONT:
            return win.nstate.get('font', 0)
        if msg in (0x2005, 0x2006):  # CCM_SETUNICODEFORMAT / CCM_GETUNICODEFORMAT
            return 1
        if msg == 0x2007:  # CCM_GETVERSION
            return 6
        if msg == 0x2008:  # CCM_SETVERSION
            return 6
        handler = {'LISTVIEW': self._listview_message, 'TREEVIEW': self._treeview_message,
                   'TOOLBAR': self._toolbar_message,
                   'REBAR': self._rebar_message, 'COMBOBOXEX': self._comboboxex_message,
                   'HEADER': self._header_message}.get(win.native)
        result = handler(win, msg, wParam, lParam) if handler else None
        if result is not None:
            return result & 0xFFFFFFFF
        if msg in (self.WM_NOTIFY, self.WM_COMMAND) and win.native in ('TOOLBAR', 'REBAR',
                                                                       'COMBOBOXEX'):
            # Notifications of the controls inside go on to the parent
            parent = self._parent_of(hwnd)
            return self._send(parent, msg, wParam, lParam) if parent else 0
        if msg == self.WM_SIZE or msg == self.WM_PAINT or msg == 0x14:  # WM_ERASEBKGND
            return 0 if msg != 0x14 else 1
        return self.DefWindowProcA([hwnd, msg, wParam, lParam])

    def _control_default(self, hwnd, msg, wParam, lParam):
        """Default procedure of a FakeControl (subclassed controls call it)"""
        control = self.gui.controls[hwnd]
        parent = self.gui.windows.get(control.parent_hwnd)
        if (control.class_name == 'EDIT' and parent is not None and parent.native == 'LISTVIEW'
                and msg == self.WM_KEYDOWN and wParam in (0x0D, 0x1B)):
            self._lv_end_edit(parent, wParam == 0x0D)
            return 0
        if (control.class_name == 'EDIT' and parent is not None and
                parent.native == 'COMBOBOXEX'):
            if msg == self.WM_KEYDOWN and wParam in (0x0D, 0x1B):  # VK_RETURN, VK_ESCAPE
                self._comboboxex_end_edit(parent, 2 if wParam == 0x0D else 3)
                return 0
            if msg in (self.WM_KEYDOWN, self.WM_CHAR, self.WM_KEYUP):
                return 0
        if msg in (self.WM_KEYDOWN, self.WM_CHAR, self.WM_KEYUP, self.WM_LBUTTONDOWN,
                   self.WM_LBUTTONUP, self.WM_MOUSEMOVE, self.WM_SETFOCUS, self.WM_KILLFOCUS):
            return 0
        return self._control_message(control, msg, wParam, lParam, True)

    def _read_struct(self, address, fmt):
        return struct.unpack(fmt, self.emu.uc.mem_read(address, struct.calcsize(fmt)))

    def _copy_text_out(self, buffer, size, text):
        """Copy text into a wide buffer of size characters (truncated, NUL-terminated)"""
        if buffer and size > 0:
            data = text[:size - 1].encode('utf-16-le') + b'\x00\x00'
            self._mem_write(buffer, data)
            return min(len(text), size - 1)
        return 0

    def _invalidate_native(self, win):
        if win.native == 'LISTVIEW':
            for item in win.nstate['items']:
                item['cache'] = {}
            win.nstate['dirty'] = True

    # ---------- Image lists ----------

    def _imagelist(self, handle):
        return self.imagelists.get(handle)

    def ImageList_Create(self, args):
        """ImageList_Create emulation"""
        cx, cy, flags = args[0], args[1], args[2]
        handle = self.get_next_handle()
        self.imagelists[handle] = {'cx': cx, 'cy': cy, 'flags': flags, 'images': []}
        return handle

    def ImageList_Destroy(self, args):
        return 1 if self.imagelists.pop(args[0], None) is not None else 0

    def ImageList_GetImageCount(self, args):
        imagelist = self._imagelist(args[0])
        return len(imagelist['images']) if imagelist else 0

    def ImageList_SetImageCount(self, args):
        imagelist = self._imagelist(args[0])
        if not imagelist:
            return 0
        images = imagelist['images'][:args[1]]
        images += [None] * (args[1] - len(images))
        imagelist['images'] = images
        return 1

    def _split_bitmap(self, imagelist, hbm, mask_color=None, hbm_mask=0):
        """Cut a bitmap into images of the list's width -> list of (w, h, rgba)"""
        bitmap = self.gdi_objects.get(hbm)
        rgb = self._bitmap_rgb(hbm)
        if rgb is None:
            return []
        width, height = bitmap['width'], bitmap['height']
        cx = imagelist['cx'] or width
        cy = min(imagelist['cy'] or height, height)
        mask_rgb = self._bitmap_rgb(hbm_mask) if hbm_mask else None
        images = []
        for left in range(0, max(width - cx + 1, 1), cx):
            out = bytearray(cx * cy * 4)
            for row in range(cy):
                for col in range(min(cx, width - left)):
                    src = ((row * width) + left + col) * 3
                    r, g, b = rgb[src], rgb[src + 1], rgb[src + 2]
                    alpha = 255
                    if mask_color is not None and (r, g, b) == mask_color:
                        alpha = 0
                    elif mask_rgb is not None and mask_rgb[src]:
                        alpha = 0
                    dst = (row * cx + col) * 4
                    out[dst:dst + 4] = bytes((r, g, b, alpha))
            images.append((cx, cy, bytes(out)))
        return images

    def ImageList_Add(self, args):
        """ImageList_Add emulation - index of the first new image"""
        imagelist = self._imagelist(args[0])
        if not imagelist:
            return 0xFFFFFFFF
        index = len(imagelist['images'])
        imagelist['images'] = imagelist['images'] + self._split_bitmap(imagelist, args[1],
                                                                       hbm_mask=args[2])
        return index

    def ImageList_AddMasked(self, args):
        """ImageList_AddMasked emulation (crMask color is transparent)"""
        imagelist = self._imagelist(args[0])
        if not imagelist:
            return 0xFFFFFFFF
        index = len(imagelist['images'])
        imagelist['images'] = imagelist['images'] + self._split_bitmap(
            imagelist, args[1], mask_color=self._colorref_to_rgb(args[2]))
        return index

    def ImageList_ReplaceIcon(self, args):
        """ImageList_ReplaceIcon emulation - icons are drawn as placeholders"""
        imagelist = self._imagelist(args[0])
        if not imagelist:
            return 0xFFFFFFFF
        index = args[1] if args[1] < 0x80000000 else -1
        images = list(imagelist['images'])
        icon = self.icons.get(args[2])
        image = icon if icon else None
        if 0 <= index < len(images):
            images[index] = image
        else:
            images.append(image)
            index = len(images) - 1
        imagelist['images'] = images
        return index

    def ImageList_Remove(self, args):
        imagelist = self._imagelist(args[0])
        if not imagelist:
            return 0
        if args[1] == 0xFFFFFFFF:
            imagelist['images'] = []
        elif args[1] < len(imagelist['images']):
            images = list(imagelist['images'])
            del images[args[1]]
            imagelist['images'] = images
        return 1

    def ImageList_GetIconSize(self, args):
        imagelist = self._imagelist(args[0])
        if not imagelist:
            return 0
        self._mem_write(args[1], struct.pack('<i', imagelist['cx']))
        self._mem_write(args[2], struct.pack('<i', imagelist['cy']))
        return 1

    def ImageList_SetBkColor(self, args):
        return 0xFFFFFFFF  # CLR_NONE

    def ImageList_Draw(self, args):
        return 1

    def ImageList_GetIcon(self, args):
        return self.get_next_handle()

    def InitCommonControlsEx(self, args):
        """InitCommonControlsEx emulation - the control classes always exist"""
        return 1

    def DllGetVersion(self, args):
        """DllGetVersion emulation (comctl32/shell32): version 6.0"""
        try:
            size = struct.unpack('<I', self.emu.uc.mem_read(args[0], 4))[0]
        except UcError:
            return 0x80070057  # E_INVALIDARG
        if size < 20:
            return 0x80070057
        self._mem_write(args[0] + 4, struct.pack('<IIII', 6, 0, 2900, 2))
        return 0

    def CreateStatusWindowW(self, args):
        """CreateStatusWindowW emulation"""
        style, lpszText, hwndParent, wID = args[0], args[1], args[2], args[3]
        text = self.read_wide_string(lpszText) if lpszText else ''
        if not (self.gui and self.gui.running) or hwndParent not in self.gui.windows:
            return 0
        return self._create_status_bar(hwndParent, text, style, wID)
