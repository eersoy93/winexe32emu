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

"""WinAPIHandler mixin: Window messages: SendMessage, PostMessage, timers, message
loop, DefWindowProc"""

import struct
import time

from unicorn import UcError

from .. import config, winapi
from ..logger import log


class MessagesMixin:
    """Window messages: SendMessage, PostMessage, timers, message loop, DefWindowProc"""

    def SendMessageA(self, args, wide=False):
        """SendMessageA/W emulation"""
        hWnd = args[0]
        Msg = args[1]
        wParam = args[2]
        lParam = args[3]

        msg_names = {
            0x0001: "WM_CREATE", 0x0002: "WM_DESTROY", 0x000F: "WM_PAINT",
            0x0010: "WM_CLOSE", 0x0012: "WM_QUIT", 0x0100: "WM_KEYDOWN",
            0x0111: "WM_COMMAND", 0x000C: "WM_SETTEXT", 0x000D: "WM_GETTEXT",
        }
        msg_name = msg_names.get(Msg, f"0x{Msg:04x}")

        log.debug(f"SendMessageA(0x{hWnd:x}, {msg_name}, 0x{wParam:x}, 0x{lParam:x})")

        target_thread = self._window_thread(hWnd)
        if target_thread not in (None, self.emu.current_thread.tid):
            return self._send_to_thread(target_thread, [hWnd, Msg, wParam, lParam], wide)

        # Text messages are handled directly (also work for controls)
        WM_SETTEXT, WM_GETTEXT, WM_GETTEXTLENGTH = 0x000C, 0x000D, 0x000E
        if Msg in (WM_SETTEXT, WM_GETTEXT, WM_GETTEXTLENGTH) and self.gui and \
                hWnd in self.gui.controls and self._control_subclass(hWnd):
            return self.emu.call_wndproc(self._control_subclass(hWnd), hWnd, Msg, wParam, lParam)
        if Msg == WM_SETTEXT and self._text_wndproc(hWnd):
            # A program's window class (a custom static text, say) sees its new
            # text and repaints; DefWindowProc stores it
            return self._call_proc(self._text_wndproc(hWnd), hWnd, Msg, wParam, lParam)
        if Msg == WM_SETTEXT:
            return self.SetWindowTextA([hWnd, lParam], wide)
        if Msg == WM_GETTEXT:
            return self.GetWindowTextA([hWnd, lParam, wParam], wide)
        if Msg == WM_GETTEXTLENGTH:
            return len(self._window_text(hWnd))

        # Control messages (LISTBOX, COMBOBOX, checkbox BUTTON); a subclassed
        # control gets them through the program's window procedure
        if self.gui and hWnd in self.gui.controls:
            subclass = self._control_subclass(hWnd)
            if subclass:
                return self.emu.call_wndproc(subclass, hWnd, Msg, wParam, lParam)
            return self._control_message(self.gui.controls[hWnd], Msg, wParam, lParam, wide)

        # Dialogs: the dialog procedure (or internal handler), then DefDlgProc
        if self.gui and hWnd in self.dialogs:
            return self._send_dialog_message(hWnd, Msg, wParam, lParam)

        # Other messages: deliver synchronously to the window's WndProc
        wndproc = self._find_wndproc_for_hwnd(hWnd)
        if wndproc:
            return self._call_proc(wndproc, hWnd, Msg, wParam, lParam)
        return 0

    SS_BITMAP, SS_REALSIZECONTROL, SS_CENTERIMAGE = 0xE, 0x40, 0x200

    def _set_static_bitmap(self, control, hbm):
        """Show a bitmap in an SS_BITMAP static; the control takes the
        bitmap's size (unless SS_CENTERIMAGE or SS_REALSIZECONTROL)"""
        bmp = self.gdi_objects.get(hbm) if hbm else None
        if bmp is not None and bmp['type'] != 'bitmap':
            bmp = None
        control.bitmap_handle = hbm if bmp is not None else 0
        control.bitmap = bmp
        if bmp is not None and control.style & 0x1F == self.SS_BITMAP and \
                not control.style & (self.SS_REALSIZECONTROL | self.SS_CENTERIMAGE):
            control.width, control.height = bmp['width'], bmp['height']

    def _window_thread(self, hwnd):
        """Guest thread that created a window of this process (a control: its
        parent's); None if unknown, another process's, or the thread is gone"""
        if not self.gui:
            return None
        win = self.gui.windows.get(hwnd)
        if win is None:
            control = self.gui.controls.get(hwnd)
            win = self.gui.windows.get(control.parent_hwnd) if control is not None else None
        if win is None or win.owner is not self:
            return None
        thread = win.thread_id
        return thread if thread in self.emu.threads else None

    def _send_to_thread(self, thread, args, wide):
        """SendMessage to a window of another thread: that thread runs the
        window procedure when it next waits for messages; the sender waits
        (and handles the messages sent to its own windows meanwhile)"""
        request = {'args': args, 'wide': wide, 'done': False, 'result': 0}
        with self.message_lock:
            self.sent_messages.setdefault(thread, []).append(request)
        self.emu.wake_threads()

        def finished():
            if not request['done']:
                self._process_sent_messages()
            return request['done'] or thread not in self.emu.threads
        self.emu.wait_until(finished)
        return request['result']

    def _process_sent_messages(self):
        """Run the window procedures for the messages other threads sent to
        the calling thread's windows"""
        thread = self.emu.current_thread.tid
        while True:
            with self.message_lock:
                queue = self.sent_messages.get(thread)
                if not queue:
                    return
                request = queue.pop(0)
            try:
                request['result'] = self.SendMessageA(request['args'], request['wide'])
            finally:
                request['done'] = True
                self.emu.wake_threads()

    def SendMessageW(self, args):
        return self.SendMessageA(args, wide=True)

    def _text_wndproc(self, hwnd):
        """Window procedure that gets WM_SETTEXT for hwnd: that of a window of
        a program's own class (not a dialog or an emulated control), else 0"""
        win = self.gui.windows.get(hwnd) if self.gui else None
        if win is None or win.native or hwnd in self.dialogs or win.owner is not self:
            return 0
        return self._find_wndproc_for_hwnd(hwnd)

    PBM_SETRANGE, PBM_SETPOS, PBM_DELTAPOS, PBM_SETSTEP = 0x401, 0x402, 0x403, 0x404
    PBM_STEPIT, PBM_SETRANGE32, PBM_GETRANGE, PBM_GETPOS = 0x405, 0x406, 0x407, 0x408
    PBM_SETBARCOLOR, PBM_SETBKCOLOR = 0x409, 0x2001  # PBM_SETBKCOLOR = CCM_SETBKCOLOR

    def _progress_bar_message(self, control, Msg, wParam, lParam):
        """Progress bar (msctls_progress32) messages; None if not one of them"""
        def signed(value):
            return value - (1 << 32) if value & 0x80000000 else value

        def set_pos(pos):
            prev = control.scroll_pos
            control.scroll_pos = max(control.scroll_min, min(pos, control.scroll_max))
            return prev & 0xFFFFFFFF

        def set_range(low, high):
            prev = ((control.scroll_max & 0xFFFF) << 16) | (control.scroll_min & 0xFFFF)
            control.scroll_min, control.scroll_max = low, high
            control.scroll_pos = max(low, min(control.scroll_pos, high))
            return prev

        def colorref(value):
            if value == 0xFF000000:  # CLR_DEFAULT
                return None
            return (value & 0xFF, (value >> 8) & 0xFF, (value >> 16) & 0xFF)

        def to_colorref(color):
            return 0xFF000000 if color is None else color[0] | color[1] << 8 | color[2] << 16

        if Msg == self.PBM_SETRANGE:
            return set_range(lParam & 0xFFFF, (lParam >> 16) & 0xFFFF)
        if Msg == self.PBM_SETRANGE32:
            return set_range(signed(wParam), signed(lParam))
        if Msg == self.PBM_SETPOS:
            return set_pos(signed(wParam))
        if Msg == self.PBM_DELTAPOS:
            return set_pos(control.scroll_pos + signed(wParam))
        if Msg == self.PBM_SETSTEP:
            prev, control.progress_step = control.progress_step, signed(wParam)
            return prev & 0xFFFFFFFF
        if Msg == self.PBM_STEPIT:
            pos = control.scroll_pos + control.progress_step
            if pos > control.scroll_max:  # Wraps around like the real control
                pos = control.scroll_min + (pos - control.scroll_max)
            return set_pos(pos)
        if Msg == self.PBM_GETRANGE:
            if lParam:
                self._mem_write(lParam, struct.pack('<ii', control.scroll_min,
                                                    control.scroll_max))
            return (control.scroll_min if wParam else control.scroll_max) & 0xFFFFFFFF
        if Msg == self.PBM_GETPOS:
            return control.scroll_pos & 0xFFFFFFFF
        if Msg == self.PBM_SETBARCOLOR:
            prev, control.progress_bar_color = control.progress_bar_color, colorref(lParam)
            return to_colorref(prev)
        if Msg == self.PBM_SETBKCOLOR:
            prev, control.progress_bk_color = control.progress_bk_color, colorref(lParam)
            return to_colorref(prev)
        return None

    BM_CLICK = 0x00F5

    def _click_button(self, control):
        """BM_CLICK: the button acts as if clicked (an automatic check box or
        radio button changes its state) and its parent gets WM_COMMAND with
        BN_CLICKED at once"""
        style = control.style & 0xF
        parent = control.parent_hwnd
        if control.class_name == 'CHECKBOX':
            if style == 0x3:  # BS_AUTOCHECKBOX
                control.checked = not control.checked
            elif style == 0x9 and self.gui and parent in self.gui.windows:  # BS_AUTORADIOBUTTON
                with self.gui.lock:
                    self.gui._check_auto_radio(self.gui.windows[parent], control)
        if parent:
            wParam = ((self.BN_CLICKED & 0xFFFF) << 16) | (control.control_id & 0xFFFF)
            self.SendMessageA([parent, self.WM_COMMAND, wParam, control.hwnd])
        return 0

    def _control_message(self, control, Msg, wParam, lParam, wide=False):
        """Handle a message sent to a child control (emulation thread).

        Item lists are swapped in as new list objects so the GUI thread can
        keep painting the snapshot it already holds.
        """
        items = control.items

        if control.class_name == 'STATUSBAR':
            result = self._status_bar_message(control, Msg, wParam, lParam, wide)
            if result is not None:
                return result
        elif control.class_name == 'PROGRESSBAR':
            result = self._progress_bar_message(control, Msg, wParam, lParam)
            if result is not None:
                return result

        WM_SETFONT, WM_GETFONT = 0x0030, 0x0031
        if Msg == WM_SETFONT:
            font = self.gdi_objects.get(wParam)
            control.font_handle = wParam
            control.font = font if font and font['type'] == 'font' else None
            return 0
        if Msg == WM_GETFONT:
            return control.font_handle

        if control.class_name == 'EDIT' or (control.class_name == 'COMBOBOX' and
                                            Msg in (0x0140, 0x0141, 0x0142)):
            result = self._edit_message(control, Msg, wParam, lParam, wide)
            if result is not None:
                return result

        if control.class_name == 'STATIC' and Msg in (0x0170, 0x0171, 0x0172, 0x0173):
            # STM_SETICON, STM_GETICON, STM_SETIMAGE, STM_GETIMAGE
            previous = control.icon_handle
            if Msg == 0x0170 or (Msg == 0x0172 and wParam == 1):  # IMAGE_ICON
                handle = wParam if Msg == 0x0170 else lParam
                control.icon_handle = handle
                control.icon = self.icons.get(handle)
                return previous
            if Msg == 0x0172 and wParam == 0:  # IMAGE_BITMAP
                previous = control.bitmap_handle
                self._set_static_bitmap(control, lParam)
                return previous
            if Msg == 0x0173 and wParam == 0:
                return control.bitmap_handle
            return previous if Msg == 0x0171 or wParam == 1 else 0

        # ----- Checkbox / button messages -----
        if Msg == self.BM_GETCHECK:
            return 1 if control.checked else 0
        if Msg == self.BM_SETCHECK:
            control.checked = bool(wParam)
            return 0
        if Msg == self.BM_CLICK and control.class_name in ('BUTTON', 'CHECKBOX'):
            return self._click_button(control)

        # ----- Listbox messages -----
        if Msg == self.LB_ADDSTRING:
            control.items = items + [self._read_text(lParam, wide)]
            return len(control.items) - 1
        if Msg == self.LB_INSERTSTRING:
            index = len(items) if wParam >= len(items) else wParam
            control.items = items[:index] + [self._read_text(lParam, wide)] + items[index:]
            return index
        if Msg == self.LB_DELETESTRING:
            if wParam >= len(items):
                return self.LB_ERR
            control.items = items[:wParam] + items[wParam + 1:]
            if control.sel_index >= len(control.items):
                control.sel_index = -1
            return len(control.items)
        if Msg == self.LB_RESETCONTENT:
            control.items = []
            control.sel_index = -1
            control.top_index = 0
            return 0
        if Msg == self.LB_GETCOUNT:
            return len(items)
        if Msg == self.LB_GETCURSEL:
            return control.sel_index if control.sel_index >= 0 else self.LB_ERR
        if Msg == self.LB_SETCURSEL:
            if wParam == 0xFFFFFFFF:
                control.sel_index = -1
                return self.LB_ERR
            if wParam < len(items):
                control.sel_index = wParam
                # Scroll the selected item into view
                if control.class_name == "LISTBOX":
                    rows = max(1, (control.height - 2) // self.gui.LISTBOX_ITEM_H)
                    if wParam < control.top_index:
                        control.top_index = wParam
                    elif wParam >= control.top_index + rows:
                        control.top_index = wParam - rows + 1
                return wParam
            return self.LB_ERR
        if Msg == self.LB_GETTEXT:
            if wParam >= len(items):
                return self.LB_ERR
            text = items[wParam]
            if lParam:
                if wide:
                    self.emu.uc.mem_write(lParam, text.encode('utf-16-le') + b'\x00\x00')
                else:
                    data = text.encode(config.ANSI_CODEPAGE, errors='replace')
                    self.emu.uc.mem_write(lParam, data + b'\x00')
            return len(text)
        if Msg == self.LB_GETTEXTLEN:
            return len(items[wParam]) if wParam < len(items) else self.LB_ERR

        # ----- Combobox messages (same item list as listbox) -----
        combo_to_list = {
            self.CB_ADDSTRING: self.LB_ADDSTRING,
            self.CB_DELETESTRING: self.LB_DELETESTRING,
            self.CB_RESETCONTENT: self.LB_RESETCONTENT,
            self.CB_GETCOUNT: self.LB_GETCOUNT,
            self.CB_GETCURSEL: self.LB_GETCURSEL,
            self.CB_SETCURSEL: self.LB_SETCURSEL,
            self.CB_GETLBTEXT: self.LB_GETTEXT,
            self.CB_GETLBTEXTLEN: self.LB_GETTEXTLEN,
        }
        if Msg in combo_to_list:
            result = self._control_message(control, combo_to_list[Msg], wParam, lParam, wide)
            if (Msg == self.CB_SETCURSEL and control.class_name == 'COMBOBOX' and
                    control.style & 0x3 in (1, 2) and 0 <= control.sel_index < len(control.items)):
                control.text = control.items[control.sel_index]
                control.select_all()
            return result
        if control.class_name == 'COMBOBOX':
            if Msg == 0x014A:  # CB_INSERTSTRING
                return self._control_message(control, self.LB_INSERTSTRING, wParam, lParam, wide)
            if Msg in (0x014C, 0x0158):  # CB_FINDSTRING, CB_FINDSTRINGEXACT
                text = self._read_text(lParam, wide).lower()
                start = wParam + 1 if wParam < 0x80000000 else 0
                order = list(range(start, len(control.items))) + list(range(0, start))
                for index in order:
                    item = control.items[index].lower()
                    if item == text or (Msg == 0x014C and item.startswith(text)):
                        return index
                return self.CB_ERR
            if Msg == 0x0150:  # CB_GETITEMDATA
                return getattr(control, 'item_data', {}).get(wParam, 0)
            if Msg == 0x0151:  # CB_SETITEMDATA
                if wParam >= len(control.items):
                    return self.CB_ERR
                if not hasattr(control, 'item_data'):
                    control.item_data = {}
                control.item_data[wParam] = lParam
                return 1
            if Msg == 0x014F:  # CB_SHOWDROPDOWN
                if self.gui:
                    self.gui.open_combo = control.hwnd if wParam else None
                return 1
            if Msg == 0x0157:  # CB_GETDROPPEDSTATE
                return 1 if self.gui and self.gui.open_combo == control.hwnd else 0
            if Msg in (0x0140, 0x0141, 0x0142, 0x0153, 0x0154, 0x0160):
                # CB_GETEDITSEL, CB_LIMITTEXT, CB_SETEDITSEL, CB_SETITEMHEIGHT,
                # CB_GETITEMHEIGHT, CB_SETDROPPEDWIDTH
                return 18 if Msg == 0x0154 else 1

        # ----- Scrollbar messages -----
        if Msg == self.SBM_SETPOS:
            pos = wParam - 0x100000000 if wParam >= 0x80000000 else wParam
            prev = control.scroll_pos
            control.scroll_pos = self._clamp_scroll_pos(control, pos)
            return prev & 0xFFFFFFFF
        if Msg == self.SBM_GETPOS:
            return control.scroll_pos & 0xFFFFFFFF
        if Msg == self.SBM_SETRANGE:
            nmin = wParam - 0x100000000 if wParam >= 0x80000000 else wParam
            nmax = lParam - 0x100000000 if lParam >= 0x80000000 else lParam
            control.scroll_min = min(nmin, nmax)
            control.scroll_max = max(nmin, nmax)
            control.scroll_pos = self._clamp_scroll_pos(control, control.scroll_pos)
            return 0
        if Msg == self.SBM_GETRANGE:
            try:
                if wParam:
                    self.emu.uc.mem_write(wParam, struct.pack("<i", control.scroll_min))
                if lParam:
                    self.emu.uc.mem_write(lParam, struct.pack("<i", control.scroll_max))
            except UcError:
                pass
            return 0

        log.debug(f"Unhandled control message 0x{Msg:04x} for {control.class_name}")
        return 0

    @staticmethod
    def clipboard_text():
        """Text on the clipboard (CF_UNICODETEXT, else CF_TEXT), or None"""
        data = winapi.WinAPIHandler.clipboard_data.get(13)
        if data is not None:
            text = data.decode('utf-16-le', errors='replace')
        else:
            data = winapi.WinAPIHandler.clipboard_data.get(1)
            if data is None:
                return None
            text = data.decode(config.ANSI_CODEPAGE, errors='replace')
        return text.split('\x00', 1)[0]

    @staticmethod
    def set_clipboard_text(text):
        """Put text on the clipboard (CF_UNICODETEXT and CF_TEXT)"""
        winapi.WinAPIHandler.clipboard_data = {
            13: text.encode('utf-16-le') + b'\x00\x00',
            1: text.encode(config.ANSI_CODEPAGE, errors='replace') + b'\x00'}

    EM_GETSEL, EM_SETSEL, EM_SCROLLCARET, EM_GETMODIFY, EM_SETMODIFY = 0xB0, 0xB1, 0xB7, 0xB8, 0xB9
    EM_GETLINECOUNT, EM_LINEINDEX, EM_LINELENGTH, EM_REPLACESEL = 0xBA, 0xBB, 0xC1, 0xC2
    EM_GETLINE, EM_LIMITTEXT, EM_CANUNDO, EM_UNDO, EM_LINEFROMCHAR = 0xC4, 0xC5, 0xC6, 0xC7, 0xC9
    EM_SETPASSWORDCHAR, EM_EMPTYUNDOBUFFER, EM_GETFIRSTVISIBLELINE = 0xCC, 0xCD, 0xCE
    EM_SETREADONLY, EM_GETPASSWORDCHAR, EM_SETMARGINS, EM_GETMARGINS = 0xCF, 0xD2, 0xD3, 0xD4
    EM_GETLIMITTEXT = 0xD5
    WM_CUT, WM_COPY, WM_PASTE, WM_CLEAR = 0x300, 0x301, 0x302, 0x303
    ES_MULTILINE, ES_PASSWORD, ES_READONLY = 0x4, 0x20, 0x800

    def _edit_message(self, control, Msg, wParam, lParam, wide):
        """EDIT control messages (and the CB_*EDITSEL ones of an editable
        combo box); None if not one of them"""
        def signed(value):
            return value - (1 << 32) if value & 0x80000000 else value

        def line_index(line):
            lines = control.edit_lines()
            if line == -1:
                line = control.line_of(control.sel_caret)
            return lines[line][0] if 0 <= line < len(lines) else -1

        readonly = control.class_name == 'EDIT' and control.style & self.ES_READONLY
        if Msg in (self.EM_GETSEL, 0x0140):  # CB_GETEDITSEL
            start, end = control.selection()
            if wParam:
                self._mem_write(wParam, struct.pack('<I', start))
            if lParam:
                self._mem_write(lParam, struct.pack('<I', end))
            return 0xFFFFFFFF if max(start, end) > 0xFFFF else (end << 16) | start
        if Msg in (self.EM_SETSEL, 0x0142):  # CB_SETEDITSEL: both in lParam
            if Msg == 0x0142:
                def s16(value):
                    return value - 0x10000 if value & 0x8000 else value
                start, end = s16(lParam & 0xFFFF), s16((lParam >> 16) & 0xFFFF)
            else:
                start, end = signed(wParam), signed(lParam)
            n = len(control.text)
            if start < 0:  # Remove the selection, the caret stays
                control.set_selection(control.sel_caret)
            else:
                control.set_selection(min(start, n), n if end < 0 else min(end, n))
            return 1 if Msg == 0x0142 else 0
        if Msg in (self.EM_LIMITTEXT, 0x0141):  # CB_LIMITTEXT
            control.text_limit = wParam
            return 1 if Msg == 0x0141 else 0
        if Msg == self.EM_GETLIMITTEXT:
            return control.text_limit or (0x7FFFFFFE if control.style & self.ES_MULTILINE
                                          else 30000)
        if Msg == self.EM_REPLACESEL:
            text = self._read_text(lParam, wide) if lParam else ''
            control.replace_selection(text)
            return 0
        if Msg == self.EM_GETMODIFY:
            return 1 if control.modified else 0
        if Msg == self.EM_SETMODIFY:
            control.modified = bool(wParam)
            return 0
        if Msg == self.EM_GETLINECOUNT:
            return len(control.edit_lines()) if control.style & self.ES_MULTILINE else 1
        if Msg == self.EM_LINEINDEX:
            return line_index(signed(wParam)) & 0xFFFFFFFF
        if Msg == self.EM_LINEFROMCHAR:
            offset = signed(wParam)
            return control.line_of(control.selection()[0] if offset < 0 else offset)
        if Msg == self.EM_LINELENGTH:
            offset = signed(wParam)
            if offset < 0:
                start, end = control.selection()
                lines = control.edit_lines()
                first, last = control.line_of(start), control.line_of(end)
                return (start - lines[first][0]) + (lines[last][1] - end)
            start, end = control.edit_lines()[control.line_of(offset)]
            return end - start
        if Msg == self.EM_GETLINE:
            lines = control.edit_lines()
            if not lParam or not 0 <= wParam < len(lines):
                return 0
            size = struct.unpack('<H', self.emu.uc.mem_read(lParam, 2))[0]
            start, end = lines[wParam]
            units = self._text_units(control.text[start:end], wide)[:size]
            self._write_units(lParam, units, wide, terminate=False)
            return len(units)
        if Msg == self.EM_SETREADONLY:
            control.style = (control.style | self.ES_READONLY) if wParam else \
                (control.style & ~self.ES_READONLY)
            return 1
        if Msg == self.EM_SETPASSWORDCHAR:
            control.password_char = chr(wParam) if wParam else ''
            control.style = (control.style | self.ES_PASSWORD) if wParam else \
                (control.style & ~self.ES_PASSWORD)
            return 0
        if Msg == self.EM_GETPASSWORDCHAR:
            return ord(control.password_char) if control.password_char else 0
        if Msg in (self.EM_SCROLLCARET, self.EM_EMPTYUNDOBUFFER):
            return 1 if Msg == self.EM_SCROLLCARET else 0
        if Msg in (self.EM_CANUNDO, self.EM_UNDO, self.EM_SETMARGINS, self.EM_GETMARGINS,
                   self.EM_GETFIRSTVISIBLELINE):
            return control.edit_top_line if Msg == self.EM_GETFIRSTVISIBLELINE else 0
        if Msg in (self.WM_COPY, self.WM_CUT):
            start, end = control.selection()
            if start != end and not control.password_char:
                self.set_clipboard_text(control.text[start:end])
                if Msg == self.WM_CUT and not readonly:
                    control.replace_selection('')
            return 0
        if Msg == self.WM_CLEAR:
            if not readonly:
                control.replace_selection('')
            return 0
        if Msg == self.WM_PASTE:
            text = self.clipboard_text()
            if text and not readonly:
                if not control.style & self.ES_MULTILINE:
                    text = text.split('\r', 1)[0].split('\n', 1)[0]
                control.replace_selection(text)
            return 0
        return None

    def PostMessageA(self, args):
        """PostMessageA emulation - queue a message for the message loop"""
        hWnd = args[0]
        Msg = args[1]
        wParam = args[2]
        lParam = args[3]
        log.debug(f"PostMessageA(0x{hWnd:x}, 0x{Msg:x}, 0x{wParam:x}, 0x{lParam:x})")
        if Msg == self.WM_QUIT:
            self.quit_code = wParam
            self.quit_requested = True
        else:
            self.post_window_message(hWnd, Msg, wParam, lParam)
        return 1

    def PostMessageW(self, args):
        return self.PostMessageA(args)

    def PostQuitMessage(self, args):
        """PostQuitMessage emulation - request message loop exit"""
        nExitCode = args[0]
        log.debug(f"PostQuitMessage({nExitCode})")
        # The blocking GetMessageA relies on this to break the loop; WM_QUIT
        # carries the exit code in wParam
        self.quit_code = nExitCode
        self.quit_requested = True
        return 0

    def SetTimer(self, args):
        """SetTimer emulation"""
        hWnd = args[0]
        nIDEvent = args[1]
        uElapse = args[2]
        lpTimerFunc = args[3]

        # Window-less timers get a fresh id (like real Windows)
        if hWnd == 0 or nIDEvent == 0:
            nIDEvent = self.next_timer_id
            self.next_timer_id += 1

        elapse = max(uElapse, 10) / 1000.0  # USER_TIMER_MINIMUM ~ 10ms
        self.timers[(hWnd, nIDEvent)] = {
            'elapse': elapse,
            'callback': lpTimerFunc,
            'next_fire': time.time() + elapse,
            'thread': self.emu.current_thread.tid,  # Gets the WM_TIMER of hWnd NULL
        }

        log.debug(f"SetTimer(0x{hWnd:x}, id={nIDEvent}, {uElapse}ms) -> {nIDEvent}")
        return nIDEvent

    def KillTimer(self, args):
        """KillTimer emulation"""
        hWnd = args[0]
        nIDEvent = args[1]
        log.debug(f"KillTimer(0x{hWnd:x}, id={nIDEvent})")
        return 1 if self.timers.pop((hWnd, nIDEvent), None) else 0

    def _pop_due_timer(self, matches=lambda hwnd, message: True):
        """Return (hwnd, id, callback) of a due timer and schedule its next fire"""
        now = time.time()
        thread = self.emu.current_thread.tid
        for (hwnd, timer_id), timer in self.timers.items():
            if not hwnd and timer.get('thread', thread) != thread:
                continue
            if now >= timer['next_fire'] and matches(hwnd, self.WM_TIMER):
                # Keep the period on its grid so polling delays don't slow the timer
                timer['next_fire'] += timer['elapse']
                if timer['next_fire'] <= now:
                    timer['next_fire'] = now + timer['elapse']
                return (hwnd, timer_id, timer['callback'])
        return None

    def _write_msg(self, lpMsg, hwnd, message, wParam, lParam):
        """Fill a MSG structure in emulated memory"""
        if lpMsg:
            # time and pt: when the message is retrieved (GetMessageTime/Pos)
            self.last_message_pos = x, y = self.gui.mouse_pos if self.gui else (0, 0)
            msg_data = struct.pack("<IIIIIii", hwnd, message, wParam, lParam,
                                   int(time.time() * 1000) & 0xFFFFFFFF, x, y)
            self.emu.uc.mem_write(lpMsg, msg_data)

    def _next_message(self, remove=True, hwnd_filter=0, msg_min=0, msg_max=0):
        """Single non-blocking scan for a pending message.

        Returns (hwnd, message, wParam, lParam) or None. Priority mirrors
        GetMessageA: synthesized WM_PAINT, then the input queue, then timers.
        hwnd_filter/msg_min/msg_max follow GetMessage's hWnd and filter range.
        """
        thread = self.emu.current_thread.tid

        def matches(hwnd, message):
            if hwnd_filter == 0xFFFFFFFF:  # (HWND)-1: thread messages only
                if hwnd != 0:
                    return False
            elif hwnd_filter and hwnd != hwnd_filter:
                return False
            # Each thread gets the messages of the windows it created
            if hwnd and self._window_thread(hwnd) not in (None, thread):
                return False
            return (msg_min == 0 and msg_max == 0) or msg_min <= message <= msg_max

        # Messages other threads sent to this thread's windows are handled
        # first, inside the message function (like Windows)
        self._process_sent_messages()
        self._audio_pump()
        self._deliver_set_cursor()
        if remove:
            self.refresh_native_views()

        # Send WM_PAINT for visible windows not yet painted
        windows = []
        if self.gui:
            with self.gui.lock:
                windows = list(self.gui.windows.items())
        for hwnd, window in windows:
            if (hwnd not in self.painted_windows and window.visible
                    and window.owner is self and matches(hwnd, self.WM_PAINT)):
                if remove:
                    self.painted_windows.add(hwnd)
                return (hwnd, self.WM_PAINT, 0, 0)

        # Owner-draw controls paint after their (painted, visible) parent
        for hwnd in list(self.dirty_controls):
            control = self.gui.controls.get(hwnd) if self.gui else None
            if control is None:
                self.dirty_controls.pop(hwnd, None)
                continue
            parent = self.gui.windows.get(control.parent_hwnd)
            ready = (parent is not None and parent.visible and control.visible
                     and control.parent_hwnd in self.painted_windows)
            if not self._owner_draw_type(control):
                # Drawn by the GUI: while painting it the system asks the
                # parent for its colors (WM_CTLCOLOR*)
                if ready and remove and matches(hwnd, self.WM_PAINT):
                    del self.dirty_controls[hwnd]
                    self._update_ctl_colors(control)
                elif parent is None:
                    self.dirty_controls.pop(hwnd, None)
                continue
            if ready and matches(hwnd, self.WM_PAINT):
                if remove:
                    del self.dirty_controls[hwnd]
                return (hwnd, self.WM_PAINT, 0, 0)

        # Queued message (input forwarded from the GUI thread)
        with self.message_lock:
            for index, msg in enumerate(self.message_queue):
                if matches(msg['hwnd'], msg['message']):
                    if remove:
                        del self.message_queue[index]
                    return (msg['hwnd'], msg['message'], msg['wParam'], msg['lParam'])

        # Fire due timers (lowest priority, like real WM_TIMER)
        if remove:
            due = self._pop_due_timer(matches)
            if due is not None:
                timer_hwnd, timer_id, callback = due
                return (timer_hwnd, self.WM_TIMER, timer_id, callback)

        return None

    def GetMessageA(self, args):
        """GetMessageA emulation - For message loop"""
        lpMsg = args[0]
        hWnd = args[1]
        wMsgFilterMin = args[2]
        wMsgFilterMax = args[3]

        log.debug("GetMessageA() - Message loop")

        # Block until a message is available, the app quits, or the GUI closes.
        # This runs on the emulation thread; the GUI thread feeds message_queue.
        while True:
            if self.quit_requested:
                self._write_msg(lpMsg, 0, self.WM_QUIT, self.quit_code, 0)
                return 0

            msg = self._next_message(True, hWnd, wMsgFilterMin, wMsgFilterMax)
            if msg is not None:
                hwnd, message, wParam, lParam = msg
                self._write_msg(lpMsg, hwnd, message, wParam, lParam)
                if message == self.WM_QUIT:
                    return 0
                return 1

            # GUI window closed -> end the message loop
            if self.gui and not self.gui.running:
                self._write_msg(lpMsg, 0, self.WM_QUIT, 0, 0)
                return 0

            # No GUI at all -> nothing can ever arrive, terminate
            if not self.gui:
                self.quit_requested = True
                self._write_msg(lpMsg, 0, self.WM_QUIT, 0, 0)
                return 0

            # Idle: wait for the GUI thread to post input (does not burn instructions)
            self.emu.idle_wait(0.01)

    def GetMessageW(self, args):
        return self.GetMessageA(args)

    def PeekMessageA(self, args):
        """PeekMessageA emulation - non-blocking message check (game loops)"""
        lpMsg = args[0]
        hWnd = args[1]
        wMsgFilterMin = args[2]
        wMsgFilterMax = args[3]
        wRemoveMsg = args[4]

        remove = bool(wRemoveMsg & self.PM_REMOVE)

        # Quit pending or GUI gone: report WM_QUIT (PeekMessage returns TRUE)
        if self.quit_requested or (self.gui and not self.gui.running) or not self.gui:
            code = self.quit_code if self.quit_requested else 0
            self._write_msg(lpMsg, 0, self.WM_QUIT, code, 0)
            return 1

        msg = self._next_message(remove, hWnd, wMsgFilterMin, wMsgFilterMax)
        if msg is None:
            return 0

        hwnd, message, wParam, lParam = msg
        self._write_msg(lpMsg, hwnd, message, wParam, lParam)
        log.debug(f"PeekMessageA() -> msg=0x{message:04x} hwnd=0x{hwnd:x}")
        return 1

    def PeekMessageW(self, args):
        """PeekMessageW emulation (same as PeekMessageA in the emulator)"""
        return self.PeekMessageA(args)

    def TranslateMessage(self, args):
        """TranslateMessage emulation"""
        lpMsg = args[0]
        log.debug("TranslateMessage()")
        return 1

    def DispatchMessageA(self, args):
        """DispatchMessageA emulation - Call WndProc"""
        lpMsg = args[0]
        log.debug("DispatchMessageA()")

        # Read MSG structure: hwnd, message, wParam, lParam, time, pt.x, pt.y
        try:
            msg_data = self.emu.uc.mem_read(lpMsg, 28)
            hwnd, message, wParam, lParam, time_val, pt_x, pt_y = struct.unpack(
                "<IIIIIii", msg_data)

            log.debug(f"DispatchMessageA: hwnd=0x{hwnd:x}, msg=0x{message:x}")

            if message == self.WM_PAINT and self.gui and hwnd in self.gui.controls:
                return self._paint_control(hwnd)

            # Controls: their (possibly subclassed) window procedure
            if self.gui and hwnd in self.gui.controls and not self._dialog_of(hwnd):
                subclass = self._control_subclass(hwnd)
                if subclass:
                    return self.emu.call_wndproc(subclass, hwnd, message, wParam, lParam)
                return self._control_default(hwnd, message, wParam, lParam)

            # Dialog windows: keyboard navigation and the dialog procedure
            if self._dialog_of(hwnd) and not (message == self.WM_TIMER and lParam):
                return self._dispatch(hwnd, message, wParam, lParam)

            # WM_TIMER with a TimerProc: call the callback instead of the WndProc
            if message == self.WM_TIMER and lParam:
                tick = int(time.time() * 1000) & 0xFFFFFFFF
                return self.emu.call_callback(lParam, [hwnd, message, wParam, tick])

            # Find WndProc for this hwnd
            wndproc = self._find_wndproc_for_hwnd(hwnd)

            if wndproc and wndproc != 0:
                log.debug(f"Calling WndProc: 0x{wndproc:x}(hwnd=0x{hwnd:x}, msg=0x{message:x}, "
                          f"wParam=0x{wParam:x}, lParam=0x{lParam:x})")

                # Call WndProc callback
                result = self._call_proc(wndproc, hwnd, message, wParam, lParam)

                log.debug(f"WndProc returned: 0x{result:x}")
                return result
            else:
                log.debug(f"WndProc not found, hwnd=0x{hwnd:x}")

        except UcError as e:
            log.warning(f"DispatchMessageA error: {e}")

        return 0

    def DispatchMessageW(self, args):
        return self.DispatchMessageA(args)

    def _find_wndproc_for_hwnd(self, hwnd):
        """Find WndProc address for a specific hwnd"""
        # Get window class from GUI (only this process's own windows, no consoles)
        if self.gui and hwnd in self.gui.windows:
            window = self.gui.windows[hwnd]
            if window.owner is not self or hwnd in self.gui.consoles:
                return 0
            dialog = self.dialogs.get(hwnd)
            if dialog is not None:
                return dialog['proc']
            # Subclassed window (SetWindowLong GWL_WNDPROC) or emulated control
            if window.wndproc:
                return window.wndproc
            # The window's class: the one of its module, else by its name
            if getattr(window, 'wndclass', None) is not None:
                return window.wndclass.get('wndproc', 0)
            class_name = getattr(window, 'class_name', None)
            if class_name and class_name in self.registered_classes:
                return self.registered_classes[class_name].get('wndproc', 0)
            # No WndProc if no class_name (internal window)
            if not class_name:
                return 0

        return 0

    def DefWindowProcA(self, args, wide=False):
        """DefWindowProcA/W emulation"""
        hWnd = args[0]
        Msg = args[1]
        wParam = args[2]
        lParam = args[3]
        log.debug(f"DefWindowProcA(0x{hWnd:x}, 0x{Msg:x})")

        if Msg == 0x000C:  # WM_SETTEXT: the window's text (its caption)
            if self.gui:
                self.gui.set_window_text(hWnd, self._read_text(lParam, wide) if lParam else '')
            return 1
        if Msg == 0x000D:  # WM_GETTEXT
            return self.GetWindowTextA([hWnd, lParam, wParam], wide)
        if Msg == 0x000E:  # WM_GETTEXTLENGTH
            return len(self._window_text(hWnd))
        if 0x0132 <= Msg <= 0x0138:  # WM_CTLCOLORMSGBOX ... WM_CTLCOLORSTATIC
            return self._default_ctl_color(Msg, wParam)
        if Msg == self.WM_SETCURSOR:
            return self._default_set_cursor(hWnd, wParam, lParam)
        if Msg == self.WM_NCCREATE:
            return 1  # Continue creating the window
        if Msg in (self.WM_CONTEXTMENU, self.WM_MOUSEWHEEL) and self.gui:
            # A child window passes them on to its parent
            win = self.gui.windows.get(hWnd)
            parent = win.parent if win is not None else 0
            if parent:
                return self._send(parent, Msg, hWnd if Msg == self.WM_CONTEXTMENU else wParam,
                                  lParam)
            return 0
        # Default WM_CLOSE handling: destroy the window (like real Windows)
        if Msg == self.WM_CLOSE:
            self.DestroyWindow([hWnd])
        # Alt+F4 -> SC_CLOSE -> WM_CLOSE (posted: no nested WndProc calls here)
        elif Msg == self.WM_SYSKEYDOWN and wParam == 0x73 and lParam & 0x20000000:  # VK_F4
            self.post_window_message(hWnd, self.WM_SYSCOMMAND, self.SC_CLOSE, 0)
        elif Msg == self.WM_SYSCOMMAND and wParam & 0xFFF0 == self.SC_CLOSE:
            self.post_window_message(hWnd, self.WM_CLOSE, 0, 0)

        return 0

    def DefWindowProcW(self, args):
        return self.DefWindowProcA(args, wide=True)

