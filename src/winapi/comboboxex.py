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

"""WinAPIHandler mixin: ComboBoxEx control"""

import struct

from .. import config


class ComboBoxExMixin:
    """ComboBoxEx control"""

    # ---------- ComboBoxEx ----------

    def _comboboxex_layout(self, win):
        edit = self.gui.controls.get(win.nstate.get('edit'))
        if edit is not None:
            edit.x, edit.y = 22, 2
            edit.width = max(10, win.width - 22 - 20)
            edit.height = self.COMBOBOX_BOX_H - 4

    def _comboboxex_item_struct(self, address, wide):
        mask, index, text_ptr, cch, image, sel_image, overlay, indent, param = \
            self._read_struct(address, '<IiIiiiiiI')
        info = {'mask': mask, 'index': index, 'text_ptr': text_ptr, 'cch': cch}
        if mask & 0x1:
            info['text'] = self._read_text(text_ptr, wide) if text_ptr and \
                text_ptr != 0xFFFFFFFF else ''
        if mask & 0x2:
            info['image'] = image
        if mask & 0x4:
            info['sel_image'] = sel_image
        if mask & 0x10:
            info['indent'] = indent
        if mask & 0x20:
            info['param'] = param
        return info

    def _comboboxex_edit_text(self, win):
        edit = self.gui.controls.get(win.nstate.get('edit'))
        if edit is not None:
            return edit.text
        sel = win.nstate['sel']
        return win.nstate['items'][sel]['text'] if 0 <= sel < len(win.nstate['items']) else ''

    def comboboxex_set_text(self, win, text):
        edit = self.gui.controls.get(win.nstate.get('edit'))
        if edit is not None:
            edit.text = text
        win.text = win.title = text

    def _comboboxex_end_edit(self, win, why):
        """CBEN_ENDEDITW (Enter: CBENF_RETURN 2, Escape: CBENF_ESCAPE 3)"""
        text = self._comboboxex_edit_text(win)[:259]
        payload = struct.pack('<Ii', 1, win.nstate['sel']) + \
            text.encode('utf-16-le').ljust(520, b'\x00') + struct.pack('<i', why)
        self._notify_simple(win, -806, payload)

    def comboboxex_command(self, win, code):
        parent = self._parent_of(win.hwnd)
        if parent:
            self._send(parent, self.WM_COMMAND, (code << 16) | (win.control_id & 0xFFFF), win.hwnd)

    def _comboboxex_message(self, win, msg, wParam, lParam):
        """ComboBoxEx32 messages; None for the default processing"""
        st = win.nstate
        items = st['items']
        wide_msgs = {0x40B: 0x401, 0x40C: 0x405, 0x40D: 0x404}
        wide = msg in wide_msgs
        msg = wide_msgs.get(msg, msg)
        signed_w = wParam - (1 << 32) if wParam & 0x80000000 else wParam
        if msg == self.WM_LBUTTONDOWN:
            # Opening the list asks the parent to fill it (CBN_DROPDOWN)
            if not st['dropped']:
                self.comboboxex_command(win, 7)  # CBN_DROPDOWN
                st['dropped'] = True
                self.gui.open_native_combo = win.hwnd
            else:
                st['dropped'] = False
                self.gui.open_native_combo = None
                self.comboboxex_command(win, 8)  # CBN_CLOSEUP
            return 0
        if msg == 0x0400 + 0x7F:  # Private: list item chosen by the GUI (wParam index)
            st['dropped'] = False
            if 0 <= signed_w < len(items):
                st['sel'] = signed_w
                self.comboboxex_set_text(win, items[signed_w]['text'])
                self.comboboxex_command(win, 1)  # CBN_SELCHANGE
                self.comboboxex_command(win, 8)  # CBN_CLOSEUP
                self.comboboxex_command(win, 9)  # CBN_SELENDOK
            else:
                self.comboboxex_command(win, 8)
                self.comboboxex_command(win, 10)  # CBN_SELENDCANCEL
            return 0
        if msg == 0x401:  # CBEM_INSERTITEM
            info = self._comboboxex_item_struct(lParam, wide)
            item = {'text': info.get('text', ''), 'image': info.get('image', -1),
                    'indent': info.get('indent', 0), 'param': info.get('param', 0)}
            index = info['index'] if 0 <= info['index'] <= len(items) else len(items)
            st['items'] = items[:index] + [item] + items[index:]
            return index
        if msg == 0x402:  # CBEM_SETIMAGELIST
            previous, st['imagelist'] = st['imagelist'], lParam
            return previous
        if msg == 0x403:  # CBEM_GETIMAGELIST
            return st['imagelist']
        if msg == 0x404:  # CBEM_GETITEM
            info = self._comboboxex_item_struct(lParam, wide)
            index = st['sel'] if info['index'] == -1 else info['index']
            if info['index'] == -1:
                text, image = self._comboboxex_edit_text(win), st.get('image', -1)
                param = 0
            elif 0 <= index < len(items):
                item = items[index]
                text, image, param = item['text'], item['image'], item['param']
            else:
                return 0
            if info['mask'] & 0x1 and info['text_ptr']:
                if wide:
                    self._copy_text_out(info['text_ptr'], info['cch'], text)
                else:
                    data = text.encode(config.ANSI_CODEPAGE, 'replace')[:max(0, info['cch'] - 1)]
                    self._mem_write(info['text_ptr'], data + b'\x00')
            if info['mask'] & 0x2:
                self._mem_write(lParam + 16, struct.pack('<i', image))
            if info['mask'] & 0x20:
                self._mem_write(lParam + 32, struct.pack('<I', param))
            return 1
        if msg == 0x405:  # CBEM_SETITEM (index -1: the edit/selection field)
            info = self._comboboxex_item_struct(lParam, wide)
            if info['index'] == -1:
                if 'text' in info:
                    self.comboboxex_set_text(win, info['text'])
                if 'image' in info:
                    st['image'] = info['image']
                return 1
            if not 0 <= info['index'] < len(items):
                return 0
            new = list(items)
            item = dict(new[info['index']])
            for key in ('text', 'image', 'indent', 'param'):
                if key in info:
                    item[key] = info[key]
            new[info['index']] = item
            st['items'] = new
            return 1
        if msg == 0x406:  # CBEM_GETCOMBOCONTROL
            return win.hwnd
        if msg == 0x407:  # CBEM_GETEDITCONTROL
            return st['edit']
        if msg in (0x408, 0x40E):  # CBEM_SETEXSTYLE / CBEM_SETEXTENDEDSTYLE
            previous = st.get('ex_style', 0)
            mask = wParam or 0xFFFFFFFF
            st['ex_style'] = (previous & ~mask) | (lParam & mask)
            return previous
        if msg == 0x409:  # CBEM_GETEXTENDEDSTYLE
            return st.get('ex_style', 0)
        if msg == 0x40A:  # CBEM_HASEDITCHANGED
            return 0
        if msg == 0x144:  # CB_DELETESTRING (CBEM_DELETEITEM)
            if not 0 <= wParam < len(items):
                return self.CB_ERR
            st['items'] = items[:wParam] + items[wParam + 1:]
            return len(st['items'])
        if msg == 0x146:  # CB_GETCOUNT
            return len(items)
        if msg == 0x147:  # CB_GETCURSEL
            return st['sel'] & 0xFFFFFFFF
        if msg == 0x14E:  # CB_SETCURSEL
            st['sel'] = signed_w if 0 <= signed_w < len(items) else -1
            if st['sel'] >= 0:
                self.comboboxex_set_text(win, items[st['sel']]['text'])
            return st['sel'] & 0xFFFFFFFF
        if msg == 0x14B:  # CB_RESETCONTENT
            st['items'] = []
            st['sel'] = -1
            return 0
        if msg == 0x14F:  # CB_SHOWDROPDOWN
            if wParam and not st['dropped']:
                self.comboboxex_command(win, 7)
                st['dropped'] = True
                self.gui.open_native_combo = win.hwnd
            elif not wParam and st['dropped']:
                st['dropped'] = False
                self.gui.open_native_combo = None
            return 1
        if msg == 0x157:  # CB_GETDROPPEDSTATE
            return 1 if st['dropped'] else 0
        if msg in (0x148, 0x149):  # CB_GETLBTEXT, CB_GETLBTEXTLEN
            if not 0 <= wParam < len(items):
                return self.CB_ERR
            text = items[wParam]['text']
            if msg == 0x148 and lParam:
                self._write_text(lParam, text, True)
            return len(text)
        if msg == 0x150:  # CB_GETITEMDATA
            return items[wParam]['param'] if 0 <= wParam < len(items) else self.CB_ERR
        if msg == 0x151:  # CB_SETITEMDATA
            if 0 <= wParam < len(items):
                new = list(items)
                new[wParam] = dict(new[wParam], param=lParam)
                st['items'] = new
                return 1
            return self.CB_ERR
        if msg in (0x140, 0x141, 0x142):  # CB_GETEDITSEL, CB_LIMITTEXT, CB_SETEDITSEL
            return 1
        if msg == self.WM_SIZE:
            self._comboboxex_layout(win)
            return 0
        if msg == self.WM_SETFOCUS:
            edit = st.get('edit')
            if edit:
                self.gui.focused_control = edit
            return 0
        if 0x140 <= msg < 0x170 or 0x400 <= msg < 0x420:
            return 0
        return None
