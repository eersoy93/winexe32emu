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

"""WinAPIHandler mixin: ListView control"""

import struct
from functools import cmp_to_key

from unicorn import UcError

from .. import config
from ..logger import log


class ListViewMixin:
    """ListView control"""

    # ---------- ListView ----------

    LVIF_TEXT, LVIF_IMAGE, LVIF_PARAM, LVIF_STATE = 0x1, 0x2, 0x4, 0x8
    LVIS_FOCUSED, LVIS_SELECTED = 0x1, 0x2
    LV_ROW_H = 18
    LV_HEADER_H = 20
    LPSTR_TEXTCALLBACK = 0xFFFFFFFF
    I_IMAGECALLBACK = 0xFFFFFFFF
    LVN_ITEMCHANGED, LVN_INSERTITEM, LVN_DELETEITEM = -101, -102, -103
    LVN_DELETEALLITEMS, LVN_COLUMNCLICK, LVN_BEGINDRAG = -104, -108, -109
    LVN_ITEMACTIVATE, LVN_KEYDOWN, LVN_GETDISPINFOW = -114, -155, -177
    NM_CLICK, NM_DBLCLK, NM_RETURN, NM_RCLICK = -2, -3, -4, -5
    NM_SETFOCUS, NM_KILLFOCUS = -7, -8

    def _lv_view(self, win):
        return win.style & 0x3  # LVS_ICON 0, LVS_REPORT 1, LVS_SMALLICON 2, LVS_LIST 3

    def lv_header_height(self, win):
        """Height of a list view's header (report view without LVS_NOCOLUMNHEADER)"""
        if self._lv_view(win) != 1 or win.style & 0x4000:
            return 0
        return self.LV_HEADER_H

    LV_ICON_CELL = (76, 66)  # Large icon spacing: the icon and two label lines

    def lv_icon_space(self, win):
        """Pixels before an item's label in the report, list and small icon
        views: the small icon (none without a LVSIL_SMALL image list)"""
        return 20 if win.nstate['imagelists'].get(1) else 0

    def lv_cell_width(self, win):
        """Cell width of the small icon and list views: the widest label known"""
        st = win.nstate
        width = 80
        for item in st['items']:
            text = item['cache'].get(0)
            if text is None:
                text = item['texts'].get(0) or ''
            if text:
                width = max(width, self._native_text_width(text) + 10 + self.lv_icon_space(win))
        return min(width, 320)

    def lv_grid(self, win):
        """Item layout of a list view: (cell width, cell height, items per line,
        visible lines, column major). A line is a row of the report, small icon
        and icon views and a column of the list view; st['top'] is the first
        item of the first visible line."""
        width, height = self.gui.client_size(win)
        view = self._lv_view(win)
        if view == 1:
            rows = (height - self.lv_header_height(win) -
                    (16 if self._lv_hscroll_needed(win) else 0)) // self.LV_ROW_H
            return width, self.LV_ROW_H, 1, max(1, rows), False
        if view == 3:  # LVS_LIST: columns from top to bottom, scrolled sideways
            cell_w = win.nstate.get('cell_w') or 120
            rows = max(1, (height - 16) // self.LV_ROW_H)
            columns = max(1, width // cell_w)
            if (len(win.nstate['items']) + rows - 1) // rows <= columns:
                rows = max(1, height // self.LV_ROW_H)  # No scroll bar needed
            return cell_w, self.LV_ROW_H, rows, columns, True
        cell_w, cell_h = (self.LV_ICON_CELL if view == 0 else
                          (win.nstate.get('cell_w') or 120, self.LV_ROW_H))
        per_row = max(1, (width - 16) // cell_w)
        return cell_w, cell_h, per_row, max(1, height // cell_h), False

    def lv_rows_per_page(self, win):
        """Items that fit in the view (LVM_GETCOUNTPERPAGE)"""
        _, _, per_line, lines, _ = self.lv_grid(win)
        return per_line * lines

    def lv_item_rect(self, win, index):
        """(left, top, right, bottom) of an item in client coordinates"""
        st = win.nstate
        cell_w, cell_h, per_line, _, column_major = self.lv_grid(win)
        relative = index - st['top']
        line, position = relative // per_line, relative % per_line
        if self._lv_view(win) == 1:
            top = self.lv_header_height(win) + relative * cell_h
            return (-st['hscroll'], top,
                    sum(c['width'] for c in st['columns']) - st['hscroll'], top + cell_h)
        column, row = (line, position) if column_major else (position, line)
        left, top = column * cell_w, row * cell_h
        return left, top, left + cell_w, top + cell_h

    def _lv_hscroll_needed(self, win):
        width = self.gui.client_size(win)[0] if self.gui else 0
        return self._lv_view(win) == 1 and sum(c['width'] for c in win.nstate['columns']) > width

    def _lv_item_struct(self, address, wide=True):
        """LVITEM -> dict of the fields its mask names"""
        mask, index, sub, state, state_mask, text_ptr, cch, image, param = \
            self._read_struct(address, '<IiiIIIiiI')
        info = {'mask': mask, 'index': index, 'sub': sub, 'state': state,
                'state_mask': state_mask, 'text_ptr': text_ptr, 'cch': cch,
                'image': image, 'param': param}
        if mask & self.LVIF_TEXT:
            if text_ptr == self.LPSTR_TEXTCALLBACK or (not wide and text_ptr == 0xFFFFFFFF):
                info['text'] = None
            else:
                info['text'] = self._read_text(text_ptr, wide) if text_ptr else ''
        return info

    def _lv_new_item(self, info):
        item = {'texts': {0: info.get('text', '')}, 'image': 0, 'state': 0, 'param': 0,
                'cache': {}}
        if info['mask'] & self.LVIF_IMAGE:
            item['image'] = info['image']
        if info['mask'] & self.LVIF_PARAM:
            item['param'] = info['param']
        if info['mask'] & self.LVIF_STATE:
            # Like comctl32, inserting ignores stateMask
            item['state'] = info['state'] & 0xFF & ~self.LVIS_FOCUSED
        return item

    def _lv_send_changed(self, win, index, old_state, new_state):
        """LVN_ITEMCHANGED for a state change of item index"""
        item = win.nstate['items'][index]
        payload = struct.pack('<iiIIIiiI', index, 0, new_state, old_state, self.LVIF_STATE,
                              0, 0, item['param'])
        self._notify_simple(win, self.LVN_ITEMCHANGED, payload)

    def _lv_set_state(self, win, index, state, mask, notify=True):
        """Change item states (index -1: all items); sends LVN_ITEMCHANGED"""
        st = win.nstate
        items = st['items']
        indices = range(len(items)) if index < 0 else [index] if index < len(items) else []
        for i in indices:
            item = items[i]
            old = item['state'] | (self.LVIS_FOCUSED if st['focus'] == i else 0)
            new = (old & ~mask) | (state & mask)
            if new & self.LVIS_FOCUSED and not old & self.LVIS_FOCUSED:
                previous = st['focus']
                if 0 <= previous < len(items) and previous != i:
                    st['focus'] = -1
                    if notify:
                        prev_state = items[previous]['state']
                        self._lv_send_changed(win, previous, prev_state | self.LVIS_FOCUSED,
                                              prev_state)
                st['focus'] = i
            elif old & self.LVIS_FOCUSED and not new & self.LVIS_FOCUSED:
                st['focus'] = -1
            item['state'] = new & ~self.LVIS_FOCUSED
            if new != old and notify and i < len(win.nstate['items']):
                self._lv_send_changed(win, i, old, new)
        return 1

    def _lv_select_only(self, win, index, notify=True):
        """Select and focus item index alone (like a plain click)"""
        items = win.nstate['items']
        for i, item in enumerate(items):
            if i != index and item['state'] & self.LVIS_SELECTED:
                self._lv_set_state(win, i, 0, self.LVIS_SELECTED, notify)
        if 0 <= index < len(win.nstate['items']):
            self._lv_set_state(win, index, self.LVIS_SELECTED | self.LVIS_FOCUSED,
                               self.LVIS_SELECTED | self.LVIS_FOCUSED, notify)
            win.nstate['mark'] = index
            self._lv_ensure_visible(win, index)

    def _lv_top_limit(self, win, top):
        """top kept inside the items and on the start of a line"""
        _, _, per_line, lines, _ = self.lv_grid(win)
        count = len(win.nstate['items'])
        last_line = max(0, (count + per_line - 1) // per_line - lines)
        return max(0, min(top // per_line, last_line)) * per_line

    def _lv_ensure_visible(self, win, index):
        st = win.nstate
        _, _, per_line, lines, _ = self.lv_grid(win)
        page = per_line * lines
        if index < st['top']:
            st['top'] = index
        elif index >= st['top'] + page:
            st['top'] = index - page + per_line
        st['top'] = self._lv_top_limit(win, st['top'])
        st['dirty'] = True

    def _lv_scroll_to(self, win, top):
        st = win.nstate
        st['top'] = self._lv_top_limit(win, top)
        st['dirty'] = True

    def _lv_scroll_lines(self, win, lines):
        """Scroll by whole lines (rows, or columns of the list view)"""
        per_line = self.lv_grid(win)[2]
        self._lv_scroll_to(win, win.nstate['top'] + lines * per_line)

    def _lv_item_text(self, win, index, sub):
        """Text of an item/subitem, asking the parent (LVN_GETDISPINFOW) for
        LPSTR_TEXTCALLBACK texts"""
        st = win.nstate
        item = st['items'][index]
        if sub in item['cache']:
            return item['cache'][sub]
        # Subitems never set are callback texts too (like comctl32)
        text = item['texts'].get(sub, '' if sub == 0 else None)
        if text is None or (sub == 0 and item['image'] == -1):
            text, image = self._lv_dispinfo(win, index, sub, text is None,
                                            sub == 0 and item['image'] == -1)
            if image is not None:
                item['cache_image'] = image
            text = text or ''
        item['cache'][sub] = text
        return text

    def _lv_dispinfo(self, win, index, sub, want_text, want_image):
        """LVN_GETDISPINFOW -> (text or None, image or None)"""
        item = win.nstate['items'][index]
        buf_chars = 520
        text_buf = self.emu.heap_alloc(buf_chars * 2)
        mask = (self.LVIF_TEXT if want_text else 0) | (self.LVIF_IMAGE if want_image else 0)
        payload = struct.pack('<IiiIIIiiIi', mask, index, sub, item['state'], 0, text_buf,
                              buf_chars, 0, item['param'], 0) + b'\x00' * 16
        _, buf = self._notify(win, self.LVN_GETDISPINFOW, payload)
        text = image = None
        try:
            _, _, _, _, _, text_ptr, _, image_value, _ = self._read_struct(buf + 12, '<IiiIIIiiI')
            if want_text:
                text = self.read_wide_string(text_ptr, 1024) if text_ptr else ''
            if want_image:
                image = image_value
        except UcError:
            pass
        self.emu.heap_free(buf)
        self.emu.heap_free(text_buf)
        return text, image

    def refresh_native_views(self):
        """Resolve the callback texts of the visible list view rows (the GUI
        thread only draws what is cached)"""
        if not self.gui:
            return
        for win in list(self.gui.windows.values()):
            if win.native != 'LISTVIEW' or win.owner is not self or not win.nstate.get('dirty'):
                continue
            if not win.visible or not win.nstate['redraw']:
                continue
            st = win.nstate
            st['dirty'] = False
            if self._lv_view(win) in (2, 3):
                st['cell_w'] = self.lv_cell_width(win)
            st['top'] = self._lv_top_limit(win, st['top'])  # The view may have changed
            rows = self.lv_rows_per_page(win) + self.lv_grid(win)[2]
            columns = st['columns'] if self._lv_view(win) == 1 else [{'sub': 0}]
            if not columns:
                columns = [{'sub': 0}]
            for index in range(st['top'], min(len(st['items']), st['top'] + rows)):
                if index >= len(st['items']):
                    break
                for column in columns:
                    self._lv_item_text(win, index, column['sub'])

    def _lv_hit(self, win, x, y):
        """(item index or -1, subitem) at client point"""
        st = win.nstate
        header = self.lv_header_height(win)
        if y < header:
            return -1, 0
        if self._lv_view(win) != 1:
            cell_w, cell_h, per_line, _, column_major = self.lv_grid(win)
            if x < 0 or y < 0:
                return -1, 0
            column, row = x // cell_w, y // cell_h
            if column_major:
                if row >= per_line:
                    return -1, 0
                index = st['top'] + column * per_line + row
            else:
                if column >= per_line:
                    return -1, 0
                index = st['top'] + row * per_line + column
            if not 0 <= index < len(st['items']):
                return -1, 0
            # Only the icon and the label are the item
            left = x - column * cell_w
            label_w = self._native_text_width(self._lv_item_text(win, index, 0))
            if self._lv_view(win) == 0:
                if abs(left - cell_w // 2) > max(18, min(cell_w, label_w + 4) // 2):
                    return -1, 0
            elif left > self.lv_icon_space(win) + label_w + 4:
                return -1, 0
            return index, 0
        index = st['top'] + (y - header) // self.LV_ROW_H
        if not 0 <= index < len(st['items']):
            return -1, 0
        sub = 0
        if self._lv_view(win) == 1:
            left = -st['hscroll']
            for column in self._lv_ordered_columns(win):
                if left <= x < left + column['width']:
                    sub = column['sub']
                    break
                left += column['width']
            else:
                return -1, 0
        return index, sub

    def _lv_ordered_columns(self, win):
        columns = win.nstate['columns']
        return sorted(columns, key=lambda c: c.get('order', 0))

    def _lv_header_hit(self, win, x):
        left = -win.nstate['hscroll']
        for column in self._lv_ordered_columns(win):
            if left <= x < left + column['width']:
                return win.nstate['columns'].index(column)
            left += column['width']
        return -1

    LV_DIVIDER_GRIP = 4  # Pixels on each side of a header divider that grab it

    def _lv_divider_hit(self, win, x, y):
        """Column whose right header divider is at client point (x, y), or -1
        (report view only; the rightmost of overlapping dividers, so a column
        narrowed to zero can be widened again)"""
        if self._lv_view(win) != 1 or not 0 <= y < self.lv_header_height(win):
            return -1
        left, found = -win.nstate['hscroll'], -1
        for column in self._lv_ordered_columns(win):
            left += column['width']
            if abs(x - left) <= self.LV_DIVIDER_GRIP:
                found = win.nstate['columns'].index(column)
        return found

    def _lv_set_width(self, win, index, width):
        columns = [dict(c) for c in win.nstate['columns']]  # Copy: the GUI thread reads it
        columns[index]['width'] = max(0, width)
        win.nstate['columns'] = columns

    def _lv_track(self, win, msg, wParam, lParam):
        """Dragging a header divider (begun by WM_LBUTTONDOWN, with the mouse
        captured): the column follows the mouse until the button is released"""
        st = win.nstate
        index, start_x, start_width = st['track']
        x = lParam & 0xFFFF
        x = x - 0x10000 if x & 0x8000 else x
        if 0 <= index < len(st['columns']):
            self._lv_set_width(win, index, start_width + x - start_x)
        if msg == self.WM_LBUTTONUP or not wParam & self.MK_LBUTTON or \
                self.capture_hwnd != win.hwnd:
            st.pop('track', None)
            if self.capture_hwnd == win.hwnd:
                self.capture_hwnd = 0
        return 0

    LVN_BEGINLABELEDITW, LVN_ENDLABELEDITW = -175, -176

    def _lv_begin_edit(self, win, index):
        """LVM_EDITLABEL: an edit control over the item's label; returns its hwnd"""
        st = win.nstate
        if not 0 <= index < len(st['items']):
            return 0
        self._lv_end_edit(win, False)
        text = self._lv_item_text(win, index, 0)
        payload = struct.pack('<IiiIIIiiIi', self.LVIF_TEXT, index, 0, 0, 0, 0, 0, 0,
                              st['items'][index]['param'], 0) + b'\x00' * 16
        if self._notify_simple(win, self.LVN_BEGINLABELEDITW, payload):
            return 0
        self._lv_ensure_visible(win, index)
        left, top, right, bottom = self.lv_item_rect(win, index)
        view = self._lv_view(win)
        icon = self.lv_icon_space(win)
        if view == 1:
            x, width = left + icon, (st['columns'][0]['width'] - icon if st['columns']
                                     else right - left - icon)
        elif view == 0:  # Under the icon
            x, width, top = left, right - left, top + 38
        else:
            x, width = left + icon, max(right - left - icon, self._native_text_width(text) + 12)
        edit = self.gui.create_control(win.hwnd, 'EDIT', text, x, top, max(width, 40),
                                       self.LV_ROW_H, 0x50800080, control_id=0)
        st['edit'] = (edit, index)
        self.gui.focused_control = edit
        self.gui.controls[edit].select_all()
        return edit

    def _lv_end_edit(self, win, accept):
        """Finish label editing: LVN_ENDLABELEDITW (pszText NULL if cancelled)"""
        st = win.nstate
        edit, index = st.pop('edit', (0, -1))
        control = self.gui.controls.get(edit)
        if control is None:
            return
        text = control.text
        self.gui.destroy_control(edit)
        if not 0 <= index < len(st['items']):
            return
        buf = self.emu.heap_alloc((len(text) + 1) * 2) if accept else 0
        if buf:
            self._write_text(buf, text, True)
        payload = struct.pack('<IiiIIIiiIi', self.LVIF_TEXT, index, 0, 0, 0, buf, 260 if buf else 0,
                              0, st['items'][index]['param'], 0) + b'\x00' * 16
        result = self._notify_simple(win, self.LVN_ENDLABELEDITW, payload)
        if buf:
            if (result and index < len(st['items']) and
                    st['items'][index]['texts'].get(0) is not None):
                st['items'][index]['texts'][0] = text
            st['items'][index]['cache'].pop(0, None) if index < len(st['items']) else None
            self.emu.heap_free(buf)
        st['dirty'] = True
        self.SetFocus([win.hwnd])

    def _lv_activate(self, win, index, code):
        """NM_DBLCLK/NM_RETURN (none for Alt+Enter) followed by LVN_ITEMACTIVATE;
        uKeyFlags tells the modifier keys (LVKF_ALT, LVKF_CONTROL, LVKF_SHIFT)"""
        param = win.nstate['items'][index]['param'] if 0 <= index < len(win.nstate['items']) else 0
        keys = self.gui.key_states if self.gui else {}
        flags = (1 if keys.get(0x12) else 0) | (2 if keys.get(0x11) else 0) | \
            (4 if keys.get(0x10) else 0)
        payload = struct.pack('<iiIIIiiII', index, 0, 0, 0, 0, 0, 0, param, flags)
        if code is not None:
            self._notify_simple(win, code, payload)
        if self._native_window(win.hwnd) is not None:
            self._notify_simple(win, self.LVN_ITEMACTIVATE, payload)

    def _lv_mouse(self, win, msg, wParam, lParam):
        st = win.nstate
        x = lParam & 0xFFFF
        y = (lParam >> 16) & 0xFFFF
        x, y = (x - 0x10000 if x & 0x8000 else x), (y - 0x10000 if y & 0x8000 else y)
        width, height = self.gui.client_size(win)
        if st.get('edit'):
            self._lv_end_edit(win, True)
        self.SetFocus([win.hwnd])
        _, _, per_line, lines, column_major = self.lv_grid(win)
        if column_major and msg in (self.WM_LBUTTONDOWN, self.WM_LBUTTONDBLCLK) and \
                y >= height - 16 and len(st['items']) > per_line * lines:
            # Horizontal scroll bar of the list view: arrows and page areas
            if x < 16:
                self._lv_scroll_lines(win, -1)
            elif x >= width - 16:
                self._lv_scroll_lines(win, 1)
            else:
                total = (len(st['items']) + per_line - 1) // per_line
                thumb = 16 + int((width - 32) * (st['top'] // per_line) / max(1, total))
                self._lv_scroll_lines(win, lines if x > thumb else -lines)
            return 0
        if not column_major and msg in (self.WM_LBUTTONDOWN, self.WM_LBUTTONDBLCLK) and \
                x >= width - 16 and len(st['items']) > per_line * lines:
            # Vertical scroll bar: arrows and page areas
            header = self.lv_header_height(win)
            if y < header + 16:
                self._lv_scroll_lines(win, -1)
            elif y >= height - 16:
                self._lv_scroll_lines(win, 1)
            else:
                track = max(1, height - header - 32)
                thumb = header + 16 + int(track * st['top'] / max(1, len(st['items'])))
                self._lv_scroll_lines(win, lines if y > thumb else -lines)
            return 0
        divider = self._lv_divider_hit(win, x, y)
        if divider >= 0 and msg in (self.WM_LBUTTONDOWN, self.WM_LBUTTONDBLCLK):
            if msg == self.WM_LBUTTONDBLCLK:  # Fit the column to its contents
                self._listview_message(win, 0x101E, divider, 0xFFFF)  # LVSCW_AUTOSIZE
            else:
                st['track'] = (divider, x, st['columns'][divider]['width'])
                self.capture_hwnd = win.hwnd
            return 0
        if msg == self.WM_LBUTTONDOWN and y < self.lv_header_height(win):
            column = self._lv_header_hit(win, x)
            if column >= 0:
                payload = struct.pack('<iiIIIiiI', -1, st['columns'][column]['sub'], 0, 0, 0,
                                      x, y, 0)
                self._notify_simple(win, self.LVN_COLUMNCLICK, payload)
            return 0
        index, sub = self._lv_hit(win, x, y)
        ctrl = bool(self.gui.key_states.get(0x11))
        shift = bool(self.gui.key_states.get(0x10))
        if msg in (self.WM_LBUTTONDOWN, self.WM_RBUTTONDOWN, self.WM_LBUTTONDBLCLK):
            single = win.style & 0x4  # LVS_SINGLESEL
            if index < 0:
                if msg != self.WM_LBUTTONDBLCLK and not ctrl and not shift:
                    for i, item in enumerate(st['items']):
                        if item['state'] & self.LVIS_SELECTED:
                            self._lv_set_state(win, i, 0, self.LVIS_SELECTED)
            elif msg == self.WM_LBUTTONDOWN and ctrl and not single:
                selected = st['items'][index]['state'] & self.LVIS_SELECTED
                self._lv_set_state(win, index, (0 if selected else self.LVIS_SELECTED) |
                                   self.LVIS_FOCUSED, self.LVIS_SELECTED | self.LVIS_FOCUSED)
                st['mark'] = index
            elif msg == self.WM_LBUTTONDOWN and shift and not single and st['mark'] >= 0:
                low, high = sorted((st['mark'], index))
                for i in range(len(st['items'])):
                    want = self.LVIS_SELECTED if low <= i <= high else 0
                    if st['items'][i]['state'] & self.LVIS_SELECTED != want:
                        self._lv_set_state(win, i, want, self.LVIS_SELECTED)
                self._lv_set_state(win, index, self.LVIS_FOCUSED, self.LVIS_FOCUSED)
            elif not (msg == self.WM_RBUTTONDOWN and
                      st['items'][index]['state'] & self.LVIS_SELECTED):
                self._lv_select_only(win, index)
            param = st['items'][index]['param'] if 0 <= index < len(st['items']) else 0
            payload = struct.pack('<iiIIIiiII', index, sub, 0, 0, 0, x, y, param, 0)
            if msg == self.WM_LBUTTONDOWN:
                self._notify_simple(win, self.NM_CLICK, payload)
            elif msg == self.WM_LBUTTONDBLCLK:
                self._lv_activate(win, index, self.NM_DBLCLK)
            else:
                self._notify_simple(win, self.NM_RCLICK, payload)
                sx, sy = self.gui.client_origin(win)
                self._send(win.hwnd, self.WM_CONTEXTMENU, win.hwnd,
                           ((sy + y) & 0xFFFF) << 16 | ((sx + x) & 0xFFFF))
        return 0

    def _lv_key(self, win, vk):
        st = win.nstate
        count = len(st['items'])
        payload = struct.pack('<HI', vk, 0) + b'\x00' * 2
        if self._notify_simple(win, self.LVN_KEYDOWN, payload):
            return 0
        if self._native_window(win.hwnd) is None:
            return 0
        if vk == 0x0D:  # VK_RETURN
            self._lv_activate(win, st['focus'], self.NM_RETURN)
            return 0
        if not count:
            return 0
        _, _, per_line, lines, column_major = self.lv_grid(win)
        rows = per_line * lines
        focus = st['focus'] if st['focus'] >= 0 else 0
        moves = {0x26: focus - 1, 0x28: focus + 1, 0x24: 0, 0x23: count - 1,
                 0x21: focus - rows + 1, 0x22: focus + rows - 1}  # Up Down Home End PgUp PgDn
        view = self._lv_view(win)
        if view == 3:  # List: Left/Right go to the neighbor column
            moves.update({0x25: focus - per_line, 0x27: focus + per_line})
        elif view in (0, 2):  # Icons: rows of per_line items
            moves.update({0x25: focus - 1, 0x27: focus + 1, 0x26: focus - per_line,
                          0x28: focus + per_line, 0x21: focus - (lines - 1 or 1) * per_line,
                          0x22: focus + (lines - 1 or 1) * per_line})
        if vk in moves:
            target = max(0, min(count - 1, moves[vk]))
            if st['focus'] < 0 and vk in (0x25, 0x26, 0x27, 0x28):
                target = 0
            ctrl = bool(self.gui.key_states.get(0x11))
            shift = bool(self.gui.key_states.get(0x10))
            if ctrl:
                self._lv_set_state(win, target, self.LVIS_FOCUSED, self.LVIS_FOCUSED)
                self._lv_ensure_visible(win, target)
            elif shift and not win.style & 0x4 and st['mark'] >= 0:
                low, high = sorted((st['mark'], target))
                for i in range(count):
                    want = self.LVIS_SELECTED if low <= i <= high else 0
                    if st['items'][i]['state'] & self.LVIS_SELECTED != want:
                        self._lv_set_state(win, i, want, self.LVIS_SELECTED)
                self._lv_set_state(win, target, self.LVIS_FOCUSED, self.LVIS_FOCUSED)
                self._lv_ensure_visible(win, target)
            else:
                self._lv_select_only(win, target)
        elif vk == 0x20 and self.gui.key_states.get(0x11) and st['focus'] >= 0:  # Ctrl+Space
            selected = st['items'][st['focus']]['state'] & self.LVIS_SELECTED
            self._lv_set_state(win, st['focus'], 0 if selected else self.LVIS_SELECTED,
                               self.LVIS_SELECTED)
        return 0

    def _lv_fill_item(self, win, address, index, wide=True):
        """LVM_GETITEM: fill the LVITEM at address for the fields its mask asks"""
        info = self._lv_item_struct(address, wide)
        st = win.nstate
        if not 0 <= info['index'] < len(st['items']):
            return 0
        item = st['items'][info['index']]
        mask = info['mask']
        if mask & self.LVIF_TEXT and info['text_ptr'] and info['cch'] > 0:
            text = self._lv_item_text(win, info['index'], info['sub'])
            if wide:
                self._copy_text_out(info['text_ptr'], info['cch'], text)
            else:
                data = text.encode(config.ANSI_CODEPAGE, errors='replace')[:info['cch'] - 1]
                self._mem_write(info['text_ptr'], data + b'\x00')
        if mask & self.LVIF_IMAGE:
            self._mem_write(address + 28, struct.pack('<i', item.get('cache_image', item['image'])))
        if mask & self.LVIF_PARAM:
            self._mem_write(address + 32, struct.pack('<I', item['param']))
        if mask & self.LVIF_STATE:
            state = item['state'] | (self.LVIS_FOCUSED if st['focus'] == info['index'] else 0)
            self._mem_write(address + 12, struct.pack('<I', state & info['state_mask']))
        return 1

    def _lv_column_struct(self, address, wide=True):
        mask, fmt, cx, text_ptr, cch, sub, image, order = self._read_struct(address, '<IIiIiiii')
        info = {'mask': mask, 'fmt': fmt, 'cx': cx, 'text_ptr': text_ptr, 'cch': cch,
                'sub': sub, 'image': image, 'order': order}
        if mask & 0x4 and text_ptr:  # LVCF_TEXT
            info['text'] = self._read_text(text_ptr, wide)
        return info

    def _lv_apply_column(self, column, info):
        if info['mask'] & 0x1:
            column['fmt'] = info['fmt']
        if info['mask'] & 0x2:
            column['width'] = max(0, info['cx'])
        if 'text' in info:
            column['text'] = info['text']
        if info['mask'] & 0x8:
            column['sub'] = info['sub']
        if info['mask'] & 0x20:
            column['order'] = info['order']

    def _lv_sort(self, win, compare, param, by_index):
        st = win.nstate
        items = list(st['items'])
        focused = items[st['focus']] if 0 <= st['focus'] < len(items) else None
        positions = {id(item): i for i, item in enumerate(items)}

        def cmp(a, b):
            if by_index:
                args = [positions[id(a)], positions[id(b)], param]
            else:
                args = [a['param'], b['param'], param]
            result = self.emu.call_callback(compare, args)
            return result - (1 << 32) if result & 0x80000000 else result
        items.sort(key=cmp_to_key(cmp))
        st['items'] = items
        st['focus'] = next((i for i, item in enumerate(items) if item is focused), -1)
        st['dirty'] = True
        return 1

    def _listview_message(self, win, msg, wParam, lParam):
        """SysListView32 messages; None for the default processing"""
        st = win.nstate
        items = st['items']
        wide_msgs = {0x104B: 0x1005, 0x104C: 0x1006, 0x104D: 0x1007, 0x105F: 0x1019,
                     0x1060: 0x101A, 0x1061: 0x101B, 0x1073: 0x102D, 0x1074: 0x102E,
                     0x1053: 0x100D, 0x1057: 0x1011}
        wide = msg in wide_msgs or msg >= 0x2000
        msg = wide_msgs.get(msg, msg)
        signed_w = wParam - (1 << 32) if wParam & 0x80000000 else wParam

        if msg in (self.WM_MOUSEMOVE, self.WM_LBUTTONUP) and st.get('track'):
            return self._lv_track(win, msg, wParam, lParam)
        if msg == self.WM_SETCURSOR and lParam & 0xFFFF == self.HTCLIENT and self.gui:
            # The header shows the sizing cursor over its dividers
            x, y = self.gui._client_point(win, *self.gui.mouse_pos)
            if self._lv_divider_hit(win, x, y) >= 0:
                self.current_cursor = self._system_cursor(self.IDC_SIZEWE)
                return 1
        if msg in (self.WM_LBUTTONDOWN, self.WM_RBUTTONDOWN, self.WM_LBUTTONDBLCLK):
            return self._lv_mouse(win, msg, wParam, lParam)
        if msg == self.WM_KEYDOWN:
            return self._lv_key(win, wParam)
        if msg == self.WM_SYSKEYDOWN and wParam == 0x0D:  # Alt+Enter activates too
            if st['focus'] >= 0 and self._native_window(win.hwnd) is not None:
                self._lv_activate(win, st['focus'], None)
            return 0
        if msg == self.WM_MOUSEWHEEL:
            delta = (wParam >> 16) - 0x10000 if wParam & 0x80000000 else wParam >> 16
            if self._lv_view(win) == 1:
                self._lv_scroll_to(win, st['top'] - 3 * delta // 120)
            else:
                self._lv_scroll_lines(win, -delta // 120)
            return 0
        if msg == self.WM_SETFOCUS:
            self._notify_simple(win, self.NM_SETFOCUS)
            return 0
        if msg == self.WM_KILLFOCUS:
            self._notify_simple(win, self.NM_KILLFOCUS)
            return 0
        if msg == 0x000B:  # WM_SETREDRAW
            st['redraw'] = bool(wParam)
            st['dirty'] = True
            return 0
        if msg == 0x1000:  # LVM_GETBKCOLOR
            return 0xFFFFFF
        if msg in (0x1001, 0x1024, 0x1026):  # LVM_SETBKCOLOR, SETTEXTCOLOR, SETTEXTBKCOLOR
            return 1
        if msg == 0x1002:  # LVM_GETIMAGELIST
            return st['imagelists'].get(wParam, 0)
        if msg == 0x1003:  # LVM_SETIMAGELIST
            previous = st['imagelists'].get(wParam, 0)
            st['imagelists'][wParam] = lParam
            return previous
        if msg == 0x1004:  # LVM_GETITEMCOUNT
            return len(items)
        if msg == 0x1005:  # LVM_GETITEM
            return self._lv_fill_item(win, lParam, 0, wide)
        if msg == 0x1006:  # LVM_SETITEM
            info = self._lv_item_struct(lParam, wide)
            if not 0 <= info['index'] < len(items):
                return 0
            item = items[info['index']]
            if 'text' in info:
                item['texts'][info['sub']] = info['text']
                item['cache'].pop(info['sub'], None)
            if info['sub'] == 0:
                if info['mask'] & self.LVIF_IMAGE:
                    item['image'] = info['image']
                    item.pop('cache_image', None)
                if info['mask'] & self.LVIF_PARAM:
                    item['param'] = info['param']
                if info['mask'] & self.LVIF_STATE:
                    self._lv_set_state(win, info['index'], info['state'], info['state_mask'])
            st['dirty'] = True
            return 1
        if msg == 0x1007:  # LVM_INSERTITEM
            info = self._lv_item_struct(lParam, wide)
            if info['sub'] != 0:
                return 0xFFFFFFFF
            index = max(0, min(info['index'], len(items)))
            item = self._lv_new_item(info)
            st['items'] = items[:index] + [item] + items[index:]
            if st['focus'] >= index:
                st['focus'] += 1
            st['dirty'] = True
            return index
        if msg == 0x1008:  # LVM_DELETEITEM
            if not 0 <= wParam < len(items):
                return 0
            payload = struct.pack('<iiIIIiiI', wParam, 0, 0, 0, 0, 0, 0, items[wParam]['param'])
            self._notify_simple(win, self.LVN_DELETEITEM, payload)
            items = st['items']
            if not 0 <= wParam < len(items):
                return 1
            st['items'] = items[:wParam] + items[wParam + 1:]
            if st['focus'] == wParam:
                st['focus'] = -1
            elif st['focus'] > wParam:
                st['focus'] -= 1
            st['dirty'] = True
            return 1
        if msg == 0x1009:  # LVM_DELETEALLITEMS
            if items and not self._notify_simple(win, self.LVN_DELETEALLITEMS,
                                                 struct.pack('<iiIIIiiI', -1, 0, 0, 0, 0, 0, 0, 0)):
                for i, item in enumerate(items):
                    self._notify_simple(win, self.LVN_DELETEITEM,
                                        struct.pack('<iiIIIiiI', i, 0, 0, 0, 0, 0, 0,
                                                    item['param']))
            st['items'] = []
            st['focus'] = st['mark'] = -1
            st['top'] = 0
            st['dirty'] = True
            return 1
        if msg == 0x100C:  # LVM_GETNEXTITEM
            flags = lParam & 0xFFFF
            start = signed_w
            for i in range(start + 1, len(items)):
                state = items[i]['state'] | (self.LVIS_FOCUSED if st['focus'] == i else 0)
                if (flags & 0x1 and not state & self.LVIS_FOCUSED) or \
                        (flags & 0x2 and not state & self.LVIS_SELECTED) or \
                        (flags & 0x4 and not state & 0x4) or (flags & 0x8 and not state & 0x8):
                    continue
                if flags & 0xF00:  # LVNI_ABOVE/BELOW/TOLEFT/TORIGHT
                    if flags & 0x100 and start >= 0:  # LVNI_ABOVE
                        return (start - 1) & 0xFFFFFFFF if start > 0 else 0xFFFFFFFF
                    if flags & 0x200:  # LVNI_BELOW
                        return start + 1 if start + 1 < len(items) else 0xFFFFFFFF
                return i
            return 0xFFFFFFFF
        if msg == 0x100D:  # LVM_FINDITEM
            start = signed_w
            flags, text_ptr, param = self._read_struct(lParam, '<III')
            text = self._read_text(text_ptr, wide) if flags & 0x2 and text_ptr else None
            for i in range(start + 1, len(items)):
                if flags & 0x1 and items[i]['param'] == param:
                    return i
                if text is not None:
                    name = self._lv_item_text(win, i, 0)
                    if name.lower() == text.lower() or (flags & 0x8 and
                                                        name.lower().startswith(text.lower())):
                        return i
            return 0xFFFFFFFF
        if msg == 0x100E:  # LVM_GETITEMRECT
            if not 0 <= wParam < len(items):
                return 0
            code = struct.unpack('<i', self.emu.uc.mem_read(lParam, 4))[0]
            left, top, right, bottom = self.lv_item_rect(win, wParam)
            if self._lv_view(win) == 0:  # Icon above the label
                if code == 1:  # LVIR_ICON
                    left, right, bottom = left + (right - left - 32) // 2, \
                        left + (right - left + 32) // 2, top + 36
                elif code == 2:  # LVIR_LABEL
                    top += 36
            elif code == 1:  # LVIR_ICON
                right = left + self.lv_icon_space(win)
            elif code == 2:  # LVIR_LABEL starts after the icon
                left += self.lv_icon_space(win)
                if self._lv_view(win) == 1 and st['columns']:
                    right = left - self.lv_icon_space(win) + st['columns'][0]['width']
            self._mem_write(lParam, struct.pack('<iiii', left, top, right, bottom))
            return 1
        if msg == 0x1010:  # LVM_GETITEMPOSITION
            left, top, _, _ = self.lv_item_rect(win, wParam)
            self._mem_write(lParam, struct.pack('<ii', left, top))
            return 1
        if msg == 0x1011:  # LVM_GETSTRINGWIDTH
            return self._native_text_width(self._read_text(lParam, wide))
        if msg == 0x1012:  # LVM_HITTEST
            x, y = self._read_struct(lParam, '<ii')
            index, sub = self._lv_hit(win, x, y)
            self._mem_write(lParam + 8, struct.pack('<Iii', 0x4 if index >= 0 else 0x1,
                                                    index, sub))
            return index & 0xFFFFFFFF
        if msg == 0x1039:  # LVM_SUBITEMHITTEST
            x, y = self._read_struct(lParam, '<ii')
            index, sub = self._lv_hit(win, x, y)
            self._mem_write(lParam + 8, struct.pack('<Iii', 0x4 if index >= 0 else 0x1,
                                                    index, sub))
            return index & 0xFFFFFFFF
        if msg == 0x1013:  # LVM_ENSUREVISIBLE
            if 0 <= wParam < len(items):
                self._lv_ensure_visible(win, wParam)
            return 1
        if msg == 0x1014:  # LVM_SCROLL
            dx = signed_w
            dy = lParam - (1 << 32) if lParam & 0x80000000 else lParam
            cell_w, cell_h, _, _, column_major = self.lv_grid(win)
            if column_major:
                self._lv_scroll_lines(win, int(dx / cell_w))
            else:
                self._lv_scroll_lines(win, int(dy / cell_h))
            return 1
        if msg in (0x1015, 0x102A):  # LVM_REDRAWITEMS, LVM_UPDATE
            self._invalidate_native(win)
            return 1
        if msg == 0x1019:  # LVM_GETCOLUMN
            if not 0 <= wParam < len(st['columns']):
                return 0
            column = st['columns'][wParam]
            info = self._lv_column_struct(lParam, wide)
            if info['mask'] & 0x1:
                self._mem_write(lParam + 4, struct.pack('<I', column['fmt']))
            if info['mask'] & 0x2:
                self._mem_write(lParam + 8, struct.pack('<i', column['width']))
            if info['mask'] & 0x4 and info['text_ptr']:
                if wide:
                    self._copy_text_out(info['text_ptr'], info['cch'], column['text'])
                else:
                    data = column['text'].encode(config.ANSI_CODEPAGE, 'replace')
                    data = data[:max(0, info['cch'] - 1)]
                    self._mem_write(info['text_ptr'], data + b'\x00')
            if info['mask'] & 0x8:
                self._mem_write(lParam + 20, struct.pack('<i', column['sub']))
            if info['mask'] & 0x20:
                self._mem_write(lParam + 28, struct.pack('<i', column.get('order', wParam)))
            return 1
        if msg == 0x101A:  # LVM_SETCOLUMN
            if not 0 <= wParam < len(st['columns']):
                return 0
            columns = [dict(c) for c in st['columns']]
            self._lv_apply_column(columns[wParam], self._lv_column_struct(lParam, wide))
            st['columns'] = columns
            return 1
        if msg == 0x101B:  # LVM_INSERTCOLUMN
            info = self._lv_column_struct(lParam, wide)
            index = max(0, min(wParam, len(st['columns'])))
            column = {'text': '', 'width': 60, 'fmt': 0, 'sub': index, 'order': index}
            self._lv_apply_column(column, info)
            columns = [dict(c) for c in st['columns']]
            for c in columns:
                if c.get('order', 0) >= column['order']:
                    c['order'] = c.get('order', 0) + 1
            columns.insert(index, column)
            st['columns'] = columns
            self._invalidate_native(win)
            return index
        if msg == 0x101C:  # LVM_DELETECOLUMN
            if not 0 <= wParam < len(st['columns']):
                return 0
            columns = [dict(c) for c in st['columns']]
            removed = columns.pop(wParam)
            for c in columns:
                if c.get('order', 0) > removed.get('order', 0):
                    c['order'] -= 1
            st['columns'] = columns
            return 1
        if msg == 0x101D:  # LVM_GETCOLUMNWIDTH
            return st['columns'][wParam]['width'] if 0 <= wParam < len(st['columns']) else 0
        if msg == 0x101E:  # LVM_SETCOLUMNWIDTH
            if 0 <= wParam < len(st['columns']):
                width = lParam & 0xFFFF
                if width >= 0xFFFE:  # LVSCW_AUTOSIZE(_USEHEADER)
                    column = st['columns'][wParam]
                    icon = self.lv_icon_space(win) if column['sub'] == 0 else 0
                    width = max([self._native_text_width(column['text']) + 12] +
                                [self._native_text_width(
                                    self._lv_item_text(win, i, column['sub'])) + 12 + icon
                                 for i in range(min(len(items), 200))])
                columns = [dict(c) for c in st['columns']]
                columns[wParam]['width'] = width - 0x10000 if width & 0x8000 else width
                st['columns'] = columns
            return 1
        if msg == 0x101F:  # LVM_GETHEADER
            return st['header']
        if msg == 0x1027:  # LVM_GETTOPINDEX
            return st['top']
        if msg == 0x1028:  # LVM_GETCOUNTPERPAGE
            return self.lv_rows_per_page(win)
        if msg == 0x1029:  # LVM_GETORIGIN
            self._mem_write(lParam, struct.pack('<ii', 0, 0))
            return 1
        if msg == 0x102B:  # LVM_SETITEMSTATE
            _, _, _, state, state_mask = self._read_struct(lParam, '<IiiII')
            return self._lv_set_state(win, signed_w, state, state_mask)
        if msg == 0x102C:  # LVM_GETITEMSTATE
            if not 0 <= wParam < len(items):
                return 0
            state = items[wParam]['state'] | (self.LVIS_FOCUSED if st['focus'] == wParam else 0)
            return state & lParam
        if msg == 0x102D:  # LVM_GETITEMTEXT
            if not 0 <= wParam < len(items):
                return 0
            _, _, sub, _, _, text_ptr, cch = self._read_struct(lParam, '<IiiIIIi')
            text = self._lv_item_text(win, wParam, sub)
            if wide:
                return self._copy_text_out(text_ptr, cch, text)
            data = text.encode(config.ANSI_CODEPAGE, 'replace')[:max(0, cch - 1)]
            self._mem_write(text_ptr, data + b'\x00')
            return len(data)
        if msg == 0x102E:  # LVM_SETITEMTEXT
            if not 0 <= wParam < len(items):
                return 0
            info = self._lv_item_struct(lParam, wide)
            info['mask'] |= self.LVIF_TEXT
            text_ptr = info['text_ptr']
            text = None if text_ptr == self.LPSTR_TEXTCALLBACK else \
                (self._read_text(text_ptr, wide) if text_ptr else '')
            items[wParam]['texts'][info['sub']] = text
            items[wParam]['cache'].pop(info['sub'], None)
            st['dirty'] = True
            return 1
        if msg == 0x102F:  # LVM_SETITEMCOUNT (capacity hint without LVS_OWNERDATA)
            return 1
        if msg == 0x1030:  # LVM_SORTITEMS
            return self._lv_sort(win, lParam, wParam, False)
        if msg == 0x1051:  # LVM_SORTITEMSEX
            return self._lv_sort(win, lParam, wParam, True)
        if msg == 0x1032:  # LVM_GETSELECTEDCOUNT
            return sum(1 for item in items if item['state'] & self.LVIS_SELECTED)
        if msg == 0x1033:  # LVM_GETITEMSPACING (wParam: small icon view)
            cell_w, cell_h = self.LV_ICON_CELL if not wParam else \
                (st.get('cell_w') or 120, self.LV_ROW_H)
            return (cell_h << 16) | cell_w
        if msg == 0x1036:  # LVM_SETEXTENDEDLISTVIEWSTYLE
            previous = st['ex_style']
            mask = wParam or 0xFFFFFFFF
            st['ex_style'] = (previous & ~mask) | (lParam & mask)
            return previous
        if msg == 0x1037:  # LVM_GETEXTENDEDLISTVIEWSTYLE
            return st['ex_style']
        if msg == 0x103A:  # LVM_SETCOLUMNORDERARRAY
            count = min(wParam, len(st['columns']))
            order = struct.unpack(f'<{count}i', self.emu.uc.mem_read(lParam, 4 * count))
            columns = [dict(c) for c in st['columns']]
            for position, index in enumerate(order):
                if 0 <= index < len(columns):
                    columns[index]['order'] = position
            st['columns'] = columns
            return 1
        if msg == 0x103B:  # LVM_GETCOLUMNORDERARRAY
            count = min(wParam, len(st['columns']))
            order = [st['columns'].index(c) for c in self._lv_ordered_columns(win)][:count]
            self._mem_write(lParam, struct.pack(f'<{count}i', *order))
            return 1
        if msg == 0x1042:  # LVM_GETSELECTIONMARK
            return st['mark'] & 0xFFFFFFFF
        if msg == 0x1043:  # LVM_SETSELECTIONMARK
            previous, st['mark'] = st['mark'], lParam - (1 << 32) if lParam & 0x80000000 else lParam
            return previous & 0xFFFFFFFF
        if msg in (0x1076, 0x1017):  # LVM_EDITLABELW/A
            return self._lv_begin_edit(win, signed_w)
        if msg == 0x1018:  # LVM_GETEDITCONTROL
            return st.get('edit', (0, -1))[0]
        if msg == 0x108E:  # LVM_SETVIEW
            win.style = (win.style & ~0x3) | {0: 0, 1: 1, 2: 2, 3: 3, 4: 1}.get(wParam, 1)
            st['dirty'] = True
            return 1
        if msg == 0x108F:  # LVM_GETVIEW
            return self._lv_view(win)
        if 0x1000 <= msg < 0x1100:
            return 0
        if msg in (0x0114, 0x0115):  # WM_HSCROLL / WM_VSCROLL
            return 0
        return None

    def _header_message(self, win, msg, wParam, lParam):
        """SysHeader32 of a list view: its items are the list view's columns"""
        listview = self._native_window(win.nstate.get('listview'), 'LISTVIEW')
        columns = listview.nstate['columns'] if listview else []
        if msg == 0x1200:  # HDM_GETITEMCOUNT
            return len(columns)
        if msg in (0x1203, 0x120B):  # HDM_GETITEMA/W
            if not 0 <= wParam < len(columns):
                return 0
            mask = struct.unpack('<I', self.emu.uc.mem_read(lParam, 4))[0]
            column = columns[wParam]
            if mask & 0x1:  # HDI_WIDTH
                self._mem_write(lParam + 4, struct.pack('<i', column['width']))
            if mask & 0x4:  # HDI_FORMAT
                self._mem_write(lParam + 20, struct.pack('<I', column.get('hdfmt', column['fmt'])))
            if mask & 0x80:  # HDI_ORDER
                self._mem_write(lParam + 32, struct.pack('<i', column.get('order', wParam)))
            return 1
        if msg in (0x1204, 0x120C):  # HDM_SETITEMA/W
            if not 0 <= wParam < len(columns):
                return 0
            mask, cxy, _, _, _, fmt = self._read_struct(lParam, '<IiIIII')
            new_columns = [dict(c) for c in columns]
            if mask & 0x1:
                new_columns[wParam]['width'] = cxy
            if mask & 0x4:
                new_columns[wParam]['hdfmt'] = fmt
            listview.nstate['columns'] = new_columns
            return 1
        if msg == 0x1207:  # HDM_GETITEMRECT
            if not 0 <= wParam < len(columns):
                return 0
            left = sum(c['width'] for c in sorted(columns, key=lambda c: c.get('order', 0))
                       if c.get('order', 0) < columns[wParam].get('order', 0))
            self._mem_write(lParam, struct.pack('<iiii', left, 0, left + columns[wParam]['width'],
                                                self.LV_HEADER_H))
            return 1
        return None

    def _native_text_width(self, text):
        font = self.gui and (getattr(self.gui, 'font_list', None) or self.gui.font)
        if font:
            try:
                return font.size(text)[0]
            except (ValueError, UnicodeError) as e:  # Text pygame cannot measure
                log.debug(f"Text width of {text!r}: {e}")
        return 7 * len(text)
