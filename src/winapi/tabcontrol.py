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

"""WinAPIHandler mixin: the tab control (SysTabControl32)"""

import struct


class TabControlMixin:
    """SysTabControl32: one row of tabs (TCM_INSERTITEM...), the selected one
    changed by a click with TCN_SELCHANGING / TCN_SELCHANGE"""

    TAB_ROW_H = 20
    TCN_SELCHANGE, TCN_SELCHANGING = -551, -552
    # TCM_*W messages -> their A counterparts
    TAB_WIDE_MESSAGES = {0x133C: 0x1305, 0x133D: 0x1306, 0x133E: 0x1307}

    @staticmethod
    def _tab_state(win):
        st = win.nstate
        if 'tabs' not in st:
            st.update(tabs=[], sel=-1, focus=-1, imagelist=0, item_size=None, extra=4)
        return st

    @staticmethod
    def tab_label(text):
        """A tab's text as shown: & marks the mnemonic, && is an &"""
        return text.replace('&&', '\0').replace('&', '').replace('\0', '&')

    def _tab_rects(self, win):
        """Tab rectangles (left, top, right, bottom) in client coordinates. A
        TCS_MULTILINE control wraps them into rows filling its width, the row
        of the selected tab at the bottom next to the page."""
        st = self._tab_state(win)
        imagelist = self._imagelist(st['imagelist']) if st['imagelist'] else None
        widths = []
        for tab in st['tabs']:
            if st['item_size'] and st['item_size'][0] and win.style & 0x400:  # TCS_FIXEDWIDTH
                width = st['item_size'][0]
            else:
                width = self._native_text_width(self.tab_label(tab['text'])) + 12
                if imagelist and tab['image'] >= 0:
                    width += imagelist['cx'] + 4
            widths.append(width)
        room = (self.gui.client_size(win)[0] if self.gui else 0) - 4
        rows, row = [], []
        for i, width in enumerate(widths):
            if win.style & 0x200 and row and sum(widths[j] for j in row) + width > room:
                rows.append(row)
                row = []
            row.append(i)
        if row:
            rows.append(row)
        if len(rows) > 1 and not win.style & 0x800:  # Not TCS_RAGGEDRIGHT: fill the rows
            for row in rows:
                extra = max(0, room - sum(widths[i] for i in row))
                for k, i in enumerate(row):
                    widths[i] += extra // len(row) + (1 if k < extra % len(row) else 0)
        selected = next((r for r in rows if st['sel'] in r), None)
        if selected is not None:
            rows.remove(selected)
            rows.append(selected)
        rects = [None] * len(widths)
        for number, row in enumerate(rows):
            x, top = 2, 2 + number * self.TAB_ROW_H
            for i in row:
                rects[i] = (x, top, x + widths[i], top + self.TAB_ROW_H)
                x += widths[i]
        return rects

    def _tab_rows(self, win):
        rects = self._tab_rects(win)
        return len({r[1] for r in rects}) or 1

    def _tab_read_item(self, address, wide, old=None):
        """TCITEM (mask, state, state mask, text, cch, image, lParam...) -> dict"""
        mask, _, _, text_ptr, _, image = struct.unpack('<5Ii', self.emu.uc.mem_read(address, 24))
        item = dict(old) if old else {'text': '', 'image': -1, 'lparam': 0}
        if mask & 0x1 and text_ptr:  # TCIF_TEXT
            item['text'] = self._read_text(text_ptr, wide)
        if mask & 0x2:  # TCIF_IMAGE
            item['image'] = image
        if mask & 0x8:  # TCIF_PARAM (the app's extra bytes; 4 of them by default)
            item['lparam'] = struct.unpack('<I', self.emu.uc.mem_read(address + 24, 4))[0]
        return item

    def _tab_select(self, win, index, notify):
        st = self._tab_state(win)
        if index == st['sel'] or not 0 <= index < len(st['tabs']):
            return
        if notify and self._notify_simple(win, self.TCN_SELCHANGING):
            return  # The parent keeps the page
        st['sel'] = st['focus'] = index
        if notify:
            self._notify_simple(win, self.TCN_SELCHANGE)

    def _tab_message(self, win, msg, wParam, lParam):
        """SysTabControl32 messages; None for the default processing"""
        st = self._tab_state(win)
        tabs = st['tabs']
        wide = msg in self.TAB_WIDE_MESSAGES
        msg = self.TAB_WIDE_MESSAGES.get(msg, msg)
        if msg in (self.WM_LBUTTONDOWN, self.WM_LBUTTONDBLCLK):
            x, y = lParam & 0xFFFF, (lParam >> 16) & 0xFFFF
            for i, (left, top, right, bottom) in enumerate(self._tab_rects(win)):
                if left <= x < right and top <= y < bottom:
                    self._tab_select(win, i, True)
                    break
            return 0
        if msg == 0x1302:  # TCM_GETIMAGELIST
            return st['imagelist']
        if msg == 0x1303:  # TCM_SETIMAGELIST
            previous, st['imagelist'] = st['imagelist'], lParam
            return previous
        if msg == 0x1304:  # TCM_GETITEMCOUNT
            return len(tabs)
        if msg == 0x1305:  # TCM_GETITEM
            if not 0 <= wParam < len(tabs) or not lParam:
                return 0
            tab = tabs[wParam]
            mask, _, _, text_ptr, cch = struct.unpack('<5I', self.emu.uc.mem_read(lParam, 20))
            if mask & 0x1 and text_ptr and cch:
                self._write_text(text_ptr, tab['text'][:cch - 1], wide)
            if mask & 0x2:
                self._mem_write(lParam + 20, struct.pack('<i', tab['image']))
            if mask & 0x8:
                self._mem_write(lParam + 24, struct.pack('<I', tab['lparam']))
            return 1
        if msg in (0x1306, 0x1307):  # TCM_SETITEM, TCM_INSERTITEM
            if not lParam:
                return 0xFFFFFFFF if msg == 0x1307 else 0
            if msg == 0x1306:
                if not 0 <= wParam < len(tabs):
                    return 0
                tabs[wParam] = self._tab_read_item(lParam, wide, tabs[wParam])
                return 1
            index = max(0, min(wParam, len(tabs)))
            tabs.insert(index, self._tab_read_item(lParam, wide))
            if st['sel'] < 0:
                st['sel'] = st['focus'] = 0
            elif index <= st['sel']:
                st['sel'] += 1
            return index
        if msg == 0x1308:  # TCM_DELETEITEM
            if not 0 <= wParam < len(tabs):
                return 0
            del tabs[wParam]
            if st['sel'] >= len(tabs) or wParam < st['sel']:
                st['sel'] = min(max(st['sel'] - 1, 0), len(tabs) - 1)
            return 1
        if msg == 0x1309:  # TCM_DELETEALLITEMS
            tabs.clear()
            st['sel'] = st['focus'] = -1
            return 1
        if msg == 0x130A:  # TCM_GETITEMRECT
            rects = self._tab_rects(win)
            if not 0 <= wParam < len(rects) or not lParam:
                return 0
            self._mem_write(lParam, struct.pack('<4i', *rects[wParam]))
            return 1
        if msg in (0x130B, 0x132F):  # TCM_GETCURSEL, TCM_GETCURFOCUS
            return (st['sel'] if msg == 0x130B else st['focus']) & 0xFFFFFFFF
        if msg in (0x130C, 0x1330):  # TCM_SETCURSEL, TCM_SETCURFOCUS (no notifications)
            previous = st['sel']
            if 0 <= wParam < len(tabs):
                st['sel'] = st['focus'] = wParam
                return previous & 0xFFFFFFFF
            return 0xFFFFFFFF
        if msg == 0x130D:  # TCM_HITTEST(0, TCHITTESTINFO *)
            x, y = struct.unpack('<2i', self.emu.uc.mem_read(lParam, 8))
            for i, (left, top, right, bottom) in enumerate(self._tab_rects(win)):
                if left <= x < right and top <= y < bottom:
                    self._mem_write(lParam + 8, struct.pack('<I', 6))  # TCHT_ONITEM
                    return i
            self._mem_write(lParam + 8, struct.pack('<I', 1))  # TCHT_NOWHERE
            return 0xFFFFFFFF
        if msg == 0x130E:  # TCM_SETITEMEXTRA
            st['extra'] = wParam
            return 1
        if msg == 0x1328:  # TCM_ADJUSTRECT(larger, RECT *): window <-> display area
            left, top, right, bottom = struct.unpack('<4i', self.emu.uc.mem_read(lParam, 16))
            row = 2 + self.TAB_ROW_H * self._tab_rows(win)
            if wParam:
                left, top, right, bottom = left - 4, top - row - 4, right + 4, bottom + 4
            else:
                left, top, right, bottom = left + 4, top + row + 4, right - 4, bottom - 4
            self._mem_write(lParam, struct.pack('<4i', left, top, right, bottom))
            return 0
        if msg == 0x1329:  # TCM_SETITEMSIZE
            previous = st['item_size'] or (0, self.TAB_ROW_H)
            st['item_size'] = (lParam & 0xFFFF, lParam >> 16)
            return (previous[1] << 16) | previous[0]
        if msg == 0x132C:  # TCM_GETROWCOUNT
            return self._tab_rows(win)
        if 0x1300 <= msg < 0x1340:
            return 0
        return None
