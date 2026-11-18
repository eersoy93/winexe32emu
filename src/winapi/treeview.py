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

"""WinAPIHandler mixin: TreeView control (SysTreeView32)"""

import struct


class TreeViewMixin:
    """TreeView control: items in win.nstate ('items': handle -> item dict,
    'roots': top-level handles); the GUI draws the visible rows"""

    # ---------- TreeView ----------

    TVIF_TEXT, TVIF_IMAGE, TVIF_PARAM, TVIF_STATE = 0x1, 0x2, 0x4, 0x8
    TVIF_HANDLE, TVIF_SELECTEDIMAGE, TVIF_CHILDREN = 0x10, 0x20, 0x40
    TVIS_SELECTED, TVIS_EXPANDED, TVIS_EXPANDEDONCE = 0x2, 0x20, 0x40
    TVI_ROOT, TVI_FIRST, TVI_LAST, TVI_SORT = 0xFFFF0000, 0xFFFF0001, 0xFFFF0002, 0xFFFF0003
    TVE_COLLAPSE, TVE_EXPAND, TVE_TOGGLE = 1, 2, 3
    TVC_UNKNOWN, TVC_BYMOUSE, TVC_BYKEYBOARD = 0, 1, 2
    TVS_HASBUTTONS, TVS_HASLINES, TVS_LINESATROOT = 0x1, 0x2, 0x4
    TV_ROW_H = 18
    TV_INDENT = 19
    # Notifications: (ANSI, Unicode) codes
    TVN_SELCHANGING, TVN_SELCHANGED = (-401, -450), (-402, -451)
    TVN_ITEMEXPANDING, TVN_ITEMEXPANDED = (-405, -454), (-406, -455)
    TVN_DELETEITEM, TVN_KEYDOWN = (-409, -458), (-412, -412)

    # TVM_* A/W pairs: the Unicode message -> the ANSI one
    TV_WIDE_MESSAGES = {0x1132: 0x1100, 0x113E: 0x110C, 0x113F: 0x110D}

    def _tv_new_state(self):
        return {'items': {}, 'roots': [], 'next': 1, 'selected': 0, 'top': 0,
                'imagelist': 0, 'unicode': False}

    # ---- Item tree ----

    def _tv_children(self, st, parent):
        return st['roots'] if not parent else st['items'][parent]['children']

    def _tv_visible(self, st):
        """Handles of the rows shown: roots and the children of expanded items"""
        rows = []

        def walk(handles):
            for handle in handles:
                rows.append(handle)
                item = st['items'][handle]
                if item['state'] & self.TVIS_EXPANDED:
                    walk(item['children'])
        walk(st['roots'])
        return rows

    def tv_rows(self, win):
        """(handle, item, depth) of the visible rows, from the first one"""
        st = win.nstate
        rows = []

        def walk(handles, depth):
            for handle in handles:
                item = st['items'][handle]
                rows.append((handle, item, depth))
                if item['state'] & self.TVIS_EXPANDED:
                    walk(item['children'], depth + 1)
        walk(st['roots'], 0)
        return rows

    def tv_has_buttons(self, item):
        """Does an item show a +/- box (children, or cChildren says so)?"""
        return bool(item['children']) or item['cchildren'] == 1

    def _tv_lines(self, win):
        _, height = self.gui.client_size(win)
        return max(1, height // self.TV_ROW_H)

    def _tv_scroll_to(self, win, top):
        st = win.nstate
        count = len(self._tv_visible(st))
        st['top'] = max(0, min(top, count - self._tv_lines(win)))

    def _tv_ensure_visible(self, win, handle):
        st = win.nstate
        parent = st['items'][handle]['parent'] if handle in st['items'] else 0
        while parent:
            st['items'][parent]['state'] |= self.TVIS_EXPANDED
            parent = st['items'][parent]['parent']
        rows = self._tv_visible(st)
        if handle not in rows:
            return
        index = rows.index(handle)
        lines = self._tv_lines(win)
        if index < st['top']:
            st['top'] = index
        elif index >= st['top'] + lines:
            st['top'] = index - lines + 1

    def _tv_item_struct(self, address, wide):
        """TVITEM -> dict of its fields (text only with TVIF_TEXT)"""
        (mask, handle, state, state_mask, text_ptr, cch, image, selimage, cchildren,
         param) = self._read_struct(address, '<IIIIIiiiiI')
        info = {'mask': mask, 'handle': handle, 'state': state, 'state_mask': state_mask,
                'text_ptr': text_ptr, 'cch': cch, 'image': image, 'selimage': selimage,
                'cchildren': cchildren, 'param': param}
        if mask & self.TVIF_TEXT:
            info['text'] = (self._read_text(text_ptr, wide)
                            if text_ptr and text_ptr != 0xFFFFFFFF else '')
        return info

    def _tv_apply(self, item, info):
        mask = info['mask']
        if mask & self.TVIF_TEXT:
            item['text'] = info['text']
        if mask & self.TVIF_IMAGE:
            item['image'] = info['image']
        if mask & self.TVIF_SELECTEDIMAGE:
            item['selimage'] = info['selimage']
        if mask & self.TVIF_CHILDREN:
            item['cchildren'] = info['cchildren']
        if mask & self.TVIF_PARAM:
            item['param'] = info['param']
        if mask & self.TVIF_STATE:
            keep = item['state'] & ~info['state_mask'] & ~self.TVIS_SELECTED
            item['state'] = keep | (info['state'] & info['state_mask'] & ~self.TVIS_SELECTED)

    def _tv_insert(self, win, address, wide):
        """TVM_INSERTITEM: TVINSERTSTRUCT {hParent, hInsertAfter, TVITEM}"""
        st = win.nstate
        parent, after = self._read_struct(address, '<II')
        if parent in (0, self.TVI_ROOT):
            parent = 0
        elif parent not in st['items']:
            return 0
        info = self._tv_item_struct(address + 8, wide)
        handle = st['next']
        st['next'] += 1
        item = {'parent': parent, 'children': [], 'text': '', 'image': 0, 'selimage': 0,
                'cchildren': 0, 'param': 0, 'state': 0}
        self._tv_apply(item, info)
        st['items'][handle] = item
        siblings = self._tv_children(st, parent)
        if after == self.TVI_FIRST:
            siblings.insert(0, handle)
        elif after == self.TVI_SORT:
            position = len(siblings)
            for i, other in enumerate(siblings):
                if st['items'][other]['text'].lower() > item['text'].lower():
                    position = i
                    break
            siblings.insert(position, handle)
        elif after in siblings:
            siblings.insert(siblings.index(after) + 1, handle)
        else:
            siblings.append(handle)
        return handle

    def _tv_payload(self, st, handle):
        """TVITEM of a notification (handle, state, lParam)"""
        item = st['items'].get(handle)
        if item is None:
            return struct.pack('<10I', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        return struct.pack('<IIIIIiiiiI', self.TVIF_HANDLE | self.TVIF_STATE | self.TVIF_PARAM,
                           handle, item['state'], 0xFFFF, 0, 0, item['image'],
                           item['selimage'], item['cchildren'], item['param'])

    def _tv_notify(self, win, codes, action, old, new):
        """NMTREEVIEW notification; returns the parent's result"""
        st = win.nstate
        payload = (struct.pack('<I', action) + self._tv_payload(st, old) +
                   self._tv_payload(st, new) + struct.pack('<ii', 0, 0))
        return self._notify_simple(win, codes[1 if st['unicode'] else 0], payload)

    def _tv_delete(self, win, handle):
        """Delete an item and its children (TVN_DELETEITEM for each)"""
        st = win.nstate
        item = st['items'].get(handle)
        if item is None:
            return False
        for child in list(item['children']):
            self._tv_delete(win, child)
        self._tv_notify(win, self.TVN_DELETEITEM, 0, handle, 0)
        self._tv_children(st, item['parent']).remove(handle)
        del st['items'][handle]
        if st['selected'] == handle:
            st['selected'] = 0
        return True

    def _tv_select(self, win, handle, action):
        """Select an item: TVN_SELCHANGING (TRUE cancels), then TVN_SELCHANGED"""
        st = win.nstate
        old = st['selected']
        if handle == old or (handle and handle not in st['items']):
            if handle:
                self._tv_ensure_visible(win, handle)
            return bool(handle)
        if self._tv_notify(win, self.TVN_SELCHANGING, action, old, handle):
            return False
        if old in st['items']:
            st['items'][old]['state'] &= ~self.TVIS_SELECTED
        st['selected'] = handle
        if handle:
            st['items'][handle]['state'] |= self.TVIS_SELECTED
            self._tv_ensure_visible(win, handle)
        self._tv_notify(win, self.TVN_SELCHANGED, action, old, handle)
        return True

    def _tv_expand(self, win, handle, code, notify=True):
        """Expand/collapse an item (TVN_ITEMEXPANDING may cancel)"""
        st = win.nstate
        item = st['items'].get(handle)
        if item is None:
            return False
        code &= 0x3
        expanded = bool(item['state'] & self.TVIS_EXPANDED)
        expand = not expanded if code == self.TVE_TOGGLE else code == self.TVE_EXPAND
        if expand == expanded:
            return True
        action = self.TVE_EXPAND if expand else self.TVE_COLLAPSE
        if notify and self._tv_notify(win, self.TVN_ITEMEXPANDING, action, 0, handle):
            return False
        item = st['items'].get(handle)  # The parent may have changed the tree
        if item is None:
            return False
        if expand:
            item['state'] |= self.TVIS_EXPANDED | self.TVIS_EXPANDEDONCE
        else:
            item['state'] &= ~self.TVIS_EXPANDED
            # The selection inside goes to the collapsed item
            selected = st['selected']
            while selected:
                selected = st['items'][selected]['parent'] if selected in st['items'] else 0
                if selected == handle:
                    self._tv_select(win, handle, self.TVC_UNKNOWN)
                    break
        if notify:
            self._tv_notify(win, self.TVN_ITEMEXPANDED, action, 0, handle)
        self._tv_scroll_to(win, st['top'])
        return True

    def _tv_next(self, win, code, handle):
        """TVM_GETNEXTITEM"""
        st = win.nstate
        item = st['items'].get(handle)
        if code == 0:  # TVGN_ROOT
            return st['roots'][0] if st['roots'] else 0
        if code == 9:  # TVGN_CARET
            return st['selected']
        if code == 5:  # TVGN_FIRSTVISIBLE
            rows = self._tv_visible(st)
            return rows[st['top']] if st['top'] < len(rows) else 0
        if item is None:
            return 0
        if code in (1, 2):  # TVGN_NEXT / TVGN_PREVIOUS
            siblings = self._tv_children(st, item['parent'])
            index = siblings.index(handle) + (1 if code == 1 else -1)
            return siblings[index] if 0 <= index < len(siblings) else 0
        if code == 3:  # TVGN_PARENT
            return item['parent']
        if code == 4:  # TVGN_CHILD
            return item['children'][0] if item['children'] else 0
        if code in (6, 7):  # TVGN_NEXTVISIBLE / TVGN_PREVIOUSVISIBLE
            rows = self._tv_visible(st)
            if handle not in rows:
                return 0
            index = rows.index(handle) + (1 if code == 6 else -1)
            return rows[index] if 0 <= index < len(rows) else 0
        return 0

    def tv_item_rect(self, win, handle, text_only=False):
        """(left, top, right, bottom) of an item's row, or of its label with
        text_only; None if it is not visible"""
        st = win.nstate
        rows = self.tv_rows(win)
        for index, (row_handle, item, depth) in enumerate(rows):
            if row_handle == handle:
                top = (index - st['top']) * self.TV_ROW_H
                width, _ = self.gui.client_size(win)
                if not text_only:
                    return 0, top, width, top + self.TV_ROW_H
                left = self.tv_text_left(win, depth)
                return (left, top, left + self._native_text_width(item['text']) + 4,
                        top + self.TV_ROW_H)
        return None

    def tv_button_left(self, win, depth):
        """x of the +/- box column of a depth; the roots have one only with
        TVS_LINESATROOT (else it is left of the client area)"""
        at_root = 1 if win.style & self.TVS_LINESATROOT else 0
        return (depth + at_root - 1) * self.TV_INDENT + 2

    def tv_text_left(self, win, depth):
        """x of an item's label (after the box column and the icon)"""
        left = self.tv_button_left(win, depth) + self.TV_INDENT
        if win.nstate['imagelist']:
            left += 18
        return left

    def _tv_hit(self, win, x, y):
        """(handle, part) at a client point: part 'button', 'label' or None"""
        st = win.nstate
        index = st['top'] + y // self.TV_ROW_H
        rows = self.tv_rows(win)
        if y < 0 or not 0 <= index < len(rows):
            return 0, None
        handle, item, depth = rows[index]
        button = self.tv_button_left(win, depth)
        if win.style & self.TVS_HASBUTTONS and self.tv_has_buttons(item) and \
                button <= x < button + self.TV_INDENT:
            return handle, 'button'
        return handle, 'label'

    # ---- Messages ----

    def _tv_mouse(self, win, msg, lParam):
        st = win.nstate
        x = lParam & 0xFFFF
        y = (lParam >> 16) & 0xFFFF
        x, y = (x - 0x10000 if x & 0x8000 else x), (y - 0x10000 if y & 0x8000 else y)
        self.SetFocus([win.hwnd])
        width, height = self.gui.client_size(win)
        lines = self._tv_lines(win)
        count = len(self._tv_visible(st))
        if count > lines and x >= width - 16 and msg != self.WM_RBUTTONDOWN:
            # Vertical scroll bar: arrows and page areas
            if y < 16:
                self._tv_scroll_to(win, st['top'] - 1)
            elif y >= height - 16:
                self._tv_scroll_to(win, st['top'] + 1)
            else:
                thumb = 16 + int((height - 32) * st['top'] / max(1, count))
                self._tv_scroll_to(win, st['top'] + (lines if y > thumb else -lines))
            return 0
        handle, part = self._tv_hit(win, x, y)
        if msg == self.WM_LBUTTONDOWN:
            if part == 'button':
                self._tv_expand(win, handle, self.TVE_TOGGLE)
            elif handle:
                self._tv_select(win, handle, self.TVC_BYMOUSE)
            self._notify_simple(win, self.NM_CLICK)
        elif msg == self.WM_LBUTTONDBLCLK:
            if handle and part == 'label' and not self._notify_simple(win, self.NM_DBLCLK):
                self._tv_expand(win, handle, self.TVE_TOGGLE)
        elif msg == self.WM_RBUTTONDOWN:
            # Right-click highlights the item for the context menu (like a drop target)
            st['drophilite'] = handle
            if not self._notify_simple(win, self.NM_RCLICK):
                sx, sy = self.gui.client_origin(win)
                self._send(win.hwnd, self.WM_CONTEXTMENU, win.hwnd,
                           ((sy + y) & 0xFFFF) << 16 | ((sx + x) & 0xFFFF))
            st['drophilite'] = 0
        return 0

    def _tv_key(self, win, vk):
        st = win.nstate
        if self._notify_simple(win, self.TVN_KEYDOWN[0], struct.pack('<HI', vk, 0)):
            return 0
        rows = self._tv_visible(st)
        selected = st['selected']
        if vk == 0x0D:  # VK_RETURN
            self._notify_simple(win, self.NM_RETURN)
            return 0
        if not rows:
            return 0
        index = rows.index(selected) if selected in rows else -1
        item = st['items'].get(selected)
        target = None
        if vk == 0x26:  # Up
            target = rows[max(0, index - 1)]
        elif vk == 0x28:  # Down
            target = rows[min(len(rows) - 1, index + 1)]
        elif vk == 0x24:  # Home
            target = rows[0]
        elif vk == 0x23:  # End
            target = rows[-1]
        elif vk in (0x21, 0x22):  # Page Up / Page Down
            step = self._tv_lines(win) - 1 or 1
            target = rows[max(0, min(len(rows) - 1, index + (step if vk == 0x22 else -step)))]
        elif vk == 0x25 and item is not None:  # Left: collapse, or go to the parent
            if item['state'] & self.TVIS_EXPANDED:
                self._tv_expand(win, selected, self.TVE_COLLAPSE)
            elif item['parent']:
                target = item['parent']
        elif vk == 0x27 and item is not None:  # Right: expand, or go to the first child
            if not item['state'] & self.TVIS_EXPANDED and self.tv_has_buttons(item):
                self._tv_expand(win, selected, self.TVE_EXPAND)
            elif item['children']:
                target = item['children'][0]
        elif vk in (0x6B, 0x6D) and item is not None:  # Numpad + / -
            self._tv_expand(win, selected, self.TVE_EXPAND if vk == 0x6B else self.TVE_COLLAPSE)
        if target is None and index < 0 and vk in (0x26, 0x28):
            target = rows[0]
        if target:
            self._tv_select(win, target, self.TVC_BYKEYBOARD)
        return 0

    def _treeview_message(self, win, msg, wParam, lParam):
        """SysTreeView32 messages; None for the default processing"""
        st = win.nstate
        wide = msg in self.TV_WIDE_MESSAGES
        msg = self.TV_WIDE_MESSAGES.get(msg, msg)
        if msg in (self.WM_LBUTTONDOWN, self.WM_LBUTTONDBLCLK, self.WM_RBUTTONDOWN):
            return self._tv_mouse(win, msg, lParam)
        if msg == self.WM_KEYDOWN:
            return self._tv_key(win, wParam)
        if msg == self.WM_MOUSEWHEEL:
            delta = (wParam >> 16) - 0x10000 if wParam & 0x80000000 else wParam >> 16
            self._tv_scroll_to(win, st['top'] - 3 * delta // 120)
            return 0
        if msg == 0x2005:  # CCM_SETUNICODEFORMAT
            previous, st['unicode'] = st['unicode'], bool(wParam)
            return int(previous)
        if msg == 0x2006:  # CCM_GETUNICODEFORMAT
            return int(st['unicode'])
        if msg == 0x1100:  # TVM_INSERTITEM
            return self._tv_insert(win, lParam, wide)
        if msg == 0x1101:  # TVM_DELETEITEM
            if lParam in (0, self.TVI_ROOT):
                for handle in list(st['roots']):
                    self._tv_delete(win, handle)
                st['top'] = 0
                return 1
            result = self._tv_delete(win, lParam)
            self._tv_scroll_to(win, st['top'])
            return int(result)
        if msg == 0x1102:  # TVM_EXPAND
            return int(self._tv_expand(win, lParam, wParam))
        if msg == 0x1104:  # TVM_GETITEMRECT (lParam: the item handle in, RECT out)
            if not lParam:
                return 0
            handle = struct.unpack('<I', self.emu.uc.mem_read(lParam, 4))[0]
            rect = self.tv_item_rect(win, handle, bool(wParam))
            if rect is None:
                return 0
            self._mem_write(lParam, struct.pack('<iiii', *rect))
            return 1
        if msg == 0x1105:  # TVM_GETCOUNT
            return len(st['items'])
        if msg == 0x1106:  # TVM_GETINDENT
            return self.TV_INDENT
        if msg == 0x1108:  # TVM_GETIMAGELIST
            return st['imagelist'] if wParam == 0 else 0
        if msg == 0x1109:  # TVM_SETIMAGELIST (TVSIL_NORMAL only)
            if wParam != 0:
                return 0
            previous, st['imagelist'] = st['imagelist'], lParam
            return previous
        if msg == 0x110A:  # TVM_GETNEXTITEM
            return self._tv_next(win, wParam, lParam)
        if msg == 0x110B:  # TVM_SELECTITEM
            if wParam & 0xFF == 9:  # TVGN_CARET
                return int(self._tv_select(win, lParam, self.TVC_UNKNOWN))
            if wParam & 0xFF == 5 and lParam in st['items']:  # TVGN_FIRSTVISIBLE
                rows = self._tv_visible(st)
                if lParam in rows:
                    self._tv_scroll_to(win, rows.index(lParam))
                return 1
            return 1 if wParam & 0xFF == 8 else 0  # TVGN_DROPHILITE
        if msg == 0x110C:  # TVM_GETITEM
            info = self._tv_item_struct(lParam, wide)
            item = st['items'].get(info['handle'])
            if item is None:
                return 0
            mask = info['mask']
            if mask & self.TVIF_TEXT and info['text_ptr'] and info['cch'] > 0:
                units = self._text_units(item['text'], wide)[:info['cch'] - 1]
                self._write_units(info['text_ptr'], units, wide)
            self._mem_write(lParam + 8, struct.pack('<I', item['state'] &
                                                    (info['state_mask'] or 0xFFFF)))
            self._mem_write(lParam + 24, struct.pack('<iiiI', item['image'], item['selimage'],
                                                     item['cchildren'], item['param']))
            return 1
        if msg == 0x110D:  # TVM_SETITEM
            info = self._tv_item_struct(lParam, wide)
            item = st['items'].get(info['handle'])
            if item is None:
                return 0
            self._tv_apply(item, info)
            return 1
        if msg == 0x1111:  # TVM_HITTEST: TVHITTESTINFO {pt, flags, hItem}
            x, y = self._read_struct(lParam, '<ii')
            handle, part = self._tv_hit(win, x, y)
            flags = {'button': 0x10, 'label': 0x4}.get(part, 0x1)  # ONITEMBUTTON / LABEL / NOWHERE
            self._mem_write(lParam + 8, struct.pack('<II', flags, handle))
            return handle
        if msg == 0x1113:  # TVM_SORTCHILDREN
            siblings = self._tv_children(st, 0 if lParam in (0, self.TVI_ROOT) else lParam)
            siblings.sort(key=lambda h: st['items'][h]['text'].lower())
            return 1
        if msg == 0x1114:  # TVM_ENSUREVISIBLE
            if lParam in st['items']:
                self._tv_ensure_visible(win, lParam)
                return 1
            return 0
        if msg == 0x1116:  # TVM_ENDEDITLABELNOW
            return 1
        if msg == 0x1110:  # TVM_GETVISIBLECOUNT
            return self._tv_lines(win)
        if 0x1100 <= msg < 0x1200:
            return 0
        return None
