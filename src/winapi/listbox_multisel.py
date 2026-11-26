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

"""WinAPIHandler mixin: list boxes with more than one selected item
(LBS_MULTIPLESEL, LBS_EXTENDEDSEL)

Such a list keeps the set of its selected items besides its caret item (the
one with the focus rectangle, control.sel_index). Access 95's Show Table
dialog adds the tables selected in one (LB_GETSELITEMS)."""

import struct

from unicorn import UcError

LBS_MULTIPLESEL, LBS_EXTENDEDSEL = 0x0008, 0x0800

LB_SELITEMRANGEEX, LB_SETSEL, LB_GETSEL = 0x0183, 0x0185, 0x0187
LB_GETCURSEL, LB_SETCURSEL = 0x0188, 0x0186
LB_GETSELCOUNT, LB_GETSELITEMS = 0x0190, 0x0191
LB_SELITEMRANGE, LB_SETANCHORINDEX, LB_GETANCHORINDEX = 0x019B, 0x019C, 0x019D
LB_SETCARETINDEX, LB_GETCARETINDEX = 0x019E, 0x019F
LB_ADDSTRING, LB_INSERTSTRING, LB_DELETESTRING, LB_RESETCONTENT = 0x0180, 0x0181, 0x0182, 0x0184
LB_ERR = 0xFFFFFFFF


def is_multi_select(control):
    """Does the LISTBOX control select more than one item?"""
    return control.class_name == 'LISTBOX' and bool(control.style & (LBS_MULTIPLESEL |
                                                                      LBS_EXTENDEDSEL))


def selected_items(control):
    """The selected item indexes of a multiple-selection list (a set)"""
    selected = getattr(control, 'multi_selected', None)
    if selected is None:
        selected = control.multi_selected = set()
    return selected


def item_selected(control, index):
    """Is item index of a LISTBOX shown selected?"""
    if is_multi_select(control):
        return index in selected_items(control)
    return index == control.sel_index


def click_item(control, index, ctrl=False, shift=False):
    """A left click on item index of a multiple-selection list: LBS_MULTIPLESEL
    toggles it; LBS_EXTENDEDSEL selects only it, Ctrl toggles it and Shift
    selects the range from the anchor"""
    selected = selected_items(control)
    anchor = getattr(control, 'sel_anchor_item', -1)
    if control.style & LBS_EXTENDEDSEL and shift and 0 <= anchor < len(control.items):
        low, high = sorted((anchor, index))
        if not ctrl:
            selected.clear()
        selected.update(range(low, high + 1))
    elif control.style & LBS_EXTENDEDSEL and not ctrl:
        selected.clear()
        selected.add(index)
        control.sel_anchor_item = index
    else:
        selected.symmetric_difference_update({index})
        control.sel_anchor_item = index
    control.sel_index = index


class ListBoxMultiSelMixin:
    """The LB_* messages of a multiple-selection list box"""

    def _multi_select_message(self, control, msg, wparam, lparam):
        """Handle msg for a LISTBOX; None to leave it to the common code (the
        selection is still kept right when items come and go)"""
        if control.class_name != 'LISTBOX':
            return None
        count = len(control.items)
        if msg == LB_GETSEL:
            if wparam >= count:
                return LB_ERR
            return 1 if item_selected(control, wparam) else 0
        if msg == LB_GETCARETINDEX:
            return max(control.sel_index, 0) if count else 0
        if not is_multi_select(control):
            if msg in (LB_GETSELCOUNT, LB_GETSELITEMS, LB_SETSEL, LB_SELITEMRANGE,
                       LB_SELITEMRANGEEX):
                return LB_ERR  # Only for multiple-selection lists
            return None
        selected = selected_items(control)
        if msg in (LB_INSERTSTRING, LB_DELETESTRING, LB_RESETCONTENT):
            self._multi_select_shift(control, msg, wparam)
            return None
        if msg == LB_SETSEL:
            select = bool(wparam)
            target = range(count) if lparam == 0xFFFFFFFF else (lparam,)
            if lparam != 0xFFFFFFFF and lparam >= count:
                return LB_ERR
            for item in target:
                (selected.add if select else selected.discard)(item)
            if lparam != 0xFFFFFFFF:
                control.sel_index = lparam
            return 0
        if msg == LB_GETSELCOUNT:
            return len([i for i in selected if i < count])
        if msg == LB_GETSELITEMS:
            items = sorted(i for i in selected if i < count)[:wparam]
            if items and lparam:
                try:
                    self.emu.uc.mem_write(lparam, struct.pack(f'<{len(items)}i', *items))
                except UcError:
                    return LB_ERR
            return len(items)
        if msg in (LB_SELITEMRANGE, LB_SELITEMRANGEEX):
            if msg == LB_SELITEMRANGE:
                select, first, last = bool(wparam), lparam & 0xFFFF, lparam >> 16
            else:
                first, last = wparam, lparam
                select = first <= last
            low, high = sorted((first, last))
            for item in range(low, min(high, count - 1) + 1):
                (selected.add if select else selected.discard)(item)
            return 0
        if msg == LB_GETCURSEL:
            # The caret item (the one with the focus rectangle)
            return max(control.sel_index, 0)
        if msg == LB_SETCURSEL:
            return LB_ERR  # Not for multiple-selection lists
        if msg == LB_SETCARETINDEX:
            if wparam >= count:
                return LB_ERR
            control.sel_index = wparam
            return 0
        if msg == LB_SETANCHORINDEX:
            if wparam >= count:
                return LB_ERR
            control.sel_anchor_item = wparam
            return 0
        if msg == LB_GETANCHORINDEX:
            return max(getattr(control, 'sel_anchor_item', 0), 0)
        return None

    @staticmethod
    def _multi_select_shift(control, msg, index):
        """Keep the selected indexes on their items when one is inserted or
        deleted (before the common code changes the list)"""
        selected = selected_items(control)
        if msg == LB_RESETCONTENT:
            selected.clear()
            return
        count = len(control.items)
        if msg == LB_INSERTSTRING and index < count:
            moved = {i + 1 if i >= index else i for i in selected}
        elif msg == LB_DELETESTRING and index < count:
            moved = {i - 1 if i > index else i for i in selected if i != index}
        else:
            return
        selected.clear()
        selected.update(moved)

    LBS_NOTIFY = 0x0001
    MK_SHIFT, MK_CONTROL = 0x0004, 0x0008

    def _listbox_mouse_message(self, control, msg, wparam, lparam):
        """WM_LBUTTONDOWN or WM_LBUTTONDBLCLK that a subclassing procedure
        passes on to the list box procedure: the item under the mouse is
        selected and the parent told (LBN_SELCHANGE, LBN_DBLCLK). Access 95's
        query field lists add the double-clicked field to the grid."""
        y = (lparam >> 16) & 0xFFFF
        if y & 0x8000:
            return 0
        item_h = getattr(control, 'item_height', None) or (
            self.gui.LISTBOX_ITEM_H if self.gui else 16)
        index = control.top_index + y // item_h
        if not 0 <= index < len(control.items):
            return 0
        if is_multi_select(control):
            click_item(control, index, bool(wparam & self.MK_CONTROL),
                       bool(wparam & self.MK_SHIFT))
        else:
            control.sel_index = index
        self._list_changed(control)
        if control.style & self.LBS_NOTIFY and control.parent_hwnd:
            codes = [self.LBN_SELCHANGE]
            if msg == self.WM_LBUTTONDBLCLK:
                codes.append(self.LBN_DBLCLK)
            for code in codes:
                self._send(control.parent_hwnd, self.WM_COMMAND,
                           (code << 16) | (control.control_id & 0xFFFF), control.hwnd)
        return 0
