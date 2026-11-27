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

"""WinAPIHandler mixin: owner-draw list boxes (LBS_OWNERDRAWFIXED,
LBS_OWNERDRAWVARIABLE) and the item height of owner-draw combo boxes

The GUI draws the list's frame, background and scroll bar; the parent draws
every visible item (WM_DRAWITEM) after telling the item height
(WM_MEASUREITEM). Access 95's query design shows a table's fields in one."""

import struct

from unicorn import UcError

from .listbox_multisel import item_selected

LBS_OWNERDRAWFIXED, LBS_OWNERDRAWVARIABLE, LBS_HASSTRINGS = 0x0010, 0x0020, 0x0040
LB_SETTOPINDEX, LB_SETITEMHEIGHT, LB_GETITEMHEIGHT = 0x0197, 0x01A0, 0x01A1
WM_MEASUREITEM = 0x002C
ODT_LISTBOX, ODT_COMBOBOX, ODA_DRAWENTIRE, ODS_SELECTED = 2, 3, 0x0001, 0x0001
CBS_OWNERDRAWFIXED, CBS_OWNERDRAWVARIABLE = 0x0010, 0x0020
# Messages after which the items look different
LIST_CHANGES = (0x0180, 0x0181, 0x0182, 0x0184, 0x0185, 0x0186, 0x019B, 0x0183,
                LB_SETTOPINDEX, 0x019A)  # ..., LB_SETITEMDATA


def is_owner_draw_list(control):
    """Is control an owner-draw LISTBOX?"""
    return control.class_name == 'LISTBOX' and bool(
        control.style & (LBS_OWNERDRAWFIXED | LBS_OWNERDRAWVARIABLE))


def is_owner_draw_combo(control):
    """Is control an owner-draw COMBOBOX?"""
    return control.class_name == 'COMBOBOX' and bool(
        control.style & (CBS_OWNERDRAWFIXED | CBS_OWNERDRAWVARIABLE))


def list_paint_state(control):
    """What an owner-draw list's items look like: when it changes (a click,
    scrolling) the items are drawn again"""
    shown = tuple(i for i in range(len(control.items)) if item_selected(control, i))
    return (control.top_index, control.sel_index, shown, len(control.items),
            control.width, control.height)


class OwnerDrawListMixin:
    """WM_MEASUREITEM and WM_DRAWITEM of owner-draw list boxes"""

    def _send_to_parent(self, control, message, wparam, lparam):
        """Send message to the control's parent (a dialog: its dialog procedure)"""
        parent = control.parent_hwnd
        if self._dialog_of(parent) == parent:
            return self._dialog_message(parent, message, wparam, lparam)
        wndproc = self._find_wndproc_for_hwnd(parent)
        if wndproc:
            return self.emu.call_wndproc(wndproc, parent, message, wparam, lparam)
        return 0

    def _list_item_height(self, control):
        """Height of the items of an owner-draw list or combo box: the parent
        tells it (WM_MEASUREITEM) the first time it is needed, unless
        LB_SETITEMHEIGHT / CB_SETITEMHEIGHT set it"""
        height = getattr(control, 'item_height', None)
        if height:
            return height
        default = self.gui.LISTBOX_ITEM_H if self.gui else 16
        control.item_height = default  # Asked only once, even if it fails
        buffer = self.emu.heap_alloc(24)
        if not buffer:
            return default
        try:
            # CtlType, CtlID, itemID, itemWidth, itemHeight, itemData
            self.emu.uc.mem_write(buffer, struct.pack(
                '<6I', ODT_COMBOBOX if control.class_name == 'COMBOBOX' else ODT_LISTBOX,
                control.control_id & 0xFFFFFFFF, 0,
                max(control.width - 2, 0), default, 0))
            self._send_to_parent(control, WM_MEASUREITEM, control.control_id, buffer)
            height = struct.unpack('<I', self.emu.uc.mem_read(buffer + 16, 4))[0]
        except UcError:
            height = default
        finally:
            self.emu.heap_free(buffer)
        if 0 < height < 256:
            control.item_height = height
        return control.item_height

    def _owner_draw_list_message(self, control, msg, wparam, lparam):
        """LB_SETITEMHEIGHT/LB_GETITEMHEIGHT of any list; the owner-draw lists
        are drawn again after a change. None: not handled here."""
        if control.class_name != 'LISTBOX':
            return None
        if msg == LB_GETITEMHEIGHT:
            if is_owner_draw_list(control):
                return self._list_item_height(control)
            return self.gui.LISTBOX_ITEM_H if self.gui else 16
        if msg == LB_SETITEMHEIGHT:
            if not 0 < (lparam & 0xFFFF) < 256:
                return 0xFFFFFFFF  # LB_ERR
            control.item_height = lparam & 0xFFFF
            self._list_changed(control)
            return 0
        if msg in LIST_CHANGES and is_owner_draw_list(control):
            self._list_changed(control)
        return None

    def _list_changed(self, control):
        """The list's items are to be drawn again (its next WM_PAINT)"""
        dirty = getattr(self, 'dirty_controls', None)
        if dirty is not None:
            dirty[control.hwnd] = True

    def _paint_owner_draw_list(self, control):
        """WM_PAINT of an owner-draw list: WM_DRAWITEM for each visible item"""
        hwnd = control.hwnd
        item_h = self._list_item_height(control)
        self.gui.clear_drawings(hwnd)
        control.painted_state = list_paint_state(control)
        count = len(control.items)
        rows = max(1, (control.height - 2) // item_h)
        top = max(0, min(control.top_index, count - rows))
        width = control.width - 1 - (self.gui.SCROLL_BTN if count > rows else 0)
        buffer = self.emu.heap_alloc(48)
        hdc = self._create_dc(hwnd)
        state = self.dc_state[hdc]
        if control.font_handle in self.gdi_objects:
            state['font'] = control.font_handle
        state['bk_color'] = self.SYS_COLORS.get(5, (255, 255, 255))  # COLOR_WINDOW
        state['text_color'] = self.SYS_COLORS.get(8, (0, 0, 0))  # COLOR_WINDOWTEXT
        data = self._list_item_data(control)
        try:
            for index in range(top, min(count, top + rows)):
                y = 1 + (index - top) * item_h
                item_state = ODS_SELECTED if item_selected(control, index) else 0
                # CtlType, CtlID, itemID, itemAction, itemState, hwndItem, hDC,
                # rcItem, itemData
                self.emu.uc.mem_write(buffer, struct.pack(
                    '<7I4iI', ODT_LISTBOX, control.control_id & 0xFFFFFFFF, index,
                    ODA_DRAWENTIRE, item_state, hwnd, hdc, 1, y, width, y + item_h,
                    data[index] & 0xFFFFFFFF if index < len(data) else 0))
                self._send_to_parent(control, self.WM_DRAWITEM, control.control_id, buffer)
        except UcError:
            pass
        finally:
            self._delete_dc(hdc)
            self.emu.heap_free(buffer)
        return 0

