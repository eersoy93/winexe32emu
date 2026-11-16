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

"""WinAPIHandler mixin: Menus and accelerators"""

import struct

from unicorn import *

from ..logger import log


class MenusMixin:
    """Menus and accelerators"""

    # ==================== MENU APIs ====================

    MF_SEPARATOR = 0x0800
    MF_POPUP = 0x0010

    def CreateMenu(self, args):
        """CreateMenu emulation"""
        handle = self.get_next_handle()
        self.menus[handle] = []
        log.debug(f"CreateMenu() -> 0x{handle:x}")
        return handle

    def CreatePopupMenu(self, args):
        """CreatePopupMenu emulation"""
        handle = self.get_next_handle()
        self.menus[handle] = []
        log.debug(f"CreatePopupMenu() -> 0x{handle:x}")
        return handle

    def AppendMenuA(self, args):
        """AppendMenuA emulation"""
        hMenu = args[0]
        uFlags = args[1]
        uIDNewItem = args[2]
        lpNewItem = args[3]

        if hMenu not in self.menus:
            return 0

        text = ""
        if not (uFlags & self.MF_SEPARATOR) and lpNewItem:
            text = self.read_string(lpNewItem)

        self.menus[hMenu].append({
            'flags': uFlags,
            'id': uIDNewItem,
            'text': text,
            'submenu': uIDNewItem if (uFlags & self.MF_POPUP) else 0,
        })

        log.debug(f"AppendMenuA(0x{hMenu:x}, flags=0x{uFlags:x}, id=0x{uIDNewItem:x}, '{text}')")
        self._menus_changed()
        return 1

    @staticmethod
    def _menu_label(text):
        """(label, shortcut) of a menu item text: "&Open\\tEnter" -> ("Open", "Enter");
        "&" marks the mnemonic and "&&" is a literal "&"""
        if not isinstance(text, str):
            return '', ''
        label, _, shortcut = text.partition('\t')
        label = '&'.join(part.replace('&', '') for part in label.split('&&'))
        return label, shortcut

    def _build_menu_tree(self, hmenu, depth=0):
        """Convert menu handles into the plain structure the GUI renders:
        [{'text', 'shortcut', 'id', 'items' (submenu or None), 'separator',
        'grayed', 'checked', 'radio', 'hmenu', 'break'}]; 'break' is 'bar'
        (MF_MENUBARBREAK) or 'plain' (MF_MENUBREAK) for an item that starts a
        new column"""
        tree = []
        for item in self.menus.get(hmenu, []):
            flags = item['flags']
            column_break = ('bar' if flags & self.MF_MENUBARBREAK else
                            'plain' if flags & self.MF_MENUBREAK else None)
            if flags & self.MF_SEPARATOR:
                tree.append({'separator': True, 'text': '', 'id': 0, 'items': None,
                             'break': column_break})
                continue
            label, shortcut = self._menu_label(item['text'])
            node = {'text': label, 'shortcut': shortcut, 'id': item['id'], 'items': None,
                    'grayed': bool(flags & (self.MF_GRAYED | self.MF_DISABLED)),
                    'checked': bool(flags & self.MF_CHECKED),
                    'radio': bool(flags & self.MFT_RADIOCHECK), 'hmenu': 0,
                    'break': column_break}
            if flags & self.MF_POPUP:
                node['id'] = 0
                node['hmenu'] = item['submenu']
                node['items'] = (self._build_menu_tree(item['submenu'], depth + 1)
                                 if depth < 8 else [])
            tree.append(node)
        if depth == 0:
            # Separators make no sense at the top level of a menu bar
            return tree
        return tree

    def SetMenu(self, args):
        """SetMenu emulation - attach a menu bar to a window"""
        hWnd = args[0]
        hMenu = args[1]

        log.debug(f"SetMenu(0x{hWnd:x}, 0x{hMenu:x})")

        if self.gui and hWnd in self.gui.windows:
            window = self.gui.windows[hWnd]
            window.menu_handle = hMenu
            window.menu = self._build_menu_tree(hMenu) if hMenu else None
        return 1

    def DrawMenuBar(self, args):
        """DrawMenuBar emulation - the menu bar shows the current menu items"""
        self._menus_changed()
        return 1

    def DestroyMenu(self, args):
        """DestroyMenu emulation"""
        hMenu = args[0]
        return 1 if self.menus.pop(hMenu, None) is not None else 0

    # ---------- Menus from resources, item states, popup menus ----------

    MF_GRAYED, MF_DISABLED, MF_CHECKED, MF_BYPOSITION = 0x1, 0x2, 0x8, 0x400
    MFT_RADIOCHECK, MF_DEFAULT = 0x200, 0x1000
    MF_MENUBARBREAK, MF_MENUBREAK = 0x20, 0x40
    WM_INITMENUPOPUP = 0x0117

    def _new_menu(self, items=None):
        handle = self.get_next_handle()
        self.menus[handle] = items or []
        return handle

    def _parse_menu_template(self, data):
        """RT_MENU resource (MENU or MENUEX template) -> menu handle"""
        version, header_size = struct.unpack_from('<HH', data, 0)
        pos = 4 + header_size

        def read_text():
            nonlocal pos
            end = pos
            while data[end:end + 2] != b'\x00\x00':
                end += 2
            text = data[pos:end].decode('utf-16-le', errors='replace')
            pos = end + 2
            return text

        def parse_items():
            nonlocal pos
            items = []
            while pos < len(data):
                if version == 1:
                    pos = (pos + 3) & ~3
                    mtype, mstate, mid, flags = struct.unpack_from('<IIIH', data, pos)
                    pos += 14
                    text = read_text()
                    item = {'flags': (mtype & 0xFFFF) | (mstate & 0x100B), 'id': mid,
                            'text': text, 'submenu': 0}
                    if not text and not flags & 0x1:
                        item['flags'] |= self.MF_SEPARATOR  # Like Windows: a NULL item
                    if flags & 0x1:
                        pos = (pos + 3) & ~3
                        pos += 4  # dwHelpId
                        item['submenu'] = self._new_menu(parse_items())
                        item['flags'] |= self.MF_POPUP
                    items.append(item)
                    if flags & 0x80:
                        break
                else:
                    flags = struct.unpack_from('<H', data, pos)[0]
                    pos += 2
                    mid = 0
                    if not flags & self.MF_POPUP:
                        mid = struct.unpack_from('<H', data, pos)[0]
                        pos += 2
                    text = read_text()
                    item = {'flags': flags & ~0x80, 'id': mid, 'text': text, 'submenu': 0}
                    if not text and not flags & self.MF_POPUP and mid == 0:
                        item['flags'] |= self.MF_SEPARATOR
                    if flags & self.MF_POPUP:
                        item['submenu'] = self._new_menu(parse_items())
                    items.append(item)
                    if flags & 0x80:  # MF_END
                        break
            return items

        if version == 1:
            pos = 4 + header_size
        return self._new_menu(parse_items())

    def _resource_name_key(self, value, wide):
        if value < 0x10000:
            return value
        name = self._read_text(value, wide)
        if name.startswith('#') and name[1:].isdigit():
            return int(name[1:])
        return name.upper()

    def _load_menu_resource(self, key):
        """Menu handle of the EXE's RT_MENU resource key, or 0"""
        resource = self._find_resource(4, key)
        if resource is None:
            return 0
        try:
            return self._parse_menu_template(bytes(self.emu.uc.mem_read(*resource)))
        except (struct.error, UcError):
            return 0

    def LoadMenuA(self, args, wide=False):
        """LoadMenuA/W emulation - an RT_MENU resource of the EXE"""
        hInstance, lpMenuName = args[0], args[1]
        key = self._resource_name_key(lpMenuName, wide)
        resource = self._find_resource(4, key) if self._is_own_module(hInstance) else None
        if resource is None:
            self._last_error = 1814  # ERROR_RESOURCE_NAME_NOT_FOUND
            return 0
        try:
            return self._parse_menu_template(bytes(self.emu.uc.mem_read(*resource)))
        except (struct.error, UcError):
            self._last_error = 1814
            return 0

    def LoadMenuW(self, args):
        return self.LoadMenuA(args, wide=True)

    def _menu_item(self, hmenu, item, by_position):
        """(menu handle, index) of an item by position or command id (submenus
        are searched for ids), or (None, -1)"""
        items = self.menus.get(hmenu)
        if items is None:
            return None, -1
        if by_position:
            return (hmenu, item) if 0 <= item < len(items) else (None, -1)
        for index, entry in enumerate(items):
            if entry['id'] == item and not entry['flags'] & self.MF_POPUP:
                return hmenu, index
        for entry in items:
            if entry['flags'] & self.MF_POPUP and entry['submenu'] in self.menus:
                found = self._menu_item(entry['submenu'], item, False)
                if found[0] is not None:
                    return found
        # A popup item can be addressed by its submenu handle too
        for index, entry in enumerate(items):
            if entry['flags'] & self.MF_POPUP and entry['submenu'] == item:
                return hmenu, index
        return None, -1

    def _menus_changed(self):
        """Rebuild the menu bars the GUI shows (after menu changes)"""
        if not self.gui:
            return
        for win in list(self.gui.windows.values()):
            if win.owner is self and getattr(win, 'menu_handle', 0):
                if win.menu_handle in self.menus:
                    win.menu = self._build_menu_tree(win.menu_handle)
                else:
                    win.menu = None
        popup = self.gui.popup_menu
        if popup is not None and popup.get('owner') is self and popup['hmenu'] in self.menus:
            popup['tree'] = self._build_menu_tree(popup['hmenu'])

    def GetSubMenu(self, args):
        """GetSubMenu emulation"""
        items = self.menus.get(args[0])
        if items is None or not 0 <= args[1] < len(items):
            return 0
        item = items[args[1]]
        return item['submenu'] if item['flags'] & self.MF_POPUP else 0

    def GetMenuItemCount(self, args):
        items = self.menus.get(args[0])
        return len(items) if items is not None else 0xFFFFFFFF

    def GetMenuItemID(self, args):
        items = self.menus.get(args[0])
        if items is None or not 0 <= args[1] < len(items):
            return 0xFFFFFFFF
        item = items[args[1]]
        return 0xFFFFFFFF if item['flags'] & self.MF_POPUP else item['id']

    def GetMenuState(self, args):
        hmenu, index = self._menu_item(args[0], args[1], args[2] & self.MF_BYPOSITION)
        if hmenu is None:
            return 0xFFFFFFFF
        return self.menus[hmenu][index]['flags'] & 0xFFFF

    def GetMenu(self, args):
        """GetMenu emulation - the menu bar of a window"""
        win = self.gui.windows.get(args[0]) if self.gui else None
        return getattr(win, 'menu_handle', 0) if win else 0

    def EnableMenuItem(self, args):
        """EnableMenuItem emulation - previous state (MF_GRAYED/MF_DISABLED) or -1"""
        hmenu, index = self._menu_item(args[0], args[1], args[2] & self.MF_BYPOSITION)
        if hmenu is None:
            return 0xFFFFFFFF
        item = self.menus[hmenu][index]
        previous = item['flags'] & (self.MF_GRAYED | self.MF_DISABLED)
        item['flags'] = (item['flags'] & ~(self.MF_GRAYED | self.MF_DISABLED)) | \
            (args[2] & (self.MF_GRAYED | self.MF_DISABLED))
        self._menus_changed()
        return previous

    def CheckMenuItem(self, args):
        """CheckMenuItem emulation - previous MF_CHECKED state or -1"""
        hmenu, index = self._menu_item(args[0], args[1], args[2] & self.MF_BYPOSITION)
        if hmenu is None:
            return 0xFFFFFFFF
        item = self.menus[hmenu][index]
        previous = item['flags'] & self.MF_CHECKED
        item['flags'] = (item['flags'] & ~self.MF_CHECKED) | (args[2] & self.MF_CHECKED)
        self._menus_changed()
        return previous

    def CheckMenuRadioItem(self, args):
        """CheckMenuRadioItem emulation"""
        hmenu, first, last, check, flags = args[:5]
        by_position = flags & self.MF_BYPOSITION
        found = False
        for menu, items in ([(hmenu, self.menus.get(hmenu, []))] if by_position else
                            [(h, i) for h, i in self.menus.items()]):
            for index, item in enumerate(items):
                key = index if by_position else item['id']
                if item['flags'] & self.MF_POPUP and not by_position:
                    continue
                if first <= key <= last:
                    if key == check:
                        item['flags'] |= self.MF_CHECKED | self.MFT_RADIOCHECK
                        found = True
                    else:
                        item['flags'] &= ~self.MF_CHECKED
            if by_position:
                break
        self._menus_changed()
        return 1 if found else 0

    def RemoveMenu(self, args, destroy=False):
        """RemoveMenu emulation (DeleteMenu also destroys a submenu)"""
        hmenu, index = self._menu_item(args[0], args[1], args[2] & self.MF_BYPOSITION)
        if hmenu is None:
            return 0
        items = list(self.menus[hmenu])
        item = items.pop(index)
        self.menus[hmenu] = items
        if destroy and item['flags'] & self.MF_POPUP:
            self.menus.pop(item['submenu'], None)
        self._menus_changed()
        return 1

    def DeleteMenu(self, args):
        return self.RemoveMenu(args, destroy=True)

    def AppendMenuW(self, args):
        """AppendMenuW emulation"""
        hMenu, uFlags, uIDNewItem, lpNewItem = args[:4]
        if hMenu not in self.menus:
            return 0
        text = ''
        if not uFlags & (self.MF_SEPARATOR | 0x4 | 0x100) and lpNewItem:  # MF_BITMAP, MF_OWNERDRAW
            text = self.read_wide_string(lpNewItem)
        self.menus[hMenu] = self.menus[hMenu] + [{
            'flags': uFlags, 'id': uIDNewItem, 'text': text,
            'submenu': uIDNewItem if uFlags & self.MF_POPUP else 0}]
        self._menus_changed()
        return 1

    def InsertMenuA(self, args, wide=False):
        """InsertMenuA/W emulation"""
        hMenu, position, uFlags, uIDNewItem, lpNewItem = args[:5]
        items = self.menus.get(hMenu)
        if items is None:
            return 0
        if uFlags & self.MF_BYPOSITION:
            index = len(items) if position >= 0x80000000 else min(position, len(items))
        else:
            menu, index = self._menu_item(hMenu, position, False)
            if menu != hMenu:
                index = len(items)
        text = ''
        if not uFlags & (self.MF_SEPARATOR | 0x4 | 0x100) and lpNewItem:
            text = self._read_text(lpNewItem, wide)
        items = list(items)
        items.insert(index, {'flags': uFlags & ~self.MF_BYPOSITION, 'id': uIDNewItem,
                             'text': text,
                             'submenu': uIDNewItem if uFlags & self.MF_POPUP else 0})
        self.menus[hMenu] = items
        self._menus_changed()
        return 1

    def InsertMenuW(self, args):
        return self.InsertMenuA(args, wide=True)

    def ModifyMenuW(self, args):
        """ModifyMenuW emulation"""
        hmenu, index = self._menu_item(args[0], args[1], args[2] & self.MF_BYPOSITION)
        if hmenu is None:
            return 0
        flags = args[2] & ~self.MF_BYPOSITION
        item = self.menus[hmenu][index]
        item['flags'], item['id'] = flags, args[3]
        item['submenu'] = args[3] if flags & self.MF_POPUP else 0
        if not flags & (self.MF_SEPARATOR | 0x4 | 0x100) and args[4]:
            item['text'] = self.read_wide_string(args[4])
        self._menus_changed()
        return 1

    def _menu_item_info(self, address, wide):
        """MENUITEMINFO -> dict of the fields its fMask names"""
        (size, mask, ftype, fstate, mid, submenu, _, _, data, type_data,
         cch) = self._read_struct(address, '<11I')
        info = {'mask': mask, 'type': ftype, 'state': fstate, 'id': mid, 'submenu': submenu,
                'data': data, 'type_data': type_data, 'cch': cch}
        return info

    def _apply_menu_item_info(self, item, info, wide):
        mask = info['mask']
        flags = item['flags']
        if mask & 0x10 or mask & 0x100:  # MIIM_TYPE / MIIM_FTYPE
            flags = (flags & ~(self.MF_SEPARATOR | self.MFT_RADIOCHECK | 0x4 | 0x100 | 0x20 |
                               0x40)) | (info['type'] & (self.MF_SEPARATOR | self.MFT_RADIOCHECK |
                                                        0x4 | 0x100 | 0x20 | 0x40))
        if mask & 0x10 or mask & 0x40:  # MIIM_TYPE / MIIM_STRING
            if not info['type'] & (self.MF_SEPARATOR | 0x4 | 0x100) and info['type_data']:
                item['text'] = self._read_text(info['type_data'], wide)
            elif mask & 0x40 and not info['type_data']:
                item['text'] = ''
        if mask & 0x1:  # MIIM_STATE
            flags = (flags & ~(self.MF_GRAYED | self.MF_DISABLED | self.MF_CHECKED |
                               self.MF_DEFAULT | 0x80)) | (info['state'] & (0x3 | 0x8 | 0x1000 | 0x80))
        if mask & 0x2:  # MIIM_ID
            item['id'] = info['id']
        if mask & 0x4:  # MIIM_SUBMENU
            item['submenu'] = info['submenu']
            flags = (flags | self.MF_POPUP) if info['submenu'] else (flags & ~self.MF_POPUP)
        if mask & 0x20:  # MIIM_DATA
            item['data'] = info['data']
        item['flags'] = flags

    def InsertMenuItemA(self, args, wide=False):
        """InsertMenuItemA/W emulation"""
        hMenu, position, by_position, lpmii = args[:4]
        items = self.menus.get(hMenu)
        if items is None:
            return 0
        if by_position:
            index = len(items) if position >= 0x80000000 else min(position, len(items))
        else:
            menu, index = self._menu_item(hMenu, position, False)
            if menu != hMenu:
                index = len(items)
        item = {'flags': 0, 'id': 0, 'text': '', 'submenu': 0}
        self._apply_menu_item_info(item, self._menu_item_info(lpmii, wide), wide)
        items = list(items)
        items.insert(index, item)
        self.menus[hMenu] = items
        self._menus_changed()
        return 1

    def InsertMenuItemW(self, args):
        return self.InsertMenuItemA(args, wide=True)

    def SetMenuItemInfoA(self, args, wide=False):
        """SetMenuItemInfoA/W emulation"""
        hmenu, index = self._menu_item(args[0], args[1], args[2])
        if hmenu is None:
            self._last_error = 1456  # ERROR_MENU_ITEM_NOT_FOUND
            return 0
        self._apply_menu_item_info(self.menus[hmenu][index],
                                   self._menu_item_info(args[3], wide), wide)
        self._menus_changed()
        return 1

    def SetMenuItemInfoW(self, args):
        return self.SetMenuItemInfoA(args, wide=True)

    def GetMenuItemInfoA(self, args, wide=False):
        """GetMenuItemInfoA/W emulation"""
        hmenu, index = self._menu_item(args[0], args[1], args[2])
        if hmenu is None:
            self._last_error = 1456  # ERROR_MENU_ITEM_NOT_FOUND
            return 0
        item = self.menus[hmenu][index]
        address = args[3]
        info = self._menu_item_info(address, wide)
        mask = info['mask']
        flags = item['flags']
        ftype = flags & (self.MF_SEPARATOR | self.MFT_RADIOCHECK | 0x4 | 0x100 | 0x20 | 0x40)
        if mask & (0x10 | 0x100):
            self._mem_write(address + 8, struct.pack('<I', ftype))
        if mask & 0x1:
            self._mem_write(address + 12, struct.pack('<I', flags & (0x3 | 0x8 | 0x1000 | 0x80)))
        if mask & 0x2:
            self._mem_write(address + 16, struct.pack('<I', item['id']))
        if mask & 0x4:
            self._mem_write(address + 20, struct.pack(
                '<I', item['submenu'] if flags & self.MF_POPUP else 0))
        if mask & 0x20:
            self._mem_write(address + 32, struct.pack('<I', item.get('data', 0)))
        if mask & (0x10 | 0x40) and not ftype & (self.MF_SEPARATOR | 0x4 | 0x100):
            text = item['text'] if isinstance(item['text'], str) else ''
            units = self._text_units(text, wide)
            if info['type_data'] and info['cch']:
                self._write_units(info['type_data'], units[:info['cch'] - 1], wide)
            self._mem_write(address + 40, struct.pack('<I', len(units)))
        return 1

    def GetMenuItemInfoW(self, args):
        return self.GetMenuItemInfoA(args, wide=True)

    def GetMenuStringW(self, args):
        hmenu, index = self._menu_item(args[0], args[1], args[4] & self.MF_BYPOSITION)
        if hmenu is None:
            return 0
        text = self.menus[hmenu][index]['text'] or ''
        if args[2] and args[3]:
            self._copy_text_out(args[2], args[3], text)
        return len(text)

    def TrackPopupMenuEx(self, args):
        """TrackPopupMenuEx emulation - a modal popup menu at screen (x, y);
        TPM_RETURNCMD returns the chosen command, else it is sent as WM_COMMAND"""
        hmenu, flags, x, y, hwnd = args[:5]
        x, y = self._read_signed_args(args, 2, 2)
        if hmenu not in self.menus or not self.gui or not self.gui.running:
            return 0
        self._send(hwnd, self.WM_INITMENUPOPUP, hmenu, 0)
        popup = {'hmenu': hmenu, 'tree': self._build_menu_tree(hmenu), 'x': x, 'y': y,
                 'owner': self, 'hwnd': hwnd, 'result': None, 'done': False, 'open': []}
        with self.gui.lock:
            self.gui.popup_menu = popup
        self.emu.wait_until(lambda: popup['done'] or not self.gui.running)
        with self.gui.lock:
            if self.gui.popup_menu is popup:
                self.gui.popup_menu = None
        command = popup['result'] or 0
        if flags & 0x100:  # TPM_RETURNCMD
            return command
        if command:
            self.post_window_message(hwnd, self.WM_COMMAND, command & 0xFFFF, 0)
        return 1 if command else 0

    def TrackPopupMenu(self, args):
        return self.TrackPopupMenuEx([args[0], args[1], args[2], args[3], args[5], 0])

    # ---------- Accelerators ----------

    def LoadAcceleratorsA(self, args, wide=False):
        """LoadAcceleratorsA/W emulation - an RT_ACCELERATOR table of the EXE"""
        key = self._resource_name_key(args[1], wide)
        resource = self._find_resource(9, key) if self._is_own_module(args[0]) else None
        if resource is None:
            self._last_error = 1814  # ERROR_RESOURCE_NAME_NOT_FOUND
            return 0
        data = bytes(self.emu.uc.mem_read(*resource))
        entries = []
        for pos in range(0, len(data) - 7, 8):
            flags, key_code, command = struct.unpack_from('<HHH', data, pos)
            entries.append((flags, key_code, command))
            if flags & 0x80:
                break
        handle = self.get_next_handle()
        self.accelerators[handle] = entries
        return handle

    def LoadAcceleratorsW(self, args):
        return self.LoadAcceleratorsA(args, wide=True)

    def CreateAcceleratorTableW(self, args):
        count = args[1]
        entries = []
        for i in range(count):
            flags, key_code, command = self._read_struct(args[0] + 6 * i, '<BxHH')
            entries.append((flags, key_code, command))
        handle = self.get_next_handle()
        self.accelerators[handle] = entries
        return handle

    def DestroyAcceleratorTable(self, args):
        return 1 if self.accelerators.pop(args[0], None) is not None else 0

    def TranslateAcceleratorA(self, args):
        """TranslateAcceleratorA/W emulation - WM_COMMAND for a matching keystroke"""
        hwnd, haccel, lpMsg = args[0], args[1], args[2]
        entries = self.accelerators.get(haccel)
        if not entries or not lpMsg:
            return 0
        _, message, wParam, lParam = self._read_struct(lpMsg, '<IIII')
        if message not in (self.WM_KEYDOWN, self.WM_SYSKEYDOWN, self.WM_CHAR, self.WM_SYSCHAR):
            return 0
        keys = self.gui.key_states if self.gui else {}
        shift, ctrl = bool(keys.get(0x10)), bool(keys.get(0x11))
        alt = bool(keys.get(0x12)) or message in (self.WM_SYSKEYDOWN, self.WM_SYSCHAR)
        for flags, key_code, command in entries:
            if flags & 0x1:  # FVIRTKEY
                if message not in (self.WM_KEYDOWN, self.WM_SYSKEYDOWN) or wParam != key_code:
                    continue
                if bool(flags & 0x4) != shift or bool(flags & 0x8) != ctrl or \
                        bool(flags & 0x10) != alt:
                    continue
            else:
                if message not in (self.WM_CHAR, self.WM_SYSCHAR) or wParam != key_code:
                    continue
                if bool(flags & 0x10) != alt:
                    continue
            self._send(hwnd, self.WM_COMMAND, (1 << 16) | command, 0)
            return 1
        return 0

    def TranslateAcceleratorW(self, args):
        return self.TranslateAcceleratorA(args)
