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

"""PseudoWindowsGUI mixin: the keyboard in menu bars: Alt+letter opens the
menu with that mnemonic (DefWindowProc's WM_SYSCHAR), then a letter picks an
item of the open menu and Left / Right move to the next menu"""

from ..config import PYGAME_AVAILABLE

if PYGAME_AVAILABLE:
    import pygame


class MenuKeysMixin:
    """Menu bar mnemonics and keys"""

    @staticmethod
    def _menu_mnemonic(text):
        """The lower-case letter after the "&" of a menu text ("&&" is an
        ampersand), or None"""
        text = (text or '').split('\t', 1)[0]
        index = 0
        while True:
            index = text.find('&', index)
            if index < 0 or index + 1 >= len(text):
                return None
            if text[index + 1] != '&':
                return text[index + 1].lower()
            index += 2

    def open_menu_by_mnemonic(self, hwnd, char):
        """Alt+char in a window: open the menu bar item of its top-level window
        with that mnemonic (called on the emulation thread). True if one opened."""
        with self.lock:
            win = self.windows.get(self.top_level_of(hwnd))
            if win is None or not win.menu or not win.visible:
                return False
            for index, item in enumerate(win.menu):
                if not item.get('grayed') and self._menu_mnemonic(item.get('raw_text')) == \
                        char.lower():
                    self.open_menu = None
                    self._activate_menu_item(win, index)
                    return True
        return False

    def _menu_key(self, event):
        """A key while a menu bar dropdown is open; True if the menu took it"""
        if self.open_menu is None or self.popup_menu is not None:
            return False
        root = self._menu_root()
        if root is None:
            return False
        items, _, _, win = root
        for index in self.menu_path:
            if 0 <= index < len(items) and items[index].get('items') is not None:
                items = items[index]['items']
        if event.key in (pygame.K_LEFT, pygame.K_RIGHT):
            if self.menu_path:
                self.menu_path = self.menu_path[:-1] if event.key == pygame.K_LEFT else \
                    self.menu_path
                return True
            index = (self.open_menu[1] + (1 if event.key == pygame.K_RIGHT else -1)) % \
                len(win.menu)
            self.open_menu = None
            self._activate_menu_item(win, index)
            return True
        letter = event.unicode.lower() if event.unicode and event.unicode.isalnum() else None
        if letter is None:
            return True  # The menu has the keyboard while it is open
        for index, item in enumerate(items):
            if item.get('separator') or item.get('grayed') or \
                    self._menu_mnemonic(item.get('raw_text')) != letter:
                continue
            if item.get('items') is not None:
                self.menu_path = self.menu_path + [index]
                self._post_init_menu(win, item.get('hmenu', 0), index)
            else:
                self.open_menu = None
                self.menu_path = []
                if self.winapi:
                    self.winapi.post_window_message(win.hwnd, self.winapi.WM_COMMAND,
                                                    item['id'] & 0xFFFF, 0)
            return True
        return True
