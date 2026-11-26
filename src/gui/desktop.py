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

"""PseudoWindowsGUI mixin: Desktop icons and the desktop context menu"""

import os

from .. import winapi
from ..config import EXPLORER_PATH, PYGAME_AVAILABLE
from ..paths import resolve_drive_path
from ..resources import read_exe_icon
from .desktop_icons import DesktopIconsMixin

if PYGAME_AVAILABLE:
    import pygame


class DesktopMixin(DesktopIconsMixin):
    """Desktop icons and the desktop context menu"""

    # ==================== DESKTOP ICONS ====================

    ICON_CELL_W = 76
    ICON_CELL_H = 72
    ICON_MARGIN = 6
    ICON_SIZE = 32
    DOUBLE_CLICK_MS = 500

    def _refresh_desktop_icons(self):
        """Read the desktop icons, (label, path or shortcut) pairs: My Computer
        (Explorer, if compiled) and the folders Explorer opens (the user's,
        the network, the Recycle Bin: ('special', kind)), then the shortcuts
        and programs of the user's (C:\\Users\\User\\Desktop) and the public
        Desktop folders"""
        self.desktop_icons, self.desktop_icon_paths = [], {}
        if self._explorer_available():
            self.desktop_icons.append((self._program_label(EXPLORER_PATH), EXPLORER_PATH))
            self.desktop_icon_paths[EXPLORER_PATH] = resolve_drive_path(EXPLORER_PATH)
            self.desktop_icons += self._special_desktop_entries()
        folders = [winapi.WinAPIHandler.SHELL_FOLDERS[0x10],   # CSIDL_DESKTOPDIRECTORY
                   winapi.WinAPIHandler.SHELL_FOLDERS[0x19]]   # CSIDL_COMMON_DESKTOPDIRECTORY
        for folder in folders:
            # Like on a real installation the Desktop folders exist, ready for shortcuts
            host = resolve_drive_path(folder)
            if host:
                try:
                    os.makedirs(host, exist_ok=True)
                except OSError:
                    pass
        _, items = self._shortcut_entries(folders, self.desktop_icon_paths)
        self.desktop_icons += items
        self.selected_icon = None
        self.exe_icon_cache.clear()  # Programs may have been replaced

    def _default_exe_icon(self, size):
        """Default program icon (a small window with a title bar) of size x size"""
        shadow = max(1, size // 16)
        surface = pygame.Surface((size, size), pygame.SRCALPHA)
        body = pygame.Rect(0, size * 3 // 32, size - shadow, size * 25 // 32)
        pygame.draw.rect(surface, (64, 64, 64), body.move(shadow, shadow))
        pygame.draw.rect(surface, self.COLOR_EDIT_BG, body)
        pygame.draw.rect(surface, self.COLOR_TITLE_BAR,
                         pygame.Rect(body.x, body.y, body.width, max(3, size * 6 // 32)))
        pygame.draw.rect(surface, self.COLOR_TEXT, body, 1)
        return surface

    def _computer_icon(self, size):
        """(normal, selected) size x size surfaces of the My Computer icon: a
        monitor on a desktop case, drawn at 32x32 (cached)"""
        key = ('computer', size)
        images = self.exe_icon_cache.get(key)
        if images is not None:
            return images
        image = pygame.Surface((32, 32), pygame.SRCALPHA)
        beige, light, dark, black = (212, 208, 200), (255, 255, 255), (128, 128, 128), (32, 32, 32)
        # Monitor: beige bezel with a 3D edge around a blue screen
        bezel = pygame.Rect(4, 1, 24, 20)
        pygame.draw.rect(image, beige, bezel)
        pygame.draw.line(image, light, bezel.topleft, (bezel.right - 2, bezel.top))
        pygame.draw.line(image, light, bezel.topleft, (bezel.left, bezel.bottom - 2))
        pygame.draw.rect(image, black, bezel, 1)
        screen = pygame.Rect(7, 4, 18, 13)
        image.blit(self._gradient(screen.size, (0, 0, 128), (16, 132, 208)), screen.topleft)
        corner = (screen.left - 1, screen.top - 1)
        pygame.draw.line(image, dark, corner, (screen.right, screen.top - 1))
        pygame.draw.line(image, dark, corner, (screen.left - 1, screen.bottom))
        pygame.draw.line(image, light, (screen.left, screen.bottom), (screen.right, screen.bottom))
        pygame.draw.line(image, light, (screen.right, screen.top), (screen.right, screen.bottom))
        pygame.draw.line(image, (200, 230, 255), (screen.left + 2, screen.top + 2),
                         (screen.left + 6, screen.top + 2))  # Glare
        # Stand
        pygame.draw.rect(image, dark, pygame.Rect(13, 21, 6, 3))
        # Case: a drive slot and a green power light
        case = pygame.Rect(2, 24, 28, 7)
        pygame.draw.rect(image, beige, case)
        pygame.draw.line(image, light, case.topleft, (case.right - 2, case.top))
        pygame.draw.rect(image, black, case, 1)
        pygame.draw.line(image, black, (6, 27), (15, 27))
        pygame.draw.line(image, dark, (6, 28), (15, 28))
        pygame.draw.rect(image, (0, 192, 0), pygame.Rect(24, 27, 2, 2))
        if size != 32:
            image = pygame.transform.smoothscale(image, (size, size))
        selected = image.copy()
        selected.fill((96, 96, 200, 255), special_flags=pygame.BLEND_RGBA_MULT)
        self.exe_icon_cache[key] = (image, selected)
        return image, selected

    def _program_icon(self, data, host_path, size):
        """(normal, selected) icons of a desktop or Start menu entry: My
        Computer's own icon for Explorer, else the program's EXE icon"""
        if isinstance(data, str) and data.lower() == EXPLORER_PATH.lower():
            return self._computer_icon(size)
        if isinstance(data, tuple) and data[0] == 'special':
            return self._special_desktop_icon(data[1], size)
        return self._exe_icon(host_path, size)

    def _exe_icon(self, host_path, size):
        """(normal, selected) size x size surfaces of an EXE's own icon, or of
        the default program icon if it has none (cached)"""
        key = (host_path, size)
        images = self.exe_icon_cache.get(key)
        if images is not None:
            return images
        icon = read_exe_icon(host_path, size) if host_path else None
        if icon is None:
            image = self._default_exe_icon(size)
        else:
            width, height, rgba = icon
            image = pygame.image.frombuffer(rgba, (width, height), 'RGBA').copy()
            if (width, height) != (size, size):
                image = pygame.transform.smoothscale(image, (size, size))
        # Selected icons are tinted with the selection color (alpha kept)
        selected = image.copy()
        selected.fill((96, 96, 200, 255), special_flags=pygame.BLEND_RGBA_MULT)
        self.exe_icon_cache[key] = (image, selected)
        return image, selected

    def _desktop_icon_rects(self):
        """One cell rect per desktop icon, in columns from the top left"""
        rows = max(1, (self.height - self.TASKBAR_H - self.ICON_MARGIN) // self.ICON_CELL_H)
        return [pygame.Rect(self.ICON_MARGIN + (i // rows) * self.ICON_CELL_W,
                            self.ICON_MARGIN + (i % rows) * self.ICON_CELL_H,
                            self.ICON_CELL_W, self.ICON_CELL_H)
                for i in range(len(self.desktop_icons))]

    def _desktop_icon_at(self, pos):
        """Index of the desktop icon under pos, or None"""
        for i, rect in enumerate(self._desktop_icon_rects()):
            if rect.collidepoint(pos):
                return i
        return None

    def _fit_text(self, font, text, max_width):
        """text cut with '...' to fit max_width pixels"""
        if font.size(text)[0] <= max_width:
            return text
        while text and font.size(text + "...")[0] > max_width:
            text = text[:-1]
        return text + "..." if text else ""

    def _draw_desktop_icons(self):
        """Draw the desktop icons with their labels under them"""
        self._check_desktop_questions()
        for i, ((name, data), rect) in enumerate(zip(self.desktop_icons,
                                                     self._desktop_icon_rects(), strict=False)):
            selected = (i == self.selected_icon)
            normal, tinted = self._program_icon(data, self.desktop_icon_paths.get(data),
                                                self.ICON_SIZE)
            self.screen.blit(tinted if selected else normal,
                             (rect.centerx - self.ICON_SIZE // 2, rect.y + 4))
            label = self._fit_text(self.font_small, name, rect.width - 6)
            text = self.font_small.render(label, True, self.COLOR_TITLE_TEXT)
            text_rect = text.get_rect(midtop=(rect.centerx, rect.y + self.ICON_SIZE + 10))
            if selected:
                pygame.draw.rect(self.screen, self.COLOR_TITLE_BAR, text_rect.inflate(4, 2))
            else:
                shadow = self.font_small.render(label, True, self.COLOR_TEXT)
                self.screen.blit(shadow, text_rect.move(1, 1))
            self.screen.blit(text, text_rect)

    def _double_click(self, target):
        """Record the target of the current left click; True if it is the
        second click of a double click on the same target"""
        now, pos, _ = self.last_click
        last_time, last_pos, last_target = self.prev_click
        if (target == last_target and now - last_time <= self.DOUBLE_CLICK_MS
                and abs(pos[0] - last_pos[0]) <= 4 and abs(pos[1] - last_pos[1]) <= 4):
            self.last_click = (0, pos, None)  # A third click starts over
            return True
        self.last_click = (now, pos, target)
        return False

    def _launch_icon(self, index):
        if not 0 <= index < len(self.desktop_icons):
            return
        data = self.desktop_icons[index][1]
        if isinstance(data, tuple) and data[0] == 'special':
            self._open_special_folder(data[1])
        elif isinstance(data, tuple):
            self._open_shortcut(data)
        elif self.launcher:
            self.launcher(data)

    def _handle_desktop_click(self, pos, button):
        """Click on the desktop background: select / run icons, right-click menu"""
        index = self._desktop_icon_at(pos)
        if button == 1:
            self.selected_icon = index
            if index is not None and self._double_click(('icon', index)):
                self._launch_icon(index)
        elif button == 3:
            self.selected_icon = index
            data = self.desktop_icons[index][1] if index is not None else None
            if isinstance(data, tuple) and data[0] == 'special':
                items = self._special_menu_items(data[1])  # Empty Recycle Bin
            elif index is not None:
                items = [("Open", lambda: self._launch_icon(index))]
            else:
                items = [("Refresh", self._refresh_desktop_icons), None,
                         ("Properties", self._show_display_properties)]
            self._open_desktop_menu(pos, items)

    def _show_display_properties(self):
        self._show_messagebox(
            "Display Properties",
            f"Screen area: {self.width} by {self.height} pixels, Colors: True Color (32 bit)", 0)

    def _open_desktop_menu(self, pos, items):
        """Open the right-click menu at pos, kept inside the screen"""
        width = max(120, max(self.font.size(item[0])[0] for item in items if item) + 30)
        heights = [self.START_SEP_H if item is None else self.START_ITEM_H for item in items]
        menu = pygame.Rect(pos[0], pos[1], width, sum(heights) + 6)
        menu.right = min(menu.right, self.width)
        menu.bottom = min(menu.bottom, self.height - self.TASKBAR_H)
        menu.x, menu.y = max(0, menu.x), max(0, menu.y)
        rects, y = [], menu.y + 3
        for h in heights:
            rects.append(pygame.Rect(menu.x + 3, y, menu.width - 6, h))
            y += h
        self.desktop_menu = (menu, items, rects)
        self.start_menu_open = False

    def _draw_desktop_menu(self):
        if not self.desktop_menu:
            return
        menu, items, rects = self.desktop_menu
        self._draw_menu_panel(menu)
        mouse_pos = pygame.mouse.get_pos()
        for item, rect in zip(items, rects, strict=False):
            if item is None:
                self._draw_menu_separator(rect)
            else:
                self._draw_menu_row(rect, item[0], rect.collidepoint(mouse_pos))

    def _handle_desktop_menu_click(self, pos, button):
        """Any click closes the right-click menu; True if it was inside the menu"""
        menu, items, rects = self.desktop_menu
        self.desktop_menu = None
        if not menu.collidepoint(pos):
            return False
        for item, rect in zip(items, rects, strict=False):
            if item and button in (1, 3) and rect.collidepoint(pos):
                item[1]()
        return True
