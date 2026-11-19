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

"""PseudoWindowsGUI mixin: The Start button and the Start menu with its submenus"""

import os
import ntpath

from .. import winapi
from ..config import EXPLORER_PATH, PYGAME_AVAILABLE
from ..paths import _program_subfolders, resolve_drive_path
from ..resources import parse_shell_link

if PYGAME_AVAILABLE:
    import pygame


class StartMenuMixin:
    """The Start button and the Start menu with its submenus"""

    # ==================== START MENU ====================

    START_ITEM_H = 22
    START_TOP_ITEM_H = 36  # Rows of the Start menu itself (32x32 icons)
    START_TOP_ICON_SIZE = 32
    START_SEP_H = 8
    START_MENU_W = 200
    START_STRIP_W = 24

    def _start_button_rect(self):
        return pygame.Rect(2, self.height - self.TASKBAR_H + 3, 66, self.TASKBAR_H - 6)

    @staticmethod
    def _explorer_available():
        path = resolve_drive_path(EXPLORER_PATH)
        return bool(path) and os.path.isfile(path)

    def _fill_start_menu(self):
        """Build the Start menu: Programs (the Start Menu folders of the user and
        of all users with their shortcuts, then My Computer, if compiled, in
        its own section) and Exit.
        Rows are ('program', label, path or shortcut), ('submenu', label, rows),
        ('exit', label, None), ('separator', None, None) or ('empty', label, None)"""
        self.start_icon_paths = {}
        folders = winapi.WinAPIHandler.SHELL_FOLDERS
        # CSIDL_PROGRAMS, CSIDL_COMMON_PROGRAMS
        shortcut_rows = self._shortcut_rows([folders[0x02], folders[0x17]])
        rows = []
        if self._explorer_available():
            rows = [('program', self._program_label(EXPLORER_PATH), EXPLORER_PATH)]
            self.start_icon_paths[EXPLORER_PATH] = resolve_drive_path(EXPLORER_PATH)
        if shortcut_rows:
            rows = shortcut_rows + ([('separator', None, None)] + rows if rows else [])
        self.start_menu_rows = [
            ('submenu', "Programs", rows or [('empty', "(no programs found)", None)]),
            ('separator', None, None),
            ('exit', "Exit", None),
        ]
        self.start_open_path = []

    def _shortcut_entries(self, folders, icon_paths):
        """Merged contents of folders (Windows paths), like Windows merges the
        user's and the all users' Start Menu or Desktop folders:
        ({lower-case name: (name, [Windows paths])} of the subfolders,
        sorted [(label, ('shortcut', target, arguments, working directory))]
        of the shortcuts (.lnk) and programs). The host paths of the EXE
        targets are added to icon_paths."""
        subfolders, items = {}, {}
        for folder in folders:
            host = resolve_drive_path(folder)
            if not host or not os.path.isdir(host):
                continue
            for name in _program_subfolders(host):
                subfolders.setdefault(name.lower(), (name, []))[1].append(folder + '\\' + name)
            for name in sorted(os.listdir(host), key=str.lower):
                label, ext = os.path.splitext(name)
                file_path = os.path.join(host, name)
                if ext.lower() not in ('.lnk', '.exe') or not os.path.isfile(file_path):
                    continue
                if ext.lower() == '.exe':
                    data = ('shortcut', folder + '\\' + name, '', '')
                else:
                    try:
                        with open(file_path, 'rb') as f:
                            link = parse_shell_link(f.read(65536))
                    except OSError:
                        link = None
                    if link is None or not link['path']:
                        continue
                    data = ('shortcut', link['path'], link['arguments'], link['workdir'])
                if label.lower() not in items:
                    items[label.lower()] = (label, data)
                    if data[1].lower().endswith('.exe'):
                        icon_paths[data] = resolve_drive_path(data[1])
        return subfolders, [item for _, item in sorted(items.items())]

    def _shortcut_rows(self, folders, depth=0):
        """Start menu rows of Start Menu folders (Windows paths): their merged
        subfolders as submenus first, then their shortcuts and programs"""
        subfolders, items = self._shortcut_entries(folders, self.start_icon_paths)
        rows = []
        if depth < 8:
            for _, (name, paths) in sorted(subfolders.items()):
                rows.append(('submenu', name, self._shortcut_rows(paths, depth + 1)
                             or [('empty', "(Empty)", None)]))
        rows += [('program', label, data) for label, data in items]
        return rows

    def _open_shortcut(self, data):
        """Run the target of a Start menu shortcut (only programs can be run)"""
        _, target, arguments, workdir = data
        name = ntpath.basename(target)
        host = resolve_drive_path(target) if target else None
        if not host or not os.path.isfile(host):
            self._show_messagebox("Problem with Shortcut",
                                  f"The item '{name}' that this shortcut refers to has "
                                  "been changed or moved.", 0x10)
        elif not target.lower().endswith('.exe'):
            self._show_messagebox(name, "This file does not have a program associated "
                                  "with it for performing this action.", 0x10)
        elif self.launcher:
            command_line = f'"{target}"' + (f' {arguments}' if arguments else '')
            self.launcher(target, command_line, workdir or ntpath.dirname(target))

    def _menu_row_rects(self, menu, rows, strip=False, item_h=None):
        """Row rects inside a menu panel rect (right of the blue strip if strip)"""
        rects = []
        y = menu.y + 3
        left = menu.x + (self.START_STRIP_W + 2 if strip else 3)
        for kind, _, _ in rows:
            h = self.START_SEP_H if kind == 'separator' else (item_h or self.START_ITEM_H)
            rects.append(pygame.Rect(left, y, menu.right - 3 - left, h))
            y += h
        return rects

    def _menu_rows_height(self, rows, item_h):
        """Height of a menu panel holding these rows (with its 3-pixel edges)"""
        return sum(self.START_SEP_H if kind == 'separator' else item_h
                   for kind, _, _ in rows) + 6

    def _start_menu_levels(self):
        """[(menu rect, rows, row rects)] of the Start menu and its open submenus"""
        rows = self.start_menu_rows
        height = self._menu_rows_height(rows, self.START_TOP_ITEM_H)
        menu = pygame.Rect(0, self.height - self.TASKBAR_H - height, self.START_MENU_W, height)
        levels = [(menu, rows, self._menu_row_rects(menu, rows, strip=True,
                                                    item_h=self.START_TOP_ITEM_H))]
        for index in self.start_open_path:
            menu, rows, rects = levels[-1]
            if not (0 <= index < len(rows)) or rows[index][0] != 'submenu':
                break
            parent_row = rects[index]
            sub_rows = rows[index][2]
            height = self._menu_rows_height(sub_rows, self.START_ITEM_H)
            width = max([self.START_MENU_W] + [self.font.size(label)[0] + 60
                                               for kind, label, _ in sub_rows if label])
            top = max(0, min(parent_row.y - 3, self.height - self.TASKBAR_H - height))
            sub = pygame.Rect(menu.right - 2, top, width, height)
            levels.append((sub, sub_rows, self._menu_row_rects(sub, sub_rows)))
        return levels

    def _start_menu_hit(self, pos):
        """(level, row index or None) of the topmost Start menu panel under pos, or None"""
        levels = self._start_menu_levels()
        for level in range(len(levels) - 1, -1, -1):
            menu, rows, rects = levels[level]
            if menu.collidepoint(pos):
                for i, rect in enumerate(rects):
                    if rect.collidepoint(pos) and rows[i][0] != 'separator':
                        return level, i
                return level, None
        return None

    def _draw_menu_panel(self, rect):
        """Raised 3D panel behind a menu, with a soft shadow"""
        self._draw_shadow(rect)
        pygame.draw.rect(self.screen, self.COLOR_BUTTON, rect)
        self._draw_raised(rect)

    def _draw_menu_separator(self, rect):
        """Etched horizontal line across a menu row"""
        y = rect.centery
        pygame.draw.line(self.screen, self.COLOR_BUTTON_SHADOW,
                         (rect.x + 2, y - 1), (rect.right - 3, y - 1))
        pygame.draw.line(self.screen, self.COLOR_BUTTON_BORDER_LIGHT,
                         (rect.x + 2, y), (rect.right - 3, y))

    def _draw_menu_row(self, rect, label, highlighted, icon=None):
        """Menu row: an optional icon (16x16 or 32x32), then the label"""
        if highlighted:
            pygame.draw.rect(self.screen, self.COLOR_TITLE_BAR, rect)
        color = self.COLOR_TITLE_TEXT if highlighted else self.COLOR_TEXT
        text_x = rect.x + 6
        if icon is not None:
            self.screen.blit(icon, (rect.x + 4, rect.y + (rect.height - icon.get_height()) // 2))
            text_x = rect.x + 4 + icon.get_width() + (10 if icon.get_width() > 16 else 8)
        text = self.font.render(label, True, color)
        self.screen.blit(text, (text_x, rect.y + (rect.height - text.get_height()) // 2))
        return color

    def _scaled_icon(self, name, icon, size):
        """A 16x16 drawn icon doubled to size (cached), keeping its crisp pixels"""
        if size == icon.get_width():
            return icon
        key = (name, size)
        scaled = self.exe_icon_cache.get(key)
        if scaled is None:
            scaled = pygame.transform.scale(icon, (size, size))
            self.exe_icon_cache[key] = scaled
        return scaled

    def _draw_start_strip(self, menu):
        """Gradient strip at the left of the Start menu with the emulator's name
        written upwards at its bottom"""
        strip = pygame.Rect(menu.x + 3, menu.y + 3, self.START_STRIP_W - 3, menu.height - 6)
        self.screen.blit(self._gradient(strip.size, self.COLOR_START_STRIP_TOP,
                                        self.COLOR_START_STRIP_BOTTOM, horizontal=False),
                         strip.topleft)
        for bold, regular in ((self.font_bold, self.font), (self.font_small_bold, self.font_small)):
            first = bold.render("winexe", True, self.COLOR_TITLE_TEXT)
            second = regular.render("32emu", True, (200, 220, 255))
            width = first.get_width() + second.get_width()
            if width <= strip.height - 8:
                break
        else:
            return  # Too short a menu for the name
        label = pygame.Surface((width, max(first.get_height(), second.get_height())),
                               pygame.SRCALPHA)
        label.blit(first, (0, 0))
        label.blit(second, (first.get_width(), label.get_height() - second.get_height()))
        label = pygame.transform.rotate(label, 90)  # Reads bottom to top
        self.screen.blit(label, (strip.centerx - label.get_width() // 2,
                                 strip.bottom - 6 - label.get_height()))

    def _folder_icon(self):
        """16x16 yellow folder icon of the Start menu's submenus (cached)"""
        icon = self.exe_icon_cache.get(('folder', 16))
        if icon is None:
            icon = pygame.Surface((16, 16), pygame.SRCALPHA)
            pygame.draw.rect(icon, (255, 255, 128), pygame.Rect(1, 2, 6, 3))
            pygame.draw.rect(icon, (128, 128, 0), pygame.Rect(1, 2, 6, 3), 1)
            body = pygame.Rect(1, 4, 14, 10)
            pygame.draw.rect(icon, (255, 255, 128), body)
            pygame.draw.rect(icon, (128, 128, 0), body, 1)
            self.exe_icon_cache[('folder', 16)] = icon
        return icon

    def _exit_icon(self):
        """16x16 Exit icon: an open door with a green arrow leaving it (cached)"""
        icon = self.exe_icon_cache.get(('exit', 16))
        if icon is None:
            icon = pygame.Surface((16, 16), pygame.SRCALPHA)
            frame = pygame.Rect(1, 1, 9, 14)
            pygame.draw.rect(icon, (64, 64, 64), frame)
            # The door is swung open towards the viewer
            pygame.draw.polygon(icon, (160, 96, 32), [(2, 2), (7, 3), (7, 15), (2, 14)])
            pygame.draw.polygon(icon, (96, 48, 0), [(2, 2), (7, 3), (7, 15), (2, 14)], 1)
            icon.set_at((6, 9), (255, 220, 0))  # Knob
            green, dark = (0, 192, 0), (0, 96, 0)
            arrow = [(8, 7), (11, 7), (11, 4), (15, 8), (11, 12), (11, 9), (8, 9)]
            pygame.draw.polygon(icon, green, arrow)
            pygame.draw.polygon(icon, dark, arrow, 1)
            self.exe_icon_cache[('exit', 16)] = icon
        return icon

    @staticmethod
    def _program_label(path):
        if path.lower() == EXPLORER_PATH.lower():
            return "My Computer"
        return os.path.splitext(path.rsplit('\\', 1)[-1])[0]

    def _draw_start_menu(self):
        """Draw the Start menu and its open submenus"""
        if not self.start_menu_open:
            return
        mouse_pos = pygame.mouse.get_pos()
        # Hovering a row opens its submenu and closes the deeper ones
        hit = self._start_menu_hit(mouse_pos)
        if hit and hit[1] is not None:
            level, index = hit
            rows = self._start_menu_levels()[level][1]
            self.start_open_path = self.start_open_path[:level] + (
                [index] if rows[index][0] == 'submenu' else [])

        for level, (menu, rows, rects) in enumerate(self._start_menu_levels()):
            self._draw_menu_panel(menu)
            # The Start menu itself has the side strip and 32x32 icons
            icon_size = self.CAPTION_ICON_SIZE
            if level == 0:
                self._draw_start_strip(menu)
                icon_size = self.START_TOP_ICON_SIZE
            open_index = (self.start_open_path[level]
                          if level < len(self.start_open_path) else None)
            for i, ((kind, label, data), rect) in enumerate(zip(rows, rects, strict=False)):
                if kind == 'separator':
                    self._draw_menu_separator(rect)
                elif kind == 'empty':
                    text = self.font.render(label, True, (128, 128, 128))
                    self.screen.blit(text, (rect.x + 6, rect.y + 3))
                elif kind == 'submenu':
                    icon = self._scaled_icon('folder', self._folder_icon(), icon_size)
                    color = self._draw_menu_row(rect, label, i == open_index, icon=icon)
                    ax, ay = rect.right - 12, rect.centery
                    pygame.draw.polygon(self.screen, color,
                                        [(ax, ay - 4), (ax + 4, ay), (ax, ay + 4)])
                elif kind == 'program':
                    icon = self._program_icon(data, self.start_icon_paths.get(data), icon_size)[0]
                    self._draw_menu_row(rect, label, rect.collidepoint(mouse_pos), icon=icon)
                elif kind == 'exit':
                    icon = self._scaled_icon('exit', self._exit_icon(), icon_size)
                    self._draw_menu_row(rect, label, rect.collidepoint(mouse_pos), icon=icon)

    def _handle_start_menu_click(self, pos, button):
        """Start button toggles the menu; returns True if the click was consumed"""
        if self._fullscreen_window() is not None:
            return False  # A full-screen window covers the taskbar
        if self._start_button_rect().collidepoint(pos):
            self.start_menu_open = not self.start_menu_open
            if self.start_menu_open:
                self.open_menu = None
                self.open_combo = None
                self.desktop_menu = None
                self._fill_start_menu()
            return True
        if not self.start_menu_open:
            return False

        hit = self._start_menu_hit(pos)
        if hit is None:
            self.start_menu_open = False  # A click outside closes the menu
            return False
        level, index = hit
        if index is None or button != 1:
            return True
        kind, _, data = self._start_menu_levels()[level][1][index]
        if kind == 'submenu':
            self.start_open_path = self.start_open_path[:level] + [index]
        elif kind == 'program':
            self.start_menu_open = False
            if isinstance(data, tuple):
                self._open_shortcut(data)
            elif self.launcher:
                self.launcher(data)
        elif kind == 'exit':
            self.start_menu_open = False
            self.running = False  # Like closing the emulator's window
        return True
