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

"""PseudoWindowsGUI mixin: The taskbar: window buttons, the tray clock"""

import time

from ..config import PYGAME_AVAILABLE

if PYGAME_AVAILABLE:
    import pygame


class TaskbarMixin:
    """The taskbar: window buttons, the tray clock"""

    TASKBAR_H = 30
    TASK_BTN_MAX_W = 160
    TASK_BTN_MIN_W = 40
    TOOLTIP_DELAY_MS = 500
    COLOR_TOOLTIP = (255, 255, 225)

    def _tray_rect(self):
        """Sunken system tray area holding the clock (right side of the taskbar)"""
        width = max(60, self.font_small.size("88:88")[0] + 24)
        return pygame.Rect(self.width - width - 2, self.height - self.TASKBAR_H + 3,
                           width, self.TASKBAR_H - 6)

    def _taskbar_buttons(self):
        """[(hwnd, window, rect)] of the taskbar buttons: top-level windows
        (not dialogs) in creation order, so the buttons keep their places"""
        top_level = set(self.z_order)
        windows = [(hwnd, win) for hwnd, win in self.windows.items()
                   if hwnd in top_level and win.visible and not win.is_dialog]
        if not windows:
            return []
        left = self._start_button_rect().right + 6
        available = self._tray_rect().x - 6 - left
        btn_width = max(self.TASK_BTN_MIN_W,
                        min(self.TASK_BTN_MAX_W, available // len(windows) - 4))
        buttons = []
        for i, (hwnd, win) in enumerate(windows):
            rect = pygame.Rect(left + i * (btn_width + 4), self.height - self.TASKBAR_H + 3,
                               btn_width, self.TASKBAR_H - 6)
            if rect.right > left + available:
                break  # No room left for more buttons
            buttons.append((hwnd, win, rect))
        return buttons

    def _draw_taskbar(self):
        """Draw taskbar"""
        top = self.height - self.TASKBAR_H
        pygame.draw.rect(self.screen, self.COLOR_TASKBAR,
                         pygame.Rect(0, top, self.width, self.TASKBAR_H))
        # Raised top edge
        pygame.draw.line(self.screen, self.COLOR_BUTTON, (0, top), (self.width, top))
        pygame.draw.line(self.screen, self.COLOR_BUTTON_BORDER_LIGHT,
                         (0, top + 1), (self.width, top + 1))

        self._draw_start_button()

        # System tray with the clock (sunken)
        tray = self._tray_rect()
        pygame.draw.rect(self.screen, self.COLOR_TASKBAR, tray)
        self._draw_edge(tray, self.COLOR_BUTTON_SHADOW, self.COLOR_BUTTON_BORDER_LIGHT)
        time_text = self.font_small.render(time.strftime("%H:%M"), True, self.COLOR_TEXT)
        self.screen.blit(time_text, time_text.get_rect(center=tray.center))

        for hwnd, win, rect in self._taskbar_buttons():
            is_active = (hwnd == self.active_window) and not win.minimized
            self._draw_taskbar_button(rect, win, is_active)

    def _draw_start_button(self):
        """Start button: a computer icon and a bold "Start", pressed while the
        Start menu is open"""
        rect = self._start_button_rect()
        pressed = self.start_menu_open
        pygame.draw.rect(self.screen, self.COLOR_BUTTON, rect)
        if pressed:
            self._draw_sunken(rect)
        else:
            self._draw_raised(rect)
        offset = 1 if pressed else 0
        icon = self._start_icon()
        text = self.font_bold.render("Start", True, self.COLOR_TEXT)
        width = icon.get_width() + 4 + text.get_width()
        x = rect.x + (rect.width - width) // 2 + offset
        self.screen.blit(icon, (x, rect.centery - icon.get_height() // 2 + offset))
        self.screen.blit(text, (x + icon.get_width() + 4,
                                rect.centery - text.get_height() // 2 + offset))
        if pressed:
            # Dotted focus rectangle like the classic pressed Start button
            focus = rect.inflate(-6, -6)
            for px in range(focus.x, focus.right, 2):
                self.screen.set_at((px, focus.y), self.COLOR_TEXT)
                self.screen.set_at((px, focus.bottom - 1), self.COLOR_TEXT)
            for py in range(focus.y, focus.bottom, 2):
                self.screen.set_at((focus.x, py), self.COLOR_TEXT)
                self.screen.set_at((focus.right - 1, py), self.COLOR_TEXT)

    def _start_icon(self):
        """16x16 icon of the Start button: a small computer (cached)"""
        icon = self.exe_icon_cache.get(('start', 16))
        if icon is None:
            icon = pygame.Surface((16, 16), pygame.SRCALPHA)
            case = pygame.Rect(1, 1, 14, 11)
            pygame.draw.rect(icon, (192, 192, 192), case)
            pygame.draw.rect(icon, (64, 64, 64), case, 1)
            screen = pygame.Rect(3, 3, 10, 7)
            icon.blit(self._gradient(screen.size, (0, 0, 128), (16, 132, 208)), screen.topleft)
            pygame.draw.line(icon, (255, 255, 255), (4, 4), (6, 4))
            pygame.draw.rect(icon, (128, 128, 128), pygame.Rect(6, 12, 4, 2))
            pygame.draw.rect(icon, (64, 64, 64), pygame.Rect(3, 14, 10, 2))
            self.exe_icon_cache[('start', 16)] = icon
        return icon

    def _draw_taskbar_button(self, rect, win, is_active):
        """Draw a taskbar button with the program icon and the window title; the
        active window's one is pressed with bold text"""
        if is_active:
            # Classic checkered face of a pressed taskbar button
            self.screen.blit(self._checker_surface(rect.size), rect.topleft)
            self._draw_sunken(rect)
        else:
            pygame.draw.rect(self.screen, self.COLOR_BUTTON, rect)
            self._draw_raised(rect)

        offset = 1 if is_active else 0
        size = self.CAPTION_ICON_SIZE
        text_x = rect.x + 5 + offset
        if rect.width >= size + 14:
            icon = self._exe_icon(win.icon_path, size)[0]
            self.screen.blit(icon, (text_x, rect.y + (rect.height - size) // 2 + offset))
            text_x += size + 4
        font = self.font_small_bold if is_active else self.font_small
        label = self._fit_text(font, win.title, rect.right - 5 - text_x)
        text_surface = font.render(label, True, self.COLOR_TEXT)
        text_y = rect.y + (rect.height - text_surface.get_height()) // 2 + offset
        self.screen.blit(text_surface, (text_x, text_y))

    def _checker_surface(self, size):
        """White / gray checkered surface of this size (cached)"""
        cache = self._checker_cache
        surface = cache.get(size)
        if surface is None:
            surface = pygame.Surface(size)
            surface.fill(self.COLOR_BUTTON_BORDER_LIGHT)
            for y in range(size[1]):
                for x in range(y & 1, size[0], 2):
                    surface.set_at((x, y), self.COLOR_TASKBAR)
            cache.clear()  # Only the current button width is needed
            cache[size] = surface
        return surface

    def _draw_clock_tooltip(self):
        """Date tooltip after hovering the clock for a moment"""
        if self._fullscreen_window() is not None or self.start_menu_open or self.desktop_menu:
            self.tray_hover_since = None
            return
        if not self._tray_rect().collidepoint(pygame.mouse.get_pos()):
            self.tray_hover_since = None
            return
        now = pygame.time.get_ticks()
        if self.tray_hover_since is None:
            self.tray_hover_since = now
        if now - self.tray_hover_since < self.TOOLTIP_DELAY_MS:
            return
        text = self.font_small.render(time.strftime("%A, %B %d, %Y"), True, self.COLOR_TEXT)
        tip = pygame.Rect(0, 0, text.get_width() + 8, text.get_height() + 4)
        tip.bottomright = (self.width - 2, self.height - self.TASKBAR_H - 2)
        tip.x = max(0, tip.x)
        pygame.draw.rect(self.screen, self.COLOR_TOOLTIP, tip)
        pygame.draw.rect(self.screen, self.COLOR_TEXT, tip, 1)
        self.screen.blit(text, (tip.x + 4, tip.y + 2))

    def _handle_taskbar_click(self, pos, button):
        """Taskbar button click: restore a minimized window, minimize the active
        one, or bring another one to the front"""
        if button != 1:
            return
        for hwnd, win, rect in self._taskbar_buttons():
            if not rect.collidepoint(pos):
                continue
            if win.minimized:
                win.restore()
            elif hwnd == self.active_window:
                win.minimize()
                self._activate_next_window(skip_dialogs=True)
                return
            self.active_window = hwnd
            self.z_order.remove(hwnd)
            self.z_order.append(hwnd)
            return

    def _activate_next_window(self, skip_dialogs=False):
        """Activate the topmost visible, not minimized window (after a minimize)"""
        for h in reversed(self.z_order):
            win = self.windows.get(h)
            if (win and win.visible and not win.minimized
                    and not (skip_dialogs and win.is_dialog)):
                self.active_window = h
                return
