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

"""PseudoWindowsGUI mixin: Message boxes"""

import re
import queue

from .. import winapi
from ..config import PYGAME_AVAILABLE
from ..windows import FakeControl

if PYGAME_AVAILABLE:
    import pygame


class MessageBoxesMixin:
    """Message boxes"""

    def _check_messagebox(self):
        """Check MessageBox requests"""
        try:
            msg = self.messagebox_queue.get_nowait()
        except queue.Empty:
            return
        process = msg.get('process')
        if process is not None and process.process_exited:
            return  # Its program ended before the box was shown
        self._show_messagebox(msg['caption'], msg['text'], msg['type'], msg.get('request'),
                              process)

    def _show_messagebox(self, caption, text, msg_type, request=None, process=None):
        """Show MessageBox; each line of text gets its own row, the buttons of
        its MB_* type below. request (if any) gets the chosen button's id."""
        buttons, default, cancel = winapi.WinAPIHandler.messagebox_buttons(msg_type)
        line_h = 18
        icon = (msg_type >> 4) & 0x7  # MB_ICONHAND, QUESTION, EXCLAMATION, ASTERISK
        text_x = 64 if icon in (1, 2, 3, 4) else 20
        # Like Windows, long lines wrap at word breaks: the box stays narrower
        # than the screen
        lines = self._wrap_text(text, max(200, self.width * 5 // 8 - text_x))
        button_w, gap = 80, 8
        buttons_w = len(buttons) * button_w + (len(buttons) - 1) * gap
        text_w = max(self.font.size(line)[0] for line in lines)
        width = min(max(300, text_w + text_x + 30, buttons_w + 40), self.width - 20)
        height = 90 + max(len(lines) * line_h, 40 if text_x > 20 else 0)
        x = (self.width - width) // 2
        y = (self.height - height) // 2

        hwnd = self.create_window(caption, x, y, width, height)
        win = self.windows[hwnd]
        win.is_dialog = True  # Show only close button
        win.messagebox_icon = icon if text_x > 20 else 0

        # Text
        for i, line in enumerate(lines):
            if line:
                win.controls.append(FakeControl(self.get_next_hwnd(), "STATIC", line,
                                                text_x, 20 + i * line_h, width - text_x - 20,
                                                line_h, 0x80))  # SS_NOPREFIX

        # Buttons, the default one with the thick frame
        left = (width - buttons_w) // 2
        controls = []
        for index, (label, result) in enumerate(buttons):
            button = FakeControl(self.get_next_hwnd(), "BUTTON", label,
                                 left + index * (button_w + gap), height - 60, button_w, 25,
                                 1 if index == default else 0)  # BS_DEFPUSHBUTTON
            button.mb_result = result
            win.controls.append(button)
            controls.append(button)
        self.messageboxes[hwnd] = {'request': request, 'buttons': controls,
                                   'focus': default, 'cancel': cancel, 'process': process}

        self.show_window(hwnd)

    def _messagebox_icon_surface(self, icon):
        """32x32 MessageBox icon (1 stop, 2 question, 3 exclamation, 4
        information) drawn with shapes, not font glyphs (a bold "i" may look
        like an "I" or "!"); drawn 4x larger and smoothly scaled down, cached"""
        cache = self.__dict__.setdefault('_messagebox_icons', {})
        if icon in cache:
            return cache[icon]
        k = 4
        big = pygame.Surface((32 * k, 32 * k), pygame.SRCALPHA)

        def circle(color, cx, cy, r, width=0):
            pygame.draw.circle(big, color, (cx * k, cy * k), r * k, width * k)

        def rect(color, x, y, w, h):
            pygame.draw.rect(big, color, (x * k, y * k, w * k, h * k))

        if icon == 3:  # Exclamation: yellow triangle with a black "!"
            points = [(16 * k, 1 * k), (31 * k, 29 * k), (1 * k, 29 * k)]
            pygame.draw.polygon(big, (255, 220, 0), points)
            pygame.draw.polygon(big, (0, 0, 0), points, k)
            rect((0, 0, 0), 14.5, 9, 3, 12)
            rect((0, 0, 0), 14.5, 23, 3, 3)
        else:
            fill = {1: (210, 0, 0), 2: (0, 70, 200)}.get(icon, (0, 70, 200))
            circle(fill, 16, 16, 15)
            circle((40, 40, 40), 16, 16, 15, 1)
            white = (255, 255, 255)
            if icon == 1:  # Stop: white "X"
                for a, b in (((10, 10), (22, 22)), ((22, 10), (10, 22))):
                    pygame.draw.line(big, white, (a[0] * k, a[1] * k), (b[0] * k, b[1] * k),
                                     int(3.5 * k))
            elif icon == 2:  # Question: white "?" (arc, stem and dot)
                pygame.draw.arc(big, white, (11 * k, 6 * k, 10 * k, 10 * k), -1.2, 3.3, 3 * k)
                rect(white, 14.5, 15, 3, 5)
                rect(white, 14.5, 22, 3, 3)
            else:  # Information: white "i" (dot and stem)
                circle(white, 16, 8.5, 2)
                rect(white, 14.5, 13, 3, 12)
                rect(white, 12.5, 13, 3, 2)
                rect(white, 12.5, 23, 7, 2)
        surface = pygame.transform.smoothscale(big, (32, 32))
        cache[icon] = surface
        return surface

    def _draw_messagebox_icon(self, icon, x, y):
        """32x32 MessageBox icon at (x, y)"""
        self.screen.blit(self._messagebox_icon_surface(icon), (x, y))

    def _messagebox_done(self, hwnd, result):
        """A message box closes with result (a button id)"""
        box = self.messageboxes.pop(hwnd, None)
        if box is not None and box['request'] is not None:
            box['request']['result'] = result
        if hwnd in self.windows:
            self._remove_window(hwnd)

    def _messagebox_focus(self, hwnd, index):
        """Move the default button frame (keyboard focus) to button index"""
        box = self.messageboxes[hwnd]
        index %= len(box['buttons'])
        box['focus'] = index
        for n, button in enumerate(box['buttons']):
            button.style = 1 if n == index else 0

    def _messagebox_key(self, event):
        """Keyboard input of the active message box; True if it took the key"""
        hwnd = self.active_window
        box = self.messageboxes.get(hwnd)
        if box is None:
            return False
        if event.key in (pygame.K_RETURN, pygame.K_KP_ENTER, pygame.K_SPACE):
            self._messagebox_done(hwnd, box['buttons'][box['focus']].mb_result)
        elif event.key == pygame.K_ESCAPE:
            if box['cancel'] is not None:
                self._messagebox_done(hwnd, box['cancel'])
        elif event.key in (pygame.K_LEFT, pygame.K_UP) or (
                event.key == pygame.K_TAB and event.mod & pygame.KMOD_SHIFT):
            self._messagebox_focus(hwnd, box['focus'] - 1)
        elif event.key in (pygame.K_RIGHT, pygame.K_DOWN, pygame.K_TAB):
            self._messagebox_focus(hwnd, box['focus'] + 1)
        elif event.unicode:
            for button in box['buttons']:
                mnemonic = re.search(r'&([^&])', button.text)
                if mnemonic and mnemonic.group(1).lower() == event.unicode.lower():
                    self._messagebox_done(hwnd, button.mb_result)
                    break
        return True
