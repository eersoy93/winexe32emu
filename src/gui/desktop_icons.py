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

"""PseudoWindowsGUI mixin: the desktop's folder icons besides My Computer (the
user's folder, the network, the Recycle Bin) and what they do: they open in
Explorer; the Recycle Bin can be emptied from its right-click menu.

The icons are drawn here with shapes at 32x32 (and scaled), like My
Computer's: no icon files. The system image lists of the emulated programs
show them too (SYS_ICON_USER... of shell_namespace.py)."""

import os
import time

from .. import config, recycle_bin, winapi
from ..config import EXPLORER_PATH, PYGAME_AVAILABLE, USER_PROFILE_FOLDER
from ..paths import resolve_drive_path

if PYGAME_AVAILABLE:
    import pygame

BLACK, DARK, LIGHT, WHITE = (32, 32, 32), (128, 128, 128), (212, 208, 200), (255, 255, 255)
FOLDER_FILL, FOLDER_EDGE = (240, 200, 80), (150, 110, 20)


class DesktopIconsMixin:
    """The user folder, network and Recycle Bin desktop icons"""

    # Desktop entries of the folders: ('special', kind)
    SPECIAL_USER, SPECIAL_NETWORK, SPECIAL_BIN = 'user', 'network', 'bin'
    BIN_CHECK_SECONDS = 0.5

    def _special_desktop_entries(self):
        """(label, data) of the folder icons that follow My Computer, like
        on Windows: the user's folder, the network and the Recycle Bin"""
        handler = winapi.WinAPIHandler
        return [(config.USER_NAME, ('special', self.SPECIAL_USER)),
                (handler.NETWORK_NAME, ('special', self.SPECIAL_NETWORK)),
                (handler.RECYCLE_BIN_NAME, ('special', self.SPECIAL_BIN))]

    def _special_folder_path(self, kind):
        """What Explorer opens for a folder icon: a path or a parsing name"""
        handler = winapi.WinAPIHandler
        return {self.SPECIAL_USER: USER_PROFILE_FOLDER,
                self.SPECIAL_NETWORK: handler.NETWORK_PATH,
                self.SPECIAL_BIN: handler.RECYCLE_BIN_PATH}[kind]

    def _open_special_folder(self, kind):
        """Open a folder icon in Explorer (explorer.exe <folder>)"""
        target = self._special_folder_path(kind)
        if kind == self.SPECIAL_USER:
            host = resolve_drive_path(target)
            if host:
                try:
                    os.makedirs(host, exist_ok=True)  # It exists on every Windows
                except OSError:
                    pass
        if self.launcher:
            self.launcher(EXPLORER_PATH, f'"{EXPLORER_PATH}" "{target}"',
                          EXPLORER_PATH.rsplit('\\', 1)[0])

    def _special_menu_items(self, kind):
        """Right-click menu of a folder icon"""
        items = [("Open", lambda: self._open_special_folder(kind))]
        if kind == self.SPECIAL_BIN:
            items += [None, ("Empty Recycle Bin", self._ask_empty_recycle_bin)]
        return items

    # ---------- The Recycle Bin ----------

    def _recycle_bin_full(self):
        """Does a bin hold something? The index files are looked at only now
        and then, the items counted only when they changed."""
        cache = self.__dict__.setdefault('_bin_state', {'time': 0, 'token': None,
                                                        'full': False})
        now = time.monotonic()
        if now - cache['time'] >= self.BIN_CHECK_SECONDS:
            cache['time'] = now
            token = recycle_bin.state_token()
            if token != cache['token']:
                cache['token'] = token
                cache['full'] = recycle_bin.query()[1] > 0
        return cache['full']

    def _ask_empty_recycle_bin(self):
        """Empty Recycle Bin of the desktop: asks first, like the shell"""
        found = recycle_bin.items()
        if not found:
            self._show_messagebox("Recycle Bin", "The Recycle Bin is already empty.", 0x40)
            return
        if len(found) == 1:
            caption = "Confirm File Delete"
            text = f"Are you sure you want to permanently delete '{found[0].name}'?"
        else:
            caption = "Confirm Multiple File Delete"
            text = f"Are you sure you want to permanently delete these {len(found)} items?"
        request = {'result': None}
        self._show_messagebox(caption, text, 0x34, request)  # MB_YESNO | MB_ICONEXCLAMATION
        self.__dict__.setdefault('_desktop_questions', []).append(
            (request, lambda answer: answer == 6 and self._empty_recycle_bin_now()))

    def _empty_recycle_bin_now(self):
        recycle_bin.empty()
        self.__dict__.get('_bin_state', {})['time'] = 0  # Show the empty bin at once

    def _check_desktop_questions(self):
        """Act on the answered desktop message boxes (once per frame)"""
        questions = self.__dict__.get('_desktop_questions')
        if not questions:
            return
        for question in list(questions):
            request, on_answer = question
            if request['result'] is not None:
                questions.remove(question)
                on_answer(request['result'])

    # ---------- Drawing ----------

    def _special_desktop_icon(self, kind, size):
        """(normal, selected) icon of a desktop folder entry"""
        handler = winapi.WinAPIHandler
        if kind == self.SPECIAL_USER:
            return self._shell_icon_images(handler.SYS_ICON_USER, size)
        if kind == self.SPECIAL_NETWORK:
            return self._shell_icon_images(handler.SYS_ICON_NETWORK, size)
        full = self._recycle_bin_full()
        return self._shell_icon_images(handler.SYS_ICON_BIN_FULL if full else
                                       handler.SYS_ICON_BIN_EMPTY, size)

    def _shell_icon_images(self, base, size):
        """(normal, selected) size x size surfaces of a system image list
        icon base from 5 on (My Computer and the folder icons), cached"""
        handler = winapi.WinAPIHandler
        if base == handler.SYS_ICON_COMPUTER:
            return self._computer_icon(size)
        key = ('shell icon', base, size)
        images = self.exe_icon_cache.get(key)
        if images is not None:
            return images
        image = pygame.Surface((32, 32), pygame.SRCALPHA)
        if base == handler.SYS_ICON_USER:
            self._paint_user_folder(image)
        elif base == handler.SYS_ICON_NETWORK:
            self._paint_network(image)
        else:
            self._paint_recycle_bin(image, base == handler.SYS_ICON_BIN_FULL)
        if size != 32:
            image = pygame.transform.smoothscale(image, (size, size))
        selected = image.copy()
        selected.fill((96, 96, 200, 255), special_flags=pygame.BLEND_RGBA_MULT)
        self.exe_icon_cache[key] = (image, selected)
        return image, selected

    @staticmethod
    def _paint_user_folder(image):
        """A manila folder with a person in front of it"""
        back = pygame.Rect(1, 7, 28, 21)
        pygame.draw.rect(image, FOLDER_FILL, pygame.Rect(1, 4, 11, 4))  # Tab
        pygame.draw.rect(image, FOLDER_EDGE, pygame.Rect(1, 4, 11, 4), 1)
        pygame.draw.rect(image, FOLDER_FILL, back)
        pygame.draw.rect(image, FOLDER_EDGE, back, 1)
        pygame.draw.line(image, (255, 235, 160), (2, 9), (27, 9))  # Light inner edge
        # The person: shoulders (a blue shirt) and a head
        shirt, skin = (40, 90, 190), (240, 196, 150)
        pygame.draw.ellipse(image, shirt, pygame.Rect(12, 21, 18, 14))
        pygame.draw.ellipse(image, (20, 50, 120), pygame.Rect(12, 21, 18, 14), 1)
        pygame.draw.circle(image, skin, (21, 17), 5)
        pygame.draw.circle(image, (150, 100, 60), (21, 17), 5, 1)

    @staticmethod
    def _paint_network(image):
        """Two computers wired to the same cable, under a globe"""
        def small_computer(x, y):
            bezel = pygame.Rect(x, y, 12, 10)
            pygame.draw.rect(image, LIGHT, bezel)
            pygame.draw.rect(image, BLACK, bezel, 1)
            pygame.draw.rect(image, (16, 90, 180), pygame.Rect(x + 2, y + 2, 8, 6))
            pygame.draw.rect(image, DARK, pygame.Rect(x + 4, y + 10, 4, 2))
            pygame.draw.rect(image, LIGHT, pygame.Rect(x - 1, y + 12, 14, 3))
            pygame.draw.rect(image, BLACK, pygame.Rect(x - 1, y + 12, 14, 3), 1)

        # Globe: blue with green land and grid lines
        pygame.draw.circle(image, (40, 120, 220), (16, 8), 7)
        pygame.draw.ellipse(image, (40, 160, 60), pygame.Rect(11, 4, 6, 5))
        pygame.draw.ellipse(image, (40, 160, 60), pygame.Rect(16, 9, 5, 4))
        pygame.draw.ellipse(image, (200, 230, 255), pygame.Rect(13, 1, 6, 14), 1)
        pygame.draw.circle(image, (10, 50, 120), (16, 8), 7, 1)
        # The cable, then the computers on it
        cable = (60, 60, 60)
        pygame.draw.line(image, cable, (7, 28), (25, 28), 2)
        pygame.draw.line(image, cable, (7, 26), (7, 28), 2)
        pygame.draw.line(image, cable, (25, 26), (25, 28), 2)
        pygame.draw.line(image, cable, (16, 15), (16, 28), 1)
        small_computer(1, 14)
        small_computer(19, 14)

    @staticmethod
    def _paint_recycle_bin(image, full):
        """A wire waste basket (paper sticking out of it when full)"""
        body = [(6, 9), (26, 9), (23, 30), (9, 30)]
        pygame.draw.polygon(image, (200, 210, 205), body)
        # Ribs of the basket and its shadow side
        for x_top, x_bottom in ((10, 11), (14, 14), (18, 18), (22, 21)):
            pygame.draw.line(image, (120, 130, 128), (x_top, 11), (x_bottom, 29))
        pygame.draw.polygon(image, (150, 160, 158), [(22, 9), (26, 9), (23, 30), (20, 30)])
        pygame.draw.polygon(image, BLACK, body, 1)
        if full:
            # Crumpled paper over the rim
            paper, fold = WHITE, (170, 170, 170)
            for rect in (pygame.Rect(7, 3, 9, 8), pygame.Rect(14, 1, 10, 9),
                         pygame.Rect(19, 5, 7, 6)):
                pygame.draw.ellipse(image, paper, rect)
                pygame.draw.ellipse(image, fold, rect, 1)
            pygame.draw.line(image, fold, (17, 3), (20, 7))
            pygame.draw.line(image, fold, (9, 6), (12, 8))
        # Rim
        rim = pygame.Rect(5, 8, 22, 3)
        pygame.draw.rect(image, (225, 232, 230), rim)
        pygame.draw.rect(image, BLACK, rim, 1)
