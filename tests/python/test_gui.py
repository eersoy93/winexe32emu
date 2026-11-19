# Copyright 2026 Erdem Ersoy (eersoy93)
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

"""Smoke test of the fake desktop (PseudoWindowsGUI) without a display: SDL's
dummy video driver. It starts the GUI thread, feeds it mouse and keyboard
events (the Start menu, the desktop) and checks that it keeps running and
stops cleanly. Skipped without Pygame.

Run from the repository root:
    python3 -m unittest discover -s tests/python -v
"""

import os
import sys
import threading
import time
import unittest

os.environ.setdefault('SDL_VIDEODRIVER', 'dummy')
os.environ.setdefault('SDL_AUDIODRIVER', 'dummy')

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
from src.config import PYGAME_AVAILABLE  # noqa: E402
from src.logger import DebugLogger  # noqa: E402

if PYGAME_AVAILABLE:
    import pygame  # noqa: E402

    from src.gui import PseudoWindowsGUI  # noqa: E402


@unittest.skipUnless(PYGAME_AVAILABLE, "Pygame is not installed")
class FakeDesktopTest(unittest.TestCase):
    def setUp(self):
        self.errors = []
        self.previous_hook = threading.excepthook
        threading.excepthook = lambda info: self.errors.append(info.exc_value)
        self.previous_level = DebugLogger.level
        DebugLogger.level = DebugLogger.WARNING + 1

    def tearDown(self):
        threading.excepthook = self.previous_hook
        DebugLogger.level = self.previous_level

    def wait_frames(self, gui, seconds=0.3):
        time.sleep(seconds)
        self.assertTrue(gui.gui_thread.is_alive(), self.errors)

    def test_start_events_stop(self):
        gui = PseudoWindowsGUI(800, 600)
        self.assertTrue(gui.start())
        try:
            self.wait_frames(gui)
            start = gui._start_button_rect()
            events = [
                (pygame.MOUSEMOTION, {'pos': start.center, 'rel': (0, 0), 'buttons': (0, 0, 0)}),
                (pygame.MOUSEBUTTONDOWN, {'pos': start.center, 'button': 1}),
                (pygame.MOUSEBUTTONUP, {'pos': start.center, 'button': 1}),
            ]
            for kind, attributes in events:
                pygame.event.post(pygame.event.Event(kind, attributes))
            self.wait_frames(gui)
            self.assertTrue(gui.start_menu_open, "a click on Start opens the Start menu")
            # Close the Start menu: a click on the desktop, then a key
            for kind, attributes in (
                    (pygame.MOUSEBUTTONDOWN, {'pos': (400, 200), 'button': 1}),
                    (pygame.MOUSEBUTTONUP, {'pos': (400, 200), 'button': 1}),
                    (pygame.KEYDOWN, {'key': pygame.K_ESCAPE, 'mod': 0, 'unicode': '\x1b',
                                      'scancode': 41}),
                    (pygame.KEYUP, {'key': pygame.K_ESCAPE, 'mod': 0, 'unicode': '\x1b',
                                    'scancode': 41})):
                pygame.event.post(pygame.event.Event(kind, attributes))
            self.wait_frames(gui)
            self.assertFalse(gui.start_menu_open, "a click elsewhere closes it")
            self.assertTrue(gui.running)
        finally:
            gui.stop()
        self.assertFalse(gui.gui_thread.is_alive())
        self.assertEqual(self.errors, [])

    def test_long_messagebox_text_wraps(self):
        """A long message box line wraps like on Windows: the box stays
        narrower than the screen and shows the whole text"""
        gui = PseudoWindowsGUI(800, 600)
        self.assertTrue(gui.start())
        try:
            text = ("Setup couldn't create a SYSTEM.MDW file. After Setup is completed, "
                    "reboot your computer, then run the Workgroup Administrator before you "
                    "run this application.")
            gui.show_messagebox('Workgroup Administrator', text, 0x30)
            self.wait_frames(gui)
            with gui.lock:
                (hwnd,) = list(gui.messageboxes)
                win = gui.windows[hwnd]
                lines = [c.text for c in win.controls if c.class_name == 'STATIC']
            self.assertLess(win.width, 800 * 3 // 4)
            self.assertGreater(len(lines), 1)
            self.assertEqual(' '.join(lines), text)
        finally:
            gui.stop()
        self.assertEqual(self.errors, [])


if __name__ == '__main__':
    unittest.main()
