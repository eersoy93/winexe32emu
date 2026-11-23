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

"""The pseudo Windows GUI (desktop, taskbar, windows) with pygame.

PseudoWindowsGUI is made of mixins, one module each: the desktop, the Start menu, the
taskbar, window frames and controls, menus, input, message boxes and consoles.
This module holds its state, the GUI thread and the frame loop."""

import os
import threading
import queue
import warnings

from ..config import PYGAME_AVAILABLE, WINEXE32EMU_VERSION
from ..logger import log
from ..windows import _ProcessRouter

if PYGAME_AVAILABLE:
    import pygame

from .desktop import DesktopMixin
from .start_menu import StartMenuMixin
from .window_manager import WindowManagerMixin
from .taskbar import TaskbarMixin
from .window_drawing import WindowDrawingMixin
from .common_controls import CommonControlsMixin
from .menus import MenusMixin
from .control_drawing import ControlDrawingMixin
from .layout import LayoutMixin
from .display_list import DisplayListMixin
from .mouse import MouseMixin
from .keyboard import KeyboardMixin
from .messageboxes import MessageBoxesMixin
from .console import ConsoleMixin
from .font_cache import CachedFont


class PseudoWindowsGUI(DesktopMixin, StartMenuMixin, WindowManagerMixin, TaskbarMixin,
                       WindowDrawingMixin, CommonControlsMixin, MenusMixin, ControlDrawingMixin,
                       LayoutMixin, DisplayListMixin, MouseMixin, KeyboardMixin, MessageBoxesMixin,
                       ConsoleMixin):
    """Pygame-based fake Windows GUI environment"""

    # Windows colors
    COLOR_DESKTOP = (58, 110, 165)  # #3a6ea5, Windows 2000 blue
    COLOR_WINDOW_BG = (212, 208, 200)  # Classic Windows gray (COLOR_BTNFACE)
    COLOR_TITLE_BAR = (0, 0, 128)  # Classic blue
    COLOR_TITLE_BAR_INACTIVE = (128, 128, 128)
    # Right ends of the caption gradients (COLOR_GRADIENT[IN]ACTIVECAPTION)
    COLOR_TITLE_BAR_GRADIENT = (16, 132, 208)
    COLOR_TITLE_BAR_INACTIVE_GRADIENT = (192, 192, 192)
    COLOR_TITLE_TEXT = (255, 255, 255)
    COLOR_TITLE_TEXT_INACTIVE = (212, 208, 200)
    COLOR_BUTTON = (212, 208, 200)
    COLOR_BUTTON_BORDER_LIGHT = (255, 255, 255)
    COLOR_BUTTON_BORDER_DARK = (64, 64, 64)
    COLOR_BUTTON_SHADOW = (128, 128, 128)  # COLOR_BTNSHADOW, inner dark edge of 3D frames
    COLOR_TEXT = (0, 0, 0)
    COLOR_EDIT_BG = (255, 255, 255)
    COLOR_TASKBAR = (212, 208, 200)
    # Start menu side strip: a vertical gradient, dark at the bottom
    COLOR_START_STRIP_TOP = (16, 132, 208)
    COLOR_START_STRIP_BOTTOM = (0, 0, 96)

    # Resize settings
    RESIZE_BORDER = 6      # Edge grab margin (pixels)
    MIN_WINDOW_WIDTH = 120
    MIN_WINDOW_HEIGHT = 80

    # Window chrome geometry (client area origin = x+BORDER, y+BORDER+TITLE_BAR_H)
    BORDER = 3
    TITLE_BAR_H = 25
    MENU_H = 20  # Menu bar height (only when the window has a menu)
    LISTBOX_ITEM_H = 18  # Row height in LISTBOX and COMBOBOX dropdowns

    # Window styles deciding the frame of a top-level window
    WS_POPUP = 0x80000000
    WS_CAPTION = 0x00C00000
    WS_BORDER = 0x00800000
    WS_DLGFRAME = 0x00400000
    WS_THICKFRAME = 0x00040000
    DS_MODALFRAME = 0x80

    def __init__(self, width=1024, height=768):
        self.width = width
        self.height = height
        # Display mode set at startup (the registry mode); ChangeDisplaySettings
        # changes width/height, the GUI thread then resizes the screen
        self.desktop_width = width
        self.desktop_height = height
        self.pending_mode = None
        self.display_mode_owner = None  # Process that changed the display mode
        self.screen = None
        self.running = False
        self.clock = None
        # Running programs (WinAPIHandler each); winapi routes messages to them
        self.processes = []
        self.winapi = _ProcessRouter(self)

        # Window management
        self.windows = {}  # hwnd -> FakeWindow
        self.controls = {}  # hwnd -> FakeControl
        self.next_hwnd = 0x10000
        self.active_window = None
        self.notified_active = None  # Window last told it is active (WM_ACTIVATE)
        self.z_order = []  # Window ordering (topmost is at end)

        # Keyboard focus (EDIT controls)
        self.focused_control = None  # hwnd of the focused control

        # Open dropdown menu: (window_hwnd, top_level_item_index) or None
        self.open_menu = None

        # Open combobox dropdown: control hwnd or None
        self.open_combo = None
        self.combo_shown = None  # Open combo whose list was scrolled to its selection
        self.dragging_list_thumb = None  # (list or combo hwnd, grab offset) of a thumb drag

        # Open submenus of the open menu bar dropdown (item index per level),
        # popup menu of TrackPopupMenu (dict) and open ComboBoxEx list (hwnd)
        self.menu_path = []
        self.popup_menu = None
        self.open_native_combo = None
        # Focused child window (SetFocus on a list view etc.): gets the keys
        self.focused_window = None
        self._rgba_cache = {}

        # Start menu: open flag, rows (Programs: C:\ programs; Exit), and the callback that runs
        # a program (set by main)
        self.start_menu_open = False
        self.start_menu_rows = []
        self.start_open_path = []  # Row index of the open submenu at each level
        self.start_icon_paths = {}  # Windows path -> host path of the menu's programs
        self.launcher = None

        # Desktop icons (Windows paths of the C:\ programs) and the selected one
        self.desktop_icons = []
        self.desktop_icon_paths = {}  # Windows path -> host path
        # (host EXE path, size) -> (normal, selected) icon surfaces
        self.exe_icon_cache = {}
        self.selected_icon = None
        # Desktop right-click menu: (rect, [(label, action) or None], row rects) or None
        self.desktop_menu = None

        # Left clicks (ticks, pos, target) for double-click detection
        self.last_click = (0, (0, 0), None)
        self.prev_click = (0, (0, 0), None)

        # When the mouse started hovering the clock (date tooltip), or None
        self.tray_hover_since = None
        self._checker_cache = {}  # Pressed taskbar button face per size
        self._gradient_cache = {}  # (size, colors, horizontal) -> gradient surface

        # Keyboard state for GetAsyncKeyState (vk -> bool, GUI thread writes)
        self.key_states = {}
        # Left Alt held (WM_SYSKEY* messages) and whether another key was pressed
        # with it; the right Alt is AltGr (Ctrl+Alt), which types characters
        self.alt_down = False
        self.alt_combo = False
        self.alt_f4_seen = False  # F4 arrived as a key while Alt was held

        # Last mouse position for GetCursorPos (GUI thread writes)
        self.mouse_pos = (0, 0)

        # Font
        self.font = None
        self.font_small = None
        self.font_list = None
        self.font_bold = None
        self._font_cache = {}  # (face, size, bold, italic) -> pygame Font

        # Event queue
        self.event_queue = queue.Queue()
        self.message_queue = queue.Queue()

        # MessageBox queue
        self.messagebox_queue = queue.Queue()
        self.messageboxes = {}  # hwnd -> MessageBox state (buttons, request)
        # Guards windows/controls/z_order and display lists across threads
        self.lock = threading.RLock()
        self.messagebox_result = None

        # Thread
        self.gui_thread = None
        self.ready = threading.Event()  # Set once the GUI loop is running
        self.consoles_opened = 0  # Cascades the console windows

        # Console windows of the programs: hwnd -> FakeConsole
        self.consoles = {}
        self.font_console = None  # Monospace font
        self.console_cursor_visible = True  # Input cursor blinking
        self.console_cursor_timer = 0

        # Window dragging
        self.dragging_window = None  # Dragged window hwnd
        self.drag_offset_x = 0
        self.drag_offset_y = 0

        # Scrollbar thumb dragging: (control hwnd, grab offset in thumb) or None
        self.dragging_scrollbar = None

        # Window resizing
        self.resizing_window = None  # Resized window hwnd
        self.resize_edge = None      # Active edge: 'left','right','top','bottom' + corners
        self.resize_start_mouse = (0, 0)  # Mouse pos when resize began
        self.resize_start_rect = (0, 0, 0, 0)  # Window (x, y, w, h) when resize began
        self.current_cursor = None   # Shown cursor key (avoid redundant sets)
        self.cursor_cache = {}       # id(cursor dict) -> (cursor dict, pygame Cursor)

    def start(self):
        """Start GUI thread"""
        if not PYGAME_AVAILABLE:
            log.warning("Pygame not available, GUI could not start!")
            return False

        self.gui_thread = threading.Thread(target=self._gui_loop, daemon=True)
        self.gui_thread.start()

        # Wait until the screen exists; programs started next need it
        # (e.g. a console program opens its console window at once)
        self.ready.wait(timeout=30)
        return self.running

    def stop(self):
        """Stop GUI"""
        self.running = False
        if self.gui_thread:
            self.gui_thread.join(timeout=1.0)

    def _gui_loop(self):
        """Main GUI loop"""
        # A click that focuses the emulator's window is also passed to the program
        os.environ.setdefault('SDL_MOUSE_FOCUS_CLICKTHROUGH', '1')
        pygame.init()
        pygame.display.set_caption(
            f"Windows 32-bit EXE Emulator v{WINEXE32EMU_VERSION} - Fake Desktop")

        self.screen = pygame.display.set_mode((self.width, self.height), pygame.SCALED)
        self.clock = pygame.time.Clock()

        # Load fonts
        pygame.font.init()
        # The fonts keep the texts they rendered (CachedFont)
        self.font = CachedFont(pygame.font.SysFont('arial', 14))
        self.font_small = CachedFont(pygame.font.SysFont('arial', 11))
        self.font_small_bold = CachedFont(pygame.font.SysFont('arial', 11, bold=True))
        self.font_bold = CachedFont(pygame.font.SysFont('arial', 14, bold=True))
        self.font_console = CachedFont(pygame.font.SysFont('consolas,courier,monospace', 12))
        # List views use a font close to the 8 pt dialog font of Windows
        self.font_list = CachedFont(pygame.font.SysFont('arial', 12))

        self._refresh_desktop_icons()

        self.running = True
        self.ready.set()

        while self.running:
            # Window state is shared with the emulation thread
            with self.lock:
                if self.pending_mode is not None:
                    # Display surfaces belong to this thread (ChangeDisplaySettings)
                    self.screen = pygame.display.set_mode(self.pending_mode, pygame.SCALED)
                    self.pending_mode = None
                    self._focus_host_window()
                self._process_frame()
                self._update_mouse_cursor()
                self._post_size_changes()
                self._post_activation_changes()

            pygame.display.flip()
            self.clock.tick(60)

        pygame.quit()

    @staticmethod
    def _focus_host_window():
        """Give the emulator's own window the input focus again (a display mode
        change resizes it), so the first click already reaches the program"""
        try:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', DeprecationWarning)
                pygame.Window.from_display_module().focus()
        except (AttributeError, pygame.error):
            pass  # pygame without the Window API

    # pygame mouse button -> VK_LBUTTON, VK_MBUTTON, VK_RBUTTON (key_states)
    MOUSE_BUTTON_VKS = {1: 0x01, 2: 0x04, 3: 0x02}

    def _process_frame(self):
        """Handle pending input events and redraw the screen"""
        # Process Pygame events
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                if self.alt_down and not self.key_states.get(0x11):
                    # The host's window manager took Alt+F4 for the emulator's
                    # window: it is meant for the fake desktop's active window
                    if not self.alt_f4_seen:
                        self._alt_f4()
                else:
                    self.running = False
            elif event.type == pygame.MOUSEBUTTONDOWN:
                if event.button in self.MOUSE_BUTTON_VKS:
                    self.key_states[self.MOUSE_BUTTON_VKS[event.button]] = True
                self._handle_mouse_click(event.pos, event.button)
            elif event.type == pygame.MOUSEBUTTONUP:
                if event.button in self.MOUSE_BUTTON_VKS:
                    self.key_states[self.MOUSE_BUTTON_VKS[event.button]] = False
                # Release drag / resize; forward release to app if neither
                was_interacting = (self.dragging_window is not None or
                                   self.resizing_window is not None or
                                   self.dragging_scrollbar is not None or
                                   self.dragging_list_thumb is not None)
                if self.dragging_scrollbar is not None:
                    self._end_scrollbar_drag()
                self.dragging_list_thumb = None
                self.dragging_window = None
                self.resizing_window = None
                self.resize_edge = None
                if not was_interacting:
                    self._forward_mouse_up(event.pos, event.button)
            elif event.type == pygame.MOUSEMOTION:
                self.mouse_pos = event.pos
                # Scrollbar thumb dragging grabs the mouse first
                if self.dragging_scrollbar is not None:
                    self._drag_scrollbar_to(event.pos)
                elif self.dragging_list_thumb is not None:
                    self._drag_list_thumb_to(event.pos)
                # Window resizing (takes priority over dragging)
                elif self.resizing_window and self.resizing_window in self.windows:
                    self._resize_window_to(self.windows[self.resizing_window], event.pos)
                # Window dragging
                elif self.dragging_window and self.dragging_window in self.windows:
                    win = self.windows[self.dragging_window]
                    win.x = event.pos[0] - self.drag_offset_x
                    win.y = event.pos[1] - self.drag_offset_y
                    # Keep within screen boundaries
                    win.x = max(0, min(win.x, self.width - 50))
                    win.y = max(0, min(win.y, self.height - 60))
                else:
                    # Forward WM_MOUSEMOVE to the app window
                    self._forward_mouse_move(event.pos, event.buttons)
            elif event.type == pygame.KEYDOWN:
                vk = self._pygame_key_to_vk(event)
                if vk is not None:
                    self.key_states[vk] = True
                if event.key == pygame.K_LALT:
                    self.alt_down, self.alt_combo, self.alt_f4_seen = True, False, False
                elif self.alt_down:
                    self.alt_combo = True  # Alt+key: releasing Alt is a plain WM_KEYUP
                    if event.key == pygame.K_F4:
                        self.alt_f4_seen = True
                self._handle_key_press(event)
            elif event.type == pygame.KEYUP:
                vk = self._pygame_key_to_vk(event)
                if vk is not None:
                    self.key_states[vk] = False
                    self._forward_key_up(vk, event)
                if event.key == pygame.K_LALT:
                    self.alt_down = False

        # MessageBox check
        self._check_messagebox()

        # Cursor blinking (when a console waits for input)
        if any(c.input_active for c in self.consoles.values()):
            self.console_cursor_timer += 1
            if self.console_cursor_timer >= 30:  # ~0.5 seconds
                self.console_cursor_timer = 0
                self.console_cursor_visible = not self.console_cursor_visible

        # Draw screen
        self._draw()

    def _draw(self):
        """Draw screen"""
        # Desktop background
        self.screen.fill(self.COLOR_DESKTOP)
        self._draw_desktop_icons()

        # Taskbar
        self._draw_taskbar()

        # Draw windows (according to z-order)
        for hwnd in self.z_order:
            if hwnd in self.windows:
                if hwnd in self.consoles:
                    self._draw_console_window(self.windows[hwnd], self.consoles[hwnd])
                else:
                    self._draw_window(self.windows[hwnd])

        # Open dropdown menu is drawn over all windows
        self._draw_open_menu()

        # Open combobox dropdowns and popup menus are drawn over all windows too
        self._draw_open_combo()
        self._draw_open_native_combo()
        self._draw_popup_menu()

        # Desktop right-click menu, the Start menu and the clock tooltip are the topmost layers
        self._draw_desktop_menu()
        self._draw_start_menu()
        self._draw_clock_tooltip()
