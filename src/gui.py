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

"""The pseudo Windows GUI (desktop, taskbar, windows) with pygame"""

import os
import re
import threading
import queue
import time
import ntpath
import warnings

from . import winapi
from .config import FILE_MANAGER_PATH, PYGAME_AVAILABLE, WINEXE32EMU_VERSION
from .logger import log
from .paths import _program_subfolders, resolve_c_drive_path
from .resources import parse_shell_link, read_exe_icon, standard_cursor_image
from .windows import FakeConsole, FakeControl, FakeWindow, gui_locked, _ProcessRouter

if PYGAME_AVAILABLE:
    import pygame


class PseudoWindowsGUI:
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
        self.font = pygame.font.SysFont('arial', 14)
        self.font_small = pygame.font.SysFont('arial', 11)
        self.font_small_bold = pygame.font.SysFont('arial', 11, bold=True)
        self.font_bold = pygame.font.SysFont('arial', 14, bold=True)
        self.font_console = pygame.font.SysFont('consolas,courier,monospace', 12)
        # List views use a font close to the 8 pt dialog font of Windows
        self.font_list = pygame.font.SysFont('arial', 12)

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
                self._handle_mouse_click(event.pos, event.button)
            elif event.type == pygame.MOUSEBUTTONUP:
                # Release drag / resize; forward release to app if neither
                was_interacting = (self.dragging_window is not None or
                                   self.resizing_window is not None or
                                   self.dragging_scrollbar is not None)
                if self.dragging_scrollbar is not None:
                    self._end_scrollbar_drag()
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

    # ==================== DESKTOP ICONS ====================

    ICON_CELL_W = 76
    ICON_CELL_H = 72
    ICON_MARGIN = 6
    ICON_SIZE = 32
    DOUBLE_CLICK_MS = 500

    def _refresh_desktop_icons(self):
        """Read the desktop icons, (label, path or shortcut) pairs: My Computer
        (the file manager, if compiled), then the shortcuts and programs of the
        user's (C:\\Users\\User\\Desktop) and the public Desktop folders"""
        self.desktop_icons, self.desktop_icon_paths = [], {}
        if self._file_manager_available():
            self.desktop_icons.append((self._program_label(FILE_MANAGER_PATH), FILE_MANAGER_PATH))
            self.desktop_icon_paths[FILE_MANAGER_PATH] = resolve_c_drive_path(FILE_MANAGER_PATH)
        folders = [winapi.WinAPIHandler.SHELL_FOLDERS[0x10],   # CSIDL_DESKTOPDIRECTORY
                   winapi.WinAPIHandler.SHELL_FOLDERS[0x19]]   # CSIDL_COMMON_DESKTOPDIRECTORY
        for folder in folders:
            # Like on a real installation the Desktop folders exist, ready for shortcuts
            host = resolve_c_drive_path(folder)
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
        for i, ((name, data), rect) in enumerate(zip(self.desktop_icons,
                                                     self._desktop_icon_rects())):
            selected = (i == self.selected_icon)
            normal, tinted = self._exe_icon(self.desktop_icon_paths.get(data), self.ICON_SIZE)
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
        if isinstance(data, tuple):
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
            if index is not None:
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
        for item, rect in zip(items, rects):
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
        for item, rect in zip(items, rects):
            if item and button in (1, 3) and rect.collidepoint(pos):
                item[1]()
        return True

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
    def _file_manager_available():
        path = resolve_c_drive_path(FILE_MANAGER_PATH)
        return bool(path) and os.path.isfile(path)

    def _fill_start_menu(self):
        """Build the Start menu: Programs (the Start Menu folders of the user and
        of all users with their shortcuts, then My Computer, if compiled, in
        its own section) and Exit.
        Rows are ('program', label, path or shortcut), ('submenu', label, rows),
        ('exit', label, None), ('separator', None, None) or ('empty', label, None)"""
        self.start_icon_paths = {}
        shortcut_rows = self._shortcut_rows([winapi.WinAPIHandler.SHELL_FOLDERS[0x02],    # CSIDL_PROGRAMS
                                             winapi.WinAPIHandler.SHELL_FOLDERS[0x17]])  # COMMON_PROGRAMS
        rows = []
        if self._file_manager_available():
            rows = [('program', self._program_label(FILE_MANAGER_PATH), FILE_MANAGER_PATH)]
            self.start_icon_paths[FILE_MANAGER_PATH] = resolve_c_drive_path(FILE_MANAGER_PATH)
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
            host = resolve_c_drive_path(folder)
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
                        icon_paths[data] = resolve_c_drive_path(data[1])
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
        host = resolve_c_drive_path(target) if target else None
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
        if path.lower() == FILE_MANAGER_PATH.lower():
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
            for i, ((kind, label, data), rect) in enumerate(zip(rows, rects)):
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
                    icon = self._exe_icon(self.start_icon_paths.get(data), icon_size)[0]
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

    @gui_locked
    def register_process(self, process):
        """A program starts: its windows get input from now on"""
        self.processes.append(process)

    @gui_locked
    def unregister_process(self, process):
        """A program ended: close its windows; its console stays to show the output"""
        if process in self.processes:
            self.processes.remove(process)
        if self.display_mode_owner is process:
            # Like Windows, a CDS_FULLSCREEN mode ends with its program
            self.set_display_mode(self.desktop_width, self.desktop_height)
        # Its message boxes go too (one shown by a thread when another one ends
        # the program, e.g. the main window closed while the box is up)
        for hwnd, box in list(self.messageboxes.items()):
            if box.get('process') is process:
                self._messagebox_done(hwnd, box['cancel'] or box['buttons'][box['focus']].mb_result)
        for hwnd, win in list(self.windows.items()):
            if win.owner is not process:
                continue
            console = self.consoles.get(hwnd)
            if console is None:
                self._remove_window(hwnd)
                continue
            self.cancel_console_input(console)
            win.owner = None
            win.title += " [finished]"

    def window_owner(self, hwnd):
        """Process (WinAPIHandler) owning a window or control, or None"""
        win = self.windows.get(hwnd)
        if win is None:
            control = self.controls.get(hwnd)
            win = self.windows.get(control.parent_hwnd) if control else None
        return win.owner if win else None

    @gui_locked
    def _remove_window(self, hwnd):
        """Delete a window, its child windows and its controls, dropping every
        reference to them"""
        win = self.windows.pop(hwnd, None)
        if win is None:
            return
        for child in list(win.children):
            self._remove_window(child)
        parent = self.windows.get(win.parent)
        if parent is not None and hwnd in parent.children:
            parent.children.remove(hwnd)
        if self.focused_window == hwnd:
            self.focused_window = None
        if self.open_native_combo == hwnd:
            self.open_native_combo = None
        for chwnd in [h for h, c in self.controls.items() if c.parent_hwnd == hwnd]:
            del self.controls[chwnd]
            if self.focused_control == chwnd:
                self.focused_control = None
            if self.open_combo == chwnd:
                self.open_combo = None
            if self.dragging_scrollbar and self.dragging_scrollbar[0] == chwnd:
                self.dragging_scrollbar = None
        if hwnd in self.z_order:
            self.z_order.remove(hwnd)
        if self.active_window == hwnd:
            self.active_window = self.z_order[-1] if self.z_order else None
        if self.open_menu and self.open_menu[0] == hwnd:
            self.open_menu = None
        if self.dragging_window == hwnd:
            self.dragging_window = None
        if self.resizing_window == hwnd:
            self.resizing_window = None
    
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
        self.screen.blit(text_surface, (text_x,
                                        rect.y + (rect.height - text_surface.get_height()) // 2 + offset))

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
    
    def _draw_window_frame(self, window, border):
        """Soft shadow, face and the classic raised frame of a top-level window
        (a 1-pixel border is a plain dark line)"""
        frame_rect = pygame.Rect(window.x, window.y, window.width, window.height)
        if not window.maximized:
            self._draw_shadow(frame_rect)
        pygame.draw.rect(self.screen, self.COLOR_WINDOW_BG, frame_rect)
        if border > 1:
            self._draw_raised(frame_rect)
        else:
            pygame.draw.rect(self.screen, self.COLOR_BUTTON_BORDER_DARK, frame_rect, 1)

    def _draw_window(self, window):
        """Draw window"""
        if not window.visible or window.minimized:
            return
        
        is_active = (window.hwnd == self.active_window)
        border, caption = self.window_frame(window)

        if border:
            self._draw_window_frame(window, border)

        if caption:
            self._draw_title_bar(window, is_active)

        # Menu bar (between title bar and client area)
        if window.menu:
            self._draw_menu_bar(window)

        # Content area
        client_x, client_y = self.client_origin(window)
        client_w, client_h = self.client_size(window)
        content_rect = pygame.Rect(client_x, client_y, client_w, client_h)
        pygame.draw.rect(self.screen, window.bg_color, content_rect)

        # Clip client-area drawing to the window (GDI shapes may overflow)
        self.screen.set_clip(content_rect)

        # Render GDI shapes and texts (Rectangle, Ellipse, TextOut, ...)
        for shape in window.drawn_shapes:
            self._draw_shape(shape, client_x, client_y)

        if getattr(window, 'messagebox_icon', 0):
            self._draw_messagebox_icon(window.messagebox_icon, client_x + 20, client_y + 18)

        # Draw controls
        for control in window.controls:
            self._draw_control(control, client_x, client_y)

        self._draw_child_windows(window)

        self.screen.set_clip(None)

    CAPTION_BTN_W = 18
    CAPTION_BTN_H = 16

    def _title_rect(self, window):
        """Screen rect of a window's title bar (inside the frame, a 1-pixel gap
        above the menu bar or the client area)"""
        border, caption = (self.BORDER, self.TITLE_BAR_H) if window.hwnd in self.consoles \
            else self.window_frame(window)
        return pygame.Rect(window.x + border, window.y + border,
                           window.width - 2 * border, caption - 1)

    def _caption_button_rects(self, window):
        """{'close' / 'max' / 'min': screen rect} of a window's caption buttons;
        dialogs only have the close button. Drawing and clicks both use these."""
        bar = self._title_rect(window)
        w, h = self.CAPTION_BTN_W, self.CAPTION_BTN_H
        y = bar.y + (bar.height - h) // 2
        close = pygame.Rect(bar.right - 2 - w, y, w, h)
        rects = {'close': close}
        if not window.is_dialog:
            # Maximize and minimize sit together, two pixels left of close
            rects['max'] = pygame.Rect(close.x - 2 - w, y, w, h)
            rects['min'] = pygame.Rect(close.x - 2 - 2 * w, y, w, h)
        return rects

    def _draw_title_bar(self, window, is_active):
        """Draw a window's caption: a gradient bar, the program icon, the title
        and the caption buttons"""
        bar = self._title_rect(window)
        if is_active:
            colors = (self.COLOR_TITLE_BAR, self.COLOR_TITLE_BAR_GRADIENT)
            text_color = self.COLOR_TITLE_TEXT
        else:
            colors = (self.COLOR_TITLE_BAR_INACTIVE, self.COLOR_TITLE_BAR_INACTIVE_GRADIENT)
            text_color = self.COLOR_TITLE_TEXT_INACTIVE
        self.screen.blit(self._gradient(bar.size, *colors), bar.topleft)

        buttons = self._caption_button_rects(window)

        # Program icon (not on dialogs), then the title cut with "..." before the caption buttons
        text_x = self._draw_caption_icon(window)
        max_title_w = min(r.x for r in buttons.values()) - 4 - text_x
        title = self._fit_text(self.font_bold, window.title, max_title_w)
        title_text = self.font_bold.render(title, True, text_color)
        self.screen.blit(title_text, (text_x, bar.centery - title_text.get_height() // 2))

        self._draw_window_button(buttons['close'], "×", "close")
        if 'max' in buttons:
            self._draw_window_button(buttons['max'], "❐" if window.maximized else "□", "max")
            self._draw_window_button(buttons['min'], "─", "min")

    CAPTION_ICON_SIZE = 16

    def _draw_caption_icon(self, window):
        """Draw the small program icon at the left of a title bar (dialogs have
        none); returns the x where the title text starts"""
        bar = self._title_rect(window)
        if window.is_dialog:
            return bar.x + 4
        icon = self._exe_icon(window.icon_path, self.CAPTION_ICON_SIZE)[0]
        self.screen.blit(icon, (bar.x + 2, bar.centery - self.CAPTION_ICON_SIZE // 2))
        return bar.x + 2 + self.CAPTION_ICON_SIZE + 4

    def _draw_shape(self, shape, ox, oy, target=None):
        """Render one GDI display list entry at client origin (ox, oy) on target
        (default: the screen)"""
        screen = self.screen if target is None else target
        stype = shape['type']

        if stype == 'line':
            color, width = shape['pen']
            x1, y1 = shape['from']
            x2, y2 = shape['to']
            pygame.draw.line(screen, color, (ox + x1, oy + y1), (ox + x2, oy + y2), width)

        elif stype in ('rect', 'ellipse'):
            left, top, right, bottom = shape['rect']
            rect = pygame.Rect(ox + left, oy + top, right - left, bottom - top)
            draw_func = pygame.draw.rect if stype == 'rect' else pygame.draw.ellipse
            if shape.get('fill') is not None:
                draw_func(screen, shape['fill'], rect)
            if shape.get('pen') is not None:
                color, width = shape['pen']
                draw_func(screen, color, rect, width)

        elif stype == 'roundrect':
            left, top, right, bottom = shape['rect']
            rect = pygame.Rect(ox + left, oy + top, right - left, bottom - top)
            radius = shape.get('radius', 0)
            if shape.get('fill') is not None:
                pygame.draw.rect(screen, shape['fill'], rect, border_radius=radius)
            if shape.get('pen') is not None:
                color, width = shape['pen']
                pygame.draw.rect(screen, color, rect, width, border_radius=radius)

        elif stype == 'polygon':
            points = [(ox + x, oy + y) for x, y in shape['points']]
            if len(points) >= 3:
                if shape.get('fill') is not None:
                    pygame.draw.polygon(screen, shape['fill'], points)
                if shape.get('pen') is not None:
                    color, width = shape['pen']
                    pygame.draw.polygon(screen, color, points, width)

        elif stype == 'polyline':
            points = [(ox + x, oy + y) for x, y in shape['points']]
            if len(points) >= 2 and shape.get('pen') is not None:
                color, width = shape['pen']
                pygame.draw.lines(screen, color, False, points, width)

        elif stype == 'arc':
            left, top, right, bottom = shape['rect']
            rect = pygame.Rect(ox + left, oy + top, right - left, bottom - top)
            if shape.get('pen') is not None:
                color, width = shape['pen']
                pygame.draw.arc(screen, color, rect,
                                shape['start'], shape['end'], width)

        elif stype == 'text':
            x, y = shape['pos']
            font = self._get_render_font(shape.get('font'))
            surface = font.render(shape['text'], True, shape.get('color') or self.COLOR_TEXT,
                                  shape.get('bk'))
            screen.blit(surface, (ox + x, oy + y))
            if shape.get('font') and shape['font'].get('underline'):
                line_y = oy + y + surface.get_height() - 2
                pygame.draw.line(screen, shape.get('color') or self.COLOR_TEXT,
                                 (ox + x, line_y), (ox + x + surface.get_width(), line_y))

        elif stype == 'pixel':
            x, y = shape['pos']
            rect = pygame.Rect(ox + x, oy + y, 1, 1)
            pygame.draw.rect(screen, shape['color'], rect)

        elif stype == 'image':
            x, y = shape['pos']
            if shape['size'][0] > 0 and shape['size'][1] > 0:
                screen.blit(self._image_surface(shape), (ox + x, oy + y))

    def _image_surface(self, shape):
        """Pygame surface of an image shape, cached in the shape.

        Raster operations are approximated with transparency: SRCAND leaves
        white pixels out (mask), SRCPAINT/SRCINVERT leave black pixels out.
        """
        rop = shape.get('rop')
        key = (shape['size'], rop)
        cached = shape.get('_surface')
        if cached and cached[0] == key:
            return cached[1]
        data = shape['data']
        if rop == winapi.WinAPIHandler.NOTSRCCOPY:
            data = bytes(255 - b for b in data)
        from_bytes = getattr(pygame.image, 'frombytes', None) or pygame.image.fromstring
        surface = from_bytes(data, shape['dim'], 'RGB')
        if shape['size'] != shape['dim']:
            surface = pygame.transform.scale(surface, shape['size'])
        if rop == winapi.WinAPIHandler.SRCAND:
            surface.set_colorkey((255, 255, 255))
        elif rop in (winapi.WinAPIHandler.SRCPAINT, winapi.WinAPIHandler.SRCINVERT):
            surface.set_colorkey((0, 0, 0))
        shape['_surface'] = (key, surface)
        return surface

    # Free fonts with the metrics of the common Windows fonts
    METRIC_FONTS = {'arial': 'liberationsans', 'helvetica': 'liberationsans',
                    'times new roman': 'liberationserif', 'times': 'liberationserif',
                    'courier new': 'liberationmono', 'courier': 'liberationmono'}

    def _get_render_font(self, font_dict):
        """Pygame font for a GDI font dict (cached); None -> default GUI font.
        A positive GDI height is the cell height (ascent + descent), a negative
        one the character height, which is the pygame size."""
        if not font_dict:
            return self.font
        height = font_dict.get('height', 13)
        cell = font_dict.get('cell', True)
        face = (font_dict.get('face') or 'arial').lower()
        bold = font_dict.get('bold', False)
        italic = font_dict.get('italic', False)
        key = (face, height, cell, bold, italic)
        if key not in self._font_cache:
            # The face itself if installed, else a free font with its metrics
            installed = face.replace(' ', '') in pygame.font.get_fonts()
            alias = self.METRIC_FONTS.get(face, 'liberationsans')
            names = f"{face},{alias},arial" if installed else f"{alias},{face},arial"
            font = pygame.font.SysFont(names, height, bold=bold, italic=italic)
            if cell and font.get_height() > height:
                size = max(6, round(height * height / font.get_height()))
                font = pygame.font.SysFont(names, size, bold=bold, italic=italic)
            self._font_cache[key] = font
        return self._font_cache[key]

    def _draw_menu_bar(self, window):
        """Draw a window's menu bar and highlight the open item"""
        bar = self._menu_bar_rect(window)
        pygame.draw.rect(self.screen, self.COLOR_WINDOW_BG, bar)
        pygame.draw.line(self.screen, (128, 128, 128),
                         (bar.x, bar.bottom - 1), (bar.right - 1, bar.bottom - 1))

        item_rects = self._menu_item_rects(window)
        for i, (item, rect) in enumerate(zip(window.menu, item_rects)):
            is_open = (self.open_menu == (window.hwnd, i))
            if is_open:
                pygame.draw.rect(self.screen, self.COLOR_TITLE_BAR, rect)
            color = self.COLOR_TITLE_TEXT if is_open else self.COLOR_TEXT
            text = self.font.render(item['text'], True, color)
            self.screen.blit(text, (rect.x + 8, rect.y + (rect.height - text.get_height()) // 2))

    def _draw_open_menu(self):
        """Draw the open dropdown menu (and its open submenus) on top of everything"""
        root = self._menu_root()
        if root is None:
            self.open_menu = None
            return
        items, x, y, win = root
        panels = self._menu_panels(items, x, y, self.menu_path)
        self._menu_hover(panels, self.menu_path,
                         lambda hmenu, index: self._post_init_menu(win, hmenu, index))
        self._draw_menu_panels(self._menu_panels(items, x, y, self.menu_path))
    
    def _combo_dropdown_rects(self, control):
        """Dropdown rect and item rects of an open combobox (screen coords)."""
        win = self.windows.get(control.parent_hwnd)
        if not win or not win.visible or win.minimized:
            return None, []
        ox, oy = self.client_origin(win)
        box_h = min(control.height, 24)
        item_h = self.LISTBOX_ITEM_H
        count = max(1, len(control.items))
        drop = pygame.Rect(ox + control.x, oy + control.y + box_h,
                           control.width, count * item_h + 2)
        rects = [pygame.Rect(drop.x + 1, drop.y + 1 + i * item_h,
                             drop.width - 2, item_h)
                 for i in range(len(control.items))]
        return drop, rects

    def _draw_open_combo(self):
        """Draw the open combobox dropdown on top of everything"""
        if not self.open_combo:
            return
        control = self.controls.get(self.open_combo)
        if not control or not control.visible:
            self.open_combo = None
            return

        drop, item_rects = self._combo_dropdown_rects(control)
        if drop is None:
            self.open_combo = None
            return

        shadow = pygame.Rect(drop.x + 3, drop.y + 3, drop.width, drop.height)
        pygame.draw.rect(self.screen, (64, 64, 64), shadow)
        pygame.draw.rect(self.screen, self.COLOR_EDIT_BG, drop)
        pygame.draw.rect(self.screen, (128, 128, 128), drop, 1)

        mouse_pos = pygame.mouse.get_pos()
        for i, (item, rect) in enumerate(zip(control.items, item_rects)):
            hovered = rect.collidepoint(mouse_pos)
            selected = (i == control.sel_index)
            if hovered or selected:
                pygame.draw.rect(self.screen, self.COLOR_TITLE_BAR, rect)
            color = self.COLOR_TITLE_TEXT if (hovered or selected) else self.COLOR_TEXT
            text = self.font.render(item, True, color)
            self.screen.blit(text, (rect.x + 3, rect.y + 1))

    # ==================== EMULATED COMMON CONTROLS ====================

    def child_at(self, hwnd, x, y):
        """Deepest visible child window of hwnd at screen point (x, y) (hwnd itself
        if no child is there)"""
        win = self.windows.get(hwnd)
        if win is None:
            return hwnd
        for child in reversed(win.children):
            c = self.windows.get(child)
            if c is None or not c.visible:
                continue
            cx, cy = self.client_origin(c)
            border = self._child_border(c)
            if cx - border <= x < cx - border + c.width and cy - border <= y < cy - border + c.height:
                return self.child_at(child, x, y)
        return hwnd

    def top_level_of(self, hwnd):
        """Top-level window that contains a window or control"""
        control = self.controls.get(hwnd)
        if control is not None:
            hwnd = control.parent_hwnd
        seen = 0
        while hwnd in self.windows and self.windows[hwnd].parent and seen < 64:
            hwnd = self.windows[hwnd].parent
            seen += 1
        return hwnd

    @gui_locked
    def reparent(self, hwnd, new_parent):
        """Move a child window or control into another parent window"""
        if new_parent not in self.windows:
            return
        control = self.controls.get(hwnd)
        if control is not None:
            old = self.windows.get(control.parent_hwnd)
            if old is not None:
                old.controls = [c for c in old.controls if c.hwnd != hwnd]
            control.parent_hwnd = new_parent
            self.windows[new_parent].controls.append(control)
            return
        win = self.windows.get(hwnd)
        if win is None:
            return
        old = self.windows.get(win.parent)
        if old is not None and hwnd in old.children:
            old.children.remove(hwnd)
        if hwnd in self.z_order:
            self.z_order.remove(hwnd)
        win.parent = new_parent
        self.windows[new_parent].children.append(hwnd)

    SYS_ICON_COLORS = {0: ((255, 255, 255), (96, 96, 96)), 1: ((240, 200, 80), (150, 110, 20)),
                       2: ((200, 200, 200), (80, 80, 80)), 3: ((120, 170, 230), (40, 70, 140)),
                       4: ((210, 225, 255), (40, 60, 140))}

    def _draw_system_icon(self, index, x, y, size=16):
        """Draw one of the fake system image list icons"""
        fill, line = self.SYS_ICON_COLORS.get(index, self.SYS_ICON_COLORS[0])
        s = size / 16
        if index == 1:  # Folder
            pygame.draw.rect(self.screen, fill, (x + 1 * s, y + 4 * s, 14 * s, 10 * s))
            pygame.draw.rect(self.screen, fill, (x + 1 * s, y + 2 * s, 6 * s, 3 * s))
            pygame.draw.rect(self.screen, line, (x + 1 * s, y + 4 * s, 14 * s, 10 * s), 1)
        elif index == 2:  # Drive
            pygame.draw.rect(self.screen, fill, (x + 1 * s, y + 5 * s, 14 * s, 7 * s))
            pygame.draw.rect(self.screen, line, (x + 1 * s, y + 5 * s, 14 * s, 7 * s), 1)
            pygame.draw.rect(self.screen, (0, 160, 0), (x + 11 * s, y + 9 * s, 2 * s, 2 * s))
        else:  # Document (archive: with a band, program: window)
            pygame.draw.rect(self.screen, fill, (x + 3 * s, y + 1 * s, 10 * s, 14 * s))
            pygame.draw.rect(self.screen, line, (x + 3 * s, y + 1 * s, 10 * s, 14 * s), 1)
            if index == 3:
                pygame.draw.rect(self.screen, (60, 60, 160), (x + 7 * s, y + 1 * s, 2 * s, 14 * s))
                pygame.draw.rect(self.screen, (220, 180, 40), (x + 6 * s, y + 7 * s, 4 * s, 3 * s))
            elif index == 4:
                pygame.draw.rect(self.screen, (0, 0, 128), (x + 3 * s, y + 1 * s, 10 * s, 3 * s))

    def _image_surface_rgba(self, image):
        """pygame Surface of an image list entry (w, h, rgba bytes), cached"""
        key = id(image)
        cached = self._rgba_cache.get(key)
        if cached is not None and cached[0] is image:
            return cached[1]
        width, height, rgba = image
        surface = pygame.image.frombuffer(rgba, (width, height), 'RGBA').convert_alpha()
        if len(self._rgba_cache) > 256:
            self._rgba_cache.clear()
        self._rgba_cache[key] = (image, surface)
        return surface

    def _draw_imagelist_image(self, owner, himl, index, x, y, disabled=False):
        """Draw image index of an image list; False if there is none"""
        imagelist = owner.imagelists.get(himl) if owner is not None else None
        if imagelist is None or not 0 <= index < len(imagelist['images']):
            return False
        image = imagelist['images'][index]
        if image is None:
            return False
        if image[0] == 'system':
            self._draw_system_icon(image[1], x, y, imagelist['cx'])
            return True
        surface = self._image_surface_rgba(image)
        if disabled:
            surface = surface.copy()
            surface.set_alpha(90)
        self.screen.blit(surface, (x, y))
        return True

    def _draw_native(self, win, cx, cy, cw, ch):
        """Draw an emulated common control's client area"""
        if win.native == 'LISTVIEW':
            self._draw_listview(win, cx, cy, cw, ch)
        elif win.native == 'TOOLBAR':
            self._draw_toolbar(win, cx, cy, cw, ch)
        elif win.native == 'REBAR':
            pygame.draw.rect(self.screen, self.COLOR_WINDOW_BG, (cx, cy, cw, ch))
            for band in win.nstate['bands']:
                rect = band.get('rect')
                if rect and rect[0] > 0:
                    pygame.draw.line(self.screen, (128, 128, 128), (cx + rect[0] - 1, cy + 1),
                                     (cx + rect[0] - 1, cy + ch - 2))
                    pygame.draw.line(self.screen, (255, 255, 255), (cx + rect[0], cy + 1),
                                     (cx + rect[0], cy + ch - 2))
        elif win.native == 'COMBOBOXEX':
            st = win.nstate
            pygame.draw.rect(self.screen, self.COLOR_EDIT_BG, (cx, cy, cw, ch))
            pygame.draw.rect(self.screen, (128, 128, 128), (cx, cy, cw, ch), 1)
            image = st.get('image', -1)
            if image is not None and image >= 0:
                self._draw_imagelist_image(win.owner, st['imagelist'], image, cx + 3,
                                           cy + (ch - 16) // 2)
            button = pygame.Rect(cx + cw - 18, cy + 2, 16, ch - 4)
            self._draw_button_3d(button, '', pressed=st.get('dropped', False))
            self._draw_arrow(button, 'down')

    def _draw_listview(self, win, cx, cy, cw, ch):
        gui_font = self.font
        self.font = self.font_list or self.font
        try:
            self._draw_listview_body(win, cx, cy, cw, ch)
        finally:
            self.font = gui_font

    def _draw_listview_body(self, win, cx, cy, cw, ch):
        st = win.nstate
        owner = win.owner
        report = (win.style & 0x3) == 1
        if not report and owner is not None:
            self._draw_listview_grid(win, cx, cy, cw, ch)
            return
        header_h = owner.lv_header_height(win) if owner else 0
        row_h = winapi.WinAPIHandler.LV_ROW_H
        columns = sorted(st['columns'], key=lambda c: c.get('order', 0)) if report else []
        if not columns:
            columns = [{'sub': 0, 'width': cw, 'fmt': 0, 'text': ''}]
        focused = self.focused_window == win.hwnd and self.top_level_of(win.hwnd) == \
            self.active_window
        himl = st['imagelists'].get(1) or st['imagelists'].get(0)
        items = st['items']
        rows = max(1, (ch - header_h) // row_h)
        scrollbar = len(items) > rows
        text_w = cw - (16 if scrollbar else 0)
        clip = self.screen.get_clip()
        x0 = cx - st['hscroll']
        if header_h:
            x = x0
            for column in columns:
                rect = pygame.Rect(x, cy, column['width'], header_h)
                self._draw_button_3d(rect, '')
                label = self._fit_text(self.font, column.get('text', ''), max(0, column['width'] - 12))
                surface = self.font.render(label, True, self.COLOR_TEXT)
                align = column['fmt'] & 0x3
                tx = x + 5 if align == 0 else (x + column['width'] - surface.get_width() - 6
                                               if align == 1 else
                                               x + (column['width'] - surface.get_width()) // 2)
                self.screen.blit(surface, (tx, cy + (header_h - surface.get_height()) // 2))
                hdfmt = column.get('hdfmt', 0)
                if hdfmt & 0x600:  # HDF_SORTUP / HDF_SORTDOWN
                    ax = x + column['width'] - 12
                    up = hdfmt & 0x400
                    pts = [(ax, cy + 12), (ax + 6, cy + 12), (ax + 3, cy + 7)] if up else \
                        [(ax, cy + 8), (ax + 6, cy + 8), (ax + 3, cy + 13)]
                    pygame.draw.polygon(self.screen, (96, 96, 96), pts)
                x += column['width']
            if x < cx + cw:
                self._draw_button_3d(pygame.Rect(x, cy, cx + cw - x, header_h), '')
        body = pygame.Rect(cx, cy + header_h, text_w, ch - header_h)
        self.screen.set_clip(body.clip(clip) if clip else body)
        for row in range(rows + 1):
            index = st['top'] + row
            if index >= len(items):
                break
            item = items[index]
            y = cy + header_h + row * row_h
            selected = item['state'] & 0x2
            if selected:
                color = self.COLOR_TITLE_BAR if focused else (192, 192, 192)
                sel_w = (sum(c['width'] for c in columns) if report and st['ex_style'] & 0x20
                         else columns[0]['width'] if report else text_w)
                pygame.draw.rect(self.screen, color, (x0, y, sel_w, row_h))
            x = x0
            for n, column in enumerate(columns):
                sub = column['sub']
                text = item['cache'].get(sub)
                if text is None:
                    text = item['texts'].get(sub) or ''
                tx = x + 4
                if sub == 0:
                    image = item.get('cache_image', item['image'])
                    if image is not None and image >= 0 and himl:
                        self._draw_imagelist_image(owner, himl, image, x + 2, y + 1)
                    # No small image list: no icon space (like comctl32)
                    tx = x + 2 + (owner.lv_icon_space(win) if owner else 20)
                width = column['width'] - (tx - x) - 4
                if width > 0 and text:
                    label = self._fit_text(self.font, text, width)
                    surface = self.font.render(label, True, (255, 255, 255) if selected and
                                               focused and (n == 0 or st['ex_style'] & 0x20)
                                               else self.COLOR_TEXT)
                    if column['fmt'] & 0x3 == 1:
                        tx = x + column['width'] - surface.get_width() - 6
                    self.screen.blit(surface, (tx, y + (row_h - surface.get_height()) // 2))
                x += column['width']
            if index == st['focus'] and focused:
                width = columns[0]['width'] if report else text_w
                pygame.draw.rect(self.screen, (128, 128, 128), (x0, y, width, row_h), 1)
        if report and st['ex_style'] & 0x1:  # LVS_EX_GRIDLINES
            # Row lines down the whole body (below the items too), column
            # lines at the columns' right edges
            grid = self.COLOR_BUTTON
            for row in range(1, rows + 2):
                y = cy + header_h + row * row_h - 1
                pygame.draw.line(self.screen, grid, (body.left, y), (body.right - 1, y))
            x = x0
            for column in columns:
                x += column['width']
                if body.left <= x - 1 < body.right:
                    pygame.draw.line(self.screen, grid, (x - 1, body.top), (x - 1, body.bottom - 1))
        self.screen.set_clip(clip)
        if scrollbar:
            bar = pygame.Rect(cx + cw - 16, cy + header_h, 16, ch - header_h)
            pygame.draw.rect(self.screen, (230, 228, 222), bar)
            up = pygame.Rect(bar.x, bar.y, 16, 16)
            down = pygame.Rect(bar.x, bar.bottom - 16, 16, 16)
            self._draw_button_3d(up, '')
            self._draw_arrow(up, 'up')
            self._draw_button_3d(down, '')
            self._draw_arrow(down, 'down')
            track = bar.height - 32
            if track > 8:
                thumb_h = max(10, track * rows // max(1, len(items)))
                thumb_y = bar.y + 16 + (track - thumb_h) * st['top'] // max(1, len(items) - rows)
                self._draw_button_3d(pygame.Rect(bar.x, thumb_y, 16, thumb_h), '')

    def _draw_listview_grid(self, win, cx, cy, cw, ch):
        """Icon, small icon and list views: items in cells laid out by the
        owner's lv_grid (rows of cells, or columns for the list view)"""
        st = win.nstate
        owner = win.owner
        icons = (win.style & 0x3) == 0
        cell_w, cell_h, per_line, lines, column_major = owner.lv_grid(win)
        focused = self.focused_window == win.hwnd and self.top_level_of(win.hwnd) == \
            self.active_window
        himl = (st['imagelists'].get(0) or st['imagelists'].get(1)) if icons else \
            (st['imagelists'].get(1) or st['imagelists'].get(0))
        items = st['items']
        clip = self.screen.get_clip()
        body = pygame.Rect(cx, cy, cw, ch)
        self.screen.set_clip(body.clip(clip) if clip else body)
        page = per_line * (lines + 1)
        for index in range(st['top'], min(len(items), st['top'] + page)):
            item = items[index]
            left, top, right, bottom = owner.lv_item_rect(win, index)
            x, y = cx + left, cy + top
            selected = item['state'] & 0x2
            text = item['cache'].get(0)
            if text is None:
                text = item['texts'].get(0) or ''
            image = item.get('cache_image', item['image'])
            text_color = (255, 255, 255) if selected and focused else self.COLOR_TEXT
            select_color = self.COLOR_TITLE_BAR if focused else (192, 192, 192)
            if icons:
                if image is not None and image >= 0 and himl:
                    self._draw_imagelist_image(owner, himl, image, x + (cell_w - 32) // 2, y + 2)
                lines_text = self._wrap_text(text, cell_w - 4)[:2]
                if len(self._wrap_text(text, cell_w - 4)) > 2:
                    lines_text[1] = self._fit_text(self.font, lines_text[1] + '...', cell_w - 4)
                label_h = len(lines_text) * self.font.get_linesize()
                label_w = max([self.font.size(line)[0] for line in lines_text] + [8])
                label = pygame.Rect(x + (cell_w - label_w) // 2 - 2, y + 37, label_w + 4, label_h)
                if selected:
                    pygame.draw.rect(self.screen, select_color, label)
                for n, line in enumerate(lines_text):
                    surface = self.font.render(line, True, text_color)
                    self.screen.blit(surface, (x + (cell_w - surface.get_width()) // 2,
                                               label.y + n * self.font.get_linesize()))
                if index == st['focus'] and focused:
                    pygame.draw.rect(self.screen, (128, 128, 128), label, 1)
                continue
            if image is not None and image >= 0 and himl:
                self._draw_imagelist_image(owner, himl, image, x + 2, y + 1)
            icon = owner.lv_icon_space(win)
            label_text = self._fit_text(self.font, text, max(0, cell_w - icon - 6))
            surface = self.font.render(label_text, True, text_color)
            label = pygame.Rect(x + icon, y, surface.get_width() + 4, cell_h)
            if selected:
                pygame.draw.rect(self.screen, select_color, label)
            self.screen.blit(surface, (label.x + 2, y + (cell_h - surface.get_height()) // 2))
            if index == st['focus'] and focused:
                pygame.draw.rect(self.screen, (128, 128, 128), label, 1)
        self.screen.set_clip(clip)
        lines_total = (len(items) + per_line - 1) // per_line
        if lines_total <= lines:
            return
        # Scroll bar: horizontal for the list view's columns, vertical otherwise
        first_line = st['top'] // per_line
        if column_major:
            bar = pygame.Rect(cx, cy + ch - 16, cw, 16)
            pygame.draw.rect(self.screen, (230, 228, 222), bar)
            for rect, arrow in ((pygame.Rect(bar.x, bar.y, 16, 16), 'left'),
                                (pygame.Rect(bar.right - 16, bar.y, 16, 16), 'right')):
                self._draw_button_3d(rect, '')
                self._draw_arrow(rect, arrow)
            track = bar.width - 32
            if track > 8:
                thumb_w = max(10, track * lines // lines_total)
                thumb_x = bar.x + 16 + (track - thumb_w) * first_line // max(1, lines_total - lines)
                self._draw_button_3d(pygame.Rect(thumb_x, bar.y, thumb_w, 16), '')
        else:
            bar = pygame.Rect(cx + cw - 16, cy, 16, ch)
            pygame.draw.rect(self.screen, (230, 228, 222), bar)
            for rect, arrow in ((pygame.Rect(bar.x, bar.y, 16, 16), 'up'),
                                (pygame.Rect(bar.x, bar.bottom - 16, 16, 16), 'down')):
                self._draw_button_3d(rect, '')
                self._draw_arrow(rect, arrow)
            track = bar.height - 32
            if track > 8:
                thumb_h = max(10, track * lines // lines_total)
                thumb_y = bar.y + 16 + (track - thumb_h) * first_line // max(1, lines_total - lines)
                self._draw_button_3d(pygame.Rect(bar.x, thumb_y, 16, thumb_h), '')

    VIEW_GLYPHS = {8: 'up', 10: 'new'}  # Standard VIEW_* bitmaps (IDB_VIEW_*_COLOR)

    def _view_glyph_surface(self, glyph, width, height):
        """16x16 picture of a standard VIEW_* toolbar bitmap (scaled to the
        toolbar's bitmap size), cached"""
        cache = self.__dict__.setdefault('_view_glyph_cache', {})
        key = (glyph, width, height)
        if key in cache:
            return cache[key]
        surface = pygame.Surface((16, 16), pygame.SRCALPHA)
        fill, line = self.SYS_ICON_COLORS[1]
        # Folder in the lower left: tab and body
        pygame.draw.rect(surface, fill, (1, 4, 6, 3))
        pygame.draw.rect(surface, line, (1, 4, 6, 3), 1)
        pygame.draw.rect(surface, fill, (1, 6, 11, 9))
        pygame.draw.rect(surface, line, (1, 6, 11, 9), 1)
        pygame.draw.line(surface, (255, 240, 170), (2, 7), (10, 7))
        if glyph == 'up':
            # Arrow out of the folder's top right corner
            pygame.draw.polygon(surface, (0, 0, 0), [(9, 5), (15, 5), (12, 2)])
            pygame.draw.rect(surface, (0, 0, 0), (11, 5, 2, 6))
        elif glyph == 'new':
            # Sparkle on the folder's top right corner
            sparkle = (255, 230, 0)
            pygame.draw.line(surface, sparkle, (12, 1), (12, 7))
            pygame.draw.line(surface, sparkle, (9, 4), (15, 4))
            pygame.draw.line(surface, sparkle, (10, 2), (14, 6))
            pygame.draw.line(surface, sparkle, (10, 6), (14, 2))
        if (width, height) != (16, 16):
            surface = pygame.transform.scale(surface, (width, height))
        cache[key] = surface
        return surface

    @staticmethod
    def _disabled_glyph(surface):
        """Disabled toolbar image like Windows draws it: a gray silhouette
        embossed with a white one offset by a pixel"""
        mask = pygame.mask.from_surface(surface)
        width, height = surface.get_size()
        result = pygame.Surface((width + 1, height + 1), pygame.SRCALPHA)
        result.blit(mask.to_surface(setcolor=(255, 255, 255, 255), unsetcolor=(0, 0, 0, 0)),
                    (1, 1))
        result.blit(mask.to_surface(setcolor=(128, 128, 128, 255), unsetcolor=(0, 0, 0, 0)),
                    (0, 0))
        return result

    def _draw_toolbar(self, win, cx, cy, cw, ch):
        st = win.nstate
        owner = win.owner
        pygame.draw.rect(self.screen, self.COLOR_WINDOW_BG, (cx, cy, cw, ch))
        if not win.style & 0x40:  # CCS_NODIVIDER
            pygame.draw.line(self.screen, (128, 128, 128), (cx, cy), (cx + cw, cy))
            pygame.draw.line(self.screen, (255, 255, 255), (cx, cy + 1), (cx + cw, cy + 1))
        if owner is None:
            return
        rects = owner._tb_layout(win)
        bw, bh = st['bitmap_size']
        mouse = self.mouse_pos
        for i, (button, (left, top, right, bottom)) in enumerate(zip(st['buttons'], rects)):
            if button['state'] & 0x8:
                continue
            rect = pygame.Rect(cx + left, cy + top, right - left, bottom - top)
            if button['style'] & 0x1:  # Separator
                pygame.draw.line(self.screen, (128, 128, 128), (rect.centerx - 1, rect.y + 2),
                                 (rect.centerx - 1, rect.bottom - 3))
                pygame.draw.line(self.screen, (255, 255, 255), (rect.centerx, rect.y + 2),
                                 (rect.centerx, rect.bottom - 3))
                continue
            enabled = button['state'] & 0x4
            pressed = st['pressed'] == i or button['state'] & 0x3
            if pressed:
                pygame.draw.rect(self.screen, (255, 255, 255), rect)
                pygame.draw.line(self.screen, (128, 128, 128), rect.topleft, rect.topright)
                pygame.draw.line(self.screen, (128, 128, 128), rect.topleft, rect.bottomleft)
            elif enabled and rect.collidepoint(mouse) and win.style & 0x800:  # TBSTYLE_FLAT
                pygame.draw.rect(self.screen, (255, 255, 255), rect, 1)
                pygame.draw.line(self.screen, (128, 128, 128), rect.bottomleft, rect.bottomright)
                pygame.draw.line(self.screen, (128, 128, 128), rect.topright, rect.bottomright)
            elif not win.style & 0x800:
                self._draw_button_3d(rect, '')
            text = owner._tb_text(win, button)
            ix = rect.x + (rect.width - bw) // 2
            iy = rect.y + 3 + (1 if pressed else 0)
            drawn = False
            if st['imagelist']:
                drawn = self._draw_imagelist_image(owner, st['imagelist'], button['bitmap'],
                                                   ix, iy, disabled=not enabled)
            if not drawn:
                glyph = self.VIEW_GLYPHS.get(button['bitmap'])
                if glyph:
                    surface = self._view_glyph_surface(glyph, bw or 16, bh or 16)
                    if not enabled:
                        surface = self._disabled_glyph(surface)
                    self.screen.blit(surface, (ix, iy))
            if text and st['max_text_rows']:
                label = self._fit_text(self.font_small, text, rect.width - 4)
                surface = self.font_small.render(label, True, (0, 0, 0) if enabled else
                                                 (128, 128, 128))
                self.screen.blit(surface, (rect.x + (rect.width - surface.get_width()) // 2,
                                           rect.bottom - surface.get_height() - 3))

    def _native_combo_rects(self, win):
        """Dropdown rect and item rects of an open ComboBoxEx (screen coordinates)"""
        cx, cy = self.client_origin(win)
        items = win.nstate['items']
        item_h = self.LISTBOX_ITEM_H
        height = min(len(items), max(1, (self.height - cy - win.height - 40) // item_h))
        drop = pygame.Rect(cx - 1, cy + win.height - 1, win.width, max(1, height) * item_h + 2)
        rects = [pygame.Rect(drop.x + 1, drop.y + 1 + i * item_h, drop.width - 2, item_h)
                 for i in range(height)]
        return drop, rects

    def _draw_open_native_combo(self):
        hwnd = self.open_native_combo
        win = self.windows.get(hwnd) if hwnd else None
        if win is None or not win.visible or not win.nstate.get('dropped'):
            self.open_native_combo = None
            return
        drop, rects = self._native_combo_rects(win)
        pygame.draw.rect(self.screen, (64, 64, 64), drop.move(2, 2))
        pygame.draw.rect(self.screen, self.COLOR_EDIT_BG, drop)
        pygame.draw.rect(self.screen, (0, 0, 0), drop, 1)
        st = win.nstate
        for i, (item, rect) in enumerate(zip(st['items'], rects)):
            hovered = rect.collidepoint(self.mouse_pos)
            if hovered:
                pygame.draw.rect(self.screen, self.COLOR_TITLE_BAR, rect)
            x = rect.x + 3 + 10 * item.get('indent', 0)
            if item.get('image', -1) >= 0:
                self._draw_imagelist_image(win.owner, st['imagelist'], item['image'], x,
                                           rect.y + 1)
                x += 20
            surface = self.font.render(item['text'], True,
                                       self.COLOR_TITLE_TEXT if hovered else self.COLOR_TEXT)
            self.screen.blit(surface, (x, rect.y + 1))

    def _handle_native_combo_click(self, pos):
        """Click while a ComboBoxEx list is open; True if consumed"""
        win = self.windows.get(self.open_native_combo)
        if win is None or win.owner is None:
            self.open_native_combo = None
            return False
        drop, rects = self._native_combo_rects(win)
        choice = -1
        for i, rect in enumerate(rects):
            if rect.collidepoint(pos):
                choice = i
        self.open_native_combo = None
        win.owner.post_window_message(win.hwnd, 0x047F, choice & 0xFFFFFFFF, 0)
        return drop.collidepoint(pos) or True

    # ---------- Menus: dropdowns with submenus, popup menus ----------

    MENU_ITEM_H = 20
    MENU_SEP_H = 7

    def _menu_panel_rects(self, items, x, y):
        """Panel rect and item rects of a menu panel opened at (x, y); an item
        with a column break (MF_MENUBREAK, MF_MENUBARBREAK) starts a new column"""
        columns = []
        for sub in items:
            if not columns or sub.get('break'):
                columns.append([])
            columns[-1].append(sub)
        widths = []
        for column in columns:
            width = 120 if len(columns) == 1 else 60
            for sub in column:
                if sub.get('text'):
                    shortcut_w = (self.font.size(sub['shortcut'])[0] + 24
                                  if sub.get('shortcut') else 0)
                    width = max(width, self.font.size(sub['text'])[0] + 48 + shortcut_w)
            widths.append(width)
        height = max(sum(self.MENU_SEP_H if sub.get('separator') else self.MENU_ITEM_H
                         for sub in column) for column in columns) + 4 if columns else 4
        total = sum(widths) + 4 * (len(widths) - 1) if widths else 120
        x = max(0, min(x, self.width - total))
        y = max(0, min(y, self.height - height))
        panel = pygame.Rect(x, y, total, height)
        rects = []
        left = x
        for column, width in zip(columns, widths):
            top = y + 2
            for sub in column:
                h = self.MENU_SEP_H if sub.get('separator') else self.MENU_ITEM_H
                rects.append(pygame.Rect(left + 2, top, width - 4, h))
                top += h
            left += width + 4
        return panel, rects

    def _menu_panels(self, items, x, y, path):
        """[(items, panel rect, item rects)] of a menu and its open submenus"""
        panels = []
        for level in range(len(path) + 1):
            panel, rects = self._menu_panel_rects(items, x, y)
            panels.append((items, panel, rects))
            if level >= len(path):
                break
            index = path[level]
            if not 0 <= index < len(items) or items[index].get('items') is None:
                break
            x, y = panel.right - 3, rects[index].y - 2
            items = items[index]['items']
        return panels

    def _draw_menu_panels(self, panels):
        mouse = self.mouse_pos
        for items, panel, rects in panels:
            self._draw_menu_panel(panel)
            for index, (sub, rect) in enumerate(zip(items, rects)):
                if index and sub.get('break') == 'bar':
                    # Etched vertical line between the columns
                    bar_x = rect.x - 5
                    pygame.draw.line(self.screen, (128, 128, 128), (bar_x, panel.y + 2),
                                     (bar_x, panel.bottom - 3))
                    pygame.draw.line(self.screen, (255, 255, 255), (bar_x + 1, panel.y + 2),
                                     (bar_x + 1, panel.bottom - 3))
                if sub.get('separator'):
                    mid = rect.y + rect.height // 2
                    pygame.draw.line(self.screen, (128, 128, 128), (rect.x + 2, mid),
                                     (rect.right - 2, mid))
                    pygame.draw.line(self.screen, (255, 255, 255), (rect.x + 2, mid + 1),
                                     (rect.right - 2, mid + 1))
                    continue
                hovered = rect.collidepoint(mouse)
                if hovered:
                    pygame.draw.rect(self.screen, self.COLOR_TITLE_BAR, rect)
                if sub.get('grayed'):
                    color = (128, 128, 128) if not hovered else (192, 192, 192)
                else:
                    color = self.COLOR_TITLE_TEXT if hovered else self.COLOR_TEXT
                ty = rect.y + (rect.height - self.font.get_height()) // 2
                if sub.get('checked'):
                    if sub.get('radio'):
                        pygame.draw.circle(self.screen, color, (rect.x + 9, rect.centery), 3)
                    else:
                        pygame.draw.lines(self.screen, color, False,
                                          [(rect.x + 5, rect.centery), (rect.x + 8, rect.centery + 3),
                                           (rect.x + 13, rect.centery - 3)], 2)
                self.screen.blit(self.font.render(sub['text'], True, color), (rect.x + 20, ty))
                if sub.get('shortcut'):
                    surface = self.font.render(sub['shortcut'], True, color)
                    self.screen.blit(surface, (rect.right - 16 - surface.get_width(), ty))
                if sub.get('items') is not None:
                    ax, ay = rect.right - 9, rect.centery
                    pygame.draw.polygon(self.screen, color, [(ax, ay - 4), (ax, ay + 4), (ax + 4, ay)])

    def _menu_hover(self, panels, path, notify):
        """Open the submenu under the mouse (closing deeper ones); notify(hmenu,
        index) for a newly opened one"""
        mouse = self.mouse_pos
        for level in range(len(panels) - 1, -1, -1):
            items, panel, rects = panels[level]
            if not panel.collidepoint(mouse):
                continue
            for index, (sub, rect) in enumerate(zip(items, rects)):
                if not rect.collidepoint(mouse) or sub.get('separator'):
                    continue
                if sub.get('items') is not None and not sub.get('grayed'):
                    new_path = path[:level] + [index]
                    if path[:level + 1] != new_path:
                        notify(sub.get('hmenu', 0), index)
                        path[:] = new_path
                elif len(path) > level:
                    path[:] = path[:level]
                return
            return

    def _menu_panels_click(self, panels, pos):
        """('command', id) / ('submenu', level, index) / ('inside',) / None"""
        for level in range(len(panels) - 1, -1, -1):
            items, panel, rects = panels[level]
            if not panel.collidepoint(pos):
                continue
            for index, (sub, rect) in enumerate(zip(items, rects)):
                if rect.collidepoint(pos) and not sub.get('separator'):
                    if sub.get('grayed'):
                        return ('inside',)
                    if sub.get('items') is not None:
                        return ('submenu', level, index)
                    return ('command', sub['id'])
            return ('inside',)
        return None

    def _menu_root(self):
        """(items, x, y, owner window) of the open menu bar dropdown, or None"""
        if not self.open_menu:
            return None
        hwnd, index = self.open_menu
        win = self.windows.get(hwnd)
        if not win or not win.visible or win.minimized or not win.menu or index >= len(win.menu):
            return None
        rects = self._menu_item_rects(win)
        if index >= len(rects):
            return None
        return win.menu[index].get('items') or [], rects[index].x, rects[index].bottom, win

    def _post_init_menu(self, win, hmenu, index):
        if hmenu and win is not None and win.owner is not None and self._is_app_window(win.hwnd):
            win.owner.post_window_message(win.hwnd, winapi.WinAPIHandler.WM_INITMENUPOPUP, hmenu,
                                          index & 0xFFFF)

    def _draw_popup_menu(self):
        popup = self.popup_menu
        if popup is None:
            return
        panels = self._menu_panels(popup['tree'], popup['x'], popup['y'], popup['open'])
        owner = popup['owner']

        def notify(hmenu, index):
            if hmenu:
                owner.post_window_message(popup['hwnd'], winapi.WinAPIHandler.WM_INITMENUPOPUP,
                                          hmenu, index & 0xFFFF)
        self._menu_hover(panels, popup['open'], notify)
        panels = self._menu_panels(popup['tree'], popup['x'], popup['y'], popup['open'])
        self._draw_menu_panels(panels)

    def _handle_popup_menu_click(self, pos, button):
        """Click while a popup menu (TrackPopupMenu) is open: always consumed"""
        popup = self.popup_menu
        panels = self._menu_panels(popup['tree'], popup['x'], popup['y'], popup['open'])
        hit = self._menu_panels_click(panels, pos)
        if hit is None:
            popup['done'] = True
            self.popup_menu = None
        elif hit[0] == 'command':
            popup['result'] = hit[1]
            popup['done'] = True
            self.popup_menu = None
        elif hit[0] == 'submenu':
            popup['open'][:] = popup['open'][:hit[1]] + [hit[2]]
        return True

    def _draw_control(self, control, parent_x, parent_y):
        """Draw control in its WM_SETFONT font"""
        if not control.visible:
            return
        if control.class_name == "STATUSBAR":
            self.layout_statusbar(control)
        gui_font = self.font
        if control.font:
            self.font = self._get_render_font(control.font)
        try:
            self._draw_control_body(control, parent_x + control.x, parent_y + control.y)
        finally:
            self.font = gui_font
        if control.drawn_shapes:
            abs_x, abs_y = parent_x + control.x, parent_y + control.y
            prev_clip = self.screen.get_clip()
            rect = pygame.Rect(abs_x, abs_y, control.width, control.height)
            self.screen.set_clip(rect.clip(prev_clip) if prev_clip else rect)
            for shape in control.drawn_shapes:
                self._draw_shape(shape, abs_x, abs_y)
            self.screen.set_clip(prev_clip)

    def _wrap_text(self, text, width):
        """Split text into lines that fit width pixels (word wrap)"""
        lines = []
        for paragraph in text.split('\n'):
            line = ''
            for word in paragraph.split(' '):
                candidate = f"{line} {word}" if line else word
                if line and self.font.size(candidate)[0] > width:
                    lines.append(line)
                    line = word
                else:
                    line = candidate
            lines.append(line)
        return lines

    SS_NOPREFIX = 0x80

    def _draw_edit_text(self, control, rect, padding=4):
        """Text of an EDIT control (or an editable combo box) with the selection,
        the blinking caret and the scrolling that keeps the caret visible"""
        font = self.font
        shown = self._edit_display_text(control)
        focused = control.hwnd == self.focused_control
        start, end = control.selection()
        caret = min(max(control.sel_caret, 0), len(shown))
        lines = control.edit_lines()
        line_h = font.get_linesize()
        multiline = control.class_name == "EDIT" and control.style & 0x4
        inner_w = max(1, rect.width - 2 * padding)
        caret_line = control.line_of(caret)
        caret_px = font.size(shown[lines[caret_line][0]:caret])[0]
        if caret_px - control.edit_scroll > inner_w - 1:
            control.edit_scroll = caret_px - inner_w + 1
        elif caret_px < control.edit_scroll:
            control.edit_scroll = max(0, caret_px - inner_w // 3)
        if multiline:
            visible = max(1, (rect.height - 4) // line_h)
            if caret_line < control.edit_top_line:
                control.edit_top_line = caret_line
            elif caret_line >= control.edit_top_line + visible:
                control.edit_top_line = caret_line - visible + 1
            top, first_y = control.edit_top_line, rect.y + 2
        else:
            top, first_y = 0, rect.y + (rect.height - font.get_height()) // 2
        color = self.COLOR_TEXT if control.enabled else (128, 128, 128)
        show_selection = focused or control.style & 0x100  # ES_NOHIDESEL
        prev_clip = self.screen.get_clip()
        inner = rect.inflate(-2, -2)
        self.screen.set_clip(inner.clip(prev_clip) if prev_clip else inner)
        x0 = rect.x + padding - control.edit_scroll
        for index in range(top, len(lines)):
            line_start, line_end = lines[index]
            y = first_y + (index - top) * line_h
            if y > rect.bottom:
                break
            first, last = max(start, line_start), min(end, line_end)
            if show_selection and first < last:
                x = x0
                for piece, selected in ((shown[line_start:first], False),
                                        (shown[first:last], True),
                                        (shown[last:line_end], False)):
                    if not piece:
                        continue
                    width = font.size(piece)[0]
                    if selected:
                        pygame.draw.rect(self.screen, self.COLOR_TITLE_BAR, (x, y, width, line_h))
                    self.screen.blit(font.render(piece, True, self.COLOR_TITLE_TEXT if selected
                                                 else color), (x, y))
                    x += width
            elif line_end > line_start:
                self.screen.blit(font.render(shown[line_start:line_end], True, color), (x0, y))
        if focused and (pygame.time.get_ticks() // 500) % 2 == 0:
            caret_x = x0 + caret_px
            if multiline:
                caret_y = first_y + (caret_line - top) * line_h
                pygame.draw.line(self.screen, self.COLOR_TEXT, (caret_x, caret_y),
                                 (caret_x, caret_y + line_h - 1))
            else:
                pygame.draw.line(self.screen, self.COLOR_TEXT, (caret_x, rect.y + 3),
                                 (caret_x, rect.bottom - 4))
        self.screen.set_clip(prev_clip)

    @staticmethod
    def _mnemonic_text(text):
        """Control text as drawn: "&x" marks the mnemonic (underlined on
        Windows), "&&" is a literal "&"""
        return re.sub(r'&(.)', r'\1', text or '')

    def _draw_static(self, control, rect):
        """Draw a STATIC control by its SS_* type"""
        kind = control.style & 0x1F
        dark, light = (128, 128, 128), (255, 255, 255)
        x, y, w, h = rect
        if kind == 0x10:    # SS_ETCHEDHORZ
            pygame.draw.line(self.screen, dark, (x, y), (x + w - 1, y))
            pygame.draw.line(self.screen, light, (x, y + 1), (x + w - 1, y + 1))
        elif kind == 0x11:  # SS_ETCHEDVERT
            pygame.draw.line(self.screen, dark, (x, y), (x, y + h - 1))
            pygame.draw.line(self.screen, light, (x + 1, y), (x + 1, y + h - 1))
        elif kind == 0x12:  # SS_ETCHEDFRAME
            pygame.draw.rect(self.screen, light, (x + 1, y + 1, w - 1, h - 1), 1)
            pygame.draw.rect(self.screen, dark, (x, y, w - 1, h - 1), 1)
        elif kind == 3:  # SS_ICON
            if control.icon:
                surface = self._image_surface_rgba(control.icon)
                if control.style & 0x200:  # SS_CENTERIMAGE
                    self.screen.blit(surface, surface.get_rect(center=rect.center))
                else:
                    self.screen.blit(surface, (x, y))
        elif kind in (4, 5, 6):  # SS_BLACKRECT, SS_GRAYRECT, SS_WHITERECT
            pygame.draw.rect(self.screen, ((0, 0, 0), dark, light)[kind - 4], rect)
        elif kind in (7, 8, 9):  # SS_BLACKFRAME, SS_GRAYFRAME, SS_WHITEFRAME
            pygame.draw.rect(self.screen, ((0, 0, 0), dark, light)[kind - 7], rect, 1)
        elif kind in (0, 1, 2, 0xB, 0xC):  # Text: left, center, right, simple, no wrap
            text = control.text
            if not control.style & self.SS_NOPREFIX:
                text = self._mnemonic_text(text)
            lines = self._wrap_text(text, w) if kind <= 2 else text.split('\n')
            prev_clip = self.screen.get_clip()
            # The first line is never cut: the font may be taller than the
            # one-line height the dialog template gives the control
            text_rect = pygame.Rect(x, y, w, max(h, self.font.get_linesize()))
            self.screen.set_clip(text_rect.clip(prev_clip) if prev_clip else text_rect)
            line_y = y
            for line in lines:
                surface = self.font.render(line, True, self.COLOR_TEXT)
                if kind == 1:
                    line_x = x + (w - surface.get_width()) // 2
                elif kind == 2:
                    line_x = x + w - surface.get_width()
                else:
                    line_x = x
                self.screen.blit(surface, (line_x, line_y))
                line_y += self.font.get_linesize()
                if line_y >= y + h:
                    break
            self.screen.set_clip(prev_clip)

    STATUSBAR_H = 20

    def layout_statusbar(self, control):
        """Dock a status bar to the bottom (CCS_TOP: top) of its parent's client area"""
        if control.style & 0x0C:  # CCS_NORESIZE, CCS_NOPARENTALIGN
            return
        win = self.windows.get(control.parent_hwnd)
        if win is None:
            return
        width, height = self.client_size(win)
        top = 0 if control.style & 0x3 == 1 else height - self.STATUSBAR_H
        control.x, control.y = 0, top
        control.width, control.height = width, self.STATUSBAR_H

    def _draw_statusbar(self, control, abs_x, abs_y):
        """Status bar: sunken panes with their texts"""
        rect = pygame.Rect(abs_x, abs_y, control.width, control.height)
        pygame.draw.rect(self.screen, self.COLOR_BUTTON, rect)
        dark, light = (128, 128, 128), (255, 255, 255)
        if control.simple:
            panes = [(-1, control.part_texts.get(255, ''))]
        else:
            panes = [(edge, control.text if i == 0 else control.part_texts.get(i, ''))
                     for i, edge in enumerate(control.parts)]
        prev_clip = self.screen.get_clip()
        left = abs_x + 2
        for edge, text in panes:
            right = rect.right - 2 if edge < 0 else min(abs_x + edge, rect.right - 2)
            pane = pygame.Rect(left, abs_y + 2, max(0, right - left - 2), control.height - 3)
            if pane.width > 0:
                pygame.draw.line(self.screen, dark, pane.topleft, (pane.right - 1, pane.top))
                pygame.draw.line(self.screen, dark, pane.topleft, (pane.left, pane.bottom - 1))
                pygame.draw.line(self.screen, light, (pane.left, pane.bottom - 1),
                                 (pane.right - 1, pane.bottom - 1))
                pygame.draw.line(self.screen, light, (pane.right - 1, pane.top),
                                 (pane.right - 1, pane.bottom - 1))
                self.screen.set_clip(pane.clip(prev_clip) if prev_clip else pane)
                surface = self.font.render(text.replace('\t', ' '), True, self.COLOR_TEXT)
                self.screen.blit(surface, (pane.x + 3,
                                           pane.y + (pane.height - surface.get_height()) // 2))
                self.screen.set_clip(prev_clip)
            left = right

    def _draw_progressbar(self, control, abs_x, abs_y):
        """Progress bar (msctls_progress32): sunken box filled up to the position,
        with blocks unless PBS_SMOOTH; PBS_VERTICAL fills from the bottom"""
        rect = pygame.Rect(abs_x, abs_y, control.width, control.height)
        pygame.draw.rect(self.screen, control.progress_bk_color or self.COLOR_BUTTON, rect)
        dark, light = (128, 128, 128), (255, 255, 255)
        pygame.draw.line(self.screen, dark, rect.topleft, (rect.right - 1, rect.top))
        pygame.draw.line(self.screen, dark, rect.topleft, (rect.left, rect.bottom - 1))
        pygame.draw.line(self.screen, light, (rect.left, rect.bottom - 1),
                         (rect.right - 1, rect.bottom - 1))
        pygame.draw.line(self.screen, light, (rect.right - 1, rect.top),
                         (rect.right - 1, rect.bottom - 1))
        inner = rect.inflate(-4, -4)
        span = control.scroll_max - control.scroll_min
        if inner.width <= 0 or inner.height <= 0 or span <= 0:
            return
        fraction = min(1.0, max(0.0, (control.scroll_pos - control.scroll_min) / span))
        vertical = bool(control.style & 0x4)  # PBS_VERTICAL
        length = round((inner.height if vertical else inner.width) * fraction)
        color = control.progress_bar_color or (0, 0, 128)
        if control.style & 0x1:  # PBS_SMOOTH
            blocks = [(0, length)]
        else:
            size = max(2, ((inner.width if vertical else inner.height) * 2) // 3)
            blocks = [(start, min(size, length - start))
                      for start in range(0, length, size + 2)]
        for start, extent in blocks:
            if vertical:
                block = pygame.Rect(inner.left, inner.bottom - start - extent,
                                    inner.width, extent)
            else:
                block = pygame.Rect(inner.left + start, inner.top, extent, inner.height)
            pygame.draw.rect(self.screen, color, block)

    def _draw_control_body(self, control, abs_x, abs_y):
        if control.class_name == "STATUSBAR":
            self._draw_statusbar(control, abs_x, abs_y)
        elif control.class_name == "BUTTON":
            rect = pygame.Rect(abs_x, abs_y, control.width, control.height)
            label = self._mnemonic_text(control.text)
            if (control.style & 0xF) == 7:  # BS_GROUPBOX
                self._draw_group_box(control, rect)
            elif (control.style & 0xF) == 1:  # BS_DEFPUSHBUTTON: black outer frame
                self._draw_button_3d(rect.inflate(-2, -2), label,
                                     disabled=not control.enabled)
                pygame.draw.rect(self.screen, (0, 0, 0), rect, 1)
            else:
                self._draw_button_3d(rect, label, pressed=control.checked,
                                     disabled=not control.enabled)
            
        elif control.class_name == "STATIC":
            self._draw_static(control, pygame.Rect(abs_x, abs_y, control.width, control.height))
            
        elif control.class_name == "EDIT":
            rect = pygame.Rect(abs_x, abs_y, control.width, control.height)
            # Disabled and read-only edit controls have the dialog color
            readonly = control.style & 0x800  # ES_READONLY
            pygame.draw.rect(self.screen, self.COLOR_EDIT_BG if control.enabled and not readonly
                             else self.COLOR_BUTTON, rect)
            inset = self._draw_window_edge(rect, control.style, control.ex_style)
            self._draw_edit_text(control, rect, padding=inset + 2)
            
        elif control.class_name == "LISTBOX":
            rect = pygame.Rect(abs_x, abs_y, control.width, control.height)
            pygame.draw.rect(self.screen, self.COLOR_EDIT_BG, rect)
            pygame.draw.rect(self.screen, (128, 128, 128), rect, 1)

            # Items with the selected one highlighted
            prev_clip = self.screen.get_clip()
            self.screen.set_clip(rect)
            item_h = self.LISTBOX_ITEM_H
            top = min(control.top_index, max(0, len(control.items) - 1))
            for i, item in enumerate(control.items[top:], top):
                item_rect = pygame.Rect(abs_x + 1, abs_y + 1 + (i - top) * item_h,
                                        control.width - 2, item_h)
                if item_rect.top > rect.bottom:
                    break
                selected = (i == control.sel_index)
                if selected:
                    pygame.draw.rect(self.screen, self.COLOR_TITLE_BAR, item_rect)
                color = self.COLOR_TITLE_TEXT if selected else self.COLOR_TEXT
                text = self.font.render(item, True, color)
                self.screen.blit(text, (item_rect.x + 3, item_rect.y + 1))
            self.screen.set_clip(prev_clip)

        elif control.class_name == "COMBOBOX":
            box_h = min(control.height, 24)
            rect = pygame.Rect(abs_x, abs_y, control.width, box_h)
            pygame.draw.rect(self.screen, self.COLOR_EDIT_BG if control.enabled
                             else self.COLOR_BUTTON, rect)
            self._draw_window_edge(rect, 0, 0x200)  # Sunken like WS_EX_CLIENTEDGE

            # Selected item text (editable combos: the edit field's text)
            sel_text = ""
            if control.style & 0x3 in (1, 2):  # CBS_SIMPLE, CBS_DROPDOWN
                self._draw_edit_text(control, pygame.Rect(abs_x, abs_y, control.width - 18,
                                                          box_h))
            elif 0 <= control.sel_index < len(control.items):
                sel_text = control.items[control.sel_index]
            if sel_text:
                prev_clip = self.screen.get_clip()
                self.screen.set_clip(rect)
                text = self.font.render(sel_text, True, self.COLOR_TEXT)
                self.screen.blit(text, (abs_x + 4, abs_y + (box_h - text.get_height()) // 2))
                self.screen.set_clip(prev_clip)

            # Dropdown arrow inside the sunken edge
            arrow_rect = pygame.Rect(abs_x + control.width - 18, abs_y + 2, 16, box_h - 4)
            self._draw_button_3d(arrow_rect, "", small=True, arrow='down')
            
        elif control.class_name in ["CHECKBOX", "BS_CHECKBOX"]:
            if (control.style & 0xF) in (0x4, 0x9):  # Radio button
                center = (abs_x + 6, abs_y + 8)
                pygame.draw.circle(self.screen, self.COLOR_EDIT_BG, center, 6)
                pygame.draw.circle(self.screen, (128, 128, 128), center, 6, 1)
                if control.checked:
                    pygame.draw.circle(self.screen, self.COLOR_TEXT, center, 2)
                text = self.font.render(self._mnemonic_text(control.text), True,
                                        self.COLOR_TEXT)
                self.screen.blit(text, (abs_x + 18, abs_y))
                return
            # Checkbox box
            box_rect = pygame.Rect(abs_x, abs_y + 2, 13, 13)
            pygame.draw.rect(self.screen, self.COLOR_EDIT_BG, box_rect)
            pygame.draw.rect(self.screen, (128, 128, 128), box_rect, 1)
            if control.checked:
                pygame.draw.line(self.screen, self.COLOR_TEXT, 
                               (abs_x + 2, abs_y + 8), (abs_x + 5, abs_y + 11), 2)
                pygame.draw.line(self.screen, self.COLOR_TEXT, 
                               (abs_x + 5, abs_y + 11), (abs_x + 11, abs_y + 4), 2)
            # Label
            text = self.font.render(self._mnemonic_text(control.text), True, self.COLOR_TEXT)
            self.screen.blit(text, (abs_x + 18, abs_y))
            
        elif control.class_name == "PROGRESSBAR":
            self._draw_progressbar(control, abs_x, abs_y)

        elif control.class_name == "SCROLLBAR":
            m = self._scrollbar_metrics(control, abs_x, abs_y)

            # Track (classic dotted-gray look approximated with a light gray)
            pygame.draw.rect(self.screen, (224, 224, 224), m['track'])
            pygame.draw.rect(self.screen, (128, 128, 128),
                             pygame.Rect(abs_x, abs_y, control.width, control.height), 1)

            # Arrow buttons
            if m['vertical']:
                self._draw_button_3d(m['up'], "", small=True, arrow='up')
                self._draw_button_3d(m['down'], "", small=True, arrow='down')
            else:
                self._draw_button_3d(m['up'], "", small=True, arrow='left')
                self._draw_button_3d(m['down'], "", small=True, arrow='right')

            # Thumb (pressed look while dragging)
            dragging = (self.dragging_scrollbar is not None and
                        self.dragging_scrollbar[0] == control.hwnd)
            self._draw_button_3d(m['thumb'], "", pressed=dragging)
    
    def _draw_window_edge(self, rect, style, ex_style):
        """Classic border of a child window by its styles: WS_EX_CLIENTEDGE
        (2 px sunken), WS_EX_STATICEDGE (1 px sunken), WS_BORDER (1 px black).
        Returns the border width."""
        x, y, r, b = rect.x, rect.y, rect.right - 1, rect.bottom - 1
        draw = pygame.draw.line
        if ex_style & 0x200:  # WS_EX_CLIENTEDGE
            draw(self.screen, (128, 128, 128), (x, y), (r - 1, y))
            draw(self.screen, (128, 128, 128), (x, y), (x, b - 1))
            draw(self.screen, self.COLOR_BUTTON_BORDER_LIGHT, (x, b), (r, b))
            draw(self.screen, self.COLOR_BUTTON_BORDER_LIGHT, (r, y), (r, b))
            draw(self.screen, self.COLOR_BUTTON_BORDER_DARK, (x + 1, y + 1), (r - 2, y + 1))
            draw(self.screen, self.COLOR_BUTTON_BORDER_DARK, (x + 1, y + 1), (x + 1, b - 2))
            draw(self.screen, self.COLOR_BUTTON, (x + 1, b - 1), (r - 1, b - 1))
            draw(self.screen, self.COLOR_BUTTON, (r - 1, y + 1), (r - 1, b - 1))
            return 2
        if ex_style & 0x20000:  # WS_EX_STATICEDGE
            draw(self.screen, (128, 128, 128), (x, y), (r - 1, y))
            draw(self.screen, (128, 128, 128), (x, y), (x, b - 1))
            draw(self.screen, self.COLOR_BUTTON_BORDER_LIGHT, (x, b), (r, b))
            draw(self.screen, self.COLOR_BUTTON_BORDER_LIGHT, (r, y), (r, b))
            return 1
        if style & 0x00800000:  # WS_BORDER
            pygame.draw.rect(self.screen, (0, 0, 0), rect, 1)
            return 1
        return 0

    def _draw_group_box(self, control, rect):
        """BS_GROUPBOX: etched frame with the caption on its top edge"""
        caption = self._mnemonic_text(control.text)
        text = self.font.render(caption, True, self.COLOR_TEXT) if caption else None
        top = rect.y + (text.get_height() // 2 if text else 0)
        frame = pygame.Rect(rect.x, top, rect.width - 1, rect.bottom - top - 1)
        pygame.draw.rect(self.screen, self.COLOR_BUTTON_BORDER_DARK, frame, 1)
        pygame.draw.rect(self.screen, self.COLOR_BUTTON_BORDER_LIGHT, frame.move(1, 1), 1)
        if text:
            label = pygame.Rect(rect.x + 8, rect.y, text.get_width() + 4, text.get_height())
            pygame.draw.rect(self.screen, self.COLOR_BUTTON, label)
            self.screen.blit(text, (label.x + 2, label.y))

    def _draw_edge(self, rect, top_left, bottom_right):
        """One-pixel 3D edge around rect: top and left lines in one color,
        bottom and right lines in the other"""
        if rect.width <= 0 or rect.height <= 0:
            return
        x, y, r, b = rect.x, rect.y, rect.right - 1, rect.bottom - 1
        pygame.draw.line(self.screen, top_left, (x, y), (r, y))
        pygame.draw.line(self.screen, top_left, (x, y), (x, b))
        pygame.draw.line(self.screen, bottom_right, (r, y), (r, b))
        pygame.draw.line(self.screen, bottom_right, (x, b), (r, b))

    def _draw_raised(self, rect):
        """Classic 2-pixel raised edge (window frames, buttons, menus)"""
        self._draw_edge(rect, self.COLOR_BUTTON, self.COLOR_BUTTON_BORDER_DARK)
        self._draw_edge(rect.inflate(-2, -2), self.COLOR_BUTTON_BORDER_LIGHT,
                        self.COLOR_BUTTON_SHADOW)

    def _draw_sunken(self, rect):
        """Classic 2-pixel sunken edge of a pressed button"""
        self._draw_edge(rect, self.COLOR_BUTTON_BORDER_DARK, self.COLOR_BUTTON_BORDER_LIGHT)
        self._draw_edge(rect.inflate(-2, -2), self.COLOR_BUTTON_SHADOW, self.COLOR_BUTTON)

    def _gradient(self, size, start, end, horizontal=True):
        """Surface of this size shading from start to end, left to right (or
        top to bottom); cached"""
        key = (size, start, end, horizontal)
        surface = self._gradient_cache.get(key)
        if surface is None:
            width, height = size
            surface = pygame.Surface((max(1, width), max(1, height)))
            steps = width if horizontal else height
            for i in range(steps):
                t = i / max(1, steps - 1)
                color = tuple(round(a + (b - a) * t) for a, b in zip(start, end))
                if horizontal:
                    pygame.draw.line(surface, color, (i, 0), (i, height - 1))
                else:
                    pygame.draw.line(surface, color, (0, i), (width - 1, i))
            if len(self._gradient_cache) > 64:
                self._gradient_cache.clear()  # Old window sizes
            self._gradient_cache[key] = surface
        return surface

    SHADOW_SIZE = 4

    def _draw_shadow(self, rect):
        """Soft drop shadow at the right and the bottom of a window or menu"""
        size = self.SHADOW_SIZE
        for i in range(size):
            alpha = 56 - i * 12
            right = pygame.Surface((1, rect.height - size + 1 + i), pygame.SRCALPHA)
            right.fill((0, 0, 0, alpha))
            self.screen.blit(right, (rect.right + i, rect.y + size - i))
            bottom = pygame.Surface((rect.width - size + 1 + i, 1), pygame.SRCALPHA)
            bottom.fill((0, 0, 0, alpha))
            self.screen.blit(bottom, (rect.x + size - i, rect.bottom + i))

    def _draw_button_3d(self, rect, text, pressed=False, small=False, arrow=None, bold=False,
                        disabled=False):
        """Draw 3D-style button.

        When ``arrow`` is one of 'up'/'down'/'left'/'right', a filled triangle
        is drawn instead of ``text``. Triangles render crisply at any size and
        don't depend on the system font carrying Unicode arrow glyphs.
        """
        pygame.draw.rect(self.screen, self.COLOR_BUTTON, rect)
        if pressed:
            self._draw_sunken(rect)
        else:
            self._draw_raised(rect)

        if arrow:
            self._draw_arrow(rect, arrow, pressed=pressed)
            return

        # Text
        font = (self.font_small_bold if bold else self.font_small) if small else (
            self.font_bold if bold else self.font)
        if disabled:
            # Embossed gray text (COLOR_GRAYTEXT with a white shadow)
            shadow = font.render(text, True, self.COLOR_BUTTON_BORDER_LIGHT)
            self.screen.blit(shadow, shadow.get_rect(center=(rect.centerx + 1,
                                                            rect.centery + 1)))
        text_surface = font.render(text, True, (128, 128, 128) if disabled else self.COLOR_TEXT)
        text_rect = text_surface.get_rect(center=rect.center)
        if pressed:
            text_rect.move_ip(1, 1)  # The face moves in with the press
        self.screen.blit(text_surface, text_rect)

    def _draw_arrow(self, rect, direction, pressed=False):
        """Draw a small filled triangle centered in ``rect``.

        ``direction`` is 'up', 'down', 'left' or 'right'. Used for scrollbar
        arrow buttons and the combo-box dropdown, replacing font glyphs that
        render poorly (or not at all) at small sizes on some systems.
        """
        cx, cy = rect.center
        if pressed:
            cx += 1
            cy += 1
        dw, dh = 3, 2  # triangle half-base / depth -> 7px base, 4px tall
        if direction == 'down':
            points = [(cx - dw, cy - dh), (cx + dw, cy - dh), (cx, cy + dh)]
        elif direction == 'up':
            points = [(cx - dw, cy + dh), (cx + dw, cy + dh), (cx, cy - dh)]
        elif direction == 'right':
            points = [(cx - dh, cy - dw), (cx - dh, cy + dw), (cx + dh, cy)]
        else:  # 'left'
            points = [(cx + dh, cy - dw), (cx + dh, cy + dw), (cx - dh, cy)]
        pygame.draw.polygon(self.screen, self.COLOR_TEXT, points)

    def _draw_window_button(self, rect, symbol, btn_type):
        """Draw a caption button (minimize, maximize / restore, close) with a
        classic raised face and a crisp black glyph"""
        pygame.draw.rect(self.screen, self.COLOR_BUTTON, rect)
        self._draw_raised(rect)
        black = self.COLOR_TEXT
        cx, cy = rect.centerx, rect.centery
        if btn_type == "close":
            # 8x7 "x" drawn two pixels thick
            x0, y0 = cx - 4, cy - 4
            for dx in (0, 1):
                pygame.draw.line(self.screen, black, (x0 + dx, y0), (x0 + dx + 6, y0 + 6))
                pygame.draw.line(self.screen, black, (x0 + dx + 6, y0), (x0 + dx, y0 + 6))
        elif btn_type == "max" and symbol == "❐":
            # Restore: two overlapping windows, the front one lower left
            back = pygame.Rect(cx - 2, cy - 5, 6, 6)
            front = pygame.Rect(cx - 5, cy - 2, 6, 6)
            for box in (back, front):
                pygame.draw.rect(self.screen, self.COLOR_BUTTON, box)
                pygame.draw.rect(self.screen, black, box, 1)
                pygame.draw.line(self.screen, black, (box.x, box.y + 1), (box.right - 1, box.y + 1))
        elif btn_type == "max":
            # Maximize: a window with a thick caption
            box = pygame.Rect(cx - 5, cy - 5, 9, 9)
            pygame.draw.rect(self.screen, black, box, 1)
            pygame.draw.line(self.screen, black, (box.x, box.y + 1), (box.right - 1, box.y + 1))
        elif btn_type == "min":
            # Minimize: a short thick bar at the bottom
            pygame.draw.rect(self.screen, black, pygame.Rect(cx - 4, cy + 2, 6, 2))

    def _get_resize_edge(self, win, x, y):
        """Return which edge/corner the point is on, or None.

        Returns one of: 'left','right','top','bottom','topleft','topright',
        'bottomleft','bottomright'. Resizing is disabled for maximized,
        minimized and dialog (MessageBox) windows.
        """
        if win.maximized or win.minimized or win.is_dialog:
            return None
        if win.parent is None and not self.window_frame(win)[0]:
            return None  # No frame to grab

        m = self.RESIZE_BORDER

        # Point must be near the window rectangle (inner border band)
        if not (win.x - m <= x <= win.x + win.width + m and
                win.y - m <= y <= win.y + win.height + m):
            return None

        left = abs(x - win.x) <= m
        right = abs(x - (win.x + win.width)) <= m
        top = abs(y - win.y) <= m
        bottom = abs(y - (win.y + win.height)) <= m

        edge = ""
        if top:
            edge += "top"
        elif bottom:
            edge += "bottom"
        if left:
            edge += "left"
        elif right:
            edge += "right"

        return edge or None

    def _resize_window_to(self, win, pos):
        """Resize a window while the user drags an edge/corner."""
        mx, my = pos
        edge = self.resize_edge
        sx, sy = self.resize_start_mouse
        ox, oy, ow, oh = self.resize_start_rect

        dx = mx - sx
        dy = my - sy

        new_x, new_y, new_w, new_h = ox, oy, ow, oh

        if "left" in edge:
            new_x = ox + dx
            new_w = ow - dx
        elif "right" in edge:
            new_w = ow + dx

        if "top" in edge:
            new_y = oy + dy
            new_h = oh - dy
        elif "bottom" in edge:
            new_h = oh + dy

        # Enforce minimum size, keeping the opposite edge anchored
        if new_w < self.MIN_WINDOW_WIDTH:
            if "left" in edge:
                new_x -= (self.MIN_WINDOW_WIDTH - new_w)
            new_w = self.MIN_WINDOW_WIDTH
        if new_h < self.MIN_WINDOW_HEIGHT:
            if "top" in edge:
                new_y -= (self.MIN_WINDOW_HEIGHT - new_h)
            new_h = self.MIN_WINDOW_HEIGHT

        # Keep the title bar reachable on screen
        new_y = max(0, new_y)

        win.x, win.y, win.width, win.height = new_x, new_y, new_w, new_h

    # Window edge -> standard cursor (IDC_SIZEWE, IDC_SIZENS, IDC_SIZENWSE, IDC_SIZENESW)
    RESIZE_CURSORS = {"left": 32644, "right": 32644, "top": 32645, "bottom": 32645,
                      "topleft": 32642, "bottomright": 32642, "topright": 32643,
                      "bottomleft": 32643}

    def _program_cursor(self, pos):
        """Cursor a program shows at pos: (True, cursor dict or None if hidden),
        or (False, None) if pos is not over a program's client area"""
        if self.start_menu_open or self.desktop_menu or self.open_menu or self.open_combo:
            return False, None
        captured = self._capture_target()
        if captured is not None:
            return True, captured.owner.displayed_cursor(captured.hwnd)
        x, y = pos
        if y >= self.height - self.TASKBAR_H and self._fullscreen_window() is None:
            return False, None
        for hwnd in reversed(self.z_order):
            win = self.windows.get(hwnd)
            if not (win and win.visible and not win.minimized and win.contains_point(x, y)):
                continue
            if (win.is_dialog or not self._is_app_window(hwnd) or
                    self._get_resize_edge(win, x, y) or y < self.client_origin(win)[1]):
                return False, None
            return True, win.owner.displayed_cursor(hwnd)
        return False, None

    def _update_mouse_cursor(self):
        """Show the cursor of the mouse position (every frame): a resize arrow
        on window edges, the program's cursor (SetCursor, class cursor,
        ShowCursor) over its client area, else the arrow. Standard cursors are
        the built-in ones (standard_cursor_image), not the host's."""
        pos = self.mouse_pos
        edge = self.resize_edge if self.resizing_window else None
        if edge is None and not (self.dragging_window or self.dragging_scrollbar):
            for hwnd in reversed(self.z_order):
                win = self.windows.get(hwnd)
                if win and win.visible and not win.minimized and win.contains_point(*pos):
                    edge = self._get_resize_edge(win, *pos)
                    break
        cursor = None
        if edge:
            cursor = standard_cursor_image(self.RESIZE_CURSORS[edge])
        else:
            program, cursor = (self._program_cursor(pos)
                               if not (self.dragging_window or self.dragging_scrollbar)
                               else (False, None))
            if not program:
                cursor = standard_cursor_image(winapi.WinAPIHandler.IDC_ARROW)
            elif cursor is not None and 'system' in cursor:
                cursor = standard_cursor_image(cursor['system'])
        key = ('hidden',) if cursor is None else ('custom', id(cursor))
        if key == self.current_cursor:
            return
        self.current_cursor = key
        try:
            pygame.mouse.set_visible(key[0] != 'hidden')
            if key[0] == 'custom':
                cached = self.cursor_cache.get(key[1])
                if cached is None or cached[0] is not cursor:
                    surface = pygame.image.frombuffer(cursor['rgba'], cursor['size'],
                                                      'RGBA').copy()
                    cached = (cursor, pygame.cursors.Cursor(cursor['hotspot'], surface))
                    if len(self.cursor_cache) >= 64:
                        self.cursor_cache.clear()
                    self.cursor_cache[key[1]] = cached
                pygame.mouse.set_cursor(cached[1])
        except (pygame.error, AttributeError, TypeError, ValueError):
            pass  # The video driver may not support (color) cursors

    def _is_app_window(self, hwnd):
        """True if hwnd is an emulated application window with a WndProc.

        Once the owning process has exited, its windows are dead: nothing
        consumes their messages, so they are treated as plain windows again
        (X click hides directly, input is no longer forwarded).
        """
        win = self.windows.get(hwnd)
        owner = win.owner if win else None
        if owner is None or owner.process_exited or hwnd in self.consoles:
            return False
        return bool(owner._find_wndproc_for_hwnd(hwnd)) or hwnd in owner.dialogs

    def client_origin(self, win):
        """Screen coordinates of a window's client area origin."""
        if win.parent in self.windows:
            px, py = self.client_origin(self.windows[win.parent])
            border = self._child_border(win)
            return (px + win.x + border, py + win.y + border)
        border, caption = self.window_frame(win)
        top = win.y + border + caption
        if win.menu:
            top += self.MENU_H
        return (win.x + border, top)

    def client_size(self, win):
        """Client area size (width, height) of a window."""
        if win.parent in self.windows:
            border = self._child_border(win)
            return (max(0, win.width - 2 * border), max(0, win.height - 2 * border))
        border, caption = self.window_frame(win)
        height = win.height - 2 * border - caption
        if win.menu:
            height -= self.MENU_H
        return (max(0, win.width - 2 * border), max(0, height))

    @classmethod
    def frame_size(cls, style, dialog=False):
        """(border, caption height) of a top-level window with this style.
        Overlapped windows always have a caption; pop-ups only with WS_CAPTION."""
        if not style & cls.WS_POPUP or style & cls.WS_CAPTION == cls.WS_CAPTION:
            return cls.BORDER, cls.TITLE_BAR_H
        if style & (cls.WS_DLGFRAME | cls.WS_THICKFRAME) or (dialog and
                                                             style & cls.DS_MODALFRAME):
            return cls.BORDER, 0
        if style & cls.WS_BORDER:
            return 1, 0
        return 0, 0

    def window_frame(self, win):
        """(border, caption height) of a top-level window"""
        return self.frame_size(win.style, win.is_dialog)

    def _fullscreen_window(self):
        """The topmost visible window if it covers the whole screen, else None"""
        for hwnd in reversed(self.z_order):
            win = self.windows.get(hwnd)
            if win is None or not win.visible or win.minimized:
                continue
            if (win.x <= 0 and win.y <= 0 and win.x + win.width >= self.width
                    and win.y + win.height >= self.height):
                return hwnd
            return None
        return None

    @gui_locked
    def set_display_mode(self, width, height, owner=None):
        """Change the fake desktop resolution (ChangeDisplaySettings); the GUI
        thread resizes the screen on its next frame"""
        self.display_mode_owner = owner
        if (width, height) == (self.width, self.height):
            return
        self.width, self.height = width, height
        self.pending_mode = (width, height)
        self.start_menu_open = False
        self.start_open_path = []
        self.desktop_menu = None
        for win in self.windows.values():
            if win.maximized and win.parent is None:
                win.x, win.y, win.width, win.height = 0, 0, width, height - 30
        log.info(f"Display mode changed to {width}x{height}")

    @staticmethod
    def _child_border(win):
        """Frame width of a child window: 1 with WS_BORDER or WS_EX_CLIENTEDGE"""
        return 1 if win.style & 0x00800000 or win.ex_style & 0x200 else 0

    def size_state(self, win):
        """(SIZE_RESTORED/MINIMIZED/MAXIMIZED, client width, client height) for WM_SIZE"""
        width, height = self.client_size(win)
        return (1 if win.minimized else 2 if win.maximized else 0, width, height)

    def _post_size_changes(self):
        """Post WM_SIZE for windows the user resized, maximized or minimized"""
        for hwnd, win in list(self.windows.items()):
            if win.size_state is None:
                continue  # The app has not been told a size yet
            state = self.size_state(win)
            if state != win.size_state:
                win.size_state = state
                if self._is_app_window(hwnd):
                    kind, width, height = state
                    win.owner.post_window_message(hwnd, win.owner.WM_SIZE, kind,
                                                  ((height & 0xFFFF) << 16) | (width & 0xFFFF))

    def _post_activation_changes(self):
        """Post WM_ACTIVATE when the active (not minimized) window changes"""
        active = self.active_window
        if active not in self.windows or self.windows[active].minimized:
            active = None
        previous = self.notified_active
        if active == previous:
            return
        self.notified_active = active
        if previous is not None and self._is_app_window(previous):
            owner = self.windows[previous].owner
            owner.post_window_message(previous, owner.WM_ACTIVATE, 0, active or 0)  # WA_INACTIVE
        if active is not None and self._is_app_window(active):
            owner = self.windows[active].owner
            owner.post_window_message(active, owner.WM_ACTIVATE, 1, previous or 0)  # WA_ACTIVE

    def _draw_child_windows(self, window):
        """Draw the visible child windows of window (inside its client area)"""
        parent_clip = self.screen.get_clip()
        for hwnd in window.children:
            child = self.windows.get(hwnd)
            if child is None or not child.visible:
                continue
            cx, cy = self.client_origin(child)
            cw, ch = self.client_size(child)
            border = self._child_border(child)
            frame = pygame.Rect(cx - border, cy - border, cw + 2 * border, ch + 2 * border)
            self.screen.set_clip(frame.clip(parent_clip))
            if border:
                pygame.draw.rect(self.screen, (0, 0, 0), frame, border)
            content = pygame.Rect(cx, cy, cw, ch)
            pygame.draw.rect(self.screen, child.bg_color, content)
            self.screen.set_clip(content.clip(parent_clip))
            if child.native:
                self._draw_native(child, cx, cy, cw, ch)
            for shape in child.drawn_shapes:
                self._draw_shape(shape, cx, cy)
            for control in child.controls:
                self._draw_control(control, cx, cy)
            self._draw_child_windows(child)
        self.screen.set_clip(parent_clip)

    def _client_point(self, win, x, y):
        """Convert screen coordinates to a window's client coordinates."""
        ox, oy = self.client_origin(win)
        return (x - ox, y - oy)

    SS_NOTIFY = 0x100

    def control_origin(self, control):
        """Screen coordinates of a control's client area origin, or None"""
        parent = self.windows.get(control.parent_hwnd)
        if parent is None:
            return None
        px, py = self.client_origin(parent)
        return (px + control.x, py + control.y)

    def _notify_static_at(self, win, x, y):
        """Visible SS_NOTIFY static control at screen point (x, y), or None.
        Other statics are transparent to the mouse (HTTRANSPARENT)."""
        ox, oy = self.client_origin(win)
        for control in win.controls:
            if (control.visible and control.class_name == 'STATIC'
                    and control.style & self.SS_NOTIFY
                    and ox + control.x <= x < ox + control.x + control.width
                    and oy + control.y <= y < oy + control.y + control.height):
                return control
        return None

    def _mouse_target(self, win, x, y):
        """(hwnd, client x, client y) of the mouse message for screen point (x, y)
        in an application window: an SS_NOTIFY static under it gets its own
        messages, like in Windows; else the window itself"""
        control = None if win.is_dialog else self._notify_static_at(win, x, y)
        if control is not None:
            cx, cy = self.control_origin(control)
            return control.hwnd, x - cx, y - cy
        cx, cy = self._client_point(win, x, y)
        return win.hwnd, cx, cy

    # Upper bound for a retained display list (oldest shapes are dropped)
    MAX_SHAPES = 20000

    @staticmethod
    def covers_area(shape, width, height):
        """True if shape is an opaque rect hiding everything in a width x height area"""
        return PseudoWindowsGUI.covers_rect(shape, (0, 0, width, height))

    @staticmethod
    def covers_rect(shape, area):
        """True if shape opaquely hides everything in area (left, top, right, bottom)"""
        if shape['type'] == 'image':
            if shape.get('rop') not in (0x00CC0020, 0x00330008):  # SRCCOPY, NOTSRCCOPY
                return False
            (left, top), (w, h) = shape['pos'], shape['size']
            right, bottom = left + w, top + h
        elif shape['type'] != 'rect' or shape.get('fill') is None:
            return False
        else:
            left, top, right, bottom = shape['rect']
        return left <= area[0] and top <= area[1] and right >= area[2] and bottom >= area[3]

    @gui_locked
    def add_shape(self, hwnd, shape):
        """Append a GDI shape to a window's display list (emu thread)."""
        win = self.windows.get(hwnd)
        if win is None:
            control = self.controls.get(hwnd)
            if control is not None:
                if self.covers_area(shape, control.width, control.height):
                    control.drawn_shapes = [shape]
                else:
                    control.drawn_shapes = self.add_to_display_list(
                        control.drawn_shapes, shape)[-self.MAX_SHAPES:]
            return
        # New list objects keep the GUI thread's current snapshot intact
        if self.covers_area(shape, *self.client_size(win)):
            win.drawn_shapes = [shape]
            return
        shapes = self.add_to_display_list(win.drawn_shapes, shape)
        if len(shapes) > self.FLATTEN_SHAPES:
            flat = self._flatten_shapes(win, shapes)
            if flat is not None:
                shapes = [flat]
        if len(shapes) > self.MAX_SHAPES:
            shapes = shapes[-(self.MAX_SHAPES // 2):]
        win.drawn_shapes = shapes

    # Longer window display lists are rasterized into one image shape, so
    # partially overlapping game updates don't slow every frame down
    FLATTEN_SHAPES = 256

    def _flatten_shapes(self, win, shapes):
        """Client-area image shape showing shapes over the window background, or None"""
        width, height = self.client_size(win)
        if width <= 0 or height <= 0:
            return None
        surface = pygame.Surface((width, height))
        surface.fill(win.bg_color)
        for shape in shapes:
            self._draw_shape(shape, 0, 0, surface)
        to_bytes = getattr(pygame.image, 'tobytes', None) or pygame.image.tostring
        rop = winapi.WinAPIHandler.SRCCOPY
        return {'type': 'image', 'pos': (0, 0), 'dim': (width, height),
                'size': (width, height), 'data': to_bytes(surface, 'RGB'), 'rop': rop,
                '_surface': (((width, height), rop), surface)}

    # Only this many recent entries are checked for being hidden by a new shape
    HIDDEN_SCAN = 1024

    @staticmethod
    def shape_bbox(shape):
        """(left, top, right, bottom) a display list entry can paint, or None"""
        stype = shape['type']
        if 'rect' in shape:
            l, t, r, b = shape['rect']
            return (min(l, r), min(t, b), max(l, r), max(t, b))
        if stype == 'image':
            (x, y), (w, h) = shape['pos'], shape['size']
            return (x, y, x + w, y + h)
        if stype == 'pixel':
            x, y = shape['pos']
            return (x, y, x + 1, y + 1)
        if stype == 'text':
            x, y = shape['pos']
            height = (shape.get('font') or {}).get('height', 16)
            return (x, y, x + len(shape['text']) * height, y + height * 2)
        points = shape.get('points') or [p for p in (shape.get('from'), shape.get('to')) if p]
        if not points:
            return None
        pad = (shape['pen'][1] if shape.get('pen') else 1) + 1
        xs, ys = [p[0] for p in points], [p[1] for p in points]
        return (min(xs) - pad, min(ys) - pad, max(xs) + pad, max(ys) + pad)

    @classmethod
    def add_to_display_list(cls, shapes, shape):
        """shapes plus shape, without recent entries the new shape fully hides
        (keeps redraw-in-place game loops from growing the list)"""
        cover = None
        if shape['type'] == 'rect' and shape.get('fill') is not None:
            cover = cls.shape_bbox(shape)
        elif shape['type'] == 'image' and shape.get('rop') in (0x00CC0020, 0x00330008):
            cover = cls.shape_bbox(shape)
        same_text = shape['type'] == 'text' and shape.get('bk') is not None
        if cover is None and not same_text:
            shapes.append(shape)  # Cheap path: most shapes hide nothing
            return shapes

        def hidden(old):
            if same_text:
                return old['type'] == 'text' and old['pos'] == shape['pos'] and \
                    len(old['text']) <= len(shape['text']) and old.get('font') == shape.get('font')
            box = cls.shape_bbox(old)
            return box is not None and box[0] >= cover[0] and box[1] >= cover[1] and \
                box[2] <= cover[2] and box[3] <= cover[3]

        split = max(0, len(shapes) - cls.HIDDEN_SCAN)
        return shapes[:split] + [s for s in shapes[split:] if not hidden(s)] + [shape]

    @gui_locked
    def clear_drawings(self, hwnd):
        """Reset a window's display list (start of a paint cycle).

        A new empty list is assigned instead of clearing in place, so the GUI
        thread can safely keep iterating a snapshot it already picked up.
        """
        if hwnd in self.windows:
            self.windows[hwnd].drawn_shapes = []
        elif hwnd in self.controls:
            self.controls[hwnd].drawn_shapes = []

    # ==================== MENU BAR ====================

    def _menu_bar_rect(self, win):
        """Screen rect of a window's menu bar strip (or None)."""
        if not win.menu:
            return None
        border, caption = self.window_frame(win)
        return pygame.Rect(win.x + border,
                           win.y + border + max(0, caption - 3),
                           win.width - 2 * border,
                           self.MENU_H)

    def _menu_item_rects(self, win):
        """Screen rects of the top-level menu items (computed, not cached)."""
        bar = self._menu_bar_rect(win)
        if bar is None:
            return []
        rects = []
        x = bar.x + 4
        for item in win.menu:
            text_w = self.font.size(item['text'])[0]
            width = text_w + 16
            rects.append(pygame.Rect(x, bar.y, width, bar.height))
            x += width
        return rects

    def _menu_dropdown_rects(self, win, index):
        """Dropdown rect and item rects of an open top-level menu."""
        item_rects = self._menu_item_rects(win)
        if index >= len(item_rects):
            return None, []
        top_rect = item_rects[index]
        items = win.menu[index].get('items') or []

        width = 100
        for sub in items:
            if sub.get('text'):
                shortcut_w = (self.font.size(sub['shortcut'])[0] + 24
                              if sub.get('shortcut') else 0)
                width = max(width, self.font.size(sub['text'])[0] + 32 + shortcut_w)

        item_h = 20
        sep_h = 7
        height = sum(sep_h if sub.get('separator') else item_h for sub in items) + 4

        drop = pygame.Rect(top_rect.x, top_rect.bottom, width, height)
        rects = []
        y = drop.y + 2
        for sub in items:
            h = sep_h if sub.get('separator') else item_h
            rects.append(pygame.Rect(drop.x + 2, y, width - 4, h))
            y += h
        return drop, rects

    @staticmethod
    def _make_lparam(cx, cy):
        """Pack client x/y into an lParam (LOWORD=x, HIWORD=y)."""
        return ((cy & 0xFFFF) << 16) | (cx & 0xFFFF)

    def _post_control_command(self, win, control, notify_code):
        """Notify a window's WndProc about a control event via WM_COMMAND."""
        parent_hwnd = control.parent_hwnd or win.hwnd
        wParam = ((notify_code & 0xFFFF) << 16) | (control.control_id & 0xFFFF)
        self.winapi.post_window_message(parent_hwnd, self.winapi.WM_COMMAND,
                                        wParam, control.hwnd)

    # ==================== SCROLLBAR CONTROLS ====================

    SCROLL_BTN = 16       # Arrow button length (pixels)
    SCROLL_MIN_THUMB = 12  # Minimum thumb length

    def _scrollbar_metrics(self, control, abs_x, abs_y):
        """Geometry of a scrollbar control at its absolute screen position.

        Returns a dict with 'vertical', arrow rects 'up'/'down', 'track' and
        'thumb' rects, plus 'track_len' and 'thumb_len' along the scroll axis.
        """
        vertical = bool(control.style & 0x0001)  # SBS_VERT
        length = control.height if vertical else control.width
        btn = min(self.SCROLL_BTN, max(0, length // 2))
        track_len = max(1, length - 2 * btn)

        span = 1
        pos_max = control.scroll_max
        if self.winapi:
            pos_max = self.winapi.scroll_pos_max(control)
        span = max(1, pos_max - control.scroll_min)

        # Thumb length: proportional when a page size is set
        if control.scroll_page > 0:
            content = max(1, control.scroll_max - control.scroll_min + 1)
            thumb_len = int(track_len * control.scroll_page / content)
        else:
            thumb_len = self.SCROLL_MIN_THUMB
        thumb_len = max(self.SCROLL_MIN_THUMB, min(thumb_len, track_len))

        frac = (control.scroll_pos - control.scroll_min) / span
        frac = max(0.0, min(1.0, frac))
        thumb_off = int((track_len - thumb_len) * frac)

        if vertical:
            up = pygame.Rect(abs_x, abs_y, control.width, btn)
            down = pygame.Rect(abs_x, abs_y + control.height - btn,
                               control.width, btn)
            track = pygame.Rect(abs_x, abs_y + btn, control.width, track_len)
            thumb = pygame.Rect(abs_x, abs_y + btn + thumb_off,
                                control.width, thumb_len)
        else:
            up = pygame.Rect(abs_x, abs_y, btn, control.height)
            down = pygame.Rect(abs_x + control.width - btn, abs_y,
                               btn, control.height)
            track = pygame.Rect(abs_x + btn, abs_y, track_len, control.height)
            thumb = pygame.Rect(abs_x + btn + thumb_off, abs_y,
                                thumb_len, control.height)

        return {'vertical': vertical, 'up': up, 'down': down, 'track': track,
                'thumb': thumb, 'track_len': track_len, 'thumb_len': thumb_len,
                'span': span, 'pos_max': pos_max}

    def _scrollbar_abs_pos(self, control):
        """Absolute screen position of a scrollbar control, or None"""
        win = self.windows.get(control.parent_hwnd)
        if not win or not win.visible or win.minimized:
            return None
        content_x, content_y = self.client_origin(win)
        return (content_x + control.x, content_y + control.y)

    def _post_scroll(self, control, code, pos):
        """Post WM_VSCROLL/WM_HSCROLL for a scrollbar control to its parent."""
        if not self.winapi or not control.parent_hwnd:
            return
        vertical = bool(control.style & 0x0001)
        msg = self.winapi.WM_VSCROLL if vertical else self.winapi.WM_HSCROLL
        wparam = (code & 0xFFFF) | ((pos & 0xFFFF) << 16)
        self.winapi.post_window_message(control.parent_hwnd, msg,
                                        wparam, control.hwnd)

    def _scroll_by(self, control, delta, code):
        """Move a scrollbar by delta positions and notify the parent."""
        pos_max = self.winapi.scroll_pos_max(control) if self.winapi \
            else control.scroll_max
        new_pos = max(control.scroll_min, min(control.scroll_pos + delta, pos_max))
        control.scroll_pos = new_pos
        self._post_scroll(control, code, new_pos)

    def _handle_scrollbar_click(self, control, x, y, abs_x, abs_y):
        """Handle a left click inside a scrollbar control."""
        winapi = self.winapi
        if not winapi:
            return
        m = self._scrollbar_metrics(control, abs_x, abs_y)
        page = control.scroll_page if control.scroll_page > 0 else 10

        if m['up'].collidepoint(x, y):
            self._scroll_by(control, -1, winapi.SB_LINEUP)
        elif m['down'].collidepoint(x, y):
            self._scroll_by(control, 1, winapi.SB_LINEDOWN)
        elif m['thumb'].collidepoint(x, y):
            grab = (y - m['thumb'].y) if m['vertical'] else (x - m['thumb'].x)
            self.dragging_scrollbar = (control.hwnd, grab)
        elif m['track'].collidepoint(x, y):
            before = (y < m['thumb'].y) if m['vertical'] else (x < m['thumb'].x)
            if before:
                self._scroll_by(control, -page, winapi.SB_PAGEUP)
            else:
                self._scroll_by(control, page, winapi.SB_PAGEDOWN)

    def _drag_scrollbar_to(self, pos):
        """Track a scrollbar thumb drag (SB_THUMBTRACK)."""
        hwnd, grab = self.dragging_scrollbar
        control = self.controls.get(hwnd)
        if not control or not self.winapi:
            self.dragging_scrollbar = None
            return
        abs_pos = self._scrollbar_abs_pos(control)
        if abs_pos is None:
            self.dragging_scrollbar = None
            return
        m = self._scrollbar_metrics(control, abs_pos[0], abs_pos[1])
        slide = m['track_len'] - m['thumb_len']
        if slide <= 0:
            return
        coord = pos[1] if m['vertical'] else pos[0]
        track_start = m['track'].y if m['vertical'] else m['track'].x
        frac = (coord - grab - track_start) / slide
        frac = max(0.0, min(1.0, frac))
        new_pos = control.scroll_min + int(round(frac * m['span']))
        if new_pos != control.scroll_pos:
            control.scroll_pos = new_pos
            self._post_scroll(control, self.winapi.SB_THUMBTRACK, new_pos)

    def _end_scrollbar_drag(self):
        """Finish a thumb drag: SB_THUMBPOSITION then SB_ENDSCROLL."""
        hwnd, _ = self.dragging_scrollbar
        self.dragging_scrollbar = None
        control = self.controls.get(hwnd)
        if control and self.winapi:
            self._post_scroll(control, self.winapi.SB_THUMBPOSITION,
                              control.scroll_pos)
            self._post_scroll(control, self.winapi.SB_ENDSCROLL, 0)

    def _post_button_command(self, win, control):
        """Notify a window's WndProc that one of its buttons was clicked."""
        self._post_control_command(win, control, self.winapi.BN_CLICKED)

    def _check_auto_radio(self, win, control):
        """Check a BS_AUTORADIOBUTTON and uncheck the other radio buttons of its
        group (controls from a WS_GROUP control up to the next one)"""
        WS_GROUP = 0x00020000
        controls = win.controls
        index = controls.index(control)
        first = index
        while first > 0 and not controls[first].style & WS_GROUP:
            first -= 1
        last = index + 1
        while last < len(controls) and not controls[last].style & WS_GROUP:
            last += 1
        for other in controls[first:last]:
            if other.class_name == "CHECKBOX" and (other.style & 0xF) == 0x9:
                other.checked = other is control

    def _handle_combo_click(self, pos, button):
        """Handle clicks while a combobox dropdown is open.

        Returns True if the click was consumed by the dropdown.
        """
        control = self.controls.get(self.open_combo)
        if not control:
            self.open_combo = None
            return False

        drop, item_rects = self._combo_dropdown_rects(control)
        if drop is not None and drop.collidepoint(pos):
            if button == 1:
                for i, rect in enumerate(item_rects):
                    if rect.collidepoint(pos):
                        control.sel_index = i
                        if control.style & 0x3 in (1, 2):
                            control.text = control.items[i]
                            control.select_all()
                        self.open_combo = None
                        win = self.windows.get(control.parent_hwnd)
                        if win and self.winapi:
                            self._post_control_command(win, control,
                                                       self.winapi.CBN_SELCHANGE)
                        return True
            return True  # Click inside dropdown chrome: swallow

        # Click elsewhere: close the dropdown, then process the click normally
        self.open_combo = None
        return False

    def _capture_target(self):
        """Window that currently captures the mouse (SetCapture), or None."""
        if not self.winapi:
            return None
        cap = self.winapi.capture_hwnd
        if cap and cap in self.windows and self._is_app_window(cap):
            return self.windows[cap]
        return None

    def _forward_mouse_move(self, pos, buttons):
        """Forward WM_MOUSEMOVE to the captured or hovered app window."""
        if not self.winapi:
            return
        x, y = pos
        wparam = 0
        if buttons[0]:
            wparam |= self.winapi.MK_LBUTTON
        if buttons[2]:
            wparam |= self.winapi.MK_RBUTTON

        # Mouse capture: every move goes to the capturing window
        win = self._capture_target()
        if win is not None:
            target, cx, cy = win.hwnd, *self._client_point(win, x, y)
        else:
            # Otherwise: topmost visible app window under the cursor
            for hwnd in reversed(self.z_order):
                w = self.windows.get(hwnd)
                if w and w.visible and not w.minimized and w.contains_point(x, y):
                    if w.is_dialog or not self._is_app_window(hwnd):
                        return
                    if y < self.client_origin(w)[1]:
                        return  # title bar / menu bar / chrome
                    win = w
                    break
            if win is None:
                return
            target, cx, cy = self._mouse_target(win, x, y)
            child = self.windows.get(self.child_at(win.hwnd, x, y))
            if not (child is not None and child is not win and self._is_app_window(child.hwnd)):
                child = None
            # Without capture the (deepest) window under the mouse chooses the
            # cursor first: WM_SETCURSOR goes to it, its DefWindowProc asks the
            # parents, then its own class cursor is shown
            cursor_hwnd = child.hwnd if child is not None else win.hwnd
            self.winapi.post_window_message(
                cursor_hwnd, self.winapi.WM_SETCURSOR, cursor_hwnd,
                (self.winapi.WM_MOUSEMOVE << 16) | self.winapi.HTCLIENT)
            if child is not None:
                if child.native:
                    return  # Emulated controls don't track the mouse without capture
                target = child.hwnd
                cx, cy = self._client_point(child, x, y)
        self.winapi.post_window_message(target, self.winapi.WM_MOUSEMOVE,
                                        wparam, self._make_lparam(cx, cy))

    def _forward_mouse_up(self, pos, button):
        """Forward a mouse-button release to the app window under the cursor."""
        if not self.winapi:
            return
        x, y = pos

        # Mouse capture: the release always goes to the capturing window
        win = self._capture_target()
        if win is not None:
            cx, cy = self._client_point(win, x, y)
            lparam = self._make_lparam(cx, cy)
            if button == 1:
                self.winapi.post_window_message(win.hwnd, self.winapi.WM_LBUTTONUP,
                                                0, lparam)
            elif button == 3:
                self.winapi.post_window_message(win.hwnd, self.winapi.WM_RBUTTONUP,
                                                0, lparam)
            return

        for hwnd in reversed(self.z_order):
            win = self.windows.get(hwnd)
            if win and win.visible and not win.minimized and win.contains_point(x, y):
                if win.is_dialog or not self._is_app_window(hwnd):
                    return
                if y < self.client_origin(win)[1]:
                    return  # title bar / menu bar / chrome, not client area
                target, cx, cy = self._mouse_target(win, x, y)
                child = self.windows.get(self.child_at(hwnd, x, y))
                if child is not None and child is not win and self._is_app_window(child.hwnd):
                    target = child.hwnd
                    cx, cy = self._client_point(child, x, y)
                lparam = self._make_lparam(cx, cy)
                if button == 1:
                    self.winapi.post_window_message(target, self.winapi.WM_LBUTTONUP, 0, lparam)
                elif button == 3:
                    self.winapi.post_window_message(target, self.winapi.WM_RBUTTONUP, 0, lparam)
                return

    def _handle_menu_click(self, pos, button):
        """Handle clicks while a dropdown menu is open.

        Returns True if the click was consumed by the menu system.
        """
        root = self._menu_root()
        if root is None:
            self.open_menu = None
            return False
        items, x, y, win = root
        hit = self._menu_panels_click(self._menu_panels(items, x, y, self.menu_path), pos)
        if hit is not None:
            if button == 1 and hit[0] == 'command':
                self.open_menu = None
                self.menu_path = []
                if self.winapi:
                    # Menu WM_COMMAND: HIWORD(wParam)=0, LOWORD=menu id
                    self.winapi.post_window_message(win.hwnd, self.winapi.WM_COMMAND,
                                                    hit[1] & 0xFFFF, 0)
            elif hit[0] == 'submenu':
                self.menu_path = self.menu_path[:hit[1]] + [hit[2]]
            return True

        # Clicking another top-level item switches the open dropdown
        for i, rect in enumerate(self._menu_item_rects(win)):
            if rect.collidepoint(pos):
                self._activate_menu_item(win, i)
                return True

        # Click elsewhere: close the menu, then process the click normally
        self.open_menu = None
        self.menu_path = []
        return False

    def _activate_menu_item(self, win, index):
        """Open a dropdown or fire a plain top-level menu item"""
        item = win.menu[index]
        self.menu_path = []
        if item.get('items') is not None:
            # Toggle dropdown; the program may fill it in now (WM_INITMENUPOPUP)
            if self.open_menu == (win.hwnd, index):
                self.open_menu = None
            else:
                self.open_menu = (win.hwnd, index)
                self._post_init_menu(win, item.get('hmenu', 0), index)
        else:
            self.open_menu = None
            if self.winapi:
                self.winapi.post_window_message(
                    win.hwnd, self.winapi.WM_COMMAND, item['id'] & 0xFFFF, 0)

    def _handle_mouse_click(self, pos, button):
        """Handle mouse click"""
        x, y = pos
        if button == 1:
            self.prev_click, self.last_click = (self.last_click,
                                                (pygame.time.get_ticks(), pos, None))

        # The desktop right-click menu closes on any click
        if self.desktop_menu and self._handle_desktop_menu_click(pos, button):
            return

        # The Start menu grabs clicks first
        if self._handle_start_menu_click(pos, button):
            return

        # A popup menu (TrackPopupMenu) is modal: it gets every click
        if self.popup_menu is not None:
            self._handle_popup_menu_click(pos, button)
            return

        # An open dropdown menu grabs clicks first
        if self.open_menu and self._handle_menu_click(pos, button):
            return

        # An open ComboBoxEx list closes on any click (choosing an item or not)
        if self.open_native_combo and self._handle_native_combo_click(pos):
            return

        # An open combobox dropdown grabs clicks next
        if self.open_combo and self._handle_combo_click(pos, button):
            return

        # Click on taskbar windows (a full-screen window covers the taskbar)
        if y >= self.height - self.TASKBAR_H and self._fullscreen_window() is None:
            self._handle_taskbar_click(pos, button)
            return

        self.selected_icon = None  # The desktop click below selects again
        
        # Check windows in reverse order (topmost first)
        for hwnd in reversed(self.z_order):
            if hwnd in self.windows:
                win = self.windows[hwnd]
                if win.visible and not win.minimized and win.contains_point(x, y):
                    # Make window active and bring to front
                    self.active_window = hwnd
                    self.z_order.remove(hwnd)
                    self.z_order.append(hwnd)
                    border, caption = self.window_frame(win)
                    
                    # Caption buttons (the rects they are drawn at; dialogs only have close)
                    buttons = self._caption_button_rects(win) if caption else {}
                    if 'close' in buttons and buttons['close'].collidepoint(x, y):
                        self._close_window(hwnd)
                        return
                    if 'max' in buttons and buttons['max'].collidepoint(x, y):
                        win.maximize(self.width, self.height, self.TASKBAR_H)
                        return
                    if 'min' in buttons and buttons['min'].collidepoint(x, y):
                        win.minimize()
                        self._activate_next_window()
                        return

                    # Edge/corner resizing (left button only)
                    if button == 1:
                        edge = self._get_resize_edge(win, x, y)
                        if edge:
                            self.resizing_window = hwnd
                            self.resize_edge = edge
                            self.resize_start_mouse = (x, y)
                            self.resize_start_rect = (win.x, win.y, win.width, win.height)
                            return

                    # Title bar click: a double click maximizes / restores,
                    # otherwise dragging starts (if not maximized)
                    if caption and win.y + border <= y <= win.y + caption:
                        if (button == 1 and not win.is_dialog
                                and self._double_click(('title', hwnd))):
                            self.dragging_window = None
                            win.maximize(self.width, self.height, self.TASKBAR_H)
                            return
                        if not win.maximized:
                            self.dragging_window = hwnd
                            self.drag_offset_x = x - win.x
                            self.drag_offset_y = y - win.y
                        return

                    # Menu bar click
                    if win.menu and button == 1:
                        for i, rect in enumerate(self._menu_item_rects(win)):
                            if rect.collidepoint(x, y):
                                self._activate_menu_item(win, i)
                                return
                        bar = self._menu_bar_rect(win)
                        if bar and bar.collidepoint(x, y):
                            return  # Empty menu bar area: swallow the click

                    # The deepest child window under the mouse gets the click
                    target = self.windows.get(self.child_at(hwnd, x, y), win)
                    if target is not win and target.native is None:
                        self.focused_control = None
                    content_x, content_y = self.client_origin(target)
                    if target is not win and y < content_y:
                        return
                    for control in target.controls:
                        if not (control.visible and control.enabled):
                            continue
                        ctrl_x = content_x + control.x
                        ctrl_y = content_y + control.y
                        # A combobox only occupies its closed box; the
                        # CreateWindow height includes the dropdown area
                        ctrl_h = control.height
                        if control.class_name == "COMBOBOX":
                            ctrl_h = min(control.height, 24)
                        if not (ctrl_x <= x <= ctrl_x + control.width and
                                ctrl_y <= y <= ctrl_y + ctrl_h):
                            continue

                        if control.class_name == "STATIC":
                            if not control.style & self.SS_NOTIFY:
                                continue  # Transparent: the click goes to what is below
                            # The static gets the click, its parent STN_CLICKED
                            if button in (1, 3) and self._is_app_window(hwnd):
                                if not win.is_dialog:
                                    message, mk = ((self.winapi.WM_LBUTTONDOWN,
                                                    self.winapi.MK_LBUTTON) if button == 1 else
                                                   (self.winapi.WM_RBUTTONDOWN,
                                                    self.winapi.MK_RBUTTON))
                                    self.winapi.post_window_message(
                                        control.hwnd, message, mk,
                                        self._make_lparam(x - ctrl_x, y - ctrl_y))
                                if button == 1:
                                    self._post_control_command(win, control, 0)  # STN_CLICKED
                            return

                        if control.class_name == "BUTTON":
                            if (control.style & 0xF) == 7:
                                continue  # A group box lets clicks through to its buttons
                            # Clicking a button takes focus away from edits
                            self.focused_control = None
                            # If dialog window (MessageBox) - OK/Cancel button closes it
                            if hwnd in self.messageboxes:
                                self._messagebox_done(hwnd, getattr(control, 'mb_result', 1))
                                return
                            if win.is_dialog and not self._is_app_window(hwnd):
                                self._close_window(hwnd)
                                return
                            # Normal window - notify WndProc with WM_COMMAND
                            if button == 1 and self.winapi:
                                self._post_button_command(win, control)
                            return
                        elif control.class_name == "EDIT":
                            # Give keyboard focus to the edit control, the caret
                            # goes where it was clicked
                            if button == 1:
                                self.focused_control = control.hwnd
                                offset = self._edit_caret_from_x(control, x - ctrl_x,
                                                                 y - ctrl_y)
                                shift = pygame.key.get_mods() & pygame.KMOD_SHIFT
                                control.set_selection(control.sel_anchor if shift else offset,
                                                      offset)
                            return
                        elif control.class_name == "CHECKBOX":
                            if button == 1:
                                self.focused_control = None
                                # BS_AUTOCHECKBOX (0x3) toggles by itself
                                if (control.style & 0xF) == 0x3:
                                    control.checked = not control.checked
                                elif (control.style & 0xF) == 0x9:  # BS_AUTORADIOBUTTON
                                    self._check_auto_radio(win, control)
                                if self.winapi:
                                    self._post_button_command(win, control)
                            return
                        elif control.class_name == "LISTBOX":
                            if button in (4, 5):  # Mouse wheel
                                rows = max(1, (control.height - 2) // self.LISTBOX_ITEM_H)
                                step = 3 if button == 5 else -3
                                control.top_index = max(0, min(control.top_index + step,
                                                               len(control.items) - rows))
                            elif button == 1:
                                self.focused_control = None
                                index = ((y - ctrl_y - 1) // self.LISTBOX_ITEM_H
                                         + control.top_index)
                                if 0 <= index < len(control.items):
                                    control.sel_index = index
                                    if self.winapi:
                                        self._post_control_command(
                                            win, control, self.winapi.LBN_SELCHANGE)
                                        if self._double_click(('listbox', control.hwnd, index)):
                                            self._post_control_command(
                                                win, control, self.winapi.LBN_DBLCLK)
                            return
                        elif control.class_name == "COMBOBOX":
                            if (button == 1 and control.style & 0x3 in (1, 2) and
                                    x < ctrl_x + control.width - 18):
                                self.focused_control = control.hwnd  # Type into it
                                offset = self._edit_caret_from_x(control, x - ctrl_x)
                                shift = pygame.key.get_mods() & pygame.KMOD_SHIFT
                                control.set_selection(control.sel_anchor if shift else offset,
                                                      offset)
                                self.open_combo = None
                                return
                            if button == 1:
                                self.focused_control = None
                                # Toggle the dropdown list
                                if self.open_combo == control.hwnd:
                                    self.open_combo = None
                                else:
                                    self.open_combo = control.hwnd
                            return
                        elif control.class_name == "SCROLLBAR":
                            if button == 1:
                                self.focused_control = None
                                self._handle_scrollbar_click(control, x, y,
                                                             ctrl_x, ctrl_y)
                            return
                        # Other control types: swallow the click
                        return

                    # Clicking empty client area clears edit focus
                    if button == 1:
                        self.focused_control = None

                    # Child windows (emulated controls too) get their own mouse messages
                    if target is not win and self._is_app_window(target.hwnd):
                        self._post_mouse_down(target, x, y, button)
                        break

                    # No control hit -> forward raw mouse click to the WndProc
                    if (not win.is_dialog and y >= content_y and
                            self._is_app_window(hwnd)):
                        cx, cy = self._client_point(win, x, y)
                        lparam = self._make_lparam(cx, cy)
                        if button == 1:
                            self.winapi.post_window_message(
                                hwnd, self.winapi.WM_LBUTTONDOWN,
                                self.winapi.MK_LBUTTON, lparam)
                        elif button == 3:
                            self.winapi.post_window_message(
                                hwnd, self.winapi.WM_RBUTTONDOWN,
                                self.winapi.MK_RBUTTON, lparam)

                    break
        else:
            # No window under the mouse: the desktop gets the click
            if self._fullscreen_window() is None:
                self._handle_desktop_click(pos, button)
    
    def _post_mouse_down(self, target, x, y, button):
        """Post a button press (or wheel turn) to a child window at screen (x, y)"""
        api = target.owner
        cx, cy = self._client_point(target, x, y)
        lparam = self._make_lparam(cx, cy)
        if button == 1:
            message = (api.WM_LBUTTONDBLCLK if self._double_click(('child', target.hwnd))
                       else api.WM_LBUTTONDOWN)
            api.post_window_message(target.hwnd, message, api.MK_LBUTTON, lparam)
        elif button == 3:
            api.post_window_message(target.hwnd, api.WM_RBUTTONDOWN, api.MK_RBUTTON, lparam)
        elif button in (4, 5):
            delta = 120 if button == 4 else -120
            api.post_window_message(target.hwnd, api.WM_MOUSEWHEEL, (delta & 0xFFFF) << 16,
                                    self._make_lparam(x, y))

    def key_target(self):
        """Window that gets the keystrokes: the focused child window of the active
        window, else the active window"""
        focus = self.focused_window
        if (focus in self.windows and self.windows[focus].visible and
                self.top_level_of(focus) == self.active_window):
            return focus
        return self.active_window

    def _pygame_key_to_vk(self, event):
        """Map a Pygame key to a Windows virtual-key code, or None."""
        key = event.key
        if pygame.K_a <= key <= pygame.K_z:
            return key - 32            # 'a' (0x61) -> VK 'A' (0x41)
        if pygame.K_0 <= key <= pygame.K_9:
            return key                 # '0' (0x30) -> VK 0x30
        if pygame.K_F1 <= key <= pygame.K_F12:
            return 0x70 + (key - pygame.K_F1)
        special = {
            pygame.K_ESCAPE: 0x1B, pygame.K_RETURN: 0x0D, pygame.K_KP_ENTER: 0x0D,
            pygame.K_SPACE: 0x20, pygame.K_TAB: 0x09, pygame.K_BACKSPACE: 0x08,
            pygame.K_DELETE: 0x2E, pygame.K_LEFT: 0x25, pygame.K_UP: 0x26,
            pygame.K_RIGHT: 0x27, pygame.K_DOWN: 0x28, pygame.K_HOME: 0x24,
            pygame.K_END: 0x23, pygame.K_PAGEUP: 0x21, pygame.K_PAGEDOWN: 0x22,
            pygame.K_LSHIFT: 0x10, pygame.K_RSHIFT: 0x10,
            pygame.K_LCTRL: 0x11, pygame.K_RCTRL: 0x11,
            pygame.K_LALT: 0x12, pygame.K_RALT: 0x12,
        }
        return special.get(key)

    def _alt_f4(self):
        """Alt+F4 that reached the emulator only as a host window close request:
        send it to the active program window, or close an emulator window"""
        self.alt_combo = True
        hwnd = self.active_window
        if not hwnd or hwnd not in self.windows:
            return
        if self._is_app_window(hwnd):
            self.winapi.post_window_message(hwnd, self.winapi.WM_SYSKEYDOWN, 0x73, 0x20000001)
            self.winapi.post_window_message(hwnd, self.winapi.WM_SYSKEYUP, 0x73, 0xE0000001)
        else:
            self._close_window(hwnd)

    def _is_sys_key(self, vk):
        """Is this keystroke a system key (WM_SYSKEY*): F10 or with the left Alt,
        but not with Ctrl (Ctrl+Alt is AltGr)"""
        if self.key_states.get(0x11):
            return False
        return vk == 0x79 or self.alt_down  # VK_F10

    def _forward_key_up(self, vk, event=None):
        """Forward a key release (WM_KEYUP / WM_SYSKEYUP) to the active application window."""
        if not self.winapi:
            return
        hwnd = self.key_target()
        if not hwnd or not self._is_app_window(hwnd):
            return
        lparam = 0xC0000001  # Previous key state and transition state bits
        if event is not None and event.key == pygame.K_LALT:
            # Alt alone is a system key; after Alt+key its release is a plain key-up
            sys_key = not self.alt_combo and not self.key_states.get(0x11)
        else:
            sys_key = self._is_sys_key(vk)
        if sys_key and self.alt_down:
            lparam |= 0x20000000  # Context code: Alt is down
        message = self.winapi.WM_SYSKEYUP if sys_key else self.winapi.WM_KEYUP
        self.winapi.post_window_message(hwnd, message, vk, lparam)

    def _forward_key_to_window(self, event):
        """Forward a keystroke to the active application window's WndProc."""
        if not self.winapi:
            return
        hwnd = self.key_target()
        if not hwnd or not self._is_app_window(hwnd):
            return
        vk = self._pygame_key_to_vk(event)
        sys_key = self._is_sys_key(vk)
        lparam = 0x20000001 if sys_key and self.alt_down else 1  # Context code: Alt is down
        if vk is not None:
            message = self.winapi.WM_SYSKEYDOWN if sys_key else self.winapi.WM_KEYDOWN
            self.winapi.post_window_message(hwnd, message, vk, lparam)
        # Synthesize WM_CHAR / WM_SYSCHAR for printable input (TranslateMessage behavior)
        if event.unicode and len(event.unicode) == 1 and event.unicode.isprintable():
            message = self.winapi.WM_SYSCHAR if sys_key else self.winapi.WM_CHAR
            self.winapi.post_window_message(hwnd, message, ord(event.unicode), lparam)

    def _handle_key_press(self, event):
        """Handle keyboard key press"""
        # Escape closes popup menus, dropdown menus and ComboBoxEx lists first
        if event.key == pygame.K_ESCAPE and (self.popup_menu is not None or self.open_menu
                                             or self.open_native_combo):
            if self.popup_menu is not None:
                self.popup_menu['done'] = True
                self.popup_menu = None
            elif self.open_menu:
                self.open_menu = None
                self.menu_path = []
            else:
                self._handle_native_combo_click((-1, -1))
            return
        # Alt+F4 goes to the active window even from a console or an edit control
        if event.key == pygame.K_F4 and self.alt_down and self._is_sys_key(0x73):
            if self.active_window in self.windows and not self._is_app_window(self.active_window):
                self._close_window(self.active_window)  # Emulator window
            else:
                self._forward_key_to_window(event)
            return
        if self._messagebox_key(event):
            return

        # The active console window takes the line its program is waiting for
        console = self.consoles.get(self.active_window)
        if console is not None and console.input_active:
            if event.key in (pygame.K_RETURN, pygame.K_KP_ENTER):
                # Enter - input completed; it stays on screen like in a real console
                line = console.input
                console.input = ""
                self.console_write(console, line + "\n", "stdin")
                console.input_result = line
                console.input_active = False
                console.input_ready.set()  # Send signal to waiting thread
            elif event.key == pygame.K_BACKSPACE:
                # Backspace - delete last character
                console.input = console.input[:-1]
            elif event.key == pygame.K_ESCAPE:
                # ESC - clear the line being typed
                console.input = ""
            else:
                # Printable character
                if event.unicode and event.unicode.isprintable():
                    console.input += event.unicode
            return

        # A focused EDIT control consumes keystrokes
        if self._handle_edit_key(event):
            return

        # Otherwise forward the keystroke to the active application window
        self._forward_key_to_window(event)

    def _handle_edit_key(self, event):
        """Type into the focused EDIT control. Returns True if consumed."""
        control = self.controls.get(self.focused_control)
        if not control or not (control.class_name == "EDIT" or (
                control.class_name == "COMBOBOX" and control.style & 0x3 in (1, 2))):
            return False
        # Only edit when the parent window is visible and active
        win = self.windows.get(self.top_level_of(control.hwnd))
        if not win or not win.visible or win.minimized or win.hwnd != self.active_window:
            return False
        if not (control.visible and control.enabled):
            return False
        parent = self.windows.get(control.parent_hwnd)
        if (parent is not None and parent.native in ('COMBOBOXEX', 'LISTVIEW') and
                parent.owner is not None and
                event.key in (pygame.K_RETURN, pygame.K_KP_ENTER, pygame.K_ESCAPE)):
            # The (subclassed) edit control of a ComboBoxEx or a list view label ends the edit
            vk = 0x1B if event.key == pygame.K_ESCAPE else 0x0D
            parent.owner.post_window_message(control.hwnd, winapi.WinAPIHandler.WM_KEYDOWN, vk, 1)
            return True

        multiline = control.class_name == "EDIT" and control.style & 0x4  # ES_MULTILINE
        in_dialog = win.owner is not None and control.parent_hwnd in win.owner.dialogs
        if event.key in (pygame.K_RETURN, pygame.K_KP_ENTER) and multiline and (
                control.style & 0x1000 or not in_dialog):  # ES_WANTRETURN
            self._edit_insert(win, control, '\r\n')
            return True
        if event.key in (pygame.K_RETURN, pygame.K_KP_ENTER, pygame.K_ESCAPE, pygame.K_TAB):
            if in_dialog:
                return False  # The dialog handles them (default button, Cancel, next edit)
            self.focused_control = None
            return True
        self._edit_key(win, control, event)
        return True

    @staticmethod
    def _edit_word_boundary(text, offset, direction):
        """Offset of the previous (-1) or next (1) word start from offset"""
        if direction < 0:
            while offset > 0 and text[offset - 1].isspace():
                offset -= 1
            while offset > 0 and not text[offset - 1].isspace():
                offset -= 1
        else:
            while offset < len(text) and not text[offset].isspace():
                offset += 1
            while offset < len(text) and text[offset].isspace():
                offset += 1
        return offset

    def _edit_notify_change(self, win, control):
        """EN_CHANGE (CBN_EDITCHANGE for a combo box) after the user changed the text"""
        if win.owner is None:
            return
        parent = self.windows.get(control.parent_hwnd)
        if parent is not None and parent.native:
            return  # Edit of a common control (ComboBoxEx, list view label)
        self._post_control_command(win, control, 5 if control.class_name == "COMBOBOX"
                                   else 0x0300)

    def _edit_insert(self, win, control, text):
        """Type text into an edit control (replacing the selection)"""
        if control.class_name == "EDIT":
            if control.style & 0x800:  # ES_READONLY
                return
            if control.style & 0x2000 and not text.isdigit():  # ES_NUMBER
                return
            if control.style & 0x8:  # ES_UPPERCASE
                text = text.upper()
            elif control.style & 0x10:  # ES_LOWERCASE
                text = text.lower()
        if control.replace_selection(text):
            self._edit_notify_change(win, control)

    def _edit_key(self, win, control, event):
        """Caret movement, selection, deletion, clipboard and typing in an
        edit control (or the edit part of a combo box)"""
        text = control.text
        ctrl = bool(event.mod & pygame.KMOD_CTRL)
        shift = bool(event.mod & pygame.KMOD_SHIFT)
        readonly = control.class_name == "EDIT" and control.style & 0x800
        start, end = control.selection()
        caret = min(max(control.sel_caret, 0), len(text))
        lines = control.edit_lines()

        def move(offset):
            # Never stop between the CR and LF of a line break
            if 0 < offset < len(text) and text[offset - 1] == '\r' and text[offset] == '\n':
                offset += 1 if offset > caret else -1
            control.set_selection(control.sel_anchor if shift else offset, offset)

        def delete(first, last):
            if readonly or first == last:
                return
            control.set_selection(first, last)
            control.replace_selection('')
            self._edit_notify_change(win, control)

        key = event.key
        if key in (pygame.K_LEFT, pygame.K_RIGHT):
            step = -1 if key == pygame.K_LEFT else 1
            if start != end and not shift:
                offset = start if step < 0 else end
            elif ctrl:
                offset = self._edit_word_boundary(text, caret, step)
            else:
                offset = max(0, min(len(text), caret + step))
                if step < 0 and offset > 0 and text[offset - 1:offset + 1] == '\r\n':
                    offset -= 1
                elif step > 0 and text[caret:caret + 2] == '\r\n':
                    offset = caret + 2
            move(offset)
        elif key in (pygame.K_HOME, pygame.K_END):
            line_start, line_end = lines[control.line_of(caret)]
            if ctrl:
                offset = 0 if key == pygame.K_HOME else len(text)
            else:
                offset = line_start if key == pygame.K_HOME else line_end
            move(offset)
        elif key in (pygame.K_UP, pygame.K_DOWN) and len(lines) > 1:
            index = control.line_of(caret)
            target = index + (-1 if key == pygame.K_UP else 1)
            if 0 <= target < len(lines):
                column = caret - lines[index][0]
                move(min(lines[target][0] + column, lines[target][1]))
        elif key == pygame.K_BACKSPACE:
            if start != end:
                delete(start, end)
            elif ctrl:
                delete(self._edit_word_boundary(text, caret, -1), caret)
            elif caret > 0:
                delete(caret - 2 if text[caret - 2:caret] == '\r\n' else caret - 1, caret)
        elif key == pygame.K_DELETE:
            if start != end:
                if shift:  # Shift+Del: cut
                    winapi.WinAPIHandler.set_clipboard_text(text[start:end])
                delete(start, end)
            elif caret < len(text):
                delete(caret, caret + 2 if text[caret:caret + 2] == '\r\n' else caret + 1)
        elif ctrl and key == pygame.K_a:
            control.select_all()
        elif (ctrl and key in (pygame.K_c, pygame.K_x, pygame.K_INSERT)) and start != end:
            if not control.password_char:
                winapi.WinAPIHandler.set_clipboard_text(text[start:end])
                if key == pygame.K_x:
                    delete(start, end)
        elif (ctrl and key == pygame.K_v) or (shift and key == pygame.K_INSERT):
            pasted = winapi.WinAPIHandler.clipboard_text()
            if pasted:
                if not control.style & 0x4:
                    pasted = pasted.split('\r', 1)[0].split('\n', 1)[0]
                self._edit_insert(win, control, pasted)
        elif event.unicode and event.unicode.isprintable() and not ctrl:
            self._edit_insert(win, control, event.unicode)

    def _edit_caret_from_x(self, control, x, y=None):
        """Character offset nearest to a click at control-relative (x, y)"""
        font = self.font
        lines = control.edit_lines()
        index = 0
        if y is not None and control.style & 0x4 and len(lines) > 1:
            index = min(len(lines) - 1, max(0, control.edit_top_line +
                                            (y - 3) // font.get_linesize()))
        start, end = lines[index]
        shown = self._edit_display_text(control)
        target = x - 4 + control.edit_scroll
        best, best_d = start, abs(target)
        for offset in range(start, end + 1):
            d = abs(font.size(shown[start:offset])[0] - target)
            if d < best_d:
                best, best_d = offset, d
        return best

    @staticmethod
    def _edit_display_text(control):
        """Text as an edit control shows it (password characters)"""
        if control.password_char:
            return ''.join(c if c in '\r\n' else control.password_char for c in control.text)
        return control.text

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
        lines = text.replace('\r\n', '\n').split('\n')
        line_h = 18
        icon = (msg_type >> 4) & 0x7  # MB_ICONHAND, QUESTION, EXCLAMATION, ASTERISK
        text_x = 64 if icon in (1, 2, 3, 4) else 20
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
    
    @gui_locked
    def _close_window(self, hwnd, notify_app=True):
        """Close window.

        App windows with a WndProc get WM_CLOSE posted so the app decides
        (DestroyWindow / PostQuitMessage). Other windows are hidden directly.
        DestroyWindow calls this with notify_app=False to avoid a loop.
        """
        if hwnd not in self.windows:
            return

        box = self.messageboxes.get(hwnd)
        if box is not None:
            # Only a message box with a Cancel (or a lone OK) button can be closed
            if box['cancel'] is not None:
                self._messagebox_done(hwnd, box['cancel'])
            return

        console = self.consoles.get(hwnd)
        if console is not None:
            # Closing a console ends the program attached to it (like Windows)
            owner = self.windows[hwnd].owner
            if owner is not None:
                owner.request_termination()
            self.close_console(console)
            return

        if notify_app and self._is_app_window(hwnd):
            self.winapi.post_window_message(hwnd, self.winapi.WM_CLOSE, 0, 0)
            return

        self.windows[hwnd].visible = False
        if hwnd in self.z_order:
            self.z_order.remove(hwnd)
        if self.active_window == hwnd:
            self.active_window = self.z_order[-1] if self.z_order else None
        if self.open_menu and self.open_menu[0] == hwnd:
            self.open_menu = None
    
    @gui_locked
    def get_next_hwnd(self):
        """Get new HWND"""
        hwnd = self.next_hwnd
        self.next_hwnd += 4
        return hwnd
    
    @gui_locked
    def create_window(self, title, x, y, width, height, style=0, owner=None, parent=0):
        """Create new window (a child window if parent is a window handle)"""
        hwnd = self.get_next_hwnd()
        window = FakeWindow(hwnd, title, x, y, width, height, style)
        window.owner = owner
        # The title bar shows the owning program's EXE icon
        loader = getattr(getattr(owner, 'emu', None), 'pe_loader', None)
        window.icon_path = getattr(loader, 'filepath', None)
        self.windows[hwnd] = window
        if parent in self.windows:
            # Child windows are drawn inside their parent, not on the desktop
            window.parent = parent
            self.windows[parent].children.append(hwnd)
        else:
            self.z_order.append(hwnd)
        
        log.debug(f"GUI: Window created - HWND=0x{hwnd:08x}, '{title}'")
        return hwnd
    
    @gui_locked
    def create_control(self, parent_hwnd, class_name, text, x, y, width, height, style=0,
                       control_id=0, ex_style=0):
        """Create new control"""
        hwnd = self.get_next_hwnd()
        control = FakeControl(hwnd, class_name, text, x, y, width, height, style, ex_style)
        control.parent_hwnd = parent_hwnd
        control.control_id = control_id

        self.controls[hwnd] = control
        
        if parent_hwnd in self.windows:
            self.windows[parent_hwnd].controls.append(control)
        
        log.debug(f"GUI: Control created - HWND=0x{hwnd:08x}, {class_name}, '{text}'")
        return hwnd

    @gui_locked
    def destroy_control(self, hwnd):
        """Remove a child control (DestroyWindow)"""
        control = self.controls.pop(hwnd, None)
        if control is None:
            return
        parent = self.windows.get(control.parent_hwnd)
        if parent is not None:
            parent.controls = [c for c in parent.controls if c.hwnd != hwnd]
        if self.focused_control == hwnd:
            self.focused_control = None
        if self.open_combo == hwnd:
            self.open_combo = None
    
    @gui_locked
    def show_window(self, hwnd, show=True):
        """Show/hide window"""
        if hwnd in self.windows:
            self.windows[hwnd].visible = show
            if show and not self.windows[hwnd].parent:
                self.active_window = hwnd
                if hwnd not in self.z_order:
                    self.z_order.append(hwnd)
        elif hwnd in self.controls:
            self.controls[hwnd].visible = show
    
    @gui_locked
    def set_window_text(self, hwnd, text):
        """Set window/control text"""
        if hwnd in self.windows:
            self.windows[hwnd].title = text
            self.windows[hwnd].text = text
        elif hwnd in self.controls:
            control = self.controls[hwnd]
            control.text = text
            # Like WM_SETTEXT of an edit control: caret at the start, unmodified
            control.set_selection(0)
            control.edit_scroll = control.edit_top_line = 0
            control.modified = False
    
    def get_window_text(self, hwnd):
        """Get window/control text"""
        if hwnd in self.windows:
            return self.windows[hwnd].text
        elif hwnd in self.controls:
            return self.controls[hwnd].text
        return ""
    
    def show_messagebox(self, caption, text, msg_type=0, request=None, process=None):
        """Show MessageBox (thread-safe); the chosen button's id is stored in
        request['result'] when it closes. process (if any) owns it: the box
        closes when that program ends."""
        self.messagebox_queue.put({
            'caption': caption,
            'text': text,
            'type': msg_type,
            'request': request,
            'process': process,
        })
        return 1  # IDOK
    
    # ==================== CONSOLE WINDOW ====================
    
    @gui_locked
    def create_console(self, title, owner):
        """Open a console window for a process (called on its emulation thread)"""
        offset = 24 * (self.consoles_opened % 8)  # Cascade, so none hides another
        self.consoles_opened += 1
        hwnd = self.create_window(title, 50 + offset, 400 - offset, 600, 280, owner=owner)
        self.windows[hwnd].bg_color = (12, 12, 12)  # Black background
        console = FakeConsole(hwnd)
        self.consoles[hwnd] = console
        self.show_window(hwnd)
        return console

    @gui_locked
    def cancel_console_input(self, console):
        """Unblock a pending read for good (process ending or console closing)"""
        console.cancelled = True
        console.input_active = False
        console.input_result = None
        console.input_ready.set()

    @gui_locked
    def close_console(self, console):
        """Close a console window"""
        self.cancel_console_input(console)
        self.consoles.pop(console.hwnd, None)
        self._remove_window(console.hwnd)
    
    def _draw_console_window(self, window, console):
        """Draw console window"""
        if not window.visible or window.minimized:
            return

        is_active = (window.hwnd == self.active_window)
        self._draw_window_frame(window, self.BORDER)
        self._draw_title_bar(window, is_active)

        # Content area (console output, the line being typed continues it)
        content_x = window.x + 5
        content_y = window.y + 30
        content_width = window.width - 10
        content_height = window.height - 35
        
        # Content background
        content_rect = pygame.Rect(content_x, content_y, content_width, content_height)
        self._draw_edge(content_rect.inflate(2, 2), self.COLOR_BUTTON_SHADOW,
                        self.COLOR_BUTTON_BORDER_LIGHT)
        pygame.draw.rect(self.screen, (12, 12, 12), content_rect)

        rows = list(console.lines)
        if console.input_active:
            typed = (console.input, self.CONSOLE_COLORS['stdin'])
            if console.line_open and rows:
                rows[-1] = rows[-1] + [typed]
            else:
                rows.append([typed])

        # Draw the last rows that fit (scrolled back by console.scroll)
        line_height = 14
        max_visible_lines = max(1, (content_height - 4) // line_height)
        end_line = max(0, len(rows) - console.scroll)
        start_line = max(0, end_line - max_visible_lines)

        self.screen.set_clip(content_rect)
        y_offset = content_y + 2
        x = content_x + 3
        for row in rows[start_line:end_line]:
            x = content_x + 3
            for text, color in row:
                if text:
                    surface = self.font_console.render(text, True, color)
                    self.screen.blit(surface, (x, y_offset))
                    x += surface.get_width()
            y_offset += line_height

        # Blinking block cursor after the typed text
        if console.input_active and self.console_cursor_visible and console.scroll == 0:
            cursor_h = self.font_console.get_height()
            pygame.draw.rect(self.screen, self.CONSOLE_COLORS['stdin'],
                             (x, y_offset - line_height + cursor_h - 3, 8, 2))
        self.screen.set_clip(None)

    # Console text colors per stream
    CONSOLE_COLORS = {'stdout': (192, 192, 192), 'stderr': (255, 64, 64),
                      'stdin': (192, 192, 192)}

    @gui_locked
    def console_write(self, console, text, stream="stdout"):
        """Write to a process's console (thread-safe); text without a final LF
        leaves the line open, so later output (or typed input) continues it"""
        color = self.CONSOLE_COLORS.get(stream, self.CONSOLE_COLORS['stdout'])
        
        # CR has no glyph; console lines are split on LF only
        text = text.replace('\r\n', '\n').replace('\r', '')

        for i, part in enumerate(text.split('\n')):
            if i > 0:
                # LF: end the open line, or add an empty one at a line start
                if not console.line_open:
                    console.lines.append([])
                console.line_open = False
            if part:
                if console.line_open:
                    console.lines[-1].append((part, color))
                else:
                    console.lines.append([(part, color)])
                    console.line_open = True
        
        # Check maximum line count
        del console.lines[:-FakeConsole.MAX_LINES]
    
    def request_console_input(self, console):
        """
        Read a line typed into a console - called from the emulation thread,
        blocks until the GUI thread delivers it. None if the read is cancelled.
        """
        with self.lock:
            if console.cancelled or console.hwnd not in self.consoles:
                return None
            console.input = ""
            console.input_result = None
            console.input_ready.clear()
            console.input_active = True
            self.console_cursor_visible = True
            self.console_cursor_timer = 0
            # Bring the console to the front so typing goes to it
            win = self.windows[console.hwnd]
            win.minimized = False
            if console.hwnd in self.z_order:
                self.z_order.remove(console.hwnd)
            self.z_order.append(console.hwnd)
            self.active_window = console.hwnd
        
        console.input_ready.wait()  # Blocking wait
        return console.input_result
