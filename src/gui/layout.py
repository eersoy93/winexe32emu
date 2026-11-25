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

"""PseudoWindowsGUI mixin: Window geometry: resizing, the mouse cursor, frame and client sizes,
display modes, activation"""


from .. import winapi
from ..config import PYGAME_AVAILABLE
from ..logger import log
from ..resources import standard_cursor_image
from ..windows import gui_locked

if PYGAME_AVAILABLE:
    import pygame


class LayoutMixin:
    """Window geometry: resizing, the mouse cursor, frame and client sizes, display modes,
    activation"""

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

    def frame_origin(self, win):
        """Screen coordinates of a window's top-left corner (its frame)"""
        if win.parent in self.windows:
            px, py = self.client_origin(self.windows[win.parent])
            return (px + win.x, py + win.y)
        return (win.x, win.y)

    def client_origin(self, win):
        """Screen coordinates of a window's client area origin."""
        if win.parent in self.windows:
            px, py = self.client_origin(self.windows[win.parent])
            border, caption = self.child_frame(win)
            return (px + win.x + border, py + win.y + border + caption)
        border, caption = self.window_frame(win)
        top = win.y + border + caption
        if win.menu:
            top += self.MENU_H
        return (win.x + border, top)

    def client_size(self, win):
        """Client area size (width, height) of a window."""
        if win.parent in self.windows:
            border, caption = self.child_frame(win)
            return (max(0, win.width - 2 * border),
                    max(0, win.height - 2 * border - caption))
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
        left, top, right, bottom = self.work_area()
        for win in self.windows.values():
            if win.maximized and win.parent is None:
                win.x, win.y, win.width, win.height = left, top, right - left, bottom - top
        log.info(f"Display mode changed to {width}x{height}")

    WS_EX_DLGMODALFRAME = 0x1
    WS_EX_CLIENTEDGE = 0x200

    @classmethod
    def child_frame_size(cls, style, ex_style=0, dialog=False):
        """(border, caption height) of a child window with this style: a child
        with WS_CAPTION has a title bar and a dialog frame like a top-level
        window (Office 95 Setup's dialogs are child windows), WS_DLGFRAME,
        WS_THICKFRAME and a dialog's DS_MODALFRAME give the raised frame,
        WS_BORDER and WS_EX_CLIENTEDGE a 1-pixel line"""
        if style & cls.WS_CAPTION == cls.WS_CAPTION:
            return cls.BORDER, cls.TITLE_BAR_H
        if (style & (cls.WS_DLGFRAME | cls.WS_THICKFRAME) or ex_style & cls.WS_EX_DLGMODALFRAME
                or (dialog and style & cls.DS_MODALFRAME)):
            return cls.BORDER, 0
        if style & cls.WS_BORDER or ex_style & cls.WS_EX_CLIENTEDGE:
            return 1, 0
        return 0, 0

    def child_frame(self, win):
        """(border, caption height) of a child window"""
        return self.child_frame_size(win.style, win.ex_style,
                                     getattr(win, 'class_name', None) == '#32770')

    def _child_border(self, win):
        """Frame width of a child window"""
        return self.child_frame(win)[0]

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
        old_owner = self.windows[previous].owner if previous is not None and \
            self._is_app_window(previous) else None
        new_owner = self.windows[active].owner if active is not None and \
            self._is_app_window(active) else None
        # WM_ACTIVATEAPP (0x001C) first when the activation moves to another
        # program: Excel 95 learns from it that it is the active application
        if old_owner is not None:
            if new_owner is not old_owner:
                old_owner.post_window_message(previous, 0x001C, 0, 0)
            old_owner.post_window_message(previous, old_owner.WM_ACTIVATE, 0,
                                          active or 0)  # WA_INACTIVE
        if new_owner is not None:
            if new_owner is not old_owner:
                new_owner.post_window_message(active, 0x001C, 1, 0)
            new_owner.post_window_message(active, new_owner.WM_ACTIVATE, 1,
                                          previous or 0)  # WA_ACTIVE

    WS_CLIPSIBLINGS = 0x04000000

    def _child_paint_order(self, window):
        """The order the child windows of window are drawn in, the one that
        shows on top last. window.children is in Z order, the top one first
        (GetWindow's order). A WS_CLIPSIBLINGS child is clipped by the
        siblings above it, so these are drawn from the bottom up. A child
        without it paints over its siblings, and Windows paints them from
        the top down: the lowest one shows (PowerPoint 95's Tip of the Day
        puts the tip's text below the white box it is drawn on)."""
        clipped = [h for h in reversed(window.children)
                   if h in self.windows and self.windows[h].style & self.WS_CLIPSIBLINGS]
        return clipped + [h for h in window.children
                          if h in self.windows and
                          not self.windows[h].style & self.WS_CLIPSIBLINGS]

    def _draw_child_windows(self, window):
        """Draw the visible child windows of window (inside its client area)"""
        parent_clip = self.screen.get_clip()
        # The topmost child with a title bar shows it active (with its top-level window)
        captioned = [hwnd for hwnd in window.children
                     if hwnd in self.windows and self.windows[hwnd].visible
                     and self.child_frame(self.windows[hwnd])[1]]
        active_child = captioned[0] if captioned and \
            self.top_level_of(window.hwnd) == self.active_window else None
        for hwnd in self._child_paint_order(window):
            child = self.windows.get(hwnd)
            if child is None or not child.visible:
                continue
            cx, cy = self.client_origin(child)
            cw, ch = self.client_size(child)
            border, caption = self.child_frame(child)
            frame = pygame.Rect(*self.frame_origin(child), child.width, child.height)
            self.screen.set_clip(frame.clip(parent_clip))
            if border > 1:
                pygame.draw.rect(self.screen, self.COLOR_WINDOW_BG, frame)
                self._draw_raised(frame)
            elif border:
                pygame.draw.rect(self.screen, (0, 0, 0), frame, border)
            if caption:
                self._draw_child_caption(child, hwnd == active_child)
            content = pygame.Rect(cx, cy, cw, ch)
            if not child.transparent or child.dialog_brush:
                pygame.draw.rect(self.screen, child.dialog_brush or child.bg_color, content)
            self.screen.set_clip(content.clip(parent_clip))
            if child.native:
                self._draw_native(child, cx, cy, cw, ch)
            for shape in child.drawn_shapes:
                self._draw_shape(shape, cx, cy)
            self._draw_caret(hwnd, cx, cy)
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
