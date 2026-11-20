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

"""PseudoWindowsGUI mixin: Mouse input: menu bars, scroll bars, clicks, drags, capture"""


from ..config import PYGAME_AVAILABLE

if PYGAME_AVAILABLE:
    import pygame


class MouseMixin:
    """Mouse input: menu bars, scroll bars, clicks, drags, capture"""

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
                if self.open_menu is None:
                    self._post_enter_menu(win)
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
                    self.raise_window(hwnd)
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
                                and not self._popup_without_size_boxes(win)
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
                        if button == 1 and self.child_frame(target)[1]:
                            self._child_caption_click(target, x, y)
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

    def _child_caption_click(self, child, x, y):
        """A left click on the title bar of a child window: its close button
        closes it (WM_CLOSE), the rest of the bar starts dragging it inside
        its parent"""
        bar, close = self._child_caption_rects(child)
        if close is not None and close.collidepoint(x, y):
            self._close_window(child.hwnd)
        elif bar.collidepoint(x, y):
            # Child coordinates are relative to the parent's client area
            self.dragging_window = child.hwnd
            self.drag_offset_x = x - child.x
            self.drag_offset_y = y - child.y

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
