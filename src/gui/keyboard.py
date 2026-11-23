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

"""PseudoWindowsGUI mixin: Keyboard input: focus, virtual keys, edit controls"""


from .. import winapi
from ..config import PYGAME_AVAILABLE

if PYGAME_AVAILABLE:
    import pygame


class KeyboardMixin:
    """Keyboard input: focus, virtual keys, edit controls"""

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
        # Synthesize WM_CHAR / WM_SYSCHAR like TranslateMessage (GetMessageA
        # gives the ANSI character)
        char = self._key_char(event, vk)
        if char is not None:
            message = self.winapi.WM_SYSCHAR if sys_key else self.winapi.WM_CHAR
            self.winapi.post_window_message(hwnd, message, char, lparam)

    # Keys whose character is a control code: Backspace, Tab, Enter, Esc
    CONTROL_KEY_CHARS = {0x08: 0x08, 0x09: 0x09, 0x0D: 0x0D, 0x1B: 0x1B}

    def _key_char(self, event, vk):
        """Character code of a keystroke (WM_CHAR wParam), or None: printable
        characters, the control codes of Backspace, Tab, Enter and Esc, and
        Ctrl+letter (Ctrl+A = 1 ... Ctrl+Z = 26; ^Z accelerators)"""
        ctrl = self.key_states.get(0x11) and not self.key_states.get(0x12)  # Ctrl+Alt: AltGr
        if ctrl and vk is not None and 0x41 <= vk <= 0x5A:
            return vk - 0x40
        if vk in self.CONTROL_KEY_CHARS:
            return self.CONTROL_KEY_CHARS[vk]
        if event.unicode and len(event.unicode) == 1 and event.unicode.isprintable():
            return ord(event.unicode)
        return None

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
