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
from ..scan_codes import VK_SCAN_CODES

if PYGAME_AVAILABLE:
    import pygame


def _physical_key_vks():
    """Host scan code (a USB HID keyboard usage, layout-independent) ->
    the virtual-key code of the key at that place on a US keyboard"""
    table = {4 + i: 0x41 + i for i in range(26)}              # A-Z
    table.update({30 + i: 0x31 + i for i in range(9)})        # 1-9
    table.update({58 + i: 0x70 + i for i in range(12)})       # F1-F12
    table.update({89 + i: 0x61 + i for i in range(9)})        # Keypad 1-9
    table.update({
        39: 0x30, 40: 0x0D, 41: 0x1B, 42: 0x08, 43: 0x09, 44: 0x20,
        # - = [ ] \ (# of ISO keyboards) ; ' ` , . /
        45: 0xBD, 46: 0xBB, 47: 0xDB, 48: 0xDD, 49: 0xDC, 50: 0xDC, 51: 0xBA,
        52: 0xDE, 53: 0xC0, 54: 0xBC, 55: 0xBE, 56: 0xBF,
        57: 0x14, 70: 0x2C, 71: 0x91, 72: 0x13, 73: 0x2D, 74: 0x24, 75: 0x21,
        76: 0x2E, 77: 0x23, 78: 0x22, 79: 0x27, 80: 0x25, 81: 0x28, 82: 0x26,
        83: 0x90, 84: 0x6F, 85: 0x6A, 86: 0x6D, 87: 0x6B, 88: 0x0D, 98: 0x60,
        99: 0x6E,
        100: 0xE2,  # The extra key of ISO keyboards (< > on Turkish Q)
        224: 0x11, 225: 0x10, 226: 0x12, 228: 0x11, 229: 0x10, 230: 0x12,
    })
    return table


PHYSICAL_KEY_VKS = _physical_key_vks()


def key_lparam(vk, flags=1):
    """lParam of a key message: flags (repeat count, context and transition
    bits) with the key's scan code in bits 16-23 and the extended key flag
    in bit 24, like the messages of a real keyboard"""
    return flags | (VK_SCAN_CODES.get(vk, 0) << 16)


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
        """Map a Pygame key to a Windows virtual-key code, or None. Letters
        and digits follow the host layout, like the virtual keys of Windows
        (Ctrl+Z is Z on any keyboard); the other keys go by their place on
        the keyboard: on a Turkish Q keyboard the keys of ş, ğ, ü, ö, ç and
        ı give no ASCII key code, but a program that reads keys (DOSBox) must
        still get them. Their characters (WM_CHAR) follow the host layout."""
        key = event.key
        if pygame.K_a <= key <= pygame.K_z:
            return key - 32            # 'a' (0x61) -> VK 'A' (0x41)
        if pygame.K_0 <= key <= pygame.K_9:
            return key                 # '0' (0x30) -> VK 0x30
        physical = PHYSICAL_KEY_VKS.get(getattr(event, 'scancode', 0) or 0)
        if physical is not None:
            return physical
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
            pygame.K_INSERT: 0x2D, pygame.K_CAPSLOCK: 0x14, pygame.K_NUMLOCK: 0x90,
            pygame.K_SCROLLOCK: 0x91, pygame.K_PAUSE: 0x13, pygame.K_PRINT: 0x2C,
            # The punctuation keys of a US keyboard (VK_OEM_*): programs that
            # read keys, not characters (SDL games, DOSBox), need them too
            pygame.K_SEMICOLON: 0xBA, pygame.K_EQUALS: 0xBB, pygame.K_COMMA: 0xBC,
            pygame.K_MINUS: 0xBD, pygame.K_PERIOD: 0xBE, pygame.K_SLASH: 0xBF,
            pygame.K_BACKQUOTE: 0xC0, pygame.K_LEFTBRACKET: 0xDB,
            pygame.K_BACKSLASH: 0xDC, pygame.K_RIGHTBRACKET: 0xDD, pygame.K_QUOTE: 0xDE,
            # Numeric keypad
            pygame.K_KP_PERIOD: 0x6E, pygame.K_KP_DIVIDE: 0x6F,
            pygame.K_KP_MULTIPLY: 0x6A, pygame.K_KP_MINUS: 0x6D, pygame.K_KP_PLUS: 0x6B,
        }
        keypad = (pygame.K_KP0, pygame.K_KP1, pygame.K_KP2, pygame.K_KP3, pygame.K_KP4,
                  pygame.K_KP5, pygame.K_KP6, pygame.K_KP7, pygame.K_KP8, pygame.K_KP9)
        if key in keypad:
            return 0x60 + keypad.index(key)  # VK_NUMPAD0-9
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
        lparam = key_lparam(vk, 0xC0000001)  # Previous key state and transition state bits
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
        # Context code: Alt is down
        lparam = key_lparam(vk, 0x20000001 if sys_key and self.alt_down else 1)
        # The WM_CHAR / WM_SYSCHAR of the keystroke (GetMessageA gives the
        # ANSI character): posted by TranslateMessage, like Windows
        char = self._key_char(event, vk)
        char_message = self.winapi.WM_SYSCHAR if sys_key else self.winapi.WM_CHAR
        if vk is not None:
            message = self.winapi.WM_SYSKEYDOWN if sys_key else self.winapi.WM_KEYDOWN
            self.winapi.post_window_message(hwnd, message, vk, lparam,
                                            char=None if char is None else (char_message, char))
        elif char is not None:
            # A key without a virtual-key code here (punctuation): just its character
            self.winapi.post_window_message(hwnd, char_message, char, lparam)

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
        alt = self.key_states.get(0x12) and not self.key_states.get(0x11)
        if alt and vk is not None and (0x41 <= vk <= 0x5A or 0x30 <= vk <= 0x39):
            # Alt+letter may come without its text: the WM_SYSCHAR of a menu mnemonic
            return vk | 0x20 if vk >= 0x41 else vk
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
        if self._menu_key(event):  # An open menu bar dropdown has the keyboard
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
        # Win+R, and the keys of the desktop's own dialogs (Run)
        if self._host_dialog_key(event):
            return

        # The active console window takes the line its program is waiting for
        console = self.consoles.get(self.active_window)
        if console is not None and console.input_active:
            if event.key in (pygame.K_RETURN, pygame.K_KP_ENTER):
                # Enter - input completed; it stays on screen like in a real console
                line = console.input
                console.input = ""
                console.input_cursor = 0
                self.console_line_entered(console, line)
                self.console_write(console, line + "\n", "stdin")
                console.input_result = line
                console.input_active = False
                console.input_ready.set()  # Send signal to waiting thread
            else:
                # Typing, the cursor keys, Backspace/Delete, Esc, the history
                self.console_edit_key(console, event.key, event.unicode)
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
        owner = win.owner
        if (owner is not None and not in_dialog and control.class_name == "EDIT" and
                owner._control_subclass(control.hwnd)):
            # A subclassed edit sees its keys first, like on Windows: WM_KEYDOWN,
            # then the WM_CHAR of TranslateMessage. Schedule+'s in-place editors
            # end on Enter there; what they pass on, the edit procedure types
            # (edit_message)
            vk = self._pygame_key_to_vk(event)
            char = self._key_char(event, vk)
            if vk is not None:
                owner.post_window_message(control.hwnd, owner.WM_KEYDOWN, vk, key_lparam(vk),
                                          char=None if char is None else (owner.WM_CHAR, char))
            elif char is not None:
                owner.post_window_message(control.hwnd, owner.WM_CHAR, char, 1)
            return True
        if event.key in (pygame.K_RETURN, pygame.K_KP_ENTER) and multiline and (
                control.style & 0x1000 or not in_dialog):  # ES_WANTRETURN
            self._edit_insert(win, control, '\r\n')
            return True
        if event.key == pygame.K_TAB and multiline and not in_dialog and not (
                event.mod & (pygame.KMOD_CTRL | pygame.KMOD_ALT)):
            self._edit_insert(win, control, '\t')  # Outside a dialog Tab is a character
            return True
        if win.owner is not None and not in_dialog and self._edit_passes_key(event):
            # Keys the edit control has no use for go to the program's message
            # loop, where TranslateAccelerator sees them like on Windows
            # (Notepad's Ctrl+S, F3 and F5)
            self._forward_key_to_window(event)
            return True
        if event.key in (pygame.K_RETURN, pygame.K_KP_ENTER, pygame.K_ESCAPE, pygame.K_TAB):
            if in_dialog:
                return False  # The dialog handles them (default button, Cancel, next edit)
            if win.owner is not None:
                # The edit gets them, like Windows: the program's message loop
                # makes them press its default button (Office's file dialogs)
                vk = self._pygame_key_to_vk(event)
                win.owner.post_window_message(control.hwnd, winapi.WinAPIHandler.WM_KEYDOWN,
                                              vk, 1, char=(winapi.WinAPIHandler.WM_CHAR, vk))
                return True
            self.focused_control = None
            return True
        self._edit_key(win, control, event)
        return True

    # Ctrl+key combinations an edit control acts on itself (see _edit_key)
    EDIT_CTRL_KEY_NAMES = frozenset(('a', 'c', 'v', 'x', 'z', 'insert', 'left', 'right', 'up',
                                     'down', 'home', 'end', 'backspace', 'delete'))

    def _edit_passes_key(self, event):
        """Is this a keystroke an edit control does not handle: the function
        keys, Alt+key and Ctrl+key other than its own (Ctrl+Alt is AltGr,
        which types characters)?"""
        if pygame.K_F1 <= event.key <= pygame.K_F12:
            return True
        ctrl, alt = event.mod & pygame.KMOD_CTRL, event.mod & pygame.KMOD_ALT
        if ctrl and alt:
            return False
        if alt:
            return event.key != pygame.K_BACKSPACE  # Alt+Backspace: undo
        if ctrl:
            return pygame.key.name(event.key) not in self.EDIT_CTRL_KEY_NAMES
        return False

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

    # WM_CHAR control codes an edit control acts on -> (pygame key name, Ctrl)
    EDIT_CHAR_KEYS = {0x08: ('backspace', False), 0x01: ('a', True), 0x03: ('c', True),
                      0x16: ('v', True), 0x18: ('x', True)}
    # Virtual keys an edit control acts on in WM_KEYDOWN -> pygame key names
    EDIT_VK_KEYS = {0x25: 'left', 0x27: 'right', 0x26: 'up', 0x28: 'down', 0x24: 'home',
                    0x23: 'end', 0x2E: 'delete', 0x2D: 'insert'}

    def edit_message(self, control, message, code, wide=True):
        """Default processing of a WM_KEYDOWN or WM_CHAR of an EDIT control:
        the keys a subclassing procedure passes on to the edit procedure, and
        the characters a program sends it. Called on the emulation thread."""
        if not PYGAME_AVAILABLE:
            return
        win = self.windows.get(self.top_level_of(control.hwnd))
        if win is None:
            return
        ctrl, shift = bool(self.key_states.get(0x11)), bool(self.key_states.get(0x10))
        name = None
        if message == winapi.WinAPIHandler.WM_KEYDOWN:
            name = self.EDIT_VK_KEYS.get(code)
        elif code in self.EDIT_CHAR_KEYS:
            name, ctrl = self.EDIT_CHAR_KEYS[code]
        elif code == 0x0D:
            if control.style & 0x4:  # ES_MULTILINE
                with self.lock:
                    self._edit_insert(win, control, '\r\n')
            return
        elif code >= 0x20 and code != 0x7F:
            from .. import config
            char = (bytes([code]).decode(config.ANSI_CODEPAGE, errors='replace')
                    if not wide and code < 0x100 else chr(code & 0xFFFF))
            with self.lock:
                self._edit_insert(win, control, char)
            return
        if name is None:
            return
        mod = (pygame.KMOD_CTRL if ctrl else 0) | (pygame.KMOD_SHIFT if shift else 0)
        event = pygame.event.Event(pygame.KEYDOWN, key=pygame.key.key_code(name), mod=mod,
                                   unicode='')
        with self.lock:
            self._edit_key(win, control, event)

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

        def line_last(index):
            # Where the caret ends on a line: before the break of a word-wrapped
            # line (its end is where the next line starts and shows)
            line_start, line_end = lines[index]
            if index + 1 < len(lines) and lines[index + 1][0] == line_end > line_start:
                return line_end - 1
            return line_end

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
            line_start = lines[control.line_of(caret)][0]
            if ctrl:
                offset = 0 if key == pygame.K_HOME else len(text)
            else:
                offset = line_start if key == pygame.K_HOME else line_last(control.line_of(caret))
            move(offset)
        elif key in (pygame.K_UP, pygame.K_DOWN) and len(lines) > 1:
            index = control.line_of(caret)
            target = index + (-1 if key == pygame.K_UP else 1)
            if 0 <= target < len(lines):
                column = caret - lines[index][0]
                move(min(lines[target][0] + column, line_last(target)))
        elif key in (pygame.K_PAGEUP, pygame.K_PAGEDOWN) and control.style & 0x4:
            move(self._edit_page(control, caret, key == pygame.K_PAGEDOWN))
        elif (ctrl and key == pygame.K_z) or (event.mod & pygame.KMOD_ALT and
                                              key == pygame.K_BACKSPACE):
            if not readonly and control.undo():
                self._edit_notify_change(win, control)
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
            d = abs(self._edit_text_width(font, shown[start:offset]) - target)
            if d < best_d:
                best, best_d = offset, d
        return best

    @staticmethod
    def _edit_display_text(control):
        """Text as an edit control shows it (password characters)"""
        if control.password_char:
            return ''.join(c if c in '\r\n' else control.password_char for c in control.text)
        return control.text
