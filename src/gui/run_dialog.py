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

"""PseudoWindowsGUI mixin: The Start menu's Run dialog and its Browse dialog.

They are windows of the fake desktop itself (like the message boxes), not of
an emulated program: the desktop draws them with its controls and handles
their buttons, keys and list clicks through the host dialog hooks below."""

import ntpath
import os

from .. import recent_documents, shell_open
from ..config import DRIVES, PYGAME_AVAILABLE
from ..paths import resolve_drive_path

if PYGAME_AVAILABLE:
    import pygame


class RunDialogMixin:
    """The Run dialog (Start menu, Win+R) and its Browse dialog"""

    RUN_DIALOG_W = 400
    RUN_DIALOG_H = 170
    BROWSE_DIALOG_W = 340
    BROWSE_DIALOG_H = 330

    # ==================== HOST DIALOG HOOKS ====================

    def _host_dialogs(self):
        """hwnd -> state of the desktop's own dialogs: 'buttons' (control hwnd ->
        callback), 'default' and 'cancel' callbacks, optional 'edit' (the
        control typed into) and 'list' (callback(index, double_click))"""
        return self.__dict__.setdefault('host_dialogs', {})

    def _host_dialog(self, hwnd):
        dialogs = self._host_dialogs()
        state = dialogs.get(hwnd)
        if state is not None and hwnd not in self.windows:
            dialogs.pop(hwnd, None)  # Its window went away without the dialog
            return None
        return state

    def _host_dialog_button(self, hwnd, control):
        """A click on a button of a desktop dialog; True if it was one"""
        state = self._host_dialog(hwnd)
        if state is None:
            return False
        callback = state['buttons'].get(control.hwnd)
        if callback is not None:
            callback()
        return True

    def _host_dialog_list_click(self, hwnd, control, index):
        """A left click on an item of a desktop dialog's list; True if it was one"""
        state = self._host_dialog(hwnd)
        if state is None or 'list' not in state:
            return False
        double = self._double_click(('listbox', control.hwnd, index))
        state['list'](index, double)
        return True

    def _host_dialog_close(self, hwnd):
        """The close button of a desktop dialog cancels it; True if it was one"""
        state = self._host_dialog(hwnd)
        if state is None:
            return False
        state['cancel']()
        return True

    def _close_host_dialog(self, hwnd):
        self._host_dialogs().pop(hwnd, None)
        if hwnd in self.windows:
            self._remove_window(hwnd)

    def _host_dialog_key(self, event):
        """Keys of the desktop: Win+R opens the Run dialog, Esc closes the Start
        menu, the active desktop dialog takes Enter (its default button),
        Esc (Cancel) and the arrow keys of its list. True if the key was used."""
        if event.key == pygame.K_r and event.mod & pygame.KMOD_GUI:
            self._open_run_dialog()
            return True
        if event.key == pygame.K_ESCAPE and self.start_menu_open:
            self.start_menu_open = False
            return True
        state = self._host_dialog(self.active_window)
        if state is None:
            return False
        if self.open_combo is not None and event.key in (
                pygame.K_RETURN, pygame.K_KP_ENTER, pygame.K_ESCAPE):
            self.open_combo = None  # The list closes first, like Windows
            return True
        if event.key in (pygame.K_RETURN, pygame.K_KP_ENTER):
            state['default']()
            return True
        if event.key == pygame.K_ESCAPE:
            state['cancel']()
            return True
        if event.key == pygame.K_TAB:
            return True  # The edit keeps the focus
        listbox = self.controls.get(state.get('listbox'))
        if listbox is not None and event.key in (pygame.K_UP, pygame.K_DOWN) and listbox.items:
            step = -1 if event.key == pygame.K_UP else 1
            listbox.sel_index = max(0, min(len(listbox.items) - 1, listbox.sel_index + step))
            rows = max(1, listbox.height // self.LISTBOX_ITEM_H)
            listbox.top_index = min(max(listbox.top_index, listbox.sel_index - rows + 1),
                                    listbox.sel_index)
            return True
        edit = state.get('edit')
        if edit in self.controls and self.focused_control != edit:
            self.focused_control = edit  # Typing goes to the dialog's edit field
        return False

    # ==================== RUN ====================

    def _run_dialog_icon_image(self):
        """(32, 32, RGBA) of the Run icon for the dialog's SS_ICON static"""
        image = self.__dict__.get('_run_icon_rgba')
        if image is None:
            surface = self._scaled_icon('run', self._run_icon(), 32)
            image = (32, 32, pygame.image.tobytes(surface, 'RGBA'))
            self._run_icon_rgba = image
        return image

    def _open_run_dialog(self):
        """Show the Run dialog (or bring the open one to the front) with the
        last command typed, selected, and the older ones in its list"""
        self.start_menu_open = False
        for hwnd, state in list(self._host_dialogs().items()):
            if state.get('kind') == 'run' and self._host_dialog(hwnd) is not None:
                self.raise_window(hwnd)
                self.active_window = hwnd
                self.focused_control = state['edit']
                return hwnd
        width, height = self.RUN_DIALOG_W, self.RUN_DIALOG_H
        y = max(0, self.height - self.TASKBAR_H - height - 12)
        hwnd = self.create_window("Run", 12, y, width, height)
        win = self.windows[hwnd]
        win.is_dialog = True  # Only the close button
        icon = self.create_control(hwnd, "STATIC", "", 14, 14, 32, 32, 0x3)  # SS_ICON
        self.controls[icon].icon = self._run_dialog_icon_image()
        prompt = ("Type the name of a program, folder, or document, and Windows will "
                  "open it for you.")
        for index, line in enumerate(self._wrap_text(prompt, width - 80)[:2]):
            self.create_control(hwnd, "STATIC", line, 60, 14 + 18 * index, width - 76, 18,
                                0x80)  # SS_NOPREFIX
        self.create_control(hwnd, "STATIC", "&Open:", 14, 66, 44, 18)
        history = shell_open.run_mru()
        combo_hwnd = self.create_control(hwnd, "COMBOBOX", history[0] if history else "",
                                         60, 62, width - 78, 160, 0x42, 12298)  # CBS_DROPDOWN
        combo = self.controls[combo_hwnd]
        combo.items = list(history)
        combo.select_all()
        button_w, button_h, gap = 80, 25, 8
        top = height - self.TITLE_BAR_H - 2 * self.BORDER - button_h - 12
        right = width - 2 * self.BORDER - 14
        buttons = {}
        for index, (label, callback, style) in enumerate((
                ("OK", lambda: self._run_dialog_ok(hwnd), 1),  # BS_DEFPUSHBUTTON
                ("Cancel", lambda: self._close_host_dialog(hwnd), 0),
                ("&Browse...", lambda: self._open_browse_dialog(hwnd), 0))):
            left = right - (3 - index) * button_w - (2 - index) * gap
            buttons[self.create_control(hwnd, "BUTTON", label, left, top, button_w, button_h,
                                        style, (1, 2, 12288)[index])] = callback
        self._host_dialogs()[hwnd] = {
            'kind': 'run', 'buttons': buttons, 'edit': combo_hwnd,
            'default': lambda: self._run_dialog_ok(hwnd),
            'cancel': lambda: self._close_host_dialog(hwnd)}
        self.show_window(hwnd)
        self.focused_control = combo_hwnd
        return hwnd

    def _run_dialog_ok(self, hwnd):
        """OK: run the typed command; the dialog stays open if it failed"""
        state = self._host_dialog(hwnd)
        combo = self.controls.get(state['edit']) if state else None
        if combo is None:
            return
        text = combo.text.strip()
        if not text:
            return  # Windows' OK button is disabled without a command
        # On failure the dialog stays open under the error message, like
        # Windows, so the command can be corrected
        if self.run_command(text):
            self._close_host_dialog(hwnd)

    def run_command(self, text):
        """Start a command line like the Run dialog: a program (searched in the
        Windows folders, PATH and App Paths, .exe added) with its arguments,
        a document with its associated program, or a folder in Explorer.
        Shows an error message box and returns False if it can't."""
        text = text.strip()
        path, arguments = shell_open.split_command(text)
        if path is None:
            name = arguments.strip('"') or text
            self._show_messagebox(name, f"Cannot find the file '{name}' (or one of its "
                                  "components). Make sure the path and filename are "
                                  "correct and that all required libraries are "
                                  "available.", 0x10)
            return False
        program, command_line, directory = shell_open.open_command(path, '', arguments)
        if program is None:
            self._show_messagebox(ntpath.basename(path.rstrip('\\')) or path,
                                  "This file does not have a program associated with it "
                                  "for performing this action.", 0x10)
            return False
        if not self.launcher:
            return False
        self.launcher(program, command_line, directory)
        host = resolve_drive_path(path)
        if host and os.path.isfile(host) and not shell_open.is_program(path):
            recent_documents.add_recent_document(path)
        shell_open.add_run_mru(text)
        return True

    # ==================== BROWSE ====================

    def _open_browse_dialog(self, run_hwnd):
        """Browse...: pick a file for the Run dialog in a folder list, starting
        in the folder of the typed command (else C:\\)"""
        run_state = self._host_dialog(run_hwnd)
        if run_state is None:
            return None
        for hwnd, state in self._host_dialogs().items():
            if state.get('kind') == 'browse' and hwnd in self.windows:
                self.raise_window(hwnd)
                self.active_window = hwnd
                return hwnd
        combo = self.controls[run_state['edit']]
        found, _ = shell_open.split_command(combo.text) if combo.text.strip() else (None, '')
        folder = 'C:\\'
        if found:
            host = resolve_drive_path(found)
            folder = found if host and os.path.isdir(host) else ntpath.dirname(found)
        width, height = self.BROWSE_DIALOG_W, self.BROWSE_DIALOG_H
        run_win = self.windows[run_hwnd]
        x = max(0, min(run_win.x + 20, self.width - width))
        y = max(0, min(run_win.y - height + 120, self.height - self.TASKBAR_H - height))
        hwnd = self.create_window("Browse", x, y, width, height)
        win = self.windows[hwnd]
        win.is_dialog = True
        win.owner_hwnd = run_hwnd  # Closing it activates the Run dialog again
        client_w = width - 2 * self.BORDER
        self.create_control(hwnd, "STATIC", "Look in:", 12, 10, 60, 18)
        path_hwnd = self.create_control(hwnd, "STATIC", folder, 72, 10, client_w - 84, 18, 0x80)
        list_h = height - self.TITLE_BAR_H - 2 * self.BORDER - 90
        list_hwnd = self.create_control(hwnd, "LISTBOX", "", 12, 34, client_w - 24, list_h,
                                        0x00A00001, 1120)  # LBS_NOTIFY | WS_VSCROLL
        top = 34 + list_h + 12
        buttons = {}
        state = {'kind': 'browse', 'folder': folder, 'listbox': list_hwnd,
                 'path': path_hwnd, 'run': run_hwnd, 'buttons': buttons}
        for index, (label, callback, style) in enumerate((
                ("&Open", lambda: self._browse_open(hwnd), 1),
                ("Cancel", lambda: self._close_browse_dialog(hwnd), 0))):
            left = client_w - 12 - (2 - index) * 80 - (1 - index) * 8
            buttons[self.create_control(hwnd, "BUTTON", label, left, top, 80, 25, style,
                                        (1, 2)[index])] = callback
        state['default'] = lambda: self._browse_open(hwnd)
        state['cancel'] = lambda: self._close_browse_dialog(hwnd)
        state['list'] = lambda index, double: self._browse_list_click(hwnd, index, double)
        self._host_dialogs()[hwnd] = state
        self._browse_fill(hwnd)
        self.show_window(hwnd)
        self.focused_control = None
        return hwnd

    def _browse_fill(self, hwnd):
        """The browse list: [..], the folders, the files, then the other drives"""
        state = self._host_dialogs()[hwnd]
        folder = state['folder']
        host = resolve_drive_path(folder)
        try:
            names = sorted(os.listdir(host), key=str.lower)
        except (OSError, TypeError):
            names = []
        folders = [n for n in names if os.path.isdir(os.path.join(host, n))]
        files = [n for n in names if os.path.isfile(os.path.join(host, n))]
        entries = [] if len(folder.rstrip('\\')) <= 2 else [('up', '[..]', None)]
        entries += [('folder', f'[{n}]', n) for n in folders]
        entries += [('file', n, n) for n in files]
        entries += [('drive', f'[{letter}:]', letter + ':\\') for letter in DRIVES
                    if letter != folder[:1].upper() and resolve_drive_path(letter + ':\\')]
        state['entries'] = entries
        listbox = self.controls[state['listbox']]
        listbox.items = [label for _, label, _ in entries]
        listbox.sel_index, listbox.top_index = -1, 0
        self.controls[state['path']].text = folder

    def _browse_navigate(self, hwnd, kind, name):
        state = self._host_dialogs()[hwnd]
        if kind == 'up':
            target = ntpath.dirname(state['folder'].rstrip('\\'))
            target = target if len(target) > 2 else target[:2] + '\\'
        elif kind == 'drive':
            target = name
        else:
            target = ntpath.join(state['folder'], name)
        state['folder'] = shell_open.canonical_path(target) or state['folder']
        self._browse_fill(hwnd)

    def _browse_list_click(self, hwnd, index, double):
        state = self._host_dialog(hwnd)
        if state is None or not 0 <= index < len(state['entries']):
            return
        self.controls[state['listbox']].sel_index = index
        if double:
            self._browse_open(hwnd)

    def _browse_open(self, hwnd):
        """Open: go into the selected folder, or give the selected file to the
        Run dialog (quoted when it has spaces)"""
        state = self._host_dialog(hwnd)
        if state is None:
            return
        index = self.controls[state['listbox']].sel_index
        if not 0 <= index < len(state['entries']):
            return
        kind, _, name = state['entries'][index]
        if kind != 'file':
            self._browse_navigate(hwnd, kind, name)
            return
        path = ntpath.join(state['folder'], name)
        run_state = self._host_dialog(state['run'])
        self._close_browse_dialog(hwnd)
        if run_state is not None:
            combo = self.controls[run_state['edit']]
            combo.text = f'"{path}"' if ' ' in path else path
            combo.select_all()
            self.focused_control = run_state['edit']

    def _close_browse_dialog(self, hwnd):
        run = self._host_dialogs().get(hwnd, {}).get('run')
        self._close_host_dialog(hwnd)
        if run in self.windows:
            self.raise_window(run)
            self.active_window = run
            self.focused_control = self._host_dialogs().get(run, {}).get('edit')
