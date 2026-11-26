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

"""WinAPIHandler mixin: the Find (FindTextW) and Replace (ReplaceTextA/W)
common dialogs, and RegisterWindowMessageW they are used with"""

import struct

from unicorn import UcError

from .. import winapi


class FindReplaceMixin:
    """The Find and Replace common dialogs (comdlg32)"""

    # FINDREPLACE.Flags
    FR_WHOLEWORD, FR_REPLACE, FR_REPLACEALL = 0x2, 0x10, 0x20
    FR_NOUPDOWN, FR_NOMATCHCASE, FR_NOWHOLEWORD = 0x400, 0x800, 0x1000
    FR_HIDEUPDOWN, FR_HIDEWHOLEWORD = 0x4000, 0x10000
    # Control IDs of the dialogs (those of Windows' dialog templates, which
    # programs that customize them refer to)
    FR_ID_FIND, FR_ID_REPLACE_WITH, FR_ID_WHOLE, FR_ID_CASE = 1152, 1153, 1040, 1041
    FR_ID_UP, FR_ID_DOWN, FR_ID_DO_REPLACE, FR_ID_REPLACE_ALL = 1056, 1057, 1024, 1025

    def RegisterWindowMessageW(self, args):
        """RegisterWindowMessageW emulation - the ids of RegisterWindowMessageA"""
        name = self.read_wide_string(args[0]).upper() if args[0] else ''
        if not name:
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0
        messages = winapi.WinAPIHandler.registered_messages
        if name not in messages:
            messages[name] = 0xC000 + len(messages)
        return messages[name]

    def _find_replace_dialog(self, lpfr, wide, replace):
        """A modeless Find or Replace dialog for a FINDREPLACE; the owner gets
        the "commdlg_FindReplace" registered message with the struct's Flags
        and strings updated. Returns the dialog's window."""
        try:
            (hwndOwner, _, flags, find_what, replace_with, find_length,
             replace_length) = struct.unpack('<IIIIIHH', self.emu.uc.mem_read(lpfr + 4, 24))
        except UcError:
            return 0
        if (not self.gui or not self.gui.running or not find_what or not find_length or
                (replace and (not replace_with or not replace_length))):
            self._last_error = 0x4001  # FRERR_BUFFERLENGTHZERO
            return 0
        messages = winapi.WinAPIHandler.registered_messages
        find_message = messages.setdefault('COMMDLG_FINDREPLACE', 0xC000 + len(messages))
        item = self._dialog_item
        items = [item('STATIC', 'Fi&nd what:', 6, 9, 56, 10, 0xFFFF),
                 item('EDIT', self._read_text(find_what, wide), 62, 7, 108, 12,
                      self.FR_ID_FIND, 0x00810080)]
        y = 24
        if replace:
            items += [item('STATIC', 'Re&place with:', 6, 27, 56, 10, 0xFFFF),
                      item('EDIT', self._read_text(replace_with, wide), 62, 25, 108, 12,
                           self.FR_ID_REPLACE_WITH, 0x00810080)]
            y = 44
        if not flags & self.FR_HIDEWHOLEWORD:
            items.append(item('BUTTON', 'Match &whole word only', 6, y, 100, 12,
                              self.FR_ID_WHOLE, 0x00010003))
        if not flags & self.FR_HIDEMATCHCASE:
            items.append(item('BUTTON', 'Match &case', 6, y + 14, 100, 12, self.FR_ID_CASE,
                              0x00010003))
        if not replace and not flags & self.FR_HIDEUPDOWN:
            items += [item('BUTTON', 'Direction', 110, y - 6, 60, 26, 0xFFFF, 0x7),
                      item('BUTTON', '&Up', 114, y + 6, 26, 12, self.FR_ID_UP, 0x00010009),
                      item('BUTTON', '&Down', 140, y + 6, 28, 12, self.FR_ID_DOWN, 0x9)]
        buttons = [('&Find Next', 1, 0x00010001)]
        if replace:
            buttons += [('&Replace', self.FR_ID_DO_REPLACE, 0x00010000),
                        ('Replace &All', self.FR_ID_REPLACE_ALL, 0x00010000)]
        buttons.append(('Cancel', 2, 0x00010000))
        for index, (text, control_id, style) in enumerate(buttons):
            items.append(item('BUTTON', text, 176, 5 + 18 * index, 56, 14, control_id, style))
        height = max(y + 30, 10 + 18 * len(buttons))
        owner = self._owner_window(hwndOwner)
        limits = {find_what: find_length, replace_with: replace_length}

        def control(control_id):
            return self._dialog_control(dlg, control_id)

        def checked(control_id):
            button = control(control_id)
            return button is not None and button.checked

        def store(address, control_id):
            edit = control(control_id)
            if address and edit is not None:
                units = self._text_units(edit.text, wide)[:limits[address] - 1]
                self._write_units(address, units, wide)

        def notify(action):
            try:
                current = struct.unpack('<I', self.emu.uc.mem_read(lpfr + 12, 4))[0]
            except UcError:
                return
            options = ((self.FR_WHOLEWORD if checked(self.FR_ID_WHOLE) else 0) |
                       (self.FR_MATCHCASE if checked(self.FR_ID_CASE) else 0))
            if replace or control(self.FR_ID_UP) is None or not checked(self.FR_ID_UP):
                options |= self.FR_DOWN  # The Replace dialog searches down
            current &= ~(self.FR_DOWN | self.FR_WHOLEWORD | self.FR_MATCHCASE |
                         self.FR_FINDNEXT | self.FR_REPLACE | self.FR_REPLACEALL |
                         self.FR_DIALOGTERM)
            if action != self.FR_DIALOGTERM:
                current |= options
                store(find_what, self.FR_ID_FIND)
                if replace:
                    store(replace_with, self.FR_ID_REPLACE_WITH)
            self._mem_write(lpfr + 12, struct.pack('<I', current | action))
            self._dispatch(owner, find_message, 0, lpfr)

        def handler(message, wParam, lParam):
            if message == self.WM_INITDIALOG:
                for control_id, flag in ((self.FR_ID_WHOLE, self.FR_WHOLEWORD),
                                         (self.FR_ID_CASE, self.FR_MATCHCASE)):
                    if control(control_id) is not None:
                        control(control_id).checked = bool(flags & flag)
                for control_id, down in ((self.FR_ID_UP, False), (self.FR_ID_DOWN, True)):
                    if control(control_id) is not None:
                        control(control_id).checked = bool(flags & self.FR_DOWN) == down
                        control(control_id).enabled = not flags & self.FR_NOUPDOWN
                for control_id, flag in ((self.FR_ID_WHOLE, self.FR_NOWHOLEWORD),
                                         (self.FR_ID_CASE, self.FR_NOMATCHCASE)):
                    if control(control_id) is not None and flags & flag:
                        control(control_id).enabled = False
                edit = control(self.FR_ID_FIND)
                if edit is not None:
                    self.gui.focused_control = edit.hwnd
                    edit.select_all()
                return 1
            command = wParam & 0xFFFF if message == self.WM_COMMAND else None
            actions = {1: self.FR_FINDNEXT, self.FR_ID_DO_REPLACE: self.FR_REPLACE,
                       self.FR_ID_REPLACE_ALL: self.FR_REPLACEALL}
            if command in actions:
                if control(self.FR_ID_FIND).text:
                    notify(actions[command])
            elif command == 2 or message == self.WM_CLOSE:
                self._close_dialog(dlg)
                notify(self.FR_DIALOGTERM)
            return 0

        title = 'Replace' if replace else 'Find'
        dlg = self._create_dialog(self._dialog_template(title, 238, height, items), owner,
                                  handler=handler)
        self._show_dialog(dlg, 0)
        return dlg

    def FindTextW(self, args):
        """FindTextW emulation - modeless Find dialog (see _find_replace_dialog)"""
        return self._find_replace_dialog(args[0], True, False)

    def ReplaceTextA(self, args):
        """ReplaceTextA emulation - modeless Replace dialog"""
        return self._find_replace_dialog(args[0], False, True)

    def ReplaceTextW(self, args):
        return self._find_replace_dialog(args[0], True, True)
