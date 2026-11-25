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

"""WinAPIHandler mixin: Shell folders (shell32), keyboard, system settings, display modes"""

import os
import struct
import ntpath

from unicorn import UcError

from .. import config, winapi
from ..config import (PROGRAM_DATA_FOLDER, PROGRAM_FILES_FOLDER, PUBLIC_FOLDER,
                      USER_APPDATA_FOLDER, USER_LOCAL_APPDATA_FOLDER, USER_PROFILE_FOLDER)
from ..logger import log


ADMINISTRATIVE_TOOLS = '\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools'


class ShellFoldersMixin:
    """Shell folders (shell32), keyboard, system settings, display modes"""

    # ---------- Shell folders (shell32) ----------

    # CSIDL -> folder, laid out like Windows Vista and later: the user's
    # folders are in the profile (C:\Users\<user>), the shared ones in
    # C:\Users\Public and C:\ProgramData
    SHELL_FOLDERS = {
        0x00: USER_PROFILE_FOLDER + '\\Desktop',                     # CSIDL_DESKTOP
        0x02: USER_APPDATA_FOLDER + '\\Microsoft\\Windows\\Start Menu\\Programs',  # CSIDL_PROGRAMS
        0x05: USER_PROFILE_FOLDER + '\\Documents',                   # CSIDL_PERSONAL
        0x06: USER_PROFILE_FOLDER + '\\Favorites',                   # CSIDL_FAVORITES
        0x07: USER_APPDATA_FOLDER + '\\Microsoft\\Windows\\Start Menu\\Programs\\Startup',
        0x08: USER_APPDATA_FOLDER + '\\Microsoft\\Windows\\Recent',  # CSIDL_RECENT
        0x09: USER_APPDATA_FOLDER + '\\Microsoft\\Windows\\SendTo',  # CSIDL_SENDTO
        0x0B: USER_APPDATA_FOLDER + '\\Microsoft\\Windows\\Start Menu',  # CSIDL_STARTMENU
        0x0D: USER_PROFILE_FOLDER + '\\Music',                       # CSIDL_MYMUSIC
        0x0E: USER_PROFILE_FOLDER + '\\Videos',                      # CSIDL_MYVIDEO
        0x10: USER_PROFILE_FOLDER + '\\Desktop',                     # CSIDL_DESKTOPDIRECTORY
        0x14: 'C:\\Windows\\Fonts',                                  # CSIDL_FONTS
        0x15: USER_APPDATA_FOLDER + '\\Microsoft\\Windows\\Templates',  # CSIDL_TEMPLATES
        0x16: PROGRAM_DATA_FOLDER + '\\Microsoft\\Windows\\Start Menu',  # CSIDL_COMMON_STARTMENU
        0x17: PROGRAM_DATA_FOLDER + '\\Microsoft\\Windows\\Start Menu\\Programs',
        0x18: PROGRAM_DATA_FOLDER + '\\Microsoft\\Windows\\Start Menu\\Programs\\Startup',
        0x19: PUBLIC_FOLDER + '\\Desktop',             # CSIDL_COMMON_DESKTOPDIRECTORY
        0x1A: USER_APPDATA_FOLDER,                                    # CSIDL_APPDATA
        0x1C: USER_LOCAL_APPDATA_FOLDER,                              # CSIDL_LOCAL_APPDATA
        0x1F: USER_PROFILE_FOLDER + '\\Favorites',                   # CSIDL_COMMON_FAVORITES
        0x20: USER_LOCAL_APPDATA_FOLDER + '\\Microsoft\\Windows\\INetCache',  # CSIDL_INTERNET_CACHE
        0x21: USER_LOCAL_APPDATA_FOLDER + '\\Microsoft\\Windows\\INetCookies',  # CSIDL_COOKIES
        0x22: USER_LOCAL_APPDATA_FOLDER + '\\Microsoft\\Windows\\History',  # CSIDL_HISTORY
        0x23: PROGRAM_DATA_FOLDER,                                    # CSIDL_COMMON_APPDATA
        0x24: 'C:\\Windows',                                          # CSIDL_WINDOWS
        0x25: 'C:\\Windows\\System32',                                # CSIDL_SYSTEM
        0x26: PROGRAM_FILES_FOLDER,                                   # CSIDL_PROGRAM_FILES
        0x27: USER_PROFILE_FOLDER + '\\Pictures',                    # CSIDL_MYPICTURES
        0x28: USER_PROFILE_FOLDER,                                    # CSIDL_PROFILE
        0x29: 'C:\\Windows\\System32',                                # CSIDL_SYSTEMX86
        0x2A: PROGRAM_FILES_FOLDER,                                   # CSIDL_PROGRAM_FILESX86
        0x2B: PROGRAM_FILES_FOLDER + '\\Common Files',               # CSIDL_PROGRAM_FILES_COMMON
        0x2D: PROGRAM_DATA_FOLDER + '\\Microsoft\\Windows\\Templates',  # CSIDL_COMMON_TEMPLATES
        0x2E: PUBLIC_FOLDER + '\\Documents',                         # CSIDL_COMMON_DOCUMENTS
        0x2F: PROGRAM_DATA_FOLDER + ADMINISTRATIVE_TOOLS,         # CSIDL_COMMON_ADMINTOOLS
        0x30: USER_APPDATA_FOLDER + ADMINISTRATIVE_TOOLS,         # CSIDL_ADMINTOOLS
        0x35: PUBLIC_FOLDER + '\\Music',                             # CSIDL_COMMON_MUSIC
        0x36: PUBLIC_FOLDER + '\\Pictures',                          # CSIDL_COMMON_PICTURES
        0x37: PUBLIC_FOLDER + '\\Videos',                            # CSIDL_COMMON_VIDEO
    }

    # CSIDL_DRIVES: My Computer, the virtual folder of the drives, has no
    # path (SHGetFolderPath fails); its PIDL holds the parsing name
    CSIDL_DRIVES = 0x11
    MY_COMPUTER_PATH = '::{20D04FE0-3AEA-1069-A2D8-08002B30309D}'
    MY_COMPUTER_NAME = 'My Computer'

    def _is_my_computer(self, path):
        return path is not None and path.upper() == self.MY_COMPUTER_PATH

    def _shell_folder(self, csidl):
        """Windows path of a CSIDL special folder (created like on a real
        installation, where they exist), or None if unknown"""
        folder = self.SHELL_FOLDERS.get(csidl & 0xFF)
        if folder is None:
            return None
        path = self.resolve_drive_path(folder)
        if path is not None:
            try:
                os.makedirs(path, exist_ok=True)
            except OSError as e:
                log.warning(f"Cannot create shell folder {folder}: {e}")
        return folder

    def SHGetFolderPathA(self, args, wide=False):
        """SHGetFolderPathA/W emulation - HRESULT, the path has no trailing backslash"""
        csidl, pszPath = args[1], args[4]
        folder = self._shell_folder(csidl)
        log.debug(f"SHGetFolderPath(0x{csidl:x}) -> {folder}")
        if folder is None:
            return 0x80070057  # E_INVALIDARG
        if not pszPath or not self._write_units(pszPath, self._text_units(folder, wide)[:259],
                                                wide):
            return 0x80070057
        return 0  # S_OK

    def SHGetFolderPathW(self, args):
        return self.SHGetFolderPathA(args, wide=True)

    def SHGetSpecialFolderPathA(self, args, wide=False):
        """SHGetSpecialFolderPathA/W emulation - BOOL"""
        pszPath, csidl = args[1], args[2]
        folder = self._shell_folder(csidl)
        log.debug(f"SHGetSpecialFolderPath(0x{csidl:x}) -> {folder}")
        if folder is None or not pszPath:
            return 0
        return 1 if self._write_units(pszPath, self._text_units(folder, wide)[:259],
                                      wide) else 0

    def SHGetSpecialFolderPathW(self, args):
        return self.SHGetSpecialFolderPathA(args, wide=True)

    def _make_pidl(self, path):
        """Item ID list (one item holding the path) for a Windows path"""
        data = path.encode('utf-16-le') + b'\x00\x00'
        pidl = self.emu.heap_alloc(2 + len(data) + 2)
        if pidl:
            self._mem_write(pidl, struct.pack('<H', 2 + len(data)) + data + b'\x00\x00')
            self.pidls[pidl] = path
        return pidl

    def _pidl_path(self, pidl):
        """Windows path an item ID list stands for: '' for the empty list
        (the desktop), None if unknown. The PIDLs made here have one item
        holding a full path; copies the program made of them (with IMalloc,
        or a parent's items in front) are read from memory: the last item."""
        if not pidl:
            return None
        path = self.pidls.get(pidl)
        if path is not None:
            return path
        last, position = None, pidl
        for _ in range(64):
            try:
                cb = struct.unpack('<H', self.emu.uc.mem_read(position, 2))[0]
                data = bytes(self.emu.uc.mem_read(position + 2, cb - 2)) if cb >= 4 else b''
            except UcError:
                return None
            if cb == 0:
                return '' if last is None else last
            if cb < 6 or cb % 2 or data[-2:] != b'\x00\x00':
                return None
            try:
                text = data[:-2].decode('utf-16-le')
            except UnicodeDecodeError:
                return None
            if text != self.MY_COMPUTER_PATH and not (len(text) >= 2 and text[1] == ':'):
                return None  # Not an item of ours
            last = text
            position += cb
        return None

    def _make_empty_pidl(self):
        """The empty item ID list: the desktop, the root of the namespace"""
        pidl = self.emu.heap_alloc(2)
        if pidl:
            self._mem_write(pidl, b'\x00\x00')
            self.pidls[pidl] = ''
        return pidl

    def _pidl_file_path(self, pidl):
        """Like _pidl_path, the desktop as its folder in the file system"""
        path = self._pidl_path(pidl)
        return self._shell_folder(0) if path == '' else path

    def SHGetPathFromIDListA(self, args, wide=False):
        """SHGetPathFromIDListA/W emulation (PIDLs of SHBrowseForFolder)"""
        pidl, pszPath = args[0], args[1]
        path = self._pidl_file_path(pidl)
        if path is None or self._is_my_computer(path) or not pszPath:
            if pszPath:
                self._write_units(pszPath, [], wide)
            return 0
        return 1 if self._write_units(pszPath, self._text_units(path, wide)[:259], wide) else 0

    def SHGetPathFromIDListW(self, args):
        return self.SHGetPathFromIDListA(args, wide=True)

    SHGetPathFromIDList = SHGetPathFromIDListA  # The ANSI export without A

    def CoTaskMemAlloc(self, args):
        """CoTaskMemAlloc emulation"""
        return self.emu.heap_alloc(max(args[0], 1))

    def CoTaskMemFree(self, args):
        """CoTaskMemFree emulation (also frees SHBrowseForFolder PIDLs)"""
        if args[0]:
            self.pidls.pop(args[0], None)
            self.emu.heap_free(args[0])
        return 0

    IID_IMALLOC = '00000002-0000-0000-c000-000000000046'

    def SHGetMalloc(self, args):
        """SHGetMalloc emulation - the shell's task allocator (IMalloc over
        CoTaskMemAlloc/CoTaskMemFree)"""
        if not args[0]:
            return 0x80070057  # E_INVALIDARG
        if not self.shell_malloc:
            pointers = self._com_new_object(
                [((self.IID_IMALLOC, self.IID_IUNKNOWN),
                  self._com_vtable('IMalloc', 'malloc'))], {})
            self.shell_malloc = pointers[self.IID_IUNKNOWN]
        else:
            self.com_objects[self.shell_malloc]['refs'] += 1
        self._mem_write(args[0], struct.pack('<I', self.shell_malloc))
        return 0  # S_OK

    def _com_malloc(self, method, wide, args):
        """IMalloc methods of SHGetMalloc's allocator (it is never freed)"""
        if method in ('AddRef', 'Release'):
            return 1
        if method == 'QueryInterface':
            return self._com_unknown(method, args)
        if method == 'Alloc':
            return self.CoTaskMemAlloc([args[1]])
        if method == 'Free':
            self.CoTaskMemFree([args[1]])
            return 0
        if method == 'Realloc':
            return self.CoTaskMemRealloc([args[1], args[2]])
        if method == 'GetSize':
            size = self.emu.heap_block_size(args[1])
            return 0xFFFFFFFF if size is None else size
        if method == 'DidAlloc':
            return 1 if self.emu.heap_block_size(args[1]) is not None else 0
        return 0  # HeapMinimize

    def CoTaskMemRealloc(self, args):
        """CoTaskMemRealloc emulation"""
        pv, cb = args[0], args[1]
        if not pv:
            return self.CoTaskMemAlloc([cb])
        if not cb:
            self.CoTaskMemFree([pv])
            return 0
        old = self.emu.heap_block_size(pv)
        if old is None:
            return 0
        new = self.emu.heap_alloc(cb)
        if new:
            self._mem_write(new, bytes(self.emu.uc.mem_read(pv, min(old, cb))))
            self.CoTaskMemFree([pv])
        return new

    BFFM_INITIALIZED, BFFM_SELCHANGED = 1, 2
    BFFM_SETSTATUSTEXTA, BFFM_ENABLEOK, BFFM_SETSELECTIONA = 0x464, 0x465, 0x466
    BFFM_SETSELECTIONW, BFFM_SETSTATUSTEXTW, BFFM_SETOKTEXT = 0x467, 0x468, 0x469
    BFFM_SETEXPANDED = 0x46A

    def SHBrowseForFolderA(self, args, wide=False):
        """SHBrowseForFolderA/W emulation - a modal folder browser; returns a PIDL"""
        lpbi = args[0]
        try:
            (hwndOwner, pidlRoot, pszDisplayName, lpszTitle, ulFlags, lpfn,
             lParam) = struct.unpack('<7I', self.emu.uc.mem_read(lpbi, 28))
        except UcError:
            return 0
        if not self.gui or not self.gui.running:
            return 0
        title = self._read_text(lpszTitle, wide) if lpszTitle else ''
        # (the desktop, the empty list, is the root of everything: C:)
        root = (self._pidl_path(pidlRoot) or 'C:\\').rstrip('\\') if pidlRoot else 'C:'
        # Rooted at My Computer, the top level lists the drives (LOGICAL_DRIVES)
        computer = self.MY_COMPUTER_PATH
        if self._is_my_computer(root):
            root = computer
        log.info(f"SHBrowseForFolder{'W' if wide else 'A'}(\"{title}\")")

        ID_TITLE, ID_PATH, ID_LIST, ID_STATUS = 0x3742, 0x3743, 0x3744, 0x3745
        template = self._dialog_template('Browse for Folder', 220, 196, [
            self._dialog_item('STATIC', title, 7, 6, 206, 18, ID_TITLE),
            self._dialog_item('STATIC', '', 7, 28, 206, 10, ID_PATH, 0x80),  # SS_NOPREFIX
            self._dialog_item('LISTBOX', '', 7, 40, 206, 116, ID_LIST, 0x00A10001),
            self._dialog_item('STATIC', '', 7, 158, 206, 10, ID_STATUS, 0x80),
            self._dialog_item('BUTTON', 'OK', 106, 174, 50, 14, 1, 0x00010001),
            self._dialog_item('BUTTON', 'Cancel', 163, 174, 50, 14, 2, 0x00010000)])
        state = {'dir': root, 'result': None}

        def at_root():
            return state['dir'].rstrip('\\').lower() == root.lower()

        def in_computer():
            return state['dir'] == computer

        def selected():
            """Folder chosen now: the selected list entry or the current folder"""
            listbox = self._dialog_control(dlg, ID_LIST)
            if 0 <= listbox.sel_index < len(listbox.items):
                item = listbox.items[listbox.sel_index]
                if in_computer():
                    return item + '\\'  # A drive: "C:" -> C:\\
                if item != '..':
                    return state['dir'].rstrip('\\') + '\\' + item
            if in_computer():
                return computer
            return state['dir'] if len(state['dir']) > 2 else state['dir'] + '\\'

        def notify_selection():
            path = selected()
            self._dialog_control(dlg, ID_PATH).text = \
                self.MY_COMPUTER_NAME if path == computer else path
            if lpfn:
                pidl = self._make_pidl(path)
                self.emu.call_callback(lpfn, [dlg, self.BFFM_SELCHANGED, pidl, lParam])
                self.CoTaskMemFree([pidl])

        def fill(select=None):
            if in_computer():
                entries = [f"{letter}:" for letter in self.LOGICAL_DRIVES]
            else:
                host_dir = self.resolve_drive_path(state['dir'] + '\\')
                try:
                    entries = sorted((e for e in os.listdir(host_dir)
                                      if os.path.isdir(os.path.join(host_dir, e))),
                                     key=str.lower)
                except (OSError, TypeError):
                    entries = []
            listbox = self._dialog_control(dlg, ID_LIST)
            listbox.items = ([] if at_root() else ['..']) + entries
            listbox.top_index = 0
            listbox.sel_index = -1
            if select is not None:
                names = [item.lower() for item in listbox.items]
                if select.lower() in names:
                    listbox.sel_index = names.index(select.lower())
                    rows = max(1, (listbox.height - 2) // self.gui.LISTBOX_ITEM_H)
                    listbox.top_index = max(0, listbox.sel_index - rows + 1)
            notify_selection()

        def navigate(path, select=None):
            if path == computer:
                if root != computer:
                    return False
                state['dir'] = computer
                fill(select)
                return True
            # The trailing backslash keeps "C:" from meaning the current directory
            full = self.full_windows_path(path.rstrip('\\') + '\\', clamp=True)
            host = self.resolve_drive_path(full) if full else None
            if host is None or not os.path.isdir(host):
                return False
            full = full.rstrip('\\')
            if root != computer and not full.lower().startswith(root.lower()):
                return False
            state['dir'] = full
            fill(select)
            return True

        def set_selection(path):
            """BFFM_SETSELECTION: show the nearest existing folder selected"""
            full = self.full_windows_path(path, clamp=True)
            while full:
                full = full.rstrip('\\')
                parent, name = ntpath.split(full)
                host = self.resolve_drive_path(full + '\\')
                if host is not None and os.path.isdir(host):
                    if name and full.lower() != root.lower():
                        navigate(parent, select=name)
                    elif not name and root == computer:
                        navigate(computer, select=full)  # A drive root: "C:"
                    else:
                        navigate(full)
                    return 1
                if not name:
                    break
                full = parent
            return 0

        def handler(message, wParam, lParam_):
            if message == self.WM_INITDIALOG:
                fill()
                return 1
            if message in (self.BFFM_SETSELECTIONA, self.BFFM_SETSELECTIONW,
                           self.BFFM_SETEXPANDED):
                if wParam:
                    path = self._read_text(lParam_, message != self.BFFM_SETSELECTIONA)
                else:
                    path = self.pidls.get(lParam_)
                return set_selection(path) if path else 0
            if message in (self.BFFM_SETSTATUSTEXTA, self.BFFM_SETSTATUSTEXTW):
                text = self._read_text(lParam_, message == self.BFFM_SETSTATUSTEXTW)
                self._dialog_control(dlg, ID_STATUS).text = text
                return 0
            if message == self.BFFM_ENABLEOK:
                self._dialog_control(dlg, 1).enabled = bool(lParam_)
                return 0
            if message == self.BFFM_SETOKTEXT:
                self._dialog_control(dlg, 1).text = self.read_wide_string(lParam_)
                return 0
            if message == self.WM_CLOSE:
                self.EndDialog([dlg, 0])
            elif message == self.WM_COMMAND:
                control_id, code = wParam & 0xFFFF, wParam >> 16
                listbox = self._dialog_control(dlg, ID_LIST)
                if control_id == ID_LIST and code == self.LBN_SELCHANGE:
                    notify_selection()
                elif control_id == ID_LIST and code == self.LBN_DBLCLK:
                    if 0 <= listbox.sel_index < len(listbox.items):
                        item = listbox.items[listbox.sel_index]
                        if item == '..':
                            parent, name = ntpath.split(state['dir'])
                            if not name:  # A drive root: up to My Computer
                                navigate(computer, select=state['dir'])
                            else:
                                navigate(parent, select=name)
                        elif in_computer():
                            navigate(item)
                        else:
                            navigate(state['dir'] + '\\' + item)
                elif control_id == 1:
                    state['result'] = selected()
                    self.EndDialog([dlg, 1])
                elif control_id == 2:
                    self.EndDialog([dlg, 0])
            return 0

        dlg = self._create_dialog(template, self._owner_window(hwndOwner), handler=handler)
        # The status line is shown with BIF_STATUSTEXT, but not in the new dialog style
        self._dialog_control(dlg, ID_STATUS).visible = ulFlags & 0x44 == 0x04
        self._show_dialog(dlg, 0)
        if lpfn and dlg in self.dialogs:
            self.emu.call_callback(lpfn, [dlg, self.BFFM_INITIALIZED, 0, lParam])
        if self._run_modal_dialog(dlg) != 1 or not state['result']:
            return 0
        path = state['result']
        if pszDisplayName:
            name = self.MY_COMPUTER_NAME if path == computer else \
                (self._drive_display_name(path) or ntpath.basename(path.rstrip('\\')) or path)
            self._write_units(pszDisplayName, self._text_units(name, wide)[:259], wide)
        return self._make_pidl(path)

    def SHBrowseForFolderW(self, args):
        return self.SHBrowseForFolderA(args, wide=True)

    # ---------- Keyboard ----------

    def GetKeyboardState(self, args):
        """GetKeyboardState emulation - 256 key bytes (0x80: down, 0x01: toggled)"""
        state = bytearray(self.keyboard_toggles)
        if self.gui:
            for vk, down in list(self.gui.key_states.items()):
                if down and 0 <= vk < 256:
                    state[vk] |= 0x80
        return 1 if self._mem_write(args[0], bytes(state)) else 0

    def SetKeyboardState(self, args):
        """SetKeyboardState emulation - only the toggle bits are kept"""
        try:
            data = self.emu.uc.mem_read(args[0], 256)
        except UcError:
            self._last_error = 998  # ERROR_NOACCESS
            return 0
        self.keyboard_toggles = bytearray(b & 1 for b in data)
        return 1

    def LoadKeyboardLayoutA(self, args):
        """LoadKeyboardLayoutA emulation - HKL of a KLID like "0000041F" """
        klid = self.read_string(args[0]).strip()
        try:
            layout = int(klid, 16)
        except ValueError:
            return 0
        lang = layout & 0xFFFF
        return ((layout >> 16 or lang) << 16 | lang) if lang else 0

    def _oem_table(self, to_oem):
        """bytes.translate table between the ANSI and the OEM code page"""
        oem = f"cp{self.OEM_CODEPAGES.get(self._ansi_codepage_number(), 437)}"
        src, dst = (config.ANSI_CODEPAGE, oem) if to_oem else (oem, config.ANSI_CODEPAGE)
        table = bytearray(range(128))
        for b in range(128, 256):
            ch = bytes([b]).decode(src, errors='replace')
            out = ch.encode(dst, errors='replace') if ch != '\ufffd' else b'?'
            table.append(out[0] if len(out) == 1 else 0x3F)
        return bytes(table)

    def _convert_oem_buffer(self, args, to_oem):
        src, dst, length = args[0], args[1], args[2]
        try:
            data = bytes(self.emu.uc.mem_read(src, length)) if length else b''
        except UcError:
            return 0
        return 1 if self._mem_write(dst, data.translate(self._oem_table(to_oem))) else 0

    def CharToOemBuffA(self, args):
        """CharToOemBuffA emulation - ANSI -> OEM code page"""
        return self._convert_oem_buffer(args, True)

    def OemToCharBuffA(self, args):
        """OemToCharBuffA emulation - OEM -> ANSI code page"""
        return self._convert_oem_buffer(args, False)

    # ---------- System settings, display modes ----------

    # Registered window messages are system-wide: name (upper case) -> id
    registered_messages = {}

    def RegisterWindowMessageA(self, args):
        """RegisterWindowMessageA emulation - ids from 0xC000, case-insensitive"""
        name = self.read_string(args[0]).upper()
        if not name:
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0
        messages = winapi.WinAPIHandler.registered_messages
        if name not in messages:
            messages[name] = 0xC000 + len(messages)
        return messages[name]

    @staticmethod
    def _logfont(height=-11, weight=400, face="MS Sans Serif"):
        """LOGFONTA bytes (60)"""
        return (struct.pack('<5i8B', height, 0, 0, 0, weight, 0, 0, 0, 0, 0, 0, 0, 0)
                + face.encode('ascii').ljust(32, b'\x00'))

    def SystemParametersInfoA(self, args):
        """SystemParametersInfoA emulation - common SPI_GET* queries; SPI_SET* are accepted"""
        action, ui_param, pv_param = args[0], args[1], args[2]
        width, height = self._screen_size()
        dword_values = {
            0x01: 1,     # SPI_GETBEEP
            0x0A: 31,    # SPI_GETKEYBOARDSPEED
            0x0E: 0,     # SPI_GETSCREENSAVETIMEOUT
            0x10: 0,     # SPI_GETSCREENSAVEACTIVE
            0x16: 1,     # SPI_GETKEYBOARDDELAY
            0x23: 1,     # SPI_GETFASTTASKSWITCH
            0x26: 0,     # SPI_GETDRAGFULLWINDOWS
            0x38: 0,     # SPI_GETSHOWSOUNDS
            0x4A: 0,     # SPI_GETFONTSMOOTHING
            0x53: 0,     # SPI_GETLOWPOWERACTIVE
            0x54: 0,     # SPI_GETPOWEROFFACTIVE
            0x5F: 0,     # SPI_GETMOUSETRAILS
            0x68: 3,     # SPI_GETWHEELSCROLLLINES
        }
        if action in dword_values:
            data = struct.pack('<I', dword_values[action])
        elif action == 0x03:  # SPI_GETMOUSE: threshold1, threshold2, acceleration
            data = struct.pack('<3i', 6, 10, 1)
        elif action == 0x30:  # SPI_GETWORKAREA: the desktop without the taskbar and appbars
            data = struct.pack('<4i', *self._work_area())
        elif action == 0x1F:  # SPI_GETICONTITLELOGFONT
            data = self._logfont()
        elif action == 0x29:  # SPI_GETNONCLIENTMETRICS
            data = (struct.pack('<6i', 340, 1, 16, 16, 18, 18) + self._logfont(weight=700)
                    + struct.pack('<2i', 12, 15) + self._logfont()
                    + struct.pack('<2i', 18, 18) + self._logfont()
                    + self._logfont() + self._logfont())
        elif action in (0x02, 0x0B, 0x0F, 0x11, 0x17, 0x2F, 0x55, 0x56, 0x69):
            return 1  # SPI_SET* (beep, keyboard, screen saver, work area, power...)
        else:
            log.debug(f"SystemParametersInfoA(0x{action:x}) not supported")
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0
        if not pv_param:
            self._last_error = 87
            return 0
        return 1 if self._mem_write(pv_param, data) else 0

    DISPLAY_MODES = [(640, 480), (800, 600), (1024, 768), (1280, 1024)]

    def _desktop_size(self):
        """Display mode of the fake desktop at startup (the registry mode)"""
        if self.gui:
            return self.gui.desktop_width, self.gui.desktop_height
        return self._screen_size()

    def _display_modes(self):
        width, height = self._desktop_size()
        sizes = [(w, h) for w, h in self.DISPLAY_MODES if w <= width and h <= height]
        if (width, height) not in sizes:
            sizes.append((width, height))
        return [(w, h, bpp) for w, h in sizes for bpp in (8, 16, 32)]

    def EnumDisplaySettingsA(self, args):
        """EnumDisplaySettingsA emulation - the startup mode and smaller standard ones"""
        mode_num, lpDevMode = args[1], args[2]
        if mode_num == 0xFFFFFFFF:  # ENUM_CURRENT_SETTINGS
            width, height = self._screen_size()
            mode = (width, height, 32)
        elif mode_num == 0xFFFFFFFE:  # ENUM_REGISTRY_SETTINGS
            width, height = self._desktop_size()
            mode = (width, height, 32)
        else:
            modes = self._display_modes()
            if mode_num >= len(modes):
                return 0
            mode = modes[mode_num]
        try:
            self.emu.uc.mem_write(lpDevMode, b'DISPLAY'.ljust(32, b'\x00')
                                  + struct.pack('<HHHHI', 0x0401, 0, 156, 0, 0x7C0000))
            self.emu.uc.mem_write(lpDevMode + 104, struct.pack('<5I', mode[2], mode[0],
                                                               mode[1], 0, 60))
        except UcError:
            return 0
        return 1

    WM_DISPLAYCHANGE = 0x007E

    def ChangeDisplaySettingsA(self, args):
        """ChangeDisplaySettingsA emulation - an enumerated mode changes the fake
        desktop resolution (the color depth stays 32 bpp); NULL restores the
        startup mode"""
        lpDevMode, dwFlags = args[0], args[1]
        if not lpDevMode:
            if not dwFlags & 0x2:  # CDS_TEST
                self._set_display_mode(*self._desktop_size(), owner=None)
            return 0  # DISP_CHANGE_SUCCESSFUL (back to the registry mode)
        try:
            fields = struct.unpack('<I', self.emu.uc.mem_read(lpDevMode + 40, 4))[0]
            bpp, width, height = struct.unpack('<3I', self.emu.uc.mem_read(lpDevMode + 104, 12))
        except UcError:
            return 0xFFFFFFFB  # DISP_CHANGE_BADPARAM
        screen_w, screen_h = self._screen_size()
        width = width if fields & 0x80000 else screen_w    # DM_PELSWIDTH
        height = height if fields & 0x100000 else screen_h  # DM_PELSHEIGHT
        sizes = {(w, h) for w, h, _ in self._display_modes()}
        if ((fields & 0x40000 and bpp not in (1, 4, 8, 15, 16, 24, 32)) or
                (width, height) not in sizes):
            return 0xFFFFFFFE  # DISP_CHANGE_BADMODE
        if not dwFlags & 0x2:  # CDS_TEST only checks the mode
            # CDS_FULLSCREEN modes end with the program
            owner = self if dwFlags & 0x4 else None
            self._set_display_mode(width, height, owner)
        return 0

    def _set_display_mode(self, width, height, owner):
        """Resize the fake desktop and tell the top-level windows (WM_DISPLAYCHANGE)"""
        if not self.gui:
            return
        changed = (width, height) != self._screen_size()
        self.gui.set_display_mode(width, height, owner)
        if not changed:
            return
        lparam = ((height & 0xFFFF) << 16) | (width & 0xFFFF)
        for hwnd, win in list(self.gui.windows.items()):
            if win.parent is None and win.owner is self and self._find_wndproc_for_hwnd(hwnd):
                self.post_window_message(hwnd, self.WM_DISPLAYCHANGE, 32, lparam)
