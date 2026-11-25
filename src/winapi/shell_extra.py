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

"""WinAPIHandler mixin: shell32 extras (command lines, known folders, item
ID lists, directories, drag and drop, the notification area, the recycle
bin), COM GUID helpers and rpcrt4 UUIDs"""

import os
import struct
import time
import uuid

from unicorn import UcError

from ..config import USER_PROFILE_FOLDER
from ..logger import log
from ..paths import resolve_drive_path
from ..windows import APPBARS, AppBar, work_area


class ShellExtraMixin:
    """shell32 extras, COM GUID helpers and rpcrt4 UUIDs"""

    # ---------- Command lines ----------

    def CommandLineToArgvW(self, args):
        """CommandLineToArgvW(command line, &argc) - one LocalAlloc block
        holding the pointer array and the strings"""
        text = self.read_wide_string(args[0]) if args[0] else ''
        if not text.strip():
            arguments = [self.windows_exe_path()]
        else:
            arguments = self.split_command_line(text)
        strings = [a.encode('utf-16-le') + b'\x00\x00' for a in arguments]
        table_size = 4 * (len(arguments) + 1)
        block = self.emu.heap_alloc(table_size + sum(len(s) for s in strings))
        if not block:
            self._last_error = 8  # ERROR_NOT_ENOUGH_MEMORY
            return 0
        pointers, offset = [], table_size
        for data in strings:
            self._mem_write(block + offset, data)
            pointers.append(block + offset)
            offset += len(data)
        self._mem_write(block, struct.pack(f'<{len(pointers) + 1}I', *pointers, 0))
        if args[1]:
            self._mem_write(args[1], struct.pack('<I', len(arguments)))
        return block

    # ---------- Known folders ----------

    # FOLDERID -> CSIDL (or a path for the folders without one)
    KNOWN_FOLDERS = {
        'b4bfcc3a-db2c-424c-b029-7fe99a87c641': 0x10,  # Desktop
        'fdd39ad0-238f-46af-adb4-6c85480369c7': 0x05,  # Documents
        '3eb685db-65f9-4cf6-a03a-e3ef65729f3d': 0x1A,  # RoamingAppData
        'f1b32785-6fba-4fcf-9d55-7b8e7f157091': 0x1C,  # LocalAppData
        '62ab5d82-fdc1-4dc3-a9dd-070d1d495d97': 0x23,  # ProgramData
        '905e63b6-c1bf-494e-b29c-65b732d3d21a': 0x26,  # ProgramFiles
        # On 32-bit Windows the x86 folders are the normal ones (there is no
        # WOW64); FOLDERID_ProgramFilesX64 and the like don't exist
        '7c5a40ef-a0fb-4bfc-874a-c0f2e0b9fa8e': 0x26,  # ProgramFilesX86
        'f7f1ed05-9f6d-47a2-aaae-29d317c6f066': 0x2B,  # ProgramFilesCommon
        'de974d24-d9c6-4d3e-bf91-f4455120b917': 0x2B,  # ProgramFilesCommonX86
        'f38bf404-1d43-42f2-9305-67de0b28fc23': 0x24,  # Windows
        '1ac14e77-02e7-4e5d-b744-2eb1ae5198b7': 0x25,  # System
        'd65231b0-b2f1-4857-a4ce-a8e7c6ea7d27': 0x25,  # SystemX86
        'fd228cb7-ae11-4ae3-864c-16f3910ab8fe': 0x14,  # Fonts
        '5e6c858f-0e22-4760-9afe-ea3317b67173': 0x28,  # Profile
        '4bd8d571-6d19-48d3-be97-422220080e43': 0x0D,  # Music
        '33e28130-4e1e-4676-835a-98395c3bc3bb': 0x27,  # Pictures
        '18989b1d-99b5-455b-841c-ab7c74e4ddfc': 0x0E,  # Videos
        '1777f761-68ad-4d8a-87bd-30b759fa33dd': 0x06,  # Favorites
        '625b53c3-ab48-4ec1-ba1f-a1ef4146fc19': 0x0B,  # StartMenu
        'a77f5d77-2e2b-44c3-a6a2-aba601054a51': 0x02,  # Programs
        'b97d20bb-f46a-4c97-ba10-5e3608430854': 0x07,  # Startup
        'ae50c081-ebd2-438a-8655-8a092e34987a': 0x08,  # Recent
        '8983036c-27c0-404b-8f08-102d10dcfd74': 0x09,  # SendTo
        'a63293e8-664e-48db-a079-df759e0509f7': 0x15,  # Templates
        'c4aa340d-f20f-4863-afef-f87ef2e6ba25': 0x19,  # PublicDesktop
        '0139d44e-6afe-49f2-8690-3dafcae6ffb8': 0x17,  # CommonPrograms
        'a4115719-d62e-491d-aa7c-e74b8be3b067': 0x16,  # CommonStartMenu
        '82a5ea35-d9cd-47c5-9629-e15d2f714e6e': 0x18,  # CommonStartup
        '374de290-123f-4565-9164-39c4925e467b': USER_PROFILE_FOLDER + '\\Downloads',
        'a520a1a4-1780-4ff6-bd18-167343c5af16': USER_PROFILE_FOLDER + '\\AppData\\LocalLow',
        '4c5c32ff-bb9d-43b0-b5b4-2d72e54eaaa4': USER_PROFILE_FOLDER + '\\Saved Games',
    }

    @classmethod
    def known_folder_paths(cls):
        """Windows paths of the CSIDL and FOLDERID folders (no duplicates)"""
        folders = []
        for folder in list(cls.SHELL_FOLDERS.values()) + list(cls.KNOWN_FOLDERS.values()):
            if isinstance(folder, str) and folder.lower() not in (f.lower() for f in folders):
                folders.append(folder)
        return folders

    @classmethod
    def create_known_folders(cls):
        """Create every known folder in drives/ (at each start, like the
        folders of a Windows installation)"""
        for folder in cls.known_folder_paths():
            path = resolve_drive_path(folder)
            if path is None:
                continue
            try:
                os.makedirs(path, exist_ok=True)
            except OSError as e:
                log.warning(f"Cannot create known folder {folder}: {e}")

    def _known_folder_path(self, guid_addr):
        """Windows path of a FOLDERID, or None"""
        folder = self.KNOWN_FOLDERS.get(self._read_guid(guid_addr))
        if folder is None:
            return None
        if isinstance(folder, int):
            return self._shell_folder(folder)
        host = self.resolve_drive_path(folder)
        if host is not None:
            try:
                os.makedirs(host, exist_ok=True)
            except OSError:
                pass
        return folder

    def SHGetKnownFolderPath(self, args):
        """SHGetKnownFolderPath(FOLDERID, flags, token, &CoTaskMemAlloc'ed path)"""
        path = self._known_folder_path(args[0])
        if not args[3]:
            return 0x80070057  # E_INVALIDARG
        if path is None:
            self._mem_write(args[3], struct.pack('<I', 0))
            return 0x80070002  # HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)
        self._mem_write(args[3], struct.pack('<I', self._alloc_units(
            self._text_units(path, True), True)))
        return 0

    def SHGetFolderPathEx(self, args):
        """SHGetFolderPathEx(FOLDERID, flags, token, buffer, size)"""
        path = self._known_folder_path(args[0])
        if path is None:
            return 0x80070002
        units = self._text_units(path, True)
        if len(units) >= args[4]:
            return 0x8007007A  # HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER)
        self._write_units(args[3], units, True)
        return 0

    def SHGetKnownFolderIDList(self, args):
        """SHGetKnownFolderIDList(FOLDERID, flags, token, &PIDL)"""
        path = self._known_folder_path(args[0])
        if path is None:
            return 0x80070002
        self._mem_write(args[3], struct.pack('<I', self._make_pidl(path)))
        return 0

    def SHGetFolderLocation(self, args):
        """SHGetFolderLocation(hwnd, CSIDL, token, reserved, &PIDL)"""
        return self.SHGetSpecialFolderLocation([args[0], args[1], args[4]])

    def SHGetFolderPathAndSubDirA(self, args, wide=False):
        """SHGetFolderPathAndSubDirA/W(hwnd, CSIDL, token, flags, subfolder, path)"""
        folder = self._shell_folder(args[1])
        if folder is None:
            return 0x80070057
        if args[4]:
            folder = folder + '\\' + self._read_text(args[4], wide).strip('\\')
            if args[1] & 0x8000:  # CSIDL_FLAG_CREATE
                host = self.resolve_drive_path(folder)
                if host is None:
                    return 0x80070005  # E_ACCESSDENIED
                os.makedirs(host, exist_ok=True)
        self._write_units(args[5], self._text_units(folder, wide)[:259], wide)
        return 0

    def SHGetFolderPathAndSubDirW(self, args):
        return self.SHGetFolderPathAndSubDirA(args, wide=True)

    # ---------- Item ID lists ----------

    def _pidl_size(self, pidl):
        """Bytes of an item ID list with its terminator"""
        size, position = 0, pidl
        while True:
            try:
                cb = struct.unpack('<H', self.emu.uc.mem_read(position, 2))[0]
            except UcError:
                return size
            if cb == 0:
                return size + 2
            size += cb
            position += cb

    def ILFree(self, args):
        return self.CoTaskMemFree(args)

    def ILGetSize(self, args):
        return self._pidl_size(args[0]) if args[0] else 0

    def ILClone(self, args):
        """ILClone - a copy of an item ID list"""
        if not args[0]:
            return 0
        if args[0] in self.pidls:
            path = self.pidls[args[0]]
            return self._make_pidl(path) if path else self._make_empty_pidl()
        size = self._pidl_size(args[0])
        copy = self.emu.heap_alloc(size)
        self._mem_write(copy, self.emu.uc.mem_read(args[0], size))
        return copy

    def ILFindLastID(self, args):
        """ILFindLastID - the last item of an ID list"""
        last = position = args[0]
        while position:
            cb = struct.unpack('<H', self.emu.uc.mem_read(position, 2))[0]
            if cb == 0:
                break
            last = position
            position += cb
        return last

    def ILCreateFromPathA(self, args, wide=False):
        """ILCreateFromPathA/W - an ID list of an existing path"""
        path = self.full_windows_path(self._read_text(args[0], wide)) if args[0] else None
        host = self.resolve_drive_path(path) if path else None
        if host is None or not os.path.exists(host):
            return 0
        return self._make_pidl(path)

    def ILCreateFromPathW(self, args):
        return self.ILCreateFromPathA(args, wide=True)

    def SHILCreateFromPath(self, args):
        """SHILCreateFromPath(wide path, &PIDL, &attributes)"""
        pidl = self.ILCreateFromPathA([args[0]], wide=True)
        self._mem_write(args[1], struct.pack('<I', pidl))
        if args[2]:
            self._mem_write(args[2], struct.pack('<I', 0))
        return 0 if pidl else 0x80070002

    def SHParseDisplayName(self, args):
        """SHParseDisplayName(name, bind context, &PIDL, attributes in, &attributes out)"""
        pidl = self.ILCreateFromPathA([args[0]], wide=True)
        self._mem_write(args[2], struct.pack('<I', pidl))
        if args[4]:
            self._mem_write(args[4], struct.pack('<I', 0))
        return 0 if pidl else 0x80070002

    # ---------- Directories and files ----------

    def SHCreateDirectoryExA(self, args, wide=False):
        """SHCreateDirectoryExA/W(hwnd, path, security) - with missing parents"""
        text = self._read_text(args[1], wide) if args[1] else ''
        if self._path_is_relative(text) or not text:
            return 161  # ERROR_BAD_PATHNAME
        host = self.resolve_drive_path(text)
        if host is None:
            return 5  # ERROR_ACCESS_DENIED
        if os.path.isdir(host):
            return 183  # ERROR_ALREADY_EXISTS
        if os.path.exists(host):
            return 80  # ERROR_FILE_EXISTS
        if self._write_protected(host):
            return self._last_error or 5
        try:
            os.makedirs(host)
        except OSError:
            return 3  # ERROR_PATH_NOT_FOUND
        return 0

    def SHCreateDirectoryExW(self, args):
        return self.SHCreateDirectoryExA(args, wide=True)

    def SHCreateDirectory(self, args):
        return self.SHCreateDirectoryExA([args[0], args[1], 0], wide=True)

    def SHGetDiskFreeSpaceExA(self, args):
        return self.GetDiskFreeSpaceExA(args)

    def SHGetDiskFreeSpaceExW(self, args):
        return self.GetDiskFreeSpaceExW(args)

    def FindExecutableA(self, args, wide=False):
        """FindExecutableA/W(file, directory, result) - a program runs itself"""
        name = self._read_text(args[0], wide) if args[0] else ''
        directory = self._read_text(args[1], wide) if args[1] else ''
        if directory and self._path_is_relative(name):
            name = directory.rstrip('\\') + '\\' + name
        full = self.full_windows_path(name)
        host = self.resolve_drive_path(full) if full else None
        if host is None or not os.path.isfile(host):
            self._write_text(args[2], '', wide)
            return 2  # SE_ERR_FNF
        if not full.lower().endswith(('.exe', '.com', '.bat')):
            self._write_text(args[2], '', wide)
            return 31  # SE_ERR_NOASSOC
        self._write_text(args[2], full, wide)
        return 42

    def FindExecutableW(self, args):
        return self.FindExecutableA(args, wide=True)

    def SHAddToRecentDocs(self, args):
        return 0

    def SHQueryRecycleBinA(self, args):
        """SHQueryRecycleBinA/W(root, SHQUERYRBINFO) - an empty recycle bin"""
        self._mem_write(args[1] + 4, b'\x00' * 16)
        return 0

    SHQueryRecycleBinW = SHQueryRecycleBinA

    def SHEmptyRecycleBinA(self, args):
        return 0

    SHEmptyRecycleBinW = SHEmptyRecycleBinA

    def SHFreeNameMappings(self, args):
        return 0

    def SHGetSetSettings(self, args):
        """SHGetSetSettings(SHELLSTATE, mask, set) - default settings"""
        if not args[2] and args[0]:
            self._mem_write(args[0], b'\x00' * 32)
        return 0

    # ---------- Drag and drop (HDROP: DROPFILES and a file list) ----------

    def DragAcceptFiles(self, args):
        return 0

    def _drop_files(self, hdrop):
        hdrop = self._hglobal_pointer(hdrop)  # (a program may make a moveable one)
        try:
            offset, _, _, _, wide = struct.unpack('<IiiII', self.emu.uc.mem_read(hdrop, 20))
        except UcError:
            return []
        return self._read_multi_string(hdrop + offset, bool(wide))

    def DragQueryFileA(self, args, wide=False):
        """DragQueryFileA/W(drop, index, buffer, size) - 0xFFFFFFFF: the file count"""
        files = self._drop_files(args[0])
        if args[1] == 0xFFFFFFFF:
            return len(files)
        if args[1] >= len(files):
            return 0
        units = self._text_units(files[args[1]], wide)
        if not args[2]:
            return len(units)
        if not args[3]:
            return 0
        units = units[:args[3] - 1]
        self._write_units(args[2], units, wide)
        return len(units)

    def DragQueryFileW(self, args):
        return self.DragQueryFileA(args, wide=True)

    def DragQueryPoint(self, args):
        """DragQueryPoint(drop, &point) - TRUE if dropped in the client area"""
        try:
            x, y, non_client = struct.unpack('<iiI', self.emu.uc.mem_read(args[0] + 4, 12))
        except UcError:
            return 0
        self._mem_write(args[1], struct.pack('<ii', x, y))
        return 0 if non_client else 1

    def DragFinish(self, args):
        self.GlobalFree(args)
        return 0

    # ---------- Notification area and the taskbar ----------

    def Shell_NotifyIconA(self, args, wide=False):
        """Shell_NotifyIconA/W(message, NOTIFYICONDATA) - the fake taskbar has
        no notification area: the tip is logged"""
        message, data = args[0], args[1]
        if message > 4:
            return 0
        try:
            flags = struct.unpack('<I', self.emu.uc.mem_read(data + 12, 4))[0]
        except UcError:
            return 0
        if flags & 0x4 and message in (0, 1):  # NIF_TIP with NIM_ADD/NIM_MODIFY
            tip = self._read_text(data + 24, wide)
            log.debug(f"Shell_NotifyIcon({message}): \"{tip}\"")
        return 1

    def Shell_NotifyIconW(self, args):
        return self.Shell_NotifyIconA(args, wide=True)

    def SHAppBarMessage(self, args):
        """SHAppBarMessage(message, APPBARDATA) - application desktop toolbars
        docked at an edge of the desktop next to the taskbar at the bottom.
        APPBARDATA: cbSize, hWnd, uCallbackMessage, uEdge, rc, lParam."""
        message, data = args[0], args[1]
        width, height = self._screen_size()
        if message == 5:  # ABM_GETTASKBARPOS
            self._mem_write(data + 12, struct.pack('<I4i', 3, 0, height - 30, width, height))
            return 1
        if message == 4:  # ABM_GETSTATE: ABS_ALWAYSONTOP
            return 2
        if message == 10:  # ABM_SETSTATE (the taskbar's own state)
            return 1
        try:
            hwnd, callback, edge, *rect = struct.unpack('<3I4i', self.emu.uc.mem_read(data + 4, 28))
        except UcError:
            return 0
        if message == 0:  # ABM_NEW
            if hwnd in APPBARS:
                return 0
            APPBARS[hwnd] = AppBar(self, callback)
            return 1
        if message == 7:  # ABM_GETAUTOHIDEBAR
            return next((h for h, bar in APPBARS.items() if edge in bar.autohide), 0)
        bar = APPBARS.get(hwnd)
        if bar is None:
            return 0
        if message == 1:  # ABM_REMOVE
            del APPBARS[hwnd]
            if bar.rect is not None:
                self._appbars_changed(hwnd)
            return 1
        if message in (2, 3):  # ABM_QUERYPOS, ABM_SETPOS
            if edge > 3:
                return 0
            left, top, right, bottom = work_area(width, height, exclude=hwnd)
            x1, y1, x2, y2 = rect
            if edge in (0, 2):  # ABE_LEFT, ABE_RIGHT: keep the width
                size = x2 - x1
                x1, x2 = (left, left + size) if edge == 0 else (right - size, right)
                y1, y2 = max(y1, top), min(y2, bottom)
            else:  # ABE_TOP, ABE_BOTTOM: keep the height
                size = y2 - y1
                y1, y2 = (top, top + size) if edge == 1 else (bottom - size, bottom)
                x1, x2 = max(x1, left), min(x2, right)
            self._mem_write(data + 16, struct.pack('<4i', x1, y1, x2, y2))
            if message == 3 and (bar.edge, bar.rect) != (edge, (x1, y1, x2, y2)):
                bar.edge, bar.rect = edge, (x1, y1, x2, y2)
                self._appbars_changed(hwnd)
            return 1
        if message == 8:  # ABM_SETAUTOHIDEBAR (lParam: register or unregister)
            if edge > 3:
                return 0
            lparam = struct.unpack('<i', self.emu.uc.mem_read(data + 32, 4))[0]
            owner = next((h for h, other in APPBARS.items() if edge in other.autohide), None)
            if not lparam:
                bar.autohide.discard(edge)
                return 1
            if owner not in (None, hwnd):
                return 0  # Only one autohide appbar per edge
            bar.autohide.add(edge)
            return 1
        return 1  # ABM_ACTIVATE, ABM_WINDOWPOSCHANGED

    def _work_area(self):
        """(left, top, right, bottom) of the desktop without the taskbar and the appbars"""
        return work_area(*self._screen_size())

    def _appbars_changed(self, hwnd):
        """The work area changed: refit the maximized windows, tell the other appbars"""
        if self.gui:
            self.gui.appbars_changed(hwnd)

    def ShellAboutA(self, args, wide=False):
        """ShellAboutA/W(hwnd, title, other text, icon) - a message box"""
        title = self._read_text(args[1], wide) if args[1] else 'Windows'
        title = title.split('#')[0]
        other = self._read_text(args[2], wide) if args[2] else ''
        text = 'Windows (winexe32emu)\nVersion 6.0 (Build 6002: Service Pack 2)'
        if other:
            text += '\n\n' + other
        self._message_box(text, f'About {title}', 0x40)
        return 1

    def ShellAboutW(self, args):
        return self.ShellAboutA(args, wide=True)

    def DuplicateIcon(self, args):
        return self.CopyIcon([args[1]])

    def ExtractAssociatedIconA(self, args, wide=False):
        """ExtractAssociatedIconA/W(instance, path, &index) - an icon handle"""
        if args[2]:
            self._mem_write(args[2], struct.pack('<H', 0))
        return self.get_next_handle()

    def ExtractAssociatedIconW(self, args):
        return self.ExtractAssociatedIconA(args, wide=True)

    def SHGetStockIconInfo(self, args):
        """SHGetStockIconInfo(SIID, flags, SHSTOCKICONINFO)"""
        info = args[2]
        try:
            size = struct.unpack('<I', self.emu.uc.mem_read(info, 4))[0]
        except UcError:
            return 0x80070057
        if size < 536:
            return 0x80070057  # E_INVALIDARG
        icon = self.get_next_handle() if args[1] & 0x100 else 0  # SHGSI_ICON
        path = 'C:\\Windows\\System32\\shell32.dll'.encode('utf-16-le').ljust(520, b'\x00')
        self._mem_write(info + 4, struct.pack('<Iii', icon, 0, args[0]) + path)
        return 0

    # ---------- COM GUID helpers (ole32) ----------

    @staticmethod
    def _parse_guid_text(text):
        """Lower-case GUID string of "{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}", or None"""
        text = text.strip()
        if len(text) != 38 or text[0] != '{' or text[-1] != '}':
            return None
        try:
            return str(uuid.UUID(text[1:-1]))
        except ValueError:
            return None

    def _write_guid(self, address, guid):
        return self._mem_write(address, self._guid_bytes(guid))

    def StringFromGUID2(self, args):
        """StringFromGUID2(GUID, buffer, size) - characters written with the NUL"""
        text = '{' + self._read_guid(args[0]).upper() + '}'
        if args[2] < 39:
            return 0
        self._write_text(args[1], text, True)
        return 39

    def StringFromCLSID(self, args):
        """StringFromCLSID/StringFromIID(GUID, &CoTaskMemAlloc'ed string)"""
        text = '{' + self._read_guid(args[0]).upper() + '}'
        address = self._alloc_units(self._text_units(text, True), True)
        if not self._mem_write(args[1], struct.pack('<I', address)):
            return 0x80070057
        return 0 if address else 0x8007000E  # E_OUTOFMEMORY

    StringFromIID = StringFromCLSID

    def _class_root_value(self, path):
        """Default value of HKEY_CLASSES_ROOT\\path (None if there is none)"""
        node, _ = self._registry_walk(self.HKEY_CLASSES_ROOT, path)
        value = node['values'].get('') if node is not None else None
        if value is None or not isinstance(value['data'], str):
            return None
        return value['data'].rstrip('\x00')

    def CLSIDFromString(self, args):
        """CLSIDFromString(text, &CLSID) - a GUID string or a registered ProgID"""
        text = self.read_wide_string(args[0]) if args[0] else ''
        if not text:
            self._write_guid(args[1], '00000000-0000-0000-0000-000000000000')
            return 0
        guid = self._parse_guid_text(text)
        if guid is None:
            clsid = self._class_root_value(text + '\\CLSID')
            guid = self._parse_guid_text(clsid) if clsid else None
            if guid is None:
                return 0x800401F3  # CO_E_CLASSSTRING
        self._write_guid(args[1], guid)
        return 0

    def IIDFromString(self, args):
        """IIDFromString(text, &IID)"""
        text = self.read_wide_string(args[0]) if args[0] else ''
        guid = self._parse_guid_text(text) if text else '00000000-0000-0000-0000-000000000000'
        if guid is None:
            return 0x80070057  # E_INVALIDARG
        self._write_guid(args[1], guid)
        return 0

    def CLSIDFromProgID(self, args):
        """CLSIDFromProgID(ProgID, &CLSID) - HKEY_CLASSES_ROOT\\ProgID\\CLSID"""
        progid = self.read_wide_string(args[0]) if args[0] else ''
        clsid = self._class_root_value(progid + '\\CLSID') if progid else None
        guid = self._parse_guid_text(clsid) if clsid else None
        if guid is None:
            return 0x800401F3  # CO_E_CLASSSTRING
        self._write_guid(args[1], guid)
        return 0

    CLSIDFromProgIDEx = CLSIDFromProgID

    def ProgIDFromCLSID(self, args):
        """ProgIDFromCLSID(CLSID, &CoTaskMemAlloc'ed ProgID)"""
        clsid = '{' + self._read_guid(args[0]).upper() + '}'
        progid = self._class_root_value(f'CLSID\\{clsid}\\ProgID')
        if progid is None:
            return 0x80040154  # REGDB_E_CLASSNOTREG
        address = self._alloc_units(self._text_units(progid, True), True)
        self._mem_write(args[1], struct.pack('<I', address))
        return 0

    def CoCreateGuid(self, args):
        """CoCreateGuid(&GUID) - a random (version 4) GUID"""
        return 0 if self._mem_write(args[0], uuid.uuid4().bytes_le) else 0x80070057

    def CoInitializeEx(self, args):
        return self.CoInitialize(args)

    def CoGetMalloc(self, args):
        """CoGetMalloc(MEMCTX_TASK, &IMalloc) - the task allocator"""
        return self.SHGetMalloc([args[1]])

    def CoFreeUnusedLibraries(self, args):
        return 0

    CoFreeUnusedLibrariesEx = CoFreeAllLibraries = CoFreeUnusedLibraries

    def CoInitializeSecurity(self, args):
        return 0

    def CoSetProxyBlanket(self, args):
        return 0

    def CoRegisterMessageFilter(self, args):
        """CoRegisterMessageFilter(filter, &previous) - there was none"""
        if args[1]:
            self._mem_write(args[1], struct.pack('<I', 0))
        return 0

    def CoGetCurrentProcess(self, args):
        return self.GetCurrentProcessId(args)

    def CoFileTimeNow(self, args):
        """CoFileTimeNow(&FILETIME)"""
        return 0 if self._mem_write(args[0], struct.pack('<Q', self._filetime(time.time()))) \
            else 0x80070057

    def CoRegisterClassObject(self, args):
        """CoRegisterClassObject(CLSID, factory, context, flags, &cookie) -
        CoGetClassObject of the process finds the factory"""
        cookie = self.get_next_handle()
        if args[4]:
            self._mem_write(args[4], struct.pack('<I', cookie))
        if args[1]:
            classes = self.__dict__.setdefault('_class_objects', {})
            classes[cookie] = (self._read_guid(args[0]), args[1])
        return 0

    def CoRevokeClassObject(self, args):
        self.__dict__.get('_class_objects', {}).pop(args[0], None)
        return 0

    def _inproc_server(self, clsid):
        """The DLL HKEY_CLASSES_ROOT\\CLSID\\{clsid}\\InprocServer32 names ('' if none)"""
        node, _ = self._registry_walk(self.HKEY_CLASSES_ROOT, f"CLSID\\{{{clsid}}}\\InprocServer32")
        value = node['values'].get('') if node else None
        return str(value['data']).rstrip('\x00') if value else ''

    def CoGetClassObject(self, args):
        """CoGetClassObject(rclsid, context, server info, riid, ppv) - a
        factory the process registered (CoRegisterClassObject), else the
        DllGetClassObject of the class's in-process server DLL"""
        rclsid, _context, _info, riid, ppv = args[:5]
        clsid = self._read_guid(rclsid)
        if not ppv:
            return 0x80004003  # E_POINTER
        self._mem_write(ppv, struct.pack('<I', 0))
        for registered, factory in self.__dict__.get('_class_objects', {}).values():
            if registered == clsid:
                vtable = struct.unpack('<I', self.emu.uc.mem_read(factory, 4))[0]
                query = struct.unpack('<I', self.emu.uc.mem_read(vtable, 4))[0]
                return self.emu.call_callback(query, [factory, riid, ppv])
        path = self._inproc_server(clsid)
        if not path:
            log.debug(f"CoGetClassObject({{{clsid}}}): not registered")
            return 0x80040154  # REGDB_E_CLASSNOTREG
        handle = self._module_handle(path, load=True)
        module = self.emu.find_dll(handle) if handle else None
        entry = module['exports'].get('DllGetClassObject', 0) if module else 0
        log.debug(f"CoGetClassObject({{{clsid}}}) -> \"{path}\" (DllGetClassObject 0x{entry:x})")
        if not entry:
            return 0x8007007E if not handle else 0x80040154  # ERROR_MOD_NOT_FOUND
        return self.emu.call_callback(entry, [rclsid, riid, ppv])

    def CoLockObjectExternal(self, args):
        return 0

    def CoAddRefServerProcess(self, args):
        self.__dict__['_server_refs'] = self.__dict__.get('_server_refs', 0) + 1
        return self.__dict__['_server_refs']

    def CoReleaseServerProcess(self, args):
        self.__dict__['_server_refs'] = max(0, self.__dict__.get('_server_refs', 0) - 1)
        return self.__dict__['_server_refs']

    def CoWaitForMultipleHandles(self, args):
        """CoWaitForMultipleHandles(flags, ms, count, handles, &index)"""
        handles = list(struct.unpack(f'<{args[2]}I', self.emu.uc.mem_read(args[3], 4 * args[2]))) \
            if args[2] else []
        if not handles:
            return 0x80070057  # E_INVALIDARG
        result = self._wait_objects(handles, bool(args[0] & 1), args[1])  # COWAIT_WAITALL
        if result == 0x102:
            return 0x80010115  # RPC_S_CALLPENDING
        if result == 0xFFFFFFFF:
            return 0x80070006  # E_HANDLE
        if args[4]:
            self._mem_write(args[4], struct.pack('<I', result))
        return 0

    # ---------- rpcrt4 UUIDs ----------

    RPC_S_OK = 0
    RPC_S_INVALID_STRING_UUID = 1705
    NIL_UUID = '00000000-0000-0000-0000-000000000000'

    def UuidCreate(self, args):
        """UuidCreate(&UUID) - a random UUID"""
        return self.RPC_S_OK if self._mem_write(args[0], uuid.uuid4().bytes_le) else 1783

    def UuidCreateSequential(self, args):
        """UuidCreateSequential(&UUID) - a time-based (version 1) UUID"""
        return self.RPC_S_OK if self._mem_write(args[0], uuid.uuid1().bytes_le) else 1783

    def UuidCreateNil(self, args):
        self._write_guid(args[0], self.NIL_UUID)
        return self.RPC_S_OK

    def UuidToStringA(self, args, wide=False):
        """UuidToStringA/W(UUID, &RPC string) - "xxxxxxxx-xxxx-..." (lower case)"""
        text = self._read_guid(args[0]) if args[0] else self.NIL_UUID
        address = self._alloc_units(self._text_units(text, wide), wide)
        if not self._mem_write(args[1], struct.pack('<I', address)):
            return 1783  # RPC_X_BAD_STUB_DATA
        return self.RPC_S_OK if address else 14  # RPC_S_OUT_OF_MEMORY

    def UuidToStringW(self, args):
        return self.UuidToStringA(args, wide=True)

    def UuidFromStringA(self, args, wide=False):
        """UuidFromStringA/W(text, &UUID) - NULL text: the nil UUID"""
        if not args[0]:
            self._write_guid(args[1], self.NIL_UUID)
            return self.RPC_S_OK
        text = self._read_text(args[0], wide)
        if len(text) != 36:
            return self.RPC_S_INVALID_STRING_UUID
        try:
            value = uuid.UUID(text)
        except ValueError:
            return self.RPC_S_INVALID_STRING_UUID
        self._mem_write(args[1], value.bytes_le)
        return self.RPC_S_OK

    def UuidFromStringW(self, args):
        return self.UuidFromStringA(args, wide=True)

    def RpcStringFreeA(self, args):
        """RpcStringFreeA/W(&RPC string) - frees it and clears the pointer"""
        address = self._read_u32(args[0])
        if address:
            self.emu.heap_free(address)
        self._mem_write(args[0], struct.pack('<I', 0))
        return self.RPC_S_OK

    RpcStringFreeW = RpcStringFreeA

    def _uuid_status(self, address):
        if address:
            self._mem_write(address, struct.pack('<I', self.RPC_S_OK))

    def _uuid_value(self, address):
        return self._read_guid(address) if address else self.NIL_UUID

    def UuidIsNil(self, args):
        self._uuid_status(args[1])
        return 1 if self._uuid_value(args[0]) == self.NIL_UUID else 0

    def UuidEqual(self, args):
        self._uuid_status(args[2])
        return 1 if self._uuid_value(args[0]) == self._uuid_value(args[1]) else 0

    def UuidCompare(self, args):
        """UuidCompare(a, b, &status) - -1, 0 or 1 (by the UUID fields)"""
        self._uuid_status(args[2])
        first = uuid.UUID(self._uuid_value(args[0])).fields
        second = uuid.UUID(self._uuid_value(args[1])).fields
        return 0 if first == second else (0xFFFFFFFF if first < second else 1)

    def UuidHash(self, args):
        self._uuid_status(args[1])
        data = self._guid_bytes(self._uuid_value(args[0]))
        return sum(struct.unpack('<8H', data)) & 0xFFFF
