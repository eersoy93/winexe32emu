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

"""WinAPIHandler mixin: the shell's virtual folders besides My Computer (the
Recycle Bin, the network) and the Recycle Bin APIs (SHFileOperation's
FOF_ALLOWUNDO, SHQueryRecycleBin, SHEmptyRecycleBin). The bin store itself is
src/recycle_bin.py."""

import os
import shutil
import struct
import ntpath

from unicorn import UcError

from .. import recycle_bin
from ..logger import log


class ShellNamespaceMixin:
    """The Recycle Bin and the network folder of the shell namespace"""

    # Parsing names of the virtual folders (their CLSIDs, like My Computer's):
    # Explorer takes them on its command line
    RECYCLE_BIN_PATH = '::{645FF040-5081-101B-9F08-00AA002F954E}'
    NETWORK_PATH = '::{208D2C60-3AEA-1069-A2D7-08002B30309D}'
    RECYCLE_BIN_NAME = 'Recycle Bin'
    NETWORK_NAME = 'Network'
    # CSIDL_BITBUCKET, CSIDL_NETWORK -> parsing name
    VIRTUAL_FOLDERS = {0x0A: RECYCLE_BIN_PATH, 0x12: NETWORK_PATH}

    # Bases of the desktop's own icons in the system image lists (after the
    # six fixed ones of Shell32Mixin; the GUI draws them, desktop_icons.py)
    SYS_ICON_USER, SYS_ICON_NETWORK, SYS_ICON_BIN_EMPTY, SYS_ICON_BIN_FULL = 6, 7, 8, 9

    FOF_MULTIDESTFILES, FOF_ALLOWUNDO = 0x1, 0x40
    SHERB_NOCONFIRMATION = 0x1

    def _is_virtual_folder(self, path):
        """Is path the Recycle Bin's or the network's parsing name?"""
        return path is not None and path.upper() in (self.RECYCLE_BIN_PATH, self.NETWORK_PATH)

    def _virtual_folder_file_info(self, path, psfi, cbFileInfo, flags, wide):
        """SHGetFileInfo of the Recycle Bin (its icon shows whether it is
        empty) or of the network (empty: the PC has no network)"""
        SFGAO_FOLDER = 0x20000000
        if path.upper() == self.RECYCLE_BIN_PATH:
            full = recycle_bin.query()[1] > 0
            base = self.SYS_ICON_BIN_FULL if full else self.SYS_ICON_BIN_EMPTY
            name = self.RECYCLE_BIN_NAME
        else:
            base, name = self.SYS_ICON_NETWORK, self.NETWORK_NAME
        index = self._sys_file_icon(('shell', base, None))
        return self._write_file_info(psfi, cbFileInfo, flags, wide, index, SFGAO_FOLDER, name,
                                     'System Folder')

    # ---------- SHFileOperation and the Recycle Bin ----------

    @staticmethod
    def _recyclable(hosts):
        """Can all these files go to a Recycle Bin? (Not on the floppy A:,
        nor items already in a bin: those are deleted for good)"""
        return bool(hosts) and all(recycle_bin.can_recycle(host) for host in hosts)

    @staticmethod
    def _in_recycle_store(host):
        return host is not None and recycle_bin.store_letter(host) is not None

    @staticmethod
    def _recycle_forget(host):
        """A bin item was deleted for good (FO_DELETE of the bin's own file)"""
        if recycle_bin.store_letter(host):
            recycle_bin.forget(host)

    def _confirm_recycle(self, sources, hosts):
        """The shell's question before sending files to the Recycle Bin"""
        if len(sources) == 1:
            name = ntpath.basename(sources[0].rstrip('\\'))
            if os.path.isdir(hosts[0]):
                caption = "Confirm Folder Delete"
                text = (f"Are you sure you want to remove the folder '{name}' and move all "
                        f"its contents to the Recycle Bin?")
            else:
                caption = "Confirm File Delete"
                text = f"Are you sure you want to send '{name}' to the Recycle Bin?"
        else:
            caption = "Confirm Multiple File Delete"
            text = f"Are you sure you want to send these {len(sources)} items to the Recycle Bin?"
        return self._message_box(text, caption, 0x34) == 6  # MB_YESNO | MB_ICONEXCLAMATION

    def _recycle_files(self, sources, hosts, confirm):
        """FO_DELETE with FOF_ALLOWUNDO: move the files into their drive's
        bin; SHFileOperation's result code"""
        if confirm and not self._confirm_recycle(sources, hosts):
            return self.ERROR_CANCELLED
        for source, host in zip(sources, hosts, strict=False):
            try:
                recycle_bin.recycle(host)
            except (OSError, ValueError) as e:
                log.warning(f"Cannot send {source} to the Recycle Bin: {e}")
                return 5  # ERROR_ACCESS_DENIED
        return 0

    def _recycle_move_out(self, src, dst, flags, confirm):
        """FO_MOVE / FO_RENAME of a bin item (Explorer's Restore): it gets
        its original name in a folder target, its folders are made again;
        0 when done, None if the user skipped it, else an error code"""
        item = recycle_bin.find(src)
        if os.path.isdir(dst) and not flags & self.FOF_MULTIDESTFILES:
            dst = os.path.join(dst, item.name if item else os.path.basename(src))
        if os.path.lexists(dst) and os.path.realpath(dst) != os.path.realpath(src):
            if confirm:
                kind = 'folder' if os.path.isdir(dst) else 'file'
                answer = self._message_box(
                    f"This folder already contains a {kind} named '{os.path.basename(dst)}'."
                    f"\n\nWould you like to replace the existing {kind}?",
                    f"Confirm {kind.capitalize()} Replace", 0x33)  # MB_YESNOCANCEL
                if answer == 2:
                    return self.ERROR_CANCELLED
                if answer == 7:
                    return None
            if os.path.isdir(dst):
                shutil.rmtree(dst)
            else:
                os.remove(dst)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.move(src, dst)
        recycle_bin.forget(src)
        return 0

    # ---------- Recycle Bin APIs ----------

    def _recycle_bin_drives(self, p_root, wide):
        """Drives a root path argument names (NULL / "": all bins), or None
        if it names no drive"""
        root = self._read_text(p_root, wide) if p_root else ''
        if not root:
            return recycle_bin.bin_drives()
        letter = recycle_bin.drive_of_root(root)
        if letter is None or letter not in self.LOGICAL_DRIVES:
            return None
        return [letter] if letter in recycle_bin.bin_drives() else []

    def SHQueryRecycleBinA(self, args, wide=False):
        """SHQueryRecycleBinA/W(root, SHQUERYRBINFO) - total size and number
        of the items in the bin of a drive (or of all drives)"""
        p_root, info = args[0], args[1]
        drives = self._recycle_bin_drives(p_root, wide)
        if drives is None or not info:
            return 0x80070057  # E_INVALIDARG
        try:
            size = struct.unpack('<I', self.emu.uc.mem_read(info, 4))[0]
        except UcError:
            return 0x80070057
        if size < 20:  # cbSize, i64Size, i64NumItems (packed)
            return 0x80070057
        total, count = recycle_bin.query(drives) if drives else (0, 0)
        self._mem_write(info + 4, struct.pack('<qq', total, count))
        return 0  # S_OK

    def SHQueryRecycleBinW(self, args):
        return self.SHQueryRecycleBinA(args, wide=True)

    def SHEmptyRecycleBinA(self, args, wide=False):
        """SHEmptyRecycleBinA/W(hwnd, root, flags) - delete the bin's items
        for good, after asking unless SHERB_NOCONFIRMATION"""
        p_root, flags = args[1], args[2]
        drives = self._recycle_bin_drives(p_root, wide)
        if drives is None:
            return 0x80070057  # E_INVALIDARG
        found = recycle_bin.items(drives) if drives else []
        if not found:
            return 0  # S_OK: nothing to delete
        if not flags & self.SHERB_NOCONFIRMATION:
            if len(found) == 1:
                caption = "Confirm File Delete"
                text = f"Are you sure you want to permanently delete '{found[0].name}'?"
            else:
                caption = "Confirm Multiple File Delete"
                text = f"Are you sure you want to permanently delete these {len(found)} items?"
            if self._message_box(text, caption, 0x34) != 6:
                return 0x800704C7  # HRESULT_FROM_WIN32(ERROR_CANCELLED)
        log.info(f"SHEmptyRecycleBin: {len(found)} item(s) deleted")
        recycle_bin.empty(drives)
        return 0

    def SHEmptyRecycleBinW(self, args):
        return self.SHEmptyRecycleBinA(args, wide=True)
