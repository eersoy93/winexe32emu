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

"""WinAPIHandler mixin: shell32 (file info, ShellExecute, SHFileOperation), ole32 drag and drop, advapi32"""

import os
import shutil
import struct
import ntpath

from .. import config, winapi
from ..logger import log


class Shell32Mixin:
    """shell32 (file info, ShellExecute, SHFileOperation), ole32 drag and drop, advapi32"""

    # ---------- shell32 ----------

    (SYS_ICON_FILE, SYS_ICON_FOLDER, SYS_ICON_DRIVE, SYS_ICON_ARCHIVE, SYS_ICON_EXE,
     SYS_ICON_COMPUTER) = range(6)
    ARCHIVE_EXTENSIONS = {'7z', 'zip', 'rar', 'gz', 'tgz', 'bz2', 'tbz2', 'xz', 'txz', 'tar',
                          'cab', 'arj', 'lzh', 'lzma', 'z', 'taz', 'iso', 'wim', 'zst', '001',
                          'cpio', 'rpm', 'deb', 'dmg', 'jar', 'apk', 'msi', 'squashfs'}

    def _system_imagelist(self, large):
        """The (fake) system image list: generic file, folder, drive, archive, program"""
        key = 'large' if large else 'small'
        handle = self._sys_imagelists.get(key)
        if handle is None:
            size = 32 if large else 16
            handle = self.get_next_handle()
            self.imagelists[handle] = {'cx': size, 'cy': size, 'flags': 0x21,
                                       'images': [('system', i) for i in range(6)]}
            self._sys_imagelists[key] = handle
        return handle

    def _sys_icon_index(self, name, attributes):
        if attributes & 0x10:
            return self.SYS_ICON_FOLDER
        if len(name) <= 3 and name[1:2] == ':':
            return self.SYS_ICON_DRIVE
        ext = name.rsplit('.', 1)[-1].lower() if '.' in name else ''
        if ext in self.ARCHIVE_EXTENSIONS:
            return self.SYS_ICON_ARCHIVE
        if ext in ('exe', 'com', 'bat', 'cmd'):
            return self.SYS_ICON_EXE
        return self.SYS_ICON_FILE

    def SHGetFileInfoA(self, args, wide=False):
        """SHGetFileInfoA/W emulation - type names, display names and indexes into
        the (fake) system image list"""
        pszPath, attributes, psfi, cbFileInfo, flags = args[:5]
        SHGFI_USEFILEATTRIBUTES, SHGFI_PIDL = 0x10, 0x8
        if flags & SHGFI_PIDL:
            path = self.pidls.get(pszPath, '')
        else:
            path = self._read_text(pszPath, wide) if pszPath else ''
        if self._is_my_computer(path):
            return self._my_computer_file_info(psfi, cbFileInfo, flags, wide)
        name = ntpath.basename(path.rstrip('\\')) or path
        if not flags & SHGFI_USEFILEATTRIBUTES and path:
            host = self.resolve_c_drive_path(path)
            if host is None or not os.path.exists(host):
                return 0
            attributes = 0x10 if os.path.isdir(host) else 0x80
        index = self._sys_icon_index(path if len(path) <= 3 else name, attributes)
        if attributes & 0x10:
            type_name = 'File folder' if len(path) > 3 else 'Local Disk'
        else:
            ext = name.rsplit('.', 1)[-1].upper() if '.' in name else ''
            type_name = f"{ext} File" if ext else 'File'
        return self._write_file_info(psfi, cbFileInfo, flags, wide, index,
                                     0x40000000 if attributes & 0x10 else 0, name, type_name)

    def _write_file_info(self, psfi, cbFileInfo, flags, wide, index, sfgao, name, type_name):
        """Fill SHFILEINFO; SHGetFileInfo's result"""
        SHGFI_SYSICONINDEX, SHGFI_SMALLICON, SHGFI_ICON = 0x4000, 0x1, 0x100
        if psfi:
            data = struct.pack('<IiI', self.get_next_handle() if flags & SHGFI_ICON else 0,
                               index, sfgao)
            if wide:
                data += name.encode('utf-16-le')[:518].ljust(520, b'\x00')
                data += type_name.encode('utf-16-le')[:158].ljust(160, b'\x00')
            else:
                data += name.encode(config.ANSI_CODEPAGE, 'replace')[:259].ljust(260, b'\x00')
                data += type_name.encode(config.ANSI_CODEPAGE, 'replace')[:79].ljust(80, b'\x00')
            self._mem_write(psfi, data[:max(cbFileInfo, 12)])
        if flags & SHGFI_SYSICONINDEX:
            return self._system_imagelist(not flags & SHGFI_SMALLICON)
        return 1

    def _my_computer_file_info(self, psfi, cbFileInfo, flags, wide):
        """SHGetFileInfo of My Computer (CSIDL_DRIVES): a system folder with
        the computer icon, like the desktop's My Computer"""
        SFGAO_FOLDER, SFGAO_HASSUBFOLDER = 0x20000000, 0x80000000
        return self._write_file_info(psfi, cbFileInfo, flags, wide, self.SYS_ICON_COMPUTER,
                                     SFGAO_FOLDER | SFGAO_HASSUBFOLDER,
                                     self.MY_COMPUTER_NAME, 'System Folder')

    def SHGetFileInfoW(self, args):
        return self.SHGetFileInfoA(args, wide=True)

    def SHGetSpecialFolderLocation(self, args):
        """SHGetSpecialFolderLocation emulation - a PIDL of the folder path"""
        csidl, ppidl = args[1], args[2]
        if csidl & 0xFF == self.CSIDL_DRIVES:
            folder = self.MY_COMPUTER_PATH
        else:
            folder = self._shell_folder(csidl & 0xFF)
        if folder is None:
            if ppidl:
                self._mem_write(ppidl, struct.pack('<I', 0))
            return 0x80004005  # E_FAIL
        pidl = self._make_pidl(folder)
        self._mem_write(ppidl, struct.pack('<I', pidl))
        return 0

    def SHChangeNotify(self, args):
        return 0

    def ExtractIconExA(self, args):
        """ExtractIconExA/W emulation - no icons are extracted"""
        if args[1] == 0xFFFFFFFF:
            return 0
        for ptr in (args[2], args[3]):
            if ptr:
                self._mem_write(ptr, struct.pack('<I', 0))
        return 0

    def ExtractIconExW(self, args):
        return self.ExtractIconExA(args)

    def _shell_execute(self, verb, file, params, directory, hwnd):
        """ShellExecute(Ex): run an EXE of the sandbox; returns (code > 32 on
        success, child emulator)"""
        full = self.full_windows_path(file) if file else None
        host = self.resolve_c_drive_path(full) if full else None
        log.info(f"ShellExecute(\"{verb}\", \"{file}\", \"{params}\")")
        if host is None or not os.path.exists(host):
            return 2, None  # SE_ERR_FNF
        if os.path.isdir(host):
            return 31, None  # SE_ERR_NOASSOC: no Explorer
        if not full.lower().endswith(('.exe', '.com')) or verb.lower() not in ('', 'open'):
            return 31, None
        starter = winapi.WinAPIHandler.process_starter
        if starter is None:
            return 31, None
        quoted = f'"{full}"' if ' ' in full else full
        cmdline = quoted + (' ' + params if params else '')
        current = self.full_windows_path(directory, clamp=True) if directory else \
            ntpath.dirname(full)
        child = starter(full, cmdline, current)
        return (42, child) if child is not None else (31, None)

    def ShellExecuteA(self, args, wide=False):
        """ShellExecuteA/W emulation"""
        hwnd, lpOperation, lpFile, lpParameters, lpDirectory = args[:5]
        verb = self._read_text(lpOperation, wide) if lpOperation else ''
        file = self._read_text(lpFile, wide) if lpFile else ''
        params = self._read_text(lpParameters, wide) if lpParameters else ''
        directory = self._read_text(lpDirectory, wide) if lpDirectory else ''
        code, _ = self._shell_execute(verb, file, params, directory, hwnd)
        return code

    def ShellExecuteW(self, args):
        return self.ShellExecuteA(args, wide=True)

    def ShellExecuteExA(self, args, wide=False):
        """ShellExecuteExA/W emulation (SHELLEXECUTEINFO)"""
        info = args[0]
        (_, mask, hwnd, lpVerb, lpFile, lpParameters, lpDirectory, _) = self._read_struct(
            info, '<8I')
        verb = self._read_text(lpVerb, wide) if lpVerb else ''
        file = self._read_text(lpFile, wide) if lpFile else ''
        if mask & 0xC and not file:  # SEE_MASK_IDLIST / SEE_MASK_INVOKEIDLIST
            file = self.pidls.get(self._read_struct(info, '<I' * 10)[9], '')
        params = self._read_text(lpParameters, wide) if lpParameters else ''
        directory = self._read_text(lpDirectory, wide) if lpDirectory else ''
        code, child = self._shell_execute(verb, file, params, directory, hwnd)
        self._mem_write(info + 32, struct.pack('<I', code))  # hInstApp
        if mask & 0x40 and child is not None:  # SEE_MASK_NOCLOSEPROCESS
            handle = self.get_next_handle()
            self.handles[handle] = {'type': 'process', 'emulator': child}
            self._mem_write(info + 56, struct.pack('<I', handle))
        if code <= 32:
            self._last_error = {2: 2, 31: 1155}.get(code, 1155)  # ERROR_NO_ASSOCIATION
            return 0
        return 1

    def ShellExecuteExW(self, args):
        return self.ShellExecuteExA(args, wide=True)

    def _read_multi_string(self, address, wide):
        """Double-NUL-terminated string list"""
        names = []
        while address and len(names) < 100000:
            text = self._read_text(address, wide)
            if not text:
                break
            names.append(text)
            address += (len(text) + 1) * (2 if wide else 1)
        return names

    FOF_NOCONFIRMATION = 0x10
    ERROR_CANCELLED = 1223

    def _confirm_delete(self, sources, hosts):
        """The shell's delete confirmation (there is no Recycle Bin: the
        files are deleted for good); True if confirmed"""
        if len(sources) == 1:
            name = ntpath.basename(sources[0].rstrip('\\'))
            if os.path.isdir(hosts[0]):
                caption = "Delete Folder"
                text = (f"Are you sure you want to permanently delete the folder '{name}' "
                        f"and all of its contents?")
            else:
                caption = "Delete File"
                text = f"Are you sure you want to permanently delete '{name}'?"
        else:
            caption = "Delete Multiple Items"
            text = f"Are you sure you want to permanently delete these {len(sources)} items?"
        return self._message_box(text, caption, 0x34) == 6  # MB_YESNO | MB_ICONEXCLAMATION

    def SHFileOperationA(self, args, wide=False):
        """SHFileOperationA/W emulation - delete/copy/move/rename in the sandbox
        (deleted files don't go to a Recycle Bin). Asks like the shell unless
        FOF_NOCONFIRMATION: before deleting and before replacing a file."""
        hwnd, func, p_from, p_to, flags = self._read_struct(args[0], '<IIIIH')
        sources = self._read_multi_string(p_from, wide)
        targets = self._read_multi_string(p_to, wide) if p_to else []
        log.info(f"SHFileOperation({func}, {sources}, {targets})")
        confirm = not flags & self.FOF_NOCONFIRMATION
        aborted = False

        def finish(code):
            self._mem_write(args[0] + 18, struct.pack('<I', 1 if aborted else 0))
            return code

        hosts = [self.resolve_c_drive_path(source) for source in sources]
        for src in hosts:
            if src is None or not os.path.exists(src):
                return finish(2)  # ERROR_FILE_NOT_FOUND (DE_FILENOTFOUND)
        if func == 3 and confirm and sources and not self._confirm_delete(sources, hosts):
            aborted = True
            return finish(self.ERROR_CANCELLED)
        try:
            for i, src in enumerate(hosts):
                if func == 3:  # FO_DELETE
                    if os.path.isdir(src):
                        shutil.rmtree(src)
                    else:
                        os.remove(src)
                    continue
                target = targets[i] if i < len(targets) else (targets[0] if targets else '')
                dst = self.resolve_c_drive_path(target)
                if dst is None:
                    return finish(5)
                if os.path.isdir(dst) and func in (1, 2):
                    dst = os.path.join(dst, os.path.basename(src))
                if os.path.isfile(dst) and os.path.isfile(src) and \
                        os.path.realpath(dst) != os.path.realpath(src):
                    if confirm:
                        answer = self._message_box(
                            f"This folder already contains a file named "
                            f"'{os.path.basename(dst)}'.\n\nWould you like to replace the "
                            f"existing file?", "Confirm File Replace", 0x33)  # YESNOCANCEL
                        if answer == 2:  # Cancel
                            aborted = True
                            return finish(self.ERROR_CANCELLED)
                        if answer == 7:  # No: skip this file
                            aborted = True
                            continue
                    os.remove(dst)
                if func == 2:  # FO_COPY
                    if os.path.isdir(src):
                        shutil.copytree(src, dst, dirs_exist_ok=True)
                    else:
                        shutil.copy2(src, dst)
                else:  # FO_MOVE, FO_RENAME
                    shutil.move(src, dst)
        except OSError as e:
            log.warning(f"SHFileOperation failed: {e}")
            return finish(5)  # ERROR_ACCESS_DENIED
        return finish(0)

    def SHFileOperationW(self, args):
        return self.SHFileOperationA(args, wide=True)

    # ---------- ole32 drag and drop ----------

    def RegisterDragDrop(self, args):
        return 0  # S_OK (nothing is ever dropped)

    def RevokeDragDrop(self, args):
        return 0

    def DoDragDrop(self, args):
        """DoDragDrop emulation - the drag is cancelled at once"""
        if args[3]:
            self._mem_write(args[3], struct.pack('<I', 0))
        return 0x00040101  # DRAGDROP_S_CANCEL

    def ReleaseStgMedium(self, args):
        return 0

    # ---------- advapi32 ----------

    def GetFileSecurityW(self, args):
        """GetFileSecurityW emulation - the file system has no security descriptors"""
        self._last_error = 50  # ERROR_NOT_SUPPORTED
        return 0

    def SetFileSecurityW(self, args):
        return 1

    def LsaOpenPolicy(self, args):
        return 0xC0000022  # STATUS_ACCESS_DENIED

    def LsaClose(self, args):
        return 0

    def LsaAddAccountRights(self, args):
        return 0xC0000022

    def LookupAccountNameW(self, args):
        self._last_error = 1332  # ERROR_NONE_MAPPED
        return 0
