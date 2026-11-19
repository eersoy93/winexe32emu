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

"""WinAPIHandler mixin: version.dll (version resources of files)"""

import os
import struct

from unicorn import UcError

from .. import config
from ..logger import log
from .lz32 import expand_szdd

try:
    import pefile
except ImportError:  # pragma: no cover - pefile is a requirement
    pefile = None


class VersionInfoMixin:
    """version.dll: GetFileVersionInfoSize, GetFileVersionInfo, VerQueryValue"""

    RT_VERSION = 16

    def _version_file_host_path(self, name):
        """Host path of a file named like LoadLibrary does (a bare name is
        searched in the SearchPath folders)"""
        names = [name]
        if '\\' not in name and '/' not in name and name[1:2] != ':':
            names = [d.rstrip('\\') + '\\' + name for d in self._search_path_dirs()]
        for candidate in names:
            full = self.full_windows_path(candidate)
            host = self.resolve_drive_path(full) if full else None
            if host and os.path.isfile(host):
                return host
        return None

    def _version_resource(self, name):
        """Raw VS_VERSIONINFO block of a PE file, or None (last error set)"""
        host = self._version_file_host_path(name) if name else None
        if host is None:
            self._last_error = 2  # ERROR_FILE_NOT_FOUND
            return None
        try:
            pe = pefile.PE(host, fast_load=True)
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
            for type_entry in getattr(pe, 'DIRECTORY_ENTRY_RESOURCE', None).entries:
                if type_entry.id != self.RT_VERSION:
                    continue
                for name_entry in type_entry.directory.entries:
                    for lang in name_entry.directory.entries:
                        data = lang.data.struct
                        return pe.get_data(data.OffsetToData, data.Size)
        except (pefile.PEFormatError, AttributeError, OSError):
            pass
        self._last_error = 1813  # ERROR_RESOURCE_TYPE_NOT_FOUND
        return None

    def GetFileVersionInfoSizeA(self, args, wide=False):
        """GetFileVersionInfoSizeA/W emulation - room for the version resource
        and the ANSI copies of its strings (VerQueryValueA)"""
        name = self._read_text(args[0], wide) if args[0] else ''
        if args[1]:
            self._mem_write(args[1], struct.pack('<I', 0))
        raw = self._version_resource(name)
        log.debug(f"GetFileVersionInfoSize(\"{name}\") -> {len(raw) if raw else 0}")
        return 2 * len(raw) if raw else 0

    def GetFileVersionInfoSizeW(self, args):
        return self.GetFileVersionInfoSizeA(args, wide=True)

    def GetFileVersionInfoA(self, args, wide=False):
        """GetFileVersionInfoA/W emulation"""
        name = self._read_text(args[0], wide) if args[0] else ''
        dwLen, lpData = args[2], args[3]
        raw = self._version_resource(name)
        if raw is None or not lpData:
            return 0
        data = raw[:dwLen]
        self._mem_write(lpData, data + b'\x00' * (dwLen - len(data)))
        return 1

    def GetFileVersionInfoW(self, args):
        return self.GetFileVersionInfoA(args, wide=True)

    @staticmethod
    def _version_node(block, offset):
        """(length, value length, type, key, value offset, children offset) of
        the version node at offset"""
        length, value_length, value_type = struct.unpack_from('<HHH', block, offset)
        end = offset + 6
        while block[end:end + 2] != b'\x00\x00':
            end += 2
        key = block[offset + 6:end].decode('utf-16-le', 'replace')
        value = (end + 2 + 3) & ~3
        size = value_length * (2 if value_type == 1 else 1)
        children = (value + size + 3) & ~3
        return length, value_length, value_type, key, value, children

    def VerQueryValueA(self, args, wide=False):
        """VerQueryValueA/W emulation - "\\" (VS_FIXEDFILEINFO),
        "\\VarFileInfo\\Translation" and "\\StringFileInfo\\<lang>\\<name>";
        VerQueryValueA hands out ANSI copies of the strings"""
        pBlock, lpSubBlock, lplpBuffer, puLen = args[:4]
        sub = self._read_text(lpSubBlock, wide) if lpSubBlock else ''
        try:
            total = struct.unpack('<H', self.emu.uc.mem_read(pBlock, 2))[0]
            block = bytes(self.emu.uc.mem_read(pBlock, total))
        except (UcError, struct.error):
            return 0
        offset = 0
        try:
            node = self._version_node(block, offset)
            for part in [p for p in sub.split('\\') if p]:
                child, end = node[5], offset + node[0]
                while child < end:
                    found = self._version_node(block, child)
                    if found[0] == 0:
                        child = end
                        break
                    if found[3].lower() == part.lower():
                        break
                    child = (child + found[0] + 3) & ~3
                if child >= end:
                    log.debug(f"VerQueryValue(\"{sub}\") -> not found")
                    self._last_error = 1813  # ERROR_RESOURCE_TYPE_NOT_FOUND
                    return 0
                offset, node = child, found
        except (struct.error, IndexError):
            return 0
        _, value_length, value_type, _, value, _ = node
        if value_length == 0:
            return 0
        address, length = pBlock + value, value_length
        if value_type == 1 and not wide:
            text = block[value:value + 2 * value_length].decode('utf-16-le', 'replace')
            text = text.split('\x00', 1)[0]
            data = text.encode(config.ANSI_CODEPAGE, 'replace') + b'\x00'
            # The ANSI copy goes to the second half of the buffer
            # (GetFileVersionInfoSizeA makes room for it)
            address = pBlock + total + value
            self._mem_write(address, data)
            length = len(data)
        log.debug(f"VerQueryValue(\"{sub}\") -> 0x{address:x} ({length})")
        if lplpBuffer:
            self._mem_write(lplpBuffer, struct.pack('<I', address))
        if puLen:
            self._mem_write(puLen, struct.pack('<I', length))
        return 1

    def VerQueryValueW(self, args):
        return self.VerQueryValueA(args, wide=True)

    # ---------- Installing files (VerFindFile, VerInstallFile) ----------

    VFFF_ISSHAREDFILE = 0x1
    VFF_CURNEDEST = 0x1
    VFF_BUFFTOOSMALL = 0x4
    VIFF_FORCEINSTALL = 0x1
    VIF_TEMPFILE = 0x1
    VIF_SRCOLD = 0x4
    VIF_WRITEPROT = 0x40
    VIF_CANNOTCREATE = 0x800
    VIF_CANNOTREADSRC = 0x10000
    VIF_BUFFTOOSMALL = 0x40000

    def _write_sized_text(self, buffer, size_ptr, text):
        """Write text to a buffer whose size (with the NUL) is in *size_ptr,
        which receives the needed size; False if it does not fit"""
        size = self._read_u32(size_ptr) if size_ptr else 0
        needed = len(text.encode(config.ANSI_CODEPAGE, errors='replace')) + 1
        if size_ptr:
            self._mem_write(size_ptr, struct.pack('<I', needed))
        if not buffer or size < needed:
            return False
        self._write_text(buffer, text, False)
        return True

    def VerFindFileA(self, args):
        """VerFindFileA(uFlags, szFileName, szWinDir, szAppDir, szCurDir,
        puCurDirLen, szDestDir, puDestDirLen) - where a file being installed
        should go (the system folder for shared files, else the application's
        folder) and where a version of it already is"""
        flags = args[0]
        name = self.read_string(args[1]) if args[1] else ''
        win_dir = self.read_string(args[2]) if args[2] else 'C:\\Windows'
        app_dir = self.read_string(args[3]) if args[3] else ''
        system_dir = 'C:\\Windows\\System32'
        dest = system_dir if flags & self.VFFF_ISSHAREDFILE or not app_dir else app_dir
        current = ''
        for folder in (dest, system_dir, win_dir, app_dir):
            if not folder or not name:
                continue
            host = self.resolve_drive_path(folder.rstrip('\\') + '\\' + name)
            if host and os.path.isfile(host):
                current = folder.rstrip('\\') or folder
                break
        log.debug(f"VerFindFileA(\"{name}\") -> current \"{current}\", destination \"{dest}\"")
        result = 0
        if not self._write_sized_text(args[4], args[5], current):
            result |= self.VFF_BUFFTOOSMALL
        if not self._write_sized_text(args[6], args[7], dest):
            result |= self.VFF_BUFFTOOSMALL
        if current and current.lower() != dest.rstrip('\\').lower():
            result |= self.VFF_CURNEDEST
        return result

    @staticmethod
    def _fixed_file_version(data):
        """(file version MS, LS) of the VS_FIXEDFILEINFO in a file's bytes, or None"""
        index = data.find(b'\xbd\x04\xef\xfe')
        if index < 0 or index + 16 > len(data):
            return None
        return struct.unpack_from('<II', data, index + 8)

    def VerInstallFileA(self, args):
        """VerInstallFileA(uFlags, szSrcFileName, szDestFileName, szSrcDir,
        szDestDir, szCurDir, szTmpFile, puTmpFileLen) - copies (and expands) a
        file into the destination folder. Unless forced, a newer installed
        version is kept: the source is left as a temporary file
        (VIF_TEMPFILE | VIF_SRCOLD)."""
        flags = args[0]
        src_name, dest_name, src_dir, dest_dir = (
            self.read_string(a) if a else '' for a in args[1:5])
        source = self.resolve_drive_path(src_dir.rstrip('\\') + '\\' + src_name)
        dest_folder = self.resolve_drive_path(dest_dir) if dest_dir else None
        log.info(f"VerInstallFile: \"{src_dir}\\{src_name}\" -> \"{dest_dir}\\{dest_name}\"")
        try:
            with open(source, 'rb') as f:
                data = expand_szdd(f.read())
        except (OSError, TypeError):
            return self.VIF_CANNOTREADSRC
        if dest_folder is None or self._write_protected(dest_folder):
            return self.VIF_WRITEPROT
        dest = os.path.join(dest_folder, dest_name)
        existing = None
        if os.path.isfile(dest):
            try:
                with open(dest, 'rb') as f:
                    existing = f.read()
            except OSError:
                existing = None
        new_version = self._fixed_file_version(data)
        old_version = self._fixed_file_version(existing) if existing else None
        if (not flags & self.VIFF_FORCEINSTALL and new_version and old_version and
                old_version > new_version):
            temp_name = 'VER' + format(os.getpid() & 0xFFFF, '04X') + '.TMP'
            try:
                with open(os.path.join(dest_folder, temp_name), 'wb') as f:
                    f.write(data)
            except OSError:
                return self.VIF_CANNOTCREATE
            result = self.VIF_TEMPFILE | self.VIF_SRCOLD
            if not self._write_sized_text(args[6], args[7], temp_name):
                result |= self.VIF_BUFFTOOSMALL
            return result
        try:
            os.makedirs(dest_folder, exist_ok=True)
            with open(dest, 'wb') as f:
                f.write(data)
        except OSError as e:
            log.warning(f"VerInstallFile: {e}")
            return self.VIF_CANNOTCREATE
        if args[7]:
            self._mem_write(args[7], struct.pack('<I', 0))
        return 0
