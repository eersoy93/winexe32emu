# Copyright 2026 Erdem Ersoy (eersoy93)
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

"""WinAPIHandler mixin: lz32.dll, the files compressed by COMPRESS.EXE
(SZDD format) that setup programs expand while they copy them"""

import struct

from unicorn import UcError

from ..logger import log


SZDD_SIGNATURE = b'SZDD\x88\xf0\x27\x33'

# LZERROR_* results (negative LONGs)
LZERROR_BADINHANDLE = -1
LZERROR_BADOUTHANDLE = -2
LZERROR_READ = -3
LZERROR_WRITE = -4
LZERROR_BADVALUE = -7


def is_szdd(data):
    return data[:8] == SZDD_SIGNATURE and len(data) >= 14


def expand_szdd(data):
    """Contents of a file compressed by COMPRESS.EXE (SZDD, LZSS with a 4 KiB
    window); other data is returned unchanged"""
    if not is_szdd(data):
        return data
    size = struct.unpack_from('<I', data, 10)[0]
    window = bytearray(b' ' * 4096)
    position = 4096 - 16
    out = bytearray()
    i, n = 14, len(data)
    while i < n and len(out) < size:
        flags = data[i]
        i += 1
        for bit in range(8):
            if i >= n or len(out) >= size:
                break
            if flags & (1 << bit):  # A literal byte
                byte = data[i]
                i += 1
                out.append(byte)
                window[position] = byte
                position = (position + 1) & 0xFFF
            else:  # A match: 12-bit window offset, 4-bit length - 3
                if i + 1 >= n:
                    i = n
                    break
                offset = data[i] | ((data[i + 1] & 0xF0) << 4)
                length = (data[i + 1] & 0x0F) + 3
                i += 2
                for k in range(length):
                    byte = window[(offset + k) & 0xFFF]
                    out.append(byte)
                    window[position] = byte
                    position = (position + 1) & 0xFFF
    return bytes(out[:size])


def expanded_name(name, data):
    """The original name of a compressed file ("FILE.EX_" -> "FILE.EXE"), from
    the last character its SZDD header keeps"""
    if not is_szdd(data) or not name.endswith('_'):
        return name
    last = chr(data[9]) if data[9] else ''
    return name[:-1] + last if last else name[:-1].rstrip('.')


class Lz32Mixin:
    """LZOpenFile, LZRead, LZSeek, LZCopy and the other lz32 functions"""

    def _lz_files(self):
        """LZ handles of compressed files: {handle: {'data', 'pos'}}"""
        return self.__dict__.setdefault('_lz_handles', {})

    def _lz_new_handle(self, data):
        files = self._lz_files()
        handle = 0x400
        while handle in files or handle in self.handles:
            handle += 1
        files[handle] = {'data': data, 'pos': 0}
        return handle

    def _hfile_read_all(self, handle):
        """Rest of an open file (from its position), None if not a file"""
        info = self.handles.get(handle)
        if not info or not info.get('fp'):
            return None
        try:
            return info['fp'].read()
        except OSError:
            return None

    def _lz_init(self, handle):
        """LZ handle reading a compressed file, or the file handle itself"""
        info = self.handles.get(handle)
        if not info or not info.get('fp'):
            return LZERROR_BADINHANDLE & 0xFFFFFFFF
        fp = info['fp']
        try:
            start = fp.tell()
            header = fp.read(14)
            if not is_szdd(header):
                fp.seek(start)
                return handle
            fp.seek(start)
            data = expand_szdd(fp.read())
        except OSError:
            return LZERROR_READ & 0xFFFFFFFF
        self.CloseHandle([handle])
        return self._lz_new_handle(data)

    def LZOpenFileA(self, args, wide=False):
        """LZOpenFileA/W(lpFileName, lpReOpenBuf, wStyle) - like OpenFile; a
        compressed file is opened expanded. A missing "NAME.EXT" is looked for
        as its compressed name "NAME.EX_"."""
        address, ofs, style = args[0], args[1], args[2]
        if wide:  # OpenFile takes an ANSI name
            name = self.read_wide_string(address)
            address = self.emu.heap_alloc(len(name) * 2 + 2)
            self._write_text(address, name, False)
        handle = self.OpenFile([address, ofs, style])
        if handle == self.HFILE_ERROR and not style & 0x1000:  # OF_CREATE
            name = self.read_string(address)
            if name and not name.endswith('_'):
                alt = self.emu.heap_alloc(len(name) + 2)
                self._write_text(alt, name[:-1] + '_' if '.' in name[-4:] else name + '._',
                                 False)
                handle = self.OpenFile([alt, ofs, style])
        if handle == self.HFILE_ERROR:
            return LZERROR_BADINHANDLE & 0xFFFFFFFF
        if style & 0x5303:  # OF_EXIST, OF_CREATE, OF_DELETE, OF_PARSE, write access
            return handle
        return self._lz_init(handle)

    def LZOpenFileW(self, args):
        return self.LZOpenFileA(args, wide=True)

    def LZInit(self, args):
        """LZInit(hfSource) - an LZ handle if the file is compressed"""
        return self._lz_init(args[0])

    def LZStart(self, args):
        return 1

    def LZDone(self, args):
        return 0

    def LZRead(self, args):
        """LZRead(hFile, lpBuffer, cbRead) - the bytes read"""
        handle, buffer, count = args[0], args[1], self._signed32(args[2])
        lz = self._lz_files().get(handle)
        if lz is None:
            if handle not in self.handles:
                return LZERROR_BADINHANDLE & 0xFFFFFFFF
            return self._lread(args)
        data = lz['data'][lz['pos']:lz['pos'] + max(count, 0)]
        if data and not self._mem_write(buffer, data):
            return LZERROR_BADVALUE & 0xFFFFFFFF
        lz['pos'] += len(data)
        return len(data)

    def LZSeek(self, args):
        """LZSeek(hFile, lOffset, iOrigin) - the new position"""
        handle, offset, origin = args[0], self._signed32(args[1]), args[2]
        lz = self._lz_files().get(handle)
        if lz is None:
            if handle not in self.handles:
                return LZERROR_BADINHANDLE & 0xFFFFFFFF
            return self._llseek(args)
        base = {0: 0, 1: lz['pos'], 2: len(lz['data'])}.get(origin)
        if base is None or base + offset < 0:
            return LZERROR_BADVALUE & 0xFFFFFFFF
        lz['pos'] = base + offset
        return lz['pos']

    def LZClose(self, args):
        if self._lz_files().pop(args[0], None) is None and args[0] in self.handles:
            self.CloseHandle([args[0]])
        return 0

    def LZCopy(self, args):
        """LZCopy(hfSource, hfDest) - expands the source into the destination;
        the bytes written, or an LZERROR_* value"""
        source, dest = args[0], args[1]
        lz = self._lz_files().get(source)
        if lz is not None:
            data = lz['data'][lz['pos']:]
            lz['pos'] = len(lz['data'])
        else:
            data = self._hfile_read_all(source)
            if data is None:
                return LZERROR_BADINHANDLE & 0xFFFFFFFF
            data = expand_szdd(data)
        info = self.handles.get(dest)
        if not info or not info.get('fp'):
            return LZERROR_BADOUTHANDLE & 0xFFFFFFFF
        try:
            info['fp'].write(data)
        except OSError as e:
            log.warning(f"LZCopy: {e}")
            return LZERROR_WRITE & 0xFFFFFFFF
        return len(data)

    def CopyLZFile(self, args):
        return self.LZCopy(args)

    def GetExpandedNameA(self, args, wide=False):
        """GetExpandedNameA/W(lpszSource, lpszBuffer) - the original name of a
        compressed file (the name itself if it is not compressed)"""
        name = self._read_text(args[0], wide)
        path = self.resolve_drive_path(name) if name else None
        try:
            with open(path, 'rb') as f:
                header = f.read(14)
        except (OSError, TypeError):
            header = b''
        try:
            self._write_text(args[1], expanded_name(name, header), wide)
        except UcError:
            return LZERROR_BADVALUE & 0xFFFFFFFF
        return 1

    def GetExpandedNameW(self, args):
        return self.GetExpandedNameA(args, wide=True)
