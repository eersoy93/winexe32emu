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

"""WinAPIHandler mixin: INI files (GetPrivateProfileString /
WritePrivateProfileString), environment strings"""

import re

from unicorn import UcError

from .. import config
from ..logger import log


class IniFilesMixin:
    """INI files (GetPrivateProfileString / WritePrivateProfileString), environment strings"""

    # ---------- INI files (GetPrivateProfileString / WritePrivateProfileString) ----------

    def _profile_path(self, filename):
        """Host path of an INI file; a bare name lives in the Windows directory"""
        if '\\' not in filename and '/' not in filename:
            filename = "C:\\Windows\\" + filename
        return self.resolve_drive_path(filename)

    @staticmethod
    def _ini_section_name(line):
        """Section name of a "[name]" line, else None"""
        line = line.strip()
        if line.startswith('[') and ']' in line:
            return line[1:line.index(']')].strip()
        return None

    @staticmethod
    def _ini_key_value(line):
        """(key, value) of a "key=value" line, else None"""
        if line.lstrip().startswith(';') or '=' not in line:
            return None
        key, _, value = line.partition('=')
        return key.strip(), value.strip()

    def _ini_read_lines(self, path):
        try:
            with open(path, 'rb') as fp:
                return fp.read().decode(config.ANSI_CODEPAGE, errors='replace').splitlines()
        except OSError:
            return None

    def _ini_section_range(self, lines, section):
        """(header index, end index) of a section (case-insensitive), or None"""
        start = None
        for i, line in enumerate(lines):
            name = self._ini_section_name(line)
            if name is None:
                continue
            if start is not None:
                return (start, i)
            if name.lower() == section.lower():
                start = i
        return None if start is None else (start, len(lines))

    def _ini_value(self, lines, section, key):
        """Value of a key in INI lines (enclosing quotes removed), or None"""
        bounds = self._ini_section_range(lines, section)
        if bounds:
            for line in lines[bounds[0] + 1:bounds[1]]:
                pair = self._ini_key_value(line)
                if pair and pair[0].lower() == key.lower():
                    value = pair[1]
                    if len(value) >= 2 and value[0] == value[-1] and value[0] in '"\'':
                        value = value[1:-1]
                    return value
        return None

    def GetPrivateProfileIntA(self, args, wide=False):
        """GetPrivateProfileIntA/W emulation - the leading integer of a value
        (decimal, or hexadecimal with 0x); nDefault if the key is missing"""
        lpAppName, lpKeyName, nDefault, lpFileName = args[:4]
        section = self._read_text(lpAppName, wide) if lpAppName else ''
        key = self._read_text(lpKeyName, wide) if lpKeyName else ''
        filename = self._read_text(lpFileName, wide) if lpFileName else ''
        path = self._profile_path(filename) if filename else None
        lines = (self._ini_read_lines(path) if path else None) or []
        value = self._ini_value(lines, section, key) if lpAppName and lpKeyName else None
        log.debug(f"GetPrivateProfileInt({section!r}, {key!r}, \"{filename}\") -> {value!r}")
        if value is None:
            return nDefault
        match = re.match(r'\s*([-+]?)(0[xX][0-9a-fA-F]+|\d+)', value)
        if not match:
            return 0
        digits = match.group(2)
        number = int(digits, 16) if digits[:2].lower() == '0x' else int(digits)
        return (-number if match.group(1) == '-' else number) & 0xFFFFFFFF

    def GetPrivateProfileIntW(self, args):
        return self.GetPrivateProfileIntA(args, wide=True)

    def _ini_lines_of(self, filename):
        path = self._profile_path(filename) if filename else None
        return (self._ini_read_lines(path) if path else None) or []

    def _ini_section_lines(self, lines, section):
        """The key=value (and other non-blank) lines of a section"""
        bounds = self._ini_section_range(lines, section)
        if not bounds:
            return []
        return [line.strip() for line in lines[bounds[0] + 1:bounds[1]]
                if line.strip() and not line.lstrip().startswith(';')]

    def _write_name_list(self, names, buffer, size, wide):
        """Copy NUL-separated names ending with an extra NUL (truncated to
        size, the last name still ends with two NULs); returns the length
        without the final NUL (size - 2 if truncated)"""
        units = []
        for name in names:
            units += self._text_units(name, wide) + [0]
        if len(units) + 1 > size:
            units = units[:max(0, size - 2)]
            self._write_units(buffer, (units + [0, 0])[:size], wide, terminate=False)
            return len(units)
        self._write_units(buffer, units, wide)
        return len(units)

    def GetPrivateProfileStringA(self, args, wide=False):
        """GetPrivateProfileStringA/W emulation (INI files inside drives/)"""
        lpAppName, lpKeyName, lpDefault = args[0], args[1], args[2]
        lpReturnedString, nSize, lpFileName = args[3], args[4], args[5]
        section = self._read_text(lpAppName, wide) if lpAppName else None
        key = self._read_text(lpKeyName, wide) if lpKeyName else None
        default = self._read_text(lpDefault, wide).rstrip(' ') if lpDefault else ''
        filename = self._read_text(lpFileName, wide) if lpFileName else 'win.ini'
        log.debug(f"GetPrivateProfileString({section!r}, {key!r}, {default!r}, \"{filename}\")")

        if not lpReturnedString or nSize == 0:
            return 0
        lines = self._ini_lines_of(filename)

        if section is None or key is None:
            # Name lists: every name NUL-terminated, the list ends with an extra NUL
            if section is None:
                names = [n for n in map(self._ini_section_name, lines) if n is not None]
            else:
                names = [pair[0] for pair in map(self._ini_key_value,
                                                 self._ini_section_lines(lines, section))
                         if pair]
            return self._write_name_list(names, lpReturnedString, nSize, wide)

        value = self._ini_value(lines, section, key)
        if value is None:
            value = default

        units = self._text_units(value, wide)[:nSize - 1]
        self._write_units(lpReturnedString, units, wide)
        return len(units)

    def GetPrivateProfileStringW(self, args):
        return self.GetPrivateProfileStringA(args, wide=True)

    def _ini_save(self, path, lines, filename):
        if self._write_protected(path):
            return 0
        try:
            with open(path, 'wb') as fp:
                fp.write(''.join(line + '\r\n' for line in lines)
                         .encode(config.ANSI_CODEPAGE, errors='replace'))
        except OSError as e:
            log.error(f"WritePrivateProfile(\"{filename}\") failed: {e}")
            self._last_error = 3  # ERROR_PATH_NOT_FOUND
            return 0
        return 1

    def WritePrivateProfileStringA(self, args, wide=False):
        """WritePrivateProfileStringA/W emulation (NULL key deletes the section,
        NULL string deletes the key)"""
        lpAppName, lpKeyName, lpString, lpFileName = args[0], args[1], args[2], args[3]
        if not lpAppName:
            return 0  # Only flushes the (nonexistent) cache
        section = self._read_text(lpAppName, wide)
        key = self._read_text(lpKeyName, wide) if lpKeyName else None
        value = self._read_text(lpString, wide) if lpString else None
        filename = self._read_text(lpFileName, wide) if lpFileName else 'win.ini'
        log.debug(f"WritePrivateProfileString({section!r}, {key!r}, {value!r}, \"{filename}\")")

        path = self._profile_path(filename)
        if path is None:
            self._last_error = 5  # ERROR_ACCESS_DENIED
            return 0
        lines = self._ini_read_lines(path) or []
        bounds = self._ini_section_range(lines, section)

        if key is None:
            if bounds:
                del lines[bounds[0]:bounds[1]]
        elif bounds:
            index = None
            for i in range(bounds[0] + 1, bounds[1]):
                pair = self._ini_key_value(lines[i])
                if pair and pair[0].lower() == key.lower():
                    index = i
                    break
            if value is None:
                if index is not None:
                    del lines[index]
            elif index is not None:
                lines[index] = f"{key}={value}"
            else:
                # Append after the section's last non-blank line
                end = bounds[1]
                while end > bounds[0] + 1 and not lines[end - 1].strip():
                    end -= 1
                lines.insert(end, f"{key}={value}")
        elif value is not None:
            lines += [f"[{section}]", f"{key}={value}"]
        return self._ini_save(path, lines, filename)

    def WritePrivateProfileStringW(self, args):
        return self.WritePrivateProfileStringA(args, wide=True)

    def GetPrivateProfileSectionA(self, args, wide=False):
        """GetPrivateProfileSectionA/W(section, buffer, size, file) - its
        "key=value" lines, each NUL-terminated, and a final NUL"""
        if not args[1] or not args[2]:
            return 0
        section = self._read_text(args[0], wide) if args[0] else ''
        filename = self._read_text(args[3], wide) if args[3] else 'win.ini'
        lines = self._ini_section_lines(self._ini_lines_of(filename), section)
        return self._write_name_list(lines, args[1], args[2], wide)

    def GetPrivateProfileSectionW(self, args):
        return self.GetPrivateProfileSectionA(args, wide=True)

    def GetPrivateProfileSectionNamesA(self, args, wide=False):
        """GetPrivateProfileSectionNamesA/W(buffer, size, file)"""
        if not args[0] or not args[1]:
            return 0
        filename = self._read_text(args[2], wide) if args[2] else 'win.ini'
        names = [n for n in map(self._ini_section_name, self._ini_lines_of(filename))
                 if n is not None]
        return self._write_name_list(names, args[0], args[1], wide)

    def GetPrivateProfileSectionNamesW(self, args):
        return self.GetPrivateProfileSectionNamesA(args, wide=True)

    def WritePrivateProfileSectionA(self, args, wide=False):
        """WritePrivateProfileSectionA/W(section, "k=v\0k=v\0\0", file) - replaces
        the section (NULL data deletes it)"""
        if not args[0]:
            return 0
        section = self._read_text(args[0], wide)
        filename = self._read_text(args[2], wide) if args[2] else 'win.ini'
        path = self._profile_path(filename)
        if path is None:
            self._last_error = 5
            return 0
        lines = self._ini_read_lines(path) or []
        bounds = self._ini_section_range(lines, section)
        new = [] if not args[1] else \
            [f"[{section}]"] + self._read_multi_string(args[1], wide)
        if bounds:
            lines[bounds[0]:bounds[1]] = new
        else:
            lines += new
        return self._ini_save(path, lines, filename)

    def WritePrivateProfileSectionW(self, args):
        return self.WritePrivateProfileSectionA(args, wide=True)

    # win.ini (C:\Windows\win.ini): the Profile APIs

    def GetProfileStringA(self, args, wide=False):
        """GetProfileStringA/W(section, key, default, buffer, size)"""
        return self.GetPrivateProfileStringA(list(args[:5]) + [0], wide)

    def GetProfileStringW(self, args):
        return self.GetProfileStringA(args, wide=True)

    def GetProfileIntA(self, args, wide=False):
        """GetProfileIntA/W(section, key, default)"""
        name = self._alloc_units(self._text_units('win.ini', wide), wide)
        try:
            return self.GetPrivateProfileIntA([args[0], args[1], args[2], name], wide)
        finally:
            self.emu.heap_free(name)

    def GetProfileIntW(self, args):
        return self.GetProfileIntA(args, wide=True)

    def WriteProfileStringA(self, args, wide=False):
        """WriteProfileStringA/W(section, key, value)"""
        return self.WritePrivateProfileStringA(list(args[:3]) + [0], wide)

    def WriteProfileStringW(self, args):
        return self.WriteProfileStringA(args, wide=True)

    def GetProfileSectionA(self, args, wide=False):
        return self.GetPrivateProfileSectionA(list(args[:3]) + [0], wide)

    def GetProfileSectionW(self, args):
        return self.GetProfileSectionA(args, wide=True)

    def WriteProfileSectionA(self, args, wide=False):
        return self.WritePrivateProfileSectionA(list(args[:2]) + [0], wide)

    def WriteProfileSectionW(self, args):
        return self.WriteProfileSectionA(args, wide=True)

    def GetPrivateProfileStructA(self, args, wide=False):
        """GetPrivateProfileStructA/W(section, key, struct, size, file) - the
        value is the bytes in hex and a checksum byte"""
        section = self._read_text(args[0], wide) if args[0] else ''
        key = self._read_text(args[1], wide) if args[1] else ''
        filename = self._read_text(args[4], wide) if args[4] else 'win.ini'
        value = self._ini_value(self._ini_lines_of(filename), section, key)
        try:
            data = bytes.fromhex(value or '')
        except ValueError:
            data = b''
        if not value or len(data) != args[3] + 1 or sum(data[:-1]) & 0xFF != data[-1]:
            self._last_error = 13  # ERROR_INVALID_DATA
            return 0
        return 1 if self._mem_write(args[2], data[:-1]) else 0

    def GetPrivateProfileStructW(self, args):
        return self.GetPrivateProfileStructA(args, wide=True)

    def WritePrivateProfileStructA(self, args, wide=False):
        """WritePrivateProfileStructA/W(section, key, struct, size, file)"""
        if not args[2]:
            return self.WritePrivateProfileStringA([args[0], args[1], 0, args[4]], wide)
        try:
            data = bytes(self.emu.uc.mem_read(args[2], args[3]))
        except UcError:
            self._last_error = 998
            return 0
        text = (data + bytes([sum(data) & 0xFF])).hex().upper()
        value = self._alloc_units(self._text_units(text, wide), wide)
        try:
            return self.WritePrivateProfileStringA([args[0], args[1], value, args[4]], wide)
        finally:
            self.emu.heap_free(value)

    def WritePrivateProfileStructW(self, args):
        return self.WritePrivateProfileStructA(args, wide=True)

    def ExpandEnvironmentStringsA(self, args, wide=False):
        """ExpandEnvironmentStringsA/W emulation - %NAME% from the process
        environment (unknown names stay as they are)"""
        lpSrc, lpDst, nSize = args[0], args[1], args[2]
        src = self._read_text(lpSrc, wide)
        result = re.sub(r'%([^%]+)%',
                        lambda m: self.environment.get(m.group(1).upper(), m.group(0)), src)
        log.debug(f"ExpandEnvironmentStrings(\"{src}\") -> \"{result}\"")
        length = len(self._text_units(result, wide)) + 1
        if lpDst and length <= nSize:
            self._write_text(lpDst, result, wide)
        return length

    def ExpandEnvironmentStringsW(self, args):
        return self.ExpandEnvironmentStringsA(args, wide=True)

