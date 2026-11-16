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

"""WinAPIHandler mixin: INI files (GetPrivateProfileString / WritePrivateProfileString), environment strings"""

import re

from .. import config
from ..logger import log


class IniFilesMixin:
    """INI files (GetPrivateProfileString / WritePrivateProfileString), environment strings"""

    # ---------- INI files (GetPrivateProfileString / WritePrivateProfileString) ----------

    def _profile_path(self, filename):
        """Host path of an INI file; a bare name lives in the Windows directory"""
        if '\\' not in filename and '/' not in filename:
            filename = "C:\\Windows\\" + filename
        return self.resolve_c_drive_path(filename)

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

    def GetPrivateProfileStringA(self, args):
        """GetPrivateProfileStringA emulation (INI files inside c_drive/)"""
        lpAppName, lpKeyName, lpDefault = args[0], args[1], args[2]
        lpReturnedString, nSize, lpFileName = args[3], args[4], args[5]
        section = self.read_string(lpAppName) if lpAppName else None
        key = self.read_string(lpKeyName) if lpKeyName else None
        default = self.read_string(lpDefault).rstrip(' ') if lpDefault else ''
        filename = self.read_string(lpFileName)
        log.debug(f"GetPrivateProfileStringA({section!r}, {key!r}, {default!r}, \"{filename}\")")

        if not lpReturnedString or nSize == 0:
            return 0
        path = self._profile_path(filename)
        lines = (self._ini_read_lines(path) if path else None) or []

        if section is None or key is None:
            # Name lists: every name NUL-terminated, the list ends with an extra NUL
            if section is None:
                names = [n for n in map(self._ini_section_name, lines) if n is not None]
            else:
                bounds = self._ini_section_range(lines, section)
                names = []
                if bounds:
                    for line in lines[bounds[0] + 1:bounds[1]]:
                        pair = self._ini_key_value(line)
                        if pair:
                            names.append(pair[0])
            data = b''.join(n.encode(config.ANSI_CODEPAGE, errors='replace') + b'\x00' for n in names)
            if len(data) + 1 > nSize:
                # Truncated: the last name still ends with two NULs
                data = data[:max(0, nSize - 2)]
                self.emu.uc.mem_write(lpReturnedString, (data + b'\x00\x00')[:nSize])
                return len(data)
            self.emu.uc.mem_write(lpReturnedString, data + b'\x00')
            return len(data)

        value = self._ini_value(lines, section, key)
        if value is None:
            value = default

        data = value.encode(config.ANSI_CODEPAGE, errors='replace')[:nSize - 1]
        self.emu.uc.mem_write(lpReturnedString, data + b'\x00')
        return len(data)

    def WritePrivateProfileStringA(self, args):
        """WritePrivateProfileStringA emulation (NULL key deletes the section,
        NULL string deletes the key)"""
        lpAppName, lpKeyName, lpString, lpFileName = args[0], args[1], args[2], args[3]
        if not lpAppName:
            return 0  # Only flushes the (nonexistent) cache
        section = self.read_string(lpAppName)
        key = self.read_string(lpKeyName) if lpKeyName else None
        value = self.read_string(lpString) if lpString else None
        filename = self.read_string(lpFileName)
        log.debug(f"WritePrivateProfileStringA({section!r}, {key!r}, {value!r}, \"{filename}\")")

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

        try:
            with open(path, 'wb') as fp:
                fp.write(''.join(line + '\r\n' for line in lines)
                         .encode(config.ANSI_CODEPAGE, errors='replace'))
        except OSError as e:
            log.error(f"WritePrivateProfileStringA(\"{filename}\") failed: {e}")
            self._last_error = 3  # ERROR_PATH_NOT_FOUND
            return 0
        return 1
    
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
    
