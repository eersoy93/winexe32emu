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

"""WinAPIHandler mixin: SHLWAPI path and string functions, registry helpers"""

import os
import re
import struct

from .registry import registry_locked


MAX_PATH = 260
BACKSLASH, SLASH, COLON, DOT, SPACE, QUOTE = 0x5C, 0x2F, 0x3A, 0x2E, 0x20, 0x22


class ShlwapiMixin:
    """SHLWAPI path and string functions, registry helpers"""

    # ---------- Paths: functions that return a pointer into the string ----------

    def _unit_size(self, wide):
        return 2 if wide else 1

    def PathFindFileNameA(self, args, wide=False):
        """PathFindFileNameA/W - the file name part (after the last \\, / or :)"""
        units = self._read_units(args[0], wide)
        last = 0
        for i, unit in enumerate(units):
            if (unit in (BACKSLASH, SLASH, COLON) and i + 1 < len(units) and
                    units[i + 1] not in (BACKSLASH, SLASH)):
                last = i + 1
        return args[0] + last * self._unit_size(wide)

    def PathFindFileNameW(self, args):
        return self.PathFindFileNameA(args, wide=True)

    @staticmethod
    def _extension_index(units):
        """Index of the extension's dot in a path (the end if it has none)"""
        dot = None
        for i, unit in enumerate(units):
            if unit in (BACKSLASH, SPACE):
                dot = None
            elif unit == DOT:
                dot = i
        return len(units) if dot is None else dot

    def PathFindExtensionA(self, args, wide=False):
        """PathFindExtensionA/W - the extension's dot, or the terminating NUL"""
        if not args[0]:
            return 0
        units = self._read_units(args[0], wide)
        return args[0] + self._extension_index(units) * self._unit_size(wide)

    def PathFindExtensionW(self, args):
        return self.PathFindExtensionA(args, wide=True)

    def PathGetArgsA(self, args, wide=False):
        """PathGetArgsA/W - the arguments after the first unquoted space"""
        units = self._read_units(args[0], wide)
        quoted = False
        for i, unit in enumerate(units):
            if unit == QUOTE:
                quoted = not quoted
            elif unit == SPACE and not quoted:
                return args[0] + (i + 1) * self._unit_size(wide)
        return args[0] + len(units) * self._unit_size(wide)

    def PathGetArgsW(self, args):
        return self.PathGetArgsA(args, wide=True)

    @staticmethod
    def _root_length(text):
        """Length of the root of a path: "C:\\", "\\", "\\\\server\\share\\" (0: none)"""
        if text.startswith('\\\\'):
            parts = text[2:].split('\\', 2)
            length = 2 + len(parts[0])
            if len(parts) > 1:
                length += 1 + len(parts[1])
                if len(parts) > 2:
                    length += 1
            return length
        if len(text) >= 2 and text[1] == ':':
            return 3 if text[2:3] == '\\' else 2
        return 1 if text.startswith('\\') else 0

    def PathSkipRootA(self, args, wide=False):
        """PathSkipRootA/W - the part after the root (NULL without a root)"""
        text = self._read_text(args[0], wide)
        length = self._root_length(text)
        if not length or (length == 1 and not text.startswith('\\')):
            return 0
        units = self._text_units(text[:length], wide)
        return args[0] + len(units) * self._unit_size(wide)

    def PathSkipRootW(self, args):
        return self.PathSkipRootA(args, wide=True)

    def PathFindNextComponentA(self, args, wide=False):
        """PathFindNextComponentA/W - the component after the next backslash"""
        if not args[0]:
            return 0
        units = self._read_units(args[0], wide)
        if not units:
            return 0
        size = self._unit_size(wide)
        for i, unit in enumerate(units):
            if unit == BACKSLASH:
                return args[0] + (i + 1) * size
        return args[0] + len(units) * size

    def PathFindNextComponentW(self, args):
        return self.PathFindNextComponentA(args, wide=True)

    # ---------- Paths: tests ----------

    def PathFileExistsA(self, args, wide=False):
        """PathFileExistsA/W - does the file or folder exist (in drives/)?"""
        if not args[0]:
            return 0
        path = self.resolve_drive_path(self._read_text(args[0], wide))
        return 1 if path is not None and os.path.exists(path) else 0

    def PathFileExistsW(self, args):
        return self.PathFileExistsA(args, wide=True)

    def PathIsDirectoryA(self, args, wide=False):
        """PathIsDirectoryA/W - FILE_ATTRIBUTE_DIRECTORY for a folder, else 0"""
        if not args[0]:
            return 0
        path = self.resolve_drive_path(self._read_text(args[0], wide))
        return 0x10 if path is not None and os.path.isdir(path) else 0

    def PathIsDirectoryW(self, args):
        return self.PathIsDirectoryA(args, wide=True)

    @staticmethod
    def _path_is_relative(text):
        return not (text.startswith('\\') or text[1:2] == ':')

    def PathIsRelativeA(self, args, wide=False):
        """PathIsRelativeA/W"""
        text = self._read_text(args[0], wide) if args[0] else ''
        return 1 if self._path_is_relative(text) else 0

    def PathIsRelativeW(self, args):
        return self.PathIsRelativeA(args, wide=True)

    @staticmethod
    def _path_is_root(text):
        if text in ('\\',) or (len(text) == 3 and text[1:] == ':\\'):
            return True
        if text.startswith('\\\\'):
            rest = text[2:]
            return rest.count('\\') == 0 or (rest.count('\\') == 1 and not rest.endswith('\\'))
        return False

    def PathIsRootA(self, args, wide=False):
        """PathIsRootA/W - "\\", "C:\\", "\\\\server" or "\\\\server\\share\""""
        return 1 if args[0] and self._path_is_root(self._read_text(args[0], wide)) else 0

    def PathIsRootW(self, args):
        return self.PathIsRootA(args, wide=True)

    def PathIsUNCA(self, args, wide=False):
        """PathIsUNCA/W"""
        return 1 if args[0] and self._read_text(args[0], wide).startswith('\\\\') else 0

    def PathIsUNCW(self, args):
        return self.PathIsUNCA(args, wide=True)

    def PathIsFileSpecA(self, args, wide=False):
        """PathIsFileSpecA/W - no ':' and no '\\' in the path"""
        text = self._read_text(args[0], wide) if args[0] else ''
        return 0 if ':' in text or '\\' in text else 1

    def PathIsFileSpecW(self, args):
        return self.PathIsFileSpecA(args, wide=True)

    def PathIsURLA(self, args, wide=False):
        """PathIsURLA/W - "scheme:..." with a scheme of two or more characters"""
        text = self._read_text(args[0], wide) if args[0] else ''
        return 1 if re.match(r'[A-Za-z][A-Za-z0-9+.\-]+:', text) else 0

    def PathIsURLW(self, args):
        return self.PathIsURLA(args, wide=True)

    def PathGetDriveNumberA(self, args, wide=False):
        """PathGetDriveNumberA/W - 0 for A: ... 25 for Z:, -1 without a drive"""
        text = self._read_text(args[0], wide) if args[0] else ''
        if len(text) >= 2 and text[1] == ':' and 'a' <= text[0].lower() <= 'z':
            return ord(text[0].lower()) - ord('a')
        return 0xFFFFFFFF

    def PathGetDriveNumberW(self, args):
        return self.PathGetDriveNumberA(args, wide=True)

    @staticmethod
    def _spec_matches(name, spec):
        """Does a file name match a wildcard (* and ?) spec, ignoring case?"""
        spec = spec.strip()
        if spec in ('*.*', '*'):
            return True
        pattern = ''.join('.*' if c == '*' else '.' if c == '?' else re.escape(c)
                          for c in spec)
        return re.fullmatch(pattern, name, re.IGNORECASE | re.DOTALL) is not None

    def PathMatchSpecA(self, args, wide=False):
        """PathMatchSpecA/W - wildcard specs separated by ';'"""
        name = self._read_text(args[0], wide) if args[0] else ''
        specs = self._read_text(args[1], wide) if args[1] else ''
        return 1 if any(self._spec_matches(name, spec) for spec in specs.split(';')
                        if spec.strip()) else 0

    def PathMatchSpecW(self, args):
        return self.PathMatchSpecA(args, wide=True)

    # ---------- Paths: functions that change the string ----------

    def _set_path(self, address, text, wide):
        self._write_text(address, text, wide)

    def PathAddBackslashA(self, args, wide=False):
        """PathAddBackslashA/W - pointer to the NUL; NULL if it doesn't fit"""
        text = self._read_text(args[0], wide)
        if text and not text.endswith('\\'):
            if len(text) + 1 >= MAX_PATH:
                return 0
            text += '\\'
            self._set_path(args[0], text, wide)
        return args[0] + len(self._text_units(text, wide)) * self._unit_size(wide)

    def PathAddBackslashW(self, args):
        return self.PathAddBackslashA(args, wide=True)

    def PathRemoveBackslashA(self, args, wide=False):
        """PathRemoveBackslashA/W - pointer to the NUL if a backslash went,
        else to the last character"""
        text = self._read_text(args[0], wide)
        size = self._unit_size(wide)
        if text.endswith('\\') and not self._path_is_root(text):
            text = text[:-1]
            self._set_path(args[0], text, wide)
            return args[0] + len(self._text_units(text, wide)) * size
        return args[0] + max(len(self._text_units(text, wide)) - 1, 0) * size

    def PathRemoveBackslashW(self, args):
        return self.PathRemoveBackslashA(args, wide=True)

    @staticmethod
    def _remove_file_spec(text):
        """(new text, removed?) of PathRemoveFileSpec (Windows' rules)"""
        start = 0
        if text.startswith('\\'):
            start = 2 if text.startswith('\\\\') else 1
        cut = start
        i = start
        while i < len(text):
            if text[i] == '\\':
                cut = i
            elif text[i] == ':':
                cut = i + 1
                if text[i + 1:i + 2] == '\\':
                    cut += 1
                    i += 1  # The root's backslash stays
            i += 1
        if cut < len(text):
            return text[:cut], True
        return text, False

    def PathRemoveFileSpecA(self, args, wide=False):
        """PathRemoveFileSpecA/W - remove the file name and its backslash"""
        if not args[0]:
            return 0
        text, removed = self._remove_file_spec(self._read_text(args[0], wide))
        if removed:
            self._set_path(args[0], text, wide)
        return 1 if removed else 0

    def PathRemoveFileSpecW(self, args):
        return self.PathRemoveFileSpecA(args, wide=True)

    def PathStripPathA(self, args, wide=False):
        """PathStripPathA/W - keep only the file name"""
        start = self.PathFindFileNameA(args, wide)
        if start != args[0]:
            self._set_path(args[0], self._read_text(start, wide), wide)
        return 0

    def PathStripPathW(self, args):
        return self.PathStripPathA(args, wide=True)

    def PathStripToRootA(self, args, wide=False):
        """PathStripToRootA/W - keep only the root; FALSE if there is none"""
        text = self._read_text(args[0], wide)
        length = self._root_length(text)
        if text.startswith('\\\\') and text[length - 1:length] == '\\':
            length -= 1  # "\\server\share" without the backslash
        self._set_path(args[0], text[:length], wide)
        return 1 if length else 0

    def PathStripToRootW(self, args):
        return self.PathStripToRootA(args, wide=True)

    def PathRemoveExtensionA(self, args, wide=False):
        """PathRemoveExtensionA/W"""
        units = self._read_units(args[0], wide)
        index = self._extension_index(units)
        if index < len(units):
            self._write_units(args[0], units[:index], wide)
        return 0

    def PathRemoveExtensionW(self, args):
        return self.PathRemoveExtensionA(args, wide=True)

    def PathRenameExtensionA(self, args, wide=False):
        """PathRenameExtensionA/W - replace (or add) the extension"""
        units = self._read_units(args[0], wide)
        extension = self._read_units(args[1], wide)
        units = units[:self._extension_index(units)] + extension
        if len(units) >= MAX_PATH:
            return 0
        self._write_units(args[0], units, wide)
        return 1

    def PathRenameExtensionW(self, args):
        return self.PathRenameExtensionA(args, wide=True)

    def PathAddExtensionA(self, args, wide=False):
        """PathAddExtensionA/W - add an extension (".exe" if NULL) if it has none"""
        units = self._read_units(args[0], wide)
        if self._extension_index(units) < len(units):
            return 0
        extension = self._read_units(args[1], wide) if args[1] else \
            self._text_units('.exe', wide)
        if len(units) + len(extension) >= MAX_PATH:
            return 0
        self._write_units(args[0], units + extension, wide)
        return 1

    def PathAddExtensionW(self, args):
        return self.PathAddExtensionA(args, wide=True)

    def PathQuoteSpacesA(self, args, wide=False):
        """PathQuoteSpacesA/W - put a path with spaces in quotes"""
        text = self._read_text(args[0], wide) if args[0] else ''
        if ' ' not in text or len(text) + 2 >= MAX_PATH:
            return 0
        self._set_path(args[0], f'"{text}"', wide)
        return 1

    def PathQuoteSpacesW(self, args):
        return self.PathQuoteSpacesA(args, wide=True)

    def PathUnquoteSpacesA(self, args, wide=False):
        """PathUnquoteSpacesA/W - remove the quotes around a path"""
        text = self._read_text(args[0], wide) if args[0] else ''
        if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
            self._set_path(args[0], text[1:-1], wide)
            return 1
        return 0

    def PathUnquoteSpacesW(self, args):
        return self.PathUnquoteSpacesA(args, wide=True)

    @classmethod
    def _canonicalize(cls, text):
        """PathCanonicalize: resolve "." and ".." components"""
        root_length = cls._root_length(text)
        root, rest = text[:root_length], text[root_length:]
        parts = []
        for part in rest.split('\\'):
            if part == '..':
                if parts and parts[-1] != '':
                    parts.pop()
            elif part != '.':
                parts.append(part)
        result = root + '\\'.join(parts)
        if not result:
            return '\\'
        if len(result) == 2 and result[1] == ':':
            result += '\\'
        return result

    def PathCanonicalizeA(self, args, wide=False):
        """PathCanonicalizeA/W(dest, src)"""
        if not args[0] or not args[1]:
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0
        text = self._canonicalize(self._read_text(args[1], wide))
        if len(text) >= MAX_PATH:
            self._write_text(args[0], '', wide)
            return 0
        self._write_text(args[0], text, wide)
        return 1

    def PathCanonicalizeW(self, args):
        return self.PathCanonicalizeA(args, wide=True)

    def _path_combine(self, directory, file):
        """Text of PathCombine (None if too long)"""
        if directory is None and file is None:
            return None
        if not file:
            combined = directory or ''
        elif not directory or not self._path_is_relative(file):
            if directory and file.startswith('\\') and not file.startswith('\\\\'):
                # "\file" goes to the root of the folder's drive
                root = directory[:self._root_length(directory)].rstrip('\\')
                combined = root + file
            else:
                combined = file
        else:
            combined = directory if directory.endswith('\\') else directory + '\\'
            combined += file
        if len(combined) >= MAX_PATH:
            return None
        return self._canonicalize(combined)

    def PathCombineA(self, args, wide=False):
        """PathCombineA/W(dest, dir, file) - dest, or NULL on failure"""
        dest = args[0]
        if not dest:
            return 0
        directory = self._read_text(args[1], wide) if args[1] else None
        file = self._read_text(args[2], wide) if args[2] else None
        text = self._path_combine(directory, file)
        if text is None:
            self._write_text(dest, '', wide)
            return 0
        self._write_text(dest, text, wide)
        return dest

    def PathCombineW(self, args):
        return self.PathCombineA(args, wide=True)

    def PathAppendA(self, args, wide=False):
        """PathAppendA/W(path, more) - BOOL"""
        path = self._read_text(args[0], wide)
        more = self._read_text(args[1], wide) if args[1] else ''
        if not more.startswith('\\\\'):
            more = more.lstrip('\\')
        text = self._path_combine(path, more)
        if text is None:
            return 0
        self._write_text(args[0], text, wide)
        return 1

    def PathAppendW(self, args):
        return self.PathAppendA(args, wide=True)

    def PathBuildRootA(self, args, wide=False):
        """PathBuildRootA/W(root, drive number) - "A:\\" ... "Z:\\\""""
        if args[1] < 26 and args[0]:
            self._write_text(args[0], chr(ord('A') + args[1]) + ':\\', wide)
        return args[0]

    def PathBuildRootW(self, args):
        return self.PathBuildRootA(args, wide=True)

    # ---------- Strings ----------

    def _str_text(self, address, wide):
        return self._read_text(address, wide) if address else ''

    @staticmethod
    def _sign(value):
        return 0xFFFFFFFF if value < 0 else (1 if value > 0 else 0)

    def _shlwapi_compare(self, first, second, wide, ignore_case, count=None):
        a = self._read_units(first, wide)
        b = self._read_units(second, wide)
        if count is not None:
            a, b = a[:count], b[:count]
        if ignore_case:
            a = [self._fold_unit(u) for u in a]
            b = [self._fold_unit(u) for u in b]
        return self._sign((a > b) - (a < b))

    def StrCmpW(self, args):
        return self._shlwapi_compare(args[0], args[1], True, False)

    def StrCmpIW(self, args):
        return self._shlwapi_compare(args[0], args[1], True, True)

    def StrCmpNA(self, args, wide=False):
        return self._shlwapi_compare(args[0], args[1], wide, False, args[2])

    def StrCmpNW(self, args):
        return self.StrCmpNA(args, wide=True)

    def StrCmpNIA(self, args, wide=False):
        return self._shlwapi_compare(args[0], args[1], wide, True, args[2])

    def StrCmpNIW(self, args):
        return self.StrCmpNIA(args, wide=True)

    @staticmethod
    def _logical_key(text):
        parts = re.split(r'(\d+)', text.lower())
        return [(0, int(p), '') if p.isdigit() else (1, 0, p) for p in parts if p]

    def StrCmpLogicalW(self, args):
        """StrCmpLogicalW - Explorer's sort order: numbers by value"""
        a = self._logical_key(self._str_text(args[0], True))
        b = self._logical_key(self._str_text(args[1], True))
        return self._sign((a > b) - (a < b))

    def _str_find(self, args, wide, ignore_case, reverse=False):
        haystack = self._str_text(args[0], wide)
        needle = self._str_text(args[1], wide)
        if not args[0] or not args[1]:
            return 0
        if ignore_case:
            haystack_cmp, needle_cmp = haystack.lower(), needle.lower()
        else:
            haystack_cmp, needle_cmp = haystack, needle
        index = haystack_cmp.rfind(needle_cmp) if reverse else haystack_cmp.find(needle_cmp)
        if index < 0:
            return 0
        return args[0] + len(self._text_units(haystack[:index], wide)) * self._unit_size(wide)

    def StrStrA(self, args, wide=False):
        """StrStrA/W - first occurrence of a substring"""
        return self._str_find(args, wide, False)

    def StrStrW(self, args):
        return self.StrStrA(args, wide=True)

    def StrStrIA(self, args, wide=False):
        """StrStrIA/W - first occurrence, ignoring case"""
        return self._str_find(args, wide, True)

    def StrStrIW(self, args):
        return self.StrStrIA(args, wide=True)

    def _str_char(self, address, char, wide, ignore_case, reverse=False, end=0):
        units = self._read_units(address, wide)
        if end:
            units = units[:max(0, (end - address) // self._unit_size(wide))]
        char &= 0xFFFF if wide else 0xFF
        if ignore_case:
            char = self._fold_unit(char)
        found = None
        for i, unit in enumerate(units):
            if (self._fold_unit(unit) if ignore_case else unit) == char:
                found = i
                if not reverse:
                    break
        return 0 if found is None else address + found * self._unit_size(wide)

    def StrChrA(self, args, wide=False):
        """StrChrA/W - first occurrence of a character"""
        return self._str_char(args[0], args[1], wide, False) if args[0] else 0

    def StrChrW(self, args):
        return self.StrChrA(args, wide=True)

    def StrChrIA(self, args, wide=False):
        return self._str_char(args[0], args[1], wide, True) if args[0] else 0

    def StrChrIW(self, args):
        return self.StrChrIA(args, wide=True)

    def StrRChrA(self, args, wide=False):
        """StrRChrA/W(start, end, char) - last occurrence before end (NULL: the NUL)"""
        return self._str_char(args[0], args[2], wide, False, True, args[1]) if args[0] else 0

    def StrRChrW(self, args):
        return self.StrRChrA(args, wide=True)

    def StrRChrIA(self, args, wide=False):
        return self._str_char(args[0], args[2], wide, True, True, args[1]) if args[0] else 0

    def StrRChrIW(self, args):
        return self.StrRChrIA(args, wide=True)

    def StrPBrkA(self, args, wide=False):
        """StrPBrkA/W - first character that is in a set"""
        units = self._read_units(args[0], wide)
        accept = set(self._read_units(args[1], wide))
        for i, unit in enumerate(units):
            if unit in accept:
                return args[0] + i * self._unit_size(wide)
        return 0

    def StrPBrkW(self, args):
        return self.StrPBrkA(args, wide=True)

    def _str_span_length(self, args, wide, accept, ignore_case=False):
        units = self._read_units(args[0], wide)
        charset = self._read_units(args[1], wide)
        if ignore_case:
            units = [self._fold_unit(u) for u in units]
            charset = [self._fold_unit(u) for u in charset]
        charset = set(charset)
        for i, unit in enumerate(units):
            if (unit in charset) != accept:
                return i
        return len(units)

    def StrSpnA(self, args, wide=False):
        return self._str_span_length(args, wide, True)

    def StrSpnW(self, args):
        return self.StrSpnA(args, wide=True)

    def StrCSpnA(self, args, wide=False):
        return self._str_span_length(args, wide, False)

    def StrCSpnW(self, args):
        return self.StrCSpnA(args, wide=True)

    def StrCSpnIA(self, args, wide=False):
        return self._str_span_length(args, wide, False, True)

    def StrCSpnIW(self, args):
        return self.StrCSpnIA(args, wide=True)

    def StrDupA(self, args, wide=False):
        """StrDupA/W - LocalAlloc copy of a string"""
        return self._alloc_units(self._read_units(args[0], wide), wide) if args[0] else 0

    def StrDupW(self, args):
        return self.StrDupA(args, wide=True)

    def SHStrDupA(self, args, wide=False):
        """SHStrDupA/W(src, &dest) - CoTaskMemAlloc copy as a wide string"""
        if not args[1]:
            return 0x80070057  # E_INVALIDARG
        text = self._str_text(args[0], wide)
        address = self._alloc_units(self._text_units(text, True), True) if args[0] else 0
        self._mem_write(args[1], struct.pack('<I', address))
        if args[0] and not address:
            return 0x8007000E  # E_OUTOFMEMORY
        return 0 if args[0] else 0x80070057

    def SHStrDupW(self, args):
        return self.SHStrDupA(args, wide=True)

    def StrCpyW(self, args):
        self._write_units(args[0], self._read_units(args[1], True), True)
        return args[0]

    def StrCpyNW(self, args):
        """StrCpyNW(dest, src, count) - at most count-1 characters and a NUL"""
        if args[2] > 0:
            self._write_units(args[0], self._read_units(args[1], True)[:args[2] - 1], True)
        return args[0]

    def StrCatW(self, args):
        units = self._read_units(args[0], True) + self._read_units(args[1], True)
        self._write_units(args[0], units, True)
        return args[0]

    def StrCatBuffA(self, args, wide=False):
        """StrCatBuffA/W(dest, src, size) - append, truncated to the buffer"""
        units = self._read_units(args[0], wide)
        units = (units + self._read_units(args[1], wide))[:max(args[2] - 1, len(units))]
        self._write_units(args[0], units, wide)
        return args[0]

    def StrCatBuffW(self, args):
        return self.StrCatBuffA(args, wide=True)

    def StrNCatA(self, args, wide=False):
        """StrNCatA/W(dest, src, count) - append at most count-1 characters"""
        if args[2] > 0:
            units = self._read_units(args[0], wide) + \
                self._read_units(args[1], wide)[:args[2] - 1]
            self._write_units(args[0], units, wide)
        return args[0]

    def StrNCatW(self, args):
        return self.StrNCatA(args, wide=True)

    @staticmethod
    def _parse_str_int(text, hex_allowed):
        """Value of StrToIntEx: leading spaces, sign, decimal or 0x hex digits"""
        text = text.lstrip(' \t')
        match = re.match(r'0[xX]([0-9a-fA-F]+)', text) if hex_allowed else None
        if match:
            return int(match.group(1), 16), True
        match = re.match(r'([-+]?)(\d+)', text)
        if not match:
            return 0, False
        value = int(match.group(2))
        return (-value if match.group(1) == '-' else value), True

    def StrToIntA(self, args, wide=False):
        """StrToIntA/W - decimal value of the start of a string"""
        value, _ = self._parse_str_int(self._str_text(args[0], wide), False)
        return value & 0xFFFFFFFF

    def StrToIntW(self, args):
        return self.StrToIntA(args, wide=True)

    def StrToIntExA(self, args, wide=False):
        """StrToIntExA/W(text, flags, &value) - STIF_SUPPORT_HEX allows 0x"""
        value, ok = self._parse_str_int(self._str_text(args[0], wide), bool(args[1] & 1))
        if args[2]:
            self._mem_write(args[2], struct.pack('<I', value & 0xFFFFFFFF))
        return 1 if ok else 0

    def StrToIntExW(self, args):
        return self.StrToIntExA(args, wide=True)

    def StrToInt64ExA(self, args, wide=False):
        """StrToInt64ExA/W(text, flags, &value)"""
        value, ok = self._parse_str_int(self._str_text(args[0], wide), bool(args[1] & 1))
        if args[2]:
            self._mem_write(args[2], struct.pack('<Q', value & 0xFFFFFFFFFFFFFFFF))
        return 1 if ok else 0

    def StrToInt64ExW(self, args):
        return self.StrToInt64ExA(args, wide=True)

    def StrTrimA(self, args, wide=False):
        """StrTrimA/W(text, characters) - TRUE if something was trimmed"""
        text = self._str_text(args[0], wide)
        trimmed = text.strip(self._str_text(args[1], wide))
        if trimmed == text:
            return 0
        self._write_text(args[0], trimmed, wide)
        return 1

    def StrTrimW(self, args):
        return self.StrTrimA(args, wide=True)

    @staticmethod
    def _byte_size_text(size):
        """StrFormatByteSize: "532 bytes", "1.17 KB", "12.3 MB", "123 GB"
        (three significant digits, truncated)"""
        if size < 1024:
            return f"{size} bytes"
        for unit in ('KB', 'MB', 'GB', 'TB', 'PB', 'EB'):
            size /= 1024
            if size < 1000 or unit == 'EB':
                break
        if size < 10:
            return f"{int(size * 100) / 100:.2f} {unit}"
        if size < 100:
            return f"{int(size * 10) / 10:.1f} {unit}"
        return f"{int(size)} {unit}"

    def _format_size(self, text, buffer, size, wide):
        if not buffer or not size:
            return 0
        units = self._text_units(text, wide)[:size - 1]
        self._write_units(buffer, units, wide)
        return buffer

    def StrFormatByteSizeA(self, args):
        """StrFormatByteSizeA(DWORD size, buffer, cch)"""
        return self._format_size(self._byte_size_text(args[0]), args[1], args[2], False)

    def StrFormatByteSize64A(self, args):
        """StrFormatByteSize64A(LONGLONG size, buffer, cch)"""
        return self._format_size(self._byte_size_text(self._arg_qword(args, 0)),
                                 args[2], args[3], False)

    def StrFormatByteSizeW(self, args):
        """StrFormatByteSizeW(LONGLONG size, buffer, cch)"""
        return self._format_size(self._byte_size_text(self._arg_qword(args, 0)),
                                 args[2], args[3], True)

    def StrFormatByteSizeEx(self, args):
        """StrFormatByteSizeEx(ULONGLONG size, flags, buffer, cch) - HRESULT"""
        if not self._format_size(self._byte_size_text(self._arg_qword(args, 0)),
                                 args[3], args[4], True):
            return 0x80070057  # E_INVALIDARG
        return 0

    def StrFormatKBSizeA(self, args, wide=False):
        """StrFormatKBSizeA/W(LONGLONG size, buffer, cch) - "1,234 KB" (rounded up)"""
        kilobytes = (self._arg_qword(args, 0) + 1023) // 1024
        return self._format_size(f"{kilobytes:,} KB", args[2], args[3], wide)

    def StrFormatKBSizeW(self, args):
        return self.StrFormatKBSizeA(args, wide=True)

    def wnsprintfA(self, args, wide=False):
        """wnsprintfA/W(buffer, cch, format, ...) - cdecl; the length written"""
        return self._wnsprintf(args[0], args[1], args[2], args[3:], wide)

    def wnsprintfW(self, args):
        return self.wnsprintfA(args, wide=True)

    def wvnsprintfA(self, args, wide=False):
        """wvnsprintfA/W(buffer, cch, format, va_list)"""
        return self._wnsprintf(args[0], args[1], args[2], self._va_args(args[3]), wide)

    def wvnsprintfW(self, args):
        return self.wvnsprintfA(args, wide=True)

    def _wnsprintf(self, buffer, size, fmt_addr, varargs, wide):
        if not buffer or not size:
            return 0xFFFFFFFF
        fmt = self._read_text(fmt_addr, wide)
        units = self._text_units(self._format_string(fmt, varargs, wide_fmt=wide), wide)
        truncated = len(units) >= size
        self._write_units(buffer, units[:size - 1], wide)
        return 0xFFFFFFFF if truncated else len(units)

    def wsprintfW(self, args, varargs=None):
        """wsprintfW emulation (user32, cdecl varargs; at most 1024 characters)"""
        fmt = self.read_wide_string(args[1])
        text = self._format_string(fmt, args[2:] if varargs is None else varargs,
                                   wide_fmt=True)
        units = self._text_units(text, True)[:1023]
        self._write_units(args[0], units, True)
        return len(units)

    def wvsprintfW(self, args):
        """wvsprintfW emulation (stdcall, arguments in a va_list)"""
        return self.wsprintfW(args, self._va_args(args[2]))

    # ---------- Registry helpers ----------

    @registry_locked
    def SHGetValueA(self, args, wide=False):
        """SHGetValueA/W(hkey, subkey, value, &type, data, &size)"""
        subkey = self._str_text(args[1], wide)
        name = self._str_text(args[2], wide)
        node, error = self._registry_walk(args[0], subkey)
        if node is None:
            return error
        value = node['values'].get(name.lower())
        if value is None:
            return self.ERROR_FILE_NOT_FOUND
        return self._registry_store_data(value, wide, args[3], args[4], args[5])

    def SHGetValueW(self, args):
        return self.SHGetValueA(args, wide=True)

    def SHQueryValueExA(self, args):
        return self.RegQueryValueExA(args)

    def SHQueryValueExW(self, args):
        return self.RegQueryValueExW(args)

    @registry_locked
    def SHSetValueA(self, args, wide=False):
        """SHSetValueA/W(hkey, subkey, value, type, data, size) - creates the key"""
        subkey = self._str_text(args[1], wide)
        node, error = self._registry_walk(args[0], subkey, create=True)
        if node is None:
            return error
        handle = self._temporary_hkey(node)
        try:
            return self.RegSetValueExA([handle, args[2], 0, args[3], args[4], args[5]], wide)
        finally:
            del self.registry_handles[handle]

    def SHSetValueW(self, args):
        return self.SHSetValueA(args, wide=True)

    @registry_locked
    def SHDeleteValueA(self, args, wide=False):
        """SHDeleteValueA/W(hkey, subkey, value)"""
        node, error = self._registry_walk(args[0], self._str_text(args[1], wide))
        if node is None:
            return error
        if node['values'].pop(self._str_text(args[2], wide).lower(), None) is None:
            return self.ERROR_FILE_NOT_FOUND
        if not node['volatile']:
            self._save_registry()
        return self.ERROR_SUCCESS

    def SHDeleteValueW(self, args):
        return self.SHDeleteValueA(args, wide=True)

    def SHDeleteKeyA(self, args, wide=False):
        """SHDeleteKeyA/W(hkey, subkey) - the key and all its subkeys"""
        return self._registry_delete_tree(args[0], self._str_text(args[1], wide))

    def SHDeleteKeyW(self, args):
        return self.SHDeleteKeyA(args, wide=True)

    def SHDeleteEmptyKeyA(self, args, wide=False):
        """SHDeleteEmptyKeyA/W(hkey, subkey) - only a key without subkeys or values"""
        return self._registry_delete_tree(args[0], self._str_text(args[1], wide), True)

    def SHDeleteEmptyKeyW(self, args):
        return self.SHDeleteEmptyKeyA(args, wide=True)

    # ---------- Others ----------

    def SHAutoComplete(self, args):
        """SHAutoComplete - edit controls don't autocomplete here: S_OK"""
        return 0

    def ColorRGBToHLS(self, args):
        """ColorRGBToHLS(COLORREF, &hue, &luminance, &saturation) - 0..240 scale"""
        red, green, blue = args[0] & 0xFF, (args[0] >> 8) & 0xFF, (args[0] >> 16) & 0xFF
        high, low = max(red, green, blue), min(red, green, blue)
        luminance = ((high + low) * 240 + 255) // 510
        if high == low:
            hue, saturation = 160, 0  # Undefined hue: Windows uses 160
        else:
            delta = high - low
            if luminance <= 120:
                saturation = (delta * 240 + (high + low) // 2) // (high + low)
            else:
                saturation = (delta * 240 + (510 - high - low) // 2) // (510 - high - low)
            if red == high:
                hue = (green - blue) * 40 / delta
            elif green == high:
                hue = 80 + (blue - red) * 40 / delta
            else:
                hue = 160 + (red - green) * 40 / delta
            hue = int(round(hue)) % 240
        for address, value in zip(args[1:4], (hue, luminance, saturation), strict=True):
            if address:
                self._mem_write(address, struct.pack('<H', value))
        return 0

    def SHGetSettings(self, args):
        """SHGetSettings - default Explorer settings (all flags clear)"""
        self._mem_write(args[0], b'\x00' * 4)
        return 0

    def GetMenuPosFromID(self, args):
        """GetMenuPosFromID(hmenu, id) - position of a menu item, -1 if missing"""
        items = self.menus.get(args[0])
        if items is not None:
            for index, item in enumerate(items):
                if item.get('id') == args[1] and not item.get('submenu'):
                    return index
        return 0xFFFFFFFF
