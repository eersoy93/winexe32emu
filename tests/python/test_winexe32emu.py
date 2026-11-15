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

"""Unit tests of winexe32emu.py parts that need no emulated program
(the C test programs in tests/ cover the emulation: scripts/run_tests.sh).

Run from the repository root:
    python3 -m unittest discover -s tests/python -v
"""

import datetime
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
import winexe32emu as emu  # noqa: E402

WinAPIHandler = emu.WinAPIHandler
# Some tests provoke warnings (blocked paths, a broken registry file)
emu.DebugLogger.level = emu.DebugLogger.WARNING + 1


def bare_handler():
    """A WinAPIHandler without an emulator (for its pure helpers)"""
    handler = WinAPIHandler.__new__(WinAPIHandler)
    handler.com_arg_counts = {}
    handler._api_map = {}
    return handler


class CommandLineTest(unittest.TestCase):
    """split_command_line: the Microsoft C runtime's argv rules"""

    CASES = [
        (r'C:\a.exe', [r'C:\a.exe']),
        (r'"C:\Program Files\a.exe" x y', [r'C:\Program Files\a.exe', 'x', 'y']),
        (r'a.exe "a b" c', ['a.exe', 'a b', 'c']),
        (r'a.exe a\\\"b', ['a.exe', 'a\\"b']),        # 2n+1 backslashes + quote
        (r'a.exe "a\\" b', ['a.exe', 'a\\', 'b']),     # 2n backslashes + quote
        (r'a.exe a\b\c', ['a.exe', r'a\b\c']),         # other backslashes stay
        (r'a.exe "a""b"', ['a.exe', 'a"b']),           # "" inside quotes
        (r'a.exe ""', ['a.exe', '']),
        ('a.exe \t x  ', ['a.exe', 'x']),
        (r'"C:\a b\x.exe"tail', [r'C:\a b\x.exe', 'tail']),  # argv[0] ends at the quote
    ]

    def test_cases(self):
        for command_line, expected in self.CASES:
            with self.subTest(command_line=command_line):
                self.assertEqual(WinAPIHandler.split_command_line(command_line), expected)


class ParseIntegerTest(unittest.TestCase):
    """_parse_c_integer (strtol/strtoul): (value, characters consumed)"""

    def test_bases(self):
        parse = bare_handler()._parse_c_integer
        self.assertEqual(parse('  -42xyz', 10), (-42, 5))
        self.assertEqual(parse('0x1F', 0), (31, 4))
        self.assertEqual(parse('0x1F', 16), (31, 4))
        self.assertEqual(parse('017', 0), (15, 3))
        self.assertEqual(parse('zz', 36), (36 * 35 + 35, 2))
        self.assertEqual(parse('abc', 10), (0, 0))  # no conversion

    def test_zero_prefixes(self):
        parse = bare_handler()._parse_c_integer
        # "0" is a number, not just an octal prefix
        self.assertEqual(parse('0', 0), (0, 1))
        self.assertEqual(parse('09', 0), (0, 1))
        # "0x" without hex digits: the number is the 0
        self.assertEqual(parse('0x', 0), (0, 1))
        self.assertEqual(parse('0xg', 16), (0, 1))


class NamesTest(unittest.TestCase):
    def test_ordinal_names(self):
        self.assertEqual(emu.PELoader.ordinal_name('COMCTL32.dll', 17), 'InitCommonControls')
        self.assertEqual(emu.PELoader.ordinal_name('comctl32.dll', 9999), 'Ordinal_9999')
        if emu.ordlookup is not None:
            self.assertEqual(emu.PELoader.ordinal_name('oleaut32', 6), 'SysFreeString')

    def test_undecorated_type_names(self):
        undecorate = bare_handler()._undecorate_type_name
        self.assertEqual(undecorate('.?AVFoo@bar@@'), 'class bar::Foo')
        self.assertEqual(undecorate('.?AUPoint@@'), 'struct Point')
        self.assertEqual(undecorate('.?AW4Color@@'), 'enum Color')
        self.assertEqual(undecorate('.H'), 'int')
        self.assertEqual(undecorate('.?AV?$vector@H@std@@'), '.?AV?$vector@H@std@@')


class DateTimeFormatTest(unittest.TestCase):
    def test_pictures(self):
        handler = bare_handler()
        when = datetime.datetime(2024, 3, 5, 14, 7, 9)
        self.assertEqual(handler._format_picture('M/d/yyyy', when, True), '3/5/2024')
        self.assertEqual(handler._format_picture('dddd, MMMM d, yyyy', when, True),
                         'Tuesday, March 5, 2024')
        self.assertEqual(handler._format_picture("yy'-'MM'-'dd ''", when, True), "24-03-05 '")
        self.assertEqual(handler._format_picture('h:mm:ss tt', when, False), '2:07:09 PM')
        self.assertEqual(handler._format_picture('HH:mm t', when, False), '14:07 P')


class RegistryFileTest(unittest.TestCase):
    def test_round_trip(self):
        root = WinAPIHandler._new_registry_key('HKEY_CURRENT_USER')
        key = WinAPIHandler._new_registry_key('Name \u011f \u4e2d')
        key['values']['text'] = {'name': 'Text', 'type': 1, 'data': 'Value \u4e2d\x00'}
        key['values']['bin'] = {'name': 'Bin', 'type': 3, 'data': b'\x00\xff'}
        root['keys'][key['name'].lower()] = key
        root['keys']['gone'] = WinAPIHandler._new_registry_key('Gone', volatile=True)

        data = json.loads(json.dumps(WinAPIHandler._registry_to_json(root)))
        loaded = WinAPIHandler._registry_from_json(data)
        self.assertNotIn('gone', loaded['keys'])  # volatile keys are not saved
        child = loaded['keys']['name \u011f \u4e2d']
        self.assertEqual(child['values']['text']['data'], 'Value \u4e2d\x00')
        self.assertEqual(child['values']['bin']['data'], b'\x00\xff')
        self.assertEqual(list(child['values']), ['text', 'bin'])  # creation order

    def test_invalid_file(self):
        with tempfile.TemporaryDirectory() as folder:
            saved = WinAPIHandler.REGISTRY_FILE
            WinAPIHandler.REGISTRY_FILE = os.path.join(folder, 'registry.json')
            try:
                self.assertEqual(WinAPIHandler._load_registry_file(), {})  # no file
                with open(WinAPIHandler.REGISTRY_FILE, 'w', encoding='utf-8') as f:
                    f.write('{not json')
                self.assertEqual(WinAPIHandler._load_registry_file(), {})
            finally:
                WinAPIHandler.REGISTRY_FILE = saved


class ApiBindingTest(unittest.TestCase):
    def test_handler_names(self):
        names = WinAPIHandler._api_method_names()
        for api in ('CreateWindowExA', 'GetProcAddress', '_lock', 'CompareStringA',
                    'RegEnumValueW'):
            self.assertIn(api, names)
        # Helpers and the like never match an imported name
        for helper in ('_mem_write', '_read_u32', 'read_string', '_str_cat', '_crt_noop',
                       '__init__', 'split_command_line'):
            self.assertNotIn(helper, names)

    def test_only_windows_dlls(self):
        handler = bare_handler()
        self.assertIsNotNone(handler.get_api_handler('GetVersion', 'KERNEL32.dll'))
        self.assertIsNone(handler.get_api_handler('GetVersion', 'myplugin.dll'))
        self.assertIsNone(handler.get_api_handler('_mem_write', 'kernel32.dll'))
        for dll in ('msvcr71.dll', 'vcruntime140.dll', 'api-ms-win-crt-runtime-l1-1-0.dll',
                    'msimg32.dll', 'shell32'):
            self.assertTrue(handler.is_system_dll_name(dll), dll)

    def test_calling_conventions(self):
        handler = bare_handler()
        self.assertEqual(handler.stack_cleanup_bytes('kernel32.dll', 'Sleep'), 4)
        self.assertEqual(handler.stack_cleanup_bytes('msvcrt.dll', 'printf'), 0)
        self.assertEqual(handler.stack_cleanup_bytes('vcruntime140.dll', 'memset'), 0)
        self.assertEqual(handler.stack_cleanup_bytes('vcruntime140.dll', '_CxxThrowException'), 8)
        self.assertEqual(handler.stack_cleanup_bytes('ntdll.dll', 'strlen'), 0)
        self.assertEqual(handler.stack_cleanup_bytes('ntdll.dll', '_alldiv'), 16)
        self.assertIsNone(handler.stack_cleanup_bytes('kernel32.dll', 'NoSuchApi'))


class SandboxTest(unittest.TestCase):
    def test_paths_stay_in_c_drive(self):
        root = os.path.realpath(emu.C_DRIVE_PATH)
        for name in (r'C:\Windows\..\..\..\etc\passwd', r'..\..\x', '/etc/passwd',
                     r'\\server\share\x', r'\\?\C:\..\..\x', r'D:\..\..\x'):
            with self.subTest(name=name):
                path = emu.resolve_c_drive_path(name)
                self.assertTrue(path is None or os.path.realpath(path).startswith(root + os.sep),
                                path)

    def test_win32_prefixes(self):
        self.assertEqual(emu.strip_win32_path_prefix(r'\\?\C:\x'), r'C:\x')
        self.assertEqual(emu.strip_win32_path_prefix(r'\\.\C:\x'), r'C:\x')
        self.assertIsNone(emu.strip_win32_path_prefix(r'\\?\UNC\server\x'))
        self.assertEqual(emu.strip_win32_path_prefix(r'C:\x'), r'C:\x')


class CpuExceptionStateTest(unittest.TestCase):
    def test_calibration(self):
        """The field that turns a second #DE into a double fault is found"""
        offset = emu.CPUEmulator._find_exception_state_offset()
        self.assertIsInstance(offset, int)


if __name__ == '__main__':
    unittest.main()
