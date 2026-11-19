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

"""Unit tests of the winexe32emu parts (src/) that need no emulated program
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
from src import pe_loader  # noqa: E402
from src.config import C_DRIVE_PATH, DRIVES_PATH, drive_host_path  # noqa: E402
from src.cpu import CPUEmulator  # noqa: E402
from src.logger import DebugLogger  # noqa: E402
from src.paths import (device_name, drive_path_error, resolve_drive_path,  # noqa: E402
                       strip_win32_path_prefix, windows_path_of_host)
from src.pe_loader import PELoader  # noqa: E402
from src.winapi import WinAPIHandler  # noqa: E402

# Some tests provoke warnings (blocked paths, a broken registry file)
DebugLogger.level = DebugLogger.WARNING + 1


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
        self.assertEqual(PELoader.ordinal_name('COMCTL32.dll', 17), 'InitCommonControls')
        self.assertEqual(PELoader.ordinal_name('comctl32.dll', 9999), 'Ordinal_9999')
        if pe_loader.ordlookup is not None:
            self.assertEqual(PELoader.ordinal_name('oleaut32', 6), 'SysFreeString')

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
    def test_paths_stay_in_their_drive(self):
        for name, letter in ((r'C:\Windows\..\..\..\etc\passwd', 'C'), (r'..\..\x', 'C'),
                             ('/etc/passwd', 'C'), (r'\\server\share\x', 'C'),
                             (r'\\?\C:\..\..\x', 'C'), (r'D:\..\..\x', 'D'),
                             (r'a:\..\C\x', 'A')):
            with self.subTest(name=name):
                root = os.path.realpath(drive_host_path(letter))
                path = resolve_drive_path(name)
                self.assertTrue(path is None or os.path.realpath(path).startswith(root + os.sep),
                                path)

    def test_drive_folders(self):
        self.assertEqual(resolve_drive_path(r'C:\Windows'),
                         os.path.realpath(os.path.join(C_DRIVE_PATH, 'Windows')))
        self.assertEqual(resolve_drive_path(r'd:\setup.exe'),
                         os.path.realpath(os.path.join(DRIVES_PATH, 'D', 'setup.exe')))
        self.assertEqual(resolve_drive_path('A:\\'), os.path.realpath(drive_host_path('A')))
        self.assertIsNone(resolve_drive_path(r'E:\x'))  # No such drive
        self.assertEqual(windows_path_of_host(os.path.join(DRIVES_PATH, 'D', 'x', 'y.exe')),
                         r'D:\x\y.exe')
        self.assertIsNone(windows_path_of_host('/etc/passwd'))

    def test_case_insensitive_names(self):
        os.makedirs(C_DRIVE_PATH, exist_ok=True)
        folder = tempfile.mkdtemp(prefix='CaseTest', dir=C_DRIVE_PATH)
        try:
            with open(os.path.join(folder, 'Read.Me'), 'w') as f:
                f.write('x')
            name = os.path.basename(folder)
            expected = os.path.realpath(os.path.join(folder, 'Read.Me'))
            for spelling in (name.upper(), name.lower()):
                with self.subTest(spelling=spelling):
                    self.assertEqual(resolve_drive_path(f'C:\\{spelling}\\READ.ME'), expected)
                    self.assertEqual(resolve_drive_path(f'c:/{spelling}/read.me'), expected)
            # A new file keeps its spelling, in the existing folder
            self.assertEqual(resolve_drive_path(f'C:\\{name.upper()}\\New.Txt'),
                             os.path.join(os.path.realpath(folder), 'New.Txt'))
            # Trailing dots and spaces are dropped
            self.assertEqual(resolve_drive_path(f'C:\\{name}\\read.me. .'), expected)
            self.assertEqual(resolve_drive_path(f'C:\\{name}.\\read.me'), expected)
        finally:
            for entry in os.listdir(folder):
                os.remove(os.path.join(folder, entry))
            os.rmdir(folder)

    def test_invalid_names_and_devices(self):
        for name in (r'C:\x.txt:stream', r'C:\a*b', r'C:\a?b', 'C:\\a<b', 'C:\\a|b',
                     'C:\\a"b', 'C:\\a\x01b'):
            with self.subTest(name=name):
                self.assertIsNone(resolve_drive_path(name))
                self.assertEqual(drive_path_error(name), 123)  # ERROR_INVALID_NAME
        for name in ('NUL', 'nul', r'C:\Windows\NUL', r'C:\x\nul.txt', 'con', 'Com1',
                     r'\\.\NUL', 'LPT9.log', 'C:nul', 'aux '):
            with self.subTest(name=name):
                self.assertIsNotNone(device_name(name))
                self.assertIsNone(resolve_drive_path(name))
        self.assertEqual(device_name('CONOUT$'), 'CONOUT$')
        self.assertEqual(device_name(r'C:\x\Nul.txt'), 'NUL')
        for name in ('null', 'console', 'COM0', 'COM10', r'C:\nul\x.txt', 'conout$.txt',
                     'a.nul'):
            with self.subTest(name=name):
                self.assertIsNone(device_name(name))
        self.assertEqual(drive_path_error(r'E:\x'), 3)  # ERROR_PATH_NOT_FOUND

    def test_win32_prefixes(self):
        self.assertEqual(strip_win32_path_prefix(r'\\?\C:\x'), r'C:\x')
        self.assertEqual(strip_win32_path_prefix(r'\\.\C:\x'), r'C:\x')
        self.assertIsNone(strip_win32_path_prefix(r'\\?\UNC\server\x'))
        self.assertEqual(strip_win32_path_prefix(r'C:\x'), r'C:\x')


class ShlwapiTest(unittest.TestCase):
    """Path and size text helpers of the shlwapi emulation"""

    def test_canonicalize(self):
        canonicalize = WinAPIHandler._canonicalize
        self.assertEqual(canonicalize(r'C:\a\.\b\..\c'), r'C:\a\c')
        self.assertEqual(canonicalize(r'C:\a\..\..'), 'C:\\')
        self.assertEqual(canonicalize(r'\\server\share\x\..\y'), r'\\server\share\y')

    def test_remove_file_spec(self):
        remove = WinAPIHandler._remove_file_spec
        self.assertEqual(remove(r'C:\dir\file.txt'), (r'C:\dir', True))
        self.assertEqual(remove(r'C:\file.txt'), ('C:\\', True))
        self.assertEqual(remove('C:\\'), ('C:\\', False))
        self.assertEqual(remove(r'\\server\share'), (r'\\server', True))

    def test_byte_sizes(self):
        size = WinAPIHandler._byte_size_text
        self.assertEqual(size(532), '532 bytes')
        self.assertEqual(size(1536), '1.50 KB')
        self.assertEqual(size(2047), '1.99 KB')  # Truncated, not rounded
        self.assertEqual(size(12 * 1024 * 1024 + 300 * 1024), '12.2 MB')
        self.assertEqual(size(123 * 1024 ** 3), '123 GB')

    def test_spec_match(self):
        match = WinAPIHandler._spec_matches
        self.assertTrue(match('Read.Me', '*.me'))
        self.assertTrue(match('noext', '*.*'))
        self.assertFalse(match('a.txt', 'a?.txt'))


class KnownFoldersTest(unittest.TestCase):
    def test_known_folder_paths(self):
        folders = WinAPIHandler.known_folder_paths()
        lowered = [f.lower() for f in folders]
        self.assertEqual(len(lowered), len(set(lowered)))  # No duplicates
        for folder in folders:
            self.assertTrue(folder.startswith('C:\\'), folder)
            self.assertIsNotNone(resolve_drive_path(folder), folder)
        self.assertIn(r'C:\Program Files\Common Files', folders)
        self.assertTrue(any(f.endswith(r'\Downloads') for f in folders))
        self.assertFalse(any('(x86)' in f or 'syswow64' in f.lower() for f in folders))


class SecurityAndNetworkTest(unittest.TestCase):
    def test_sid_bytes(self):
        data = WinAPIHandler._sid_bytes('S-1-5-32-544')
        self.assertEqual(data, bytes([1, 2, 0, 0, 0, 0, 0, 5]) + bytes([32, 0, 0, 0, 0x20, 2, 0, 0]))
        self.assertIsNone(WinAPIHandler._sid_bytes('S-2-5'))
        self.assertIsNone(WinAPIHandler._sid_bytes('not a SID'))

    def test_inet_addr_forms(self):
        parse = WinAPIHandler._parse_ipv4
        self.assertEqual(parse('127.0.0.1'), bytes([127, 0, 0, 1]))
        self.assertEqual(parse('10.258'), bytes([10, 0, 1, 2]))  # "a.b": b is 24 bits
        self.assertEqual(parse('0x7f.1'), bytes([127, 0, 0, 1]))
        self.assertIsNone(parse('1.2.3.256'))
        self.assertIsNone(parse('1..2'))

    def test_new_calling_conventions(self):
        handler = bare_handler()
        self.assertEqual(handler.stack_cleanup_bytes('shlwapi.dll', 'PathCombineA'), 12)
        self.assertEqual(handler.stack_cleanup_bytes('shlwapi.dll', 'wnsprintfA'), 0)
        self.assertEqual(handler.stack_cleanup_bytes('ws2_32.dll', 'getaddrinfo'), 16)
        self.assertEqual(handler.stack_cleanup_bytes('kernel32.dll', 'VerSetConditionMask'), 16)
        self.assertIn('__WSAFDIsSet', WinAPIHandler._api_method_names())
        for helper in ('_no_service', '_no_theme', '_not_a_socket', '_wsa_fd_is_set'):
            self.assertNotIn(helper, WinAPIHandler._api_method_names())


class CpuExceptionStateTest(unittest.TestCase):
    def test_calibration(self):
        """The field that turns a second #DE into a double fault is found"""
        offset = CPUEmulator._find_exception_state_offset()
        self.assertIsInstance(offset, int)


if __name__ == '__main__':
    unittest.main()
