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
import threading
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
from src.winapi.dde import parse_progman_commands, split_command_line  # noqa: E402
from src.winapi.lz32 import expand_szdd, expanded_name  # noqa: E402

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
        # A name no CD in drives/D has (a SETUP.EXE there keeps its own case)
        self.assertEqual(resolve_drive_path(r'd:\no_such_setup.exe'),
                         os.path.realpath(os.path.join(DRIVES_PATH, 'D', 'no_such_setup.exe')))
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


class SymlinkSandboxTest(unittest.TestCase):
    def test_symlink_out_of_a_drive_is_blocked(self):
        os.makedirs(C_DRIVE_PATH, exist_ok=True)
        with tempfile.TemporaryDirectory() as outside:
            link = os.path.join(C_DRIVE_PATH, 'SymlinkTest')
            try:
                os.symlink(outside, link)
            except (OSError, NotImplementedError):
                self.skipTest("no symbolic links")
            try:
                self.assertIsNone(resolve_drive_path(r'C:\SymlinkTest\x.txt'))
                self.assertIsNone(resolve_drive_path(r'c:\symlinktest'))
            finally:
                os.remove(link)


class PageProtectionTest(unittest.TestCase):
    def test_permissions(self):
        from unicorn import UC_PROT_ALL, UC_PROT_EXEC, UC_PROT_NONE, UC_PROT_READ, UC_PROT_WRITE
        emu = CPUEmulator.__new__(CPUEmulator)
        emu.dep_enabled = True
        self.assertEqual(emu.uc_permissions(0x04), UC_PROT_READ | UC_PROT_WRITE)
        self.assertEqual(emu.uc_permissions(0x02), UC_PROT_READ)
        self.assertEqual(emu.uc_permissions(0x20), UC_PROT_READ | UC_PROT_EXEC)
        self.assertEqual(emu.uc_permissions(0x40), UC_PROT_ALL)
        self.assertEqual(emu.uc_permissions(0x01), UC_PROT_NONE)
        self.assertEqual(emu.uc_permissions(0x04 | 0x100), UC_PROT_NONE)  # PAGE_GUARD
        self.assertEqual(emu.uc_permissions(0), UC_PROT_NONE)  # reserved
        emu.dep_enabled = False  # Without DEP readable memory executes
        self.assertEqual(emu.uc_permissions(0x04), UC_PROT_ALL)
        self.assertEqual(emu.uc_permissions(0x02), UC_PROT_READ | UC_PROT_EXEC)

    def test_valid_protection(self):
        valid = WinAPIHandler.valid_protection
        for protection in (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x104, 0x204):
            self.assertTrue(valid(protection), hex(protection))
        for protection in (0, 0x03, 0x06, 0x100, 0x1004):
            self.assertFalse(valid(protection), hex(protection))

    def test_recorded_ranges_split(self):
        handler = bare_handler()
        handler.page_protections = []
        handler.record_protection(0x10000, 0x14000, 0x04)
        handler.record_protection(0x11000, 0x12000, 0x02)
        self.assertEqual(handler._page_protection(0x10000), 0x04)
        self.assertEqual(handler._page_protection(0x11000), 0x02)
        self.assertEqual(handler._page_protection(0x13000), 0x04)
        self.assertEqual(handler._page_protection(0x20000), 0x40)  # not recorded: RWX
        handler.record_protection(0x10000, 0x14000, 0x40)  # back to the default
        self.assertEqual(handler.page_protections, [])

    def test_section_protections(self):
        protections = CPUEmulator._SECTION_PROTECTIONS
        self.assertEqual(protections[(1, 1, 0)], 0x20)  # .text: PAGE_EXECUTE_READ
        self.assertEqual(protections[(0, 1, 0)], 0x02)  # .rdata: PAGE_READONLY
        self.assertEqual(protections[(0, 1, 1)], 0x08)  # .data: PAGE_WRITECOPY
        self.assertEqual(len(protections), 8)


class MissingApiReportTest(unittest.TestCase):
    def test_report_file(self):
        class Loader:
            filepath = '/x/prog.exe'
        emu = CPUEmulator.__new__(CPUEmulator)
        emu.missing_apis, emu.pe_loader, emu.api_handler = {}, Loader(), None
        emu.note_missing_api('KERNEL32.dll', 'NoSuchApi', 'called, returned 0')
        emu.note_missing_api('kernel32.dll', 'NoSuchApi', 'called, returned 0')
        emu.note_missing_api('user32.dll', 'Other', 'GetProcAddress returned NULL')
        with tempfile.TemporaryDirectory() as folder:
            CPUEmulator.missing_apis_file = os.path.join(folder, 'missing.txt')
            try:
                emu.report_missing_apis()
                with open(CPUEmulator.missing_apis_file, encoding='utf-8') as f:
                    lines = f.read().splitlines()
            finally:
                CPUEmulator.missing_apis_file = None
        self.assertEqual(lines, ['?\tkernel32.dll!NoSuchApi: called, returned 0 (2 times)',
                                 '?\tuser32.dll!Other: GetProcAddress returned NULL'])


class MessageQueueTest(unittest.TestCase):
    def test_coalescing(self):
        handler = bare_handler()
        handler.message_queue, handler.message_lock = [], threading.Lock()
        post = handler.post_window_message
        post(1, handler.WM_MOUSEMOVE, 0, 1)
        post(1, handler.WM_MOUSEMOVE, 0, 2)  # replaces the pending one
        post(2, handler.WM_MOUSEMOVE, 0, 3)  # another window
        post(1, handler.WM_SETCURSOR, 1, 0)
        post(1, 0x0100, 0x41, 0)  # WM_KEYDOWN
        post(1, handler.WM_SETCURSOR, 1, 1)  # only the latest per window stays
        self.assertEqual([(m['hwnd'], m['message'], m['lParam']) for m in handler.message_queue],
                         [(1, 0x200, 2), (2, 0x200, 3), (1, 0x100, 0), (1, 0x20, 1)])
        post(-1, 0x10, -1, 0)  # values are 32-bit
        self.assertEqual(handler.message_queue[-1]['hwnd'], 0xFFFFFFFF)
        self.assertEqual(handler.message_queue[-1]['wParam'], 0xFFFFFFFF)


class VersionTest(unittest.TestCase):
    def test_pyproject_version(self):
        import tomllib
        from src.config import WINEXE32EMU_VERSION
        root = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..')
        with open(os.path.join(root, 'pyproject.toml'), 'rb') as f:
            project = tomllib.load(f)['project']
        self.assertEqual(project['version'], WINEXE32EMU_VERSION)


class ProcessIdTest(unittest.TestCase):
    def test_unique_ids(self):
        ids = [CPUEmulator.allocate_id() for _ in range(100)]
        self.assertEqual(len(set(ids)), 100)
        self.assertTrue(all(i % 4 == 0 for i in ids))


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


class ProgramManagerDdeTest(unittest.TestCase):
    def test_parse_commands(self):
        commands = parse_progman_commands(
            '[CreateGroup(Microsoft Office)] [ShowGroup("Microsoft Office",1)]'
            '[AddItem("C:\\MSOffice\\Word, 7\\WINWORD.EXE" /n,Microsoft Word,,0)][Reload]')
        self.assertEqual(commands, [
            ('creategroup', ['Microsoft Office']),
            ('showgroup', ['Microsoft Office', '1']),
            ('additem', ['C:\\MSOffice\\Word, 7\\WINWORD.EXE /n', 'Microsoft Word', '', '0']),
            ('reload', []),
        ])
        self.assertEqual(split_command_line('"C:\\A B\\x.exe" /s'), ('C:\\A B\\x.exe', '/s'))
        self.assertEqual(split_command_line('C:\\x.exe'), ('C:\\x.exe', ''))

    def test_groups_and_items(self):
        handler = bare_handler()
        with tempfile.TemporaryDirectory() as folder:
            handler.SHELL_FOLDERS = {0x02: 'C:\\Programs', 0x17: 'C:\\Common'}
            handler.resolve_drive_path = lambda path: os.path.join(
                folder, *path[3:].split('\\'))
            handler._write_protected = lambda *paths: False
            handler._shell_link_data = lambda link: ('|'.join(
                (link['path'], link['arguments'], link['workdir']))).encode()
            self.assertTrue(handler._progman_execute(
                '[CreateGroup(Office: 95)][AddItem("C:\\Office\\winword.exe" /n,Word,,,,,C:\\Docs)]'
                '[AddItem(C:\\Office\\excel.exe)]'))
            group = os.path.join(folder, 'Programs', 'Office_ 95')
            self.assertEqual(sorted(os.listdir(group)), ['Word.lnk', 'excel.lnk'])
            with open(os.path.join(group, 'Word.lnk'), 'rb') as f:
                self.assertEqual(f.read(), b'C:\\Office\\winword.exe|/n|C:\\Docs')
            self.assertEqual(handler._progman_request('Groups'), 'Office_ 95\r\n')
            self.assertTrue(handler._progman_execute('[DeleteItem(excel)]'))
            self.assertEqual(os.listdir(group), ['Word.lnk'])
            self.assertTrue(handler._progman_execute('[DeleteGroup(Office: 95)]'))
            self.assertFalse(os.path.exists(group))
            self.assertFalse(handler._progman_execute('[AddItem()]'))

    def test_connect(self):
        handler = bare_handler()
        state = handler._dde_state()
        state['instances'][1] = {'callback': 0, 'flags': 0, 'wide': False, 'error': 0}
        state['strings'].update({2: 'PROGMAN', 3: 'Excel', 4: 'progman'})
        self.assertEqual(handler.DdeCmpStringHandles([2, 4]), 0)
        self.assertNotEqual(handler.DdeConnect([1, 2, 2, 0]), 0)
        self.assertEqual(handler.DdeConnect([1, 3, 3, 0]), 0)
        self.assertEqual(handler.DdeGetLastError([1]), 0x400A)  # DMLERR_NO_CONV_ESTABLISHED
        self.assertEqual(handler.DdeGetLastError([1]), 0)


class SzddTest(unittest.TestCase):
    def test_expand(self):
        header = b'SZDD\x88\xf0\x27\x33A' + b'T' + (9).to_bytes(4, 'little')
        # Literals A, B, C, then a match of 6 bytes from the window position
        # where the first literal went (4096 - 16 = 0xFF0)
        data = header + bytes([0x07]) + b'ABC' + bytes([0xF0, 0xF3])
        self.assertEqual(expand_szdd(data), b'ABCABCABC')
        self.assertEqual(expanded_name('README.TX_', data), 'README.TXT')
        self.assertEqual(expand_szdd(b'plain'), b'plain')
        self.assertEqual(expanded_name('README.TXT', b'plain'), 'README.TXT')


class SecurityAndNetworkTest(unittest.TestCase):
    def test_sid_bytes(self):
        data = WinAPIHandler._sid_bytes('S-1-5-32-544')
        self.assertEqual(data, bytes([1, 2, 0, 0, 0, 0, 0, 5]) +
                         bytes([32, 0, 0, 0, 0x20, 2, 0, 0]))
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


class DrawTextTest(unittest.TestCase):
    def test_prefixes(self):
        self.assertEqual(WinAPIHandler._strip_prefixes('&Typical'), ('Typical', 0))
        self.assertEqual(WinAPIHandler._strip_prefixes('C&ustom'), ('Custom', 1))
        self.assertEqual(WinAPIHandler._strip_prefixes('A && B'), ('A & B', -1))

    def test_word_break(self):
        handler = bare_handler()
        handler.gui = None
        handler.dc_state = {}  # No font: 8 pixels per character
        breaks = WinAPIHandler.DT_WORDBREAK
        self.assertEqual(handler._text_lines(1, 'aaa bbb ccc', 60, breaks), [(0, 7), (8, 11)])
        self.assertEqual(handler._text_lines(1, 'one\r\ntwo', 400, breaks), [(0, 3), (5, 8)])
        self.assertEqual(handler._text_lines(1, 'aaa bbb ccc', 60, WinAPIHandler.DT_SINGLELINE),
                         [(0, 11)])
        # A word wider than the line gets a line of its own
        self.assertEqual(handler._text_lines(1, 'aaaaaaaaaa b', 40, breaks), [(0, 10), (11, 12)])


class VirtualReservationTest(unittest.TestCase):
    def test_reserved_pages_are_not_used_memory(self):
        """A MEM_RESERVE region counts only its committed pages (Microsoft Jet
        reserves as much address space as the physical memory)"""
        handler = bare_handler()
        base = 0x20000000
        handler.virtual_allocs = {base: 0x40000000, 0x60000000: 0x100000}
        handler.mapped_virtual_allocs = {base, 0x60000000}
        handler.virtual_commits = {base: set()}
        self.assertEqual(handler._big_region_usage(), 0x100000)
        self.assertTrue(handler._commit_pages(base, base + 0x1000, base + 0x4000))
        self.assertTrue(handler._commit_pages(base, base, base + 0x2000))  # One page again
        self.assertEqual(handler._big_region_usage(), 0x100000 + 0x4000)
        handler.BIG_REGION_BUDGET = 0x105000
        self.assertFalse(handler._commit_pages(base, base + 0x4000, base + 0x6000))


class ShellFoldersRegistryTest(unittest.TestCase):
    def test_defaults(self):
        roots = WinAPIHandler._default_registry()
        node = roots[0x80000001]
        for part in ('software', 'microsoft', 'windows', 'currentversion', 'explorer',
                     'shell folders'):
            node = node['keys'][part]
        self.assertEqual(node['values']['programs']['data'],
                         WinAPIHandler.SHELL_FOLDERS[0x02] + '\x00')

    def test_merge_keeps_saved_values(self):
        saved = WinAPIHandler._new_registry_key('HKEY_CURRENT_USER')
        saved['values']['x'] = {'name': 'X', 'type': 1, 'data': 'saved\x00'}
        default = WinAPIHandler._new_registry_key('HKEY_CURRENT_USER')
        default['values']['x'] = {'name': 'X', 'type': 1, 'data': 'default\x00'}
        default['values']['y'] = {'name': 'Y', 'type': 1, 'data': 'y\x00'}
        default['keys']['software'] = WinAPIHandler._new_registry_key('Software')
        merged = WinAPIHandler._merge_registry_defaults(saved, default)
        self.assertEqual(merged['values']['x']['data'], 'saved\x00')
        self.assertEqual(merged['values']['y']['data'], 'y\x00')
        self.assertIn('software', merged['keys'])


class ChildFrameTest(unittest.TestCase):
    def test_child_frames(self):
        from src.gui import PseudoWindowsGUI
        gui = PseudoWindowsGUI
        # Office 95 Setup's dialogs: WS_CHILD | WS_CAPTION | WS_SYSMENU | DS_MODALFRAME
        self.assertEqual(gui.child_frame_size(0x44C800C0, dialog=True),
                         (gui.BORDER, gui.TITLE_BAR_H))
        self.assertEqual(gui.child_frame_size(0x440000C0, dialog=True), (gui.BORDER, 0))
        self.assertEqual(gui.child_frame_size(0x440000C0), (0, 0))
        self.assertEqual(gui.child_frame_size(0x50800000), (1, 0))  # WS_BORDER
        self.assertEqual(gui.child_frame_size(0x50000000, 0x200), (1, 0))  # Client edge
        self.assertEqual(gui.child_frame_size(0x50000000), (0, 0))


class CpuExceptionStateTest(unittest.TestCase):
    def test_calibration(self):
        """The field that turns a second #DE into a double fault is found (a
        Unicorn upgrade may move it: requirements.txt pins the version)"""
        offset = CPUEmulator._find_exception_state_offset()
        self.assertIsInstance(offset, int)


if __name__ == '__main__':
    unittest.main()
