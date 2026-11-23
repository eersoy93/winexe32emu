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

"""Unit tests of API handlers that read and write guest memory: the
scanf engine, _strupr/_strlwr, VerQueryValue, RegGetValue, list box item
data, the import table of the PE loader and aligned heap blocks; the
characters of keystrokes and the console input of ReadFile.

Run from the repository root:
    python3 -m unittest discover -s tests/python -v
"""

import io
import os
import struct
import sys
import threading
import types
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
from src import config  # noqa: E402
from src.cpu import CPUEmulator  # noqa: E402
from src.gui.keyboard import KeyboardMixin  # noqa: E402
from src.pe_loader import PELoader  # noqa: E402
from src.windows import FakeControl  # noqa: E402
from src.winapi import WinAPIHandler  # noqa: E402
from tests.python.test_word95_support import FakeEmulator  # noqa: E402

BASE = FakeEmulator.BASE


class MemoryHandlerTest(unittest.TestCase):
    """A handler with 1 MB of guest memory at BASE"""

    def setUp(self):
        self.handler = WinAPIHandler.__new__(WinAPIHandler)
        self.handler.emu = FakeEmulator()
        self.uc = self.handler.emu.uc
        self.free = BASE + 0x80000  # Scratch memory of a test

    def put(self, data):
        """Write data to the scratch memory: its address"""
        address = self.free
        self.uc.mem_write(address, data)
        self.free += (len(data) + 15) & ~15
        return address

    def read(self, address, size):
        return bytes(self.uc.mem_read(address, size))


class ScanfTest(MemoryHandlerTest):
    def test_float_before_other_conversions(self):
        # The float conversion used to overwrite the format being walked
        src = self.put(b'1.5 2 abc\x00')
        fmt = self.put(b'%f %d %3s\x00')
        f, d, s = self.put(b'\x00' * 4), self.put(b'\x00' * 4), self.put(b'\x00' * 8)
        self.assertEqual(self.handler._scan_string(src, fmt, [f, d, s]), 3)
        self.assertEqual(struct.unpack('<f', self.read(f, 4))[0], 1.5)
        self.assertEqual(struct.unpack('<i', self.read(d, 4))[0], 2)
        self.assertEqual(self.read(s, 4), b'abc\x00')

    def test_double(self):
        src = self.put(b'2.25 7\x00')
        fmt = self.put(b'%lf %d\x00')
        f, d = self.put(b'\x00' * 8), self.put(b'\x00' * 4)
        self.assertEqual(self.handler._scan_string(src, fmt, [f, d]), 2)
        self.assertEqual(struct.unpack('<d', self.read(f, 8))[0], 2.25)
        self.assertEqual(struct.unpack('<i', self.read(d, 4))[0], 7)


class StringCaseTest(MemoryHandlerTest):
    def test_strupr_keeps_the_length(self):
        # 'ß'.upper() is 'SS': the string must not grow past its buffer
        s = self.put('straße\x00'.encode('cp1252') + b'\xAA')
        self.handler._strupr([s])
        self.assertEqual(self.read(s, 8), 'STRAßE\x00'.encode('cp1252') + b'\xAA')

    def test_only_ascii_letters_change(self):
        # The "C" locale: 'µ' (0xB5) has no uppercase byte
        s = self.put(b'a\xb5\xc4Z\x00')
        self.handler._strlwr([s])
        self.assertEqual(self.read(s, 5), b'a\xb5\xc4z\x00')
        self.handler._strupr([s])
        self.assertEqual(self.read(s, 5), b'A\xb5\xc4Z\x00')


class VersionNodeTest(unittest.TestCase):
    def test_key_past_the_end(self):
        # A node whose key never ends used to loop forever
        with self.assertRaises(IndexError):
            WinAPIHandler._version_node(b'\x10\x00\x00\x00\x01\x00AB', 0)

    def test_node(self):
        key = 'VS_VERSION_INFO'.encode('utf-16-le') + b'\x00\x00'
        block = struct.pack('<HHH', 6 + len(key), 0, 0) + key
        length, value_length, _, name, _, _ = WinAPIHandler._version_node(block, 0)
        self.assertEqual((length, value_length, name), (len(block), 0, 'VS_VERSION_INFO'))


class RegGetValueTest(MemoryHandlerTest):
    RRF_RT_ANY, RRF_ZEROONFAILURE = 0xFFFF, 0x20000000

    def test_zero_on_failure_stays_in_the_buffer(self):
        node = {'values': {'big': {'name': 'big', 'type': 3, 'data': b'x' * 100}}}
        self.handler._registry_walk = lambda hkey, subkey, create=False: (node, 0)
        name = self.put(b'big\x00')
        data = self.put(b'\xAA' * 64)
        size = self.put(struct.pack('<I', 16))
        result = self.handler.RegGetValueA(
            [0x80000002, 0, name, self.RRF_RT_ANY | self.RRF_ZEROONFAILURE, 0, data, size])
        self.assertEqual(result, 234)  # ERROR_MORE_DATA
        self.assertEqual(struct.unpack('<I', self.read(size, 4))[0], 100)  # The size needed
        # Only the caller's 16 bytes are zeroed
        self.assertEqual(self.read(data, 64), b'\x00' * 16 + b'\xAA' * 48)


class ListBoxItemDataTest(MemoryHandlerTest):
    LBS_OWNERDRAWFIXED, LBS_HASSTRINGS = 0x10, 0x40

    def message(self, control, msg, wParam=0, lParam=0):
        return self.handler._control_message(control, msg, wParam, lParam)

    def test_item_data(self):
        h = self.handler
        box = FakeControl(1, 'LISTBOX', '', 0, 0, 100, 100)
        self.message(box, h.LB_ADDSTRING, 0, self.put(b'one\x00'))
        self.message(box, h.LB_ADDSTRING, 0, self.put(b'two\x00'))
        self.assertEqual(self.message(box, h.LB_SETITEMDATA, 1, 0x1234), 1)
        self.message(box, h.LB_INSERTSTRING, 0, self.put(b'zero\x00'))
        self.assertEqual(self.message(box, h.LB_GETITEMDATA, 2), 0x1234)  # Moved with its item
        self.message(box, h.LB_DELETESTRING, 0)
        self.assertEqual(self.message(box, h.LB_GETITEMDATA, 1), 0x1234)
        self.assertEqual(self.message(box, h.LB_GETITEMDATA, 5), h.LB_ERR)
        self.assertEqual(self.message(box, h.LB_FINDSTRINGEXACT, 0xFFFFFFFF,
                                      self.put(b'TWO\x00')), 1)
        self.assertEqual(self.message(box, h.LB_FINDSTRING, 0xFFFFFFFF, self.put(b'o\x00')), 0)

    def test_owner_draw_without_strings(self):
        # lParam is item data: reading it as a string pointer stopped the program
        h = self.handler
        box = FakeControl(1, 'LISTBOX', '', 0, 0, 100, 100, style=self.LBS_OWNERDRAWFIXED)
        self.assertEqual(self.message(box, h.LB_ADDSTRING, 0, 5), 0)
        self.assertEqual(self.message(box, h.LB_ADDSTRING, 0, 7), 1)
        self.assertEqual(self.message(box, h.LB_GETITEMDATA, 1), 7)
        self.assertEqual(self.message(box, h.LB_FINDSTRING, 0xFFFFFFFF, 7), 1)
        out = self.put(b'\x00' * 4)
        self.assertEqual(self.message(box, h.LB_GETTEXT, 0, out), 4)
        self.assertEqual(struct.unpack('<I', self.read(out, 4))[0], 5)

    def test_combo_box_item_data(self):
        h = self.handler
        combo = FakeControl(1, 'COMBOBOX', '', 0, 0, 100, 100)
        self.message(combo, h.CB_ADDSTRING, 0, self.put(b'a\x00'))
        self.message(combo, h.CB_ADDSTRING, 0, self.put(b'b\x00'))
        self.message(combo, 0x0151, 1, 99)  # CB_SETITEMDATA
        self.message(combo, h.CB_DELETESTRING, 0)
        self.assertEqual(self.message(combo, 0x0150, 0), 99)  # CB_GETITEMDATA
        self.message(combo, h.CB_RESETCONTENT)
        self.assertEqual(self.message(combo, 0x0150, 0), h.CB_ERR)


class FailureResultTest(unittest.TestCase):
    def test_error_code_apis_do_not_report_success(self):
        # A handler that fails returns this: 0 is success for these APIs
        failure = WinAPIHandler.failure_result
        self.assertEqual(failure('RegQueryValueExA'), 998)  # ERROR_NOACCESS
        self.assertEqual(failure('SHGetValueW'), 998)
        self.assertEqual(failure('IStorage::OpenStream'), 0x80004005)  # E_FAIL
        self.assertEqual(failure('IStorage::Release'), 0)
        self.assertEqual(failure('RegisterClassA'), 0)  # An ATOM: 0 is failure
        self.assertEqual(failure('CreateFileA'), 0)


class SubclassedControlTextTest(MemoryHandlerTest):
    def test_ansi_text_through_call_window_proc(self):
        # CallWindowProcA from an ANSI subclass: the text is ANSI, not UTF-16
        box = FakeControl(1, 'LISTBOX', '', 0, 0, 100, 100)
        self.handler.gui = types.SimpleNamespace(controls={1: box}, windows={})
        self.handler._control_default(1, self.handler.LB_ADDSTRING, 0,
                                      self.put('çalış\x00'.encode('cp1254')), wide=False)
        old_codepage = config.ANSI_CODEPAGE
        try:
            config.ANSI_CODEPAGE = 'cp1254'
            self.handler._control_default(1, self.handler.LB_ADDSTRING, 0,
                                          self.put('şey\x00'.encode('cp1254')), wide=False)
        finally:
            config.ANSI_CODEPAGE = old_codepage
        self.assertEqual(box.items[1], 'şey')


class CharacterMessageTest(unittest.TestCase):
    def test_ansi_characters(self):
        # GetMessageA: WM_CHAR in the ANSI code page ('ş' is 0xFE in cp1254)
        old_codepage = config.ANSI_CODEPAGE
        try:
            config.ANSI_CODEPAGE = 'cp1254'
            self.assertEqual(WinAPIHandler._ansi_char_code(ord('ş')), 0xFE)
            self.assertEqual(WinAPIHandler._ansi_char_code(ord('a')), ord('a'))
            self.assertEqual(WinAPIHandler._ansi_char_code(0x4E2D), 0x3F)  # No ANSI character: '?'
        finally:
            config.ANSI_CODEPAGE = old_codepage

    def key_char(self, unicode, vk, **keys):
        gui = types.SimpleNamespace(key_states=keys.get('states', {}),
                                    CONTROL_KEY_CHARS=KeyboardMixin.CONTROL_KEY_CHARS)
        return KeyboardMixin._key_char(gui, types.SimpleNamespace(unicode=unicode), vk)

    def test_control_keys(self):
        # Enter, Backspace, Tab and Escape give WM_CHAR too (TranslateMessage)
        self.assertEqual(self.key_char('\r', 0x0D), 0x0D)
        self.assertEqual(self.key_char('\x08', 0x08), 0x08)
        self.assertEqual(self.key_char('', 0x09), 0x09)
        self.assertEqual(self.key_char('\x1b', 0x1B), 0x1B)
        self.assertEqual(self.key_char('z', 0x5A, states={0x11: True}), 26)  # Ctrl+Z
        # AltGr (Ctrl+Alt) types its character
        self.assertEqual(self.key_char('@', 0x51, states={0x11: True, 0x12: True}), ord('@'))
        self.assertEqual(self.key_char('ş', 0xBA), ord('ş'))
        self.assertIsNone(self.key_char('', 0x25))  # Left arrow: no character


class ConsoleReadFileTest(unittest.TestCase):
    def test_lines_in_parts(self):
        # A line that does not fit is kept for the next ReadFile
        handler = WinAPIHandler.__new__(WinAPIHandler)
        handler.gui = None
        stdin = sys.stdin
        sys.stdin = types.SimpleNamespace(buffer=io.BytesIO(b'hello world\n'))
        try:
            parts = [handler._read_console_input_bytes(5) for _ in range(4)]
        finally:
            sys.stdin = stdin
        self.assertEqual(parts, [b'hello', b' worl', b'd\r\n', b''])


class DuplicateImportDescriptorTest(unittest.TestCase):
    def test_descriptors_of_one_dll_add_up(self):
        # Delphi and Borland EXEs name kernel32.dll in several descriptors
        def descriptor(dll, names):
            return types.SimpleNamespace(dll=dll, imports=[
                types.SimpleNamespace(name=n, address=0x1000 + i * 4, ordinal=None)
                for i, n in enumerate(names)])
        loader = PELoader.__new__(PELoader)
        loader.imports = {}
        loader.pe = types.SimpleNamespace(DIRECTORY_ENTRY_IMPORT=[
            descriptor(b'kernel32.dll', [b'GetVersion', b'ExitProcess']),
            descriptor(b'user32.dll', [b'MessageBoxA']),
            descriptor(b'kernel32.dll', [b'Sleep'])])
        loader._parse_imports()
        self.assertEqual([f['name'] for f in loader.imports['kernel32.dll']],
                         ['GetVersion', 'ExitProcess', 'Sleep'])


class AlignedHeapBlockTest(unittest.TestCase):
    def test_freed_aligned_block_is_reused(self):
        # Thread stacks (64 KB aligned) are freed when their thread ends
        emu = CPUEmulator.__new__(CPUEmulator)
        emu.HEAP_BASE, emu.HEAP_SIZE = 0x10000000, 0x1000000
        emu.heap_current = emu.HEAP_BASE
        emu.heap_blocks, emu.heap_free_bins, emu.heap_free_ends = {}, {}, {}
        emu.heap_class_map = None
        emu._tls = threading.local()
        emu.main_thread = types.SimpleNamespace(
            uc=types.SimpleNamespace(mem_write=lambda address, data: None))
        stack = emu.heap_alloc(0x40000, alignment=0x10000)
        emu.heap_alloc(0x10)  # Not the top block anymore
        self.assertTrue(emu.heap_free(stack))
        self.assertEqual(emu.heap_alloc(0x40000, alignment=0x10000), stack)


if __name__ == '__main__':
    unittest.main()
