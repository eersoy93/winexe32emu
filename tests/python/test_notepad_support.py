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

"""Unit tests of what Notepad (apps/notepad) needs from the emulator and that
works without an emulated program: the Windows code page numbers and
conversions, CPINFO, string lengths in UTF-16 units, the edit control's
undo, word wrap and line lookup, RegisterWindowMessageW.

Run from the repository root:
    python3 -m unittest discover -s tests/python -v
"""

import os
import struct
import sys
import types
import unittest

from unicorn import Uc, UC_ARCH_X86, UC_MODE_32

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
from src import config  # noqa: E402
from src.windows import FakeControl  # noqa: E402
from src.winapi import WinAPIHandler  # noqa: E402
from src.winapi.codepages import (codec_for_codepage, decode_codepage,  # noqa: E402
                                  encode_codepage, max_char_size)


class FakeEmulator:
    """Just enough of CPUEmulator for the handlers: memory, a thread, a heap
    and callbacks"""
    BASE = 0x100000
    SIZE = 0x200000

    def __init__(self):
        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        self.uc.mem_map(self.BASE, self.SIZE)
        self.current_thread = types.SimpleNamespace(last_error=0)
        self.next_free = self.BASE + 0x100000
        self.callbacks = []

    def heap_alloc(self, size):
        address = self.next_free
        self.next_free += (size + 15) & ~15
        return address

    def heap_free(self, address):
        pass

    def call_callback(self, proc, args):
        self.callbacks.append(self.uc.mem_read(args[0], 32))
        return 1


def bare_handler():
    handler = WinAPIHandler.__new__(WinAPIHandler)
    handler.emu = FakeEmulator()
    handler.handles = {}
    handler.gui = None
    return handler


class CodePageTableTest(unittest.TestCase):
    def test_windows_numbers(self):
        self.assertEqual(codec_for_codepage(1254), 'cp1254')
        self.assertEqual(codec_for_codepage(28591), 'iso8859-1')
        self.assertEqual(codec_for_codepage(28599), 'iso8859-9')
        self.assertEqual(codec_for_codepage(20866), 'koi8-r')
        self.assertEqual(codec_for_codepage(936), 'gbk')
        self.assertEqual(codec_for_codepage(54936), 'gb18030')
        self.assertEqual(codec_for_codepage(65001), 'utf-8')
        self.assertIsNone(codec_for_codepage(1200))  # UTF-16: not for these APIs
        self.assertIsNone(codec_for_codepage(99999))

    def test_max_char_size(self):
        self.assertEqual(max_char_size(1252), 1)
        self.assertEqual(max_char_size(932), 2)
        self.assertEqual(max_char_size(65001), 4)

    def test_undefined_single_bytes_round_trip(self):
        # Windows-1252 has no character for 0x81: it is U+0081 and back
        text = decode_codepage(b'a\x81b', 'cp1252')
        self.assertEqual(text, 'a\x81b')
        self.assertEqual(encode_codepage(text, 'cp1252'), (b'a\x81b', False))

    def test_unrepresentable_characters_use_the_default(self):
        self.assertEqual(encode_codepage('aşb', 'cp1252'), (b'a?b', True))
        self.assertEqual(encode_codepage('aşb', 'cp1252', b'#'), (b'a#b', True))
        self.assertEqual(encode_codepage('aşb', 'cp1254'), (b'a\xfeb', False))

    def test_strict_multibyte(self):
        self.assertIsNone(decode_codepage(b'a\xff', 'utf-8', strict=True))
        self.assertEqual(decode_codepage(b'a\xff', 'utf-8'), 'a�')


class ConversionApiTest(unittest.TestCase):
    SRC, DST = FakeEmulator.BASE, FakeEmulator.BASE + 0x1000

    def setUp(self):
        self.handler = bare_handler()
        self.mem = self.handler.emu.uc

    def error(self):
        return self.handler.emu.current_thread.last_error

    def to_wide(self, code_page, data, flags=0):
        self.mem.mem_write(self.SRC, data)
        count = self.handler.MultiByteToWideChar([code_page, flags, self.SRC, len(data),
                                                  self.DST, 0x400])
        return bytes(self.mem.mem_read(self.DST, count * 2)).decode('utf-16-le') if count \
            else None

    def test_iso_and_koi8_code_pages(self):
        self.assertEqual(self.to_wide(28599, b'\xf0\xfd\xfe'), 'ğış')
        self.assertEqual(self.to_wide(20866, b'\xf0\xd2\xc9'), 'При')

    def test_oem_code_page_is_not_the_ansi_one(self):
        # CP_OEMCP of a Western Windows is 850: 0x82 is e-acute (not cp1252's comma)
        self.assertEqual(config.ANSI_CODEPAGE, 'cp1252')
        self.assertEqual(self.to_wide(1, b'\x82'), 'é')

    def test_mb_err_invalid_chars(self):
        self.assertIsNone(self.to_wide(65001, b'a\xc0\x80', flags=0x8))
        self.assertEqual(self.error(), 1113)  # ERROR_NO_UNICODE_TRANSLATION
        self.assertEqual(self.to_wide(65001, b'a\xff'), 'a�')

    def test_default_char_and_used_default(self):
        text = 'xşy'.encode('utf-16-le')
        self.mem.mem_write(self.SRC, text)
        self.mem.mem_write(self.SRC + 0x100, b'*\x00')
        used = self.SRC + 0x200
        count = self.handler.WideCharToMultiByte([1252, 0, self.SRC, 3, self.DST, 16,
                                                  self.SRC + 0x100, used])
        self.assertEqual(bytes(self.mem.mem_read(self.DST, count)), b'x*y')
        self.assertEqual(struct.unpack('<I', self.mem.mem_read(used, 4))[0], 1)

    def test_long_null_terminated_input(self):
        # Not cut at 32K characters (Notepad converts whole files)
        text = ('ğ' * 40000 + '\0').encode('utf-16-le')
        self.mem.mem_write(self.SRC, text)
        size = self.handler.WideCharToMultiByte([65001, 0, self.SRC, 0xFFFFFFFF, 0, 0, 0, 0])
        self.assertEqual(size, 80001)

    def test_cp_info(self):
        info = self.SRC + 0x800
        self.assertEqual(self.handler.GetCPInfo([932, info]), 1)
        size, default, lead = struct.unpack('<I2s12s', self.mem.mem_read(info, 18))
        self.assertEqual((size, default[:1], lead[:4]), (2, b'?', b'\x81\x9f\xe0\xfc'))
        self.assertEqual(self.handler.GetCPInfo([12345, info]), 0)
        self.assertEqual(self.error(), 87)

    def test_cp_info_ex(self):
        info = self.SRC + 0x800
        self.assertEqual(self.handler.GetCPInfoExW([1254, 0, info]), 1)
        code_page = struct.unpack('<I', self.mem.mem_read(info + 20, 4))[0]
        name = bytes(self.mem.mem_read(info + 24, 80)).decode('utf-16-le').split('\0')[0]
        self.assertEqual((code_page, name), (1254, '1254  (ANSI - Turkish)'))

    def test_is_valid_code_page(self):
        self.assertEqual(self.handler.IsValidCodePage([28605]), 1)
        self.assertEqual(self.handler.IsValidCodePage([51949]), 1)
        self.assertEqual(self.handler.IsValidCodePage([1200]), 0)

    def test_enum_system_code_pages(self):
        self.assertEqual(self.handler.EnumSystemCodePagesW([0x1234, 1]), 1)
        listed = {bytes(data).decode('utf-16-le').split('\0')[0]
                  for data in self.handler.emu.callbacks}
        self.assertTrue({'437', '1254', '20866', '28599', '65001'} <= listed)

    def test_string_lengths_count_utf16_units(self):
        self.mem.mem_write(self.SRC, 'a\U0001F600b\0'.encode('utf-16-le'))
        self.assertEqual(self.handler.lstrlenW([self.SRC]), 4)
        self.assertEqual(self.handler.wcslen([self.SRC]), 4)
        self.mem.mem_write(self.SRC, b'x' * 50000 + b'\0')  # Not cut at 32K
        self.assertEqual(self.handler.lstrlenA([self.SRC]), 50000)

    def test_register_window_message_w(self):
        self.mem.mem_write(self.SRC, b'commdlg_FindReplace\0')
        self.mem.mem_write(self.DST, 'COMMDLG_FINDREPLACE\0'.encode('utf-16-le'))
        self.assertEqual(self.handler.RegisterWindowMessageW([self.DST]),
                         self.handler.RegisterWindowMessageA([self.SRC]))


class TextAssociationTest(unittest.TestCase):
    def test_txt_opens_in_notepad(self):
        roots = WinAPIHandler._default_registry()
        classes = roots[0x80000002]['keys']['software']['keys']['classes']

        def default(path):
            node = classes
            for part in path.split('\\'):
                node = node['keys'][part.lower()]
            return node['values']['']['data'].rstrip('\0')
        self.assertEqual(default('.txt'), 'txtfile')
        self.assertEqual(default('txtfile\\shell\\open\\command'),
                         'C:\\Windows\\notepad.exe %1')


class EditControlTest(unittest.TestCase):
    def edit(self, text='', style=0x4 | 0x80):
        control = FakeControl(1, 'EDIT', text, 0, 0, 200, 100, style)
        return control

    def test_typing_is_undone_at_once_and_undo_redoes(self):
        control = self.edit('ab')
        control.set_selection(2)
        for char in 'xyz':
            control.replace_selection(char)
        self.assertEqual(control.text, 'abxyz')
        self.assertTrue(control.undo())
        self.assertEqual(control.text, 'ab')
        self.assertTrue(control.undo())  # Undoing the undo redoes
        self.assertEqual(control.text, 'abxyz')

    def test_undo_messages(self):
        handler = bare_handler()
        control = self.edit('one')
        message = handler._edit_message
        self.assertEqual(message(control, 0xC6, 0, 0, True), 0)  # EM_CANUNDO
        control.select_all()
        control.replace_selection('two')
        self.assertEqual(message(control, 0xC6, 0, 0, True), 1)
        self.assertEqual(message(control, 0xC7, 0, 0, True), 1)  # EM_UNDO
        self.assertEqual(control.text, 'one')
        message(control, 0xCD, 0, 0, True)  # EM_EMPTYUNDOBUFFER
        self.assertEqual(message(control, 0xC6, 0, 0, True), 0)

    def test_line_lookup(self):
        control = self.edit('ab\r\ncd\r\n\r\nef')
        self.assertEqual(control.edit_lines(), [(0, 2), (4, 6), (8, 8), (10, 12)])
        self.assertEqual([control.line_of(i) for i in (0, 2, 3, 4, 8, 9, 12)],
                         [0, 0, 0, 1, 2, 2, 3])

    def test_word_wrap(self):
        # Without ES_AUTOHSCROLL a multiline edit breaks lines after a blank
        control = self.edit('aaa bbb ccc\r\ndd', style=0x4)
        control.set_wrap(60, lambda char: 10)
        self.assertEqual(control.edit_lines(), [(0, 4), (4, 8), (8, 11), (13, 15)])
        self.assertEqual(control.line_of(4), 1)  # The caret at a break starts the line
        control.set_wrap(200, lambda char: 10)
        self.assertEqual(control.edit_lines(), [(0, 11), (13, 15)])

    def test_scroll_messages(self):
        handler = bare_handler()
        control = self.edit('\r\n'.join(str(i) for i in range(50)))
        control.edit_visible_lines = 10
        self.assertEqual(handler._edit_message(control, 0xB6, 0, 15, True), 1)  # EM_LINESCROLL
        self.assertEqual(control.edit_top_line, 15)
        handler._edit_message(control, 0xB5, 3, 0, True)  # EM_SCROLL, SB_PAGEDOWN
        self.assertEqual(control.edit_top_line, 25)
        self.assertEqual(handler._edit_message(control, 0xCE, 0, 0, True), 25)


if __name__ == '__main__':
    unittest.main()
