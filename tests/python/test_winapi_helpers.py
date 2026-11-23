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

"""Unit tests of API modules the C test programs reach only in part:
wildcards, the time conversions, INI files, the printf engine,
VerQueryValue, hard links in the sandbox, the share modes of CreateFile,
the DIB decoder and the GUI's text cache.

Run from the repository root:
    python3 -m unittest discover -s tests/python -v
"""

import os
import random
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
from src.config import C_DRIVE_PATH, DRIVES_PATH  # noqa: E402
from src.gui.font_cache import CachedFont  # noqa: E402
from src.logger import DebugLogger  # noqa: E402
from src.winapi import WinAPIHandler  # noqa: E402
from src.winapi.memory_dc import MemoryDCMixin  # noqa: E402
from tests.python.test_word95_support import FakeEmulator  # noqa: E402

DebugLogger.level = DebugLogger.WARNING + 1
BASE = FakeEmulator.BASE


class MemoryHandlerTest(unittest.TestCase):
    """A handler with 1 MB of guest memory at BASE"""

    def setUp(self):
        self.handler = WinAPIHandler.__new__(WinAPIHandler)
        self.handler.emu = FakeEmulator()
        self.handler.current_directory = 'C:\\'
        self.uc = self.handler.emu.uc
        self.free = BASE + 0x80000

    def put(self, data):
        address = self.free
        self.uc.mem_write(address, data)
        self.free += (len(data) + 15) & ~15
        return address

    def read(self, address, size):
        return bytes(self.uc.mem_read(address, size))

    @property
    def last_error(self):
        return self.handler.emu.current_thread.last_error


class WildcardTest(unittest.TestCase):
    def test_patterns(self):
        regex = WinAPIHandler._wildcard_regex
        cases = [('*.txt', 'README.TXT', True), ('*.txt', 'a.txt.bak', False),
                 ('a?c', 'abc', True), ('a?c', 'ac', False), ('*.*', 'README', True),
                 ('*', '.hidden', True), ('[x].txt', '[x].txt', True),
                 ('file?.dat', 'FILE1.DAT', True)]
        for pattern, name, expected in cases:
            with self.subTest(pattern=pattern, name=name):
                self.assertEqual(bool(regex(pattern).match(name)), expected)


class TimeConversionTest(MemoryHandlerTest):
    def test_system_time_round_trip(self):
        system = self.put(struct.pack('<8H', 2026, 11, 1, 23, 14, 5, 9, 250))
        filetime = self.put(b'\x00' * 8)
        self.assertEqual(self.handler.SystemTimeToFileTime([system, filetime]), 1)
        back = self.put(b'\x00' * 16)
        self.assertEqual(self.handler.FileTimeToSystemTime([filetime, back]), 1)
        year, month, weekday, day, hour, minute, second, ms = struct.unpack(
            '<8H', self.read(back, 16))
        self.assertEqual((year, month, day, hour, minute, second, ms),
                         (2026, 11, 23, 14, 5, 9, 250))
        self.assertEqual(weekday, 1)  # Monday (Sunday is 0)

    def test_known_filetime(self):
        # 1970-01-01 is 11644473600 seconds after 1601-01-01
        filetime = self.put(struct.pack('<Q', 11644473600 * 10000000))
        out = self.put(b'\x00' * 16)
        self.handler.FileTimeToSystemTime([filetime, out])
        self.assertEqual(struct.unpack('<8H', self.read(out, 16))[:4], (1970, 1, 4, 1))

    def test_invalid_system_time(self):
        system = self.put(struct.pack('<8H', 2026, 13, 0, 1, 0, 0, 0, 0))
        self.assertEqual(self.handler.SystemTimeToFileTime([system, self.put(b'\x00' * 8)]),
                         0)
        self.assertEqual(self.last_error, 87)  # ERROR_INVALID_PARAMETER

    def test_dos_date_time(self):
        # 2026-11-23 14:05:08 (DOS times count 2-second steps)
        dos_date = ((2026 - 1980) << 9) | (11 << 5) | 23
        dos_time = (14 << 11) | (5 << 5) | 4
        filetime = self.put(b'\x00' * 8)
        self.assertEqual(self.handler.DosDateTimeToFileTime([dos_date, dos_time, filetime]), 1)
        date_out, time_out = self.put(b'\x00' * 2), self.put(b'\x00' * 2)
        self.assertEqual(self.handler.FileTimeToDosDateTime([filetime, date_out, time_out]), 1)
        self.assertEqual(struct.unpack('<H', self.read(date_out, 2))[0], dos_date)
        self.assertEqual(struct.unpack('<H', self.read(time_out, 2))[0], dos_time)

    def test_dos_dates_start_in_1980(self):
        filetime = self.put(struct.pack('<Q', 11644473600 * 10000000))  # 1970
        self.assertEqual(self.handler.FileTimeToDosDateTime([filetime, 0, 0]), 0)

    def test_compare(self):
        early, late = self.put(struct.pack('<Q', 5)), self.put(struct.pack('<Q', 9))
        self.assertEqual(self.handler.CompareFileTime([early, late]), 0xFFFFFFFF)
        self.assertEqual(self.handler.CompareFileTime([late, early]), 1)
        self.assertEqual(self.handler.CompareFileTime([late, late]), 0)


class IniParsingTest(unittest.TestCase):
    LINES = ['; comment', '[Setup]', 'Name = "Ski 32"', 'path=C:\\SKI', '',
             '[Other]', 'Name=x', '[setup2]', 'a=b']

    def setUp(self):
        self.handler = WinAPIHandler.__new__(WinAPIHandler)

    def test_lines(self):
        self.assertEqual(WinAPIHandler._ini_section_name(' [Setup] '), 'Setup')
        self.assertIsNone(WinAPIHandler._ini_section_name('Setup'))
        self.assertEqual(WinAPIHandler._ini_key_value(' Key = value '), ('Key', 'value'))
        self.assertIsNone(WinAPIHandler._ini_key_value('; a=b'))
        self.assertIsNone(WinAPIHandler._ini_key_value('no value'))

    def test_values(self):
        value = self.handler._ini_value
        self.assertEqual(value(self.LINES, 'setup', 'NAME'), 'Ski 32')  # Quotes removed
        self.assertEqual(value(self.LINES, 'Setup', 'Path'), 'C:\\SKI')
        self.assertEqual(value(self.LINES, 'Other', 'name'), 'x')
        self.assertIsNone(value(self.LINES, 'Setup', 'a'))  # In another section
        self.assertIsNone(value(self.LINES, 'Missing', 'Name'))
        self.assertEqual(self.handler._ini_section_range(self.LINES, 'OTHER'), (5, 7))


class FormatStringTest(MemoryHandlerTest):
    def format(self, fmt, *args):
        return self.handler._format_string(fmt, list(args))

    def test_integers(self):
        self.assertEqual(self.format('%d|%5d|%-5d|%05d', 42, 42, 42, 42),
                         '42|   42|42   |00042')
        self.assertEqual(self.format('%d %u', 0xFFFFFFFF, 0xFFFFFFFF), '-1 4294967295')
        self.assertEqual(self.format('%x %X %#x %o', 255, 255, 255, 8), 'ff FF 0xff 10')
        self.assertEqual(self.format('%+d %+d', 5, 0xFFFFFFFB), '+5 -5')

    def test_64_bit_integers_take_two_slots(self):
        value = 0x123456789
        self.assertEqual(self.format('%I64d %d', value & 0xFFFFFFFF, value >> 32, 7),
                         f'{value} 7')
        self.assertEqual(self.format('%lld', 0xFFFFFFFF, 0xFFFFFFFF), '-1')

    def test_doubles(self):
        low, high = struct.unpack('<II', struct.pack('<d', 3.14159))
        self.assertEqual(self.format('%.2f|%8.3f|%e', low, high, low, high, low, high),
                         '3.14|   3.142|3.141590e+00')

    def test_strings_and_characters(self):
        text = self.put(b'hello\x00')
        self.assertEqual(self.format('[%s] [%10s] [%-7s] [%.3s]', text, text, text, text),
                         '[hello] [     hello] [hello  ] [hel]')
        self.assertEqual(self.format('%c%c %%', ord('o'), ord('k')), 'ok %')
        self.assertEqual(self.format('%s', 0), '(null)')

    def test_star_width(self):
        self.assertEqual(self.format('[%*d] [%-*d]', 4, 7, 3, 1), '[   7] [1  ]')

    def test_wsprintf(self):
        out = self.put(b'\x00' * 64)
        fmt = self.put(b'%s=%d\x00')
        self.assertEqual(self.handler.wsprintfA([out, fmt, self.put(b'x\x00'), 12]), 4)
        self.assertEqual(self.read(out, 5), b'x=12\x00')


class VerQueryValueTest(MemoryHandlerTest):
    @staticmethod
    def node(key, value=b'', value_type=0, children=b''):
        """A version resource node: header, key, value and children, DWORD-aligned"""
        name = key.encode('utf-16-le') + b'\x00\x00'
        head = 6 + len(name)
        head += -head % 4
        value_length = len(value) // 2 if value_type == 1 else len(value)
        body = value + b'\x00' * (-len(value) % 4)
        length = head + len(body) + len(children)
        return (struct.pack('<HHH', length, value_length, value_type) + name +
                b'\x00' * (head - 6 - len(name)) + body + children)

    def block(self):
        fixed = struct.pack('<13I', 0xFEEF04BD, 0x10000, 0x10002, 0x30004, 0x10002,
                            0x30004, 0x3F, 0, 4, 1, 0, 0, 0)
        company = self.node('CompanyName', 'Example\x00'.encode('utf-16-le'), 1)
        table = self.node('040904b0', children=company)
        strings = self.node('StringFileInfo', value_type=1, children=table)
        return self.node('VS_VERSION_INFO', fixed, 0, strings)

    def query(self, block, sub_block, wide=False):
        pointer, length = self.put(b'\x00' * 4), self.put(b'\x00' * 4)
        sub = self.put(sub_block.encode('utf-16-le' if wide else 'ascii') +
                       (b'\x00\x00' if wide else b'\x00'))
        api = self.handler.VerQueryValueW if wide else self.handler.VerQueryValueA
        ok = api([block, sub, pointer, length])
        return ok, struct.unpack('<I', self.read(pointer, 4))[0], \
            struct.unpack('<I', self.read(length, 4))[0]

    def test_fixed_file_info(self):
        data = self.block()
        block = self.put(data + b'\x00' * len(data))  # Room for the ANSI copies
        ok, address, length = self.query(block, '\\')
        self.assertEqual((ok, length), (1, 52))
        self.assertEqual(struct.unpack('<I', self.read(address, 4))[0], 0xFEEF04BD)

    def test_string(self):
        data = self.block()
        block = self.put(data + b'\x00' * len(data))
        ok, address, length = self.query(block, '\\StringFileInfo\\040904B0\\CompanyName')
        self.assertEqual(ok, 1)
        self.assertEqual(self.read(address, length), b'Example\x00')  # The ANSI copy
        ok, address, length = self.query(block, '\\StringFileInfo\\040904b0\\CompanyName',
                                         wide=True)
        self.assertEqual(self.read(address, 2 * 7), 'Example'.encode('utf-16-le'))

    def test_missing(self):
        block = self.put(self.block() * 2)
        self.assertEqual(self.query(block, '\\StringFileInfo\\040904b0\\Nothing')[0], 0)


class HardLinkTest(MemoryHandlerTest):
    """CreateHardLink must not reach the read-only CD-ROM D: (a link shares
    its file's data)"""

    def setUp(self):
        super().setUp()
        self.c_dir = tempfile.mkdtemp(prefix='LinkTest', dir=self._drive('C'))
        self.d_dir = tempfile.mkdtemp(prefix='LinkTest', dir=self._drive('D'))
        for folder in (self.c_dir, self.d_dir):
            with open(os.path.join(folder, 'file.txt'), 'w') as f:
                f.write('data')

    def tearDown(self):
        for folder in (self.c_dir, self.d_dir):
            for name in os.listdir(folder):
                os.remove(os.path.join(folder, name))
            os.rmdir(folder)

    @staticmethod
    def _drive(letter):
        path = C_DRIVE_PATH if letter == 'C' else os.path.join(DRIVES_PATH, letter)
        os.makedirs(path, exist_ok=True)
        return path

    def link(self, new, existing):
        return self.handler.CreateHardLinkA([self.put(new.encode() + b'\x00'),
                                             self.put(existing.encode() + b'\x00'), 0])

    def test_links(self):
        c = 'C:\\' + os.path.basename(self.c_dir)
        d = 'D:\\' + os.path.basename(self.d_dir)
        self.assertEqual(self.link(c + '\\link.txt', c + '\\file.txt'), 1)
        self.assertTrue(os.path.exists(os.path.join(self.c_dir, 'link.txt')))
        self.assertEqual(self.link(c + '\\from_d.txt', d + '\\file.txt'), 0)
        self.assertEqual(self.last_error, 5)  # ERROR_ACCESS_DENIED: D: is read-only
        self.assertEqual(self.link(d + '\\to_d.txt', c + '\\file.txt'), 0)
        self.assertEqual(self.last_error, 5)
        self.assertFalse(os.path.exists(os.path.join(self.c_dir, 'from_d.txt')))
        self.assertFalse(os.path.exists(os.path.join(self.d_dir, 'to_d.txt')))
        self.assertEqual(self.link(c + '\\link.txt', c + '\\file.txt'), 0)
        self.assertEqual(self.last_error, 183)  # ERROR_ALREADY_EXISTS


class ShareModeTest(unittest.TestCase):
    GENERIC_READ, GENERIC_WRITE = 0x80000000, 0x40000000

    def handler_with(self, access, share):
        handler = WinAPIHandler.__new__(WinAPIHandler)
        handler.handles = {4: {'type': 'file', 'path': '/x/file.txt',
                               'share_kinds': WinAPIHandler._share_kinds(access),
                               'share_mode': share}}
        return handler

    def test_conflicts(self):
        read, write = self.GENERIC_READ, self.GENERIC_WRITE
        kinds = WinAPIHandler._share_kinds
        cases = [  # (open handle access, its share, new access, new share, violation)
            (read, 1, read, 1, False), (read, 1, write, 3, True), (read, 0, read, 7, True),
            (write, 3, read, 1, True),  # The open handle writes: the new one must share writing
            (write, 3, read, 3, False), (read | write, 7, 0, 0, False),
            (0x10000, 7, read, 3, True)]  # DELETE needs FILE_SHARE_DELETE
        for held, held_share, access, share, violation in cases:
            with self.subTest(held=held, held_share=held_share, access=access, share=share):
                handler = self.handler_with(held, held_share)
                self.assertEqual(handler._sharing_violation('/x/file.txt', kinds(access), share),
                                 violation)
        self.assertFalse(self.handler_with(read, 0)._sharing_violation('/x/other.txt',
                                                                       kinds(read), 0))


class DibDecodeTest(unittest.TestCase):
    @staticmethod
    def reference(data, width, height, bpp, masks):
        """Top-down RGB of 16/32 bpp bitfield pixels, pixel by pixel"""
        stride = ((width * bpp + 31) // 32) * 4
        out = bytearray()
        for row in range(height):
            src = height - 1 - row  # Bottom-up
            for i in range(width):
                fmt, step = ('<H', 2) if bpp == 16 else ('<I', 4)
                value = struct.unpack_from(fmt, data, src * stride + i * step)[0]
                out += bytes(MemoryDCMixin._bitfield_channel(value, m) for m in masks)
        return bytes(out)

    def test_bitfields(self):
        rng = random.Random(7)
        for bpp, masks in ((16, (0x7C00, 0x03E0, 0x001F)), (16, (0xF800, 0x07E0, 0x001F)),
                           (32, (0xFF0000, 0x00FF00, 0x0000FF)),
                           (32, (0x3FF00000, 0x000FFC00, 0x000003FF))):
            with self.subTest(bpp=bpp, masks=masks):
                width, height = 7, 3
                stride = ((width * bpp + 31) // 32) * 4
                bits = bytes(rng.randrange(256) for _ in range(stride * height))
                header = struct.pack('<IiiHHIIiiII', 40, width, height, 1, bpp, 3,
                                     0, 0, 0, 0, 0) + struct.pack('<III', *masks)
                decoded = MemoryDCMixin._decode_dib(header + bits)
                self.assertEqual(decoded[:2], (width, height))
                self.assertEqual(decoded[2], self.reference(bits, width, height, bpp, masks))

    def test_known_pixels(self):
        # 16 bpp 5-6-5: pure red, green and blue; top-down (negative height)
        pixels = struct.pack('<3H', 0xF800, 0x07E0, 0x001F) + b'\x00\x00'
        header = struct.pack('<IiiHHIIiiII', 40, 3, -1, 1, 16, 3, 0, 0, 0, 0, 0) + \
            struct.pack('<III', 0xF800, 0x07E0, 0x001F)
        self.assertEqual(MemoryDCMixin._decode_dib(header + pixels)[2],
                         bytes((255, 0, 0, 0, 255, 0, 0, 0, 255)))


class CachedFontTest(unittest.TestCase):
    class Font:
        def __init__(self):
            self.renders = 0

        def render(self, text, antialias, color, background=None):
            self.renders += 1
            return object()

        def size(self, text):
            return (len(text) * 7, 14)

    def test_cache(self):
        font = self.Font()
        cached = CachedFont(font)
        first = cached.render('File', True, (0, 0, 0))
        self.assertIs(cached.render('File', True, (0, 0, 0)), first)
        self.assertIsNot(cached.render('File', True, (255, 0, 0)), first)  # Another color
        self.assertIsNot(cached.render('File', True, (0, 0, 0), (255, 255, 255)), first)
        self.assertEqual(font.renders, 3)
        self.assertEqual(cached.size('File'), (28, 14))  # The font's own methods

    def test_least_recently_used_go_first(self):
        font = self.Font()
        cached = CachedFont(font)
        cached.MAX_TEXTS = 2
        a = cached.render('a', True, (0, 0, 0))
        cached.render('b', True, (0, 0, 0))
        cached.render('a', True, (0, 0, 0))  # 'a' is used again: 'b' is the oldest
        cached.render('c', True, (0, 0, 0))
        self.assertIs(cached.render('a', True, (0, 0, 0)), a)
        cached.render('b', True, (0, 0, 0))
        self.assertEqual(font.renders, 4)  # a, b, c, then b again


if __name__ == '__main__':
    unittest.main()
