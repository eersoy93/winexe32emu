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

"""Unit tests of what DOSBox 0.74-3 and its NSIS installer need: the RTF
reader of rich edit controls, MapVirtualKey, the keys of non-US host
keyboards, WM_QUIT, the gamma ramp and the CRT's file descriptor I/O.

Run from the repository root:
    python3 -m unittest discover -s tests/python -v
"""

import os
import struct
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
from src import config  # noqa: E402
from src.logger import DebugLogger  # noqa: E402
from src.winapi import WinAPIHandler  # noqa: E402
from src.winapi.richedit import rtf_to_text, text_to_rtf  # noqa: E402
from tests.python.test_word95_support import FakeEmulator  # noqa: E402

DebugLogger.level = DebugLogger.WARNING + 1


class RtfReaderTest(unittest.TestCase):
    def test_text_without_tables_and_formatting(self):
        rtf = (rb"{\rtf1\ansi\deff0{\fonttbl{\f0\fswiss Arial;}}{\colortbl;\red0\green0\blue0;}"
               b"\r\n" rb"\f0\fs20 GNU \b GENERAL\b0  PUBLIC LICENSE\par" b"\r\n"
               rb"Version 2\tab June 1991\par}")
        self.assertEqual(rtf_to_text(rtf), "GNU GENERAL PUBLIC LICENSE\r\nVersion 2\tJune 1991\r\n")

    def test_escapes_code_page_and_unicode(self):
        rtf = (rb"{\rtf1\ansi\ansicpg1254 \'e7\'f0\'fe \{x\} a\\b"
               rb"{\*\generator Writer;} \uc1\u351?x\u-3874?}")
        self.assertEqual(rtf_to_text(rtf), "\u00e7\u011f\u015f {x} a\\b \u015fx\uf0de")

    def test_round_trip(self):
        text = "Line one\r\n{braces} and \\slash\r\n\u00e7ok g\u00fczel"
        self.assertEqual(rtf_to_text(text_to_rtf(text, 'cp1254')), text)


class MapVirtualKeyTest(unittest.TestCase):
    def setUp(self):
        self.handler = WinAPIHandler.__new__(WinAPIHandler)

    def test_vk_and_scan_codes(self):
        map_key = self.handler.MapVirtualKeyA
        self.assertEqual(map_key([0x41, 0]), 0x1E)     # A
        self.assertEqual(map_key([0x24, 0]), 0x47)     # Home, without the extended flag
        self.assertEqual(map_key([0xBA, 0]), 0x27)     # VK_OEM_1 (;)
        self.assertEqual(map_key([0x1E, 1]), 0x41)
        self.assertEqual(map_key([0x47, 1]), 0x24)     # Home, not keypad 7
        self.assertEqual(map_key([0x36, 1]), 0x10)     # Right Shift: VK_SHIFT
        self.assertEqual(map_key([0x36, 3]), 0xA1)     # ...and VK_RSHIFT with _EX
        self.assertEqual(map_key([0xBA, 2]), ord(';'))
        self.assertEqual(map_key([0x65, 2]), ord('5'))
        self.assertEqual(self.handler.MapVirtualKeyExA([0x57, 1, 0x04090409]), 0x7A)  # F11


@unittest.skipUnless(config.PYGAME_AVAILABLE, "needs pygame")
class HostKeyboardTest(unittest.TestCase):
    def vk(self, key, scancode=0):
        from src.gui.keyboard import KeyboardMixin
        return KeyboardMixin._pygame_key_to_vk(None, types.SimpleNamespace(
            key=key, scancode=scancode))

    def test_turkish_q_keys(self):
        import pygame
        # ş, ğ, ç give no ASCII key code: their place on the keyboard counts
        self.assertEqual(self.vk(0x15F, 51), 0xBA)
        self.assertEqual(self.vk(0x11F, 47), 0xDB)
        self.assertEqual(self.vk(0xE7, 55), 0xBE)
        self.assertEqual(self.vk(0x3C, 100), 0xE2)   # < > of ISO keyboards
        # Letters follow the host layout (the i of Turkish Q is where ' is)
        self.assertEqual(self.vk(pygame.K_i, 52), 0x49)
        self.assertEqual(self.vk(pygame.K_SEMICOLON), 0xBA)  # No scan code


class QuitMessageTest(unittest.TestCase):
    def setUp(self):
        handler = self.handler = WinAPIHandler.__new__(WinAPIHandler)
        handler.emu = FakeEmulator()
        handler.emu.stop_emulation = False
        handler.gui = None
        handler.quit_requested = False
        handler.quit_message_taken = False
        handler.quit_code = 0
        self.msg = handler.emu.BASE

    def test_removed_wm_quit_is_gone(self):
        # SDL 1.2: PeekMessage(PM_NOREMOVE) says a message waits, GetMessage
        # takes it; after WM_QUIT the loop must end
        handler = self.handler
        handler.PostQuitMessage([0])
        self.assertEqual(handler.PeekMessageA([self.msg, 0, 0, 0, 0]), 1)
        self.assertEqual(struct.unpack('<I', handler.emu.uc.mem_read(self.msg + 4, 4))[0],
                         handler.WM_QUIT)
        self.assertEqual(handler.GetMessageA([self.msg, 0, 0, 0]), 0)
        self.assertEqual(handler.PeekMessageA([self.msg, 0, 0, 0, 0]), 0)

    def test_running_gui_ends_the_quit_state(self):
        handler = self.handler
        handler.gui = types.SimpleNamespace(running=True)
        handler.PostQuitMessage([3])
        handler._take_quit_message()
        self.assertFalse(handler.quit_requested)


class GammaRampTest(unittest.TestCase):
    def test_identity_until_set(self):
        handler = WinAPIHandler.__new__(WinAPIHandler)
        handler.emu = FakeEmulator()
        handler.dc_map = {0x40: 0}
        ramp = handler.emu.BASE
        self.assertEqual(handler.GetDeviceGammaRamp([0x40, ramp]), 1)
        values = struct.unpack('<768H', handler.emu.uc.mem_read(ramp, 1536))
        self.assertEqual((values[0], values[1], values[255], values[256]), (0, 257, 65535, 0))
        handler.emu.uc.mem_write(ramp, b'\x01\x00' * 768)
        self.assertEqual(handler.SetDeviceGammaRamp([0x40, ramp]), 1)
        handler.emu.uc.mem_write(ramp, b'\x00' * 1536)
        handler.GetDeviceGammaRamp([0x40, ramp])
        self.assertEqual(struct.unpack('<H', handler.emu.uc.mem_read(ramp, 2))[0], 1)
        self.assertEqual(handler.GetDeviceGammaRamp([0x99, ramp]), 0)


class FileDescriptorTest(unittest.TestCase):
    """fopen, then the descriptor: what the MinGW C++ library's fstream does"""

    def setUp(self):
        # Temporary drives: a fresh checkout (CI) has no drives/ folder
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        patcher = mock.patch.object(config, 'DRIVES_PATH', temp.name)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.folder = os.path.join(temp.name, 'C', 'DOSBox')
        os.makedirs(self.folder)
        self.name = 'C:\\DOSBox\\dosbox.conf'
        handler = self.handler = WinAPIHandler.__new__(WinAPIHandler)
        handler.emu = FakeEmulator()
        handler.current_directory = 'C:\\'
        handler.file_streams = {}
        handler.next_fd = 3
        handler._iob_addr = 0
        handler.std_streams = []
        handler._errno_addr = 0
        handler._crt_static = {}
        handler.handles = {}
        self.uc = handler.emu.uc
        self.strings = handler.emu.heap_alloc(0x200)

    def string(self, text, offset=0):
        address = self.strings + offset
        self.uc.mem_write(address, text.encode('ascii') + b'\x00')
        return address

    def test_descriptor_of_an_fopen_stream(self):
        handler = self.handler
        stream = handler.fopen([self.string(self.name), self.string('w+b', 0x100)])
        self.assertTrue(stream)
        # The FILE struct is real memory: fileno inlined reads _file
        fd = struct.unpack('<I', self.uc.mem_read(stream + 16, 4))[0]
        self.assertEqual(fd, handler._fileno([stream]))
        data = self.string('[sdl]\r\nfullscreen=false\r\n', 0x140)
        self.assertEqual(handler._write([fd, data, 25]), 25)
        self.assertEqual(handler._lseek([fd, 0, 0]), 0)
        buffer = handler.emu.heap_alloc(64)
        self.assertEqual(handler._read([fd, buffer, 64]), 25)
        self.assertEqual(bytes(self.uc.mem_read(buffer, 5)), b'[sdl]')
        self.assertEqual(handler._read([fd, buffer, 64]), 0)  # End of the file
        stat = handler.emu.heap_alloc(36)
        self.assertEqual(handler._fstat([fd, stat]), 0)
        mode, = struct.unpack('<H', self.uc.mem_read(stat + 6, 2))
        size, = struct.unpack('<i', self.uc.mem_read(stat + 20, 4))
        self.assertEqual((mode & 0xF000, size), (0x8000, 25))
        self.assertEqual(handler._chsize([fd, 6]), 0)
        self.assertEqual(handler._stat([self.string(self.name), stat]), 0)
        self.assertEqual(struct.unpack('<i', self.uc.mem_read(stat + 20, 4))[0], 6)
        self.assertEqual(handler.fclose([stream]), 0)
        self.assertEqual(handler._read([fd, buffer, 1]), 0xFFFFFFFF)  # EBADF

    def test_freopen_keeps_the_stream(self):
        handler = self.handler
        first = handler.fopen([self.string(self.name), self.string('wb', 0x100)])
        fd = handler._fileno([first])
        other = self.name.replace('dosbox.conf', 'stdout.txt')
        self.assertEqual(handler.freopen([self.string(other), self.string('w', 0x100), first]),
                         first)
        self.assertEqual(handler._fileno([first]), fd)
        handler.fputs([self.string('ok', 0x140), first])
        handler.fclose([first])
        with open(os.path.join(self.folder, 'stdout.txt'), 'rb') as f:
            self.assertEqual(f.read(), b'ok')


if __name__ == '__main__':
    unittest.main()
