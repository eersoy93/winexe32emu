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

"""Unit tests of the APIs Microsoft Bookshelf 95 needs that work without an
emulated program: GetFileTitle (comdlg32) and multimedia file I/O (mmio)
with the DOS I/O procedure and an installed one.

Run from the repository root:
    python3 -m unittest discover -s tests/python -v
"""

import os
import struct
import sys
import tempfile
import types
import unittest

from unicorn import Uc, UC_ARCH_X86, UC_MODE_32

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
from src.winapi import WinAPIHandler  # noqa: E402


class FakeEmulator:
    """Memory, a heap and guest callbacks that run Python functions"""
    BASE = 0x100000

    def __init__(self):
        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        self.uc.mem_map(self.BASE, 0x100000)
        self.next = self.BASE + 0x80000
        self.blocks = {}
        self.callbacks = {}
        self.current_thread = types.SimpleNamespace(last_error=0)

    def heap_alloc(self, size, alignment=16):
        address = self.next
        self.next += (max(size, 1) + 15) & ~15
        self.blocks[address] = size
        return address

    def heap_free(self, address):
        return self.blocks.pop(address, None) is not None

    def call_callback(self, address, args, **kwargs):
        return self.callbacks[address](*args) & 0xFFFFFFFF


class Bookshelf95Test(unittest.TestCase):
    STR, BUF, INFO = FakeEmulator.BASE, FakeEmulator.BASE + 0x1000, FakeEmulator.BASE + 0x2000

    def setUp(self):
        self.handler = WinAPIHandler.__new__(WinAPIHandler)
        self.handler.emu = FakeEmulator()
        self.handler.mci_devices = {}
        self.handler.wave_outs = {}
        self.handler.current_directory = 'C:\\'
        self.uc = self.handler.emu.uc
        self.tmp = tempfile.TemporaryDirectory()
        self.handler.resolve_drive_path = lambda name: os.path.join(
            self.tmp.name, name.replace('C:\\', '').replace('\\', '/'))

    def tearDown(self):
        self.tmp.cleanup()

    def put(self, address, text):
        self.uc.mem_write(address, text.encode('ascii') + b'\0')
        return address

    def test_get_file_title(self):
        name = self.put(self.STR, 'C:\\MSOffice\\Books95\\BS9532.EXE')
        self.assertEqual(self.handler.GetFileTitleA([name, self.BUF, 260]), 0)
        self.assertEqual(bytes(self.uc.mem_read(self.BUF, 11)), b'BS9532.EXE\0')
        # Too small: the size needed, with the null
        self.assertEqual(self.handler.GetFileTitleA([name, self.BUF, 4]), 11)
        self.assertEqual(self.handler.GetFileTitleA([self.put(self.STR, 'C:\\*.txt'),
                                                     self.BUF, 260]), 0xFFFFFFFF)

    def test_dos_io_procedure(self):
        with open(os.path.join(self.tmp.name, 'SOUND.WAV'), 'wb') as f:
            f.write(b'RIFF0123WAVEdata')
        name = self.put(self.STR, 'C:\\SOUND.WAV')
        hmmio = self.handler.mmioOpenA([name, 0, 0])
        self.assertNotEqual(hmmio, 0)
        self.assertEqual(self.handler.mmioSeek([hmmio, 8, 0]), 8)
        self.assertEqual(self.handler.mmioRead([hmmio, self.BUF, 100]), 8)
        self.assertEqual(bytes(self.uc.mem_read(self.BUF, 8)), b'WAVEdata')
        self.assertEqual(self.handler.mmioRead([hmmio, self.BUF, 100]), 0)
        self.assertEqual(self.handler.mmioClose([hmmio, 0]), 0)
        self.assertEqual(self.handler.mmioClose([hmmio, 0]), 5)  # Already closed
        # A missing file: NULL, the error in wErrorRet of the MMIOINFO given
        self.uc.mem_write(self.INFO, bytes(72))
        self.assertEqual(self.handler.mmioOpenA([self.put(self.STR, 'C:\\NONE.WAV'),
                                                 self.INFO, 0]), 0)
        self.assertEqual(struct.unpack('<I', self.uc.mem_read(self.INFO + 12, 4))[0], 257)
        name = self.put(self.STR, 'C:\\SOUND.WAV')
        self.assertEqual(self.handler.mmioOpenA([name, 0, 0x4000]), 1)  # MMIO_EXIST

    def test_installed_io_procedure(self):
        # Bookshelf reads sounds out of its title files with an "M14 " procedure
        content = b'0123456789'
        calls = []

        def io_proc(info, message, param1, param2):
            calls.append(message)
            offset = struct.unpack('<i', self.uc.mem_read(info + 44, 4))[0]
            if message == 3:  # MMIOM_OPEN: the file name is param1
                self.assertEqual(self.handler.read_string(param1), 'C:\\BOOK.M14+SOUND')
                return 0
            if message == 0:  # MMIOM_READ
                data = content[offset:offset + param2]
                self.uc.mem_write(param1, data)
                self.uc.mem_write(info + 44, struct.pack('<i', offset + len(data)))
                return len(data)
            if message == 2:  # MMIOM_SEEK
                self.uc.mem_write(info + 44, struct.pack('<i', param1))
                return param1
            return 0

        proc = 0x401000
        self.handler.emu.callbacks[proc] = io_proc
        m14 = struct.unpack('<I', b'M14 ')[0]
        self.assertEqual(self.handler.mmioInstallIOProcA([m14, proc, 0x10000]), proc)
        self.assertEqual(self.handler.mmioInstallIOProcA([m14, 0, 0x40000]), proc)
        hmmio = self.handler.mmioOpenA([self.put(self.STR, 'C:\\BOOK.M14+SOUND'), 0, 0])
        self.assertNotEqual(hmmio, 0)
        self.assertEqual(self.handler.mmioSeek([hmmio, 4, 0]), 4)
        self.assertEqual(self.handler.mmioRead([hmmio, self.BUF, 3]), 3)
        self.assertEqual(bytes(self.uc.mem_read(self.BUF, 3)), b'456')
        self.assertEqual(self.handler.mmioClose([hmmio, 0]), 0)
        self.assertEqual(calls, [3, 2, 0, 4])
        self.assertEqual(self.handler.mmioInstallIOProcA([m14, proc, 0x20000]), proc)
        # No procedure for the extension any more
        self.assertEqual(self.handler.mmioOpenA([self.put(self.STR, 'C:\\BOOK.M14+X'), 0, 0]), 0)

    def test_mci_command_strings(self):
        import wave
        with wave.open(os.path.join(self.tmp.name, 'DING.WAV'), 'wb') as wav:
            wav.setnchannels(1)
            wav.setsampwidth(1)
            wav.setframerate(8000)
            wav.writeframes(b'\x80' * 4000)
        self.handler.next_mci_id = 1

        def send(text):
            self.uc.mem_write(self.BUF, bytes(64))
            result = self.handler.mciSendStringA([self.put(self.STR, text), self.BUF, 64, 0])
            return result, bytes(self.uc.mem_read(self.BUF, 64)).split(b'\0')[0].decode()

        self.assertEqual(send('open "C:\\DING.WAV" type waveaudio alias ding'), (0, '1'))
        self.assertEqual(self.handler.mciGetDeviceIDA([self.put(self.STR, 'ding')]), 1)
        self.assertEqual(send('status ding length'), (0, '500'))
        self.assertEqual(send('status ding mode'), (0, 'stopped'))
        self.assertEqual(send('close ding')[0], 0)
        self.assertEqual(send('play ding')[0], 263)  # Closed: MCIERR_INVALID_DEVICE_NAME
        self.assertEqual(send('frobnicate ding')[0], 261)  # MCIERR_UNRECOGNIZED_COMMAND
        # A device type the emulator does not have fails, no crash
        self.assertNotEqual(send('open C:\\INTRO.AVI type avivideo')[0], 0)
        self.assertEqual(self.handler.mciGetErrorStringA([263, self.BUF, 64]), 1)


if __name__ == '__main__':
    unittest.main()
