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

"""Unit tests of what the Setup and Autorun of Command & Conquer: Red Alert 2
and the game's menus need: the placeholder files of the emulated system DLLs,
volume labels of the drive folders, DirectDraw, DirectSound, repaints shown
when they are complete, timeGetDevCaps, the IMM queries, timers seen without
removing messages, combo box sizes and lists, controls that are clicked,
updated and destroyed through their subclassing procedures, the launcher's
message and shared memory handle to the game, and sound streams played as
a looping ring.

Run from the repository root:
    python3 -m unittest discover -s tests/python -v
"""

import os
import struct
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest import mock

os.environ.setdefault('SDL_VIDEODRIVER', 'dummy')
os.environ.setdefault('SDL_AUDIODRIVER', 'dummy')

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
import pefile  # noqa: E402
from unicorn import UC_ARCH_X86, UC_MODE_32, Uc  # noqa: E402
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_ESP  # noqa: E402

from src import config, system_files  # noqa: E402
from src.logger import DebugLogger  # noqa: E402
from src.sound import SoundPlayer  # noqa: E402
from src.cpu import CPUEmulator, GuestThread  # noqa: E402
from src.winapi import WinAPIHandler  # noqa: E402
from src.windows import FakeControl  # noqa: E402
from tests.python.test_word95_support import FakeEmulator  # noqa: E402

DebugLogger.level = DebugLogger.WARNING + 1


class SystemFilesTest(unittest.TestCase):
    def test_placeholder_has_a_version_resource(self):
        data = system_files.build_placeholder_dll('comctl32.dll', (5, 82, 6002, 18005))
        pe = pefile.PE(data=data)
        self.assertTrue(pe.is_dll())
        fixed = pe.VS_FIXEDFILEINFO[0]
        self.assertEqual((fixed.FileVersionMS >> 16, fixed.FileVersionMS & 0xFFFF), (5, 82))
        self.assertEqual((fixed.FileVersionLS >> 16, fixed.FileVersionLS & 0xFFFF),
                         (6002, 18005))
        strings = {}
        for info in pe.FileInfo[0]:
            for table in getattr(info, 'StringTable', []):
                strings.update(table.entries)
        self.assertEqual(strings[b'FileVersion'], b'5.82.6002.18005')
        self.assertEqual(strings[b'OriginalFilename'], b'comctl32.dll')

    def test_version_queries_read_the_placeholder(self):
        # Red Alert 2's Setup asks for an update when COMCTL32.DLL is older
        # than 4.72
        self.assertGreaterEqual(system_files.system_file_version('COMCTL32.DLL'), (4, 72))
        handler = WinAPIHandler.__new__(WinAPIHandler)
        handler.emu = FakeEmulator()
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, 'ddraw.dll')
            with open(path, 'wb') as f:
                f.write(system_files.build_placeholder_dll(
                    'ddraw.dll', system_files.SYSTEM_FILE_VERSION))
            with mock.patch.object(WinAPIHandler, '_version_file_host_path',
                                   return_value=path):
                raw = handler._version_resource('ddraw.dll')
        self.assertIsNotNone(raw)
        self.assertEqual(struct.unpack_from('<I', raw, 40)[0], 0xFEEF04BD)

    def test_files_are_created_once(self):
        with tempfile.TemporaryDirectory() as folder:
            def resolve(name):
                return os.path.join(folder, name.rsplit('\\', 1)[-1])
            own = os.path.join(folder, 'user32.dll')
            with open(own, 'wb') as f:
                f.write(b'installed by a setup program')
            with mock.patch.object(system_files, 'resolve_drive_path', resolve):
                system_files.create_system_files({'user32.dll', 'ddraw.dll',
                                                  'ucrtbase.dll'})
            self.assertEqual(sorted(os.listdir(folder)), ['ddraw.dll', 'user32.dll'])
            with open(own, 'rb') as f:
                self.assertEqual(f.read(), b'installed by a setup program')

    def test_placeholders_are_never_loaded(self):
        handler = WinAPIHandler.__new__(WinAPIHandler)
        for name in sorted(WinAPIHandler.EMULATED_DLLS | WinAPIHandler.SYSTEM_DLLS):
            self.assertTrue(handler._is_system_dll(name), name)
        self.assertTrue(handler._is_system_dll('ddraw.dll'))
        self.assertTrue(handler._is_system_dll('dsound.dll'))


class VolumeLabelTest(unittest.TestCase):
    def setUp(self):
        handler = self.handler = WinAPIHandler.__new__(WinAPIHandler)
        handler.emu = FakeEmulator()
        handler.current_directory = 'C:\\'
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        patcher = mock.patch.object(config, 'DRIVES_PATH', self.folder.name)
        patcher.start()
        self.addCleanup(patcher.stop)
        labels = mock.patch.object(WinAPIHandler, 'volume_labels', {})
        labels.start()
        self.addCleanup(labels.stop)

    def label(self, root):
        base = self.handler.emu.BASE
        self.handler.emu.uc.mem_write(base, root.encode() + b'\x00')
        self.assertEqual(self.handler.GetVolumeInformationA(
            [base, base + 0x100, 64, 0, 0, 0, 0, 0]), 1)
        return bytes(self.handler.emu.uc.mem_read(base + 0x100, 64)).split(b'\x00')[0]

    def test_label_file_of_a_cd(self):
        self.assertEqual(self.label('D:\\'), b'')
        with open(os.path.join(self.folder.name, 'D.label'), 'w') as f:
            f.write('RA1\n')
        self.assertEqual(self.label('D:\\'), b'RA1')

    def test_set_volume_label_is_kept(self):
        base = self.handler.emu.BASE
        self.handler.emu.uc.mem_write(base + 0x200, b'C:\\\x00games\x00')
        self.assertEqual(self.handler.SetVolumeLabelA([base + 0x200, base + 0x204]), 1)
        WinAPIHandler.volume_labels.clear()  # The next start of the emulator
        self.assertEqual(self.label('C:\\'), b'GAMES')
        # A CD cannot be renamed
        self.handler.emu.uc.mem_write(base + 0x200, b'D:\\\x00')
        self.assertEqual(self.handler.SetVolumeLabelA([base + 0x200, base + 0x204]), 0)


class ComEmulator(FakeEmulator):
    """FakeEmulator that can also make the stubs of COM vtables"""

    def __init__(self):
        super().__init__()
        self.stubs = 0x70000000
        self.stop_emulation = False

    def _create_api_stub(self, dll, name):
        self.stubs += 4
        return self.stubs


def com_handler():
    handler = WinAPIHandler.__new__(WinAPIHandler)
    handler.emu = ComEmulator()
    handler._com_vtables, handler.com_objects, handler.com_arg_counts = {}, {}, {}
    handler._api_map = {}
    handler.dc_state, handler.dc_map, handler.gdi_objects = {}, {}, {}
    handler.next_handle = 0x1000
    handler.process_exited = False
    handler.gui = None
    return handler


class FakeGui:
    """The parts of the fake desktop DirectDraw uses"""
    WS_POPUP, WS_CAPTION, WS_THICKFRAME = 0x80000000, 0x00C00000, 0x00040000

    def __init__(self):
        self.width, self.height = 640, 480
        self.desktop_width, self.desktop_height = 1024, 768
        self.lock = threading.RLock()
        self.active_window = 0
        self.window = types.SimpleNamespace(x=100, y=50, width=200, height=100,
                                            style=0x00CF0000, maximized=True,
                                            parent=None, owner=None)
        self.windows = {0x10000: self.window}
        self.shapes = []
        self.modes = []

    def client_origin(self, win):
        return win.x, win.y

    def client_size(self, win):
        return win.width, win.height

    def window_owner(self, hwnd):
        return None

    def add_shape(self, hwnd, shape):
        self.shapes.append((hwnd, shape))

    def set_display_mode(self, width, height, owner=None):
        self.width, self.height = width, height
        self.modes.append((width, height))


@unittest.skipUnless(config.PYGAME_AVAILABLE, "needs pygame")
class DirectDrawTest(unittest.TestCase):
    HWND = 0x10000

    def setUp(self):
        handler = self.handler = com_handler()
        handler.gui = FakeGui()
        handler.DD_PRESENT_INTERVAL = 0  # Every change is shown at once
        self.uc = handler.emu.uc
        self.mem = handler.emu.heap_alloc(0x1000)
        self.assertEqual(handler.DirectDrawCreate([0, self.mem, 0]), 0)
        self.dd = self.dword(self.mem)

    def dword(self, address):
        return struct.unpack('<I', self.uc.mem_read(address, 4))[0]

    def dd_call(self, method, *args):
        return self.handler._com_ddraw1(method, False, [self.dd, *args])

    def surface_call(self, surface, method, *args):
        return self.handler._com_ddsurface(method, False, [surface, *args])

    def create_surface(self, caps, width=0, height=0, bpp=0):
        handler = self.handler
        desc = bytearray(108)
        flags = handler.DDSD_CAPS
        if width:
            flags |= handler.DDSD_WIDTH | handler.DDSD_HEIGHT
        struct.pack_into('<IIII', desc, 0, 108, flags, height, width)
        if bpp:
            struct.pack_into('<I', desc, 4, flags | handler.DDSD_PIXELFORMAT)
            struct.pack_into('<4I', desc, 72, 32, handler.DDPF_RGB, 0, bpp)
        struct.pack_into('<I', desc, 104, caps)
        self.uc.mem_write(self.mem + 0x100, bytes(desc))
        self.assertEqual(self.dd_call('CreateSurface', self.mem + 0x100, self.mem, 0), 0)
        return self.dword(self.mem)

    def lock(self, surface, flags=0):
        desc = self.mem + 0x200
        self.uc.mem_write(desc, struct.pack('<I', 108) + bytes(104))
        self.assertEqual(self.surface_call(surface, 'Lock', 0, desc, flags, 0), 0)
        height, width, pitch = struct.unpack('<IIi', self.uc.mem_read(desc + 8, 12))
        return self.dword(desc + 36), width, height, pitch

    def fill(self, surface, color, rect=None):
        handler = self.handler
        fx = self.mem + 0x300
        self.uc.mem_write(fx, struct.pack('<I', 100) + bytes(76) + struct.pack('<I', color) +
                          bytes(16))
        lp_rect = 0
        if rect:
            lp_rect = self.mem + 0x380
            self.uc.mem_write(lp_rect, struct.pack('<4i', *rect))
        self.assertEqual(self.surface_call(surface, 'Blt', lp_rect, 0, 0,
                                           handler.DDBLT_COLORFILL, fx), 0)

    def test_exclusive_mode_and_display_mode(self):
        handler, gui = self.handler, self.handler.gui
        self.assertEqual(self.dd_call('SetDisplayMode', 640, 480, 16),
                         handler.DDERR_NOEXCLUSIVEMODE)
        self.assertEqual(self.dd_call('SetCooperativeLevel', self.HWND,
                                      handler.DDSCL_EXCLUSIVE | handler.DDSCL_FULLSCREEN), 0)
        self.assertEqual(self.dd_call('SetDisplayMode', 800, 600, 16), 0)
        self.assertEqual(gui.modes, [(800, 600)])
        # The program's window covers the screen, without a frame
        win = gui.window
        self.assertEqual((win.x, win.y, win.width, win.height), (0, 0, 800, 600))
        self.assertFalse(win.style & gui.WS_CAPTION)
        self.assertEqual(self.dd_call('SetDisplayMode', 123, 45, 16), handler.DDERR_INVALIDMODE)
        primary = self.create_surface(handler.DDSCAPS_PRIMARYSURFACE)
        _, width, height, pitch = self.lock(primary)
        self.assertEqual((width, height, pitch), (800, 600, 1600))
        # The display mode ends with the last reference to DirectDraw
        self.assertEqual(self.surface_call(primary, 'Unlock', 0), 0)
        self.surface_call(primary, 'Release')
        self.assertEqual(self.dd_call('Release'), 0)
        self.assertEqual(gui.modes[-1], (1024, 768))

    def test_lock_blt_and_color_key(self):
        handler = self.handler
        self.dd_call('SetCooperativeLevel', self.HWND, handler.DDSCL_NORMAL)
        sprite = self.create_surface(handler.DDSCAPS_OFFSCREENPLAIN, 4, 2, 16)
        target = self.create_surface(handler.DDSCAPS_OFFSCREENPLAIN, 8, 4, 16)
        memory, width, height, pitch = self.lock(sprite)
        self.assertEqual((width, height, pitch), (4, 2, 8))
        red, key = 0xF800, 0x07E0
        self.uc.mem_write(memory, struct.pack('<8H', red, key, red, key, key, red, key, red))
        # A locked surface cannot be drawn on
        self.assertEqual(self.surface_call(sprite, 'BltFast', 0, 0, target, 0, 0),
                         handler.DDERR_SURFACEBUSY)
        self.assertEqual(self.surface_call(sprite, 'Unlock', 0), 0)
        self.assertEqual(self.surface_call(sprite, 'Unlock', 0), handler.DDERR_NOTLOCKED)

        self.fill(target, 0x001F)  # Blue
        self.uc.mem_write(self.mem + 0x400, struct.pack('<II', key, key))
        self.assertEqual(self.surface_call(sprite, 'SetColorKey', handler.DDCKEY_SRCBLT,
                                           self.mem + 0x400), 0)
        self.assertEqual(self.surface_call(target, 'BltFast', 2, 1, sprite, 0,
                                           handler.DDBLTFAST_SRCCOLORKEY), 0)
        memory, _, _, pitch = self.lock(target, handler.DDLOCK_READONLY)
        row = struct.unpack('<8H', self.uc.mem_read(memory + pitch, 16))
        self.assertEqual(row, (0x1F, 0x1F, red, 0x1F, red, 0x1F, 0x1F, 0x1F))
        self.surface_call(target, 'Unlock', 0)

        # A stretched copy without the color key
        self.uc.mem_write(self.mem + 0x380, struct.pack('<4i', 0, 0, 8, 4))
        self.assertEqual(self.surface_call(target, 'Blt', self.mem + 0x380, sprite, 0, 0, 0), 0)
        memory, _, _, pitch = self.lock(target, handler.DDLOCK_READONLY)
        row = struct.unpack('<8H', self.uc.mem_read(memory, 16))
        self.assertEqual(row, (red, red, key, key, red, red, key, key))

    def test_primary_surface_is_shown_in_the_window(self):
        handler, gui = self.handler, self.handler.gui
        self.dd_call('SetCooperativeLevel', self.HWND, handler.DDSCL_NORMAL)
        primary = self.create_surface(handler.DDSCAPS_PRIMARYSURFACE)
        # The primary surface is the screen: 32 bpp on the fake desktop
        pixel_format = self.mem + 0x500
        self.assertEqual(self.surface_call(primary, 'GetPixelFormat', pixel_format), 0)
        self.assertEqual(struct.unpack('<8I', self.uc.mem_read(pixel_format, 32))[3:7],
                         (32, 0xFF0000, 0xFF00, 0xFF))
        gui.shapes.clear()
        # The window's client area is at (100, 50) on the screen
        self.fill(primary, 0x00FF8040, (100, 50, 102, 51))
        hwnd, shape = gui.shapes[-1]
        self.assertEqual(hwnd, self.HWND)
        self.assertEqual((shape['pos'], shape['size']), ((0, 0), (200, 100)))
        self.assertEqual(bytes(shape['data'][:9]), b'\xff\x80\x40\xff\x80\x40\x00\x00\x00')
        # A window of a normal program: its child windows stay on top
        self.assertFalse(gui.window.shapes_over_children)

    def test_exclusive_screen_covers_the_child_windows(self):
        handler, gui = self.handler, self.handler.gui
        self.dd_call('SetCooperativeLevel', self.HWND,
                     handler.DDSCL_EXCLUSIVE | handler.DDSCL_FULLSCREEN)
        primary = self.create_surface(handler.DDSCAPS_PRIMARYSURFACE)
        self.fill(primary, 0x00FF8040, (0, 0, 2, 1))
        self.assertTrue(gui.window.shapes_over_children)
        # The windows drawn by GDI are shown again
        self.assertEqual(self.dd_call('FlipToGDISurface'), 0)
        self.assertFalse(gui.window.shapes_over_children)

    def test_flip_and_palette(self):
        handler, gui = self.handler, self.handler.gui
        self.dd_call('SetCooperativeLevel', self.HWND,
                     handler.DDSCL_EXCLUSIVE | handler.DDSCL_FULLSCREEN)
        self.assertEqual(self.dd_call('SetDisplayMode', 640, 480, 8), 0)
        desc = bytearray(108)
        struct.pack_into('<II', desc, 0, 108, handler.DDSD_CAPS | handler.DDSD_BACKBUFFERCOUNT)
        struct.pack_into('<I', desc, 20, 1)
        struct.pack_into('<I', desc, 104, handler.DDSCAPS_PRIMARYSURFACE | handler.DDSCAPS_FLIP |
                         handler.DDSCAPS_COMPLEX)
        self.uc.mem_write(self.mem + 0x100, bytes(desc))
        self.assertEqual(self.dd_call('CreateSurface', self.mem + 0x100, self.mem, 0), 0)
        primary = self.dword(self.mem)
        self.uc.mem_write(self.mem + 0x600, struct.pack('<I', handler.DDSCAPS_BACKBUFFER))
        self.assertEqual(self.surface_call(primary, 'GetAttachedSurface', self.mem + 0x600,
                                           self.mem), 0)
        back = self.dword(self.mem)

        entries = bytearray(1024)
        entries[4 * 7:4 * 7 + 3] = bytes((10, 200, 30))
        self.uc.mem_write(self.mem + 0x800, bytes(entries))
        self.assertEqual(self.dd_call('CreatePalette', handler.DDPCAPS_8BIT, self.mem + 0x800,
                                      self.mem, 0), 0)
        palette = self.dword(self.mem)
        self.assertEqual(self.surface_call(primary, 'SetPalette', palette), 0)

        self.fill(back, 7)
        gui.shapes.clear()
        self.assertEqual(self.surface_call(primary, 'Flip', 0, 0), 0)
        _, shape = gui.shapes[-1]
        self.assertEqual(bytes(shape['data'][:3]), bytes((10, 200, 30)))
        # A palette animation changes the picture on the screen
        self.uc.mem_write(self.mem + 0x800, bytes((1, 2, 3, 0)))
        self.assertEqual(handler._com_ddpalette('SetEntries', False,
                                                [palette, 0, 7, 1, self.mem + 0x800]), 0)
        self.assertEqual(bytes(gui.shapes[-1][1]['data'][:3]), bytes((1, 2, 3)))

    def test_no_directdraw_without_a_display(self):
        handler = self.handler
        handler.gui = None
        self.assertEqual(handler.DirectDrawCreate([0, self.mem, 0]), handler.DDERR_GENERIC)
        self.assertEqual(self.dword(self.mem), 0)


class DirectSoundTest(unittest.TestCase):
    def setUp(self):
        handler = self.handler = com_handler()
        self.uc = handler.emu.uc
        self.mem = handler.emu.heap_alloc(0x1000)

    def dword(self, address):
        return struct.unpack('<I', self.uc.mem_read(address, 4))[0]

    def test_no_driver_without_sound_output(self):
        handler = self.handler
        with mock.patch.object(SoundPlayer, 'available', return_value=False):
            self.assertEqual(handler.DirectSoundCreate([0, self.mem, 0]),
                             handler.DSERR_NODRIVER)
        self.assertEqual(self.dword(self.mem), 0)

    def test_looping_buffer_follows_the_clock(self):
        handler = self.handler
        with mock.patch.object(SoundPlayer, 'available', return_value=True):
            self.assertEqual(handler.DirectSoundCreate([0, self.mem, 0]), 0)
        sound = self.dword(self.mem)
        wave_format = self.mem + 0x100
        self.uc.mem_write(wave_format, struct.pack('<HHIIHHH', 1, 1, 22050, 44100, 2, 16, 0))
        desc = self.mem + 0x200
        self.uc.mem_write(desc, struct.pack('<5I', 20, 0, 32768, 0, wave_format))
        self.assertEqual(handler._com_dsound('CreateSoundBuffer', False,
                                             [sound, desc, self.mem, 0]), 0)
        buffer = self.dword(self.mem)

        def call(method, *args):
            return handler._com_dsbuffer(method, False, [buffer, *args])

        # A lock past the end wraps to the start of the ring
        out = self.mem + 0x300
        self.assertEqual(call('Lock', 24576, 16384, out, out + 4, out + 8, out + 12, 0), 0)
        first, count1, second, count2 = struct.unpack('<4I', self.uc.mem_read(out, 16))
        self.assertEqual((first - second, count1, count2), (24576, 8192, 8192))
        self.assertEqual(call('Unlock', first, count1, second, count2), 0)
        self.assertEqual(call('Lock', 0, 40000, out, out + 4, 0, 0, 0),
                         handler.DSERR_INVALIDPARAM)

        with mock.patch.object(SoundPlayer, 'available', return_value=False), \
                mock.patch('src.winapi.directsound.time.monotonic') as clock:
            clock.return_value = 100.0
            self.assertEqual(call('Play', 0, 0, handler.DSBPLAY_LOOPING), 0)
            self.assertEqual(call('GetStatus', out), 0)
            self.assertEqual(self.dword(out), handler.DSBSTATUS_PLAYING |
                             handler.DSBSTATUS_LOOPING)
            clock.return_value = 100.5   # 22050 bytes later
            self.assertEqual(call('GetCurrentPosition', out, out + 4), 0)
            self.assertEqual(self.dword(out), 22050)
            clock.return_value = 101.0   # Once around the 32768 byte ring
            call('GetCurrentPosition', out, 0)
            self.assertEqual(self.dword(out), 44100 - 32768)
            self.assertEqual(call('Stop'), 0)
            clock.return_value = 105.0
            call('GetCurrentPosition', out, 0)
            self.assertEqual(self.dword(out), 44100 - 32768)
            call('GetStatus', out)
            self.assertEqual(self.dword(out), 0)
        self.assertEqual(call('Release'), 0)
        self.assertEqual(handler._ds_buffers(), [])

    @unittest.skipUnless(config.PYGAME_AVAILABLE, "needs pygame")
    def test_looping_buffer_plays_as_a_ring(self):
        """The mixer loops a copy of the ring that starts at the play cursor;
        what the program writes later goes into it at the same place"""
        mixer = SoundPlayer._mixer()
        if not mixer or mixer[1] != -16 or mixer[0] % 11025:
            self.skipTest("needs a 16-bit mixer at a multiple of 11025 Hz")
        handler = self.handler
        self.assertEqual(handler.DirectSoundCreate([0, self.mem, 0]), 0)
        sound = self.dword(self.mem)
        wave_format = self.mem + 0x100
        self.uc.mem_write(wave_format, struct.pack('<HHIIHHH', 1, 1, 11025, 22050, 2, 16, 0))
        desc = self.mem + 0x200
        self.uc.mem_write(desc, struct.pack('<5I', 20, 0, 8, 0, wave_format))
        handler._com_dsound('CreateSoundBuffer', False, [sound, desc, self.mem, 0])
        buffer = self.dword(self.mem)
        state = handler.com_objects[buffer]
        self.uc.mem_write(state['mem'], struct.pack('<4h', 1, 2, 3, 4))

        def call(method, *args):
            return handler._com_dsbuffer(method, False, [buffer, *args])

        def ring_frames():
            samples = struct.unpack(f'<{len(state["ring_view"]) // 2}h',
                                    bytes(state['ring_view']))
            return list(samples[::mixer[2] * mixer[0] // 11025])

        call('SetCurrentPosition', 4)
        self.assertEqual(call('Play', 0, 0, handler.DSBPLAY_LOOPING), 0)
        self.assertEqual(ring_frames(), [3, 4, 1, 2])
        out = self.mem + 0x300
        call('Lock', 0, 2, out, out + 4, 0, 0, 0)
        self.uc.mem_write(state['mem'], struct.pack('<h', 9))
        call('Unlock', self.dword(out), 2, 0, 0)
        self.assertEqual(ring_frames(), [3, 4, 9, 2])
        call('Stop')
        self.assertIsNone(state['ring'])
        call('Release')


class FileMappingTest(unittest.TestCase):
    """The 1.006 patch of Red Alert 2 writes the new files through mapped
    views and maps the 281 MB ra2.mix"""

    def setUp(self):
        handler = self.handler = com_handler()
        handler.handles, handler.mapping_views = {}, {}
        emu = handler.emu
        emu._align_size = lambda size, unit: (size + unit - 1) & ~(unit - 1)
        emu._free_image_base = lambda preferred, size: 0x02000000
        emu.mapped = {}
        emu.map_foreign = lambda base, size, buf, ptr: emu.mapped.__setitem__(base, buf)
        emu.unmap_shared = lambda base, size: emu.mapped.pop(base)
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.path = os.path.join(self.folder.name, 'new.bin')

    def open_file(self, mode):
        fp = open(self.path, mode)
        self.addCleanup(fp.close)
        self.handler.handles[0x500] = {'type': 'file', 'fp': fp, 'path': self.path}
        return fp

    def test_writable_view_changes_the_file(self):
        handler = self.handler
        self.open_file('w+b')
        mapping = handler.CreateFileMappingA([0x500, 0, handler.PAGE_READWRITE, 0, 0x12345, 0])
        self.assertNotEqual(mapping, 0)
        self.assertEqual(os.path.getsize(self.path), 0x12345)  # The file grew
        view = handler.MapViewOfFile([mapping, 0x2, 0, 0x10000, 0x2345])
        self.assertEqual(view, 0x02010000)
        buf = handler.emu.mapped[0x02000000]
        buf[0x10000:0x10004] = b'RA2!'
        self.assertEqual(handler.FlushViewOfFile([view, 0]), 1)
        self.assertEqual(handler.UnmapViewOfFile([view]), 1)
        self.assertEqual(handler.UnmapViewOfFile([view]), 0)  # Not mapped any more
        buf.flush()
        with open(self.path, 'rb') as f:
            f.seek(0x10000)
            self.assertEqual(f.read(4), b'RA2!')
        # The last handle takes the mapping out of the address space
        handler.handles[mapping]['refs'] = 0
        handler._release_mapping(handler.handles[mapping])
        self.assertEqual(handler.emu.mapped, {})

    def test_read_only_view_leaves_the_file(self):
        handler = self.handler
        with open(self.path, 'wb') as f:
            f.write(b'old file')
        self.open_file('rb')
        mapping = handler.CreateFileMappingA([0x500, 0, 0x2, 0, 0, 0])  # PAGE_READONLY
        view = handler.MapViewOfFile([mapping, 0x4, 0, 0, 0])
        self.assertEqual(view, 0x02000000)
        buf = handler.emu.mapped[view]
        self.assertEqual(buf[:8], b'old file')
        buf[:3] = b'NEW'  # A private copy
        with open(self.path, 'rb') as f:
            self.assertEqual(f.read(), b'old file')
        # A second mapping is not mistaken for the first one
        other = handler.CreateFileMappingA([0x500, 0, 0x2, 0, 0, 0])
        self.assertIsNot(handler.handles[other], handler.handles[mapping])
        self.assertEqual(len(handler.mapping_views), 1)

    def test_size_limits(self):
        handler = self.handler
        self.assertEqual(handler.CreateFileMappingA(
            [0xFFFFFFFF, 0, handler.PAGE_READWRITE, 0, 0x20000000, 0]), 0)  # 512 MB of memory
        self.assertEqual(handler.CreateFileMappingA(
            [0xFFFFFFFF, 0, handler.PAGE_READWRITE, 0, 0, 0]), 0)
        self.assertGreaterEqual(handler.MAX_FILE_MAPPING, 0x20000000)


class PaintSnapshotTest(unittest.TestCase):
    def test_repaint_is_shown_when_it_is_complete(self):
        # Red Alert 2's Autorun repaints itself four times a second: the
        # half-drawn window must not flicker on the screen
        from src.windows import FakeWindow
        win = FakeWindow(0x10000, 'Autorun', 0, 0, 640, 480)
        old = win.drawn_shapes = [{'type': 'rect'}]
        win.begin_paint()
        win.drawn_shapes = []  # BeginPaint clears, then the program draws
        self.assertIs(win.shown_shapes(), old)
        win.drawn_shapes = [{'type': 'image'}]
        win.end_paint()
        self.assertIs(win.shown_shapes(), win.drawn_shapes)
        # A paint that never ends (a dialog opened inside WM_PAINT) is shown
        win.begin_paint()
        win.drawn_shapes = [{'type': 'text'}]
        with mock.patch('src.windows.time.monotonic',
                        return_value=win.paint_snapshot[0] + 1.0):
            self.assertIs(win.shown_shapes(), win.drawn_shapes)


class SmallApisTest(unittest.TestCase):
    def test_time_caps_and_no_ime(self):
        handler = WinAPIHandler.__new__(WinAPIHandler)
        handler.emu = FakeEmulator()
        base = handler.emu.BASE
        self.assertEqual(handler.timeGetDevCaps([base, 8]), 0)
        self.assertEqual(struct.unpack('<II', handler.emu.uc.mem_read(base, 8)), (1, 1000000))
        self.assertEqual(handler.timeGetDevCaps([base, 4]), 97)
        self.assertEqual(handler.ImmGetDefaultIMEWnd([0x10000]), 0)
        self.assertEqual(handler.STDCALL_ARG_COUNTS['ImmGetDefaultIMEWnd'], 1)
        self.assertEqual(handler.STDCALL_ARG_COUNTS['DirectDrawCreate'], 3)

    def test_enum_protocols_lists_tcp_ip_only(self):
        # GAME.EXE looks through the installed transports when it starts
        handler = WinAPIHandler.__new__(WinAPIHandler)
        handler.emu = FakeEmulator()
        handler._last_error = 0
        uc, base = handler.emu.uc, handler.emu.BASE
        length, buffer = base, base + 16
        self.assertEqual(handler.STDCALL_ARG_COUNTS['EnumProtocolsA'], 3)

        # A buffer that is too small: the needed size comes back
        uc.mem_write(length, struct.pack('<I', 8))
        self.assertEqual(handler.EnumProtocolsA([0, buffer, length]), 0xFFFFFFFF)
        self.assertEqual(handler._last_error, 122)  # ERROR_INSUFFICIENT_BUFFER
        needed = struct.unpack('<I', uc.mem_read(length, 4))[0]
        self.assertEqual(needed, 2 * 32 + 2 * len(b'TCP/IP\0'))

        self.assertEqual(handler.EnumProtocolsA([0, buffer, length]), 2)
        rows = [struct.unpack('<IiiiiiII', uc.mem_read(buffer + 32 * i, 32)) for i in (0, 1)]
        self.assertEqual([(row[1], row[4], row[5]) for row in rows], [(2, 1, 6), (2, 2, 17)])
        self.assertTrue(rows[1][0] & 1)  # XP_CONNECTIONLESS
        self.assertEqual(bytes(uc.mem_read(rows[0][7], 7)), b'TCP/IP\0')
        self.assertEqual(bytes(uc.mem_read(rows[1][7], 7)), b'UDP/IP\0')

        # Only the protocols asked for; IPX (NSPROTO_IPX 1000) is not installed
        uc.mem_write(base + 0x400, struct.pack('<3i', 1000, 17, 0))
        uc.mem_write(length, struct.pack('<I', 256))
        self.assertEqual(handler.EnumProtocolsA([base + 0x400, buffer, length]), 1)
        self.assertEqual(struct.unpack('<i', uc.mem_read(buffer + 20, 4))[0], 17)
        uc.mem_write(base + 0x400, struct.pack('<2i', 1000, 0))
        self.assertEqual(handler.EnumProtocolsA([base + 0x400, buffer, length]), 0)

        uc.mem_write(length, struct.pack('<I', 256))
        self.assertEqual(handler.EnumProtocolsW([0, buffer, length]), 2)
        name = struct.unpack('<I', uc.mem_read(buffer + 28, 4))[0]
        self.assertEqual(bytes(uc.mem_read(name, 14)).decode('utf-16-le'), 'TCP/IP\0')

    def test_write_to_a_read_only_handle_is_denied(self):
        handler = WinAPIHandler.__new__(WinAPIHandler)
        handler.emu = FakeEmulator()
        handler._last_error = 0
        handler.dib_sections = {}
        uc, base = handler.emu.uc, handler.emu.BASE
        with tempfile.NamedTemporaryFile() as file, open(file.name, 'rb') as fp:
            handler.handles = {0x1000: {'type': 'file', 'name': file.name, 'fp': fp}}
            uc.mem_write(base, struct.pack('<I', 99))
            with mock.patch.object(handler, '_sync_dib_sections_at', create=True):
                self.assertEqual(handler.WriteFile([0x1000, base + 16, 4, base, 0]), 0)
            self.assertEqual(handler._last_error, 5)  # ERROR_ACCESS_DENIED
            self.assertEqual(struct.unpack('<I', uc.mem_read(base, 4))[0], 0)

    def test_trackbar_range_and_position(self):
        # The difficulty slider of the campaign menu: the game divides by
        # the range of a trackbar it never set
        handler = WinAPIHandler.__new__(WinAPIHandler)
        handler.emu = FakeEmulator()
        handler.gui = types.SimpleNamespace(client_size=lambda win: (210, 21))
        win = types.SimpleNamespace(nstate={'font': 0}, style=0x50000018)

        def send(msg, wparam=0, lparam=0):
            return handler._trackbar_message(win, msg, wparam, lparam)

        self.assertEqual((send(0x401), send(0x402), send(0x400)), (0, 100, 0))
        self.assertEqual((send(0x418), send(0x416)), (1, 20))  # Line and page size
        send(0x406, 1, (9 << 16) | 2)  # TBM_SETRANGE 2..9
        self.assertEqual((send(0x401), send(0x402), send(0x400)), (2, 9, 2))
        send(0x405, 1, 50)  # TBM_SETPOS beyond the range
        self.assertEqual(send(0x400), 9)
        send(0x408, 1, 4)  # TBM_SETRANGEMAX below the position
        self.assertEqual(send(0x400), 4)
        self.assertEqual(send(0x415, 0, 3), 0)  # TBM_SETPAGESIZE gives the old one
        self.assertEqual(send(0x416), 3)
        base = handler.emu.BASE
        send(0x41A, 0, base)  # TBM_GETCHANNELRECT
        send(0x419, 0, base + 16)  # TBM_GETTHUMBRECT
        channel = struct.unpack('<4i', handler.emu.uc.mem_read(base, 16))
        slider = struct.unpack('<4i', handler.emu.uc.mem_read(base + 16, 16))
        self.assertTrue(0 < channel[0] < channel[2] <= 210)
        self.assertTrue(channel[0] <= slider[0] < slider[2] <= channel[2])
        self.assertIsNone(send(0x000F))  # WM_PAINT: not a trackbar message


class ClassObjectTest(unittest.TestCase):
    def test_registration_holds_a_reference(self):
        # The game's class factories delete themselves at the last Release:
        # without the reference of CoRegisterClassObject the first
        # CoCreateInstance would destroy them
        handler = WinAPIHandler.__new__(WinAPIHandler)
        handler.emu = FakeEmulator()
        handler.process_exited = False
        handler.next_handle = 0x1000
        calls = []
        handler.emu.call_callback = lambda address, args: calls.append((address, args)) or 0
        uc, base = handler.emu.uc, handler.emu.BASE
        factory, vtable, clsid, cookie = base, base + 0x40, base + 0x80, base + 0xC0
        uc.mem_write(factory, struct.pack('<I', vtable))
        uc.mem_write(vtable, struct.pack('<3I', 0x401000, 0x401010, 0x401020))
        self.assertEqual(handler.CoRegisterClassObject([clsid, factory, 1, 1, cookie]), 0)
        self.assertEqual(calls, [(0x401010, [factory])])  # AddRef
        token = struct.unpack('<I', uc.mem_read(cookie, 4))[0]
        self.assertEqual(handler.CoRevokeClassObject([token]), 0)
        self.assertEqual(calls[-1], (0x401020, [factory]))  # Release
        self.assertEqual(handler.CoRevokeClassObject([token]), 0)
        self.assertEqual(len(calls), 2)


class ProgramPaintedControlTest(unittest.TestCase):
    """The game subclasses every control of its menus and paints them
    itself on the DirectDraw surface"""

    def setUp(self):
        self.handler = handler = WinAPIHandler.__new__(WinAPIHandler)
        handler.emu = FakeEmulator()
        self.calls = calls = []
        handler.emu.call_wndproc = lambda *args: calls.append(args) or 0
        handler.paint_pending, handler.update_rects = set(), {}
        handler.window_longs = {0x20: {-4: 0x401000}}
        handler._native_wndproc_addr = 0x70000004
        self.control = types.SimpleNamespace(
            hwnd=0x20, class_name='STATIC', style=0x50000000, parent_hwnd=0)
        handler.gui = types.SimpleNamespace(controls={0x20: self.control, 0x24: None})

    def test_subclass_gets_wm_paint(self):
        handler = self.handler
        self.assertEqual(handler._send_control_paint(0x20), 0)
        self.assertEqual(self.calls, [(0x401000, 0x20, handler.WM_PAINT, 0, 0)])
        self.assertTrue(self.control.program_painted)
        self.assertNotIn(0x20, handler.paint_pending)

    def test_own_procedure_draws_the_control_again(self):
        handler = self.handler
        handler._send_control_paint(0x20)
        with mock.patch.object(handler, '_update_ctl_colors') as colors:
            # The subclassing procedure passed WM_PAINT on with CallWindowProc
            self.assertEqual(handler._control_default(0x20, handler.WM_PAINT, 0, 0), 0)
        colors.assert_called_once_with(self.control)
        self.assertFalse(self.control.program_painted)

    def test_plain_control_is_not_asked(self):
        handler = self.handler
        handler.window_longs = {}
        with mock.patch.object(handler, '_paint_control', return_value=0) as paint:
            handler._send_control_paint(0x20)
        paint.assert_called_once_with(0x20)
        self.assertEqual(self.calls, [])


class TimerPeekTest(unittest.TestCase):
    """The game's menu loop peeks with PM_NOREMOVE and fetches a message only
    when there is one: a due timer must be seen there too"""

    def setUp(self):
        self.handler = handler = WinAPIHandler.__new__(WinAPIHandler)
        handler.emu = FakeEmulator()
        handler.emu.current_thread.tid = 1
        handler.timers = {(0x20, 1): {'elapse': 0.03, 'callback': 0, 'next_fire': 0.0,
                                      'thread': 1}}

    def test_peek_does_not_take_the_timer(self):
        handler = self.handler
        self.assertEqual(handler._pop_due_timer(remove=False), (0x20, 1, 0))
        self.assertEqual(handler.timers[(0x20, 1)]['next_fire'], 0.0)
        self.assertEqual(handler._pop_due_timer(), (0x20, 1, 0))
        self.assertGreater(handler.timers[(0x20, 1)]['next_fire'], 0.0)
        self.assertIsNone(handler._pop_due_timer(remove=False))


class ComboBoxSizeTest(unittest.TestCase):
    """A drop-down combo box's window is its selection field; the height it
    was created with includes the list"""

    def test_drop_down_list_is_its_field(self):
        combo = FakeControl(0x20, 'COMBOBOX', '', 10, 10, 120, 200, style=0x50000203)
        self.assertEqual(combo.window_height, FakeControl.COMBO_FIELD_HEIGHT)
        simple = FakeControl(0x24, 'COMBOBOX', '', 10, 10, 120, 200, style=0x50000001)
        self.assertEqual(simple.window_height, 200)
        listbox = FakeControl(0x28, 'LISTBOX', '', 10, 10, 120, 200)
        self.assertEqual(listbox.window_height, 200)

    def test_selection_field_height(self):
        handler = WinAPIHandler.__new__(WinAPIHandler)
        handler.gui = None
        combo = FakeControl(0x20, 'COMBOBOX', '', 10, 10, 120, 200, style=0x50000213)
        # CB_SETITEMHEIGHT/CB_GETITEMHEIGHT of the field (-1): its text height
        self.assertEqual(handler._control_message(combo, 0x0153, 0xFFFFFFFF, 19), 0)
        self.assertEqual(combo.window_height, 25)
        self.assertEqual(handler._control_message(combo, 0x0154, 0xFFFFFFFF, 0), 19)
        self.assertEqual(handler._control_message(combo, 0x0153, 0xFFFFFFFF, 0),
                         handler.CB_ERR)
        # ... and of the list's items
        self.assertEqual(handler._control_message(combo, 0x0153, 0, 23), 0)
        self.assertEqual(combo.item_height, 23)


class SubclassedControlTest(unittest.TestCase):
    """The game subclasses its controls: a click on a combo box, UpdateWindow
    and DestroyWindow go through its procedure"""

    PROC = 0x401000

    def setUp(self):
        self.handler = handler = WinAPIHandler.__new__(WinAPIHandler)
        handler.emu = FakeEmulator()
        self.calls = calls = []
        handler.emu.call_wndproc = lambda *args: calls.append(args[:3]) or 0
        handler.paint_pending, handler.update_rects = set(), {}
        handler.painted_windows, handler.updating_windows = set(), set()
        handler.dirty_controls = {}
        handler.message_queue, handler.message_lock = [], threading.Lock()
        handler.window_longs = {0x20: {-4: self.PROC}}
        handler._native_wndproc_addr = 0x70000004
        self.combo = FakeControl(0x20, 'COMBOBOX', '', 10, 10, 120, 25, style=0x50000213)
        self.combo.parent_hwnd = 0x10
        dialog = types.SimpleNamespace(visible=True, minimized=False, parent=None,
                                       owner=handler, controls=[self.combo])
        handler.gui = types.SimpleNamespace(controls={0x20: self.combo},
                                            windows={0x10: dialog}, open_combo=None,
                                            focused_control=None,
                                            client_size=lambda win: (640, 480))

        def destroy_control(hwnd):
            handler.gui.controls.pop(hwnd, None)
        handler.gui.destroy_control = destroy_control

    def test_click_passed_on_opens_the_list(self):
        handler = self.handler
        handler._control_default(0x20, handler.WM_LBUTTONDOWN, 1, 0)
        self.assertEqual(handler.gui.open_combo, 0x20)
        handler._control_default(0x20, handler.WM_LBUTTONDOWN, 1, 0)
        self.assertIsNone(handler.gui.open_combo)

    def test_update_window_paints_at_once(self):
        handler = self.handler
        self.assertEqual(handler.UpdateWindow([0x20]), 1)
        self.assertEqual(self.calls, [])  # Nothing to paint
        handler.dirty_controls[0x20] = True
        self.assertEqual(handler.UpdateWindow([0x20]), 1)
        self.assertEqual(self.calls, [(self.PROC, 0x20, handler.WM_PAINT)])
        self.assertNotIn(0x20, handler.dirty_controls)

    def test_check_box_click_goes_through_the_procedure(self):
        """The game keeps the state of its check boxes in its procedure: the
        click passed on checks the box with BM_SETCHECK sent to it"""
        handler = self.handler
        box = FakeControl(0x24, 'CHECKBOX', 'Short Game', 10, 40, 150, 17, style=0x50000003)
        box.parent_hwnd, box.control_id = 0x10, 0x54e
        handler.gui.controls[0x24] = box
        sent = []
        handler.SendMessageA = lambda args: sent.append(tuple(args)) or 0
        inside, outside = (8 << 16) | 5, (8 << 16) | 200
        handler._control_default(0x24, handler.WM_LBUTTONDOWN, 1, inside)
        handler._control_default(0x24, handler.WM_LBUTTONUP, 0, outside)
        self.assertEqual(sent, [])  # Released elsewhere: no click
        handler._control_default(0x24, handler.WM_LBUTTONDOWN, 1, inside)
        handler._control_default(0x24, handler.WM_LBUTTONUP, 0, inside)
        self.assertEqual(sent, [(0x24, handler.BM_SETCHECK, 1, 0),
                                (0x10, handler.WM_COMMAND,
                                 (handler.BN_CLICKED << 16) | 0x54e, 0x24)])

    def test_destroy_window_tells_the_procedure(self):
        handler = self.handler
        handler.cbt_destroy_window = lambda hwnd: False
        handler.painted_windows.add(0x10)
        self.assertEqual(handler.DestroyWindow([0x20]), 1)
        self.assertEqual(self.calls, [(self.PROC, 0x20, handler.WM_DESTROY),
                                      (self.PROC, 0x20, handler.WM_NCDESTROY)])
        self.assertNotIn(0x20, handler.gui.controls)
        # What was under it is painted again
        self.assertEqual(handler.update_rects[0x10], (10, 10, 130, 34))


class LauncherHandshakeTest(unittest.TestCase):
    """The Ra2.exe launcher starts GAME.EXE with an inheritable handle of a
    shared memory block and posts its value to the game's main thread"""

    def process(self, tid):
        handler = com_handler()
        handler.handles, handler.inheritable_handles, handler.std_handles = {}, set(), {}
        handler.environment, handler.has_console = {}, False
        handler.emu.threads = {tid: object()}
        handler.posted = []
        handler.post_window_message = lambda *args, **kw: handler.posted.append((args, kw))
        return handler

    def test_thread_message_to_another_process(self):
        launcher, game = self.process(0x404), self.process(0x410)
        launcher.gui = game.gui = types.SimpleNamespace(processes=[launcher, game])
        self.assertEqual(launcher.PostThreadMessageA([0x410, 0xBEEF, 0, 0x1018]), 1)
        self.assertEqual(game.posted, [((0, 0xBEEF, 0, 0x1018), {'thread': 0x410})])
        self.assertEqual(launcher.PostThreadMessageA([0x999, 0xBEEF, 0, 0]), 0)
        self.assertEqual(launcher._last_error, 1444)  # ERROR_INVALID_THREAD_ID

    def test_inherited_handles_keep_their_values(self):
        launcher, game = self.process(0x404), self.process(0x410)
        attributes = launcher.emu.heap_alloc(12)
        launcher.emu.uc.mem_write(attributes, struct.pack('<3I', 12, 0, 1))
        mapping = {'type': 'mapping', 'size': 50, 'refs': 1}
        launcher.handles[0x1018] = mapping
        launcher.handles[0x101c] = {'type': 'event', 'refs': 1}  # Not inheritable
        self.assertEqual(launcher._mark_inheritable(attributes, 0x1018), 0x1018)
        self.assertEqual(launcher._mark_inheritable(0, 0x101c), 0x101c)
        # Without bInheritHandles the child gets none of them
        launcher._child_inheritance(0, 0, 0, 0, False)(types.SimpleNamespace(api_handler=game))
        self.assertEqual(game.handles, {})
        launcher._child_inheritance(1, 0, 0, 0, False)(types.SimpleNamespace(api_handler=game))
        self.assertEqual(game.handles, {0x1018: mapping})
        self.assertEqual(mapping['refs'], 2)
        self.assertIn(0x1018, game.inheritable_handles)
        # The child's own handles do not take the inherited value
        game.next_handle = 0x1018
        self.assertEqual(game.get_next_handle(), 0x101c)


class NativeStubTest(unittest.TestCase):
    """The Interlocked APIs and IsLost run as guest code"""
    CODE, DATA, STACK, RETURN = 0x100000, 0x200000, 0x300000, 0x100800

    def call(self, key, *args):
        uc = Uc(UC_ARCH_X86, UC_MODE_32)
        for base in (self.CODE, self.DATA, self.STACK):
            uc.mem_map(base, 0x1000)
        uc.mem_write(self.CODE, CPUEmulator.NATIVE_STUBS[key])
        uc.mem_write(self.RETURN, b'\x90')
        uc.mem_write(self.DATA, struct.pack('<I', 10))
        esp = self.STACK + 0x800
        uc.mem_write(esp, struct.pack(f'<{1 + len(args)}I', self.RETURN, *args))
        uc.reg_write(UC_X86_REG_ESP, esp)
        uc.emu_start(self.CODE, self.RETURN)
        # stdcall: the arguments are popped
        self.assertEqual(uc.reg_read(UC_X86_REG_ESP), esp + 4 + 4 * len(args))
        value = struct.unpack('<I', uc.mem_read(self.DATA, 4))[0]
        return uc.reg_read(UC_X86_REG_EAX), value

    def test_interlocked(self):
        k = 'kernel32.dll'
        self.assertEqual(self.call((k, 'InterlockedIncrement'), self.DATA), (11, 11))
        self.assertEqual(self.call((k, 'InterlockedDecrement'), self.DATA), (9, 9))
        self.assertEqual(self.call((k, 'InterlockedExchange'), self.DATA, 5), (10, 5))
        self.assertEqual(self.call((k, 'InterlockedExchangeAdd'), self.DATA, 5), (10, 15))
        self.assertEqual(self.call((k, 'InterlockedCompareExchange'), self.DATA, 7, 10),
                         (10, 7))
        self.assertEqual(self.call((k, 'InterlockedCompareExchange'), self.DATA, 7, 3),
                         (10, 10))

    def test_surface_is_never_lost(self):
        self.assertEqual(self.call(('ole32.dll', 'IDirectDrawSurface7::IsLost'), 0x1234)[0], 0)


class SchedulerTurnTest(unittest.TestCase):
    """A thread gives its turn away only to a thread that wants to run"""

    def setUp(self):
        self.emu = emu = CPUEmulator.__new__(CPUEmulator)
        emu._tls = threading.local()
        emu.main_thread = GuestThread(4)
        self.other = GuestThread(8)
        emu.threads = {4: emu.main_thread, 8: self.other}
        emu._threads_woken = False

    def test_sleeping_thread_does_not_get_a_turn(self):
        self.other.wake_at = time.monotonic() + 10
        self.assertFalse(self.emu._others_runnable())
        self.other.wake_at = time.monotonic() - 1  # Its sleep is over
        self.assertTrue(self.emu._others_runnable())
        self.other.wake_at = None  # Waits for the lock
        self.assertTrue(self.emu._others_runnable())

    def test_woken_threads_get_a_turn(self):
        self.other.wake_at = time.monotonic() + 10
        self.emu._threads_woken = True
        self.assertTrue(self.emu._others_runnable())
        self.assertFalse(self.emu._others_runnable())

    def test_exited_thread_is_skipped(self):
        self.other.exited = True
        self.assertFalse(self.emu._others_runnable())


if __name__ == '__main__':
    unittest.main()
