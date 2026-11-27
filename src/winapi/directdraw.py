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

"""WinAPIHandler mixin: DirectDraw (ddraw.dll) in software.

The pixels of a DirectDraw surface live in a pygame surface of the same
pixel format, so copies, color keys, fills and stretching run in SDL. Lock
hands the program a copy of them in guest memory and Unlock takes it back.
The primary surface is the fake desktop's screen: what is drawn on it is
shown in the client area of the program's window.

Interfaces, structures and constants follow the public DirectX headers
(ddraw.h of MinGW-w64) and the DirectDraw documentation.
"""

import struct
import threading
import time

from unicorn import UcError

from ..config import PYGAME_AVAILABLE
from ..logger import log
from .com import ComMixin
from .core import CoreMixin

if PYGAME_AVAILABLE:
    import pygame


def _dd_error(code):
    """MAKE_DDHRESULT(code)"""
    return 0x88760000 | code


# IDirectDraw7's vtable; IDirectDraw2 and IDirectDraw4 are prefixes of it
_DDRAW_METHODS = [
    ('QueryInterface', 3), ('AddRef', 1), ('Release', 1), ('Compact', 1),
    ('CreateClipper', 4), ('CreatePalette', 5), ('CreateSurface', 4),
    ('DuplicateSurface', 3), ('EnumDisplayModes', 5), ('EnumSurfaces', 5),
    ('FlipToGDISurface', 1), ('GetCaps', 3), ('GetDisplayMode', 2), ('GetFourCCCodes', 3),
    ('GetGDISurface', 2), ('GetMonitorFrequency', 2), ('GetScanLine', 2),
    ('GetVerticalBlankStatus', 2), ('Initialize', 2), ('RestoreDisplayMode', 1),
    ('SetCooperativeLevel', 3), ('SetDisplayMode', 6), ('WaitForVerticalBlank', 3),
    ('GetAvailableVidMem', 4), ('GetSurfaceFromDC', 3), ('RestoreAllSurfaces', 1),
    ('TestCooperativeLevel', 1), ('GetDeviceIdentifier', 3), ('StartModeTest', 4),
    ('EvaluateMode', 3)]
# IDirectDraw: SetDisplayMode has no refresh rate and flags
_DDRAW1_METHODS = [(name, 4 if name == 'SetDisplayMode' else argc)
                   for name, argc in _DDRAW_METHODS[:23]]

# IDirectDrawSurface7's vtable; the older surface interfaces are prefixes of it
_SURFACE_METHODS = [
    ('QueryInterface', 3), ('AddRef', 1), ('Release', 1), ('AddAttachedSurface', 2),
    ('AddOverlayDirtyRect', 2), ('Blt', 6), ('BltBatch', 4), ('BltFast', 6),
    ('DeleteAttachedSurface', 3), ('EnumAttachedSurfaces', 3), ('EnumOverlayZOrders', 4),
    ('Flip', 3), ('GetAttachedSurface', 3), ('GetBltStatus', 2), ('GetCaps', 2),
    ('GetClipper', 2), ('GetColorKey', 3), ('GetDC', 2), ('GetFlipStatus', 2),
    ('GetOverlayPosition', 3), ('GetPalette', 2), ('GetPixelFormat', 2),
    ('GetSurfaceDesc', 2), ('Initialize', 3), ('IsLost', 1), ('Lock', 5), ('ReleaseDC', 2),
    ('Restore', 1), ('SetClipper', 2), ('SetColorKey', 3), ('SetOverlayPosition', 3),
    ('SetPalette', 2), ('Unlock', 2), ('UpdateOverlay', 6), ('UpdateOverlayDisplay', 2),
    ('UpdateOverlayZOrder', 3), ('GetDDInterface', 2), ('PageLock', 2), ('PageUnlock', 2),
    ('SetSurfaceDesc', 3), ('SetPrivateData', 5), ('GetPrivateData', 4),
    ('FreePrivateData', 2), ('GetUniquenessValue', 2), ('ChangeUniquenessValue', 1),
    ('SetPriority', 2), ('GetPriority', 2), ('SetLOD', 2), ('GetLOD', 2)]

ComMixin.COM_INTERFACES.update({
    'ddraw1': _DDRAW1_METHODS,
    'ddraw': _DDRAW_METHODS,
    'ddsurface': _SURFACE_METHODS,
    'ddpalette': [
        ('QueryInterface', 3), ('AddRef', 1), ('Release', 1), ('GetCaps', 2),
        ('GetEntries', 5), ('Initialize', 4), ('SetEntries', 5)],
    'ddclipper': [
        ('QueryInterface', 3), ('AddRef', 1), ('Release', 1), ('GetClipList', 4),
        ('GetHWnd', 2), ('Initialize', 3), ('IsClipListChanged', 2), ('SetClipList', 3),
        ('SetHWnd', 3)],
})

CoreMixin.STDCALL_ARG_COUNTS.update({
    'DirectDrawCreate': 3, 'DirectDrawCreateEx': 4, 'DirectDrawCreateClipper': 3,
    'DirectDrawEnumerateA': 2, 'DirectDrawEnumerateW': 2,
    'DirectDrawEnumerateExA': 3, 'DirectDrawEnumerateExW': 3,
})


class DirectDrawMixin:
    """DirectDraw in software (ddraw.dll)"""

    IID_IDIRECTDRAW = '6c14db80-a733-11ce-a521-0020af0be560'
    IID_IDIRECTDRAW2 = 'b3a6f3e0-2b43-11cf-a2de-00aa00b93356'
    IID_IDIRECTDRAW4 = '9c59509a-39bd-11d1-8c4a-00c04fd930c5'
    IID_IDIRECTDRAW7 = '15e65ec0-3b9c-11d2-b92f-00609797ea5b'
    IID_IDIRECTDRAWSURFACES = (
        '6c14db81-a733-11ce-a521-0020af0be560',   # IDirectDrawSurface
        '57805885-6eec-11cf-9441-a82303c10e27',   # IDirectDrawSurface2
        'da044e00-69b2-11d0-a1d5-00aa00b8dfbb',   # IDirectDrawSurface3
        '0b2b8630-ad35-11d0-8ea6-00609797ea5b',   # IDirectDrawSurface4
        '06675a80-3b9b-11d2-b92f-00609797ea5b')   # IDirectDrawSurface7
    IID_IDIRECTDRAWPALETTE = '6c14db84-a733-11ce-a521-0020af0be560'
    IID_IDIRECTDRAWCLIPPER = '6c14db85-a733-11ce-a521-0020af0be560'

    DD_OK = 0
    DDERR_GENERIC = 0x80004005
    DDERR_UNSUPPORTED = 0x80004001
    DDERR_INVALIDPARAMS = 0x80070057
    DDERR_INVALIDMODE = _dd_error(120)
    DDERR_INVALIDPIXELFORMAT = _dd_error(145)
    DDERR_INVALIDRECT = _dd_error(150)
    DDERR_NOCOLORKEY = _dd_error(215)
    DDERR_NOEXCLUSIVEMODE = _dd_error(225)
    DDERR_NOTFOUND = _dd_error(255)
    DDERR_SURFACEBUSY = _dd_error(430)
    DDERR_NOCLIPPERATTACHED = _dd_error(568)
    DDERR_NOPALETTEATTACHED = _dd_error(572)
    DDERR_NOTLOCKED = _dd_error(584)
    DDERR_NODC = _dd_error(586)
    DDERR_NOTFLIPPABLE = _dd_error(582)
    DDERR_DCALREADYCREATED = _dd_error(620)

    DDSCL_FULLSCREEN, DDSCL_NORMAL, DDSCL_EXCLUSIVE = 0x1, 0x8, 0x10

    DDSD_CAPS, DDSD_HEIGHT, DDSD_WIDTH, DDSD_PITCH = 0x1, 0x2, 0x4, 0x8
    DDSD_BACKBUFFERCOUNT, DDSD_LPSURFACE, DDSD_PIXELFORMAT = 0x20, 0x800, 0x1000
    DDSD_CKSRCBLT, DDSD_REFRESHRATE = 0x10000, 0x40000

    DDSCAPS_BACKBUFFER, DDSCAPS_COMPLEX, DDSCAPS_FLIP = 0x4, 0x8, 0x10
    DDSCAPS_FRONTBUFFER, DDSCAPS_OFFSCREENPLAIN = 0x20, 0x40
    DDSCAPS_PALETTE, DDSCAPS_PRIMARYSURFACE = 0x100, 0x200
    DDSCAPS_SYSTEMMEMORY, DDSCAPS_VISIBLE = 0x800, 0x8000

    DDPF_PALETTEINDEXED8, DDPF_RGB = 0x20, 0x40

    DDBLT_COLORFILL, DDBLT_DDFX, DDBLT_KEYSRC = 0x400, 0x800, 0x8000
    DDBLT_KEYSRCOVERRIDE, DDBLT_ROP = 0x10000, 0x20000
    DDBLTFAST_SRCCOLORKEY = 0x1
    DDCKEY_SRCBLT = 0x8
    DDLOCK_READONLY = 0x10
    DDPCAPS_8BIT, DDPCAPS_ALLOW256 = 0x4, 0x40

    DDSURFACEDESC_SIZE, DDSURFACEDESC2_SIZE = 108, 124

    # Bits per pixel -> (red, green, blue) masks of the display's pixel format
    DD_MASKS = {8: (0, 0, 0), 16: (0xF800, 0x07E0, 0x001F),
                24: (0xFF0000, 0x00FF00, 0x0000FF), 32: (0xFF0000, 0x00FF00, 0x0000FF)}
    # Shortest time between two pictures of the primary surface on the screen
    DD_PRESENT_INTERVAL = 0.015

    # ---------- Creating DirectDraw ----------

    def _dd_available(self):
        return PYGAME_AVAILABLE and self.gui is not None

    def _dd_create(self, out, riid=None):
        if not out:
            return self.DDERR_INVALIDPARAMS
        if not self._dd_available():
            # A PC without a display driver for DirectDraw
            self._mem_write(out, struct.pack('<I', 0))
            return self.DDERR_GENERIC
        state = {'kind': 'ddraw', 'hwnd': 0, 'exclusive': False, 'bpp': 32,
                 'mode_set': False, 'surfaces': [], 'primary': None}
        pointers = self._com_new_object(
            [((self.IID_IUNKNOWN, self.IID_IDIRECTDRAW),
              self._com_vtable('IDirectDraw', 'ddraw1')),
             ((self.IID_IDIRECTDRAW2, self.IID_IDIRECTDRAW4, self.IID_IDIRECTDRAW7),
              self._com_vtable('IDirectDraw7', 'ddraw'))], state)
        pointer = pointers.get(riid or self.IID_IDIRECTDRAW)
        self._mem_write(out, struct.pack('<I', pointer or 0))
        return self.DD_OK if pointer else self.E_NOINTERFACE

    def DirectDrawCreate(self, args):
        """DirectDrawCreate(lpGUID, lplpDD, pUnkOuter) - the display's IDirectDraw"""
        result = self._dd_create(args[1])
        log.debug(f"DirectDrawCreate() -> 0x{result:08x}")
        return result

    def DirectDrawCreateEx(self, args):
        """DirectDrawCreateEx(lpGUID, lplpDD, iid, pUnkOuter) - IDirectDraw7"""
        return self._dd_create(args[1], self._read_guid(args[2]))

    def _dd_enumerate(self, args, wide, extended):
        """One call of the enumeration callback: (GUID, description, name,
        context[, monitor]); a NULL GUID and monitor name the primary display"""
        if not args[0]:
            return self.DDERR_INVALIDPARAMS
        if self._dd_available():
            text = self.emu.heap_alloc(128)
            self._write_text(text, 'display', wide)
            self._write_text(text + 32, 'Primary Display Driver', wide)
            self.emu.call_callback(args[0], [0, text + 32, text, args[1]] + [0] * extended)
            self.emu.heap_free(text)
        return self.DD_OK

    def DirectDrawEnumerateA(self, args):
        """DirectDrawEnumerateA(callback, context) - the one display driver"""
        return self._dd_enumerate(args, False, False)

    def DirectDrawEnumerateW(self, args):
        return self._dd_enumerate(args, True, False)

    def DirectDrawEnumerateExA(self, args):
        """DirectDrawEnumerateExA(callback, context, flags) - the callback also
        gets a monitor handle"""
        return self._dd_enumerate(args, False, True)

    def DirectDrawEnumerateExW(self, args):
        return self._dd_enumerate(args, True, True)

    def DirectDrawCreateClipper(self, args):
        """DirectDrawCreateClipper(flags, lplpClipper, pUnkOuter)"""
        return self._dd_new_clipper(args[1])

    # ---------- Helpers ----------

    def _dd_object(self, pointer, kind):
        state = self.com_objects.get(pointer)
        return state if state is not None and state.get('kind') == kind else None

    def _dd_unknown(self, method, args, released=None):
        """IUnknown methods of a DirectDraw object; released(state) runs when
        its last reference is gone. None: another method."""
        state = self.com_objects.get(args[0])
        result = self._com_unknown(method, args)
        if (method == 'Release' and state is not None and released is not None
                and args[0] not in self.com_objects):
            released(state)
        return result

    def _dd_add_ref(self, state):
        state['refs'] += 1

    def _dd_read_rect(self, address):
        """(left, top, right, bottom) of a RECT, or None for NULL"""
        if not address:
            return None
        return struct.unpack('<4i', self.emu.uc.mem_read(address, 16))

    def _dd_display_bpp(self, dd):
        return dd['bpp'] if dd is not None else 32

    @classmethod
    def _dd_new_pixels(cls, width, height, bpp, masks=None):
        """pygame surface holding the pixels of a DirectDraw surface"""
        width, height = max(1, width), max(1, height)
        if bpp == 8:
            return pygame.Surface((width, height), 0, 8)
        red, green, blue = masks or cls.DD_MASKS[bpp]
        return pygame.Surface((width, height), 0, bpp, (red, green, blue, 0))

    @staticmethod
    def _dd_pixel_format(pixels):
        """DDPIXELFORMAT of a pygame surface"""
        bpp = pixels.get_bitsize()
        if bpp == 8:
            return struct.pack('<8I', 32, DirectDrawMixin.DDPF_PALETTEINDEXED8 |
                               DirectDrawMixin.DDPF_RGB, 0, 8, 0, 0, 0, 0)
        red, green, blue, _ = pixels.get_masks()
        return struct.pack('<8I', 32, DirectDrawMixin.DDPF_RGB, 0, bpp, red, green, blue, 0)

    def _dd_desc(self, surface, size, lp_surface=0):
        """DDSURFACEDESC (or DDSURFACEDESC2, by size) of a surface"""
        pixels = surface['pixels']
        flags = (self.DDSD_CAPS | self.DDSD_HEIGHT | self.DDSD_WIDTH | self.DDSD_PITCH |
                 self.DDSD_PIXELFORMAT)
        if lp_surface:
            flags |= self.DDSD_LPSURFACE
        if surface['back_count']:
            flags |= self.DDSD_BACKBUFFERCOUNT
        key = surface['color_key']
        if key is not None:
            flags |= self.DDSD_CKSRCBLT
        if size < self.DDSURFACEDESC_SIZE:
            size = self.DDSURFACEDESC_SIZE
        desc = bytearray(size)
        struct.pack_into('<IIIIiI', desc, 0, size, flags, pixels.get_height(),
                         pixels.get_width(), pixels.get_pitch(), surface['back_count'])
        struct.pack_into('<I', desc, 36, lp_surface)
        if key is not None:
            struct.pack_into('<II', desc, 64, key, key)
        desc[72:104] = self._dd_pixel_format(pixels)
        struct.pack_into('<I', desc, 104, surface['caps'])
        return bytes(desc)

    def _dd_new_surface(self, dd, width, height, bpp, caps, masks=None):
        """A surface object; returns its state"""
        state = {'kind': 'ddsurface', 'dd': dd, 'caps': caps, 'color_key': None,
                 'pixels': self._dd_new_pixels(width, height, bpp, masks),
                 'palette': None, 'clipper': None, 'attached': None, 'back_count': 0,
                 'mem': 0, 'synced': False, 'guest_newer': False, 'locked': False,
                 'dc': None, 'primary': False,
                 'last_present': 0.0, 'present_timer': None}
        vtable = self._com_vtable('IDirectDrawSurface7', 'ddsurface')
        self._com_new_object([((self.IID_IUNKNOWN,) + self.IID_IDIRECTDRAWSURFACES, vtable)],
                             state)
        state['pointer'] = state['base']
        if dd is not None:
            dd['surfaces'].append(state)
            if bpp == 8 and dd.get('palette_colors'):
                state['pixels'].set_palette(dd['palette_colors'])
        return state

    def _dd_surface_released(self, state):
        if state['mem']:
            self.emu.heap_free(state['mem'])
            state['mem'] = 0
        state['present_timer'] = None  # A pending picture is not shown
        if state['dc']:
            self._dd_drop_dc(state)
        dd = state['dd']
        if dd is not None:
            if state in dd['surfaces']:
                dd['surfaces'].remove(state)
            if dd.get('primary') is state:
                dd['primary'] = None
        for name in ('attached', 'palette', 'clipper'):
            other = state.get(name)
            state[name] = None
            if other is not None and other['base'] in self.com_objects:
                self._dd_unknown('Release', [other['base']],
                                 self._dd_surface_released if name == 'attached' else None)

    # ---------- IDirectDraw ----------

    def _com_ddraw1(self, method, wide, args):
        return self._dd_method(method, args, first_version=True)

    def _com_ddraw(self, method, wide, args):
        return self._dd_method(method, args, first_version=False)

    def _dd_released(self, dd):
        """The last reference to DirectDraw is gone: the display mode it set ends"""
        self._dd_show_gdi(dd)
        if dd['mode_set']:
            dd['mode_set'] = False
            self._set_display_mode(*self._desktop_size(), owner=None)

    def _dd_method(self, method, args, first_version):
        result = self._dd_unknown(method, args, self._dd_released)
        if result is not None:
            return result
        dd = self._dd_object(args[0], 'ddraw')
        if dd is None:
            return self.DDERR_INVALIDPARAMS
        log.debug(f"IDirectDraw::{method}({', '.join(f'0x{a:x}' for a in args[1:6])})")
        handler = getattr(self, f'_dd_{method}', None)
        if handler is None:
            return self.DD_OK if method in self.DD_HARMLESS_METHODS else self.DDERR_UNSUPPORTED
        return handler(dd, args)

    # Methods that have nothing to do on a software display
    DD_HARMLESS_METHODS = frozenset((
        'Compact', 'FlipToGDISurface', 'Initialize', 'WaitForVerticalBlank',
        'RestoreAllSurfaces', 'TestCooperativeLevel'))

    def _dd_SetCooperativeLevel(self, dd, args):
        hwnd, flags = args[1], args[2]
        exclusive = bool(flags & self.DDSCL_EXCLUSIVE)
        if exclusive and not (flags & self.DDSCL_FULLSCREEN and hwnd):
            return self.DDERR_INVALIDPARAMS
        dd['hwnd'], dd['exclusive'] = hwnd, exclusive
        if exclusive:
            self._dd_cover_screen(dd)
        return self.DD_OK

    def _dd_cover_screen(self, dd):
        """An exclusive full-screen program owns the whole screen: its window
        covers it without a frame, whatever size the program created it with"""
        win = self.gui.windows.get(dd['hwnd']) if self.gui else None
        if win is None:
            return
        with self.gui.lock:
            width, height = self._screen_size()
            win.style = (win.style | self.gui.WS_POPUP) & ~(
                self.gui.WS_CAPTION | self.gui.WS_THICKFRAME)
            win.maximized = False
            win.x, win.y, win.width, win.height = 0, 0, width, height

    def _dd_SetDisplayMode(self, dd, args):
        width, height, bpp = args[1], args[2], args[3]
        if not dd['exclusive']:
            return self.DDERR_NOEXCLUSIVEMODE
        if bpp not in self.DD_MASKS or (width, height) not in {
                (w, h) for w, h, _ in self._display_modes()}:
            return self.DDERR_INVALIDMODE
        dd['bpp'], dd['mode_set'] = bpp, True
        self._set_display_mode(width, height, owner=self)
        self._dd_cover_screen(dd)
        return self.DD_OK

    def _dd_show_gdi(self, dd):
        """The windows are on the screen again, not the primary surface"""
        win = self.gui.windows.get(dd['hwnd']) if self.gui else None
        if win is not None:
            win.shapes_over_children = False

    def _dd_FlipToGDISurface(self, dd, args):
        self._dd_show_gdi(dd)
        return self.DD_OK

    def _dd_RestoreDisplayMode(self, dd, args):
        if dd['mode_set']:
            dd['mode_set'] = False
            dd['bpp'] = 32
            self._set_display_mode(*self._desktop_size(), owner=None)
        return self.DD_OK

    def _dd_mode_desc(self, size, width, height, bpp):
        desc = bytearray(max(size, self.DDSURFACEDESC_SIZE))
        flags = (self.DDSD_HEIGHT | self.DDSD_WIDTH | self.DDSD_PITCH |
                 self.DDSD_PIXELFORMAT | self.DDSD_REFRESHRATE)
        pitch = (width * bpp // 8 + 3) & ~3
        struct.pack_into('<IIIIiII', desc, 0, len(desc), flags, height, width, pitch, 0, 60)
        desc[72:104] = self._dd_pixel_format(self._dd_new_pixels(1, 1, bpp))
        return bytes(desc)

    def _dd_desc_size(self, address, default):
        """dwSize the program put in a surface description it passes"""
        try:
            size = self._read_u32(address)
        except UcError:
            return default
        return size if size in (self.DDSURFACEDESC_SIZE, self.DDSURFACEDESC2_SIZE) else default

    def _dd_GetDisplayMode(self, dd, args):
        if not args[1]:
            return self.DDERR_INVALIDPARAMS
        size = self._dd_desc_size(args[1], self.DDSURFACEDESC_SIZE)
        width, height = self._screen_size()
        self._mem_write(args[1], self._dd_mode_desc(size, width, height, dd['bpp']))
        return self.DD_OK

    def _dd_EnumDisplayModes(self, dd, args):
        wanted, context, callback = args[2], args[3], args[4]
        if not callback:
            return self.DDERR_INVALIDPARAMS
        size = self._dd_desc_size(wanted, self.DDSURFACEDESC_SIZE) if wanted else \
            self.DDSURFACEDESC_SIZE
        block = self.emu.heap_alloc(self.DDSURFACEDESC2_SIZE)
        try:
            for width, height, bpp in self._display_modes():
                if self.emu.stop_emulation:
                    break
                self._mem_write(block, self._dd_mode_desc(size, width, height, bpp))
                if not self.emu.call_callback(callback, [block, context]):
                    break  # DDENUMRET_CANCEL
        finally:
            self.emu.heap_free(block)
        return self.DD_OK

    DDCAPS_BLT, DDCAPS_BLTSTRETCH, DDCAPS_COLORKEY = 0x40, 0x200, 0x400000
    DDCAPS_PALETTE, DDCAPS_BLTCOLORFILL = 0x8000, 0x4000000
    DDCKEYCAPS_SRCBLT = 0x200
    DD_VIDEO_MEMORY = 16 * 1024 * 1024

    def _dd_GetCaps(self, dd, args):
        """Driver and emulation layer capabilities: plain software blitting"""
        for address in (args[1], args[2]):
            if not address:
                continue
            size = min(self._read_u32(address), 380)
            if size < 16:
                return self.DDERR_INVALIDPARAMS
            caps = bytearray(size)
            struct.pack_into('<IIII', caps, 0, size,
                             self.DDCAPS_BLT | self.DDCAPS_BLTSTRETCH | self.DDCAPS_COLORKEY |
                             self.DDCAPS_PALETTE | self.DDCAPS_BLTCOLORFILL, 0,
                             self.DDCKEYCAPS_SRCBLT)
            if size >= 68:
                struct.pack_into('<II', caps, 60, self.DD_VIDEO_MEMORY, self.DD_VIDEO_MEMORY)
            self._mem_write(address, bytes(caps))
        return self.DD_OK

    def _dd_GetAvailableVidMem(self, dd, args):
        for address in (args[2], args[3]):
            if address:
                self._mem_write(address, struct.pack('<I', self.DD_VIDEO_MEMORY))
        return self.DD_OK

    def _dd_GetMonitorFrequency(self, dd, args):
        if args[1]:
            self._mem_write(args[1], struct.pack('<I', 60))
        return self.DD_OK

    def _dd_GetVerticalBlankStatus(self, dd, args):
        if args[1]:
            self._mem_write(args[1], struct.pack('<I', 1))
        return self.DD_OK

    def _dd_GetScanLine(self, dd, args):
        if args[1]:
            self._mem_write(args[1], struct.pack('<I', 0))
        return self.DD_OK

    def _dd_GetFourCCCodes(self, dd, args):
        if args[1]:
            self._mem_write(args[1], struct.pack('<I', 0))
        return self.DD_OK

    def _dd_CreateSurface(self, dd, args):
        lp_desc, out = args[1], args[2]
        if not lp_desc or not out:
            return self.DDERR_INVALIDPARAMS
        try:
            desc = bytes(self.emu.uc.mem_read(lp_desc, self.DDSURFACEDESC_SIZE))
        except UcError:
            return self.DDERR_INVALIDPARAMS
        size, flags, height, width, _, back_count = struct.unpack_from('<IIIIiI', desc)
        if size not in (self.DDSURFACEDESC_SIZE, self.DDSURFACEDESC2_SIZE):
            return self.DDERR_INVALIDPARAMS
        caps = struct.unpack_from('<I', desc, 104)[0] if flags & self.DDSD_CAPS else 0
        bpp, masks = dd['bpp'], None
        if caps & self.DDSCAPS_PRIMARYSURFACE:
            width, height = self._screen_size()
            caps |= self.DDSCAPS_VISIBLE | self.DDSCAPS_FRONTBUFFER
        else:
            if not (flags & self.DDSD_WIDTH and flags & self.DDSD_HEIGHT) or \
                    not 0 < width <= 16384 or not 0 < height <= 16384:
                return self.DDERR_INVALIDPARAMS
            if flags & self.DDSD_PIXELFORMAT:
                _, pf_flags, _, pf_bpp, red, green, blue = struct.unpack_from('<7I', desc, 72)
                if pf_bpp not in self.DD_MASKS or not pf_flags & (
                        self.DDPF_RGB | self.DDPF_PALETTEINDEXED8):
                    return self.DDERR_INVALIDPIXELFORMAT
                bpp = pf_bpp
                if bpp != 8 and red and green and blue:
                    masks = (red, green, blue)
            if not caps & self.DDSCAPS_BACKBUFFER:
                caps |= self.DDSCAPS_OFFSCREENPLAIN
        caps |= self.DDSCAPS_SYSTEMMEMORY
        try:
            surface = self._dd_new_surface(dd, width, height, bpp, caps, masks)
        except (pygame.error, ValueError):
            return self.DDERR_INVALIDPIXELFORMAT
        if flags & self.DDSD_CKSRCBLT:
            surface['color_key'] = struct.unpack_from('<I', desc, 64)[0]
        if caps & self.DDSCAPS_PRIMARYSURFACE:
            surface['primary'] = True
            dd['primary'] = surface
        if flags & self.DDSD_BACKBUFFERCOUNT and back_count and caps & self.DDSCAPS_FLIP:
            # A flipping chain: each surface has the next one attached
            surface['back_count'] = back_count
            previous = surface
            back_caps = ((caps & ~(self.DDSCAPS_PRIMARYSURFACE | self.DDSCAPS_VISIBLE |
                                   self.DDSCAPS_FRONTBUFFER)) | self.DDSCAPS_BACKBUFFER)
            for _ in range(min(back_count, 8)):
                back = self._dd_new_surface(dd, width, height, bpp, back_caps, masks)
                previous['attached'] = back
                previous, back_caps = back, back_caps & ~self.DDSCAPS_BACKBUFFER
        self._mem_write(out, struct.pack('<I', surface['pointer']))
        return self.DD_OK

    def _dd_CreatePalette(self, dd, args):
        flags, table, out = args[1], args[2], args[3]
        if not out or not flags & self.DDPCAPS_8BIT:
            return self.DDERR_INVALIDPARAMS if not out else self.DDERR_UNSUPPORTED
        entries = bytes(self.emu.uc.mem_read(table, 1024)) if table else bytes(1024)
        state = {'kind': 'ddpalette', 'dd': dd, 'caps': flags,
                 'colors': [tuple(entries[i:i + 3]) for i in range(0, 1024, 4)],
                 'flags': bytearray(entries[3::4])}
        self._com_new_object([((self.IID_IUNKNOWN, self.IID_IDIRECTDRAWPALETTE),
                               self._com_vtable('IDirectDrawPalette', 'ddpalette'))], state)
        self._mem_write(out, struct.pack('<I', state['base']))
        return self.DD_OK

    def _dd_new_clipper(self, out):
        if not out:
            return self.DDERR_INVALIDPARAMS
        state = {'kind': 'ddclipper', 'hwnd': 0}
        self._com_new_object([((self.IID_IUNKNOWN, self.IID_IDIRECTDRAWCLIPPER),
                               self._com_vtable('IDirectDrawClipper', 'ddclipper'))], state)
        self._mem_write(out, struct.pack('<I', state['base']))
        return self.DD_OK

    def _dd_CreateClipper(self, dd, args):
        return self._dd_new_clipper(args[2])

    def _dd_GetGDISurface(self, dd, args):
        primary = dd['primary']
        if primary is None or not args[1]:
            return self.DDERR_NOTFOUND
        self._dd_add_ref(primary)
        self._mem_write(args[1], struct.pack('<I', primary['pointer']))
        return self.DD_OK

    def _dd_GetDeviceIdentifier(self, dd, args):
        """DDDEVICEIDENTIFIER: driver and description texts, then the IDs"""
        if not args[1]:
            return self.DDERR_INVALIDPARAMS
        block = bytearray(1024 + 8 + 16 + 16 + 4)
        block[0:11] = b'winexe32emu'
        block[512:534] = b'Primary Display Driver'
        self._mem_write(args[1], bytes(block))
        return self.DD_OK

    # ---------- IDirectDrawPalette, IDirectDrawClipper ----------

    def _dd_apply_palette(self, palette):
        """Give the surfaces that use a palette its current colors"""
        dd = palette['dd']
        primary = dd['primary']
        on_primary = primary is not None and primary['palette'] is palette
        if on_primary:
            # 8 bpp surfaces without a palette of their own show the screen's
            dd['palette_colors'] = list(palette['colors'])
        for surface in list(dd['surfaces']):
            if surface['pixels'].get_bitsize() != 8:
                continue
            if surface['palette'] is palette or (on_primary and surface['palette'] is None):
                surface['pixels'].set_palette(palette['colors'])
        if on_primary:
            self._dd_present(primary)

    def _com_ddpalette(self, method, wide, args):
        result = self._dd_unknown(method, args)
        if result is not None:
            return result
        palette = self._dd_object(args[0], 'ddpalette')
        if palette is None:
            return self.DDERR_INVALIDPARAMS
        if method == 'GetCaps':
            self._mem_write(args[1], struct.pack('<I', palette['caps']))
            return self.DD_OK
        if method in ('GetEntries', 'SetEntries'):
            start, count, address = args[2], args[3], args[4]
            if start + count > 256 or not address:
                return self.DDERR_INVALIDPARAMS
            if method == 'GetEntries':
                self._mem_write(address, b''.join(
                    bytes(palette['colors'][i]) + bytes((palette['flags'][i],))
                    for i in range(start, start + count)))
                return self.DD_OK
            entries = bytes(self.emu.uc.mem_read(address, 4 * count))
            for i in range(count):
                palette['colors'][start + i] = tuple(entries[4 * i:4 * i + 3])
                palette['flags'][start + i] = entries[4 * i + 3]
            self._dd_apply_palette(palette)
            return self.DD_OK
        return self.DD_OK  # Initialize

    def _com_ddclipper(self, method, wide, args):
        result = self._dd_unknown(method, args)
        if result is not None:
            return result
        clipper = self._dd_object(args[0], 'ddclipper')
        if clipper is None:
            return self.DDERR_INVALIDPARAMS
        if method == 'SetHWnd':
            clipper['hwnd'] = args[2]
        elif method == 'GetHWnd':
            self._mem_write(args[1], struct.pack('<I', clipper['hwnd']))
        elif method == 'IsClipListChanged':
            self._mem_write(args[1], struct.pack('<I', 0))
        elif method == 'GetClipList':
            return self.DDERR_UNSUPPORTED
        return self.DD_OK

    # ---------- IDirectDrawSurface ----------

    def _com_ddsurface(self, method, wide, args):
        result = self._dd_unknown(method, args, self._dd_surface_released)
        if result is not None:
            return result
        surface = self._dd_object(args[0], 'ddsurface')
        if surface is None:
            return self.DDERR_INVALIDPARAMS
        handler = getattr(self, f'_dds_{method}', None)
        if handler is None:
            log.debug(f"IDirectDrawSurface::{method}: not emulated")
            return self.DD_OK if method in self.DDS_HARMLESS_METHODS else self.DDERR_UNSUPPORTED
        try:
            return handler(surface, args)
        except UcError:
            return self.DDERR_INVALIDPARAMS

    # A software surface is never lost, busy or paged out
    DDS_HARMLESS_METHODS = frozenset((
        'GetBltStatus', 'GetFlipStatus', 'IsLost', 'Restore', 'PageLock', 'PageUnlock',
        'Initialize', 'ChangeUniquenessValue', 'SetPriority', 'SetLOD', 'FreePrivateData'))

    def _dds_GetCaps(self, surface, args):
        # DDSCAPS, or the larger DDSCAPS2 of IDirectDrawSurface4 and later
        # (its other members stay as the program set them)
        self._mem_write(args[1], struct.pack('<I', surface['caps']))
        return self.DD_OK

    def _dds_GetPixelFormat(self, surface, args):
        self._mem_write(args[1], self._dd_pixel_format(surface['pixels']))
        return self.DD_OK

    def _dds_GetSurfaceDesc(self, surface, args):
        size = self._dd_desc_size(args[1], 0)
        if not size:
            return self.DDERR_INVALIDPARAMS
        self._mem_write(args[1], self._dd_desc(surface, size))
        return self.DD_OK

    def _dds_GetDDInterface(self, surface, args):
        dd = surface['dd']
        if dd is None or not args[1]:
            return self.DDERR_INVALIDPARAMS
        self._dd_add_ref(dd)
        self._mem_write(args[1], struct.pack('<I', dd['base']))
        return self.DD_OK

    def _dds_Lock(self, surface, args):
        """Lock(lpRect, lpDDSD, flags, hEvent): the pixels as guest memory"""
        lp_rect, lp_desc, flags = args[1], args[2], args[3]
        size = self._dd_desc_size(lp_desc, 0) if lp_desc else 0
        if not size:
            return self.DDERR_INVALIDPARAMS
        if surface['locked'] or surface['dc']:
            return self.DDERR_SURFACEBUSY
        pixels = surface['pixels']
        offset = 0
        rect = self._dd_read_rect(lp_rect)
        if rect is not None:
            left, top, right, bottom = rect
            if not (0 <= left < right <= pixels.get_width() and
                    0 <= top < bottom <= pixels.get_height()):
                return self.DDERR_INVALIDRECT
            offset = top * pixels.get_pitch() + left * pixels.get_bytesize()
        if not surface['mem']:
            surface['mem'] = self.emu.heap_alloc(pixels.get_pitch() * pixels.get_height())
            if not surface['mem']:
                return self.DDERR_GENERIC
            surface['synced'] = False
        if not surface['synced']:
            # The guest's copy of the pixels is only written again after a
            # change from outside (Blt, GDI): Red Alert 2 locks its 640x480
            # surfaces hundreds of times a second
            self._mem_write(surface['mem'], pixels.get_buffer().raw)
            surface['synced'] = True
        surface['locked'] = 'read' if flags & self.DDLOCK_READONLY else 'write'
        self._mem_write(lp_desc, self._dd_desc(surface, size, surface['mem'] + offset))
        return self.DD_OK

    def _dds_Unlock(self, surface, args):
        if not surface['locked']:
            return self.DDERR_NOTLOCKED
        if surface['locked'] == 'write':
            # What the program wrote is taken into the host's picture when
            # something else needs it (Blt, GDI, the screen): Red Alert 2
            # locks its 640x480 back buffer hundreds of times a frame-second.
            # The primary surface is on the screen: it is taken at once.
            surface['guest_newer'] = True
            if surface['primary']:
                self._dd_pull(surface)
        written = surface['locked'] == 'write'
        surface['locked'] = False
        if written:
            self._dd_present(surface)
        return self.DD_OK

    def _dd_pull(self, surface):
        """The host's picture of a surface, with what the program wrote
        through Lock since; returns it"""
        pixels = surface['pixels']
        if surface['guest_newer'] and surface['mem']:
            size = pixels.get_pitch() * pixels.get_height()
            pixels.get_buffer().write(bytes(self.emu.uc.mem_read(surface['mem'], size)), 0)
            surface['guest_newer'] = False
        return pixels

    def _dd_color(self, pixels, value):
        """pygame color of a pixel value of a surface"""
        mask = (1 << pixels.get_bitsize()) - 1 if pixels.get_bitsize() < 32 else 0xFFFFFFFF
        return pixels.unmap_rgb(value & mask)

    def _dd_copy(self, target, dest_rect, source, src_rect, keyed, key=None):
        """Copy (and stretch) a part of a surface onto another one. Rectangles
        are (left, top, right, bottom), None for the whole surface."""
        dst, src = self._dd_pull(target), self._dd_pull(source)
        sl, st, sr, sb = src_rect or (0, 0, src.get_width(), src.get_height())
        dl, dt, dr, db = dest_rect or (0, 0, dst.get_width(), dst.get_height())
        if sr <= sl or sb <= st or dr <= dl or db <= dt:
            return self.DDERR_INVALIDRECT
        if sl < 0 or st < 0 or sr > src.get_width() or sb > src.get_height():
            return self.DDERR_INVALIDRECT
        area = pygame.Rect(sl, st, sr - sl, sb - st)
        stretched = (sr - sl, sb - st) != (dr - dl, db - dt)
        if stretched or src is dst:
            piece = src.subsurface(area).copy()
            if stretched:
                piece = pygame.transform.scale(piece, (dr - dl, db - dt))
            area = None
        else:
            piece = src
        if keyed:
            value = source['color_key'] if key is None else key
            if value is None:
                return self.DDERR_NOCOLORKEY
            piece.set_colorkey(self._dd_color(src, value))
        try:
            dst.blit(piece, (dl, dt), area)
        finally:
            if keyed:
                piece.set_colorkey(None)
        target['synced'] = False
        self._dd_present(target)
        return self.DD_OK

    BLACKNESS_ROP, WHITENESS_ROP = 0x00000042, 0x00FF0062

    def _dds_Blt(self, surface, args):
        """Blt(lpDestRect, lpSrcSurface, lpSrcRect, flags, lpDDBltFx)"""
        dest_rect = self._dd_read_rect(args[1])
        flags, lp_fx = args[4], args[5]
        if surface['locked']:
            return self.DDERR_SURFACEBUSY
        fx = bytes(self.emu.uc.mem_read(lp_fx, 100)) if lp_fx else None
        fill = None
        if flags & self.DDBLT_COLORFILL:
            if fx is None:
                return self.DDERR_INVALIDPARAMS
            fill = struct.unpack_from('<I', fx, 80)[0]
        elif flags & self.DDBLT_ROP and fx is not None:
            rop = struct.unpack_from('<I', fx, 8)[0]
            if rop == self.BLACKNESS_ROP:
                fill = 0
            elif rop == self.WHITENESS_ROP:
                fill = 0xFFFFFFFF
            elif rop != self.SRCCOPY:
                return self.DDERR_UNSUPPORTED
        if fill is not None:
            pixels = self._dd_pull(surface)
            if dest_rect is None:
                pixels.fill(self._dd_color(pixels, fill))
            else:
                left, top, right, bottom = dest_rect
                pixels.fill(self._dd_color(pixels, fill),
                            pygame.Rect(left, top, right - left, bottom - top))
            surface['synced'] = False
            self._dd_present(surface)
            return self.DD_OK
        source = self._dd_object(args[2], 'ddsurface')
        if source is None:
            return self.DDERR_INVALIDPARAMS
        key = None
        if flags & self.DDBLT_KEYSRCOVERRIDE and fx is not None:
            key = struct.unpack_from('<I', fx, 92)[0]
        keyed = bool(flags & (self.DDBLT_KEYSRC | self.DDBLT_KEYSRCOVERRIDE))
        return self._dd_copy(surface, dest_rect, source, self._dd_read_rect(args[3]),
                             keyed, key)

    def _dds_BltFast(self, surface, args):
        """BltFast(x, y, lpSrcSurface, lpSrcRect, trans) - an unstretched copy"""
        x, y = self._read_signed_args(args, 1, 2)
        source = self._dd_object(args[3], 'ddsurface')
        if source is None:
            return self.DDERR_INVALIDPARAMS
        if surface['locked']:
            return self.DDERR_SURFACEBUSY
        src_rect = self._dd_read_rect(args[4]) or (
            0, 0, source['pixels'].get_width(), source['pixels'].get_height())
        dest_rect = (x, y, x + src_rect[2] - src_rect[0], y + src_rect[3] - src_rect[1])
        return self._dd_copy(surface, dest_rect, source, src_rect,
                             bool(args[5] & self.DDBLTFAST_SRCCOLORKEY))

    # A surface's picture: the host's pixels, the program's copy (Lock) and
    # which of them is newer
    DD_PICTURE_KEYS = ('pixels', 'mem', 'synced', 'guest_newer')

    def _dds_Flip(self, surface, args):
        """Flip(lpTargetOverride, flags): the back buffer becomes the front"""
        chain = [surface]
        while chain[-1]['attached'] is not None and chain[-1]['attached'] not in chain:
            chain.append(chain[-1]['attached'])
        if len(chain) < 2:
            return self.DDERR_NOTFLIPPABLE
        target = self._dd_object(args[1], 'ddsurface') if args[1] else None
        if target is not None and target in chain[1:]:
            for name in self.DD_PICTURE_KEYS:
                surface[name], target[name] = target[name], surface[name]
        else:
            # The pictures rotate: each surface gets the one of the next
            first = [chain[0][name] for name in self.DD_PICTURE_KEYS]
            for index in range(len(chain) - 1):
                for name in self.DD_PICTURE_KEYS:
                    chain[index][name] = chain[index + 1][name]
            for name, value in zip(self.DD_PICTURE_KEYS, first):
                chain[-1][name] = value
        self._dd_pull(surface)  # The new front buffer is shown
        self._dd_present(surface, now=True)
        return self.DD_OK

    def _dds_GetAttachedSurface(self, surface, args):
        attached = surface['attached']
        if not args[2]:
            return self.DDERR_INVALIDPARAMS
        wanted = self._read_u32(args[1]) if args[1] else 0
        if attached is None or (wanted and not attached['caps'] & wanted):
            self._mem_write(args[2], struct.pack('<I', 0))
            return self.DDERR_NOTFOUND
        self._dd_add_ref(attached)
        self._mem_write(args[2], struct.pack('<I', attached['pointer']))
        return self.DD_OK

    def _dds_AddAttachedSurface(self, surface, args):
        other = self._dd_object(args[1], 'ddsurface')
        if other is None or other is surface:
            return self.DDERR_INVALIDPARAMS
        self._dd_add_ref(other)
        surface['attached'] = other
        return self.DD_OK

    def _dds_SetColorKey(self, surface, args):
        if not args[1] & self.DDCKEY_SRCBLT:
            return self.DDERR_UNSUPPORTED
        surface['color_key'] = self._read_u32(args[2]) if args[2] else None
        return self.DD_OK

    def _dds_GetColorKey(self, surface, args):
        if surface['color_key'] is None or not args[1] & self.DDCKEY_SRCBLT:
            return self.DDERR_NOCOLORKEY
        self._mem_write(args[2], struct.pack('<II', surface['color_key'],
                                             surface['color_key']))
        return self.DD_OK

    def _dd_set_link(self, surface, name, pointer, kind):
        """Attach a palette or clipper (NULL detaches), keeping a reference"""
        other = self._dd_object(pointer, kind) if pointer else None
        if pointer and other is None:
            return self.DDERR_INVALIDPARAMS
        previous = surface[name]
        if other is not None:
            self._dd_add_ref(other)
        surface[name] = other
        if previous is not None and previous['base'] in self.com_objects:
            self._dd_unknown('Release', [previous['base']])
        return self.DD_OK

    def _dds_SetPalette(self, surface, args):
        result = self._dd_set_link(surface, 'palette', args[1], 'ddpalette')
        if result == self.DD_OK and surface['palette'] is not None:
            self._dd_apply_palette(surface['palette'])
        return result

    def _dds_GetPalette(self, surface, args):
        palette = surface['palette']
        if palette is None:
            self._mem_write(args[1], struct.pack('<I', 0))
            return self.DDERR_NOPALETTEATTACHED
        self._dd_add_ref(palette)
        self._mem_write(args[1], struct.pack('<I', palette['base']))
        return self.DD_OK

    def _dds_SetClipper(self, surface, args):
        return self._dd_set_link(surface, 'clipper', args[1], 'ddclipper')

    def _dds_GetClipper(self, surface, args):
        clipper = surface['clipper']
        if clipper is None:
            self._mem_write(args[1], struct.pack('<I', 0))
            return self.DDERR_NOCLIPPERATTACHED
        self._dd_add_ref(clipper)
        self._mem_write(args[1], struct.pack('<I', clipper['base']))
        return self.DD_OK

    # ---------- GDI on a surface ----------

    def _dds_GetDC(self, surface, args):
        """GetDC(lphDC): a memory DC that starts with the surface's picture;
        ReleaseDC paints what GDI drew through it back on the surface"""
        if not args[1]:
            return self.DDERR_INVALIDPARAMS
        if surface['dc']:
            return self.DDERR_DCALREADYCREATED
        if surface['locked']:
            return self.DDERR_SURFACEBUSY
        pixels = self._dd_pull(surface)
        to_bytes = getattr(pygame.image, 'tobytes', None) or pygame.image.tostring
        bitmap = self._new_bitmap(pixels.get_width(), pixels.get_height(), 32,
                                  to_bytes(pixels, 'RGB'))
        hdc = self._create_dc(0, memory=True)
        state = self.dc_state[hdc]
        state['bitmap'] = bitmap
        state['shapes'] = list(self.gdi_objects[bitmap]['shapes'])
        surface['dc'] = (hdc, bitmap)
        self._mem_write(args[1], struct.pack('<I', hdc))
        return self.DD_OK

    def _dd_drop_dc(self, surface):
        hdc, bitmap = surface['dc']
        surface['dc'] = None
        self.dc_map.pop(hdc, None)
        self.dc_state.pop(hdc, None)
        self.gdi_objects.pop(bitmap, None)

    def _dds_ReleaseDC(self, surface, args):
        if not surface['dc'] or surface['dc'][0] != args[1]:
            return self.DDERR_NODC
        state = self.dc_state.get(args[1])
        shapes = state['shapes'] if state else []
        self._dd_drop_dc(surface)
        if len(shapes) > 1 or (shapes and shapes[0].get('type') != 'image'):
            pixels = surface['pixels']
            canvas = pygame.Surface(pixels.get_size())
            with self.gui.lock:  # The fonts and caches of the GUI's painter
                for shape in shapes:
                    self.gui._draw_shape(shape, 0, 0, canvas)
            pixels.blit(canvas, (0, 0))
            surface['synced'] = False
            self._dd_present(surface)
        return self.DD_OK

    # ---------- The primary surface on the screen ----------

    def _dd_present(self, surface, now=False):
        """Show a changed primary surface, at most once per frame time; a
        change that comes sooner is shown by a timer"""
        if not surface['primary'] or self.gui is None:
            return
        elapsed = time.monotonic() - surface['last_present']
        if now or elapsed >= self.DD_PRESENT_INTERVAL:
            self._dd_present_now(surface)
        elif surface['present_timer'] is None:
            surface['present_timer'] = surface['last_present'] + self.DD_PRESENT_INTERVAL
            self._dd_presenter().append(surface)

    def _dd_presenter(self):
        """Surfaces waiting to be shown; a thread of the process shows each at
        its time (a timer thread per picture cost Red Alert 2 2% of its time)"""
        pending = self.__dict__.get('_dd_pending')
        if pending is None:
            pending = self._dd_pending = []
            threading.Thread(target=self._dd_present_later, args=(pending,),
                             name='DirectDraw present', daemon=True).start()
        return pending

    def _dd_present_later(self, pending):
        while not self.process_exited:
            time.sleep(self.DD_PRESENT_INTERVAL / 3)
            now = time.monotonic()
            for surface in [s for s in pending if (s['present_timer'] or 0) <= now]:
                pending.remove(surface)
                if surface['present_timer'] is not None:
                    self._dd_present_now(surface)

    def _dd_present_window(self, surface):
        """Window showing the primary surface: the clipper's, else the one
        given to SetCooperativeLevel"""
        clipper, dd = surface['clipper'], surface['dd']
        hwnd = (clipper['hwnd'] if clipper is not None else 0) or (dd['hwnd'] if dd else 0)
        if not hwnd and self.gui.window_owner(self.gui.active_window) is self:
            hwnd = self.gui.active_window
        return hwnd

    def _dd_present_now(self, surface):
        surface['present_timer'] = None
        surface['last_present'] = time.monotonic()
        gui = self.gui
        if gui is None or self.process_exited:
            return
        hwnd = self._dd_present_window(surface)
        win = gui.windows.get(hwnd)
        if win is None:
            return
        pixels = surface['pixels']
        with gui.lock:
            left, top = gui.client_origin(win)
            width, height = gui.client_size(win)
        # The primary surface is the screen: the window shows the part under
        # its client area
        area = pygame.Rect(left, top, width, height).clip(pixels.get_rect())
        if area.width <= 0 or area.height <= 0:
            return
        to_bytes = getattr(pygame.image, 'tobytes', None) or pygame.image.tostring
        try:
            data = to_bytes(pixels.subsurface(area), 'RGB')
        except (pygame.error, ValueError):
            return
        # An exclusive program's primary surface is the whole screen: what it
        # writes there replaces what its child windows (dialogs whose controls
        # it paints itself) showed
        dd = surface['dd']
        win.shapes_over_children = bool(dd and dd['exclusive'])
        gui.add_shape(hwnd, {'type': 'image', 'pos': (area.x - left, area.y - top),
                             'dim': area.size, 'size': area.size, 'data': data,
                             'rop': self.SRCCOPY})
