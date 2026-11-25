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

"""WinAPIHandler mixin: Memory DC / double buffering, bitmaps, device independent bitmaps"""

import array
import struct
import sys

from unicorn import UcError

from .. import config, gui
from ..config import PYGAME_AVAILABLE
from ..logger import log
from .font_files import RASTER_FONTTYPE, TRUETYPE_FONTTYPE, FontFace

if PYGAME_AVAILABLE:
    import pygame


BITMAPCOREHEADER_SIZE = 12
_DWORD_ARRAY = 'I' if array.array('I').itemsize == 4 else 'L'  # 32-bit array items


def core_dib_to_info(data):
    """A packed DIB with an OS/2-style BITMAPCOREHEADER (12 bytes: WORD sizes,
    RGBTRIPLE colors) as a BITMAPINFOHEADER one; other DIBs are unchanged"""
    if len(data) < BITMAPCOREHEADER_SIZE or \
            struct.unpack_from('<I', data)[0] != BITMAPCOREHEADER_SIZE:
        return data
    _, width, height, planes, bpp = struct.unpack_from('<IHHHH', data)
    count = 1 << bpp if bpp <= 8 else 0
    triples = data[BITMAPCOREHEADER_SIZE:BITMAPCOREHEADER_SIZE + 3 * count]
    table = b''.join(triples[i:i + 3] + b'\x00' for i in range(0, len(triples), 3))
    header = struct.pack('<IiiHHIIiiII', 40, width, height, planes, bpp, 0, 0, 0, 0,
                         count, 0)
    return header + table + data[BITMAPCOREHEADER_SIZE + 3 * count:]


def decompress_rle(bits, width, height, bpp):
    """BI_RLE8 (bpp 8) / BI_RLE4 (bpp 4) bitmap bits as uncompressed bottom-up
    rows (DWORD-aligned stride); skipped pixels stay color index 0"""
    stride = ((width * bpp + 31) // 32) * 4
    out = bytearray(stride * height)
    x = y = i = 0

    def put(px, index):
        if px >= width or y >= height:
            return
        if bpp == 8:
            out[y * stride + px] = index
        else:
            pos = y * stride + px // 2
            out[pos] |= (index & 0x0F) << (0 if px & 1 else 4)

    while i + 1 < len(bits) and y < height:
        count, value = bits[i], bits[i + 1]
        i += 2
        if count:  # Encoded run: count pixels of value (RLE4: two alternating)
            for k in range(count):
                put(x, value if bpp == 8 else (value >> 4 if k % 2 == 0 else value & 0x0F))
                x += 1
        elif value == 0:  # End of line
            x, y = 0, y + 1
        elif value == 1:  # End of bitmap
            break
        elif value == 2:  # Delta
            if i + 1 >= len(bits):
                break
            x, y = x + bits[i], y + bits[i + 1]
            i += 2
        else:  # Absolute run of value pixels, padded to a WORD
            nbytes = value if bpp == 8 else (value + 1) // 2
            literal = bits[i:i + nbytes]
            for k in range(value):
                if bpp == 8:
                    index = literal[k] if k < len(literal) else 0
                else:
                    b = literal[k // 2] if k // 2 < len(literal) else 0
                    index = b >> 4 if k % 2 == 0 else b & 0x0F
                put(x, index)
                x += 1
            i += nbytes + (nbytes & 1)
    return bytes(out)


class MemoryDCMixin:
    """Memory DC / double buffering, bitmaps, device independent bitmaps"""

    # ==================== MEMORY DC / DOUBLE BUFFERING ====================

    def CreateCompatibleDC(self, args):
        """CreateCompatibleDC emulation - off-screen memory DC"""
        hdc = args[0]
        mem_dc = self._create_dc(0, memory=True)
        log.debug(f"CreateCompatibleDC(0x{hdc:x}) -> 0x{mem_dc:x}")
        return mem_dc

    def CreateCompatibleBitmap(self, args):
        """CreateCompatibleBitmap emulation"""
        hdc = args[0]
        width = args[1]
        height = args[2]
        handle = self.get_next_handle()
        self.gdi_objects[handle] = {'type': 'bitmap', 'width': width, 'height': height,
                                    'bpp': 32, 'shapes': []}
        log.debug(f"CreateCompatibleBitmap(0x{hdc:x}, {width}, {height}) -> 0x{handle:x}")
        return handle

    def CreateDiscardableBitmap(self, args):
        """CreateDiscardableBitmap(hdc, cx, cy) - a compatible bitmap (Win32
        never discards it)"""
        return self.CreateCompatibleBitmap(args)

    CBM_INIT = 0x4

    def CreateDIBitmap(self, args):
        """CreateDIBitmap(hdc, pbmih, flInit, pjBits, pbmi, iUsage) - a
        device-dependent bitmap, with the DIB's picture if CBM_INIT"""
        hdc, header, flags, bits, info, usage = args[:6]
        try:
            width, height = self._read_dib_header(header)[1:3] if header else (0, 0)
        except UcError:
            return 0
        rgb = None
        if flags & self.CBM_INIT and bits and info:
            decoded = self._read_dib(hdc, info, bits, usage)
            if decoded is not None:
                dib_width, dib_height, rgb, _ = decoded
                if (dib_width, dib_height) != (abs(width), abs(height)):
                    rgb = None
        handle = self._new_bitmap(abs(width), abs(height), 32, rgb)
        log.debug(f"CreateDIBitmap({width}x{height}, init={bool(rgb)}) -> 0x{handle:x}")
        return handle

    def DeleteDC(self, args):
        """DeleteDC emulation - free a memory DC"""
        hdc = args[0]
        log.debug(f"DeleteDC(0x{hdc:x})")
        self._delete_dc(hdc)
        return 1

    @staticmethod
    def _translate_shape(shape, dx, dy):
        """Copy of a display list entry shifted by (dx, dy)"""
        moved = dict(shape)
        for key in ('rect', 'clip'):
            if key in moved:
                left, top, right, bottom = moved[key]
                moved[key] = (left + dx, top + dy, right + dx, bottom + dy)
        if moved.get('region'):
            moved['region'] = tuple((left + dx, top + dy, right + dx, bottom + dy)
                                    for left, top, right, bottom in moved['region'])
        if 'pos' in moved:
            x, y = moved['pos']
            moved['pos'] = (x + dx, y + dy)
        if 'from' in moved:
            x, y = moved['from']
            moved['from'] = (x + dx, y + dy)
        if 'to' in moved:
            x, y = moved['to']
            moved['to'] = (x + dx, y + dy)
        if 'points' in moved:
            moved['points'] = [(x + dx, y + dy) for x, y in moved['points']]
        return moved

    def BitBlt(self, args):
        """BitBlt emulation - copy a memory DC's display list to the target.

        A blit that covers the whole client area replaces the window's
        display list, so per-frame game rendering doesn't accumulate shapes.
        """
        hdcDest = args[0]
        x, y, cx, cy = self._read_signed_args(args, 1, 4)
        hdcSrc = args[5]
        sx, sy = self._read_signed_args(args, 6, 2)
        rop = args[8]

        log.debug(f"BitBlt(0x{hdcDest:x}, {x}, {y}, {cx}, {cy}, src=0x{hdcSrc:x}, rop=0x{rop:08x})")

        if rop in (self.BLACKNESS, self.WHITENESS, self.PATCOPY):
            return self.PatBlt([hdcDest, x, y, cx, cy, rop])

        self._refresh_dc_dib_section(hdcSrc)
        src_state = self.dc_state.get(hdcSrc)
        if not src_state or not src_state.get('memory'):
            return 1  # Only memory DC sources carry shapes

        # The source's shapes are in device coordinates: map its logical
        # origin (Word draws a line at its document y in a one-line bitmap
        # whose viewport origin is moved up by that y)
        sx, sy = self._lp_to_dp(hdcSrc, sx, sy)
        if rop != self.SRCCOPY and self._blit_pixels(hdcDest, x, y, cx, cy, hdcSrc, sx, sy, rop):
            return 1
        dx, dy = x - sx, y - sy
        shapes = []
        for shape in src_state['shapes']:
            if shape['type'] == 'image':
                shape = self._crop_image(shape, sx, sy, cx, cy, rop)
                if shape is None:
                    continue
            else:
                box = gui.PseudoWindowsGUI.shape_bbox(shape)
                if box and (box[2] <= sx or box[0] >= sx + cx or
                            box[3] <= sy or box[1] >= sy + cy):
                    continue  # Outside the copied area
                if shape['type'] == 'rect':
                    left, top, right, bottom = box
                    shape = dict(shape, rect=(max(left, sx), max(top, sy),
                                              min(right, sx + cx), min(bottom, sy + cy)))
            shapes.append(self._translate_shape(shape, dx, dy))

        if rop not in self._IMAGE_ROPS or (rop == self.SRCINVERT and all(
                s['type'] != 'image' or self._is_monochrome(s) for s in shapes)):
            # Raster operations that depend on the destination (a caret
            # blitted with PDSxxn, SRCINVERT of a black and white bitmap)
            pattern = 1 if sum(self._dc_brush_color(hdcDest)) >= 384 else 0
            shapes = [part for shape in shapes
                      for part in self._rop3_shapes(shape, rop, pattern)]

        if rop in (self.DSPDXAX, self.PSDPXAX):
            # The source is a mask: its white (DSPDxax) or black (PSDPxax)
            # pixels paint the destination's brush color, the others leave it
            brush = self._dc_brush_color(hdcDest)
            shapes = [self._mask_paint(s, brush, rop == self.DSPDXAX) if s['type'] == 'image'
                      else s for s in shapes]

        # Shapes under a later one covering the whole copied area are invisible
        for i in range(len(shapes) - 1, 0, -1):
            if gui.PseudoWindowsGUI.covers_rect(shapes[i], (x, y, x + cx, y + cy)):
                shapes = shapes[i:]
                break

        # Logical coordinates of the destination -> device coordinates
        shapes = [self._map_shape(hdcDest, s) for s in shapes]
        x, y = self._lp_to_dp(hdcDest, x, y)
        dest_state = self.dc_state.get(hdcDest)
        if dest_state and dest_state.get('memory'):
            bmp = self.gdi_objects.get(dest_state.get('bitmap', 0))
            if bmp and bmp.get('bpp') == 1:
                shapes = [self._to_monochrome(s, src_state['bk_color']) for s in shapes]
            for shape in shapes:
                self._add_shape(hdcDest, shape, mapped=True)
            return 1

        hwnd = self._dc_hwnd(hdcDest)
        clipped = self._draw_clip(hdcDest) is not None
        if clipped:
            shapes = [part for shape in shapes for part in self._clip_shape(hdcDest, shape)]
        if self.gui and hwnd in self.gui.controls:
            # An owner-draw control's DC (WM_DRAWITEM)
            for shape in shapes:
                self.gui.add_shape(hwnd, shape)
            return 1
        if not self.gui or not hwnd or hwnd not in self.gui.windows:
            return 1

        window = self.gui.windows[hwnd]
        client_w, client_h = self.gui.client_size(window)
        if not clipped and x <= 0 and y <= 0 and x + cx >= client_w and y + cy >= client_h:
            # Full-area blit: swap in a fresh list (GUI thread iterates snapshots)
            window.drawn_shapes = shapes
        else:
            for shape in shapes:
                self.gui.add_shape(hwnd, shape)
        return 1

    # Raster operations
    SRCCOPY = 0x00CC0020
    SRCPAINT = 0x00EE0086
    SRCAND = 0x008800C6
    SRCINVERT = 0x00660046
    NOTSRCCOPY = 0x00330008
    DSNA = 0x00220326  # D AND NOT S: a mask's white part blackens the destination
    DSPDXAX = 0x00E20746  # Brush color where the source is white (transparent bitmaps)
    PSDPXAX = 0x00B8074A  # Brush color where the source is black
    MERGEPAINT = 0x00BB0226  # NOT S OR D
    PATCOPY = 0x00F00021
    BLACKNESS = 0x00000042
    WHITENESS = 0x00FF0062

    # Raster operations image shapes are drawn with as they are (see
    # PseudoWindowsGUI._rop_blend and _image_surface, and BitBlt's masks)
    _IMAGE_ROPS = (SRCCOPY, SRCPAINT, SRCAND, SRCINVERT, NOTSRCCOPY, DSNA, DSPDXAX,
                   PSDPXAX, MERGEPAINT)

    @staticmethod
    def rop3_effect(rop, pattern, source):
        """What a ternary raster operation does to the destination where the
        pattern (brush) and source bits are pattern and source (0 or 1):
        'keep', 'invert', 'black' (all bits 0) or 'white' (all bits 1).
        Bit P*4 + S*2 + D of the ROP index is the result for P, S, D."""
        index = (rop >> 16) & 0xFF
        base = pattern * 4 + source * 2
        result = ((index >> base) & 1, (index >> (base + 1)) & 1)  # For D = 0, 1
        return {(0, 1): 'keep', (1, 0): 'invert', (0, 0): 'black',
                (1, 1): 'white'}[result]

    @staticmethod
    def _is_monochrome(shape):
        """Has an image shape only black and white pixels?"""
        return not bytes(shape['data']).translate(None, b'\x00\xff')

    def _rop3_shapes(self, shape, rop, pattern):
        """Display list entries drawing shape with raster operation rop, where
        the pattern bit is pattern: source pixels lighter than mid-gray are 1
        bits. Inverted parts become 'invert' shapes (with a mask of their
        pixels), black and white ones color-keyed images."""
        if shape['type'] != 'image':
            effect = self.rop3_effect(rop, pattern, 1)
            if effect == 'keep':
                return []
            if effect == 'invert' and shape['type'] == 'rect' and shape.get('fill') is not None:
                return [{'type': 'invert', 'rect': shape['rect']}]
            return [shape]
        if shape['size'] != shape['dim']:
            return [shape]  # Stretched: drawn as a copy
        effects = (self.rop3_effect(rop, pattern, 0), self.rop3_effect(rop, pattern, 1))
        (x, y), (w, h) = shape['pos'], shape['dim']
        rect = (x, y, x + w, y + h)
        if effects[0] == effects[1]:
            return self._rop3_part(effects[0], rect, None)
        # 0xFF where the source bit is 1 (its red channel is light)
        ones = bytes(shape['data'][0::3]).translate(bytes(0xFF if v >= 128 else 0
                                                          for v in range(256)))
        zeros = ones.translate(bytes(range(255, -1, -1)))
        parts = []
        for effect, mask in zip(effects, (zeros, ones), strict=True):
            parts.extend(self._rop3_part(effect, rect, (w, h, mask)))
        return parts

    @staticmethod
    def _rop3_part(effect, rect, mask):
        """Shapes doing effect ('keep', 'invert', 'black', 'white') in rect,
        only on the pixels set in mask ((w, h, one 0/0xFF byte a pixel) or
        None for all of them)"""
        if effect == 'keep' or (mask is not None and not mask[2].strip(b'\x00')):
            return []
        if effect == 'invert':
            return [{'type': 'invert', 'rect': rect, 'mask': mask}]
        color = (0, 0, 0) if effect == 'black' else (255, 255, 255)
        if mask is None:
            return [{'type': 'rect', 'rect': rect, 'fill': color, 'pen': None}]
        w, h, bits = mask
        # The other color is transparent
        key = (255, 255, 255) if effect == 'black' else (0, 0, 0)
        plane = bits.translate(bytes(color[0] if b else key[0] for b in range(256)))
        rgb = bytearray(len(plane) * 3)
        rgb[0::3] = rgb[1::3] = rgb[2::3] = plane
        return [{'type': 'image', 'pos': rect[:2], 'dim': (w, h), 'size': (w, h),
                 'data': bytes(rgb), 'rop': MemoryDCMixin.SRCCOPY, 'colorkey': key}]

    # Largest memory bitmap (pixels) whose raster operations are done on pixels
    PIXEL_ROP_MAX_AREA = 1024 * 1024

    @staticmethod
    def rop3_bytes(rop, pattern, source, dest):
        """Bytes of a ternary raster operation applied to equally long pattern,
        source and destination bytes (None: not used by the operation, taken
        as 0). Bit P*4 + S*2 + D of the ROP index is the result bit."""
        index = (rop >> 16) & 0xFF
        size = len(dest)
        full = (1 << (8 * size)) - 1
        planes = [int.from_bytes(plane, 'little') if plane is not None else 0
                  for plane in (dest, source, pattern)]
        result = 0
        for term in range(8):
            if not (index >> term) & 1:
                continue
            bits = full
            for bit, plane in enumerate(planes):
                bits &= plane if (term >> bit) & 1 else ~plane & full
            result |= bits
        return result.to_bytes(size, 'little')

    @staticmethod
    def _crop_rgb(rgb, width, left, top, w, h):
        """The w x h pixels at (left, top) of top-down RGB bytes width wide"""
        row = width * 3
        return b''.join(rgb[(top + r) * row + left * 3:(top + r) * row + (left + w) * 3]
                        for r in range(h))

    def _blit_pixels(self, hdcDest, x, y, cx, cy, hdcSrc, sx, sy, rop):
        """Do a raster operation that depends on the destination on the pixels
        of a memory DC's bitmap: masks and pictures built with SRCAND, SRCPAINT,
        DSTINVERT... (Excel 95's toolbar buttons) need the real result, not a
        display list of layers. x, y are logical, sx, sy device coordinates;
        hdcSrc is 0 for PatBlt. Returns False if it cannot be done here (the
        destination is a window, or the pictures cannot be rendered)."""
        state = self.dc_state.get(hdcDest)
        if not state or not state.get('memory'):
            return False
        hbm = state.get('bitmap', 0)
        bmp = self.gdi_objects.get(hbm)
        if not bmp or bmp['type'] != 'bitmap' or bmp.get('dib'):
            return False
        width, height = bmp['width'], bmp['height']
        if not 0 < width * height <= self.PIXEL_ROP_MAX_AREA:
            return False
        x, y = self._lp_to_dp(hdcDest, x, y)
        src_bmp = src_rgb = None
        src_size = (0, 0)
        if hdcSrc:
            src_state = self.dc_state.get(hdcSrc) or {}
            src_hbm = src_state.get('bitmap', 0)
            src_bmp = self.gdi_objects.get(src_hbm)
            if not src_bmp or src_bmp['type'] != 'bitmap':
                return False
            src_size = (src_bmp['width'], src_bmp['height'])
            if not 0 < src_size[0] * src_size[1] <= self.PIXEL_ROP_MAX_AREA:
                return False
        # Clip to both bitmaps
        left, top = max(x, 0), max(y, 0)
        right, bottom = min(x + cx, width), min(y + cy, height)
        if hdcSrc:
            left, top = max(left, x - sx), max(top, y - sy)
            right = min(right, x - sx + src_size[0])
            bottom = min(bottom, y - sy + src_size[1])
        if right <= left or bottom <= top:
            return True  # Nothing inside
        w, h = right - left, bottom - top
        try:
            dest_rgb = self._bitmap_rgb(hbm)
            if hdcSrc:
                src_rgb = self._bitmap_rgb(src_hbm)
        except (UcError, ValueError, TypeError):
            return False
        if dest_rgb is None or (hdcSrc and src_rgb is None):
            return False
        dest_mono = bmp.get('bpp') == 1
        source = None
        if hdcSrc:
            source = self._crop_rgb(src_rgb, src_size[0], left - x + sx, top - y + sy, w, h)
            src_mono = src_bmp.get('bpp') == 1
            if src_mono and not dest_mono:
                # 0 bits are the destination's text color, 1 bits its background
                text = bytes(state.get('text_color') or (0, 0, 0))
                back = bytes(state.get('bk_color') or (255, 255, 255))
                if (text, back) != (b'\x00\x00\x00', b'\xff\xff\xff'):
                    source = b''.join(back if source[i] else text
                                      for i in range(0, len(source), 3))
            elif dest_mono and not src_mono:
                # The source's background color is 1 (white), the others 0
                back = bytes(src_state.get('bk_color') or (255, 255, 255))
                source = b''.join(b'\xff\xff\xff' if source[i:i + 3] == back
                                  else b'\x00\x00\x00' for i in range(0, len(source), 3))
        brush = self._dc_brush_color(hdcDest)
        if dest_mono:
            brush = (255, 255, 255) if sum(brush) >= 384 else (0, 0, 0)
        pattern = bytes(brush) * (w * h)
        dest = self._crop_rgb(dest_rgb, width, left, top, w, h)
        result = self.rop3_bytes(rop, pattern, source, dest)
        row = width * 3
        pixels = bytearray(dest_rgb)
        for r in range(h):
            start = (top + r) * row + left * 3
            pixels[start:start + w * 3] = result[r * w * 3:(r + 1) * w * 3]
        state['shapes'] = [{'type': 'image', 'pos': (0, 0), 'dim': (width, height),
                            'size': (width, height), 'data': bytes(pixels),
                            'rop': self.SRCCOPY}]
        return True

    def _crop_image(self, shape, sx, sy, cx, cy, rop):
        """Part of an image shape inside the source rect (sx, sy, cx, cy), or None.

        A non-SRCCOPY blit replaces the raster operation the image is drawn with.
        """
        x, y = shape['pos']
        w, h = shape['dim']
        if shape['size'] != shape['dim']:
            cropped = dict(shape)  # Stretched images are not cropped
        else:
            left, top = max(x, sx), max(y, sy)
            right, bottom = min(x + w, sx + cx), min(y + h, sy + cy)
            if right <= left or bottom <= top:
                return None
            if (left, top, right, bottom) == (x, y, x + w, y + h):
                cropped = dict(shape)
            else:
                row = w * 3
                start = (left - x) * 3
                end = (right - x) * 3
                data = b''.join(shape['data'][r * row + start:r * row + end]
                                for r in range(top - y, bottom - y))
                cropped = dict(shape, pos=(left, top), dim=(right - left, bottom - top),
                               size=(right - left, bottom - top), data=data)
        if rop != self.SRCCOPY:
            cropped['rop'] = rop
        cropped.pop('_surface', None)
        return cropped

    def _dc_brush_color(self, hdc):
        """(r, g, b) of the brush selected into a DC (the default is white)"""
        state = self.dc_state.get(hdc) or {}
        color = self._brush_color(state.get('brush'), hdc) if state.get('brush') else None
        return color if color is not None else (255, 255, 255)

    @staticmethod
    def _mask_paint(shape, brush, white):
        """Image shape of a mask blitted with DSPDxax / PSDPxax: the brush
        color where the mask is white (white True) or black, transparent
        (a color key) elsewhere"""
        key = (0, 0, 0) if brush != (0, 0, 0) else (255, 255, 255)
        paint, keep = bytes(brush), bytes(key)
        data = shape['data']
        target = b'\xff\xff\xff' if white else b'\x00\x00\x00'
        pixels = b''.join(paint if data[i:i + 3] == target else keep
                          for i in range(0, len(data), 3))
        painted = dict(shape, data=pixels, rop=MemoryDCMixin.SRCCOPY, colorkey=key)
        painted.pop('_surface', None)
        return painted

    def _to_monochrome(self, shape, bk_color):
        """Shape blitted into a monochrome bitmap: the background color becomes
        white, every other color black (how masks are built from sprites)"""
        def mono(color):
            return (255, 255, 255) if color == bk_color else (0, 0, 0)
        shape = dict(shape)
        shape.pop('_surface', None)
        if shape['type'] == 'image':
            bk = bytes(bk_color)
            data = shape['data']
            shape['data'] = b''.join(b'\xff\xff\xff' if data[i:i + 3] == bk else b'\x00\x00\x00'
                                     for i in range(0, len(data), 3))
        for key in ('fill', 'color'):
            if shape.get(key) is not None:
                shape[key] = mono(shape[key])
        return shape

    def _new_bitmap(self, width, height, bpp, rgb=None):
        """Create a bitmap GDI object; rgb (top-down RGB bytes) becomes its picture"""
        handle = self.get_next_handle()
        shapes = []
        if rgb is not None and width > 0 and height > 0:
            shapes.append({'type': 'image', 'pos': (0, 0), 'dim': (width, height),
                           'size': (width, height), 'data': rgb, 'rop': self.SRCCOPY})
        self.gdi_objects[handle] = {'type': 'bitmap', 'width': width, 'height': height,
                                    'bpp': bpp, 'shapes': shapes}
        return handle

    @staticmethod
    def _bitfield_channel(value, mask):
        """A color channel (0-255) of a 16 or 32 bpp pixel (BI_BITFIELDS mask)"""
        if not mask:
            return 0
        shift = (mask & -mask).bit_length() - 1
        top = mask >> shift
        return ((value & mask) >> shift) * 255 // top

    _BITFIELD_TABLES = {}  # 16 bpp masks -> RGB bytes of each of the 65536 pixels

    @classmethod
    def _bitfield_converter(cls, bpp, masks):
        """converter(row, width) -> RGB bytes of a row of 16 or 32 bpp pixels.
        A DIB section of a game is decoded again for every BitBlt, so no
        Python code runs per pixel: 16 bpp pixels go through a table of all
        65536 values, 32 bpp pixels whose masks are whole bytes are sliced."""
        if bpp == 16:
            table = cls._BITFIELD_TABLES.get(masks)
            if table is None:
                channel = cls._bitfield_channel
                table = [bytes((channel(v, masks[0]), channel(v, masks[1]),
                                channel(v, masks[2]))) for v in range(0x10000)]
                cls._BITFIELD_TABLES[masks] = table

            def convert16(line, width):
                pixels = array.array('H', bytes(line[:2 * width]))
                if sys.byteorder == 'big':
                    pixels.byteswap()
                return b''.join(map(table.__getitem__, pixels))
            return convert16

        byte_masks = (0xFF, 0xFF00, 0xFF0000, 0xFF000000)
        if all(m in byte_masks for m in masks):
            offsets = [byte_masks.index(m) for m in masks]

            def convert32_bytes(line, width):
                out = bytearray(width * 3)
                for c, offset in enumerate(offsets):
                    out[c::3] = line[offset:width * 4:4]
                return out
            return convert32_bytes

        channel = cls._bitfield_channel

        def convert32(line, width):  # Masks of other widths (10-10-10...)
            pixels = array.array(_DWORD_ARRAY, bytes(line[:4 * width]))
            if sys.byteorder == 'big':
                pixels.byteswap()
            return bytes(channel(v, m) for v in pixels for m in masks)
        return convert32

    @staticmethod
    def _decode_dib(data):
        """(width, height, top-down RGB bytes) of a packed DIB (BITMAPINFOHEADER,
        color table, bits), or None for unsupported formats"""
        data = core_dib_to_info(data)
        if len(data) < 40:
            return None
        (hdr_size, width, height, _, bpp, compression, _, _, _,
         clr_used, _) = struct.unpack_from('<IiiHHIIiiII', data)
        if hdr_size < 40 or width <= 0 or height == 0 or compression not in (0, 1, 2, 3) or \
                bpp not in (1, 4, 8, 16, 24, 32):
            return None
        # BI_RLE8 / BI_RLE4: 8 / 4 bits per pixel, always bottom-up
        if compression in (1, 2) and (bpp != (8 if compression == 1 else 4) or height < 0):
            return None
        bottom_up = height > 0
        height = abs(height)
        offset = hdr_size
        masks = None
        if compression == 3:  # BI_BITFIELDS
            if bpp not in (16, 32):
                return None
            masks = struct.unpack_from('<III', data, offset)
            offset += 12
        elif bpp == 16:
            masks = (0x7C00, 0x03E0, 0x001F)  # 5-5-5
        palette = []
        if bpp <= 8:
            count = clr_used or (1 << bpp)
            for i in range(count):
                b, g, r = data[offset + 4 * i:offset + 4 * i + 3]
                palette.append(bytes((r, g, b)))
            offset += 4 * count
        if compression in (1, 2):
            data = bytes(data[:offset]) + decompress_rle(data[offset:], width, height, bpp)
        stride = ((width * bpp + 31) // 32) * 4
        if len(data) < offset + stride * height:
            return None

        if masks is not None:
            converter = MemoryDCMixin._bitfield_converter(bpp, masks)

        if bpp <= 8:
            # Indexed: unpack pixels to one index byte each, then map every
            # channel through a 256-entry translate table
            padded = palette + [b'\x00\x00\x00'] * (256 - len(palette))
            tables = [bytes(p[c] for p in padded[:256]) for c in range(3)]
            per_byte = 8 // bpp
            mask = (1 << bpp) - 1
            unpack = [bytes((b >> (8 - bpp * (k + 1))) & mask for b in range(256))
                      for k in range(per_byte)] if bpp < 8 else None

        rows = []
        for r in range(height):
            src_row = (height - 1 - r) if bottom_up else r
            line = data[offset + src_row * stride:offset + (src_row + 1) * stride]
            if bpp == 24:
                out = bytearray(width * 3)
                out[0::3] = line[2:width * 3:3]
                out[1::3] = line[1:width * 3:3]
                out[2::3] = line[0:width * 3:3]
            elif bpp == 32 and masks is None:
                out = bytearray(width * 3)
                out[0::3] = line[2:width * 4:4]
                out[1::3] = line[1:width * 4:4]
                out[2::3] = line[0:width * 4:4]
            elif bpp in (16, 32):
                out = converter(line, width)
            else:
                line = bytes(line)
                if unpack is None:
                    indices = line[:width]
                else:
                    expanded = bytearray(len(line) * per_byte)
                    for k in range(per_byte):
                        expanded[k::per_byte] = line.translate(unpack[k])
                    indices = bytes(expanded[:width])
                out = bytearray(width * 3)
                for c in range(3):
                    out[c::3] = indices.translate(tables[c])
            rows.append(bytes(out))
        return width, height, b''.join(rows)

    # OBM_* system bitmaps drawn here: glyphs as rows of '#' (black) on the 3D face
    OBM_GLYPHS = {
        32738: ['#######', ' ##### ', '  ###  ', '   #   '],                # OBM_COMBO
        32739: ['#   ', '##  ', '### ', '####', '### ', '##  ', '#   '],   # OBM_MNARROW
        32760: ['      #', '     ##', '#   ###', '## ### ', '#####  ', ' ###   ',
                '  #    '],                                                # OBM_CHECK
    }
    OBM_ARROWS = {32753: 'up', 32752: 'down', 32751: 'right', 32750: 'left',
                  32743: 'up', 32742: 'down', 32741: 'right', 32740: 'left'}
    OBM_CHECKBOXES = 32759

    def _system_bitmap(self, name):
        """(width, height, RGB bytes) of an OBM_* system bitmap, or None"""
        face, black, white = (212, 208, 200), (0, 0, 0), (255, 255, 255)
        shadow, dark = (128, 128, 128), (64, 64, 64)
        if name in self.OBM_GLYPHS:
            rows = self.OBM_GLYPHS[name]
            pixels = [[black if c == '#' else face for c in row] for row in rows]
        elif name in self.OBM_ARROWS:
            # A 16x16 raised (pushed: sunken) scroll bar button with its arrow
            size, pushed = 16, name <= 32743
            pixels = [[face] * size for _ in range(size)]
            for i in range(size):
                top_left, bottom_right = (shadow, shadow) if pushed else (white, dark)
                pixels[0][i] = pixels[i][0] = top_left
                pixels[size - 1][i] = pixels[i][size - 1] = bottom_right
            glyph = ['   #   ', '  ###  ', ' ##### ', '#######']
            kind = self.OBM_ARROWS[name]
            for y, row in enumerate(glyph):
                for x, c in enumerate(row):
                    if c != '#':
                        continue
                    px, py = {'up': (x, y), 'down': (x, 3 - y), 'left': (y, x),
                              'right': (3 - y, x)}[kind]
                    if kind in ('up', 'down'):
                        pixels[6 + py][4 + px] = black
                    else:
                        pixels[4 + py][6 + px] = black
        elif name == self.OBM_CHECKBOXES:
            # 4 x 3 images of 13x13: check boxes (unchecked, checked, pushed,
            # pushed and checked), radio buttons, three-state boxes
            pixels = [[face] * 52 for _ in range(39)]
            check = self.OBM_GLYPHS[32760]
            for row in range(3):
                for col in range(4):
                    ox, oy = col * 13, row * 13
                    fill = face if col >= 2 else white
                    for y in range(13):
                        for x in range(13):
                            edge = x == 0 or y == 0 or x == 12 or y == 12
                            inner = x == 1 or y == 1 or x == 11 or y == 11
                            if row == 1 and (x - 6) ** 2 + (y - 6) ** 2 > 36:
                                continue  # Radio buttons are round
                            pixels[oy + y][ox + x] = (shadow if edge and (x == 0 or y == 0)
                                                      else white if edge else
                                                      dark if inner and (x == 1 or y == 1)
                                                      else face if inner else fill)
                    if col % 2:  # Checked
                        if row == 1:
                            for y in range(5, 8):
                                for x in range(5, 8):
                                    pixels[oy + y][ox + x] = black
                        else:
                            for y, line in enumerate(check):
                                for x, c in enumerate(line):
                                    if c == '#':
                                        pixels[oy + 3 + y][ox + 3 + x] = \
                                            shadow if row == 2 else black
        else:
            return None
        rgb = b''.join(bytes(color) for line in pixels for color in line)
        return len(pixels[0]), len(pixels), rgb

    def LoadBitmapA(self, args):
        """LoadBitmapA emulation - a bitmap resource of the program, or (no
        hInstance) one of the OBM_* system bitmaps"""
        hInstance, lpBitmapName = args[0], args[1]
        name = self._resource_key(lpBitmapName)
        if not hInstance:
            system = self._system_bitmap(name)
            if system is None:
                log.warning(f"LoadBitmapA: system bitmap {name} is not available")
                return 0
            return self._new_bitmap(*system[:2], 32, system[2])
        resource = self._find_resource(2, name, hInstance)  # RT_BITMAP
        decoded = None
        if resource:
            try:
                decoded = self._decode_dib(bytes(self.emu.uc.mem_read(*resource)))
            except UcError:
                decoded = None
        if decoded is None:
            log.warning(f"LoadBitmapA({name!r}): bitmap not found or unsupported")
            self._last_error = 1814  # ERROR_RESOURCE_NAME_NOT_FOUND
            return 0
        width, height, rgb = decoded
        handle = self._new_bitmap(width, height, 32, rgb)
        log.debug(f"LoadBitmapA({name!r}) -> 0x{handle:x} ({width}x{height})")
        return handle

    BITS_CACHE_SIZE = 8
    DIB_CACHE_SIZE = 64        # Entries of at most DIB_CACHE_MAX_BYTES each
    DIB_CACHE_MAX_BYTES = 65536

    # b'0'/b'1' bit characters -> black/white channel bytes
    _BIT_TO_GRAY = bytes.maketrans(b'01', b'\x00\xff')
    # Palette index bytes -> hex digit characters (for 4 bpp packing)
    _INDEX_TO_HEX = bytes.maketrans(bytes(range(16)), b'0123456789abcdef')

    def CreateBitmap(self, args):
        """CreateBitmap emulation - monochrome (1 bpp) or 24/32 bpp bits"""
        width, height = self._read_signed_args(args, 0, 2)
        planes, bit_count, lpBits = args[2], args[3], args[4]
        bpp = planes * bit_count
        if width <= 0 or height <= 0:
            return 0
        rgb = None
        if lpBits and bpp in (1, 24, 32):
            stride = ((width * bpp + 15) // 16) * 2  # DDB rows are WORD aligned
            try:
                bits = bytes(self.emu.uc.mem_read(lpBits, stride * height))
            except UcError:
                return 0
            # Shared picture for equal bits, so GetDIBits' cache can recognize it
            key = (width, height, bpp, bits)
            rgb = self._bits_cache.get(key)
            if rgb is not None:
                handle = self._new_bitmap(width, height, 1 if bpp == 1 else 32, rgb)
                log.debug(f"CreateBitmap({width}, {height}, {bpp} bpp) -> 0x{handle:x}")
                return handle
            out = bytearray(width * height * 3)
            if bpp == 1:
                digits = format(int.from_bytes(bits, 'big'), f'0{len(bits) * 8}b')
                if stride * 8 != width:
                    digits = ''.join(digits[r * stride * 8:r * stride * 8 + width]
                                     for r in range(height))
                gray = digits.encode().translate(self._BIT_TO_GRAY)
                out[0::3] = out[1::3] = out[2::3] = gray
            else:
                row = width * 3
                step = bpp // 8
                end = width * step
                for r in range(height):
                    line = bits[r * stride:(r + 1) * stride]
                    base = r * row
                    out[base:base + row:3] = line[2:end:step]
                    out[base + 1:base + row:3] = line[1:end:step]
                    out[base + 2:base + row:3] = line[0:end:step]
            rgb = bytes(out)
            if len(self._bits_cache) >= self.BITS_CACHE_SIZE:
                del self._bits_cache[next(iter(self._bits_cache))]
            self._bits_cache[key] = rgb
        handle = self._new_bitmap(width, height, 1 if bpp == 1 else 32, rgb)
        log.debug(f"CreateBitmap({width}, {height}, {bpp} bpp) -> 0x{handle:x}")
        return handle

    def GetObjectA(self, args):
        """GetObjectA emulation - BITMAP, LOGPEN, LOGBRUSH and LOGFONTA"""
        hObject, cbBuffer, lpvObject = args[0], args[1], args[2]
        obj = self.gdi_objects.get(hObject)
        if obj is None:
            return 0
        kind = obj['type']
        if kind == 'bitmap' and obj.get('dib'):
            return self._get_dib_section_object(obj, cbBuffer, lpvObject)
        if kind == 'bitmap':
            bpp = obj.get('bpp', 32)
            width, height = obj['width'], obj['height']
            data = struct.pack('<iiiiHHI', 0, width, height,
                               ((width * bpp + 15) // 16) * 2, 1, bpp, 0)
        elif kind == 'pen':
            r, g, b = obj['color']
            data = struct.pack('<IiiI', obj.get('style', 0), obj['width'], 0,
                               r | (g << 8) | (b << 16))
        elif kind == 'brush':
            color = obj.get('color')
            if color is None:
                data = struct.pack('<III', 1, 0, 0)  # BS_NULL
            else:
                r, g, b = color
                data = struct.pack('<III', 0, r | (g << 8) | (b << 16), 0)
        elif kind == 'font':
            face = obj.get('face', '').encode(config.ANSI_CODEPAGE, errors='replace')[:31]
            data = struct.pack('<iiiii8B32s', -obj['height'], 0, 0, 0,
                               700 if obj.get('bold') else 400,
                               1 if obj.get('italic') else 0,
                               1 if obj.get('underline') else 0, 0, 0, 0, 0, 0, 0, face)
        elif kind == 'palette':
            data = struct.pack('<H', len(obj['entries']))
        else:
            return 0
        if not lpvObject:
            return len(data)
        data = data[:cbBuffer]
        return len(data) if self._mem_write(lpvObject, data) else 0

    DIBSECTION_SIZE = 84  # BITMAP, BITMAPINFOHEADER, dsBitfields[3], dshSection, dsOffset

    def _get_dib_section_object(self, obj, cbBuffer, lpvObject):
        """GetObject of a CreateDIBSection bitmap: a BITMAP with the DIB's own
        format and bmBits, or a DIBSECTION if the buffer has room for one"""
        dib = obj['dib']
        header = dib['header']
        size = struct.unpack_from('<I', header)[0]
        colors = 0
        if size == BITMAPCOREHEADER_SIZE:
            width, height, _, bpp = struct.unpack_from('<HHHH', header, 4)
            compression = 0
        else:
            width, height, _, bpp, compression = struct.unpack_from('<iiHHI', header, 4)
            colors = struct.unpack_from('<I', header, 32)[0]
        stride = ((width * bpp + 31) // 32) * 4  # DIB rows are DWORD-aligned
        bitmap = struct.pack('<iiiiHHI', 0, width, abs(height), stride, 1, bpp, dib['bits'])
        if not lpvObject:
            return len(bitmap)
        if cbBuffer < self.DIBSECTION_SIZE:
            data = bitmap[:cbBuffer]
            return len(data) if self._mem_write(lpvObject, data) else 0
        if bpp <= 8:
            colors = colors or (1 << bpp)
        if compression == 3:  # BI_BITFIELDS: the masks follow (or end) a BITMAPINFOHEADER
            masks = struct.unpack_from('<III', header, 40)
        elif bpp == 16:
            masks = (0x7C00, 0x03E0, 0x001F)  # 5-5-5
        elif bpp == 32:
            masks = (0xFF0000, 0x00FF00, 0x0000FF)
        else:
            masks = (0, 0, 0)
        info = struct.pack('<IiiHHIIiiII', 40, width, height, 1, bpp, compression,
                           dib['size'], 0, 0, colors, 0)
        data = bitmap + info + struct.pack('<5I', *masks, 0, 0)
        return len(data) if self._mem_write(lpvObject, data) else 0

    @staticmethod
    def _scale_shape(shape, sx_src, sy_src, xd, yd, scale_x, scale_y):
        """Copy of a display list entry mapped through a StretchBlt transform"""
        def tx(x):
            return int(round(xd + (x - sx_src) * scale_x))

        def ty(y):
            return int(round(yd + (y - sy_src) * scale_y))

        scaled = dict(shape)
        for key in ('rect', 'clip'):
            if key in scaled:
                left, top, right, bottom = scaled[key]
                x1, x2 = tx(left), tx(right)
                y1, y2 = ty(top), ty(bottom)
                # Normalize so mirrored blits keep left < right, top < bottom
                scaled[key] = (min(x1, x2), min(y1, y2), max(x1, x2), max(y1, y2))
        if 'pos' in scaled:
            x, y = scaled['pos']
            scaled['pos'] = (tx(x), ty(y))
        if 'from' in scaled:
            x, y = scaled['from']
            scaled['from'] = (tx(x), ty(y))
        if 'to' in scaled:
            x, y = scaled['to']
            scaled['to'] = (tx(x), ty(y))
        if 'points' in scaled:
            scaled['points'] = [(tx(x), ty(y)) for x, y in scaled['points']]
        if scaled.get('region'):
            scaled['region'] = tuple(
                (min(tx(left), tx(right)), min(ty(top), ty(bottom)),
                 max(tx(left), tx(right)), max(ty(top), ty(bottom)))
                for left, top, right, bottom in scaled['region'])
        if 'dx' in scaled:
            scaled['dx'] = [int(round(d * scale_x)) for d in scaled['dx']]
            scaled.pop('_surface', None)
        if 'radius' in scaled:
            scale_avg = (abs(scale_x) + abs(scale_y)) / 2.0
            scaled['radius'] = max(0, int(round(scaled['radius'] * scale_avg)))
        if scaled['type'] == 'image':
            w, h = scaled['size']
            x, y = scaled['pos']
            x2, y2 = tx(shape['pos'][0] + w), ty(shape['pos'][1] + h)
            scaled['pos'] = (min(x, x2), min(y, y2))
            scaled['size'] = (abs(x2 - x), abs(y2 - y))
            scaled.pop('_surface', None)
        return scaled

    def StretchBlt(self, args):
        """StretchBlt emulation - copy a memory DC's display list scaled.

        Like BitBlt, but the source rectangle is mapped onto the destination
        rectangle; shape coordinates are transformed accordingly (pen widths
        and font sizes are kept as-is).
        """
        hdcDest = args[0]
        xd, yd, wd, hd = self._read_signed_args(args, 1, 4)
        hdcSrc = args[5]
        xs, ys, ws, hs = self._read_signed_args(args, 6, 4)
        rop = args[10]

        log.debug(f"StretchBlt(0x{hdcDest:x}, dst=({xd},{yd},{wd},{hd}), "
                  f"src=0x{hdcSrc:x} ({xs},{ys},{ws},{hs}), rop=0x{rop:08x})")

        if ws == 0 or hs == 0:
            return 0

        self._refresh_dc_dib_section(hdcSrc)
        src_state = self.dc_state.get(hdcSrc)
        if not src_state or not src_state.get('memory'):
            return 1  # Only memory DC sources carry shapes

        # The source rect in the device coordinates its shapes are in
        (xs, ys), (xs2, ys2) = self._lp_to_dp(hdcSrc, xs, ys), \
            self._lp_to_dp(hdcSrc, xs + ws, ys + hs)
        ws, hs = xs2 - xs, ys2 - ys
        if ws == 0 or hs == 0:
            return 0
        scale_x = wd / ws
        scale_y = hd / hs
        shapes = []
        for shape in src_state['shapes']:
            if shape['type'] == 'image':
                shape = self._crop_image(shape, min(xs, xs + ws), min(ys, ys + hs),
                                         abs(ws), abs(hs), rop)
                if shape is None:
                    continue
            shapes.append(self._scale_shape(shape, xs, ys, xd, yd, scale_x, scale_y))

        # Logical coordinates of the destination -> device coordinates
        shapes = [self._map_shape(hdcDest, s) for s in shapes]
        (xd, yd), (x2, y2) = self._lp_to_dp(hdcDest, xd, yd), \
            self._lp_to_dp(hdcDest, xd + wd, yd + hd)
        wd, hd = x2 - xd, y2 - yd
        dest_state = self.dc_state.get(hdcDest)
        if dest_state and dest_state.get('memory'):
            dest_state['shapes'].extend(shapes)
            return 1

        hwnd = self._dc_hwnd(hdcDest)
        if self.gui and hwnd in self.gui.controls:
            # An owner-draw control's DC (WM_DRAWITEM)
            for shape in shapes:
                self.gui.add_shape(hwnd, shape)
            return 1
        if not self.gui or not hwnd or hwnd not in self.gui.windows:
            return 1

        window = self.gui.windows[hwnd]
        client_w, client_h = self.gui.client_size(window)
        if xd <= 0 and yd <= 0 and xd + wd >= client_w and yd + hd >= client_h:
            # Full-area blit: swap in a fresh list (GUI thread iterates snapshots)
            window.drawn_shapes = shapes
        else:
            window.drawn_shapes = window.drawn_shapes + shapes
        return 1

    # ---------- Device independent bitmaps ----------

    def _dc_palette_colors(self, hdc):
        """RGB entries of the palette selected into a DC (DIB_PAL_COLORS)"""
        state = self.dc_state.get(hdc) or {}
        palette = self.gdi_objects.get(state.get('palette', 0))
        if palette and palette['type'] == 'palette':
            return [entry[:3] for entry in palette['entries']]
        return []

    def _read_dib_header(self, address):
        """(header size, width, height, bpp, compression, colors used) of the
        BITMAPINFOHEADER or BITMAPCOREHEADER at address (UcError if unreadable)"""
        size = struct.unpack('<I', self.emu.uc.mem_read(address, 4))[0]
        if size == BITMAPCOREHEADER_SIZE:
            _, width, height, _, bpp = struct.unpack(
                '<IHHHH', self.emu.uc.mem_read(address, BITMAPCOREHEADER_SIZE))
            return size, width, height, bpp, 0, 0
        (size, width, height, _, bpp, compression, _, _, _, clr_used, _) = struct.unpack(
            '<IiiHHIIiiII', self.emu.uc.mem_read(address, 40))
        return size, width, height, bpp, compression, clr_used

    def _read_dib(self, hdc, lpbmi, lpBits, usage):
        """(width, height, top-down RGB, bottom_up) of a DIB given as BITMAPINFO
        and bits, or None for unsupported formats"""
        try:
            hdr_size, width, height, bpp, compression, clr_used = self._read_dib_header(lpbmi)
            quad = 3 if hdr_size == BITMAPCOREHEADER_SIZE else 4  # RGBTRIPLE / RGBQUAD
            if bpp <= 8:
                count = clr_used or (1 << bpp)
                if usage == 1:  # DIB_PAL_COLORS: WORD indices into the DC's palette
                    indices = struct.unpack(f'<{count}H',
                                            self.emu.uc.mem_read(lpbmi + hdr_size, 2 * count))
                    colors = self._dc_palette_colors(hdc)
                    table = b''.join(bytes((b, g, r, 0)) for r, g, b in
                                     (colors[i] if i < len(colors) else (0, 0, 0)
                                      for i in indices))
                else:
                    table = bytes(self.emu.uc.mem_read(lpbmi + hdr_size, quad * count))
                    if quad == 3:
                        table = b''.join(table[i:i + 3] + b'\x00'
                                         for i in range(0, len(table), 3))
            elif compression == 3:  # BI_BITFIELDS (masks in V4/V5 headers too)
                count = 0
                table = bytes(self.emu.uc.mem_read(lpbmi + 40, 12))
            else:
                count, table = 0, b''
            stride = ((abs(width) * bpp + 31) // 32) * 4
            bits = bytes(self.emu.uc.mem_read(lpBits, stride * abs(height)))
        except (UcError, struct.error, OverflowError):
            return None
        packed = struct.pack('<IiiHHIIiiII', 40, width, height, 1, bpp, compression,
                             0, 0, 0, count, 0) + table + bits
        decoded = self._decode_dib(packed)
        if decoded is None:
            log.warning(f"Unsupported DIB: {width}x{height}, {bpp} bpp, "
                        f"compression {compression}")
            return None
        return decoded + (height > 0,)

    @staticmethod
    def _flip_rgb(data, width, height, flip_x, flip_y):
        """Mirror top-down RGB pixel data horizontally and/or vertically"""
        row = width * 3
        rows = [data[r * row:(r + 1) * row] for r in range(height)]
        if flip_y:
            rows.reverse()
        if flip_x:
            flipped = []
            for line in rows:
                reverse = line[::-1]  # Pixels reversed, channels as B, G, R
                out = bytearray(row)
                out[0::3], out[1::3], out[2::3] = reverse[2::3], reverse[1::3], reverse[0::3]
                flipped.append(bytes(out))
            rows = flipped
        return b''.join(rows)

    def StretchDIBits(self, args):
        """StretchDIBits emulation - a DIB (or part of it) scaled onto a DC"""
        hdc = args[0]
        xd, yd, wd, hd, xs, ys, ws, hs = self._read_signed_args(args, 1, 8)
        lpBits, lpbmi, usage, rop = args[9], args[10], args[11], args[12]
        log.debug(f"StretchDIBits(0x{hdc:x}, dst=({xd},{yd},{wd},{hd}), "
                  f"src=({xs},{ys},{ws},{hs}), rop=0x{rop:08x})")
        if rop in (self.BLACKNESS, self.WHITENESS, self.PATCOPY):
            self.PatBlt([hdc, xd, yd, wd, hd, rop])
            return abs(hs)
        if not wd or not hd or not ws or not hs or not lpBits or not lpbmi:
            return 0
        decoded = self._read_dib(hdc, lpbmi, lpBits, usage)
        if decoded is None:
            return 0
        width, height, rgb, bottom_up = decoded

        # Source rectangle in top-down image rows (ySrc counts from the bottom
        # of a bottom-up DIB)
        left, src_w = min(xs, xs + ws), abs(ws)
        low, src_h = min(ys, ys + hs), abs(hs)
        top = height - (low + src_h) if bottom_up else low
        scale_x, scale_y = abs(wd) / src_w, abs(hd) / src_h
        dst_x, dst_y = min(xd, xd + wd), min(yd, yd + hd)
        flip_x, flip_y = (ws < 0) != (wd < 0), (hs < 0) != (hd < 0)

        # Clip the source rectangle to the image
        c_left, c_top = max(left, 0), max(top, 0)
        c_right, c_bottom = min(left + src_w, width), min(top + src_h, height)
        if c_right <= c_left or c_bottom <= c_top:
            return 0
        if flip_x:
            dst_x += round((left + src_w - c_right) * scale_x)
        else:
            dst_x += round((c_left - left) * scale_x)
        if flip_y:
            dst_y += round((top + src_h - c_bottom) * scale_y)
        else:
            dst_y += round((c_top - top) * scale_y)
        cw, ch = c_right - c_left, c_bottom - c_top
        if (cw, ch) != (width, height):
            row = width * 3
            rgb = b''.join(rgb[r * row + c_left * 3:r * row + c_right * 3]
                           for r in range(c_top, c_bottom))
        if flip_x or flip_y:
            rgb = self._flip_rgb(rgb, cw, ch, flip_x, flip_y)
        size = (max(1, round(cw * scale_x)), max(1, round(ch * scale_y)))
        self._add_shape(hdc, {'type': 'image', 'pos': (dst_x, dst_y), 'dim': (cw, ch),
                              'size': size, 'data': rgb, 'rop': rop})
        return abs(hs)

    def SetStretchBltMode(self, args):
        """SetStretchBltMode emulation - returns the previous mode"""
        state = self.dc_state.get(args[0])
        if state is None or not 1 <= args[1] <= 4:
            return 0
        previous = state.get('stretch_mode', 1)  # BLACKONWHITE
        state['stretch_mode'] = args[1]
        return previous

    def _bitmap_shapes(self, hbm, bmp):
        """Display list of a bitmap; when selected, the DC has the live drawing"""
        self._refresh_dib_section(hbm)
        for state in self.dc_state.values():
            if state.get('memory') and state.get('bitmap') == hbm:
                return state['shapes']
        return bmp['shapes']

    @staticmethod
    def _shapes_key(shapes):
        """(hashable key, image data objects) of a display list. Image data is
        keyed by identity, so the caller must keep the data objects alive."""
        parts, refs = [], []
        for shape in shapes:
            items = []
            for name, value in shape.items():
                if name in ('_surface', '_mask'):
                    continue
                if name == 'data':
                    refs.append(value)
                    value = id(value)
                items.append((name, value))
            parts.append(repr(items))
        return '\n'.join(parts), refs

    def _bitmap_rgb(self, hbm):
        """Top-down RGB pixels of a bitmap object, rendered from its display list"""
        bmp = self.gdi_objects.get(hbm)
        if not bmp or bmp['type'] != 'bitmap':
            return None
        width, height = bmp['width'], bmp['height']
        shapes = self._bitmap_shapes(hbm, bmp)
        if (len(shapes) == 1 and shapes[0]['type'] == 'image' and shapes[0]['pos'] == (0, 0)
                and shapes[0]['dim'] == shapes[0]['size'] == (width, height)
                and shapes[0].get('rop') == self.SRCCOPY):
            return shapes[0]['data']
        if not PYGAME_AVAILABLE or not self.gui:
            return None
        surface = pygame.Surface((width, height))
        surface.fill((255, 255, 255) if bmp.get('bpp') == 1 else (0, 0, 0))
        for shape in shapes:
            self.gui._draw_shape(shape, 0, 0, target=surface)
        to_bytes = getattr(pygame.image, 'tobytes', None) or pygame.image.tostring
        return to_bytes(surface, 'RGB')

    def GetDIBits(self, args):
        """GetDIBits emulation - bitmap info (lpvBits NULL) or 24/32 bpp pixels"""
        hdc, hbm, start, lines, lpvBits, lpbmi, usage = args[:7]
        bmp = self.gdi_objects.get(hbm)
        if not bmp or bmp['type'] != 'bitmap' or not lpbmi:
            return 0
        width, height = bmp['width'], bmp['height']
        try:
            hdr_size, _, req_height, bpp = self._read_dib_header(lpbmi)[:4]
        except UcError:
            return 0
        core = hdr_size == BITMAPCOREHEADER_SIZE
        if not lpvBits:
            if bpp == 0:
                bpp = 1 if bmp.get('bpp') == 1 else 32
                stride = ((width * bpp + 31) // 32) * 4
                header = struct.pack('<IHHHH', hdr_size, width, height, 1, bpp) if core else \
                    struct.pack('<IiiHHIIiiII', max(hdr_size, 40), width, height, 1,
                                bpp, 0, stride * height, 0, 0, 0, 0)
                if not self._mem_write(lpbmi, header):
                    return 0
            return height
        if bpp not in (1, 4, 8, 24, 32):
            log.warning(f"GetDIBits: {bpp} bpp output is not supported")
            return 0
        stride = ((width * bpp + 31) // 32) * 4
        step = bpp // 8
        bottom_up = req_height >= 0
        lines = min(lines, max(0, height - start))
        out = bytearray(stride * lines)
        palette = None
        if bpp <= 8:
            if bpp == 1:
                palette = [(0, 0, 0), (255, 255, 255)]
            elif bpp == 4:
                palette = [(0, 0, 0), (128, 0, 0), (0, 128, 0), (128, 128, 0), (0, 0, 128),
                           (128, 0, 128), (0, 128, 128), (192, 192, 192), (128, 128, 128),
                           (255, 0, 0), (0, 255, 0), (255, 255, 0), (0, 0, 255),
                           (255, 0, 255), (0, 255, 255), (255, 255, 255)]
            else:
                palette = self._dc_palette_colors(hdc)[:256] or [
                    (r * 255 // 7, g * 255 // 7, b * 255 // 3)
                    for r in range(8) for g in range(8) for b in range(4)]
            if usage == 1:  # DIB_PAL_COLORS
                table = struct.pack(f'<{len(palette)}H', *range(len(palette)))
            else:
                table = b''.join(bytes((b, g, r) if core else (b, g, r, 0))
                                 for r, g, b in palette)
            self._mem_write(lpbmi + hdr_size, table)
            if not core:
                self._mem_write(lpbmi + 32, struct.pack('<I', len(palette)))  # biClrUsed

        # Programs often re-read the same picture (e.g. text drawn into a bitmap)
        shapes_key, refs = self._shapes_key(self._bitmap_shapes(hbm, bmp))
        key = (width, height, bmp.get('bpp'), bpp, bottom_up, start, lines,
               tuple(map(tuple, palette)) if palette else None, shapes_key)
        cached = self._dib_cache.get(key)
        if cached is not None:
            return lines if self._mem_write(lpvBits, cached[0]) else 0
        rgb = self._bitmap_rgb(hbm)
        if rgb is None:
            return 0
        if palette is not None:
            class Nearest(dict):
                def __missing__(cache, color):
                    index = min(range(len(palette)), key=lambda i: sum(
                        (a - b) ** 2 for a, b in zip(palette[i], color, strict=False)))
                    cache[color] = index
                    return index
            index_of = Nearest().__getitem__
            reds = rgb[0::3]
            if reds == rgb[1::3] == rgb[2::3]:
                # Gray image (e.g. monochrome bitmaps): map the levels with one table
                gray = bytearray(256)
                for level in set(reds):
                    gray[level] = index_of((level, level, level))
                indices = reds.translate(gray)
            else:
                indices = bytes(map(index_of, zip(reds, rgb[1::3], rgb[2::3], strict=False)))
            row_bytes = (width * bpp + 7) // 8

            def pack(row_indices, nbytes):
                if bpp == 8:
                    return row_indices
                digits = row_indices.translate(self._INDEX_TO_HEX).ljust(
                    nbytes * 8 // bpp, b'0')
                if bpp == 1:
                    return int(digits, 2).to_bytes(nbytes, 'big')
                return bytes.fromhex(digits.decode())

            packed = None
            if width * bpp % 8 == 0:
                packed = pack(indices, row_bytes * height)
        for i in range(lines):
            scan = start + i  # Scan lines count from the bottom of a bottom-up DIB
            src_row = height - 1 - scan if bottom_up else scan
            base = i * stride
            if palette is not None:
                if packed is not None:
                    row = packed[src_row * row_bytes:(src_row + 1) * row_bytes]
                else:
                    row = pack(indices[src_row * width:(src_row + 1) * width], row_bytes)
                out[base:base + row_bytes] = row
                continue
            line = rgb[src_row * width * 3:(src_row + 1) * width * 3]
            out[base + 2:base + width * step:step] = line[0::3]
            out[base + 1:base + width * step:step] = line[1::3]
            out[base:base + width * step:step] = line[2::3]
        if len(out) <= self.DIB_CACHE_MAX_BYTES:
            if len(self._dib_cache) >= self.DIB_CACHE_SIZE:
                del self._dib_cache[next(iter(self._dib_cache))]
            self._dib_cache[key] = (bytes(out), refs)
        return lines if self._mem_write(lpvBits, out) else 0

    def CreateDCA(self, args):
        """CreateDCA emulation - "DISPLAY" gives a screen DC"""
        driver = self.read_string(args[0]).upper() if args[0] else ''
        device = self.read_string(args[1]).upper() if args[1] else ''
        if driver.strip('\\.') == 'DISPLAY' or device.strip('\\.') == 'DISPLAY1':
            return self._create_dc(0)
        log.warning(f"CreateDCA({driver!r}, {device!r}): only the display is available")
        return 0

    FONT_FAMILIES = [FontFace('Arial', 0x22, TRUETYPE_FONTTYPE, 0, 400),
                     FontFace('Courier New', 0x31, TRUETYPE_FONTTYPE, 0, 400),
                     FontFace('Times New Roman', 0x12, TRUETYPE_FONTTYPE, 0, 400),
                     FontFace('MS Sans Serif', 0x22, RASTER_FONTTYPE, 13, 400),
                     FontFace('System', 0x22, RASTER_FONTTYPE, 16, 700)] + [
                         # SMALLE.FON's sizes at 96 DPI
                         FontFace('Small Fonts', 0x22, RASTER_FONTTYPE, height, 400)
                         for height in (3, 5, 6, 8, 10, 11)]

    def _enumerated_fonts(self, family):
        """The fonts EnumFontFamilies/EnumFonts report: one per face, or with
        a face name every size and weight of that face (a raster font has
        a few). The fonts added with AddFontResource come with them."""
        fonts = self.FONT_FAMILIES + self.added_font_faces()
        if family is None:
            first = {}
            for face in fonts:
                first.setdefault(face.name.lower(), face)
            return list(first.values())
        unique = {}
        for face in fonts:
            if face.name.lower() == family.lower():
                unique.setdefault((face.height, face.weight), face)
        return list(unique.values())

    @staticmethod
    def _enum_font_structs(face):
        """ENUMLOGFONTA (156 bytes) and NEWTEXTMETRICA (72 bytes) of a font"""
        truetype = face.font_type == TRUETYPE_FONTTYPE
        height = face.height or 16
        ascent = (height * 13 + 8) // 16
        average = max(1, (height * 7 + 8) // 16)
        name = face.name.encode(config.ANSI_CODEPAGE, errors='replace')[:31]
        logfont = (struct.pack('<5i8B', -(height * 13 // 16) if truetype else height, 0, 0, 0,
                               face.weight, 0, 0, 0, 0, 0, 0,
                               2 if truetype else 0, face.pitch_family)  # PROOF_QUALITY
                   + name.ljust(32, b'\x00'))
        style = b'Bold' if face.weight >= 700 else b'Regular'
        enum_logfont = logfont + name.ljust(64, b'\x00') + style.ljust(32, b'\x00')
        # tmPitchAndFamily: TMPF_FIXED_PITCH is set for variable-pitch fonts
        tm_pitch = (face.pitch_family & 0xF0) | (0 if face.pitch_family & 3 == 1 else 1) | \
            (4 if truetype else 0)
        metrics = (struct.pack('<11i9B', height, ascent, height - ascent, 0, 0, average,
                               average * 2, face.weight, 0, 96, 96,
                               0x20, 0xFF, 0x1F, 0x20, 0, 0, 0, tm_pitch, 0)
                   + b'\x00' * 3 + struct.pack('<4I', 0x40 if truetype else 0,
                                               2048 if truetype else 0, 16, 6))
        return enum_logfont, metrics

    def EnumFontFamiliesA(self, args):
        """EnumFontFamiliesA emulation - common font families and the fonts
        added with AddFontResource"""
        hdc, lpszFamily, lpProc, lParam = args[:4]
        family = self.read_string(lpszFamily) if lpszFamily else None
        fonts = self._enumerated_fonts(family)
        log.debug(f"EnumFontFamilies/EnumFonts({family!r}): {len(fonts)} font(s)")
        if not fonts:
            return 1
        buffer = self.emu.heap_alloc(156 + 72)
        if not buffer:
            return 0
        result = 1
        try:
            for face in fonts:
                enum_logfont, metrics = self._enum_font_structs(face)
                self._mem_write(buffer, enum_logfont + metrics)
                result = self.emu.call_callback(lpProc, [buffer, buffer + 156, face.font_type,
                                                         lParam])
                if not result:
                    break
        finally:
            self.emu.heap_free(buffer)
        return result

    # EnumFontsA(hdc, lpFaceName, lpProc, lParam): the same callback arguments
    # (an ENUMLOGFONT starts with the LOGFONT)
    EnumFontsA = EnumFontFamiliesA

    def ValidateRect(self, args):
        """ValidateRect emulation - mark the window as painted"""
        hWnd = args[0]
        self.painted_windows.add(hWnd)
        self.paint_pending.discard(hWnd)
        self.update_rects.pop(hWnd, None)
        return 1
