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

"""WinAPIHandler mixin: more of gdi32 - window and viewport origins and
extents, regions, bitmap bits, Windows metafiles, text queries, and the
printing functions of a computer without printers"""

import math
import struct

from unicorn import UcError

from ..logger import log


class GdiExtraMixin:
    """Mapping (origins and extents), regions, bitmap bits, metafiles, text
    queries and printing"""

    # ---------- Mapping: logical -> device coordinates ----------

    MM_ISOTROPIC, MM_ANISOTROPIC = 7, 8
    # Logical units per inch of the fixed mapping modes (y grows upwards)
    MAP_MODE_UNITS = {2: 254, 3: 2540, 4: 100, 5: 1000, 6: 1440}  # LOMETRIC..TWIPS

    def _dc_mapping(self, hdc):
        """(window origin, viewport origin, x scale, y scale) of a DC's
        logical -> device transform, or None when they are the same"""
        state = self.dc_state.get(hdc)
        if not state:
            return None
        mode = state.get('map_mode', 1)
        window_org = state.get('window_org', (0, 0))
        viewport_org = state.get('viewport_org', (0, 0))
        if mode in self.MAP_MODE_UNITS:
            scale_x = 96 / self.MAP_MODE_UNITS[mode]
            scale_y = -scale_x
        elif mode in (self.MM_ISOTROPIC, self.MM_ANISOTROPIC):
            window_ext = state.get('window_ext', (1, 1))
            viewport_ext = state.get('viewport_ext', (1, 1))
            scale_x = viewport_ext[0] / (window_ext[0] or 1)
            scale_y = viewport_ext[1] / (window_ext[1] or 1)
            if mode == self.MM_ISOTROPIC:  # The same scale on both axes
                scale = min(abs(scale_x), abs(scale_y))
                scale_x, scale_y = math.copysign(scale, scale_x), math.copysign(scale, scale_y)
        else:  # MM_TEXT
            scale_x = scale_y = 1
        if window_org == viewport_org == (0, 0) and scale_x == scale_y == 1:
            return None
        return window_org, viewport_org, scale_x, scale_y

    def _lp_to_dp(self, hdc, x, y):
        mapping = self._dc_mapping(hdc)
        if mapping is None:
            return x, y
        (wx, wy), (vx, vy), sx, sy = mapping
        return int(round((x - wx) * sx + vx)), int(round((y - wy) * sy + vy))

    def _dp_to_lp(self, hdc, x, y):
        mapping = self._dc_mapping(hdc)
        if mapping is None:
            return x, y
        (wx, wy), (vx, vy), sx, sy = mapping
        return int(round((x - vx) / sx + wx)), int(round((y - vy) / sy + wy))

    def _map_shape(self, hdc, shape):
        """A shape drawn in logical coordinates, in device coordinates"""
        mapping = self._dc_mapping(hdc)
        if mapping is None:
            return shape
        (wx, wy), (vx, vy), sx, sy = mapping
        return self._scale_shape(shape, wx, wy, vx, vy, sx, sy)

    def _set_dc_pair(self, args, key, default, previous_ptr, only_modes=None):
        """SetXxxOrgEx/SetXxxExtEx: store (x, y), write the previous pair"""
        state = self.dc_state.get(args[0])
        if state is None:
            return 0
        previous = state.get(key, default)
        if previous_ptr and not self._mem_write(previous_ptr, struct.pack('<2i', *previous)):
            return 0
        x, y = self._read_signed_args(args, 1, 2)
        if only_modes is None or state.get('map_mode', 1) in only_modes:
            if key.endswith('_ext') and (x == 0 or y == 0):
                return 0
            state[key] = (x, y)
        return 1

    def _get_dc_pair(self, hdc, key, default, ptr):
        state = self.dc_state.get(hdc)
        if state is None or not ptr:
            return 0
        return 1 if self._mem_write(ptr, struct.pack('<2i', *state.get(key, default))) else 0

    def SetWindowOrgEx(self, args):
        """SetWindowOrgEx(hdc, x, y, lppt)"""
        return self._set_dc_pair(args, 'window_org', (0, 0), args[3])

    def SetViewportOrgEx(self, args):
        """SetViewportOrgEx(hdc, x, y, lppt)"""
        return self._set_dc_pair(args, 'viewport_org', (0, 0), args[3])

    def SetWindowExtEx(self, args):
        """SetWindowExtEx(hdc, x, y, lpsz) - only MM_ISOTROPIC and MM_ANISOTROPIC
        have extents the program sets"""
        return self._set_dc_pair(args, 'window_ext', (1, 1), args[3],
                                 (self.MM_ISOTROPIC, self.MM_ANISOTROPIC))

    def SetViewportExtEx(self, args):
        return self._set_dc_pair(args, 'viewport_ext', (1, 1), args[3],
                                 (self.MM_ISOTROPIC, self.MM_ANISOTROPIC))

    def GetWindowOrgEx(self, args):
        return self._get_dc_pair(args[0], 'window_org', (0, 0), args[1])

    def GetViewportOrgEx(self, args):
        return self._get_dc_pair(args[0], 'viewport_org', (0, 0), args[1])

    def GetWindowExtEx(self, args):
        return self._get_dc_pair(args[0], 'window_ext', (1, 1), args[1])

    def GetViewportExtEx(self, args):
        return self._get_dc_pair(args[0], 'viewport_ext', (1, 1), args[1])

    def OffsetViewportOrgEx(self, args):
        """OffsetViewportOrgEx(hdc, dx, dy, lppt)"""
        state = self.dc_state.get(args[0])
        if state is None:
            return 0
        x, y = state.get('viewport_org', (0, 0))
        dx, dy = self._read_signed_args(args, 1, 2)
        return self.SetViewportOrgEx([args[0], (x + dx) & 0xFFFFFFFF, (y + dy) & 0xFFFFFFFF,
                                      args[3]])

    def OffsetWindowOrgEx(self, args):
        state = self.dc_state.get(args[0])
        if state is None:
            return 0
        x, y = state.get('window_org', (0, 0))
        dx, dy = self._read_signed_args(args, 1, 2)
        return self.SetWindowOrgEx([args[0], (x + dx) & 0xFFFFFFFF, (y + dy) & 0xFFFFFFFF,
                                    args[3]])

    def ScaleViewportExtEx(self, args):
        """ScaleViewportExtEx(hdc, xNum, xDenom, yNum, yDenom, lpsz)"""
        state = self.dc_state.get(args[0])
        if state is None:
            return 0
        x_num, x_den, y_num, y_den = self._read_signed_args(args, 1, 4)
        if not x_den or not y_den:
            return 0
        x, y = state.get('viewport_ext', (1, 1))
        return self.SetViewportExtEx([args[0], (x * x_num // x_den) & 0xFFFFFFFF,
                                      (y * y_num // y_den) & 0xFFFFFFFF, args[5]])

    def _convert_points(self, args, convert):
        hdc, points, count = args[:3]
        if hdc not in self.dc_state:
            return 0
        if count >= 0x80000000:
            return 0
        try:
            values = struct.unpack(f'<{2 * count}i', self.emu.uc.mem_read(points, 8 * count))
        except UcError:
            return 0
        out = []
        for i in range(count):
            out += convert(hdc, values[2 * i], values[2 * i + 1])
        return 1 if self._mem_write(points, struct.pack(f'<{2 * count}i', *out)) else 0

    # ---------- Brush origin, background mode, visibility ----------

    def SetBrushOrgEx(self, args):
        """SetBrushOrgEx(hdc, x, y, lppt) - brushes are solid, so the origin
        changes nothing drawn"""
        return self._set_dc_pair(args, 'brush_org', (0, 0), args[3])

    def GetBrushOrgEx(self, args):
        return self._get_dc_pair(args[0], 'brush_org', (0, 0), args[1])

    def GetBkMode(self, args):
        state = self.dc_state.get(args[0])
        return state.get('bk_mode', 2) if state else 0  # OPAQUE

    def RectVisible(self, args):
        """RectVisible(hdc, lprect) - is part of the rectangle inside the clip
        region?"""
        rect = self._read_rect(args[1]) if args[1] else None
        if args[0] not in self.dc_state or rect is None:
            return 0
        clip = self._dc_clip(args[0])
        if clip is None:
            return 1
        left, top, right, bottom = rect
        return 1 if any(left < x2 and x1 < right and top < y2 and y1 < bottom
                        for x1, y1, x2, y2 in clip) else 0

    def GdiFlush(self, args):
        return 1

    def UnrealizeObject(self, args):
        """UnrealizeObject(h) - brushes and palettes need no realizing here"""
        return 1 if args[0] in self.gdi_objects else 0

    # OBJ_PEN .. OBJ_MEMDC by GDI object kind
    OBJECT_TYPES = {'pen': 1, 'brush': 2, 'palette': 5, 'font': 6, 'bitmap': 7, 'region': 8,
                    'metafile': 9}

    def GetObjectType(self, args):
        """GetObjectType(h) - OBJ_PEN, OBJ_BRUSH, OBJ_DC, ... (0 if invalid)"""
        state = self.dc_state.get(args[0])
        if state is not None:
            if state.get('metafile') is not None:
                return 4  # OBJ_METADC
            return 10 if state.get('memory') else 3  # OBJ_MEMDC / OBJ_DC
        obj = self.gdi_objects.get(args[0])
        kind = self.OBJECT_TYPES.get(obj['type']) if obj else None
        if kind is None:
            self._last_error = 6  # ERROR_INVALID_HANDLE
            return 0
        return kind

    # ---------- Regions ----------

    def _region(self, handle):
        region = self.gdi_objects.get(handle)
        return region if region is not None and region['type'] == 'region' else None

    def SetRectRgn(self, args):
        """SetRectRgn(hrgn, left, top, right, bottom)"""
        region = self._region(args[0])
        if region is None:
            return 0
        left, top, right, bottom = self._read_signed_args(args, 1, 4)
        left, right = min(left, right), max(left, right)
        top, bottom = min(top, bottom), max(top, bottom)
        region['rects'] = [(left, top, right, bottom)] if left < right and top < bottom else []
        return 1

    def OffsetRgn(self, args):
        """OffsetRgn(hrgn, x, y) - the kind of the moved region"""
        region = self._region(args[0])
        if region is None:
            return 0
        dx, dy = self._read_signed_args(args, 1, 2)
        region['rects'] = [(x1 + dx, y1 + dy, x2 + dx, y2 + dy)
                           for x1, y1, x2, y2 in region['rects']]
        return self._region_kind(region['rects'])

    def CreatePolygonRgn(self, args):
        """CreatePolygonRgn(lppt, cPoints, iMode): the pixel rows inside the
        polygon (ALTERNATE: odd crossings, WINDING: nonzero winding number)"""
        points_ptr, count, mode = args[:3]
        if count < 3 or count > 0x10000:
            return self._new_region([])
        try:
            values = struct.unpack(f'<{2 * count}i', self.emu.uc.mem_read(points_ptr, 8 * count))
        except UcError:
            return 0
        points = list(zip(values[0::2], values[1::2], strict=True))
        top, bottom = min(y for _, y in points), max(y for _, y in points)
        rects = []
        previous = None
        for y in range(top, bottom):
            center = y + 0.5
            crossings = []
            for (x1, y1), (x2, y2) in zip(points, points[1:] + points[:1], strict=True):
                if (y1 <= center < y2) or (y2 <= center < y1):
                    x = x1 + (center - y1) * (x2 - x1) / (y2 - y1)
                    crossings.append((x, 1 if y2 > y1 else -1))
            crossings.sort()
            spans, winding = [], 0
            for i, (x, direction) in enumerate(crossings[:-1]):
                winding += direction
                inside = winding != 0 if mode == 2 else (i % 2 == 0)
                if inside:
                    left, right = int(round(x)), int(round(crossings[i + 1][0]))
                    if left < right:
                        spans.append((left, right))
            if previous is not None and previous[0] == spans:
                previous[2] = y + 1  # The same spans as the row above: one band
                continue
            if previous is not None:
                rects += [(x1, previous[1], x2, previous[2]) for x1, x2 in previous[0]]
            previous = [spans, y, y + 1]
        if previous is not None:
            rects += [(x1, previous[1], x2, previous[2]) for x1, x2 in previous[0]]
        return self._new_region(rects)

    def FillRgn(self, args):
        """FillRgn(hdc, hrgn, hbr)"""
        region, brush = self._region(args[1]), self.gdi_objects.get(args[2])
        if args[0] not in self.dc_state or region is None or not brush or \
                brush['type'] != 'brush':
            return 0
        if brush.get('color') is not None:
            for rect in region['rects']:
                self._add_shape(args[0], {'type': 'rect', 'rect': rect, 'fill': brush['color'],
                                          'pen': None})
        return 1

    def InvertRgn(self, args):
        """InvertRgn(hdc, hrgn) - like InvertRect, nothing is redrawn inverted"""
        return 1 if args[0] in self.dc_state and self._region(args[1]) else 0

    # ---------- Bitmap bits and dimensions ----------

    def CreateBitmapIndirect(self, args):
        """CreateBitmapIndirect(lpbm) - a BITMAP structure's CreateBitmap"""
        try:
            _, width, height, _, planes, bpp, bits = struct.unpack(
                '<iiiiHHI', self.emu.uc.mem_read(args[0], 24))
        except UcError:
            return 0
        return self.CreateBitmap([width & 0xFFFFFFFF, height & 0xFFFFFFFF, planes, bpp, bits])

    def GetBitmapBits(self, args):
        """GetBitmapBits(hbm, cb, lpvBits): the bitmap's rows top-down, WORD
        aligned, in its own format (1 or 32 bits per pixel)"""
        hbm, size, buffer = args[:3]
        bmp = self.gdi_objects.get(hbm)
        if not bmp or bmp['type'] != 'bitmap':
            return 0
        width, height = bmp['width'], bmp['height']
        bpp = 1 if bmp.get('bpp') == 1 else 32
        word_stride = ((width * bpp + 15) // 16) * 2
        if not buffer:
            return word_stride * height
        dword_stride = ((width * bpp + 31) // 32) * 4
        info = self.emu.heap_alloc(40 + 8 + dword_stride * height)
        if not info:
            return 0
        try:
            header = struct.pack('<IiiHHIIiiII', 40, width, -height, 1, bpp, 0, 0, 0, 0, 0, 0)
            self._mem_write(info, header)
            bits = info + 48
            if not self.GetDIBits([0, hbm, 0, height, bits, info, 0]):
                return 0
            data = bytes(self.emu.uc.mem_read(bits, dword_stride * height))
        finally:
            self.emu.heap_free(info)
        rows = b''.join(data[r * dword_stride:r * dword_stride + word_stride]
                        for r in range(height))[:size]
        return len(rows) if self._mem_write(buffer, rows) else 0

    def SetBitmapBits(self, args):
        """SetBitmapBits(hbm, cb, lpBits) - new pixels in the bitmap's format"""
        hbm, size, bits = args[:3]
        bmp = self.gdi_objects.get(hbm)
        if not bmp or bmp['type'] != 'bitmap' or not bits:
            return 0
        bpp = 1 if bmp.get('bpp') == 1 else 32
        temp = self.CreateBitmap([bmp['width'], bmp['height'], 1, bpp, bits])
        if not temp:
            return 0
        bmp['shapes'] = self.gdi_objects.pop(temp)['shapes']
        stride = ((bmp['width'] * bpp + 15) // 16) * 2
        return min(size, stride * bmp['height'])

    def SetBitmapDimensionEx(self, args):
        """SetBitmapDimensionEx(hbm, x, y, lpsz) - a size in 0.1 mm the program
        keeps with the bitmap"""
        bmp = self.gdi_objects.get(args[0])
        if not bmp or bmp['type'] != 'bitmap':
            return 0
        previous = bmp.get('dimension', (0, 0))
        if args[3] and not self._mem_write(args[3], struct.pack('<2i', *previous)):
            return 0
        bmp['dimension'] = tuple(self._read_signed_args(args, 1, 2))
        return 1

    def GetBitmapDimensionEx(self, args):
        bmp = self.gdi_objects.get(args[0])
        if not bmp or bmp['type'] != 'bitmap' or not args[1]:
            return 0
        return 1 if self._mem_write(args[1], struct.pack('<2i', *bmp.get('dimension', (0, 0)))) \
            else 0

    def SetDIBitsToDevice(self, args):
        """SetDIBitsToDevice(hdc, xDest, yDest, w, h, xSrc, ySrc, uStartScan,
        cScanLines, lpvBits, lpbmi, ColorUse): StretchDIBits without scaling.
        The bits may hold a band of cScanLines rows from uStartScan (counted
        from the bottom of a bottom-up DIB)."""
        hdc, x, y, width, height, x_src, y_src, start, lines, bits, info, usage = args[:12]
        try:
            header = bytearray(self.emu.uc.mem_read(info, 40))
            hdr_size, dib_height = struct.unpack_from('<Ii', header)
        except UcError:
            return 0
        if hdr_size == 12:  # BITMAPCOREHEADER
            dib_height = struct.unpack_from('<H', header, 6)[0]
        total = abs(dib_height)
        if start == 0 and lines >= total:
            result = self.StretchDIBits([hdc, x, y, width, height, x_src, y_src, width, height,
                                         bits, info, usage, self.SRCCOPY])
            return lines if result else 0
        # A band: a copy of the header for just its rows
        if hdr_size == 12:
            return 0
        lines = min(lines, max(0, total - start))
        band = self.emu.heap_alloc(hdr_size + 1024)
        if not band or not lines:
            return 0
        try:
            data = bytearray(self.emu.uc.mem_read(info, hdr_size + 1024))
            struct.pack_into('<i', data, 8, lines if dib_height > 0 else -lines)
            self._mem_write(band, bytes(data))
            x_dest, y_dest = self._read_signed_args([x, y], 0, 2)
            # Rows of the band in top-down picture coordinates
            band_top = total - start - lines if dib_height > 0 else start
            self.StretchDIBits([hdc, x_dest & 0xFFFFFFFF,
                                (y_dest + band_top - y_src) & 0xFFFFFFFF, width, lines,
                                x_src, 0, width, lines, bits, band, usage, self.SRCCOPY])
        finally:
            self.emu.heap_free(band)
        return lines

    # ---------- Text queries ----------

    def GetTextFaceA(self, args, wide=False):
        """GetTextFaceA/W(hdc, c, lpName) - the face name of the DC's font"""
        hdc, count, buffer = args[:3]
        if hdc not in self.dc_state:
            return 0
        font = self._dc_font(hdc)
        face = (font.get('face') if font else None) or 'System'
        if not buffer:
            return len(face) + 1
        if count <= 0:
            return 0
        face = face[:count - 1]
        self._write_text(buffer, face, wide)
        return len(face) + 1

    def GetTextFaceW(self, args):
        return self.GetTextFaceA(args, wide=True)

    def GetKerningPairsA(self, args):
        """GetKerningPairsA/W(hdc, nPairs, lpkrnpair) - the fonts drawn here
        have no kerning pairs"""
        return 0

    GetKerningPairsW = GetKerningPairsA

    def GetOutlineTextMetricsA(self, args):
        """GetOutlineTextMetricsA/W - fails like for a raster font: the fonts
        are drawn with the desktop's own fonts, which have no TrueType data"""
        return 0

    GetOutlineTextMetricsW = GetOutlineTextMetricsA

    def GetGlyphOutlineA(self, args):
        """GetGlyphOutlineA/W - no glyph outlines (GDI_ERROR)"""
        return self.GDI_ERROR

    GetGlyphOutlineW = GetGlyphOutlineA

    # (character set, ANSI code page, bit of FONTSIGNATURE.fsCsb[0])
    CHARSETS = [(0, 1252, 0), (238, 1250, 1), (204, 1251, 2), (161, 1253, 3),
                (162, 1254, 4), (177, 1255, 5), (178, 1256, 6), (186, 1257, 7),
                (163, 1258, 8), (222, 874, 16), (128, 932, 17), (134, 936, 18),
                (129, 949, 19), (136, 950, 20), (130, 1361, 21), (2, 42, 31)]
    TCI_SRCCHARSET, TCI_SRCCODEPAGE, TCI_SRCFONTSIG = 1, 2, 3

    def TranslateCharsetInfo(self, args):
        """TranslateCharsetInfo(lpSrc, lpCs, dwFlags) - CHARSETINFO
        (ciCharset, ciACP, FONTSIGNATURE) of a character set, code page
        (lpSrc is the value itself) or font signature (lpSrc: its fsCsb)"""
        source, out, flags = args[:3]
        if flags == self.TCI_SRCFONTSIG:
            try:
                source = struct.unpack('<I', self.emu.uc.mem_read(source, 4))[0]
            except UcError:
                return 0
            found = [entry for entry in self.CHARSETS if source & (1 << entry[2])]
        else:
            column = {self.TCI_SRCCHARSET: 0, self.TCI_SRCCODEPAGE: 1}.get(flags)
            found = [entry for entry in self.CHARSETS
                     if column is not None and entry[column] == source]
        if not found or not out:
            return 0
        charset, codepage, bit = found[0]
        return 1 if self._mem_write(out, struct.pack('<II4I2I', charset, codepage,
                                                     0, 0, 0, 0, 1 << bit, 0)) else 0

    # ---------- Printing: the computer has no printer ----------

    SP_ERROR = 0xFFFFFFFF

    def CreateICA(self, args):
        """CreateICA(driver, device, port, devmode) - an information context
        is a DC that is not drawn on"""
        return self.CreateDCA(args)

    def ResetDCA(self, args):
        """ResetDCA/W(hdc, lpdm) - the DC is unchanged"""
        return args[0] if args[0] in self.dc_state else 0

    ResetDCW = ResetDCA

    def StartDocA(self, args):
        """StartDocA/W(hdc, lpdi) - SP_ERROR: the DC is no printer's"""
        self._last_error = 6  # ERROR_INVALID_HANDLE
        return self.SP_ERROR

    StartDocW = StartDocA

    def EndDoc(self, args):
        return self.SP_ERROR

    def StartPage(self, args):
        return self.SP_ERROR

    def EndPage(self, args):
        return self.SP_ERROR

    def AbortDoc(self, args):
        return self.SP_ERROR

    def SetAbortProc(self, args):
        return self.SP_ERROR

    QUERYESCSUPPORT = 8

    def Escape(self, args):
        """Escape(hdc, nEscape, cbInput, lpvIn, lpvOut) - no printer escapes:
        0 (not implemented), also for QUERYESCSUPPORT"""
        return 0

    def ExtEscape(self, args):
        """ExtEscape(hdc, iEscape, cjInput, lpInData, cjOutput, lpOutData)"""
        return 0

    # ---------- Windows metafiles ----------

    META_EOF = 0
    WMF_HEADER = struct.Struct('<HHHIHIH')  # type, header size, version, size, objects, max

    def CreateMetaFileA(self, args, wide=False):
        """CreateMetaFileA/W(pszFile): a memory DC that records what is drawn"""
        name = self._read_text(args[0], wide) if args[0] else None
        hdc = self.CreateCompatibleDC([0])
        if hdc:
            self.dc_state[hdc]['metafile'] = {'file': name}
        return hdc

    def CreateMetaFileW(self, args):
        return self.CreateMetaFileA(args, wide=True)

    def _wmf_bytes(self, records=b'', objects=0):
        """A WMF: header, records and the EOF record"""
        body = records + struct.pack('<IH', 3, self.META_EOF)
        size = (18 + len(body)) // 2
        return self.WMF_HEADER.pack(1, 9, 0x300, size, objects, 3, 0) + body

    def CloseMetaFile(self, args):
        """CloseMetaFile(hdc) - the HMETAFILE of what was drawn; the shapes are
        played back by PlayMetaFile, the file gets an empty WMF (the
        records are not written)"""
        state = self.dc_state.get(args[0])
        if not state or state.get('metafile') is None:
            return 0
        info = state['metafile']
        shapes = list(state.get('shapes', []))
        self._delete_dc(args[0])
        data = self._wmf_bytes()
        if info['file']:
            path = self.resolve_drive_path(info['file'])
            try:
                if path is None or self._write_protected(path):
                    raise OSError
                with open(path, 'wb') as f:
                    f.write(data)
            except OSError:
                return 0
        handle = self.get_next_handle()
        self.gdi_objects[handle] = {'type': 'metafile', 'shapes': shapes, 'bits': data}
        return handle

    def SetMetaFileBitsEx(self, args):
        """SetMetaFileBitsEx(cbBuffer, lpData) - an HMETAFILE of WMF bits"""
        try:
            data = bytes(self.emu.uc.mem_read(args[1], args[0]))
        except UcError:
            return 0
        if len(data) < 18:
            return 0
        handle = self.get_next_handle()
        self.gdi_objects[handle] = {'type': 'metafile', 'shapes': None, 'bits': data}
        return handle

    def GetMetaFileBitsEx(self, args):
        """GetMetaFileBitsEx(hmf, cbBuffer, lpData) - the WMF's size, or a copy"""
        meta = self.gdi_objects.get(args[0])
        if not meta or meta['type'] != 'metafile':
            return 0
        data = meta['bits']
        if not args[2]:
            return len(data)
        if args[1] < len(data):
            return 0
        return len(data) if self._mem_write(args[2], data) else 0

    def DeleteMetaFile(self, args):
        meta = self.gdi_objects.get(args[0])
        if not meta or meta['type'] != 'metafile':
            return 0
        del self.gdi_objects[args[0]]
        return 1

    def _wmf_records(self, data):
        """[(offset, size in bytes, function, parameter WORDs)] of a WMF"""
        if len(data) < 18:
            return []
        header_words = struct.unpack_from('<H', data, 2)[0]
        position = header_words * 2
        records = []
        while position + 6 <= len(data):
            size_words, function = struct.unpack_from('<IH', data, position)
            if size_words < 3 or position + size_words * 2 > len(data):
                break
            words = struct.unpack_from(f'<{size_words - 3}H', data, position + 6)
            records.append((position, size_words * 2, function, words))
            if function == self.META_EOF:
                break
            position += size_words * 2
        return records

    @staticmethod
    def _wmf_signed(value):
        return value - 0x10000 if value >= 0x8000 else value

    def _play_wmf_record(self, hdc, function, words, table):
        """Draw one WMF record on hdc; table: the metafile's object slots"""
        s = self._wmf_signed
        u32 = lambda v: v & 0xFFFFFFFF  # noqa: E731

        def add_object(handle):
            slot = next((i for i, h in enumerate(table) if h is None), len(table))
            if slot == len(table):
                table.append(handle)
            else:
                table[slot] = handle

        def with_buffer(data, call):
            buffer = self.emu.heap_alloc(max(len(data), 1))
            if not buffer:
                return
            try:
                self._mem_write(buffer, data)
                call(buffer)
            finally:
                self.emu.heap_free(buffer)

        def points(count, offset):
            values = [s(w) for w in words[offset:offset + 2 * count]]
            return struct.pack(f'<{len(values)}i', *values)

        if function == 0x020B:  # META_SETWINDOWORG (y, x)
            self.SetWindowOrgEx([hdc, u32(s(words[1])), u32(s(words[0])), 0])
        elif function == 0x020C:  # META_SETWINDOWEXT
            self.SetWindowExtEx([hdc, u32(s(words[1])), u32(s(words[0])), 0])
        elif function == 0x020D:  # META_SETVIEWPORTORG
            self.SetViewportOrgEx([hdc, u32(s(words[1])), u32(s(words[0])), 0])
        elif function == 0x020E:  # META_SETVIEWPORTEXT
            self.SetViewportExtEx([hdc, u32(s(words[1])), u32(s(words[0])), 0])
        elif function == 0x0103:  # META_SETMAPMODE
            self.SetMapMode([hdc, words[0]])
        elif function == 0x0102:  # META_SETBKMODE
            self.SetBkMode([hdc, words[0]])
        elif function == 0x0201:  # META_SETBKCOLOR
            self.SetBkColor([hdc, words[0] | (words[1] << 16)])
        elif function == 0x0209:  # META_SETTEXTCOLOR
            self.SetTextColor([hdc, words[0] | (words[1] << 16)])
        elif function == 0x0214:  # META_MOVETO (y, x)
            self.MoveToEx([hdc, u32(s(words[1])), u32(s(words[0])), 0])
        elif function == 0x0213:  # META_LINETO
            self.LineTo([hdc, u32(s(words[1])), u32(s(words[0]))])
        elif function in (0x041B, 0x0418):  # META_RECTANGLE, META_ELLIPSE (b, r, t, l)
            call = self.Rectangle if function == 0x041B else self.Ellipse
            call([hdc] + [u32(s(w)) for w in (words[3], words[2], words[1], words[0])])
        elif function in (0x0324, 0x0325):  # META_POLYGON, META_POLYLINE
            count = words[0]
            call = self.Polygon if function == 0x0324 else self.Polyline
            with_buffer(points(count, 1), lambda p: call([hdc, p, count]))
        elif function == 0x0521:  # META_TEXTOUT: count, string, y, x
            count = words[0]
            raw = struct.pack(f'<{len(words)}H', *words)[2:2 + count]
            y_word = 1 + (count + 1) // 2
            if len(words) > y_word + 1:
                y, x = s(words[y_word]), s(words[y_word + 1])
                with_buffer(raw, lambda p: self.TextOutA([hdc, u32(x), u32(y), p, count]))
        elif function == 0x0A32:  # META_EXTTEXTOUT: y, x, count, options[, rect], string
            y, x, count, options = s(words[0]), s(words[1]), words[2], words[3]
            offset = 4 + (4 if options & 0x6 else 0)  # ETO_OPAQUE | ETO_CLIPPED
            raw = struct.pack(f'<{len(words)}H', *words)[offset * 2:offset * 2 + count]
            with_buffer(raw, lambda p: self.TextOutA([hdc, u32(x), u32(y), p, count]))
        elif function == 0x02FA:  # META_CREATEPENINDIRECT: style, width (POINT), color
            add_object(self.CreatePen([words[0], s(words[1]) & 0xFFFFFFFF,
                                       words[3] | (words[4] << 16)]))
        elif function == 0x02FC:  # META_CREATEBRUSHINDIRECT: style, color, hatch
            style, color = words[0], words[1] | (words[2] << 16)
            add_object(self.GetStockObject([5]) if style == 1 else
                       self.CreateSolidBrush([color]))
        elif function == 0x02FB:  # META_CREATEFONTINDIRECT: a LOGFONT16
            raw = struct.pack(f'<{len(words)}H', *words)
            height, width, escapement, orientation, weight = struct.unpack_from('<5h', raw)
            logfont = struct.pack('<5i', height, width, escapement, orientation, weight) + \
                raw[10:18] + raw[18:50].split(b'\x00')[0][:31].ljust(32, b'\x00')
            with_buffer(logfont, lambda p: add_object(self.CreateFontIndirectA([p])))
        elif function == 0x00F7:  # META_CREATEPALETTE: a placeholder slot
            add_object(self.GetStockObject([15]))
        elif function == 0x012D:  # META_SELECTOBJECT
            if words[0] < len(table) and table[words[0]]:
                self.SelectObject([hdc, table[words[0]]])
        elif function == 0x01F0:  # META_DELETEOBJECT
            if words[0] < len(table) and table[words[0]]:
                self.DeleteObject([table[words[0]]])
                table[words[0]] = None
        elif function in (0x0F43, 0x0B41):  # META_STRETCHDIB, META_DIBSTRETCHBLT
            raw = struct.pack(f'<{len(words)}H', *words)
            if function == 0x0F43:  # rop, usage, srcH, srcW, srcY, srcX, h, w, y, x, DIB
                rop = words[0] | (words[1] << 16)
                (src_h, src_w, src_y, src_x, h, w, y, x) = (s(v) for v in words[3:11])
                dib, usage = raw[22:], words[2]
            else:  # rop, srcY, srcX, h, w, y, x, DIB (no srcW/srcH: the DIB's size)
                rop = words[0] | (words[1] << 16)
                (src_h, src_w, src_y, src_x, h, w, y, x) = (s(v) for v in words[2:10])
                dib, usage = raw[20:], 0
            if len(dib) >= 40:
                header_size = struct.unpack_from('<I', dib)[0]
                bpp = struct.unpack_from('<H', dib, 14)[0] if header_size >= 40 else 0
                colors = struct.unpack_from('<I', dib, 32)[0] if header_size >= 40 else 0
                table_size = 4 * (colors or (1 << bpp if bpp <= 8 else 0))
                bits_offset = header_size + table_size

                def stretch(p):
                    self.StretchDIBits([hdc] + [u32(v) for v in (x, y, w, h, src_x, src_y,
                                                                  src_w, src_h)] +
                                       [p + bits_offset, p, usage, rop])
                with_buffer(dib, stretch)

    def _play_metafile(self, hdc, meta):
        """Draw a metafile: the recorded shapes, or its WMF records"""
        if meta['shapes'] is not None:
            for shape in meta['shapes']:
                self._add_shape(hdc, shape)
            return
        table = []
        state = dict(self.dc_state[hdc])
        for _, _, function, words in self._wmf_records(meta['bits']):
            try:
                self._play_wmf_record(hdc, function, words, table)
            except (IndexError, struct.error) as e:
                log.debug(f"PlayMetaFile: bad record 0x{function:04x}: {e}")
        for handle in table:  # Objects the metafile did not delete
            if handle:
                self.DeleteObject([handle])
        # Playing leaves the DC's selected objects and mapping as they were
        self.dc_state[hdc].update(state)

    def PlayMetaFile(self, args):
        """PlayMetaFile(hdc, hmf)"""
        meta = self.gdi_objects.get(args[1])
        if args[0] not in self.dc_state or not meta or meta['type'] != 'metafile':
            return 0
        self._play_metafile(args[0], meta)
        return 1

    def EnumMetaFile(self, args):
        """EnumMetaFile(hdc, hmf, proc, lParam): proc(hdc, lpHTable, lpMR,
        nObj, lParam) for each record, which it may play with
        PlayMetaFileRecord"""
        hdc, hmf, proc, lparam = args[:4]
        meta = self.gdi_objects.get(hmf)
        if not meta or meta['type'] != 'metafile' or not proc:
            return 0
        data = meta['bits']
        objects = max(1, struct.unpack_from('<H', data, 10)[0]) if len(data) >= 18 else 1
        block = self.emu.heap_alloc(len(data) + 4 * objects)
        if not block:
            return 0
        table_ptr = block + len(data)
        self._mem_write(block, data + b'\x00' * (4 * objects))
        self._metafile_tables[table_ptr] = [None] * objects
        result = 1
        try:
            for offset, _, function, _ in self._wmf_records(data):
                if function == self.META_EOF:
                    break
                result = self.emu.call_callback(proc, [hdc, table_ptr, block + offset, objects,
                                                       lparam])
                if not result:
                    break
        finally:
            for handle in self._metafile_tables.pop(table_ptr, []):
                if handle:
                    self.DeleteObject([handle])
            self.emu.heap_free(block)
        return 1 if result else 0

    def PlayMetaFileRecord(self, args):
        """PlayMetaFileRecord(hdc, lpHandleTable, lpMR, noObjs)"""
        hdc, table_ptr, record = args[:3]
        if hdc not in self.dc_state:
            return 0
        try:
            size_words, function = struct.unpack('<IH', self.emu.uc.mem_read(record, 6))
            words = struct.unpack(f'<{max(0, size_words - 3)}H',
                                  self.emu.uc.mem_read(record + 6, max(0, size_words - 3) * 2))
        except (UcError, struct.error):
            return 0
        table = self._metafile_tables.setdefault(table_ptr, [None] * args[3])
        try:
            self._play_wmf_record(hdc, function, words, table)
        except (IndexError, struct.error):
            return 0
        # The slots the program can see hold the object handles
        self._mem_write(table_ptr, struct.pack(f'<{len(table)}I', *(h or 0 for h in table)))
        return 1

    # ---------- DIB sections: bitmaps whose pixels the program writes ----------

    def CreateDIBSection(self, args):
        """CreateDIBSection(hdc, pbmi, usage, ppvBits, hSection, offset) - a
        bitmap whose pixels are in memory the program writes to. The picture
        is read from that memory again whenever the bitmap is copied (what
        GDI draws on it stays in its display list, not in the memory)."""
        hdc, info, usage, out = args[:4]
        try:
            hdr_size, width, height, bpp, compression, colors = self._read_dib_header(info)
        except UcError:
            return 0
        if width <= 0 or height == 0 or bpp not in (1, 4, 8, 16, 24, 32) or \
                compression not in (0, 3):
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0
        stride = ((width * bpp + 31) // 32) * 4
        quad = 3 if hdr_size == 12 else 4
        table = (colors or (1 << bpp)) * (2 if usage == 1 else quad) if bpp <= 8 else \
            (12 if compression == 3 else 0)
        header = bytes(self.emu.uc.mem_read(info, hdr_size + table))
        bits = self.emu.heap_alloc(stride * abs(height))
        if not bits:
            return 0
        self._mem_write(bits, b'\x00' * (stride * abs(height)))
        handle = self._new_bitmap(width, abs(height), 32 if bpp > 1 else 1)
        self.gdi_objects[handle]['dib'] = {'bits': bits, 'size': stride * abs(height),
                                           'header': header, 'usage': usage, 'hdc': hdc,
                                           'snapshot': None}
        if out:
            self._mem_write(out, struct.pack('<I', bits))
        self._refresh_dib_section(handle)
        return handle

    def _refresh_dib_section(self, hbm):
        """A DIB section's picture from its memory, if the program changed it"""
        bmp = self.gdi_objects.get(hbm)
        dib = bmp.get('dib') if bmp else None
        if dib is None:
            return
        try:
            bits = bytes(self.emu.uc.mem_read(dib['bits'], dib['size']))
        except UcError:
            return
        if bits == dib['snapshot']:
            return
        dib['snapshot'] = bits
        info = self.emu.heap_alloc(len(dib['header']))
        if not info:
            return
        try:
            self._mem_write(info, dib['header'])
            decoded = self._read_dib(dib['hdc'], info, dib['bits'], dib['usage'])
        finally:
            self.emu.heap_free(info)
        if decoded is None:
            return
        width, height, rgb, _ = decoded
        image = {'type': 'image', 'pos': (0, 0), 'dim': (width, height),
                 'size': (width, height), 'data': rgb, 'rop': self.SRCCOPY}
        bmp['shapes'] = [image]
        for state in self.dc_state.values():
            if state.get('memory') and state.get('bitmap') == hbm:
                state['shapes'] = [image]

    def _refresh_dc_dib_section(self, hdc):
        state = self.dc_state.get(hdc)
        if state and state.get('memory') and state.get('bitmap'):
            self._refresh_dib_section(state['bitmap'])

    # ---------- Palettes ----------

    def CreateHalftonePalette(self, args):
        """CreateHalftonePalette(hdc) - the 20 static colors and a 6x6x6 cube
        with grays (256 entries)"""
        cube = [(r * 51, g * 51, b * 51) for r in range(6) for g in range(6) for b in range(6)]
        grays = [(gray, gray, gray) for gray in range(8, 248, 8)][:256 - 20 - len(cube)]
        colors = list(self.DEFAULT_PALETTE_COLORS[:10]) + cube + grays + \
            list(self.DEFAULT_PALETTE_COLORS[10:])
        handle = self.get_next_handle()
        self.gdi_objects[handle] = {'type': 'palette', 'entries': [(r, g, b, 0)
                                                                   for r, g, b in colors]}
        return handle

    def _palette(self, handle):
        palette = self.gdi_objects.get(handle)
        return palette if palette is not None and palette['type'] == 'palette' else None

    def GetPaletteEntries(self, args):
        """GetPaletteEntries(hpal, iStart, cEntries, pPalEntries) - entries
        copied, or with no buffer the palette's size"""
        palette = self._palette(args[0])
        if palette is None:
            return 0
        entries = palette['entries']
        if not args[3]:
            return len(entries)
        chosen = entries[args[1]:args[1] + args[2]]
        data = b''.join(bytes(entry[:4]) for entry in chosen)
        return len(chosen) if self._mem_write(args[3], data) else 0

    def GetNearestPaletteIndex(self, args):
        """GetNearestPaletteIndex(hpal, color)"""
        palette = self._palette(args[0])
        if palette is None or not palette['entries']:
            return 0xFFFFFFFF  # CLR_INVALID
        r, g, b = args[1] & 0xFF, (args[1] >> 8) & 0xFF, (args[1] >> 16) & 0xFF
        return min(range(len(palette['entries'])),
                   key=lambda i: (palette['entries'][i][0] - r) ** 2 +
                   (palette['entries'][i][1] - g) ** 2 + (palette['entries'][i][2] - b) ** 2)

    def GetSystemPaletteEntries(self, args):
        """GetSystemPaletteEntries(hdc, iStart, cEntries, pPalEntries) - 0:
        the display has 32 bits per pixel, not a palette"""
        return 0

    def GetSystemPaletteUse(self, args):
        return 1  # SYSPAL_STATIC

    # ---------- Current objects and text ----------

    def GetCurrentObject(self, args):
        """GetCurrentObject(hdc, type): OBJ_PEN, OBJ_BRUSH, OBJ_PAL, OBJ_FONT,
        OBJ_BITMAP"""
        state = self.dc_state.get(args[0])
        kind = {1: 'pen', 2: 'brush', 5: 'palette', 6: 'font', 7: 'bitmap'}.get(args[1])
        if state is None or kind is None:
            return 0
        if kind == 'palette':
            return state.get('palette') or self.GetStockObject([15])
        return state.get(kind) or self._dc_default_objects()[kind]

    def SetTextCharacterExtra(self, args):
        """SetTextCharacterExtra(hdc, extra) - the previous extra spacing (kept,
        text is drawn without it)"""
        state = self.dc_state.get(args[0])
        if state is None:
            return 0x80000000
        previous = state.get('char_extra', 0)
        state['char_extra'] = self._read_signed_args(args, 1, 1)[0]
        return previous & 0xFFFFFFFF

    def GetTextCharacterExtra(self, args):
        state = self.dc_state.get(args[0])
        return state.get('char_extra', 0) & 0xFFFFFFFF if state is not None else 0x80000000

    def GetTextExtentExPointA(self, args, wide=False):
        """GetTextExtentExPointA/W(hdc, lpszString, cchString, nMaxExtent,
        lpnFit, lpnDx, lpSize): the size of the text, how many characters fit
        in nMaxExtent and the extent after each character"""
        hdc, text_ptr, count, max_extent, fit_ptr, dx_ptr, size_ptr = args[:7]
        if hdc not in self.dc_state:
            return 0
        text = self._read_text(text_ptr, wide)[:count] if text_ptr and count else ''
        extents = [self._text_extent(hdc, text[:i + 1])[0] for i in range(len(text))]
        _, height = self._text_extent(hdc, text or ' ')
        if fit_ptr:
            limit = max_extent if max_extent < 0x80000000 else -1
            fit = sum(1 for extent in extents if extent <= limit) if limit >= 0 else 0
            self._mem_write(fit_ptr, struct.pack('<i', fit))
        if dx_ptr and extents:
            self._mem_write(dx_ptr, struct.pack(f'<{len(extents)}i', *extents))
        if size_ptr:
            self._mem_write(size_ptr, struct.pack('<ii', extents[-1] if extents else 0, height))
        return 1

    def GetTextExtentExPointW(self, args):
        return self.GetTextExtentExPointA(args, wide=True)

    # ---------- Metafiles from files, enhanced metafiles ----------

    WMF_PLACEABLE_KEY = 0x9AC6CDD7

    def GetMetaFileA(self, args, wide=False):
        """GetMetaFileA/W(lpszFile) - an HMETAFILE of a .WMF file (a placeable
        metafile's 22-byte header is skipped)"""
        name = self._read_text(args[0], wide) if args[0] else ''
        host = self.resolve_drive_path(name) if name else None
        try:
            with open(host, 'rb') as f:
                data = f.read()
        except (OSError, TypeError):
            self._last_error = 2  # ERROR_FILE_NOT_FOUND
            return 0
        if len(data) >= 22 and struct.unpack_from('<I', data)[0] == self.WMF_PLACEABLE_KEY:
            data = data[22:]
        if len(data) < 18:
            return 0
        handle = self.get_next_handle()
        self.gdi_objects[handle] = {'type': 'metafile', 'shapes': None, 'bits': data}
        return handle

    def GetMetaFileW(self, args):
        return self.GetMetaFileA(args, wide=True)

    def SetWinMetaFileBits(self, args):
        """SetWinMetaFileBits(nSize, lpMeta16Data, hdcRef, lpMFP) - an
        enhanced metafile handle playing the Windows metafile"""
        try:
            data = bytes(self.emu.uc.mem_read(args[1], args[0]))
        except UcError:
            return 0
        if len(data) < 18:
            return 0
        handle = self.get_next_handle()
        self.gdi_objects[handle] = {'type': 'enhmetafile', 'wmf': data}
        return handle

    def GetEnhMetaFileA(self, args, wide=False):
        """GetEnhMetaFileA/W(lpszMetaFile) - an .EMF file's handle (it is not
        drawn: only Windows metafiles are played)"""
        name = self._read_text(args[0], wide) if args[0] else ''
        host = self.resolve_drive_path(name) if name else None
        try:
            with open(host, 'rb') as f:
                data = f.read()
        except (OSError, TypeError):
            self._last_error = 2  # ERROR_FILE_NOT_FOUND
            return 0
        if len(data) < 88 or struct.unpack_from('<I', data)[0] != 1:  # EMR_HEADER
            self._last_error = 2003  # ERROR_INVALID_ENHANCED_METAFILE: not an EMF
            return 0
        handle = self.get_next_handle()
        self.gdi_objects[handle] = {'type': 'enhmetafile', 'emf': data}
        return handle

    def GetEnhMetaFileW(self, args):
        return self.GetEnhMetaFileA(args, wide=True)

    def DeleteEnhMetaFile(self, args):
        meta = self.gdi_objects.get(args[0])
        if not meta or meta['type'] != 'enhmetafile':
            return 0
        del self.gdi_objects[args[0]]
        return 1

    def GetEnhMetaFilePaletteEntries(self, args):
        """GetEnhMetaFilePaletteEntries(hemf, cEntries, lppe) - no palette"""
        meta = self.gdi_objects.get(args[0])
        return 0 if meta and meta['type'] == 'enhmetafile' else 0xFFFFFFFF

    def PlayEnhMetaFile(self, args):
        """PlayEnhMetaFile(hdc, hemf, lprect) - a Windows metafile (from
        SetWinMetaFileBits) is played scaled into the rectangle"""
        hdc, meta = args[0], self.gdi_objects.get(args[1])
        if hdc not in self.dc_state or not meta or meta['type'] != 'enhmetafile':
            return 0
        if 'wmf' not in meta:
            log.debug("PlayEnhMetaFile: enhanced metafile records are not drawn")
            return 1
        rect = self._read_rect(args[2]) if args[2] else None
        state = self.dc_state[hdc]
        saved = {key: state.get(key) for key in ('map_mode', 'window_org', 'window_ext',
                                                  'viewport_org', 'viewport_ext')}
        if rect is not None:
            left, top, right, bottom = rect
            state.update({'map_mode': self.MM_ANISOTROPIC, 'viewport_org': (left, top),
                          'viewport_ext': (right - left or 1, bottom - top or 1),
                          'window_org': (0, 0), 'window_ext': (right - left or 1,
                                                               bottom - top or 1)})
        self._play_metafile(hdc, {'shapes': None, 'bits': meta['wmf']})
        for key, value in saved.items():
            if value is None:
                state.pop(key, None)
            else:
                state[key] = value
        return 1
