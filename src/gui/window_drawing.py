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

"""PseudoWindowsGUI mixin: Top-level window frames, title bars, display list shapes, menu bars,
dropdowns"""


from .. import winapi
from ..config import PYGAME_AVAILABLE
from .font_cache import CachedFont

if PYGAME_AVAILABLE:
    import pygame


class WindowDrawingMixin:
    """Top-level window frames, title bars, display list shapes, menu bars, dropdowns"""

    def _draw_window_frame(self, window, border):
        """Soft shadow, face and the classic raised frame of a top-level window
        (a 1-pixel border is a plain dark line)"""
        frame_rect = pygame.Rect(window.x, window.y, window.width, window.height)
        if not window.maximized:
            self._draw_shadow(frame_rect)
        pygame.draw.rect(self.screen, self.COLOR_WINDOW_BG, frame_rect)
        if border > 1:
            self._draw_raised(frame_rect)
        else:
            pygame.draw.rect(self.screen, self.COLOR_BUTTON_BORDER_DARK, frame_rect, 1)

    def _draw_window(self, window):
        """Draw window"""
        if not window.visible or window.minimized:
            return

        is_active = (window.hwnd == self.active_window)
        border, caption = self.window_frame(window)

        if border:
            self._draw_window_frame(window, border)

        if caption:
            self._draw_title_bar(window, is_active)

        # Menu bar (between title bar and client area)
        if window.menu:
            self._draw_menu_bar(window)

        # Content area
        client_x, client_y = self.client_origin(window)
        client_w, client_h = self.client_size(window)
        content_rect = pygame.Rect(client_x, client_y, client_w, client_h)
        pygame.draw.rect(self.screen, window.dialog_brush or window.bg_color, content_rect)

        # Clip client-area drawing to the window (GDI shapes may overflow)
        self.screen.set_clip(content_rect)

        # Render GDI shapes and texts (Rectangle, Ellipse, TextOut, ...)
        for shape in window.drawn_shapes:
            self._draw_shape(shape, client_x, client_y)

        if getattr(window, 'messagebox_icon', 0):
            self._draw_messagebox_icon(window.messagebox_icon, client_x + 20, client_y + 18)

        # Draw controls
        for control in window.controls:
            self._draw_control(control, client_x, client_y)

        self._draw_child_windows(window)

        self.screen.set_clip(None)

    CAPTION_BTN_W = 18
    CAPTION_BTN_H = 16

    def _title_rect(self, window):
        """Screen rect of a window's title bar (inside the frame, a 1-pixel gap
        above the menu bar or the client area)"""
        border, caption = (self.BORDER, self.TITLE_BAR_H) if window.hwnd in self.consoles \
            else self.window_frame(window)
        return pygame.Rect(window.x + border, window.y + border,
                           window.width - 2 * border, caption - 1)

    def _caption_button_rects(self, window):
        """{'close' / 'max' / 'min': screen rect} of a window's caption buttons;
        dialogs only have the close button. Drawing and clicks both use these."""
        bar = self._title_rect(window)
        w, h = self.CAPTION_BTN_W, self.CAPTION_BTN_H
        y = bar.y + (bar.height - h) // 2
        close = pygame.Rect(bar.right - 2 - w, y, w, h)
        rects = {'close': close}
        if not window.is_dialog and not self._popup_without_size_boxes(window):
            # Maximize and minimize sit together, two pixels left of close
            rects['max'] = pygame.Rect(close.x - 2 - w, y, w, h)
            rects['min'] = pygame.Rect(close.x - 2 - 2 * w, y, w, h)
        return rects

    WS_MINIMIZEBOX, WS_MAXIMIZEBOX = 0x20000, 0x10000  # (WS_POPUP: PseudoWindowsGUI)

    def _popup_without_size_boxes(self, window):
        """A program's popup window without WS_MINIMIZEBOX and WS_MAXIMIZEBOX
        (a dialog it made itself, such as Word's): only the close button"""
        return (window.owner is not None and window.style & self.WS_POPUP and
                not window.style & (self.WS_MINIMIZEBOX | self.WS_MAXIMIZEBOX))

    def _draw_title_bar(self, window, is_active):
        """Draw a window's caption: a gradient bar, the program icon, the title
        and the caption buttons"""
        bar = self._title_rect(window)
        if is_active:
            colors = (self.COLOR_TITLE_BAR, self.COLOR_TITLE_BAR_GRADIENT)
            text_color = self.COLOR_TITLE_TEXT
        else:
            colors = (self.COLOR_TITLE_BAR_INACTIVE, self.COLOR_TITLE_BAR_INACTIVE_GRADIENT)
            text_color = self.COLOR_TITLE_TEXT_INACTIVE
        self.screen.blit(self._gradient(bar.size, *colors), bar.topleft)

        buttons = self._caption_button_rects(window)

        # Program icon (not on dialogs), then the title cut with "..." before the caption buttons
        text_x = self._draw_caption_icon(window)
        max_title_w = min(r.x for r in buttons.values()) - 4 - text_x
        title = self._fit_text(self.font_bold, window.title, max_title_w)
        title_text = self.font_bold.render(title, True, text_color)
        self.screen.blit(title_text, (text_x, bar.centery - title_text.get_height() // 2))

        self._draw_window_button(buttons['close'], "×", "close")
        if 'max' in buttons:
            self._draw_window_button(buttons['max'], "❐" if window.maximized else "□", "max")
            self._draw_window_button(buttons['min'], "─", "min")

    WS_SYSMENU = 0x00080000

    def _child_caption_rects(self, child):
        """(title bar, close button or None) screen rects of a child window
        with a caption; the close button is there with WS_SYSMENU"""
        border, caption = self.child_frame(child)
        fx, fy = self.frame_origin(child)
        bar = pygame.Rect(fx + border, fy + border, child.width - 2 * border, caption - 1)
        if not child.style & self.WS_SYSMENU:
            return bar, None
        w, h = self.CAPTION_BTN_W, self.CAPTION_BTN_H
        return bar, pygame.Rect(bar.right - 2 - w, bar.y + (bar.height - h) // 2, w, h)

    def _draw_child_caption(self, child, is_active):
        """Title bar of a child window (WS_CAPTION): the gradient, the title and
        the close button, like a dialog's"""
        bar, close = self._child_caption_rects(child)
        if is_active:
            colors = (self.COLOR_TITLE_BAR, self.COLOR_TITLE_BAR_GRADIENT)
            text_color = self.COLOR_TITLE_TEXT
        else:
            colors = (self.COLOR_TITLE_BAR_INACTIVE, self.COLOR_TITLE_BAR_INACTIVE_GRADIENT)
            text_color = self.COLOR_TITLE_TEXT_INACTIVE
        if bar.width <= 0 or bar.height <= 0:
            return
        self.screen.blit(self._gradient(bar.size, *colors), bar.topleft)
        right = close.x if close is not None else bar.right
        title = self._fit_text(self.font_bold, child.title, right - 4 - (bar.x + 4))
        title_text = self.font_bold.render(title, True, text_color)
        self.screen.blit(title_text, (bar.x + 4, bar.centery - title_text.get_height() // 2))
        if close is not None:
            self._draw_window_button(close, "×", "close")

    CAPTION_ICON_SIZE = 16

    def _draw_caption_icon(self, window):
        """Draw the small program icon at the left of a title bar (dialogs have
        none); returns the x where the title text starts"""
        bar = self._title_rect(window)
        if window.is_dialog or (window.owner is not None and window.style & self.WS_POPUP and
                                window.ex_style & self.WS_EX_DLGMODALFRAME):
            return bar.x + 4
        icon = self._exe_icon(window.icon_path, self.CAPTION_ICON_SIZE)[0]
        self.screen.blit(icon, (bar.x + 2, bar.centery - self.CAPTION_ICON_SIZE // 2))
        return bar.x + 2 + self.CAPTION_ICON_SIZE + 4

    def _draw_shape(self, shape, ox, oy, target=None):
        """Render one GDI display list entry at client origin (ox, oy) on target
        (default: the screen)"""
        screen = self.screen if target is None else target
        stype = shape['type']

        if stype == 'line':
            color, width = shape['pen']
            x1, y1 = shape['from']
            x2, y2 = shape['to']
            pygame.draw.line(screen, color, (ox + x1, oy + y1), (ox + x2, oy + y2), width)

        elif stype in ('rect', 'ellipse'):
            left, top, right, bottom = shape['rect']
            rect = pygame.Rect(ox + left, oy + top, right - left, bottom - top)
            draw_func = pygame.draw.rect if stype == 'rect' else pygame.draw.ellipse
            if shape.get('fill') is not None:
                draw_func(screen, shape['fill'], rect)
            if shape.get('pen') is not None:
                color, width = shape['pen']
                draw_func(screen, color, rect, width)

        elif stype == 'roundrect':
            left, top, right, bottom = shape['rect']
            rect = pygame.Rect(ox + left, oy + top, right - left, bottom - top)
            radius = shape.get('radius', 0)
            if shape.get('fill') is not None:
                pygame.draw.rect(screen, shape['fill'], rect, border_radius=radius)
            if shape.get('pen') is not None:
                color, width = shape['pen']
                pygame.draw.rect(screen, color, rect, width, border_radius=radius)

        elif stype == 'polygon':
            points = [(ox + x, oy + y) for x, y in shape['points']]
            if len(points) >= 3:
                if shape.get('fill') is not None:
                    pygame.draw.polygon(screen, shape['fill'], points)
                if shape.get('pen') is not None:
                    color, width = shape['pen']
                    pygame.draw.polygon(screen, color, points, width)

        elif stype == 'polyline':
            points = [(ox + x, oy + y) for x, y in shape['points']]
            if len(points) >= 2 and shape.get('pen') is not None:
                color, width = shape['pen']
                pygame.draw.lines(screen, color, False, points, width)

        elif stype == 'arc':
            left, top, right, bottom = shape['rect']
            rect = pygame.Rect(ox + left, oy + top, right - left, bottom - top)
            if shape.get('pen') is not None:
                color, width = shape['pen']
                pygame.draw.arc(screen, color, rect,
                                shape['start'], shape['end'], width)

        elif stype == 'text':
            x, y = shape['pos']
            font = self._get_render_font(shape.get('font'))
            if shape.get('dx'):
                surface = self._spaced_text_surface(shape, font)
            else:
                surface = font.render(shape['text'], True,
                                      shape.get('color') or self.COLOR_TEXT, shape.get('bk'))
            prev_clip = None
            if shape.get('clip'):
                # ExtTextOut's ETO_CLIPPED rectangle
                left, top, right, bottom = shape['clip']
                prev_clip = screen.get_clip()
                screen.set_clip(pygame.Rect(ox + left, oy + top, right - left,
                                            bottom - top).clip(prev_clip))
            screen.blit(surface, (ox + x, oy + y))
            if shape.get('font') and shape['font'].get('underline'):
                line_y = oy + y + surface.get_height() - 2
                pygame.draw.line(screen, shape.get('color') or self.COLOR_TEXT,
                                 (ox + x, line_y), (ox + x + surface.get_width(), line_y))
            if prev_clip is not None:
                screen.set_clip(prev_clip)

        elif stype == 'icon':
            x, y = shape['pos']
            if 'system' in shape:
                surface = (self._messagebox_icon_surface(shape['system']) if shape['system']
                           else self._exe_icon(None, 32)[0])
            else:
                surface = self._image_surface_rgba(shape['image'])
            if surface.get_size() != shape['size']:
                surface = pygame.transform.smoothscale(surface, shape['size'])
            screen.blit(surface, (ox + x, oy + y))

        elif stype == 'pixel':
            x, y = shape['pos']
            rect = pygame.Rect(ox + x, oy + y, 1, 1)
            pygame.draw.rect(screen, shape['color'], rect)

        elif stype == 'image':
            x, y = shape['pos']
            if shape['size'][0] > 0 and shape['size'][1] > 0:
                screen.blit(self._image_surface(shape), (ox + x, oy + y),
                            special_flags=self._rop_blend(shape.get('rop')))

        elif stype == 'invert':
            self._invert_area(screen, shape, ox, oy)

    def _spaced_text_surface(self, shape, font):
        """Surface of a text shape whose characters ExtTextOut placed with
        lpDx (shape['dx']), cached in the shape"""
        cached = shape.get('_surface')
        if cached is not None and cached[0] is font:
            return cached[1]
        color = shape.get('color') or self.COLOR_TEXT
        positions, x = [], 0
        for advance in shape['dx']:
            positions.append(x)
            x += advance
        glyphs = [font.render(ch, True, color) for ch in shape['text']]
        width = max([x] + [p + g.get_width() for p, g in zip(positions, glyphs, strict=True)])
        surface = pygame.Surface((max(1, width), font.get_height()), pygame.SRCALPHA)
        if shape.get('bk') is not None:
            surface.fill(tuple(shape['bk']) + (255,), pygame.Rect(0, 0, max(1, x),
                                                                  font.get_height()))
        for pos, glyph in zip(positions, glyphs, strict=True):
            surface.blit(glyph, (pos, 0))
        shape['_surface'] = (font, surface)
        return surface

    @staticmethod
    def _invert_area(screen, shape, ox, oy):
        """Invert the colors under an 'invert' display list entry (InvertRect,
        PatBlt with DSTINVERT, a caret or selection blitted with an XOR
        raster operation); a mask limits it to the pixels it sets"""
        left, top, right, bottom = shape['rect']
        full = pygame.Rect(ox + left, oy + top, right - left, bottom - top)
        area = full.clip(screen.get_clip()).clip(screen.get_rect())
        if area.width <= 0 or area.height <= 0:
            return
        inverted = pygame.Surface(area.size)
        inverted.fill((255, 255, 255))
        inverted.blit(screen.subsurface(area), (0, 0), special_flags=pygame.BLEND_RGB_SUB)
        mask = shape.get('mask')
        if mask is None:
            screen.blit(inverted, area.topleft)
            return
        cached = shape.get('_mask')
        if cached is None or cached[0] != full.size:
            width, height, bits = mask
            rgba = bytearray(len(bits) * 4)
            rgba[0::4] = rgba[1::4] = rgba[2::4] = b'\xff' * len(bits)
            rgba[3::4] = bits
            from_bytes = getattr(pygame.image, 'frombytes', None) or pygame.image.fromstring
            surface = from_bytes(bytes(rgba), (width, height), 'RGBA')
            if surface.get_size() != full.size:
                surface = pygame.transform.scale(surface, full.size)
            cached = (full.size, surface)
            shape['_mask'] = cached
        masked = pygame.Surface(area.size, pygame.SRCALPHA)
        masked.blit(inverted, (0, 0))
        masked.blit(cached[1], (full.x - area.x, full.y - area.y),
                    special_flags=pygame.BLEND_RGBA_MULT)
        screen.blit(masked, area.topleft)

    @staticmethod
    def _rop_blend(rop):
        """Pygame blend flag that draws an image with raster operation rop over
        what is below (0: a plain copy). With the black and white masks
        programs use them for, the results are exact: D AND S is D * S,
        D OR S is max(D, S); the NOT S operations blend the inverted image."""
        api = winapi.WinAPIHandler
        if rop in (api.SRCAND, api.DSNA):
            return pygame.BLEND_RGB_MULT
        if rop in (api.SRCPAINT, api.MERGEPAINT):
            return pygame.BLEND_RGB_MAX
        return 0

    def _image_surface(self, shape):
        """Pygame surface of an image shape, cached in the shape. The NOT S
        raster operations get the inverted image (see _rop_blend); SRCINVERT is
        approximated with transparency: black pixels leave the destination."""
        rop = shape.get('rop')
        key = (shape['size'], rop)
        cached = shape.get('_surface')
        if cached and cached[0] == key:
            return cached[1]
        data = shape['data']
        api = winapi.WinAPIHandler
        if rop in (api.NOTSRCCOPY, api.DSNA, api.MERGEPAINT):
            data = bytes(data).translate(bytes(range(255, -1, -1)))
        from_bytes = getattr(pygame.image, 'frombytes', None) or pygame.image.fromstring
        surface = from_bytes(data, shape['dim'], 'RGB')
        if shape['size'] != shape['dim']:
            surface = pygame.transform.scale(surface, shape['size'])
        if rop == api.SRCINVERT:
            surface.set_colorkey((0, 0, 0))
        elif shape.get('colorkey') is not None:
            surface.set_colorkey(shape['colorkey'])  # Its transparent pixels
        shape['_surface'] = (key, surface)
        return surface

    # Free fonts with the metrics of the common Windows fonts
    METRIC_FONTS = {'arial': 'liberationsans', 'helvetica': 'liberationsans',
                    'times new roman': 'liberationserif', 'times': 'liberationserif',
                    'courier new': 'liberationmono', 'courier': 'liberationmono'}

    def _get_render_font(self, font_dict):
        """Pygame font for a GDI font dict (cached); None -> default GUI font.
        A positive GDI height is the cell height (ascent + descent), a negative
        one the character height, which is the pygame size."""
        if not font_dict:
            return self.font
        height = font_dict.get('height', 13)
        cell = font_dict.get('cell', True)
        face = (font_dict.get('face') or 'arial').lower()
        bold = font_dict.get('bold', False)
        italic = font_dict.get('italic', False)
        key = (face, height, cell, bold, italic)
        if key not in self._font_cache:
            # The face itself if installed, else a free font with its metrics
            installed = face.replace(' ', '') in pygame.font.get_fonts()
            alias = self.METRIC_FONTS.get(face, 'liberationsans')
            names = f"{face},{alias},arial" if installed else f"{alias},{face},arial"
            font = pygame.font.SysFont(names, height, bold=bold, italic=italic)
            if cell and font.get_height() > height:
                size = max(6, round(height * height / font.get_height()))
                font = pygame.font.SysFont(names, size, bold=bold, italic=italic)
            self._font_cache[key] = CachedFont(font)
        return self._font_cache[key]

    def _draw_menu_bar(self, window):
        """Draw a window's menu bar and highlight the open item"""
        bar = self._menu_bar_rect(window)
        pygame.draw.rect(self.screen, self.COLOR_WINDOW_BG, bar)
        pygame.draw.line(self.screen, (128, 128, 128),
                         (bar.x, bar.bottom - 1), (bar.right - 1, bar.bottom - 1))

        item_rects = self._menu_item_rects(window)
        for i, (item, rect) in enumerate(zip(window.menu, item_rects, strict=False)):
            is_open = (self.open_menu == (window.hwnd, i))
            if is_open:
                pygame.draw.rect(self.screen, self.COLOR_TITLE_BAR, rect)
            color = self.COLOR_TITLE_TEXT if is_open else self.COLOR_TEXT
            text = self.font.render(item['text'], True, color)
            self.screen.blit(text, (rect.x + 8, rect.y + (rect.height - text.get_height()) // 2))

    def _draw_open_menu(self):
        """Draw the open dropdown menu (and its open submenus) on top of everything"""
        root = self._menu_root()
        if root is None:
            self.open_menu = None
            return
        items, x, y, win = root
        panels = self._menu_panels(items, x, y, self.menu_path)
        self._menu_hover(panels, self.menu_path,
                         lambda hmenu, index: self._post_init_menu(win, hmenu, index))
        self._draw_menu_panels(self._menu_panels(items, x, y, self.menu_path))

    COMBO_DEFAULT_ROWS = 8  # Rows shown when the template height leaves no room for a list

    def _combo_visible_rows(self, control):
        """Rows the open dropdown list shows (from the control's height, which includes it)"""
        count = max(1, len(control.items))
        box_h = min(control.height, 24)
        rows = (control.height - box_h - 2) // self.LISTBOX_ITEM_H
        if rows < 1:
            rows = self.COMBO_DEFAULT_ROWS
        return max(1, min(rows, count))

    def _combo_dropdown_rects(self, control):
        """Geometry of an open combobox dropdown (screen coords), or None.

        A dict with 'drop' (the whole list), 'items' as (index, rect) pairs of
        the visible rows, 'rows', and the scroll bar's 'bar', 'up', 'down',
        'track' and 'thumb' rects ('bar' is None when every item fits).
        """
        win = self.windows.get(control.parent_hwnd)
        if not win or not win.visible or win.minimized:
            return None
        ox, oy = self.client_origin(win)
        box_h = min(control.height, 24)
        item_h = self.LISTBOX_ITEM_H
        count = len(control.items)
        top_y = oy + control.y + box_h
        rows = self._combo_visible_rows(control)
        # Keep the list on screen (above the taskbar)
        room = (self.height - self.TASKBAR_H - top_y - 2) // item_h
        rows = max(1, min(rows, room)) if room >= 1 else rows
        top = max(0, min(control.top_index, count - rows))
        control.top_index = top
        drop = pygame.Rect(ox + control.x, top_y, control.width, rows * item_h + 2)
        geo = self._list_geometry(drop, count, rows, top)
        geo['drop'] = drop
        return geo

    def _list_geometry(self, frame, count, rows, top):
        """Rows and vertical scroll bar inside a list's 1-pixel frame (screen coords).

        A dict with 'items' as (index, rect) pairs of the visible rows, 'rows',
        and the scroll bar's 'bar', 'up', 'down', 'track' and 'thumb' rects
        ('bar' is None when every item fits).
        """
        item_h = self.LISTBOX_ITEM_H
        scroll = count > rows
        body_w = frame.width - 2 - (self.SCROLL_BTN if scroll else 0)
        items = [(i, pygame.Rect(frame.x + 1, frame.y + 1 + (i - top) * item_h, body_w, item_h))
                 for i in range(top, min(count, top + rows))]
        geo = {'items': items, 'rows': rows, 'bar': None}
        if scroll:
            btn = self.SCROLL_BTN
            bar = pygame.Rect(frame.right - 1 - btn, frame.y + 1, btn, frame.height - 2)
            b = min(btn, bar.height // 2)
            track = pygame.Rect(bar.x, bar.y + b, btn, max(0, bar.height - 2 * b))
            thumb_h = max(self.SCROLL_MIN_THUMB, track.height * rows // count)
            thumb_h = min(thumb_h, track.height)
            thumb_y = track.y + (track.height - thumb_h) * top // max(1, count - rows)
            geo.update(bar=bar, up=pygame.Rect(bar.x, bar.y, btn, b),
                       down=pygame.Rect(bar.x, bar.bottom - b, btn, b), track=track,
                       thumb=pygame.Rect(bar.x, thumb_y, btn, thumb_h))
        return geo

    def _listbox_rects(self, control, abs_pos=None):
        """Geometry of a LISTBOX at abs_pos (default: its screen position; see
        _list_geometry), or None"""
        abs_pos = abs_pos or self._scrollbar_abs_pos(control)
        if abs_pos is None:
            return None
        frame = pygame.Rect(abs_pos[0], abs_pos[1], control.width, control.height)
        rows = max(1, (control.height - 2) // self.LISTBOX_ITEM_H)
        count = len(control.items)
        control.top_index = max(0, min(control.top_index, count - rows))
        geo = self._list_geometry(frame, count, rows, control.top_index)
        geo['drop'] = frame
        return geo

    def _draw_list_scrollbar(self, geo, hwnd):
        """Draw the scroll bar of a list geometry (if it has one)"""
        if geo['bar'] is None:
            return
        pygame.draw.rect(self.screen, (224, 224, 224), geo['track'])
        self._draw_button_3d(geo['up'], "", small=True, arrow='up')
        self._draw_button_3d(geo['down'], "", small=True, arrow='down')
        if geo['track'].height >= self.SCROLL_MIN_THUMB:
            dragging = (self.dragging_list_thumb is not None and
                        self.dragging_list_thumb[0] == hwnd)
            self._draw_button_3d(geo['thumb'], "", pressed=dragging)

    def _combo_scroll_to_selection(self, control):
        """Scroll the dropdown list so the selected item is visible"""
        rows = self._combo_visible_rows(control)
        sel = control.sel_index
        if 0 <= sel < len(control.items):
            if sel < control.top_index:
                control.top_index = sel
            elif sel >= control.top_index + rows:
                control.top_index = sel - rows + 1

    def _draw_open_combo(self):
        """Draw the open combobox dropdown on top of everything"""
        if not self.open_combo:
            self.combo_shown = None
            return
        control = self.controls.get(self.open_combo)
        if not control or not control.visible:
            self.open_combo = None
            return

        if self.combo_shown != control.hwnd:  # Just opened: show the selection
            self.combo_shown = control.hwnd
            self._combo_scroll_to_selection(control)
        geo = self._combo_dropdown_rects(control)
        if geo is None:
            self.open_combo = None
            return
        drop = geo['drop']

        shadow = pygame.Rect(drop.x + 3, drop.y + 3, drop.width, drop.height)
        pygame.draw.rect(self.screen, (64, 64, 64), shadow)
        pygame.draw.rect(self.screen, self.COLOR_EDIT_BG, drop)
        pygame.draw.rect(self.screen, (128, 128, 128), drop, 1)

        mouse_pos = pygame.mouse.get_pos()
        prev_clip = self.screen.get_clip()
        for i, rect in geo['items']:
            hovered = rect.collidepoint(mouse_pos)
            selected = (i == control.sel_index)
            if hovered or selected:
                pygame.draw.rect(self.screen, self.COLOR_TITLE_BAR, rect)
            color = self.COLOR_TITLE_TEXT if (hovered or selected) else self.COLOR_TEXT
            text = self.font.render(control.items[i], True, color)
            self.screen.set_clip(rect)
            self.screen.blit(text, (rect.x + 3, rect.y + 1))
            self.screen.set_clip(prev_clip)

        self._draw_list_scrollbar(geo, control.hwnd)
