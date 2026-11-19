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
        if not window.is_dialog:
            # Maximize and minimize sit together, two pixels left of close
            rects['max'] = pygame.Rect(close.x - 2 - w, y, w, h)
            rects['min'] = pygame.Rect(close.x - 2 - 2 * w, y, w, h)
        return rects

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

    CAPTION_ICON_SIZE = 16

    def _draw_caption_icon(self, window):
        """Draw the small program icon at the left of a title bar (dialogs have
        none); returns the x where the title text starts"""
        bar = self._title_rect(window)
        if window.is_dialog:
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
            surface = font.render(shape['text'], True, shape.get('color') or self.COLOR_TEXT,
                                  shape.get('bk'))
            screen.blit(surface, (ox + x, oy + y))
            if shape.get('font') and shape['font'].get('underline'):
                line_y = oy + y + surface.get_height() - 2
                pygame.draw.line(screen, shape.get('color') or self.COLOR_TEXT,
                                 (ox + x, line_y), (ox + x + surface.get_width(), line_y))

        elif stype == 'pixel':
            x, y = shape['pos']
            rect = pygame.Rect(ox + x, oy + y, 1, 1)
            pygame.draw.rect(screen, shape['color'], rect)

        elif stype == 'image':
            x, y = shape['pos']
            if shape['size'][0] > 0 and shape['size'][1] > 0:
                screen.blit(self._image_surface(shape), (ox + x, oy + y))

    def _image_surface(self, shape):
        """Pygame surface of an image shape, cached in the shape.

        Raster operations are approximated with transparency: SRCAND leaves
        white pixels out (mask), SRCPAINT/SRCINVERT leave black pixels out.
        """
        rop = shape.get('rop')
        key = (shape['size'], rop)
        cached = shape.get('_surface')
        if cached and cached[0] == key:
            return cached[1]
        data = shape['data']
        if rop == winapi.WinAPIHandler.NOTSRCCOPY:
            data = bytes(255 - b for b in data)
        from_bytes = getattr(pygame.image, 'frombytes', None) or pygame.image.fromstring
        surface = from_bytes(data, shape['dim'], 'RGB')
        if shape['size'] != shape['dim']:
            surface = pygame.transform.scale(surface, shape['size'])
        if rop == winapi.WinAPIHandler.SRCAND:
            surface.set_colorkey((255, 255, 255))
        elif rop in (winapi.WinAPIHandler.SRCPAINT, winapi.WinAPIHandler.SRCINVERT):
            surface.set_colorkey((0, 0, 0))
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
            self._font_cache[key] = font
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

    def _combo_dropdown_rects(self, control):
        """Dropdown rect and item rects of an open combobox (screen coords)."""
        win = self.windows.get(control.parent_hwnd)
        if not win or not win.visible or win.minimized:
            return None, []
        ox, oy = self.client_origin(win)
        box_h = min(control.height, 24)
        item_h = self.LISTBOX_ITEM_H
        count = max(1, len(control.items))
        drop = pygame.Rect(ox + control.x, oy + control.y + box_h,
                           control.width, count * item_h + 2)
        rects = [pygame.Rect(drop.x + 1, drop.y + 1 + i * item_h,
                             drop.width - 2, item_h)
                 for i in range(len(control.items))]
        return drop, rects

    def _draw_open_combo(self):
        """Draw the open combobox dropdown on top of everything"""
        if not self.open_combo:
            return
        control = self.controls.get(self.open_combo)
        if not control or not control.visible:
            self.open_combo = None
            return

        drop, item_rects = self._combo_dropdown_rects(control)
        if drop is None:
            self.open_combo = None
            return

        shadow = pygame.Rect(drop.x + 3, drop.y + 3, drop.width, drop.height)
        pygame.draw.rect(self.screen, (64, 64, 64), shadow)
        pygame.draw.rect(self.screen, self.COLOR_EDIT_BG, drop)
        pygame.draw.rect(self.screen, (128, 128, 128), drop, 1)

        mouse_pos = pygame.mouse.get_pos()
        for i, (item, rect) in enumerate(zip(control.items, item_rects, strict=False)):
            hovered = rect.collidepoint(mouse_pos)
            selected = (i == control.sel_index)
            if hovered or selected:
                pygame.draw.rect(self.screen, self.COLOR_TITLE_BAR, rect)
            color = self.COLOR_TITLE_TEXT if (hovered or selected) else self.COLOR_TEXT
            text = self.font.render(item, True, color)
            self.screen.blit(text, (rect.x + 3, rect.y + 1))
