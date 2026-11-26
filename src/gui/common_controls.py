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

"""PseudoWindowsGUI mixin: Child window lookup and the emulated common controls (tree view, list
view, toolbar, combo box ex)"""


from .. import winapi
from ..config import PYGAME_AVAILABLE
from ..windows import gui_locked

if PYGAME_AVAILABLE:
    import pygame


class CommonControlsMixin:
    """Child window lookup and the emulated common controls (tree view, list view, toolbar, combo
    box ex)"""

    # ==================== EMULATED COMMON CONTROLS ====================

    def child_at(self, hwnd, x, y):
        """Deepest visible child window of hwnd at screen point (x, y) (hwnd itself
        if no child is there)"""
        win = self.windows.get(hwnd)
        if win is None:
            return hwnd
        for child in win.children:  # In Z order, the top one first
            c = self.windows.get(child)
            if c is None or not c.visible:
                continue
            fx, fy = self.frame_origin(c)
            if fx <= x < fx + c.width and fy <= y < fy + c.height:
                if c.native == 'TAB' and not self._on_tab(c, x, y):
                    continue  # Its page is HTTRANSPARENT: the siblings under it get it
                return self.child_at(child, x, y)
        return hwnd

    def _on_tab(self, win, x, y):
        """Is screen point (x, y) on one of a tab control's tabs?"""
        owner = win.owner
        if owner is None or 'tabs' not in win.nstate:
            return False
        cx, cy = self.client_origin(win)
        return any(left <= x - cx < right and top <= y - cy < bottom
                   for left, top, right, bottom in owner._tab_rects(win))

    def top_level_of(self, hwnd):
        """Top-level window that contains a window or control"""
        control = self.controls.get(hwnd)
        if control is not None:
            hwnd = control.parent_hwnd
        seen = 0
        while hwnd in self.windows and self.windows[hwnd].parent and seen < 64:
            hwnd = self.windows[hwnd].parent
            seen += 1
        return hwnd

    @gui_locked
    def reparent(self, hwnd, new_parent):
        """Move a child window or control into another parent window"""
        if new_parent not in self.windows:
            return
        control = self.controls.get(hwnd)
        if control is not None:
            old = self.windows.get(control.parent_hwnd)
            if old is not None:
                old.controls = [c for c in old.controls if c.hwnd != hwnd]
            control.parent_hwnd = new_parent
            self.windows[new_parent].controls.append(control)
            return
        win = self.windows.get(hwnd)
        if win is None:
            return
        old = self.windows.get(win.parent)
        if old is not None and hwnd in old.children:
            old.children.remove(hwnd)
        if hwnd in self.z_order:
            self.z_order.remove(hwnd)
        win.parent = new_parent
        self.windows[new_parent].children.append(hwnd)

    SYS_ICON_COLORS = {0: ((255, 255, 255), (96, 96, 96)), 1: ((240, 200, 80), (150, 110, 20)),
                       2: ((200, 200, 200), (80, 80, 80)), 3: ((120, 170, 230), (40, 70, 140)),
                       4: ((210, 225, 255), (40, 60, 140))}

    def _draw_system_icon(self, index, x, y, size=16):
        """Draw one of the fake system image list icons"""
        if index >= 5:  # My Computer and the other desktop icons (desktop_icons.py)
            self.screen.blit(self._shell_icon_images(index, size)[0], (x, y))
            return
        fill, line = self.SYS_ICON_COLORS.get(index, self.SYS_ICON_COLORS[0])
        s = size / 16
        if index == 1:  # Folder
            pygame.draw.rect(self.screen, fill, (x + 1 * s, y + 4 * s, 14 * s, 10 * s))
            pygame.draw.rect(self.screen, fill, (x + 1 * s, y + 2 * s, 6 * s, 3 * s))
            pygame.draw.rect(self.screen, line, (x + 1 * s, y + 4 * s, 14 * s, 10 * s), 1)
        elif index == 2:  # Drive
            pygame.draw.rect(self.screen, fill, (x + 1 * s, y + 5 * s, 14 * s, 7 * s))
            pygame.draw.rect(self.screen, line, (x + 1 * s, y + 5 * s, 14 * s, 7 * s), 1)
            pygame.draw.rect(self.screen, (0, 160, 0), (x + 11 * s, y + 9 * s, 2 * s, 2 * s))
        else:  # Document (archive: with a band, program: window)
            pygame.draw.rect(self.screen, fill, (x + 3 * s, y + 1 * s, 10 * s, 14 * s))
            pygame.draw.rect(self.screen, line, (x + 3 * s, y + 1 * s, 10 * s, 14 * s), 1)
            if index == 3:
                pygame.draw.rect(self.screen, (60, 60, 160), (x + 7 * s, y + 1 * s, 2 * s, 14 * s))
                pygame.draw.rect(self.screen, (220, 180, 40), (x + 6 * s, y + 7 * s, 4 * s, 3 * s))
            elif index == 4:
                pygame.draw.rect(self.screen, (0, 0, 128), (x + 3 * s, y + 1 * s, 10 * s, 3 * s))

    def _image_surface_rgba(self, image):
        """pygame Surface of an image list entry (w, h, rgba bytes), cached"""
        key = id(image)
        cached = self._rgba_cache.get(key)
        if cached is not None and cached[0] is image:
            return cached[1]
        width, height, rgba = image
        surface = pygame.image.frombuffer(rgba, (width, height), 'RGBA').convert_alpha()
        if len(self._rgba_cache) > 256:
            self._rgba_cache.clear()
        self._rgba_cache[key] = (image, surface)
        return surface

    def _draw_imagelist_image(self, owner, himl, index, x, y, disabled=False):
        """Draw image index of an image list; False if there is none"""
        imagelist = owner.imagelists.get(himl) if owner is not None else None
        if imagelist is None or not 0 <= index < len(imagelist['images']):
            return False
        image = imagelist['images'][index]
        if image is None:
            return False
        if image[0] == 'system':
            self._draw_system_icon(image[1], x, y, imagelist['cx'])
            return True
        if image[0] == 'shell':
            # A file's own icon (an EXE's icon, a shortcut's target icon) or a type icon
            _, base, host = image
            size = imagelist['cx']
            if host:
                self.screen.blit(self._exe_icon(host, size)[0], (x, y))
            else:
                self._draw_system_icon(base, x, y, size)
            return True
        surface = self._image_surface_rgba(image)
        if disabled:
            surface = surface.copy()
            surface.set_alpha(90)
        self.screen.blit(surface, (x, y))
        return True

    def _draw_tooltip_windows(self):
        """The tips the programs' tooltip controls show (over all windows)"""
        font = self.font_list or self.font
        for win in list(self.windows.values()):
            tip = win.nstate.get('tip') if win.native == 'TOOLTIPS' else None
            if not tip or win.owner is None:
                continue
            rect = pygame.Rect(tip['rect'])
            pygame.draw.rect(self.screen, self.COLOR_TOOLTIP, rect)
            pygame.draw.rect(self.screen, self.COLOR_TEXT, rect, 1)
            for i, line in enumerate(tip['text']):
                self.screen.blit(font.render(line, True, self.COLOR_TEXT),
                                 (rect.x + 4, rect.y + 2 + 16 * i))

    def _draw_native(self, win, cx, cy, cw, ch):
        """Draw an emulated common control's client area"""
        if win.native == 'LISTVIEW':
            self._draw_listview(win, cx, cy, cw, ch)
        elif win.native == 'TREEVIEW':
            gui_font = self.font
            self.font = self.font_list or self.font
            try:
                self._draw_treeview(win, cx, cy, cw, ch)
            finally:
                self.font = gui_font
        elif win.native == 'TOOLBAR':
            self._draw_toolbar(win, cx, cy, cw, ch)
        elif win.native == 'REBAR':
            pygame.draw.rect(self.screen, self.COLOR_WINDOW_BG, (cx, cy, cw, ch))
            for band in win.nstate['bands']:
                rect = band.get('rect')
                if rect and rect[0] > 0:
                    pygame.draw.line(self.screen, (128, 128, 128), (cx + rect[0] - 1, cy + 1),
                                     (cx + rect[0] - 1, cy + ch - 2))
                    pygame.draw.line(self.screen, (255, 255, 255), (cx + rect[0], cy + 1),
                                     (cx + rect[0], cy + ch - 2))
        elif win.native == 'COMBOBOXEX':
            st = win.nstate
            pygame.draw.rect(self.screen, self.COLOR_EDIT_BG, (cx, cy, cw, ch))
            pygame.draw.rect(self.screen, (128, 128, 128), (cx, cy, cw, ch), 1)
            image = st.get('image', -1)
            if image is not None and image >= 0:
                self._draw_imagelist_image(win.owner, st['imagelist'], image, cx + 3,
                                           cy + (ch - 16) // 2)
            button = pygame.Rect(cx + cw - 18, cy + 2, 16, ch - 4)
            self._draw_button_3d(button, '', pressed=st.get('dropped', False))
            self._draw_arrow(button, 'down')
        elif win.native == 'TAB':
            self._draw_tab_control(win, cx, cy, cw, ch)

    def _draw_tab_control(self, win, cx, cy, cw, ch):
        """SysTabControl32: a row of tabs over a raised page frame"""
        owner = win.owner
        if owner is None or 'tabs' not in win.nstate:
            return
        st = win.nstate
        rects = owner._tab_rects(win)
        white, gray, dark = (255, 255, 255), (128, 128, 128), (64, 64, 64)
        # The page is not filled: the controls on it are the tab control's siblings
        top = cy + max((r[3] for r in rects), default=2 + owner.TAB_ROW_H)
        page = pygame.Rect(cx, top, cw, max(0, cy + ch - top))
        pygame.draw.line(self.screen, white, page.topleft, (page.right - 1, page.top))
        pygame.draw.line(self.screen, white, page.topleft, (page.left, page.bottom - 1))
        pygame.draw.line(self.screen, dark, (page.right - 1, page.top),
                         (page.right - 1, page.bottom - 1))
        pygame.draw.line(self.screen, dark, (page.left, page.bottom - 1),
                         (page.right - 1, page.bottom - 1))
        pygame.draw.line(self.screen, gray, (page.right - 2, page.top + 1),
                         (page.right - 2, page.bottom - 2))
        pygame.draw.line(self.screen, gray, (page.left + 1, page.bottom - 2),
                         (page.right - 2, page.bottom - 2))
        font = self.font_list or self.font
        for i, (left, t, right, bottom) in enumerate(rects):
            tab = st['tabs'][i]
            selected = i == st['sel']
            rect = pygame.Rect(cx + left, cy + t, right - left, bottom - t)
            if selected:  # The selected tab is bigger and joins the page
                rect.inflate_ip(4, 0)
                rect.y -= 2
                rect.height += 3
            pygame.draw.rect(self.screen, self.COLOR_WINDOW_BG, rect)
            pygame.draw.line(self.screen, white, (rect.left, rect.top + 2),
                             (rect.left, rect.bottom - 1))
            pygame.draw.line(self.screen, white, (rect.left + 2, rect.top),
                             (rect.right - 3, rect.top))
            self.screen.set_at((rect.left + 1, rect.top + 1), white)
            pygame.draw.line(self.screen, dark, (rect.right - 1, rect.top + 2),
                             (rect.right - 1, rect.bottom - 1))
            pygame.draw.line(self.screen, gray, (rect.right - 2, rect.top + 1),
                             (rect.right - 2, rect.bottom - 1))
            x = rect.x + 6
            image = tab['image']
            if st['imagelist'] and image >= 0:
                if self._draw_imagelist_image(owner, st['imagelist'], image, x, rect.y + 2):
                    x += owner.imagelists[st['imagelist']]['cx'] + 4
            label = font.render(owner.tab_label(tab['text']), True, self.COLOR_TEXT)
            self.screen.blit(label, (x, rect.y + (rect.height - label.get_height()) // 2))

    def _draw_dotted(self, start, end, color=(128, 128, 128)):
        """Dotted horizontal or vertical line (tree view lines)"""
        (x1, y1), (x2, y2) = start, end
        if y1 == y2:
            for x in range(min(x1, x2), max(x1, x2) + 1, 2):
                self.screen.set_at((x, y1), color)
        else:
            for y in range(min(y1, y2), max(y1, y2) + 1, 2):
                self.screen.set_at((x1, y), color)

    def _draw_treeview(self, win, cx, cy, cw, ch):
        """SysTreeView32: the visible rows with their lines, +/- boxes, icons
        and labels, and a vertical scroll bar when they don't fit"""
        st = win.nstate
        owner = win.owner
        pygame.draw.rect(self.screen, (255, 255, 255), (cx, cy, cw, ch))
        if owner is None:
            return
        row_h, indent = owner.TV_ROW_H, owner.TV_INDENT
        rows = owner.tv_rows(win)
        lines = max(1, ch // row_h)
        scrollbar = len(rows) > lines
        body_w = cw - (16 if scrollbar else 0)
        focused = self.focused_window == win.hwnd and self.top_level_of(win.hwnd) == \
            self.active_window
        has_lines = win.style & owner.TVS_HASLINES
        has_buttons = win.style & owner.TVS_HASBUTTONS
        himl = st['imagelist']
        clip = self.screen.get_clip()
        body = pygame.Rect(cx, cy, body_w, ch)
        self.screen.set_clip(body.clip(clip) if clip else body)
        top = st['top']
        for index in range(top, min(len(rows), top + lines + 1)):
            handle, item, depth = rows[index]
            y = cy + (index - top) * row_h
            mid = y + row_h // 2
            bx = cx + owner.tv_button_left(win, depth)
            center = bx + indent // 2 - 2
            if has_lines and (depth or win.style & owner.TVS_LINESATROOT):
                # Line to the item, and down to its next sibling
                siblings = owner._tv_children(st, item['parent'])
                last = siblings and siblings[-1] == handle
                first_root = not item['parent'] and siblings and siblings[0] == handle
                self._draw_dotted((center, mid), (center + indent // 2, mid))
                self._draw_dotted((center, y if not first_root else mid),
                                  (center, mid if last else y + row_h))
                # Lines of the ancestors that have later siblings
                parent, level = item['parent'], depth - 1
                while parent:
                    parent_item = st['items'][parent]
                    parent_siblings = owner._tv_children(st, parent_item['parent'])
                    if parent_siblings and parent_siblings[-1] != parent and \
                            (level or win.style & owner.TVS_LINESATROOT):
                        px = cx + owner.tv_button_left(win, level) + indent // 2 - 2
                        self._draw_dotted((px, y), (px, y + row_h))
                    parent, level = parent_item['parent'], level - 1
            if has_buttons and owner.tv_has_buttons(item) and \
                    (depth or win.style & owner.TVS_LINESATROOT):
                box = pygame.Rect(center - 4, mid - 4, 9, 9)
                pygame.draw.rect(self.screen, (255, 255, 255), box)
                pygame.draw.rect(self.screen, (128, 128, 128), box, 1)
                pygame.draw.line(self.screen, (0, 0, 0), (box.x + 2, mid), (box.right - 3, mid))
                if not item['state'] & owner.TVIS_EXPANDED:
                    pygame.draw.line(self.screen, (0, 0, 0), (center, box.y + 2),
                                     (center, box.bottom - 3))
            tx = cx + owner.tv_text_left(win, depth)
            selected = handle == st['selected']
            if himl:
                image = item['selimage'] if selected else item['image']
                self._draw_imagelist_image(owner, himl, image, tx - 18, y + 1)
            label = item['text'] or ''
            surface = self.font.render(label, True, (255, 255, 255) if selected and focused
                                       else self.COLOR_TEXT)
            label_rect = pygame.Rect(tx, y + 1, surface.get_width() + 4, row_h - 2)
            if selected or st.get('drophilite') == handle:
                pygame.draw.rect(self.screen, self.COLOR_TITLE_BAR if selected and focused
                                 else (192, 192, 192), label_rect)
                if not focused and selected:
                    surface = self.font.render(label, True, self.COLOR_TEXT)
            self.screen.blit(surface, (tx + 2, y + (row_h - surface.get_height()) // 2))
            if selected and focused:
                pygame.draw.rect(self.screen, (128, 128, 128), label_rect, 1)
        self.screen.set_clip(clip)
        if scrollbar:
            bar = pygame.Rect(cx + cw - 16, cy, 16, ch)
            pygame.draw.rect(self.screen, (230, 228, 222), bar)
            up = pygame.Rect(bar.x, bar.y, 16, 16)
            down = pygame.Rect(bar.x, bar.bottom - 16, 16, 16)
            self._draw_button_3d(up, '')
            self._draw_arrow(up, 'up')
            self._draw_button_3d(down, '')
            self._draw_arrow(down, 'down')
            track = bar.height - 32
            if track > 8:
                thumb_h = max(10, track * lines // max(1, len(rows)))
                thumb_y = bar.y + 16 + (track - thumb_h) * top // max(1, len(rows) - lines)
                self._draw_button_3d(pygame.Rect(bar.x, thumb_y, 16, thumb_h), '')

    def _draw_listview(self, win, cx, cy, cw, ch):
        gui_font = self.font
        self.font = self.font_list or self.font
        try:
            self._draw_listview_body(win, cx, cy, cw, ch)
        finally:
            self.font = gui_font

    def _draw_listview_body(self, win, cx, cy, cw, ch):
        st = win.nstate
        owner = win.owner
        report = (win.style & 0x3) == 1
        if not report and owner is not None:
            self._draw_listview_grid(win, cx, cy, cw, ch)
            return
        header_h = owner.lv_header_height(win) if owner else 0
        row_h = winapi.WinAPIHandler.LV_ROW_H
        columns = sorted(st['columns'], key=lambda c: c.get('order', 0)) if report else []
        if not columns:
            columns = [{'sub': 0, 'width': cw, 'fmt': 0, 'text': ''}]
        focused = self.focused_window == win.hwnd and self.top_level_of(win.hwnd) == \
            self.active_window
        himl = st['imagelists'].get(1) or st['imagelists'].get(0)
        items = st['items']
        rows = max(1, (ch - header_h) // row_h)
        scrollbar = len(items) > rows
        text_w = cw - (16 if scrollbar else 0)
        clip = self.screen.get_clip()
        x0 = cx - st['hscroll']
        if header_h:
            x = x0
            for column in columns:
                rect = pygame.Rect(x, cy, column['width'], header_h)
                self._draw_button_3d(rect, '')
                label = self._fit_text(self.font, column.get('text', ''),
                                       max(0, column['width'] - 12))
                surface = self.font.render(label, True, self.COLOR_TEXT)
                align = column['fmt'] & 0x3
                tx = x + 5 if align == 0 else (x + column['width'] - surface.get_width() - 6
                                               if align == 1 else
                                               x + (column['width'] - surface.get_width()) // 2)
                self.screen.blit(surface, (tx, cy + (header_h - surface.get_height()) // 2))
                hdfmt = column.get('hdfmt', 0)
                if hdfmt & 0x600:  # HDF_SORTUP / HDF_SORTDOWN
                    ax = x + column['width'] - 12
                    up = hdfmt & 0x400
                    pts = [(ax, cy + 12), (ax + 6, cy + 12), (ax + 3, cy + 7)] if up else \
                        [(ax, cy + 8), (ax + 6, cy + 8), (ax + 3, cy + 13)]
                    pygame.draw.polygon(self.screen, (96, 96, 96), pts)
                x += column['width']
            if x < cx + cw:
                self._draw_button_3d(pygame.Rect(x, cy, cx + cw - x, header_h), '')
        body = pygame.Rect(cx, cy + header_h, text_w, ch - header_h)
        self.screen.set_clip(body.clip(clip) if clip else body)
        for row in range(rows + 1):
            index = st['top'] + row
            if index >= len(items):
                break
            item = items[index]
            y = cy + header_h + row * row_h
            selected = item['state'] & 0x2
            if selected:
                color = self.COLOR_TITLE_BAR if focused else (192, 192, 192)
                sel_w = (sum(c['width'] for c in columns) if report and st['ex_style'] & 0x20
                         else columns[0]['width'] if report else text_w)
                pygame.draw.rect(self.screen, color, (x0, y, sel_w, row_h))
            x = x0
            for n, column in enumerate(columns):
                sub = column['sub']
                text = item['cache'].get(sub)
                if text is None:
                    text = item['texts'].get(sub) or ''
                tx = x + 4
                if sub == 0:
                    state_w = owner.lv_state_image_width(win) if owner else 0
                    state_image = (item['state'] >> 12) & 0xF
                    if state_w and state_image:  # 1-based: INDEXTOSTATEIMAGEMASK
                        self._draw_imagelist_image(owner, st['imagelists'][2], state_image - 1,
                                                   x + 2, y + 1)
                    image = item.get('cache_image', item['image'])
                    if image is not None and image >= 0 and himl:
                        self._draw_imagelist_image(owner, himl, image, x + 2 + state_w, y + 1)
                    # No small image list: no icon space (like comctl32)
                    tx = x + 2 + (owner.lv_icon_space(win) if owner else 20)
                width = column['width'] - (tx - x) - 4
                if width > 0 and text:
                    label = self._fit_text(self.font, text, width)
                    surface = self.font.render(label, True, (255, 255, 255) if selected and
                                               focused and (n == 0 or st['ex_style'] & 0x20)
                                               else self.COLOR_TEXT)
                    if column['fmt'] & 0x3 == 1:
                        tx = x + column['width'] - surface.get_width() - 6
                    self.screen.blit(surface, (tx, y + (row_h - surface.get_height()) // 2))
                x += column['width']
            if index == st['focus'] and focused:
                width = columns[0]['width'] if report else text_w
                pygame.draw.rect(self.screen, (128, 128, 128), (x0, y, width, row_h), 1)
        if report and st['ex_style'] & 0x1:  # LVS_EX_GRIDLINES
            # Row lines down the whole body (below the items too), column
            # lines at the columns' right edges
            grid = self.COLOR_BUTTON
            for row in range(1, rows + 2):
                y = cy + header_h + row * row_h - 1
                pygame.draw.line(self.screen, grid, (body.left, y), (body.right - 1, y))
            x = x0
            for column in columns:
                x += column['width']
                if body.left <= x - 1 < body.right:
                    pygame.draw.line(self.screen, grid, (x - 1, body.top), (x - 1, body.bottom - 1))
        self.screen.set_clip(clip)
        if scrollbar:
            bar = pygame.Rect(cx + cw - 16, cy + header_h, 16, ch - header_h)
            pygame.draw.rect(self.screen, (230, 228, 222), bar)
            up = pygame.Rect(bar.x, bar.y, 16, 16)
            down = pygame.Rect(bar.x, bar.bottom - 16, 16, 16)
            self._draw_button_3d(up, '')
            self._draw_arrow(up, 'up')
            self._draw_button_3d(down, '')
            self._draw_arrow(down, 'down')
            track = bar.height - 32
            if track > 8:
                thumb_h = max(10, track * rows // max(1, len(items)))
                thumb_y = bar.y + 16 + (track - thumb_h) * st['top'] // max(1, len(items) - rows)
                self._draw_button_3d(pygame.Rect(bar.x, thumb_y, 16, thumb_h), '')

    def _draw_listview_grid(self, win, cx, cy, cw, ch):
        """Icon, small icon and list views: items in cells laid out by the
        owner's lv_grid (rows of cells, or columns for the list view)"""
        st = win.nstate
        owner = win.owner
        icons = (win.style & 0x3) == 0
        cell_w, cell_h, per_line, lines, column_major = owner.lv_grid(win)
        focused = self.focused_window == win.hwnd and self.top_level_of(win.hwnd) == \
            self.active_window
        himl = (st['imagelists'].get(0) or st['imagelists'].get(1)) if icons else \
            (st['imagelists'].get(1) or st['imagelists'].get(0))
        items = st['items']
        clip = self.screen.get_clip()
        body = pygame.Rect(cx, cy, cw, ch)
        self.screen.set_clip(body.clip(clip) if clip else body)
        page = per_line * (lines + 1)
        for index in range(st['top'], min(len(items), st['top'] + page)):
            item = items[index]
            left, top, right, bottom = owner.lv_item_rect(win, index)
            x, y = cx + left, cy + top
            selected = item['state'] & 0x2
            text = item['cache'].get(0)
            if text is None:
                text = item['texts'].get(0) or ''
            image = item.get('cache_image', item['image'])
            text_color = (255, 255, 255) if selected and focused else self.COLOR_TEXT
            select_color = self.COLOR_TITLE_BAR if focused else (192, 192, 192)
            if icons:
                if image is not None and image >= 0 and himl:
                    self._draw_imagelist_image(owner, himl, image, x + (cell_w - 32) // 2, y + 2)
                lines_text = self._wrap_text(text, cell_w - 4)[:2]
                if len(self._wrap_text(text, cell_w - 4)) > 2:
                    lines_text[1] = self._fit_text(self.font, lines_text[1] + '...', cell_w - 4)
                label_h = len(lines_text) * self.font.get_linesize()
                label_w = max([self.font.size(line)[0] for line in lines_text] + [8])
                label = pygame.Rect(x + (cell_w - label_w) // 2 - 2, y + 37, label_w + 4, label_h)
                if selected:
                    pygame.draw.rect(self.screen, select_color, label)
                for n, line in enumerate(lines_text):
                    surface = self.font.render(line, True, text_color)
                    self.screen.blit(surface, (x + (cell_w - surface.get_width()) // 2,
                                               label.y + n * self.font.get_linesize()))
                if index == st['focus'] and focused:
                    pygame.draw.rect(self.screen, (128, 128, 128), label, 1)
                continue
            if image is not None and image >= 0 and himl:
                self._draw_imagelist_image(owner, himl, image, x + 2, y + 1)
            icon = owner.lv_icon_space(win)
            label_text = self._fit_text(self.font, text, max(0, cell_w - icon - 6))
            surface = self.font.render(label_text, True, text_color)
            label = pygame.Rect(x + icon, y, surface.get_width() + 4, cell_h)
            if selected:
                pygame.draw.rect(self.screen, select_color, label)
            self.screen.blit(surface, (label.x + 2, y + (cell_h - surface.get_height()) // 2))
            if index == st['focus'] and focused:
                pygame.draw.rect(self.screen, (128, 128, 128), label, 1)
        self.screen.set_clip(clip)
        lines_total = (len(items) + per_line - 1) // per_line
        if lines_total <= lines:
            return
        # Scroll bar: horizontal for the list view's columns, vertical otherwise
        first_line = st['top'] // per_line
        if column_major:
            bar = pygame.Rect(cx, cy + ch - 16, cw, 16)
            pygame.draw.rect(self.screen, (230, 228, 222), bar)
            for rect, arrow in ((pygame.Rect(bar.x, bar.y, 16, 16), 'left'),
                                (pygame.Rect(bar.right - 16, bar.y, 16, 16), 'right')):
                self._draw_button_3d(rect, '')
                self._draw_arrow(rect, arrow)
            track = bar.width - 32
            if track > 8:
                thumb_w = max(10, track * lines // lines_total)
                thumb_x = bar.x + 16 + (track - thumb_w) * first_line // max(1, lines_total - lines)
                self._draw_button_3d(pygame.Rect(thumb_x, bar.y, thumb_w, 16), '')
        else:
            bar = pygame.Rect(cx + cw - 16, cy, 16, ch)
            pygame.draw.rect(self.screen, (230, 228, 222), bar)
            for rect, arrow in ((pygame.Rect(bar.x, bar.y, 16, 16), 'up'),
                                (pygame.Rect(bar.x, bar.bottom - 16, 16, 16), 'down')):
                self._draw_button_3d(rect, '')
                self._draw_arrow(rect, arrow)
            track = bar.height - 32
            if track > 8:
                thumb_h = max(10, track * lines // lines_total)
                thumb_y = bar.y + 16 + (track - thumb_h) * first_line // max(1, lines_total - lines)
                self._draw_button_3d(pygame.Rect(bar.x, thumb_y, 16, thumb_h), '')

    VIEW_GLYPHS = {8: 'up', 10: 'new'}  # Standard VIEW_* bitmaps (IDB_VIEW_*_COLOR)
    # VIEW_LARGEICONS, VIEW_SMALLICONS, VIEW_LIST, VIEW_DETAILS too when the
    # toolbar's bitmap is known to be comctl32's IDB_VIEW_SMALL/LARGE_COLOR
    VIEW_BITMAP_GLYPHS = {0: 'large', 1: 'small', 2: 'list', 3: 'details', 8: 'up', 10: 'new'}

    @staticmethod
    def _toolbar_view_index(st, index):
        """Index of a button image in comctl32's VIEW bitmap it was added from
        (TB_ADDBITMAP HINST_COMMCTRL IDB_VIEW_*), None if it is from another one"""
        first = 0
        bitmaps = st['bitmaps']
        for number, (count, (hinst, nid)) in enumerate(bitmaps):
            # The last one may be used past its count (the whole standard bitmap)
            if first <= index and (index < first + count or number == len(bitmaps) - 1):
                return index - first if hinst == 0xFFFFFFFF and nid in (4, 5) else None
            first += count
        return None

    def _view_glyph_surface(self, glyph, width, height):
        """16x16 picture of a standard VIEW_* toolbar bitmap (scaled to the
        toolbar's bitmap size), cached"""
        cache = self.__dict__.setdefault('_view_glyph_cache', {})
        key = (glyph, width, height)
        if key in cache:
            return cache[key]
        surface = pygame.Surface((16, 16), pygame.SRCALPHA)
        if glyph in ('large', 'small', 'list', 'details'):
            self._draw_view_mode_glyph(surface, glyph)
            if (width, height) != (16, 16):
                surface = pygame.transform.scale(surface, (width, height))
            cache[key] = surface
            return surface
        fill, line = self.SYS_ICON_COLORS[1]
        # Folder in the lower left: tab and body
        pygame.draw.rect(surface, fill, (1, 4, 6, 3))
        pygame.draw.rect(surface, line, (1, 4, 6, 3), 1)
        pygame.draw.rect(surface, fill, (1, 6, 11, 9))
        pygame.draw.rect(surface, line, (1, 6, 11, 9), 1)
        pygame.draw.line(surface, (255, 240, 170), (2, 7), (10, 7))
        if glyph == 'up':
            # Arrow out of the folder's top right corner
            pygame.draw.polygon(surface, (0, 0, 0), [(9, 5), (15, 5), (12, 2)])
            pygame.draw.rect(surface, (0, 0, 0), (11, 5, 2, 6))
        elif glyph == 'new':
            # Sparkle on the folder's top right corner
            sparkle = (255, 230, 0)
            pygame.draw.line(surface, sparkle, (12, 1), (12, 7))
            pygame.draw.line(surface, sparkle, (9, 4), (15, 4))
            pygame.draw.line(surface, sparkle, (10, 2), (14, 6))
            pygame.draw.line(surface, sparkle, (10, 6), (14, 2))
        if (width, height) != (16, 16):
            surface = pygame.transform.scale(surface, (width, height))
        cache[key] = surface
        return surface

    @staticmethod
    def _draw_view_mode_glyph(surface, glyph):
        """List view mode pictures: large icons, small icons, list, details"""
        blue, black = (0, 0, 160), (0, 0, 0)
        if glyph == 'large':
            for x, y in ((1, 1), (9, 1), (1, 9), (9, 9)):
                pygame.draw.rect(surface, blue, (x, y, 5, 4))
                pygame.draw.line(surface, black, (x, y + 5), (x + 4, y + 5))
        elif glyph == 'details':
            for y in (2, 6, 10, 14):
                pygame.draw.rect(surface, blue, (1, y - 1, 3, 3))
                pygame.draw.line(surface, black, (5, y), (14, y))
        else:  # Small icons in rows or in columns (list)
            for i in range(4):
                for j in range(2):
                    x, y = 1 + 8 * j, 1 + 4 * i
                    pygame.draw.rect(surface, blue, (x, y, 2, 2))
                    pygame.draw.line(surface, black, (x + 3, y + 1), (x + 6, y + 1))
            if glyph == 'list':
                pygame.draw.line(surface, (128, 128, 128), (8, 0), (8, 15))

    @staticmethod
    def _disabled_glyph(surface):
        """Disabled toolbar image like Windows draws it: a gray silhouette
        embossed with a white one offset by a pixel"""
        mask = pygame.mask.from_surface(surface)
        width, height = surface.get_size()
        result = pygame.Surface((width + 1, height + 1), pygame.SRCALPHA)
        result.blit(mask.to_surface(setcolor=(255, 255, 255, 255), unsetcolor=(0, 0, 0, 0)),
                    (1, 1))
        result.blit(mask.to_surface(setcolor=(128, 128, 128, 255), unsetcolor=(0, 0, 0, 0)),
                    (0, 0))
        return result

    def _draw_toolbar(self, win, cx, cy, cw, ch):
        st = win.nstate
        owner = win.owner
        pygame.draw.rect(self.screen, self.COLOR_WINDOW_BG, (cx, cy, cw, ch))
        if not win.style & 0x40:  # CCS_NODIVIDER
            pygame.draw.line(self.screen, (128, 128, 128), (cx, cy), (cx + cw, cy))
            pygame.draw.line(self.screen, (255, 255, 255), (cx, cy + 1), (cx + cw, cy + 1))
        if owner is None:
            return
        owner.tb_refresh_bitmaps(win)
        rects = owner._tb_layout(win)
        bw, bh = st['bitmap_size']
        mouse = self.mouse_pos
        buttons = zip(st['buttons'], rects, strict=False)
        for i, (button, (left, top, right, bottom)) in enumerate(buttons):
            if button['state'] & 0x8:
                continue
            rect = pygame.Rect(cx + left, cy + top, right - left, bottom - top)
            if button['style'] & 0x1 and rect.width > rect.height:  # Separator row (wrapped)
                pygame.draw.line(self.screen, (128, 128, 128), (rect.x + 2, rect.centery - 1),
                                 (rect.right - 3, rect.centery - 1))
                pygame.draw.line(self.screen, (255, 255, 255), (rect.x + 2, rect.centery),
                                 (rect.right - 3, rect.centery))
                continue
            if button['style'] & 0x1:  # Separator
                pygame.draw.line(self.screen, (128, 128, 128), (rect.centerx - 1, rect.y + 2),
                                 (rect.centerx - 1, rect.bottom - 3))
                pygame.draw.line(self.screen, (255, 255, 255), (rect.centerx, rect.y + 2),
                                 (rect.centerx, rect.bottom - 3))
                continue
            enabled = button['state'] & 0x4
            pressed = st['pressed'] == i or button['state'] & 0x3
            if pressed:
                pygame.draw.rect(self.screen, (255, 255, 255), rect)
                pygame.draw.line(self.screen, (128, 128, 128), rect.topleft, rect.topright)
                pygame.draw.line(self.screen, (128, 128, 128), rect.topleft, rect.bottomleft)
            elif enabled and rect.collidepoint(mouse) and win.style & 0x800:  # TBSTYLE_FLAT
                pygame.draw.rect(self.screen, (255, 255, 255), rect, 1)
                pygame.draw.line(self.screen, (128, 128, 128), rect.bottomleft, rect.bottomright)
                pygame.draw.line(self.screen, (128, 128, 128), rect.topright, rect.bottomright)
            elif not win.style & 0x800:
                self._draw_button_3d(rect, '')
            text = owner._tb_text(win, button)
            ix = rect.x + (rect.width - bw) // 2 + (1 if pressed else 0)
            iy = rect.y + (3 if text and st['max_text_rows'] else (rect.height - bh) // 2) + \
                (1 if pressed else 0)
            drawn = False
            if st['imagelist']:
                drawn = self._draw_imagelist_image(owner, st['imagelist'], button['bitmap'],
                                                   ix, iy, disabled=not enabled)
            elif st.get('bitmap_list'):  # TB_ADDBITMAP bitmaps
                drawn = self._draw_imagelist_image(owner, st['bitmap_list'], button['bitmap'],
                                                   ix, iy, disabled=not enabled)
            if not drawn:
                view_index = self._toolbar_view_index(st, button['bitmap'])
                glyph = self.VIEW_BITMAP_GLYPHS.get(view_index) if view_index is not None \
                    else self.VIEW_GLYPHS.get(button['bitmap'])
                if glyph:
                    surface = self._view_glyph_surface(glyph, bw or 16, bh or 16)
                    if not enabled:
                        surface = self._disabled_glyph(surface)
                    self.screen.blit(surface, (ix, iy))
            if text and st['max_text_rows']:
                label = self._fit_text(self.font_small, text, rect.width - 4)
                surface = self.font_small.render(label, True, (0, 0, 0) if enabled else
                                                 (128, 128, 128))
                self.screen.blit(surface, (rect.x + (rect.width - surface.get_width()) // 2,
                                           rect.bottom - surface.get_height() - 3))

    def _native_combo_rects(self, win):
        """Dropdown rect and item rects of an open ComboBoxEx (screen coordinates)"""
        cx, cy = self.client_origin(win)
        items = win.nstate['items']
        item_h = self.LISTBOX_ITEM_H
        height = min(len(items), max(1, (self.height - cy - win.height - 40) // item_h))
        drop = pygame.Rect(cx - 1, cy + win.height - 1, win.width, max(1, height) * item_h + 2)
        rects = [pygame.Rect(drop.x + 1, drop.y + 1 + i * item_h, drop.width - 2, item_h)
                 for i in range(height)]
        return drop, rects

    def _draw_open_native_combo(self):
        hwnd = self.open_native_combo
        win = self.windows.get(hwnd) if hwnd else None
        if win is None or not win.visible or not win.nstate.get('dropped'):
            self.open_native_combo = None
            return
        drop, rects = self._native_combo_rects(win)
        pygame.draw.rect(self.screen, (64, 64, 64), drop.move(2, 2))
        pygame.draw.rect(self.screen, self.COLOR_EDIT_BG, drop)
        pygame.draw.rect(self.screen, (0, 0, 0), drop, 1)
        st = win.nstate
        for item, rect in zip(st['items'], rects, strict=False):
            hovered = rect.collidepoint(self.mouse_pos)
            if hovered:
                pygame.draw.rect(self.screen, self.COLOR_TITLE_BAR, rect)
            x = rect.x + 3 + 10 * item.get('indent', 0)
            if item.get('image', -1) >= 0:
                self._draw_imagelist_image(win.owner, st['imagelist'], item['image'], x,
                                           rect.y + 1)
                x += 20
            surface = self.font.render(item['text'], True,
                                       self.COLOR_TITLE_TEXT if hovered else self.COLOR_TEXT)
            self.screen.blit(surface, (x, rect.y + 1))

    def _handle_native_combo_click(self, pos):
        """Click while a ComboBoxEx list is open; True if consumed"""
        win = self.windows.get(self.open_native_combo)
        if win is None or win.owner is None:
            self.open_native_combo = None
            return False
        drop, rects = self._native_combo_rects(win)
        choice = -1
        for i, rect in enumerate(rects):
            if rect.collidepoint(pos):
                choice = i
        self.open_native_combo = None
        win.owner.post_window_message(win.hwnd, 0x047F, choice & 0xFFFFFFFF, 0)
        return drop.collidepoint(pos) or True
