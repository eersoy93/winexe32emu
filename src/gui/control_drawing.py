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

"""PseudoWindowsGUI mixin: Drawing the standard controls (buttons, edits, statics, status and
progress bars) and 3D frames"""

import re

from ..config import PYGAME_AVAILABLE

if PYGAME_AVAILABLE:
    import pygame


class ControlDrawingMixin:
    """Drawing the standard controls (buttons, edits, statics, status and progress bars) and 3D
    frames"""

    def _draw_control(self, control, parent_x, parent_y):
        """Draw control in its WM_SETFONT font"""
        if not control.visible:
            return
        if control.class_name == "STATUSBAR":
            self.layout_statusbar(control)
        gui_font = self.font
        if control.font:
            self.font = self._get_render_font(control.font)
        try:
            # An owner-draw button or static shows only what its parent draws
            # (WM_DRAWITEM): its own face and text are not drawn
            if not self._is_owner_draw(control):
                self._draw_control_body(control, parent_x + control.x, parent_y + control.y)
        finally:
            self.font = gui_font
        if control.drawn_shapes:
            abs_x, abs_y = parent_x + control.x, parent_y + control.y
            prev_clip = self.screen.get_clip()
            rect = pygame.Rect(abs_x, abs_y, control.width, control.height)
            self.screen.set_clip(rect.clip(prev_clip) if prev_clip else rect)
            for shape in control.drawn_shapes:
                self._draw_shape(shape, abs_x, abs_y)
            self.screen.set_clip(prev_clip)

    @staticmethod
    def _is_owner_draw(control):
        """BS_OWNERDRAW button or SS_OWNERDRAW static"""
        return ((control.class_name == 'BUTTON' and control.style & 0xF == 0xB) or
                (control.class_name == 'STATIC' and control.style & 0x1F == 0xD))

    def _wrap_text(self, text, width):
        """Split text into lines that fit width pixels (word wrap)"""
        lines = []
        for paragraph in text.replace('\r\n', '\n').replace('\r', '\n').split('\n'):
            line = ''
            for word in paragraph.split(' '):
                candidate = f"{line} {word}" if line else word
                if line and self.font.size(candidate)[0] > width:
                    lines.append(line)
                    line = word
                else:
                    line = candidate
            lines.append(line)
        return lines

    SS_NOPREFIX = 0x80

    def _draw_edit_text(self, control, rect, padding=4):
        """Text of an EDIT control (or an editable combo box) with the selection,
        the blinking caret and the scrolling that keeps the caret visible"""
        font = self.font
        shown = self._edit_display_text(control)
        focused = control.hwnd == self.focused_control
        start, end = control.selection()
        caret = min(max(control.sel_caret, 0), len(shown))
        lines = control.edit_lines()
        line_h = font.get_linesize()
        multiline = control.class_name == "EDIT" and control.style & 0x4
        inner_w = max(1, rect.width - 2 * padding)
        caret_line = control.line_of(caret)
        caret_px = font.size(shown[lines[caret_line][0]:caret])[0]
        if caret_px - control.edit_scroll > inner_w - 1:
            control.edit_scroll = caret_px - inner_w + 1
        elif caret_px < control.edit_scroll:
            control.edit_scroll = max(0, caret_px - inner_w // 3)
        if multiline:
            visible = max(1, (rect.height - 4) // line_h)
            if caret_line < control.edit_top_line:
                control.edit_top_line = caret_line
            elif caret_line >= control.edit_top_line + visible:
                control.edit_top_line = caret_line - visible + 1
            top, first_y = control.edit_top_line, rect.y + 2
        else:
            top, first_y = 0, rect.y + (rect.height - font.get_height()) // 2
        color = self.COLOR_TEXT if control.enabled else (128, 128, 128)
        show_selection = focused or control.style & 0x100  # ES_NOHIDESEL
        prev_clip = self.screen.get_clip()
        inner = rect.inflate(-2, -2)
        self.screen.set_clip(inner.clip(prev_clip) if prev_clip else inner)
        x0 = rect.x + padding - control.edit_scroll
        for index in range(top, len(lines)):
            line_start, line_end = lines[index]
            y = first_y + (index - top) * line_h
            if y > rect.bottom:
                break
            first, last = max(start, line_start), min(end, line_end)
            if show_selection and first < last:
                x = x0
                for piece, selected in ((shown[line_start:first], False),
                                        (shown[first:last], True),
                                        (shown[last:line_end], False)):
                    if not piece:
                        continue
                    width = font.size(piece)[0]
                    if selected:
                        pygame.draw.rect(self.screen, self.COLOR_TITLE_BAR, (x, y, width, line_h))
                    self.screen.blit(font.render(piece, True, self.COLOR_TITLE_TEXT if selected
                                                 else color), (x, y))
                    x += width
            elif line_end > line_start:
                self.screen.blit(font.render(shown[line_start:line_end], True, color), (x0, y))
        if focused and (pygame.time.get_ticks() // 500) % 2 == 0:
            caret_x = x0 + caret_px
            if multiline:
                caret_y = first_y + (caret_line - top) * line_h
                pygame.draw.line(self.screen, self.COLOR_TEXT, (caret_x, caret_y),
                                 (caret_x, caret_y + line_h - 1))
            else:
                pygame.draw.line(self.screen, self.COLOR_TEXT, (caret_x, rect.y + 3),
                                 (caret_x, rect.bottom - 4))
        self.screen.set_clip(prev_clip)

    @staticmethod
    def _mnemonic_text(text):
        """Control text as drawn: "&x" marks the mnemonic (underlined on
        Windows), "&&" is a literal "&"""
        return re.sub(r'&(.)', r'\1', text or '')

    def _fill_ctl_background(self, control, rect):
        """Background brush the parent chose with WM_CTLCOLOR* (none: the
        parent's background shows)"""
        colors = control.ctl_colors
        if colors and colors['brush'] is not None:
            pygame.draw.rect(self.screen, colors['brush'], rect)

    def _ctl_text_colors(self, control):
        """(text color, text background or None) of a control's DC after
        WM_CTLCOLOR* (SetTextColor, SetBkMode OPAQUE with SetBkColor)"""
        colors = control.ctl_colors
        if not colors:
            return self.COLOR_TEXT, None
        return colors['text'], colors['bk_color'] if colors['bk_mode'] == 2 else None

    def _draw_static(self, control, rect):
        """Draw a STATIC control by its SS_* type"""
        kind = control.style & 0x1F
        dark, light = (128, 128, 128), (255, 255, 255)
        x, y, w, h = rect
        if kind == 0x10:    # SS_ETCHEDHORZ
            pygame.draw.line(self.screen, dark, (x, y), (x + w - 1, y))
            pygame.draw.line(self.screen, light, (x, y + 1), (x + w - 1, y + 1))
        elif kind == 0x11:  # SS_ETCHEDVERT
            pygame.draw.line(self.screen, dark, (x, y), (x, y + h - 1))
            pygame.draw.line(self.screen, light, (x + 1, y), (x + 1, y + h - 1))
        elif kind == 0x12:  # SS_ETCHEDFRAME
            pygame.draw.rect(self.screen, light, (x + 1, y + 1, w - 1, h - 1), 1)
            pygame.draw.rect(self.screen, dark, (x, y, w - 1, h - 1), 1)
        elif kind == 3:  # SS_ICON
            if control.icon:
                surface = self._image_surface_rgba(control.icon)
                if control.style & 0x200:  # SS_CENTERIMAGE
                    self.screen.blit(surface, surface.get_rect(center=rect.center))
                else:
                    self.screen.blit(surface, (x, y))
        elif kind == 0xE:  # SS_BITMAP
            bitmap = control.bitmap
            if bitmap:
                bx, by = x, y
                if control.style & 0x200:  # SS_CENTERIMAGE
                    bx = x + (w - bitmap['width']) // 2
                    by = y + (h - bitmap['height']) // 2
                prev_clip = self.screen.get_clip()
                self.screen.set_clip(rect.clip(prev_clip) if prev_clip else rect)
                for shape in list(bitmap['shapes']):
                    self._draw_shape(shape, bx, by)
                self.screen.set_clip(prev_clip)
        elif kind in (4, 5, 6):  # SS_BLACKRECT, SS_GRAYRECT, SS_WHITERECT
            pygame.draw.rect(self.screen, ((0, 0, 0), dark, light)[kind - 4], rect)
        elif kind in (7, 8, 9):  # SS_BLACKFRAME, SS_GRAYFRAME, SS_WHITEFRAME
            pygame.draw.rect(self.screen, ((0, 0, 0), dark, light)[kind - 7], rect, 1)
        elif kind in (0, 1, 2, 0xB, 0xC):  # Text: left, center, right, simple, no wrap
            self._fill_ctl_background(control, rect)
            text_color, text_bg = self._ctl_text_colors(control)
            text = control.text
            if not control.style & self.SS_NOPREFIX:
                text = self._mnemonic_text(text)
            lines = self._wrap_text(text, w) if kind <= 2 else \
                text.replace('\r\n', '\n').split('\n')
            prev_clip = self.screen.get_clip()
            # The first line is never cut: the font may be taller than the
            # one-line height the dialog template gives the control
            text_rect = pygame.Rect(x, y, w, max(h, self.font.get_linesize()))
            self.screen.set_clip(text_rect.clip(prev_clip) if prev_clip else text_rect)
            line_y = y
            for line in lines:
                if control.enabled:
                    surface = self.font.render(line, True, text_color, text_bg)
                else:
                    # Disabled: embossed gray text whatever the DC's colors (DSS_DISABLED)
                    surface = self.font.render(line, True, light, text_bg)
                if kind == 1:
                    line_x = x + (w - surface.get_width()) // 2
                elif kind == 2:
                    line_x = x + w - surface.get_width()
                else:
                    line_x = x
                if not control.enabled:
                    self.screen.blit(surface, (line_x + 1, line_y + 1))
                    surface = self.font.render(line, True, dark)
                self.screen.blit(surface, (line_x, line_y))
                line_y += self.font.get_linesize()
                if line_y >= y + h:
                    break
            self.screen.set_clip(prev_clip)

    STATUSBAR_H = 20

    def layout_statusbar(self, control):
        """Dock a status bar to the bottom (CCS_TOP: top) of its parent's client area"""
        if control.style & 0x0C:  # CCS_NORESIZE, CCS_NOPARENTALIGN
            return
        win = self.windows.get(control.parent_hwnd)
        if win is None:
            return
        width, height = self.client_size(win)
        top = 0 if control.style & 0x3 == 1 else height - self.STATUSBAR_H
        control.x, control.y = 0, top
        control.width, control.height = width, self.STATUSBAR_H

    def _draw_statusbar(self, control, abs_x, abs_y):
        """Status bar: sunken panes with their texts"""
        rect = pygame.Rect(abs_x, abs_y, control.width, control.height)
        pygame.draw.rect(self.screen, self.COLOR_BUTTON, rect)
        dark, light = (128, 128, 128), (255, 255, 255)
        if control.simple:
            panes = [(-1, control.part_texts.get(255, ''))]
        else:
            panes = [(edge, control.text if i == 0 else control.part_texts.get(i, ''))
                     for i, edge in enumerate(control.parts)]
        prev_clip = self.screen.get_clip()
        left = abs_x + 2
        for edge, text in panes:
            right = rect.right - 2 if edge < 0 else min(abs_x + edge, rect.right - 2)
            pane = pygame.Rect(left, abs_y + 2, max(0, right - left - 2), control.height - 3)
            if pane.width > 0:
                pygame.draw.line(self.screen, dark, pane.topleft, (pane.right - 1, pane.top))
                pygame.draw.line(self.screen, dark, pane.topleft, (pane.left, pane.bottom - 1))
                pygame.draw.line(self.screen, light, (pane.left, pane.bottom - 1),
                                 (pane.right - 1, pane.bottom - 1))
                pygame.draw.line(self.screen, light, (pane.right - 1, pane.top),
                                 (pane.right - 1, pane.bottom - 1))
                self.screen.set_clip(pane.clip(prev_clip) if prev_clip else pane)
                surface = self.font.render(text.replace('\t', ' '), True, self.COLOR_TEXT)
                self.screen.blit(surface, (pane.x + 3,
                                           pane.y + (pane.height - surface.get_height()) // 2))
                self.screen.set_clip(prev_clip)
            left = right

    def _draw_progressbar(self, control, abs_x, abs_y):
        """Progress bar (msctls_progress32): sunken box filled up to the position,
        with blocks unless PBS_SMOOTH; PBS_VERTICAL fills from the bottom"""
        rect = pygame.Rect(abs_x, abs_y, control.width, control.height)
        pygame.draw.rect(self.screen, control.progress_bk_color or self.COLOR_BUTTON, rect)
        dark, light = (128, 128, 128), (255, 255, 255)
        pygame.draw.line(self.screen, dark, rect.topleft, (rect.right - 1, rect.top))
        pygame.draw.line(self.screen, dark, rect.topleft, (rect.left, rect.bottom - 1))
        pygame.draw.line(self.screen, light, (rect.left, rect.bottom - 1),
                         (rect.right - 1, rect.bottom - 1))
        pygame.draw.line(self.screen, light, (rect.right - 1, rect.top),
                         (rect.right - 1, rect.bottom - 1))
        inner = rect.inflate(-4, -4)
        span = control.scroll_max - control.scroll_min
        if inner.width <= 0 or inner.height <= 0 or span <= 0:
            return
        fraction = min(1.0, max(0.0, (control.scroll_pos - control.scroll_min) / span))
        vertical = bool(control.style & 0x4)  # PBS_VERTICAL
        length = round((inner.height if vertical else inner.width) * fraction)
        color = control.progress_bar_color or (0, 0, 128)
        if control.style & 0x1:  # PBS_SMOOTH
            blocks = [(0, length)]
        else:
            size = max(2, ((inner.width if vertical else inner.height) * 2) // 3)
            blocks = [(start, min(size, length - start))
                      for start in range(0, length, size + 2)]
        for start, extent in blocks:
            if vertical:
                block = pygame.Rect(inner.left, inner.bottom - start - extent,
                                    inner.width, extent)
            else:
                block = pygame.Rect(inner.left + start, inner.top, extent, inner.height)
            pygame.draw.rect(self.screen, color, block)

    def _draw_control_body(self, control, abs_x, abs_y):
        if control.class_name == "STATUSBAR":
            self._draw_statusbar(control, abs_x, abs_y)
        elif control.class_name == "BUTTON":
            rect = pygame.Rect(abs_x, abs_y, control.width, control.height)
            label = self._mnemonic_text(control.text)
            if (control.style & 0xF) == 7:  # BS_GROUPBOX
                self._draw_group_box(control, rect)
            elif (control.style & 0xF) == 1:  # BS_DEFPUSHBUTTON: black outer frame
                self._draw_button_3d(rect.inflate(-2, -2), label,
                                     disabled=not control.enabled)
                pygame.draw.rect(self.screen, (0, 0, 0), rect, 1)
            else:
                self._draw_button_3d(rect, label, pressed=control.checked,
                                     disabled=not control.enabled)

        elif control.class_name == "STATIC":
            self._draw_static(control, pygame.Rect(abs_x, abs_y, control.width, control.height))

        elif control.class_name == "EDIT":
            rect = pygame.Rect(abs_x, abs_y, control.width, control.height)
            # Disabled and read-only edit controls have the dialog color
            readonly = control.style & 0x800  # ES_READONLY
            pygame.draw.rect(self.screen, self.COLOR_EDIT_BG if control.enabled and not readonly
                             else self.COLOR_BUTTON, rect)
            inset = self._draw_window_edge(rect, control.style, control.ex_style)
            self._draw_edit_text(control, rect, padding=inset + 2)

        elif control.class_name == "LISTBOX":
            rect = pygame.Rect(abs_x, abs_y, control.width, control.height)
            pygame.draw.rect(self.screen, self.COLOR_EDIT_BG, rect)
            pygame.draw.rect(self.screen, (128, 128, 128), rect, 1)

            # Items with the selected one highlighted, and the scroll bar
            geo = self._listbox_rects(control, (abs_x, abs_y))
            prev_clip = self.screen.get_clip()
            for i, item_rect in geo['items']:
                selected = (i == control.sel_index)
                if selected:
                    pygame.draw.rect(self.screen, self.COLOR_TITLE_BAR, item_rect)
                color = self.COLOR_TITLE_TEXT if selected else self.COLOR_TEXT
                text = self.font.render(control.items[i], True, color)
                self.screen.set_clip(item_rect.clip(prev_clip))
                self.screen.blit(text, (item_rect.x + 3, item_rect.y + 1))
                self.screen.set_clip(prev_clip)
            self._draw_list_scrollbar(geo, control.hwnd)

        elif control.class_name == "COMBOBOX":
            box_h = min(control.height, 24)
            rect = pygame.Rect(abs_x, abs_y, control.width, box_h)
            pygame.draw.rect(self.screen, self.COLOR_EDIT_BG if control.enabled
                             else self.COLOR_BUTTON, rect)
            self._draw_window_edge(rect, 0, 0x200)  # Sunken like WS_EX_CLIENTEDGE

            # Selected item text (editable combos: the edit field's text)
            sel_text = ""
            if control.style & 0x3 in (1, 2):  # CBS_SIMPLE, CBS_DROPDOWN
                self._draw_edit_text(control, pygame.Rect(abs_x, abs_y, control.width - 18,
                                                          box_h))
            elif 0 <= control.sel_index < len(control.items):
                sel_text = control.items[control.sel_index]
            if sel_text:
                prev_clip = self.screen.get_clip()
                self.screen.set_clip(rect)
                text = self.font.render(sel_text, True, self.COLOR_TEXT)
                self.screen.blit(text, (abs_x + 4, abs_y + (box_h - text.get_height()) // 2))
                self.screen.set_clip(prev_clip)

            # Dropdown arrow inside the sunken edge
            arrow_rect = pygame.Rect(abs_x + control.width - 18, abs_y + 2, 16, box_h - 4)
            self._draw_button_3d(arrow_rect, "", small=True, arrow='down')

        elif control.class_name in ["CHECKBOX", "BS_CHECKBOX"]:
            self._fill_ctl_background(control, pygame.Rect(abs_x, abs_y, control.width,
                                                           control.height))
            if (control.style & 0xF) in (0x4, 0x9):  # Radio button
                center = (abs_x + 6, abs_y + 8)
                pygame.draw.circle(self.screen, self.COLOR_EDIT_BG, center, 6)
                pygame.draw.circle(self.screen, (128, 128, 128), center, 6, 1)
                if control.checked:
                    pygame.draw.circle(self.screen, self.COLOR_TEXT, center, 2)
                text = self.font.render(self._mnemonic_text(control.text), True,
                                        *self._ctl_text_colors(control))
                self.screen.blit(text, (abs_x + 18, abs_y))
                return
            # Checkbox box
            box_rect = pygame.Rect(abs_x, abs_y + 2, 13, 13)
            pygame.draw.rect(self.screen, self.COLOR_EDIT_BG, box_rect)
            pygame.draw.rect(self.screen, (128, 128, 128), box_rect, 1)
            if control.checked:
                pygame.draw.line(self.screen, self.COLOR_TEXT,
                               (abs_x + 2, abs_y + 8), (abs_x + 5, abs_y + 11), 2)
                pygame.draw.line(self.screen, self.COLOR_TEXT,
                               (abs_x + 5, abs_y + 11), (abs_x + 11, abs_y + 4), 2)
            # Label
            text = self.font.render(self._mnemonic_text(control.text), True,
                                    *self._ctl_text_colors(control))
            self.screen.blit(text, (abs_x + 18, abs_y))

        elif control.class_name == "PROGRESSBAR":
            self._draw_progressbar(control, abs_x, abs_y)

        elif control.class_name == "SCROLLBAR":
            m = self._scrollbar_metrics(control, abs_x, abs_y)

            # Track (classic dotted-gray look approximated with a light gray)
            pygame.draw.rect(self.screen, (224, 224, 224), m['track'])
            pygame.draw.rect(self.screen, (128, 128, 128),
                             pygame.Rect(abs_x, abs_y, control.width, control.height), 1)

            # Arrow buttons
            if m['vertical']:
                self._draw_button_3d(m['up'], "", small=True, arrow='up')
                self._draw_button_3d(m['down'], "", small=True, arrow='down')
            else:
                self._draw_button_3d(m['up'], "", small=True, arrow='left')
                self._draw_button_3d(m['down'], "", small=True, arrow='right')

            # Thumb (pressed look while dragging)
            dragging = (self.dragging_scrollbar is not None and
                        self.dragging_scrollbar[0] == control.hwnd)
            self._draw_button_3d(m['thumb'], "", pressed=dragging)

    def _draw_window_edge(self, rect, style, ex_style):
        """Classic border of a child window by its styles: WS_EX_CLIENTEDGE
        (2 px sunken), WS_EX_STATICEDGE (1 px sunken), WS_BORDER (1 px black).
        Returns the border width."""
        x, y, r, b = rect.x, rect.y, rect.right - 1, rect.bottom - 1
        draw = pygame.draw.line
        if ex_style & 0x200:  # WS_EX_CLIENTEDGE
            draw(self.screen, (128, 128, 128), (x, y), (r - 1, y))
            draw(self.screen, (128, 128, 128), (x, y), (x, b - 1))
            draw(self.screen, self.COLOR_BUTTON_BORDER_LIGHT, (x, b), (r, b))
            draw(self.screen, self.COLOR_BUTTON_BORDER_LIGHT, (r, y), (r, b))
            draw(self.screen, self.COLOR_BUTTON_BORDER_DARK, (x + 1, y + 1), (r - 2, y + 1))
            draw(self.screen, self.COLOR_BUTTON_BORDER_DARK, (x + 1, y + 1), (x + 1, b - 2))
            draw(self.screen, self.COLOR_BUTTON, (x + 1, b - 1), (r - 1, b - 1))
            draw(self.screen, self.COLOR_BUTTON, (r - 1, y + 1), (r - 1, b - 1))
            return 2
        if ex_style & 0x20000:  # WS_EX_STATICEDGE
            draw(self.screen, (128, 128, 128), (x, y), (r - 1, y))
            draw(self.screen, (128, 128, 128), (x, y), (x, b - 1))
            draw(self.screen, self.COLOR_BUTTON_BORDER_LIGHT, (x, b), (r, b))
            draw(self.screen, self.COLOR_BUTTON_BORDER_LIGHT, (r, y), (r, b))
            return 1
        if style & 0x00800000:  # WS_BORDER
            pygame.draw.rect(self.screen, (0, 0, 0), rect, 1)
            return 1
        return 0

    def _draw_group_box(self, control, rect):
        """BS_GROUPBOX: etched frame with the caption on its top edge"""
        caption = self._mnemonic_text(control.text)
        text = self.font.render(caption, True, self.COLOR_TEXT) if caption else None
        top = rect.y + (text.get_height() // 2 if text else 0)
        frame = pygame.Rect(rect.x, top, rect.width - 1, rect.bottom - top - 1)
        pygame.draw.rect(self.screen, self.COLOR_BUTTON_BORDER_DARK, frame, 1)
        pygame.draw.rect(self.screen, self.COLOR_BUTTON_BORDER_LIGHT, frame.move(1, 1), 1)
        if text:
            label = pygame.Rect(rect.x + 8, rect.y, text.get_width() + 4, text.get_height())
            pygame.draw.rect(self.screen, self.COLOR_BUTTON, label)
            self.screen.blit(text, (label.x + 2, label.y))

    def _draw_edge(self, rect, top_left, bottom_right):
        """One-pixel 3D edge around rect: top and left lines in one color,
        bottom and right lines in the other"""
        if rect.width <= 0 or rect.height <= 0:
            return
        x, y, r, b = rect.x, rect.y, rect.right - 1, rect.bottom - 1
        pygame.draw.line(self.screen, top_left, (x, y), (r, y))
        pygame.draw.line(self.screen, top_left, (x, y), (x, b))
        pygame.draw.line(self.screen, bottom_right, (r, y), (r, b))
        pygame.draw.line(self.screen, bottom_right, (x, b), (r, b))

    def _draw_raised(self, rect):
        """Classic 2-pixel raised edge (window frames, buttons, menus)"""
        self._draw_edge(rect, self.COLOR_BUTTON, self.COLOR_BUTTON_BORDER_DARK)
        self._draw_edge(rect.inflate(-2, -2), self.COLOR_BUTTON_BORDER_LIGHT,
                        self.COLOR_BUTTON_SHADOW)

    def _draw_sunken(self, rect):
        """Classic 2-pixel sunken edge of a pressed button"""
        self._draw_edge(rect, self.COLOR_BUTTON_BORDER_DARK, self.COLOR_BUTTON_BORDER_LIGHT)
        self._draw_edge(rect.inflate(-2, -2), self.COLOR_BUTTON_SHADOW, self.COLOR_BUTTON)

    def _gradient(self, size, start, end, horizontal=True):
        """Surface of this size shading from start to end, left to right (or
        top to bottom); cached"""
        key = (size, start, end, horizontal)
        surface = self._gradient_cache.get(key)
        if surface is None:
            width, height = size
            surface = pygame.Surface((max(1, width), max(1, height)))
            steps = width if horizontal else height
            for i in range(steps):
                t = i / max(1, steps - 1)
                color = tuple(round(a + (b - a) * t) for a, b in zip(start, end, strict=False))
                if horizontal:
                    pygame.draw.line(surface, color, (i, 0), (i, height - 1))
                else:
                    pygame.draw.line(surface, color, (0, i), (width - 1, i))
            if len(self._gradient_cache) > 64:
                self._gradient_cache.clear()  # Old window sizes
            self._gradient_cache[key] = surface
        return surface

    SHADOW_SIZE = 4

    def _draw_shadow(self, rect):
        """Soft drop shadow at the right and the bottom of a window or menu"""
        size = self.SHADOW_SIZE
        for i in range(size):
            alpha = 56 - i * 12
            right = pygame.Surface((1, rect.height - size + 1 + i), pygame.SRCALPHA)
            right.fill((0, 0, 0, alpha))
            self.screen.blit(right, (rect.right + i, rect.y + size - i))
            bottom = pygame.Surface((rect.width - size + 1 + i, 1), pygame.SRCALPHA)
            bottom.fill((0, 0, 0, alpha))
            self.screen.blit(bottom, (rect.x + size - i, rect.bottom + i))

    def _draw_button_3d(self, rect, text, pressed=False, small=False, arrow=None, bold=False,
                        disabled=False):
        """Draw 3D-style button.

        When ``arrow`` is one of 'up'/'down'/'left'/'right', a filled triangle
        is drawn instead of ``text``. Triangles render crisply at any size and
        don't depend on the system font carrying Unicode arrow glyphs.
        """
        pygame.draw.rect(self.screen, self.COLOR_BUTTON, rect)
        if pressed:
            self._draw_sunken(rect)
        else:
            self._draw_raised(rect)

        if arrow:
            self._draw_arrow(rect, arrow, pressed=pressed)
            return

        # Text
        font = (self.font_small_bold if bold else self.font_small) if small else (
            self.font_bold if bold else self.font)
        if disabled:
            # Embossed gray text (COLOR_GRAYTEXT with a white shadow)
            shadow = font.render(text, True, self.COLOR_BUTTON_BORDER_LIGHT)
            self.screen.blit(shadow, shadow.get_rect(center=(rect.centerx + 1,
                                                            rect.centery + 1)))
        text_surface = font.render(text, True, (128, 128, 128) if disabled else self.COLOR_TEXT)
        text_rect = text_surface.get_rect(center=rect.center)
        if pressed:
            text_rect.move_ip(1, 1)  # The face moves in with the press
        self.screen.blit(text_surface, text_rect)

    def _draw_arrow(self, rect, direction, pressed=False):
        """Draw a small filled triangle centered in ``rect``.

        ``direction`` is 'up', 'down', 'left' or 'right'. Used for scrollbar
        arrow buttons and the combo-box dropdown, replacing font glyphs that
        render poorly (or not at all) at small sizes on some systems.
        """
        cx, cy = rect.center
        if pressed:
            cx += 1
            cy += 1
        dw, dh = 3, 2  # triangle half-base / depth -> 7px base, 4px tall
        if direction == 'down':
            points = [(cx - dw, cy - dh), (cx + dw, cy - dh), (cx, cy + dh)]
        elif direction == 'up':
            points = [(cx - dw, cy + dh), (cx + dw, cy + dh), (cx, cy - dh)]
        elif direction == 'right':
            points = [(cx - dh, cy - dw), (cx - dh, cy + dw), (cx + dh, cy)]
        else:  # 'left'
            points = [(cx + dh, cy - dw), (cx + dh, cy + dw), (cx - dh, cy)]
        pygame.draw.polygon(self.screen, self.COLOR_TEXT, points)

    def _draw_window_button(self, rect, symbol, btn_type):
        """Draw a caption button (minimize, maximize / restore, close) with a
        classic raised face and a crisp black glyph"""
        pygame.draw.rect(self.screen, self.COLOR_BUTTON, rect)
        self._draw_raised(rect)
        black = self.COLOR_TEXT
        cx, cy = rect.centerx, rect.centery
        if btn_type == "close":
            # 8x7 "x" drawn two pixels thick
            x0, y0 = cx - 4, cy - 4
            for dx in (0, 1):
                pygame.draw.line(self.screen, black, (x0 + dx, y0), (x0 + dx + 6, y0 + 6))
                pygame.draw.line(self.screen, black, (x0 + dx + 6, y0), (x0 + dx, y0 + 6))
        elif btn_type == "max" and symbol == "❐":
            # Restore: two overlapping windows, the front one lower left
            back = pygame.Rect(cx - 2, cy - 5, 6, 6)
            front = pygame.Rect(cx - 5, cy - 2, 6, 6)
            for box in (back, front):
                pygame.draw.rect(self.screen, self.COLOR_BUTTON, box)
                pygame.draw.rect(self.screen, black, box, 1)
                pygame.draw.line(self.screen, black, (box.x, box.y + 1), (box.right - 1, box.y + 1))
        elif btn_type == "max":
            # Maximize: a window with a thick caption
            box = pygame.Rect(cx - 5, cy - 5, 9, 9)
            pygame.draw.rect(self.screen, black, box, 1)
            pygame.draw.line(self.screen, black, (box.x, box.y + 1), (box.right - 1, box.y + 1))
        elif btn_type == "min":
            # Minimize: a short thick bar at the bottom
            pygame.draw.rect(self.screen, black, pygame.Rect(cx - 4, cy + 2, 6, 2))
