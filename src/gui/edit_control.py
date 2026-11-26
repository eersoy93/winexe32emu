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

"""PseudoWindowsGUI mixin: multiline EDIT controls: word wrap, the vertical
scroll bar (WS_VSCROLL), the mouse wheel and Page Up / Page Down"""

from ..config import PYGAME_AVAILABLE

if PYGAME_AVAILABLE:
    import pygame


class EditControlMixin:
    """Multiline EDIT controls: word wrap, scroll bar, wheel and paging"""

    WS_VSCROLL = 0x00200000

    def _edit_measure(self, font):
        """A function giving a character's width in font. The same function
        for the same font, so that the edit's wrapped lines stay cached."""
        measures = getattr(self, '_edit_measures', None)
        if measures is None:
            measures = self._edit_measures = {}
        measure = measures.get(font)
        if measure is None:
            widths = {}

            def measure(char):
                width = widths.get(char)
                if width is None:
                    width = widths[char] = font.size(char)[0]
                return width
            measures[font] = measure
        return measure

    @classmethod
    def _edit_has_vscroll(cls, control):
        return (control.class_name == 'EDIT' and control.style & 0x4 and
                control.style & cls.WS_VSCROLL)

    @staticmethod
    def _edit_inset(control):
        """Border width of an edit control (see _draw_window_edge)"""
        if control.ex_style & 0x200:  # WS_EX_CLIENTEDGE
            return 2
        return 1 if control.ex_style & 0x20000 or control.style & 0x00800000 else 0

    def _edit_scrollbar_rects(self, control, abs_x, abs_y):
        """Geometry of a multiline edit's vertical scroll bar at screen
        (abs_x, abs_y): 'bar', 'up', 'down', 'track', 'thumb' rects, 'rows'
        shown and 'span' (lines it can scroll); None without WS_VSCROLL"""
        if not self._edit_has_vscroll(control):
            return None
        inset, btn = self._edit_inset(control), self.SCROLL_BTN
        bar = pygame.Rect(abs_x + control.width - inset - btn, abs_y + inset, btn,
                          max(0, control.height - 2 * inset))
        b = min(btn, bar.height // 2)
        track = pygame.Rect(bar.x, bar.y + b, btn, max(0, bar.height - 2 * b))
        count = len(control.edit_lines())
        rows = max(1, control.edit_visible_lines)
        span = max(0, count - rows)
        thumb = pygame.Rect(bar.x, track.y, btn, 0)
        if span and track.height >= self.SCROLL_MIN_THUMB:
            thumb.height = min(track.height, max(self.SCROLL_MIN_THUMB,
                                                 track.height * rows // count))
            thumb.y = track.y + (track.height - thumb.height) * min(
                control.edit_top_line, span) // span
        return {'bar': bar, 'up': pygame.Rect(bar.x, bar.y, btn, b),
                'down': pygame.Rect(bar.x, bar.bottom - b, btn, b), 'track': track,
                'thumb': thumb, 'rows': rows, 'span': span}

    def _edit_text_rect(self, control, rect):
        """The part of an edit control's rect left for its text (not its scroll bar)"""
        if not self._edit_has_vscroll(control):
            return rect
        return pygame.Rect(rect.x, rect.y, max(1, rect.width - self.SCROLL_BTN), rect.height)

    def _draw_edit_scrollbar(self, control, abs_x, abs_y):
        geo = self._edit_scrollbar_rects(control, abs_x, abs_y)
        if geo is None or geo['bar'].height < 4:
            return
        pygame.draw.rect(self.screen, (224, 224, 224), geo['track'])
        self._draw_button_3d(geo['up'], "", small=True, arrow='up')
        self._draw_button_3d(geo['down'], "", small=True, arrow='down')
        if geo['thumb'].height:
            dragging = (self.dragging_list_thumb is not None and
                        self.dragging_list_thumb[0] == control.hwnd)
            self._draw_button_3d(geo['thumb'], "", pressed=dragging)

    @staticmethod
    def _edit_scroll(control, delta):
        """Scroll a multiline edit's view by delta lines; the caret stays (the
        view does not jump back to it)"""
        lines = len(control.edit_lines())
        rows = max(1, control.edit_visible_lines)
        control.edit_top_line = max(0, min(control.edit_top_line + delta, max(0, lines - rows)))
        control.edit_caret_shown = (control.sel_caret, control.text)

    def _edit_scrollbar_click(self, control, pos, abs_x, abs_y):
        """A left click on an edit's scroll bar; True if it hit the bar"""
        geo = self._edit_scrollbar_rects(control, abs_x, abs_y)
        if geo is None or not geo['bar'].collidepoint(pos):
            return False
        rows = geo['rows']
        if geo['up'].collidepoint(pos):
            self._edit_scroll(control, -1)
        elif geo['down'].collidepoint(pos):
            self._edit_scroll(control, 1)
        elif geo['thumb'].height and geo['thumb'].collidepoint(pos):
            self.dragging_list_thumb = (control.hwnd, pos[1] - geo['thumb'].y)
        elif geo['thumb'].height and pos[1] < geo['thumb'].y:
            self._edit_scroll(control, -rows)
        elif geo['thumb'].height:
            self._edit_scroll(control, rows)
        return True

    def _drag_edit_thumb_to(self, control, pos, grab):
        """Track a thumb drag in an edit's scroll bar"""
        origin = self._scrollbar_abs_pos(control)
        geo = self._edit_scrollbar_rects(control, *origin) if origin else None
        if geo is None or not geo['span'] or not geo['thumb'].height:
            self.dragging_list_thumb = None
            return
        free = geo['track'].height - geo['thumb'].height
        if free <= 0:
            return
        offset = max(0, min(pos[1] - grab - geo['track'].y, free))
        control.edit_top_line = (offset * geo['span'] + free // 2) // free
        control.edit_caret_shown = (control.sel_caret, control.text)

    def _edit_page(self, control, caret, down):
        """Page Up / Page Down: the view and the caret move by the lines shown;
        returns the caret's new offset"""
        lines = control.edit_lines()
        rows = max(1, control.edit_visible_lines - 1)
        index = control.line_of(caret)
        target = max(0, min(len(lines) - 1, index + (rows if down else -rows)))
        self._edit_scroll(control, target - index)
        column = caret - lines[index][0]
        return min(lines[target][0] + column, lines[target][1])
