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

"""WinAPIHandler mixin: the screen bits a child window leaves behind when it
is hidden or moved with SWP_NOREDRAW"""


class WindowBitsMixin:
    """SetWindowPos with SWP_NOREDRAW does not repaint what a child window
    uncovers: on Windows its last image stays on the screen until the parent
    paints that place again. Access 95's table grids rely on it: the cell
    editor is hidden "without redraw" when the caret leaves a cell, and the
    text it showed is what the user sees in the cell. The emulator draws every
    window from its display list, so the child's image is copied into the
    parent's list, where the parent's next painting of the place covers it."""

    def _unpainted_bits(self):
        """hwnd -> the display list a child window had when it was shown or
        moved without redrawing: until it draws again (a new list object), its
        list is not what the screen shows at its place"""
        return self.__dict__.setdefault('_unpainted_window_bits', {})

    def _window_pos_bits(self, win, flags, moves):
        """SetWindowPos of the child window win (before it is applied):
        SWP_NOREDRAW leaves its image when it hides or moves it, and its list
        is stale after a show or move that is not drawn"""
        if not flags & self.SWP_NOREDRAW or not win.parent:
            return
        if flags & self.SWP_HIDEWINDOW or (moves and win.visible):
            self._leave_window_bits(win)
        if (flags & self.SWP_SHOWWINDOW and not win.visible) or moves:
            self._unpainted_bits()[win.hwnd] = win.drawn_shapes

    SWP_SHOWWINDOW, SWP_HIDEWINDOW = 0x0040, 0x0080

    def _leave_window_bits(self, win):
        """Copy the visible child window win's client image to its parent's
        display list (at the place it covers now)"""
        if not self.gui or not win.parent or not win.visible or not win.drawn_shapes:
            return
        stale = self._unpainted_bits().pop(win.hwnd, None)
        if stale is win.drawn_shapes:
            return  # Not drawn at this place: the parent's image is still there
        parent = self.gui.windows.get(win.parent)
        if parent is None or not parent.visible:
            return
        flatten = getattr(self.gui, '_flatten_shapes', None)
        if flatten is None:
            return
        with self.gui.lock:
            image = flatten(win, list(win.drawn_shapes))
        if image is None:
            return
        border, caption = self.gui.child_frame(win)
        image = dict(image, pos=(win.x + border, win.y + border + caption))
        self.gui.add_shape(parent.hwnd, image)
