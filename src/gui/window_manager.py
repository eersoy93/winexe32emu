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

"""PseudoWindowsGUI mixin: Windows of the emulated programs: processes, creating, showing,
closing and removing windows and controls"""


from ..config import PYGAME_AVAILABLE
from ..logger import log
from ..windows import FakeControl, FakeWindow, gui_locked

if PYGAME_AVAILABLE:
    pass


class WindowManagerMixin:
    """Windows of the emulated programs: processes, creating, showing, closing and removing
    windows and controls"""

    @gui_locked
    def register_process(self, process):
        """A program starts: its windows get input from now on"""
        self.processes.append(process)

    @gui_locked
    def unregister_process(self, process):
        """A program ended: close its windows; its console stays to show the output"""
        if process in self.processes:
            self.processes.remove(process)
        if self.display_mode_owner is process:
            # Like Windows, a CDS_FULLSCREEN mode ends with its program
            self.set_display_mode(self.desktop_width, self.desktop_height)
        # Its message boxes go too (one shown by a thread when another one ends
        # the program, e.g. the main window closed while the box is up)
        for hwnd, box in list(self.messageboxes.items()):
            if box.get('process') is process:
                self._messagebox_done(hwnd, box['cancel'] or box['buttons'][box['focus']].mb_result)
        for hwnd, win in list(self.windows.items()):
            if win.owner is not process:
                continue
            console = self.consoles.get(hwnd)
            if console is None:
                self._remove_window(hwnd)
                continue
            self.cancel_console_input(console)
            win.owner = None
            win.title += " [finished]"

    def window_owner(self, hwnd):
        """Process (WinAPIHandler) owning a window or control, or None"""
        win = self.windows.get(hwnd)
        if win is None:
            control = self.controls.get(hwnd)
            win = self.windows.get(control.parent_hwnd) if control else None
        return win.owner if win else None

    @gui_locked
    def _remove_window(self, hwnd):
        """Delete a window, its child windows and its controls, dropping every
        reference to them"""
        win = self.windows.pop(hwnd, None)
        if win is None:
            return
        for child in list(win.children):
            self._remove_window(child)
        parent = self.windows.get(win.parent)
        if parent is not None and hwnd in parent.children:
            parent.children.remove(hwnd)
        if self.focused_window == hwnd:
            self.focused_window = None
        if self.open_native_combo == hwnd:
            self.open_native_combo = None
        for chwnd in [h for h, c in self.controls.items() if c.parent_hwnd == hwnd]:
            del self.controls[chwnd]
            if self.focused_control == chwnd:
                self.focused_control = None
            if self.open_combo == chwnd:
                self.open_combo = None
            if self.dragging_scrollbar and self.dragging_scrollbar[0] == chwnd:
                self.dragging_scrollbar = None
        if hwnd in self.z_order:
            self.z_order.remove(hwnd)
        if self.active_window == hwnd:
            self.active_window = self.z_order[-1] if self.z_order else None
        if self.open_menu and self.open_menu[0] == hwnd:
            self.open_menu = None
        if self.dragging_window == hwnd:
            self.dragging_window = None
        if self.resizing_window == hwnd:
            self.resizing_window = None

    @gui_locked
    def _close_window(self, hwnd, notify_app=True):
        """Close window.

        App windows with a WndProc get WM_CLOSE posted so the app decides
        (DestroyWindow / PostQuitMessage). Other windows are hidden directly.
        DestroyWindow calls this with notify_app=False to avoid a loop.
        """
        if hwnd not in self.windows:
            return

        box = self.messageboxes.get(hwnd)
        if box is not None:
            # Only a message box with a Cancel (or a lone OK) button can be closed
            if box['cancel'] is not None:
                self._messagebox_done(hwnd, box['cancel'])
            return

        console = self.consoles.get(hwnd)
        if console is not None:
            # Closing a console ends the program attached to it (like Windows)
            owner = self.windows[hwnd].owner
            if owner is not None:
                owner.request_termination()
            self.close_console(console)
            return

        if notify_app and self._is_app_window(hwnd):
            self.winapi.post_window_message(hwnd, self.winapi.WM_CLOSE, 0, 0)
            return

        self.windows[hwnd].visible = False
        if hwnd in self.z_order:
            self.z_order.remove(hwnd)
        if self.active_window == hwnd:
            self.active_window = self.z_order[-1] if self.z_order else None
        if self.open_menu and self.open_menu[0] == hwnd:
            self.open_menu = None

    @gui_locked
    def raise_window(self, hwnd):
        """Bring a top-level window to the top of the Z order, with the
        windows it owns (directly or not) above it, like Windows"""
        if hwnd not in self.z_order:
            return
        self.z_order.remove(hwnd)
        self.z_order.append(hwnd)
        raised = {hwnd}
        for other in list(self.z_order[:-1]):
            win = self.windows.get(other)
            owner = win.owner_hwnd if win is not None else 0
            seen = set()
            while owner and owner not in raised and owner not in seen:
                seen.add(owner)
                owner_win = self.windows.get(owner)
                owner = owner_win.owner_hwnd if owner_win is not None else 0
            if owner in raised:
                self.z_order.remove(other)
                self.z_order.append(other)
                raised.add(other)

    @gui_locked
    def get_next_hwnd(self):
        """Get new HWND"""
        hwnd = self.next_hwnd
        self.next_hwnd += 4
        return hwnd

    @gui_locked
    def create_window(self, title, x, y, width, height, style=0, owner=None, parent=0):
        """Create new window (a child window if parent is a window handle)"""
        hwnd = self.get_next_hwnd()
        window = FakeWindow(hwnd, title, x, y, width, height, style)
        window.owner = owner
        emu = getattr(owner, 'emu', None)
        if emu is not None:
            window.thread_id = emu.current_thread.tid
        # The title bar shows the owning program's EXE icon
        loader = getattr(getattr(owner, 'emu', None), 'pe_loader', None)
        window.icon_path = getattr(loader, 'filepath', None)
        self.windows[hwnd] = window
        if parent in self.windows:
            # Child windows are drawn inside their parent, not on the desktop
            window.parent = parent
            self.windows[parent].children.append(hwnd)
        else:
            self.z_order.append(hwnd)

        log.debug(f"GUI: Window created - HWND=0x{hwnd:08x}, '{title}'")
        return hwnd

    @gui_locked
    def create_control(self, parent_hwnd, class_name, text, x, y, width, height, style=0,
                       control_id=0, ex_style=0, hwnd=None):
        """Create new control (hwnd: the handle of a window it replaces)"""
        hwnd = hwnd or self.get_next_hwnd()
        control = FakeControl(hwnd, class_name, text, x, y, width, height, style, ex_style)
        control.parent_hwnd = parent_hwnd
        control.control_id = control_id

        self.controls[hwnd] = control

        if parent_hwnd in self.windows:
            self.windows[parent_hwnd].controls.append(control)

        log.debug(f"GUI: Control created - HWND=0x{hwnd:08x}, {class_name}, '{text}'")
        return hwnd

    @gui_locked
    def destroy_control(self, hwnd):
        """Remove a child control (DestroyWindow)"""
        control = self.controls.pop(hwnd, None)
        if control is None:
            return
        parent = self.windows.get(control.parent_hwnd)
        if parent is not None:
            parent.controls = [c for c in parent.controls if c.hwnd != hwnd]
        if self.focused_control == hwnd:
            self.focused_control = None
        if self.open_combo == hwnd:
            self.open_combo = None

    @gui_locked
    def show_window(self, hwnd, show=True):
        """Show/hide window"""
        if hwnd in self.windows:
            self.windows[hwnd].visible = show
            if show and not self.windows[hwnd].parent:
                self.active_window = hwnd
                if hwnd not in self.z_order:
                    self.z_order.append(hwnd)
            elif not show and self.active_window == hwnd:
                # Like Windows, hiding the active window activates the next
                # one (Office's file dialogs hide a window that kept the keys)
                self._activate_next_window()
                if self.active_window == hwnd:
                    self.active_window = None
        elif hwnd in self.controls:
            self.controls[hwnd].visible = show

    @gui_locked
    def set_window_text(self, hwnd, text):
        """Set window/control text"""
        if hwnd in self.windows:
            self.windows[hwnd].title = text
            self.windows[hwnd].text = text
        elif hwnd in self.controls:
            control = self.controls[hwnd]
            control.text = text
            # Like WM_SETTEXT of an edit control: caret at the start, unmodified
            control.set_selection(0)
            control.edit_scroll = control.edit_top_line = 0
            control.modified = False

    def get_window_text(self, hwnd):
        """Get window/control text"""
        if hwnd in self.windows:
            return self.windows[hwnd].text
        elif hwnd in self.controls:
            return self.controls[hwnd].text
        return ""

    def show_messagebox(self, caption, text, msg_type=0, request=None, process=None):
        """Show MessageBox (thread-safe); the chosen button's id is stored in
        request['result'] when it closes. process (if any) owns it: the box
        closes when that program ends."""
        self.messagebox_queue.put({
            'caption': caption,
            'text': text,
            'type': msg_type,
            'request': request,
            'process': process,
        })
        return 1  # IDOK
