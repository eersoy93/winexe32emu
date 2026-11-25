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

"""WinAPIHandler mixin: the multiple document interface (MDICLIENT,
DefFrameProc, DefMDIChildProc, CreateMDIWindow)"""

import struct

from unicorn import UcError


class MdiMixin:
    """Multiple document interface.

    The MDI client is an emulated control window (native kind 'MDICLIENT',
    its procedure is NativeWndProc, so programs can subclass it). Its MDI
    children are ordinary child windows of the program's classes; the
    client keeps which one is active, which one is maximized and the
    "Window" menu items listing them in win.nstate.
    """

    WM_MDICREATE, WM_MDIDESTROY, WM_MDIACTIVATE, WM_MDIRESTORE = 0x220, 0x221, 0x222, 0x223
    WM_MDINEXT, WM_MDIMAXIMIZE, WM_MDITILE, WM_MDICASCADE = 0x224, 0x225, 0x226, 0x227
    WM_MDIICONARRANGE, WM_MDIGETACTIVE = 0x228, 0x229
    WM_MDISETMENU, WM_MDIREFRESHMENU = 0x230, 0x234
    WM_CHILDACTIVATE, WM_NCACTIVATE, WM_GETMINMAXINFO = 0x0022, 0x0086, 0x0024
    WM_SETTEXT = 0x000C
    WS_EX_MDICHILD = 0x40
    # The styles an MDI child always has (WS_CHILD, WS_CLIPSIBLINGS, WS_CAPTION,
    # WS_SYSMENU, WS_THICKFRAME, WS_MINIMIZEBOX, WS_MAXIMIZEBOX)
    MDI_CHILD_STYLES = 0x40000000 | 0x04000000 | 0x00C00000 | 0x00080000 | 0x00040000 | \
        0x00020000 | 0x00010000
    WS_MAXIMIZE, WS_MINIMIZE = 0x01000000, 0x20000000
    # (SC_SIZE, SC_MOVE, SC_MINIMIZE, SC_MAXIMIZE, SC_RESTORE: User32MiscMixin)
    SC_NEXTWINDOW, SC_PREVWINDOW = 0xF040, 0xF050
    MDIS_ALLCHILDSTYLES = 0x0001
    MDI_MAX_MENU_ITEMS = 9  # Like Windows: "More Windows..." after nine
    COLOR_APPWORKSPACE = (128, 128, 128)

    # ---------- The client window ----------

    def _mdi_client_init(self, win, lpParam):
        """A new MDICLIENT window: its CLIENTCREATESTRUCT (window menu, first
        child id) comes in lpCreateParams"""
        window_menu = first_child = 0
        if lpParam:
            try:
                window_menu, first_child = struct.unpack(
                    '<II', self.emu.uc.mem_read(lpParam, 8))
            except UcError:
                pass
        win.bg_color = self.COLOR_APPWORKSPACE
        win.nstate.update(window_menu=window_menu, first_child=first_child & 0xFFFF,
                          active=0, maximized=0, menu_children=[])

    def _mdi_client(self, hwnd):
        """The MDICLIENT window hwnd, or None"""
        return self._native_window(hwnd, 'MDICLIENT') if self.gui else None

    def _mdi_client_of(self, child):
        """The MDI client a child window belongs to, or None"""
        win = self.gui.windows.get(child) if self.gui else None
        return self._mdi_client(win.parent) if win is not None and win.parent else None

    def _mdi_children(self, client):
        """The client's MDI child windows, in Z order (top first)"""
        return [h for h in client.children if h in self.gui.windows]

    def _mdiclient_message(self, win, msg, wParam, lParam, wide):
        """Messages of the MDI client window; None for the default ones"""
        st = win.nstate
        if msg == self.WM_MDICREATE:
            return self._mdi_create(win, lParam, wide)
        if msg == self.WM_MDIDESTROY:
            if wParam in self.gui.windows:
                self.DestroyWindow([wParam])
            return 0
        if msg == self.WM_MDIACTIVATE:
            if wParam in self._mdi_children(win):
                self._mdi_activate(win, wParam)
            return 0
        if msg == self.WM_MDIGETACTIVE:
            active = st['active'] if st['active'] in self.gui.windows else 0
            if lParam:
                self._mem_write(lParam, struct.pack('<I', 1 if active and
                                                    active == st['maximized'] else 0))
            return active
        if msg == self.WM_MDIMAXIMIZE:
            if wParam in self.gui.windows:
                self._mdi_maximize(win, wParam)
            return 0
        if msg == self.WM_MDIRESTORE:
            if wParam in self.gui.windows:
                self._mdi_restore(win, wParam)
            return 0
        if msg == self.WM_MDINEXT:
            self._mdi_next(win, wParam, bool(lParam))
            return 0
        if msg == self.WM_MDICASCADE:
            self._mdi_cascade(win)
            return 1
        if msg == self.WM_MDITILE:
            self._mdi_tile(win, wParam)
            return 1
        if msg == self.WM_MDIICONARRANGE:
            return 0
        if msg == self.WM_MDISETMENU:
            return self._mdi_set_menu(win, wParam, lParam)
        if msg == self.WM_MDIREFRESHMENU:
            self._mdi_update_window_menu(win)
            frame = self.gui.windows.get(win.parent)
            return frame.menu_handle if frame is not None else 0
        if msg == self.WM_SETFOCUS:
            # The active child gets the focus
            active = st['active']
            if active in self.gui.windows and not self.gui.windows[active].minimized:
                self.SetFocus([active])
            return 0
        if msg == self.WM_SIZE:
            maximized = st['maximized']
            if maximized in self.gui.windows:
                self._mdi_fit_maximized(win, maximized)
            return 0
        return None

    # ---------- Creating, activating, destroying children ----------

    def _mdi_create(self, client, lParam, wide):
        """WM_MDICREATE: create the MDI child its MDICREATESTRUCT describes"""
        try:
            (sz_class, sz_title, owner, x, y, cx, cy, style,
             _param) = struct.unpack('<IIIiiiiII', self.emu.uc.mem_read(lParam, 36))
        except UcError:
            return 0
        args = [self.WS_EX_MDICHILD, sz_class, sz_title, style, x & 0xFFFFFFFF,
                y & 0xFFFFFFFF, cx & 0xFFFFFFFF, cy & 0xFFFFFFFF, client.hwnd, 0, owner,
                lParam]
        self._mdi_creating = lParam  # lpCreateParams is the MDICREATESTRUCT itself
        try:
            return self.CreateWindowExA(args, wide)
        finally:
            self._mdi_creating = 0

    def _mdi_child_style(self, client, style):
        """The style an MDI child of the client gets"""
        if not client.style & self.MDIS_ALLCHILDSTYLES:
            style |= self.MDI_CHILD_STYLES
        return (style | 0x40000000) & ~0x80000000  # WS_CHILD, never WS_POPUP

    def _mdi_default_rect(self, client, x, y, width, height, default):
        """Position of a new MDI child with CW_USEDEFAULT coordinates: the
        next cascade position, three quarters of the client"""
        cw, ch = self.gui.client_size(client)
        step = self.gui.TITLE_BAR_H + 2
        count = len(self._mdi_children(client))
        if default[0]:
            x = y = (count % 8) * step
        if default[1]:
            width, height = max(cw * 3 // 4, 100), max(ch * 3 // 4, 60)
        return x, y, width, height

    def _mdi_create_params(self, client, args, wide):
        """CreateWindowEx of an MDI child (WS_EX_MDICHILD or an MDICLIENT
        parent): (style, x, y, width, height, lpParam) to create it with.
        lpCreateParams of its WM_CREATE points to an MDICREATESTRUCT."""
        CW_USEDEFAULT = 0x80000000
        style = self._mdi_child_style(client, args[3])
        x, y, width, height = self._read_signed_args(args, 4, 4)
        default = (args[4] == CW_USEDEFAULT, args[6] == CW_USEDEFAULT)
        x, y, width, height = self._mdi_default_rect(client, x, y, width, height, default)
        lp_param = getattr(self, '_mdi_creating', 0)
        if not lp_param:
            lp_param = self.emu.heap_alloc(36)
            self._mem_write(lp_param, struct.pack(
                '<IIIiiiiII', args[1], args[2], args[10], x, y, width, height,
                style & 0xFFFFFFFF, args[11]))
            self.__dict__.setdefault('_mdi_create_structs', []).append(lp_param)
        return style, x, y, width, height, lp_param

    def _mdi_child_created(self, hwnd):
        """A new MDI child is shown and activated (or maximized like the
        active one)"""
        client = self._mdi_client_of(hwnd)
        win = self.gui.windows.get(hwnd) if client is not None else None
        if win is None:
            return
        for address in self.__dict__.pop('_mdi_create_structs', []):
            self.emu.heap_free(address)
        win.ex_style |= self.WS_EX_MDICHILD
        maximize = bool(win.style & self.WS_MAXIMIZE) or \
            client.nstate['maximized'] in self.gui.windows
        if win.style & self.WS_VISIBLE or maximize:
            self.gui.show_window(hwnd, True)
        if not win.visible:
            return
        self._mdi_activate(client, hwnd)
        if maximize:
            self._mdi_maximize(client, hwnd)
        else:
            self._send_size(hwnd)
        self._mdi_update_window_menu(client)

    def _mdi_activate(self, client, child):
        """Make child the active MDI child (0: none): the old one gets
        WM_NCACTIVATE(FALSE) and WM_MDIACTIVATE, the new one comes to the top,
        WM_NCACTIVATE(TRUE), WM_MDIACTIVATE and the focus"""
        st = client.nstate
        old = st['active'] if st['active'] in self.gui.windows else 0
        if child:
            with self.gui.lock:
                if child in client.children:
                    client.children.remove(child)
                    client.children.insert(0, child)
        if old == child:
            if child and self.gui.top_level_of(child) == self.gui.active_window:
                self.SetFocus([child])
            return
        st['active'] = child
        if old and st['maximized'] == old and child:
            # The maximized state goes with the activation
            self._mdi_restore(client, old, refit=False)
            st['maximized'] = 0
            self._mdi_maximize(client, child)
        if old:
            self._send(old, self.WM_NCACTIVATE, 0, 0)
            self._send(old, self.WM_MDIACTIVATE, old, child)
        if child:
            self._send(child, self.WM_NCACTIVATE, 1, 0)
            self._send(child, self.WM_MDIACTIVATE, old, child)
            self.SetFocus([child])
        self._mdi_update_window_menu(client)

    def _mdi_child_destroyed(self, client, hwnd):
        """An MDI child is gone (DestroyWindow): the next one is activated"""
        st = client.nstate
        if st['maximized'] == hwnd:
            st['maximized'] = 0
            self._mdi_frame_title(client)
        if st['active'] == hwnd:
            st['active'] = 0
            rest = [h for h in self._mdi_children(client) if h != hwnd and
                    self.gui.windows[h].visible]
            if rest:
                self._mdi_activate(client, rest[0])
            elif self.gui.windows.get(client.parent) is not None:
                self.SetFocus([client.parent])
        self._mdi_update_window_menu(client)

    def _mdi_next(self, client, current, previous):
        """WM_MDINEXT: activate the child below current (or the bottom one)"""
        children = [h for h in self._mdi_children(client) if self.gui.windows[h].visible]
        if len(children) < 2:
            return
        if current not in children:
            current = client.nstate['active'] if client.nstate['active'] in children else \
                children[0]
        index = children.index(current)
        target = children[index - 1] if previous else children[(index + 1) % len(children)]
        if not previous:
            # The current one goes to the bottom, like Windows' Ctrl+F6
            with self.gui.lock:
                client.children.remove(current)
                client.children.append(current)
        self._mdi_activate(client, target)

    # ---------- Maximize, restore, arrange ----------

    def _mdi_fit_maximized(self, client, hwnd):
        """A maximized child covers the client area with its frame outside it"""
        win = self.gui.windows[hwnd]
        cw, ch = self.gui.client_size(client)
        border, caption = self.gui.child_frame_size(win.style, win.ex_style)
        self.SetWindowPos([hwnd, 0, (-border) & 0xFFFFFFFF, (-border - caption) & 0xFFFFFFFF,
                           cw + 2 * border, ch + 2 * border + caption, 0x14])  # NOZORDER|NOACTIVATE

    def _mdi_maximize(self, client, hwnd):
        """Maximize an MDI child inside the client (its title joins the frame's)"""
        st = client.nstate
        win = self.gui.windows[hwnd]
        old = st['maximized']
        if old and old != hwnd and old in self.gui.windows:
            self._mdi_restore(client, old, refit=False)
        if not win.maximized:
            win.restore_x, win.restore_y = win.x, win.y
            win.restore_width, win.restore_height = win.width, win.height
        win.maximized, win.minimized = True, False
        win.style = (win.style | self.WS_MAXIMIZE) & ~self.WS_MINIMIZE
        st['maximized'] = hwnd
        self.gui.show_window(hwnd, True)
        self._mdi_fit_maximized(client, hwnd)
        if st['active'] != hwnd:
            self._mdi_activate(client, hwnd)
        self._mdi_frame_title(client)

    def _mdi_restore(self, client, hwnd, refit=True):
        """Restore a maximized or minimized MDI child to its old place"""
        st = client.nstate
        win = self.gui.windows[hwnd]
        if win.maximized or win.minimized:
            win.maximized = win.minimized = False
            win.style &= ~(self.WS_MAXIMIZE | self.WS_MINIMIZE)
            self.SetWindowPos([hwnd, 0, win.restore_x & 0xFFFFFFFF, win.restore_y & 0xFFFFFFFF,
                               win.restore_width, win.restore_height, 0x14])
        if st['maximized'] == hwnd:
            st['maximized'] = 0
            if refit:
                self._mdi_frame_title(client)

    def _mdi_minimize(self, client, hwnd):
        """Minimize an MDI child: an icon-sized title bar at the bottom of the client"""
        win = self.gui.windows[hwnd]
        st = client.nstate
        if st['maximized'] == hwnd:
            self._mdi_restore(client, hwnd)
        if not win.minimized:
            win.restore_x, win.restore_y = win.x, win.y
            win.restore_width, win.restore_height = win.width, win.height
        win.minimized = True
        win.style |= self.WS_MINIMIZE
        cw, ch = self.gui.client_size(client)
        icons = [h for h in self._mdi_children(client)
                 if h != hwnd and self.gui.windows[h].minimized]
        width, height = 160, self.gui.TITLE_BAR_H + 6
        per_row = max(cw // width, 1)
        x = (len(icons) % per_row) * width
        y = ch - height * (1 + len(icons) // per_row)
        win.minimized = False  # SetWindowPos moves it; drawn as its title bar
        self.SetWindowPos([hwnd, 0, x & 0xFFFFFFFF, y & 0xFFFFFFFF, width, height, 0x14])
        win.minimized = True
        self._send_size(hwnd)

    def _mdi_cascade(self, client):
        """WM_MDICASCADE: the restored children overlap from the top left"""
        cw, ch = self.gui.client_size(client)
        step = self.gui.TITLE_BAR_H + 2
        children = [h for h in self._mdi_children(client) if self.gui.windows[h].visible and
                    not self.gui.windows[h].minimized]
        if client.nstate['maximized'] in children:
            self._mdi_restore(client, client.nstate['maximized'])
        for index, hwnd in enumerate(reversed(children)):
            offset = (index % 8) * step
            self.SetWindowPos([hwnd, 0, offset, offset, max(cw * 3 // 4, 100),
                               max(ch * 3 // 4, 60), 0x14])

    def _mdi_tile(self, client, how):
        """WM_MDITILE: side by side (MDITILE_VERTICAL 0) or one above the other
        (MDITILE_HORIZONTAL 1)"""
        cw, ch = self.gui.client_size(client)
        children = [h for h in self._mdi_children(client) if self.gui.windows[h].visible and
                    not self.gui.windows[h].minimized]
        if not children:
            return
        if client.nstate['maximized'] in children:
            self._mdi_restore(client, client.nstate['maximized'])
        count = len(children)
        for index, hwnd in enumerate(children):
            if how & 1:
                part = ch // count
                rect = (0, index * part, cw, part)
            else:
                part = cw // count
                rect = (index * part, 0, part, ch)
            self.SetWindowPos([hwnd, 0, *rect, 0x14])

    # ---------- Frame title and the Window menu ----------

    def _mdi_frame_title(self, client):
        """The frame's caption shows "Frame - [Child]" while a child is maximized"""
        frame = self.gui.windows.get(client.parent)
        if frame is None:
            return
        st = client.nstate
        base = st.get('frame_title')
        if base is None:
            base = st['frame_title'] = frame.title
        maximized = self.gui.windows.get(st['maximized'])
        title = f"{base} - [{maximized.title}]" if maximized is not None and \
            maximized.title else base
        frame.title = title

    def _mdi_set_menu(self, client, frame_menu, window_menu):
        """WM_MDISETMENU: a new frame menu and/or Window menu; the old frame menu"""
        frame = self.gui.windows.get(client.parent)
        old = frame.menu_handle if frame is not None else 0
        st = client.nstate
        if window_menu and window_menu != st['window_menu']:
            self._mdi_remove_window_items(client)
            st['window_menu'] = window_menu
        if frame_menu and frame is not None:
            self.SetMenu([frame.hwnd, frame_menu])
        self._mdi_update_window_menu(client)
        return old

    def _mdi_remove_window_items(self, client):
        st = client.nstate
        items = self.menus.get(st['window_menu'])
        if items is None:
            st['menu_children'] = []
            return
        first = st['first_child']
        self.menus[st['window_menu']] = [
            item for item in items
            if not (item.get('mdi') or first <= item['id'] < first + self.MDI_MAX_MENU_ITEMS + 1)]
        st['menu_children'] = []

    def _mdi_update_window_menu(self, client):
        """The Window menu lists the visible children ("&1 Title"), the
        active one checked, after a separator"""
        st = client.nstate
        hmenu = st['window_menu']
        if hmenu not in self.menus or not st['first_child']:
            return
        self._mdi_remove_window_items(client)
        children = [h for h in self._mdi_children(client) if self.gui.windows[h].visible]
        # Creation order, like Windows numbers them
        order = st.setdefault('creation_order', [])
        order[:] = [h for h in order if h in children] + [h for h in children if h not in order]
        listed = order[:self.MDI_MAX_MENU_ITEMS]
        if not listed:
            self._menus_changed()
            return
        items = list(self.menus[hmenu])
        items.append({'flags': self.MF_SEPARATOR, 'id': 0, 'text': '', 'submenu': 0,
                      'mdi': True})
        for index, hwnd in enumerate(listed):
            flags = self.MF_CHECKED if hwnd == st['active'] else 0
            items.append({'flags': flags, 'id': st['first_child'] + index,
                          'text': f"&{index + 1} {self.gui.windows[hwnd].title}",
                          'submenu': 0, 'mdi': True})
        self.menus[hmenu] = items
        st['menu_children'] = listed
        self._menus_changed()

    # ---------- DefFrameProc / DefMDIChildProc ----------

    def DefFrameProcA(self, args, wide=False):
        """DefFrameProcA/W(hwnd, hwndMDIClient, msg, wParam, lParam) - default
        procedure of an MDI frame window"""
        hwnd, hclient, msg, wParam, lParam = args[:5]
        client = self._mdi_client(hclient)
        if client is not None:
            st = client.nstate
            if msg == self.WM_COMMAND and not lParam:
                cmd = wParam & 0xFFFF
                first = st['first_child']
                listed = st['menu_children']
                if first and first <= cmd < first + len(listed):
                    child = listed[cmd - first]
                    if child in self.gui.windows:
                        win = self.gui.windows[child]
                        if win.minimized:
                            self._mdi_restore(client, child)
                        self._mdi_activate(client, child)
                    return 0
                # The system menu commands of a maximized child
                active = st['maximized']
                if active in self.gui.windows and cmd >= 0xF000:
                    return self._send(active, self.WM_SYSCOMMAND, wParam, lParam)
            elif msg == self.WM_SETFOCUS:
                if not self.gui.windows.get(hwnd) or not self.gui.windows[hwnd].minimized:
                    self.SetFocus([hclient])
                return 0
            elif msg == self.WM_SIZE:
                width, height = lParam & 0xFFFF, (lParam >> 16) & 0xFFFF
                if wParam != 1:  # SIZE_MINIMIZED
                    self.MoveWindow([hclient, 0, 0, width, height, 1])
                return 0
            elif msg == self.WM_NCACTIVATE:
                active = st['active']
                if active in self.gui.windows:
                    self._send(active, self.WM_NCACTIVATE, wParam, lParam)
            elif msg == self.WM_SETTEXT:  # The title without the maximized child's
                result = self.DefWindowProcA([hwnd, msg, wParam, lParam], wide)
                frame = self.gui.windows.get(hwnd)
                if frame is not None:
                    st['frame_title'] = frame.title
                    self._mdi_frame_title(client)
                return result
        return self.DefWindowProcA([hwnd, msg, wParam, lParam], wide)

    def DefFrameProcW(self, args):
        return self.DefFrameProcA(args, wide=True)

    def DefMDIChildProcA(self, args, wide=False):
        """DefMDIChildProcA/W(hwnd, msg, wParam, lParam) - default procedure of
        an MDI child window"""
        hwnd, msg, wParam, lParam = args[:4]
        client = self._mdi_client_of(hwnd)
        if client is None:
            return self.DefWindowProcA([hwnd, msg, wParam, lParam], wide)
        if msg == self.WM_CHILDACTIVATE:
            self._mdi_activate(client, hwnd)
            return 0
        if msg == self.WM_SETFOCUS:
            if client.nstate['active'] != hwnd:
                self._mdi_activate(client, hwnd)
            return 0
        if msg == self.WM_CLOSE:
            self._send(client.hwnd, self.WM_MDIDESTROY, hwnd, 0)
            return 0
        if msg == self.WM_SYSCOMMAND:
            command = wParam & 0xFFF0
            if command == self.SC_CLOSE:
                self._send(hwnd, self.WM_CLOSE, 0, 0)
            elif command == self.SC_MAXIMIZE:
                self._mdi_maximize(client, hwnd)
            elif command == self.SC_RESTORE:
                self._mdi_restore(client, hwnd)
                self._mdi_activate(client, hwnd)
            elif command == self.SC_MINIMIZE:
                self._mdi_minimize(client, hwnd)
            elif command in (self.SC_NEXTWINDOW, self.SC_PREVWINDOW):
                self._mdi_next(client, hwnd, command == self.SC_PREVWINDOW)
            else:
                return self.DefWindowProcA([hwnd, msg, wParam, lParam], wide)
            return 0
        if msg == self.WM_SETTEXT:
            result = self.DefWindowProcA([hwnd, msg, wParam, lParam], wide)
            self._mdi_update_window_menu(client)
            if client.nstate['maximized'] == hwnd:
                self._mdi_frame_title(client)
            return result
        if msg == self.WM_GETMINMAXINFO:
            return 0
        if msg == 0x0120:  # WM_MENUCHAR: the frame's menu handles Alt+letter
            frame = client.parent
            return self._send(frame, msg, wParam, lParam) if frame else 0
        return self.DefWindowProcA([hwnd, msg, wParam, lParam], wide)

    def DefMDIChildProcW(self, args):
        return self.DefMDIChildProcA(args, wide=True)

    def CreateMDIWindowA(self, args, wide=False):
        """CreateMDIWindowA/W(class, title, style, x, y, width, height, client,
        hInstance, lParam) - WM_MDICREATE in one call"""
        sz_class, sz_title, style, x, y, width, height, hclient, hinstance, lparam = args[:10]
        client = self._mdi_client(hclient)
        if client is None:
            self._last_error = 1400  # ERROR_INVALID_WINDOW_HANDLE
            return 0
        address = self.emu.heap_alloc(36)
        try:
            self._mem_write(address, struct.pack('<IIIIIIIII', sz_class, sz_title, hinstance,
                                                 x, y, width, height, style, lparam))
            return self._mdi_create(client, address, wide)
        finally:
            self.emu.heap_free(address)

    def CreateMDIWindowW(self, args):
        return self.CreateMDIWindowA(args, wide=True)

    def TranslateMDISysAccel(self, args):
        """TranslateMDISysAccel(hwndClient, msg) - Ctrl+F4 closes, Ctrl+F6 moves
        to the next MDI child; TRUE if the message was one of them"""
        hclient, lpmsg = args[0], args[1]
        client = self._mdi_client(hclient)
        if client is None or not lpmsg:
            return 0
        try:
            _hwnd, message, wParam = struct.unpack('<III', self.emu.uc.mem_read(lpmsg, 12))
        except UcError:
            return 0
        if message not in (self.WM_KEYDOWN, 0x0104):  # WM_SYSKEYDOWN
            return 0
        ctrl = self.GetKeyState([0x11]) & 0x8000
        if not ctrl or self.GetKeyState([0x12]) & 0x8000:  # VK_CONTROL, not VK_MENU
            return 0
        active = client.nstate['active']
        if active not in self.gui.windows:
            return 0
        if wParam == 0x73:  # VK_F4
            self.post_window_message(active, self.WM_SYSCOMMAND, self.SC_CLOSE, 0)
            return 1
        if wParam == 0x75:  # VK_F6
            shift = self.GetKeyState([0x10]) & 0x8000
            self.post_window_message(active, self.WM_SYSCOMMAND,
                                     self.SC_PREVWINDOW if shift else self.SC_NEXTWINDOW, 0)
            return 1
        return 0
