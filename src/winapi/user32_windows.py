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

"""WinAPIHandler mixin: USER32: system metrics, message boxes, window classes, creating windows"""

import struct

from colorama import Fore, Style
from unicorn import UcError

from .. import config, windows
from ..logger import log
from .richedit import RICHEDIT_CLASSES


class User32WindowsMixin:
    """USER32: system metrics, message boxes, window classes, creating windows"""

    # USER32.DLL APIs
    def _screen_size(self):
        """Size of the fake desktop (fixed 1920x1080 without the GUI)"""
        if self.gui:
            return self.gui.width, self.gui.height
        return 1920, 1080

    def GetSystemMetrics(self, args):
        """GetSystemMetrics emulation"""
        nIndex = args[0]
        width, height = self._screen_size()

        metrics = {
            0: width,  # SM_CXSCREEN
            1: height, # SM_CYSCREEN
            2: 20,     # SM_CXVSCROLL
            3: 20,     # SM_CYHSCROLL
            4: 25,     # SM_CYCAPTION
            5: 1,      # SM_CXBORDER
            6: 1,      # SM_CYBORDER
            16: width,  # SM_CXFULLSCREEN
            17: height - 30 - 25,  # SM_CYFULLSCREEN: minus taskbar and caption
            7: 3, 8: 3,    # SM_CXDLGFRAME, SM_CYDLGFRAME
            # SM_CXICON, SM_CYICON: Word's message boxes put their text after the icon
            11: 32, 12: 32,
            13: 32, 14: 32,  # SM_CXCURSOR, SM_CYCURSOR
            15: 20,    # SM_CYMENU
            19: 1,     # SM_MOUSEPRESENT
            # SM_RESERVED2: the cursor's display counter (ShowCursor). Word
            # reads it to hide the pointer while typing and to show it again
            # when the mouse moves; with 0 it hid the pointer for good
            25: self.cursor_count,
            32: 3, 33: 3,  # SM_CXFRAME, SM_CYFRAME
            36: 4, 37: 4,  # SM_CXDOUBLECLK, SM_CYDOUBLECLK
            43: 3,     # SM_CMOUSEBUTTONS
            45: 2, 46: 2,  # SM_CXEDGE, SM_CYEDGE
            49: 16, 50: 16,  # SM_CXSMICON, SM_CYSMICON
            68: 4, 69: 4,  # SM_CXDRAG, SM_CYDRAG
            80: 1,     # SM_CMONITORS
        }

        result = metrics.get(nIndex, 0)
        log.debug(f"GetSystemMetrics({nIndex}) -> {result}")
        return result & 0xFFFFFFFF

    # MB_OK ... MB_CANCELTRYCONTINUE: (label, result id) of the buttons
    MESSAGEBOX_BUTTONS = {0: [('OK', 1)], 1: [('OK', 1), ('Cancel', 2)],
                          2: [('&Abort', 3), ('&Retry', 4), ('&Ignore', 5)],
                          3: [('&Yes', 6), ('&No', 7), ('Cancel', 2)],
                          4: [('&Yes', 6), ('&No', 7)], 5: [('&Retry', 4), ('Cancel', 2)],
                          6: [('Cancel', 2), ('&Try Again', 10), ('&Continue', 11)]}

    @classmethod
    def messagebox_buttons(cls, utype):
        """(buttons, index of the default button, result of Esc/close or None)"""
        buttons = cls.MESSAGEBOX_BUTTONS.get(utype & 0xF, cls.MESSAGEBOX_BUTTONS[0])
        default = min((utype >> 8) & 0xF, len(buttons) - 1)
        ids = [result for _, result in buttons]
        cancel = 2 if 2 in ids else (1 if ids == [1] else None)
        return buttons, default, cancel

    def _message_box(self, text, caption, utype):
        """Modal message box: blocks until a button is chosen, returns its id"""
        log.info(f"{Fore.YELLOW}[MESSAGEBOX]{Style.RESET_ALL} {caption}: {text}")
        buttons, default, cancel = self.messagebox_buttons(utype)
        if not (self.gui and self.gui.running):
            return buttons[default][1]  # Nobody can answer: the default button
        request = {'result': None}
        self.gui.show_messagebox(caption, text, utype, request, process=self)
        # A modal loop: messages other threads send are handled meanwhile
        self.emu.wait_until(lambda: self._process_sent_messages() or
                            request['result'] is not None or not self.gui.running)
        if request['result'] is None:
            return cancel or buttons[default][1]
        return request['result']

    def MessageBoxA(self, args, wide=False):
        """MessageBoxA/W emulation"""
        lpText, lpCaption, uType = args[1], args[2], args[3]
        text = self._read_text(lpText, wide) if lpText else ""
        caption = self._read_text(lpCaption, wide) if lpCaption else "Error"
        return self._message_box(text, caption, uType)

    def MessageBoxW(self, args):
        return self.MessageBoxA(args, wide=True)

    def RegisterClassA(self, args, wide=False):
        """RegisterClassA/W emulation"""
        lpWndClass = args[0]

        # Read WNDCLASS structure
        try:
            wndclass_data = self.emu.uc.mem_read(lpWndClass, 40)
            style = struct.unpack("<I", wndclass_data[0:4])[0]
            lpfnWndProc = struct.unpack("<I", wndclass_data[4:8])[0]
            cls_extra, wnd_extra = struct.unpack("<ii", wndclass_data[8:16])
            hInstance = struct.unpack("<I", wndclass_data[16:20])[0]
            hCursor = struct.unpack("<I", wndclass_data[24:28])[0]
            hbrBackground = struct.unpack("<I", wndclass_data[28:32])[0]
            lpszMenuName = struct.unpack("<I", wndclass_data[32:36])[0]
            lpszClassName = struct.unpack("<I", wndclass_data[36:40])[0]

            class_name = self._read_text(lpszClassName, wide)

            atom = self.next_atom
            self.next_atom += 1

            self.registered_classes[class_name] = {
                'atom': atom,
                'style': style,
                'wndproc': lpfnWndProc,
                'hInstance': hInstance,
                'background': hbrBackground,
                'cursor': hCursor,
                'menu': (lpszMenuName if lpszMenuName < 0x10000 else
                         self._read_text(lpszMenuName, wide)) if lpszMenuName else 0,
                # GetClassInfo gives them back: a program superclassing its
                # own class keeps its window bytes after the base class's
                'cls_extra': max(cls_extra, 0),
                'wnd_extra': max(wnd_extra, 0),
            }
            self.atoms[atom] = class_name
            self.module_classes[(class_name.lower(), hInstance)] = \
                self.registered_classes[class_name]

            self._note_superclass(class_name, lpWndClass)
            log.debug(f"RegisterClassA('{class_name}') -> 0x{atom:x}")
            return atom
        except UcError:
            return 0

    def RegisterClassW(self, args):
        return self.RegisterClassA(args, wide=True)

    def _note_superclass(self, class_name, wndclass_address):
        """A class registered from the WNDCLASS GetClassInfo filled for a
        system class is a superclass of it (Word's OpusFedt of EDIT, Office's
        OpenListView of SysListView32): its windows are that emulated
        control, run through the class's window procedure, which passes on
        to the one GetClassInfo gave (CallWindowProc)"""
        base = self.superclass_buffers.pop(wndclass_address, None)
        if base is not None and base.upper() != class_name.upper():
            self.registered_classes[class_name]['base'] = base
            log.debug(f"Class '{class_name}' is a superclass of {base}")

    def RegisterClassExA(self, args, wide=False):
        """RegisterClassExA/W emulation"""
        lpwcx = args[0]

        try:
            # Read WNDCLASSEX structure
            wcex_data = self.emu.uc.mem_read(lpwcx, 48)
            cbSize = struct.unpack("<I", wcex_data[0:4])[0]
            style = struct.unpack("<I", wcex_data[4:8])[0]
            lpfnWndProc = struct.unpack("<I", wcex_data[8:12])[0]
            cls_extra, wnd_extra = struct.unpack("<ii", wcex_data[12:20])
            hInstance = struct.unpack("<I", wcex_data[20:24])[0]
            hCursor = struct.unpack("<I", wcex_data[28:32])[0]
            hbrBackground = struct.unpack("<I", wcex_data[32:36])[0]
            lpszMenuName = struct.unpack("<I", wcex_data[36:40])[0]
            lpszClassName = struct.unpack("<I", wcex_data[40:44])[0]

            class_name = self._read_text(lpszClassName, wide)

            atom = self.next_atom
            self.next_atom += 1

            self.registered_classes[class_name] = {
                'atom': atom,
                'style': style,
                'wndproc': lpfnWndProc,
                'hInstance': hInstance,
                'background': hbrBackground,
                'cursor': hCursor,
                'menu': (lpszMenuName if lpszMenuName < 0x10000 else
                         self._read_text(lpszMenuName, wide)) if lpszMenuName else 0,
                'cls_extra': max(cls_extra, 0),
                'wnd_extra': max(wnd_extra, 0),
            }
            self.atoms[atom] = class_name
            self.module_classes[(class_name.lower(), hInstance)] = \
                self.registered_classes[class_name]

            self._note_superclass(class_name, lpwcx)
            log.debug(f"RegisterClassExA('{class_name}') -> 0x{atom:x}")
            return atom
        except UcError:
            return 0

    def RegisterClassExW(self, args):
        return self.RegisterClassExA(args, wide=True)

    def CreateWindowExA(self, args, wide=False):
        """CreateWindowExA/W emulation"""
        dwExStyle = args[0]
        lpClassName = args[1]
        lpWindowName = args[2]
        dwStyle = args[3]
        CW_USEDEFAULT = -0x80000000
        x, y, nWidth, nHeight = self._read_signed_args(args, 4, 4)
        x = x if x != CW_USEDEFAULT else 100
        y = y if y != CW_USEDEFAULT else 100
        if nWidth == CW_USEDEFAULT and not dwStyle & (self.WS_CHILD | self.WS_POPUP):
            # Like Windows: a default overlapped window gets 3/4 of the desktop
            screen_w, screen_h = self._screen_size()
            nWidth = min(screen_w * 3 // 4, screen_w - x)
            nHeight = min((screen_h - 30) * 3 // 4, screen_h - 30 - y)
        nWidth = nWidth if nWidth != CW_USEDEFAULT else 400
        nHeight = nHeight if nHeight != CW_USEDEFAULT else 300
        hWndParent = args[8]
        hMenu = args[9]
        hInstance = args[10]
        lpParam = args[11]
        # An MDI child: its MDI styles and place, an MDICREATESTRUCT for WM_CREATE
        mdi_client = self._mdi_client(hWndParent) if self.gui and \
            dwExStyle & self.WS_EX_MDICHILD else None
        if mdi_client is not None:
            dwStyle, x, y, nWidth, nHeight, lpParam = self._mdi_create_params(
                mdi_client, args, wide)

        # Class name can be atom or string
        if lpClassName < 0x10000:
            class_name = self.atoms.get(lpClassName, f"ATOM_{lpClassName}")
        else:
            class_name = self._read_text(lpClassName, wide)

        window_name = self._read_text(lpWindowName, wide)

        log.info(f"{Fore.GREEN}CreateWindowExA{Style.RESET_ALL}('{class_name}', '{window_name}', "
                f"pos=({x},{y}), size=({nWidth},{nHeight}))")

        # Create real window if GUI exists
        if self.gui and self.gui.running:
            # A superclass of a system class is created as that control
            superclass = self._superclass_of(class_name, hInstance)
            base_class = superclass['base'] if superclass else class_name
            native = self.NATIVE_CLASSES.get(base_class.upper()) if isinstance(base_class, str) \
                else None
            if native and (hWndParent in self.gui.windows or not dwStyle & self.WS_CHILD):
                hwnd = self._create_native(native, class_name, window_name, x, y, nWidth,
                                           nHeight, dwStyle, dwExStyle, hWndParent, hMenu)
                win = self.gui.windows[hwnd]
                if native == 'MDICLIENT':
                    self._mdi_client_init(win, lpParam)
                if superclass:
                    win.wndproc = superclass['wndproc']
                    win.wndclass = superclass
                if self._cbt_refuses(hwnd, lpParam, hInstance, hMenu, hWndParent, nHeight,
                                     nWidth, y, x, dwStyle, lpWindowName, lpClassName,
                                     dwExStyle):
                    return 0
                if superclass:
                    self._send_create(superclass['wndproc'], hwnd, lpParam, hInstance, hMenu,
                                      hWndParent, nHeight, nWidth, y, x, dwStyle,
                                      lpWindowName, lpClassName, dwExStyle)
                if dwStyle & self.WS_VISIBLE and native != 'TOOLTIPS':
                    win.visible = True
                if native == 'TOOLBAR' and not dwStyle & 0x4:  # CCS_NORESIZE
                    self._tb_autosize(win)
                return hwnd
            # Create control for top-level controls
            if base_class.upper() == "MSCTLS_STATUSBAR32" and hWndParent in self.gui.windows:
                hwnd = self._create_status_bar(hWndParent, window_name, dwStyle, hMenu)
            elif base_class.upper() in ["BUTTON", "EDIT", "STATIC", "LISTBOX", "COMBOBOX",
                                        "SCROLLBAR", "MSCTLS_PROGRESS32", *RICHEDIT_CLASSES]:
                # BUTTON with a checkbox or radio button style is drawn and
                # clicked as a checkbox
                control_class = base_class
                rich_edit = base_class.upper() in RICHEDIT_CLASSES
                if rich_edit:
                    control_class = "EDIT"  # A plain text edit control (richedit.py)
                if (base_class.upper() == "BUTTON" and
                        (dwStyle & 0xF) in self.CHECK_BUTTON_STYLES):
                    control_class = "CHECKBOX"
                elif base_class.upper() == "MSCTLS_PROGRESS32":
                    control_class = "PROGRESSBAR"
                # For child controls hMenu carries the control ID (used by WM_COMMAND)
                hwnd = self.gui.create_control(hWndParent, control_class, window_name,
                                               x, y, nWidth, nHeight, dwStyle,
                                               control_id=hMenu, ex_style=dwExStyle)
                self.dirty_controls[hwnd] = True
                if not dwStyle & self.WS_VISIBLE and hwnd in self.gui.controls:
                    # Hidden until ShowWindow (Office's file dialogs keep spare edits)
                    self.gui.controls[hwnd].visible = False
                if rich_edit and hwnd in self.gui.controls:
                    # GetClassName gives "RichEdit20A", not "Edit"
                    self.gui.controls[hwnd].rich_edit = True
                    self.gui.controls[hwnd].superclass_name = base_class
                if superclass and hwnd in self.gui.controls:
                    # GetClassName gives the superclass; its procedure gets the messages
                    self.gui.controls[hwnd].superclass_name = class_name
                    self.window_longs.setdefault(hwnd, {})[-4] = superclass['wndproc']
            else:
                parent = hWndParent if dwStyle & self.WS_CHILD else 0
                hwnd = self.gui.create_window(window_name, x, y, nWidth, nHeight, dwStyle,
                                              owner=self, parent=parent)

            # Save class_name to window (for finding WndProc)
            if hwnd in self.gui.windows:
                self.gui.windows[hwnd].class_name = class_name
                if not dwStyle & self.WS_CHILD:
                    self.gui.windows[hwnd].ex_style = dwExStyle
                    self.gui.windows[hwnd].owner_hwnd = self._top_level_window(hWndParent)
                if hInstance:  # GWL_HINSTANCE (a DLL finds its resources with it)
                    self.window_longs.setdefault(hwnd, {})[-6] = hInstance
                # Like Windows, the class the module hInstance registered comes
                # first (two DLLs may register classes of the same name)
                wndclass = self.module_classes.get((class_name.lower(), hInstance)) \
                    if isinstance(class_name, str) else None
                if wndclass is not None:
                    self.gui.windows[hwnd].wndclass = wndclass
                else:
                    wndclass = self.registered_classes.get(class_name)
                # The client area is erased with the class background brush
                if wndclass and wndclass.get('background'):
                    color = self._brush_color(wndclass['background'])
                    if color is not None:
                        self.gui.windows[hwnd].bg_color = color
                elif wndclass and dwStyle & self.WS_CHILD:
                    self.gui.windows[hwnd].transparent = True
                # Top-level windows get their menu bar from hMenu (like SetMenu),
                # else from the class menu (lpszMenuName)
                if (not dwStyle & self.WS_CHILD and not hMenu and wndclass and
                        wndclass.get('menu')):
                    menu_name = wndclass['menu']
                    hMenu = self._load_menu_resource(menu_name.upper() if isinstance(
                        menu_name, str) and not menu_name.startswith('#') else
                        int(menu_name[1:]) if isinstance(menu_name, str) else menu_name)
                if not dwStyle & self.WS_CHILD and hMenu in self.menus:
                    self.gui.windows[hwnd].menu_handle = hMenu
                    self.gui.windows[hwnd].menu = self._build_menu_tree(hMenu)
                elif dwStyle & self.WS_CHILD:
                    self.gui.windows[hwnd].control_id = hMenu

            # The WH_CBT hooks see the window first (MFC subclasses it there)
            if self._cbt_refuses(hwnd, lpParam, hInstance, hMenu, hWndParent, nHeight,
                                 nWidth, y, x, dwStyle, lpWindowName, lpClassName, dwExStyle):
                return 0
            # Real Windows sends WM_CREATE to the WndProc synchronously, before
            # CreateWindowEx returns. Apps often create their child controls here.
            # Controls have no app WndProc, so this only fires for app windows.
            wndproc = self._find_wndproc_for_hwnd(hwnd)
            if not wndproc and superclass and self.gui and hwnd in self.gui.controls:
                wndproc = superclass['wndproc']
            if wndproc:
                self._send_create(wndproc, hwnd, lpParam, hInstance, hMenu, hWndParent,
                                  nHeight, nWidth, y, x, dwStyle, lpWindowName, lpClassName,
                                  dwExStyle)
            if hwnd in self.superclass_windows:
                # Its class turned out to superclass a control while creating it
                self.superclass_windows.discard(hwnd)
                self._make_superclass_control(hwnd, class_name, dwStyle, dwExStyle, hMenu)
                if dwStyle & (self.WS_CHILD | self.WS_POPUP):
                    self._send_size(hwnd)  # Overlapped windows get it from ShowWindow
            elif (dwStyle & (self.WS_CHILD | self.WS_POPUP) and wndproc and
                  hwnd in self.gui.windows and self.gui.windows[hwnd].size_state is None):
                # Like Windows, child and pop-up windows get WM_SIZE right after
                # WM_CREATE, not at their first ShowWindow (Schedule+ attaches the
                # window's object after CreateWindowEx and shows it before the
                # object is complete: its WM_SIZE handler must not run then)
                self._send_size(hwnd)
            # WS_VISIBLE windows are shown without an explicit ShowWindow call
            win = self.gui.windows.get(hwnd)
            if (dwStyle & self.WS_VISIBLE and isinstance(win, windows.FakeWindow)
                    and not win.visible):
                self.gui.show_window(hwnd, True)
                if win.size_state is None:
                    self._send_size(hwnd)
            if mdi_client is not None and hwnd in self.gui.windows:
                self._mdi_child_created(hwnd)
        else:
            hwnd = self.get_next_handle()

        return hwnd

    def _send_create(self, wndproc, hwnd, *create_args):
        """Send WM_NCCREATE (many frameworks attach their window object there),
        then WM_CREATE, with a CREATESTRUCT of create_args"""
        cs_addr = self._build_createstruct(*create_args)
        try:
            self.emu.call_wndproc(wndproc, hwnd, self.WM_NCCREATE, 0, cs_addr)
            self.emu.call_wndproc(wndproc, hwnd, self.WM_CREATE, 0, cs_addr)
        finally:
            self.emu.heap_free(cs_addr)

    def _make_superclass_control(self, hwnd, class_name, style, ex_style, control_id):
        """Turn the plain child window hwnd of a superclass of a control class
        into that control, keeping its handle, text and window procedure"""
        win = self.gui.windows.get(hwnd)
        wndclass = getattr(win, 'wndclass', None) or self.registered_classes.get(class_name)
        base = wndclass.get('base') if wndclass else None
        if win is None or base not in self.CONTROL_CLASS_PROCS or win.parent not in \
                self.gui.windows:
            return
        control_class = base
        if base == 'BUTTON' and (style & 0xF) in self.CHECK_BUTTON_STYLES:
            control_class = 'CHECKBOX'
        with self.gui.lock:
            parent = self.gui.windows[win.parent]
            parent.children = [h for h in parent.children if h != hwnd]
            del self.gui.windows[hwnd]
            if hwnd in self.gui.z_order:
                self.gui.z_order.remove(hwnd)
            self.gui.create_control(parent.hwnd, control_class, win.title, win.x, win.y,
                                    win.width, win.height, style, control_id=control_id,
                                    ex_style=ex_style, hwnd=hwnd)
            control = self.gui.controls[hwnd]
            control.superclass_name = class_name
            control.visible = win.visible or bool(style & self.WS_VISIBLE)
        self.window_longs.setdefault(hwnd, {})[-4] = proc = (
            win.wndproc or wndclass['wndproc'])
        self.dirty_controls[hwnd] = True
        log.debug(f"Window 0x{hwnd:x} of '{class_name}' is now a {base} control "
                  f"(procedure 0x{proc:x})")

    def _superclass_of(self, class_name, hinstance):
        """Registered class of class_name (the module's own first) if it is a
        superclass of a system class (see _note_superclass), else None"""
        if not isinstance(class_name, str):
            return None
        wndclass = self.module_classes.get((class_name.lower(), hinstance))
        if wndclass is None:
            wndclass = self.registered_classes.get(class_name)
        if wndclass is None:
            match = next((n for n in self.registered_classes
                          if n.lower() == class_name.lower()), None)
            wndclass = self.registered_classes.get(match) if match else None
        return wndclass if wndclass and wndclass.get('base') else None

    def _cbt_refuses(self, hwnd, *create_args):
        """Call the WH_CBT hooks for a new window (HCBT_CREATEWND with its
        CREATESTRUCT); True if one refused it (the window is destroyed)"""
        if not self._hook_chain(self.WH_CBT):
            return False
        cs_addr = self._build_createstruct(*create_args)
        try:
            refused = self.cbt_create_window(hwnd, cs_addr)
        finally:
            self.emu.heap_free(cs_addr)
        if refused:
            log.debug(f"CreateWindowEx: a WH_CBT hook refused window 0x{hwnd:x}")
            self.DestroyWindow([hwnd])
        return refused

    def _top_level_window(self, hwnd):
        """The top-level window a window or control belongs to (the owner
        Windows records for hWndParent of a top-level window); 0 if none"""
        if not self.gui:
            return 0
        seen = set()
        while hwnd and hwnd not in seen:
            seen.add(hwnd)
            control = self.gui.controls.get(hwnd)
            if control is not None:
                hwnd = control.parent_hwnd
                continue
            win = self.gui.windows.get(hwnd)
            if win is None:
                return 0
            if not win.parent:
                return hwnd
            hwnd = win.parent
        return 0

    def CreateWindowExW(self, args):
        return self.CreateWindowExA(args, wide=True)

    WM_NCCREATE = 0x0081
    WS_CHILD = 0x40000000
    WS_POPUP = 0x80000000
    WS_VISIBLE = 0x10000000
    WS_BORDER = 0x00800000
    WS_EX_CLIENTEDGE = 0x00000200
    WM_SIZE = 0x0005
    WM_ACTIVATE = 0x0006

    def _send_size(self, hwnd):
        """Send WM_SIZE now if the window's client size or state changed
        (window creation, MoveWindow, SetWindowPos)"""
        if not self.gui or hwnd not in self.gui.windows:
            return
        win = self.gui.windows[hwnd]
        state = self.gui.size_state(win)
        if state == win.size_state:
            return
        win.size_state = state
        wndproc = self._find_wndproc_for_hwnd(hwnd)
        if wndproc:
            kind, width, height = state
            self.emu.call_wndproc(wndproc, hwnd, self.WM_SIZE, kind,
                                  ((height & 0xFFFF) << 16) | (width & 0xFFFF))

    def _build_createstruct(self, lpCreateParams, hInstance, hMenu, hwndParent,
                            cy, cx, y, x, style, lpszName, lpszClass, dwExStyle):
        """Allocate and fill a CREATESTRUCTA, return its address (for WM_CREATE)."""
        addr = self.emu.heap_alloc(48)
        data = struct.pack("<IIIIiiiiIIII",
                           lpCreateParams & 0xFFFFFFFF,
                           hInstance & 0xFFFFFFFF,
                           hMenu & 0xFFFFFFFF,
                           hwndParent & 0xFFFFFFFF,
                           cy, cx, y, x,
                           style & 0xFFFFFFFF,
                           lpszName & 0xFFFFFFFF,
                           lpszClass & 0xFFFFFFFF,
                           dwExStyle & 0xFFFFFFFF)
        self.emu.uc.mem_write(addr, data)
        return addr

    # ShowWindow commands that minimize, maximize, or show without activating
    SW_MINIMIZING = (2, 6, 7, 11)  # SW_SHOWMINIMIZED, SW_MINIMIZE, SW_SHOWMINNOACTIVE,
    #                                SW_FORCEMINIMIZE
    SW_NOT_ACTIVATING = (4, 6, 7, 8, 11)  # SW_SHOWNOACTIVATE, ..., SW_SHOWNA

    def ShowWindow(self, args):
        """ShowWindow emulation - returns whether the window was visible"""
        hWnd = args[0]
        nCmdShow = args[1]

        show_names = {0: "SW_HIDE", 1: "SW_SHOWNORMAL", 2: "SW_SHOWMINIMIZED",
                      3: "SW_SHOWMAXIMIZED", 4: "SW_SHOWNOACTIVATE", 5: "SW_SHOW",
                      6: "SW_MINIMIZE", 7: "SW_SHOWMINNOACTIVE", 8: "SW_SHOWNA",
                      9: "SW_RESTORE", 10: "SW_SHOWDEFAULT", 11: "SW_FORCEMINIMIZE"}
        show_name = show_names.get(nCmdShow, f"SW_{nCmdShow}")

        log.debug(f"ShowWindow(0x{hWnd:x}, {show_name})")

        if not (self.gui and self.gui.running):
            return 0
        win = self.gui.windows.get(hWnd)
        target = win if win is not None else self.gui.controls.get(hWnd)
        was_visible = 1 if target is not None and target.visible else 0
        if win is not None and was_visible != (nCmdShow != 0):
            # Like Windows: WM_SHOWWINDOW before the window is shown or hidden
            # (Access fills in its alert dialog there)
            self._send(hWnd, self.WM_SHOWWINDOW, 1 if nCmdShow else 0, 0)
            win = self.gui.windows.get(hWnd)
            if win is None:
                return was_visible
        if nCmdShow == 0:  # SW_HIDE
            self.gui.show_window(hWnd, False)
            if win is not None and was_visible:
                self._uncovered(win, (win.x, win.y, win.width, win.height), True)
            elif target is not None and was_visible:
                self._control_uncovered(target, (target.x, target.y, target.width,
                                                 target.height), True)
            return was_visible
        if win is None or win.parent is not None:  # A control or child window
            self.gui.show_window(hWnd, True)
            if win is not None and win.size_state is None:
                self._send_size(hWnd)
            return was_visible

        with self.gui.lock:
            if nCmdShow in self.SW_NOT_ACTIVATING:
                win.visible = True  # Shown on top, but the active window stays active
                if hWnd not in self.gui.z_order:
                    self.gui.z_order.append(hWnd)
            else:
                self.gui.show_window(hWnd, True)
            if nCmdShow in self.SW_MINIMIZING:
                win.minimize()
                if self.gui.active_window == hWnd:
                    self.gui._activate_next_window()
            elif nCmdShow == 3:  # SW_SHOWMAXIMIZED
                if not win.maximized:
                    win.minimized = False
                    win.maximize(self.gui.width, self.gui.height, 30)
            elif nCmdShow in (1, 9, 10):  # SW_SHOWNORMAL, SW_RESTORE, SW_SHOWDEFAULT
                if win.minimized or nCmdShow == 9:
                    win.restore()
        self._send_size(hWnd)  # Only if the size or the state changed (SIZE_MINIMIZED...)
        return was_visible

    def UpdateWindow(self, args):
        """UpdateWindow emulation"""
        hWnd = args[0]
        log.debug(f"UpdateWindow(0x{hWnd:x})")
        if self.gui and hWnd in self.gui.controls:
            return self._update_control(hWnd)
        win = self.gui.windows.get(hWnd) if self.gui else None
        if (win is None or win.owner is not self or hWnd in self.painted_windows or
                hWnd in self.updating_windows or hWnd in self.dialogs or
                hWnd in self.gui.consoles or not self._shown_with_parents(win)):
            return 1
        wndproc = self._find_wndproc_for_hwnd(hWnd)
        if not wndproc or self._is_native_proc(wndproc):
            return 1
        # WM_PAINT is sent at once, not left for the message loop
        self.painted_windows.add(hWnd)
        self.paint_pending.add(hWnd)
        self.updating_windows.add(hWnd)
        try:
            self._call_proc(wndproc, hWnd, self.WM_PAINT, 0, 0)
        finally:
            self.updating_windows.discard(hWnd)
            if hWnd in self.paint_pending:
                self.paint_pending.discard(hWnd)
                self.update_rects.pop(hWnd, None)
        return 1

    def _update_control(self, hwnd):
        """UpdateWindow of a control waiting for WM_PAINT that its program
        paints (subclassed or owner-draw): WM_PAINT is sent at once. Red Alert
        2 updates every control while its dialog paints, then copies the
        dialog's area with the frames the controls drew around them."""
        control = self.gui.controls[hwnd]
        parent = self.gui.windows.get(control.parent_hwnd)
        if (hwnd not in self.dirty_controls or hwnd in self.updating_windows or
                not control.visible or parent is None or parent.owner is not self or
                not self._shown_with_parents(parent) or
                not (self._control_subclass(hwnd) or self._owner_draw_type(control))):
            return 1
        del self.dirty_controls[hwnd]
        self.updating_windows.add(hwnd)
        try:
            self._send_control_paint(hwnd)
        finally:
            self.updating_windows.discard(hwnd)
        return 1

    def _shown_with_parents(self, win):
        """Is a window visible, with all its parents (and not minimized)?"""
        for _ in range(64):
            if not win.visible or getattr(win, 'minimized', False):
                return False
            parent = self.gui.windows.get(win.parent) if win.parent else None
            if parent is None:
                return True
            win = parent
        return False

    def DestroyWindow(self, args):
        """DestroyWindow emulation"""
        hWnd = args[0]
        log.debug(f"DestroyWindow(0x{hWnd:x})")

        if (self.gui and (hWnd in self.gui.controls or hWnd in self.gui.windows) and
                self.cbt_destroy_window(hWnd)):
            return 0  # A WH_CBT hook prevented it
        if self.gui and hWnd in self.gui.controls:
            self._destroy_control(hWnd)
        elif self.gui and hWnd in self.dialogs:
            dialog = self.dialogs[hWnd]
            if not dialog.get('destroying'):
                # WM_DESTROY reaches the dialog procedure while its controls still exist
                dialog['destroying'] = True
                if dialog['proc']:
                    self.emu.call_wndproc(dialog['proc'], hWnd, self.WM_DESTROY, 0, 0)
                self._close_dialog(hWnd)
        elif self.gui and hWnd in self.gui.windows and self.gui.windows[hWnd].parent:
            # A child window (control) goes away at once, after its WM_DESTROY
            wndproc = self._find_wndproc_for_hwnd(hWnd)
            if wndproc:
                self._call_proc(wndproc, hWnd, self.WM_DESTROY, 0, 0)
            child = self.gui.windows.get(hWnd)
            if child is None:  # Its WM_DESTROY destroyed it already
                return 1
            mdi_client = self._mdi_client(child.parent)
            was_visible, child.visible = child.visible, False
            self._uncovered(child, (child.x, child.y, child.width, child.height), was_visible)
            with self.gui.lock:
                gone = self._window_and_children(hWnd)
                self.gui._remove_window(hWnd)
            for handle in gone:
                self._forget_window(handle)
            self.window_longs.pop(hWnd, None)
            if mdi_client is not None:
                self._mdi_child_destroyed(mdi_client, hWnd)
        elif self.gui and hWnd in self.gui.windows:
            # Like Windows: WM_DESTROY is sent at once, while the window still
            # exists, then the window and its children are gone (IsWindow is
            # FALSE, its pending messages are dropped)
            wndproc = self._find_wndproc_for_hwnd(hWnd)
            if wndproc:
                self._call_proc(wndproc, hWnd, self.WM_DESTROY, 0, 0)
            self.gui._close_window(hWnd, notify_app=False)
            with self.gui.lock:
                gone = self._window_and_children(hWnd)
                self.gui._remove_window(hWnd)
            with self.message_lock:
                self.message_queue[:] = [m for m in self.message_queue if m['hwnd'] not in gone]
            for handle in gone:
                self._forget_window(handle)
                self.window_longs.pop(handle, None)
        elif self.gui:
            self._last_error = 1400  # ERROR_INVALID_WINDOW_HANDLE
            return 0

        return 1

    WM_NCDESTROY = 0x0082

    def _destroy_control(self, hwnd):
        """DestroyWindow of a control: a procedure the program subclassed it
        with gets WM_DESTROY and WM_NCDESTROY while it still exists (Red
        Alert 2 unregisters its list's scroll bar there; without it its
        dialog stopped animating after a drop-down list closed), then what
        was under it is painted again"""
        control = self.gui.controls[hwnd]
        subclass = self._control_subclass(hwnd)
        if subclass:
            self.emu.call_wndproc(subclass, hwnd, self.WM_DESTROY, 0, 0)
            if hwnd in self.gui.controls:
                self.emu.call_wndproc(subclass, hwnd, self.WM_NCDESTROY, 0, 0)
            if hwnd not in self.gui.controls:
                return  # Its procedure destroyed it already
        was_visible = control.visible
        control.visible = False
        self._control_uncovered(control, (control.x, control.y, control.width,
                                          control.window_height), was_visible)
        self.gui.destroy_control(hwnd)
        self.dirty_controls.pop(hwnd, None)
        self.window_longs.pop(hwnd, None)
        with self.message_lock:
            self.message_queue[:] = [m for m in self.message_queue if m['hwnd'] != hwnd]

    def _window_and_children(self, hwnd):
        """A window's handle and those of its child windows and controls"""
        handles = {hwnd}
        win = self.gui.windows.get(hwnd)
        for child in (win.children if win else []):
            handles |= self._window_and_children(child)
        handles |= {h for h, c in self.gui.controls.items() if c.parent_hwnd == hwnd}
        return handles

    def SetWindowTextA(self, args, wide=False):
        """SetWindowTextA/W emulation"""
        hWnd = args[0]
        lpString = args[1]

        text = self._read_long_text(lpString, wide)
        log.debug(f"SetWindowTextA(0x{hWnd:x}, '{text[:200]}')")

        if self._text_wndproc(hWnd):
            # Like Windows: WM_SETTEXT to the window's procedure
            return self.SendMessageA([hWnd, 0x000C, 0, lpString], wide)  # WM_SETTEXT
        combo = self._native_window(hWnd, 'COMBOBOXEX') if self.gui else None
        if combo is not None:
            self.comboboxex_set_text(combo, text)
        elif self.gui:
            self.gui.set_window_text(hWnd, text)

        return 1

    def SetWindowTextW(self, args):
        return self.SetWindowTextA(args, wide=True)

    def GetWindowTextA(self, args, wide=False):
        """GetWindowTextA/W emulation"""
        hWnd = args[0]
        lpString = args[1]
        nMaxCount = args[2]

        text = self._window_text(hWnd)
        self._last_error = 0

        # Always null-terminate the buffer (like real Windows), even when
        # the text is empty - the caller's buffer is uninitialized memory
        if lpString and nMaxCount > 0:
            if wide:
                text_bytes = text.encode('utf-16-le')[:(nMaxCount - 1) * 2]
                self.emu.uc.mem_write(lpString, text_bytes + b'\x00\x00')
                copied = len(text_bytes) // 2
            else:
                text_bytes = text.encode(config.ANSI_CODEPAGE, errors='replace')[:nMaxCount - 1]
                self.emu.uc.mem_write(lpString, text_bytes + b'\x00')
                copied = len(text_bytes)
        else:
            copied = 0

        log.debug(f"GetWindowTextA(0x{hWnd:x}) -> '{text[:200]}'")
        return copied

    def GetWindowTextW(self, args):
        return self.GetWindowTextA(args, wide=True)

    def GetClientRect(self, args):
        """GetClientRect emulation"""
        hWnd = args[0]
        lpRect = args[1]

        # Default rectangle
        left, top, right, bottom = 0, 0, 400, 300

        combo = self._combo_of_edit(hWnd)
        if combo is not None:
            left, top, right, bottom = self._combo_edit_rect(combo)
            right, bottom, left, top = right - left, bottom - top, 0, 0
        elif self.gui and hWnd in self.gui.windows:
            win = self.gui.windows[hWnd]
            right, bottom = self.gui.client_size(win)
        elif hWnd == self.DESKTOP_HWND:
            right, bottom = self._screen_size()
        elif self.gui and hWnd in self.gui.controls:
            control = self.gui.controls[hWnd]
            if control.class_name == 'STATUSBAR':
                self.gui.layout_statusbar(control)
            right, bottom = control.width, control.window_height

        if lpRect:
            rect_data = struct.pack("<iiii", left, top, right, bottom)
            self.emu.uc.mem_write(lpRect, rect_data)

        log.debug(f"GetClientRect(0x{hWnd:x}) -> ({left}, {top}, {right}, {bottom})")
        return 1

    def GetWindowRect(self, args):
        """GetWindowRect emulation"""
        hWnd = args[0]
        lpRect = args[1]

        left, top, right, bottom = 100, 100, 500, 400

        combo = self._combo_of_edit(hWnd)
        if combo is not None:
            # The edit field of a combo box: inside the combo box's window rect
            parent = self.gui.windows.get(combo.parent_hwnd)
            ox, oy = self.gui.client_origin(parent) if parent else (0, 0)
            left, top, right, bottom = self._combo_edit_rect(combo)
            left, top = ox + combo.x + left, oy + combo.y + top
            right, bottom = ox + combo.x + right, oy + combo.y + bottom
            if lpRect:
                self._write_rect(lpRect, left, top, right, bottom)
            return 1
        if self.gui and hWnd == self.DESKTOP_HWND:
            # The desktop window covers the screen (dialogs are kept inside it)
            if lpRect:
                self._write_rect(lpRect, 0, 0, *self._screen_size())
            return 1
        if self.gui and hWnd not in self.gui.windows and hWnd not in self.gui.controls:
            # No such window: fails and leaves the RECT alone (Word asks for
            # the zoom box's edit child and filled the toolbar with gray)
            log.debug(f"GetWindowRect(0x{hWnd:x}) -> invalid window")
            self._last_error = 1400  # ERROR_INVALID_WINDOW_HANDLE
            return 0
        if self.gui and hWnd in self.gui.windows:
            win = self.gui.windows[hWnd]
            left, top = win.x, win.y
            if win.parent in self.gui.windows:
                ox, oy = self.gui.client_origin(self.gui.windows[win.parent])
                left, top = ox + win.x, oy + win.y
            right = left + win.width
            bottom = top + win.height
        elif self.gui and hWnd in self.gui.controls:
            control = self.gui.controls[hWnd]
            parent = self.gui.windows.get(control.parent_hwnd)
            if control.class_name == 'STATUSBAR':
                self.gui.layout_statusbar(control)
            ox, oy = self.gui.client_origin(parent) if parent else (0, 0)
            left, top = ox + control.x, oy + control.y
            right, bottom = left + control.width, top + control.window_height

        if lpRect:
            rect_data = struct.pack("<iiii", left, top, right, bottom)
            self.emu.uc.mem_write(lpRect, rect_data)

        log.debug(f"GetWindowRect(0x{hWnd:x}) -> ({left}, {top}, {right}, {bottom})")
        return 1
