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

"""WinAPIHandler mixin: Dialog boxes, property sheets (comctl32), common dialogs (comdlg32)"""

import os
import struct
import time
import fnmatch
import ntpath

from unicorn import UcError

from .. import config, gui, winapi
from ..logger import log
from ..sound import SoundPlayer


class DialogsMixin:
    """Dialog boxes, property sheets (comctl32), common dialogs (comdlg32)"""

    # ---------- Dialog boxes ----------

    DIALOG_CLASS_ATOMS = {0x80: 'BUTTON', 0x81: 'EDIT', 0x82: 'STATIC',
                          0x83: 'LISTBOX', 0x84: 'SCROLLBAR', 0x85: 'COMBOBOX'}
    WM_INITDIALOG = 0x0110
    DS_SETFONT = 0x40
    DS_CENTER = 0x800

    @staticmethod
    def _parse_dialog_template(data):
        """DLGTEMPLATE / DLGTEMPLATEEX -> dict with the dialog and its items"""
        pos = 0

        def sz_or_ord():
            nonlocal pos
            first = struct.unpack_from('<H', data, pos)[0]
            if first == 0:
                pos += 2
                return ''
            if first == 0xFFFF:
                pos += 4
                return struct.unpack_from('<H', data, pos - 2)[0]
            end = pos
            while struct.unpack_from('<H', data, end)[0]:
                end += 2
            text = data[pos:end].decode('utf-16-le', errors='replace')
            pos = end + 2
            return text

        extended = struct.unpack_from('<HH', data, 0) == (1, 0xFFFF)
        if extended:
            ex_style, style = struct.unpack_from('<II', data, 8)
            pos = 16
        else:
            style, ex_style = struct.unpack_from('<II', data, 0)
            pos = 8
        count, x, y, cx, cy = struct.unpack_from('<Hhhhh', data, pos)
        pos += 10
        dialog = {'style': style, 'ex_style': ex_style, 'x': x, 'y': y, 'cx': cx, 'cy': cy,
                  'menu': sz_or_ord(), 'class': sz_or_ord(), 'title': sz_or_ord(),
                  'font': None, 'items': []}
        if style & winapi.WinAPIHandler.DS_SETFONT:
            size = struct.unpack_from('<H', data, pos)[0]
            pos += 6 if extended else 2  # weight, italic, charset
            dialog['font'] = (sz_or_ord(), size)
        for _ in range(count):
            pos = (pos + 3) & ~3
            if extended:
                _, iex, istyle, ix, iy, icx, icy, iid = struct.unpack_from('<IIIhhhhI', data, pos)
                pos += 24
            else:
                istyle, iex, ix, iy, icx, icy, iid = struct.unpack_from('<IIhhhhH', data, pos)
                pos += 18
            item = {'style': istyle, 'ex_style': iex, 'x': ix, 'y': iy, 'cx': icx,
                    'cy': icy, 'id': iid, 'class': sz_or_ord(), 'text': sz_or_ord()}
            pos += 2 + struct.unpack_from('<H', data, pos)[0]  # Creation data
            dialog['items'].append(item)
        return dialog

    @staticmethod
    def _dialog_units(template):
        """Pixels per horizontal / vertical dialog unit of a template's font"""
        size = template['font'][1] if template['font'] else 8
        return 1.5 * size / 8, 1.625 * size / 8

    def _create_dialog(self, template, owner, proc=0, handler=None, parent=0, pos=(0, 0),
                       child_style=None):
        """Create a dialog window and its controls from a parsed template (a
        child dialog of parent at client position pos, like a property page;
        child_style is its window style, else a frameless WS_CHILD).
        Dialog units are converted for an 8 pt dialog font."""
        bx, by = self._dialog_units(template)
        client_w, client_h = round(template['cx'] * bx), round(template['cy'] * by)
        title = template['title'] if isinstance(template['title'], str) else ''
        if parent:
            style = self.WS_CHILD if child_style is None else child_style & ~self.WS_VISIBLE
            ex_style = 0 if child_style is None else template['ex_style']
            # A child dialog with WS_CAPTION or DS_MODALFRAME has a frame around
            # the client area of the template's size
            border, caption = gui.PseudoWindowsGUI.child_frame_size(style, ex_style, dialog=True)
            hwnd = self.gui.create_window(title, pos[0], pos[1],
                                          client_w + 2 * border,
                                          client_h + 2 * border + caption,
                                          style, owner=self, parent=parent)
            win = self.gui.windows[hwnd]
            win.class_name = '#32770'
            win.ex_style = ex_style
            self.dialogs[hwnd] = {'proc': proc, 'handler': handler, 'owner': owner,
                                  'result': 0, 'ended': False}
            self._set_dialog_instance(hwnd, template)
            self._cbt_create_dialog(hwnd, template, parent, style, ex_style)
            self._create_dialog_items(hwnd, template, bx, by)
            return hwnd
        border, caption = gui.PseudoWindowsGUI.frame_size(template['style'], dialog=True)
        width, height = client_w + 2 * border, client_h + 2 * border + caption
        owner_win = self.gui.windows.get(owner)
        screen_w, screen_h = self._screen_size()
        if template['style'] & self.DS_CENTER or owner_win is None:
            if owner_win is not None and owner_win.visible and not owner_win.minimized:
                x = owner_win.x + (owner_win.width - width) // 2
                y = owner_win.y + (owner_win.height - height) // 2
            else:
                x, y = (screen_w - width) // 2, (screen_h - 30 - height) // 2
        else:
            ox, oy = self.gui.client_origin(owner_win)
            x, y = ox + round(template['x'] * bx), oy + round(template['y'] * by)
        x = max(0, min(x, screen_w - width))
        y = max(0, min(y, screen_h - 30 - height))
        hwnd = self.gui.create_window(title, x, y, width, height,
                                      template['style'] & ~self.WS_VISIBLE, owner=self)
        win = self.gui.windows[hwnd]
        win.class_name = '#32770'
        win.is_dialog = True
        self.dialogs[hwnd] = {'proc': proc, 'handler': handler, 'owner': owner,
                              'result': 0, 'ended': False}
        self._set_dialog_instance(hwnd, template)
        self._cbt_create_dialog(hwnd, template, owner, template['style'], template['ex_style'])
        self._create_dialog_items(hwnd, template, bx, by)
        return hwnd

    def _cbt_create_dialog(self, hwnd, template, parent, style, ex_style):
        """WH_CBT HCBT_CREATEWND of a program's dialog, before its controls and
        WM_INITDIALOG (MFC attaches its CDialog and subclasses the dialog)"""
        if self.dialogs[hwnd]['handler'] or not self._hook_chain(self.WH_CBT):
            return
        win = self.gui.windows[hwnd]
        cs_addr = self._build_createstruct(0, template.get('module') or 0, 0, parent,
                                           win.height, win.width, win.y, win.x, style,
                                           0, 0x8002, ex_style)  # The #32770 atom
        try:
            if self.cbt_create_window(hwnd, cs_addr):
                log.debug(f"A WH_CBT hook refused dialog 0x{hwnd:x} (ignored)")
        finally:
            self.emu.heap_free(cs_addr)

    def _set_dialog_instance(self, hwnd, template):
        """GWL_HINSTANCE of a dialog (the module of its template) and its
        DS_SETFONT font (WM_GETFONT)"""
        if template.get('module'):
            self.window_longs.setdefault(hwnd, {})[-6] = template['module']
        self.dialogs[hwnd]['font'] = self._dialog_font(template)

    def _dialog_font(self, template):
        """GDI font handle of a dialog template's DS_SETFONT font (shared by the
        dialogs that use it), or 0. Its point size is for 96 DPI, like the
        dialog units the controls are laid out with."""
        if not template['font']:
            return 0
        face, size = template['font']
        if not isinstance(face, str):
            face = ''
        key = (face.lower(), size)
        if key not in self._dialog_fonts:
            handle = self.get_next_handle()
            self.gdi_objects[handle] = {
                'type': 'font', 'height': max(1, round(size * 96 / 72)), 'cell': False,
                'bold': False, 'italic': False, 'underline': False,
                'face': 'Tahoma' if key[0] in ('ms shell dlg', 'ms shell dlg 2') else face}
            self._dialog_fonts[key] = handle
        return self._dialog_fonts[key]

    def _create_dialog_items(self, hwnd, template, bx, by):
        """Create the controls of a dialog template; they get the dialog's font
        (WM_SETFONT) like on Windows"""
        font_handle = self._dialog_font(template)
        for item in template['items']:
            cls = item['class']
            cls = self.DIALOG_CLASS_ATOMS.get(cls, 'STATIC') if isinstance(cls, int) else cls
            text = item['text'] if isinstance(item['text'], str) else ''
            style = item['style']
            native = self.NATIVE_CLASSES.get(cls.upper())
            if native:
                child = self._create_native(
                    native, cls, text, round(item['x'] * bx), round(item['y'] * by),
                    round(item['cx'] * bx), round(item['cy'] * by),
                    style | self.WS_CHILD, item['ex_style'], hwnd, item['id'] & 0xFFFF)
                child_win = self.gui.windows[child]
                child_win.visible = bool(style & self.WS_VISIBLE) and native != 'TOOLTIPS'
                self._native_moved(child_win)
                continue
            if self._app_class(cls) is not None:
                self._create_class_item(hwnd, item, cls, text, bx, by, font_handle,
                                        template.get('module', 0))
                continue
            if cls.upper() == 'BUTTON' and (style & 0xF) in self.CHECK_BUTTON_STYLES:
                cls = 'CHECKBOX'
            elif cls.upper() == 'MSCTLS_STATUSBAR32':
                cls = 'STATUSBAR'
            elif cls.upper() == 'MSCTLS_PROGRESS32':
                cls = 'PROGRESSBAR'
            ex_style = item['ex_style']
            if cls.upper() == 'EDIT' and style & self.WS_BORDER:
                # Like the dialog manager of Windows 95 and later (DS_3DLOOK):
                # a bordered edit control gets the sunken 3D client edge
                style &= ~self.WS_BORDER
                ex_style |= self.WS_EX_CLIENTEDGE
            chwnd = self.gui.create_control(
                hwnd, cls, text, round(item['x'] * bx), round(item['y'] * by),
                round(item['cx'] * bx), round(item['cy'] * by), style,
                control_id=item['id'] & 0xFFFF, ex_style=ex_style)
            self.dirty_controls[chwnd] = True
            control = self.gui.controls[chwnd]
            if font_handle:
                control.font_handle = font_handle
                control.font = self.gdi_objects[font_handle]
            if cls.upper() == 'STATIC' and style & 0x1F == 3 and item['text'] not in ('', None):
                # SS_ICON: the text names an icon resource; the control takes its size
                key = item['text'] if isinstance(item['text'], int) else \
                    (int(item['text'][1:]) if item['text'][1:].isdigit() and
                     item['text'][:1] == '#' else item['text'].upper())
                control.text = ''
                control.icon = self._load_icon_image(key, hModule=template.get('module', 0))
                if control.icon and not style & 0x40:  # SS_REALSIZECONTROL
                    control.width, control.height = control.icon[0], control.icon[1]
            control.visible = bool(style & self.WS_VISIBLE)
            control.enabled = not style & 0x08000000  # WS_DISABLED

    # Classes the emulator draws itself even if a program registers one by that name
    SYSTEM_CONTROL_CLASSES = ('BUTTON', 'EDIT', 'STATIC', 'LISTBOX', 'COMBOBOX', 'SCROLLBAR',
                              'MSCTLS_STATUSBAR32', 'MSCTLS_PROGRESS32')

    def _app_class(self, name):
        """Name of the program's registered window class called name (window
        class names ignore case), or None for the system's control classes"""
        if not isinstance(name, str) or name.upper() in self.SYSTEM_CONTROL_CLASSES:
            return None
        if name in self.registered_classes:
            return name
        upper = name.upper()
        return next((key for key in self.registered_classes if key.upper() == upper), None)

    def _create_class_item(self, dlg, item, cls, text, bx, by, font_handle, module):
        """A dialog item of a class the program registered (like the gauge and
        the status texts of Microsoft Setup's DLL): a child window with the
        class's window procedure, created like CreateWindowEx does (WM_CREATE,
        then the dialog's font with WM_SETFONT)"""
        atom = self.registered_classes[self._app_class(cls)]['atom']
        name = self._alloc_units(self._text_units(text, False), False) if text else 0
        try:
            hwnd = self.CreateWindowExA([
                item['ex_style'], atom, name, (item['style'] | self.WS_CHILD) & 0xFFFFFFFF,
                round(item['x'] * bx) & 0xFFFFFFFF, round(item['y'] * by) & 0xFFFFFFFF,
                round(item['cx'] * bx) & 0xFFFFFFFF, round(item['cy'] * by) & 0xFFFFFFFF,
                dlg, item['id'] & 0xFFFF, module, 0])
        finally:
            if name:
                self.emu.heap_free(name)
        win = self.gui.windows.get(hwnd)
        if win is None:
            return
        win.ex_style = item['ex_style']
        win.enabled = not item['style'] & 0x08000000  # WS_DISABLED
        if font_handle:
            self._send(hwnd, 0x0030, font_handle, 0)  # WM_SETFONT

    def _dialog_of(self, hwnd):
        """The dialog hwnd belongs to (itself or the parent of a control), or 0"""
        if hwnd in self.dialogs:
            return hwnd
        control = self.gui.controls.get(hwnd) if self.gui else None
        if control is not None and control.parent_hwnd in self.dialogs:
            return control.parent_hwnd
        return 0

    def _dialog_button(self, dlg, control_id=None):
        """Button of a dialog by id, or its default push button (control_id None)"""
        win = self.gui.windows.get(dlg)
        for control in (win.controls if win else []):
            if control.class_name != 'BUTTON' or not control.visible:
                continue
            if control_id is None and (control.style & 0xF) == 1:
                return control
            if control_id is not None and control.control_id == control_id:
                return control
        return None

    def _dialog_message(self, dlg, message, wParam, lParam):
        """Deliver a message to a dialog's procedure (or internal handler)"""
        dialog = self.dialogs.get(dlg)
        if dialog is None:
            return 0
        if dialog['handler']:
            return dialog['handler'](message, wParam, lParam) or 0
        subclass = self._dialog_subclass(dlg)
        if subclass:
            # A subclassed dialog (SetWindowLong GWL_WNDPROC, MFC's AfxWndProc):
            # its procedure passes on to DefDlgProc, which calls the dialog's
            result = self.emu.call_wndproc(subclass, dlg, message, wParam, lParam)
        else:
            result = self.emu.call_wndproc(dialog['proc'], dlg, message, wParam, lParam)
        if message == self.WM_CLOSE and not result and dlg in self.dialogs:
            # DefDlgProc: closing a dialog clicks its Cancel button
            cancel = self._dialog_button(dlg, 2)
            self.emu.call_wndproc(dialog['proc'], dlg, self.WM_COMMAND, 2,
                                  cancel.hwnd if cancel else 0)
        return result

    def _is_def_dlg_proc(self, proc):
        """Is proc a stub of DefDlgProcA/W (the window procedure of a dialog)?"""
        hook = self.emu.api_hooks.get(proc)
        return hook is not None and hook['name'] in ('DefDlgProcA', 'DefDlgProcW')

    def dialog_window_proc(self):
        """GWL_WNDPROC of a dialog that is not subclassed: DefDlgProc"""
        return self.emu.get_api_stub('user32.dll', 'DefDlgProcA')

    def _dialog_subclass(self, dlg):
        """Window procedure a program subclassed a dialog with, or 0"""
        win = self.gui.windows.get(dlg) if self.gui else None
        proc = win.wndproc if win is not None else 0
        return proc if proc and not self._is_def_dlg_proc(proc) else 0

    def _owner_draw_type(self, control):
        """ODT_* type of an owner-draw control, or 0"""
        if control.class_name == 'STATIC' and (control.style & 0x1F) == 0xD:  # SS_OWNERDRAW
            return 5  # ODT_STATIC
        if control.class_name == 'BUTTON' and (control.style & 0xF) == 0xB:  # BS_OWNERDRAW
            return 4  # ODT_BUTTON
        return 0

    def _paint_control(self, hwnd):
        """WM_PAINT of an owner-draw control: send WM_DRAWITEM to its parent"""
        control = self.gui.controls.get(hwnd)
        kind = self._owner_draw_type(control) if control else 0
        if not kind:
            return 0
        if not self._drawitem_buf:
            self._drawitem_buf = self.emu.heap_alloc(48)
        hdc = self._create_dc(hwnd)
        self.gui.clear_drawings(hwnd)
        # CtlType, CtlID, itemID, itemAction (ODA_DRAWENTIRE), itemState, hwndItem, hDC,
        # rcItem, itemData
        self.emu.uc.mem_write(self._drawitem_buf, struct.pack(
            '<7I4iI', kind, control.control_id, 0, 1, 0, hwnd, hdc,
            0, 0, control.width, control.height, 0))
        parent = control.parent_hwnd
        # Like the button and static controls of Windows: the DC gets the
        # control's font and the colors its parent chooses with WM_CTLCOLOR*
        # (DefWindowProc's are the 3D face color and black text)
        state = self.dc_state[hdc]
        if control.font_handle in self.gdi_objects:
            state['font'] = control.font_handle
        state['bk_color'] = self.SYS_COLORS.get(15, (212, 208, 200))  # COLOR_BTNFACE
        state['text_color'] = self.SYS_COLORS.get(18, (0, 0, 0))  # COLOR_BTNTEXT
        message = self.WM_CTLCOLORBTN if kind == 4 else self.WM_CTLCOLORSTATIC
        if self._dialog_of(parent) == parent:
            self._dialog_message(parent, message, hdc, hwnd)
        elif self._find_wndproc_for_hwnd(parent):
            self.emu.call_wndproc(self._find_wndproc_for_hwnd(parent), parent, message, hdc,
                                  hwnd)
        try:
            if self._dialog_of(parent):
                self._dialog_message(parent, self.WM_DRAWITEM, control.control_id,
                                     self._drawitem_buf)
            else:
                wndproc = self._find_wndproc_for_hwnd(parent)
                if wndproc:
                    self.emu.call_wndproc(wndproc, parent, self.WM_DRAWITEM,
                                          control.control_id, self._drawitem_buf)
        finally:
            self._delete_dc(hdc)
        return 0

    WM_CTLCOLOREDIT, WM_CTLCOLORLISTBOX, WM_CTLCOLORBTN = 0x0133, 0x0134, 0x0135
    WM_CTLCOLORDLG, WM_CTLCOLORSTATIC = 0x0136, 0x0138

    def _ctl_color_message(self, control):
        """WM_CTLCOLOR* message a control sends its parent before drawing"""
        cls = control.class_name
        if cls == 'EDIT':
            # Read-only and disabled edit controls draw like statics
            return self.WM_CTLCOLORSTATIC if control.style & 0x800 or not control.enabled \
                else self.WM_CTLCOLOREDIT
        if cls == 'LISTBOX':
            return self.WM_CTLCOLORLISTBOX
        if cls in ('STATIC', 'CHECKBOX') or (cls == 'BUTTON' and control.style & 0xF == 7):
            return self.WM_CTLCOLORSTATIC  # Statics, check boxes, radios, group boxes
        if cls == 'BUTTON':
            return self.WM_CTLCOLORBTN
        return None

    def _ask_ctl_colors(self, parent, message, hwnd):
        """Send a WM_CTLCOLOR* message to parent with a fresh DC of hwnd:
        {'text', 'bk_mode', 'bk_color', 'brush'} the program chose, or None
        if it left the defaults (returned no brush)"""
        hdc = self._create_dc(hwnd)
        try:
            if self._dialog_of(parent) == parent:
                brush = self._dialog_message(parent, message, hdc, hwnd)
            else:
                wndproc = self._find_wndproc_for_hwnd(parent)
                brush = self.emu.call_wndproc(wndproc, parent, message, hdc, hwnd) \
                    if wndproc else 0
            state = self.dc_state.get(hdc)
            if not brush or state is None or self._is_default_ctl_color(message, brush, state):
                return None
            # A hollow brush (NULL_BRUSH) has no color: the parent shows through
            return {'text': state['text_color'], 'bk_mode': state['bk_mode'],
                    'bk_color': state['bk_color'], 'brush': self._brush_color(brush)}
        finally:
            self._delete_dc(hdc)

    WM_CTLCOLORMSGBOX, WM_CTLCOLORSCROLLBAR = 0x0132, 0x0137

    def _default_ctl_color(self, message, hdc):
        """DefWindowProc's (and DefDlgProc's) WM_CTLCOLOR*: the DC gets black
        text on the 3D face color (the window color for edit controls and list
        boxes); returns the brush of that color"""
        index = 5 if message in (self.WM_CTLCOLOREDIT, self.WM_CTLCOLORLISTBOX) else 15
        state = self.dc_state.get(hdc)
        if state is not None:
            state['text_color'] = self.SYS_COLORS[8]  # COLOR_WINDOWTEXT
            state['bk_color'] = self.SYS_COLORS[index]
        return self.GetSysColorBrush([index])

    def _is_default_ctl_color(self, message, brush, state):
        """The answer to a WM_CTLCOLOR* message is DefWindowProc's (the parent
        chose nothing)"""
        index = 5 if message in (self.WM_CTLCOLOREDIT, self.WM_CTLCOLORLISTBOX) else 15
        return (brush == self.GetSysColorBrush([index]) and
                state['text_color'] == self.SYS_COLORS[8] and
                state['bk_color'] == self.SYS_COLORS[index])

    def _update_ctl_colors(self, control):
        """Colors of a control from its parent's WM_CTLCOLOR* answer"""
        message = self._ctl_color_message(control)
        if message is not None and control.parent_hwnd:
            control.ctl_colors = self._ask_ctl_colors(control.parent_hwnd, message,
                                                      control.hwnd)

    def _dispatch(self, hwnd, message, wParam, lParam):
        """DispatchMessage for a message already read from the queue"""
        if message == self.WM_PAINT and hwnd in self.gui.controls:
            return self._paint_control(hwnd)
        if message == self.WM_PAINT and hwnd in self.dialogs:
            # The dialog's background: WM_CTLCOLORDLG to its own procedure
            colors = self._ask_ctl_colors(hwnd, self.WM_CTLCOLORDLG, hwnd)
            win = self.gui.windows.get(hwnd)
            if win is not None:
                win.dialog_brush = colors['brush'] if colors else None
        if message == self.WM_TIMER and lParam:
            tick = int(time.time() * 1000) & 0xFFFFFFFF
            return self.emu.call_callback(lParam, [hwnd, message, wParam, tick])
        dlg = self._dialog_of(hwnd)
        if dlg:
            if message == self.WM_KEYDOWN and wParam in (0x0D, 0x1B):
                # Enter: focused or default push button, Escape: Cancel
                if wParam == 0x0D:
                    focused = self.gui.controls.get(self.gui.focused_control)
                    if (focused is not None and focused.parent_hwnd == dlg and
                            focused.class_name == 'BUTTON' and (focused.style & 0xF) in (0, 1)):
                        button = focused
                    else:
                        button = self._dialog_button(dlg)
                    if button is not None and not button.enabled:
                        return 0
                else:
                    button = self._dialog_button(dlg, 2)
                control_id = button.control_id if button else (1 if wParam == 0x0D else 2)
                return self._dialog_message(dlg, self.WM_COMMAND, control_id,
                                            button.hwnd if button else 0)
            if message == self.WM_KEYDOWN and wParam == 0x09:  # Tab: next edit control
                win = self.gui.windows.get(dlg)
                edits = [c.hwnd for c in (win.controls if win else [])
                         if self._is_text_input(c) and c.visible and c.enabled]
                if edits:
                    current = self.gui.focused_control
                    index = edits.index(current) + 1 if current in edits else 0
                    self.gui.focused_control = edits[index % len(edits)]
                    # The dialog manager selects the text of the edit it moves to
                    self.gui.controls[self.gui.focused_control].select_all()
                return 0
            if hwnd != dlg:
                # A control of the dialog: its own (possibly subclassed) procedure
                # gets what was posted to it (BM_CLICK, its WM_TIMER, the keys)
                if message == self.WM_CHAR and wParam in (0x09, 0x0D, 0x1B):
                    return 0  # The dialog manager took Tab, Enter and Escape
                subclass = self._control_subclass(hwnd)
                if subclass:
                    return self.emu.call_wndproc(subclass, hwnd, message, wParam, lParam)
                return self._control_default(hwnd, message, wParam, lParam)
            return self._dialog_message(dlg, message, wParam, lParam)
        wndproc = self._find_wndproc_for_hwnd(hwnd)
        return self.emu.call_wndproc(wndproc, hwnd, message, wParam, lParam) if wndproc else 0

    def _close_dialog(self, dlg):
        """Destroy a dialog window and reactivate its owner"""
        dialog = self.dialogs.pop(dlg, None)
        self.painted_windows.discard(dlg)
        self.gui._remove_window(dlg)
        owner = self.gui.windows.get(dialog['owner']) if dialog else None
        if owner is not None:
            owner.enabled = True
            if owner.visible and not owner.parent:
                self.BringWindowToTop([owner.hwnd])

    def _run_modal_dialog(self, dlg):
        """Message loop of a modal dialog; returns its EndDialog result"""
        dialog = self.dialogs[dlg]
        owner = self.gui.windows.get(dialog['owner'])
        if owner is not None:
            owner.enabled = False
        result = 0xFFFFFFFF
        try:
            while not dialog['ended']:
                if (self.emu.stop_emulation or self.quit_requested or
                        not self.gui.running or dlg not in self.gui.windows):
                    break
                msg = self._next_message(True)
                if msg is None:
                    self._audio_pump()
                    self.emu.idle_wait(0.01)
                    continue
                if msg[1] == self.WM_QUIT:
                    self.quit_requested = True
                    break
                self._translate_key(*msg)
                self._dispatch(*msg)
            else:
                result = dialog['result']
        finally:
            self._close_dialog(dlg)
        return result

    @staticmethod
    def _is_text_input(control):
        """An EDIT control or the edit field of a CBS_SIMPLE/CBS_DROPDOWN combo box"""
        return control.class_name == 'EDIT' or (control.class_name == 'COMBOBOX' and
                                                control.style & 0x3 in (1, 2))

    def _show_dialog(self, dlg, init_param, show=True):
        """Send WM_INITDIALOG to a new dialog, focus its first edit control and
        show it (a modeless one only if its template has WS_VISIBLE)"""
        win = self.gui.windows[dlg]
        edits = [c for c in win.controls
                 if self._is_text_input(c) and c.visible and c.enabled]
        first = next((c for c in win.controls
                      if c.visible and c.enabled and c.style & 0x00010000), None)  # WS_TABSTOP
        set_focus = self._dialog_message(dlg, self.WM_INITDIALOG,
                                         first.hwnd if first else 0, init_param)
        if dlg not in self.gui.windows:
            return
        if set_focus and edits and self.gui.focused_control not in [c.hwnd for c in edits]:
            self.gui.focused_control = edits[0].hwnd
            edits[0].select_all()  # Like DefDlgProc's initial focus (EM_SETSEL 0, -1)
        if show:
            self.gui.show_window(dlg, True)

    def _load_dialog_template(self, hInstance, lpTemplateName, wide, api_name):
        """Parsed RT_DIALOG resource of the EXE, or None (last error set)"""
        if lpTemplateName < 0x10000:
            key = lpTemplateName
        else:
            name = self._read_text(lpTemplateName, wide)
            key = int(name[1:]) if name.startswith('#') and name[1:].isdigit() else name.upper()
        found = self._find_resource(5, key, hInstance)
        log.info(f"{api_name}({key!r})")
        if found is None:
            self._last_error = 1814  # ERROR_RESOURCE_NAME_NOT_FOUND
            return None
        if not self.gui or not self.gui.running:
            return None
        try:
            template = self._parse_dialog_template(bytes(self.emu.uc.mem_read(*found)))
            template['module'] = hInstance  # Its SS_ICON controls name icons of this module
            return template
        except (struct.error, UcError) as e:
            log.error(f"{api_name}: bad dialog template ({e})")
            return None

    def DialogBoxParamA(self, args, wide=False):
        """DialogBoxParamA/W emulation - modal dialog from an RT_DIALOG resource"""
        hInstance, lpTemplateName, hWndParent, lpDialogFunc, dwInitParam = args[:5]
        template = self._load_dialog_template(hInstance, lpTemplateName, wide,
                                              'DialogBoxParamW' if wide else 'DialogBoxParamA')
        if template is None:
            return 0xFFFFFFFF
        owner = hWndParent
        control = self.gui.controls.get(owner)
        if control is not None:
            owner = control.parent_hwnd
        dlg = self._create_dialog(template, owner, proc=lpDialogFunc)
        self._show_dialog(dlg, dwInitParam)
        return self._run_modal_dialog(dlg)

    def DialogBoxParamW(self, args):
        return self.DialogBoxParamA(args, wide=True)

    def CreateDialogParamA(self, args, wide=False):
        """CreateDialogParamA/W emulation - modeless dialog from an RT_DIALOG
        resource; the program's message loop drives it (IsDialogMessage)"""
        hInstance, lpTemplateName, hWndParent, lpDialogFunc, dwInitParam = args[:5]
        template = self._load_dialog_template(
            hInstance, lpTemplateName, wide,
            'CreateDialogParamW' if wide else 'CreateDialogParamA')
        if template is None:
            return 0
        if template['style'] & self.WS_CHILD and hWndParent in self.gui.windows:
            # A child dialog (DS_CONTROL pages of wizards) inside its parent's client area
            bx, by = self._dialog_units(template)
            dlg = self._create_dialog(template, hWndParent, proc=lpDialogFunc,
                                      parent=hWndParent,
                                      pos=(round(template['x'] * bx), round(template['y'] * by)),
                                      child_style=template['style'])
        else:
            dlg = self._create_dialog(template, self._owner_window(hWndParent),
                                      proc=lpDialogFunc)
        self._show_dialog(dlg, dwInitParam, show=bool(template['style'] & self.WS_VISIBLE))
        return dlg if dlg in self.dialogs else 0

    def CreateDialogParamW(self, args):
        return self.CreateDialogParamA(args, wide=True)

    WM_NEXTDLGCTL = 0x0028

    def _send_dialog_message(self, dlg, message, wParam, lParam):
        """SendMessage to a dialog: its procedure, then the DefDlgProc defaults"""
        result = self._dialog_message(dlg, message, wParam, lParam)
        if message == 0x0031 and not result and dlg in self.dialogs:  # WM_GETFONT
            return self.dialogs[dlg].get('font', 0)  # DefDlgProc: the dialog's font
        if self.WM_CTLCOLORMSGBOX <= message <= self.WM_CTLCOLORSTATIC and not result:
            return self._default_ctl_color(message, wParam)
        if message == self.WM_NEXTDLGCTL and not result and dlg in self.dialogs:
            win = self.gui.windows.get(dlg)
            if lParam & 0xFFFF:  # wParam is the control to focus
                target = wParam
            else:  # Next (wParam 0) or previous tab stop
                stops = [c.hwnd for c in (win.controls if win else [])
                         if c.visible and c.enabled and c.style & 0x00010000]  # WS_TABSTOP
                if not stops:
                    return 0
                current = self.gui.focused_control
                index = stops.index(current) if current in stops else -1
                target = stops[(index + (-1 if wParam else 1)) % len(stops)]
            control = self.gui.controls.get(target)
            if control is not None and control.parent_hwnd == dlg:
                self.SetFocus([target])
        return result

    def EndDialog(self, args):
        """EndDialog emulation - the modal loop ends with nResult"""
        dialog = self.dialogs.get(args[0])
        if dialog is None:
            self._last_error = 1400  # ERROR_INVALID_WINDOW_HANDLE
            return 0
        dialog['ended'] = True
        dialog['result'] = args[1]
        if self.gui and args[0] in self.gui.windows:
            self.gui.windows[args[0]].visible = False
        return 1

    def IsDialogMessageA(self, args):
        """IsDialogMessageA emulation - processes messages for a dialog's window"""
        hDlg, lpMsg = args[0], args[1]
        if hDlg not in self.dialogs:
            return 0
        try:
            hwnd, message, wParam, lParam = struct.unpack('<4I', self.emu.uc.mem_read(lpMsg, 16))
        except UcError:
            return 0
        if self._dialog_of(hwnd) != hDlg:
            return 0
        self._translate_key(hwnd, message, wParam, lParam)  # Like Windows' IsDialogMessage
        self._dispatch(hwnd, message, wParam, lParam)
        return 1

    def IsDialogMessageW(self, args):
        return self.IsDialogMessageA(args)

    # ---------- Property sheets (comctl32) ----------

    PSN_SETACTIVE, PSN_KILLACTIVE, PSN_APPLY, PSN_RESET = -200, -201, -202, -203
    ID_APPLY_NOW = 0x3021
    PSM_CHANGED, PSM_UNCHANGED = 0x468, 0x46D

    def _page_template(self, hinst, template_ref, flags):
        """Dialog template of a property page (resource or in memory)"""
        if flags & 0x1:  # PSP_DLGINDIRECT
            return self._parse_dialog_template(bytes(self.emu.uc.mem_read(template_ref, 0x4000)))
        key = (template_ref if template_ref < 0x10000 else
               self._resource_name_key(template_ref, True))
        resource = self._find_resource(5, key, hinst)
        if resource is None:
            return None
        return self._parse_dialog_template(bytes(self.emu.uc.mem_read(*resource)))

    def PropertySheetW(self, args, wide=True):
        """PropertySheetW/A emulation - a modal dialog with a button per page
        (instead of tabs) and OK, Cancel and Apply"""
        header = args[0]
        _, flags, hwnd_parent, _, _, caption, npages, start, ppsp = self._read_struct(
            header, '<9I')
        if not (self.gui and self.gui.running) or not npages:
            return 0xFFFFFFFF
        if not flags & 0x8:  # PSH_PROPSHEETPAGE (HPROPSHEETPAGE arrays: not emulated)
            log.warning("PropertySheet: only PSH_PROPSHEETPAGE sheets are emulated")
            return 0xFFFFFFFF
        title = self._read_text(caption, wide) if caption >= 0x10000 else ''
        if flags & 0x1:  # PSH_PROPTITLE
            title = f"{title} Properties"
        pages = []
        address = ppsp
        for _ in range(min(npages, 32)):
            psize, pflags, phinst, ptemplate, _, ptitle, proc, _ = self._read_struct(address, '<8I')
            try:
                template = self._page_template(phinst, ptemplate, pflags)
            except (struct.error, UcError):
                template = None
            if template is None:
                log.warning("PropertySheet: page template not found")
                return 0xFFFFFFFF
            name = self._read_text(ptitle, wide) if pflags & 0x8 and ptitle >= 0x10000 else \
                (template['title'] if isinstance(template['title'], str) else '')
            pages.append({'addr': address, 'template': template, 'title': name or '?',
                          'proc': proc, 'hwnd': 0})
            address += psize or 40
        sizes = []
        for page in pages:
            bx, by = self._dialog_units(page['template'])
            sizes.append((round(page['template']['cx'] * bx), round(page['template']['cy'] * by)))
        margin, tab_h, button_w, button_h = 7, 22, 75, 23
        page_w = max(w for w, _ in sizes)
        page_h = max(h for _, h in sizes)
        client_w = max(page_w, 3 * (button_w + 6)) + 2 * margin
        client_h = margin + tab_h + 4 + page_h + margin + button_h + margin
        style = 0x80C80000  # WS_POPUP | WS_CAPTION | WS_SYSMENU
        border, caption_h = gui.PseudoWindowsGUI.frame_size(style, dialog=True)
        width, height = client_w + 2 * border, client_h + 2 * border + caption_h
        owner = self._owner_window(hwnd_parent)
        owner_win = self.gui.windows.get(owner)
        screen_w, screen_h = self._screen_size()
        if owner_win is not None and owner_win.visible:
            x = owner_win.x + (owner_win.width - width) // 2
            y = owner_win.y + (owner_win.height - height) // 2
        else:
            x, y = (screen_w - width) // 2, (screen_h - 30 - height) // 2
        x = max(0, min(x, screen_w - width))
        y = max(0, min(y, screen_h - 30 - height))
        sheet = self.gui.create_window(title, x, y, width, height, style, owner=self)
        sheet_win = self.gui.windows[sheet]
        sheet_win.class_name = '#32770'
        sheet_win.is_dialog = True
        tabs = []
        tab_x = margin
        for i, page in enumerate(pages):
            tab_w = self._native_text_width(page['title']) + 20
            tabs.append(self.gui.create_control(sheet, 'BUTTON', page['title'], tab_x, margin,
                                                tab_w, tab_h, 0x50010000, control_id=0x3100 + i))
            tab_x += tab_w + 2
        button_y = client_h - margin - button_h
        for i, (label, control_id) in enumerate((('OK', 1), ('Cancel', 2),
                                                 ('Apply', self.ID_APPLY_NOW))):
            self.gui.create_control(sheet, 'BUTTON', label,
                                    client_w - margin - (3 - i) * (button_w + 6) + 6, button_y,
                                    button_w, button_h, 0x50010001 if i == 0 else 0x50010000,
                                    control_id=control_id)
        state = {'current': -1}

        def notify(page, code):
            buf = self.emu.heap_alloc(16)
            self._mem_write(buf, struct.pack('<IIiI', sheet, 0, code, 0))
            self.window_longs.setdefault(page['hwnd'], {})[0] = 0
            self._dialog_message(page['hwnd'], self.WM_NOTIFY, 0, buf)
            self.emu.heap_free(buf)
            return self.window_longs.get(page['hwnd'], {}).get(0, 0)

        def activate(index):
            if not 0 <= index < len(pages):
                return
            current = state['current']
            if current == index:
                return
            if current >= 0:
                if notify(pages[current], self.PSN_KILLACTIVE):
                    return  # The page has invalid input
                page_win = self.gui.windows.get(pages[current]['hwnd'])
                if page_win is not None:
                    page_win.visible = False
                self.gui.controls[tabs[current]].checked = False
            page = pages[index]
            if not page['hwnd']:
                page['hwnd'] = self._create_dialog(page['template'], sheet, proc=page['proc'],
                                                   parent=sheet,
                                                   pos=(margin, margin + tab_h + 4))
                self._dialog_message(page['hwnd'], self.WM_INITDIALOG, 0, page['addr'])
            page_win = self.gui.windows.get(page['hwnd'])
            if page_win is not None:
                page_win.visible = True
            state['current'] = index
            self.gui.controls[tabs[index]].checked = True
            notify(page, self.PSN_SETACTIVE)

        def apply():
            current = state['current']
            if current >= 0 and notify(pages[current], self.PSN_KILLACTIVE):
                return False
            for page in pages:
                if page['hwnd']:
                    notify(page, self.PSN_APPLY)
            return True

        def handler(message, wParam, lParam):
            if message == self.WM_INITDIALOG:
                activate(start if start < len(pages) else 0)
                return 0
            if message == self.WM_COMMAND:
                control_id = wParam & 0xFFFF
                if control_id == 1:
                    if apply():
                        self.EndDialog([sheet, 1])
                elif control_id in (2, self.WM_CLOSE):
                    for page in pages:
                        if page['hwnd']:
                            notify(page, self.PSN_RESET)
                    self.EndDialog([sheet, 0])
                elif control_id == self.ID_APPLY_NOW:
                    apply()
                elif 0x3100 <= control_id < 0x3100 + len(pages):
                    activate(control_id - 0x3100)
                return 0
            if message == self.WM_CLOSE:
                return handler(self.WM_COMMAND, 2, 0)
            return 0

        self.dialogs[sheet] = {'proc': 0, 'handler': handler, 'owner': owner, 'result': 0,
                               'ended': False}
        self._show_dialog(sheet, 0)
        result = self._run_modal_dialog(sheet)
        for page in pages:
            self.dialogs.pop(page['hwnd'], None)
        return 1 if result == 1 else 0

    def PropertySheetA(self, args):
        return self.PropertySheetW(args, wide=False)

    # ---------- Common dialogs (comdlg32) ----------

    @staticmethod
    def _dialog_item(cls, text, x, y, cx, cy, control_id, style=0):
        return {'class': cls, 'text': text, 'x': x, 'y': y, 'cx': cx, 'cy': cy,
                'id': control_id, 'style': 0x50000000 | style, 'ex_style': 0}

    @staticmethod
    def _dialog_template(title, cx, cy, items):
        return {'style': 0x80C80000 | 0x800, 'ex_style': 0, 'x': 0, 'y': 0, 'cx': cx,
                'cy': cy, 'menu': '', 'class': '', 'title': title, 'font': None,
                'items': items}

    def _dialog_control(self, dlg, control_id):
        win = self.gui.windows.get(dlg)
        return next((c for c in (win.controls if win else [])
                     if c.control_id == control_id), None)

    def _owner_window(self, hwnd):
        """Top-level window owning hwnd (a control's parent), or 0"""
        control = self.gui.controls.get(hwnd) if self.gui else None
        return control.parent_hwnd if control is not None else hwnd

    def _file_dialog(self, lpofn, save, wide=False):
        """GetOpenFileNameA/W / GetSaveFileNameA/W: a modal file browser"""
        try:
            (hwndOwner, _, lpstrFilter, _, _, nFilterIndex, lpstrFile, nMaxFile,
             lpstrFileTitle, nMaxFileTitle, lpstrInitialDir, lpstrTitle,
             flags) = struct.unpack('<13I', self.emu.uc.mem_read(lpofn + 4, 52))
            lpstrDefExt = struct.unpack('<I', self.emu.uc.mem_read(lpofn + 60, 4))[0]
            filters = []
            if lpstrFilter:
                parts, address = [], lpstrFilter
                while len(parts) < 256:
                    text = self._read_text(address, wide)
                    if not text:
                        break
                    parts.append(text)
                    address += (len(text) + 1) * (2 if wide else 1)
                filters = list(zip(parts[0::2], parts[1::2], strict=False))
        except UcError:
            return 0
        if not self.gui or not self.gui.running:
            return 0
        initial = self._read_text(lpstrFile, wide) if lpstrFile else ''
        default_ext = self._read_text(lpstrDefExt, wide) if lpstrDefExt else ''
        title = (self._read_text(lpstrTitle, wide) if lpstrTitle else
                 ('Save As' if save else 'Open'))
        index = nFilterIndex if 0 < nFilterIndex <= len(filters) else 1
        patterns = (filters[index - 1][1].split(';') if filters else ['*.*'])
        start_dir = self._read_text(lpstrInitialDir, wide) if lpstrInitialDir else ''
        if '\\' in initial or ':' in initial:
            start_dir, initial = ntpath.split(initial)
        directory = self.full_windows_path(start_dir or self.current_directory, clamp=True)
        host = self.resolve_drive_path(directory) if directory else None
        if host is None or not os.path.isdir(host):
            directory = self.current_directory
        log.info(f"{'GetSaveFileNameA' if save else 'GetOpenFileNameA'}"
                 f"(\"{title}\", dir=\"{directory}\", filter={patterns})")

        ID_PATH, ID_LIST, ID_EDIT = 1088, 1120, 1152
        template = self._dialog_template(title, 220, 170, [
            self._dialog_item('STATIC', '', 7, 6, 206, 10, ID_PATH),
            self._dialog_item('LISTBOX', '', 7, 20, 206, 104, ID_LIST, 0x00810001),
            self._dialog_item('STATIC', 'File name:', 7, 134, 40, 10, 0xFFFF),
            self._dialog_item('EDIT', initial if '*' not in initial and '?' not in initial
                              else '', 48, 132, 165, 12, ID_EDIT, 0x00810080),
            self._dialog_item('BUTTON', 'Save' if save else 'Open', 106, 150, 50, 14, 1,
                              0x00010001),
            self._dialog_item('BUTTON', 'Cancel', 163, 150, 50, 14, 2, 0x00010000)])
        state = {'dir': directory, 'patterns': patterns, 'result': None}

        def fill():
            host_dir = self.resolve_drive_path(state['dir'])
            try:
                entries = sorted(os.listdir(host_dir), key=str.lower)
            except (OSError, TypeError):
                entries = []
            dirs = [e for e in entries if os.path.isdir(os.path.join(host_dir, e))]
            files = [e for e in entries if os.path.isfile(os.path.join(host_dir, e)) and
                     any(fnmatch.fnmatch(e.lower(), p.strip().lower().replace('*.*', '*'))
                         for p in state['patterns'])]
            items = ([] if state['dir'].rstrip('\\').endswith(':') else ['[..]'])
            items += [f'[{d}]' for d in dirs] + files
            listbox = self._dialog_control(dlg, ID_LIST)
            listbox.items, listbox.sel_index, listbox.top_index = items, -1, 0
            self._dialog_control(dlg, ID_PATH).text = state['dir']

        def navigate(name):
            target = self.full_windows_path(ntpath.join(state['dir'], name), clamp=True)
            host_dir = self.resolve_drive_path(target) if target else None
            if host_dir is None or not os.path.isdir(host_dir):
                return False
            state['dir'] = target
            fill()
            return True

        def accept():
            name = self._dialog_control(dlg, ID_EDIT).text.strip().strip('"')
            if not name:
                return
            if '*' in name or '?' in name:
                state['patterns'] = name.split(';')
                self._dialog_control(dlg, ID_EDIT).text = ''
                fill()
                return
            if navigate(name):
                self._dialog_control(dlg, ID_EDIT).text = ''
                return
            full = self.full_windows_path(ntpath.join(state['dir'], name), clamp=True)
            if full is None:
                return
            path = self.resolve_drive_path(full)
            if not ntpath.splitext(full)[1] and default_ext and \
                    not (path and os.path.isfile(path)):
                full += '.' + default_ext
                path = self.resolve_drive_path(full)
            if path is None or (flags & 0x1000 and not os.path.isfile(path)):  # OFN_FILEMUSTEXIST
                SoundPlayer.tone(440, 150)
                return
            state['result'] = full
            self.EndDialog([dlg, 1])

        def handler(message, wParam, lParam):
            if message == self.WM_INITDIALOG:
                fill()
                return 1
            if message == self.WM_CLOSE:
                self.EndDialog([dlg, 0])
            elif message == self.WM_COMMAND:
                control_id, code = wParam & 0xFFFF, wParam >> 16
                if control_id == ID_LIST and code == self.LBN_SELCHANGE:
                    listbox = self._dialog_control(dlg, ID_LIST)
                    if 0 <= listbox.sel_index < len(listbox.items):
                        item = listbox.items[listbox.sel_index]
                        if item.startswith('[') and item.endswith(']'):
                            navigate(item[1:-1])
                        else:
                            self._dialog_control(dlg, ID_EDIT).text = item
                elif control_id == 1:
                    accept()
                elif control_id == 2:
                    self.EndDialog([dlg, 0])
            return 0

        dlg = self._create_dialog(template, self._owner_window(hwndOwner), handler=handler)
        self._show_dialog(dlg, 0)
        if self._run_modal_dialog(dlg) != 1 or not state['result']:
            self._last_error = 0
            return 0
        full = state['result']
        units = self._text_units(full, wide)
        if len(units) + 1 > nMaxFile:
            if nMaxFile >= 2:
                self._mem_write(lpstrFile, struct.pack('<H', min(len(units) + 1, 0xFFFF)))
            self._last_error = 0x3003  # FNERR_BUFFERTOOSMALL
            return 0
        self._write_units(lpstrFile, units, wide)
        backslash, period = ord('\\'), ord('.')
        offset = max((i for i, u in enumerate(units) if u == backslash), default=-1) + 1
        dot = max((i for i, u in enumerate(units) if u == period), default=-1)
        extension = dot + 1 if dot >= offset else len(units)
        self._mem_write(lpofn + 56, struct.pack('<HH', offset, extension))
        if lpstrFileTitle and nMaxFileTitle:
            self._write_units(lpstrFileTitle, units[offset:][:nMaxFileTitle - 1], wide)
        self._mem_write(lpofn + 24, struct.pack('<I', index))
        if not flags & 0x8:  # OFN_NOCHANGEDIR
            self.current_directory = ntpath.dirname(full) if offset > 3 else full[:3]
        return 1

    def GetOpenFileNameA(self, args):
        """GetOpenFileNameA emulation"""
        return self._file_dialog(args[0], save=False)

    def GetSaveFileNameA(self, args):
        """GetSaveFileNameA emulation"""
        return self._file_dialog(args[0], save=True)

    def GetOpenFileNameW(self, args):
        return self._file_dialog(args[0], save=False, wide=True)

    def GetSaveFileNameW(self, args):
        return self._file_dialog(args[0], save=True, wide=True)

    def CommDlgExtendedError(self, args):
        """CommDlgExtendedError emulation - the last common dialog error"""
        error = self._last_error
        return error if 0x1000 <= error < 0x4000 else 0

    FR_DOWN, FR_MATCHCASE, FR_FINDNEXT, FR_DIALOGTERM = 0x1, 0x4, 0x8, 0x40
    FR_HIDEMATCHCASE = 0x8000

    def FindTextA(self, args):
        """FindTextA emulation - modeless Find dialog; the owner gets the
        "commdlg_FindReplace" registered message"""
        lpfr = args[0]
        try:
            hwndOwner, _, flags, lpstrFindWhat, _, length = struct.unpack(
                '<IIIIIH', self.emu.uc.mem_read(lpfr + 4, 22))
        except UcError:
            return 0
        if not self.gui or not self.gui.running or not lpstrFindWhat or not length:
            return 0
        messages = winapi.WinAPIHandler.registered_messages
        find_message = messages.setdefault('COMMDLG_FINDREPLACE', 0xC000 + len(messages))
        ID_EDIT, ID_CASE = 1152, 1041
        items = [self._dialog_item('STATIC', 'Find what:', 6, 9, 40, 10, 0xFFFF),
                 self._dialog_item('EDIT', self.read_string(lpstrFindWhat), 48, 7, 128, 12,
                                   ID_EDIT, 0x00810080),
                 self._dialog_item('BUTTON', 'Find Next', 182, 5, 50, 14, 1, 0x00010001),
                 self._dialog_item('BUTTON', 'Cancel', 182, 23, 50, 14, 2, 0x00010000)]
        if not flags & self.FR_HIDEMATCHCASE:
            items.append(self._dialog_item('BUTTON', 'Match case', 6, 28, 64, 12, ID_CASE,
                                           0x00010003))
        owner = self._owner_window(hwndOwner)

        def notify(new_flags):
            try:
                current = struct.unpack('<I', self.emu.uc.mem_read(lpfr + 12, 4))[0]
            except UcError:
                return
            current = (current & ~(self.FR_FINDNEXT | self.FR_DIALOGTERM | self.FR_MATCHCASE)
                       | new_flags)
            self._mem_write(lpfr + 12, struct.pack('<I', current))
            self._dispatch(owner, find_message, 0, lpfr)

        def handler(message, wParam, lParam):
            if message == self.WM_INITDIALOG:
                case = self._dialog_control(dlg, ID_CASE)
                if case is not None:
                    case.checked = bool(flags & self.FR_MATCHCASE)
                return 1
            command = wParam & 0xFFFF if message == self.WM_COMMAND else None
            if command == 1:
                text = self._dialog_control(dlg, ID_EDIT).text
                if text:
                    data = text.encode(config.ANSI_CODEPAGE, errors='replace')[:length - 1]
                    self._mem_write(lpstrFindWhat, data + b'\x00')
                    case = self._dialog_control(dlg, ID_CASE)
                    notify(self.FR_FINDNEXT |
                           (self.FR_MATCHCASE if case is not None and case.checked else 0))
            elif command == 2 or message == self.WM_CLOSE:
                self._close_dialog(dlg)
                notify(self.FR_DIALOGTERM)
            return 0

        dlg = self._create_dialog(self._dialog_template('Find', 238, 44, items), owner,
                                  handler=handler)
        self._show_dialog(dlg, 0)
        return dlg
