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

"""WinAPIHandler mixin: Toolbar and ReBar controls"""

import struct


class ToolbarMixin:
    """Toolbar and ReBar controls"""

    # ---------- Toolbar ----------

    def _tb_layout(self, win):
        """Button rects (left, top, right, bottom) in toolbar client coordinates"""
        st = win.nstate
        bw, bh = self._tb_button_size(win)
        width = self.gui.client_size(win)[0] if self.gui else 0
        wrap = win.style & 0x200 and width > 0  # TBSTYLE_WRAPABLE
        x, y = 0, 2 if not win.style & 0x40 else 0  # CCS_NODIVIDER
        rects = []
        for button in st['buttons']:
            if button['state'] & 0x8:  # TBSTATE_HIDDEN
                rects.append((x, y, x, y))
                continue
            w = 8 if button['style'] & 0x1 else bw  # BTNS_SEP
            if button['style'] & 0x1 and button['bitmap']:
                w = button['bitmap']
            if wrap and x > 0 and x + w > width:
                x, y = 0, y + bh
            rects.append((x, y, x + w, y + bh))
            x += w
        return rects

    def _tb_button_size(self, win):
        st = win.nstate
        if st['button_size']:
            return st['button_size']
        bw, bh = st['bitmap_size']
        texts = [self._tb_text(win, b) for b in st['buttons']]
        texts = [t for t in texts if t]
        if texts and st['max_text_rows']:
            text_w = max(self._native_text_width(t) for t in texts)
            return (max(bw + 7, text_w + 10), bh + 7 + 15)
        return (bw + 7, bh + 7)

    def _tb_text(self, win, button):
        text = button.get('text')
        if text is None and 0 <= button.get('string', -1) < len(win.nstate['strings']):
            text = win.nstate['strings'][button['string']]
        return text or ''

    def _tb_autosize(self, win):
        rects = self._tb_layout(win)
        height = (max(r[3] for r in rects) if rects else self._tb_button_size(win)[1]) + 2
        if not win.style & 0x4:  # CCS_NORESIZE
            parent = self.gui.windows.get(win.parent)
            if parent is not None and not win.style & 0x8:  # CCS_NOPARENTALIGN
                width = self.gui.client_size(parent)[0]
                win.x, win.y, win.width = 0, 0, width
            win.height = height
        return height

    def _tb_index(self, win, command):
        for i, button in enumerate(win.nstate['buttons']):
            if button['id'] == command:
                return i
        return -1

    def _tb_read_buttons(self, win, address, count, wide):
        size = win.nstate['struct_size'] or 20
        buttons = []
        for i in range(count):
            bitmap, command, state, style, data, string = struct.unpack(
                '<iiBB2xII', self.emu.uc.mem_read(address + i * size, 20))
            button = {'bitmap': bitmap, 'id': command, 'state': state, 'style': style,
                      'data': data, 'string': -1, 'text': None}
            if string >= 0x10000:
                button['text'] = self._read_text(string, wide)
            else:
                button['string'] = string
            buttons.append(button)
        return buttons

    def _toolbar_message(self, win, msg, wParam, lParam):
        """ToolbarWindow32 messages; None for the default processing"""
        st = win.nstate
        buttons = st['buttons']
        wide_msgs = {0x444: 0x414, 0x443: 0x415, 0x44D: 0x41C, 0x43F: 0x441, 0x440: 0x442,
                     0x44B: 0x42D}
        wide = msg in wide_msgs
        msg = wide_msgs.get(msg, msg)

        def set_state(flag, on):
            index = self._tb_index(win, wParam)
            if index < 0:
                return 0
            button = dict(buttons[index])
            button['state'] = (button['state'] | flag) if on else (button['state'] & ~flag)
            new = list(buttons)
            new[index] = button
            st['buttons'] = new
            return 1

        if msg in (self.WM_LBUTTONDOWN, self.WM_LBUTTONDBLCLK):
            x, y = lParam & 0xFFFF, (lParam >> 16) & 0xFFFF
            for i, (left, top, right, bottom) in enumerate(self._tb_layout(win)):
                button = buttons[i]
                if (left <= x < right and top <= y < bottom and not button['style'] & 0x1 and
                        button['state'] & 0x4):  # TBSTATE_ENABLED
                    st['pressed'] = i
            return 0
        if msg == self.WM_LBUTTONUP:
            pressed, st['pressed'] = st['pressed'], -1
            x, y = lParam & 0xFFFF, (lParam >> 16) & 0xFFFF
            rects = self._tb_layout(win)
            if 0 <= pressed < len(rects):
                left, top, right, bottom = rects[pressed]
                if left <= x < right and top <= y < bottom:
                    button = buttons[pressed]
                    if button['style'] & 0x2:  # BTNS_CHECK
                        set_state(0x1, not button['state'] & 0x1)
                    parent = self._parent_of(win.hwnd)
                    if parent:
                        self.post_window_message(parent, self.WM_COMMAND,
                                                 button['id'] & 0xFFFF, win.hwnd)
            return 0
        if msg == 0x401:  # TB_ENABLEBUTTON
            return set_state(0x4, lParam & 0xFFFF)
        if msg == 0x402:  # TB_CHECKBUTTON
            return set_state(0x1, lParam & 0xFFFF)
        if msg == 0x403:  # TB_PRESSBUTTON
            return set_state(0x2, lParam & 0xFFFF)
        if msg == 0x404:  # TB_HIDEBUTTON
            return set_state(0x8, lParam & 0xFFFF)
        if msg in (0x409, 0x40A, 0x40B, 0x40C):  # TB_ISBUTTONENABLED/CHECKED/PRESSED/HIDDEN
            index = self._tb_index(win, wParam)
            flag = {0x409: 0x4, 0x40A: 0x1, 0x40B: 0x2, 0x40C: 0x8}[msg]
            return 1 if index >= 0 and buttons[index]['state'] & flag else 0
        if msg == 0x411:  # TB_SETSTATE
            index = self._tb_index(win, wParam)
            if index < 0:
                return 0
            new = list(buttons)
            new[index] = dict(new[index], state=lParam & 0xFF)
            st['buttons'] = new
            return 1
        if msg == 0x412:  # TB_GETSTATE
            index = self._tb_index(win, wParam)
            return buttons[index]['state'] if index >= 0 else 0xFFFFFFFF
        if msg == 0x413:  # TB_ADDBITMAP
            hinst, nid = self._read_struct(lParam, '<II')
            index = sum(count for count, _ in st['bitmaps'])
            st['bitmaps'] = st['bitmaps'] + [(wParam, (hinst, nid))]
            return index
        if msg == 0x414:  # TB_ADDBUTTONS
            st['buttons'] = buttons + self._tb_read_buttons(win, lParam, wParam, wide)
            return 1
        if msg == 0x415:  # TB_INSERTBUTTON
            index = max(0, min(wParam, len(buttons)))
            st['buttons'] = buttons[:index] + self._tb_read_buttons(win, lParam, 1, wide) + \
                buttons[index:]
            return 1
        if msg == 0x416:  # TB_DELETEBUTTON
            if not 0 <= wParam < len(buttons):
                return 0
            st['buttons'] = buttons[:wParam] + buttons[wParam + 1:]
            return 1
        if msg == 0x417:  # TB_GETBUTTON
            if not 0 <= wParam < len(buttons):
                return 0
            b = buttons[wParam]
            self._mem_write(lParam, struct.pack('<iiBB2xII', b['bitmap'], b['id'], b['state'],
                                                b['style'], b['data'], max(b['string'], 0)))
            return 1
        if msg == 0x418:  # TB_BUTTONCOUNT
            return len(buttons)
        if msg == 0x419:  # TB_COMMANDTOINDEX
            return self._tb_index(win, wParam) & 0xFFFFFFFF
        if msg == 0x41C:  # TB_ADDSTRING
            index = len(st['strings'])
            if lParam >= 0x10000:
                strings = []
                address = lParam
                while True:
                    text = self._read_text(address, wide)
                    if not text:
                        break
                    strings.append(text)
                    address += (len(text) + 1) * (2 if wide else 1)
                st['strings'] = st['strings'] + strings
            return index
        if msg == 0x41D:  # TB_GETITEMRECT
            rects = self._tb_layout(win)
            if not 0 <= wParam < len(rects):
                return 0
            self._mem_write(lParam, struct.pack('<iiii', *rects[wParam]))
            return 1
        if msg == 0x41E:  # TB_BUTTONSTRUCTSIZE
            st['struct_size'] = wParam
            return 0
        if msg == 0x41F:  # TB_SETBUTTONSIZE
            st['button_size'] = (lParam & 0xFFFF, lParam >> 16)
            return 1
        if msg == 0x420:  # TB_SETBITMAPSIZE
            st['bitmap_size'] = (lParam & 0xFFFF, lParam >> 16)
            return 1
        if msg == 0x421:  # TB_AUTOSIZE
            self._tb_autosize(win)
            return 0
        if msg == 0x423:  # TB_GETTOOLTIPS
            return 0
        if msg == 0x425:  # TB_SETPARENT
            previous, st['notify'] = st['notify'], wParam
            return previous
        if msg == 0x428:  # TB_GETROWS
            rects = self._tb_layout(win)
            return len({r[1] for r in rects}) or 1
        if msg == 0x430:  # TB_SETIMAGELIST
            previous, st['imagelist'] = st['imagelist'], lParam
            imagelist = self._imagelist(lParam)
            if imagelist:
                st['bitmap_size'] = (imagelist['cx'], imagelist['cy'])
            return previous
        if msg == 0x431:  # TB_GETIMAGELIST
            return st['imagelist']
        if msg == 0x433:  # TB_GETRECT
            index = self._tb_index(win, wParam)
            rects = self._tb_layout(win)
            if index < 0:
                return 0
            self._mem_write(lParam, struct.pack('<iiii', *rects[index]))
            return 1
        if msg == 0x438:  # TB_SETSTYLE
            win.style = (win.style & 0xFFFF0000) | (lParam & 0xFFFF)
            return 0
        if msg == 0x439:  # TB_GETSTYLE
            return win.style & 0xFFFF
        if msg == 0x43A:  # TB_GETBUTTONSIZE
            bw, bh = self._tb_button_size(win)
            return (bh << 16) | bw
        if msg == 0x43C:  # TB_SETMAXTEXTROWS
            st['max_text_rows'] = wParam
            return 1
        if msg == 0x43D:  # TB_GETTEXTROWS
            return st['max_text_rows']
        if msg == 0x453:  # TB_GETMAXSIZE
            rects = self._tb_layout(win)
            width = max((r[2] for r in rects), default=0)
            height = max((r[3] for r in rects), default=self._tb_button_size(win)[1])
            self._mem_write(lParam, struct.pack('<ii', width, height))
            return 1
        if msg == 0x454:  # TB_SETEXTENDEDSTYLE
            previous, st['ex_style'] = st['ex_style'], lParam
            return previous
        if msg == 0x455:  # TB_GETEXTENDEDSTYLE
            return st['ex_style']
        if msg in (0x441, 0x442):  # TB_GETBUTTONINFO / TB_SETBUTTONINFO
            index = self._tb_index(win, wParam)
            if index < 0:
                return 0xFFFFFFFF if msg == 0x441 else 0
            _, mask, command, image, state, style, cx, _, text_ptr, cch = \
                self._read_struct(lParam, '<IIiiBBHIIi')
            button = dict(buttons[index])
            if msg == 0x441:
                if mask & 0x1:  # TBIF_IMAGE
                    self._mem_write(lParam + 12, struct.pack('<i', button['bitmap']))
                if mask & 0x4:  # TBIF_STATE
                    self._mem_write(lParam + 16, struct.pack('<B', button['state']))
                if mask & 0x8:  # TBIF_STYLE
                    self._mem_write(lParam + 17, struct.pack('<B', button['style']))
                if mask & 0x2 and text_ptr:  # TBIF_TEXT
                    self._copy_text_out(text_ptr, cch, self._tb_text(win, button))
                return index
            if mask & 0x1:
                button['bitmap'] = image
            if mask & 0x4:
                button['state'] = state
            if mask & 0x8:
                button['style'] = style
            if mask & 0x20:  # TBIF_COMMAND
                button['id'] = command
            if mask & 0x2:
                button['text'] = self._read_text(text_ptr, wide) if text_ptr else ''
            new = list(buttons)
            new[index] = button
            st['buttons'] = new
            return 1
        if msg == 0x42D:  # TB_GETBUTTONTEXT
            index = self._tb_index(win, wParam)
            if index < 0:
                return 0xFFFFFFFF
            text = self._tb_text(win, buttons[index])
            if lParam:
                self._write_text(lParam, text, wide)
            return len(text)
        if msg == 0x456:  # TB_GETPADDING
            return (6 << 16) | 7
        if 0x400 <= msg < 0x480:
            return 0
        return None

    def CreateToolbarEx(self, args):
        """CreateToolbarEx emulation"""
        (hwnd, style, control_id, num_bitmaps, bm_inst, bm_id, lp_buttons, num_buttons,
         dx_button, dy_button, dx_bitmap, dy_bitmap, struct_size) = args[:13]
        if not (self.gui and self.gui.running):
            return 0
        toolbar = self._create_native('TOOLBAR', 'ToolbarWindow32', '', 0, 0, 100, 30,
                                      style | self.WS_CHILD, 0, hwnd, control_id)
        win = self.gui.windows[toolbar]
        win.visible = bool(style & self.WS_VISIBLE)
        st = win.nstate
        st['struct_size'] = struct_size or 20
        if dx_bitmap and dy_bitmap:
            st['bitmap_size'] = (dx_bitmap, dy_bitmap)
        if dx_button and dy_button:
            st['button_size'] = (dx_button, dy_button)
        st['bitmaps'] = [(num_bitmaps, (bm_inst, bm_id))]
        if lp_buttons and num_buttons:
            st['buttons'] = self._tb_read_buttons(win, lp_buttons, num_buttons, False)
        self._tb_autosize(win)
        return toolbar

    # ---------- ReBar ----------

    def rebar_layout(self, win):
        """Place the bands' child windows in one row; returns the bar height"""
        st = win.nstate
        width = self.gui.client_size(win)[0]
        bands = [b for b in st['bands'] if not b['style'] & 0x8]  # RBBS_HIDDEN
        height = max([b['cy_min'] for b in bands] + [0]) + 4
        x = 0
        for i, band in enumerate(bands):
            grip = 0 if band['style'] & 0x80 else 10  # RBBS_NOGRIPPER
            if i == len(bands) - 1:
                band_w = max(width - x, band['cx_min'] + grip)
            else:
                band_w = max(band['cx'], band['cx_min'] + grip)
            band['rect'] = (x, 0, x + band_w, height)
            child = self.gui.windows.get(band['child'])
            if child is not None:
                child.x = x + grip + 2
                child.y = 2 + max(0, (height - 4 - band['cy_min']) // 2)
                child.width = max(0, band_w - grip - 4)
                child.height = max(band['cy_min'], child.height if child.native == 'COMBOBOXEX'
                                   else band['cy_min'])
                if child.native == 'COMBOBOXEX':
                    child.height = self.COMBOBOX_BOX_H
                    self._comboboxex_layout(child)
            x += band_w
        return height

    def _rebar_band(self, address, wide):
        size, mask, style, _, _, text_ptr, _, image, child, cx_min, cy_min, cx = \
            self._read_struct(address, '<IIIIIIiiIIIi')
        band = {'mask': mask}
        if mask & 0x1:
            band['style'] = style
        if mask & 0x10:
            band['child'] = child
        if mask & 0x20:
            band['cx_min'], band['cy_min'] = cx_min, cy_min
        if mask & 0x40:
            band['cx'] = cx
        if mask & 0x4 and text_ptr:
            band['text'] = self._read_text(text_ptr, wide)
        if mask & 0x100 and size >= 56:
            band['id'] = struct.unpack('<I', self.emu.uc.mem_read(address + 52, 4))[0]
        return band

    def _rebar_message(self, win, msg, wParam, lParam):
        """ReBarWindow32 messages; None for the default processing"""
        st = win.nstate
        wide_msgs = {0x40A: 0x401, 0x40B: 0x406, 0x41C: 0x41D}
        wide = msg in wide_msgs
        msg = wide_msgs.get(msg, msg)
        if msg == 0x401:  # RB_INSERTBAND
            band = {'style': 0, 'child': 0, 'cx_min': 0, 'cy_min': 0, 'cx': 100, 'text': '',
                    'id': 0}
            band.update({k: v for k, v in self._rebar_band(lParam, wide).items() if k != 'mask'})
            child = self.gui.windows.get(band['child'])
            if child is not None:
                self.gui.reparent(band['child'], win.hwnd)
                if child.native in ('TOOLBAR', 'COMBOBOXEX'):
                    child.nstate['notify'] = win.parent
            index = wParam if wParam < 0x80000000 else len(st['bands'])
            bands = list(st['bands'])
            bands.insert(min(index, len(bands)), band)
            st['bands'] = bands
            self._rebar_resize(win)
            return 1
        if msg == 0x402:  # RB_DELETEBAND
            if not 0 <= wParam < len(st['bands']):
                return 0
            bands = list(st['bands'])
            bands.pop(wParam)
            st['bands'] = bands
            self._rebar_resize(win)
            return 1
        if msg in (0x403, 0x404):  # RB_GETBARINFO / RB_SETBARINFO
            return 1
        if msg == 0x406:  # RB_SETBANDINFO
            if not 0 <= wParam < len(st['bands']):
                return 0
            bands = [dict(b) for b in st['bands']]
            bands[wParam].update({k: v for k, v in self._rebar_band(lParam, wide).items()
                                  if k != 'mask'})
            st['bands'] = bands
            self._rebar_resize(win)
            return 1
        if msg == 0x40C:  # RB_GETBANDCOUNT
            return len(st['bands'])
        if msg == 0x40D:  # RB_GETROWCOUNT
            return 1 if st['bands'] else 0
        if msg in (0x40E, 0x41B):  # RB_GETROWHEIGHT, RB_GETBARHEIGHT
            return self.rebar_layout(win)
        if msg == 0x409:  # RB_GETRECT
            if 0 <= wParam < len(st['bands']):
                self.rebar_layout(win)
                self._mem_write(lParam, struct.pack('<iiii', *st['bands'][wParam].get(
                    'rect', (0, 0, 0, 0))))
                return 1
            return 0
        if msg in (0x41E, 0x41F, 0x417):  # RB_MINIMIZEBAND, RB_MAXIMIZEBAND, RB_SIZETORECT
            self._rebar_resize(win)
            return 1
        if msg == self.WM_SIZE:
            self._rebar_resize(win, notify=False)
            return 0
        if 0x400 <= msg < 0x440:
            return 0
        return None

    def _rebar_resize(self, win, notify=True):
        """Size the bar to its bands (CCS_NORESIZE: keep the height) and lay them out"""
        old = win.height
        height = self.rebar_layout(win)
        border = 2 if win.style & 0x00800000 else 0
        if not win.style & 0x4:  # CCS_NORESIZE
            win.height = height + border
        if notify and win.height != old and win.parent:
            self._notify_simple(win, -831)  # RBN_HEIGHTCHANGE
