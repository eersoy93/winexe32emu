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

"""WinAPIHandler mixin: the tooltip control (tooltips_class32)"""

import struct

from unicorn import UcError


class TooltipsMixin:
    """tooltips_class32: tools (TTM_ADDTOOL...), mouse messages relayed with
    TTM_RELAYEVENT, the tip shown after the initial delay (a timer of the
    tooltip window) with the text of the tool or of TTN_GETDISPINFO"""

    TTF_IDISHWND, TTF_SUBCLASS = 0x1, 0x10
    TTN_GETDISPINFOA, TTN_GETDISPINFOW = 0xFFFFFDF8, 0xFFFFFDEE  # -520, -530
    TT_TIMER_SHOW, TT_TIMER_LEAVE, TT_TIMER_POP = 1, 2, 3
    # TTM_* W messages -> their A counterparts
    TT_WIDE_MESSAGES = {0x432: 0x404, 0x433: 0x405, 0x434: 0x406, 0x435: 0x408, 0x436: 0x409,
                        0x437: 0x40A, 0x438: 0x40B, 0x439: 0x40C, 0x43A: 0x40E, 0x43B: 0x40F}

    @staticmethod
    def _tt_state(win):
        st = win.nstate
        if 'tools' not in st:
            st.update(tools=[], active=True, delays={1: 500, 2: 5000, 3: 500}, current=None,
                      tip=None, max_width=-1)
        return st

    def _tt_read_toolinfo(self, address, wide):
        """TOOLINFO -> dict (None if unreadable)"""
        try:
            size, flags, hwnd, uid, left, top, right, bottom, hinst, text = struct.unpack(
                '<4I4i2I', self.emu.uc.mem_read(address, 40))
            lparam = struct.unpack('<I', self.emu.uc.mem_read(address + 40, 4))[0] \
                if size >= 44 else 0
        except UcError:
            return None
        if text not in (0, self.LPSTR_TEXTCALLBACK) and text >= 0x10000:
            text = self._read_text(text, wide)
        return {'flags': flags, 'hwnd': hwnd, 'id': uid, 'rect': (left, top, right, bottom),
                'hinst': hinst, 'text': text, 'lparam': lparam, 'wide': wide}

    def _tt_find(self, st, info):
        for i, tool in enumerate(st['tools']):
            if tool['hwnd'] == info['hwnd'] and tool['id'] == info['id']:
                return i
        return -1

    def _tt_write_toolinfo(self, address, tool, wide):
        """Fill a TOOLINFO (the text pointer is left as the caller set it unless
        the tool keeps a callback or a resource ID)"""
        try:
            size = struct.unpack('<I', self.emu.uc.mem_read(address, 4))[0]
        except UcError:
            return
        self._mem_write(address + 4, struct.pack('<3I4i', tool['flags'], tool['hwnd'],
                                                 tool['id'], *tool['rect']))
        self._mem_write(address + 32, struct.pack('<I', tool['hinst']))
        text = tool['text']
        if isinstance(text, str):
            pointer = struct.unpack('<I', self.emu.uc.mem_read(address + 36, 4))[0]
            if pointer and pointer != self.LPSTR_TEXTCALLBACK:
                self._write_text(pointer, text, wide)
        else:
            self._mem_write(address + 36, struct.pack('<I', text))
        if size >= 44:
            self._mem_write(address + 40, struct.pack('<I', tool['lparam']))

    def _tt_tool_at(self, st, hwnd, x, y):
        """The tool of window hwnd at its client point (x, y), or None: a
        rectangle tool first, then a whole window one (TTF_IDISHWND)"""
        for tool in st['tools']:
            if not tool['flags'] & self.TTF_IDISHWND and tool['hwnd'] == hwnd:
                left, top, right, bottom = self._tt_tool_rect(tool)
                if left <= x < right and top <= y < bottom:
                    return tool
        for tool in st['tools']:
            if tool['flags'] & self.TTF_IDISHWND and tool['id'] == hwnd:
                return tool
        return None

    def _tt_tool_rect(self, tool):
        """Client rectangle of a rectangle tool. A toolbar keeps the tools of its
        buttons (ID: the command) on the buttons' rectangles, like comctl32 does
        with TTM_NEWTOOLRECT whenever it lays them out again."""
        win = self.gui.windows.get(tool['hwnd']) if self.gui else None
        if win is not None and win.native == 'TOOLBAR':
            index = self._tb_index(win, tool['id'])
            if index >= 0:
                rects = self._tb_layout(win)
                if index < len(rects):
                    return rects[index]
        return tool['rect']

    def _tt_screen_rect(self, tool):
        """Screen rectangle of a tool (None if its window is gone)"""
        hwnd = tool['id'] if tool['flags'] & self.TTF_IDISHWND else tool['hwnd']
        origin = self._client_origin_of(hwnd)
        if origin is None:
            return None
        if tool['flags'] & self.TTF_IDISHWND:
            win = self.gui.windows.get(hwnd)
            width, height = self.gui.client_size(win) if win else (0, 0)
            return origin[0], origin[1], origin[0] + width, origin[1] + height
        left, top, right, bottom = self._tt_tool_rect(tool)
        return origin[0] + left, origin[1] + top, origin[0] + right, origin[1] + bottom

    def _tt_text(self, win, tool):
        """Text of a tool: its own, a string resource or TTN_GETDISPINFO's"""
        text = tool['text']
        if isinstance(text, str):
            return text
        hinst = tool['hinst']
        if text == self.LPSTR_TEXTCALLBACK:
            wide = tool['wide']
            size = 12 + 4 + (160 if wide else 80) + 12
            buf = self.emu.heap_alloc(size)
            self._mem_write(buf, bytes(size))
            code = self.TTN_GETDISPINFOW if wide else self.TTN_GETDISPINFOA
            self._mem_write(buf, struct.pack('<3I', win.hwnd, tool['id'], code))
            self._mem_write(buf + 16 + (160 if wide else 80) + 8, struct.pack('<I',
                                                                             tool['lparam']))
            self._send(tool['hwnd'], self.WM_NOTIFY, tool['id'], buf)
            pointer = struct.unpack('<I', self.emu.uc.mem_read(buf + 12, 4))[0]
            hinst, flags = struct.unpack('<2I', self.emu.uc.mem_read(
                buf + 16 + (160 if wide else 80), 8))
            if pointer >= 0x10000 and pointer != self.LPSTR_TEXTCALLBACK:
                result = self._read_text(pointer, wide)
            elif pointer and hinst:
                result = self._tt_load_string(hinst, pointer, wide)
            else:
                result = self._read_text(buf + 16, wide)
            self.emu.heap_free(buf)
            if flags & 0x10000000:  # TTF_DI_SETITEM: keep the text
                tool['text'] = result
            return result
        if text and hinst:
            return self._tt_load_string(hinst, text, tool['wide'])
        return ''

    def _tt_load_string(self, hinst, string_id, wide):
        buf = self.emu.heap_alloc(1024)
        try:
            length = (self.LoadStringW if wide else self.LoadStringA)([hinst, string_id, buf, 512])
            return self._read_text(buf, wide) if length else ''
        finally:
            self.emu.heap_free(buf)

    def _tt_hide(self, win):
        st = self._tt_state(win)
        st['tip'] = None
        st['current'] = None
        for timer in (self.TT_TIMER_SHOW, self.TT_TIMER_LEAVE, self.TT_TIMER_POP):
            self.KillTimer([win.hwnd, timer])

    def _tt_show(self, win):
        """Show the tip of the current tool below the mouse pointer"""
        st = self._tt_state(win)
        tool = st['current']
        self.KillTimer([win.hwnd, self.TT_TIMER_SHOW])
        if tool is None or not st['active'] or tool not in st['tools']:
            return
        text = self._tt_text(win, tool)
        if not text:
            return
        lines = text.replace('\r\n', '\n').replace('\t', ' ').split('\n')
        width = max(self._native_text_width(line) for line in lines) + 8
        height = 16 * len(lines) + 4
        mouse_x, mouse_y = getattr(self.gui, 'mouse_pos', (0, 0))
        screen_w, screen_h = self._screen_size()
        x = max(0, min(mouse_x, screen_w - width))
        y = mouse_y + 20
        if y + height > screen_h:
            y = max(0, mouse_y - height - 4)
        st['tip'] = {'text': lines, 'rect': (x, y, width, height)}
        win.x, win.y, win.width, win.height = x, y, width, height
        self.SetTimer([win.hwnd, self.TT_TIMER_LEAVE, 100, 0])
        if st['delays'][2]:
            self.SetTimer([win.hwnd, self.TT_TIMER_POP, st['delays'][2], 0])

    def _tt_relay(self, win, hwnd, message, lparam):
        """A mouse message of a tool window (TTM_RELAYEVENT, TTF_SUBCLASS)"""
        st = self._tt_state(win)
        if message in (0x201, 0x202, 0x204, 0x205, 0x207, 0x208):  # Buttons: the tip goes
            if st['tip'] is not None or st['current'] is not None:
                self._tt_hide(win)
            return
        if message != self.WM_MOUSEMOVE or not st['active']:
            return
        x = lparam & 0xFFFF
        y = (lparam >> 16) & 0xFFFF
        x, y = x - 0x10000 if x & 0x8000 else x, y - 0x10000 if y & 0x8000 else y
        tool = self._tt_tool_at(st, hwnd, x, y)
        if tool is st['current']:
            return
        shown = st['tip'] is not None
        self._tt_hide(win)
        if tool is None:
            return
        st['current'] = tool
        if shown:  # Moving from tool to tool keeps the tips up (reshow delay)
            self._tt_show(win)
        else:
            self.SetTimer([win.hwnd, self.TT_TIMER_SHOW, st['delays'][1] or 500, 0])

    def _tt_timer(self, win, timer):
        st = self._tt_state(win)
        if timer == self.TT_TIMER_SHOW:
            self._tt_show(win)
        elif timer == self.TT_TIMER_POP:
            st['tip'] = None
            self.KillTimer([win.hwnd, timer])
        elif timer == self.TT_TIMER_LEAVE:
            tool = st['current']
            rect = self._tt_screen_rect(tool) if tool is not None else None
            mouse_x, mouse_y = getattr(self.gui, 'mouse_pos', (0, 0))
            if rect is None or not (rect[0] <= mouse_x < rect[2] and rect[1] <= mouse_y < rect[3]):
                self._tt_hide(win)

    def _tooltip_message(self, win, msg, wParam, lParam):
        """tooltips_class32 messages; None for the default processing"""
        st = self._tt_state(win)
        wide = msg in self.TT_WIDE_MESSAGES
        msg = self.TT_WIDE_MESSAGES.get(msg, msg)
        if msg == self.WM_TIMER:
            self._tt_timer(win, wParam)
            return 0
        if msg == 0x401:  # TTM_ACTIVATE
            st['active'] = bool(wParam)
            if not wParam:
                self._tt_hide(win)
            return 0
        if msg == 0x403:  # TTM_SETDELAYTIME(TTDT_*, MAKELONG(time, 0))
            delay = lParam & 0xFFFF
            if delay == 0xFFFF:  # -1: the default
                delay = {1: 500, 2: 5000, 3: 100}.get(wParam & 3, 500)
            if wParam & 3 == 0:  # TTDT_AUTOMATIC
                st['delays'] = {1: delay, 2: delay * 10, 3: delay // 5}
            else:
                st['delays'][wParam & 3] = delay
            return 0
        if msg == 0x415:  # TTM_GETDELAYTIME
            return st['delays'].get(wParam & 3, 500)
        if msg in (0x404, 0x405, 0x406, 0x408, 0x409, 0x40C):
            info = self._tt_read_toolinfo(lParam, wide) if lParam else None
            if info is None:
                return 0
            index = self._tt_find(st, info)
            if msg == 0x404:  # TTM_ADDTOOL
                if index >= 0:
                    st['tools'][index] = info
                else:
                    st['tools'].append(info)
                return 1
            if index < 0:
                return 0
            tool = st['tools'][index]
            if msg == 0x405:  # TTM_DELTOOL
                if st['current'] is tool:
                    self._tt_hide(win)
                del st['tools'][index]
            elif msg == 0x406:  # TTM_NEWTOOLRECT
                tool['rect'] = info['rect']
            elif msg == 0x408:  # TTM_GETTOOLINFO
                self._tt_write_toolinfo(lParam, tool, wide)
                return 1
            elif msg == 0x409:  # TTM_SETTOOLINFO
                st['tools'][index] = info
                if st['current'] is tool:
                    st['current'] = info
            else:  # TTM_UPDATETIPTEXT
                tool.update(text=info['text'], hinst=info['hinst'])
                if st['current'] is tool and st['tip'] is not None:
                    self._tt_show(win)
            return 1 if msg != 0x405 else 0
        if msg == 0x407:  # TTM_RELAYEVENT(MSG *)
            if lParam:
                hwnd, message, _, lparam = self._read_struct(lParam, '<4I')
                self._tt_relay(win, hwnd, message, lparam)
            return 0
        if msg == 0x40A:  # TTM_HITTEST(TTHITTESTINFO *): hwnd, pt, TOOLINFO
            hwnd, x, y = self._read_struct(lParam, '<I2i')
            tool = self._tt_tool_at(st, hwnd, x, y)
            if tool is None:
                return 0
            self._tt_write_toolinfo(lParam + 12, tool, wide)
            return 1
        if msg == 0x40B:  # TTM_GETTEXT(0, TOOLINFO *)
            info = self._tt_read_toolinfo(lParam, wide) if lParam else None
            index = self._tt_find(st, info) if info else -1
            pointer = self._read_struct(lParam + 36, '<I')[0] if lParam else 0
            if index >= 0 and pointer:
                self._write_text(pointer, self._tt_text(win, st['tools'][index]), wide)
            return 0
        if msg == 0x40D:  # TTM_GETTOOLCOUNT
            return len(st['tools'])
        if msg == 0x40E:  # TTM_ENUMTOOLS(index, TOOLINFO *)
            if not 0 <= wParam < len(st['tools']) or not lParam:
                return 0
            self._tt_write_toolinfo(lParam, st['tools'][wParam], wide)
            return 1
        if msg == 0x40F:  # TTM_GETCURRENTTOOL
            if st['current'] is None:
                return 0
            if lParam:
                self._tt_write_toolinfo(lParam, st['current'], wide)
            return 1
        if msg in (0x41C, 0x41D):  # TTM_POP, TTM_UPDATE
            if msg == 0x41C:
                self._tt_hide(win)
            return 0
        if msg == 0x418:  # TTM_SETMAXTIPWIDTH
            previous, st['max_width'] = st['max_width'], wParam
            return previous & 0xFFFFFFFF
        if msg == 0x419:  # TTM_GETMAXTIPWIDTH
            return st['max_width'] & 0xFFFFFFFF
        if 0x400 <= msg < 0x440:
            return 0
        return None
