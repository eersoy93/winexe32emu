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

"""WinAPIHandler mixin: the trackbar control (msctls_trackbar32)"""

import struct


class TrackbarMixin:
    """msctls_trackbar32: the range, position and step sizes a program sets
    and asks for with TBM_*, and where the channel and the slider are. The
    mouse and the keys don't move the slider yet."""

    TBS_VERT, TBS_NOTHUMB = 0x2, 0x80
    TB_THUMB_LENGTH = 21

    def _tb_state(self, win):
        """Like a new trackbar of Windows: the range 0 to 100, a line is 1
        and a page a fifth of the range"""
        state = win.nstate
        if 'tb_max' not in state:
            state.update(tb_min=0, tb_max=100, tb_pos=0, tb_line=1, tb_page=None,
                         tb_sel=(0, 0), tb_freq=1, tb_buddies={},
                         tb_thumb=self.TB_THUMB_LENGTH)
        return state

    @staticmethod
    def _tb_set_pos(state, position):
        state['tb_pos'] = max(state['tb_min'], min(state['tb_max'], position))

    def _tb_rects(self, win, state):
        """(channel, slider) rectangles in client coordinates"""
        width, height = self.gui.client_size(win)
        vertical = bool(win.style & self.TBS_VERT)
        length, across = (height, width) if vertical else (width, height)
        thumb = min(state['tb_thumb'], max(across - 2, 4))
        half = max(thumb // 4, 3)  # Half the slider's size along the channel
        start, end = 8, max(length - 8, 9)
        span = max(state['tb_max'] - state['tb_min'], 1)
        center = start + half + (state['tb_pos'] - state['tb_min']) * max(
            end - start - 2 * half, 0) // span
        middle = min(across // 2, thumb // 2 + 2)
        channel = (start, middle - 2, end, middle + 2)
        slider = (center - half, middle - thumb // 2, center + half, middle + thumb // 2)
        if vertical:
            channel = (channel[1], channel[0], channel[3], channel[2])
            slider = (slider[1], slider[0], slider[3], slider[2])
        return channel, slider

    def _trackbar_message(self, win, msg, wParam, lParam):
        """Trackbar messages; None for the default processing"""
        if not 0x400 <= msg <= 0x421:
            return None
        state = self._tb_state(win)
        signed = lParam - 0x100000000 if lParam & 0x80000000 else lParam
        if msg == 0x400:  # TBM_GETPOS
            return state['tb_pos']
        if msg == 0x401:  # TBM_GETRANGEMIN
            return state['tb_min']
        if msg == 0x402:  # TBM_GETRANGEMAX
            return state['tb_max']
        if msg == 0x405:  # TBM_SETPOS(redraw, position)
            self._tb_set_pos(state, signed)
            return 0
        if msg in (0x406, 0x407, 0x408):  # TBM_SETRANGE, TBM_SETRANGEMIN, TBM_SETRANGEMAX
            if msg == 0x406:  # MAKELONG(minimum, maximum): two 16-bit numbers
                state['tb_min'], state['tb_max'] = struct.unpack('<hh', struct.pack('<I', lParam))
            else:
                state['tb_min' if msg == 0x407 else 'tb_max'] = signed
            state['tb_max'] = max(state['tb_max'], state['tb_min'])
            self._tb_set_pos(state, state['tb_pos'])
            return 0
        if msg == 0x40A:  # TBM_SETSEL(redraw, MAKELONG(start, end))
            state['tb_sel'] = struct.unpack('<hh', struct.pack('<I', lParam))
            return 0
        if msg in (0x40B, 0x40C):  # TBM_SETSELSTART, TBM_SETSELEND
            start, end = state['tb_sel']
            state['tb_sel'] = (signed, end) if msg == 0x40B else (start, signed)
            return 0
        if msg in (0x411, 0x412):  # TBM_GETSELSTART, TBM_GETSELEND
            return state['tb_sel'][msg - 0x411]
        if msg == 0x413:  # TBM_CLEARSEL
            state['tb_sel'] = (0, 0)
            return 0
        if msg == 0x414:  # TBM_SETTICFREQ
            state['tb_freq'] = max(wParam, 1)
            return 0
        if msg == 0x410:  # TBM_GETNUMTICS: the automatic ones and both ends
            if win.style & 0x10:  # TBS_NOTICKS
                return 0
            return (state['tb_max'] - state['tb_min']) // state['tb_freq'] + 1 \
                if win.style & 0x1 else 2  # TBS_AUTOTICKS
        if msg in (0x415, 0x416):  # TBM_SETPAGESIZE, TBM_GETPAGESIZE
            page = state['tb_page']
            if page is None:
                page = (state['tb_max'] - state['tb_min']) // 5
            if msg == 0x415:
                state['tb_page'] = signed
            return page
        if msg in (0x417, 0x418):  # TBM_SETLINESIZE, TBM_GETLINESIZE
            line = state['tb_line']
            if msg == 0x417:
                state['tb_line'] = signed
            return line
        if msg in (0x419, 0x41A):  # TBM_GETTHUMBRECT, TBM_GETCHANNELRECT
            rects = self._tb_rects(win, state)
            self._mem_write(lParam, struct.pack('<4i', *rects[msg == 0x419]))
            return 0
        if msg == 0x41B:  # TBM_SETTHUMBLENGTH (of a TBS_FIXEDLENGTH trackbar)
            if win.style & 0x40:
                state['tb_thumb'] = max(wParam, 4)
            return 0
        if msg == 0x41C:  # TBM_GETTHUMBLENGTH
            return state['tb_thumb']
        if msg in (0x420, 0x421):  # TBM_SETBUDDY(left or top, window), TBM_GETBUDDY
            side = bool(wParam)
            previous = state['tb_buddies'].get(side, 0)
            if msg == 0x420:
                state['tb_buddies'][side] = lParam
            return previous
        return 0  # Tick marks and tooltips: nothing to remember
