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

"""WinAPIHandler mixin: user32 window enumeration and properties, hooks,
input state, keyboard layouts, character conversion, DPI, monitors and
display devices, window stations, indirect dialogs and menus, and comctl32
window subclassing"""

import struct
import time

from unicorn import UcError

from .. import winapi
from ..logger import log


class User32ExtraMixin:
    """user32 extras and comctl32 window subclassing"""

    # ---------- Window enumeration ----------

    def _top_level_windows(self):
        """Top-level windows of every program, top of the Z order first"""
        if not self.gui:
            return []
        with self.gui.lock:
            return [h for h in reversed(self.gui.z_order)
                    if h in self.gui.windows and not self.gui.windows[h].parent]

    def _descendants(self, hwnd):
        """Child windows and controls of a window, depth first"""
        result = []
        if not self.gui:
            return result
        with self.gui.lock:
            pending = list(reversed(self._child_handles(hwnd)))
            while pending:
                child = pending.pop()
                result.append(child)
                pending.extend(reversed(self._child_handles(child)))
        return result

    def _enum_windows(self, handles, proc, lparam):
        for hwnd in handles:
            if self.emu.stop_emulation:
                break
            if not self.emu.call_callback(proc, [hwnd, lparam]):
                return 0
        return 1

    def EnumWindows(self, args):
        """EnumWindows(proc, lParam) - top-level windows"""
        return self._enum_windows(self._top_level_windows(), args[0], args[1])

    def EnumDesktopWindows(self, args):
        """EnumDesktopWindows(desktop, proc, lParam)"""
        return self._enum_windows(self._top_level_windows(), args[1], args[2])

    def EnumChildWindows(self, args):
        """EnumChildWindows(parent, proc, lParam) - all descendants"""
        if not args[0]:
            return self.EnumWindows(args[1:])
        self._enum_windows(self._descendants(args[0]), args[1], args[2])
        return 1

    def EnumThreadWindows(self, args):
        """EnumThreadWindows(thread ID, proc, lParam) - its top-level windows"""
        handles = [h for h in self._top_level_windows()
                   if self._window_thread(h) is not None and self._window_thread(h) == args[0]]
        return self._enum_windows(handles, args[1], args[2])

    def _window_object(self, hwnd):
        """(FakeWindow of hwnd or of a control's parent, is a control)"""
        if not self.gui:
            return None, False
        control = self.gui.controls.get(hwnd)
        if control is not None:
            return self.gui.windows.get(control.parent_hwnd), True
        return self.gui.windows.get(hwnd), False

    def GetWindowThreadProcessId(self, args):
        """GetWindowThreadProcessId(hwnd, &process ID) - the creating thread"""
        if args[0] == self.DESKTOP_HWND:
            win, owner = None, self
        else:
            win, _ = self._window_object(args[0])
            if win is None:
                self._last_error = 1400  # ERROR_INVALID_WINDOW_HANDLE
                return 0
            owner = win.owner or self
        if args[1]:
            self._mem_write(args[1], struct.pack('<I', owner.GetCurrentProcessId([])))
        if win is not None and win.thread_id:
            return win.thread_id
        return self.emu.current_thread.tid

    def _real_parent(self, hwnd):
        if not self.gui:
            return 0
        control = self.gui.controls.get(hwnd)
        if control is not None:
            return control.parent_hwnd or 0
        win = self.gui.windows.get(hwnd)
        return win.parent or 0 if win is not None else 0

    def IsChild(self, args):
        """IsChild(parent, hwnd) - is hwnd a descendant of parent?"""
        hwnd = self._real_parent(args[1])
        while hwnd:
            if hwnd == args[0]:
                return 1
            hwnd = self._real_parent(hwnd)
        return 0

    def GetAncestor(self, args):
        """GetAncestor(hwnd, GA_PARENT/GA_ROOT/GA_ROOTOWNER)"""
        hwnd, flags = args[0], args[1]
        if not self.IsWindow([hwnd]):
            return 0
        if flags == 1:  # GA_PARENT
            return self._real_parent(hwnd) or self.DESKTOP_HWND
        while self._real_parent(hwnd):
            hwnd = self._real_parent(hwnd)
        if flags == 3:  # GA_ROOTOWNER
            owner = self.GetParent([hwnd])
            while owner and owner != hwnd:
                hwnd = owner
                owner = self.GetParent([hwnd])
        return hwnd

    def GetTopWindow(self, args):
        """GetTopWindow(hwnd) - its first child; NULL: the top window"""
        if not args[0] or args[0] == self.DESKTOP_HWND:
            windows = self._top_level_windows()
            return windows[0] if windows else 0
        return self.GetWindow([args[0], self.GW_CHILD])

    def GetLastActivePopup(self, args):
        return args[0]

    def IsHungAppWindow(self, args):
        return 0

    def GetWindowInfo(self, args):
        """GetWindowInfo(hwnd, WINDOWINFO)"""
        hwnd, info = args[0], args[1]
        if not self.IsWindow([hwnd]):
            self._last_error = 1400
            return 0
        rect = self.emu.heap_alloc(32)
        try:
            self.GetWindowRect([hwnd, rect])
            self.GetClientRect([hwnd, rect + 16])
            self.ClientToScreen([hwnd, rect + 16])
            self.ClientToScreen([hwnd, rect + 24])
            rects = bytes(self.emu.uc.mem_read(rect, 32))
        finally:
            self.emu.heap_free(rect)
        style = self.GetWindowLongA([hwnd, 0xFFFFFFF0])
        ex_style = self.GetWindowLongA([hwnd, 0xFFFFFFEC])
        active = 1 if self.GetForegroundWindow([]) == hwnd else 0
        border = 1 if style & 0x00C00000 else 0
        data = struct.pack('<I', 60) + rects + struct.pack('<IIIIIHH', style, ex_style, active,
                                                           border, border, 0, 0x0400)
        return 1 if self._mem_write(info, data) else 0

    # ---------- Window properties ----------

    def _prop_key(self, address, wide, create):
        """Atom of a property name (a global atom, like on Windows); 0 if missing"""
        if address < 0x10000:
            return address
        if create:
            return self._add_atom(address, wide, True)
        atom = self._find_atom(address, wide, True)
        return atom

    def _window_props(self, hwnd):
        return self.__dict__.setdefault('_props', {}).setdefault(hwnd, {})

    def SetPropA(self, args, wide=False):
        """SetPropA/W(hwnd, name, data)"""
        if not args[0]:
            self._last_error = 1400
            return 0
        key = self._prop_key(args[1], wide, True)
        if not key:
            return 0
        props = self._window_props(args[0])
        if key in props and args[1] >= 0x10000:
            self._delete_atom(key, True)  # Only one reference per property
        props[key] = args[2]
        return 1

    def SetPropW(self, args):
        return self.SetPropA(args, wide=True)

    def GetPropA(self, args, wide=False):
        """GetPropA/W(hwnd, name) - the data, NULL if there is none"""
        key = self._prop_key(args[1], wide, False)
        return self.__dict__.get('_props', {}).get(args[0], {}).get(key, 0) if key else 0

    def GetPropW(self, args):
        return self.GetPropA(args, wide=True)

    def RemovePropA(self, args, wide=False):
        """RemovePropA/W(hwnd, name) - the data of the removed property"""
        key = self._prop_key(args[1], wide, False)
        props = self.__dict__.get('_props', {}).get(args[0], {})
        if not key or key not in props:
            return 0
        if key >= 0xC000:
            self._delete_atom(key, True)
        return props.pop(key)

    def RemovePropW(self, args):
        return self.RemovePropA(args, wide=True)

    def _enum_props(self, hwnd, proc, wide, extra=None):
        props = list(self.__dict__.get('_props', {}).get(hwnd, {}).items())
        if not props:
            return 0xFFFFFFFF
        result = 1
        for key, data in props:
            name = key
            buffer = 0
            if key >= 0xC000:
                with winapi.WinAPIHandler._global_atoms_lock:
                    entry = winapi.WinAPIHandler._global_atoms.get(key)
                if entry:
                    buffer = self._alloc_units(self._text_units(entry['name'], wide), wide)
                    name = buffer
            arguments = [hwnd, name, data] + ([extra] if extra is not None else [])
            result = self.emu.call_callback(proc, arguments)
            if buffer:
                self.emu.heap_free(buffer)
            if not result:
                break
        return result

    def EnumPropsA(self, args, wide=False):
        """EnumPropsA/W(hwnd, proc) - the last callback result, -1 without properties"""
        return self._enum_props(args[0], args[1], wide)

    def EnumPropsW(self, args):
        return self.EnumPropsA(args, wide=True)

    def EnumPropsExA(self, args, wide=False):
        return self._enum_props(args[0], args[1], wide, args[2])

    def EnumPropsExW(self, args):
        return self.EnumPropsExA(args, wide=True)

    # ---------- Hooks: accepted, but never called ----------

    def SetWindowsHookExA(self, args):
        """SetWindowsHookExA/W(id, proc, module, thread) - a hook handle"""
        if not args[1]:
            self._last_error = 1428  # ERROR_HOOK_NEEDS_HMOD
            return 0
        handle = self.get_next_handle()
        self.handles[handle] = {'type': 'hook', 'id': args[0], 'proc': args[1]}
        return handle

    SetWindowsHookExW = SetWindowsHookExA

    def SetWindowsHookA(self, args):
        return self.SetWindowsHookExA([args[0], args[1], 0, 0])

    SetWindowsHookW = SetWindowsHookA

    def UnhookWindowsHookEx(self, args):
        info = self.handles.get(args[0])
        if not info or info.get('type') != 'hook':
            self._last_error = 1404  # ERROR_INVALID_HOOK_HANDLE
            return 0
        del self.handles[args[0]]
        return 1

    def UnhookWindowsHook(self, args):
        for handle, info in list(self.handles.items()):
            if info.get('type') == 'hook' and info['id'] == args[0] and info['proc'] == args[1]:
                del self.handles[handle]
                return 1
        return 0

    def CallNextHookEx(self, args):
        return 0

    def SetWinEventHook(self, args):
        """SetWinEventHook(min, max, module, proc, process, thread, flags)"""
        handle = self.get_next_handle()
        self.handles[handle] = {'type': 'win_event_hook'}
        return handle

    def UnhookWinEvent(self, args):
        info = self.handles.get(args[0])
        if not info or info.get('type') != 'win_event_hook':
            return 0
        del self.handles[args[0]]
        return 1

    def NotifyWinEvent(self, args):
        return 0

    # ---------- Messages and input state ----------

    def _message_pending(self):
        if self.quit_requested or not self.gui or not self.gui.running:
            return True
        return self._next_message(remove=False) is not None

    def GetQueueStatus(self, args):
        """GetQueueStatus(flags) - QS_POSTMESSAGE if a message is waiting"""
        if self.gui and self._next_message(remove=False) is not None:
            bits = 0x8 & args[0]  # QS_POSTMESSAGE
            return (bits << 16) | bits
        return 0

    def GetInputState(self, args):
        return 1 if self.GetQueueStatus([0x7]) else 0

    def InSendMessage(self, args):
        return 0

    def InSendMessageEx(self, args):
        return 0  # ISMEX_NOSEND

    def ReplyMessage(self, args):
        return 0

    def GetMessageTime(self, args):
        return int(time.time() * 1000) & 0x7FFFFFFF

    def GetMessageExtraInfo(self, args):
        return 0

    def SetMessageExtraInfo(self, args):
        return 0

    def WaitMessage(self, args):
        """WaitMessage - returns when a message is waiting"""
        self._wait_ms(10000, until=lambda: not self._message_pending())
        return 1

    def MsgWaitForMultipleObjects(self, args):
        """MsgWaitForMultipleObjects(count, handles, wait all, ms, wake mask)"""
        return self.MsgWaitForMultipleObjectsEx([args[0], args[1], args[3], args[4],
                                                 0x1 if args[2] else 0])  # MWMO_WAITALL

    def MsgWaitForMultipleObjectsEx(self, args):
        """MsgWaitForMultipleObjectsEx(count, handles, ms, wake mask, flags):
        WAIT_OBJECT_0 + i for an object, WAIT_OBJECT_0 + count for a message"""
        count, handles_addr, timeout, flags = args[0], args[1], args[2], args[4]
        handles = list(struct.unpack(f'<{count}I', self.emu.uc.mem_read(handles_addr, 4 * count))) \
            if count else []
        wait_all = bool(flags & 0x1)  # MWMO_WAITALL
        deadline = None if timeout == 0xFFFFFFFF else time.time() + timeout / 1000.0
        while True:
            if handles:
                result = self._wait_objects(handles, wait_all, 0)
                if result != 0x102:  # Not WAIT_TIMEOUT: signaled or WAIT_FAILED
                    return result
            if self._message_pending():
                return count
            if self.emu.stop_emulation or (deadline is not None and time.time() >= deadline):
                return 0x102  # WAIT_TIMEOUT
            remaining = 50 if deadline is None else max(1, (deadline - time.time()) * 1000)
            self._wait_ms(min(20, remaining))

    def TrackMouseEvent(self, args):
        return 1

    def _TrackMouseEvent(self, args):
        return 1

    def DragDetect(self, args):
        return 0

    def mouse_event(self, args):
        return 0

    def keybd_event(self, args):
        return 0

    def SendInput(self, args):
        """SendInput(count, inputs, size) - synthesized input is dropped"""
        return args[0]

    def BlockInput(self, args):
        return 1

    def GetLastInputInfo(self, args):
        """GetLastInputInfo(LASTINPUTINFO) - now"""
        return 1 if self._mem_write(args[0] + 4, struct.pack('<I', self.GetTickCount([]))) else 0

    def SetDoubleClickTime(self, args):
        return 1

    def SwapMouseButton(self, args):
        return 0

    def ClipCursor(self, args):
        """ClipCursor(rect) - remembered (GetClipCursor)"""
        self.__dict__['_clip_rect'] = self._read_rect(args[0]) if args[0] else None
        return 1

    def GetClipCursor(self, args):
        rect = self.__dict__.get('_clip_rect')
        if rect is None:
            width, height = self._screen_size()
            rect = (0, 0, width, height)
        return 1 if self._write_rect(args[0], *rect) else 0

    def GetCursorInfo(self, args):
        """GetCursorInfo(CURSORINFO) - showing, the current cursor and position"""
        point = self.emu.heap_alloc(8)
        try:
            self.GetCursorPos([point])
            position = bytes(self.emu.uc.mem_read(point, 8))
        finally:
            self.emu.heap_free(point)
        showing = 1 if self.cursor_count >= 0 else 0
        data = struct.pack('<III', 20, showing, self.current_cursor or 0) + position
        return 1 if self._mem_write(args[0], data) else 0

    def RegisterHotKey(self, args):
        return 1

    def UnregisterHotKey(self, args):
        return 1

    def AttachThreadInput(self, args):
        return 1

    def WaitForInputIdle(self, args):
        return 0

    def GetGUIThreadInfo(self, args):
        """GetGUIThreadInfo(thread, GUITHREADINFO)"""
        active = self.GetForegroundWindow([])
        data = struct.pack('<8I4i', 48, 0, active, self.GetFocus([]), self.capture_hwnd, 0,
                           0, 0, 0, 0, 0, 0)
        return 1 if self._mem_write(args[1], data) else 0

    # ---------- Keyboard layouts and character keys (US English) ----------

    HKL_US = 0x04090409

    # Characters typed with Shift on the US keyboard -> the unshifted key's character
    US_SHIFTED = dict(zip(')!@#$%^&*(~_+{}|:"<>?', '0123456789`-=[]\\;\',./', strict=True))
    # Character of an OEM key -> its virtual key
    US_OEM_KEYS = {';': 0xBA, '=': 0xBB, ',': 0xBC, '-': 0xBD, '.': 0xBE, '/': 0xBF,
                   '`': 0xC0, '[': 0xDB, '\\': 0xDC, ']': 0xDD, "'": 0xDE}

    def _vk_scan(self, char):
        """VkKeyScan: virtual key | shift state << 8, -1 if no key types it"""
        if 'a' <= char <= 'z':
            return ord(char.upper())
        if 'A' <= char <= 'Z':
            return ord(char) | 0x100
        if '0' <= char <= '9':
            return ord(char)
        if char in self.US_SHIFTED:
            return self._vk_scan(self.US_SHIFTED[char]) | 0x100
        if char in self.US_OEM_KEYS:
            return self.US_OEM_KEYS[char]
        special = {' ': 0x20, '\r': 0x0D, '\n': 0x20D, '\t': 0x09, '\b': 0x08, '\x1b': 0x1B,
                   '\x03': 0x243}
        return special.get(char, 0xFFFF)

    def VkKeyScanA(self, args):
        return self._vk_scan(chr(args[0] & 0xFF))

    def VkKeyScanW(self, args):
        return self._vk_scan(chr(args[0] & 0xFFFF))

    def VkKeyScanExA(self, args):
        return self.VkKeyScanA(args)

    def VkKeyScanExW(self, args):
        return self.VkKeyScanW(args)

    def _key_char(self, vk, key_state):
        """Character a virtual key types with a 256-byte key state (None if none)"""
        try:
            state = bytes(self.emu.uc.mem_read(key_state, 256)) if key_state else bytes(256)
        except UcError:
            state = bytes(256)
        shift = bool(state[0x10] & 0x80)
        if state[0x11] & 0x80 and not state[0x12] & 0x80:  # Ctrl (not AltGr)
            if 0x41 <= vk <= 0x5A:
                return chr(vk - 0x40)
            return {0xDB: '\x1b', 0xDC: '\x1c', 0xDD: '\x1d'}.get(vk)
        if 0x41 <= vk <= 0x5A:
            upper = shift != bool(state[0x14] & 1)  # Caps Lock
            return chr(vk) if upper else chr(vk).lower()
        if 0x30 <= vk <= 0x39:
            return ')!@#$%^&*('[vk - 0x30] if shift else chr(vk)
        if 0x60 <= vk <= 0x69:  # Numeric keypad
            return chr(vk - 0x30)
        keypad = {0x6A: '*', 0x6B: '+', 0x6D: '-', 0x6E: '.', 0x6F: '/'}
        if vk in keypad:
            return keypad[vk]
        for char, key in self.US_OEM_KEYS.items():
            if key == vk:
                if shift:
                    return next(s for s, base in self.US_SHIFTED.items() if base == char)
                return char
        return {0x20: ' ', 0x0D: '\r', 0x09: '\t', 0x08: '\b', 0x1B: '\x1b'}.get(vk)

    def ToAscii(self, args):
        """ToAscii(vk, scan code, key state, &char, flags) - 1 if a character"""
        if args[1] & 0x8000:  # Key up
            return 0
        char = self._key_char(args[0], args[2])
        if char is None:
            return 0
        self._mem_write(args[3], struct.pack('<H', ord(char) & 0xFF))
        return 1

    def ToAsciiEx(self, args):
        return self.ToAscii(args)

    def ToUnicode(self, args):
        """ToUnicode(vk, scan code, key state, buffer, size, flags)"""
        if args[1] & 0x8000 or not args[4]:
            return 0
        char = self._key_char(args[0], args[2])
        if char is None:
            return 0
        self._mem_write(args[3], char.encode('utf-16-le') + b'\x00\x00' if args[4] > 1
                        else char.encode('utf-16-le'))
        return 1

    def ToUnicodeEx(self, args):
        return self.ToUnicode(args)

    # Scan code -> key name (GetKeyNameText); extended keys are (scan, True)
    KEY_NAMES = {
        0x01: 'Esc', 0x0E: 'Backspace', 0x0F: 'Tab', 0x1C: 'Enter', 0x1D: 'Ctrl',
        0x2A: 'Shift', 0x36: 'Right Shift', 0x38: 'Alt', 0x39: 'Space', 0x3A: 'Caps Lock',
        0x45: 'Pause', 0x46: 'Scroll Lock', 0x37: 'Num *', 0x4A: 'Num -', 0x4E: 'Num +',
        0x47: 'Num 7', 0x48: 'Num 8', 0x49: 'Num 9', 0x4B: 'Num 4', 0x4C: 'Num 5',
        0x4D: 'Num 6', 0x4F: 'Num 1', 0x50: 'Num 2', 0x51: 'Num 3', 0x52: 'Num 0',
        0x53: 'Num Del', 0x57: 'F11', 0x58: 'F12',
        (0x1C, True): 'Num Enter', (0x1D, True): 'Right Ctrl', (0x35, True): 'Num /',
        (0x38, True): 'Right Alt', (0x45, True): 'Num Lock', (0x47, True): 'Home',
        (0x48, True): 'Up', (0x49, True): 'Page Up', (0x4B, True): 'Left',
        (0x4D, True): 'Right', (0x4F, True): 'End', (0x50, True): 'Down',
        (0x51, True): 'Page Down', (0x52, True): 'Insert', (0x53, True): 'Delete',
        (0x5B, True): 'Left Windows', (0x5C, True): 'Right Windows', (0x5D, True): 'Application',
    }
    SCAN_CHARACTERS = {0x02: '1234567890-=', 0x10: 'QWERTYUIOP[]', 0x1E: "ASDFGHJKL;'`",
                       0x2B: '\\ZXCVBNM,./'}

    def _key_name(self, scan, extended):
        name = self.KEY_NAMES.get((scan, True) if extended else scan)
        if name is None and extended:
            name = self.KEY_NAMES.get(scan)
        if name is None and 0x3B <= scan <= 0x44:
            name = f'F{scan - 0x3A}'
        if name is None:
            for start, chars in self.SCAN_CHARACTERS.items():
                if start <= scan < start + len(chars):
                    name = chars[scan - start]
        return name

    def GetKeyNameTextA(self, args, wide=False):
        """GetKeyNameTextA/W(lParam of a key message, buffer, size)"""
        scan, extended = (args[0] >> 16) & 0xFF, bool(args[0] & (1 << 24))
        name = self._key_name(scan, extended)
        if name is None or not args[1] or args[2] <= 0:
            return 0
        units = self._text_units(name, wide)[:args[2] - 1]
        self._write_units(args[1], units, wide)
        return len(units)

    def GetKeyNameTextW(self, args):
        return self.GetKeyNameTextA(args, wide=True)

    def OemKeyScan(self, args):
        """OemKeyScan(OEM character) - scan code | shift state << 16"""
        vk = self._vk_scan(chr(args[0] & 0xFF))
        if vk == 0xFFFF:
            return 0xFFFFFFFF
        scan = self.MapVirtualKeyA([vk & 0xFF, 0])
        return scan | ((vk >> 8) << 16)

    def GetKeyboardLayout(self, args):
        return self.__dict__.get('_keyboard_layout', self.HKL_US)

    def GetKeyboardLayoutList(self, args):
        """GetKeyboardLayoutList(count, list) - the active layout"""
        if args[0] and args[1]:
            self._mem_write(args[1], struct.pack('<I', self.GetKeyboardLayout([])))
        return 1

    def GetKeyboardLayoutNameA(self, args, wide=False):
        """GetKeyboardLayoutNameA/W(buffer[KL_NAMELENGTH]) - "00000409\""""
        name = f'{self.GetKeyboardLayout([]) & 0xFFFF:08X}'
        self._write_text(args[0], name, wide)
        return 1

    def GetKeyboardLayoutNameW(self, args):
        return self.GetKeyboardLayoutNameA(args, wide=True)

    def ActivateKeyboardLayout(self, args):
        """ActivateKeyboardLayout(hkl, flags) - the previous layout"""
        previous = self.GetKeyboardLayout([])
        if args[0] not in (0, 1):  # HKL_PREV/HKL_NEXT: there is only one
            self.__dict__['_keyboard_layout'] = args[0]
        return previous

    def LoadKeyboardLayoutW(self, args):
        text = self._alloc_units(self._text_units(self.read_wide_string(args[0]), False), False)
        try:
            return self.LoadKeyboardLayoutA([text, args[1]])
        finally:
            self.emu.heap_free(text)

    def UnloadKeyboardLayout(self, args):
        return 1

    def GetKeyboardType(self, args):
        """GetKeyboardType(0: type, 1: subtype, 2: function keys) - a 101/102-key keyboard"""
        return {0: 4, 1: 0, 2: 12}.get(args[0], 0)

    # ---------- Characters ----------

    def _change_case(self, address, length, wide, upper):
        units = self._read_units(address, wide)[:length] if length else []
        text = self._units_text(units, wide)
        convert = str.upper if upper else str.lower
        # Characters whose case mapping changes the length stay as they are
        changed = ''.join(convert(c) if len(convert(c)) == 1 else c for c in text)
        new_units = self._text_units(changed, wide)
        if len(new_units) == len(units):
            self._write_units(address, new_units, wide, terminate=False)
        return length

    def CharUpperBuffA(self, args):
        """CharUpperBuffA/W(string, length) - the length"""
        return self._change_case(args[0], args[1], False, True)

    def CharUpperBuffW(self, args):
        return self._change_case(args[0], args[1], True, True)

    def CharLowerBuffA(self, args):
        return self._change_case(args[0], args[1], False, False)

    def CharLowerBuffW(self, args):
        return self._change_case(args[0], args[1], True, False)

    def IsCharAlphaW(self, args):
        return 1 if chr(args[0] & 0xFFFF).isalpha() else 0

    def IsCharAlphaNumericW(self, args):
        return 1 if chr(args[0] & 0xFFFF).isalnum() else 0

    def IsCharUpperW(self, args):
        return 1 if chr(args[0] & 0xFFFF).isupper() else 0

    def IsCharLowerW(self, args):
        return 1 if chr(args[0] & 0xFFFF).islower() else 0

    def CharNextW(self, args):
        """CharNextW - the next character (stays on the NUL)"""
        try:
            unit = struct.unpack('<H', self.emu.uc.mem_read(args[0], 2))[0]
        except UcError:
            return args[0]
        return args[0] + 2 if unit else args[0]

    def CharPrevW(self, args):
        return args[1] - 2 if args[1] > args[0] else args[0]

    def CharToOemA(self, args):
        """CharToOemA(source, destination) - ANSI -> OEM, with the NUL"""
        length = len(self.read_cstring(args[0])) + 1
        return self._convert_oem_buffer([args[0], args[1], length], True)

    def OemToCharA(self, args):
        length = len(self.read_cstring(args[0])) + 1
        return self._convert_oem_buffer([args[0], args[1], length], False)

    def CharToOemW(self, args):
        """CharToOemW(wide source, OEM destination)"""
        oem = f"cp{self.OEM_CODEPAGES.get(self._ansi_codepage_number(), 437)}"
        data = self.read_wide_string(args[0]).encode(oem, errors='replace') + b'\x00'
        return 1 if self._mem_write(args[1], data) else 0

    def OemToCharW(self, args):
        """OemToCharW(OEM source, wide destination)"""
        oem = f"cp{self.OEM_CODEPAGES.get(self._ansi_codepage_number(), 437)}"
        text = self.read_cstring(args[0]).decode(oem, errors='replace')
        self._write_text(args[1], text, True)
        return 1

    def CharToOemBuffW(self, args):
        oem = f"cp{self.OEM_CODEPAGES.get(self._ansi_codepage_number(), 437)}"
        units = self._read_units(args[0], True)[:args[2]] if args[2] else []
        data = self._units_text(units, True).encode(oem, errors='replace')
        return 1 if self._mem_write(args[1], data) else 0

    def OemToCharBuffW(self, args):
        oem = f"cp{self.OEM_CODEPAGES.get(self._ansi_codepage_number(), 437)}"
        data = bytes(self.emu.uc.mem_read(args[0], args[2])) if args[2] else b''
        units = self._text_units(data.decode(oem, errors='replace'), True)
        return 1 if self._write_units(args[1], units, True, terminate=False) else 0

    # ---------- DPI: the desktop has 96 DPI ----------

    def SetProcessDPIAware(self, args):
        self.__dict__['_dpi_aware'] = True
        return 1

    def IsProcessDPIAware(self, args):
        return 1 if self.__dict__.get('_dpi_aware') else 0

    def SetProcessDpiAwarenessContext(self, args):
        self.__dict__['_dpi_aware'] = args[0] != 0xFFFFFFFF  # not ..._UNAWARE
        return 1

    def SetThreadDpiAwarenessContext(self, args):
        """SetThreadDpiAwarenessContext(context) - the previous context"""
        previous = self.GetThreadDpiAwarenessContext(args)
        self.__dict__['_thread_dpi_context'] = args[0]
        return previous

    def GetThreadDpiAwarenessContext(self, args):
        default = 0xFFFFFFFE if self.__dict__.get('_dpi_aware') else 0xFFFFFFFF
        return self.__dict__.get('_thread_dpi_context', default)

    def GetWindowDpiAwarenessContext(self, args):
        return self.GetThreadDpiAwarenessContext(args)

    def GetAwarenessFromDpiAwarenessContext(self, args):
        """DPI_AWARENESS of a context: -1 unaware, -2 system, -3/-4 per monitor"""
        return {0xFFFFFFFF: 0, 0xFFFFFFFE: 1, 0xFFFFFFFD: 2, 0xFFFFFFFC: 2,
                0xFFFFFFFB: 0}.get(args[0], 0xFFFFFFFF)

    def AreDpiAwarenessContextsEqual(self, args):
        return 1 if args[0] == args[1] else 0

    def IsValidDpiAwarenessContext(self, args):
        return 1 if args[0] in (0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD, 0xFFFFFFFC,
                                0xFFFFFFFB) else 0

    def GetDpiForWindow(self, args):
        return 96 if self.IsWindow(args) else 0

    def GetDpiForSystem(self, args):
        return 96

    def GetSystemDpiForProcess(self, args):
        return 96

    def GetSystemMetricsForDpi(self, args):
        """GetSystemMetricsForDpi(index, dpi) - scaled from 96 DPI"""
        value = self.GetSystemMetrics([args[0]])
        if value & 0x80000000:
            value -= 1 << 32
        return (value * args[1] // 96) & 0xFFFFFFFF if args[1] else value & 0xFFFFFFFF

    def SystemParametersInfoForDpi(self, args):
        return self.SystemParametersInfoW(args[:4])

    def AdjustWindowRectExForDpi(self, args):
        return self.AdjustWindowRectEx(args[:4])

    def EnableNonClientDpiScaling(self, args):
        return 1

    def LogicalToPhysicalPoint(self, args):
        return 1

    def PhysicalToLogicalPoint(self, args):
        return 1

    def LogicalToPhysicalPointForPerMonitorDPI(self, args):
        return 1

    def PhysicalToLogicalPointForPerMonitorDPI(self, args):
        return 1

    # shcore.dll

    def SetProcessDpiAwareness(self, args):
        self.__dict__['_dpi_aware'] = args[0] != 0
        return 0

    def GetProcessDpiAwareness(self, args):
        """GetProcessDpiAwareness(process, &awareness)"""
        awareness = 1 if self.__dict__.get('_dpi_aware') else 0
        return 0 if self._mem_write(args[1], struct.pack('<I', awareness)) else 0x80070057

    def GetDpiForMonitor(self, args):
        """GetDpiForMonitor(monitor, type, &x, &y) - S_OK"""
        if args[0] != self.MONITOR_HANDLE:
            return 0x80070057  # E_INVALIDARG
        self._mem_write(args[2], struct.pack('<I', 96))
        self._mem_write(args[3], struct.pack('<I', 96))
        return 0

    def GetScaleFactorForMonitor(self, args):
        """GetScaleFactorForMonitor(monitor, &scale) - SCALE_100_PERCENT"""
        return 0 if self._mem_write(args[1], struct.pack('<I', 100)) else 0x80070057

    # ---------- Monitors and display devices ----------

    def EnumDisplayMonitors(self, args):
        """EnumDisplayMonitors(hdc, clip rect, proc, lParam) - one monitor"""
        width, height = self._screen_size()
        rect = self.emu.heap_alloc(16)
        try:
            self._write_rect(rect, 0, 0, width, height)
            self.emu.call_callback(args[2], [self.MONITOR_HANDLE, args[0], rect, args[3]])
            return 1
        finally:
            self.emu.heap_free(rect)

    def EnumDisplayDevicesA(self, args, wide=False):
        """EnumDisplayDevicesA/W(device, index, DISPLAY_DEVICE, flags) - one
        adapter (\\\\.\\DISPLAY1) with one monitor"""
        device, index, info = args[0], args[1], args[2]
        if index != 0:
            return 0
        if device:
            name = self._read_text(device, wide)
            if name.upper() != '\\\\.\\DISPLAY1':
                return 0
            fields = ('\\\\.\\DISPLAY1\\Monitor0', 'Generic PnP Monitor', 0x3,
                      'MONITOR\\Default_Monitor', '')
        else:
            fields = ('\\\\.\\DISPLAY1', 'Emulated Display Adapter', 0x5,  # ATTACHED, PRIMARY
                      'PCI\\VEN_1234&DEV_1111', '')
        unit = 2 if wide else 1

        def text(value, length):
            return self._pack_units(self._text_units(value, wide), wide).ljust(
                length * unit, b'\x00')[:length * unit]

        data = (text(fields[0], 32) + text(fields[1], 128) + struct.pack('<I', fields[2]) +
                text(fields[3], 128) + text(fields[4], 128))
        return 1 if self._mem_write(info + 4, data) else 0

    def EnumDisplayDevicesW(self, args):
        return self.EnumDisplayDevicesA(args, wide=True)

    def EnumDisplaySettingsExA(self, args):
        return self.EnumDisplaySettingsA(args[:3])

    def _devmode_w_to_a(self, address):
        """Copy of a DEVMODEW in the DEVMODEA layout (heap block; caller frees)"""
        data = bytes(self.emu.uc.mem_read(address, 220))
        name = data[:64].decode('utf-16-le', errors='replace').split('\x00')[0]
        form = data[102:166].decode('utf-16-le', errors='replace').split('\x00')[0]
        converted = (name.encode('ascii', 'replace').ljust(32, b'\x00')[:32] + data[64:70] +
                     struct.pack('<H', 156) + data[72:102] +
                     form.encode('ascii', 'replace').ljust(32, b'\x00')[:32] + data[166:220])
        block = self.emu.heap_alloc(len(converted))
        self._mem_write(block, converted)
        return block

    def EnumDisplaySettingsW(self, args):
        """EnumDisplaySettingsW(device, mode, DEVMODEW)"""
        block = self.emu.heap_alloc(156)
        try:
            if not self.EnumDisplaySettingsA([0, args[1], block]):
                return 0
            data = bytes(self.emu.uc.mem_read(block, 156))
        finally:
            self.emu.heap_free(block)
        wide = (data[:32].split(b'\x00')[0].decode('ascii').encode('utf-16-le').ljust(64, b'\x00')
                + data[32:36] + struct.pack('<H', 220) + data[38:70] + b'\x00' * 64 +
                data[102:156])
        return 1 if self._mem_write(args[2], wide) else 0

    def EnumDisplaySettingsExW(self, args):
        return self.EnumDisplaySettingsW(args[:3])

    def ChangeDisplaySettingsW(self, args):
        """ChangeDisplaySettingsW(DEVMODEW, flags)"""
        if not args[0]:
            return self.ChangeDisplaySettingsA(args)
        block = self._devmode_w_to_a(args[0])
        try:
            return self.ChangeDisplaySettingsA([block, args[1]])
        finally:
            self.emu.heap_free(block)

    def ChangeDisplaySettingsExA(self, args):
        """ChangeDisplaySettingsExA(device, DEVMODE, hwnd, flags, param)"""
        return self.ChangeDisplaySettingsA([args[1], args[3]])

    def ChangeDisplaySettingsExW(self, args):
        return self.ChangeDisplaySettingsW([args[1], args[3]])

    # ---------- Window stations and desktops ----------

    WINSTA_HANDLE = 0x00000040
    DESKTOP_OBJECT_HANDLE = 0x00000044

    def GetProcessWindowStation(self, args):
        return self.WINSTA_HANDLE

    def GetThreadDesktop(self, args):
        return self.DESKTOP_OBJECT_HANDLE

    def OpenDesktopA(self, args):
        return self.DESKTOP_OBJECT_HANDLE

    OpenDesktopW = OpenInputDesktop = OpenDesktopA

    def OpenWindowStationA(self, args):
        return self.WINSTA_HANDLE

    OpenWindowStationW = OpenWindowStationA

    def CloseDesktop(self, args):
        return 1

    CloseWindowStation = SwitchDesktop = SetThreadDesktop = CloseDesktop

    def SetProcessWindowStation(self, args):
        return 1

    def GetUserObjectInformationA(self, args, wide=False):
        """GetUserObjectInformationA/W(object, index, buffer, size, &needed) -
        the interactive window station WinSta0 and its Default desktop"""
        handle, index, buffer, size, needed = args[:5]
        station = handle == self.WINSTA_HANDLE
        if handle not in (self.WINSTA_HANDLE, self.DESKTOP_OBJECT_HANDLE):
            self._last_error = 6  # ERROR_INVALID_HANDLE
            return 0
        if index == 1:  # UOI_FLAGS: USEROBJECTFLAGS (WSF_VISIBLE)
            data = struct.pack('<III', 0, 0, 1 if station else 0)
        elif index in (2, 3):  # UOI_NAME, UOI_TYPE
            text = ('WinSta0' if station else 'Default') if index == 2 else \
                ('WindowStation' if station else 'Desktop')
            data = self._pack_units(self._text_units(text, wide) + [0], wide)
        elif index == 4:  # UOI_USER_SID: none
            data = b''
        elif index == 6:  # UOI_IO: receives input
            data = struct.pack('<I', 1)
        else:
            self._last_error = 87
            return 0
        if needed:
            self._mem_write(needed, struct.pack('<I', len(data)))
        if size < len(data):
            self._last_error = 122  # ERROR_INSUFFICIENT_BUFFER
            return 0
        return 1 if not data or self._mem_write(buffer, data) else 0

    def GetUserObjectInformationW(self, args):
        return self.GetUserObjectInformationA(args, wide=True)

    def LockWorkStation(self, args):
        return 1

    def ShutdownBlockReasonCreate(self, args):
        return 1

    def ShutdownBlockReasonDestroy(self, args):
        return 1

    # ---------- Painting ----------

    def RedrawWindow(self, args):
        """RedrawWindow(hwnd, rect, region, flags) - RDW_INVALIDATE repaints,
        RDW_UPDATENOW paints at once"""
        hwnd, flags = args[0] or self.DESKTOP_HWND, args[3]
        if flags & 0x1:  # RDW_INVALIDATE
            self.InvalidateRect([hwnd, args[1], 1 if flags & 0x4 else 0])
        if flags & 0x8:  # RDW_VALIDATE
            self.ValidateRect([hwnd, args[1]])
        if flags & 0x100:  # RDW_UPDATENOW
            self.UpdateWindow([hwnd])
        return 1

    def InvalidateRgn(self, args):
        return self.InvalidateRect([args[0], 0, args[2]])

    def ValidateRgn(self, args):
        return self.ValidateRect([args[0], 0])

    def GetUpdateRect(self, args):
        """GetUpdateRect(hwnd, rect, erase) - the client area until it is painted"""
        pending = self.IsWindow([args[0]]) and args[0] not in self.painted_windows
        if args[1]:
            if pending:
                self.GetClientRect([args[0], args[1]])
            else:
                self._write_rect(args[1], 0, 0, 0, 0)
        return 1 if pending else 0

    def GetUpdateRgn(self, args):
        """GetUpdateRgn(hwnd, region, erase) - NULLREGION or SIMPLEREGION"""
        return 2 if self.IsWindow([args[0]]) and args[0] not in self.painted_windows else 1

    def GetWindowDC(self, args):
        return self.GetDC(args)

    def LockWindowUpdate(self, args):
        return 1

    def ShowOwnedPopups(self, args):
        return 1

    def FlashWindow(self, args):
        return 0

    def FlashWindowEx(self, args):
        return 0

    def AnimateWindow(self, args):
        """AnimateWindow(hwnd, time, flags) - shown or hidden at once"""
        return self.ShowWindow([args[0], 0 if args[2] & 0x10000 else 5])  # AW_HIDE

    def SetLayeredWindowAttributes(self, args):
        self.__dict__.setdefault('_layered', {})[args[0]] = (args[1], args[2] & 0xFF, args[3])
        return 1

    def GetLayeredWindowAttributes(self, args):
        """GetLayeredWindowAttributes(hwnd, &key, &alpha, &flags)"""
        values = self.__dict__.get('_layered', {}).get(args[0])
        if values is None:
            return 0
        for address, fmt, value in zip(args[1:4], ('<I', '<B', '<I'), values, strict=True):
            if address:
                self._mem_write(address, struct.pack(fmt, value))
        return 1

    def UpdateLayeredWindow(self, args):
        return 1

    def SubtractRect(self, args):
        """SubtractRect(dest, a, b) - a minus b when b covers a whole side of a"""
        first, second = self._read_rect(args[1]), self._read_rect(args[2])
        if first is None or second is None:
            return 0
        left, top, right, bottom = first
        if left >= right or top >= bottom:
            self._write_rect(args[0], 0, 0, 0, 0)
            return 0
        b_left, b_top, b_right, b_bottom = second
        if b_left <= left and b_right >= right:
            if b_top <= top and b_bottom >= bottom:
                self._write_rect(args[0], 0, 0, 0, 0)
                return 0
            if b_top <= top < b_bottom:
                top = b_bottom
            elif b_top < bottom <= b_bottom:
                bottom = b_top
        elif b_top <= top and b_bottom >= bottom:
            if b_left <= left < b_right:
                left = b_right
            elif b_left < right <= b_right:
                right = b_left
        self._write_rect(args[0], left, top, right, bottom)
        return 1

    def InvertRect(self, args):
        return 1

    def DrawEdge(self, args):
        """DrawEdge(hdc, rect, edge, flags) - BF_ADJUST shrinks the rectangle"""
        rect = self._read_rect(args[1])
        if rect is None:
            return 0
        if args[3] & 0x2000:  # BF_ADJUST
            width = (1 if args[2] & 0x3 else 0) + (1 if args[2] & 0xC else 0)
            left, top, right, bottom = rect
            flags = args[3]
            left += width if flags & 0x1 else 0
            top += width if flags & 0x2 else 0
            right -= width if flags & 0x4 else 0
            bottom -= width if flags & 0x8 else 0
            self._write_rect(args[1], left, top, right, bottom)
        return 1

    def DrawFrameControl(self, args):
        return 1

    def DrawCaption(self, args):
        return 1

    def GrayStringA(self, args):
        return 1

    GrayStringW = DrawStateA = DrawStateW = GrayStringA

    # ---------- Dialogs ----------

    def _indirect_template(self, address, api_name):
        """Parsed DLGTEMPLATE(EX) in memory, or None"""
        if not self.gui or not self.gui.running:
            return None
        data = bytearray()
        position = address
        while len(data) < 0x10000:  # Read what is mapped (a template has no size)
            try:
                data += self.emu.uc.mem_read(position, 0x1000 - (position & 0xFFF))
            except UcError:
                break
            position = (position | 0xFFF) + 1
        try:
            return self._parse_dialog_template(bytes(data))
        except (struct.error, IndexError, ValueError) as e:
            log.error(f"{api_name}: bad dialog template ({e})")
            return None

    def DialogBoxIndirectParamA(self, args):
        """DialogBoxIndirectParamA/W(instance, template, parent, proc, param)"""
        template = self._indirect_template(args[1], 'DialogBoxIndirectParam')
        if template is None:
            return 0xFFFFFFFF
        template['module'] = args[0]
        dlg = self._create_dialog(template, self._owner_window(args[2]), proc=args[3])
        self._show_dialog(dlg, args[4])
        return self._run_modal_dialog(dlg)

    DialogBoxIndirectParamW = DialogBoxIndirectParamA

    def CreateDialogIndirectParamA(self, args):
        """CreateDialogIndirectParamA/W(instance, template, parent, proc, param)"""
        template = self._indirect_template(args[1], 'CreateDialogIndirectParam')
        if template is None:
            return 0
        template['module'] = args[0]
        parent = args[2]
        if template['style'] & self.WS_CHILD and parent in self.gui.windows:
            bx, by = self._dialog_units(template)
            dlg = self._create_dialog(template, parent, proc=args[3], parent=parent,
                                      pos=(round(template['x'] * bx), round(template['y'] * by)))
            self.gui.windows[dlg].style = template['style'] & ~self.WS_VISIBLE
            self.gui.windows[dlg].ex_style = template['ex_style']
        else:
            dlg = self._create_dialog(template, self._owner_window(parent), proc=args[3])
        self._show_dialog(dlg, args[4], show=bool(template['style'] & self.WS_VISIBLE))
        return dlg if dlg in self.dialogs else 0

    CreateDialogIndirectParamW = CreateDialogIndirectParamA

    def _dialog_stops(self, dlg, group=False):
        if not self.gui:
            return []
        win = self.gui.windows.get(dlg)
        controls = [c for c in (win.controls if win else []) if c.visible and c.enabled]
        if not group:
            return [c.hwnd for c in controls if c.style & 0x00010000]  # WS_TABSTOP
        return controls

    def GetNextDlgTabItem(self, args):
        """GetNextDlgTabItem(dialog, control, previous) - the next WS_TABSTOP control"""
        stops = self._dialog_stops(args[0])
        if not stops:
            return 0
        index = stops.index(args[1]) if args[1] in stops else -1
        if index < 0:
            return stops[-1] if args[2] else stops[0]
        return stops[(index + (-1 if args[2] else 1)) % len(stops)]

    def GetNextDlgGroupItem(self, args):
        """GetNextDlgGroupItem(dialog, control, previous) - within its WS_GROUP group"""
        controls = self._dialog_stops(args[0], group=True)
        handles = [c.hwnd for c in controls]
        if args[1] not in handles:
            return handles[0] if handles else 0
        index = handles.index(args[1])
        start = index
        while start > 0 and not controls[start].style & 0x00020000:  # WS_GROUP
            start -= 1
        end = index + 1
        while end < len(controls) and not controls[end].style & 0x00020000:
            end += 1
        group = handles[start:end]
        position = group.index(args[1])
        return group[(position + (-1 if args[2] else 1)) % len(group)]

    def SetWindowContextHelpId(self, args):
        self.__dict__.setdefault('_help_ids', {})[args[0]] = args[1]
        return 1

    def GetWindowContextHelpId(self, args):
        return self.__dict__.get('_help_ids', {}).get(args[0], 0)

    def GetComboBoxInfo(self, args):
        """GetComboBoxInfo(combo box, COMBOBOXINFO)"""
        control = self.gui.controls.get(args[0]) if self.gui else None
        if control is None or 'COMBOBOX' not in control.class_name:
            return 0
        data = struct.pack('<I8iI3I', 52, 0, 0, control.width, control.height,
                           max(0, control.width - 18), 0, control.width, control.height,
                           0, args[0], 0, 0)
        return 1 if self._mem_write(args[1], data) else 0

    # ---------- Menus ----------

    def IsMenu(self, args):
        return 1 if args[0] in self.menus else 0

    def EndMenu(self, args):
        return 1

    def HiliteMenuItem(self, args):
        return 1

    def GetMenuItemRect(self, args):
        if args[3]:
            self._write_rect(args[3], 0, 0, 0, 0)
        return 0

    def MenuItemFromPoint(self, args):
        return 0xFFFFFFFF

    def GetMenuCheckMarkDimensions(self, args):
        return 13 | (13 << 16)

    def SetMenuItemBitmaps(self, args):
        return 1 if args[0] in self.menus else 0

    def SetMenuDefaultItem(self, args):
        """SetMenuDefaultItem(menu, item, by position) - item -1 clears it"""
        if args[0] not in self.menus:
            return 0
        defaults = self.__dict__.setdefault('_menu_defaults', {})
        if args[1] == 0xFFFFFFFF:
            defaults.pop(args[0], None)
            return 1
        hmenu, index = self._menu_item(args[0], args[1], args[2])
        if hmenu is None:
            return 0
        defaults[args[0]] = index
        return 1

    def GetMenuDefaultItem(self, args):
        """GetMenuDefaultItem(menu, by position, flags) - -1 without one"""
        index = self.__dict__.get('_menu_defaults', {}).get(args[0])
        items = self.menus.get(args[0])
        if index is None or items is None or index >= len(items):
            return 0xFFFFFFFF
        return index if args[1] else items[index]['id']

    def SetMenuInfo(self, args):
        """SetMenuInfo(menu, MENUINFO) - kept for GetMenuInfo"""
        if args[0] not in self.menus:
            return 0
        try:
            _, mask, *values = struct.unpack('<7I', self.emu.uc.mem_read(args[1], 28))
        except UcError:
            return 0
        info = self.__dict__.setdefault('_menu_infos', {}).setdefault(args[0], [0] * 5)
        for bit, slot in ((0x10, 0), (0x1, 1), (0x2, 2), (0x4, 3), (0x8, 4)):
            # MIM_STYLE, MIM_MAXHEIGHT, MIM_BACKGROUND, MIM_HELPID, MIM_MENUDATA
            if mask & bit:
                info[slot] = values[slot]
        return 1

    def GetMenuInfo(self, args):
        if args[0] not in self.menus:
            return 0
        info = self.__dict__.get('_menu_infos', {}).get(args[0], [0] * 5)
        return 1 if self._mem_write(args[1] + 8, struct.pack('<5I', *info)) else 0

    def GetMenuStringA(self, args):
        """GetMenuStringA(menu, item, buffer, size, flags)"""
        hmenu, index = self._menu_item(args[0], args[1], args[4] & self.MF_BYPOSITION)
        if hmenu is None:
            return 0
        text = self.menus[hmenu][index]['text'] or ''
        units = self._text_units(text, False)
        if args[2] and args[3]:
            self._write_units(args[2], units[:args[3] - 1], False)
            return min(len(units), args[3] - 1)
        return len(units)

    def ModifyMenuA(self, args):
        """ModifyMenuA(menu, item, flags, ID, text)"""
        flags = args[2] & ~self.MF_BYPOSITION
        if not flags & (self.MF_SEPARATOR | 0x4 | 0x100) and args[4]:
            text = self._alloc_units(self._text_units(self.read_string(args[4]), True), True)
            try:
                return self.ModifyMenuW(list(args[:4]) + [text])
            finally:
                self.emu.heap_free(text)
        return self.ModifyMenuW(args)

    def LoadMenuIndirectA(self, args):
        """LoadMenuIndirectA/W(MENUTEMPLATE)"""
        data = bytearray()
        position = args[0]
        while len(data) < 0x10000:
            try:
                data += self.emu.uc.mem_read(position, 0x1000 - (position & 0xFFF))
            except UcError:
                break
            position = (position | 0xFFF) + 1
        try:
            return self._parse_menu_template(bytes(data))
        except (struct.error, IndexError):
            self._last_error = 87
            return 0

    LoadMenuIndirectW = LoadMenuIndirectA

    def EnableScrollBar(self, args):
        return 1

    def ShowScrollBar(self, args):
        return 1

    # ---------- Window words ----------

    def GetWindowWord(self, args):
        return self.GetWindowLongA(args) & 0xFFFF

    def SetWindowWord(self, args):
        return self.SetWindowLongA([args[0], args[1], args[2] & 0xFFFF]) & 0xFFFF

    def GetClassWord(self, args):
        return self.GetClassLongA(args) & 0xFFFF

    def SetClassWord(self, args):
        return self.SetClassLongA([args[0], args[1], args[2] & 0xFFFF]) & 0xFFFF

    # ---------- Icons ----------

    def CopyIcon(self, args):
        """CopyIcon - a new handle with the same image"""
        if not args[0]:
            return 0
        handle = self.get_next_handle()
        if args[0] in self.icons:
            self.icons[handle] = self.icons[args[0]]
        return handle

    def GetIconInfo(self, args):
        """GetIconInfo(icon, ICONINFO) - an icon with its hot spot in the middle"""
        if not args[0]:
            self._last_error = 1402  # ERROR_INVALID_CURSOR_HANDLE
            return 0
        cursor = self.cursors.get(args[0])
        if cursor is not None and 'hotspot' in cursor:
            data = struct.pack('<5I', 0, *cursor['hotspot'], 0, 0)
        else:
            data = struct.pack('<5I', 1, 16, 16, 0, 0)
        return 1 if self._mem_write(args[1], data) else 0

    def DrawIcon(self, args):
        return 1

    def DrawIconEx(self, args):
        return 1

    # ---------- comctl32 window subclassing ----------

    def _subclass_stub(self):
        stub = self.__dict__.get('_subclass_stub_addr')
        if not stub:
            stub = self.emu.get_api_stub('comctl32.dll', 'SubclassWndProc')
            self.__dict__['_subclass_stub_addr'] = stub
        return stub

    def _subclasses(self):
        return self.__dict__.setdefault('_window_subclasses', {})

    def SetWindowSubclass(self, args):
        """SetWindowSubclass(hwnd, proc, ID, reference data)"""
        hwnd, proc, uid, data = args[:4]
        if not proc or not self.IsWindow([hwnd]):
            return 0
        state = self._subclasses().get(hwnd)
        if state is None:
            original = self._window_long(hwnd, -4, self._subclass_stub(), set_value=True)
            state = self._subclasses()[hwnd] = {'original': original, 'chain': []}
        for entry in state['chain']:
            if entry[0] == proc and entry[1] == uid:
                entry[2] = data
                return 1
        state['chain'].append([proc, uid, data])
        return 1

    def GetWindowSubclass(self, args):
        """GetWindowSubclass(hwnd, proc, ID, &reference data)"""
        state = self._subclasses().get(args[0])
        for entry in state['chain'] if state else []:
            if entry[0] == args[1] and entry[1] == args[2]:
                if args[3]:
                    self._mem_write(args[3], struct.pack('<I', entry[2]))
                return 1
        return 0

    def RemoveWindowSubclass(self, args):
        """RemoveWindowSubclass(hwnd, proc, ID) - the last one restores the
        window procedure"""
        state = self._subclasses().get(args[0])
        if state is None:
            return 0
        for entry in state['chain']:
            if entry[0] == args[1] and entry[1] == args[2]:
                state['chain'].remove(entry)
                break
        else:
            return 0
        if not state['chain']:
            if self._window_long(args[0], -4) == self._subclass_stub():
                self._window_long(args[0], -4, state['original'], set_value=True)
            del self._subclasses()[args[0]]
        return 1

    def _call_subclass(self, hwnd, chain, index, msg, wparam, lparam):
        """Call subclass procedure chain[index] (below 0: the original procedure)"""
        state = self._subclasses().get(hwnd)
        if index < 0:
            original = state['original'] if state else 0
            return self._call_proc(original, hwnd, msg, wparam, lparam) if original else \
                self.DefWindowProcW([hwnd, msg, wparam, lparam])
        proc, uid, data = chain[index]
        stack = self.__dict__.setdefault('_subclass_calls', [])
        stack.append((hwnd, chain, index))
        try:
            return self.emu.call_callback(proc, [hwnd, msg, wparam, lparam, uid, data])
        finally:
            stack.pop()

    def SubclassWndProc(self, args):
        """Window procedure of subclassed windows: the newest subclass first"""
        hwnd = args[0]
        state = self._subclasses().get(hwnd)
        chain = [list(entry) for entry in state['chain']] if state else []
        return self._call_subclass(hwnd, chain, len(chain) - 1, args[1], args[2], args[3])

    def DefSubclassProc(self, args):
        """DefSubclassProc(hwnd, msg, wParam, lParam) - the next older subclass"""
        hwnd = args[0]
        for caller_hwnd, chain, index in reversed(self.__dict__.get('_subclass_calls', [])):
            if caller_hwnd == hwnd:
                return self._call_subclass(hwnd, chain, index - 1, args[1], args[2], args[3])
        return self._call_subclass(hwnd, [], -1, args[1], args[2], args[3])

    # ---------- Activation, carets, update regions, DefDlgProc ----------

    def SetActiveWindow(self, args):
        """SetActiveWindow(hWnd) - activates (brings to the top) a top-level
        window; the previously active window"""
        previous = self.GetForegroundWindow([])
        if self.gui and args[0] in self.gui.windows:
            self.BringWindowToTop(args)
        return previous

    def HideCaret(self, args):
        """HideCaret/ShowCaret(hWnd) - the caret of edit controls is drawn by
        the fake desktop; programs' own carets are not drawn"""
        return 1

    def ShowCaret(self, args):
        return 1

    def ExcludeUpdateRgn(self, args):
        """ExcludeUpdateRgn(hdc, hWnd) - windows are redrawn whole: there is
        no update region to exclude (SIMPLEREGION)"""
        return 2 if args[0] in self.dc_state else 0

    def DefDlgProcA(self, args):
        """DefDlgProcA/W(hDlg, msg, wParam, lParam) - for the window procedure
        of a private dialog class; the emulated dialogs run their own DefDlgProc
        defaults, the rest is DefWindowProc"""
        return self.DefWindowProcA(args)

    def DefDlgProcW(self, args):
        return self.DefWindowProcW(args)
