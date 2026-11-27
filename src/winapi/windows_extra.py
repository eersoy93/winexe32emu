# Copyright 2026 Erdem Ersoy (eersoy93)
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

"""WinAPIHandler mixin: kernel32 and user32 APIs of Win16-era programs
(Word 95): thread termination, DOS device names, deferred window
positioning, scrolling, old menu and clipboard functions"""

import struct

from unicorn import UcError

from .. import config, resources
from ..logger import log


class WindowsExtraMixin:
    """TerminateThread, QueryDosDevice, DeferWindowPos, ScrollWindow(Ex),
    ScrollDC, ChangeMenu, clipboard owner and format names"""

    # ---------- kernel32 ----------

    def TerminateThread(self, args):
        """TerminateThread(hThread, dwExitCode) - the thread stops at once,
        without DLL_THREAD_DETACH notifications"""
        handle, code = args[:2]
        info = self.handles.get(handle)
        thread = self.emu.current_thread if handle == 0xFFFFFFFE else \
            (info or {}).get('thread')
        if thread is None:
            self._last_error = 6  # ERROR_INVALID_HANDLE
            return 0
        if thread.exited:
            return 1
        if thread is self.emu.main_thread:
            self._set_exit_code(code)
            self.process_exited = True
            self.emu.stop_emulation = True
            return 1
        thread.exit_code = code
        thread.exited = True
        thread.stop = True
        if thread.uc is not None:
            thread.uc.emu_stop()
        self.emu.wake_threads()
        return 1

    def DebugBreak(self, args):
        """DebugBreak - a breakpoint exception (int 3) for the program's handlers"""
        return self.raise_guest_exception(0x80000003, 0, [], 0)  # EXCEPTION_BREAKPOINT

    # Device of each drive in the NT object namespace
    DOS_DEVICES = {'A': '\\Device\\Floppy0', 'C': '\\Device\\HarddiskVolume1',
                   'D': '\\Device\\CdRom0'}
    OTHER_DOS_DEVICES = {'NUL': '\\Device\\Null', 'CON': '\\Device\\ConDrv',
                         'PRN': '\\DosDevices\\LPT1', 'AUX': '\\DosDevices\\COM1'}

    def QueryDosDeviceA(self, args, wide=False):
        """QueryDosDeviceA/W(lpDeviceName, lpTargetPath, ucchMax): the target of
        a DOS device name, or with NULL every DOS device name (a list ending
        with an empty string)"""
        name_ptr, buffer, size = args[:3]
        if name_ptr:
            name = self._read_text(name_ptr, wide).rstrip('\\').upper()
            target = self.DOS_DEVICES.get(name[:1]) if len(name) == 2 and name[1] == ':' \
                else self.OTHER_DOS_DEVICES.get(name)
            if target is None:
                self._last_error = 2  # ERROR_FILE_NOT_FOUND
                return 0
            strings = [target]
        else:
            strings = [f'{letter}:' for letter in sorted(self.DOS_DEVICES)] + \
                sorted(self.OTHER_DOS_DEVICES)
        if wide:
            data = b''.join(s.encode('utf-16-le') + b'\x00\x00' for s in strings) + b'\x00\x00'
            units = len(data) // 2
        else:
            data = b''.join(s.encode(config.ANSI_CODEPAGE, errors='replace') + b'\x00'
                            for s in strings) + b'\x00'
            units = len(data)
        if not buffer or size < units:
            self._last_error = 122  # ERROR_INSUFFICIENT_BUFFER
            return 0
        return units if self._mem_write(buffer, data) else 0

    def QueryDosDeviceW(self, args):
        return self.QueryDosDeviceA(args, wide=True)

    # ---------- user32: deferred window positioning ----------

    def BeginDeferWindowPos(self, args):
        """BeginDeferWindowPos(nNumWindows) - a list of window positions"""
        handle = self.get_next_handle()
        self.handles[handle] = {'type': 'defer_window_pos', 'moves': []}
        return handle

    def DeferWindowPos(self, args):
        """DeferWindowPos(hWinPosInfo, hWnd, hWndInsertAfter, x, y, cx, cy,
        uFlags) - remember one SetWindowPos for EndDeferWindowPos"""
        info = self.handles.get(args[0])
        if not info or info.get('type') != 'defer_window_pos':
            self._last_error = 6  # ERROR_INVALID_HANDLE
            return 0
        if not self.IsWindow([args[1]]):
            self._last_error = 1400  # ERROR_INVALID_WINDOW_HANDLE
            self.handles.pop(args[0], None)  # Windows frees the structure
            return 0
        info['moves'].append(list(args[1:8]))
        return args[0]

    def EndDeferWindowPos(self, args):
        """EndDeferWindowPos(hWinPosInfo) - move the windows"""
        info = self.handles.pop(args[0], None)
        if not info or info.get('type') != 'defer_window_pos':
            self._last_error = 6  # ERROR_INVALID_HANDLE
            return 0
        for move in info['moves']:
            self.SetWindowPos(move)
        return 1

    def ArrangeIconicWindows(self, args):
        """ArrangeIconicWindows(hWnd) - the height of a row of icons; the fake
        desktop shows no minimized child windows to arrange"""
        return 0

    # ---------- user32: scrolling ----------


    def _scroll_update(self, hwnd, rect_ptr):
        """Scrolling repaints: the display list draws every shape again at its
        place, so the window's whole client area is invalidated (the
        program draws the scrolled contents at their new positions)"""
        self.InvalidateRect([hwnd, 0, 1])
        if rect_ptr:
            self.GetClientRect([hwnd, rect_ptr])

    def ScrollWindow(self, args):
        """ScrollWindow(hWnd, XAmount, YAmount, lpRect, lpClipRect)"""
        if not self.IsWindow([args[0]]):
            return 0
        self._scroll_update(args[0], 0)
        return 1

    def ScrollWindowEx(self, args):
        """ScrollWindowEx(hWnd, dx, dy, prcScroll, prcClip, hrgnUpdate,
        prcUpdate, flags) - the kind of the update region"""
        hwnd, region, update_rect = args[0], args[5], args[6]
        if not self.IsWindow([hwnd]):
            return 0  # ERROR
        self._scroll_update(hwnd, update_rect)
        region = self.gdi_objects.get(region)
        if region is not None and region['type'] == 'region' and self.gui and \
                hwnd in self.gui.windows:
            width, height = self.gui.client_size(self.gui.windows[hwnd])
            region['rects'] = [(0, 0, width, height)]
        return self.SIMPLEREGION

    def ScrollDC(self, args):
        """ScrollDC(hDC, dx, dy, lprcScroll, lprcClip, hrgnUpdate, lprcUpdate):
        the DC's window is drawn again"""
        hdc, scroll_rect, update_rect = args[0], args[3], args[6]
        if hdc not in self.dc_state:
            return 0
        hwnd = self._dc_hwnd(hdc)
        if hwnd:
            self.InvalidateRect([hwnd, 0, 1])
        if update_rect:
            rect = self._read_rect(scroll_rect) if scroll_rect else None
            if rect is None and hwnd:
                self.GetClientRect([hwnd, update_rect])
            elif rect is not None:
                self._write_rect(update_rect, *rect)
        return 1

    # ---------- user32: menus, hooks, caret and clipboard ----------

    MF_CHANGE, MF_APPEND, MF_DELETE, MF_REMOVE = 0x80, 0x100, 0x200, 0x1000

    def ChangeMenuA(self, args, wide=False):
        """ChangeMenuA/W(hMenu, cmd, lpszNewItem, cmdInsert, flags) - the Win16
        function behind InsertMenu, AppendMenu, ModifyMenu, DeleteMenu and
        RemoveMenu; the flag of the operation picks one"""
        menu, cmd, text, insert, flags = args[:5]
        if flags & self.MF_APPEND:
            append = self.AppendMenuW if wide else self.AppendMenuA
            return append([menu, flags & ~self.MF_APPEND, insert, text])
        if flags & self.MF_DELETE:
            return self.DeleteMenu([menu, cmd, flags & ~self.MF_DELETE])
        if flags & self.MF_CHANGE:
            modify = self.ModifyMenuW if wide else self.ModifyMenuA
            return modify([menu, cmd, flags & ~self.MF_CHANGE, insert, text])
        if flags & self.MF_REMOVE:
            return self.RemoveMenu([menu, cmd, flags & ~self.MF_REMOVE])
        return self.InsertMenuA([menu, cmd, flags, insert, text], wide=wide)

    def ChangeMenuW(self, args):
        return self.ChangeMenuA(args, wide=True)

    def CreateAcceleratorTableA(self, args):
        """CreateAcceleratorTableA(lpaccl, cAccel) - ACCEL entries like the W
        function's (the character keys are below 0x80 in practice)"""
        return self.CreateAcceleratorTableW(args)

    def CallMsgFilterA(self, args):
        """CallMsgFilterA/W(lpMsg, nCode) - no WH_MSGFILTER hook handled the
        message"""
        return 0

    CallMsgFilterW = CallMsgFilterA

    def GetCaretBlinkTime(self, args):
        """GetCaretBlinkTime - Windows' default 530 ms"""
        return 530

    def GetClipboardOwner(self, args):
        """GetClipboardOwner - the window that last emptied the clipboard
        (OpenClipboard's window when EmptyClipboard was called)"""
        owner = type(self).clipboard_owner
        return owner if owner and self.IsWindow([owner]) else 0

    def GetClipboardFormatNameA(self, args, wide=False):
        """GetClipboardFormatNameA/W(format, lpszFormatName, cchMaxCount) -
        the name of a registered clipboard format (0 for a predefined one)"""
        fmt, buffer, size = args[:3]
        name = type(self).clipboard_format_names.get(fmt)
        if name is None or not buffer or size <= 0:
            self._last_error = 87 if name is not None else 0  # ERROR_INVALID_PARAMETER
            return 0
        name = name[:size - 1]
        self._write_text(buffer, name, wide)
        log.debug(f"GetClipboardFormatName(0x{fmt:x}) -> {name!r}")
        return len(name)

    def GetClipboardFormatNameW(self, args):
        return self.GetClipboardFormatNameA(args, wide=True)

    # The first window of the clipboard viewer chain (shared by the processes)
    clipboard_viewer = 0
    WM_DRAWCLIPBOARD, WM_CHANGECBCHAIN = 0x0308, 0x030D

    def _send_to_window(self, hwnd, msg, wParam, lParam):
        """Send a message to a window of this process; post it to another's"""
        win = self.gui.windows.get(hwnd) if self.gui else None
        if win is None:
            return 0
        if win.owner is self:
            return self._send(hwnd, msg, wParam, lParam)
        if win.owner is not None:
            win.owner.post_window_message(hwnd, msg, wParam, lParam)
        return 0

    def SetClipboardViewer(self, args):
        """SetClipboardViewer(hwnd) - hwnd heads the clipboard viewer chain and
        gets WM_DRAWCLIPBOARD; the next window of the chain (0 if none)"""
        hwnd = args[0]
        previous = type(self).clipboard_viewer
        if previous and not self.IsWindow([previous]):
            previous = 0
        type(self).clipboard_viewer = hwnd
        self._send_to_window(hwnd, self.WM_DRAWCLIPBOARD, 0, 0)
        return previous

    def GetClipboardViewer(self, args):
        viewer = type(self).clipboard_viewer
        return viewer if viewer and self.IsWindow([viewer]) else 0

    def ChangeClipboardChain(self, args):
        """ChangeClipboardChain(hwndRemove, hwndNext) - take a window out of the
        viewer chain: the head is replaced, else the chain is told with
        WM_CHANGECBCHAIN"""
        remove, following = args[0], args[1]
        viewer = type(self).clipboard_viewer
        if viewer == remove:
            type(self).clipboard_viewer = following
        elif viewer and self.IsWindow([viewer]):
            self._send_to_window(viewer, self.WM_CHANGECBCHAIN, remove, following)
        return 1

    # ---------- winspool: the computer has no printer ----------

    ERROR_INVALID_PRINTER_NAME = 1801

    def OpenPrinterA(self, args):
        """OpenPrinterA/W(pPrinterName, phPrinter, pDefault) - no such printer"""
        if args[1]:
            self._mem_write(args[1], b'\x00\x00\x00\x00')
        self._last_error = self.ERROR_INVALID_PRINTER_NAME
        return 0

    OpenPrinterW = OpenPrinterA

    def ClosePrinter(self, args):
        self._last_error = 6  # ERROR_INVALID_HANDLE: OpenPrinter opens none
        return 0

    def GetPrinterA(self, args):
        """GetPrinterA/W(hPrinter, Level, pPrinter, cbBuf, pcbNeeded)"""
        if args[4]:
            self._mem_write(args[4], b'\x00\x00\x00\x00')
        self._last_error = 6  # ERROR_INVALID_HANDLE
        return 0

    GetPrinterW = GetPrinterA

    def GetPrinterDriverA(self, args):
        """GetPrinterDriverA/W(hPrinter, pEnvironment, Level, pDriverInfo,
        cbBuf, pcbNeeded)"""
        if args[5]:
            self._mem_write(args[5], b'\x00\x00\x00\x00')
        self._last_error = 6  # ERROR_INVALID_HANDLE
        return 0

    GetPrinterDriverW = GetPrinterDriverA

    def EnumPrintersA(self, args):
        """EnumPrintersA/W(Flags, Name, Level, pPrinterEnum, cbBuf, pcbNeeded,
        pcReturned) - succeeds with no printers"""
        for pointer in (args[5], args[6]):
            if pointer:
                self._mem_write(pointer, b'\x00\x00\x00\x00')
        return 1

    EnumPrintersW = EnumPrintersA

    def DocumentPropertiesA(self, args):
        """DocumentPropertiesA/W(hWnd, hPrinter, pDeviceName, pDevModeOutput,
        pDevModeInput, fMode) - a negative value: no such printer"""
        self._last_error = self.ERROR_INVALID_PRINTER_NAME
        return 0xFFFFFFFF

    DocumentPropertiesW = DocumentPropertiesA

    def DeviceCapabilitiesA(self, args):
        """DeviceCapabilitiesA/W(pDevice, pPort, fwCapability, pOutput, pDevMode)
        - -1: no such printer"""
        self._last_error = self.ERROR_INVALID_PRINTER_NAME
        return 0xFFFFFFFF

    DeviceCapabilitiesW = DeviceCapabilitiesA

    # ---------- kernel32: executable types ----------

    SCS_32BIT_BINARY, SCS_DOS_BINARY, SCS_WOW_BINARY, SCS_PIF_BINARY = 0, 1, 2, 5

    def GetBinaryTypeA(self, args, wide=False):
        """GetBinaryTypeA/W(lpApplicationName, lpBinaryType): a PE (32-bit), NE
        (16-bit Windows), MZ or .COM (MS-DOS) or .PIF program"""
        name = self._read_text(args[0], wide) if args[0] else ''
        host = self.resolve_drive_path(name) if name else None
        try:
            with open(host, 'rb') as f:
                header = f.read(0x40)
                offset = struct.unpack_from('<I', header, 0x3C)[0] if len(header) >= 0x40 else 0
                f.seek(offset)
                signature = f.read(4)
        except (OSError, TypeError, struct.error):
            self._last_error = 2  # ERROR_FILE_NOT_FOUND
            return 0
        extension = name.rsplit('.', 1)[-1].lower() if '.' in name else ''
        if header[:2] in (b'MZ', b'ZM'):
            kind = self.SCS_32BIT_BINARY if signature == b'PE\x00\x00' else \
                self.SCS_WOW_BINARY if signature[:2] == b'NE' else self.SCS_DOS_BINARY
        elif extension == 'com':
            kind = self.SCS_DOS_BINARY
        elif extension == 'pif':
            kind = self.SCS_PIF_BINARY
        else:
            self._last_error = 193  # ERROR_BAD_EXE_FORMAT
            return 0
        return 1 if self._mem_write(args[1], struct.pack('<I', kind)) else 0

    def GetBinaryTypeW(self, args):
        return self.GetBinaryTypeA(args, wide=True)

    # ---------- user32: icons from memory, threads, DCs ----------

    def CreateIconFromResourceEx(self, args):
        """CreateIconFromResourceEx(presbits, dwResSize, fIcon, dwVer, cx, cy,
        Flags) - an icon from RT_ICON data (a DIB with its mask, or PNG)"""
        bits, size = args[:2]
        try:
            data = bytes(self.emu.uc.mem_read(bits, size))
        except UcError:
            return 0
        if not args[2]:  # A cursor resource starts with its hot spot
            data = data[4:]
        image = resources._icon_image_rgba(data)
        if image is None:
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0
        handle = self.get_next_handle()
        self.icons[handle] = image
        return handle

    def CreateIconFromResource(self, args):
        """CreateIconFromResource(presbits, dwResSize, fIcon, dwVer)"""
        return self.CreateIconFromResourceEx(list(args[:4]) + [0, 0, 0])

    def CreateIconIndirect(self, args):
        """CreateIconIndirect(piconinfo): ICONINFO's color bitmap with its mask
        (set bits are transparent); without a color bitmap the mask holds the
        AND mask over the XOR picture"""
        try:
            _, _, _, mask, color = struct.unpack('<IIIII', self.emu.uc.mem_read(args[0], 20))
        except UcError:
            return 0
        mask_bmp = self.gdi_objects.get(mask)
        if not mask_bmp or mask_bmp['type'] != 'bitmap':
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0
        width = mask_bmp['width']
        mask_rgb = self._bitmap_rgb(mask)
        if color:
            color_bmp = self.gdi_objects.get(color)
            color_rgb = self._bitmap_rgb(color) if color_bmp else None
            height = color_bmp['height'] if color_bmp else 0
        else:
            height = mask_bmp['height'] // 2
            color_rgb = mask_rgb[width * height * 3:] if mask_rgb else None
        if not width or not height or color_rgb is None:
            self._last_error = 87
            return 0
        rgba = bytearray(width * height * 4)
        for i in range(width * height):
            rgba[4 * i:4 * i + 3] = color_rgb[3 * i:3 * i + 3]
            transparent = mask_rgb is not None and len(mask_rgb) >= 3 * (i + 1) and \
                mask_rgb[3 * i] > 127
            rgba[4 * i + 3] = 0 if transparent else 255
        handle = self.get_next_handle()
        self.icons[handle] = (width, height, bytes(rgba))
        return handle

    def PostThreadMessageA(self, args):
        """PostThreadMessageA/W(idThread, Msg, wParam, lParam) - a message
        without a window for a thread of any program (thread ids are unique
        in the system: the Red Alert 2 launcher posts 0xBEEF to the game's
        main thread)"""
        target = self._thread_process(args[0])
        if target is None:
            self._last_error = 1444  # ERROR_INVALID_THREAD_ID
            return 0
        if target is not self:
            target.post_window_message(0, args[1], args[2], args[3], thread=args[0])
            return 1
        if args[1] == self.WM_QUIT and args[0] == self.emu.current_thread.tid:
            self.quit_code = args[2]
            self.quit_requested = True
        else:
            # Only that thread's message loop gets it (PowerPoint 95's file
            # search thread took the dialog's messages and crashed on them)
            self.post_window_message(0, args[1], args[2], args[3], thread=args[0])
        return 1

    PostThreadMessageW = PostThreadMessageA

    def _thread_process(self, tid):
        """The emulated process that has the thread tid, or None"""
        if tid in self.emu.threads:
            return self
        for process in list(self.gui.processes) if self.gui else ():
            emu = getattr(process, 'emu', None)
            if emu is not None and tid in getattr(emu, 'threads', {}):
                return process
        return None

    def WindowFromDC(self, args):
        """WindowFromDC(hdc) - the window of a window's DC (0 for others)"""
        state = self.dc_state.get(args[0])
        if state is None or state.get('memory'):
            return 0
        return self.dc_map.get(args[0], 0)
