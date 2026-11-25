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

"""WinAPIHandler mixin: Sandboxed file system, modules (GetModuleHandle,
GetProcAddress), command line"""

import io
import os
import struct

from unicorn import UcError

from .. import config, resources
from ..logger import log
from ..config import READ_ONLY_DRIVES
from ..paths import (device_name, drive_letter_of_host, resolve_drive_path,
                     strip_win32_path_prefix, is_unc_path)
from ..pe_loader import PELoader


class NullDevice(io.RawIOBase):
    """The NUL device: reads find the end of the file, writes are discarded"""

    def readable(self):
        return True

    def writable(self):
        return True

    def seekable(self):
        return True

    def readinto(self, buffer):
        return 0

    def write(self, data):
        return len(data)

    def seek(self, offset, whence=os.SEEK_SET):
        return 0

    def tell(self):
        return 0

    def truncate(self, size=None):
        return 0


class ConsoleDevice(io.RawIOBase):
    """CON / CONOUT$ opened as a file (fopen("CON", "w")): writes go to the
    program's console like its standard output"""

    def __init__(self, handler):
        super().__init__()
        self.handler = handler

    def writable(self):
        return True

    def readable(self):
        return True

    def readinto(self, buffer):
        return 0

    def write(self, data):
        text = bytes(data).decode(config.ANSI_CODEPAGE, errors='replace')
        log.program_output("STDOUT", text)
        self.handler.console_output.append(text)
        self.handler.console_write(text)
        return len(data)


class FilesMixin:
    """Sandboxed file system, modules (GetModuleHandle, GetProcAddress), command line"""

    # ==================== SANDBOXED FILE SYSTEM ====================

    def resolve_drive_path(self, filename):
        """Map a Windows-style filename into the drives/ sandbox (see the
        module-level resolve_drive_path); relative names are taken
        relative to the current directory."""
        full = self.full_windows_path(filename)
        if full is None:
            if filename and is_unc_path(filename):
                log.debug(f"No network for the UNC path \"{filename}\"")
            elif filename:
                log.warning(f"Blocked sandbox escape attempt: \"{filename}\"")
            return None
        return resolve_drive_path(full)

    # Standard handles of the console (GetStdHandle)
    CONSOLE_INPUT_HANDLE, CONSOLE_OUTPUT_HANDLE = 0x10, 0x11

    def open_device(self, filename, want_write):
        """Handle for a DOS device name (NUL, CON, CONIN$, CONOUT$...), None
        for an ordinary file name, or INVALID_HANDLE_VALUE (with the last
        error) for a device the emulated PC does not have (COM1, LPT1...)"""
        device = device_name(filename)
        if device is None:
            return None
        if device == 'NUL':
            handle = self.get_next_handle()
            self.handles[handle] = {'type': 'file', 'name': filename, 'fp': NullDevice(),
                                    'path': None, 'device': device}
        elif device in ('CONIN$', 'CONOUT$', 'CON'):
            # CON is the input or the output by the access asked for
            output = device == 'CONOUT$' or (device == 'CON' and want_write)
            handle = self.CONSOLE_OUTPUT_HANDLE if output else self.CONSOLE_INPUT_HANDLE
        else:
            self._last_error = 2  # ERROR_FILE_NOT_FOUND: no serial or printer ports
            return 0xFFFFFFFF
        self._last_error = 0
        log.debug(f"Device \"{filename}\" -> {device} (0x{handle:x})")
        return handle

    def open_device_stream(self, filename, mode):
        """Python file object of a device for fopen ("NUL", "CON"), None for
        an ordinary file name, or False for a device that cannot be opened"""
        device = device_name(filename)
        if device is None:
            return None
        if device == 'NUL':
            return NullDevice()
        if device in ('CON', 'CONOUT$') and self._crt_mode_writes(mode):
            return ConsoleDevice(self)
        return False

    def _write_protected(self, *host_paths):
        """True, with ERROR_ACCESS_DENIED, if a host path is on a read-only
        drive (the CD-ROM D:): programs cannot change its files"""
        for path in host_paths:
            if path is not None and drive_letter_of_host(path) in READ_ONLY_DRIVES:
                self._last_error = 5  # ERROR_ACCESS_DENIED
                return True
        return False

    @staticmethod
    def _host_read_only(path):
        """FILE_ATTRIBUTE_READONLY of a host path: a read-only host file, or
        any file or folder on a read-only drive (the CD-ROM D:)"""
        return (drive_letter_of_host(path) in READ_ONLY_DRIVES or
                (not os.path.isdir(path) and not os.access(path, os.W_OK)))

    def full_windows_path(self, filename, clamp=False):
        """Absolute, normalized "X:\\..." form of filename (X: its drive).

        A ".." above the root returns None, or stays at the root with clamp
        (like GetFullPathName). A name without a drive letter is on the
        current directory's drive; "name" and the current drive's "X:name"
        are relative to the current directory, another drive's "Y:name" to
        that drive's root.
        """
        if not filename:
            return None
        name = strip_win32_path_prefix(filename)
        if name is None:
            return None
        name = name.replace('/', '\\')
        current = self.current_directory
        drive = current[0].upper()
        if len(name) >= 2 and name[1] == ':':
            drive = name[0].upper()
            name = name[2:]
        if not name.startswith('\\'):
            base = current[2:] if drive == current[0].upper() else ''
            name = base + '\\' + name
        parts = []
        for part in name.split('\\'):
            if part in ('', '.'):
                continue
            if part == '..':
                if not parts and not clamp:
                    return None
                if parts:
                    parts.pop()
            else:
                parts.append(part)
        result = f"{drive}:\\" + '\\'.join(parts)
        if parts and filename.endswith(('\\', '/')) and clamp:
            result += '\\'
        return result

    def _c_mode_to_python(self, mode):
        """Translate a C fopen()/CreateFile mode string to a Python one.

        Always binary so no host newline translation corrupts data; the
        emulated program sees the exact bytes it wrote.
        """
        mode = (mode or "").lower()
        base = 'r'
        if 'a' in mode:
            base = 'a'
        elif 'w' in mode:
            base = 'w'
        elif 'r' in mode:
            base = 'r'
        if '+' in mode:
            base += '+'
        return base + 'b'

    def post_window_message(self, hwnd, message, wParam, lParam, char=None, thread=None):
        """Thread-safe: enqueue a window message (called from the GUI thread).

        The emulation thread consumes these in GetMessageA. Only plain Python
        data is touched here; Unicorn memory is written later on the emu thread.
        char ((WM_CHAR or WM_SYSCHAR, code)) is the character of a WM_KEYDOWN
        or WM_SYSKEYDOWN, posted when the program calls TranslateMessage.
        thread: the guest thread a message without a window is for
        (PostThreadMessage); only its message loop gets it.
        """
        msg = {
            'hwnd': hwnd & 0xFFFFFFFF,
            'message': message & 0xFFFFFFFF,
            'wParam': wParam & 0xFFFFFFFF,
            'lParam': lParam & 0xFFFFFFFF,
        }
        if char is not None:
            msg['char'] = char
        if thread is not None:
            msg['thread'] = thread
        with self.message_lock:
            # Coalesce mouse moves like Windows does: replace a still-pending
            # WM_MOUSEMOVE for the same window instead of flooding the queue
            if (message == self.WM_MOUSEMOVE and self.message_queue and
                    self.message_queue[-1]['message'] == self.WM_MOUSEMOVE and
                    self.message_queue[-1]['hwnd'] == msg['hwnd']):
                self.message_queue[-1] = msg
                return
            if message == self.WM_SETCURSOR:
                # Only the latest one per window matters
                self.message_queue[:] = [m for m in self.message_queue
                                         if m['message'] != self.WM_SETCURSOR
                                         or m['hwnd'] != msg['hwnd']]
            self.message_queue.append(msg)

    # KERNEL32.DLL functions
    def GetModuleHandleA(self, args):
        """GetModuleHandleA emulation"""
        lpModuleName = args[0]
        if lpModuleName == 0:
            log.debug(f"GetModuleHandleA(NULL) -> 0x{self.emu.pe_loader.image_base:08x}")
            return self.emu.pe_loader.image_base

        module_name = self.read_string(lpModuleName)
        log.debug(f"GetModuleHandleA(\"{module_name}\")")
        return self._module_handle(module_name, load=False)

    def GetModuleHandleW(self, args):
        """GetModuleHandleW emulation"""
        lpModuleName = args[0]
        if lpModuleName == 0:
            return self.emu.pe_loader.image_base

        module_name = self.read_wide_string(lpModuleName)
        log.debug(f"GetModuleHandleW(\"{module_name}\")")
        return self._module_handle(module_name, load=False)

    # DLLs whose APIs the emulator implements (always "loaded")
    EMULATED_DLLS = {'kernel32.dll', 'user32.dll', 'gdi32.dll', 'msvcrt.dll',
                     'advapi32.dll', 'ole32.dll', 'ntdll.dll', 'winmm.dll'}
    # Other Windows DLLs: never loaded from a file even if one exists
    SYSTEM_DLLS = {'oleaut32.dll', 'shell32.dll', 'comctl32.dll', 'comdlg32.dll',
                   'shlwapi.dll', 'version.dll', 'msacm32.dll', 'uxtheme.dll',
                   'psapi.dll', 'mpr.dll', 'winspool.drv', 'imm32.dll', 'kernelbase.dll',
                   'ws2_32.dll', 'wsock32.dll', 'rpcrt4.dll', 'secur32.dll', 'crypt32.dll',
                   'dbghelp.dll', 'setupapi.dll', 'userenv.dll', 'dwmapi.dll',
                   # The emulated C runtime (programs often ship copies of these)
                   'vcruntime140.dll', 'ucrtbase.dll'}

    def _is_system_dll(self, key):
        """Is a lower-case DLL file name emulated (never loaded from a file)?"""
        return (key in self.EMULATED_DLLS or key in self.SYSTEM_DLLS or
                key.startswith(('api-ms-win-', 'ext-ms-win-')))

    def _real_dll_path(self, name):
        """(Windows path, host path) of a DLL file to load for a LoadLibrary
        name, or None. Without a folder it is searched like Windows does:
        the EXE's folder, System32, Windows, the current folder."""
        name = name.replace('/', '\\')
        base = name.rsplit('\\', 1)[-1]
        if '.' not in base:
            name += '.dll'
        if '\\' in name or ':' in name:
            candidates = [self.full_windows_path(name)]
        else:
            exe_dir = self.windows_exe_path().rsplit('\\', 1)[0]
            candidates = [self.full_windows_path(folder.rstrip('\\') + '\\' + name)
                          for folder in (exe_dir, "C:\\Windows\\System32", "C:\\Windows",
                                         self.current_directory)]
        for candidate in candidates:
            path = self.resolve_drive_path(candidate) if candidate else None
            if path and os.path.isfile(path):
                return candidate, path
        return None

    def load_real_dll(self, name, call_entry=True):
        """Module info of a real (non-emulated) DLL, loading it if needed (no
        reference is taken: see CPUEmulator.load_dll); None for the
        emulated system DLLs and missing files"""
        key = name.replace('/', '\\').rsplit('\\', 1)[-1].lower()
        if '.' not in key:
            key += '.dll'
        module = self.emu.find_dll(key)
        if module is not None:
            return module
        if self._is_system_dll(key):
            return None
        found = self._real_dll_path(name)
        if found is None:
            return None
        base = self.emu.load_dll(found[1], found[0], call_entry)
        return self.emu.dlls.get(base) if base else None

    def _module_handle(self, name, load):
        """HMODULE for a DLL name; 0 if not loaded and load is False.

        Real DLL files (e.g. a program's own DLLs) are loaded and run; the
        system DLLs get a fake handle and emulated APIs."""
        key = name.replace('/', '\\').rsplit('\\', 1)[-1].lower()
        if '.' not in key:
            key += '.dll'
        if key == os.path.basename(self.emu.pe_loader.filepath).lower():
            return self.emu.pe_loader.image_base
        module = self.emu.find_dll(key)
        if module is not None:
            if load:
                module['refs'] += 1  # LoadLibrary takes a reference (FreeLibrary)
            return module['base']
        if load and not self._is_system_dll(key):
            module = self.load_real_dll(name)
            if module is not None:
                module['refs'] += 1
                return module['base']
            if (self._real_dll_path(name) is not None or '\\' in name or '/' in name or
                    not self.is_system_dll_name(key)):
                # A file that did not load, or a missing non-Windows DLL
                self._last_error = 126  # ERROR_MOD_NOT_FOUND
                return 0
        handle = self.module_handles.get(key)
        if handle is None:
            known = self.EMULATED_DLLS | {d.lower() for d in self.emu.pe_loader.imports}
            if not load and key not in known:
                self._last_error = 126  # ERROR_MOD_NOT_FOUND
                return 0
            # The base of the DLL's in-memory image (MZ/PE headers, exports)
            handle = self.emu.system_module(key) or self.get_next_handle()
            self.handles[handle] = {'type': 'module', 'name': key}
            self.module_handles[key] = handle
        return handle

    def _system_module_name(self, base):
        """Name of the emulated system DLL whose image is at base, or None"""
        module = self.emu.system_module_at(base)
        return module['name'] if module is not None and module['base'] == base else None

    def is_emulated(self, dll_name, func_name):
        """True if calls to dll_name!func_name can be emulated safely"""
        return (self.get_api_handler(func_name, dll_name) is not None and
                self.stack_cleanup_bytes(dll_name, func_name) is not None)

    def GetProcAddress(self, args):
        """GetProcAddress emulation - returns a hook stub for emulated APIs"""
        hModule = args[0]
        lpProcName = args[1]

        info = self.handles.get(hModule)
        system = self.emu.system_modules.get(self._system_module_name(hModule))
        if info is None and system is not None:
            # A system DLL base found without GetModuleHandle (PEB->Ldr)
            info = {'type': 'module', 'name': system['name']}
        module = self.emu.find_dll(hModule)
        loader = self.emu.pe_loader
        if module is None and hModule == loader.image_base:
            # The EXE's own exports (Word 95's WWINTL32.DLL calls back into it)
            if lpProcName < 0x10000:
                proc_name = f"Ordinal_{lpProcName}"
                export = next((e for e in loader.exports if e['ordinal'] == lpProcName), None)
            else:
                proc_name = self.read_string(lpProcName)
                export = next((e for e in loader.exports if e['name'] == proc_name), None)
            addr = loader.image_base + export['address'] if export else 0
            log.debug(f"GetProcAddress(EXE, \"{proc_name}\") -> 0x{addr:08x}")
            if not addr:
                self._last_error = 127  # ERROR_PROC_NOT_FOUND
            return addr
        if module is not None:
            if lpProcName < 0x10000:
                addr = module['ordinals'].get(lpProcName, 0)
                proc_name = f"Ordinal_{lpProcName}"
            else:
                proc_name = self.read_string(lpProcName)
                addr = module['exports'].get(proc_name, 0)
            log.debug(f"GetProcAddress(\"{module['name']}\", \"{proc_name}\") -> 0x{addr:08x}")
        elif not info or info.get('type') != 'module':
            log.debug(f"GetProcAddress(0x{hModule:08x}) -> unknown module")
            addr = 0
        else:
            if lpProcName < 0x10000:
                # By ordinal: the emulated APIs are known by name
                proc_name = PELoader.ordinal_name(info['name'], lpProcName)
            else:
                proc_name = self.read_string(lpProcName)
            addr = self.emu.get_api_stub(info['name'], proc_name)
            log.debug(f"GetProcAddress(\"{info['name']}\", \"{proc_name}\") -> 0x{addr:08x}")
        if not addr:
            self._last_error = 127  # ERROR_PROC_NOT_FOUND
            if (module is None and info and info.get('type') == 'module' and
                    (info['name'].lower(), proc_name.upper()) not in self.NOT_WINDOWS_APIS):
                self.emu.note_missing_api(info['name'], proc_name,
                                          'GetProcAddress returned NULL')
        return addr

    # Functions no Windows exports, which programs look up to detect another
    # environment: NULL is the right answer, not a missing API. ISTNT is in
    # the KERNEL32 of the Phar Lap TNT DOS extender (Microsoft Setup checks it).
    NOT_WINDOWS_APIS = {('kernel32.dll', 'ISTNT')}

    def ExitProcess(self, args):
        """ExitProcess emulation"""
        exit_code = args[0]
        log.success(f"ExitProcess({exit_code}) called - Terminating program...")
        self._set_exit_code(exit_code)
        # The DLLs' DllMain(DLL_PROCESS_DETACH) and the TLS callbacks
        self.emu.detach_process()
        self.process_exited = True
        self.emu.stop_emulation = True
        return 0

    def ExitWindowsEx(self, args):
        """ExitWindowsEx emulation - an emulated restart: the pending
        MOVEFILE_DELAY_UNTIL_REBOOT operations are done and the calling
        program ends (the emulator itself keeps running)"""
        uFlags = args[0]
        kind = {0: 'log off', 1: 'shut down', 2: 'restart', 8: 'power off'}.get(
            uFlags & 0xB, 'shut down')
        log.success(f"ExitWindowsEx(0x{uFlags:x}): emulated {kind}, ending the program")
        self._run_pending_file_operations()
        self._set_exit_code(0)
        self.process_exited = True
        self.emu.stop_emulation = True
        return 1

    def GetCommandLineA(self, args):
        """GetCommandLineA emulation"""
        log.debug("GetCommandLineA()")
        # Return memory address allocated for command line
        return self.emu.cmdline_addr

    def GetCommandLineW(self, args):
        """GetCommandLineW emulation"""
        log.debug("GetCommandLineW()")
        return self.emu.cmdline_wide_addr

    def SetUnhandledExceptionFilter(self, args):
        """SetUnhandledExceptionFilter emulation - the filter of unhandled
        exceptions; returns the previous one"""
        log.debug(f"SetUnhandledExceptionFilter(0x{args[0]:08x})")
        previous = self.unhandled_exception_filter
        self.unhandled_exception_filter = args[0]
        return previous

    def LoadCursorA(self, args, wide=False):
        """LoadCursorA/W emulation - a system cursor (hInstance NULL, IDC_*) or
        an RT_GROUP_CURSOR resource of the EXE"""
        hInstance, lpCursorName = args[0], args[1]
        if hInstance == 0:
            cursor = self._system_cursor(lpCursorName) if lpCursorName < 0x10000 else 0
        else:
            if lpCursorName < 0x10000:
                key = lpCursorName
            else:
                name = self._read_text(lpCursorName, wide)
                key = (int(name[1:]) if name.startswith('#') and name[1:].isdigit()
                       else name.upper())
            cursor = (self._load_resource_cursor(key, hInstance)
                      if self._is_own_module(hInstance) else 0)
        log.debug(f"LoadCursor(0x{hInstance:x}, 0x{lpCursorName:x}) -> 0x{cursor:x}")
        if not cursor:
            self._last_error = 1814  # ERROR_RESOURCE_NAME_NOT_FOUND
        return cursor

    def LoadCursorW(self, args):
        """LoadCursorW emulation"""
        return self.LoadCursorA(args, wide=True)

    def _load_icon_image(self, key, size=32, hModule=0):
        """(width, height, RGBA) of the EXE's RT_GROUP_ICON key: its image
        closest to size x size with the most colors; None if there is none"""
        group = self._find_resource(14, key, hModule)
        if group is None:
            return None
        try:
            data = bytes(self.emu.uc.mem_read(*group))
            count = struct.unpack_from('<H', data, 4)[0]
            images = []
            for i in range(count):
                w, _, _, _, _, bits, _, icon_id = struct.unpack_from('<BBBBHHIH', data,
                                                                     6 + 14 * i)
                images.append((abs((w or 256) - size), -bits, icon_id))
            for _, _, icon_id in sorted(images):
                icon = self._find_resource(3, icon_id, hModule)
                decoded = (resources._icon_image_rgba(bytes(self.emu.uc.mem_read(*icon)))
                           if icon else None)
                if decoded:
                    return decoded
        except (struct.error, UcError):
            pass
        return None

    def LoadIconA(self, args, wide=False):
        """LoadIconA/W emulation - an icon of the EXE's resources (its image is
        kept for SS_ICON statics and image lists); system icons are opaque"""
        log.debug(f"LoadIcon(0x{args[0]:x}, 0x{args[1]:x})")
        if not args[0] and args[1] in self.SYSTEM_ICONS:
            # A shared system icon: the same handle each time; DrawIcon draws
            # the message box icons (IDI_HAND, IDI_QUESTION, ...)
            handles = self.__dict__.setdefault('_system_icon_handles', {})
            if args[1] not in handles:
                handles[args[1]] = self.get_next_handle()
                self.system_icons[handles[args[1]]] = self.SYSTEM_ICONS[args[1]]
            return handles[args[1]]
        handle = self.get_next_handle()
        if args[0] and self._is_own_module(args[0]):
            image = self._load_icon_image(self._resource_name_key(args[1], wide), hModule=args[0])
            if image is None:
                self._last_error = 1813  # ERROR_RESOURCE_TYPE_NOT_FOUND
                return 0
            self.icons[handle] = image
        return handle

    # IDI_* -> the message box icon drawn for it (0: the application icon)
    SYSTEM_ICONS = {32512: 0, 32513: 1, 32514: 2, 32515: 3, 32516: 4, 32517: 0, 32518: 3}

    def LoadIconW(self, args):
        """LoadIconW emulation"""
        return self.LoadIconA(args, wide=True)
