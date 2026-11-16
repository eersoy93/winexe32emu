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

"""WinAPIHandler mixin: Sandboxed file system, modules (GetModuleHandle, GetProcAddress), command line"""

import os
import struct

from unicorn import *

from .. import resources
from ..config import C_DRIVE_PATH
from ..logger import log
from ..paths import resolve_c_drive_path, strip_win32_path_prefix
from ..pe_loader import PELoader


class FilesMixin:
    """Sandboxed file system, modules (GetModuleHandle, GetProcAddress), command line"""

    # ==================== SANDBOXED FILE SYSTEM ====================

    def resolve_c_drive_path(self, filename):
        """Map a Windows-style filename into the c_drive/ sandbox (see the
        module-level resolve_c_drive_path); relative names are taken
        relative to the current directory."""
        full = self.full_windows_path(filename)
        if full is None:
            if filename:
                log.warning(f"Blocked sandbox escape attempt: \"{filename}\"")
            return None
        if full == "C:\\":
            os.makedirs(C_DRIVE_PATH, exist_ok=True)
            return os.path.realpath(C_DRIVE_PATH)
        return resolve_c_drive_path(full)

    def full_windows_path(self, filename, clamp=False):
        """Absolute, normalized "C:\\..." form of filename.

        A ".." above the root returns None, or stays at the root with clamp
        (like GetFullPathName). Every drive letter is the emulated C: drive.
        """
        if not filename:
            return None
        name = strip_win32_path_prefix(filename)
        if name is None:
            return None
        name = name.replace('/', '\\')
        if len(name) >= 2 and name[1] == ':':
            name = name[2:]
        if not name.startswith('\\'):
            # "name" and "C:name" are relative to the current directory
            name = self.current_directory[2:] + '\\' + name
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
        result = "C:\\" + '\\'.join(parts)
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

    def post_window_message(self, hwnd, message, wParam, lParam):
        """Thread-safe: enqueue a window message (called from the GUI thread).

        The emulation thread consumes these in GetMessageA. Only plain Python
        data is touched here; Unicorn memory is written later on the emu thread.
        """
        msg = {
            'hwnd': hwnd & 0xFFFFFFFF,
            'message': message & 0xFFFFFFFF,
            'wParam': wParam & 0xFFFFFFFF,
            'lParam': lParam & 0xFFFFFFFF,
        }
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
            path = self.resolve_c_drive_path(candidate) if candidate else None
            if path and os.path.isfile(path):
                return candidate, path
        return None

    def load_real_dll(self, name):
        """Module info of a real (non-emulated) DLL, loading it if needed;
        None for the emulated system DLLs and missing files"""
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
        base = self.emu.load_dll(found[1], found[0])
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
            return module['base']
        if load and not self._is_system_dll(key):
            module = self.load_real_dll(name)
            if module is not None:
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
            handle = self.get_next_handle()
            self.handles[handle] = {'type': 'module', 'name': key}
            self.module_handles[key] = handle
        return handle

    def is_emulated(self, dll_name, func_name):
        """True if calls to dll_name!func_name can be emulated safely"""
        return (self.get_api_handler(func_name, dll_name) is not None and
                self.stack_cleanup_bytes(dll_name, func_name) is not None)
    
    def GetProcAddress(self, args):
        """GetProcAddress emulation - returns a hook stub for emulated APIs"""
        hModule = args[0]
        lpProcName = args[1]
        
        info = self.handles.get(hModule)
        module = self.emu.find_dll(hModule)
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
        return addr
    
    def ExitProcess(self, args):
        """ExitProcess emulation"""
        exit_code = args[0]
        log.success(f"ExitProcess({exit_code}) called - Terminating program...")
        self._set_exit_code(exit_code)
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
            cursor = self._load_resource_cursor(key) if self._is_own_module(hInstance) else 0
        log.debug(f"LoadCursor(0x{hInstance:x}, 0x{lpCursorName:x}) -> 0x{cursor:x}")
        if not cursor:
            self._last_error = 1814  # ERROR_RESOURCE_NAME_NOT_FOUND
        return cursor

    def LoadCursorW(self, args):
        """LoadCursorW emulation"""
        return self.LoadCursorA(args, wide=True)

    def _load_icon_image(self, key, size=32):
        """(width, height, RGBA) of the EXE's RT_GROUP_ICON key: its image
        closest to size x size with the most colors; None if there is none"""
        group = self._find_resource(14, key)
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
                icon = self._find_resource(3, icon_id)
                decoded = resources._icon_image_rgba(bytes(self.emu.uc.mem_read(*icon))) if icon else None
                if decoded:
                    return decoded
        except (struct.error, UcError):
            pass
        return None

    def LoadIconA(self, args, wide=False):
        """LoadIconA/W emulation - an icon of the EXE's resources (its image is
        kept for SS_ICON statics and image lists); system icons are opaque"""
        log.debug(f"LoadIcon(0x{args[0]:x}, 0x{args[1]:x})")
        handle = self.get_next_handle()
        if args[0] and self._is_own_module(args[0]):
            image = self._load_icon_image(self._resource_name_key(args[1], wide))
            if image is None:
                self._last_error = 1813  # ERROR_RESOURCE_TYPE_NOT_FOUND
                return 0
            self.icons[handle] = image
        return handle

    def LoadIconW(self, args):
        """LoadIconW emulation"""
        return self.LoadIconA(args, wide=True)
