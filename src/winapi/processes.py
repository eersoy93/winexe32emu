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

"""WinAPIHandler mixin: Child processes, threads and synchronization objects"""

import os
import struct

from .. import winapi
from ..logger import log
from ..paths import find_program, windows_path_of_host


class ProcessesMixin:
    """Child processes, threads and synchronization objects"""

    # ---------- Child processes ----------

    # Set by main(): (windows_path, command_line, current_directory) -> CPUEmulator or None
    process_starter = None

    def _process_image_path(self, app, cmdline):
        """Windows path of the EXE CreateProcess should start, or None"""
        return self._requested_image_path(app, cmdline)

    def _quote_program_name(self, cmdline):
        """The command line with its program name quoted if that is an
        unquoted path with spaces. On Windows 95 such a registered path is an
        8.3 one (C:\\PROGRA~1\\...), which the sandbox has none of: Office
        Setup registered MSINFO32 under its long path, and the C runtime of
        the child took "Files\\Common" for its first argument."""
        stripped = cmdline.lstrip()
        if stripped.startswith('"') or ' ' not in stripped:
            return cmdline
        words = stripped.split(' ')
        for count in range(1, len(words) + 1):
            name = ' '.join(words[:count])
            if count > 1 and not any(sep in name for sep in '\\/:'):
                break
            if self._image_path_of(name) is not None:
                if count == 1:
                    return cmdline
                rest = ' '.join(words[count:])
                return f'"{name}"' + (' ' + rest if rest else '')
        return cmdline

    def _requested_image_path(self, app, cmdline):
        """Windows path of the EXE app or the command line names, or None. Like
        Windows, an unquoted command line with spaces tries the longer names
        up to each space in turn ("C:\\Program Files\\...\\msinfo32.exe" of Word)"""
        if app:
            return self._image_path_of(app)
        cmdline = cmdline.lstrip()
        if cmdline.startswith('"'):
            return self._image_path_of(cmdline[1:].split('"', 1)[0])
        words = cmdline.split(' ')
        for count in range(1, len(words) + 1):
            name = ' '.join(words[:count]).rstrip()
            if count > 1 and not any(sep in name for sep in '\\/:'):
                break  # Only a path may contain spaces
            path = self._image_path_of(name)
            if path is not None:
                return path
        return None

    def _image_path_of(self, name):
        """Windows path of the EXE name names (searched like CreateProcess), or None"""
        if not name:
            return None
        candidates = [name] if name.lower().endswith('.exe') else [name, name + '.exe']
        folders = [None]
        if not any(sep in name for sep in '\\/:'):
            exe_dir = self.windows_exe_path().rsplit('\\', 1)[0]
            folders = [exe_dir, self.current_directory, "C:\\Windows\\System32",
                       "C:\\Windows"]
        for folder in folders:
            for candidate in candidates:
                full = self.full_windows_path(
                    candidate if folder is None else folder.rstrip('\\') + '\\' + candidate)
                path = self.resolve_drive_path(full) if full else None
                if path and os.path.isfile(path):
                    return full
        if folders != [None]:
            for candidate in candidates:
                path = find_program(candidate)
                if path:
                    return windows_path_of_host(path)
        return None

    def CreateProcessW(self, args):
        return self.CreateProcessA(args, wide=True)

    def CreateProcessA(self, args, wide=False):
        """CreateProcessA/W emulation - emulates the EXE in its own thread"""
        lpApplicationName, lpCommandLine = args[0], args[1]
        lpCurrentDirectory, lpProcessInformation = args[7], args[9]
        app = self._read_text(lpApplicationName, wide) if lpApplicationName else ''
        cmdline = self._read_text(lpCommandLine, wide) if lpCommandLine else ''
        log.info(f"CreateProcess(\"{app}\", \"{cmdline}\")")
        path = self._process_image_path(app, cmdline)
        starter = winapi.WinAPIHandler.process_starter
        if path is None or starter is None:
            self._last_error = 2  # ERROR_FILE_NOT_FOUND
            return 0
        current = self.current_directory
        if lpCurrentDirectory:
            current = self.full_windows_path(self._read_text(lpCurrentDirectory, wide),
                                             clamp=True).rstrip('\\') or current
            if len(current) == 2:
                current += '\\'
        if not cmdline.strip():
            cmdline = f'"{path}"' if ' ' in path else path
        elif not app:
            cmdline = self._quote_program_name(cmdline)
        child = starter(path, cmdline, current)
        if child is None:
            self._last_error = 193  # ERROR_BAD_EXE_FORMAT
            return 0
        pid, tid = child.process_id, child.main_thread.tid
        hProcess = self.get_next_handle()
        hThread = self.get_next_handle()
        self.handles[hProcess] = {'type': 'process', 'emulator': child}
        self.handles[hThread] = {'type': 'thread', 'emulator': child}
        if lpProcessInformation:
            self._mem_write(lpProcessInformation,
                            struct.pack('<4I', hProcess, hThread, pid, tid))
        return 1

    def WinExec(self, args):
        """WinExec(lpCmdLine, uCmdShow) - runs a program; a value above 31 on
        success, else ERROR_FILE_NOT_FOUND (2) or ERROR_BAD_FORMAT (11)"""
        info = self.emu.heap_alloc(16)
        try:
            if not self.CreateProcessA([0, args[0], 0, 0, 0, 0, 0, 0, 0, info]):
                return 11 if self._last_error == 193 else 2
            process, thread = struct.unpack('<II', self.emu.uc.mem_read(info, 8))
            self.CloseHandle([process])
            self.CloseHandle([thread])
            return 33
        finally:
            self.emu.heap_free(info)

    @staticmethod
    def _child_running(child):
        thread = getattr(child, 'thread', None)
        return thread is not None and thread.is_alive()

    def GetExitCodeProcess(self, args):
        """GetExitCodeProcess emulation - STILL_ACTIVE (259) while it runs"""
        hProcess, lpExitCode = args[0], args[1]
        if hProcess == 0xFFFFFFFF or self.handles.get(hProcess, {}).get('current'):
            code = 259
        else:
            info = self.handles.get(hProcess)
            if not info or info.get('type') != 'process':
                self._last_error = 6  # ERROR_INVALID_HANDLE
                return 0
            child = info['emulator']
            if self._child_running(child):
                code = 259
            elif child.crashed:
                code = 0xC0000005
            else:
                code = child.api_handler.exit_code or 0
        return 1 if self._mem_write(lpExitCode, struct.pack('<I', code)) else 0

    # ---------- Threads and synchronization objects ----------

    def _object_signaled(self, info, consume):
        """Is a waitable object signaled? consume: a successful wait takes it
        (auto-reset event, semaphore count, mutex ownership)"""
        kind = info.get('type')
        if kind in ('process', 'thread') and 'emulator' in info:
            return not self._child_running(info['emulator'])
        if kind == 'thread':
            return info['thread'].exited
        if kind == 'event':
            if not info['signaled']:
                return False
            if consume and not info['manual']:
                info['signaled'] = False
            return True
        if kind == 'semaphore':
            if info['count'] <= 0:
                return False
            if consume:
                info['count'] -= 1
            return True
        if kind == 'mutex':
            tid = self.emu.current_thread.tid
            if info['owner'] not in (0, tid):
                if self._thread_alive(info['owner']):
                    return False
                info['owner'], info['count'] = 0, 0  # Abandoned
            if consume:
                info['owner'] = tid
                info['count'] += 1
            return True
        if kind == 'change_notification':
            if not info['signaled']:
                self._check_change_notification(info)
            return info['signaled']
        return True  # Files, modules... are always signaled
