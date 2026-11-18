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
    _next_process_id = 0x1000

    def _process_image_path(self, app, cmdline):
        """Windows path of the EXE CreateProcess should start, or None"""
        if app:
            name = app
        else:
            cmdline = cmdline.lstrip()
            if cmdline.startswith('"'):
                name = cmdline[1:].split('"', 1)[0]
            else:
                name = cmdline.split(None, 1)[0] if cmdline.strip() else ''
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
        child = starter(path, cmdline, current)
        if child is None:
            self._last_error = 193  # ERROR_BAD_EXE_FORMAT
            return 0
        winapi.WinAPIHandler._next_process_id += 4
        pid = winapi.WinAPIHandler._next_process_id
        hProcess = self.get_next_handle()
        hThread = self.get_next_handle()
        self.handles[hProcess] = {'type': 'process', 'emulator': child}
        self.handles[hThread] = {'type': 'thread', 'emulator': child}
        if lpProcessInformation:
            self._mem_write(lpProcessInformation,
                            struct.pack('<4I', hProcess, hThread, pid, pid + 1))
        return 1

    @staticmethod
    def _child_running(child):
        thread = getattr(child, 'thread', None)
        return thread is not None and thread.is_alive()

    def GetExitCodeProcess(self, args):
        """GetExitCodeProcess emulation - STILL_ACTIVE (259) while it runs"""
        hProcess, lpExitCode = args[0], args[1]
        if hProcess == 0xFFFFFFFF:
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
