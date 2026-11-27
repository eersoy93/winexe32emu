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

from unicorn import UcError

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
        prepare = self._child_inheritance(args[4], args[5], args[6], args[8], wide)
        child = starter(path, cmdline, current, prepare=prepare)
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

    # CreateProcess flags: dwCreationFlags and STARTUPINFO.dwFlags
    DETACHED_PROCESS, CREATE_NEW_CONSOLE, CREATE_UNICODE_ENVIRONMENT = 0x8, 0x10, 0x400
    STARTF_USESTDHANDLES = 0x100
    STD_HANDLE_IDS = {'stdin': 0xFFFFFFF6, 'stdout': 0xFFFFFFF5, 'stderr': 0xFFFFFFF4}

    def _read_environment_block(self, address, wide):
        """{NAME: value} of an environment block ("NAME=value" strings, an empty
        one at the end); the names upper-case like the process environments"""
        environment = {}
        unit = 2 if wide else 1
        while len(environment) < 4096:
            text = self._read_text(address, wide)
            if not text:
                break
            name, sep, value = text[1:].partition('=')
            if sep:
                environment[(text[0] + name).upper()] = value
            address += (len(text.encode('utf-16-le')) if wide else
                        len(self.read_cstring(address))) + unit
        return environment

    def _inherited_handle(self, info):
        """The child's copy of an inherited file handle: like on Windows it
        shares the file position (a duplicated host descriptor)"""
        copy = dict(info)
        fp = info.get('fp')
        try:
            fd = fp.fileno()
        except (AttributeError, OSError, ValueError):
            return copy  # NUL and other devices: the same object will do
        try:
            fp.flush()
            # Unbuffered: the parent reads the file as soon as the child ends
            copy['fp'] = os.fdopen(os.dup(fd), fp.mode, buffering=0)
            copy['inherited'] = True
        except (OSError, ValueError) as e:
            log.warning(f"Cannot inherit {info.get('name')!r}: {e}")
        return copy

    def close_inherited_handles(self):
        """Close the host files of the inherited handles when the process ends
        (the parent's own handles stay open)"""
        for handle, info in list(self.handles.items()):
            if info.get('inherited'):
                try:
                    info['fp'].close()
                except OSError:
                    pass
                del self.handles[handle]

    def _child_inheritance(self, inherit_handles, flags, lpEnvironment, lpStartupInfo, wide):
        """What a child gets from CreateProcess, as a function applied to its
        emulator before it starts: the environment (this process's, or
        lpEnvironment), the console (a console program shares the parent's
        unless CREATE_NEW_CONSOLE or DETACHED_PROCESS), the console title of
        STARTUPINFO.lpTitle and its STARTF_USESTDHANDLES handles (cmd's
        redirections) when bInheritHandles is TRUE"""
        if lpEnvironment:
            environment = self._read_environment_block(
                lpEnvironment, wide or bool(flags & self.CREATE_UNICODE_ENVIRONMENT))
        else:
            environment = dict(self.environment)
        title, std = None, {}
        if lpStartupInfo:
            try:
                fields = struct.unpack('<17I', self.emu.uc.mem_read(lpStartupInfo, 68))
            except UcError:
                fields = (0,) * 17
            if fields[3]:  # cb, lpReserved, lpDesktop, lpTitle...
                title = self._read_text(fields[3], wide)
            if fields[11] & self.STARTF_USESTDHANDLES and inherit_handles:
                for kind, handle in zip(('stdin', 'stdout', 'stderr'), fields[14:17],
                                        strict=True):
                    info = self.handles.get(handle)
                    if info and info.get('type') == 'file' and info.get('fp') is not None:
                        std[self.STD_HANDLE_IDS[kind]] = info
        share = self.has_console and not flags & (self.DETACHED_PROCESS |
                                                  self.CREATE_NEW_CONSOLE)
        parent = self
        # Inheritable handles go to the child with the same values (the Red
        # Alert 2 launcher posts the game the handle of a shared memory block)
        inherited = {handle: self.handles[handle] for handle in sorted(self.inheritable_handles)
                     if handle in self.handles} if inherit_handles else {}

        def prepare(emulator):
            child = emulator.api_handler
            child.environment = environment
            child.console_title = title
            child.console_parent = parent if share else None
            child.console_detached = bool(flags & self.DETACHED_PROCESS)
            for handle, info in inherited.items():
                child.handles[handle] = parent._inherited_object(info)
                child.inheritable_handles.add(handle)
            for std_id, info in std.items():
                handle = next((h for h, i in inherited.items() if i is info), None)
                if handle is None:
                    handle = child.get_next_handle()
                    child.handles[handle] = parent._inherited_handle(info)
                child.std_handles[std_id] = handle
        return prepare

    def _inherited_object(self, info):
        """The child's handle to an object it inherits: a file gets its own
        host descriptor, a kernel object one more reference"""
        if info.get('type') == 'file' and info.get('fp') is not None:
            return self._inherited_handle(info)
        if 'refs' in info:
            info['refs'] += 1
        else:
            info['shared'] = info.get('shared', 0) + 1
        return info

    def _mark_inheritable(self, lpAttributes, handle):
        """A new handle is inheritable if its SECURITY_ATTRIBUTES say so
        (bInheritHandle); returns the handle"""
        if handle and handle != 0xFFFFFFFF and lpAttributes:
            try:
                inherit = struct.unpack('<I', self.emu.uc.mem_read(lpAttributes + 8, 4))[0]
            except UcError:
                inherit = 0
            if inherit:
                self.inheritable_handles.add(handle)
        return handle

    def redirected_std_file(self, kind):
        """The file a standard stream ('stdin', 'stdout', 'stderr') goes to
        when it is redirected (an inherited handle or SetStdHandle), else None"""
        handle = self.std_handles.get(self.STD_HANDLE_IDS[kind])
        info = self.handles.get(handle) if handle is not None else None
        return info.get('fp') if info and info.get('type') == 'file' else None

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
