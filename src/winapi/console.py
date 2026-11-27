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

"""WinAPIHandler mixin: Console windows and I/O, exit handlers, guest strings"""

from unicorn import UcError

from .. import config
from ..logger import log


class ConsoleMixin:
    """Console windows and I/O, exit handlers, guest strings"""

    # ==================== CONSOLE ====================

    # Set by CreateProcess before the process starts (_child_inheritance)
    console_title = None     # STARTUPINFO.lpTitle: the title of a new console
    console_parent = None    # The parent process whose console a console program shares
    console_detached = False  # DETACHED_PROCESS: no console at all
    console_shared = False   # The console belongs to the parent (it stays when we end)

    def start_console(self):
        """The console a console program starts with: its parent's (a program
        that cmd runs writes into cmd's window), or a new one"""
        parent = self.console_parent
        if self.console_detached:
            return
        if parent is not None and parent.has_console and not self.has_console:
            self.has_console = True
            self.console_shared = True
            self.console = parent.console
            if self.console is not None:
                self.console.attached.append(self)
            return
        self.alloc_console()

    def alloc_console(self):
        """Give the process its own console (window). False if it already has one."""
        if self.has_console:
            return False
        self.has_console = True
        self.console_shared = False
        if self.gui and self.gui.running:
            self.console = self.gui.create_console(self.console_title or
                                                   self.windows_exe_path(), self)
        return True

    def free_console(self):
        """Detach from the console; its window closes unless another process
        owns it. False if there was none."""
        if not self.has_console:
            return False
        self.flush_std_streams()
        self.has_console = False
        console, self.console = self.console, None
        if self.console_shared:
            self.console_shared = False
            if console is not None and self in console.attached:
                console.attached.remove(self)
        elif console is not None and self.gui:
            self.gui.close_console(console)
        return True

    def console_write(self, text, stream='stdout'):
        """Show program output in the process's GUI console, if it has one"""
        console = self.console
        if console is not None and self.gui and self.gui.running:
            self.gui.console_write(console, text, stream)

    def console_read_line(self):
        """Read a line typed into the GUI console; None without a console or when cancelled"""
        console = self.console
        if console is None or not self.gui:
            return None
        return self.gui.request_console_input(console)

    def request_termination(self):
        """Stop the process from another thread (console closed, emulator shutdown)"""
        # Also breaks guest loops that make no API calls
        self.emu.stop_all()
        self.quit_requested = True
        console = self.console
        if console is not None and self.gui:
            if self.console_shared:
                # The console goes on for its owner: only our read ends
                self.gui.wake_console_input(console)
            else:
                self.gui.cancel_console_input(console)

    def _set_exit_code(self, code):
        if self.exit_code is None:
            self.exit_code = code & 0xFFFFFFFF

    def run_exit_handlers(self):
        """Run atexit/_onexit handlers in LIFO order (once)."""
        if self._exit_handlers_ran:
            return
        self._exit_handlers_ran = True
        while self.exit_handlers and not self.emu.stop_emulation:
            func = self.exit_handlers.pop()
            log.debug(f"Running exit handler 0x{func:08x}")
            self.emu.call_callback(func, [])

    def resolve_data_import(self, dll_name, name):
        """Address of an exported CRT *variable*, or None if not a data import.

        Data imports must point at real memory: the program dereferences the
        IAT entry directly instead of calling through it.
        """
        if not dll_name.lower().startswith(self.CDECL_DLL_PREFIXES):
            return None
        resolvers = {
            '_iob': self._ensure_iob,
            '_fmode': self._ensure_fmode_addr,
            '_commode': self._ensure_commode_addr,
            '_adjust_fdiv': self._ensure_adjust_fdiv_addr,
            '_acmdln': lambda: self.api__p__acmdln([]),
            '_wcmdln': lambda: self.api__p__wcmdln([]),
            '__argc': lambda: self.api__p___argc([]),
            '__argv': lambda: self.api__p___argv([]),
            '__wargv': lambda: self.api__p___wargv([]),
            '_environ': lambda: self._ensure_env_ptr('_environ_ptr_addr'),
            '__initenv': lambda: self._ensure_env_ptr('_initenv_addr'),
            '_wenviron': lambda: self._ensure_env_ptr('_wenviron_ptr_addr', wide=True),
            '__winitenv': lambda: self._ensure_env_ptr('_winitenv_addr', wide=True),
        }
        resolvers.update(self._crt_variable_resolvers())
        resolver = resolvers.get(name)
        return resolver() if resolver else None

    def get_next_handle(self):
        """Create new handle (not one a parent process passed on: inherited
        handles keep their values)"""
        handle = self.next_handle
        self.next_handle += 4
        handles = getattr(self, 'handles', ())
        while handle in handles:
            handle, self.next_handle = self.next_handle, self.next_handle + 4
        return handle

    def _read_until_null(self, address, max_bytes, unit):
        """Read up to max_bytes from emulated memory, stopping at a NUL unit.

        Reads page by page so a short string that ends just before an
        unmapped page is still returned. Returns None if nothing is readable.
        """
        data = bytearray()
        addr = address
        while len(data) < max_bytes:
            chunk = min(max_bytes - len(data), 0x1000 - (addr & 0xFFF))
            try:
                block = self.emu.uc.mem_read(addr, chunk)
            except UcError:
                if not data:
                    return None
                break
            start = len(data)
            data += block
            addr += chunk
            # Re-scan from an aligned position so a terminator split across
            # chunks (wide strings) is found too
            pos = start - (start % unit)
            while True:
                pos = data.find(b'\x00' * unit, pos)
                if pos == -1:
                    break
                if pos % unit == 0:
                    return bytes(data[:pos])
                pos += 1
        return bytes(data[:max_bytes - (max_bytes % unit)])

    def _string_access_violation(self, address):
        """An API read a string through an unmapped pointer: fatal, like on Windows."""
        log.error(f"Access violation: READ @ 0x{address:08x} (string argument)")
        self.emu.crashed = True
        self.emu.stop_emulation = True

    def read_cstring(self, address, max_len=0x10000):
        """Raw bytes of a NUL-terminated ANSI string (b'' for NULL or unreadable)."""
        if not address:
            return b''
        data = self._read_until_null(address, max_len, 1)
        if data is None:
            self._string_access_violation(address)
            return b''
        return data

    def read_string(self, address, max_len=0x10000):
        """Read null-terminated ANSI string from memory"""
        return self.read_cstring(address, max_len).decode(config.ANSI_CODEPAGE, errors='replace')

    def read_wide_string(self, address, max_len=0x8000):
        """Read wide string (UTF-16) from memory"""
        if not address:
            return ''
        data = self._read_until_null(address, max_len * 2, 2)
        if data is None:
            self._string_access_violation(address)
            return ''
        return data.decode('utf-16-le', errors='replace')

    def _read_text(self, address, wide):
        """Read an ANSI or UTF-16 string argument (A/W API variants)"""
        return self.read_wide_string(address) if wide else self.read_string(address)
