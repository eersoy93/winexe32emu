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

"""CPUEmulator mixin: the process structures programs read directly from
memory instead of through an API

- In-memory images of the emulated system DLLs (kernel32.dll, ...): an MZ/PE
  header and an export table whose functions are the API stubs, so a module
  handle is a real image base and code that walks the exports finds them
- The loader data of the PEB (PEB->Ldr: the module lists in load order,
  memory order and initialization order)
- The process parameters of the PEB (PEB->ProcessParameters: image path,
  command line, current directory, environment, standard handles)
- Static TLS of the images (the PE TLS directory): a TLS block per module and
  thread in TEB->ThreadLocalStoragePointer, and the TLS callbacks
"""

import ntpath
import struct

from unicorn import UcError

from .logger import log


class ProcessEnvironmentMixin:
    """System DLL images, PEB loader data and process parameters, static TLS"""

    # The images of the emulated system DLLs are placed from here up (below
    # the callback and API stub regions: the export RVAs of the stubs stay
    # positive), one per SYSTEM_MODULE_SPACING
    SYSTEM_MODULE_BASE = 0x6E000000
    SYSTEM_MODULE_SPACING = 0x00100000
    # Loaded like on Windows before the program's own imports (ntdll first)
    CORE_SYSTEM_MODULES = ('ntdll.dll', 'kernel32.dll')
    # Families of exported names: the emulator does not know which DLL
    # exports which API, so a system DLL's image exports the emulated APIs of
    # its family (a superset of the real exports)
    NTDLL_PREFIXES = ('Nt', 'Zw', 'Rtl', 'Ldr', 'Dbg', 'Csr', 'Etw', 'Ki', 'Tp')

    # Slots of TEB->ThreadLocalStoragePointer (one per image with a TLS directory)
    TLS_ARRAY_SLOTS = 64
    DLL_PROCESS_ATTACH, DLL_THREAD_ATTACH, DLL_THREAD_DETACH = 1, 2, 3

    def _init_process_environment(self):
        """State of the mixin (called from CPUEmulator.__init__)"""
        self.system_modules = {}  # lower-case DLL name -> module info
        self.ldr_addr = 0
        self.process_parameters_addr = 0
        self.tls_modules = []  # [{'base', 'directory', 'index'}] by TLS index

    # ---------- System DLL images ----------

    def _system_export_names(self, key):
        """Sorted names exported by the image of the system DLL key"""
        handler = self.api_handler
        names = set(handler._api_map)
        names.update(n for n in handler._api_method_names() if not n.startswith('api_'))
        crt = key.startswith(handler.CDECL_DLL_PREFIXES)

        def belongs(name):
            lower = name[:1].islower() or name[:1] in '_?'
            if crt:
                return lower
            if key == 'ntdll.dll':
                return lower or name.startswith(self.NTDLL_PREFIXES)
            return not lower
        return sorted((n for n in names if n.isascii() and belongs(n)),
                      key=lambda n: n.encode('ascii'))

    def system_module(self, key):
        """Base address (HMODULE) of the in-memory image of the emulated system
        DLL key ("kernel32.dll"), created on first use; 0 if it cannot be"""
        module = self.system_modules.get(key)
        if module is not None:
            return module['base']
        exports = []
        for name in self._system_export_names(key):
            addr = (self.api_handler.resolve_data_import(key, name) or
                    self.get_api_stub(key, name))
            if addr:
                exports.append((name, addr))

        # Layout: headers (one page), then the export directory, the address,
        # name pointer and ordinal tables and the strings
        n = len(exports)
        export_rva = 0x1000
        functions_rva = export_rva + 40
        names_rva = functions_rva + 4 * n
        ordinals_rva = names_rva + 4 * n
        strings_rva = ordinals_rva + 2 * n
        strings = bytearray(key.upper().encode('ascii') + b'\0')
        name_rvas = []
        for name, _ in exports:
            name_rvas.append(strings_rva + len(strings))
            strings += name.encode('ascii') + b'\0'
        export_size = strings_rva + len(strings) - export_rva
        size = self._align_size(export_rva + export_size)

        base = None
        for slot in range(16):
            preferred = self.SYSTEM_MODULE_BASE + slot * self.SYSTEM_MODULE_SPACING
            if self._free_image_base(preferred, size) == preferred:
                base = preferred
                break
        else:
            base = self._free_image_base(None, size)
        if base is None:
            log.error(f"No free address range for the image of {key}")
            return 0

        image = bytearray(size)
        # DOS header and PE signature
        image[0:2] = b'MZ'
        struct.pack_into('<I', image, 0x3C, 0x80)
        image[0x80:0x84] = b'PE\0\0'
        # IMAGE_FILE_HEADER: i386, one section, a DLL
        struct.pack_into('<HHIIIHH', image, 0x84, 0x14C, 1, 0, 0, 0, 0xE0, 0x2102)
        # IMAGE_OPTIONAL_HEADER32
        opt = 0x98
        struct.pack_into('<HBBIIIIII', image, opt, 0x10B, 9, 0, 0, size - 0x1000, 0, 0,
                         0x1000, 0x1000)
        struct.pack_into('<IIIHHHHHHIIIIHHIIIIII', image, opt + 28,
                         base, 0x1000, 0x1000, 6, 0, 6, 0, 6, 0, 0, size, 0x1000, 0,
                         3, 0x0140, 0x40000, 0x1000, 0x100000, 0x1000, 0, 16)
        struct.pack_into('<II', image, opt + 96, export_rva, export_size)
        # Section header: the export data
        section = opt + 0xE0
        image[section:section + 8] = b'.edata\0\0'
        struct.pack_into('<IIIIIIHHI', image, section + 8, size - 0x1000, 0x1000,
                         size - 0x1000, 0x1000, 0, 0, 0, 0, 0x40000040)
        # IMAGE_EXPORT_DIRECTORY
        struct.pack_into('<IIHHIIIIIII', image, export_rva, 0, 0, 6, 0, strings_rva, 1,
                         n, n, functions_rva, names_rva, ordinals_rva)
        for i, (_, addr) in enumerate(exports):
            struct.pack_into('<I', image, functions_rva + 4 * i, (addr - base) & 0xFFFFFFFF)
            struct.pack_into('<I', image, names_rva + 4 * i, name_rvas[i])
            struct.pack_into('<H', image, ordinals_rva + 2 * i, i)
        image[strings_rva:strings_rva + len(strings)] = strings

        try:
            self.map_shared(base, size)
        except UcError as e:
            log.error(f"Cannot map the image of {key}: {e}")
            return 0
        self.mapped_regions.append((base, base + size))
        self.uc.mem_write(base, bytes(image))
        module = {'name': key, 'base': base, 'size': size,
                  'exports': dict(exports), 'path': 'C:\\Windows\\System32\\' + key}
        self.system_modules[key] = module
        log.debug(f"System DLL image: {key} at 0x{base:08x} ({n} exports)")
        self.add_loader_entry(base, size, 0, module['path'])
        return base

    def system_module_at(self, address):
        """System DLL image holding address, or None"""
        for module in self.system_modules.values():
            if module['base'] <= address < module['base'] + module['size']:
                return module
        return None

    # ---------- PEB loader data ----------

    def _unicode_string(self, address, text, max_chars=None):
        """Write a UNICODE_STRING at address with a new buffer for text"""
        data = text.encode('utf-16-le')
        capacity = max(len(data) + 2, 2 * (max_chars or 0))
        buffer = self.heap_alloc(capacity)
        self.uc.mem_write(buffer, data + b'\0\0')
        self.uc.mem_write(address, struct.pack('<HHI', len(data), capacity, buffer))
        return buffer

    def _setup_loader_data(self):
        """PEB->Ldr (PEB_LDR_DATA) with the EXE and the core system DLLs"""
        self.ldr_addr = self.heap_alloc(0x30)
        heads = [self.ldr_addr + offset for offset in (0x0C, 0x14, 0x1C)]
        data = bytearray(0x30)
        struct.pack_into('<IB', data, 0, 0x30, 1)  # Length, Initialized
        for head in heads:  # Empty circular lists point at themselves
            struct.pack_into('<II', data, head - self.ldr_addr, head, head)
        self.uc.mem_write(self.ldr_addr, bytes(data))
        self.uc.mem_write(self.peb_addr + 0x0C, struct.pack('<I', self.ldr_addr))

        loader = self.pe_loader
        self.add_loader_entry(loader.image_base,
                              self._align_size(loader.pe.OPTIONAL_HEADER.SizeOfImage),
                              loader.image_base + loader.entry_point,
                              self.api_handler.windows_exe_path(), initialized=False)
        for key in self.CORE_SYSTEM_MODULES:
            self.system_module(key)

    def add_loader_entry(self, base, size, entry_point, windows_path, initialized=True):
        """Append a module (LDR_DATA_TABLE_ENTRY) to the PEB loader lists; the
        EXE is not in the initialization order list"""
        if not self.ldr_addr:
            return
        entry = self.heap_alloc(0x78)
        fields = bytearray(0x78)
        struct.pack_into('<III', fields, 0x18, base, entry_point, size)
        struct.pack_into('<IH', fields, 0x34, 0x4 if initialized else 0, 0xFFFF)  # LoadCount
        self.uc.mem_write(entry, bytes(fields))
        self._unicode_string(entry + 0x24, windows_path)  # FullDllName
        self._unicode_string(entry + 0x2C, ntpath.basename(windows_path))  # BaseDllName
        # HashLinks: an empty list
        self.uc.mem_write(entry + 0x3C, struct.pack('<II', entry + 0x3C, entry + 0x3C))
        lists = [(0x0C, 0x00), (0x14, 0x08)] + ([(0x1C, 0x10)] if initialized else [])
        for head_offset, link_offset in lists:
            head = self.ldr_addr + head_offset
            link = entry + link_offset
            last = struct.unpack('<I', self.uc.mem_read(head + 4, 4))[0]
            self.uc.mem_write(link, struct.pack('<II', head, last))  # Flink, Blink
            self.uc.mem_write(last, struct.pack('<I', link))  # last->Flink
            self.uc.mem_write(head + 4, struct.pack('<I', link))  # head->Blink

    # ---------- PEB process parameters ----------

    def _setup_process_parameters(self):
        """PEB->ProcessParameters (RTL_USER_PROCESS_PARAMETERS)"""
        handler = self.api_handler
        params = self.heap_alloc(0x2A0)
        self.process_parameters_addr = params
        fields = bytearray(0x2A0)
        struct.pack_into('<III', fields, 0, 0x2A0, 0x2A0, 1)  # PARAMS_NORMALIZED
        if self.pe_loader.is_console_program():
            struct.pack_into('<III', fields, 0x18, 0x10, 0x11, 0x12)  # Std handles
        struct.pack_into('<I', fields, 0x6C, 1)  # ShowWindowFlags: SW_SHOWNORMAL
        self.uc.mem_write(params, bytes(fields))

        image_path = handler.windows_exe_path()
        self._unicode_string(params + 0x24, self._directory_with_slash(
            handler.current_directory), 260)  # CurrentDirectory.DosPath
        self._unicode_string(params + 0x30, 'C:\\Windows\\System32;C:\\Windows')  # DllPath
        self._unicode_string(params + 0x38, image_path)  # ImagePathName
        # CommandLine: the buffer of GetCommandLineW
        length = len(handler.windows_command_line().encode('utf-16-le'))
        self.uc.mem_write(params + 0x40, struct.pack('<HHI', length, length + 2,
                                                     self.cmdline_wide_addr))
        # Environment: "NAME=value\0...\0\0" in UTF-16
        block = ''.join(f"{name}={value}\0" for name, value in
                        sorted(handler.environment.items())) + '\0'
        env_data = block.encode('utf-16-le')
        env = self.heap_alloc(len(env_data))
        self.uc.mem_write(env, env_data)
        self.uc.mem_write(params + 0x48, struct.pack('<I', env))
        self._unicode_string(params + 0x70, image_path)  # WindowTitle
        self._unicode_string(params + 0x78, 'WinSta0\\Default')  # DesktopInfo
        self.uc.mem_write(self.peb_addr + 0x10, struct.pack('<I', params))

    @staticmethod
    def _directory_with_slash(directory):
        return directory if directory.endswith('\\') else directory + '\\'

    def update_process_current_directory(self, directory):
        """SetCurrentDirectory: ProcessParameters->CurrentDirectory.DosPath"""
        if not self.process_parameters_addr:
            return
        address = self.process_parameters_addr + 0x24
        _, capacity, buffer = struct.unpack('<HHI', self.uc.mem_read(address, 8))
        data = self._directory_with_slash(directory).encode('utf-16-le')
        if len(data) + 2 > capacity:
            self._unicode_string(address, self._directory_with_slash(directory))
            return
        self.uc.mem_write(buffer, data + b'\0\0')
        self.uc.mem_write(address, struct.pack('<H', len(data)))

    # ---------- Static TLS ----------

    def _tls_directory(self, base, pe):
        """(StartAddressOfRawData, EndAddressOfRawData, AddressOfIndex,
        AddressOfCallBacks, SizeOfZeroFill) of an image's TLS directory, read
        from memory (relocated), or None"""
        directories = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        if len(directories) <= 9 or not directories[9].VirtualAddress:
            return None
        try:
            return struct.unpack('<IIIII', self.uc.mem_read(
                base + directories[9].VirtualAddress, 20))
        except UcError:
            log.warning(f"Unreadable TLS directory at 0x{base:08x}")
            return None

    def register_image_tls(self, base, pe):
        """Give an image with a TLS directory a TLS index and a TLS block in
        every thread. Returns its TLS module info, or None."""
        directory = self._tls_directory(base, pe)
        if directory is None:
            return None
        if len(self.tls_modules) >= self.TLS_ARRAY_SLOTS:
            log.error(f"Too many images with TLS, 0x{base:08x} gets none")
            return None
        module = {'base': base, 'directory': directory, 'index': len(self.tls_modules)}
        self.tls_modules.append(module)
        address_of_index = directory[2]
        if address_of_index:
            try:
                self.uc.mem_write(address_of_index, struct.pack('<I', module['index']))
            except UcError:
                log.warning(f"Unwritable TLS index of the image at 0x{base:08x}")
        for thread in list(self.threads.values()):
            if getattr(thread, 'tls_array', 0):
                self._allocate_tls_block(thread, module)
        log.debug(f"TLS index {module['index']}: image at 0x{base:08x}")
        return module

    def _allocate_tls_block(self, thread, module):
        """A thread's copy of an image's TLS template (data, then zero fill)"""
        start, end, _, _, zero_fill = module['directory']
        template = bytes(self.uc.mem_read(start, end - start)) if end > start else b''
        block = self.heap_alloc(len(template) + zero_fill + 4)
        if not block:
            log.error("Heap exhausted: no TLS block")
            return
        if template:
            self.uc.mem_write(block, template)
        self.uc.mem_write(thread.tls_array + 4 * module['index'], struct.pack('<I', block))

    def init_thread_tls(self, thread):
        """TEB->ThreadLocalStoragePointer of a new thread, with its TLS blocks"""
        thread.tls_array = self.heap_alloc(4 * self.TLS_ARRAY_SLOTS)
        self.uc.mem_write(thread.teb + 0x2C, struct.pack('<I', thread.tls_array))
        for module in self.tls_modules:
            self._allocate_tls_block(thread, module)

    def free_thread_tls(self, thread):
        """Free a finished thread's TLS blocks and array"""
        array = getattr(thread, 'tls_array', 0)
        if not array:
            return
        for module in self.tls_modules:
            block = struct.unpack('<I', self.uc.mem_read(array + 4 * module['index'], 4))[0]
            if block:
                self.heap_free(block)
        self.heap_free(array)
        thread.tls_array = 0

    def run_tls_callbacks(self, reason, modules=None):
        """Call the TLS callbacks (image base, reason, NULL) of the images"""
        for module in (self.tls_modules if modules is None else modules):
            callbacks = module['directory'][3]
            while callbacks and not self.stop_emulation:
                try:
                    callback = struct.unpack('<I', self.uc.mem_read(callbacks, 4))[0]
                except UcError:
                    break
                if not callback:
                    break
                log.debug(f"TLS callback 0x{callback:08x}(0x{module['base']:08x}, {reason})")
                self.call_callback(callback, [module['base'], reason, 0])
                callbacks += 4
