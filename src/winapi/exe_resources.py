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

"""WinAPIHandler mixin: Resources of the loaded EXE, standard handles, code page conversion,
errors, virtual memory and heaps"""

import io
import re
import struct

from unicorn import UC_PROT_ALL, UcError

from .. import config
from ..logger import log
from .codepages import codec_for_codepage, decode_codepage, encode_codepage


class ExeResourcesMixin:
    """Resources of the loaded EXE, standard handles, code page conversion,
    errors, virtual memory and heaps"""

    # ---------- Resources of the loaded EXE ----------

    def _resource_key(self, value, wide=False):
        """Resource name/type: integer ID (MAKEINTRESOURCE or "#123") or upper-case name"""
        if value < 0x10000:
            return value
        name = self.read_wide_string(value) if wide else self.read_string(value)
        if name.startswith('#') and name[1:].isdigit():
            return int(name[1:])
        return name.upper()

    def _resource_module(self, hModule):
        """(base, pefile.PE) of a module whose resources can be read: the EXE
        (hModule 0 or its base) or one of the program's own loaded DLLs"""
        if hModule in (0, self.emu.pe_loader.image_base):
            return self.emu.pe_loader.image_base, self.emu.pe_loader.pe
        module = self.emu.dlls.get(hModule)
        if module is not None:
            return module['base'], module['pe']
        return None

    def _find_resource(self, res_type, name, hModule=0):
        """(address, size) of a resource of the EXE or of the loaded DLL
        hModule (first language), or None"""
        found_module = self._resource_module(hModule)
        if found_module is None:
            return None
        base, pe = found_module
        if self._resource_index is None:
            self._resource_index = {}
        index = self._resource_index.get(base)
        if index is None:
            index = self._resource_index[base] = {}
            root = getattr(pe, 'DIRECTORY_ENTRY_RESOURCE', None)
            for type_entry in (root.entries if root else []):
                tkey = str(type_entry.name).upper() if type_entry.name else type_entry.id
                for name_entry in getattr(type_entry, 'directory', None).entries:
                    nkey = str(name_entry.name).upper() if name_entry.name else name_entry.id
                    languages = getattr(name_entry, 'directory', None)
                    if languages and languages.entries:
                        data = languages.entries[0].data.struct
                        index[(tkey, nkey)] = (data.OffsetToData, data.Size)
        found = index.get((res_type, name))
        if found is None:
            return None
        return (base + found[0], found[1])

    def _is_own_module(self, hModule):
        """Is hModule the EXE or one of its loaded DLLs (modules whose
        resources are emulated)?"""
        return self._resource_module(hModule) is not None

    def FindResourceA(self, args, wide=False):
        """FindResourceA emulation (resources of the EXE and its loaded DLLs)"""
        hModule, lpName, lpType = args[0], args[1], args[2]
        name = self._resource_key(lpName, wide)
        res_type = self._resource_key(lpType, wide)
        resource = self._find_resource(res_type, name, hModule)
        log.debug(f"FindResource({name!r}, type {res_type!r}) -> {resource}")
        if resource is None:
            self._last_error = 1814  # ERROR_RESOURCE_NAME_NOT_FOUND
            return 0
        handle = self.get_next_handle()
        self.handles[handle] = {'type': 'resource', 'addr': resource[0], 'size': resource[1]}
        return handle

    def FindResourceW(self, args):
        """FindResourceW emulation: FindResourceA with UTF-16 names"""
        return self.FindResourceA(args, wide=True)

    def FindResourceExA(self, args):
        """FindResourceExA(hModule, lpType, lpName, wLanguage): the first language"""
        return self.FindResourceA([args[0], args[2], args[1]])

    def FindResourceExW(self, args):
        """FindResourceExW(hModule, lpType, lpName, wLanguage): the first language"""
        return self.FindResourceA([args[0], args[2], args[1]], wide=True)

    def LoadResource(self, args):
        """LoadResource emulation - resources are already mapped with the image"""
        info = self.handles.get(args[1])
        if not info or info.get('type') != 'resource':
            self._last_error = 6  # ERROR_INVALID_HANDLE
            return 0
        return info['addr']

    def LockResource(self, args):
        """LockResource emulation - the HGLOBAL is the data address"""
        return args[0]

    def FreeResource(self, args):
        """FreeResource emulation (obsolete, always FALSE)"""
        return 0

    def SizeofResource(self, args):
        """SizeofResource emulation"""
        info = self.handles.get(args[1])
        return info['size'] if info and info.get('type') == 'resource' else 0

    def LoadStringA(self, args):
        """LoadStringA emulation - RT_STRING blocks hold 16 counted UTF-16 strings"""
        hInstance, uID, lpBuffer, cchBufferMax = args[0], args[1] & 0xFFFF, args[2], args[3]
        text = None
        resource = self._find_resource(6, uID // 16 + 1, hInstance)
        if resource:
            try:
                block = bytes(self.emu.uc.mem_read(*resource))
                pos = 0
                for _ in range(uID % 16):
                    pos += 2 + 2 * struct.unpack_from('<H', block, pos)[0]
                length = struct.unpack_from('<H', block, pos)[0]
                if length:
                    text = block[pos + 2:pos + 2 + 2 * length].decode('utf-16-le', errors='replace')
            except (UcError, struct.error):
                text = None
        log.debug(f"LoadStringA({uID}) -> {text!r}")
        if not lpBuffer or cchBufferMax == 0:
            return 0
        if text is None:
            self._last_error = 1814  # ERROR_RESOURCE_NAME_NOT_FOUND
            self.emu.uc.mem_write(lpBuffer, b'\x00')
            return 0
        data = text.encode(config.ANSI_CODEPAGE, errors='replace')[:cchBufferMax - 1]
        self.emu.uc.mem_write(lpBuffer, data + b'\x00')
        return len(data)

    def AllocConsole(self, args):
        """AllocConsole emulation - opens the process's console window"""
        log.debug("AllocConsole()")
        if not self.alloc_console():
            self._last_error = 5  # ERROR_ACCESS_DENIED: already has a console
            return 0
        return 1

    def FreeConsole(self, args):
        """FreeConsole emulation"""
        log.debug("FreeConsole()")
        if not self.free_console():
            self._last_error = 6  # ERROR_INVALID_HANDLE
            return 0
        return 1

    def GetStdHandle(self, args):
        """GetStdHandle emulation"""
        nStdHandle = args[0]
        handle_names = {
            0xFFFFFFF6: "STD_INPUT_HANDLE",
            0xFFFFFFF5: "STD_OUTPUT_HANDLE",
            0xFFFFFFF4: "STD_ERROR_HANDLE",
        }
        # Convert signed values for 32-bit
        if nStdHandle > 0x80000000:
            nStdHandle = nStdHandle - 0x100000000

        name = handle_names.get(nStdHandle & 0xFFFFFFFF, f"Unknown({nStdHandle})")
        log.debug(f"GetStdHandle({name})")
        if (nStdHandle & 0xFFFFFFFF) in self.std_handles:  # SetStdHandle
            return self.std_handles[nStdHandle & 0xFFFFFFFF]

        # Return fixed handle values
        if (nStdHandle & 0xFFFFFFFF) == 0xFFFFFFF6:
            return 0x10
        elif (nStdHandle & 0xFFFFFFFF) == 0xFFFFFFF5:
            return 0x11
        elif (nStdHandle & 0xFFFFFFFF) == 0xFFFFFFF4:
            return 0x12
        return 0

    def GetFileType(self, args):
        """GetFileType emulation - std handles are the console, CreateFile handles disk files"""
        hFile = args[0]
        if hFile in (0x10, 0x11, 0x12) or self.handles.get(hFile, {}).get('device'):
            result = 2  # FILE_TYPE_CHAR (the console, NUL)
        elif self.handles.get(hFile, {}).get('type') == 'file':
            result = 1  # FILE_TYPE_DISK
        else:
            self._last_error = 6  # ERROR_INVALID_HANDLE
            result = 0  # FILE_TYPE_UNKNOWN
        log.debug(f"GetFileType(0x{hFile:x}) -> {result}")
        if result:
            self._last_error = 0  # NO_ERROR distinguishes a real FILE_TYPE_UNKNOWN
        return result

    def SetHandleCount(self, args):
        """SetHandleCount emulation - Win32 has no handle limit, returns the request"""
        return args[0]

    def WriteFile(self, args):
        """WriteFile emulation"""
        hFile = args[0]
        lpBuffer = args[1]
        nNumberOfBytesToWrite = args[2]
        lpNumberOfBytesWritten = args[3]
        # Saving a DIB section's bits: they show what GDI drew on it
        self._sync_dib_sections_at(lpBuffer, nNumberOfBytesToWrite)

        try:
            data = self.emu.uc.mem_read(lpBuffer, nNumberOfBytesToWrite)
            bytes_written = nNumberOfBytesToWrite

            if hFile in [0x11]:  # stdout
                text = data.decode(config.ANSI_CODEPAGE, errors='replace')
                log.program_output("STDOUT", text)
                self.console_output.append(text)
                self.console_write(text)
            elif hFile in [0x12]:  # stderr
                text = data.decode(config.ANSI_CODEPAGE, errors='replace')
                log.program_output("STDERR", text)
                self.console_output.append(text)
                self.console_write(text, 'stderr')
            else:
                # Real file handle (opened via CreateFile, inside drives/)
                info = self.handles.get(hFile)
                if info and info.get('fp'):
                    overlapped = args[4] if len(args) > 4 else 0
                    self._overlapped_seek(info, overlapped)
                    written = info['fp'].write(bytes(data))
                    bytes_written = written if written is not None else nNumberOfBytesToWrite
                    self._overlapped_done(overlapped, bytes_written)
                else:
                    # Unknown handle: report failure so callers notice.
                    if lpNumberOfBytesWritten != 0:
                        self.emu.uc.mem_write(lpNumberOfBytesWritten, struct.pack('<I', 0))
                    log.warning(f"WriteFile to unknown handle 0x{hFile:x}")
                    return 0

            # Write bytes written count to memory
            if lpNumberOfBytesWritten != 0:
                self.emu.uc.mem_write(lpNumberOfBytesWritten,
                                      struct.pack('<I', bytes_written & 0xFFFFFFFF))

            log.debug(f"WriteFile(0x{hFile:x}, {nNumberOfBytesToWrite} bytes)")
            return 1  # Success
        except io.UnsupportedOperation:
            # The handle was opened without GENERIC_WRITE
            if lpNumberOfBytesWritten != 0:
                self._mem_write(lpNumberOfBytesWritten, struct.pack('<I', 0))
            log.debug(f"WriteFile(0x{hFile:x}): handle is read-only "
                      f"({self.handles.get(hFile, {}).get('name')})")
            self._last_error = 5  # ERROR_ACCESS_DENIED
            return 0
        except Exception as e:
            log.error(f"WriteFile error: {e}")
            return 0

    def WriteConsoleA(self, args, wide=False):
        """WriteConsoleA/W emulation"""
        hConsoleOutput = args[0]
        lpBuffer = args[1]
        nNumberOfCharsToWrite = args[2]
        lpNumberOfCharsWritten = args[3]

        try:
            if wide:
                data = self.emu.uc.mem_read(lpBuffer, nNumberOfCharsToWrite * 2)
                text = data.decode('utf-16-le', errors='replace')
            else:
                data = self.emu.uc.mem_read(lpBuffer, nNumberOfCharsToWrite)
                text = data.decode(config.ANSI_CODEPAGE, errors='replace')
            log.program_output("CONSOLE", text)
            self.console_output.append(text)
            self.console_write(text)

            if lpNumberOfCharsWritten != 0:
                self.emu.uc.mem_write(lpNumberOfCharsWritten,
                                      struct.pack('<I', nNumberOfCharsToWrite))
            return 1
        except UcError as e:
            log.error(f"WriteConsoleA error: {e}")
            return 0

    def WriteConsoleW(self, args):
        return self.WriteConsoleA(args, wide=True)

    def _codepage_name(self, code_page):
        """Python codec for a Windows code page number (CP_ACP, CP_OEMCP,
        CP_MACCP, CP_THREAD_ACP too), or None if unsupported"""
        if code_page in (0, 3):  # CP_ACP, CP_THREAD_ACP
            return config.ANSI_CODEPAGE
        return codec_for_codepage(self._resolve_codepage(code_page))

    def MultiByteToWideChar(self, args):
        """MultiByteToWideChar emulation"""
        CodePage, dwFlags, lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar = args[:6]
        codec = self._codepage_name(CodePage)
        if codec is None or not lpMultiByteStr or cbMultiByte == 0:
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0
        if cbMultiByte == 0xFFFFFFFF:
            data = self.read_cstring(lpMultiByteStr, max_len=0x8000000) + b'\x00'
        else:
            data = bytes(self.emu.uc.mem_read(lpMultiByteStr, cbMultiByte))
        # MB_ERR_INVALID_CHARS: an invalid sequence fails instead of U+FFFD
        text = decode_codepage(data, codec, strict=bool(dwFlags & 0x8))
        if text is None:
            self._last_error = 1113  # ERROR_NO_UNICODE_TRANSLATION
            return 0
        out = text.encode('utf-16-le', errors='surrogatepass')
        count = len(out) // 2
        if cchWideChar == 0:
            return count
        if count > cchWideChar:
            self._last_error = 122  # ERROR_INSUFFICIENT_BUFFER
            return 0
        self.emu.uc.mem_write(lpWideCharStr, out)
        return count

    def WideCharToMultiByte(self, args):
        """WideCharToMultiByte emulation"""
        (CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr,
         cbMultiByte, lpDefaultChar, lpUsedDefaultChar) = args[:8]
        codec = self._codepage_name(CodePage)
        if codec is None or not lpWideCharStr or cchWideChar == 0:
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0
        if cchWideChar == 0xFFFFFFFF:
            text = self.read_wide_string(lpWideCharStr, max_len=0x4000000) + '\x00'
        else:
            text = bytes(self.emu.uc.mem_read(lpWideCharStr, cchWideChar * 2)).decode(
                'utf-16-le', errors='replace')
        # lpDefaultChar: the program's replacement for what the code page lacks
        default = (self.read_cstring(lpDefaultChar, max_len=2)[:2] or b'?') \
            if lpDefaultChar and codec not in ('utf-8', 'utf-7') else b'?'
        out, used_default = encode_codepage(text, codec, default)
        if lpUsedDefaultChar:
            self.emu.uc.mem_write(lpUsedDefaultChar, struct.pack('<I', used_default))
        if cbMultiByte == 0:
            return len(out)
        if len(out) > cbMultiByte:
            self._last_error = 122  # ERROR_INSUFFICIENT_BUFFER
            return 0
        self.emu.uc.mem_write(lpMultiByteStr, out)
        return len(out)

    def GetLastError(self, args):
        """GetLastError emulation"""
        log.debug(f"GetLastError() -> {self._last_error}")
        return self._last_error & 0xFFFFFFFF

    def SetLastError(self, args):
        """SetLastError emulation"""
        dwErrCode = args[0]
        log.debug(f"SetLastError({dwErrCode})")
        self._last_error = dwErrCode
        return 0

    # FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM) texts of common error codes
    SYSTEM_ERROR_MESSAGES = {
        0: "The operation completed successfully.",
        1: "Incorrect function.",
        2: "The system cannot find the file specified.",
        3: "The system cannot find the path specified.",
        4: "The system cannot open the file.",
        5: "Access is denied.",
        6: "The handle is invalid.",
        8: "Not enough memory resources are available to process this command.",
        14: "Not enough memory resources are available to complete this operation.",
        15: "The system cannot find the drive specified.",
        16: "The directory cannot be removed.",
        18: "There are no more files.",
        19: "The media is write protected.",
        21: "The device is not ready.",
        32: "The process cannot access the file because it is being used by another "
            "process.",
        33: "The process cannot access the file because another process has locked a "
            "portion of the file.",
        38: "Reached the end of the file.",
        39: "The disk is full.",
        50: "The request is not supported.",
        80: "The file exists.",
        87: "The parameter is incorrect.",
        112: "There is not enough space on the disk.",
        122: "The data area passed to a system call is too small.",
        123: "The filename, directory name, or volume label syntax is incorrect.",
        126: "The specified module could not be found.",
        127: "The specified procedure could not be found.",
        145: "The directory is not empty.",
        183: "Cannot create a file when that file already exists.",
        206: "The filename or extension is too long.",
        259: "No more data is available.",
        267: "The directory name is invalid.",
        1155: "No application is associated with the specified file for this operation.",
        1223: "The operation was canceled by the user.",
        1313: "A specified privilege does not exist.",
        1400: "Invalid window handle.",
        1813: "The specified resource type cannot be found in the image file.",
        1814: "The specified resource name cannot be found in the image file.",
    }

    FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x100
    FORMAT_MESSAGE_IGNORE_INSERTS = 0x200
    FORMAT_MESSAGE_FROM_STRING = 0x400
    FORMAT_MESSAGE_FROM_SYSTEM = 0x1000
    FORMAT_MESSAGE_ARGUMENT_ARRAY = 0x2000

    def _format_message_text(self, template, flags, arguments, wide):
        """Expand the %-sequences of a FormatMessage template"""
        if arguments and not flags & self.FORMAT_MESSAGE_ARGUMENT_ARRAY:
            arguments = self._read_u32(arguments)  # va_list *: the argument list

        def insert(match):
            index, spec = int(match.group(1)), match.group(2) or 's'
            if flags & self.FORMAT_MESSAGE_IGNORE_INSERTS or not arguments:
                return match.group(0)
            value = self._read_u32(arguments + 4 * (index - 1))
            conv = spec[-1]
            if conv in 'sS':
                return self._read_text(value, wide == (conv == 's')) if value else '(null)'
            if conv in 'cC':
                return chr(value & 0xFFFF)
            if conv in 'di':
                value = value - (1 << 32) if value & 0x80000000 else value
            try:
                return ('%' + re.sub(r'[lhIwL]|64|32', '', spec)) % value
            except (TypeError, ValueError):
                return str(value)

        out, pos = [], 0
        pattern = re.compile(r'%(?:([1-9][0-9]?)(?:!([^!]+)!)?|(.))', re.S)
        for match in pattern.finditer(template):
            out.append(template[pos:match.start()])
            pos = match.end()
            if match.group(1):
                out.append(insert(match))
                continue
            char = match.group(3)
            if char == '0':
                return ''.join(out)
            out.append({'n': '\r\n', 'r': '\r', 't': '\t'}.get(char, char))
        out.append(template[pos:])
        return ''.join(out)

    def FormatMessageA(self, args, wide=False):
        """FormatMessageA/W emulation - from a string or the system message table"""
        dwFlags, lpSource, dwMessageId, _, lpBuffer, nSize, Arguments = args[:7]
        if dwFlags & self.FORMAT_MESSAGE_FROM_STRING:
            template = self._read_text(lpSource, wide)
        elif dwFlags & self.FORMAT_MESSAGE_FROM_SYSTEM:
            message_id = dwMessageId
            if message_id & 0xFFFF0000 == 0x80070000:  # HRESULT_FROM_WIN32
                message_id &= 0xFFFF
            template = self.SYSTEM_ERROR_MESSAGES.get(message_id, {
                0x80004001: "Not implemented.", 0x80004005: "Unspecified error",
                0x8007000E: "Not enough memory resources are available to complete this "
                            "operation."}.get(dwMessageId))
            if template is None:
                log.debug(f"FormatMessage: no system message for {dwMessageId}")
                self._last_error = 317  # ERROR_MR_MID_NOT_FOUND
                return 0
            template += '\r\n'
        else:
            self._last_error = 317  # Message tables of other modules are not emulated
            return 0
        text = self._format_message_text(template, dwFlags, Arguments, wide)
        if dwFlags & 0xFF == 0xFF:  # FORMAT_MESSAGE_MAX_WIDTH_MASK: no line breaks
            text = text.replace('\r\n', ' ').rstrip(' ')
        units = self._text_units(text, wide)
        log.debug(f"FormatMessage{'W' if wide else 'A'}({dwMessageId}) -> {text!r}")
        if not lpBuffer:
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0
        if dwFlags & self.FORMAT_MESSAGE_ALLOCATE_BUFFER:
            unit_size = 2 if wide else 1
            buffer = self.emu.heap_alloc(max(len(units) + 1, nSize) * unit_size)
            if not buffer:
                self._last_error = 8  # ERROR_NOT_ENOUGH_MEMORY
                return 0
            self._write_units(buffer, units, wide)
            self._mem_write(lpBuffer, struct.pack('<I', buffer))
        else:
            if len(units) + 1 > nSize:
                self._last_error = 122  # ERROR_INSUFFICIENT_BUFFER
                return 0
            self._write_units(lpBuffer, units, wide)
        return len(units)

    def FormatMessageW(self, args):
        return self.FormatMessageA(args, wide=True)
    def VirtualAlloc(self, args):
        """VirtualAlloc emulation"""
        lpAddress = args[0]
        dwSize = args[1]
        flAllocationType = args[2]
        flProtect = args[3]

        log.debug(f"VirtualAlloc(0x{lpAddress:08x}, 0x{dwSize:x}, 0x{flAllocationType:x}, "
                  f"0x{flProtect:x})")

        MEM_COMMIT, MEM_RESERVE = 0x1000, 0x2000
        if dwSize == 0 or (flAllocationType & MEM_COMMIT and
                           not self.valid_protection(flProtect)):
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0
        reserve_only = not flAllocationType & MEM_COMMIT
        if lpAddress:
            for base, size in self.virtual_allocs.items():
                if base <= lpAddress and lpAddress + dwSize <= base + size:
                    # Committing pages of an existing reservation
                    start = lpAddress & ~0xFFF
                    end = (lpAddress + dwSize + 0xFFF) & ~0xFFF
                    if flAllocationType & MEM_COMMIT:
                        if not self._commit_pages(base, start, end):
                            self._last_error = 8  # ERROR_NOT_ENOUGH_MEMORY
                            return 0
                        self.set_protection(start, end, flProtect)
                    return start
            addr = self._map_virtual_at(lpAddress, dwSize, reserve_only)
            if not addr:
                self._last_error = 487  # ERROR_INVALID_ADDRESS
            else:
                self._protect_new_allocation(addr, flAllocationType, flProtect)
            return addr

        size = self.emu._align_size(dwSize, 0x1000)
        if size >= self.BIG_VIRTUAL_ALLOC:
            # Big blocks get their own region (host memory is committed lazily),
            # so they don't use up the heap. A reservation only takes address
            # space: Microsoft Jet reserves as much as the physical memory.
            addr = self._map_big_region(size, reserve_only)
            if addr:
                self._protect_new_allocation(addr, flAllocationType, flProtect)
                return addr
        addr = self.emu.heap_alloc(size, alignment=0x10000)  # allocation granularity
        if addr:
            self.virtual_allocs[addr] = size
            self._protect_new_allocation(addr, flAllocationType, flProtect)
        else:
            self._last_error = 8  # ERROR_NOT_ENOUGH_MEMORY
        return addr

    def _protect_new_allocation(self, base, allocation_type, protection):
        """Page protection of a new VirtualAlloc block: reserved pages (not
        committed) cannot be accessed; the committed ones get protection"""
        end = base + self.virtual_allocs[base]
        if not allocation_type & 0x1000:  # MEM_RESERVE only
            self.set_protection(base, end, 0)
        elif protection != self.PAGE_EXECUTE_READWRITE:
            self.set_protection(base, end, protection)

    BIG_VIRTUAL_ALLOC = 0x100000
    # Memory reported as "physical" besides the heap: what big allocations may use
    BIG_REGION_BUDGET = 0x40000000

    def _big_region_usage(self):
        """Bytes of the mapped VirtualAlloc regions in use: whole regions, but
        only the committed pages of reservations"""
        usage = 0
        for base in self.mapped_virtual_allocs:
            if base in self.virtual_allocs:
                pages = self.virtual_commits.get(base)
                usage += self.virtual_allocs[base] if pages is None else len(pages) * 0x1000
        return usage

    def _commit_pages(self, base, start, end):
        """Count the pages start..end of the region at base as committed; False
        if that is more than the budget of big regions allows"""
        pages = self.virtual_commits.get(base)
        if pages is None:
            return True  # Counted in full since it was allocated
        new = set(range((start - base) >> 12, (end - base) >> 12)) - pages
        if new and self._big_region_usage() + len(new) * 0x1000 > self.BIG_REGION_BUDGET:
            return False
        pages |= new
        return True

    def _map_big_region(self, size, reserve_only=False):
        """Map a big VirtualAlloc block at a free address; its base or 0"""
        emu = self.emu
        if not reserve_only and self._big_region_usage() + size > self.BIG_REGION_BUDGET:
            return 0
        base = emu._free_image_base(0, emu._align_size(size, 0x10000))
        if base is None:
            return 0
        try:
            emu.map_shared(base, size, UC_PROT_ALL)
        except UcError:
            return 0
        emu.mapped_regions.append((base, base + size))
        self.virtual_allocs[base] = size
        self.mapped_virtual_allocs.add(base)
        if reserve_only:
            self.virtual_commits[base] = set()
        return base

    def _map_virtual_at(self, address, size, reserve_only=False):
        """Map a new region at a requested address (rounded down to the 64K
        allocation granularity) if it is free; returns its base or 0"""
        emu = self.emu
        base = address & ~0xFFFF
        size = emu._align_size(address + size - base, 0x1000)
        end = base + size
        if base < 0x10000 or end > 0x80000000:
            return 0
        used = [(start, start + region[0]) for start, region in emu.shared_regions.items()]
        if any(base < stop and end > start for start, stop in used + emu._reserved_regions()):
            return 0
        try:
            emu.map_shared(base, size, UC_PROT_ALL)
        except UcError:
            return 0
        emu.mapped_regions.append((base, end))
        self.virtual_allocs[base] = size
        self.mapped_virtual_allocs.add(base)
        if reserve_only:
            self.virtual_commits[base] = set()
        return base

    def VirtualFree(self, args):
        """VirtualFree emulation"""
        lpAddress = args[0]
        dwSize = args[1]
        dwFreeType = args[2]
        log.debug(f"VirtualFree(0x{lpAddress:08x}, 0x{dwSize:x}, 0x{dwFreeType:x})")
        if dwFreeType & 0x8000:  # MEM_RELEASE
            size = self.virtual_allocs.pop(lpAddress, None)
            if size is None:
                self._last_error = 487  # ERROR_INVALID_ADDRESS
                return 0
            # Whatever reuses the memory gets it fully accessible
            self.set_protection(lpAddress, lpAddress + size, self.PAGE_EXECUTE_READWRITE)
            self.virtual_commits.pop(lpAddress, None)
            if lpAddress in self.mapped_virtual_allocs:
                self.mapped_virtual_allocs.discard(lpAddress)
                self.emu.unmap_shared(lpAddress, size)
                self.emu.mapped_regions.remove((lpAddress, lpAddress + size))
            else:
                self.emu.heap_free(lpAddress)
        elif dwFreeType & 0x4000:  # MEM_DECOMMIT: reserved again, zeroed when committed
            for base, size in self.virtual_allocs.items():
                if base <= lpAddress < base + size:
                    start = lpAddress & ~0xFFF
                    end = base + size if dwSize == 0 else min(
                        (lpAddress + dwSize + 0xFFF) & ~0xFFF, base + size)
                    pages = self.virtual_commits.get(base)
                    if pages is None:
                        self.emu.uc.mem_write(start, bytes(end - start))
                    else:
                        # Only committed pages hold data (a reservation may be huge)
                        first, last = (start - base) >> 12, (end - base) >> 12
                        for page in [p for p in pages if first <= p < last]:
                            self.emu.uc.mem_write(base + (page << 12), bytes(0x1000))
                            pages.discard(page)
                    self.set_protection(start, end, 0)
                    break
            else:
                self._last_error = 487
                return 0
        return 1

    def HeapCreate(self, args):
        """HeapCreate emulation"""
        log.debug("HeapCreate()")
        return self.get_next_handle()

    def HeapAlloc(self, args):
        """HeapAlloc emulation"""
        hHeap = args[0]
        dwFlags = args[1]
        dwBytes = args[2]

        addr = self.emu.heap_alloc(dwBytes)
        log.debug(f"HeapAlloc(0x{hHeap:x}, 0x{dwFlags:x}, 0x{dwBytes:x}) -> 0x{addr:08x}")
        return addr

    def HeapFree(self, args):
        """HeapFree emulation"""
        lpMem = args[2]
        log.debug(f"HeapFree(0x{lpMem:08x})")
        return 1 if not lpMem or self.emu.heap_free(lpMem) else 0

    def HeapReAlloc(self, args):
        """HeapReAlloc emulation"""
        dwFlags, lpMem, dwBytes = args[1], args[2], args[3]
        log.debug(f"HeapReAlloc(0x{lpMem:08x}, 0x{dwBytes:x}, flags=0x{dwFlags:x})")
        if not lpMem:
            return 0
        old_size = self.emu.heap_block_size(lpMem)
        if old_size is not None and self.emu.heap_resize(lpMem, dwBytes):
            addr = lpMem
        elif dwFlags & 0x10:  # HEAP_REALLOC_IN_PLACE_ONLY
            self._last_error = 8  # ERROR_NOT_ENOUGH_MEMORY
            return 0
        else:
            addr = self.emu.heap_alloc(dwBytes)
            if not addr:
                self._last_error = 8
                return 0
            copy_size = min(old_size, dwBytes) if old_size is not None else dwBytes
            self.emu.uc.mem_write(addr, bytes(self.emu.uc.mem_read(lpMem, copy_size)))
            self.emu.heap_free(lpMem)
        if dwFlags & 0x08 and old_size is not None and dwBytes > old_size:  # HEAP_ZERO_MEMORY
            self.emu.uc.mem_write(addr + old_size, b'\x00' * (dwBytes - old_size))
        return addr

    def HeapDestroy(self, args):
        """HeapDestroy emulation - HeapCreate heaps share the process heap"""
        return 1

    def _environment_block(self, wide):
        """Heap copy of the environment block: NAME=value\\0 ... \\0"""
        units = []
        for name, value in sorted(self.environment.items()):
            units += self._text_units(f"{name}={value}", wide) + [0]
        return self._alloc_units(units, wide)

    def GetEnvironmentStrings(self, args):
        """GetEnvironmentStrings(A) emulation"""
        return self._environment_block(False)

    def GetEnvironmentStringsA(self, args):
        return self._environment_block(False)

    def GetEnvironmentStringsW(self, args):
        """GetEnvironmentStringsW emulation"""
        return self._environment_block(True)

    def FreeEnvironmentStringsA(self, args):
        """FreeEnvironmentStringsA/W emulation"""
        if args[0]:
            self.emu.heap_free(args[0])
        return 1

    def FreeEnvironmentStringsW(self, args):
        return self.FreeEnvironmentStringsA(args)

    def GetCPInfo(self, args):
        """GetCPInfo emulation - MaxCharSize, DefaultChar and the lead bytes of
        a double-byte code page (CodePagesMixin._cp_info)"""
        codepage, lpCPInfo = args[0], args[1]
        info = self._cp_info(codepage)
        if info is None:
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0
        return 1 if self._mem_write(lpCPInfo, info[2]) else 0

    @staticmethod
    def _ctype1(ch):
        """CT_CTYPE1 flags of one character (None: not a character)"""
        if ch is None:
            return 0
        flags = 0
        if ch.isupper():
            flags |= 0x001  # C1_UPPER
        if ch.islower():
            flags |= 0x002  # C1_LOWER
        if ch in '0123456789':
            flags |= 0x004  # C1_DIGIT
        if ch in ' \t\n\v\f\r' or (ch.isspace() and ord(ch) > 0x7F):
            flags |= 0x008  # C1_SPACE
        if ch.isprintable() and not ch.isalnum() and not ch.isspace():
            flags |= 0x010  # C1_PUNCT
        if ord(ch) < 0x20 or ord(ch) == 0x7F:
            flags |= 0x020  # C1_CNTRL
        if ch in ' \t':
            flags |= 0x040  # C1_BLANK
        if ch in '0123456789abcdefABCDEF':
            flags |= 0x080  # C1_XDIGIT
        if ch.isalpha():
            flags |= 0x100  # C1_ALPHA
        return flags

    def _counted_units(self, address, count, wide):
        """cchSrc code units (-1: up to and including the terminator)"""
        if count == 0xFFFFFFFF:
            return self._read_units(address, wide) + [0]
        try:
            data = bytes(self.emu.uc.mem_read(address, count * (2 if wide else 1)))
        except UcError:
            return None
        return list(struct.unpack(f'<{count}H', data)) if wide else list(data)

    def _string_type_common(self, info_type, address, count, lpCharType, wide):
        units = self._counted_units(address, count, wide)
        if units is None or not lpCharType:
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0
        if info_type == 1:  # CT_CTYPE1
            types = [self._ctype1(chr(u) if wide else self._ansi_char(u)) for u in units]
        else:  # CT_CTYPE2 / CT_CTYPE3: no type information
            types = [0] * len(units)
        return 1 if self._mem_write(lpCharType, struct.pack(f'<{len(types)}H', *types)) else 0

    def GetStringTypeA(self, args):
        """GetStringTypeA emulation (Locale, dwInfoType, lpSrcStr, cchSrc, lpCharType)"""
        return self._string_type_common(args[1], args[2], args[3], args[4], False)

    def GetStringTypeW(self, args):
        """GetStringTypeW emulation (dwInfoType, lpSrcStr, cchSrc, lpCharType)"""
        return self._string_type_common(args[0], args[1], args[2], args[3], True)

    def LCMapStringA(self, args, wide=False):
        """LCMapStringA/W emulation - case mapping; sort keys are the code units"""
        flags, lpSrcStr, cchSrc, lpDestStr, cchDest = args[1], args[2], args[3], args[4], args[5]
        units = self._counted_units(lpSrcStr, cchSrc, wide)
        if units is None:
            self._last_error = 87
            return 0
        if flags & 0x400:  # LCMAP_SORTKEY: bytes, compared like strcmp
            key = bytes(self._pack_units(units, wide)).rstrip(b'\x00') + b'\x00'
            if cchDest:
                if cchDest < len(key):
                    self._last_error = 122  # ERROR_INSUFFICIENT_BUFFER
                    return 0
                self._mem_write(lpDestStr, key)
            return len(key)
        if flags & 0x300:  # LCMAP_LOWERCASE / LCMAP_UPPERCASE
            convert = str.lower if flags & 0x100 else str.upper
            if wide:
                mapped = [ord(convert(chr(u))) if len(convert(chr(u))) == 1 else u for u in units]
            else:
                mapped = []
                for u in units:
                    ch = self._ansi_char(u)
                    out = convert(ch).encode(config.ANSI_CODEPAGE, errors='replace') if ch else b''
                    mapped.append(out[0] if len(out) == 1 else u)
            units = mapped
        if cchDest:
            if cchDest < len(units):
                self._last_error = 122
                return 0
            self._write_units(lpDestStr, units, wide, terminate=False)
        return len(units)

    def LCMapStringW(self, args):
        return self.LCMapStringA(args, wide=True)

    def RtlUnwind(self, args):
        """RtlUnwind(TargetFrame, TargetIp, ExceptionRecord, ReturnValue)
        emulation - unwinds the SEH frames above TargetFrame (NULL: all of
        them): their __finally blocks and destructors run and their handlers
        are called with EXCEPTION_UNWINDING; then returns to the caller"""
        target_frame, record, return_value = args[0], args[2], args[3]
        self._global_unwind(target_frame, record)
        return return_value

    def UnhandledExceptionFilter(self, args):
        """UnhandledExceptionFilter emulation - runs the SetUnhandledExceptionFilter
        filter: EXCEPTION_CONTINUE_EXECUTION or EXCEPTION_EXECUTE_HANDLER (terminate)"""
        return 0xFFFFFFFF if self._top_level_filter(args[0]) == -1 else 1

    def TerminateProcess(self, args):
        """TerminateProcess emulation - only the current process can be terminated"""
        hProcess, exit_code = args[0], args[1]
        if hProcess != 0xFFFFFFFF:
            self._last_error = 5  # ERROR_ACCESS_DENIED
            return 0
        return self.ExitProcess([exit_code])
