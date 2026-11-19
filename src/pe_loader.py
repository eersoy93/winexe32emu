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

"""PE file loading and analysis"""

import pefile
try:
    import ordlookup  # installed with pefile: names of ordinal-only exports
except ImportError:
    ordlookup = None
from colorama import Fore, Style

from .logger import log


class PELoader:
    """PE file loader and analyzer"""

    # Imports by ordinal that the emulator implements by name: (dll, ordinal) -> name
    # (pefile's ordlookup knows oleaut32, ws2_32 and wsock32)
    KNOWN_ORDINALS = {('comctl32.dll', 17): 'InitCommonControls',
                      ('comctl32.dll', 6): 'CreateStatusWindowA'}

    @classmethod
    def ordinal_name(cls, dll_name, ordinal):
        """Name of a system DLL export known by its ordinal, or 'Ordinal_N'"""
        key = dll_name.lower()
        if '.' not in key:
            key += '.dll'
        name = cls.KNOWN_ORDINALS.get((key, ordinal))
        if name is None and ordlookup is not None:
            found = ordlookup.ordLookup(key.encode('ascii', 'replace'), ordinal)
            name = found.decode('ascii', 'replace') if found else None
        return name or f"Ordinal_{ordinal}"

    def __init__(self, filepath):
        self.filepath = filepath
        self.pe = None
        self.image_base = 0
        self.entry_point = 0
        self.subsystem = 0
        self.sections = []
        self.imports = {}
        self.exports = []

    def load(self):
        """Load and analyze PE file"""
        log.header("Loading PE File")
        log.info(f"The PE file: {self.filepath}")

        try:
            self.pe = pefile.PE(self.filepath)
            log.success("the PE file opened successfully!")
        except FileNotFoundError:
            log.error(f"The PE file not found: {self.filepath}")
            return False
        except pefile.PEFormatError as e:
            log.error(f"Invalid PE format: {e}")
            return False

        # Check PE type
        if self.pe.FILE_HEADER.Machine != 0x14c:  # IMAGE_FILE_MACHINE_I386
            log.error("This emulator only supports 32-bit (i386) PE files!")
            log.error(f"The PE file type: 0x{self.pe.FILE_HEADER.Machine:04x}")
            return False

        log.success("32-bit PE file verified!")

        # A .NET program (CLI header) needs the .NET runtime, not emulated
        directories = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY
        if len(directories) > 14 and directories[14].VirtualAddress:
            log.error("This is a .NET program: the .NET runtime is not emulated")
            return False

        # Get basic info
        if not self._parse_headers():
            return False
        self._parse_sections()
        self._parse_imports()
        self._parse_exports()

        return True

    def _parse_headers(self):
        """Parse PE header information"""
        log.header("PE Header Information")

        self.image_base = self.pe.OPTIONAL_HEADER.ImageBase
        self.entry_point = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        entry_point_va = self.image_base + self.entry_point

        log.info(f"Image Base: 0x{self.image_base:08x}")
        log.info(f"Entry Point (RVA): 0x{self.entry_point:08x}")
        log.info(f"Entry Point (VA): 0x{entry_point_va:08x}")
        log.info(f"Section Count: {self.pe.FILE_HEADER.NumberOfSections}")
        log.info(f"Image Size: 0x{self.pe.OPTIONAL_HEADER.SizeOfImage:08x}")
        log.info(f"Header Size: 0x{self.pe.OPTIONAL_HEADER.SizeOfHeaders:08x}")

        # Subsystem
        subsystem = self.pe.OPTIONAL_HEADER.Subsystem
        self.subsystem = subsystem
        subsystem_names = {
            1: "Native",
            2: "Windows GUI",
            3: "Windows Console",
        }
        subsystem_name = subsystem_names.get(subsystem, "Unknown")
        log.info(f"Subsystem: {subsystem_name} ({subsystem})")
        if subsystem_name == "Unknown":
            log.error(f"Unknown subsystem: {subsystem}")
            return False

        # Characteristics
        characteristics = self.pe.FILE_HEADER.Characteristics
        log.debug(f"Characteristics: 0x{characteristics:04x}")
        if characteristics & 0x0001:
            log.debug("  - RELOCS_STRIPPED")
        if characteristics & 0x0002:
            log.debug("  - EXECUTABLE_IMAGE")
        if characteristics & 0x0100:
            log.debug("  - 32BIT_MACHINE")
        if characteristics & 0x2000:
            log.debug("  - DLL")

        return True

    def _parse_sections(self):
        """Parse section information"""
        log.header("Sections")

        for section in self.pe.sections:
            # Packers give sections any bytes as names
            name = section.Name.rstrip(b'\x00').decode('latin-1')
            va = section.VirtualAddress
            vs = section.Misc_VirtualSize
            raw_size = section.SizeOfRawData
            raw_offset = section.PointerToRawData
            characteristics = section.Characteristics

            section_info = {
                'name': name,
                'virtual_address': va,
                'virtual_size': vs,
                'raw_size': raw_size,
                'raw_offset': raw_offset,
                'characteristics': characteristics,
                'data': section.get_data()
            }
            self.sections.append(section_info)

            # Determine permissions
            permissions = []
            if characteristics & 0x20000000:
                permissions.append("X")
            if characteristics & 0x40000000:
                permissions.append("R")
            if characteristics & 0x80000000:
                permissions.append("W")
            permissions_str = "".join(permissions) if permissions else "---"

            log.info(f"Section: {Fore.YELLOW}{name:8s}{Style.RESET_ALL} | "
                    f"VA: 0x{va:08x} | Size: 0x{vs:08x} | "
                    f"Raw: 0x{raw_offset:08x} | Perms: {permissions_str}")

    def _parse_imports(self):
        """Parse import table"""
        log.header("Import Table")

        if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            log.warning("Import table not found!")
            return

        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8')
            self.imports[dll_name] = []

            log.info(f"DLL: {Fore.GREEN}{dll_name}{Style.RESET_ALL}")

            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode('utf-8')
                else:
                    func_name = self.ordinal_name(dll_name, imp.ordinal)

                self.imports[dll_name].append({
                    'name': func_name,
                    'address': imp.address,
                    'ordinal': imp.ordinal
                })

                log.debug(f"  - {func_name} @ 0x{imp.address:08x}")

    def _parse_exports(self):
        """Parse export table"""
        log.header("Export Table")

        if not hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            log.info("Export table not found (normal for EXE)!")
            return

        for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                func_name = exp.name.decode('utf-8')
            else:
                func_name = f"Ordinal_{exp.ordinal}"

            self.exports.append({
                'name': func_name,
                'address': exp.address,
                'ordinal': exp.ordinal
            })

            log.info(f"Export: {func_name} @ 0x{exp.address:08x}")

    def has_relocations(self):
        """True if the image can be loaded at another base address"""
        return (hasattr(self.pe, 'DIRECTORY_ENTRY_BASERELOC') and
                not self.pe.FILE_HEADER.Characteristics & 0x0001)  # RELOCS_STRIPPED

    def rebase(self, new_base):
        """Apply base relocations so the image runs at new_base"""
        delta = new_base - self.image_base
        self.pe.relocate_image(new_base)
        self.image_base = new_base
        for section, info in zip(self.pe.sections, self.sections):
            info['data'] = bytes(section.get_data())
        for functions in self.imports.values():
            for func in functions:
                func['address'] += delta

    def get_section_by_rva(self, rva):
        """Find section by RVA address"""
        for section in self.sections:
            start = section['virtual_address']
            end = start + section['virtual_size']
            if start <= rva < end:
                return section
        return None

    def rva_to_offset(self, rva):
        """Convert RVA to file offset"""
        section = self.get_section_by_rva(rva)
        if section:
            return rva - section['virtual_address'] + section['raw_offset']
        return None

    def get_data_at_rva(self, rva, size):
        """Read data at RVA address"""
        section = self.get_section_by_rva(rva)
        if section:
            offset = rva - section['virtual_address']
            return section['data'][offset:offset+size]
        return None

    def print_summary(self):
        """PE file summary"""
        log.header("PE File Summary")
        log.success(f"Total {len(self.sections)} sections loaded!")
        log.success(f"Imports from {len(self.imports)} DLLs!")

        total_imports = sum(len(funcs) for funcs in self.imports.values())
        log.success(f"Total {total_imports} functions imported!")
        log.success(f"Total {len(self.exports)} exports!")
        log.info(f"Entry point: 0x{self.image_base + self.entry_point:08x}")

    def is_console_program(self):
        """True for IMAGE_SUBSYSTEM_WINDOWS_CUI EXEs (they start with a console)"""
        return self.subsystem == 3
