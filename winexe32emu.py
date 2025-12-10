#!/usr/bin/env python3
#
# Copyright 2025 Erdem Ersoy (eersoy93)
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

"""
Windows 32-bit EXE Emulator
PE file loading, analysis and CPU emulation module
Fake Windows GUI environment with Pygame
"""

import sys
import os
import struct
import pefile
import threading
import queue
import time
from colorama import init, Fore, Style

# Default EXE directory (c_drive/)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
C_DRIVE_PATH = os.path.join(SCRIPT_DIR, "c_drive")
from unicorn import *
from unicorn.x86_const import *
from capstone import *

# Pygame import (optional for GUI)
try:
    import pygame
    PYGAME_AVAILABLE = True
except ImportError:
    PYGAME_AVAILABLE = False
    print("Pygame not found, GUI support disabled!")

# Initialize Colorama
init(autoreset=True)


class DebugLogger:
    """Logger for colored debug output"""
    
    @staticmethod
    def info(msg):
        print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} {msg}")
    
    @staticmethod
    def success(msg):
        print(f"{Fore.GREEN}[OK]{Style.RESET_ALL} {msg}")
    
    @staticmethod
    def warning(msg):
        print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} {msg}")
    
    @staticmethod
    def error(msg):
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {msg}")
    
    @staticmethod
    def debug(msg):
        print(f"{Fore.MAGENTA}[DEBUG]{Style.RESET_ALL} {msg}")
    
    @staticmethod
    def header(msg):
        print(f"\n{Fore.WHITE}{Style.BRIGHT}{'='*60}")
        print(f" {msg}")
        print(f"{'='*60}{Style.RESET_ALL}")


log = DebugLogger()


class PELoader:
    """PE file loader and analyzer"""
    
    def __init__(self, filepath):
        self.filepath = filepath
        self.pe = None
        self.image_base = 0
        self.entry_point = 0
        self.sections = []
        self.imports = {}
        self.exports = []
        
    def load(self):
        """Load and analyze PE file"""
        log.header("Loading PE File")
        log.info(f"File: {self.filepath}")
        
        try:
            self.pe = pefile.PE(self.filepath)
            log.success("PE file opened successfully!")
        except FileNotFoundError:
            log.error(f"File not found: {self.filepath}")
            return False
        except pefile.PEFormatError as e:
            log.error(f"Invalid PE format: {e}")
            return False
        
        # Check PE type
        if self.pe.FILE_HEADER.Machine != 0x14c:  # IMAGE_FILE_MACHINE_I386
            log.error(f"This emulator only supports 32-bit (i386) PE files!")
            log.error(f"File type: 0x{self.pe.FILE_HEADER.Machine:04x}")
            return False
        
        log.success("32-bit PE file verified!")
        
        # Get basic info
        self._parse_headers()
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
        subsystem_names = {
            1: "Native",
            2: "Windows GUI",
            3: "Windows Console",
        }
        subsystem_name = subsystem_names.get(subsystem, f"Unknown ({subsystem})")
        log.info(f"Subsystem: {subsystem_name}")
        
        # Characteristics
        chars = self.pe.FILE_HEADER.Characteristics
        log.debug(f"Characteristics: 0x{chars:04x}")
        if chars & 0x0001:
            log.debug("  - RELOCS_STRIPPED")
        if chars & 0x0002:
            log.debug("  - EXECUTABLE_IMAGE")
        if chars & 0x0100:
            log.debug("  - 32BIT_MACHINE")
        if chars & 0x2000:
            log.debug("  - DLL")
    
    def _parse_sections(self):
        """Parse section information"""
        log.header("Sections")
        
        for section in self.pe.sections:
            name = section.Name.decode('utf-8').rstrip('\x00')
            va = section.VirtualAddress
            vs = section.Misc_VirtualSize
            raw_size = section.SizeOfRawData
            raw_offset = section.PointerToRawData
            chars = section.Characteristics
            
            section_info = {
                'name': name,
                'virtual_address': va,
                'virtual_size': vs,
                'raw_size': raw_size,
                'raw_offset': raw_offset,
                'characteristics': chars,
                'data': section.get_data()
            }
            self.sections.append(section_info)
            
            # Determine permissions
            perms = []
            if chars & 0x20000000:
                perms.append("X")
            if chars & 0x40000000:
                perms.append("R")
            if chars & 0x80000000:
                perms.append("W")
            perm_str = "".join(perms) if perms else "---"
            
            log.info(f"Section: {Fore.YELLOW}{name:8s}{Style.RESET_ALL} | "
                    f"VA: 0x{va:08x} | Size: 0x{vs:08x} | "
                    f"Raw: 0x{raw_offset:08x} | Perms: {perm_str}")
    
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
                    func_name = f"Ordinal_{imp.ordinal}"
                
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
            log.warning("Export table not found (normal for EXE)!")
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


class WinAPIHandler:
    """Windows API emulation"""
    
    # Windows message constants
    WM_CREATE = 0x0001
    WM_DESTROY = 0x0002
    WM_PAINT = 0x000F
    WM_CLOSE = 0x0010
    WM_QUIT = 0x0012
    WM_SHOWWINDOW = 0x0018
    WM_KEYDOWN = 0x0100
    WM_KEYUP = 0x0101
    WM_CHAR = 0x0102
    
    def __init__(self, emulator, gui=None):
        self.emu = emulator
        self.gui = gui  # PseudoWindowsGUI reference
        self.handles = {}
        self.next_handle = 0x1000
        self.console_output = []
        self.registered_classes = {}  # Registered window classes
        self.atoms = {}  # RegisterClass atoms
        self.next_atom = 0xC000
        
        # Message queue system
        self.message_queue = []
        self.painted_windows = set()  # Windows that received WM_PAINT
        self.quit_requested = False
        
        # MSVCRT global variable memory addresses (lazy init)
        self._fmode_addr = 0
        self._commode_addr = 0
        self._acmdln_addr = 0
        self._wcmdln_addr = 0
        self._environ_addr = 0
        self._wenviron_addr = 0
        self._argc = 0
        self._argv_addr = 0
        self._wargv_addr = 0
        
        # API name mapping (for functions starting with double underscore)
        self._api_map = {
            '__p__fmode': self.api__p__fmode,
            '__p__commode': self.api__p__commode,
            '__set_app_type': self.api__set_app_type,
            '__getmainargs': self.api__getmainargs,
            '__wgetmainargs': self.api__wgetmainargs,
            '__p___argc': self.api__p___argc,
            '__p___argv': self.api__p___argv,
            '__p___wargv': self.api__p___wargv,
            '__CxxFrameHandler3': self.api__CxxFrameHandler3,
            '__dllonexit': self.api__dllonexit,
            '__security_init_cookie': self.api__security_init_cookie,
            '__security_check_cookie': self.api__security_check_cookie,
            '__iob_func': self.api__iob_func,
            '__acrt_iob_func': self.api__acrt_iob_func,
        }
    
    def get_api_handler(self, func_name):
        """Find API handler"""
        # First search in mapping
        if func_name in self._api_map:
            return self._api_map[func_name]
        # Then search as normal attribute
        return getattr(self, func_name, None)
        
    def get_next_handle(self):
        """Create new handle"""
        handle = self.next_handle
        self.next_handle += 4
        return handle
    
    def read_string(self, address, max_len=256):
        """Read null-terminated string from memory"""
        try:
            data = self.emu.uc.mem_read(address, max_len)
            null_pos = data.find(b'\x00')
            if null_pos != -1:
                data = data[:null_pos]
            return data.decode('utf-8', errors='replace')
        except:
            return "<read error>"
    
    def read_wide_string(self, address, max_len=256):
        """Read wide string (UTF-16) from memory"""
        try:
            data = self.emu.uc.mem_read(address, max_len * 2)
            # Find null terminator
            for i in range(0, len(data), 2):
                if data[i:i+2] == b'\x00\x00':
                    data = data[:i]
                    break
            return data.decode('utf-16-le', errors='replace')
        except:
            return "<read error>"
    
    # KERNEL32.DLL functions
    def GetModuleHandleA(self, args):
        """GetModuleHandleA emulation"""
        lpModuleName = args[0]
        if lpModuleName == 0:
            log.debug(f"GetModuleHandleA(NULL) -> 0x{self.emu.pe_loader.image_base:08x}")
            return self.emu.pe_loader.image_base
        
        module_name = self.read_string(lpModuleName)
        log.debug(f"GetModuleHandleA(\"{module_name}\")")
        
        # Simple emulation - only main module
        return self.emu.pe_loader.image_base
    
    def GetModuleHandleW(self, args):
        """GetModuleHandleW emulation"""
        lpModuleName = args[0]
        if lpModuleName == 0:
            return self.emu.pe_loader.image_base
        
        module_name = self.read_wide_string(lpModuleName)
        log.debug(f"GetModuleHandleW(\"{module_name}\")")
        return self.emu.pe_loader.image_base
    
    def GetProcAddress(self, args):
        """GetProcAddress emulation"""
        hModule = args[0]
        lpProcName = args[1]
        
        if lpProcName < 0x10000:
            # Ordinal
            log.debug(f"GetProcAddress(0x{hModule:08x}, Ordinal_{lpProcName})")
        else:
            proc_name = self.read_string(lpProcName)
            log.debug(f"GetProcAddress(0x{hModule:08x}, \"{proc_name}\")")
        
        # Return not found
        return 0
    
    def ExitProcess(self, args):
        """ExitProcess emulation"""
        exit_code = args[0]
        log.success(f"ExitProcess({exit_code}) called - Terminating program...")
        self.emu.stop_emulation = True
        return 0
    
    def GetCommandLineA(self, args):
        """GetCommandLineA emulation"""
        log.debug("GetCommandLineA()")
        # Return memory address allocated for command line
        return self.emu.cmdline_addr
    
    def GetCommandLineW(self, args):
        """GetCommandLineW emulation"""
        log.debug("GetCommandLineW()")
        return self.emu.cmdline_wide_addr
    
    def AllocConsole(self, args):
        """AllocConsole emulation"""
        log.debug("AllocConsole() - Creating console window")
        # Assume console always exists in emulator
        return 1  # Success
    
    def FreeConsole(self, args):
        """FreeConsole emulation"""
        log.debug("FreeConsole()")
        return 1  # Success
    
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
        
        # Return fixed handle values
        if (nStdHandle & 0xFFFFFFFF) == 0xFFFFFFF6:
            return 0x10
        elif (nStdHandle & 0xFFFFFFFF) == 0xFFFFFFF5:
            return 0x11
        elif (nStdHandle & 0xFFFFFFFF) == 0xFFFFFFF4:
            return 0x12
        return 0
    
    def WriteFile(self, args):
        """WriteFile emulation"""
        hFile = args[0]
        lpBuffer = args[1]
        nNumberOfBytesToWrite = args[2]
        lpNumberOfBytesWritten = args[3]
        
        try:
            data = self.emu.uc.mem_read(lpBuffer, nNumberOfBytesToWrite)
            text = data.decode('utf-8', errors='replace')
            
            if hFile in [0x11]:  # stdout
                print(f"{Fore.YELLOW}[STDOUT]{Style.RESET_ALL} {text}", end='')
                self.console_output.append(text)
                # Write to GUI console
                if self.gui and self.gui.running:
                    self.gui.console_write_stdout(text)
            elif hFile in [0x12]:  # stderr
                print(f"{Fore.RED}[STDERR]{Style.RESET_ALL} {text}", end='')
                self.console_output.append(text)
                # Write to GUI console
                if self.gui and self.gui.running:
                    self.gui.console_write_stderr(text)
            
            # Write bytes written count to memory
            if lpNumberOfBytesWritten != 0:
                self.emu.uc.mem_write(lpNumberOfBytesWritten, 
                                      struct.pack('<I', nNumberOfBytesToWrite))
            
            log.debug(f"WriteFile(0x{hFile:x}, {nNumberOfBytesToWrite} bytes)")
            return 1  # Success
        except Exception as e:
            log.error(f"WriteFile error: {e}")
            return 0
    
    def WriteConsoleA(self, args):
        """WriteConsoleA emulation"""
        hConsoleOutput = args[0]
        lpBuffer = args[1]
        nNumberOfCharsToWrite = args[2]
        lpNumberOfCharsWritten = args[3]
        
        try:
            data = self.emu.uc.mem_read(lpBuffer, nNumberOfCharsToWrite)
            text = data.decode('utf-8', errors='replace')
            print(f"{Fore.YELLOW}[CONSOLE]{Style.RESET_ALL} {text}", end='')
            self.console_output.append(text)
            
            # Write to GUI console
            if self.gui and self.gui.running:
                self.gui.console_write_stdout(text)
            
            if lpNumberOfCharsWritten != 0:
                self.emu.uc.mem_write(lpNumberOfCharsWritten,
                                      struct.pack('<I', nNumberOfCharsToWrite))
            return 1
        except Exception as e:
            log.error(f"WriteConsoleA error: {e}")
            return 0
    
    def GetLastError(self, args):
        """GetLastError emulation"""
        log.debug("GetLastError() -> 0")
        return 0
    
    def SetLastError(self, args):
        """SetLastError emulation"""
        dwErrCode = args[0]
        log.debug(f"SetLastError({dwErrCode})")
        return 0
    
    def VirtualAlloc(self, args):
        """VirtualAlloc emulation"""
        lpAddress = args[0]
        dwSize = args[1]
        flAllocationType = args[2]
        flProtect = args[3]
        
        log.debug(f"VirtualAlloc(0x{lpAddress:08x}, 0x{dwSize:x}, 0x{flAllocationType:x}, 0x{flProtect:x})")
        
        # Simple heap allocator
        addr = self.emu.heap_alloc(dwSize)
        return addr
    
    def VirtualFree(self, args):
        """VirtualFree emulation"""
        lpAddress = args[0]
        dwSize = args[1]
        dwFreeType = args[2]
        log.debug(f"VirtualFree(0x{lpAddress:08x}, 0x{dwSize:x}, 0x{dwFreeType:x})")
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
        log.debug("HeapFree()")
        return 1
    
    def GetProcessHeap(self, args):
        """GetProcessHeap emulation"""
        log.debug("GetProcessHeap()")
        return 0x00140000  # Fixed heap handle
    
    def GetCurrentProcess(self, args):
        """GetCurrentProcess emulation"""
        log.debug("GetCurrentProcess()")
        return 0xFFFFFFFF  # Pseudo handle
    
    def GetCurrentProcessId(self, args):
        """GetCurrentProcessId emulation"""
        log.debug("GetCurrentProcessId()")
        return 1234  # Fixed PID
    
    def GetCurrentThreadId(self, args):
        """GetCurrentThreadId emulation"""
        log.debug("GetCurrentThreadId()")
        return 5678  # Fixed TID
    
    def GetTickCount(self, args):
        """GetTickCount emulation"""
        import time
        ticks = int(time.time() * 1000) & 0xFFFFFFFF
        log.debug(f"GetTickCount() -> {ticks}")
        return ticks
    
    def QueryPerformanceCounter(self, args):
        """QueryPerformanceCounter emulation"""
        lpPerformanceCount = args[0]
        import time
        count = int(time.time() * 1000000)
        
        if lpPerformanceCount != 0:
            self.emu.uc.mem_write(lpPerformanceCount, struct.pack('<Q', count))
        
        log.debug(f"QueryPerformanceCounter()")
        return 1
    
    def GetSystemTimeAsFileTime(self, args):
        """GetSystemTimeAsFileTime emulation"""
        lpSystemTimeAsFileTime = args[0]
        import time
        # Windows FILETIME: 100-nanosecond intervals since January 1, 1601
        # Unix time: seconds since January 1, 1970
        # Difference: 11644473600 seconds
        filetime = int((time.time() + 11644473600) * 10000000)
        
        if lpSystemTimeAsFileTime != 0:
            self.emu.uc.mem_write(lpSystemTimeAsFileTime, struct.pack('<Q', filetime))
        
        log.debug("GetSystemTimeAsFileTime()")
        return 0
    
    def IsDebuggerPresent(self, args):
        """IsDebuggerPresent emulation"""
        log.debug("IsDebuggerPresent() -> 0")
        return 0  # No debugger
    
    def GetVersion(self, args):
        """GetVersion emulation - Returns Windows Vista SP2"""
        log.debug("GetVersion()")
        # Windows Vista SP2: Major=6, Minor=0, Build=6002
        # Format: 0xMMMMBBBB where M=minor|major, B=build
        # Low word: Major (low byte) | Minor (high byte) = 0x0006
        # High word: Build number = 6002 = 0x1772
        return 0x17720006  # Build 6002, Version 6.0
    
    def GetVersionExA(self, args):
        """GetVersionExA emulation - Windows Vista SP2"""
        lpVersionInfo = args[0]
        log.debug(f"GetVersionExA(0x{lpVersionInfo:08x})")
        
        # Fill OSVERSIONINFOA or OSVERSIONINFOEXA structure
        try:
            # Read dwOSVersionInfoSize
            size = struct.unpack('<I', self.emu.uc.mem_read(lpVersionInfo, 4))[0]
            
            # Windows Vista SP2 info
            # OSVERSIONINFOA: 148 bytes
            # OSVERSIONINFOEXA: 156 bytes
            if size >= 156:
                # OSVERSIONINFOEXA
                version_info = struct.pack('<IIIII',
                    156,   # dwOSVersionInfoSize
                    6,     # dwMajorVersion (Vista)
                    0,     # dwMinorVersion
                    6002,  # dwBuildNumber (SP2)
                    2,     # dwPlatformId (VER_PLATFORM_WIN32_NT)
                )
                # szCSDVersion[128] - "Service Pack 2"
                csd_version = b'Service Pack 2' + b'\x00' * (128 - 14)
                # OSVERSIONINFOEXA additional fields
                ex_fields = struct.pack('<HHBBBB',
                    2,     # wServicePackMajor
                    0,     # wServicePackMinor
                    0,     # wSuiteMask
                    1,     # wProductType (VER_NT_WORKSTATION)
                    0,     # wReserved
                    0,     # padding
                )
                self.emu.uc.mem_write(lpVersionInfo, version_info + csd_version + ex_fields)
            else:
                # OSVERSIONINFOA
                version_info = struct.pack('<IIIII',
                    148,   # dwOSVersionInfoSize
                    6,     # dwMajorVersion (Vista)
                    0,     # dwMinorVersion
                    6002,  # dwBuildNumber (SP2)
                    2,     # dwPlatformId (VER_PLATFORM_WIN32_NT)
                )
                # szCSDVersion[128] - "Service Pack 2"
                csd_version = b'Service Pack 2' + b'\x00' * (128 - 14)
                self.emu.uc.mem_write(lpVersionInfo, version_info + csd_version)
            return 1
        except Exception as e:
            log.error(f"GetVersionExA error: {e}")
            return 0
    
    def GetVersionExW(self, args):
        """GetVersionExW emulation - Windows Vista SP2 (Unicode)"""
        lpVersionInfo = args[0]
        log.debug(f"GetVersionExW(0x{lpVersionInfo:08x})")
        
        try:
            # Read dwOSVersionInfoSize
            size = struct.unpack('<I', self.emu.uc.mem_read(lpVersionInfo, 4))[0]
            
            # Windows Vista SP2 info
            # OSVERSIONINFOW: 276 bytes (128 WCHAR = 256 bytes for szCSDVersion)
            # OSVERSIONINFOEXW: 284 bytes
            if size >= 284:
                # OSVERSIONINFOEXW
                version_info = struct.pack('<IIIII',
                    284,   # dwOSVersionInfoSize
                    6,     # dwMajorVersion (Vista)
                    0,     # dwMinorVersion
                    6002,  # dwBuildNumber (SP2)
                    2,     # dwPlatformId (VER_PLATFORM_WIN32_NT)
                )
                # szCSDVersion[128] WCHAR - "Service Pack 2"
                csd_version = 'Service Pack 2'.encode('utf-16-le') + b'\x00' * (256 - 28)
                # OSVERSIONINFOEXW additional fields
                ex_fields = struct.pack('<HHBBBB',
                    2,     # wServicePackMajor
                    0,     # wServicePackMinor
                    0,     # wSuiteMask
                    1,     # wProductType (VER_NT_WORKSTATION)
                    0,     # wReserved
                    0,     # padding
                )
                self.emu.uc.mem_write(lpVersionInfo, version_info + csd_version + ex_fields)
            else:
                # OSVERSIONINFOW
                version_info = struct.pack('<IIIII',
                    276,   # dwOSVersionInfoSize
                    6,     # dwMajorVersion (Vista)
                    0,     # dwMinorVersion
                    6002,  # dwBuildNumber (SP2)
                    2,     # dwPlatformId (VER_PLATFORM_WIN32_NT)
                )
                # szCSDVersion[128] WCHAR
                csd_version = 'Service Pack 2'.encode('utf-16-le') + b'\x00' * (256 - 28)
                self.emu.uc.mem_write(lpVersionInfo, version_info + csd_version)
            return 1
        except Exception as e:
            log.error(f"GetVersionExW error: {e}")
            return 0

    # ==================== ADDITIONAL APIs ====================
    
    def SetErrorMode(self, args):
        """SetErrorMode emulation"""
        uMode = args[0]
        log.debug(f"SetErrorMode(0x{uMode:x})")
        return 0  # Previous mode
    
    def GetModuleFileNameA(self, args):
        """GetModuleFileNameA emulation"""
        hModule = args[0]
        lpFilename = args[1]
        nSize = args[2]
        
        # Return file path for main module
        filepath = self.emu.pe_loader.filepath
        if len(filepath) >= nSize:
            filepath = filepath[:nSize-1]
        
        filepath_bytes = filepath.encode('utf-8') + b'\x00'
        self.emu.uc.mem_write(lpFilename, filepath_bytes)
        
        log.debug(f"GetModuleFileNameA(0x{hModule:x}) -> \"{filepath}\"")
        return len(filepath)
    
    def GetModuleFileNameW(self, args):
        """GetModuleFileNameW emulation"""
        hModule = args[0]
        lpFilename = args[1]
        nSize = args[2]
        
        filepath = self.emu.pe_loader.filepath
        if len(filepath) >= nSize:
            filepath = filepath[:nSize-1]
        
        filepath_bytes = filepath.encode('utf-16-le') + b'\x00\x00'
        self.emu.uc.mem_write(lpFilename, filepath_bytes)
        
        log.debug(f"GetModuleFileNameW(0x{hModule:x}) -> \"{filepath}\"")
        return len(filepath)
    
    def LoadLibraryA(self, args):
        """LoadLibraryA emulation"""
        lpLibFileName = args[0]
        lib_name = self.read_string(lpLibFileName)
        log.debug(f"LoadLibraryA(\"{lib_name}\")")
        
        # Return fake handle
        handle = self.get_next_handle()
        self.handles[handle] = {'type': 'module', 'name': lib_name}
        return handle
    
    def LoadLibraryW(self, args):
        """LoadLibraryW emulation"""
        lpLibFileName = args[0]
        lib_name = self.read_wide_string(lpLibFileName)
        log.debug(f"LoadLibraryW(\"{lib_name}\")")
        
        handle = self.get_next_handle()
        self.handles[handle] = {'type': 'module', 'name': lib_name}
        return handle
    
    def LoadLibraryExA(self, args):
        """LoadLibraryExA emulation"""
        lpLibFileName = args[0]
        hFile = args[1]
        dwFlags = args[2]
        
        lib_name = self.read_string(lpLibFileName)
        log.debug(f"LoadLibraryExA(\"{lib_name}\", 0x{dwFlags:x})")
        
        handle = self.get_next_handle()
        self.handles[handle] = {'type': 'module', 'name': lib_name}
        return handle
    
    def LoadLibraryExW(self, args):
        """LoadLibraryExW emulation"""
        lpLibFileName = args[0]
        hFile = args[1]
        dwFlags = args[2]
        
        lib_name = self.read_wide_string(lpLibFileName)
        log.debug(f"LoadLibraryExW(\"{lib_name}\", 0x{dwFlags:x})")
        
        handle = self.get_next_handle()
        self.handles[handle] = {'type': 'module', 'name': lib_name}
        return handle
    
    def FreeLibrary(self, args):
        """FreeLibrary emulation"""
        hLibModule = args[0]
        log.debug(f"FreeLibrary(0x{hLibModule:x})")
        
        if hLibModule in self.handles:
            del self.handles[hLibModule]
        return 1
    
    def GetSystemDirectoryA(self, args):
        """GetSystemDirectoryA emulation"""
        lpBuffer = args[0]
        uSize = args[1]
        
        sys_dir = "C:\\Windows\\System32"
        if len(sys_dir) < uSize:
            self.emu.uc.mem_write(lpBuffer, sys_dir.encode('utf-8') + b'\x00')
        
        log.debug(f"GetSystemDirectoryA() -> \"{sys_dir}\"")
        return len(sys_dir)
    
    def GetWindowsDirectoryA(self, args):
        """GetWindowsDirectoryA emulation"""
        lpBuffer = args[0]
        uSize = args[1]
        
        win_dir = "C:\\Windows"
        if len(win_dir) < uSize:
            self.emu.uc.mem_write(lpBuffer, win_dir.encode('utf-8') + b'\x00')
        
        log.debug(f"GetWindowsDirectoryA() -> \"{win_dir}\"")
        return len(win_dir)
    
    def GetTempPathA(self, args):
        """GetTempPathA emulation"""
        nBufferLength = args[0]
        lpBuffer = args[1]
        
        temp_path = "C:\\Windows\\Temp\\"
        if len(temp_path) < nBufferLength:
            self.emu.uc.mem_write(lpBuffer, temp_path.encode('utf-8') + b'\x00')
        
        log.debug(f"GetTempPathA() -> \"{temp_path}\"")
        return len(temp_path)
    
    def lstrlenA(self, args):
        """lstrlenA emulation"""
        lpString = args[0]
        
        if lpString == 0:
            return 0
        
        s = self.read_string(lpString)
        log.debug(f"lstrlenA(\"{s[:32]}...\") -> {len(s)}")
        return len(s)
    
    def lstrlenW(self, args):
        """lstrlenW emulation"""
        lpString = args[0]
        
        if lpString == 0:
            return 0
        
        s = self.read_wide_string(lpString)
        log.debug(f"lstrlenW() -> {len(s)}")
        return len(s)
    
    def GetStartupInfoA(self, args):
        """GetStartupInfoA emulation"""
        lpStartupInfo = args[0]
        log.debug(f"GetStartupInfoA(0x{lpStartupInfo:08x})")
        
        # Fill STARTUPINFOA structure (68 bytes)
        try:
            startup_info = struct.pack('<IIIIIIIIIIIIHHIIII',
                68,   # cb (structure size)
                0,    # lpReserved
                0,    # lpDesktop
                0,    # lpTitle
                0,    # dwX
                0,    # dwY
                800,  # dwXSize
                600,  # dwYSize
                80,   # dwXCountChars
                25,   # dwYCountChars
                0,    # dwFillAttribute
                0,    # dwFlags
                1,    # wShowWindow (SW_SHOWNORMAL)
                0,    # cbReserved2
                0,    # lpReserved2
                0,    # hStdInput
                0,    # hStdOutput
                0,    # hStdError
            )
            self.emu.uc.mem_write(lpStartupInfo, startup_info)
        except:
            pass
        return 0
    
    def GetStartupInfoW(self, args):
        """GetStartupInfoW emulation"""
        return self.GetStartupInfoA(args)
    
    def GetSystemDirectoryA(self, args):
        """GetSystemDirectoryA emulation"""
        lpBuffer = args[0]
        uSize = args[1]
        
        sys_dir = "C:\\Windows\\System32"
        if len(sys_dir) < uSize:
            self.emu.uc.mem_write(lpBuffer, sys_dir.encode('utf-8') + b'\x00')
        
        log.debug(f"GetSystemDirectoryA() -> \"{sys_dir}\"")
        return len(sys_dir)
    
    def GetSystemDirectoryW(self, args):
        """GetSystemDirectoryW emulation"""
        lpBuffer = args[0]
        uSize = args[1]
        
        sys_dir = "C:\\Windows\\System32"
        if len(sys_dir) < uSize:
            self.emu.uc.mem_write(lpBuffer, sys_dir.encode('utf-16-le') + b'\x00\x00')
        
        log.debug(f"GetSystemDirectoryW() -> \"{sys_dir}\"")
        return len(sys_dir)
    
    def GetWindowsDirectoryA(self, args):
        """GetWindowsDirectoryA emulation"""
        lpBuffer = args[0]
        uSize = args[1]
        
        win_dir = "C:\\Windows"
        if len(win_dir) < uSize:
            self.emu.uc.mem_write(lpBuffer, win_dir.encode('utf-8') + b'\x00')
        
        log.debug(f"GetWindowsDirectoryA() -> \"{win_dir}\"")
        return len(win_dir)
    
    def GetWindowsDirectoryW(self, args):
        """GetWindowsDirectoryW emulation"""
        lpBuffer = args[0]
        uSize = args[1]
        
        win_dir = "C:\\Windows"
        if len(win_dir) < uSize:
            self.emu.uc.mem_write(lpBuffer, win_dir.encode('utf-16-le') + b'\x00\x00')
        
        log.debug(f"GetWindowsDirectoryW() -> \"{win_dir}\"")
        return len(win_dir)

    def lstrcpyA(self, args):
        """lstrcpyA emulation"""
        lpString1 = args[0]
        lpString2 = args[1]
        
        src = self.read_string(lpString2)
        self.emu.uc.mem_write(lpString1, src.encode('utf-8') + b'\x00')
        
        log.debug(f"lstrcpyA(0x{lpString1:08x}, \"{src[:32]}...\")")
        return lpString1
    
    def lstrcpynA(self, args):
        """lstrcpynA emulation"""
        lpString1 = args[0]
        lpString2 = args[1]
        iMaxLength = args[2]
        
        src = self.read_string(lpString2, iMaxLength)
        if len(src) >= iMaxLength:
            src = src[:iMaxLength-1]
        
        self.emu.uc.mem_write(lpString1, src.encode('utf-8') + b'\x00')
        
        log.debug(f"lstrcpynA(0x{lpString1:08x}, \"{src[:32]}...\", {iMaxLength})")
        return lpString1
    
    def lstrcatA(self, args):
        """lstrcatA emulation"""
        lpString1 = args[0]
        lpString2 = args[1]
        
        dst = self.read_string(lpString1)
        src = self.read_string(lpString2)
        result = dst + src
        
        self.emu.uc.mem_write(lpString1, result.encode('utf-8') + b'\x00')
        
        log.debug(f"lstrcatA() -> \"{result[:32]}...\"")
        return lpString1
    
    def lstrcmpA(self, args):
        """lstrcmpA emulation"""
        lpString1 = args[0]
        lpString2 = args[1]
        
        s1 = self.read_string(lpString1)
        s2 = self.read_string(lpString2)
        
        if s1 < s2:
            result = -1
        elif s1 > s2:
            result = 1
        else:
            result = 0
        
        log.debug(f"lstrcmpA(\"{s1[:16]}\", \"{s2[:16]}\") -> {result}")
        return result & 0xFFFFFFFF
    
    def lstrcmpiA(self, args):
        """lstrcmpiA emulation (case-insensitive)"""
        lpString1 = args[0]
        lpString2 = args[1]
        
        s1 = self.read_string(lpString1).lower()
        s2 = self.read_string(lpString2).lower()
        
        if s1 < s2:
            result = -1
        elif s1 > s2:
            result = 1
        else:
            result = 0
        
        log.debug(f"lstrcmpiA(\"{s1[:16]}\", \"{s2[:16]}\") -> {result}")
        return result & 0xFFFFFFFF
    
    def GlobalAlloc(self, args):
        """GlobalAlloc emulation"""
        uFlags = args[0]
        dwBytes = args[1]
        
        addr = self.emu.heap_alloc(dwBytes)
        
        # Zero memory if GMEM_ZEROINIT (0x0040) flag is set
        if uFlags & 0x0040:
            self.emu.uc.mem_write(addr, b'\x00' * dwBytes)
        
        log.debug(f"GlobalAlloc(0x{uFlags:x}, {dwBytes}) -> 0x{addr:08x}")
        return addr
    
    def GlobalFree(self, args):
        """GlobalFree emulation"""
        hMem = args[0]
        log.debug(f"GlobalFree(0x{hMem:08x})")
        return 0  # Success
    
    def GlobalLock(self, args):
        """GlobalLock emulation"""
        hMem = args[0]
        log.debug(f"GlobalLock(0x{hMem:08x})")
        return hMem  # Return same address
    
    def GlobalUnlock(self, args):
        """GlobalUnlock emulation"""
        hMem = args[0]
        log.debug(f"GlobalUnlock(0x{hMem:08x})")
        return 1
    
    def LocalAlloc(self, args):
        """LocalAlloc emulation"""
        return self.GlobalAlloc(args)
    
    def LocalFree(self, args):
        """LocalFree emulation"""
        return self.GlobalFree(args)
    
    def CloseHandle(self, args):
        """CloseHandle emulation"""
        hObject = args[0]
        log.debug(f"CloseHandle(0x{hObject:x})")
        
        if hObject in self.handles:
            del self.handles[hObject]
        return 1
    
    def Sleep(self, args):
        """Sleep emulation"""
        dwMilliseconds = args[0]
        log.debug(f"Sleep({dwMilliseconds}ms)")
        # We don't actually wait
        return 0
    
    def GetFileAttributesA(self, args):
        """GetFileAttributesA emulation"""
        lpFileName = args[0]
        filename = self.read_string(lpFileName)
        log.debug(f"GetFileAttributesA(\"{filename}\")")
        
        # File not found
        return 0xFFFFFFFF  # INVALID_FILE_ATTRIBUTES
    
    def CreateFileA(self, args):
        """CreateFileA emulation"""
        lpFileName = args[0]
        dwDesiredAccess = args[1]
        dwShareMode = args[2]
        lpSecurityAttributes = args[3]
        dwCreationDisposition = args[4]
        dwFlagsAndAttributes = args[5]
        hTemplateFile = args[6]
        
        filename = self.read_string(lpFileName)
        log.debug(f"CreateFileA(\"{filename}\", 0x{dwDesiredAccess:x})")
        
        # Return fake handle
        handle = self.get_next_handle()
        self.handles[handle] = {'type': 'file', 'name': filename}
        return handle
    
    def GetFileSize(self, args):
        """GetFileSize emulation"""
        hFile = args[0]
        lpFileSizeHigh = args[1]
        
        log.debug(f"GetFileSize(0x{hFile:x})")
        
        if lpFileSizeHigh != 0:
            self.emu.uc.mem_write(lpFileSizeHigh, struct.pack('<I', 0))
        
        return 0  # File size 0
    
    def ReadFile(self, args):
        """ReadFile emulation"""
        hFile = args[0]
        lpBuffer = args[1]
        nNumberOfBytesToRead = args[2]
        lpNumberOfBytesRead = args[3]
        
        log.debug(f"ReadFile(0x{hFile:x}, {nNumberOfBytesToRead} bytes)")
        
        # 0 bytes read
        if lpNumberOfBytesRead != 0:
            self.emu.uc.mem_write(lpNumberOfBytesRead, struct.pack('<I', 0))
        
        return 1
    
    def ReadConsoleA(self, args):
        """ReadConsoleA emulation - Read user input from console"""
        hConsoleInput = args[0]
        lpBuffer = args[1]
        nNumberOfCharsToRead = args[2]
        lpNumberOfCharsRead = args[3]
        # pInputControl = args[4]  # optional, usually NULL
        
        log.debug(f"ReadConsoleA(0x{hConsoleInput:x}, max {nNumberOfCharsToRead} chars)")
        
        # Get user input from GUI (thread-safe)
        if self.gui:
            # Call GUI's request_console_input method (blocking)
            user_input = self.gui.request_console_input()
            if user_input is None:
                user_input = ""
            
            # Add line ending
            user_input += "\r\n"
            
            # Limit to maximum character count
            if len(user_input) > nNumberOfCharsToRead:
                user_input = user_input[:nNumberOfCharsToRead]
            
            # Write to buffer
            self.emu.uc.mem_write(lpBuffer, user_input.encode('cp1254', errors='replace'))
            
            # Write number of characters read
            if lpNumberOfCharsRead != 0:
                self.emu.uc.mem_write(lpNumberOfCharsRead, struct.pack('<I', len(user_input)))
            
            log.debug(f"ReadConsoleA: '{user_input.strip()}' read ({len(user_input)} chars)")
            return 1
        
        # Return empty string if no GUI
        if lpNumberOfCharsRead != 0:
            self.emu.uc.mem_write(lpNumberOfCharsRead, struct.pack('<I', 0))
        return 1
    
    def GetEnvironmentVariableA(self, args):
        """GetEnvironmentVariableA emulation"""
        lpName = args[0]
        lpBuffer = args[1]
        nSize = args[2]
        
        name = self.read_string(lpName)
        log.debug(f"GetEnvironmentVariableA(\"{name}\")")
        
        # Simple environment variables
        env_vars = {
            'PATH': 'C:\\Windows\\System32;C:\\Windows',
            'TEMP': 'C:\\Windows\\Temp',
            'TMP': 'C:\\Windows\\Temp',
            'WINDIR': 'C:\\Windows',
            'SYSTEMROOT': 'C:\\Windows',
            'COMSPEC': 'C:\\Windows\\System32\\cmd.exe',
        }
        
        value = env_vars.get(name.upper(), '')
        if value and lpBuffer != 0 and len(value) < nSize:
            self.emu.uc.mem_write(lpBuffer, value.encode('utf-8') + b'\x00')
            return len(value)
        
        return 0  # Not found
    
    def ExpandEnvironmentStringsA(self, args):
        """ExpandEnvironmentStringsA emulation"""
        lpSrc = args[0]
        lpDst = args[1]
        nSize = args[2]
        
        src = self.read_string(lpSrc)
        log.debug(f"ExpandEnvironmentStringsA(\"{src[:32]}...\")")
        
        # Simple variable expansion
        result = src
        result = result.replace('%WINDIR%', 'C:\\Windows')
        result = result.replace('%SYSTEMROOT%', 'C:\\Windows')
        result = result.replace('%TEMP%', 'C:\\Windows\\Temp')
        result = result.replace('%TMP%', 'C:\\Windows\\Temp')
        
        if lpDst != 0 and len(result) < nSize:
            self.emu.uc.mem_write(lpDst, result.encode('utf-8') + b'\x00')
        
        return len(result) + 1
    
    # USER32.DLL APIs
    def GetSystemMetrics(self, args):
        """GetSystemMetrics emulation"""
        nIndex = args[0]
        
        metrics = {
            0: 1920,   # SM_CXSCREEN
            1: 1080,   # SM_CYSCREEN
            2: 20,     # SM_CXVSCROLL
            3: 20,     # SM_CYHSCROLL
            4: 25,     # SM_CYCAPTION
            5: 1,      # SM_CXBORDER
            6: 1,      # SM_CYBORDER
            80: 1,     # SM_CMONITORS
        }
        
        result = metrics.get(nIndex, 0)
        log.debug(f"GetSystemMetrics({nIndex}) -> {result}")
        return result
    
    def MessageBoxA(self, args):
        """MessageBoxA emulation"""
        hWnd = args[0]
        lpText = args[1]
        lpCaption = args[2]
        uType = args[3]
        
        text = self.read_string(lpText) if lpText else ""
        caption = self.read_string(lpCaption) if lpCaption else ""
        
        log.info(f"{Fore.YELLOW}[MESSAGEBOX]{Style.RESET_ALL} {caption}: {text}")
        
        # Show MessageBox if GUI exists
        if self.gui and self.gui.running:
            return self.gui.show_messagebox(caption, text, uType)
        
        return 1  # IDOK
    
    def MessageBoxW(self, args):
        """MessageBoxW emulation (Unicode)"""
        hWnd = args[0]
        lpText = args[1]
        lpCaption = args[2]
        uType = args[3]
        
        text = self.read_wide_string(lpText) if lpText else ""
        caption = self.read_wide_string(lpCaption) if lpCaption else ""
        
        log.info(f"{Fore.YELLOW}[MESSAGEBOX]{Style.RESET_ALL} {caption}: {text}")
        
        if self.gui and self.gui.running:
            return self.gui.show_messagebox(caption, text, uType)
        
        return 1  # IDOK
    
    def RegisterClassA(self, args):
        """RegisterClassA emulation"""
        lpWndClass = args[0]
        
        # Read WNDCLASS structure
        try:
            wndclass_data = self.emu.uc.mem_read(lpWndClass, 40)
            style = struct.unpack("<I", wndclass_data[0:4])[0]
            lpfnWndProc = struct.unpack("<I", wndclass_data[4:8])[0]
            hInstance = struct.unpack("<I", wndclass_data[20:24])[0]
            lpszClassName = struct.unpack("<I", wndclass_data[36:40])[0]
            
            class_name = self.read_string(lpszClassName)
            
            atom = self.next_atom
            self.next_atom += 1
            
            self.registered_classes[class_name] = {
                'atom': atom,
                'style': style,
                'wndproc': lpfnWndProc,
                'hInstance': hInstance
            }
            self.atoms[atom] = class_name
            
            log.debug(f"RegisterClassA('{class_name}') -> 0x{atom:x}")
            return atom
        except:
            return 0
    
    def RegisterClassExA(self, args):
        """RegisterClassExA emulation"""
        lpwcx = args[0]
        
        try:
            # Read WNDCLASSEX structure
            wcex_data = self.emu.uc.mem_read(lpwcx, 48)
            cbSize = struct.unpack("<I", wcex_data[0:4])[0]
            style = struct.unpack("<I", wcex_data[4:8])[0]
            lpfnWndProc = struct.unpack("<I", wcex_data[8:12])[0]
            hInstance = struct.unpack("<I", wcex_data[24:28])[0]
            lpszClassName = struct.unpack("<I", wcex_data[40:44])[0]
            
            class_name = self.read_string(lpszClassName)
            
            atom = self.next_atom
            self.next_atom += 1
            
            self.registered_classes[class_name] = {
                'atom': atom,
                'style': style,
                'wndproc': lpfnWndProc,
                'hInstance': hInstance
            }
            self.atoms[atom] = class_name
            
            log.debug(f"RegisterClassExA('{class_name}') -> 0x{atom:x}")
            return atom
        except:
            return 0
    
    def CreateWindowExA(self, args):
        """CreateWindowExA emulation"""
        dwExStyle = args[0]
        lpClassName = args[1]
        lpWindowName = args[2]
        dwStyle = args[3]
        x = args[4] if args[4] != 0x80000000 else 100  # CW_USEDEFAULT
        y = args[5] if args[5] != 0x80000000 else 100
        nWidth = args[6] if args[6] != 0x80000000 else 400
        nHeight = args[7] if args[7] != 0x80000000 else 300
        hWndParent = args[8]
        hMenu = args[9]
        hInstance = args[10]
        lpParam = args[11]
        
        # Class name can be atom or string
        if lpClassName < 0x10000:
            class_name = self.atoms.get(lpClassName, f"ATOM_{lpClassName}")
        else:
            class_name = self.read_string(lpClassName)
        
        window_name = self.read_string(lpWindowName) if lpWindowName else ""
        
        log.info(f"{Fore.GREEN}CreateWindowExA{Style.RESET_ALL}('{class_name}', '{window_name}', "
                f"pos=({x},{y}), size=({nWidth},{nHeight}))")
        
        # Create real window if GUI exists
        if self.gui and self.gui.running:
            # Create control for top-level controls
            if class_name.upper() in ["BUTTON", "EDIT", "STATIC", "LISTBOX", "COMBOBOX"]:
                hwnd = self.gui.create_control(hWndParent, class_name, window_name, 
                                               x, y, nWidth, nHeight, dwStyle)
            else:
                hwnd = self.gui.create_window(window_name, x, y, nWidth, nHeight, dwStyle)
            
            # Save class_name to window (for finding WndProc)
            if hwnd in self.gui.windows:
                self.gui.windows[hwnd].class_name = class_name
        else:
            hwnd = self.get_next_handle()
        
        return hwnd
    
    def ShowWindow(self, args):
        """ShowWindow emulation"""
        hWnd = args[0]
        nCmdShow = args[1]
        
        show_names = {0: "SW_HIDE", 1: "SW_SHOWNORMAL", 2: "SW_SHOWMINIMIZED",
                     3: "SW_SHOWMAXIMIZED", 4: "SW_SHOWNOACTIVATE", 5: "SW_SHOW"}
        show_name = show_names.get(nCmdShow, f"SW_{nCmdShow}")
        
        log.debug(f"ShowWindow(0x{hWnd:x}, {show_name})")
        
        if self.gui and self.gui.running:
            show = nCmdShow in [1, 3, 5, 6, 7, 8, 9, 10]
            self.gui.show_window(hWnd, show)
        
        return 1
    
    def UpdateWindow(self, args):
        """UpdateWindow emulation"""
        hWnd = args[0]
        log.debug(f"UpdateWindow(0x{hWnd:x})")
        return 1
    
    def DestroyWindow(self, args):
        """DestroyWindow emulation"""
        hWnd = args[0]
        log.debug(f"DestroyWindow(0x{hWnd:x})")
        
        if self.gui and hWnd in self.gui.windows:
            self.gui._close_window(hWnd)
        
        return 1
    
    def SetWindowTextA(self, args):
        """SetWindowTextA emulation"""
        hWnd = args[0]
        lpString = args[1]
        
        text = self.read_string(lpString) if lpString else ""
        log.debug(f"SetWindowTextA(0x{hWnd:x}, '{text}')")
        
        if self.gui:
            self.gui.set_window_text(hWnd, text)
        
        return 1
    
    def GetWindowTextA(self, args):
        """GetWindowTextA emulation"""
        hWnd = args[0]
        lpString = args[1]
        nMaxCount = args[2]
        
        text = ""
        if self.gui:
            text = self.gui.get_window_text(hWnd)
        
        if lpString and text:
            text_bytes = text.encode('utf-8')[:nMaxCount-1] + b'\x00'
            self.emu.uc.mem_write(lpString, text_bytes)
        
        log.debug(f"GetWindowTextA(0x{hWnd:x}) -> '{text}'")
        return len(text)
    
    def GetClientRect(self, args):
        """GetClientRect emulation"""
        hWnd = args[0]
        lpRect = args[1]
        
        # Default rectangle
        left, top, right, bottom = 0, 0, 400, 300
        
        if self.gui and hWnd in self.gui.windows:
            win = self.gui.windows[hWnd]
            right = win.width - 6
            bottom = win.height - 31
        
        if lpRect:
            rect_data = struct.pack("<iiii", left, top, right, bottom)
            self.emu.uc.mem_write(lpRect, rect_data)
        
        log.debug(f"GetClientRect(0x{hWnd:x}) -> ({left}, {top}, {right}, {bottom})")
        return 1
    
    def GetWindowRect(self, args):
        """GetWindowRect emulation"""
        hWnd = args[0]
        lpRect = args[1]
        
        left, top, right, bottom = 100, 100, 500, 400
        
        if self.gui and hWnd in self.gui.windows:
            win = self.gui.windows[hWnd]
            left, top = win.x, win.y
            right = win.x + win.width
            bottom = win.y + win.height
        
        if lpRect:
            rect_data = struct.pack("<iiii", left, top, right, bottom)
            self.emu.uc.mem_write(lpRect, rect_data)
        
        log.debug(f"GetWindowRect(0x{hWnd:x}) -> ({left}, {top}, {right}, {bottom})")
        return 1
    
    def MoveWindow(self, args):
        """MoveWindow emulation"""
        hWnd = args[0]
        X = args[1]
        Y = args[2]
        nWidth = args[3]
        nHeight = args[4]
        bRepaint = args[5]
        
        log.debug(f"MoveWindow(0x{hWnd:x}, {X}, {Y}, {nWidth}, {nHeight})")
        
        if self.gui and hWnd in self.gui.windows:
            win = self.gui.windows[hWnd]
            win.x, win.y = X, Y
            win.width, win.height = nWidth, nHeight
        
        return 1
    
    def SetWindowPos(self, args):
        """SetWindowPos emulation"""
        hWnd = args[0]
        hWndInsertAfter = args[1]
        X = args[2]
        Y = args[3]
        cx = args[4]
        cy = args[5]
        uFlags = args[6]
        
        log.debug(f"SetWindowPos(0x{hWnd:x}, {X}, {Y}, {cx}, {cy})")
        
        if self.gui and hWnd in self.gui.windows:
            win = self.gui.windows[hWnd]
            if not (uFlags & 0x0002):  # SWP_NOMOVE
                win.x, win.y = X, Y
            if not (uFlags & 0x0001):  # SWP_NOSIZE
                win.width, win.height = cx, cy
        
        return 1
    
    def EnableWindow(self, args):
        """EnableWindow emulation"""
        hWnd = args[0]
        bEnable = args[1]
        log.debug(f"EnableWindow(0x{hWnd:x}, {bEnable})")
        
        if self.gui and hWnd in self.gui.windows:
            self.gui.windows[hWnd].enabled = bool(bEnable)
        elif self.gui and hWnd in self.gui.controls:
            self.gui.controls[hWnd].enabled = bool(bEnable)
        
        return 1
    
    def GetDlgItem(self, args):
        """GetDlgItem emulation"""
        hDlg = args[0]
        nIDDlgItem = args[1]
        log.debug(f"GetDlgItem(0x{hDlg:x}, {nIDDlgItem})")
        
        # Simple: return dialog item ID as handle
        return 0x20000 + nIDDlgItem
    
    def SendMessageA(self, args):
        """SendMessageA emulation"""
        hWnd = args[0]
        Msg = args[1]
        wParam = args[2]
        lParam = args[3]
        
        msg_names = {
            0x0001: "WM_CREATE", 0x0002: "WM_DESTROY", 0x000F: "WM_PAINT",
            0x0010: "WM_CLOSE", 0x0012: "WM_QUIT", 0x0100: "WM_KEYDOWN",
            0x0111: "WM_COMMAND", 0x000C: "WM_SETTEXT", 0x000D: "WM_GETTEXT",
        }
        msg_name = msg_names.get(Msg, f"0x{Msg:04x}")
        
        log.debug(f"SendMessageA(0x{hWnd:x}, {msg_name}, 0x{wParam:x}, 0x{lParam:x})")
        return 0
    
    def PostMessageA(self, args):
        """PostMessageA emulation"""
        hWnd = args[0]
        Msg = args[1]
        wParam = args[2]
        lParam = args[3]
        log.debug(f"PostMessageA(0x{hWnd:x}, 0x{Msg:x}, 0x{wParam:x}, 0x{lParam:x})")
        return 1
    
    def GetMessageA(self, args):
        """GetMessageA emulation - For message loop"""
        lpMsg = args[0]
        hWnd = args[1]
        wMsgFilterMin = args[2]
        wMsgFilterMax = args[3]
        
        log.debug(f"GetMessageA() - Message loop")
        
        # Exit if quit requested
        if self.quit_requested:
            if lpMsg:
                msg_data = struct.pack("<IIIIIii", 0, self.WM_QUIT, 0, 0, 0, 0, 0)
                self.emu.uc.mem_write(lpMsg, msg_data)
            return 0
        
        # Send WM_PAINT for windows not yet painted
        for hwnd, window in list(self.gui.windows.items()) if self.gui else []:
            if hwnd not in self.painted_windows and window.visible:
                self.painted_windows.add(hwnd)
                if lpMsg:
                    msg_data = struct.pack("<IIIIIii", hwnd, self.WM_PAINT, 0, 0, 0, 0, 0)
                    self.emu.uc.mem_write(lpMsg, msg_data)
                log.debug(f"GetMessageA() -> WM_PAINT for hwnd=0x{hwnd:x}")
                return 1
        
        # Return message if queue has one
        if self.message_queue:
            msg = self.message_queue.pop(0)
            if lpMsg:
                msg_data = struct.pack("<IIIIIii", msg['hwnd'], msg['message'], 
                                       msg['wParam'], msg['lParam'], 0, 0, 0)
                self.emu.uc.mem_write(lpMsg, msg_data)
            if msg['message'] == self.WM_QUIT:
                return 0
            return 1
        
        # WM_QUIT if GUI exists and window was closed
        if self.gui and not self.gui.running:
            if lpMsg:
                msg_data = struct.pack("<IIIIIii", 0, self.WM_QUIT, 0, 0, 0, 0, 0)
                self.emu.uc.mem_write(lpMsg, msg_data)
            return 0
        
        # Default: let program terminate (emulation is limited)
        self.quit_requested = True
        if lpMsg:
            msg_data = struct.pack("<IIIIIii", 0, self.WM_QUIT, 0, 0, 0, 0, 0)
            self.emu.uc.mem_write(lpMsg, msg_data)
        return 0
    
    def TranslateMessage(self, args):
        """TranslateMessage emulation"""
        lpMsg = args[0]
        log.debug(f"TranslateMessage()")
        return 1
    
    def DispatchMessageA(self, args):
        """DispatchMessageA emulation - Call WndProc"""
        lpMsg = args[0]
        log.debug(f"DispatchMessageA()")
        
        # Read MSG structure: hwnd, message, wParam, lParam, time, pt.x, pt.y
        try:
            msg_data = self.emu.uc.mem_read(lpMsg, 28)
            hwnd, message, wParam, lParam, time_val, pt_x, pt_y = struct.unpack("<IIIIIii", msg_data)
            
            log.debug(f"DispatchMessageA: hwnd=0x{hwnd:x}, msg=0x{message:x}")
            
            # Find WndProc for this hwnd
            wndproc = self._find_wndproc_for_hwnd(hwnd)
            
            if wndproc and wndproc != 0:
                log.info(f"Calling WndProc: 0x{wndproc:x}(hwnd=0x{hwnd:x}, msg=0x{message:x}, wParam=0x{wParam:x}, lParam=0x{lParam:x})")
                
                # Call WndProc callback
                result = self.emu.call_wndproc(wndproc, hwnd, message, wParam, lParam)
                
                log.debug(f"WndProc returned: 0x{result:x}")
                return result
            else:
                log.debug(f"WndProc not found, hwnd=0x{hwnd:x}")
                
        except Exception as e:
            log.warning(f"DispatchMessageA error: {e}")
            import traceback
            traceback.print_exc()
        
        return 0
    
    def _find_wndproc_for_hwnd(self, hwnd):
        """Find WndProc address for a specific hwnd"""
        # No WndProc for console window
        if self.gui and hwnd == self.gui.console_hwnd:
            return 0
        
        # Get window class from GUI
        if self.gui and hwnd in self.gui.windows:
            window = self.gui.windows[hwnd]
            # Find WndProc from window class name
            class_name = getattr(window, 'class_name', None)
            if class_name and class_name in self.registered_classes:
                return self.registered_classes[class_name].get('wndproc', 0)
            # No WndProc if no class_name (internal window)
            if not class_name:
                return 0
                return 0
        
        return 0
    
    def DefWindowProcA(self, args):
        """DefWindowProcA emulation"""
        hWnd = args[0]
        Msg = args[1]
        wParam = args[2]
        lParam = args[3]
        log.debug(f"DefWindowProcA(0x{hWnd:x}, 0x{Msg:x})")
        return 0
    
    def BeginPaint(self, args):
        """BeginPaint emulation"""
        hWnd = args[0]
        lpPaint = args[1]
        
        log.debug(f"BeginPaint(0x{hWnd:x})")
        
        # Fill PAINTSTRUCT structure
        if lpPaint:
            hdc = self.get_next_handle()
            # hdc, fErase, rcPaint(4 int), fRestore, fIncUpdate, rgbReserved[32]
            paint_data = struct.pack("<II", hdc, 0)  # First 8 bytes
            paint_data += struct.pack("<iiii", 0, 0, 400, 300)  # rcPaint
            paint_data += b'\x00' * (64 - len(paint_data))  # Rest
            self.emu.uc.mem_write(lpPaint, paint_data[:64])
            return hdc
        
        return self.get_next_handle()
    
    def EndPaint(self, args):
        """EndPaint emulation"""
        hWnd = args[0]
        lpPaint = args[1]
        log.debug(f"EndPaint(0x{hWnd:x})")
        return 1
    
    def InvalidateRect(self, args):
        """InvalidateRect emulation"""
        hWnd = args[0]
        lpRect = args[1]
        bErase = args[2]
        log.debug(f"InvalidateRect(0x{hWnd:x})")
        return 1
    
    def FillRect(self, args):
        """FillRect emulation"""
        hdc = args[0]
        lprc = args[1]
        hbr = args[2]
        
        # Read RECT structure
        if lprc:
            try:
                rect_data = self.emu.uc.mem_read(lprc, 16)
                left, top, right, bottom = struct.unpack("<iiii", rect_data)
                log.debug(f"FillRect(0x{hdc:x}, rect=({left},{top},{right},{bottom}), brush=0x{hbr:x})")
            except:
                log.debug(f"FillRect(0x{hdc:x})")
        else:
            log.debug(f"FillRect(0x{hdc:x})")
        
        return 1
    
    def GetDC(self, args):
        """GetDC emulation"""
        hWnd = args[0]
        log.debug(f"GetDC(0x{hWnd:x})")
        return self.get_next_handle()
    
    def ReleaseDC(self, args):
        """ReleaseDC emulation"""
        hWnd = args[0]
        hDC = args[1]
        log.debug(f"ReleaseDC(0x{hWnd:x}, 0x{hDC:x})")
        return 1
    
    # GDI32.DLL APIs
    def GetDeviceCaps(self, args):
        """GetDeviceCaps emulation"""
        hdc = args[0]
        index = args[1]
        
        caps = {
            8: 8,      # BITSPIXEL
            10: 1920,  # HORZRES
            12: 96,    # LOGPIXELSX
            88: 32,    # BITSPIXEL
            90: 96,    # LOGPIXELSX
            117: 1920, # DESKTOPHORZRES
            118: 1080, # DESKTOPVERTRES
        }
        
        result = caps.get(index, 0)
        log.debug(f"GetDeviceCaps(0x{hdc:x}, {index}) -> {result}")
        return result
    
    def TextOutA(self, args):
        """TextOutA emulation - Draw text"""
        hdc = args[0]
        x = args[1]
        y = args[2]
        lpString = args[3]
        c = args[4]
        
        text = self.read_string(lpString) if lpString else ""
        if c > 0 and len(text) > c:
            text = text[:c]
        
        log.info(f"TextOutA(0x{hdc:x}, {x}, {y}, \"{text}\")")
        
        # Draw text if GUI exists
        if self.gui:
            self.gui.draw_text(text, x, y)
        
        return 1
    
    def TextOutW(self, args):
        """TextOutW emulation - Draw Unicode text"""
        hdc = args[0]
        x = args[1]
        y = args[2]
        lpString = args[3]
        c = args[4]
        
        text = self.read_wstring(lpString) if lpString else ""
        if c > 0 and len(text) > c:
            text = text[:c]
        
        log.info(f"TextOutW(0x{hdc:x}, {x}, {y}, \"{text}\")")
        
        if self.gui:
            self.gui.draw_text(text, x, y)
        
        return 1
    
    def DrawTextA(self, args):
        """DrawTextA emulation"""
        hdc = args[0]
        lpchText = args[1]
        cchText = args[2]
        lprc = args[3]
        format_flags = args[4]
        
        text = self.read_string(lpchText) if lpchText else ""
        if cchText > 0 and len(text) > cchText:
            text = text[:cchText]
        
        # Read RECT structure
        x, y, width, height = 0, 0, 400, 300
        if lprc:
            try:
                rect_data = self.emu.uc.mem_read(lprc, 16)
                left, top, right, bottom = struct.unpack("<iiii", rect_data)
                x, y = left, top
                width, height = right - left, bottom - top
            except:
                pass
        
        log.info(f"DrawTextA(0x{hdc:x}, \"{text}\", rect=({x},{y},{width},{height}))")
        
        # DT_CENTER (0x01) ve DT_VCENTER (0x04) flag'leri
        DT_CENTER = 0x01
        DT_VCENTER = 0x04
        
        draw_x = x
        draw_y = y
        
        # Calculate centering (approximate)
        if format_flags & DT_CENTER:
            draw_x = x + (width - len(text) * 8) // 2  # 8 pixel estimated character width
        if format_flags & DT_VCENTER:
            draw_y = y + (height - 16) // 2  # 16 pixel estimated height
        
        if self.gui:
            # Draw to active window
            active_hwnd = self.gui.active_window
            if active_hwnd and active_hwnd != self.gui.console_hwnd:
                self.gui.draw_text(text, draw_x, draw_y, active_hwnd)
        
        return height  # Text height
    
    def DrawTextW(self, args):
        """DrawTextW emulation"""
        hdc = args[0]
        lpchText = args[1]
        cchText = args[2]
        lprc = args[3]
        format_flags = args[4]
        
        text = self.read_wstring(lpchText) if lpchText else ""
        if cchText > 0 and len(text) > cchText:
            text = text[:cchText]
        
        x, y = 0, 0
        if lprc:
            try:
                rect_data = self.emu.uc.mem_read(lprc, 16)
                left, top, right, bottom = struct.unpack("<iiii", rect_data)
                x, y = left, top
            except:
                pass
        
        log.info(f"DrawTextW(0x{hdc:x}, \"{text}\")")
        
        if self.gui:
            self.gui.draw_text(text, x, y)
        
        return 20  # Text height
    
    def SetTextColor(self, args):
        """SetTextColor emulation"""
        hdc = args[0]
        color = args[1]
        log.debug(f"SetTextColor(0x{hdc:x}, 0x{color:06x})")
        return 0  # Previous color
    
    def SetBkColor(self, args):
        """SetBkColor emulation"""
        hdc = args[0]
        color = args[1]
        log.debug(f"SetBkColor(0x{hdc:x}, 0x{color:06x})")
        return 0xFFFFFF  # Previous color
    
    def SetBkMode(self, args):
        """SetBkMode emulation"""
        hdc = args[0]
        mode = args[1]  # TRANSPARENT=1, OPAQUE=2
        log.debug(f"SetBkMode(0x{hdc:x}, {mode})")
        return 2  # Previous mode
    
    # ADVAPI32.DLL APIs
    def RegOpenKeyExA(self, args):
        """RegOpenKeyExA emulation"""
        hKey = args[0]
        lpSubKey = args[1]
        ulOptions = args[2]
        samDesired = args[3]
        phkResult = args[4]
        
        subkey = self.read_string(lpSubKey) if lpSubKey else ""
        log.debug(f"RegOpenKeyExA(0x{hKey:x}, \"{subkey}\")")
        
        # Return fake handle
        fake_handle = self.get_next_handle()
        if phkResult:
            self.emu.uc.mem_write(phkResult, struct.pack('<I', fake_handle))
        
        return 2  # ERROR_FILE_NOT_FOUND - key not found
    
    def RegOpenKeyExW(self, args):
        """RegOpenKeyExW emulation"""
        hKey = args[0]
        lpSubKey = args[1]
        ulOptions = args[2]
        samDesired = args[3]
        phkResult = args[4]
        
        subkey = self.read_wide_string(lpSubKey) if lpSubKey else ""
        log.debug(f"RegOpenKeyExW(0x{hKey:x}, \"{subkey}\")")
        
        fake_handle = self.get_next_handle()
        if phkResult:
            self.emu.uc.mem_write(phkResult, struct.pack('<I', fake_handle))
        
        return 2  # ERROR_FILE_NOT_FOUND
    
    def RegQueryValueExA(self, args):
        """RegQueryValueExA emulation"""
        hKey = args[0]
        lpValueName = args[1]
        lpReserved = args[2]
        lpType = args[3]
        lpData = args[4]
        lpcbData = args[5]
        
        value_name = self.read_string(lpValueName) if lpValueName else ""
        log.debug(f"RegQueryValueExA(0x{hKey:x}, \"{value_name}\")")
        
        return 2  # ERROR_FILE_NOT_FOUND
    
    def RegQueryValueExW(self, args):
        """RegQueryValueExW emulation"""
        hKey = args[0]
        lpValueName = args[1]
        lpReserved = args[2]
        lpType = args[3]
        lpData = args[4]
        lpcbData = args[5]
        
        value_name = self.read_wide_string(lpValueName) if lpValueName else ""
        log.debug(f"RegQueryValueExW(0x{hKey:x}, \"{value_name}\")")
        
        return 2  # ERROR_FILE_NOT_FOUND
    
    def RegCloseKey(self, args):
        """RegCloseKey emulation"""
        hKey = args[0]
        log.debug(f"RegCloseKey(0x{hKey:x})")
        return 0  # ERROR_SUCCESS
    
    def RegSetValueExA(self, args):
        """RegSetValueExA emulation"""
        log.debug("RegSetValueExA()")
        return 0  # ERROR_SUCCESS
    
    def RegSetValueExW(self, args):
        """RegSetValueExW emulation"""
        log.debug("RegSetValueExW()")
        return 0  # ERROR_SUCCESS
    
    def RegCreateKeyExA(self, args):
        """RegCreateKeyExA emulation"""
        hKey = args[0]
        lpSubKey = args[1]
        
        subkey = self.read_string(lpSubKey) if lpSubKey else ""
        log.debug(f"RegCreateKeyExA(0x{hKey:x}, \"{subkey}\")")
        
        # Write handle to phkResult
        phkResult = args[7]
        if phkResult:
            fake_handle = self.get_next_handle()
            self.emu.uc.mem_write(phkResult, struct.pack('<I', fake_handle))
        
        return 0  # ERROR_SUCCESS
    
    def RegCreateKeyExW(self, args):
        """RegCreateKeyExW emulation"""
        hKey = args[0]
        lpSubKey = args[1]
        
        subkey = self.read_wide_string(lpSubKey) if lpSubKey else ""
        log.debug(f"RegCreateKeyExW(0x{hKey:x}, \"{subkey}\")")
        
        phkResult = args[7]
        if phkResult:
            fake_handle = self.get_next_handle()
            self.emu.uc.mem_write(phkResult, struct.pack('<I', fake_handle))
        
        return 0  # ERROR_SUCCESS
    
    # OLE32.DLL APIs
    def OleInitialize(self, args):
        """OleInitialize emulation"""
        log.debug("OleInitialize()")
        return 0  # S_OK
    
    def OleUninitialize(self, args):
        """OleUninitialize emulation"""
        log.debug("OleUninitialize()")
        return 0
    
    def CoInitialize(self, args):
        """CoInitialize emulation"""
        log.debug("CoInitialize()")
        return 0  # S_OK
    
    def CoUninitialize(self, args):
        """CoUninitialize emulation"""
        log.debug("CoUninitialize()")
        return 0
    
    # MSVCRT.DLL APIs
    def _ensure_fmode_addr(self):
        """Allocate memory for _fmode variable"""
        if self._fmode_addr == 0:
            self._fmode_addr = self.emu.heap_alloc(4)
            self.emu.uc.mem_write(self._fmode_addr, struct.pack('<I', 0x4000))  # _O_TEXT
        return self._fmode_addr
    
    def _ensure_commode_addr(self):
        """Allocate memory for _commode variable"""
        if self._commode_addr == 0:
            self._commode_addr = self.emu.heap_alloc(4)
            self.emu.uc.mem_write(self._commode_addr, struct.pack('<I', 0))  # Default commit mode
        return self._commode_addr
    
    def api__p__fmode(self, args):
        """__p__fmode emulation - Returns address of _fmode variable"""
        addr = self._ensure_fmode_addr()
        log.debug(f"__p__fmode() -> 0x{addr:08x}")
        return addr
    
    def api__p__commode(self, args):
        """__p__commode emulation - Returns address of _commode variable"""
        addr = self._ensure_commode_addr()
        log.debug(f"__p__commode() -> 0x{addr:08x}")
        return addr
    
    def api__set_app_type(self, args):
        """__set_app_type emulation"""
        app_type = args[0]
        log.debug(f"__set_app_type({app_type})")
        return 0
    
    def _controlfp(self, args):
        """_controlfp emulation - floating point control word"""
        new_val = args[0]
        mask = args[1]
        log.debug(f"_controlfp(0x{new_val:x}, 0x{mask:x})")
        # Return default FPU control word
        return 0x9001F  # Default x86 FPU control word
    
    def _initterm(self, args):
        """_initterm emulation - Run C++ static initializer table"""
        pfbegin = args[0]
        pfend = args[1]
        log.debug(f"_initterm(0x{pfbegin:08x}, 0x{pfend:08x})")
        
        # Call each function pointer
        current = pfbegin
        while current < pfend:
            try:
                func_ptr = struct.unpack('<I', self.emu.uc.mem_read(current, 4))[0]
                if func_ptr != 0:
                    log.debug(f"  _initterm: skipping function 0x{func_ptr:08x}")
                    # We don't actually call it, could cause complexity
                current += 4
            except:
                break
        return 0
    
    def _initterm_e(self, args):
        """_initterm_e emulation - _initterm with error checking"""
        return self._initterm(args)
    
    def api__getmainargs(self, args):
        """__getmainargs emulation - Returns argc, argv, environ"""
        p_argc = args[0]
        p_argv = args[1]
        p_env = args[2]
        do_wildcard = args[3]
        # startinfo = args[4]  # Optional
        
        log.debug(f"__getmainargs(0x{p_argc:08x}, 0x{p_argv:08x}, 0x{p_env:08x}, {do_wildcard})")
        
        # argc = 1
        self.emu.uc.mem_write(p_argc, struct.pack('<I', 1))
        
        # Allocate memory for argv
        if self._argv_addr == 0:
            self._argv_addr = self.emu.heap_alloc(16)  # argv array
            argv0_addr = self.emu.heap_alloc(256)  # argv[0] string
            
            # argv[0] = program name
            prog_name = self.emu.pe_loader.filepath + "\x00"
            self.emu.uc.mem_write(argv0_addr, prog_name.encode('utf-8'))
            
            # argv[0] pointer, argv[1] = NULL
            self.emu.uc.mem_write(self._argv_addr, struct.pack('<II', argv0_addr, 0))
        
        self.emu.uc.mem_write(p_argv, struct.pack('<I', self._argv_addr))
        
        # Allocate memory for environ
        if self._environ_addr == 0:
            self._environ_addr = self.emu.heap_alloc(8)
            self.emu.uc.mem_write(self._environ_addr, struct.pack('<I', 0))  # NULL terminated
        
        self.emu.uc.mem_write(p_env, struct.pack('<I', self._environ_addr))
        
        return 0
    
    def api__wgetmainargs(self, args):
        """__wgetmainargs emulation - wide char version"""
        p_argc = args[0]
        p_argv = args[1]
        p_env = args[2]
        do_wildcard = args[3]
        
        log.debug(f"__wgetmainargs(0x{p_argc:08x}, 0x{p_argv:08x}, 0x{p_env:08x}, {do_wildcard})")
        
        # argc = 1
        self.emu.uc.mem_write(p_argc, struct.pack('<I', 1))
        
        # Allocate memory for wargv
        if self._wargv_addr == 0:
            self._wargv_addr = self.emu.heap_alloc(16)  # wargv array
            wargv0_addr = self.emu.heap_alloc(512)  # wargv[0] string
            
            # wargv[0] = program name (wide)
            prog_name = self.emu.pe_loader.filepath
            self.emu.uc.mem_write(wargv0_addr, prog_name.encode('utf-16-le') + b'\x00\x00')
            
            # wargv[0] pointer, wargv[1] = NULL
            self.emu.uc.mem_write(self._wargv_addr, struct.pack('<II', wargv0_addr, 0))
        
        self.emu.uc.mem_write(p_argv, struct.pack('<I', self._wargv_addr))
        
        # Allocate memory for wenviron
        if self._wenviron_addr == 0:
            self._wenviron_addr = self.emu.heap_alloc(8)
            self.emu.uc.mem_write(self._wenviron_addr, struct.pack('<I', 0))  # NULL terminated
        
        self.emu.uc.mem_write(p_env, struct.pack('<I', self._wenviron_addr))
        
        return 0
    
    def api__p___argc(self, args):
        """__p___argc emulation"""
        if self._argc == 0:
            self._argc = self.emu.heap_alloc(4)
            self.emu.uc.mem_write(self._argc, struct.pack('<I', 1))
        log.debug(f"__p___argc() -> 0x{self._argc:08x}")
        return self._argc
    
    def api__p___argv(self, args):
        """__p___argv emulation"""
        # Allocate memory for argv
        if self._argv_addr == 0:
            self._argv_addr = self.emu.heap_alloc(16)
            argv0_addr = self.emu.heap_alloc(256)
            prog_name = self.emu.pe_loader.filepath + "\x00"
            self.emu.uc.mem_write(argv0_addr, prog_name.encode('utf-8'))
            self.emu.uc.mem_write(self._argv_addr, struct.pack('<II', argv0_addr, 0))
        
        # Return address of argv pointer
        argv_ptr_addr = self.emu.heap_alloc(4)
        self.emu.uc.mem_write(argv_ptr_addr, struct.pack('<I', self._argv_addr))
        log.debug(f"__p___argv() -> 0x{argv_ptr_addr:08x}")
        return argv_ptr_addr
    
    def api__p___wargv(self, args):
        """__p___wargv emulation"""
        if self._wargv_addr == 0:
            self._wargv_addr = self.emu.heap_alloc(16)
            wargv0_addr = self.emu.heap_alloc(512)
            prog_name = self.emu.pe_loader.filepath
            self.emu.uc.mem_write(wargv0_addr, prog_name.encode('utf-16-le') + b'\x00\x00')
            self.emu.uc.mem_write(self._wargv_addr, struct.pack('<II', wargv0_addr, 0))
        
        wargv_ptr_addr = self.emu.heap_alloc(4)
        self.emu.uc.mem_write(wargv_ptr_addr, struct.pack('<I', self._wargv_addr))
        log.debug(f"__p___wargv() -> 0x{wargv_ptr_addr:08x}")
        return wargv_ptr_addr
    
    def _amsg_exit(self, args):
        """_amsg_exit emulation - runtime error message and exit"""
        errnum = args[0]
        log.error(f"_amsg_exit({errnum}) - Runtime error!")
        self.emu.stop_emulation = True
        return 0
    
    def _cexit(self, args):
        """_cexit emulation"""
        log.debug("_cexit()")
        return 0
    
    def _exit(self, args):
        """_exit emulation"""
        code = args[0]
        log.debug(f"_exit({code})")
        self.emu.stop_emulation = True
        return 0
    
    def exit(self, args):
        """exit emulation"""
        code = args[0]
        log.debug(f"exit({code})")
        self.emu.stop_emulation = True
        return 0
    
    def _XcptFilter(self, args):
        """_XcptFilter emulation - exception filter"""
        log.debug("_XcptFilter()")
        return 1  # EXCEPTION_EXECUTE_HANDLER
    
    def _except_handler3(self, args):
        """_except_handler3 emulation - SEH handler"""
        log.debug("_except_handler3()")
        return 0
    
    def api__CxxFrameHandler3(self, args):
        """__CxxFrameHandler3 emulation - C++ exception handler"""
        log.debug("__CxxFrameHandler3()")
        return 0
    
    def _CxxThrowException(self, args):
        """_CxxThrowException emulation"""
        log.debug("_CxxThrowException()")
        return 0
    
    def _onexit(self, args):
        """_onexit emulation - atexit registration"""
        func = args[0]
        log.debug(f"_onexit(0x{func:08x})")
        return func  # Success
    
    def atexit(self, args):
        """atexit emulation"""
        func = args[0]
        log.debug(f"atexit(0x{func:08x})")
        return 0  # Success
    
    def _lock(self, args):
        """_lock emulation - critical section"""
        locknum = args[0]
        log.debug(f"_lock({locknum})")
        return 0
    
    def _unlock(self, args):
        """_unlock emulation"""
        locknum = args[0]
        log.debug(f"_unlock({locknum})")
        return 0
    
    def _encoded_null(self, args):
        """_encoded_null emulation"""
        return 0
    
    def _decode_pointer(self, args):
        """_decode_pointer emulation"""
        ptr = args[0]
        return ptr  # No encoding, return directly
    
    def _encode_pointer(self, args):
        """_encode_pointer emulation"""
        ptr = args[0]
        return ptr  # No encoding, return directly
    
    def _crt_debugger_hook(self, args):
        """_crt_debugger_hook emulation"""
        log.debug("_crt_debugger_hook()")
        return 0
    
    def api__dllonexit(self, args):
        """__dllonexit emulation"""
        func = args[0]
        log.debug(f"__dllonexit(0x{func:08x})")
        return func
    
    def _invoke_watson(self, args):
        """_invoke_watson emulation - security error handler"""
        log.error("_invoke_watson() - Security violation detected!")
        self.emu.stop_emulation = True
        return 0
    
    def api__security_init_cookie(self, args):
        """__security_init_cookie emulation - stack cookie initialization"""
        log.debug("__security_init_cookie()")
        return 0
    
    def api__security_check_cookie(self, args):
        """__security_check_cookie emulation"""
        cookie = args[0]
        log.debug(f"__security_check_cookie(0x{cookie:08x})")
        return 0
    
    # String functions
    def strlen(self, args):
        """strlen emulation"""
        s = args[0]
        string = self.read_string(s)
        log.debug(f"strlen(\"{string[:32]}...\") -> {len(string)}")
        return len(string)
    
    def wcslen(self, args):
        """wcslen emulation"""
        s = args[0]
        string = self.read_wide_string(s)
        log.debug(f"wcslen() -> {len(string)}")
        return len(string)
    
    def memset(self, args):
        """memset emulation"""
        dest = args[0]
        c = args[1] & 0xFF
        count = args[2]
        log.debug(f"memset(0x{dest:08x}, {c}, {count})")
        try:
            self.emu.uc.mem_write(dest, bytes([c]) * count)
        except:
            pass
        return dest
    
    def memcpy(self, args):
        """memcpy emulation"""
        dest = args[0]
        src = args[1]
        count = args[2]
        log.debug(f"memcpy(0x{dest:08x}, 0x{src:08x}, {count})")
        try:
            data = self.emu.uc.mem_read(src, count)
            self.emu.uc.mem_write(dest, data)
        except:
            pass
        return dest
    
    def memmove(self, args):
        """memmove emulation"""
        return self.memcpy(args)
    
    def memcmp(self, args):
        """memcmp emulation"""
        buf1 = args[0]
        buf2 = args[1]
        count = args[2]
        try:
            data1 = self.emu.uc.mem_read(buf1, count)
            data2 = self.emu.uc.mem_read(buf2, count)
            if data1 < data2:
                return -1
            elif data1 > data2:
                return 1
            return 0
        except:
            return 0
    
    def strcpy(self, args):
        """strcpy emulation"""
        dest = args[0]
        src = args[1]
        string = self.read_string(src)
        try:
            self.emu.uc.mem_write(dest, string.encode('utf-8') + b'\x00')
        except:
            pass
        return dest
    
    def strncpy(self, args):
        """strncpy emulation"""
        dest = args[0]
        src = args[1]
        count = args[2]
        string = self.read_string(src, count)
        try:
            data = string.encode('utf-8')[:count]
            if len(data) < count:
                data += b'\x00' * (count - len(data))
            self.emu.uc.mem_write(dest, data)
        except:
            pass
        return dest
    
    def strcmp(self, args):
        """strcmp emulation"""
        s1 = self.read_string(args[0])
        s2 = self.read_string(args[1])
        if s1 < s2:
            return -1
        elif s1 > s2:
            return 1
        return 0
    
    def _stricmp(self, args):
        """_stricmp emulation (case-insensitive)"""
        s1 = self.read_string(args[0]).lower()
        s2 = self.read_string(args[1]).lower()
        if s1 < s2:
            return -1
        elif s1 > s2:
            return 1
        return 0
    
    def strcat(self, args):
        """strcat emulation"""
        dest = args[0]
        src = args[1]
        dest_str = self.read_string(dest)
        src_str = self.read_string(src)
        try:
            self.emu.uc.mem_write(dest, (dest_str + src_str).encode('utf-8') + b'\x00')
        except:
            pass
        return dest
    
    def sprintf(self, args):
        """sprintf emulation (simple)"""
        buf = args[0]
        fmt = self.read_string(args[1])
        log.debug(f"sprintf(0x{buf:08x}, \"{fmt}\")")
        # Simple format - just write the string
        try:
            self.emu.uc.mem_write(buf, fmt.encode('utf-8') + b'\x00')
        except:
            pass
        return len(fmt)
    
    def printf(self, args):
        """printf emulation"""
        fmt = self.read_string(args[0])
        log.info(f"[PRINTF] {fmt}")
        if self.gui and self.gui.running:
            self.gui.console_write_stdout(fmt)
        return len(fmt)
    
    def puts(self, args):
        """puts emulation"""
        s = self.read_string(args[0])
        log.info(f"[PUTS] {s}")
        if self.gui and self.gui.running:
            self.gui.console_write_stdout(s + "\n")
        return len(s) + 1
    
    # File functions
    def fopen(self, args):
        """fopen emulation"""
        filename = self.read_string(args[0])
        mode = self.read_string(args[1])
        log.debug(f"fopen(\"{filename}\", \"{mode}\")")
        return 0  # Failed
    
    def fclose(self, args):
        """fclose emulation"""
        log.debug("fclose()")
        return 0
    
    def fread(self, args):
        """fread emulation"""
        log.debug("fread()")
        return 0
    
    def fwrite(self, args):
        """fwrite emulation"""
        log.debug("fwrite()")
        return 0
    
    def api__iob_func(self, args):
        """__iob_func emulation - stdin/stdout/stderr file handles"""
        log.debug("__iob_func()")
        # Return an address for FILE structures
        if not hasattr(self, '_iob_addr') or self._iob_addr == 0:
            self._iob_addr = self.emu.heap_alloc(0x60)  # 3 FILE struct
        return self._iob_addr
    
    def api__acrt_iob_func(self, args):
        """__acrt_iob_func emulation - UCRT version"""
        index = args[0]
        log.debug(f"__acrt_iob_func({index})")
        if not hasattr(self, '_iob_addr') or self._iob_addr == 0:
            self._iob_addr = self.emu.heap_alloc(0x60)
        return self._iob_addr + (index * 0x20)
    
    def _get_osfhandle(self, args):
        """_get_osfhandle emulation"""
        fd = args[0]
        log.debug(f"_get_osfhandle({fd})")
        # stdin=0, stdout=1, stderr=2
        if fd == 0:
            return 0x10
        elif fd == 1:
            return 0x11
        elif fd == 2:
            return 0x12
        return 0xFFFFFFFF  # INVALID_HANDLE_VALUE
    
    def _isatty(self, args):
        """_isatty emulation"""
        fd = args[0]
        log.debug(f"_isatty({fd})")
        return 1 if fd in [0, 1, 2] else 0
    
    def _setmode(self, args):
        """_setmode emulation"""
        fd = args[0]
        mode = args[1]
        log.debug(f"_setmode({fd}, 0x{mode:x})")
        return mode  # Previous mode
    
    # Memory functions
    def malloc(self, args):
        """malloc emulation"""
        size = args[0]
        addr = self.emu.heap_alloc(size)
        log.debug(f"malloc({size}) -> 0x{addr:08x}")
        return addr
    
    def calloc(self, args):
        """calloc emulation"""
        num = args[0]
        size = args[1]
        total = num * size
        addr = self.emu.heap_alloc(total)
        # Zero memory
        try:
            self.emu.uc.mem_write(addr, b'\x00' * total)
        except:
            pass
        log.debug(f"calloc({num}, {size}) -> 0x{addr:08x}")
        return addr
    
    def realloc(self, args):
        """realloc emulation"""
        ptr = args[0]
        size = args[1]
        addr = self.emu.heap_alloc(size)
        log.debug(f"realloc(0x{ptr:08x}, {size}) -> 0x{addr:08x}")
        return addr
    
    def free(self, args):
        """free emulation"""
        ptr = args[0]
        log.debug(f"free(0x{ptr:08x})")
        return 0


# ==================== PYGAME WINDOWS GUI ====================

class FakeWindow:
    """Fake Windows window"""
    
    def __init__(self, hwnd, title, x, y, width, height, style=0):
        self.hwnd = hwnd
        self.title = title
        self.x = x
        self.y = y
        self.width = width
        self.height = height
        self.style = style
        self.visible = False
        self.enabled = True
        self.parent = None
        self.children = []
        self.controls = []  # Buttons, text boxes, etc.
        self.wndproc = 0
        self.bg_color = (240, 240, 240)  # Windows classic gray
        self.text = title
        
        # Window state
        self.minimized = False
        self.maximized = False
        self.is_dialog = False  # True if Dialog/MessageBox (only close button)
        
        # Original dimensions for restore
        self.restore_x = x
        self.restore_y = y
        self.restore_width = width
        self.restore_height = height
        
    def contains_point(self, px, py):
        """Is point inside window?"""
        if self.minimized:
            return False
        return (self.x <= px <= self.x + self.width and 
                self.y <= py <= self.y + self.height)
    
    def get_title_bar_rect(self):
        """Title bar rectangle"""
        return (self.x, self.y, self.width, 25)
    
    def minimize(self):
        """Minimize window"""
        if not self.minimized:
            self.minimized = True
    
    def restore(self):
        """Restore window"""
        if self.minimized:
            self.minimized = False
        elif self.maximized:
            self.x = self.restore_x
            self.y = self.restore_y
            self.width = self.restore_width
            self.height = self.restore_height
            self.maximized = False
    
    def maximize(self, screen_width, screen_height, taskbar_height=30):
        """Maximize window"""
        if not self.maximized:
            # Save original dimensions
            self.restore_x = self.x
            self.restore_y = self.y
            self.restore_width = self.width
            self.restore_height = self.height
            
            # Go fullscreen (except taskbar)
            self.x = 0
            self.y = 0
            self.width = screen_width
            self.height = screen_height - taskbar_height
            self.maximized = True
        else:
            # Restore
            self.restore()


class FakeControl:
    """Fake Windows control (Button, Edit, Static, etc.)"""
    
    def __init__(self, hwnd, class_name, text, x, y, width, height, style=0):
        self.hwnd = hwnd
        self.class_name = class_name.upper()
        self.text = text
        self.x = x
        self.y = y
        self.width = width
        self.height = height
        self.style = style
        self.visible = True
        self.enabled = True
        self.parent_hwnd = 0
        self.checked = False  # For Checkbox/Radio
        
    def contains_point(self, px, py, parent_x=0, parent_y=0):
        """Is point inside control?"""
        abs_x = parent_x + self.x
        abs_y = parent_y + self.y
        return (abs_x <= px <= abs_x + self.width and 
                abs_y <= py <= abs_y + self.height)


class PseudoWindowsGUI:
    """Pygame-based fake Windows GUI environment"""
    
    # Windows colors
    COLOR_DESKTOP = (0, 128, 128)  # Classic teal
    COLOR_WINDOW_BG = (240, 240, 240)
    COLOR_TITLE_BAR = (0, 0, 128)  # Classic blue
    COLOR_TITLE_BAR_INACTIVE = (128, 128, 128)
    COLOR_TITLE_TEXT = (255, 255, 255)
    COLOR_BUTTON = (212, 208, 200)
    COLOR_BUTTON_BORDER_LIGHT = (255, 255, 255)
    COLOR_BUTTON_BORDER_DARK = (64, 64, 64)
    COLOR_TEXT = (0, 0, 0)
    COLOR_EDIT_BG = (255, 255, 255)
    COLOR_TASKBAR = (192, 192, 192)
    
    def __init__(self, width=1024, height=768):
        self.width = width
        self.height = height
        self.screen = None
        self.running = False
        self.clock = None
        
        # Window management
        self.windows = {}  # hwnd -> FakeWindow
        self.controls = {}  # hwnd -> FakeControl
        self.next_hwnd = 0x10000
        self.active_window = None
        self.z_order = []  # Window ordering (topmost is at end)
        
        # Font
        self.font = None
        self.font_small = None
        self.font_bold = None
        
        # Event queue
        self.event_queue = queue.Queue()
        self.message_queue = queue.Queue()
        
        # MessageBox queue
        self.messagebox_queue = queue.Queue()
        self.messagebox_result = None
        
        # Thread
        self.gui_thread = None
        
        # Console window
        self.console_lines = []  # Console output lines
        self.console_max_lines = 100  # Maximum line count
        self.console_input = ""  # Current input
        self.console_visible = True  # Console visibility
        self.console_scroll = 0  # Scroll position
        self.console_hwnd = None  # Console window handle
        self.font_console = None  # Monospace font
        
        # Console input system (thread-safe)
        self.console_input_pending = False  # Is input pending?
        self.console_input_ready = threading.Event()  # Input ready signal
        self.console_input_result = ""  # Received input
        self.console_input_active = False  # Is input mode active?
        self.console_cursor_visible = True  # Cursor blinking
        self.console_cursor_timer = 0
        
        # Window dragging
        self.dragging_window = None  # Dragged window hwnd
        self.drag_offset_x = 0
        self.drag_offset_y = 0
        
    def start(self):
        """Start GUI thread"""
        if not PYGAME_AVAILABLE:
            log.warning("Pygame not available, GUI could not start!")
            return False
        
        self.gui_thread = threading.Thread(target=self._gui_loop, daemon=True)
        self.gui_thread.start()
        
        # Wait for GUI to start
        time.sleep(0.5)
        return True
    
    def stop(self):
        """Stop GUI"""
        self.running = False
        if self.gui_thread:
            self.gui_thread.join(timeout=1.0)
    
    def _gui_loop(self):
        """Main GUI loop"""
        pygame.init()
        pygame.display.set_caption("Windows 32-bit Emulator - Fake Desktop")
        
        self.screen = pygame.display.set_mode((self.width, self.height))
        self.clock = pygame.time.Clock()
        
        # Load fonts
        pygame.font.init()
        self.font = pygame.font.SysFont('arial', 14)
        self.font_small = pygame.font.SysFont('arial', 11)
        self.font_bold = pygame.font.SysFont('arial', 14, bold=True)
        self.font_console = pygame.font.SysFont('consolas,courier,monospace', 12)
        
        # Create console window
        self._create_console_window()
        
        self.running = True
        
        while self.running:
            # Process Pygame events
            for event in pygame.event.get():
                if event.type == pygame.QUIT:
                    self.running = False
                elif event.type == pygame.MOUSEBUTTONDOWN:
                    self._handle_mouse_click(event.pos, event.button)
                elif event.type == pygame.MOUSEBUTTONUP:
                    # Release drag
                    self.dragging_window = None
                elif event.type == pygame.MOUSEMOTION:
                    # Window dragging
                    if self.dragging_window and self.dragging_window in self.windows:
                        win = self.windows[self.dragging_window]
                        win.x = event.pos[0] - self.drag_offset_x
                        win.y = event.pos[1] - self.drag_offset_y
                        # Keep within screen boundaries
                        win.x = max(0, min(win.x, self.width - 50))
                        win.y = max(0, min(win.y, self.height - 60))
                elif event.type == pygame.KEYDOWN:
                    self._handle_key_press(event)
            
            # MessageBox check
            self._check_messagebox()
            
            # Cursor blinking (when console input is active)
            if self.console_input_active:
                self.console_cursor_timer += 1
                if self.console_cursor_timer >= 30:  # ~0.5 seconds
                    self.console_cursor_timer = 0
                    self.console_cursor_visible = not self.console_cursor_visible
            
            # Draw screen
            self._draw()
            
            pygame.display.flip()
            self.clock.tick(60)
        
        pygame.quit()
    
    def _draw(self):
        """Draw screen"""
        # Desktop background
        self.screen.fill(self.COLOR_DESKTOP)
        
        # Taskbar
        self._draw_taskbar()
        
        # Draw windows (according to z-order)
        for hwnd in self.z_order:
            if hwnd in self.windows:
                if hwnd == self.console_hwnd:
                    self._draw_console_window(self.windows[hwnd])
                else:
                    self._draw_window(self.windows[hwnd])
    
    def _draw_taskbar(self):
        """Draw taskbar"""
        taskbar_height = 30
        taskbar_rect = pygame.Rect(0, self.height - taskbar_height, self.width, taskbar_height)
        
        # Taskbar background
        pygame.draw.rect(self.screen, self.COLOR_TASKBAR, taskbar_rect)
        pygame.draw.line(self.screen, (255, 255, 255), (0, self.height - taskbar_height), 
                        (self.width, self.height - taskbar_height))
        
        # Start button
        start_rect = pygame.Rect(2, self.height - taskbar_height + 2, 60, taskbar_height - 4)
        self._draw_button_3d(start_rect, "Start", pressed=False)
        
        # System tray area (right side)
        tray_width = 80
        tray_rect = pygame.Rect(self.width - tray_width, self.height - taskbar_height + 2, 
                               tray_width - 4, taskbar_height - 4)
        # Sunken effect for tray
        pygame.draw.rect(self.screen, (192, 192, 192), tray_rect)
        pygame.draw.line(self.screen, (128, 128, 128), 
                        (tray_rect.x, tray_rect.y), (tray_rect.x + tray_rect.width, tray_rect.y))
        pygame.draw.line(self.screen, (128, 128, 128), 
                        (tray_rect.x, tray_rect.y), (tray_rect.x, tray_rect.y + tray_rect.height))
        pygame.draw.line(self.screen, (255, 255, 255), 
                        (tray_rect.x + tray_rect.width, tray_rect.y), 
                        (tray_rect.x + tray_rect.width, tray_rect.y + tray_rect.height))
        pygame.draw.line(self.screen, (255, 255, 255), 
                        (tray_rect.x, tray_rect.y + tray_rect.height), 
                        (tray_rect.x + tray_rect.width, tray_rect.y + tray_rect.height))
        
        # Saat
        current_time = time.strftime("%H:%M")
        time_text = self.font_small.render(current_time, True, self.COLOR_TEXT)
        self.screen.blit(time_text, (self.width - 45, self.height - taskbar_height + 8))
        
        # Open windows (excluding dialogs)
        x_offset = 70
        max_btn_width = 140
        
        # First count visible windows (excluding dialogs)
        visible_windows = [(hwnd, self.windows[hwnd]) for hwnd in self.z_order 
                          if hwnd in self.windows and self.windows[hwnd].visible 
                          and not self.windows[hwnd].is_dialog]
        
        # Adjust button width
        available_width = self.width - tray_width - 80  # Leave room for Start button and tray
        if visible_windows:
            btn_width = min(max_btn_width, available_width // len(visible_windows) - 5)
            btn_width = max(60, btn_width)  # Minimum 60px
        else:
            btn_width = max_btn_width
        
        for hwnd, win in visible_windows:
            btn_rect = pygame.Rect(x_offset, self.height - taskbar_height + 2, btn_width, taskbar_height - 4)
            
            is_active = (hwnd == self.active_window) and not win.minimized
            is_minimized = win.minimized
            
            # Minimized windows should not appear pressed
            # Active window should appear pressed
            self._draw_taskbar_button(btn_rect, win.title, is_active, is_minimized)
            
            x_offset += btn_width + 5
    
    def _draw_taskbar_button(self, rect, title, is_active, is_minimized):
        """Draw taskbar button"""
        # Background
        if is_active:
            # Active: pressed appearance
            pygame.draw.rect(self.screen, (192, 192, 192), rect)
            pygame.draw.line(self.screen, self.COLOR_BUTTON_BORDER_DARK, 
                           (rect.x, rect.y), (rect.x + rect.width - 1, rect.y))
            pygame.draw.line(self.screen, self.COLOR_BUTTON_BORDER_DARK, 
                           (rect.x, rect.y), (rect.x, rect.y + rect.height - 1))
            pygame.draw.line(self.screen, self.COLOR_BUTTON_BORDER_LIGHT, 
                           (rect.x + rect.width - 1, rect.y), 
                           (rect.x + rect.width - 1, rect.y + rect.height - 1))
            pygame.draw.line(self.screen, self.COLOR_BUTTON_BORDER_LIGHT, 
                           (rect.x, rect.y + rect.height - 1), 
                           (rect.x + rect.width - 1, rect.y + rect.height - 1))
        else:
            # Normal: raised appearance
            pygame.draw.rect(self.screen, self.COLOR_BUTTON, rect)
            pygame.draw.line(self.screen, self.COLOR_BUTTON_BORDER_LIGHT, 
                           (rect.x, rect.y), (rect.x + rect.width - 1, rect.y))
            pygame.draw.line(self.screen, self.COLOR_BUTTON_BORDER_LIGHT, 
                           (rect.x, rect.y), (rect.x, rect.y + rect.height - 1))
            pygame.draw.line(self.screen, self.COLOR_BUTTON_BORDER_DARK, 
                           (rect.x + rect.width - 1, rect.y), 
                           (rect.x + rect.width - 1, rect.y + rect.height - 1))
            pygame.draw.line(self.screen, self.COLOR_BUTTON_BORDER_DARK, 
                           (rect.x, rect.y + rect.height - 1), 
                           (rect.x + rect.width - 1, rect.y + rect.height - 1))
        
        # Text
        max_chars = (rect.width - 10) // 7  # Approximate character count
        display_title = title[:max_chars] if len(title) > max_chars else title
        text_color = self.COLOR_TEXT
        text_surface = self.font_small.render(display_title, True, text_color)
        text_x = rect.x + 5
        text_y = rect.y + (rect.height - text_surface.get_height()) // 2
        self.screen.blit(text_surface, (text_x, text_y))
    
    def _draw_window(self, window):
        """Draw window"""
        if not window.visible or window.minimized:
            return
        
        is_active = (window.hwnd == self.active_window)
        
        # Window shadow
        shadow_rect = pygame.Rect(window.x + 3, window.y + 3, window.width, window.height)
        pygame.draw.rect(self.screen, (64, 64, 64), shadow_rect)
        
        # Window frame
        frame_rect = pygame.Rect(window.x, window.y, window.width, window.height)
        pygame.draw.rect(self.screen, self.COLOR_WINDOW_BG, frame_rect)
        pygame.draw.rect(self.screen, self.COLOR_BUTTON_BORDER_DARK, frame_rect, 1)
        
        # 3D edge effect
        pygame.draw.line(self.screen, (255, 255, 255), 
                        (window.x, window.y), (window.x + window.width - 1, window.y))
        pygame.draw.line(self.screen, (255, 255, 255), 
                        (window.x, window.y), (window.x, window.y + window.height - 1))
        pygame.draw.line(self.screen, (64, 64, 64), 
                        (window.x + window.width - 1, window.y), 
                        (window.x + window.width - 1, window.y + window.height - 1))
        pygame.draw.line(self.screen, (64, 64, 64), 
                        (window.x, window.y + window.height - 1), 
                        (window.x + window.width - 1, window.y + window.height - 1))
        
        # Title bar
        title_color = self.COLOR_TITLE_BAR if is_active else self.COLOR_TITLE_BAR_INACTIVE
        title_rect = pygame.Rect(window.x + 3, window.y + 3, window.width - 6, 22)
        pygame.draw.rect(self.screen, title_color, title_rect)
        
        # Title text
        title_text = self.font_bold.render(window.title[:40], True, self.COLOR_TITLE_TEXT)
        self.screen.blit(title_text, (window.x + 8, window.y + 6))
        
        # Window buttons (Minimize, Maximize, Close)
        btn_size = 16
        btn_y = window.y + 5
        
        # Close button (X) - special for red hover effect
        close_rect = pygame.Rect(window.x + window.width - btn_size - 5, btn_y, btn_size, btn_size)
        self._draw_window_button(close_rect, "×", "close")
        
        # Show minimize and maximize buttons if not a dialog
        if not window.is_dialog:
            # Maximize/Restore butonu
            max_rect = pygame.Rect(window.x + window.width - btn_size * 2 - 7, btn_y, btn_size, btn_size)
            max_symbol = "❐" if window.maximized else "□"  # Restore vs Maximize
            self._draw_window_button(max_rect, max_symbol, "max")
            
            # Minimize butonu
            min_rect = pygame.Rect(window.x + window.width - btn_size * 3 - 9, btn_y, btn_size, btn_size)
            self._draw_window_button(min_rect, "─", "min")
        
        # Content area
        content_rect = pygame.Rect(window.x + 3, window.y + 28, window.width - 6, window.height - 31)
        pygame.draw.rect(self.screen, window.bg_color, content_rect)
        
        # Draw controls
        for control in window.controls:
            self._draw_control(control, window.x + 3, window.y + 28)
        
        # Render texts drawn with TextOutA/DrawTextA
        if hasattr(window, 'drawn_texts'):
            for text_item in window.drawn_texts:
                text_surface = self.font.render(text_item['text'], True, text_item.get('color', self.COLOR_TEXT))
                self.screen.blit(text_surface, (window.x + 3 + text_item['x'], window.y + 28 + text_item['y']))
    
    def _draw_control(self, control, parent_x, parent_y):
        """Draw control"""
        if not control.visible:
            return
        
        abs_x = parent_x + control.x
        abs_y = parent_y + control.y
        
        if control.class_name == "BUTTON":
            rect = pygame.Rect(abs_x, abs_y, control.width, control.height)
            self._draw_button_3d(rect, control.text)
            
        elif control.class_name == "STATIC":
            text = self.font.render(control.text, True, self.COLOR_TEXT)
            self.screen.blit(text, (abs_x, abs_y))
            
        elif control.class_name == "EDIT":
            rect = pygame.Rect(abs_x, abs_y, control.width, control.height)
            pygame.draw.rect(self.screen, self.COLOR_EDIT_BG, rect)
            pygame.draw.rect(self.screen, (128, 128, 128), rect, 1)
            # Sunken effect
            pygame.draw.line(self.screen, (64, 64, 64), (abs_x, abs_y), (abs_x + control.width, abs_y))
            pygame.draw.line(self.screen, (64, 64, 64), (abs_x, abs_y), (abs_x, abs_y + control.height))
            
            text = self.font.render(control.text[:30], True, self.COLOR_TEXT)
            self.screen.blit(text, (abs_x + 3, abs_y + 3))
            
        elif control.class_name == "LISTBOX":
            rect = pygame.Rect(abs_x, abs_y, control.width, control.height)
            pygame.draw.rect(self.screen, self.COLOR_EDIT_BG, rect)
            pygame.draw.rect(self.screen, (128, 128, 128), rect, 1)
            
        elif control.class_name == "COMBOBOX":
            rect = pygame.Rect(abs_x, abs_y, control.width, control.height)
            pygame.draw.rect(self.screen, self.COLOR_EDIT_BG, rect)
            pygame.draw.rect(self.screen, (128, 128, 128), rect, 1)
            # Dropdown arrow
            arrow_rect = pygame.Rect(abs_x + control.width - 18, abs_y + 1, 17, control.height - 2)
            self._draw_button_3d(arrow_rect, "▼", small=True)
            
        elif control.class_name in ["CHECKBOX", "BS_CHECKBOX"]:
            # Checkbox box
            box_rect = pygame.Rect(abs_x, abs_y + 2, 13, 13)
            pygame.draw.rect(self.screen, self.COLOR_EDIT_BG, box_rect)
            pygame.draw.rect(self.screen, (128, 128, 128), box_rect, 1)
            if control.checked:
                pygame.draw.line(self.screen, self.COLOR_TEXT, 
                               (abs_x + 2, abs_y + 8), (abs_x + 5, abs_y + 11), 2)
                pygame.draw.line(self.screen, self.COLOR_TEXT, 
                               (abs_x + 5, abs_y + 11), (abs_x + 11, abs_y + 4), 2)
            # Label
            text = self.font.render(control.text, True, self.COLOR_TEXT)
            self.screen.blit(text, (abs_x + 18, abs_y))
            
        elif control.class_name == "PROGRESSBAR":
            rect = pygame.Rect(abs_x, abs_y, control.width, control.height)
            pygame.draw.rect(self.screen, self.COLOR_EDIT_BG, rect)
            pygame.draw.rect(self.screen, (128, 128, 128), rect, 1)
            # Progress fill (example 50%)
            fill_width = int(control.width * 0.5)
            fill_rect = pygame.Rect(abs_x + 1, abs_y + 1, fill_width - 2, control.height - 2)
            pygame.draw.rect(self.screen, (0, 128, 0), fill_rect)
    
    def _draw_button_3d(self, rect, text, pressed=False, small=False):
        """Draw 3D-style button"""
        pygame.draw.rect(self.screen, self.COLOR_BUTTON, rect)
        
        if not pressed:
            # Raised effect
            pygame.draw.line(self.screen, self.COLOR_BUTTON_BORDER_LIGHT, 
                           (rect.x, rect.y), (rect.x + rect.width - 1, rect.y))
            pygame.draw.line(self.screen, self.COLOR_BUTTON_BORDER_LIGHT, 
                           (rect.x, rect.y), (rect.x, rect.y + rect.height - 1))
            pygame.draw.line(self.screen, self.COLOR_BUTTON_BORDER_DARK, 
                           (rect.x + rect.width - 1, rect.y), 
                           (rect.x + rect.width - 1, rect.y + rect.height - 1))
            pygame.draw.line(self.screen, self.COLOR_BUTTON_BORDER_DARK, 
                           (rect.x, rect.y + rect.height - 1), 
                           (rect.x + rect.width - 1, rect.y + rect.height - 1))
        else:
            # Sunken effect
            pygame.draw.line(self.screen, self.COLOR_BUTTON_BORDER_DARK, 
                           (rect.x, rect.y), (rect.x + rect.width - 1, rect.y))
            pygame.draw.line(self.screen, self.COLOR_BUTTON_BORDER_DARK, 
                           (rect.x, rect.y), (rect.x, rect.y + rect.height - 1))
        
        # Text
        font = self.font_small if small else self.font
        text_surface = font.render(text, True, self.COLOR_TEXT)
        text_rect = text_surface.get_rect(center=rect.center)
        self.screen.blit(text_surface, text_rect)
    
    def _draw_window_button(self, rect, symbol, btn_type):
        """Draw window control button (minimize, maximize, close)"""
        # Background
        pygame.draw.rect(self.screen, self.COLOR_BUTTON, rect)
        
        # 3D borders
        pygame.draw.line(self.screen, self.COLOR_BUTTON_BORDER_LIGHT, 
                       (rect.x, rect.y), (rect.x + rect.width - 1, rect.y))
        pygame.draw.line(self.screen, self.COLOR_BUTTON_BORDER_LIGHT, 
                       (rect.x, rect.y), (rect.x, rect.y + rect.height - 1))
        pygame.draw.line(self.screen, self.COLOR_BUTTON_BORDER_DARK, 
                       (rect.x + rect.width - 1, rect.y), 
                       (rect.x + rect.width - 1, rect.y + rect.height - 1))
        pygame.draw.line(self.screen, self.COLOR_BUTTON_BORDER_DARK, 
                       (rect.x, rect.y + rect.height - 1), 
                       (rect.x + rect.width - 1, rect.y + rect.height - 1))
        
        # Draw symbol
        center_x = rect.x + rect.width // 2
        center_y = rect.y + rect.height // 2
        
        if btn_type == "close":
            # X mark
            pygame.draw.line(self.screen, (0, 0, 0), 
                           (rect.x + 4, rect.y + 4), (rect.x + rect.width - 5, rect.y + rect.height - 5), 2)
            pygame.draw.line(self.screen, (0, 0, 0), 
                           (rect.x + rect.width - 5, rect.y + 4), (rect.x + 4, rect.y + rect.height - 5), 2)
        elif btn_type == "max":
            # Square (maximize) or double square (restore)
            if symbol == "❐":  # Restore
                # Two overlapping squares
                pygame.draw.rect(self.screen, (0, 0, 0), 
                               pygame.Rect(rect.x + 5, rect.y + 3, 8, 8), 1)
                pygame.draw.rect(self.screen, self.COLOR_BUTTON, 
                               pygame.Rect(rect.x + 3, rect.y + 5, 8, 8))
                pygame.draw.rect(self.screen, (0, 0, 0), 
                               pygame.Rect(rect.x + 3, rect.y + 5, 8, 8), 1)
            else:  # Maximize
                pygame.draw.rect(self.screen, (0, 0, 0), 
                               pygame.Rect(rect.x + 3, rect.y + 3, 10, 10), 1)
                pygame.draw.line(self.screen, (0, 0, 0), 
                               (rect.x + 3, rect.y + 5), (rect.x + 12, rect.y + 5), 1)
        elif btn_type == "min":
            # Underline (minimize)
            pygame.draw.line(self.screen, (0, 0, 0), 
                           (rect.x + 4, rect.y + rect.height - 5), 
                           (rect.x + rect.width - 5, rect.y + rect.height - 5), 2)
    
    def _handle_mouse_click(self, pos, button):
        """Handle mouse click"""
        x, y = pos
        
        # Click on taskbar windows
        taskbar_y = self.height - 30
        if y >= taskbar_y:
            # System tray area (right side) - ignore click
            tray_width = 80
            if x >= self.width - tray_width:
                return
            
            # Visible windows (excluding dialogs)
            visible_windows = [(hwnd, self.windows[hwnd]) for hwnd in self.z_order 
                              if hwnd in self.windows and self.windows[hwnd].visible 
                              and not self.windows[hwnd].is_dialog]
            
            if not visible_windows:
                return
            
            # Calculate button width
            max_btn_width = 140
            available_width = self.width - tray_width - 80
            btn_width = min(max_btn_width, available_width // len(visible_windows) - 5)
            btn_width = max(60, btn_width)
            
            # Which button was clicked?
            btn_x = 70
            for hwnd, win in visible_windows:
                if btn_x <= x <= btn_x + btn_width:
                    if win.minimized:
                        # If minimized, restore
                        win.restore()
                    elif hwnd == self.active_window:
                        # If already active, minimize
                        win.minimize()
                        # Activate next visible window
                        for h in reversed(self.z_order):
                            if h in self.windows and self.windows[h].visible and not self.windows[h].minimized and not self.windows[h].is_dialog:
                                self.active_window = h
                                break
                        return
                    
                    # Make window active and bring to front
                    self.active_window = hwnd
                    self.z_order.remove(hwnd)
                    self.z_order.append(hwnd)
                    return
                btn_x += btn_width + 5
            return
        
        # Check windows in reverse order (topmost first)
        for hwnd in reversed(self.z_order):
            if hwnd in self.windows:
                win = self.windows[hwnd]
                if win.visible and not win.minimized and win.contains_point(x, y):
                    # Make window active and bring to front
                    self.active_window = hwnd
                    self.z_order.remove(hwnd)
                    self.z_order.append(hwnd)
                    
                    # Title bar buttons (right to left: close, max, min)
                    btn_size = 16
                    btn_y_start = win.y + 5
                    btn_y_end = win.y + 5 + btn_size
                    
                    # Close butonu (X)
                    close_x = win.x + win.width - btn_size - 5
                    if close_x <= x <= close_x + btn_size and btn_y_start <= y <= btn_y_end:
                        self._close_window(hwnd)
                        return
                    
                    # Minimize and maximize buttons if not a dialog
                    if not win.is_dialog:
                        # Maximize butonu (□)
                        max_x = win.x + win.width - btn_size * 2 - 7
                        if max_x <= x <= max_x + btn_size and btn_y_start <= y <= btn_y_end:
                            win.maximize(self.width, self.height, 30)
                            return
                        
                        # Minimize butonu (_)
                        min_x = win.x + win.width - btn_size * 3 - 9
                        if min_x <= x <= min_x + btn_size and btn_y_start <= y <= btn_y_end:
                            win.minimize()
                            # Activate next visible window
                            for h in reversed(self.z_order):
                                if h in self.windows and self.windows[h].visible and not self.windows[h].minimized:
                                    self.active_window = h
                                    break
                            return
                    
                    # Title bar click (start dragging) - if not maximized
                    if win.y + 3 <= y <= win.y + 25 and not win.maximized:
                        self.dragging_window = hwnd
                        self.drag_offset_x = x - win.x
                        self.drag_offset_y = y - win.y
                        return
                    
                    # Click on controls in content area
                    content_x = win.x + 3
                    content_y = win.y + 28
                    for control in win.controls:
                        if control.class_name == "BUTTON":
                            btn_x = content_x + control.x
                            btn_y = content_y + control.y
                            if (btn_x <= x <= btn_x + control.width and 
                                btn_y <= y <= btn_y + control.height):
                                # If dialog window (MessageBox) - OK/Cancel button closes it
                                if win.is_dialog:
                                    self._close_window(hwnd)
                                    return
                                # Normal window - WM_COMMAND message (TODO)
                    
                    break
    
    def _handle_key_press(self, event):
        """Handle keyboard key press"""
        # If console input mode is active
        if self.console_input_active:
            if event.key == pygame.K_RETURN:
                # Enter - input completed
                self.console_input_result = self.console_input
                self.console_input = ""
                self.console_input_active = False
                self.console_input_ready.set()  # Send signal to waiting thread
            elif event.key == pygame.K_BACKSPACE:
                # Backspace - delete last character
                self.console_input = self.console_input[:-1]
            elif event.key == pygame.K_ESCAPE:
                # ESC - cancel
                self.console_input_result = ""
                self.console_input = ""
                self.console_input_active = False
                self.console_input_ready.set()
            else:
                # Printable character
                if event.unicode and event.unicode.isprintable():
                    self.console_input += event.unicode
    
    def _check_messagebox(self):
        """Check MessageBox requests"""
        try:
            msg = self.messagebox_queue.get_nowait()
            self._show_messagebox(msg['caption'], msg['text'], msg['type'])
        except queue.Empty:
            pass
    
    def _show_messagebox(self, caption, text, msg_type):
        """Show MessageBox"""
        # Create MessageBox window
        width = max(300, len(text) * 8 + 50)
        height = 120
        x = (self.width - width) // 2
        y = (self.height - height) // 2
        
        hwnd = self.create_window(caption, x, y, width, height)
        win = self.windows[hwnd]
        win.is_dialog = True  # Show only close button
        
        # Text
        text_ctrl = FakeControl(self.get_next_hwnd(), "STATIC", text, 20, 20, width - 40, 30)
        win.controls.append(text_ctrl)
        
        # OK button
        ok_btn = FakeControl(self.get_next_hwnd(), "BUTTON", "OK", (width - 80) // 2, height - 60, 80, 25)
        win.controls.append(ok_btn)
        
        self.show_window(hwnd)
    
    def _close_window(self, hwnd):
        """Close window"""
        if hwnd in self.windows:
            self.windows[hwnd].visible = False
            if hwnd in self.z_order:
                self.z_order.remove(hwnd)
            if self.active_window == hwnd:
                self.active_window = self.z_order[-1] if self.z_order else None
    
    def get_next_hwnd(self):
        """Get new HWND"""
        hwnd = self.next_hwnd
        self.next_hwnd += 4
        return hwnd
    
    def create_window(self, title, x, y, width, height, style=0):
        """Create new window"""
        hwnd = self.get_next_hwnd()
        window = FakeWindow(hwnd, title, x, y, width, height, style)
        self.windows[hwnd] = window
        self.z_order.append(hwnd)
        
        log.debug(f"GUI: Window created - HWND=0x{hwnd:08x}, '{title}'")
        return hwnd
    
    def create_control(self, parent_hwnd, class_name, text, x, y, width, height, style=0):
        """Create new control"""
        hwnd = self.get_next_hwnd()
        control = FakeControl(hwnd, class_name, text, x, y, width, height, style)
        control.parent_hwnd = parent_hwnd
        
        self.controls[hwnd] = control
        
        if parent_hwnd in self.windows:
            self.windows[parent_hwnd].controls.append(control)
        
        log.debug(f"GUI: Control created - HWND=0x{hwnd:08x}, {class_name}, '{text}'")
        return hwnd
    
    def show_window(self, hwnd, show=True):
        """Show/hide window"""
        if hwnd in self.windows:
            self.windows[hwnd].visible = show
            if show:
                self.active_window = hwnd
                if hwnd not in self.z_order:
                    self.z_order.append(hwnd)
    
    def set_window_text(self, hwnd, text):
        """Set window/control text"""
        if hwnd in self.windows:
            self.windows[hwnd].title = text
            self.windows[hwnd].text = text
        elif hwnd in self.controls:
            self.controls[hwnd].text = text
    
    def get_window_text(self, hwnd):
        """Get window/control text"""
        if hwnd in self.windows:
            return self.windows[hwnd].text
        elif hwnd in self.controls:
            return self.controls[hwnd].text
        return ""
    
    def show_messagebox(self, caption, text, msg_type=0):
        """Show MessageBox (thread-safe)"""
        self.messagebox_queue.put({
            'caption': caption,
            'text': text,
            'type': msg_type
        })
        return 1  # IDOK
    
    # ==================== CONSOLE WINDOW ====================
    
    def _create_console_window(self):
        """Create console window"""
        self.console_hwnd = self.create_window("Console - Program Output", 
                                                50, 400, 600, 280)
        self.windows[self.console_hwnd].bg_color = (12, 12, 12)  # Black background
        self.show_window(self.console_hwnd)
    
    def _draw_console_window(self, window):
        """Draw console window"""
        if not window.visible or window.minimized:
            return
        
        is_active = (window.hwnd == self.active_window)
        
        # Window shadow
        shadow_rect = pygame.Rect(window.x + 3, window.y + 3, window.width, window.height)
        pygame.draw.rect(self.screen, (64, 64, 64), shadow_rect)
        
        # Window frame
        frame_rect = pygame.Rect(window.x, window.y, window.width, window.height)
        pygame.draw.rect(self.screen, (12, 12, 12), frame_rect)  # Black background
        pygame.draw.rect(self.screen, self.COLOR_BUTTON_BORDER_DARK, frame_rect, 1)
        
        # 3D edge effect
        pygame.draw.line(self.screen, (64, 64, 64), 
                        (window.x, window.y), (window.x + window.width - 1, window.y))
        pygame.draw.line(self.screen, (64, 64, 64), 
                        (window.x, window.y), (window.x, window.y + window.height - 1))
        
        # Title bar
        title_color = self.COLOR_TITLE_BAR if is_active else self.COLOR_TITLE_BAR_INACTIVE
        title_rect = pygame.Rect(window.x + 3, window.y + 3, window.width - 6, 22)
        pygame.draw.rect(self.screen, title_color, title_rect)
        
        # Title text
        title_text = self.font_bold.render(window.title[:50], True, self.COLOR_TITLE_TEXT)
        self.screen.blit(title_text, (window.x + 8, window.y + 6))
        
        # Window buttons
        btn_size = 16
        btn_y = window.y + 5
        
        # Close butonu (X)
        close_rect = pygame.Rect(window.x + window.width - btn_size - 5, btn_y, btn_size, btn_size)
        self._draw_window_button(close_rect, "×", "close")
        
        # Maximize butonu
        max_rect = pygame.Rect(window.x + window.width - btn_size * 2 - 7, btn_y, btn_size, btn_size)
        max_symbol = "❐" if window.maximized else "□"
        self._draw_window_button(max_rect, max_symbol, "max")
        
        # Minimize butonu
        min_rect = pygame.Rect(window.x + window.width - btn_size * 3 - 9, btn_y, btn_size, btn_size)
        self._draw_window_button(min_rect, "─", "min")
        
        # Content area (console output)
        content_x = window.x + 5
        content_y = window.y + 30
        content_width = window.width - 10
        content_height = window.height - 55
        
        # Content background
        content_rect = pygame.Rect(content_x, content_y, content_width, content_height)
        pygame.draw.rect(self.screen, (12, 12, 12), content_rect)
        
        # Draw console lines
        line_height = 14
        max_visible_lines = content_height // line_height
        
        # Scroll calculation
        start_line = max(0, len(self.console_lines) - max_visible_lines - self.console_scroll)
        end_line = min(len(self.console_lines), start_line + max_visible_lines)
        
        y_offset = content_y + 2
        for i in range(start_line, end_line):
            if i < len(self.console_lines):
                line_data = self.console_lines[i]
                text = line_data['text']
                color = line_data.get('color', (192, 192, 192))
                
                # Render line
                if text.strip():
                    text_surface = self.font_console.render(text[:80], True, color)
                    self.screen.blit(text_surface, (content_x + 3, y_offset))
                y_offset += line_height
        
        # Input area
        input_y = window.y + window.height - 22
        input_rect = pygame.Rect(content_x, input_y, content_width, 18)
        
        # Different background color if input mode is active
        if self.console_input_active:
            pygame.draw.rect(self.screen, (32, 32, 64), input_rect)  # Blue tint
            pygame.draw.rect(self.screen, (128, 128, 255), input_rect, 1)  # Blue border
        else:
            pygame.draw.rect(self.screen, (24, 24, 24), input_rect)
            pygame.draw.rect(self.screen, (64, 64, 64), input_rect, 1)
        
        # Prompt and input
        prompt = "> "
        cursor = "|" if (self.console_input_active and self.console_cursor_visible) else ""
        input_text = prompt + self.console_input + cursor
        input_color = (0, 255, 0) if self.console_input_active else (128, 128, 128)
        prompt_surface = self.font_console.render(input_text, True, input_color)
        self.screen.blit(prompt_surface, (content_x + 3, input_y + 2))
        
        # Input waiting hint
        if self.console_input_active:
            hint_text = "[Waiting for input - Enter: Send, ESC: Cancel]"
            hint_surface = self.font_small.render(hint_text, True, (255, 255, 128))
            self.screen.blit(hint_surface, (content_x + 3, input_y - 16))
    
    def console_write(self, text, color=(192, 192, 192), stream="stdout"):
        """Write to console (thread-safe)"""
        # Determine color
        if stream == "stderr":
            color = (255, 64, 64)  # Red
        elif stream == "stdin":
            color = (64, 255, 64)  # Green
        
        # Split into lines
        lines = text.split('\n')
        for line in lines:
            if line or text.endswith('\n'):
                self.console_lines.append({
                    'text': line,
                    'color': color,
                    'stream': stream
                })
        
        # Check maximum line count
        while len(self.console_lines) > self.console_max_lines:
            self.console_lines.pop(0)
    
    def console_write_stdout(self, text):
        """Write to stdout"""
        self.console_write(text, color=(192, 192, 192), stream="stdout")
    
    def console_write_stderr(self, text):
        """Write to stderr"""
        self.console_write(text, color=(255, 64, 64), stream="stderr")
    
    def console_read_line(self):
        """Read line from console (blocking - called from emulator thread)"""
        return self.request_console_input()
    
    def request_console_input(self):
        """
        Request console input - thread-safe
        Called from emulator thread, waits for GUI thread to get input
        """
        # Activate input mode
        self.console_input = ""
        self.console_input_result = ""
        self.console_input_ready.clear()
        self.console_input_active = True
        self.console_cursor_visible = True
        self.console_cursor_timer = 0
        
        # Wait for GUI thread to get input
        self.console_input_ready.wait()  # Blocking wait
        
        # Get and return result
        result = self.console_input_result
        
        return result
    
    def console_clear(self):
        """Clear console"""
        self.console_lines.clear()
    
    def draw_text(self, text, x, y, hwnd=None, color=None):
        """Draw text inside window (for TextOutA/DrawTextA)"""
        if color is None:
            color = self.COLOR_TEXT
        
        # Find active window
        target_hwnd = hwnd or self.active_window
        if target_hwnd and target_hwnd in self.windows:
            window = self.windows[target_hwnd]
            
            # Draw text relative to window coordinates
            abs_x = window.x + 3 + x  # 3 = window border
            abs_y = window.y + 28 + y  # 28 = title bar height
            
            # Save text to FakeWindow (for redraw)
            if not hasattr(window, 'drawn_texts'):
                window.drawn_texts = []
            window.drawn_texts.append({
                'text': text,
                'x': x,
                'y': y,
                'color': color
            })
            
            log.info(f"GUI: Text drawn - '{text}' at ({x}, {y}) in HWND=0x{target_hwnd:x}")


class CPUEmulator:
    """Unicorn-based x86 CPU emulator"""
    
    # Memory layout constants
    STACK_BASE = 0x7FF00000
    STACK_SIZE = 0x00100000  # 1MB stack
    HEAP_BASE = 0x10000000
    HEAP_SIZE = 128 * 1024 * 1024  # 128 MiB heap
    API_HOOK_BASE = 0x70000000  # API hook adresleri
    
    def __init__(self, pe_loader, gui=None):
        self.pe_loader = pe_loader
        self.gui = gui  # PseudoWindowsGUI reference
        self.uc = None
        self.cs = None
        self.stop_emulation = False
        self.instruction_count = 0
        self.max_instructions = 100000  # Maximum instruction limit
        
        # Memory management
        self.heap_current = self.HEAP_BASE
        self.mapped_regions = []
        
        # API hook system
        self.api_hooks = {}
        self.api_handler = None
        self.next_hook_addr = self.API_HOOK_BASE
        
        # Callback system
        self.callback_stack = []  # Stack for nested callback support
        self.callback_return_addr = 0x6FFF0000  # Callback return hook address
        self.pending_callback = None  # Pending callback info
        
        # Console input system
        self.pending_console_read = None  # Pending ReadConsoleA request
        self.stop_for_input = False  # Paused for input?
        
        # Special memory addresses
        self.cmdline_addr = 0
        self.cmdline_wide_addr = 0
        self.peb_addr = 0
        self.teb_addr = 0
        
    def initialize(self):
        """Initialize emulator"""
        log.header("Initializing CPU Emulator")
        
        # Create Unicorn emulator (32-bit x86)
        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        
        # Create Capstone disassembler
        self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
        self.cs.detail = True
        
        log.success("Unicorn and Capstone initialized")
        
        # Create API handler (with GUI reference)
        self.api_handler = WinAPIHandler(self, self.gui)
        
        # Setup memory
        self._setup_memory()
        
        # Setup stack
        self._setup_stack()
        
        # Create PEB/TEB structures
        self._setup_peb_teb()
        
        # Setup callback return hook region
        self._setup_callback_return_hook()
        
        # Setup import hooks
        self._setup_import_hooks()
        
        # Register hooks
        self._setup_hooks()
        
        return True
    
    def _align_address(self, addr, alignment=0x1000):
        """Align address"""
        return addr & ~(alignment - 1)
    
    def _align_size(self, size, alignment=0x1000):
        """Align size"""
        return (size + alignment - 1) & ~(alignment - 1)
    
    def _map_memory(self, address, size, perms=UC_PROT_ALL):
        """Map memory region"""
        aligned_addr = self._align_address(address)
        aligned_size = self._align_size(size + (address - aligned_addr))
        
        # Check for overlap
        for start, end in self.mapped_regions:
            if aligned_addr < end and aligned_addr + aligned_size > start:
                # Already mapped, skip
                return
        
        try:
            self.uc.mem_map(aligned_addr, aligned_size, perms)
            self.mapped_regions.append((aligned_addr, aligned_addr + aligned_size))
            log.debug(f"Memory mapped: 0x{aligned_addr:08x} - 0x{aligned_addr + aligned_size:08x}")
        except UcError as e:
            log.warning(f"Memory map error: {e}")
    
    def _setup_memory(self):
        """Load PE file into memory"""
        log.header("Memory Configuration")
        
        image_base = self.pe_loader.image_base
        image_size = self.pe_loader.pe.OPTIONAL_HEADER.SizeOfImage
        
        # Allocate memory for main image
        self._map_memory(image_base, image_size)
        
        # Write PE header
        header_size = self.pe_loader.pe.OPTIONAL_HEADER.SizeOfHeaders
        pe_data = self.pe_loader.pe.get_memory_mapped_image()
        self.uc.mem_write(image_base, pe_data[:header_size])
        log.info(f"PE Header loaded: 0x{image_base:08x}")
        
        # Load sections
        for section in self.pe_loader.sections:
            va = image_base + section['virtual_address']
            data = section['data']
            
            if len(data) > 0:
                self.uc.mem_write(va, data)
                log.info(f"Section '{section['name']}' loaded: 0x{va:08x}")
        
        # Allocate memory for stack
        self._map_memory(self.STACK_BASE, self.STACK_SIZE)
        log.info(f"Stack allocated: 0x{self.STACK_BASE:08x} - 0x{self.STACK_BASE + self.STACK_SIZE:08x}")
        
        # Allocate memory for heap - larger and aligned
        try:
            self.uc.mem_map(self.HEAP_BASE, self.HEAP_SIZE, UC_PROT_ALL)
            self.mapped_regions.append((self.HEAP_BASE, self.HEAP_BASE + self.HEAP_SIZE))
            log.info(f"Heap allocated: 0x{self.HEAP_BASE:08x} - 0x{self.HEAP_BASE + self.HEAP_SIZE:08x}")
        except UcError as e:
            log.error(f"Heap allocation error: {e}")
        
        # API hook region
        self._map_memory(self.API_HOOK_BASE, 0x100000)
        log.info(f"API Hook region: 0x{self.API_HOOK_BASE:08x}")
    
    def _setup_stack(self):
        """Configure stack"""
        # Set ESP to middle of stack
        esp = self.STACK_BASE + self.STACK_SIZE - 0x1000
        self.uc.reg_write(UC_X86_REG_ESP, esp)
        self.uc.reg_write(UC_X86_REG_EBP, esp)
        
        log.info(f"Stack pointer: ESP = 0x{esp:08x}")
        
        # Allocate memory for command line
        self.cmdline_addr = self.heap_alloc(256)
        cmdline = self.pe_loader.filepath + "\x00"
        self.uc.mem_write(self.cmdline_addr, cmdline.encode('utf-8'))
        
        self.cmdline_wide_addr = self.heap_alloc(512)
        cmdline_wide = self.pe_loader.filepath.encode('utf-16-le') + b'\x00\x00'
        self.uc.mem_write(self.cmdline_wide_addr, cmdline_wide)
    
    def _setup_peb_teb(self):
        """Create PEB and TEB structures"""
        # Memory for TEB
        self.teb_addr = self.heap_alloc(0x1000)
        # Memory for PEB
        self.peb_addr = self.heap_alloc(0x1000)
        
        # TEB structure (simplified)
        # Offset 0x00: SEH chain
        # Offset 0x04: Stack base
        # Offset 0x08: Stack limit
        # Offset 0x18: TEB self pointer
        # Offset 0x30: PEB pointer
        teb_data = b'\x00' * 0x1000
        teb_data = bytearray(teb_data)
        
        # TEB self pointer (FS:[0x18])
        struct.pack_into('<I', teb_data, 0x18, self.teb_addr)
        # PEB pointer (FS:[0x30])
        struct.pack_into('<I', teb_data, 0x30, self.peb_addr)
        # ProcessId (FS:[0x20])
        struct.pack_into('<I', teb_data, 0x20, 1234)
        # ThreadId (FS:[0x24])
        struct.pack_into('<I', teb_data, 0x24, 5678)
        
        self.uc.mem_write(self.teb_addr, bytes(teb_data))
        
        # PEB structure (simplified)
        # Offset 0x02: BeingDebugged
        # Offset 0x08: ImageBaseAddress
        # Offset 0x0C: Ldr
        peb_data = b'\x00' * 0x1000
        peb_data = bytearray(peb_data)
        
        # ImageBaseAddress
        struct.pack_into('<I', peb_data, 0x08, self.pe_loader.image_base)
        # BeingDebugged = 0
        peb_data[0x02] = 0
        
        self.uc.mem_write(self.peb_addr, bytes(peb_data))
        
        # Set FS segment to TEB
        # Create GDT entry
        gdt_addr = self.heap_alloc(0x1000)
        
        # GDT entry format: base, limit, access, flags
        def create_gdt_entry(base, limit, access, flags):
            entry = bytearray(8)
            # Limit (bits 0-15)
            entry[0] = limit & 0xFF
            entry[1] = (limit >> 8) & 0xFF
            # Base (bits 0-15)
            entry[2] = base & 0xFF
            entry[3] = (base >> 8) & 0xFF
            # Base (bits 16-23)
            entry[4] = (base >> 16) & 0xFF
            # Access
            entry[5] = access
            # Limit (bits 16-19) + Flags
            entry[6] = ((limit >> 16) & 0x0F) | (flags << 4)
            # Base (bits 24-31)
            entry[7] = (base >> 24) & 0xFF
            return bytes(entry)
        
        # Null descriptor
        null_entry = b'\x00' * 8
        # Code segment (CS)
        code_entry = create_gdt_entry(0, 0xFFFFF, 0x9B, 0x0C)
        # Data segment (DS, ES, SS)
        data_entry = create_gdt_entry(0, 0xFFFFF, 0x93, 0x0C)
        # FS segment (TEB)
        fs_entry = create_gdt_entry(self.teb_addr, 0xFFF, 0x93, 0x00)
        
        gdt = null_entry + code_entry + data_entry + fs_entry
        self.uc.mem_write(gdt_addr, gdt)
        
        # Set GDTR
        self.uc.reg_write(UC_X86_REG_GDTR, (0, gdt_addr, len(gdt) - 1, 0))
        
        # Set segment registers
        self.uc.reg_write(UC_X86_REG_CS, 0x08)  # Code segment
        self.uc.reg_write(UC_X86_REG_DS, 0x10)  # Data segment
        self.uc.reg_write(UC_X86_REG_ES, 0x10)
        self.uc.reg_write(UC_X86_REG_SS, 0x10)
        self.uc.reg_write(UC_X86_REG_FS, 0x18)  # TEB segment
        self.uc.reg_write(UC_X86_REG_GS, 0x00)
        
        log.info(f"TEB configured: 0x{self.teb_addr:08x}")
        log.info(f"PEB configured: 0x{self.peb_addr:08x}")
    
    def heap_alloc(self, size):
        """Allocate memory from heap"""
        aligned_size = self._align_size(size, 16)
        addr = self.heap_current
        self.heap_current += aligned_size
        return addr
    
    def _setup_import_hooks(self):
        """Setup hooks for import functions"""
        log.header("Setting Up API Hooks")
        
        # Create hook address for each import
        for dll_name, functions in self.pe_loader.imports.items():
            log.info(f"DLL hook: {dll_name}")
            
            for func_info in functions:
                func_name = func_info['name']
                iat_addr = func_info['address']
                
                # Create hook address
                hook_addr = self.next_hook_addr
                self.next_hook_addr += 4
                
                # Write INT 0x80 instruction (hook trigger)
                # Actually we'll use RET instruction and catch it with hook_code callback
                self.uc.mem_write(hook_addr, b'\xC3')  # RET
                
                # Write hook address to IAT
                self.uc.mem_write(iat_addr, struct.pack('<I', hook_addr))
                
                # Hook registration
                self.api_hooks[hook_addr] = {
                    'dll': dll_name,
                    'name': func_name,
                    'iat_addr': iat_addr
                }
                
                log.debug(f"  Hook: {func_name} -> 0x{hook_addr:08x}")
    
    def _setup_callback_return_hook(self):
        """Setup callback return hook region"""
        # Allocate special memory region for callback return address
        # When execution reaches this address, we know callback has finished
        try:
            self.uc.mem_map(self.callback_return_addr, 0x1000, UC_PROT_ALL)
            # Write RET instruction (0xC3) - will be hooked
            self.uc.mem_write(self.callback_return_addr, b'\xC3')
            log.debug(f"Callback return hook: 0x{self.callback_return_addr:08x}")
        except UcError as e:
            log.warning(f"Could not setup callback return hook: {e}")
    
    def call_callback(self, callback_addr, args, return_handler=None):
        """
        Call callback function (WndProc, EnumWindowsProc, etc.)
        
        Args:
            callback_addr: Address of callback function
            args: Callback arguments (list)
            return_handler: Function to call when callback finishes (optional)
        
        Returns:
            Callback return value (EAX)
        """
        if callback_addr == 0:
            log.warning("Callback address is 0, skipping call")
            return 0
        
        # Save current state
        saved_esp = self.uc.reg_read(UC_X86_REG_ESP)
        saved_eip = self.uc.reg_read(UC_X86_REG_EIP)
        saved_eax = self.uc.reg_read(UC_X86_REG_EAX)
        saved_ebx = self.uc.reg_read(UC_X86_REG_EBX)
        saved_ecx = self.uc.reg_read(UC_X86_REG_ECX)
        saved_edx = self.uc.reg_read(UC_X86_REG_EDX)
        saved_esi = self.uc.reg_read(UC_X86_REG_ESI)
        saved_edi = self.uc.reg_read(UC_X86_REG_EDI)
        saved_ebp = self.uc.reg_read(UC_X86_REG_EBP)
        
        # Add callback info to stack
        callback_info = {
            'addr': callback_addr,
            'args': args,
            'return_handler': return_handler,
            'saved_state': {
                'esp': saved_esp,
                'eip': saved_eip,
                'eax': saved_eax,
                'ebx': saved_ebx,
                'ecx': saved_ecx,
                'edx': saved_edx,
                'esi': saved_esi,
                'edi': saved_edi,
                'ebp': saved_ebp,
            }
        }
        self.callback_stack.append(callback_info)
        
        # Push arguments to stack (right to left - cdecl/stdcall)
        esp = saved_esp
        
        # Push arguments in reverse order
        for arg in reversed(args):
            esp -= 4
            self.uc.mem_write(esp, struct.pack("<I", arg & 0xFFFFFFFF))
        
        # Push callback_return_addr as return address
        esp -= 4
        self.uc.mem_write(esp, struct.pack("<I", self.callback_return_addr))
        
        # Update ESP
        self.uc.reg_write(UC_X86_REG_ESP, esp)
        
        log.debug(f"Calling callback: 0x{callback_addr:08x} args={[hex(a) for a in args]}")
        
        # Run callback
        try:
            self.uc.emu_start(callback_addr, self.callback_return_addr, 0, 50000)
        except UcError as e:
            log.error(f"Callback error: {e}")
        
        # Get return value
        result = self.uc.reg_read(UC_X86_REG_EAX)
        
        # Pop callback info from stack
        if self.callback_stack:
            completed_callback = self.callback_stack.pop()
            
            # Call return handler if exists
            if completed_callback.get('return_handler'):
                completed_callback['return_handler'](result)
        
        # Restore state (except EAX - return value)
        self.uc.reg_write(UC_X86_REG_ESP, saved_esp)
        self.uc.reg_write(UC_X86_REG_EIP, saved_eip)
        self.uc.reg_write(UC_X86_REG_EBX, saved_ebx)
        self.uc.reg_write(UC_X86_REG_ECX, saved_ecx)
        self.uc.reg_write(UC_X86_REG_EDX, saved_edx)
        self.uc.reg_write(UC_X86_REG_ESI, saved_esi)
        self.uc.reg_write(UC_X86_REG_EDI, saved_edi)
        self.uc.reg_write(UC_X86_REG_EBP, saved_ebp)
        
        log.debug(f"Callback completed: 0x{callback_addr:08x} -> 0x{result:08x}")
        
        return result
    
    def call_wndproc(self, wndproc_addr, hwnd, msg, wParam, lParam):
        """
        Call WndProc callback
        
        Args:
            wndproc_addr: Address of WndProc function
            hwnd: Window handle
            msg: Message code (WM_PAINT, etc.)
            wParam: wParam value
            lParam: lParam value
        
        Returns:
            WndProc return value
        """
        return self.call_callback(wndproc_addr, [hwnd, msg, wParam, lParam])
    
    def _setup_hooks(self):
        """Register Unicorn hooks"""
        # Instruction hook
        self.uc.hook_add(UC_HOOK_CODE, self._hook_code)
        
        # Memory access error hook
        self.uc.hook_add(UC_HOOK_MEM_UNMAPPED, self._hook_mem_invalid)
        
        # Interrupt hook
        self.uc.hook_add(UC_HOOK_INTR, self._hook_interrupt)
    
    def _hook_code(self, uc, address, size, user_data):
        """Hook called for each instruction"""
        self.instruction_count += 1
        
        # Limit check
        if self.instruction_count > self.max_instructions:
            log.warning(f"Maximum instruction limit reached ({self.max_instructions})! Stopping emulation...")
            self.stop_emulation = True
            uc.emu_stop()
            return
        
        # Stop flag check
        if self.stop_emulation:
            uc.emu_stop()
            return
        
        # Callback return check
        if address == self.callback_return_addr:
            # Callback completed, stop emulation
            uc.emu_stop()
            return
        
        # API hook check
        if address in self.api_hooks:
            hook_info = self.api_hooks[address]
            self._handle_api_call(hook_info)
            return
        
        # Disassembly (only in debug mode)
        if self.instruction_count <= 50 or self.instruction_count % 1000 == 0:
            try:
                code = uc.mem_read(address, min(size, 15))
                for insn in self.cs.disasm(bytes(code), address):
                    eax = uc.reg_read(UC_X86_REG_EAX)
                    ebx = uc.reg_read(UC_X86_REG_EBX)
                    ecx = uc.reg_read(UC_X86_REG_ECX)
                    edx = uc.reg_read(UC_X86_REG_EDX)
                    
                    if self.instruction_count <= 50:
                        log.debug(f"0x{address:08x}: {insn.mnemonic:8s} {insn.op_str}")
                    break
            except:
                pass
    
    def _handle_api_call(self, hook_info):
        """Handle API call"""
        dll_name = hook_info['dll'].lower()
        func_name = hook_info['name']
        
        log.info(f"{Fore.GREEN}API Call:{Style.RESET_ALL} {dll_name}!{func_name}")
        
        # Read arguments from stack
        esp = self.uc.reg_read(UC_X86_REG_ESP)
        
        # Return address
        ret_addr = struct.unpack('<I', self.uc.mem_read(esp, 4))[0]
        
        # Arguments (maximum 16 - CreateWindowEx takes 12 arguments)
        args = []
        for i in range(16):
            arg = struct.unpack('<I', self.uc.mem_read(esp + 4 + i * 4, 4))[0]
            args.append(arg)
        
        # Find and call handler
        handler = self.api_handler.get_api_handler(func_name)
        
        if handler:
            result = handler(args)
        else:
            log.warning(f"Unemulated API: {func_name}")
            result = 0
        
        # Write result to EAX
        self.uc.reg_write(UC_X86_REG_EAX, result & 0xFFFFFFFF)
        
        # Clean up stack (stdcall convention)
        # Simple approach: jump to return address
        self.uc.reg_write(UC_X86_REG_EIP, ret_addr)
        self.uc.reg_write(UC_X86_REG_ESP, esp + 4)  # Pop return address
    
    def _hook_mem_invalid(self, uc, access, address, size, value, user_data):
        """Invalid memory access hook"""
        access_types = {
            UC_MEM_READ_UNMAPPED: "READ",
            UC_MEM_WRITE_UNMAPPED: "WRITE", 
            UC_MEM_FETCH_UNMAPPED: "FETCH",
        }
        access_type = access_types.get(access, f"Unknown({access})")
        
        log.error(f"Invalid memory access: {access_type} @ 0x{address:08x}, size={size}")
        
        # Try to auto-map memory
        try:
            aligned_addr = self._align_address(address)
            self._map_memory(aligned_addr, 0x10000)
            return True  # Continue
        except:
            return False  # Stop
    
    def _hook_interrupt(self, uc, intno, user_data):
        """Interrupt hook"""
        log.debug(f"Interrupt: {intno}")
        
        if intno == 0x80:
            # Linux syscall (not used in Windows but catch anyway)
            log.warning("Linux system call detected (INT 0x80)")
        elif intno == 0x2E:
            # Windows syscall
            eax = uc.reg_read(UC_X86_REG_EAX)
            log.warning(f"Windows system call: EAX=0x{eax:08x}")
    
    def run(self, max_instructions=None):
        """Start emulation"""
        if max_instructions:
            self.max_instructions = max_instructions
        
        log.header("Starting Emulation")
        
        entry_point = self.pe_loader.image_base + self.pe_loader.entry_point
        log.info(f"Entry point: 0x{entry_point:08x}")
        log.info(f"Maximum instructions: {self.max_instructions}")
        
        try:
            # Start emulation
            self.uc.emu_start(entry_point, 0, 0, self.max_instructions)
            
        except UcError as e:
            eip = self.uc.reg_read(UC_X86_REG_EIP)
            esp = self.uc.reg_read(UC_X86_REG_ESP)
            log.error(f"Emulation error: {e}")
            log.error(f"EIP: 0x{eip:08x}, ESP: 0x{esp:08x}")
        
        log.header("Emulation Completed")
        log.info(f"Total instruction count: {self.instruction_count}")
        
        # Show register state
        self._print_registers()
    
    def _print_registers(self):
        """Print register values"""
        log.header("Register State")
        
        regs = [
            ("EAX", UC_X86_REG_EAX), ("EBX", UC_X86_REG_EBX),
            ("ECX", UC_X86_REG_ECX), ("EDX", UC_X86_REG_EDX),
            ("ESI", UC_X86_REG_ESI), ("EDI", UC_X86_REG_EDI),
            ("EBP", UC_X86_REG_EBP), ("ESP", UC_X86_REG_ESP),
            ("EIP", UC_X86_REG_EIP), ("EFLAGS", UC_X86_REG_EFLAGS),
        ]
        
        for i in range(0, len(regs), 2):
            name1, reg1 = regs[i]
            val1 = self.uc.reg_read(reg1)
            
            if i + 1 < len(regs):
                name2, reg2 = regs[i + 1]
                val2 = self.uc.reg_read(reg2)
                log.info(f"{name1}: 0x{val1:08x}    {name2}: 0x{val2:08x}")
            else:
                log.info(f"{name1}: 0x{val1:08x}")
    
    def disassemble(self, address, count=10):
        """Disassemble starting from specified address"""
        log.header(f"Disassembly @ 0x{address:08x}")
        
        try:
            code = self.uc.mem_read(address, count * 15)  # Each instruction max 15 bytes
            
            disasm_count = 0
            for insn in self.cs.disasm(bytes(code), address):
                bytes_str = ' '.join(f'{b:02x}' for b in insn.bytes)
                log.info(f"0x{insn.address:08x}: {bytes_str:24s} {insn.mnemonic:8s} {insn.op_str}")
                disasm_count += 1
                if disasm_count >= count:
                    break
        except Exception as e:
            log.error(f"Disassembly error: {e}!")


def main():
    """Main function"""
    print(f"{Fore.CYAN}{Style.BRIGHT}")
    print("╔══════════════════════════════════════════════════════════╗")
    print("║          Windows 32-bit EXE Emulator v0.0.1              ║")
    print("║       PE Loader + CPU + Pygame GUI Emulation             ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print(f"{Style.RESET_ALL}")
    
    import argparse
    parser = argparse.ArgumentParser(
        description="Windows 32-bit EXE Emulator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"EXE files are searched in c_drive/ folder by default.\nExample: python winexe32emu.py hello_messagebox.exe"
    )
    parser.add_argument("exe", help="PE file to run (inside c_drive/ or full path)")
    parser.add_argument("-n", "--max-instructions", type=int, default=100000,
                        help="Maximum instructions to execute (default: 100000)")
    parser.add_argument("-m", "--memory", type=int, default=128,
                        help="Heap memory amount in MiB (default: 128)")
    parser.add_argument("--no-gui", action="store_true",
                        help="Run without GUI")
    
    args = parser.parse_args()
    
    # Determine EXE path
    exe_path = args.exe
    
    # If file not found directly, search in c_drive/
    if not os.path.isfile(exe_path):
        c_drive_exe = os.path.join(C_DRIVE_PATH, exe_path)
        if os.path.isfile(c_drive_exe):
            exe_path = c_drive_exe
            log.info(f"Loading EXE from c_drive/ folder: {exe_path}")
        else:
            log.error(f"File not found: {args.exe}")
            log.info(f"Also searched in c_drive/ folder: {c_drive_exe}")
            sys.exit(1)
    
    max_instr = args.max_instructions
    use_gui = not args.no_gui
    heap_size_mib = args.memory
    
    # Update heap size
    CPUEmulator.HEAP_SIZE = heap_size_mib * 1024 * 1024
    log.info(f"Heap size: {heap_size_mib} MiB ({CPUEmulator.HEAP_SIZE} bytes)")
    
    # Load PE file
    loader = PELoader(exe_path)
    
    if not loader.load():
        log.error("Failed to load PE file!")
        sys.exit(1)
    
    loader.print_summary()
    
    # Start GUI (optional)
    gui = None
    if use_gui and PYGAME_AVAILABLE:
        log.header("Starting Pygame GUI")
        gui = PseudoWindowsGUI(1024, 768)
        if gui.start():
            log.success("Pygame GUI window opened!")
        else:
            log.warning("Failed to start GUI, continuing without GUI...")
            gui = None
    elif use_gui and not PYGAME_AVAILABLE:
        log.warning("Pygame not installed, continuing without GUI...")
    
    # Start CPU emulator (with GUI reference)
    emulator = CPUEmulator(loader, gui)
    
    if not emulator.initialize():
        log.error("Failed to initialize CPU emulator!")
        if gui:
            gui.stop()
        sys.exit(1)
    
    # Disassemble entry point
    entry_point = loader.image_base + loader.entry_point
    emulator.disassemble(entry_point, 20)
    
    # Run emulation in separate thread (for GUI interaction)
    def run_emulation():
        try:
            emulator.run(max_instr)
        except Exception as e:
            log.error(f"Emulation error: {e}")
        finally:
            log.success("Emulation completed!")
    
    # Start emulation thread
    emu_thread = threading.Thread(target=run_emulation, daemon=True)
    emu_thread.start()
    
    # Wait while GUI is open
    try:
        if gui:
            log.info("GUI window is open, close the window to exit!")
            while gui.running:
                time.sleep(0.1)
            gui.stop()
        else:
            # If no GUI, wait for emulation to finish
            emu_thread.join()
    except KeyboardInterrupt:
        log.warning("Stopped by user (Ctrl+C)!")
        if gui:
            gui.running = False
            gui.stop()


if __name__ == "__main__":
    main()
