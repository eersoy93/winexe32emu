#!/usr/bin/env python3
#
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

"""
Windows 32-bit EXE Emulator
PE file loading, analysis and CPU emulation module
Fake Windows GUI environment with Pygame
"""

import sys
import os
import re
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
    WM_COMMAND = 0x0111
    WM_TIMER = 0x0113
    WM_MOUSEMOVE = 0x0200
    WM_LBUTTONDOWN = 0x0201
    WM_LBUTTONUP = 0x0202
    WM_RBUTTONDOWN = 0x0204
    WM_RBUTTONUP = 0x0205

    # Mouse key state flags (wParam for mouse messages)
    MK_LBUTTON = 0x0001
    MK_RBUTTON = 0x0002

    # Button notification codes (high word of WM_COMMAND wParam)
    BN_CLICKED = 0

    # Control notification codes (high word of WM_COMMAND wParam)
    LBN_SELCHANGE = 1
    CBN_SELCHANGE = 1

    # Button control messages
    BM_GETCHECK = 0x00F0
    BM_SETCHECK = 0x00F1

    # Listbox control messages
    LB_ADDSTRING = 0x0180
    LB_INSERTSTRING = 0x0181
    LB_DELETESTRING = 0x0182
    LB_RESETCONTENT = 0x0184
    LB_SETCURSEL = 0x0186
    LB_GETCURSEL = 0x0188
    LB_GETTEXT = 0x0189
    LB_GETTEXTLEN = 0x018A
    LB_GETCOUNT = 0x018B
    LB_ERR = 0xFFFFFFFF  # -1 as unsigned

    # Combobox control messages
    CB_ADDSTRING = 0x0143
    CB_DELETESTRING = 0x0144
    CB_GETCOUNT = 0x0146
    CB_GETCURSEL = 0x0147
    CB_GETLBTEXT = 0x0148
    CB_GETLBTEXTLEN = 0x0149
    CB_RESETCONTENT = 0x014B
    CB_SETCURSEL = 0x014E
    CB_ERR = 0xFFFFFFFF

    # PeekMessage removal flags
    PM_NOREMOVE = 0x0000
    PM_REMOVE = 0x0001

    # Scrollbar messages and notification codes
    WM_HSCROLL = 0x0114
    WM_VSCROLL = 0x0115
    SB_LINEUP = 0        # Also SB_LINELEFT
    SB_LINEDOWN = 1      # Also SB_LINERIGHT
    SB_PAGEUP = 2        # Also SB_PAGELEFT
    SB_PAGEDOWN = 3      # Also SB_PAGERIGHT
    SB_THUMBPOSITION = 4
    SB_THUMBTRACK = 5
    SB_ENDSCROLL = 8

    # Scrollbar selectors (nBar) and control style
    SB_HORZ = 0
    SB_VERT = 1
    SB_CTL = 2
    SBS_VERT = 0x0001

    # Scrollbar control messages (SBM_*)
    SBM_SETPOS = 0x00E0
    SBM_GETPOS = 0x00E1
    SBM_SETRANGE = 0x00E2
    SBM_GETRANGE = 0x00E3
    
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
        self.message_lock = threading.Lock()  # Guards message_queue (GUI thread is producer)
        self.painted_windows = set()  # Windows that received WM_PAINT
        self.quit_requested = False
        # True once the emulated process is gone (ExitProcess or emulation end).
        # After that no window can consume messages, so the GUI must stop
        # treating windows as live app windows (e.g. X click posts WM_CLOSE).
        self.process_exited = False

        # GDI object/DC state (all touched only on the emulation thread)
        self.gdi_objects = {}  # handle -> {'type': 'pen'|'brush', 'color': (r,g,b), 'width': int}
        self.dc_map = {}       # hdc -> hwnd the DC draws into
        self.dc_state = {}     # hdc -> {'pen','brush','pos','text_color','bk_mode','bk_color'}
        self._stock_objects = {}  # GetStockObject index -> handle

        # Timers: (hwnd, timer_id) -> {'elapse': sec, 'callback': addr, 'next_fire': time}
        self.timers = {}
        self.next_timer_id = 1

        # Menus: hmenu -> list of items
        # item = {'flags': int, 'id': int, 'text': str, 'submenu': hmenu or 0}
        self.menus = {}

        # Mouse capture (SetCapture/ReleaseCapture) - hwnd or 0
        self.capture_hwnd = 0

        # MSVCRT rand() state (MSVC-compatible LCG) and clock() epoch
        self._rand_seed = 1
        self._clock_epoch = time.time()
        
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
            '__p__acmdln': self.api__p__acmdln,
            '__p__wcmdln': self.api__p__wcmdln,
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
        self.process_exited = True
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
    
    def SetUnhandledExceptionFilter(self, args):
        """SetUnhandledExceptionFilter emulation - no previous filter"""
        log.debug(f"SetUnhandledExceptionFilter(0x{args[0]:08x})")
        return 0

    def LoadCursorA(self, args):
        """LoadCursorA emulation - opaque cursor handle"""
        log.debug(f"LoadCursorA(0x{args[0]:x}, 0x{args[1]:x})")
        return self.get_next_handle()

    def LoadCursorW(self, args):
        """LoadCursorW emulation"""
        return self.LoadCursorA(args)

    def LoadIconA(self, args):
        """LoadIconA emulation - opaque icon handle"""
        log.debug(f"LoadIconA(0x{args[0]:x}, 0x{args[1]:x})")
        return self.get_next_handle()

    def LoadIconW(self, args):
        """LoadIconW emulation"""
        return self.LoadIconA(args)

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

    def MulDiv(self, args):
        """MulDiv emulation - (a * b) / c with rounding to nearest"""
        n, num, den = self._read_signed_args(args, 0, 3)
        if den == 0:
            return 0xFFFFFFFF  # -1
        prod = n * num
        sign = 1 if (prod >= 0) == (den > 0) else -1
        # Builtin abs: the CRT abs() emulation shadows it on the class only
        pa, da = (prod if prod >= 0 else -prod), (den if den >= 0 else -den)
        result = sign * ((pa + da // 2) // da)
        log.debug(f"MulDiv({n}, {num}, {den}) -> {result}")
        return result & 0xFFFFFFFF

    def _write_systemtime(self, address, tm):
        """Write a SYSTEMTIME structure (8 WORDs) to memory"""
        ms = int((time.time() % 1) * 1000)
        data = struct.pack("<8H", tm.tm_year, tm.tm_mon, (tm.tm_wday + 1) % 7,
                           tm.tm_mday, tm.tm_hour, tm.tm_min,
                           min(tm.tm_sec, 59), ms)
        try:
            self.emu.uc.mem_write(address, data)
            return True
        except:
            return False

    def GetLocalTime(self, args):
        """GetLocalTime emulation"""
        lpSystemTime = args[0]
        log.debug("GetLocalTime()")
        if lpSystemTime:
            self._write_systemtime(lpSystemTime, time.localtime())
        return 0

    def GetSystemTime(self, args):
        """GetSystemTime emulation (UTC)"""
        lpSystemTime = args[0]
        log.debug("GetSystemTime()")
        if lpSystemTime:
            self._write_systemtime(lpSystemTime, time.gmtime())
        return 0

    def Beep(self, args):
        """Beep emulation (no audio device: logged only)"""
        log.debug(f"Beep({args[0]} Hz, {args[1]} ms)")
        return 1

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
        """Sleep emulation - real wait so game loops pace correctly"""
        dwMilliseconds = args[0]
        log.debug(f"Sleep({dwMilliseconds}ms)")
        # Sleep in short chunks so a stop request is not delayed
        end = time.time() + min(dwMilliseconds, 10000) / 1000.0
        while not self.emu.stop_emulation:
            remaining = end - time.time()
            if remaining <= 0:
                break
            time.sleep(min(0.05, remaining))
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
            if class_name.upper() in ["BUTTON", "EDIT", "STATIC", "LISTBOX", "COMBOBOX",
                                      "SCROLLBAR"]:
                # BUTTON with a checkbox style (BS_CHECKBOX/BS_AUTOCHECKBOX)
                # is drawn and clicked as a checkbox
                control_class = class_name
                if class_name.upper() == "BUTTON" and (dwStyle & 0xF) in (0x2, 0x3):
                    control_class = "CHECKBOX"
                # For child controls hMenu carries the control ID (used by WM_COMMAND)
                hwnd = self.gui.create_control(hWndParent, control_class, window_name,
                                               x, y, nWidth, nHeight, dwStyle,
                                               control_id=hMenu)
            else:
                hwnd = self.gui.create_window(window_name, x, y, nWidth, nHeight, dwStyle)

            # Save class_name to window (for finding WndProc)
            if hwnd in self.gui.windows:
                self.gui.windows[hwnd].class_name = class_name

            # Real Windows sends WM_CREATE to the WndProc synchronously, before
            # CreateWindowEx returns. Apps often create their child controls here.
            # Controls have no app WndProc, so this only fires for app windows.
            wndproc = self._find_wndproc_for_hwnd(hwnd)
            if wndproc:
                cs_addr = self._build_createstruct(
                    lpParam, hInstance, hMenu, hWndParent,
                    nHeight, nWidth, y, x, dwStyle, lpWindowName, lpClassName, dwExStyle)
                self.emu.call_wndproc(wndproc, hwnd, self.WM_CREATE, 0, cs_addr)
        else:
            hwnd = self.get_next_handle()

        return hwnd

    def _build_createstruct(self, lpCreateParams, hInstance, hMenu, hwndParent,
                            cy, cx, y, x, style, lpszName, lpszClass, dwExStyle):
        """Allocate and fill a CREATESTRUCTA, return its address (for WM_CREATE)."""
        addr = self.emu.heap_alloc(48)
        data = struct.pack("<IIIIiiiiIIII",
                           lpCreateParams & 0xFFFFFFFF,
                           hInstance & 0xFFFFFFFF,
                           hMenu & 0xFFFFFFFF,
                           hwndParent & 0xFFFFFFFF,
                           cy, cx, y, x,
                           style & 0xFFFFFFFF,
                           lpszName & 0xFFFFFFFF,
                           lpszClass & 0xFFFFFFFF,
                           dwExStyle & 0xFFFFFFFF)
        self.emu.uc.mem_write(addr, data)
        return addr
    
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
            self.gui._close_window(hWnd, notify_app=False)
            # Deliver WM_DESTROY via the queue: a synchronous call here would
            # nest emu_start inside an already-running callback
            if self._find_wndproc_for_hwnd(hWnd):
                self.post_window_message(hWnd, self.WM_DESTROY, 0, 0)

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

        # Always null-terminate the buffer (like real Windows), even when
        # the text is empty - the caller's buffer is uninitialized memory
        if lpString and nMaxCount > 0:
            text_bytes = text.encode('utf-8')[:nMaxCount - 1] + b'\x00'
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
            right, bottom = self.gui.client_size(win)
        
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

    # ---------- RECT utility APIs (user32) ----------

    def _read_rect(self, address):
        """Read a RECT from memory -> (left, top, right, bottom) or None"""
        try:
            return struct.unpack("<iiii", self.emu.uc.mem_read(address, 16))
        except:
            return None

    def _write_rect(self, address, left, top, right, bottom):
        """Write a RECT to memory"""
        try:
            self.emu.uc.mem_write(address, struct.pack("<iiii", left, top,
                                                       right, bottom))
            return True
        except:
            return False

    def SetRect(self, args):
        """SetRect emulation"""
        lprc = args[0]
        left, top, right, bottom = self._read_signed_args(args, 1, 4)
        if not lprc:
            return 0
        return 1 if self._write_rect(lprc, left, top, right, bottom) else 0

    def SetRectEmpty(self, args):
        """SetRectEmpty emulation"""
        lprc = args[0]
        if not lprc:
            return 0
        return 1 if self._write_rect(lprc, 0, 0, 0, 0) else 0

    def CopyRect(self, args):
        """CopyRect emulation"""
        lprcDst, lprcSrc = args[0], args[1]
        rect = self._read_rect(lprcSrc) if lprcSrc else None
        if not lprcDst or rect is None:
            return 0
        return 1 if self._write_rect(lprcDst, *rect) else 0

    def OffsetRect(self, args):
        """OffsetRect emulation"""
        lprc = args[0]
        dx, dy = self._read_signed_args(args, 1, 2)
        rect = self._read_rect(lprc) if lprc else None
        if rect is None:
            return 0
        left, top, right, bottom = rect
        return 1 if self._write_rect(lprc, left + dx, top + dy,
                                     right + dx, bottom + dy) else 0

    def InflateRect(self, args):
        """InflateRect emulation"""
        lprc = args[0]
        dx, dy = self._read_signed_args(args, 1, 2)
        rect = self._read_rect(lprc) if lprc else None
        if rect is None:
            return 0
        left, top, right, bottom = rect
        return 1 if self._write_rect(lprc, left - dx, top - dy,
                                     right + dx, bottom + dy) else 0

    def PtInRect(self, args):
        """PtInRect emulation (POINT is passed by value: two stack dwords)"""
        lprc = args[0]
        x, y = self._read_signed_args(args, 1, 2)
        rect = self._read_rect(lprc) if lprc else None
        if rect is None:
            return 0
        left, top, right, bottom = rect
        return 1 if (left <= x < right and top <= y < bottom) else 0

    def EqualRect(self, args):
        """EqualRect emulation"""
        r1 = self._read_rect(args[0]) if args[0] else None
        r2 = self._read_rect(args[1]) if args[1] else None
        if r1 is None or r2 is None:
            return 0
        return 1 if r1 == r2 else 0

    def IsRectEmpty(self, args):
        """IsRectEmpty emulation"""
        rect = self._read_rect(args[0]) if args[0] else None
        if rect is None:
            return 1
        left, top, right, bottom = rect
        return 1 if (right <= left or bottom <= top) else 0

    def IntersectRect(self, args):
        """IntersectRect emulation"""
        lprcDst = args[0]
        r1 = self._read_rect(args[1]) if args[1] else None
        r2 = self._read_rect(args[2]) if args[2] else None
        if not lprcDst or r1 is None or r2 is None:
            return 0
        left, top = max(r1[0], r2[0]), max(r1[1], r2[1])
        right, bottom = min(r1[2], r2[2]), min(r1[3], r2[3])
        if right <= left or bottom <= top:
            self._write_rect(lprcDst, 0, 0, 0, 0)
            return 0
        self._write_rect(lprcDst, left, top, right, bottom)
        return 1

    def UnionRect(self, args):
        """UnionRect emulation"""
        lprcDst = args[0]
        r1 = self._read_rect(args[1]) if args[1] else None
        r2 = self._read_rect(args[2]) if args[2] else None
        if not lprcDst or r1 is None or r2 is None:
            return 0
        empty1 = r1[2] <= r1[0] or r1[3] <= r1[1]
        empty2 = r2[2] <= r2[0] or r2[3] <= r2[1]
        if empty1 and empty2:
            self._write_rect(lprcDst, 0, 0, 0, 0)
            return 0
        if empty1:
            self._write_rect(lprcDst, *r2)
        elif empty2:
            self._write_rect(lprcDst, *r1)
        else:
            self._write_rect(lprcDst, min(r1[0], r2[0]), min(r1[1], r2[1]),
                             max(r1[2], r2[2]), max(r1[3], r2[3]))
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

        # Find the child control with this control id
        if self.gui and hDlg in self.gui.windows:
            for control in self.gui.windows[hDlg].controls:
                if control.control_id == nIDDlgItem:
                    return control.hwnd

        # Fallback: return dialog item ID as handle
        return 0x20000 + nIDDlgItem

    def GetDlgItemTextA(self, args):
        """GetDlgItemTextA emulation"""
        hDlg = args[0]
        nIDDlgItem = args[1]
        lpString = args[2]
        cchMax = args[3]
        hwnd = self.GetDlgItem([hDlg, nIDDlgItem])
        return self.GetWindowTextA([hwnd, lpString, cchMax])

    def SetDlgItemTextA(self, args):
        """SetDlgItemTextA emulation"""
        hDlg = args[0]
        nIDDlgItem = args[1]
        lpString = args[2]
        hwnd = self.GetDlgItem([hDlg, nIDDlgItem])
        return self.SetWindowTextA([hwnd, lpString])

    def CheckDlgButton(self, args):
        """CheckDlgButton emulation - set a checkbox's state by control id"""
        hDlg = args[0]
        nIDButton = args[1]
        uCheck = args[2]
        hwnd = self.GetDlgItem([hDlg, nIDButton])
        if self.gui and hwnd in self.gui.controls:
            self.gui.controls[hwnd].checked = bool(uCheck)
            return 1
        return 0

    def IsDlgButtonChecked(self, args):
        """IsDlgButtonChecked emulation"""
        hDlg = args[0]
        nIDButton = args[1]
        hwnd = self.GetDlgItem([hDlg, nIDButton])
        if self.gui and hwnd in self.gui.controls:
            return 1 if self.gui.controls[hwnd].checked else 0
        return 0

    def SetFocus(self, args):
        """SetFocus emulation - give keyboard focus to a control"""
        hWnd = args[0]
        log.debug(f"SetFocus(0x{hWnd:x})")
        prev = 0
        if self.gui:
            prev = self.gui.focused_control or 0
            if hWnd in self.gui.controls:
                self.gui.focused_control = hWnd
            else:
                self.gui.focused_control = None
        return prev

    def GetFocus(self, args):
        """GetFocus emulation"""
        return (self.gui.focused_control or 0) if self.gui else 0

    def GetAsyncKeyState(self, args):
        """GetAsyncKeyState emulation - poll key state (game loops)"""
        vKey = args[0]
        if self.gui and self.gui.key_states.get(vKey):
            return 0x8000  # Key is currently down (bit 15)
        return 0

    def GetKeyState(self, args):
        """GetKeyState emulation (same as GetAsyncKeyState in the emulator)"""
        return self.GetAsyncKeyState(args)

    def GetCursorPos(self, args):
        """GetCursorPos emulation - cursor position in fake-desktop coordinates"""
        lpPoint = args[0]
        x, y = self.gui.mouse_pos if self.gui else (0, 0)
        if lpPoint:
            try:
                self.emu.uc.mem_write(lpPoint, struct.pack("<ii", x, y))
            except:
                return 0
        log.debug(f"GetCursorPos() -> ({x}, {y})")
        return 1

    def SetCursorPos(self, args):
        """SetCursorPos emulation (accepted but not applied to the real mouse)"""
        x, y = self._read_signed_args(args, 0, 2)
        log.debug(f"SetCursorPos({x}, {y})")
        return 1

    def ScreenToClient(self, args):
        """ScreenToClient emulation"""
        hWnd = args[0]
        lpPoint = args[1]
        if not lpPoint:
            return 0
        try:
            x, y = struct.unpack("<ii", self.emu.uc.mem_read(lpPoint, 8))
        except:
            return 0
        if self.gui and hWnd in self.gui.windows:
            ox, oy = self.gui.client_origin(self.gui.windows[hWnd])
            x, y = x - ox, y - oy
        try:
            self.emu.uc.mem_write(lpPoint, struct.pack("<ii", x, y))
        except:
            return 0
        return 1

    def ClientToScreen(self, args):
        """ClientToScreen emulation"""
        hWnd = args[0]
        lpPoint = args[1]
        if not lpPoint:
            return 0
        try:
            x, y = struct.unpack("<ii", self.emu.uc.mem_read(lpPoint, 8))
        except:
            return 0
        if self.gui and hWnd in self.gui.windows:
            ox, oy = self.gui.client_origin(self.gui.windows[hWnd])
            x, y = x + ox, y + oy
        try:
            self.emu.uc.mem_write(lpPoint, struct.pack("<ii", x, y))
        except:
            return 0
        return 1

    def SetCapture(self, args):
        """SetCapture emulation - route mouse input to one window"""
        hWnd = args[0]
        prev = self.capture_hwnd
        self.capture_hwnd = hWnd
        log.debug(f"SetCapture(0x{hWnd:x})")
        return prev

    def ReleaseCapture(self, args):
        """ReleaseCapture emulation"""
        log.debug("ReleaseCapture()")
        self.capture_hwnd = 0
        return 1

    def GetCapture(self, args):
        """GetCapture emulation"""
        return self.capture_hwnd

    def GetParent(self, args):
        """GetParent emulation"""
        hWnd = args[0]
        if self.gui and hWnd in self.gui.controls:
            return self.gui.controls[hWnd].parent_hwnd or 0
        return 0

    def IsWindow(self, args):
        """IsWindow emulation"""
        hWnd = args[0]
        if self.gui and (hWnd in self.gui.windows or hWnd in self.gui.controls):
            return 1
        return 0

    def IsWindowVisible(self, args):
        """IsWindowVisible emulation"""
        hWnd = args[0]
        if self.gui:
            if hWnd in self.gui.windows:
                win = self.gui.windows[hWnd]
                return 1 if (win.visible and not win.minimized) else 0
            if hWnd in self.gui.controls:
                return 1 if self.gui.controls[hWnd].visible else 0
        return 0

    def IsWindowEnabled(self, args):
        """IsWindowEnabled emulation"""
        hWnd = args[0]
        if self.gui:
            if hWnd in self.gui.windows:
                return 1 if self.gui.windows[hWnd].enabled else 0
            if hWnd in self.gui.controls:
                return 1 if self.gui.controls[hWnd].enabled else 0
        return 0

    def MessageBeep(self, args):
        """MessageBeep emulation (no audio device: logged only)"""
        log.debug(f"MessageBeep(0x{args[0]:x})")
        return 1

    # ---------- Scrollbar APIs (user32) ----------

    def _scrollbar_control(self, hwnd, nBar):
        """Resolve a scrollbar target to its FakeControl (SB_CTL only).

        Standard window scrollbars (SB_HORZ/SB_VERT on a window handle) are
        not emulated; only SCROLLBAR controls carry scroll state.
        """
        if self.gui and hwnd in self.gui.controls:
            control = self.gui.controls[hwnd]
            if control.class_name == "SCROLLBAR":
                return control
        if nBar != self.SB_CTL:
            log.debug(f"Standard window scrollbar (nBar={nBar}) not emulated")
        return None

    @staticmethod
    def scroll_pos_max(control):
        """Highest legal scroll position (Windows: max - page + 1 if page set)"""
        if control.scroll_page > 0:
            return max(control.scroll_min,
                       control.scroll_max - control.scroll_page + 1)
        return control.scroll_max

    def _clamp_scroll_pos(self, control, pos):
        return max(control.scroll_min, min(pos, self.scroll_pos_max(control)))

    def SetScrollPos(self, args):
        """SetScrollPos emulation"""
        hWnd, nBar = args[0], args[1]
        nPos = args[2] - 0x100000000 if args[2] >= 0x80000000 else args[2]
        control = self._scrollbar_control(hWnd, nBar)
        if not control:
            return 0
        prev = control.scroll_pos
        control.scroll_pos = self._clamp_scroll_pos(control, nPos)
        log.debug(f"SetScrollPos(0x{hWnd:x}, {nPos}) -> prev {prev}")
        return prev & 0xFFFFFFFF

    def GetScrollPos(self, args):
        """GetScrollPos emulation"""
        control = self._scrollbar_control(args[0], args[1])
        return (control.scroll_pos & 0xFFFFFFFF) if control else 0

    def SetScrollRange(self, args):
        """SetScrollRange emulation"""
        hWnd, nBar = args[0], args[1]
        nMin, nMax = self._read_signed_args(args, 2, 2)
        control = self._scrollbar_control(hWnd, nBar)
        if not control:
            return 0
        control.scroll_min = min(nMin, nMax)
        control.scroll_max = max(nMin, nMax)
        control.scroll_pos = self._clamp_scroll_pos(control, control.scroll_pos)
        log.debug(f"SetScrollRange(0x{hWnd:x}, {nMin}..{nMax})")
        return 1

    def GetScrollRange(self, args):
        """GetScrollRange emulation"""
        control = self._scrollbar_control(args[0], args[1])
        lpMin, lpMax = args[2], args[3]
        if not control:
            return 0
        try:
            if lpMin:
                self.emu.uc.mem_write(lpMin, struct.pack("<i", control.scroll_min))
            if lpMax:
                self.emu.uc.mem_write(lpMax, struct.pack("<i", control.scroll_max))
        except:
            return 0
        return 1

    # SCROLLINFO fMask flags
    SIF_RANGE = 0x0001
    SIF_PAGE = 0x0002
    SIF_POS = 0x0004
    SIF_TRACKPOS = 0x0010

    def SetScrollInfo(self, args):
        """SetScrollInfo emulation"""
        hWnd, nBar, lpsi = args[0], args[1], args[2]
        control = self._scrollbar_control(hWnd, nBar)
        if not control or not lpsi:
            return 0
        try:
            # SCROLLINFO: cbSize, fMask, nMin, nMax, nPage, nPos, nTrackPos
            data = self.emu.uc.mem_read(lpsi, 28)
            _, fMask, nMin, nMax, nPage, nPos, _ = struct.unpack("<IIiiIii", data)
        except:
            return 0
        if fMask & self.SIF_RANGE:
            control.scroll_min = min(nMin, nMax)
            control.scroll_max = max(nMin, nMax)
        if fMask & self.SIF_PAGE:
            control.scroll_page = nPage
        if fMask & self.SIF_POS:
            control.scroll_pos = nPos
        control.scroll_pos = self._clamp_scroll_pos(control, control.scroll_pos)
        log.debug(f"SetScrollInfo(0x{hWnd:x}, mask=0x{fMask:x}) -> pos {control.scroll_pos}")
        return control.scroll_pos & 0xFFFFFFFF

    def GetScrollInfo(self, args):
        """GetScrollInfo emulation"""
        hWnd, nBar, lpsi = args[0], args[1], args[2]
        control = self._scrollbar_control(hWnd, nBar)
        if not control or not lpsi:
            return 0
        try:
            # Preserve the caller's cbSize and fMask, fill everything else
            head = self.emu.uc.mem_read(lpsi, 8)
            data = head + struct.pack("<iiIii", control.scroll_min,
                                      control.scroll_max, control.scroll_page,
                                      control.scroll_pos, control.scroll_pos)
            self.emu.uc.mem_write(lpsi, bytes(data))
        except:
            return 0
        return 1

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

        # Text messages are handled directly (also work for controls)
        WM_SETTEXT, WM_GETTEXT, WM_GETTEXTLENGTH = 0x000C, 0x000D, 0x000E
        if Msg == WM_SETTEXT:
            return self.SetWindowTextA([hWnd, lParam])
        if Msg == WM_GETTEXT:
            return self.GetWindowTextA([hWnd, lParam, wParam])
        if Msg == WM_GETTEXTLENGTH:
            text = self.gui.get_window_text(hWnd) if self.gui else ""
            return len(text)

        # Control messages (LISTBOX, COMBOBOX, checkbox BUTTON)
        if self.gui and hWnd in self.gui.controls:
            return self._control_message(self.gui.controls[hWnd], Msg, wParam, lParam)

        # Other messages: deliver synchronously to the window's WndProc
        wndproc = self._find_wndproc_for_hwnd(hWnd)
        if wndproc:
            return self.emu.call_wndproc(wndproc, hWnd, Msg, wParam, lParam)
        return 0

    def _control_message(self, control, Msg, wParam, lParam):
        """Handle a message sent to a child control (emulation thread).

        Item lists are swapped in as new list objects so the GUI thread can
        keep painting the snapshot it already holds.
        """
        items = control.items

        # ----- Checkbox / button messages -----
        if Msg == self.BM_GETCHECK:
            return 1 if control.checked else 0
        if Msg == self.BM_SETCHECK:
            control.checked = bool(wParam)
            return 0

        # ----- Listbox messages -----
        if Msg == self.LB_ADDSTRING:
            control.items = items + [self.read_string(lParam)]
            return len(control.items) - 1
        if Msg == self.LB_INSERTSTRING:
            index = len(items) if wParam >= len(items) else wParam
            control.items = items[:index] + [self.read_string(lParam)] + items[index:]
            return index
        if Msg == self.LB_DELETESTRING:
            if wParam >= len(items):
                return self.LB_ERR
            control.items = items[:wParam] + items[wParam + 1:]
            if control.sel_index >= len(control.items):
                control.sel_index = -1
            return len(control.items)
        if Msg == self.LB_RESETCONTENT:
            control.items = []
            control.sel_index = -1
            return 0
        if Msg == self.LB_GETCOUNT:
            return len(items)
        if Msg == self.LB_GETCURSEL:
            return control.sel_index if control.sel_index >= 0 else self.LB_ERR
        if Msg == self.LB_SETCURSEL:
            if wParam == 0xFFFFFFFF:
                control.sel_index = -1
                return self.LB_ERR
            if wParam < len(items):
                control.sel_index = wParam
                return wParam
            return self.LB_ERR
        if Msg == self.LB_GETTEXT:
            if wParam >= len(items):
                return self.LB_ERR
            text = items[wParam]
            if lParam:
                self.emu.uc.mem_write(lParam, text.encode('utf-8') + b'\x00')
            return len(text)
        if Msg == self.LB_GETTEXTLEN:
            return len(items[wParam]) if wParam < len(items) else self.LB_ERR

        # ----- Combobox messages (same item list as listbox) -----
        combo_to_list = {
            self.CB_ADDSTRING: self.LB_ADDSTRING,
            self.CB_DELETESTRING: self.LB_DELETESTRING,
            self.CB_RESETCONTENT: self.LB_RESETCONTENT,
            self.CB_GETCOUNT: self.LB_GETCOUNT,
            self.CB_GETCURSEL: self.LB_GETCURSEL,
            self.CB_SETCURSEL: self.LB_SETCURSEL,
            self.CB_GETLBTEXT: self.LB_GETTEXT,
            self.CB_GETLBTEXTLEN: self.LB_GETTEXTLEN,
        }
        if Msg in combo_to_list:
            return self._control_message(control, combo_to_list[Msg], wParam, lParam)

        # ----- Scrollbar messages -----
        if Msg == self.SBM_SETPOS:
            pos = wParam - 0x100000000 if wParam >= 0x80000000 else wParam
            prev = control.scroll_pos
            control.scroll_pos = self._clamp_scroll_pos(control, pos)
            return prev & 0xFFFFFFFF
        if Msg == self.SBM_GETPOS:
            return control.scroll_pos & 0xFFFFFFFF
        if Msg == self.SBM_SETRANGE:
            nmin = wParam - 0x100000000 if wParam >= 0x80000000 else wParam
            nmax = lParam - 0x100000000 if lParam >= 0x80000000 else lParam
            control.scroll_min = min(nmin, nmax)
            control.scroll_max = max(nmin, nmax)
            control.scroll_pos = self._clamp_scroll_pos(control, control.scroll_pos)
            return 0
        if Msg == self.SBM_GETRANGE:
            try:
                if wParam:
                    self.emu.uc.mem_write(wParam, struct.pack("<i", control.scroll_min))
                if lParam:
                    self.emu.uc.mem_write(lParam, struct.pack("<i", control.scroll_max))
            except:
                pass
            return 0

        log.debug(f"Unhandled control message 0x{Msg:04x} for {control.class_name}")
        return 0
    
    def PostMessageA(self, args):
        """PostMessageA emulation - queue a message for the message loop"""
        hWnd = args[0]
        Msg = args[1]
        wParam = args[2]
        lParam = args[3]
        log.debug(f"PostMessageA(0x{hWnd:x}, 0x{Msg:x}, 0x{wParam:x}, 0x{lParam:x})")
        if Msg == self.WM_QUIT:
            self.quit_requested = True
        else:
            self.post_window_message(hWnd, Msg, wParam, lParam)
        return 1

    def PostQuitMessage(self, args):
        """PostQuitMessage emulation - request message loop exit"""
        nExitCode = args[0]
        log.debug(f"PostQuitMessage({nExitCode})")
        # The blocking GetMessageA relies on this to break the loop
        self.quit_requested = True
        return 0

    def SetTimer(self, args):
        """SetTimer emulation"""
        hWnd = args[0]
        nIDEvent = args[1]
        uElapse = args[2]
        lpTimerFunc = args[3]

        # Window-less timers get a fresh id (like real Windows)
        if hWnd == 0 or nIDEvent == 0:
            nIDEvent = self.next_timer_id
            self.next_timer_id += 1

        elapse = max(uElapse, 10) / 1000.0  # USER_TIMER_MINIMUM ~ 10ms
        self.timers[(hWnd, nIDEvent)] = {
            'elapse': elapse,
            'callback': lpTimerFunc,
            'next_fire': time.time() + elapse,
        }

        log.debug(f"SetTimer(0x{hWnd:x}, id={nIDEvent}, {uElapse}ms) -> {nIDEvent}")
        return nIDEvent

    def KillTimer(self, args):
        """KillTimer emulation"""
        hWnd = args[0]
        nIDEvent = args[1]
        log.debug(f"KillTimer(0x{hWnd:x}, id={nIDEvent})")
        return 1 if self.timers.pop((hWnd, nIDEvent), None) else 0

    def _pop_due_timer(self):
        """Return (hwnd, id, callback) of a due timer and schedule its next fire"""
        now = time.time()
        for (hwnd, timer_id), timer in self.timers.items():
            if now >= timer['next_fire']:
                timer['next_fire'] = now + timer['elapse']
                return (hwnd, timer_id, timer['callback'])
        return None

    def _write_msg(self, lpMsg, hwnd, message, wParam, lParam):
        """Fill a MSG structure in emulated memory"""
        if lpMsg:
            msg_data = struct.pack("<IIIIIii", hwnd, message, wParam, lParam, 0, 0, 0)
            self.emu.uc.mem_write(lpMsg, msg_data)

    def _next_message(self, remove=True):
        """Single non-blocking scan for a pending message.

        Returns (hwnd, message, wParam, lParam) or None. Priority mirrors
        GetMessageA: synthesized WM_PAINT, then the input queue, then timers.
        """
        # Send WM_PAINT for visible windows not yet painted
        for hwnd, window in list(self.gui.windows.items()) if self.gui else []:
            if hwnd not in self.painted_windows and window.visible:
                if remove:
                    self.painted_windows.add(hwnd)
                return (hwnd, self.WM_PAINT, 0, 0)

        # Queued message (input forwarded from the GUI thread)
        with self.message_lock:
            if self.message_queue:
                msg = self.message_queue.pop(0) if remove else self.message_queue[0]
                return (msg['hwnd'], msg['message'], msg['wParam'], msg['lParam'])

        # Fire due timers (lowest priority, like real WM_TIMER)
        if remove:
            due = self._pop_due_timer()
            if due is not None:
                timer_hwnd, timer_id, callback = due
                return (timer_hwnd, self.WM_TIMER, timer_id, callback)

        return None

    def GetMessageA(self, args):
        """GetMessageA emulation - For message loop"""
        lpMsg = args[0]
        hWnd = args[1]
        wMsgFilterMin = args[2]
        wMsgFilterMax = args[3]

        log.debug(f"GetMessageA() - Message loop")

        # Block until a message is available, the app quits, or the GUI closes.
        # This runs on the emulation thread; the GUI thread feeds message_queue.
        while True:
            if self.quit_requested:
                self._write_msg(lpMsg, 0, self.WM_QUIT, 0, 0)
                return 0

            msg = self._next_message()
            if msg is not None:
                hwnd, message, wParam, lParam = msg
                self._write_msg(lpMsg, hwnd, message, wParam, lParam)
                if message == self.WM_QUIT:
                    return 0
                return 1

            # GUI window closed -> end the message loop
            if self.gui and not self.gui.running:
                self._write_msg(lpMsg, 0, self.WM_QUIT, 0, 0)
                return 0

            # No GUI at all -> nothing can ever arrive, terminate
            if not self.gui:
                self.quit_requested = True
                self._write_msg(lpMsg, 0, self.WM_QUIT, 0, 0)
                return 0

            # Idle: wait for the GUI thread to post input (does not burn instructions)
            time.sleep(0.01)

    def PeekMessageA(self, args):
        """PeekMessageA emulation - non-blocking message check (game loops)"""
        lpMsg = args[0]
        hWnd = args[1]
        wMsgFilterMin = args[2]
        wMsgFilterMax = args[3]
        wRemoveMsg = args[4]

        remove = bool(wRemoveMsg & self.PM_REMOVE)

        # Quit pending or GUI gone: report WM_QUIT (PeekMessage returns TRUE)
        if self.quit_requested or (self.gui and not self.gui.running) or not self.gui:
            self._write_msg(lpMsg, 0, self.WM_QUIT, 0, 0)
            return 1

        msg = self._next_message(remove=remove)
        if msg is None:
            return 0

        hwnd, message, wParam, lParam = msg
        self._write_msg(lpMsg, hwnd, message, wParam, lParam)
        log.debug(f"PeekMessageA() -> msg=0x{message:04x} hwnd=0x{hwnd:x}")
        return 1

    def PeekMessageW(self, args):
        """PeekMessageW emulation (same as PeekMessageA in the emulator)"""
        return self.PeekMessageA(args)
    
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

            # WM_TIMER with a TimerProc: call the callback instead of the WndProc
            if message == self.WM_TIMER and lParam:
                tick = int(time.time() * 1000) & 0xFFFFFFFF
                return self.emu.call_callback(lParam, [hwnd, message, wParam, tick])

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

        # Default WM_CLOSE handling: destroy the window (like real Windows)
        if Msg == self.WM_CLOSE:
            self.DestroyWindow([hWnd])

        return 0
    
    # ==================== DEVICE CONTEXT HELPERS ====================

    @staticmethod
    def _colorref_to_rgb(colorref):
        """Convert a Win32 COLORREF (0x00BBGGRR) to an (r, g, b) tuple"""
        return (colorref & 0xFF, (colorref >> 8) & 0xFF, (colorref >> 16) & 0xFF)

    def _create_dc(self, hwnd, memory=False):
        """Create a DC handle bound to a window (or an off-screen memory DC)"""
        hdc = self.get_next_handle()
        self.dc_map[hdc] = hwnd
        self.dc_state[hdc] = {
            'pen': 0,          # 0 = default black pen, width 1
            'brush': 0,        # 0 = default white brush
            'font': 0,         # 0 = default GUI font
            'pos': (0, 0),     # Current position (MoveToEx/LineTo)
            'text_color': (0, 0, 0),
            'bk_mode': 2,      # OPAQUE
            'bk_color': (255, 255, 255),
            'memory': memory,  # Memory DCs keep their own display list
            'shapes': [] if memory else None,
            'bitmap': 0,       # Selected bitmap (memory DCs)
        }
        return hdc

    def _delete_dc(self, hdc):
        """Release a DC handle"""
        self.dc_map.pop(hdc, None)
        self.dc_state.pop(hdc, None)

    def _dc_hwnd(self, hdc):
        """Window a DC belongs to (fall back to the active window)"""
        hwnd = self.dc_map.get(hdc, 0)
        if not hwnd and self.gui:
            hwnd = self.gui.active_window
        return hwnd

    def _dc_pen(self, hdc):
        """Current pen of a DC -> (color, width) or None for PS_NULL"""
        state = self.dc_state.get(hdc)
        if state and state['pen']:
            pen = self.gdi_objects.get(state['pen'])
            if pen and pen['type'] == 'pen':
                if pen.get('style', 0) == 5:  # PS_NULL
                    return None
                return (pen['color'], max(1, pen['width']))
        return ((0, 0, 0), 1)  # Default: black pen, width 1

    def _dc_brush(self, hdc):
        """Current brush color of a DC, or None for NULL_BRUSH"""
        state = self.dc_state.get(hdc)
        if state and state['brush']:
            brush = self.gdi_objects.get(state['brush'])
            if brush and brush['type'] == 'brush':
                return brush['color']  # None for NULL_BRUSH
        return (255, 255, 255)  # Default: white brush

    def _dc_font(self, hdc):
        """Current font dict of a DC, or None for the default GUI font"""
        state = self.dc_state.get(hdc)
        if state and state.get('font'):
            font = self.gdi_objects.get(state['font'])
            if font and font['type'] == 'font':
                return font
        return None

    def _memdc_size(self, hdc):
        """Bitmap size of a memory DC -> (w, h) or None"""
        state = self.dc_state.get(hdc)
        if state:
            bmp = self.gdi_objects.get(state.get('bitmap', 0))
            if bmp and bmp['type'] == 'bitmap':
                return (bmp['width'], bmp['height'])
        return None

    def _add_shape(self, hdc, shape):
        """Append a GDI shape to the display list of the DC's window.

        Memory DCs collect shapes in their own list until BitBlt copies them.
        An opaque rect covering the whole bitmap restarts the list, so a
        game loop that fills the background every frame doesn't grow it.
        """
        state = self.dc_state.get(hdc)
        if state and state.get('memory'):
            if shape['type'] == 'rect' and shape.get('fill') is not None:
                size = self._memdc_size(hdc)
                if size:
                    left, top, right, bottom = shape['rect']
                    if left <= 0 and top <= 0 and right >= size[0] and bottom >= size[1]:
                        state['shapes'] = []
            state['shapes'].append(shape)
            return

        hwnd = self._dc_hwnd(hdc)
        if self.gui and hwnd:
            self.gui.add_shape(hwnd, shape)

    def _add_text(self, hdc, text, x, y):
        """Append a text item to the DC's display list (window or memory DC)"""
        state = self.dc_state.get(hdc, {})
        shape = {
            'type': 'text',
            'pos': (x, y),
            'text': text,
            'color': state.get('text_color') or (0, 0, 0),
            'font': self._dc_font(hdc),
        }
        self._add_shape(hdc, shape)

    def BeginPaint(self, args):
        """BeginPaint emulation"""
        hWnd = args[0]
        lpPaint = args[1]

        log.debug(f"BeginPaint(0x{hWnd:x})")

        hdc = self._create_dc(hWnd)

        # Painting starts fresh: clear the window's retained display lists
        if self.gui:
            self.gui.clear_drawings(hWnd)

        # Fill PAINTSTRUCT structure
        if lpPaint:
            # Client area size
            right, bottom = 400, 300
            if self.gui and hWnd in self.gui.windows:
                win = self.gui.windows[hWnd]
                right, bottom = self.gui.client_size(win)
            # hdc, fErase, rcPaint(4 int), fRestore, fIncUpdate, rgbReserved[32]
            paint_data = struct.pack("<II", hdc, 0)  # First 8 bytes
            paint_data += struct.pack("<iiii", 0, 0, right, bottom)  # rcPaint
            paint_data += b'\x00' * (64 - len(paint_data))  # Rest
            self.emu.uc.mem_write(lpPaint, paint_data[:64])

        return hdc

    def EndPaint(self, args):
        """EndPaint emulation"""
        hWnd = args[0]
        lpPaint = args[1]
        log.debug(f"EndPaint(0x{hWnd:x})")
        # Free the DC allocated by BeginPaint
        if lpPaint:
            try:
                hdc = struct.unpack("<I", self.emu.uc.mem_read(lpPaint, 4))[0]
                self._delete_dc(hdc)
            except:
                pass
        return 1

    def InvalidateRect(self, args):
        """InvalidateRect emulation - request a repaint via WM_PAINT"""
        hWnd = args[0]
        lpRect = args[1]
        bErase = args[2]
        log.debug(f"InvalidateRect(0x{hWnd:x})")
        # GetMessageA re-synthesizes WM_PAINT for windows not in painted_windows
        self.painted_windows.discard(hWnd)
        return 1

    def FillRect(self, args):
        """FillRect emulation"""
        hdc = args[0]
        lprc = args[1]
        hbr = args[2]

        if not lprc:
            log.debug(f"FillRect(0x{hdc:x})")
            return 1

        try:
            rect_data = self.emu.uc.mem_read(lprc, 16)
            left, top, right, bottom = struct.unpack("<iiii", rect_data)
        except:
            log.debug(f"FillRect(0x{hdc:x})")
            return 1

        log.debug(f"FillRect(0x{hdc:x}, rect=({left},{top},{right},{bottom}), brush=0x{hbr:x})")

        # Resolve the brush: GDI handle, or a system color index + 1 (e.g. COLOR_WINDOW+1)
        color = self._brush_color(hbr)

        if color is not None:
            self._add_shape(hdc, {'type': 'rect', 'rect': (left, top, right, bottom),
                                  'fill': color, 'pen': None})
        return 1

    def GetDC(self, args):
        """GetDC emulation"""
        hWnd = args[0]
        log.debug(f"GetDC(0x{hWnd:x})")
        return self._create_dc(hWnd)

    def ReleaseDC(self, args):
        """ReleaseDC emulation"""
        hWnd = args[0]
        hDC = args[1]
        log.debug(f"ReleaseDC(0x{hWnd:x}, 0x{hDC:x})")
        self._delete_dc(hDC)
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

        if self.gui:
            self._add_text(hdc, text, x, y)

        return 1
    
    def TextOutW(self, args):
        """TextOutW emulation - Draw Unicode text"""
        hdc = args[0]
        x = args[1]
        y = args[2]
        lpString = args[3]
        c = args[4]
        
        text = self.read_wide_string(lpString) if lpString else ""
        if c > 0 and len(text) > c:
            text = text[:c]

        log.info(f"TextOutW(0x{hdc:x}, {x}, {y}, \"{text}\")")

        if self.gui:
            self._add_text(hdc, text, x, y)

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
            state = self.dc_state.get(hdc, {})
            if state.get('memory') or self._dc_hwnd(hdc) != self.gui.console_hwnd:
                self._add_text(hdc, text, draw_x, draw_y)

        return height  # Text height
    
    def DrawTextW(self, args):
        """DrawTextW emulation"""
        hdc = args[0]
        lpchText = args[1]
        cchText = args[2]
        lprc = args[3]
        format_flags = args[4]
        
        text = self.read_wide_string(lpchText) if lpchText else ""
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
            self._add_text(hdc, text, x, y)

        return 20  # Text height
    
    def SetTextColor(self, args):
        """SetTextColor emulation"""
        hdc = args[0]
        color = args[1]
        log.debug(f"SetTextColor(0x{hdc:x}, 0x{color:06x})")
        state = self.dc_state.get(hdc)
        prev = 0
        if state:
            r, g, b = state['text_color']
            prev = r | (g << 8) | (b << 16)
            state['text_color'] = self._colorref_to_rgb(color)
        return prev  # Previous color

    def SetBkColor(self, args):
        """SetBkColor emulation"""
        hdc = args[0]
        color = args[1]
        log.debug(f"SetBkColor(0x{hdc:x}, 0x{color:06x})")
        state = self.dc_state.get(hdc)
        if state:
            state['bk_color'] = self._colorref_to_rgb(color)
        return 0xFFFFFF  # Previous color

    def SetBkMode(self, args):
        """SetBkMode emulation"""
        hdc = args[0]
        mode = args[1]  # TRANSPARENT=1, OPAQUE=2
        log.debug(f"SetBkMode(0x{hdc:x}, {mode})")
        state = self.dc_state.get(hdc)
        prev = 2
        if state:
            prev = state['bk_mode']
            state['bk_mode'] = mode
        return prev  # Previous mode

    # ==================== GDI DRAWING APIs ====================

    def CreatePen(self, args):
        """CreatePen emulation"""
        style = args[0]   # PS_SOLID=0 ... PS_NULL=5
        width = args[1]
        colorref = args[2]

        handle = self.get_next_handle()
        self.gdi_objects[handle] = {
            'type': 'pen',
            'style': style,
            'color': self._colorref_to_rgb(colorref),
            'width': max(1, width),
        }
        log.debug(f"CreatePen(style={style}, width={width}, color=0x{colorref:06x}) -> 0x{handle:x}")
        return handle

    def CreateSolidBrush(self, args):
        """CreateSolidBrush emulation"""
        colorref = args[0]
        handle = self.get_next_handle()
        self.gdi_objects[handle] = {
            'type': 'brush',
            'color': self._colorref_to_rgb(colorref),
            'width': 0,
        }
        log.debug(f"CreateSolidBrush(0x{colorref:06x}) -> 0x{handle:x}")
        return handle

    def GetStockObject(self, args):
        """GetStockObject emulation"""
        index = args[0]

        # Cache: the same index always returns the same handle
        if index in self._stock_objects:
            return self._stock_objects[index]

        stock = {
            0: ('brush', (255, 255, 255)),   # WHITE_BRUSH
            1: ('brush', (192, 192, 192)),   # LTGRAY_BRUSH
            2: ('brush', (128, 128, 128)),   # GRAY_BRUSH
            3: ('brush', (64, 64, 64)),      # DKGRAY_BRUSH
            4: ('brush', (0, 0, 0)),         # BLACK_BRUSH
            5: ('brush', None),              # NULL_BRUSH (draws nothing)
            6: ('pen', (255, 255, 255)),     # WHITE_PEN
            7: ('pen', (0, 0, 0)),           # BLACK_PEN
            8: ('pen', None),                # NULL_PEN
        }

        handle = self.get_next_handle()
        if index in stock:
            obj_type, color = stock[index]
            obj = {'type': obj_type, 'color': color, 'width': 1}
            if color is None and obj_type == 'pen':
                obj['style'] = 5  # PS_NULL
            self.gdi_objects[handle] = obj
        else:
            # Fonts and other stock objects: return a generic handle
            self.gdi_objects[handle] = {'type': 'other', 'color': (0, 0, 0), 'width': 0}

        self._stock_objects[index] = handle
        log.debug(f"GetStockObject({index}) -> 0x{handle:x}")
        return handle

    def SelectObject(self, args):
        """SelectObject emulation"""
        hdc = args[0]
        hobj = args[1]

        state = self.dc_state.get(hdc)
        obj = self.gdi_objects.get(hobj)
        prev = 0

        if state and obj:
            if obj['type'] == 'pen':
                prev = state['pen']
                state['pen'] = hobj
            elif obj['type'] == 'brush':
                prev = state['brush']
                state['brush'] = hobj
            elif obj['type'] == 'font':
                prev = state['font']
                state['font'] = hobj
            elif obj['type'] == 'bitmap':
                prev = state.get('bitmap', 0)
                state['bitmap'] = hobj

        log.debug(f"SelectObject(0x{hdc:x}, 0x{hobj:x}) -> 0x{prev:x}")
        return prev

    def DeleteObject(self, args):
        """DeleteObject emulation"""
        hobj = args[0]
        log.debug(f"DeleteObject(0x{hobj:x})")
        # Keep stock objects alive (deleting them is a no-op in Windows too)
        if hobj in self._stock_objects.values():
            return 1
        return 1 if self.gdi_objects.pop(hobj, None) else 0

    def MoveToEx(self, args):
        """MoveToEx emulation - set current position"""
        hdc = args[0]
        x = args[1] if args[1] < 0x80000000 else args[1] - 0x100000000
        y = args[2] if args[2] < 0x80000000 else args[2] - 0x100000000
        lpPoint = args[3]

        state = self.dc_state.get(hdc)
        if state:
            if lpPoint:
                old_x, old_y = state['pos']
                self.emu.uc.mem_write(lpPoint, struct.pack("<ii", old_x, old_y))
            state['pos'] = (x, y)

        log.debug(f"MoveToEx(0x{hdc:x}, {x}, {y})")
        return 1

    def LineTo(self, args):
        """LineTo emulation - draw line from current position"""
        hdc = args[0]
        x = args[1] if args[1] < 0x80000000 else args[1] - 0x100000000
        y = args[2] if args[2] < 0x80000000 else args[2] - 0x100000000

        state = self.dc_state.get(hdc)
        if state:
            pen = self._dc_pen(hdc)
            if pen:
                self._add_shape(hdc, {'type': 'line', 'from': state['pos'],
                                      'to': (x, y), 'pen': pen})
            state['pos'] = (x, y)

        log.debug(f"LineTo(0x{hdc:x}, {x}, {y})")
        return 1

    def Rectangle(self, args):
        """Rectangle emulation - draw rectangle with current pen and brush"""
        hdc = args[0]
        left, top, right, bottom = (v if v < 0x80000000 else v - 0x100000000
                                    for v in args[1:5])

        self._add_shape(hdc, {'type': 'rect', 'rect': (left, top, right, bottom),
                              'fill': self._dc_brush(hdc), 'pen': self._dc_pen(hdc)})

        log.debug(f"Rectangle(0x{hdc:x}, {left}, {top}, {right}, {bottom})")
        return 1

    def Ellipse(self, args):
        """Ellipse emulation - draw ellipse with current pen and brush"""
        hdc = args[0]
        left, top, right, bottom = (v if v < 0x80000000 else v - 0x100000000
                                    for v in args[1:5])

        self._add_shape(hdc, {'type': 'ellipse', 'rect': (left, top, right, bottom),
                              'fill': self._dc_brush(hdc), 'pen': self._dc_pen(hdc)})

        log.debug(f"Ellipse(0x{hdc:x}, {left}, {top}, {right}, {bottom})")
        return 1

    def SetPixel(self, args):
        """SetPixel emulation"""
        hdc = args[0]
        x = args[1] if args[1] < 0x80000000 else args[1] - 0x100000000
        y = args[2] if args[2] < 0x80000000 else args[2] - 0x100000000
        colorref = args[3]

        color = self._colorref_to_rgb(colorref)
        self._add_shape(hdc, {'type': 'pixel', 'pos': (x, y), 'color': color})
        return colorref

    @staticmethod
    def _rgb_to_colorref(rgb):
        """Convert an (r, g, b) tuple to a Win32 COLORREF (0x00BBGGRR)"""
        r, g, b = rgb
        return (b << 16) | (g << 8) | r

    @staticmethod
    def _point_near_segment(px, py, x1, y1, x2, y2, radius):
        """Is (px, py) within radius of the segment (x1,y1)-(x2,y2)?"""
        dx, dy = x2 - x1, y2 - y1
        length_sq = dx * dx + dy * dy
        if length_sq == 0:
            ex, ey = px - x1, py - y1
        else:
            t = max(0.0, min(1.0, ((px - x1) * dx + (py - y1) * dy) / length_sq))
            ex, ey = px - (x1 + t * dx), py - (y1 + t * dy)
        return ex * ex + ey * ey <= radius * radius

    @staticmethod
    def _point_in_polygon(px, py, points):
        """Ray-casting point-in-polygon test"""
        inside = False
        n = len(points)
        for i in range(n):
            x1, y1 = points[i]
            x2, y2 = points[(i + 1) % n]
            if (y1 > py) != (y2 > py):
                x_cross = x1 + (py - y1) * (x2 - x1) / (y2 - y1)
                if px < x_cross:
                    inside = not inside
        return inside

    def _shape_color_at(self, shapes, x, y):
        """Color of the topmost display-list shape covering (x, y), or None"""
        for shape in reversed(shapes):
            stype = shape['type']
            if stype == 'pixel':
                if shape['pos'] == (x, y):
                    return shape['color']
            elif stype in ('rect', 'roundrect'):
                left, top, right, bottom = shape['rect']
                if left <= x < right and top <= y < bottom:
                    pen = shape.get('pen')
                    fill = shape.get('fill')
                    on_border = (x < left + 1 or x >= right - 1 or
                                 y < top + 1 or y >= bottom - 1)
                    if pen and on_border:
                        return pen[0] if isinstance(pen, tuple) else pen
                    if fill is not None:
                        return fill
            elif stype == 'ellipse':
                left, top, right, bottom = shape['rect']
                rx, ry = (right - left) / 2.0, (bottom - top) / 2.0
                if rx > 0 and ry > 0:
                    nx = (x - (left + rx)) / rx
                    ny = (y - (top + ry)) / ry
                    if nx * nx + ny * ny <= 1.0 and shape.get('fill') is not None:
                        return shape['fill']
            elif stype == 'polygon':
                if (shape.get('fill') is not None and len(shape['points']) >= 3 and
                        self._point_in_polygon(x, y, shape['points'])):
                    return shape['fill']
            elif stype == 'line':
                pen = shape.get('pen')
                if pen:
                    color, width = pen
                    x1, y1 = shape['from']
                    x2, y2 = shape['to']
                    if self._point_near_segment(x, y, x1, y1, x2, y2,
                                                max(1, width) / 2.0 + 0.5):
                        return color
            elif stype == 'polyline':
                pen = shape.get('pen')
                if pen:
                    color, width = pen
                    pts = shape['points']
                    for i in range(len(pts) - 1):
                        if self._point_near_segment(x, y, pts[i][0], pts[i][1],
                                                    pts[i + 1][0], pts[i + 1][1],
                                                    max(1, width) / 2.0 + 0.5):
                            return color
            # arc/text: no reliable hit test, skip
        return None

    def GetPixel(self, args):
        """GetPixel emulation - resolved from the DC's display list"""
        hdc = args[0]
        x, y = self._read_signed_args(args, 1, 2)

        state = self.dc_state.get(hdc)
        if state and state.get('memory'):
            shapes = state['shapes']
            background = (255, 255, 255)
        else:
            hwnd = self._dc_hwnd(hdc)
            if not self.gui or hwnd not in self.gui.windows:
                return 0xFFFFFFFF  # CLR_INVALID
            shapes = self.gui.windows[hwnd].drawn_shapes
            background = PseudoWindowsGUI.COLOR_WINDOW_BG

        color = self._shape_color_at(shapes, x, y)
        if color is None:
            color = background
        colorref = self._rgb_to_colorref(color)
        log.debug(f"GetPixel(0x{hdc:x}, {x}, {y}) -> 0x{colorref:06x}")
        return colorref

    @staticmethod
    def _read_signed_args(args, start, count):
        """Interpret stack dwords as signed 32-bit integers"""
        return [v - 0x100000000 if v >= 0x80000000 else v
                for v in args[start:start + count]]

    def _read_points(self, address, count):
        """Read an array of POINT structures -> [(x, y), ...]"""
        points = []
        try:
            data = self.emu.uc.mem_read(address, count * 8)
            for i in range(count):
                x, y = struct.unpack_from("<ii", data, i * 8)
                points.append((x, y))
        except:
            pass
        return points

    def Polygon(self, args):
        """Polygon emulation - filled polygon with current pen and brush"""
        hdc = args[0]
        points = self._read_points(args[1], args[2])
        log.debug(f"Polygon(0x{hdc:x}, {len(points)} points)")
        if len(points) >= 3:
            self._add_shape(hdc, {'type': 'polygon', 'points': points,
                                  'fill': self._dc_brush(hdc), 'pen': self._dc_pen(hdc)})
        return 1

    def Polyline(self, args):
        """Polyline emulation - connected line segments with current pen"""
        hdc = args[0]
        points = self._read_points(args[1], args[2])
        log.debug(f"Polyline(0x{hdc:x}, {len(points)} points)")
        pen = self._dc_pen(hdc)
        if len(points) >= 2 and pen:
            self._add_shape(hdc, {'type': 'polyline', 'points': points, 'pen': pen})
        return 1

    def RoundRect(self, args):
        """RoundRect emulation - rectangle with rounded corners"""
        hdc = args[0]
        left, top, right, bottom, ew, eh = self._read_signed_args(args, 1, 6)
        log.debug(f"RoundRect(0x{hdc:x}, {left}, {top}, {right}, {bottom})")
        radius = max(0, min(ew, eh) // 2)
        self._add_shape(hdc, {'type': 'roundrect', 'rect': (left, top, right, bottom),
                              'radius': radius, 'fill': self._dc_brush(hdc),
                              'pen': self._dc_pen(hdc)})
        return 1

    @staticmethod
    def _arc_angles(left, top, right, bottom, x1, y1, x2, y2):
        """GDI arc endpoints -> (start, end) angles in math orientation (radians)"""
        import math
        cx, cy = (left + right) / 2.0, (top + bottom) / 2.0
        # Screen y grows downward; math orientation flips it
        start = math.atan2(cy - y1, x1 - cx)
        end = math.atan2(cy - y2, x2 - cx)
        return start, end

    def Arc(self, args):
        """Arc emulation - elliptic arc drawn counterclockwise"""
        hdc = args[0]
        left, top, right, bottom, x1, y1, x2, y2 = self._read_signed_args(args, 1, 8)
        log.debug(f"Arc(0x{hdc:x}, {left}, {top}, {right}, {bottom})")
        pen = self._dc_pen(hdc)
        if pen:
            start, end = self._arc_angles(left, top, right, bottom, x1, y1, x2, y2)
            self._add_shape(hdc, {'type': 'arc', 'rect': (left, top, right, bottom),
                                  'start': start, 'end': end, 'pen': pen})
        return 1

    def Pie(self, args):
        """Pie emulation - filled pie slice (approximated with a polygon)"""
        import math
        hdc = args[0]
        left, top, right, bottom, x1, y1, x2, y2 = self._read_signed_args(args, 1, 8)
        log.debug(f"Pie(0x{hdc:x}, {left}, {top}, {right}, {bottom})")

        start, end = self._arc_angles(left, top, right, bottom, x1, y1, x2, y2)
        if end <= start:
            end += 2 * math.pi

        # Sample the arc into polygon points (plus the center)
        cx, cy = (left + right) / 2.0, (top + bottom) / 2.0
        rx, ry = abs(right - left) / 2.0, abs(bottom - top) / 2.0
        steps = max(8, int((end - start) * 16))
        points = [(int(cx), int(cy))]
        for i in range(steps + 1):
            a = start + (end - start) * i / steps
            points.append((int(cx + rx * math.cos(a)), int(cy - ry * math.sin(a))))

        self._add_shape(hdc, {'type': 'polygon', 'points': points,
                              'fill': self._dc_brush(hdc), 'pen': self._dc_pen(hdc)})
        return 1

    def Chord(self, args):
        """Chord emulation - arc closed by its secant (approximated polygon)"""
        import math
        hdc = args[0]
        left, top, right, bottom, x1, y1, x2, y2 = self._read_signed_args(args, 1, 8)
        log.debug(f"Chord(0x{hdc:x}, {left}, {top}, {right}, {bottom})")

        start, end = self._arc_angles(left, top, right, bottom, x1, y1, x2, y2)
        if end <= start:
            end += 2 * math.pi

        cx, cy = (left + right) / 2.0, (top + bottom) / 2.0
        rx, ry = abs(right - left) / 2.0, abs(bottom - top) / 2.0
        steps = max(8, int((end - start) * 16))
        points = []
        for i in range(steps + 1):
            a = start + (end - start) * i / steps
            points.append((int(cx + rx * math.cos(a)), int(cy - ry * math.sin(a))))

        self._add_shape(hdc, {'type': 'polygon', 'points': points,
                              'fill': self._dc_brush(hdc), 'pen': self._dc_pen(hdc)})
        return 1

    def _brush_color(self, hbr):
        """Resolve a brush handle (or COLOR_* + 1 index) to an RGB color"""
        brush = self.gdi_objects.get(hbr)
        if brush and brush['type'] == 'brush':
            return brush['color']
        if hbr < 32:
            syscolors = {
                5 + 1: (255, 255, 255),   # COLOR_WINDOW+1
                15 + 1: (240, 240, 240),  # COLOR_3DFACE/COLOR_BTNFACE+1
            }
            return syscolors.get(hbr, (240, 240, 240))
        return None

    def FrameRect(self, args):
        """FrameRect emulation - one-pixel border drawn with a brush"""
        hdc = args[0]
        lprc = args[1]
        hbr = args[2]

        rect = self._read_rect(lprc) if lprc else None
        color = self._brush_color(hbr)
        if rect is None or color is None:
            return 0

        left, top, right, bottom = rect
        log.debug(f"FrameRect(0x{hdc:x}, ({left},{top},{right},{bottom}))")
        self._add_shape(hdc, {'type': 'rect', 'rect': rect,
                              'fill': None, 'pen': (color, 1)})
        return 1

    def PatBlt(self, args):
        """PatBlt emulation - BLACKNESS/WHITENESS/PATCOPY fills"""
        hdc = args[0]
        x, y, w, h = self._read_signed_args(args, 1, 4)
        rop = args[5]

        if rop == 0x00000042:        # BLACKNESS
            color = (0, 0, 0)
        elif rop == 0x00FF0062:      # WHITENESS
            color = (255, 255, 255)
        else:                        # PATCOPY and others: current brush
            color = self._dc_brush(hdc)

        log.debug(f"PatBlt(0x{hdc:x}, {x}, {y}, {w}, {h}, rop=0x{rop:08x})")
        if color is not None and w > 0 and h > 0:
            self._add_shape(hdc, {'type': 'rect', 'rect': (x, y, x + w, y + h),
                                  'fill': color, 'pen': None})
        return 1

    def CreateHatchBrush(self, args):
        """CreateHatchBrush emulation (hatch pattern approximated as solid)"""
        iHatch = args[0]
        colorref = args[1]
        handle = self.get_next_handle()
        self.gdi_objects[handle] = {
            'type': 'brush',
            'color': self._colorref_to_rgb(colorref),
            'width': 0,
        }
        log.debug(f"CreateHatchBrush({iHatch}, 0x{colorref:06x}) -> 0x{handle:x}")
        return handle

    def CreateFontA(self, args):
        """CreateFontA emulation"""
        height = args[0] - 0x100000000 if args[0] >= 0x80000000 else args[0]
        weight = args[4]
        italic = args[5]
        underline = args[6]
        face = self.read_string(args[13]) if args[13] else ""

        handle = self.get_next_handle()
        self.gdi_objects[handle] = {
            'type': 'font',
            'height': abs(height) or 13,
            'bold': weight >= 600,
            'italic': bool(italic),
            'underline': bool(underline),
            'face': face,
        }
        log.debug(f"CreateFontA(height={height}, weight={weight}, '{face}') -> 0x{handle:x}")
        return handle

    def CreateFontIndirectA(self, args):
        """CreateFontIndirectA emulation - font from a LOGFONT structure"""
        lplf = args[0]
        try:
            data = self.emu.uc.mem_read(lplf, 60)
            height = struct.unpack_from("<i", data, 0)[0]
            weight = struct.unpack_from("<i", data, 16)[0]
            italic, underline = data[20], data[21]
            face = data[28:60].split(b'\x00')[0].decode('utf-8', errors='replace')
        except:
            return 0

        handle = self.get_next_handle()
        self.gdi_objects[handle] = {
            'type': 'font',
            'height': abs(height) or 13,
            'bold': weight >= 600,
            'italic': bool(italic),
            'underline': bool(underline),
            'face': face,
        }
        log.debug(f"CreateFontIndirectA(height={height}, '{face}') -> 0x{handle:x}")
        return handle

    def GetTextExtentPoint32A(self, args):
        """GetTextExtentPoint32A emulation - measure a string"""
        hdc = args[0]
        text = self.read_string(args[1]) if args[1] else ""
        c = args[2]
        lpSize = args[3]
        if c > 0 and len(text) > c:
            text = text[:c]

        # Rough estimate; the GUI font is close to 8x16 per character
        width, height = len(text) * 8, 16
        font = self._dc_font(hdc)
        if font:
            height = font['height']
            width = int(len(text) * height * 0.55)

        if lpSize:
            self.emu.uc.mem_write(lpSize, struct.pack("<ii", width, height))
        return 1

    # ==================== MEMORY DC / DOUBLE BUFFERING ====================

    def CreateCompatibleDC(self, args):
        """CreateCompatibleDC emulation - off-screen memory DC"""
        hdc = args[0]
        mem_dc = self._create_dc(0, memory=True)
        log.debug(f"CreateCompatibleDC(0x{hdc:x}) -> 0x{mem_dc:x}")
        return mem_dc

    def CreateCompatibleBitmap(self, args):
        """CreateCompatibleBitmap emulation"""
        hdc = args[0]
        width = args[1]
        height = args[2]
        handle = self.get_next_handle()
        self.gdi_objects[handle] = {'type': 'bitmap', 'width': width, 'height': height}
        log.debug(f"CreateCompatibleBitmap(0x{hdc:x}, {width}, {height}) -> 0x{handle:x}")
        return handle

    def DeleteDC(self, args):
        """DeleteDC emulation - free a memory DC"""
        hdc = args[0]
        log.debug(f"DeleteDC(0x{hdc:x})")
        self._delete_dc(hdc)
        return 1

    @staticmethod
    def _translate_shape(shape, dx, dy):
        """Copy of a display list entry shifted by (dx, dy)"""
        moved = dict(shape)
        if 'rect' in moved:
            l, t, r, b = moved['rect']
            moved['rect'] = (l + dx, t + dy, r + dx, b + dy)
        if 'pos' in moved:
            x, y = moved['pos']
            moved['pos'] = (x + dx, y + dy)
        if 'from' in moved:
            x, y = moved['from']
            moved['from'] = (x + dx, y + dy)
        if 'to' in moved:
            x, y = moved['to']
            moved['to'] = (x + dx, y + dy)
        if 'points' in moved:
            moved['points'] = [(x + dx, y + dy) for x, y in moved['points']]
        return moved

    def BitBlt(self, args):
        """BitBlt emulation - copy a memory DC's display list to the target.

        A blit that covers the whole client area replaces the window's
        display list, so per-frame game rendering doesn't accumulate shapes.
        """
        hdcDest = args[0]
        x, y, cx, cy = self._read_signed_args(args, 1, 4)
        hdcSrc = args[5]
        sx, sy = self._read_signed_args(args, 6, 2)
        rop = args[8]

        log.debug(f"BitBlt(0x{hdcDest:x}, {x}, {y}, {cx}, {cy}, src=0x{hdcSrc:x}, rop=0x{rop:08x})")

        src_state = self.dc_state.get(hdcSrc)
        if not src_state or not src_state.get('memory'):
            return 1  # Only memory DC sources carry shapes

        dx, dy = x - sx, y - sy
        shapes = [self._translate_shape(s, dx, dy) for s in src_state['shapes']]

        dest_state = self.dc_state.get(hdcDest)
        if dest_state and dest_state.get('memory'):
            dest_state['shapes'].extend(shapes)
            return 1

        hwnd = self._dc_hwnd(hdcDest)
        if not self.gui or not hwnd or hwnd not in self.gui.windows:
            return 1

        window = self.gui.windows[hwnd]
        client_w, client_h = self.gui.client_size(window)
        if x <= 0 and y <= 0 and x + cx >= client_w and y + cy >= client_h:
            # Full-area blit: swap in a fresh list (GUI thread iterates snapshots)
            window.drawn_shapes = shapes
        else:
            window.drawn_shapes = window.drawn_shapes + shapes
        return 1

    @staticmethod
    def _scale_shape(shape, sx_src, sy_src, xd, yd, scale_x, scale_y):
        """Copy of a display list entry mapped through a StretchBlt transform"""
        def tx(x):
            return int(round(xd + (x - sx_src) * scale_x))

        def ty(y):
            return int(round(yd + (y - sy_src) * scale_y))

        scaled = dict(shape)
        if 'rect' in scaled:
            l, t, r, b = scaled['rect']
            x1, x2 = tx(l), tx(r)
            y1, y2 = ty(t), ty(b)
            # Normalize so mirrored blits keep left < right, top < bottom
            scaled['rect'] = (min(x1, x2), min(y1, y2), max(x1, x2), max(y1, y2))
        if 'pos' in scaled:
            x, y = scaled['pos']
            scaled['pos'] = (tx(x), ty(y))
        if 'from' in scaled:
            x, y = scaled['from']
            scaled['from'] = (tx(x), ty(y))
        if 'to' in scaled:
            x, y = scaled['to']
            scaled['to'] = (tx(x), ty(y))
        if 'points' in scaled:
            scaled['points'] = [(tx(x), ty(y)) for x, y in scaled['points']]
        if 'radius' in scaled:
            scale_avg = (abs(scale_x) + abs(scale_y)) / 2.0
            scaled['radius'] = max(0, int(round(scaled['radius'] * scale_avg)))
        return scaled

    def StretchBlt(self, args):
        """StretchBlt emulation - copy a memory DC's display list scaled.

        Like BitBlt, but the source rectangle is mapped onto the destination
        rectangle; shape coordinates are transformed accordingly (pen widths
        and font sizes are kept as-is).
        """
        hdcDest = args[0]
        xd, yd, wd, hd = self._read_signed_args(args, 1, 4)
        hdcSrc = args[5]
        xs, ys, ws, hs = self._read_signed_args(args, 6, 4)
        rop = args[10]

        log.debug(f"StretchBlt(0x{hdcDest:x}, dst=({xd},{yd},{wd},{hd}), "
                  f"src=0x{hdcSrc:x} ({xs},{ys},{ws},{hs}), rop=0x{rop:08x})")

        if ws == 0 or hs == 0:
            return 0

        src_state = self.dc_state.get(hdcSrc)
        if not src_state or not src_state.get('memory'):
            return 1  # Only memory DC sources carry shapes

        scale_x = wd / ws
        scale_y = hd / hs
        shapes = [self._scale_shape(s, xs, ys, xd, yd, scale_x, scale_y)
                  for s in src_state['shapes']]

        dest_state = self.dc_state.get(hdcDest)
        if dest_state and dest_state.get('memory'):
            dest_state['shapes'].extend(shapes)
            return 1

        hwnd = self._dc_hwnd(hdcDest)
        if not self.gui or not hwnd or hwnd not in self.gui.windows:
            return 1

        window = self.gui.windows[hwnd]
        client_w, client_h = self.gui.client_size(window)
        if xd <= 0 and yd <= 0 and xd + wd >= client_w and yd + hd >= client_h:
            # Full-area blit: swap in a fresh list (GUI thread iterates snapshots)
            window.drawn_shapes = shapes
        else:
            window.drawn_shapes = window.drawn_shapes + shapes
        return 1

    def ValidateRect(self, args):
        """ValidateRect emulation - mark the window as painted"""
        hWnd = args[0]
        self.painted_windows.add(hWnd)
        return 1

    # ==================== MENU APIs ====================

    MF_SEPARATOR = 0x0800
    MF_POPUP = 0x0010

    def CreateMenu(self, args):
        """CreateMenu emulation"""
        handle = self.get_next_handle()
        self.menus[handle] = []
        log.debug(f"CreateMenu() -> 0x{handle:x}")
        return handle

    def CreatePopupMenu(self, args):
        """CreatePopupMenu emulation"""
        handle = self.get_next_handle()
        self.menus[handle] = []
        log.debug(f"CreatePopupMenu() -> 0x{handle:x}")
        return handle

    def AppendMenuA(self, args):
        """AppendMenuA emulation"""
        hMenu = args[0]
        uFlags = args[1]
        uIDNewItem = args[2]
        lpNewItem = args[3]

        if hMenu not in self.menus:
            return 0

        text = ""
        if not (uFlags & self.MF_SEPARATOR) and lpNewItem:
            text = self.read_string(lpNewItem)

        self.menus[hMenu].append({
            'flags': uFlags,
            'id': uIDNewItem,
            'text': text,
            'submenu': uIDNewItem if (uFlags & self.MF_POPUP) else 0,
        })

        log.debug(f"AppendMenuA(0x{hMenu:x}, flags=0x{uFlags:x}, id=0x{uIDNewItem:x}, '{text}')")
        return 1

    def _build_menu_tree(self, hmenu):
        """Convert menu handles into the plain structure the GUI renders"""
        tree = []
        for item in self.menus.get(hmenu, []):
            if item['flags'] & self.MF_POPUP:
                subitems = []
                for sub in self.menus.get(item['submenu'], []):
                    if sub['flags'] & self.MF_SEPARATOR:
                        subitems.append({'separator': True})
                    else:
                        subitems.append({'text': sub['text'], 'id': sub['id']})
                tree.append({'text': item['text'], 'id': 0, 'items': subitems})
            elif item['flags'] & self.MF_SEPARATOR:
                continue  # Separators make no sense at the top level
            else:
                tree.append({'text': item['text'], 'id': item['id'], 'items': None})
        return tree

    def SetMenu(self, args):
        """SetMenu emulation - attach a menu bar to a window"""
        hWnd = args[0]
        hMenu = args[1]

        log.debug(f"SetMenu(0x{hWnd:x}, 0x{hMenu:x})")

        if self.gui and hWnd in self.gui.windows:
            window = self.gui.windows[hWnd]
            window.menu = self._build_menu_tree(hMenu) if hMenu else None
        return 1

    def DrawMenuBar(self, args):
        """DrawMenuBar emulation - menu bar is redrawn every frame anyway"""
        return 1

    def DestroyMenu(self, args):
        """DestroyMenu emulation"""
        hMenu = args[0]
        return 1 if self.menus.pop(hMenu, None) is not None else 0

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

    def api__p__acmdln(self, args):
        """__p__acmdln emulation - pointer to the ANSI command line pointer"""
        if self._acmdln_addr == 0:
            self._acmdln_addr = self.emu.heap_alloc(4)
            self.emu.uc.mem_write(self._acmdln_addr,
                                  struct.pack('<I', self.emu.cmdline_addr))
        log.debug(f"__p__acmdln() -> 0x{self._acmdln_addr:08x}")
        return self._acmdln_addr

    def api__p__wcmdln(self, args):
        """__p__wcmdln emulation - pointer to the wide command line pointer"""
        if self._wcmdln_addr == 0:
            self._wcmdln_addr = self.emu.heap_alloc(4)
            self.emu.uc.mem_write(self._wcmdln_addr,
                                  struct.pack('<I', self.emu.cmdline_wide_addr))
        log.debug(f"__p__wcmdln() -> 0x{self._wcmdln_addr:08x}")
        return self._wcmdln_addr

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
    
    def _format_string(self, fmt, varargs):
        """printf/wsprintf style formatting with 32-bit stack arguments.

        Supports %d %i %u %x %X %c %s %% with optional '-', '0', width and
        precision. varargs is the argument list starting at the first value.
        """
        result = []
        arg_index = 0
        i = 0
        while i < len(fmt):
            ch = fmt[i]
            if ch != '%':
                result.append(ch)
                i += 1
                continue

            # Parse %[flags][width][.precision][l]type
            spec = re.match(r'%([-0]*)(\d*)(?:\.(\d+))?l?([diuxXcs%])', fmt[i:])
            if not spec:
                result.append(ch)
                i += 1
                continue

            flags, width, precision, conv = spec.groups()
            i += spec.end()

            if conv == '%':
                result.append('%')
                continue

            arg = varargs[arg_index] if arg_index < len(varargs) else 0
            arg_index += 1

            if conv in 'di':
                # Interpret as signed 32-bit
                value = arg - 0x100000000 if arg >= 0x80000000 else arg
                text = str(value)
            elif conv == 'u':
                text = str(arg)
            elif conv in 'xX':
                text = format(arg, conv)
            elif conv == 'c':
                text = chr(arg & 0xFF)
            else:  # 's'
                text = self.read_string(arg) if arg else ""
                if precision:
                    text = text[:int(precision)]

            if width:
                pad = int(width)
                if '-' in flags:
                    text = text.ljust(pad)
                elif '0' in flags and conv != 's':
                    sign = ''
                    if text.startswith('-'):
                        sign, text = '-', text[1:]
                    text = sign + text.rjust(pad - len(sign), '0')
                else:
                    text = text.rjust(pad)

            result.append(text)

        return ''.join(result)

    def wsprintfA(self, args):
        """wsprintfA emulation (user32, cdecl varargs)"""
        buf = args[0]
        fmt = self.read_string(args[1])
        text = self._format_string(fmt, args[2:])
        log.debug(f"wsprintfA(0x{buf:08x}, \"{fmt}\") -> \"{text}\"")
        try:
            self.emu.uc.mem_write(buf, text.encode('utf-8') + b'\x00')
        except:
            pass
        return len(text)

    def sprintf(self, args):
        """sprintf emulation"""
        buf = args[0]
        fmt = self.read_string(args[1])
        text = self._format_string(fmt, args[2:])
        log.debug(f"sprintf(0x{buf:08x}, \"{fmt}\") -> \"{text}\"")
        try:
            self.emu.uc.mem_write(buf, text.encode('utf-8') + b'\x00')
        except:
            pass
        return len(text)

    def printf(self, args):
        """printf emulation"""
        fmt = self.read_string(args[0])
        text = self._format_string(fmt, args[1:])
        log.info(f"[PRINTF] {text}")
        if self.gui and self.gui.running:
            self.gui.console_write_stdout(text)
        return len(text)
    
    def puts(self, args):
        """puts emulation"""
        s = self.read_string(args[0])
        log.info(f"[PUTS] {s}")
        if self.gui and self.gui.running:
            self.gui.console_write_stdout(s + "\n")
        return len(s) + 1

    # Numeric / time CRT functions
    def rand(self, args):
        """rand emulation (MSVC-compatible LCG, returns 0..0x7FFF)"""
        self._rand_seed = (self._rand_seed * 214013 + 2531011) & 0xFFFFFFFF
        return (self._rand_seed >> 16) & 0x7FFF

    def srand(self, args):
        """srand emulation"""
        self._rand_seed = args[0] & 0xFFFFFFFF
        log.debug(f"srand({args[0]})")
        return 0

    def time(self, args):
        """time emulation - Unix timestamp (time_t as 32-bit)"""
        lpTime = args[0]
        t = int(time.time()) & 0xFFFFFFFF
        if lpTime:
            try:
                self.emu.uc.mem_write(lpTime, struct.pack("<I", t))
            except:
                pass
        log.debug(f"time() -> {t}")
        return t

    def clock(self, args):
        """clock emulation - milliseconds since start (CLOCKS_PER_SEC=1000)"""
        return int((time.time() - self._clock_epoch) * 1000) & 0xFFFFFFFF

    def abs(self, args):
        """abs emulation"""
        v = args[0] - 0x100000000 if args[0] >= 0x80000000 else args[0]
        return (v if v >= 0 else -v) & 0xFFFFFFFF

    def labs(self, args):
        """labs emulation (long == int on win32)"""
        return self.abs(args)

    def atoi(self, args):
        """atoi emulation"""
        s = self.read_string(args[0]).strip()
        sign = 1
        if s[:1] in ('+', '-'):
            if s[0] == '-':
                sign = -1
            s = s[1:]
        digits = ''
        for ch in s:
            if not ch.isdigit():
                break
            digits += ch
        value = sign * int(digits) if digits else 0
        log.debug(f"atoi -> {value}")
        return value & 0xFFFFFFFF

    def atol(self, args):
        """atol emulation (long == int on win32)"""
        return self.atoi(args)

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
    
    def _ismbblead(self, args):
        """_ismbblead emulation - no multibyte lead bytes in the C locale"""
        return 0

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

        # Retained drawing list (GDI display list, redrawn every frame):
        # Rectangle/Ellipse/LineTo/SetPixel/Polygon/TextOut... items
        self.drawn_shapes = []

        # Menu bar: list of {'text', 'id', 'items': [...]} or None
        self.menu = None

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
        self.control_id = 0  # Control ID (hMenu in CreateWindowEx) for WM_COMMAND
        self.checked = False  # For Checkbox/Radio
        self.items = []       # For Listbox/Combobox (LB_ADDSTRING, CB_ADDSTRING)
        self.sel_index = -1   # Selected item index (-1 = none)
        # Scrollbar state (SCROLLBAR class)
        self.scroll_min = 0
        self.scroll_max = 100
        self.scroll_pos = 0
        self.scroll_page = 0  # 0 = no page size set (SetScrollInfo SIF_PAGE)
        
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

    # Resize settings
    RESIZE_BORDER = 6      # Edge grab margin (pixels)
    MIN_WINDOW_WIDTH = 120
    MIN_WINDOW_HEIGHT = 80

    # Window chrome geometry (client area origin = x+BORDER, y+BORDER+TITLE_BAR_H)
    BORDER = 3
    TITLE_BAR_H = 25
    MENU_H = 20  # Menu bar height (only when the window has a menu)
    LISTBOX_ITEM_H = 18  # Row height in LISTBOX and COMBOBOX dropdowns

    def __init__(self, width=1024, height=768):
        self.width = width
        self.height = height
        self.screen = None
        self.running = False
        self.clock = None
        self.winapi = None  # WinAPIHandler back-reference (set by CPUEmulator.initialize)
        
        # Window management
        self.windows = {}  # hwnd -> FakeWindow
        self.controls = {}  # hwnd -> FakeControl
        self.next_hwnd = 0x10000
        self.active_window = None
        self.z_order = []  # Window ordering (topmost is at end)

        # Keyboard focus (EDIT controls)
        self.focused_control = None  # hwnd of the focused control

        # Open dropdown menu: (window_hwnd, top_level_item_index) or None
        self.open_menu = None

        # Open combobox dropdown: control hwnd or None
        self.open_combo = None

        # Keyboard state for GetAsyncKeyState (vk -> bool, GUI thread writes)
        self.key_states = {}

        # Last mouse position for GetCursorPos (GUI thread writes)
        self.mouse_pos = (0, 0)

        # Font
        self.font = None
        self.font_small = None
        self.font_bold = None
        self._font_cache = {}  # (face, size, bold, italic) -> pygame Font
        
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

        # Scrollbar thumb dragging: (control hwnd, grab offset in thumb) or None
        self.dragging_scrollbar = None

        # Window resizing
        self.resizing_window = None  # Resized window hwnd
        self.resize_edge = None      # Active edge: 'left','right','top','bottom' + corners
        self.resize_start_mouse = (0, 0)  # Mouse pos when resize began
        self.resize_start_rect = (0, 0, 0, 0)  # Window (x, y, w, h) when resize began
        self.current_cursor = None   # Currently set system cursor (avoid redundant sets)

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
        
        self.screen = pygame.display.set_mode((self.width, self.height), pygame.SCALED)
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
                    # Release drag / resize; forward release to app if neither
                    was_interacting = (self.dragging_window is not None or
                                       self.resizing_window is not None or
                                       self.dragging_scrollbar is not None)
                    if self.dragging_scrollbar is not None:
                        self._end_scrollbar_drag()
                    self.dragging_window = None
                    self.resizing_window = None
                    self.resize_edge = None
                    if not was_interacting:
                        self._forward_mouse_up(event.pos, event.button)
                elif event.type == pygame.MOUSEMOTION:
                    self.mouse_pos = event.pos
                    # Scrollbar thumb dragging grabs the mouse first
                    if self.dragging_scrollbar is not None:
                        self._drag_scrollbar_to(event.pos)
                    # Window resizing (takes priority over dragging)
                    elif self.resizing_window and self.resizing_window in self.windows:
                        self._resize_window_to(self.windows[self.resizing_window], event.pos)
                    # Window dragging
                    elif self.dragging_window and self.dragging_window in self.windows:
                        win = self.windows[self.dragging_window]
                        win.x = event.pos[0] - self.drag_offset_x
                        win.y = event.pos[1] - self.drag_offset_y
                        # Keep within screen boundaries
                        win.x = max(0, min(win.x, self.width - 50))
                        win.y = max(0, min(win.y, self.height - 60))
                    else:
                        # Update mouse cursor based on hovered edge
                        self._update_resize_cursor(event.pos)
                        # Forward WM_MOUSEMOVE to the app window
                        self._forward_mouse_move(event.pos, event.buttons)
                elif event.type == pygame.KEYDOWN:
                    vk = self._pygame_key_to_vk(event)
                    if vk is not None:
                        self.key_states[vk] = True
                    self._handle_key_press(event)
                elif event.type == pygame.KEYUP:
                    vk = self._pygame_key_to_vk(event)
                    if vk is not None:
                        self.key_states[vk] = False
                        self._forward_key_up(vk)
            
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

        # Open dropdown menu is drawn over all windows
        self._draw_open_menu()

        # Open combobox dropdown is drawn over all windows too
        self._draw_open_combo()
    
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
        
        # Menu bar (between title bar and client area)
        if window.menu:
            self._draw_menu_bar(window)

        # Content area
        client_x, client_y = self.client_origin(window)
        client_w, client_h = self.client_size(window)
        content_rect = pygame.Rect(client_x, client_y, client_w, client_h)
        pygame.draw.rect(self.screen, window.bg_color, content_rect)

        # Clip client-area drawing to the window (GDI shapes may overflow)
        self.screen.set_clip(content_rect)

        # Render GDI shapes and texts (Rectangle, Ellipse, TextOut, ...)
        for shape in window.drawn_shapes:
            self._draw_shape(shape, client_x, client_y)

        # Draw controls
        for control in window.controls:
            self._draw_control(control, client_x, client_y)

        self.screen.set_clip(None)

    def _draw_shape(self, shape, ox, oy):
        """Render one GDI display list entry at client origin (ox, oy)"""
        stype = shape['type']

        if stype == 'line':
            color, width = shape['pen']
            x1, y1 = shape['from']
            x2, y2 = shape['to']
            pygame.draw.line(self.screen, color, (ox + x1, oy + y1), (ox + x2, oy + y2), width)

        elif stype in ('rect', 'ellipse'):
            left, top, right, bottom = shape['rect']
            rect = pygame.Rect(ox + left, oy + top, right - left, bottom - top)
            draw_func = pygame.draw.rect if stype == 'rect' else pygame.draw.ellipse
            if shape.get('fill') is not None:
                draw_func(self.screen, shape['fill'], rect)
            if shape.get('pen') is not None:
                color, width = shape['pen']
                draw_func(self.screen, color, rect, width)

        elif stype == 'roundrect':
            left, top, right, bottom = shape['rect']
            rect = pygame.Rect(ox + left, oy + top, right - left, bottom - top)
            radius = shape.get('radius', 0)
            if shape.get('fill') is not None:
                pygame.draw.rect(self.screen, shape['fill'], rect, border_radius=radius)
            if shape.get('pen') is not None:
                color, width = shape['pen']
                pygame.draw.rect(self.screen, color, rect, width, border_radius=radius)

        elif stype == 'polygon':
            points = [(ox + x, oy + y) for x, y in shape['points']]
            if len(points) >= 3:
                if shape.get('fill') is not None:
                    pygame.draw.polygon(self.screen, shape['fill'], points)
                if shape.get('pen') is not None:
                    color, width = shape['pen']
                    pygame.draw.polygon(self.screen, color, points, width)

        elif stype == 'polyline':
            points = [(ox + x, oy + y) for x, y in shape['points']]
            if len(points) >= 2 and shape.get('pen') is not None:
                color, width = shape['pen']
                pygame.draw.lines(self.screen, color, False, points, width)

        elif stype == 'arc':
            left, top, right, bottom = shape['rect']
            rect = pygame.Rect(ox + left, oy + top, right - left, bottom - top)
            if shape.get('pen') is not None:
                color, width = shape['pen']
                pygame.draw.arc(self.screen, color, rect,
                                shape['start'], shape['end'], width)

        elif stype == 'text':
            x, y = shape['pos']
            font = self._get_render_font(shape.get('font'))
            surface = font.render(shape['text'], True, shape.get('color') or self.COLOR_TEXT)
            self.screen.blit(surface, (ox + x, oy + y))
            if shape.get('font') and shape['font'].get('underline'):
                line_y = oy + y + surface.get_height() - 2
                pygame.draw.line(self.screen, shape.get('color') or self.COLOR_TEXT,
                                 (ox + x, line_y), (ox + x + surface.get_width(), line_y))

        elif stype == 'pixel':
            x, y = shape['pos']
            rect = pygame.Rect(ox + x, oy + y, 1, 1)
            pygame.draw.rect(self.screen, shape['color'], rect)

    def _get_render_font(self, font_dict):
        """Pygame font for a GDI font dict (cached); None -> default GUI font."""
        if not font_dict:
            return self.font
        # GDI height is in pixels; pygame SysFont sizes are close to points
        size = max(8, int(font_dict.get('height', 13) * 0.75))
        face = (font_dict.get('face') or 'arial').lower()
        bold = font_dict.get('bold', False)
        italic = font_dict.get('italic', False)
        key = (face, size, bold, italic)
        if key not in self._font_cache:
            self._font_cache[key] = pygame.font.SysFont(f"{face},arial", size,
                                                        bold=bold, italic=italic)
        return self._font_cache[key]

    def _draw_menu_bar(self, window):
        """Draw a window's menu bar and highlight the open item"""
        bar = self._menu_bar_rect(window)
        pygame.draw.rect(self.screen, self.COLOR_WINDOW_BG, bar)
        pygame.draw.line(self.screen, (128, 128, 128),
                         (bar.x, bar.bottom - 1), (bar.right - 1, bar.bottom - 1))

        item_rects = self._menu_item_rects(window)
        for i, (item, rect) in enumerate(zip(window.menu, item_rects)):
            is_open = (self.open_menu == (window.hwnd, i))
            if is_open:
                pygame.draw.rect(self.screen, self.COLOR_TITLE_BAR, rect)
            color = self.COLOR_TITLE_TEXT if is_open else self.COLOR_TEXT
            text = self.font.render(item['text'], True, color)
            self.screen.blit(text, (rect.x + 8, rect.y + (rect.height - text.get_height()) // 2))

    def _draw_open_menu(self):
        """Draw the open dropdown menu on top of everything"""
        if not self.open_menu:
            return
        hwnd, index = self.open_menu
        win = self.windows.get(hwnd)
        if not win or not win.visible or win.minimized or not win.menu:
            self.open_menu = None
            return

        drop, item_rects = self._menu_dropdown_rects(win, index)
        if drop is None:
            self.open_menu = None
            return

        # Dropdown frame with shadow
        shadow = pygame.Rect(drop.x + 3, drop.y + 3, drop.width, drop.height)
        pygame.draw.rect(self.screen, (64, 64, 64), shadow)
        pygame.draw.rect(self.screen, self.COLOR_WINDOW_BG, drop)
        pygame.draw.rect(self.screen, (128, 128, 128), drop, 1)

        mouse_pos = pygame.mouse.get_pos()
        items = win.menu[index].get('items') or []
        for sub, rect in zip(items, item_rects):
            if sub.get('separator'):
                mid_y = rect.y + rect.height // 2
                pygame.draw.line(self.screen, (128, 128, 128),
                                 (rect.x + 2, mid_y), (rect.right - 2, mid_y))
                continue
            hovered = rect.collidepoint(mouse_pos)
            if hovered:
                pygame.draw.rect(self.screen, self.COLOR_TITLE_BAR, rect)
            color = self.COLOR_TITLE_TEXT if hovered else self.COLOR_TEXT
            text = self.font.render(sub['text'], True, color)
            self.screen.blit(text, (rect.x + 16, rect.y + (rect.height - text.get_height()) // 2))
    
    def _combo_dropdown_rects(self, control):
        """Dropdown rect and item rects of an open combobox (screen coords)."""
        win = self.windows.get(control.parent_hwnd)
        if not win or not win.visible or win.minimized:
            return None, []
        ox, oy = self.client_origin(win)
        box_h = min(control.height, 24)
        item_h = self.LISTBOX_ITEM_H
        count = max(1, len(control.items))
        drop = pygame.Rect(ox + control.x, oy + control.y + box_h,
                           control.width, count * item_h + 2)
        rects = [pygame.Rect(drop.x + 1, drop.y + 1 + i * item_h,
                             drop.width - 2, item_h)
                 for i in range(len(control.items))]
        return drop, rects

    def _draw_open_combo(self):
        """Draw the open combobox dropdown on top of everything"""
        if not self.open_combo:
            return
        control = self.controls.get(self.open_combo)
        if not control or not control.visible:
            self.open_combo = None
            return

        drop, item_rects = self._combo_dropdown_rects(control)
        if drop is None:
            self.open_combo = None
            return

        shadow = pygame.Rect(drop.x + 3, drop.y + 3, drop.width, drop.height)
        pygame.draw.rect(self.screen, (64, 64, 64), shadow)
        pygame.draw.rect(self.screen, self.COLOR_EDIT_BG, drop)
        pygame.draw.rect(self.screen, (128, 128, 128), drop, 1)

        mouse_pos = pygame.mouse.get_pos()
        for i, (item, rect) in enumerate(zip(control.items, item_rects)):
            hovered = rect.collidepoint(mouse_pos)
            selected = (i == control.sel_index)
            if hovered or selected:
                pygame.draw.rect(self.screen, self.COLOR_TITLE_BAR, rect)
            color = self.COLOR_TITLE_TEXT if (hovered or selected) else self.COLOR_TEXT
            text = self.font.render(item, True, color)
            self.screen.blit(text, (rect.x + 3, rect.y + 1))

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
            border_color = (0, 0, 128) if control.hwnd == self.focused_control else (128, 128, 128)
            pygame.draw.rect(self.screen, border_color, rect, 1)
            # Sunken effect
            pygame.draw.line(self.screen, (64, 64, 64), (abs_x, abs_y), (abs_x + control.width, abs_y))
            pygame.draw.line(self.screen, (64, 64, 64), (abs_x, abs_y), (abs_x, abs_y + control.height))

            # Show the tail of the text if it is wider than the control
            text_str = control.text
            max_text_w = control.width - 8
            while text_str and self.font.size(text_str)[0] > max_text_w:
                text_str = text_str[1:]

            prev_clip = self.screen.get_clip()
            self.screen.set_clip(rect)
            text = self.font.render(text_str, True, self.COLOR_TEXT)
            text_y = abs_y + (control.height - text.get_height()) // 2
            self.screen.blit(text, (abs_x + 4, text_y))

            # Blinking caret when focused
            if control.hwnd == self.focused_control and (pygame.time.get_ticks() // 500) % 2 == 0:
                caret_x = abs_x + 4 + text.get_width() + 1
                pygame.draw.line(self.screen, self.COLOR_TEXT,
                                 (caret_x, abs_y + 3), (caret_x, abs_y + control.height - 4))
            self.screen.set_clip(prev_clip)
            
        elif control.class_name == "LISTBOX":
            rect = pygame.Rect(abs_x, abs_y, control.width, control.height)
            pygame.draw.rect(self.screen, self.COLOR_EDIT_BG, rect)
            pygame.draw.rect(self.screen, (128, 128, 128), rect, 1)

            # Items with the selected one highlighted
            prev_clip = self.screen.get_clip()
            self.screen.set_clip(rect)
            item_h = self.LISTBOX_ITEM_H
            for i, item in enumerate(control.items):
                item_rect = pygame.Rect(abs_x + 1, abs_y + 1 + i * item_h,
                                        control.width - 2, item_h)
                if item_rect.top > rect.bottom:
                    break
                selected = (i == control.sel_index)
                if selected:
                    pygame.draw.rect(self.screen, self.COLOR_TITLE_BAR, item_rect)
                color = self.COLOR_TITLE_TEXT if selected else self.COLOR_TEXT
                text = self.font.render(item, True, color)
                self.screen.blit(text, (item_rect.x + 3, item_rect.y + 1))
            self.screen.set_clip(prev_clip)

        elif control.class_name == "COMBOBOX":
            box_h = min(control.height, 24)
            rect = pygame.Rect(abs_x, abs_y, control.width, box_h)
            pygame.draw.rect(self.screen, self.COLOR_EDIT_BG, rect)
            pygame.draw.rect(self.screen, (128, 128, 128), rect, 1)

            # Selected item text
            sel_text = ""
            if 0 <= control.sel_index < len(control.items):
                sel_text = control.items[control.sel_index]
            if sel_text:
                prev_clip = self.screen.get_clip()
                self.screen.set_clip(rect)
                text = self.font.render(sel_text, True, self.COLOR_TEXT)
                self.screen.blit(text, (abs_x + 4, abs_y + (box_h - text.get_height()) // 2))
                self.screen.set_clip(prev_clip)

            # Dropdown arrow
            arrow_rect = pygame.Rect(abs_x + control.width - 18, abs_y + 1, 17, box_h - 2)
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

        elif control.class_name == "SCROLLBAR":
            m = self._scrollbar_metrics(control, abs_x, abs_y)

            # Track (classic dotted-gray look approximated with a light gray)
            pygame.draw.rect(self.screen, (224, 224, 224), m['track'])
            pygame.draw.rect(self.screen, (128, 128, 128),
                             pygame.Rect(abs_x, abs_y, control.width, control.height), 1)

            # Arrow buttons
            if m['vertical']:
                self._draw_button_3d(m['up'], "▲", small=True)
                self._draw_button_3d(m['down'], "▼", small=True)
            else:
                self._draw_button_3d(m['up'], "◄", small=True)
                self._draw_button_3d(m['down'], "►", small=True)

            # Thumb (pressed look while dragging)
            dragging = (self.dragging_scrollbar is not None and
                        self.dragging_scrollbar[0] == control.hwnd)
            self._draw_button_3d(m['thumb'], "", pressed=dragging)
    
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
    
    def _get_resize_edge(self, win, x, y):
        """Return which edge/corner the point is on, or None.

        Returns one of: 'left','right','top','bottom','topleft','topright',
        'bottomleft','bottomright'. Resizing is disabled for maximized,
        minimized and dialog (MessageBox) windows.
        """
        if win.maximized or win.minimized or win.is_dialog:
            return None

        m = self.RESIZE_BORDER

        # Point must be near the window rectangle (inner border band)
        if not (win.x - m <= x <= win.x + win.width + m and
                win.y - m <= y <= win.y + win.height + m):
            return None

        left = abs(x - win.x) <= m
        right = abs(x - (win.x + win.width)) <= m
        top = abs(y - win.y) <= m
        bottom = abs(y - (win.y + win.height)) <= m

        edge = ""
        if top:
            edge += "top"
        elif bottom:
            edge += "bottom"
        if left:
            edge += "left"
        elif right:
            edge += "right"

        return edge or None

    def _resize_window_to(self, win, pos):
        """Resize a window while the user drags an edge/corner."""
        mx, my = pos
        edge = self.resize_edge
        sx, sy = self.resize_start_mouse
        ox, oy, ow, oh = self.resize_start_rect

        dx = mx - sx
        dy = my - sy

        new_x, new_y, new_w, new_h = ox, oy, ow, oh

        if "left" in edge:
            new_x = ox + dx
            new_w = ow - dx
        elif "right" in edge:
            new_w = ow + dx

        if "top" in edge:
            new_y = oy + dy
            new_h = oh - dy
        elif "bottom" in edge:
            new_h = oh + dy

        # Enforce minimum size, keeping the opposite edge anchored
        if new_w < self.MIN_WINDOW_WIDTH:
            if "left" in edge:
                new_x -= (self.MIN_WINDOW_WIDTH - new_w)
            new_w = self.MIN_WINDOW_WIDTH
        if new_h < self.MIN_WINDOW_HEIGHT:
            if "top" in edge:
                new_y -= (self.MIN_WINDOW_HEIGHT - new_h)
            new_h = self.MIN_WINDOW_HEIGHT

        # Keep the title bar reachable on screen
        new_y = max(0, new_y)

        win.x, win.y, win.width, win.height = new_x, new_y, new_w, new_h

    def _update_resize_cursor(self, pos):
        """Set the mouse cursor to a resize arrow when hovering an edge."""
        x, y = pos
        edge = None

        # Find the topmost window under the cursor
        for hwnd in reversed(self.z_order):
            win = self.windows.get(hwnd)
            if win and win.visible and not win.minimized and win.contains_point(x, y):
                edge = self._get_resize_edge(win, x, y)
                break

        cursor_map = {
            "left": pygame.SYSTEM_CURSOR_SIZEWE,
            "right": pygame.SYSTEM_CURSOR_SIZEWE,
            "top": pygame.SYSTEM_CURSOR_SIZENS,
            "bottom": pygame.SYSTEM_CURSOR_SIZENS,
            "topleft": pygame.SYSTEM_CURSOR_SIZENWSE,
            "bottomright": pygame.SYSTEM_CURSOR_SIZENWSE,
            "topright": pygame.SYSTEM_CURSOR_SIZENESW,
            "bottomleft": pygame.SYSTEM_CURSOR_SIZENESW,
        }
        cursor = cursor_map.get(edge, pygame.SYSTEM_CURSOR_ARROW)

        if cursor != self.current_cursor:
            try:
                pygame.mouse.set_cursor(cursor)
                self.current_cursor = cursor
            except Exception:
                pass

    def _is_app_window(self, hwnd):
        """True if hwnd is an emulated application window with a WndProc.

        Once the emulated process has exited, its windows are dead: nothing
        consumes their messages, so they are treated as plain windows again
        (X click hides directly, input is no longer forwarded).
        """
        if not self.winapi or hwnd == self.console_hwnd:
            return False
        if self.winapi.process_exited:
            return False
        return bool(self.winapi._find_wndproc_for_hwnd(hwnd))

    def client_origin(self, win):
        """Screen coordinates of a window's client area origin."""
        top = win.y + self.BORDER + self.TITLE_BAR_H
        if win.menu:
            top += self.MENU_H
        return (win.x + self.BORDER, top)

    def client_size(self, win):
        """Client area size (width, height) of a window."""
        height = win.height - 2 * self.BORDER - self.TITLE_BAR_H
        if win.menu:
            height -= self.MENU_H
        return (win.width - 2 * self.BORDER, max(0, height))

    def _client_point(self, win, x, y):
        """Convert screen coordinates to a window's client coordinates."""
        ox, oy = self.client_origin(win)
        return (x - ox, y - oy)

    def add_shape(self, hwnd, shape):
        """Append a GDI shape to a window's display list (emu thread)."""
        if hwnd in self.windows:
            self.windows[hwnd].drawn_shapes.append(shape)

    def clear_drawings(self, hwnd):
        """Reset a window's display list (start of a paint cycle).

        A new empty list is assigned instead of clearing in place, so the GUI
        thread can safely keep iterating a snapshot it already picked up.
        """
        if hwnd in self.windows:
            self.windows[hwnd].drawn_shapes = []

    # ==================== MENU BAR ====================

    def _menu_bar_rect(self, win):
        """Screen rect of a window's menu bar strip (or None)."""
        if not win.menu:
            return None
        return pygame.Rect(win.x + self.BORDER,
                           win.y + self.BORDER + 22,
                           win.width - 2 * self.BORDER,
                           self.MENU_H)

    def _menu_item_rects(self, win):
        """Screen rects of the top-level menu items (computed, not cached)."""
        bar = self._menu_bar_rect(win)
        if bar is None:
            return []
        rects = []
        x = bar.x + 4
        for item in win.menu:
            text_w = self.font.size(item['text'])[0]
            width = text_w + 16
            rects.append(pygame.Rect(x, bar.y, width, bar.height))
            x += width
        return rects

    def _menu_dropdown_rects(self, win, index):
        """Dropdown rect and item rects of an open top-level menu."""
        item_rects = self._menu_item_rects(win)
        if index >= len(item_rects):
            return None, []
        top_rect = item_rects[index]
        items = win.menu[index].get('items') or []

        width = 100
        for sub in items:
            if sub.get('text'):
                width = max(width, self.font.size(sub['text'])[0] + 32)

        item_h = 20
        sep_h = 7
        height = sum(sep_h if sub.get('separator') else item_h for sub in items) + 4

        drop = pygame.Rect(top_rect.x, top_rect.bottom, width, height)
        rects = []
        y = drop.y + 2
        for sub in items:
            h = sep_h if sub.get('separator') else item_h
            rects.append(pygame.Rect(drop.x + 2, y, width - 4, h))
            y += h
        return drop, rects

    @staticmethod
    def _make_lparam(cx, cy):
        """Pack client x/y into an lParam (LOWORD=x, HIWORD=y)."""
        return ((cy & 0xFFFF) << 16) | (cx & 0xFFFF)

    def _post_control_command(self, win, control, notify_code):
        """Notify a window's WndProc about a control event via WM_COMMAND."""
        parent_hwnd = control.parent_hwnd or win.hwnd
        wParam = ((notify_code & 0xFFFF) << 16) | (control.control_id & 0xFFFF)
        self.winapi.post_window_message(parent_hwnd, self.winapi.WM_COMMAND,
                                        wParam, control.hwnd)

    # ==================== SCROLLBAR CONTROLS ====================

    SCROLL_BTN = 16       # Arrow button length (pixels)
    SCROLL_MIN_THUMB = 12  # Minimum thumb length

    def _scrollbar_metrics(self, control, abs_x, abs_y):
        """Geometry of a scrollbar control at its absolute screen position.

        Returns a dict with 'vertical', arrow rects 'up'/'down', 'track' and
        'thumb' rects, plus 'track_len' and 'thumb_len' along the scroll axis.
        """
        vertical = bool(control.style & 0x0001)  # SBS_VERT
        length = control.height if vertical else control.width
        btn = min(self.SCROLL_BTN, max(0, length // 2))
        track_len = max(1, length - 2 * btn)

        span = 1
        pos_max = control.scroll_max
        if self.winapi:
            pos_max = self.winapi.scroll_pos_max(control)
        span = max(1, pos_max - control.scroll_min)

        # Thumb length: proportional when a page size is set
        if control.scroll_page > 0:
            content = max(1, control.scroll_max - control.scroll_min + 1)
            thumb_len = int(track_len * control.scroll_page / content)
        else:
            thumb_len = self.SCROLL_MIN_THUMB
        thumb_len = max(self.SCROLL_MIN_THUMB, min(thumb_len, track_len))

        frac = (control.scroll_pos - control.scroll_min) / span
        frac = max(0.0, min(1.0, frac))
        thumb_off = int((track_len - thumb_len) * frac)

        if vertical:
            up = pygame.Rect(abs_x, abs_y, control.width, btn)
            down = pygame.Rect(abs_x, abs_y + control.height - btn,
                               control.width, btn)
            track = pygame.Rect(abs_x, abs_y + btn, control.width, track_len)
            thumb = pygame.Rect(abs_x, abs_y + btn + thumb_off,
                                control.width, thumb_len)
        else:
            up = pygame.Rect(abs_x, abs_y, btn, control.height)
            down = pygame.Rect(abs_x + control.width - btn, abs_y,
                               btn, control.height)
            track = pygame.Rect(abs_x + btn, abs_y, track_len, control.height)
            thumb = pygame.Rect(abs_x + btn + thumb_off, abs_y,
                                thumb_len, control.height)

        return {'vertical': vertical, 'up': up, 'down': down, 'track': track,
                'thumb': thumb, 'track_len': track_len, 'thumb_len': thumb_len,
                'span': span, 'pos_max': pos_max}

    def _scrollbar_abs_pos(self, control):
        """Absolute screen position of a scrollbar control, or None"""
        win = self.windows.get(control.parent_hwnd)
        if not win or not win.visible or win.minimized:
            return None
        content_x, content_y = self.client_origin(win)
        return (content_x + control.x, content_y + control.y)

    def _post_scroll(self, control, code, pos):
        """Post WM_VSCROLL/WM_HSCROLL for a scrollbar control to its parent."""
        if not self.winapi or not control.parent_hwnd:
            return
        vertical = bool(control.style & 0x0001)
        msg = self.winapi.WM_VSCROLL if vertical else self.winapi.WM_HSCROLL
        wparam = (code & 0xFFFF) | ((pos & 0xFFFF) << 16)
        self.winapi.post_window_message(control.parent_hwnd, msg,
                                        wparam, control.hwnd)

    def _scroll_by(self, control, delta, code):
        """Move a scrollbar by delta positions and notify the parent."""
        pos_max = self.winapi.scroll_pos_max(control) if self.winapi \
            else control.scroll_max
        new_pos = max(control.scroll_min, min(control.scroll_pos + delta, pos_max))
        control.scroll_pos = new_pos
        self._post_scroll(control, code, new_pos)

    def _handle_scrollbar_click(self, control, x, y, abs_x, abs_y):
        """Handle a left click inside a scrollbar control."""
        winapi = self.winapi
        if not winapi:
            return
        m = self._scrollbar_metrics(control, abs_x, abs_y)
        page = control.scroll_page if control.scroll_page > 0 else 10

        if m['up'].collidepoint(x, y):
            self._scroll_by(control, -1, winapi.SB_LINEUP)
        elif m['down'].collidepoint(x, y):
            self._scroll_by(control, 1, winapi.SB_LINEDOWN)
        elif m['thumb'].collidepoint(x, y):
            grab = (y - m['thumb'].y) if m['vertical'] else (x - m['thumb'].x)
            self.dragging_scrollbar = (control.hwnd, grab)
        elif m['track'].collidepoint(x, y):
            before = (y < m['thumb'].y) if m['vertical'] else (x < m['thumb'].x)
            if before:
                self._scroll_by(control, -page, winapi.SB_PAGEUP)
            else:
                self._scroll_by(control, page, winapi.SB_PAGEDOWN)

    def _drag_scrollbar_to(self, pos):
        """Track a scrollbar thumb drag (SB_THUMBTRACK)."""
        hwnd, grab = self.dragging_scrollbar
        control = self.controls.get(hwnd)
        if not control or not self.winapi:
            self.dragging_scrollbar = None
            return
        abs_pos = self._scrollbar_abs_pos(control)
        if abs_pos is None:
            self.dragging_scrollbar = None
            return
        m = self._scrollbar_metrics(control, abs_pos[0], abs_pos[1])
        slide = m['track_len'] - m['thumb_len']
        if slide <= 0:
            return
        coord = pos[1] if m['vertical'] else pos[0]
        track_start = m['track'].y if m['vertical'] else m['track'].x
        frac = (coord - grab - track_start) / slide
        frac = max(0.0, min(1.0, frac))
        new_pos = control.scroll_min + int(round(frac * m['span']))
        if new_pos != control.scroll_pos:
            control.scroll_pos = new_pos
            self._post_scroll(control, self.winapi.SB_THUMBTRACK, new_pos)

    def _end_scrollbar_drag(self):
        """Finish a thumb drag: SB_THUMBPOSITION then SB_ENDSCROLL."""
        hwnd, _ = self.dragging_scrollbar
        self.dragging_scrollbar = None
        control = self.controls.get(hwnd)
        if control and self.winapi:
            self._post_scroll(control, self.winapi.SB_THUMBPOSITION,
                              control.scroll_pos)
            self._post_scroll(control, self.winapi.SB_ENDSCROLL, 0)

    def _post_button_command(self, win, control):
        """Notify a window's WndProc that one of its buttons was clicked."""
        self._post_control_command(win, control, self.winapi.BN_CLICKED)

    def _handle_combo_click(self, pos, button):
        """Handle clicks while a combobox dropdown is open.

        Returns True if the click was consumed by the dropdown.
        """
        control = self.controls.get(self.open_combo)
        if not control:
            self.open_combo = None
            return False

        drop, item_rects = self._combo_dropdown_rects(control)
        if drop is not None and drop.collidepoint(pos):
            if button == 1:
                for i, rect in enumerate(item_rects):
                    if rect.collidepoint(pos):
                        control.sel_index = i
                        self.open_combo = None
                        win = self.windows.get(control.parent_hwnd)
                        if win and self.winapi:
                            self._post_control_command(win, control,
                                                       self.winapi.CBN_SELCHANGE)
                        return True
            return True  # Click inside dropdown chrome: swallow

        # Click elsewhere: close the dropdown, then process the click normally
        self.open_combo = None
        return False

    def _capture_target(self):
        """Window that currently captures the mouse (SetCapture), or None."""
        if not self.winapi:
            return None
        cap = self.winapi.capture_hwnd
        if cap and cap in self.windows and self._is_app_window(cap):
            return self.windows[cap]
        return None

    def _forward_mouse_move(self, pos, buttons):
        """Forward WM_MOUSEMOVE to the captured or hovered app window."""
        if not self.winapi:
            return
        x, y = pos
        wparam = 0
        if buttons[0]:
            wparam |= self.winapi.MK_LBUTTON
        if buttons[2]:
            wparam |= self.winapi.MK_RBUTTON

        # Mouse capture: every move goes to the capturing window
        win = self._capture_target()
        if win is None:
            # Otherwise: topmost visible app window under the cursor
            for hwnd in reversed(self.z_order):
                w = self.windows.get(hwnd)
                if w and w.visible and not w.minimized and w.contains_point(x, y):
                    if w.is_dialog or not self._is_app_window(hwnd):
                        return
                    if y < self.client_origin(w)[1]:
                        return  # title bar / menu bar / chrome
                    win = w
                    break
        if win is None:
            return
        cx, cy = self._client_point(win, x, y)
        self.winapi.post_window_message(win.hwnd, self.winapi.WM_MOUSEMOVE,
                                        wparam, self._make_lparam(cx, cy))

    def _forward_mouse_up(self, pos, button):
        """Forward a mouse-button release to the app window under the cursor."""
        if not self.winapi:
            return
        x, y = pos

        # Mouse capture: the release always goes to the capturing window
        win = self._capture_target()
        if win is not None:
            cx, cy = self._client_point(win, x, y)
            lparam = self._make_lparam(cx, cy)
            if button == 1:
                self.winapi.post_window_message(win.hwnd, self.winapi.WM_LBUTTONUP,
                                                0, lparam)
            elif button == 3:
                self.winapi.post_window_message(win.hwnd, self.winapi.WM_RBUTTONUP,
                                                0, lparam)
            return

        for hwnd in reversed(self.z_order):
            win = self.windows.get(hwnd)
            if win and win.visible and not win.minimized and win.contains_point(x, y):
                if win.is_dialog or not self._is_app_window(hwnd):
                    return
                if y < self.client_origin(win)[1]:
                    return  # title bar / menu bar / chrome, not client area
                cx, cy = self._client_point(win, x, y)
                lparam = self._make_lparam(cx, cy)
                if button == 1:
                    self.winapi.post_window_message(hwnd, self.winapi.WM_LBUTTONUP, 0, lparam)
                elif button == 3:
                    self.winapi.post_window_message(hwnd, self.winapi.WM_RBUTTONUP, 0, lparam)
                return

    def _handle_menu_click(self, pos, button):
        """Handle clicks while a dropdown menu is open.

        Returns True if the click was consumed by the menu system.
        """
        hwnd, index = self.open_menu
        win = self.windows.get(hwnd)
        if not win or not win.visible or win.minimized or not win.menu:
            self.open_menu = None
            return False

        drop, item_rects = self._menu_dropdown_rects(win, index)
        if drop is not None and drop.collidepoint(pos):
            if button == 1:
                items = win.menu[index].get('items') or []
                for sub, rect in zip(items, item_rects):
                    if not sub.get('separator') and rect.collidepoint(pos):
                        self.open_menu = None
                        if self.winapi:
                            # Menu WM_COMMAND: HIWORD(wParam)=0, LOWORD=menu id
                            self.winapi.post_window_message(
                                hwnd, self.winapi.WM_COMMAND, sub['id'] & 0xFFFF, 0)
                        return True
            return True  # Click inside dropdown chrome: swallow

        # Clicking another top-level item switches the open dropdown
        for i, rect in enumerate(self._menu_item_rects(win)):
            if rect.collidepoint(pos):
                self._activate_menu_item(win, i)
                return True

        # Click elsewhere: close the menu, then process the click normally
        self.open_menu = None
        return False

    def _activate_menu_item(self, win, index):
        """Open a dropdown or fire a plain top-level menu item"""
        item = win.menu[index]
        if item.get('items'):
            # Toggle dropdown
            if self.open_menu == (win.hwnd, index):
                self.open_menu = None
            else:
                self.open_menu = (win.hwnd, index)
        else:
            self.open_menu = None
            if self.winapi:
                self.winapi.post_window_message(
                    win.hwnd, self.winapi.WM_COMMAND, item['id'] & 0xFFFF, 0)

    def _handle_mouse_click(self, pos, button):
        """Handle mouse click"""
        x, y = pos

        # An open dropdown menu grabs clicks first
        if self.open_menu and self._handle_menu_click(pos, button):
            return

        # An open combobox dropdown grabs clicks next
        if self.open_combo and self._handle_combo_click(pos, button):
            return

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
                    
                    # Edge/corner resizing (left button only)
                    if button == 1:
                        edge = self._get_resize_edge(win, x, y)
                        if edge:
                            self.resizing_window = hwnd
                            self.resize_edge = edge
                            self.resize_start_mouse = (x, y)
                            self.resize_start_rect = (win.x, win.y, win.width, win.height)
                            return

                    # Title bar click (start dragging) - if not maximized
                    if win.y + 3 <= y <= win.y + 25 and not win.maximized:
                        self.dragging_window = hwnd
                        self.drag_offset_x = x - win.x
                        self.drag_offset_y = y - win.y
                        return

                    # Menu bar click
                    if win.menu and button == 1:
                        for i, rect in enumerate(self._menu_item_rects(win)):
                            if rect.collidepoint(x, y):
                                self._activate_menu_item(win, i)
                                return
                        bar = self._menu_bar_rect(win)
                        if bar and bar.collidepoint(x, y):
                            return  # Empty menu bar area: swallow the click

                    # Click on controls in content area
                    content_x, content_y = self.client_origin(win)
                    for control in win.controls:
                        if not (control.visible and control.enabled):
                            continue
                        ctrl_x = content_x + control.x
                        ctrl_y = content_y + control.y
                        # A combobox only occupies its closed box; the
                        # CreateWindow height includes the dropdown area
                        ctrl_h = control.height
                        if control.class_name == "COMBOBOX":
                            ctrl_h = min(control.height, 24)
                        if not (ctrl_x <= x <= ctrl_x + control.width and
                                ctrl_y <= y <= ctrl_y + ctrl_h):
                            continue

                        if control.class_name == "BUTTON":
                            # Clicking a button takes focus away from edits
                            self.focused_control = None
                            # If dialog window (MessageBox) - OK/Cancel button closes it
                            if win.is_dialog:
                                self._close_window(hwnd)
                                return
                            # Normal window - notify WndProc with WM_COMMAND
                            if button == 1 and self.winapi:
                                self._post_button_command(win, control)
                            return
                        elif control.class_name == "EDIT":
                            # Give keyboard focus to the edit control
                            if button == 1:
                                self.focused_control = control.hwnd
                            return
                        elif control.class_name == "CHECKBOX":
                            if button == 1:
                                self.focused_control = None
                                # BS_AUTOCHECKBOX (0x3) toggles by itself
                                if (control.style & 0xF) == 0x3:
                                    control.checked = not control.checked
                                if self.winapi:
                                    self._post_button_command(win, control)
                            return
                        elif control.class_name == "LISTBOX":
                            if button == 1:
                                self.focused_control = None
                                index = (y - ctrl_y - 1) // self.LISTBOX_ITEM_H
                                if 0 <= index < len(control.items):
                                    control.sel_index = index
                                    if self.winapi:
                                        self._post_control_command(
                                            win, control, self.winapi.LBN_SELCHANGE)
                            return
                        elif control.class_name == "COMBOBOX":
                            if button == 1:
                                self.focused_control = None
                                # Toggle the dropdown list
                                if self.open_combo == control.hwnd:
                                    self.open_combo = None
                                else:
                                    self.open_combo = control.hwnd
                            return
                        elif control.class_name == "SCROLLBAR":
                            if button == 1:
                                self.focused_control = None
                                self._handle_scrollbar_click(control, x, y,
                                                             ctrl_x, ctrl_y)
                            return
                        # Other control types: swallow the click
                        return

                    # Clicking empty client area clears edit focus
                    if button == 1:
                        self.focused_control = None

                    # No control hit -> forward raw mouse click to the WndProc
                    if (not win.is_dialog and y >= content_y and
                            self._is_app_window(hwnd)):
                        cx, cy = self._client_point(win, x, y)
                        lparam = self._make_lparam(cx, cy)
                        if button == 1:
                            self.winapi.post_window_message(
                                hwnd, self.winapi.WM_LBUTTONDOWN,
                                self.winapi.MK_LBUTTON, lparam)
                        elif button == 3:
                            self.winapi.post_window_message(
                                hwnd, self.winapi.WM_RBUTTONDOWN,
                                self.winapi.MK_RBUTTON, lparam)

                    break
    
    def _pygame_key_to_vk(self, event):
        """Map a Pygame key to a Windows virtual-key code, or None."""
        key = event.key
        if pygame.K_a <= key <= pygame.K_z:
            return key - 32            # 'a' (0x61) -> VK 'A' (0x41)
        if pygame.K_0 <= key <= pygame.K_9:
            return key                 # '0' (0x30) -> VK 0x30
        if pygame.K_F1 <= key <= pygame.K_F12:
            return 0x70 + (key - pygame.K_F1)
        special = {
            pygame.K_ESCAPE: 0x1B, pygame.K_RETURN: 0x0D, pygame.K_KP_ENTER: 0x0D,
            pygame.K_SPACE: 0x20, pygame.K_TAB: 0x09, pygame.K_BACKSPACE: 0x08,
            pygame.K_DELETE: 0x2E, pygame.K_LEFT: 0x25, pygame.K_UP: 0x26,
            pygame.K_RIGHT: 0x27, pygame.K_DOWN: 0x28, pygame.K_HOME: 0x24,
            pygame.K_END: 0x23, pygame.K_PAGEUP: 0x21, pygame.K_PAGEDOWN: 0x22,
            pygame.K_LSHIFT: 0x10, pygame.K_RSHIFT: 0x10,
            pygame.K_LCTRL: 0x11, pygame.K_RCTRL: 0x11,
            pygame.K_LALT: 0x12, pygame.K_RALT: 0x12,
        }
        return special.get(key)

    def _forward_key_up(self, vk):
        """Forward a key release (WM_KEYUP) to the active application window."""
        if not self.winapi:
            return
        hwnd = self.active_window
        if hwnd and self._is_app_window(hwnd):
            self.winapi.post_window_message(hwnd, self.winapi.WM_KEYUP, vk, 1)

    def _forward_key_to_window(self, event):
        """Forward a keystroke to the active application window's WndProc."""
        if not self.winapi:
            return
        hwnd = self.active_window
        if not hwnd or not self._is_app_window(hwnd):
            return
        vk = self._pygame_key_to_vk(event)
        if vk is not None:
            self.winapi.post_window_message(hwnd, self.winapi.WM_KEYDOWN, vk, 1)
        # Synthesize WM_CHAR for printable input (TranslateMessage behavior)
        if event.unicode and len(event.unicode) == 1 and event.unicode.isprintable():
            self.winapi.post_window_message(hwnd, self.winapi.WM_CHAR, ord(event.unicode), 1)

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
            return

        # A focused EDIT control consumes keystrokes
        if self._handle_edit_key(event):
            return

        # Otherwise forward the keystroke to the active application window
        self._forward_key_to_window(event)

    def _handle_edit_key(self, event):
        """Type into the focused EDIT control. Returns True if consumed."""
        control = self.controls.get(self.focused_control)
        if not control or control.class_name != "EDIT":
            return False
        # Only edit when the parent window is visible and active
        win = self.windows.get(control.parent_hwnd)
        if not win or not win.visible or win.minimized or win.hwnd != self.active_window:
            return False
        if not (control.visible and control.enabled):
            return False

        if event.key == pygame.K_BACKSPACE:
            control.text = control.text[:-1]
        elif event.key in (pygame.K_RETURN, pygame.K_KP_ENTER, pygame.K_ESCAPE, pygame.K_TAB):
            self.focused_control = None
        elif event.unicode and event.unicode.isprintable():
            control.text += event.unicode
        return True

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
    
    def _close_window(self, hwnd, notify_app=True):
        """Close window.

        App windows with a WndProc get WM_CLOSE posted so the app decides
        (DestroyWindow / PostQuitMessage). Other windows are hidden directly.
        DestroyWindow calls this with notify_app=False to avoid a loop.
        """
        if hwnd not in self.windows:
            return

        if notify_app and self._is_app_window(hwnd):
            self.winapi.post_window_message(hwnd, self.winapi.WM_CLOSE, 0, 0)
            return

        self.windows[hwnd].visible = False
        if hwnd in self.z_order:
            self.z_order.remove(hwnd)
        if self.active_window == hwnd:
            self.active_window = self.z_order[-1] if self.z_order else None
        if self.open_menu and self.open_menu[0] == hwnd:
            self.open_menu = None
    
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
    
    def create_control(self, parent_hwnd, class_name, text, x, y, width, height, style=0, control_id=0):
        """Create new control"""
        hwnd = self.get_next_hwnd()
        control = FakeControl(hwnd, class_name, text, x, y, width, height, style)
        control.parent_hwnd = parent_hwnd
        control.control_id = control_id

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

        # Give the GUI thread a back-reference so it can post window messages
        if self.gui:
            self.gui.winapi = self.api_handler
        
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
        
        # Run callback. Unicorn's instruction budget is shared with the outer
        # emu_start (nested runs clobber it), so pass 0 (unlimited) here and
        # let the Python-side max_instructions check in _hook_code limit
        # everything uniformly.
        try:
            self.uc.emu_start(callback_addr, self.callback_return_addr, 0, 0)
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

        # Limit check (max_instructions <= 0 means unlimited)
        if self.max_instructions > 0 and self.instruction_count > self.max_instructions:
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
        if max_instructions is not None:
            self.max_instructions = max_instructions

        log.header("Starting Emulation")

        entry_point = self.pe_loader.image_base + self.pe_loader.entry_point
        log.info(f"Entry point: 0x{entry_point:08x}")
        log.info(f"Maximum instructions: "
                 f"{self.max_instructions if self.max_instructions > 0 else 'unlimited'}")

        try:
            # Start emulation (count 0 = unlimited in Unicorn)
            self.uc.emu_start(entry_point, 0, 0, max(0, self.max_instructions))

        except UcError as e:
            eip = self.uc.reg_read(UC_X86_REG_EIP)
            esp = self.uc.reg_read(UC_X86_REG_ESP)
            log.error(f"Emulation error: {e}")
            log.error(f"EIP: 0x{eip:08x}, ESP: 0x{esp:08x}")
        finally:
            # However the emulation ended (ExitProcess, error, instruction
            # limit), the process is gone and can't consume messages anymore
            if self.api_handler:
                self.api_handler.process_exited = True

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
    print("║          Windows 32-bit EXE Emulator v0.0.10             ║")
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
    parser.add_argument("-n", "--max-instructions", type=int, default=None,
                        help="Maximum instructions to execute "
                             "(default: 5000000 with GUI, 100000 without; "
                             "0 = unlimited, recommended for games)")
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
    
    use_gui = not args.no_gui
    # Interactive GUI apps run a long message loop; default to a higher cap
    if args.max_instructions is not None:
        max_instr = args.max_instructions
    else:
        max_instr = 5_000_000 if use_gui else 100000
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
