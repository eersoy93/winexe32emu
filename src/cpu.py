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

"""CPU emulation with unicorn: guest threads and the emulator"""

import struct
import threading
import mmap
import ctypes
import time
import ntpath

import pefile
from unicorn import *
from unicorn.x86_const import *
from capstone import *

from . import config
from .guest import ApiJump, GuestUnwind, QWordResult, X87Result
from .logger import DebugLogger, log
from .pe_loader import PELoader
from .winapi import WinAPIHandler


class GuestThread:
    """One thread of an emulated process: its own Unicorn instance (registers,
    FS/TEB) on the process's shared memory, and per-thread API state"""

    def __init__(self, tid, uc=None):
        self.tid = tid
        self.uc = uc
        self.callback_stack = []  # Stack for nested callback support
        self.api_call_esp = 0  # ESP at the current API stub (setjmp needs it)
        self.last_error = 0  # GetLastError/SetLastError storage
        self.mapped = {}  # base -> shared region mapped into this uc
        self.region_gen = -1  # CPUEmulator.region_gen the mappings match
        self.handle = 0  # Thread handle (0: main thread)
        self.teb = 0
        self.stack = 0
        self.suspend_count = 0
        self.exited = False
        self.exit_code = 259  # STILL_ACTIVE
        self.stop = False  # ExitThread: stop this thread's emulation
        self.python_thread = None
        self.pending_fault = None  # access violation the memory hook saw
        self.dispatch_depth = 0  # exceptions being dispatched (nested ones)


class CPUEmulator:
    """Unicorn-based x86 CPU emulator"""
    
    # Memory layout constants
    STACK_BASE = 0x7FF00000
    STACK_SIZE = 0x00100000  # 1MB stack
    HEAP_BASE = 0x10000000
    HEAP_SIZE = 128 * 1024 * 1024  # 128 MiB heap
    API_HOOK_BASE = 0x70000000  # API stub addresses
    API_HOOK_SIZE = 0x100000
    CALLBACK_RETURN_ADDR = 0x6FFF0000
    PROCESS_EXIT_ADDR = CALLBACK_RETURN_ADDR + 0x10  # return address of the entry point
    # Double-returning APIs return through "fld qword [X87_RESULT_ADDR]; ret"
    X87_RETURN_STUB = CALLBACK_RETURN_ADDR + 0x20
    X87_RESULT_ADDR = CALLBACK_RETURN_ADDR + 0x100
    # x87-register-argument APIs (_CIsin, _ftol...) spill ST(i) here
    X87_ARGS_ADDR = CALLBACK_RETURN_ADDR + 0x110
    # Return address of thread start routines (returning ends the thread)
    THREAD_EXIT_ADDR = CALLBACK_RETURN_ADDR + 0x30
    # Hot CRT routines run as guest code here (no API hook: calling into
    # Python for every small memcpy makes loops such as 7-Zip's AES key
    # derivation take minutes); unmapped memory faults like on Windows
    NATIVE_CODE_ADDR = CALLBACK_RETURN_ADDR + 0x1000
    NATIVE_ROUTINES = {
        # memmove semantics (overlap-safe), like msvcrt's memcpy
        'memmove': bytes.fromhex('57568b7c240c8b7424108b4c241489f8fc39f776158d140e39d7730e'
                                 '8d740eff8d7c0ffffdf3a4fceb02f3a45e5fc3'),
        'memset': bytes.fromhex('578b7c24088b44240c8b4c241089fafcf3aa89d05fc3'),
    }
    NATIVE_ROUTINES['memcpy'] = NATIVE_ROUTINES['memmove']
    NATIVE_ROUTINE_DLLS = ('msvcrt.dll', 'ntdll.dll', 'ucrtbase.dll',
                           'api-ms-win-crt-string-l1-1-0.dll', 'vcruntime140.dll')
    # A thread that runs this long without blocking lets the others run
    THREAD_TIME_SLICE = 0.02
    
    def __init__(self, pe_loader, gui=None):
        self.pe_loader = pe_loader
        self.gui = gui  # PseudoWindowsGUI reference
        # Threads: each guest thread runs on its own host thread and Unicorn
        # instance; holding the scheduler lock is the right to run guest code
        # (one guest thread at a time), released while a thread blocks
        self._tls = threading.local()
        self.main_thread = GuestThread(5678)
        self.threads = {self.main_thread.tid: self.main_thread}
        self.next_thread_id = 5682
        self.sched = threading.Condition(threading.RLock())
        self._slice_start = time.monotonic()
        # Process memory shared by the threads' Unicorn instances:
        # base -> (size, perms, host buffer, host address)
        self.shared_regions = {}
        self.region_gen = 0
        # Loaded real DLLs: base -> module info (see load_dll)
        self.dlls = {}
        self._count_instructions = False
        self.cs = None
        self.stop_emulation = False
        self.instruction_count = 0
        self.block_insn_counts = {}  # (address, size) -> instructions in block
        self.max_instructions = 0  # Maximum instruction limit (0 = unlimited)
        
        # Memory management
        self.heap_current = self.HEAP_BASE
        self.heap_blocks = {}  # addr -> requested size (for realloc)
        self.heap_free_bins = {}  # aligned size -> set of free block addrs
        self.heap_free_ends = {}  # free block end addr -> start addr
        self.mapped_regions = []
        
        # API hook system
        self.api_hooks = {}
        self.api_handler = None
        self.crashed = False
        self.next_hook_addr = self.API_HOOK_BASE
        self.dynamic_stubs = {}  # (dll, name) -> stub addr from GetProcAddress
        
        # Callback system
        self.callback_return_addr = self.CALLBACK_RETURN_ADDR
        self.pending_callback = None  # Pending callback info
        
        # Console input system
        self.pending_console_read = None  # Pending ReadConsoleA request
        self.stop_for_input = False  # Paused for input?
        
        # Special memory addresses
        self.cmdline_addr = 0
        self.cmdline_wide_addr = 0
        self.peb_addr = 0
        self.teb_addr = 0
        self.process_heap = 0
        
    # ---------- Threads ----------

    @property
    def current_thread(self):
        """GuestThread running on the calling host thread (main thread otherwise)"""
        return getattr(self._tls, 'thread', None) or self.main_thread

    @property
    def uc(self):
        return self.current_thread.uc

    @uc.setter
    def uc(self, value):
        self.main_thread.uc = value

    @property
    def callback_stack(self):
        return self.current_thread.callback_stack

    @property
    def api_call_esp(self):
        return self.current_thread.api_call_esp

    @api_call_esp.setter
    def api_call_esp(self, value):
        self.current_thread.api_call_esp = value

    def all_ucs(self):
        return [t.uc for t in list(self.threads.values()) if t.uc is not None]

    def stop_all(self):
        """Stop every thread's emulation (process exit or termination)"""
        self.stop_emulation = True
        for uc in self.all_ucs():
            try:
                uc.emu_stop()
            except UcError:
                pass
        self.wake_threads()

    def wake_threads(self):
        """Let blocked threads re-check what they wait for (call with the
        scheduler lock, e.g. from API handlers)"""
        try:
            self.sched.notify_all()
        except RuntimeError:
            # Not the scheduler lock owner (GUI thread): they poll anyway
            pass

    def idle_wait(self, seconds):
        """Block the calling guest thread for a while and let other threads run"""
        try:
            self.sched.wait(seconds)
        except RuntimeError:
            time.sleep(seconds)
        self._slice_start = time.monotonic()

    def wait_until(self, condition, timeout_ms=0xFFFFFFFF):
        """Block until condition() is true (True), the timeout passes or the
        process stops (False); other threads run meanwhile"""
        deadline = None if timeout_ms == 0xFFFFFFFF else time.monotonic() + timeout_ms / 1000.0
        while True:
            if condition():
                return True
            if self.stop_emulation or self.current_thread.stop:
                return False
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self.idle_wait(min(remaining, 0.05))
            else:
                self.idle_wait(0.05)

    def maybe_yield(self):
        """Time slicing at API calls: a thread that runs long without
        blocking gives the other runnable threads a turn"""
        if len(self.threads) > 1 and time.monotonic() - self._slice_start > self.THREAD_TIME_SLICE:
            self.idle_wait(0.0005)

    def map_shared(self, base, size, perms=UC_PROT_ALL):
        """Map new process memory, visible to every thread's Unicorn instance"""
        buf = mmap.mmap(-1, size)
        ptr = ctypes.addressof(ctypes.c_char.from_buffer(buf))
        self.uc.mem_map_ptr(base, size, perms, ptr)
        region = (size, perms, buf, ptr)
        self.shared_regions[base] = region
        self.current_thread.mapped[base] = region
        self.region_gen += 1

    def map_foreign(self, base, size, buf, ptr, perms=UC_PROT_ALL):
        """Map host memory another process owns too (shared file mappings)"""
        self.uc.mem_map_ptr(base, size, perms, ptr)
        region = (size, perms, buf, ptr)
        self.shared_regions[base] = region
        self.current_thread.mapped[base] = region
        self.mapped_regions.append((base, base + size))
        self.region_gen += 1

    def unmap_shared(self, base, size):
        """Unmap process memory (other threads drop it at their next sync)"""
        self.shared_regions.pop(base, None)
        thread = self.current_thread
        if thread.mapped.pop(base, None) is not None:
            self.uc.mem_unmap(base, size)
        self.region_gen += 1

    def sync_regions(self, thread=None):
        """Bring a thread's Unicorn memory map up to date with the process'.
        Returns True if anything was mapped."""
        thread = thread or self.current_thread
        if thread.region_gen == self.region_gen:
            return False
        changed = False
        for base, region in list(thread.mapped.items()):
            if self.shared_regions.get(base) is not region:
                thread.uc.mem_unmap(base, region[0])
                del thread.mapped[base]
        for base, region in list(self.shared_regions.items()):
            if base not in thread.mapped:
                size, perms, _, ptr = region
                thread.uc.mem_map_ptr(base, size, perms, ptr)
                thread.mapped[base] = region
                changed = True
        thread.region_gen = self.region_gen
        return changed

    def _setup_segments(self, uc, teb):
        """GDT with flat code/data segments and FS -> teb, loaded into uc"""
        def create_gdt_entry(base, limit, access, flags):
            entry = bytearray(8)
            entry[0] = limit & 0xFF
            entry[1] = (limit >> 8) & 0xFF
            entry[2] = base & 0xFF
            entry[3] = (base >> 8) & 0xFF
            entry[4] = (base >> 16) & 0xFF
            entry[5] = access
            entry[6] = ((limit >> 16) & 0x0F) | (flags << 4)
            entry[7] = (base >> 24) & 0xFF
            return bytes(entry)

        gdt_addr = self.heap_alloc(0x100)
        gdt = (b'\x00' * 8 +                                     # Null descriptor
               create_gdt_entry(0, 0xFFFFF, 0x9B, 0x0C) +         # Code segment (CS)
               create_gdt_entry(0, 0xFFFFF, 0x93, 0x0C) +         # Data segment (DS, ES, SS)
               create_gdt_entry(teb, 0xFFF, 0x93, 0x00))          # FS segment (TEB)
        uc.mem_write(gdt_addr, gdt)
        uc.reg_write(UC_X86_REG_GDTR, (0, gdt_addr, len(gdt) - 1, 0))
        uc.reg_write(UC_X86_REG_CS, 0x08)
        uc.reg_write(UC_X86_REG_DS, 0x10)
        uc.reg_write(UC_X86_REG_ES, 0x10)
        uc.reg_write(UC_X86_REG_SS, 0x10)
        uc.reg_write(UC_X86_REG_FS, 0x18)
        uc.reg_write(UC_X86_REG_GS, 0x00)

    def _new_teb(self, tid, stack_base, stack_limit):
        """Allocate and fill a TEB for a thread"""
        teb = self.heap_alloc(0x1000)
        data = bytearray(0x1000)
        struct.pack_into('<III', data, 0x00, 0xFFFFFFFF, stack_base, stack_limit)
        struct.pack_into('<I', data, 0x18, teb)
        struct.pack_into('<I', data, 0x20, 1234)
        struct.pack_into('<I', data, 0x24, tid)
        struct.pack_into('<I', data, 0x30, self.peb_addr)
        self.uc.mem_write(teb, bytes(data))
        return teb

    def create_thread(self, start, param, stack_size=0, suspended=False):
        """Start a guest thread at start(param); returns its GuestThread or None"""
        tid = self.next_thread_id
        self.next_thread_id += 4
        thread = GuestThread(tid, Uc(UC_ARCH_X86, UC_MODE_32))
        self.sync_regions(thread)
        size = self._align_size(min(max(stack_size, 0x40000), 0x400000), 0x10000)
        stack = self.heap_alloc(size, alignment=0x10000)
        if not stack:
            return None
        thread.stack = stack
        thread.teb = self._new_teb(tid, stack + size, stack)
        uc = thread.uc
        self._setup_segments(uc, thread.teb)
        esp = stack + size - 0x100
        uc.mem_write(esp, struct.pack('<II', self.THREAD_EXIT_ADDR, param))
        uc.reg_write(UC_X86_REG_ESP, esp)
        uc.reg_write(UC_X86_REG_EBP, 0)
        self._add_hooks(uc)
        if self._count_instructions:
            uc.hook_add(UC_HOOK_BLOCK, self._hook_block)
        thread.suspend_count = 1 if suspended else 0
        self.threads[tid] = thread
        log.debug(f"Thread {tid} created: start 0x{start:08x}, param 0x{param:08x}")

        def body():
            self._tls.thread = thread
            with self.sched:
                try:
                    self.wait_until(lambda: thread.suspend_count == 0)
                    self._slice_start = time.monotonic()
                    if not (self.stop_emulation or thread.stop):
                        self.emulate(uc, start, self.THREAD_EXIT_ADDR)
                        if (not thread.exited and
                                uc.reg_read(UC_X86_REG_EIP) == self.THREAD_EXIT_ADDR):
                            thread.exit_code = uc.reg_read(UC_X86_REG_EAX)
                except UcError as e:
                    eip = uc.reg_read(UC_X86_REG_EIP)
                    log.error(f"Emulation error in thread {tid}: {e} (EIP: 0x{eip:08x})")
                    self.crashed = True
                    self.stop_all()
                except Exception as e:
                    log.error(f"Emulator error in thread {tid}: {type(e).__name__}: {e}")
                    self.crashed = True
                    self.stop_all()
                finally:
                    thread.exited = True
                    if thread.exit_code == 259 and thread.stop is False:
                        thread.exit_code = 0
                    self.threads.pop(tid, None)
                    self.heap_free(thread.teb)
                    self.sched.notify_all()
                    log.debug(f"Thread {tid} exited ({thread.exit_code})")

        thread.python_thread = threading.Thread(target=body, daemon=True)
        thread.python_thread.start()
        return thread

    def exit_current_thread(self, code):
        """ExitThread/_endthreadex: end the calling thread (the main thread
        ends the process)"""
        thread = self.current_thread
        if thread is self.main_thread:
            return False
        thread.exit_code = code
        thread.exited = True
        thread.stop = True
        thread.uc.emu_stop()
        return True

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
        if not self._setup_memory():
            return False
        
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
            self.map_shared(aligned_addr, aligned_size, perms)
            self.mapped_regions.append((aligned_addr, aligned_addr + aligned_size))
            log.debug(f"Memory mapped: 0x{aligned_addr:08x} - 0x{aligned_addr + aligned_size:08x}")
        except UcError as e:
            log.warning(f"Memory map error: {e}")
    
    def _reserved_regions(self):
        """Address ranges the emulator itself uses (start, end)"""
        return [(0, 0x10000),
                (self.HEAP_BASE, self.HEAP_BASE + self.HEAP_SIZE),
                (self.CALLBACK_RETURN_ADDR, self.API_HOOK_BASE + self.API_HOOK_SIZE),
                (self.STACK_BASE, self.STACK_BASE + self.STACK_SIZE)]

    def _choose_image_base(self, size):
        """Preferred ImageBase if free, else the first free 64K-aligned address"""
        def is_free(base):
            return (base + size <= 0x80000000 and
                    all(base + size <= start or base >= end
                        for start, end in self._reserved_regions()))

        preferred = self.pe_loader.image_base
        if is_free(preferred):
            return preferred
        for base in range(0x00400000, 0x80000000, 0x10000):
            if is_free(base):
                return base
        return None

    def _setup_memory(self):
        """Load PE file into memory. Returns False on failure."""
        log.header("Memory Configuration")
        
        image_size = self._align_size(self.pe_loader.pe.OPTIONAL_HEADER.SizeOfImage)
        image_base = self._choose_image_base(image_size)
        if image_base is None:
            log.error("No free address range for the image")
            return False
        if image_base != self.pe_loader.image_base:
            if not self.pe_loader.has_relocations():
                log.error(f"ImageBase 0x{self.pe_loader.image_base:08x} overlaps emulator "
                          f"memory and the image has no relocations")
                return False
            log.warning(f"ImageBase 0x{self.pe_loader.image_base:08x} overlaps emulator "
                        f"memory, relocating to 0x{image_base:08x}")
            self.pe_loader.rebase(image_base)
        
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
            self.map_shared(self.HEAP_BASE, self.HEAP_SIZE, UC_PROT_ALL)
            self.mapped_regions.append((self.HEAP_BASE, self.HEAP_BASE + self.HEAP_SIZE))
            log.info(f"Heap allocated: 0x{self.HEAP_BASE:08x} - 0x{self.HEAP_BASE + self.HEAP_SIZE:08x}")
        except UcError as e:
            log.error(f"Heap allocation error: {e}")
            return False
        
        # API hook region
        self._map_memory(self.API_HOOK_BASE, self.API_HOOK_SIZE)
        log.info(f"API Hook region: 0x{self.API_HOOK_BASE:08x}")
        return True
    
    def _setup_stack(self):
        """Configure stack"""
        # Set ESP to middle of stack
        esp = self.STACK_BASE + self.STACK_SIZE - 0x1000
        self.uc.reg_write(UC_X86_REG_ESP, esp)
        self.uc.reg_write(UC_X86_REG_EBP, esp)
        # Returning from the entry point ends the process with EAX as exit code
        self.uc.mem_write(esp, struct.pack('<I', self.PROCESS_EXIT_ADDR))
        
        log.info(f"Stack pointer: ESP = 0x{esp:08x}")
        
        # Allocate memory for command line
        cmdline = self.api_handler.windows_command_line()
        cmdline_bytes = cmdline.encode(config.ANSI_CODEPAGE, errors='replace') + b'\x00'
        self.cmdline_addr = self.heap_alloc(len(cmdline_bytes))
        self.uc.mem_write(self.cmdline_addr, cmdline_bytes)

        cmdline_wide = cmdline.encode('utf-16-le') + b'\x00\x00'
        self.cmdline_wide_addr = self.heap_alloc(len(cmdline_wide))
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
        
        # SEH chain end marker, StackBase, StackLimit
        struct.pack_into('<III', teb_data, 0x00, 0xFFFFFFFF,
                         self.STACK_BASE + self.STACK_SIZE, self.STACK_BASE)
        # TEB self pointer (FS:[0x18])
        struct.pack_into('<I', teb_data, 0x18, self.teb_addr)
        # PEB pointer (FS:[0x30])
        struct.pack_into('<I', teb_data, 0x30, self.peb_addr)
        # ProcessId (FS:[0x20])
        struct.pack_into('<I', teb_data, 0x20, 1234)
        # ThreadId (FS:[0x24])
        struct.pack_into('<I', teb_data, 0x24, self.main_thread.tid)
        
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
        # ProcessHeap: a real (zeroed) block so heap header reads don't fault
        self.process_heap = self.heap_alloc(0x1000)
        struct.pack_into('<I', peb_data, 0x18, self.process_heap)
        # OSMajorVersion, OSMinorVersion, OSBuildNumber, OSPlatformId (matches GetVersion)
        struct.pack_into('<IIHHI', peb_data, 0xA4, 6, 0, 6002, 0, 2)
        
        self.uc.mem_write(self.peb_addr, bytes(peb_data))
        
        self._setup_segments(self.uc, self.teb_addr)
        self.main_thread.teb = self.teb_addr
        
        log.info(f"TEB configured: 0x{self.teb_addr:08x}")
        log.info(f"PEB configured: 0x{self.peb_addr:08x}")
    
    def heap_alloc(self, size, alignment=16):
        """Allocate zeroed heap memory, reusing freed blocks. Returns 0 when exhausted."""
        span = self._align_size(max(size, 1), 16)
        free_bin = self.heap_free_bins.get(span) if alignment <= 16 else None
        if free_bin:
            addr = free_bin.pop()
            del self.heap_free_ends[addr + span]
            self.uc.mem_write(addr, b'\x00' * span)
        else:
            addr = self._align_size(self.heap_current, alignment)
            if addr + span > self.HEAP_BASE + self.HEAP_SIZE:
                log.error(f"Heap exhausted: cannot allocate {size} bytes "
                          f"(increase with -m/--memory)")
                return 0
            if addr != self.heap_current:
                # The alignment gap becomes a free block for later small allocations
                self.heap_free_bins.setdefault(addr - self.heap_current, set()).add(self.heap_current)
                self.heap_free_ends[addr] = self.heap_current
            self.heap_current = addr + span
        self.heap_blocks[addr] = size
        return addr

    def heap_free(self, addr):
        """Release a heap_alloc() block. Returns False if addr is not a live block."""
        size = self.heap_blocks.pop(addr, None)
        if size is None:
            return False
        end = addr + self._align_size(max(size, 1), 16)
        if end != self.heap_current:
            self.heap_free_bins.setdefault(end - addr, set()).add(addr)
            self.heap_free_ends[end] = addr
            return True
        # Top block: shrink the bump area, folding in free blocks below it.
        # Memory above heap_current is kept zeroed.
        top = addr
        while top in self.heap_free_ends:
            start = self.heap_free_ends.pop(top)
            self.heap_free_bins[top - start].discard(start)
            top = start
        self.heap_current = top
        self.uc.mem_write(top, b'\x00' * (end - top))
        return True

    def heap_block_size(self, addr):
        """Requested size of a heap_alloc() block, or None if unknown."""
        return self.heap_blocks.get(addr)

    def heap_resize_last(self, addr, new_size):
        """Grow/shrink the most recent block in place. Returns True on success."""
        old_size = self.heap_blocks.get(addr)
        if old_size is None:
            return False
        if addr + self._align_size(max(old_size, 1), 16) != self.heap_current:
            return False
        new_end = addr + self._align_size(max(new_size, 1), 16)
        if new_end > self.HEAP_BASE + self.HEAP_SIZE:
            return False
        if new_end < self.heap_current:
            self.uc.mem_write(new_end, b'\x00' * (self.heap_current - new_end))
        self.heap_current = new_end
        self.heap_blocks[addr] = new_size
        return True
    
    def _setup_import_hooks(self):
        """Setup hooks for import functions"""
        log.header("Setting Up API Hooks")
        
        # Create hook address for each import
        for dll_name, functions in self.pe_loader.imports.items():
            log.info(f"DLL hook: {dll_name}")
            
            for func_info in functions:
                func_name = func_info['name']
                iat_addr = func_info['address']

                # CRT variables (e.g. _iob) are dereferenced, not called:
                # point the IAT entry at real memory instead of a hook stub.
                data_addr = self.api_handler.resolve_data_import(dll_name, func_name)
                if data_addr:
                    self.uc.mem_write(iat_addr, struct.pack('<I', data_addr))
                    log.debug(f"  Data: {func_name} -> 0x{data_addr:08x}")
                    continue
                
                hook_addr = self._create_api_stub(dll_name, func_name)
                if not hook_addr:
                    break
                
                # Write hook address to IAT
                self.uc.mem_write(iat_addr, struct.pack('<I', hook_addr))
                log.debug(f"  Hook: {func_name} -> 0x{hook_addr:08x}")

    def _create_api_stub(self, dll_name, func_name):
        """Write a RET stub that _hook_code intercepts; returns its address (0 if full)

        Some CRT helpers take their arguments in x87 registers; their stub
        starts with native code that spills them to memory before the RET.
        """
        native = getattr(self, 'native_routines', {}).get(func_name)
        if native and dll_name.lower() in self.NATIVE_ROUTINE_DLLS:
            return native
        prologue = self.api_handler.native_prologue(func_name)
        entry = self.next_hook_addr
        hook_addr = entry + len(prologue)
        if hook_addr >= self.API_HOOK_BASE + self.API_HOOK_SIZE:
            log.error(f"API stub region full, cannot hook {func_name}")
            return 0
        self.next_hook_addr = (hook_addr + 4) & ~3
        self.uc.mem_write(entry, prologue + b'\xC3')  # RET
        self.api_hooks[hook_addr] = {'dll': dll_name, 'name': func_name}
        return entry

    # ---------- Real DLLs ----------

    def _free_image_base(self, preferred, size):
        """preferred if [preferred, +size) is free, else the lowest free 64K-aligned base"""
        used = sorted([(b, b + r[0]) for b, r in self.shared_regions.items()] +
                      self._reserved_regions())

        def is_free(base):
            end = base + size
            return end <= 0x80000000 and all(end <= start or base >= stop
                                             for start, stop in used)
        if preferred and is_free(preferred):
            return preferred
        candidate = 0x00400000
        for start, stop in used:
            if candidate + size <= start:
                break
            if stop > candidate:
                candidate = (stop + 0xFFFF) & ~0xFFFF
        return candidate if candidate + size <= 0x80000000 and is_free(candidate) else None

    def find_dll(self, name):
        """Loaded real DLL by base address or file name, or None"""
        if isinstance(name, int):
            return self.dlls.get(name)
        key = name.replace('/', '\\').rsplit('\\', 1)[-1].lower()
        for module in self.dlls.values():
            if module['name'] == key:
                return module
        return None

    def load_dll(self, host_path, windows_path, call_entry=True):
        """Load a real 32-bit DLL from the c_drive/ sandbox: map and relocate
        it, bind its imports to the emulated APIs (or other real DLLs) and
        run DllMain(DLL_PROCESS_ATTACH). Returns its base (HMODULE) or 0."""
        for module in self.dlls.values():
            if module['host_path'] == host_path:
                return module['base']
        try:
            pe = pefile.PE(host_path)
        except (OSError, pefile.PEFormatError) as e:
            log.error(f"Cannot load DLL {windows_path}: {e}")
            return 0
        if pe.FILE_HEADER.Machine != 0x14c or not pe.FILE_HEADER.Characteristics & 0x2000:
            log.error(f"Not a 32-bit DLL: {windows_path}")
            return 0
        size = self._align_size(pe.OPTIONAL_HEADER.SizeOfImage)
        original_base = pe.OPTIONAL_HEADER.ImageBase
        base = self._free_image_base(original_base, size)
        if base is None:
            log.error(f"No free address range for {windows_path}")
            return 0
        if base != original_base:
            if not hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'):
                log.error(f"{windows_path}: preferred base 0x{original_base:08x} is used "
                          f"and the DLL has no relocations")
                return 0
            pe.relocate_image(base)
        self.map_shared(base, size)
        self.mapped_regions.append((base, base + size))
        self.uc.mem_write(base, pe.get_memory_mapped_image()[:size])
        name = ntpath.basename(windows_path).lower()
        module = {'name': name, 'path': windows_path, 'host_path': host_path,
                  'base': base, 'size': size, 'exports': {}, 'ordinals': {}, 'pe': pe}
        self.dlls[base] = module
        log.info(f"DLL loaded: {windows_path} at 0x{base:08x}")

        # Exports (forwarders become stubs of the target API)
        export_dir = getattr(pe, 'DIRECTORY_ENTRY_EXPORT', None)
        for exp in (export_dir.symbols if export_dir else []):
            if exp.forwarder:
                target_dll, _, target = exp.forwarder.decode('ascii', 'replace').partition('.')
                addr = self.get_api_stub(target_dll + '.dll', target)
            else:
                addr = base + exp.address
            if exp.name:
                module['exports'][exp.name.decode('ascii', 'replace')] = addr
            module['ordinals'][exp.ordinal] = addr

        # Imports
        for entry in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []):
            dll_name = entry.dll.decode('ascii', 'replace')
            real = self.api_handler.load_real_dll(dll_name)
            for imp in entry.imports:
                # (relocate_image already moved the import addresses to the new base)
                iat = base + imp.address - pe.OPTIONAL_HEADER.ImageBase
                if imp.name:
                    func_name = imp.name.decode('ascii', 'replace')
                else:
                    func_name = PELoader.ordinal_name(dll_name, imp.ordinal)
                if real:
                    target = (real['exports'].get(func_name) if imp.name
                              else real['ordinals'].get(imp.ordinal))
                    addr = target or 0
                    if not addr:
                        log.warning(f"{name}: import {dll_name}!{func_name} not found")
                else:
                    addr = self.api_handler.resolve_data_import(dll_name, func_name)
                    if not addr:
                        addr = self._create_api_stub(dll_name, func_name)
                self.uc.mem_write(iat, struct.pack('<I', addr))

        entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        if call_entry and entry_point:
            result = self.call_callback(base + entry_point, [base, 1, 0])  # DLL_PROCESS_ATTACH
            if not result or self.crashed:
                log.error(f"DllMain of {windows_path} failed")
                del self.dlls[base]
                return 0
        return base

    def get_api_stub(self, dll_name, func_name):
        """Stub address for GetProcAddress, or 0 if the API is not emulated"""
        if not self.api_handler.is_emulated(dll_name, func_name):
            return 0
        key = (dll_name.lower(), func_name)
        if key not in self.dynamic_stubs:
            self.dynamic_stubs[key] = self._create_api_stub(dll_name, func_name)
        return self.dynamic_stubs[key]
    
    def _setup_callback_return_hook(self):
        """Setup callback return hook region"""
        # Allocate special memory region for callback return address
        # When execution reaches this address, we know callback has finished
        try:
            self.map_shared(self.callback_return_addr, 0x1000, UC_PROT_ALL)
            # Write RET instruction (0xC3) - will be hooked
            self.uc.mem_write(self.callback_return_addr, b'\xC3')
            # fld qword ptr [X87_RESULT_ADDR]; ret
            self.uc.mem_write(self.X87_RETURN_STUB,
                              b'\xDD\x05' + struct.pack('<I', self.X87_RESULT_ADDR) + b'\xC3')
            log.debug(f"Callback return hook: 0x{self.callback_return_addr:08x}")
            self.map_shared(self.NATIVE_CODE_ADDR, 0x1000, UC_PROT_READ | UC_PROT_EXEC)
            self.native_routines = {}
            placed = {}  # Code -> address (memcpy shares memmove's)
            address = self.NATIVE_CODE_ADDR
            for name, code in self.NATIVE_ROUTINES.items():
                if code not in placed:
                    self.uc.mem_write(address, code)
                    placed[code] = address
                    address = (address + len(code) + 15) & ~15
                self.native_routines[name] = placed[code]
        except UcError as e:
            log.warning(f"Could not setup callback return hook: {e}")
    
    @property
    def pending_unwind(self):
        return getattr(self.current_thread, 'pending_unwind', None)

    @pending_unwind.setter
    def pending_unwind(self, value):
        self.current_thread.pending_unwind = value

    def jump_belongs_here(self, jump):
        """Does a resume target (its stack pointer) belong to the innermost
        emulation level (not to a frame outside the running callback)?"""
        stack = self.callback_stack
        return not stack or jump.esp < stack[-1]['saved_state']['esp']

    JUMP_REGISTERS = {'ebx': UC_X86_REG_EBX, 'ecx': UC_X86_REG_ECX, 'edx': UC_X86_REG_EDX,
                      'esi': UC_X86_REG_ESI, 'edi': UC_X86_REG_EDI,
                      'eflags': UC_X86_REG_EFLAGS}

    def apply_jump(self, uc, jump):
        """Set the registers of an ApiJump (continue at jump.eip)"""
        uc.reg_write(UC_X86_REG_EAX, jump.eax & 0xFFFFFFFF)
        uc.reg_write(UC_X86_REG_ESP, jump.esp)
        uc.reg_write(UC_X86_REG_EIP, jump.eip)
        if jump.ebp is not None:
            uc.reg_write(UC_X86_REG_EBP, jump.ebp)
        for name, value in (jump.regs or {}).items():
            uc.reg_write(self.JUMP_REGISTERS[name], value & 0xFFFFFFFF)

    def call_callback(self, callback_addr, args, return_handler=None, regs=None):
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
        # Register arguments (thiscall ECX, the frame of an exception funclet in EBP)
        for name, value in (regs or {}).items():
            self.uc.reg_write({'ecx': UC_X86_REG_ECX, 'ebp': UC_X86_REG_EBP,
                               'eax': UC_X86_REG_EAX}[name], value & 0xFFFFFFFF)
        
        log.debug(f"Calling callback: 0x{callback_addr:08x} args={[hex(a) for a in args]}")
        
        # Run callback. Unicorn's instruction budget is shared with the outer
        # emu_start (nested runs clobber it), so pass 0 (unlimited) here and
        # let the Python-side max_instructions check in _hook_code limit
        # everything uniformly.
        try:
            self.emulate(self.uc, callback_addr, self.callback_return_addr)
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

        # An exception thrown in the callback is caught further out
        unwind = self.pending_unwind
        if unwind is not None and not self.stop_emulation:
            self.pending_unwind = None
            raise GuestUnwind(unwind)
        
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
        self._add_hooks(self.uc)

    def _add_hooks(self, uc):
        """Register the Unicorn hooks of one thread's instance"""
        # Per-instruction hooks only on API stubs and the callback return
        # address; hooking every instruction makes emulation very slow.
        uc.hook_add(UC_HOOK_CODE, self._hook_code,
                    begin=self.API_HOOK_BASE,
                    end=self.API_HOOK_BASE + self.API_HOOK_SIZE - 1)
        uc.hook_add(UC_HOOK_CODE, self._hook_code,
                    begin=self.callback_return_addr,
                    end=self.callback_return_addr)
        # Reached inside a callback only if the code left it without returning
        # (an exception handler that continued in the program): see _hook_code
        for address in (self.PROCESS_EXIT_ADDR, self.THREAD_EXIT_ADDR):
            uc.hook_add(UC_HOOK_CODE, self._hook_code, begin=address, end=address)

        # Memory access error hook
        uc.hook_add(UC_HOOK_MEM_UNMAPPED, self._hook_mem_invalid)
        
        # Interrupt hook
        uc.hook_add(UC_HOOK_INTR, self._hook_interrupt)

    def _hook_block(self, uc, address, size, user_data):
        """Hook called at the start of each basic block"""
        key = (address, size)
        count = self.block_insn_counts.get(key)
        if count is None or self.instruction_count < 50:
            insns = list(self.cs.disasm_lite(bytes(uc.mem_read(address, size)), address))
            count = max(len(insns), 1)
            self.block_insn_counts[key] = count
            for insn_addr, _, mnemonic, op_str in insns[:max(0, 50 - self.instruction_count)]:
                log.debug(f"0x{insn_addr:08x}: {mnemonic:8s} {op_str}")
        self.instruction_count += count

        # Limit check (max_instructions <= 0 means unlimited)
        if self.max_instructions > 0 and self.instruction_count > self.max_instructions:
            log.warning(f"Maximum instruction limit reached ({self.max_instructions})! Stopping emulation...")
            self.stop_emulation = True

        if self.stop_emulation:
            uc.emu_stop()
    
    def _hook_code(self, uc, address, size, user_data):
        """Hook for API stubs and the callback return address"""
        if (self.stop_emulation or self.current_thread.stop or
                address == self.callback_return_addr):
            uc.emu_stop()
            return
        if address in (self.PROCESS_EXIT_ADDR, self.THREAD_EXIT_ADDR):
            if self.callback_stack:
                # The program returned from its entry point (or thread start
                # routine) inside a callback it never returned from: continue
                # at that return address on the level that waits for it
                self.pending_unwind = ApiJump(address, uc.reg_read(UC_X86_REG_ESP),
                                              uc.reg_read(UC_X86_REG_EAX),
                                              ebp=uc.reg_read(UC_X86_REG_EBP))
            uc.emu_stop()
            return

        hook_info = self.api_hooks.get(address)
        if hook_info:
            self.maybe_yield()
            self.sync_regions()
            self._handle_api_call(hook_info)
            if self.stop_emulation or self.current_thread.stop:
                uc.emu_stop()
    
    def _handle_api_call(self, hook_info):
        """Handle API call"""
        dll_name = hook_info['dll'].lower()
        func_name = hook_info['name']
        
        log.debug(f"API Call: {dll_name}!{func_name}")
        
        # Read arguments from stack
        esp = self.uc.reg_read(UC_X86_REG_ESP)
        
        # Return address
        ret_addr = struct.unpack('<I', self.uc.mem_read(esp, 4))[0]
        
        # Up to 32 argument slots (varargs functions such as printf may use
        # many); slots beyond the top of the stack read as zero.
        try:
            args = list(struct.unpack('<32I', self.uc.mem_read(esp + 4, 128)))
        except UcError:
            args = []
            for i in range(32):
                try:
                    args.append(struct.unpack('<I', self.uc.mem_read(esp + 4 + i * 4, 4))[0])
                except UcError:
                    args.append(0)
        
        # Find and call handler
        handler = self.api_handler.get_api_handler(func_name, dll_name)
        self.api_call_esp = esp
        
        if handler:
            try:
                result = handler(args)
            except GuestUnwind as unwind:
                # The catching frame is at this level or further out
                result = unwind.jump
                if not self.jump_belongs_here(result):
                    self.pending_unwind = result
                    self.uc.emu_stop()
                    return
            except Exception as e:
                log.error(f"Emulator error in {dll_name}!{func_name}: "
                          f"{type(e).__name__}: {e}")
                if DebugLogger.level <= DebugLogger.DEBUG:
                    import traceback
                    traceback.print_exc()
                result = 0
        else:
            log.warning(f"Unemulated API: {func_name}")
            result = 0

        if isinstance(result, ApiJump):
            if not self.jump_belongs_here(result):
                self.pending_unwind = result
                self.uc.emu_stop()
                return
            self.apply_jump(self.uc, result)
            return

        x87_result = isinstance(result, X87Result)
        if x87_result:
            self.uc.mem_write(self.X87_RESULT_ADDR, struct.pack('<d', result.value))
            result = 0
        elif isinstance(result, QWordResult):
            self.uc.reg_write(UC_X86_REG_EDX, result.value >> 32)
            result = result.value
        
        # Write result to EAX
        self.uc.reg_write(UC_X86_REG_EAX, result & 0xFFFFFFFF)
        
        # Return to caller. stdcall APIs (kernel32, user32, gdi32, ...) pop
        # their own arguments; cdecl CRT functions leave them to the caller.
        cleanup = self.api_handler.stack_cleanup_bytes(dll_name, func_name)
        if cleanup is None:
            # Unknown stdcall argument count: continuing would corrupt ESP
            log.error(f"Unemulated stdcall API {dll_name}!{func_name}: "
                      f"argument count unknown, stopping emulation")
            self.crashed = True
            self.stop_emulation = True
            cleanup = 0
        if x87_result and cleanup == 0:
            # Leave the return address on the stack: the stub loads ST(0) and RETs
            self.uc.reg_write(UC_X86_REG_EIP, self.X87_RETURN_STUB)
            self.uc.reg_write(UC_X86_REG_ESP, esp)
            return
        self.uc.reg_write(UC_X86_REG_EIP, ret_addr)
        self.uc.reg_write(UC_X86_REG_ESP, esp + 4 + cleanup)
    
    def _hook_mem_invalid(self, uc, access, address, size, value, user_data):
        """Invalid memory access hook"""
        access_types = {
            UC_MEM_READ_UNMAPPED: "READ",
            UC_MEM_WRITE_UNMAPPED: "WRITE", 
            UC_MEM_FETCH_UNMAPPED: "FETCH",
        }
        access_type = access_types.get(access, f"Unknown({access})")
        eip = uc.reg_read(UC_X86_REG_EIP)
        # Memory another thread mapped meanwhile: map it here too and retry
        if self.sync_regions() and any(
                base <= address < base + region[0]
                for base, region in self.current_thread.mapped.items()):
            return True

        # Like Windows, an access to unmapped memory is an access violation
        # for the program's exception handlers: emulate() dispatches it when
        # Unicorn stops. Mapping memory on demand would silently turn
        # NULL-pointer bugs into reads of zeros.
        log.debug(f"Access violation: {access_type} @ 0x{address:08x}, "
                  f"size={size}, EIP=0x{eip:08x}")
        kind = {UC_MEM_WRITE_UNMAPPED: 1, UC_MEM_FETCH_UNMAPPED: 8}.get(access, 0)
        fault_address = address if access == UC_MEM_FETCH_UNMAPPED else eip
        self.current_thread.pending_fault = (
            self.STATUS_ACCESS_VIOLATION, [kind, address & 0xFFFFFFFF], fault_address,
            f"access violation: {access_type.lower()} of 0x{address:08x}")
        return False

    def emulate(self, uc, start, until):
        """uc.emu_start(start, until), continuing in the program's exception
        handler after an access violation or an illegal instruction, like on
        Windows; an unhandled one ends the process. Other errors are raised."""
        address = start
        while True:
            try:
                uc.emu_start(address, until, 0, 0)
                return
            except UcError as e:
                thread = self.current_thread
                fault, thread.pending_fault = thread.pending_fault, None
                if fault is None and e.errno == UC_ERR_INSN_INVALID:
                    eip = uc.reg_read(UC_X86_REG_EIP)
                    fault = (0xC000001D, [], eip, "illegal instruction")
                if fault is None or self.stop_emulation or thread.stop:
                    raise
            code, params, fault_address, description = fault
            jump = None
            try:
                jump = self.api_handler.dispatch_exception(
                    code, 0, params, fault_address,
                    self.api_handler.capture_context(eip=fault_address))
            except GuestUnwind as unwind:  # a filter or funclet threw
                jump = unwind.jump
            if self.stop_emulation or self.current_thread.stop:
                return
            if jump is None:
                log.error(f"Unhandled exception 0x{code:08x} ({description}) at "
                          f"0x{fault_address:08x}: process terminated")
                self._terminate_on_exception(uc, code)
                return
            log.debug(f"Exception 0x{code:08x} ({description}) at 0x{fault_address:08x} "
                      f"is handled at 0x{jump.eip:08x}")
            if not self.jump_belongs_here(jump):
                self.pending_unwind = jump  # the handler is outside the running callback
                return
            self.apply_jump(uc, jump)
            address = jump.eip
    
    # CPU exceptions -> (Windows exception code, description, faulting
    # instruction length: 0 when EIP already points at it)
    CPU_EXCEPTIONS = {
        0x00: (0xC0000094, "integer division by zero", 0),  # #DE
        0x01: (0x80000004, "single step", 0),  # #DB (trap flag)
        0x03: (0x80000003, "breakpoint (INT 3)", 1),  # #BP
        0x04: (0xC0000095, "integer overflow (INTO)", 1),  # #OF
        0x05: (0xC000008C, "array bounds exceeded (BOUND)", 0),  # #BR
        0x06: (0xC000001D, "illegal instruction", 0),  # #UD
        0x0D: (0xC0000005, "general protection fault", 0),  # #GP
        0x2D: (0x80000003, "breakpoint (INT 0x2D debug service)", 2),
    }
    STATUS_ACCESS_VIOLATION = 0xC0000005
    STATUS_STACK_BUFFER_OVERRUN = 0xC0000409  # __fastfail
    CONTRIBUTORY_EXCEPTIONS = (0x00, 0x08, 0x0A, 0x0B, 0x0C, 0x0D)

    # QEMU remembers a contributory CPU exception (#DE, #GP, ...) until it is
    # delivered (env->old_exception). Unicorn hands it to the hook instead,
    # so the field is never reset and the next such exception would become a
    # double fault (#DF), then a triple fault. Its offset in a Unicorn
    # context is found once with a test division by zero (None: not found).
    _exception_state_offset = False

    @staticmethod
    def _find_exception_state_offset():
        code = b'\x31\xc9\xf7\xf1\x90'  # xor ecx, ecx; div ecx; nop

        def attempt(offset):
            """Two divisions by zero; returns (interrupt numbers, candidate offsets)"""
            uc = Uc(UC_ARCH_X86, UC_MODE_32)
            uc.mem_map(0x1000, 0x1000)
            uc.mem_write(0x1000, code)
            before = bytes(uc.context_save())
            seen, candidates = [], []

            def hook(uc, intno, user_data):
                seen.append(intno)
                if len(seen) == 1:
                    if offset is None:
                        after = bytes(uc.context_save())
                        candidates.extend(
                            o for o in range(0, min(len(before), len(after)) - 3, 4)
                            if before[o:o + 4] == b'\xff' * 4 and after[o:o + 4] == b'\0' * 4)
                    else:
                        CPUEmulator._patch_exception_state(uc, offset)
                uc.reg_write(UC_X86_REG_EIP, 0x1000 if len(seen) < 2 else 0x1004)
            uc.hook_add(UC_HOOK_INTR, hook)
            uc.emu_start(0x1000, 0x1005, count=20)
            return seen, candidates

        try:
            _, candidates = attempt(None)
            for offset in candidates:
                if attempt(offset)[0] == [0, 0]:
                    return offset
        except (UcError, ctypes.ArgumentError, TypeError) as e:
            log.debug(f"CPU exception state calibration failed: {e}")
        log.warning("CPU exception state not found: a second division by zero may be "
                    "reported as a double fault")
        return None

    @staticmethod
    def _patch_exception_state(uc, offset):
        context = uc.context_save()
        address = ctypes.cast(context.context, ctypes.c_void_p).value
        ctypes.memmove(address + offset, b'\xff' * 4, 4)  # -1: no exception in flight
        uc.context_restore(context)

    def _clear_exception_state(self, uc):
        """Forget the contributory exception just handled (see above)"""
        if CPUEmulator._exception_state_offset is False:
            CPUEmulator._exception_state_offset = self._find_exception_state_offset()
        if CPUEmulator._exception_state_offset is not None:
            self._patch_exception_state(uc, CPUEmulator._exception_state_offset)

    def _hook_interrupt(self, uc, intno, user_data):
        """Interrupt hook: CPU exceptions and software interrupts become Windows
        exceptions for the program's SEH handlers, like on Windows; __fastfail
        (INT 0x29) ends the process at once"""
        eip = uc.reg_read(UC_X86_REG_EIP)
        log.debug(f"Interrupt: 0x{intno:x} at EIP=0x{eip:08x}")
        if intno in self.CONTRIBUTORY_EXCEPTIONS:
            self._clear_exception_state(uc)
        if intno == 0x08:
            # Double fault: an exception after one that was not cleared (only
            # if the calibration failed); the instruction tells which it was
            insn = None
            if self.cs is not None:
                try:
                    insn = next(self.cs.disasm_lite(bytes(uc.mem_read(eip, 16)), eip), None)
                except UcError:
                    pass
            intno = 0x00 if insn and insn[2] in ('div', 'idiv') else 0x0D

        if intno == 0x29:
            # __fastfail(code): no exception handler runs
            code = uc.reg_read(UC_X86_REG_ECX)
            log.error(f"__fastfail({code}) at 0x{eip - 2:08x}: process terminated "
                      f"(STATUS_STACK_BUFFER_OVERRUN)")
            self._terminate_on_exception(uc, self.STATUS_STACK_BUFFER_OVERRUN)
            return

        params = []
        if intno in self.CPU_EXCEPTIONS:
            code, description, length = self.CPU_EXCEPTIONS[intno]
            address = (eip - length) & 0xFFFFFFFF
            if code == 0x80000003:
                params = [0]  # BREAKPOINT_BREAK
        else:
            # A software interrupt user code may not use (INT 0x2E system calls,
            # INT 0x80, DOS INT 0x21, ...): a general protection fault, which
            # Windows reports as an access violation reading 0xFFFFFFFF
            code, address = self.STATUS_ACCESS_VIOLATION, (eip - 2) & 0xFFFFFFFF
            description = f"INT 0x{intno:02X} (privileged software interrupt)"
            if intno == 0x2E:
                description += f", system call EAX=0x{uc.reg_read(UC_X86_REG_EAX):08x}"
            params = [0, 0xFFFFFFFF]
        self._raise_cpu_exception(uc, code, address, params, description)

    def _terminate_on_exception(self, uc, code):
        """End the process like an unhandled exception does (exit code = code)"""
        if self.api_handler is not None:
            self.api_handler._set_exit_code(code)
        self.crashed = True
        self.stop_emulation = True
        uc.emu_stop()

    def _raise_cpu_exception(self, uc, code, address, params, description):
        """Dispatch an exception raised by an instruction to the SEH frames;
        continue in the handler that takes it, or end the process"""
        jump = None
        try:
            jump = self.api_handler.dispatch_exception(code, 0, params, address)
        except GuestUnwind as unwind:  # a funclet threw a C++ exception
            jump = unwind.jump
        if self.stop_emulation:
            uc.emu_stop()
            return
        if jump is None:
            log.error(f"Unhandled exception 0x{code:08x} ({description}) at "
                      f"0x{address:08x}: process terminated")
            self._terminate_on_exception(uc, code)
            return
        log.debug(f"Exception 0x{code:08x} ({description}) at 0x{address:08x} is "
                  f"handled at 0x{jump.eip:08x}")
        if not self.jump_belongs_here(jump):
            # The handler is in a frame outside the running callback
            self.pending_unwind = jump
            uc.emu_stop()
            return
        self.apply_jump(uc, jump)

    def run(self, max_instructions=None):
        """Start emulation"""
        if max_instructions is not None:
            self.max_instructions = max_instructions

        # Instruction counting costs a Python call per basic block: only for the
        # instruction limit and the verbose start-up disassembly
        count_instructions = (self.max_instructions > 0 or
                              DebugLogger.level <= DebugLogger.DEBUG)
        self._count_instructions = count_instructions
        if count_instructions:
            self.uc.hook_add(UC_HOOK_BLOCK, self._hook_block)

        log.header("Starting Emulation")

        entry_point = self.pe_loader.image_base + self.pe_loader.entry_point
        log.info(f"Entry point: 0x{entry_point:08x}")
        log.info(f"Maximum instructions: "
                 f"{self.max_instructions if self.max_instructions > 0 else 'unlimited'}")

        # Let the GUI route window messages to this process
        if self.gui:
            self.gui.register_process(self.api_handler)
        # Like Windows, only console (CUI) programs start with a console
        if self.pe_loader.is_console_program():
            self.api_handler.alloc_console()

        self.sched.acquire()
        self._tls.thread = self.main_thread
        self._slice_start = time.monotonic()
        try:
            # The instruction limit is enforced in _hook_code. Passing a count
            # to Unicorn would break nested emu_start calls (callbacks,
            # _initterm, atexit) and can crash the process.
            self.emulate(self.uc, entry_point, self.PROCESS_EXIT_ADDR)

            if (not self.crashed and
                    self.uc.reg_read(UC_X86_REG_EIP) == self.PROCESS_EXIT_ADDR):
                self.api_handler._set_exit_code(self.uc.reg_read(UC_X86_REG_EAX))

        except UcError as e:
            eip = self.uc.reg_read(UC_X86_REG_EIP)
            esp = self.uc.reg_read(UC_X86_REG_ESP)
            log.error(f"Emulation error: {e}")
            log.error(f"EIP: 0x{eip:08x}, ESP: 0x{esp:08x}")
            self.crashed = True
        finally:
            # The process ends with its main thread: stop the other threads
            self.stop_all()
            self.sched.release()
            # However the emulation ended (ExitProcess, error, instruction
            # limit), the process is gone and can't consume messages anymore
            if self.api_handler:
                self.api_handler.process_exited = True
                self.api_handler.flush_std_streams()
                if self.gui:
                    self.gui.unregister_process(self.api_handler)

        log.header("Emulation Completed")
        if count_instructions:
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
