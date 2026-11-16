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

"""WinAPIHandler mixin: Exception handling (MSVC x86 SEH, C++ exceptions), atexit, security cookie"""

import re
import struct

from unicorn import *
from unicorn.x86_const import *

from ..guest import ApiJump
from ..logger import log


class ExceptionsMixin:
    """Exception handling (MSVC x86 SEH, C++ exceptions), atexit, security cookie"""

    # ---------- Exception handling (MSVC x86: SEH chain at FS:[0]) ----------
    #
    # Exceptions are dispatched in Python like ntdll does: the vectored
    # handlers, then the SEH registration nodes from FS:[0], then the
    # top-level filter (SetUnhandledExceptionFilter). The frames of the
    # Microsoft compilers are interpreted here (their catch/__except/
    # __finally/unwind funclets run in the guest): C++ frames (a "mov eax,
    # FuncInfo; jmp __CxxFrameHandler" thunk), _except_handler3 (msvcrt or
    # the static VC6-2003 CRT) and _except_handler4 (Visual C++ 2005+, the
    # scope table is encoded with the __security_cookie). Other handlers
    # (other compilers, hand-written ones) are called in the guest.

    CXX_EXCEPTION = 0xE06D7363
    CXX_FRAME_HANDLERS = ('__CxxFrameHandler', '__CxxFrameHandler2', '__CxxFrameHandler3')
    CXX_FUNCINFO_MAGICS = (0x19930520, 0x19930521, 0x19930522)
    SEH3_HANDLERS = ('_except_handler3', '__except_handler3')
    # Start of _except_handler3 of the static VC6-2003 CRT (exsup3.asm)
    SEH3_STATIC_CODE = bytes.fromhex('558bec83ec0853565755fc8b5d0c8b4508f7400406000000')
    # _except_handler4 of the Visual C++ runtime: push the 4 arguments,
    # push __security_check_cookie, push __security_cookie (group 1), call
    # _except_handler4_common (a static or an imported one)
    # ("mov ebp, esp" has two encodings)
    SEH4_STUB_CODE = re.compile(rb'\x55(?:\x8B\xEC|\x89\xE5)\xFF\x75\x14\xFF\x75\x10\xFF\x75\x0C'
                                rb'\xFF\x75\x08\x68.{4}\x68(.{4})(?:\xE8|\xFF\x15)', re.DOTALL)
    SEH4_TOPMOST = -2
    EXCEPTION_NONCONTINUABLE = 0x1
    EXCEPTION_UNWINDING = 0x2
    EXCEPTION_EXIT_UNWIND = 0x4
    STATUS_UNWIND = 0xC0000027
    MAX_NESTED_EXCEPTIONS = 8

    # CONTEXT (x86): register -> offset (ContextFlags at 0, FloatSave at 0x1C)
    CONTEXT_SIZE = 0x2CC
    CONTEXT_OFFSETS = (('gs', 0x8C), ('fs', 0x90), ('es', 0x94), ('ds', 0x98),
                       ('edi', 0x9C), ('esi', 0xA0), ('ebx', 0xA4), ('edx', 0xA8),
                       ('ecx', 0xAC), ('eax', 0xB0), ('ebp', 0xB4), ('eip', 0xB8),
                       ('cs', 0xBC), ('eflags', 0xC0), ('esp', 0xC4), ('ss', 0xC8))
    CONTEXT_REGISTERS = {
        'gs': UC_X86_REG_GS, 'fs': UC_X86_REG_FS, 'es': UC_X86_REG_ES, 'ds': UC_X86_REG_DS,
        'edi': UC_X86_REG_EDI, 'esi': UC_X86_REG_ESI, 'ebx': UC_X86_REG_EBX,
        'edx': UC_X86_REG_EDX, 'ecx': UC_X86_REG_ECX, 'eax': UC_X86_REG_EAX,
        'ebp': UC_X86_REG_EBP, 'eip': UC_X86_REG_EIP, 'cs': UC_X86_REG_CS,
        'eflags': UC_X86_REG_EFLAGS, 'esp': UC_X86_REG_ESP, 'ss': UC_X86_REG_SS}

    @staticmethod
    def _signed(value):
        value &= 0xFFFFFFFF
        return value - 0x100000000 if value & 0x80000000 else value

    def capture_context(self, eip=None, esp=None):
        """The calling thread's registers ({'eax': ...}), EIP/ESP replaced"""
        uc = self.emu.uc
        regs = {name: uc.reg_read(reg) for name, reg in self.CONTEXT_REGISTERS.items()}
        if eip is not None:
            regs['eip'] = eip
        if esp is not None:
            regs['esp'] = esp
        return regs

    def _write_context(self, address, regs):
        """Fill a CONTEXT (CONTEXT_FULL: control, integer and segment registers)"""
        data = bytearray(self.CONTEXT_SIZE)
        struct.pack_into('<I', data, 0, 0x10007)
        for name, offset in self.CONTEXT_OFFSETS:
            struct.pack_into('<I', data, offset, regs.get(name, 0) & 0xFFFFFFFF)
        return self._mem_write(address, data)

    def _context_jump(self, address):
        """ApiJump that resumes with the registers of a CONTEXT
        (EXCEPTION_CONTINUE_EXECUTION / ExceptionContinueExecution)"""
        data = bytes(self.emu.uc.mem_read(address, 0xCC))

        def reg(name):
            return struct.unpack_from('<I', data, dict(self.CONTEXT_OFFSETS)[name])[0]
        return ApiJump(reg('eip'), reg('esp'), reg('eax'), ebp=reg('ebp'),
                       regs={name: reg(name) for name in ('ebx', 'ecx', 'edx', 'esi', 'edi',
                                                          'eflags')})

    def _read_i32(self, address):
        return struct.unpack('<i', self.emu.uc.mem_read(address, 4))[0]

    def _seh_head_addr(self):
        """Address of FS:[0] (the SEH chain head) of the calling thread"""
        thread = self.emu.current_thread
        return thread.teb if thread.teb else self.emu.teb_addr

    def _api_name_at(self, address):
        """Emulated API whose stub is at address (following "jmp [IAT]"), or None"""
        for _ in range(3):
            info = self.emu.api_hooks.get(address)
            if info is not None:
                return info['name']
            code = bytes(self.emu.uc.mem_read(address, 6))
            if code[:2] == b'\xFF\x25':  # jmp dword ptr [imm32]
                address = self._read_u32(struct.unpack_from('<I', code, 2)[0])
            elif code[:1] == b'\xE9':  # jmp rel32
                address = (address + 5 + struct.unpack_from('<i', code, 1)[0]) & 0xFFFFFFFF
            else:
                return None
        return None

    def _security_cookie_address(self, address):
        """Address of the __security_cookie of the EXE/DLL holding address (from
        its load configuration), or 0"""
        base = self._module_at(address)
        if not base:
            return 0
        if base == self.emu.pe_loader.image_base:
            pe = self.emu.pe_loader.pe
        else:
            pe = self.emu.dlls[base]['pe']
        config = getattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG', None)
        cookie = getattr(getattr(config, 'struct', None), 'SecurityCookie', 0) or 0
        # (the VA is for the preferred base; relocated images moved it)
        return (cookie - pe.OPTIONAL_HEADER.ImageBase + base) & 0xFFFFFFFF if cookie else 0

    def _classify_seh_handler(self, handler):
        """('cxx', FuncInfo) / ('seh3', None) / ('seh4', cookie) / ('other', None)"""
        try:
            code = bytes(self.emu.uc.mem_read(handler, 64))
        except UcError:
            return 'other', None
        try:
            if code[0] == 0xB8 and code[5] == 0xE9:  # mov eax, FuncInfo; jmp handler
                func_info = struct.unpack_from('<I', code, 1)[0]
                target = (handler + 10 + struct.unpack_from('<i', code, 6)[0]) & 0xFFFFFFFF
                if (self._api_name_at(target) in self.CXX_FRAME_HANDLERS or
                        self._read_u32(func_info) in self.CXX_FUNCINFO_MAGICS):
                    return 'cxx', func_info  # an imported or a static frame handler
            if (self._api_name_at(handler) in self.SEH3_HANDLERS or
                    code.startswith(self.SEH3_STATIC_CODE)):
                return 'seh3', None
            # _except_handler4: "push offset __security_cookie" then a call of
            # _except_handler4_common (imported or static); the cookie is
            # known from the load configuration or the stub's code
            cookie = self._security_cookie_address(handler)
            if cookie and b'\x68' + struct.pack('<I', cookie) in code[:48]:
                return 'seh4', cookie
            match = self.SEH4_STUB_CODE.match(code)
            if match:
                return 'seh4', struct.unpack('<I', match.group(1))[0]
        except UcError:
            pass
        return 'other', None

    def _cxx_func_info(self, address):
        magic, max_state, p_unwind, n_try, p_try = struct.unpack(
            '<5I', self.emu.uc.mem_read(address, 20))
        return {'max_state': max_state, 'unwind': p_unwind, 'n_try': n_try, 'try': p_try}

    def _call_funclet(self, address, frame_ebp, regs=None):
        """Run an exception funclet (catch/unwind/filter/__finally) on its frame"""
        all_regs = {'ebp': frame_ebp}
        all_regs.update(regs or {})
        return self.emu.call_callback(address, [], regs=all_regs)

    def _cxx_unwind_to(self, node, info, target_state):
        """Run a C++ frame's unwind actions (destructors) down to target_state"""
        state = self._read_i32(node + 8)
        guard = 0
        while state != target_state and 0 <= state < info['max_state'] and guard < 10000:
            to_state, action = struct.unpack('<iI', self.emu.uc.mem_read(
                info['unwind'] + 8 * state, 8))
            self._mem_write(node + 8, struct.pack('<i', to_state))
            if action:
                self._call_funclet(action, node + 0xC)
            state = to_state
            guard += 1
        self._mem_write(node + 8, struct.pack('<i', state if state >= -1 else -1))

    def _seh3_unwind_to(self, node, stop_level):
        """Run the __finally blocks of an _except_handler3 frame down to stop_level"""
        scope_table = self._read_u32(node + 8)
        level = self._read_i32(node + 0xC)
        guard = 0
        while level != stop_level and level >= 0 and guard < 1000:
            previous, filter_func, handler = struct.unpack('<iII', self.emu.uc.mem_read(
                scope_table + 12 * level, 12))
            self._mem_write(node + 0xC, struct.pack('<i', previous))
            if not filter_func:
                self._call_funclet(handler, node + 0x10)
            level = previous
            guard += 1

    # _except_handler4 frames: like _except_handler3's, but the scope table
    # (16-byte header of GS/EH cookie offsets, then {EnclosingLevel,
    # FilterFunc, HandlerFunc} records) is XORed with the __security_cookie
    # and the outermost level is -2

    def _seh4_scope_record(self, node, cookie_address, level):
        table = (self._read_u32(node + 8) ^ self._read_u32(cookie_address)) & 0xFFFFFFFF
        return struct.unpack('<iII', self.emu.uc.mem_read(table + 16 + 12 * level, 12))

    def _seh4_unwind_to(self, node, cookie_address, stop_level):
        """Run the __finally blocks of an _except_handler4 frame down to stop_level"""
        level = self._read_i32(node + 0xC)
        guard = 0
        while level != stop_level and level >= 0 and guard < 1000:
            enclosing, filter_func, handler = self._seh4_scope_record(node, cookie_address, level)
            self._mem_write(node + 0xC, struct.pack('<i', enclosing))
            if not filter_func:
                self._call_funclet(handler, node + 0x10)
            level = enclosing
            guard += 1

    def _seh4_handle(self, node, exc, cookie_address):
        """An _except_handler4 frame: run its filters; the jump to the __except
        block that takes the exception (or EXCEPTION_CONTINUE_EXECUTION), or None"""
        level = self._read_i32(node + 0xC)
        guard = 0
        while level >= 0 and guard < 1000:
            enclosing, filter_func, handler = self._seh4_scope_record(node, cookie_address, level)
            if filter_func:
                self._mem_write(node - 4, struct.pack('<I', exc['pointers']))
                verdict = self._signed(self._call_funclet(filter_func, node + 0x10))
                if verdict < 0:  # EXCEPTION_CONTINUE_EXECUTION
                    return self._context_jump(exc['context'])
                if verdict > 0:  # EXCEPTION_EXECUTE_HANDLER
                    self._global_unwind(node, exc['record'])
                    self._seh4_unwind_to(node, cookie_address, level)
                    self._mem_write(node + 0xC, struct.pack('<i', enclosing))
                    return ApiJump(handler, self._read_u32(node - 8), exc['code'],
                                   ebp=node + 0x10)
            level = enclosing
            guard += 1
        return None

    def _unwind_record(self, record, target_node):
        """EXCEPTION_RECORD for the unwinding handler calls: the given one marked
        EXCEPTION_UNWINDING, or a new STATUS_UNWIND one"""
        flags = self.EXCEPTION_UNWINDING | (self.EXCEPTION_EXIT_UNWIND if not target_node else 0)
        if record:
            self._mem_write(record + 4, struct.pack('<I', self._read_u32(record + 4) | flags))
            return record
        record = self.emu.heap_alloc(0x50)
        self._mem_write(record, struct.pack('<5I', self.STATUS_UNWIND, flags, 0, 0, 0))
        return record

    def _global_unwind(self, target_node, record=0):
        """Unwind the frames registered above target_node (their destructors and
        __finally blocks run; other handlers are called with EXCEPTION_UNWINDING)
        and make it the head of the SEH chain (target_node 0: all frames)"""
        head = self._seh_head_addr()
        node = self._read_u32(head)
        guard = 0
        unwind_record = None
        while node not in (0xFFFFFFFF, 0, target_node) and guard < 10000:
            next_node, handler = struct.unpack('<II', self.emu.uc.mem_read(node, 8))
            kind, info = self._classify_seh_handler(handler)
            if kind == 'cxx':
                self._cxx_unwind_to(node, self._cxx_func_info(info), -1)
            elif kind == 'seh3':
                self._seh3_unwind_to(node, -1)
            elif kind == 'seh4':
                self._seh4_unwind_to(node, info, self.SEH4_TOPMOST)
            elif self._memory_region(handler) is not None:
                if unwind_record is None:
                    unwind_record = self._unwind_record(record, target_node)
                    unwind_context = self.emu.heap_alloc(self.CONTEXT_SIZE)
                    self._write_context(unwind_context, self.capture_context())
                self.emu.call_callback(handler, [unwind_record, node, unwind_context, 0])
            self._mem_write(head, struct.pack('<I', next_node))
            node = next_node
            guard += 1
        self._mem_write(head, struct.pack('<I', target_node or 0xFFFFFFFF))

    def _catchable_types(self, throw_info):
        """[(properties, type name, pType, mdisp, pdisp, vdisp, size, copy ctor)]"""
        if not throw_info:
            return []
        array = self._read_u32(throw_info + 12)
        count = self._read_u32(array)
        types = []
        for i in range(min(count, 64)):
            entry = self._read_u32(array + 4 + 4 * i)
            props, p_type, mdisp, pdisp, vdisp, size, copy = struct.unpack(
                '<IIiiiII', self.emu.uc.mem_read(entry, 28))
            types.append((props, self.read_string(p_type + 8, 256), p_type, mdisp, pdisp,
                          vdisp, size, copy))
        return types

    def _adjust_this(self, obj, mdisp, pdisp, vdisp):
        address = obj + mdisp
        if pdisp >= 0:
            vbtable = self._read_u32(obj + pdisp)
            address += pdisp + self._read_i32(vbtable + vdisp)
        return address & 0xFFFFFFFF

    def _cxx_find_catch(self, node, info, exc):
        """(try block, catch handler, matched catchable type or None) or None"""
        state = self._read_i32(node + 8)
        types = self._catchable_types(exc['throw_info'])
        for i in range(info['n_try']):
            try_low, try_high, _, n_catches, p_handlers = struct.unpack(
                '<iiiiI', self.emu.uc.mem_read(info['try'] + 20 * i, 20))
            if not try_low <= state <= try_high:
                continue
            for j in range(n_catches):
                adjectives, p_type, disp, address = struct.unpack(
                    '<IIiI', self.emu.uc.mem_read(p_handlers + 16 * j, 16))
                name = self.read_string(p_type + 8, 256) if p_type else ''
                if not name:  # catch (...)
                    return (try_low, try_high), (adjectives, disp, address), None
                for entry in types:
                    if entry[2] == p_type or entry[1] == name:
                        return (try_low, try_high), (adjectives, disp, address), entry
        return None

    def _cxx_catch(self, node, info, found, exc):
        """Unwind to the catching frame, run the catch block; returns the ApiJump
        that continues after it"""
        (try_low, _), (adjectives, disp, handler), catch_type = found
        self._global_unwind(node, exc['record'])
        self._cxx_unwind_to(node, info, try_low)
        ebp = node + 0xC
        obj = exc['object']
        if disp and catch_type is not None and obj:
            props, _, _, mdisp, pdisp, vdisp, size, copy = catch_type
            source = self._adjust_this(obj, mdisp, pdisp, vdisp)
            target = (ebp + disp) & 0xFFFFFFFF
            if adjectives & 0x8:  # HT_IsReference
                self._mem_write(target, struct.pack('<I', source))
            elif props & 0x1 or not copy:  # CT_IsSimpleType
                self._mem_write(target, bytes(self.emu.uc.mem_read(source, size)))
            else:
                args = [source, 1] if props & 0x4 else [source]  # CT_HasVirtualBase
                self.emu.call_callback(copy, args, regs={'ecx': target})
        thread = self.emu.current_thread
        stack = getattr(thread, 'cxx_exceptions', None)
        if stack is None:
            stack = thread.cxx_exceptions = []
        stack.append(exc)
        try:
            continuation = self._call_funclet(handler, ebp)
        finally:
            stack.pop()
        throw_info = exc['throw_info']
        if obj and throw_info and not exc.get('rethrown'):
            destructor = self._read_u32(throw_info + 4)
            if destructor:
                self.emu.call_callback(destructor, [], regs={'ecx': obj})
        saved_esp = self._read_u32(node - 4)
        return ApiJump(continuation, saved_esp, continuation, ebp=ebp)

    def _seh3_handle(self, node, exc):
        """An _except_handler3 frame: run its filters; the jump to the __except
        block that takes the exception (or EXCEPTION_CONTINUE_EXECUTION), or None"""
        scope_table = self._read_u32(node + 8)
        level = self._read_i32(node + 0xC)
        guard = 0
        while level >= 0 and guard < 1000:
            previous, filter_func, handler = struct.unpack('<iII', self.emu.uc.mem_read(
                scope_table + 12 * level, 12))
            if filter_func:
                self._mem_write(node - 4, struct.pack('<I', exc['pointers']))
                verdict = self._signed(self._call_funclet(filter_func, node + 0x10))
                if verdict < 0:  # EXCEPTION_CONTINUE_EXECUTION
                    return self._context_jump(exc['context'])
                if verdict > 0:  # EXCEPTION_EXECUTE_HANDLER
                    self._global_unwind(node, exc['record'])
                    self._seh3_unwind_to(node, level)
                    self._mem_write(node + 0xC, struct.pack('<i', previous))
                    return ApiJump(handler, self._read_u32(node - 8), exc['code'],
                                   ebp=node + 0x10)
            level = previous
            guard += 1
        return None

    def _new_exception(self, code, flags, params, address, context):
        """Write EXCEPTION_RECORD, CONTEXT and EXCEPTION_POINTERS; the
        exception's info dict"""
        record = self.emu.heap_alloc(0x50 + self.CONTEXT_SIZE + 8)
        context_addr = record + 0x50
        pointers = context_addr + self.CONTEXT_SIZE
        data = struct.pack('<5I', code, flags, 0, address, min(len(params), 15))
        data += b''.join(struct.pack('<I', p & 0xFFFFFFFF) for p in params[:15])
        self._mem_write(record, data)
        self._write_context(context_addr, context)
        self._mem_write(pointers, struct.pack('<II', record, context_addr))
        cxx = code == self.CXX_EXCEPTION and len(params) > 2
        return {'code': code, 'flags': flags, 'record': record, 'context': context_addr,
                'pointers': pointers, 'object': params[1] if cxx else 0,
                'throw_info': params[2] if cxx else 0}

    def _continue_execution(self, exc):
        """Jump of EXCEPTION_CONTINUE_EXECUTION (None if the exception is
        noncontinuable)"""
        if exc['flags'] & self.EXCEPTION_NONCONTINUABLE:
            log.error(f"Exception 0x{exc['code']:08x} is noncontinuable "
                      f"(STATUS_NONCONTINUABLE_EXCEPTION)")
            return None
        return self._context_jump(exc['context'])

    def dispatch_exception(self, code, flags, params, address, context=None):
        """Find the handler of an exception like ntdll does: the vectored
        handlers, the SEH frames, then the top-level filter. Returns the
        ApiJump to the handler (or back to the faulting code), or None if the
        exception is unhandled. context: the registers at the exception
        (default: the current ones, EIP = address)."""
        thread = self.emu.current_thread
        if thread.dispatch_depth >= self.MAX_NESTED_EXCEPTIONS:
            log.error(f"Exception 0x{code:08x} while dispatching "
                      f"{thread.dispatch_depth} exceptions")
            return None
        exc = self._new_exception(code, flags, params, address,
                                  context or self.capture_context(eip=address))
        thread.dispatch_depth += 1
        try:
            for handler in list(self.vectored_handlers.values()):
                verdict = self._signed(self.emu.call_callback(handler, [exc['pointers']]))
                if verdict == -1:  # EXCEPTION_CONTINUE_EXECUTION
                    return self._continue_execution(exc)
            node = self._read_u32(self._seh_head_addr())
            guard = 0
            while node not in (0xFFFFFFFF, 0) and guard < 10000:
                next_node, handler = struct.unpack('<II', self.emu.uc.mem_read(node, 8))
                kind, info = self._classify_seh_handler(handler)
                if kind == 'cxx':
                    if code == self.CXX_EXCEPTION:
                        func_info = self._cxx_func_info(info)
                        found = self._cxx_find_catch(node, func_info, exc)
                        if found is not None:
                            return self._cxx_catch(node, func_info, found, exc)
                elif kind == 'seh3':
                    jump = self._seh3_handle(node, exc)
                    if jump is not None:
                        return jump
                elif kind == 'seh4':
                    jump = self._seh4_handle(node, exc, info)
                    if jump is not None:
                        return jump
                elif self._memory_region(handler) is not None:
                    # Another compiler's (or a hand-written) handler:
                    # EXCEPTION_DISPOSITION handler(record, frame, context, dispatcher)
                    disposition = self.emu.call_callback(
                        handler, [exc['record'], node, exc['context'], 0])
                    if disposition == 0:  # ExceptionContinueExecution
                        return self._continue_execution(exc)
                    # ExceptionContinueSearch, ExceptionNestedException, ...
                else:
                    log.warning(f"Invalid exception handler 0x{handler:08x} in the "
                                f"SEH chain (frame 0x{node:08x})")
                    break
                node = next_node
                guard += 1
            if self._top_level_filter(exc['pointers']) == -1:
                return self._continue_execution(exc)
        except UcError as e:
            log.error(f"Exception dispatch failed: {e}")
        finally:
            thread.dispatch_depth -= 1
        return None

    def _top_level_filter(self, pointers):
        """The SetUnhandledExceptionFilter filter's verdict (0: none set)"""
        if not self.unhandled_exception_filter:
            return 0
        return self._signed(self.emu.call_callback(self.unhandled_exception_filter, [pointers]))

    def raise_guest_exception(self, code, flags, params, popped_bytes):
        """Raise an exception from an API call (RaiseException,
        _CxxThrowException): the ApiJump to its handler, or 0 after ending
        the process if it is unhandled. popped_bytes: the API's stack arguments
        (the context continues after the call)."""
        return_address = self._read_u32(self.emu.api_call_esp)
        context = self.capture_context(
            eip=return_address, esp=self.emu.api_call_esp + 4 + popped_bytes)
        context['eax'] = 0
        jump = self.dispatch_exception(code, flags, params, return_address, context)
        if jump is not None or self.emu.stop_emulation:
            return jump or 0
        if code == self.CXX_EXCEPTION and len(params) > 2:
            names = [t[1] for t in self._catchable_types(params[2])] if params[2] else []
            log.error(f"Unhandled C++ exception {names[:1]}: process terminated")
        else:
            log.error(f"Unhandled exception 0x{code:08x} (RaiseException) at "
                      f"0x{return_address:08x}: process terminated")
        self._set_exit_code(code)
        self.emu.crashed = True
        self.emu.stop_emulation = True
        return 0

    def _cxx_rethrow_params(self):
        """Exception parameters of "throw;" (the C++ exception being handled),
        or None outside a catch block"""
        thread = self.emu.current_thread
        current = (getattr(thread, 'cxx_exceptions', None) or [None])[-1]
        if current is None:
            return None
        current['rethrown'] = True
        return [0x19930520, current['object'], current['throw_info']]

    def _CxxThrowException(self, args):
        """_CxxThrowException emulation - throw a C++ exception (throw;
        without an object rethrows the one being handled)"""
        obj, throw_info = args[0], args[1]
        params = [0x19930520, obj, throw_info]
        if not obj and not throw_info:
            params = self._cxx_rethrow_params()
            if params is None:
                log.error("C++ rethrow (throw;) without an exception being handled")
                self.emu.crashed = True
                self.emu.stop_emulation = True
                return 0
        names = [t[1] for t in self._catchable_types(params[2])] if params[2] else []
        log.debug(f"C++ exception thrown: {names[:1]}")
        return self.raise_guest_exception(self.CXX_EXCEPTION, self.EXCEPTION_NONCONTINUABLE,
                                          params, 8)

    # Exception handler entry points the compiled code (or a handler) calls
    # itself: the frames are handled like the dispatcher does

    def _exception_from_record(self, record, context):
        """Info dict of an exception the guest passes (EXCEPTION_RECORD, CONTEXT)"""
        code, flags = struct.unpack('<II', self.emu.uc.mem_read(record, 8))
        pointers = self.emu.heap_alloc(8)
        self._mem_write(pointers, struct.pack('<II', record, context))
        return {'code': code, 'flags': flags, 'record': record, 'context': context,
                'pointers': pointers, 'object': 0, 'throw_info': 0}

    def _frame_handler(self, record, node, context, handle):
        """Common part of _except_handler3/_except_handler4_common: unwind
        (EXCEPTION_UNWINDING) or handle the exception (ExceptionContinueSearch: 1)"""
        if self._read_u32(record + 4) & (self.EXCEPTION_UNWINDING | self.EXCEPTION_EXIT_UNWIND):
            handle(None)
            return 1
        jump = handle(self._exception_from_record(record, context))
        return jump if jump is not None else 1

    def _except_handler4_common(self, args):
        """_except_handler4_common(CookiePointer, CookieCheckFunction, record,
        frame, context, dispatcher) emulation (vcruntime140/msvcrt)"""
        cookie, record, node, context = args[0], args[2], args[3], args[4]
        return self._frame_handler(record, node, context, lambda exc: (
            self._seh4_handle(node, exc, cookie) if exc else
            self._seh4_unwind_to(node, cookie, self.SEH4_TOPMOST)))

    def _local_unwind4(self, args):
        """_local_unwind4(CookiePointer, frame, TargetLevel) emulation: run
        the frame's __finally blocks down to TargetLevel"""
        self._seh4_unwind_to(args[1], args[0], self._signed(args[2]))
        return 0

    def _local_unwind2(self, args):
        """_local_unwind2(frame, StopLevel) emulation (msvcrt)"""
        self._seh3_unwind_to(args[0], self._signed(args[1]))
        return 0

    def _global_unwind2(self, args):
        """_global_unwind2(frame) emulation (msvcrt): unwind the frames above"""
        self._global_unwind(args[0])
        return 0
    
    def _onexit(self, args):
        """_onexit emulation - atexit registration"""
        func = args[0]
        log.debug(f"_onexit(0x{func:08x})")
        if func:
            self.exit_handlers.append(func)
        return func  # Success
    
    def atexit(self, args):
        """atexit emulation"""
        func = args[0]
        log.debug(f"atexit(0x{func:08x})")
        if func:
            self.exit_handlers.append(func)
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
        if func:
            self.exit_handlers.append(func)
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
    
