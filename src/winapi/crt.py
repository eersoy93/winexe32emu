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

"""WinAPIHandler mixin: Additional CRT APIs, vcruntime140 exception and type_info helpers, math"""

import re
import struct
import math

from unicorn import *

from .. import config, winapi
from ..guest import QWordResult, X87Result
from ..logger import log


class CrtMixin:
    """Additional CRT APIs, vcruntime140 exception and type_info helpers, math"""

    # ==================== ADDITIONAL CRT APIs ====================

    # CRT errno values used by the emulated functions
    EDOM = 33
    ERANGE = 34
    EINVAL = 22
    ENOENT = 2
    EEXIST = 17
    EACCES = 13

    _ERRNO_MESSAGES = {
        0: "No error", 1: "Operation not permitted", 2: "No such file or directory",
        3: "No such process", 4: "Interrupted function call", 5: "Input/output error",
        6: "No such device or address", 7: "Arg list too long", 8: "Exec format error",
        9: "Bad file descriptor", 10: "No child processes",
        11: "Resource temporarily unavailable", 12: "Not enough space",
        13: "Permission denied", 14: "Bad address", 16: "Resource device",
        17: "File exists", 18: "Improper link", 19: "No such device",
        20: "Not a directory", 21: "Is a directory", 22: "Invalid argument",
        23: "Too many open files in system", 24: "Too many open files",
        25: "Inappropriate I/O control operation", 27: "File too large",
        28: "No space left on device", 29: "Invalid seek", 30: "Read-only file system",
        31: "Too many links", 32: "Broken pipe", 33: "Domain error",
        34: "Result too large", 36: "Resource deadlock avoided", 38: "Filename too long",
        39: "No locks available", 40: "Function not implemented",
        41: "Directory not empty", 42: "Illegal byte sequence",
    }

    # Helpers taking their arguments in x87 registers: name -> ST(i) count.
    # Their stubs spill ST(0..n-1) to X87_ARGS_ADDR before the hooked RET.
    X87_ARG_FUNCTIONS = {
        '_CIsin': 1, '_CIcos': 1, '_CItan': 1, '_CIasin': 1, '_CIacos': 1,
        '_CIatan': 1, '_CIsinh': 1, '_CIcosh': 1, '_CItanh': 1, '_CIexp': 1,
        '_CIlog': 1, '_CIlog10': 1, '_CIsqrt': 1, '_CIpow': 2, '_CIatan2': 2,
        '_CIfmod': 2, '_ftol': 1, '_ftol2': 1, '_ftol2_sse': 1,
    }

    def native_prologue(self, func_name):
        """Machine code run in an API stub before the hooked RET."""
        count = self.X87_ARG_FUNCTIONS.get(func_name)
        if count:
            base = self.emu.X87_ARGS_ADDR
            # fstp qword ptr [slot i] for ST(0), then ST(1)...
            return b''.join(b'\xDD\x1D' + struct.pack('<I', base + 8 * i)
                            for i in range(count))
        if func_name == '_fpreset':
            return b'\xDB\xE3'  # fninit
        return b''

    def _x87_args(self, count):
        """x87 register arguments spilled by the stub, in source order."""
        data = bytes(self.emu.uc.mem_read(self.emu.X87_ARGS_ADDR, 8 * count))
        values = list(struct.unpack(f'<{count}d', data))
        return values[::-1]  # slot 0 held ST(0), the last operand

    @staticmethod
    def _signed32(value):
        value &= 0xFFFFFFFF
        return value - 0x100000000 if value & 0x80000000 else value

    @staticmethod
    def _signed64(value):
        value &= 0xFFFFFFFFFFFFFFFF
        return value - (1 << 64) if value >> 63 else value

    @staticmethod
    def _arg_double(args, index):
        """A double passed in two stack slots starting at args[index]."""
        return struct.unpack('<d', struct.pack('<II', args[index], args[index + 1]))[0]

    @staticmethod
    def _arg_qword(args, index):
        return args[index] | (args[index + 1] << 32)

    def _mem_write(self, addr, data):
        try:
            self.emu.uc.mem_write(addr, bytes(data))
            return True
        except UcError:
            return False

    def _read_u32(self, addr):
        try:
            return struct.unpack('<I', self.emu.uc.mem_read(addr, 4))[0]
        except UcError:
            return 0

    def _read_units(self, addr, wide):
        """NUL-terminated string as a list of code units (bytes or UTF-16)."""
        if not addr:
            return []
        if wide:
            data = self._read_until_null(addr, 0x10000, 2)
            if data is None:
                self._string_access_violation(addr)
                return []
            return list(struct.unpack(f'<{len(data) // 2}H', data))
        return list(self.read_cstring(addr))

    @staticmethod
    def _pack_units(units, wide):
        if wide:
            return struct.pack(f'<{len(units)}H', *(u & 0xFFFF for u in units))
        return bytes(u & 0xFF for u in units)

    def _write_units(self, addr, units, wide, terminate=True):
        units = list(units) + ([0] if terminate else [])
        return self._mem_write(addr, self._pack_units(units, wide))

    @staticmethod
    def _text_units(text, wide):
        """Encode Python text to code units (ANSI bytes or UTF-16)."""
        if wide:
            raw = text.encode('utf-16-le', errors='surrogatepass')
            return list(struct.unpack(f'<{len(raw) // 2}H', raw))
        return list(text.encode(config.ANSI_CODEPAGE, errors='replace'))

    @staticmethod
    def _units_text(units, wide):
        if wide:
            return struct.pack(f'<{len(units)}H', *units).decode('utf-16-le', errors='replace')
        return bytes(units).decode(config.ANSI_CODEPAGE, errors='replace')

    def _alloc_units(self, units, wide):
        """Heap copy of a string (with terminator); returns its address."""
        data = self._pack_units(list(units) + [0], wide)
        addr = self.emu.heap_alloc(len(data))
        if addr:
            self._mem_write(addr, data)
        return addr

    def _static_buffer(self, name, size):
        """Per-function static buffer (like the CRT's internal ones)."""
        addr = self._crt_static.get(name)
        if not addr:
            addr = self.emu.heap_alloc(size)
            self._crt_static[name] = addr
        return addr

    def _store_errno(self, value):
        self._mem_write(self._errno([]), struct.pack('<I', value & 0xFFFFFFFF))

    def _load_errno(self):
        return self._read_u32(self._errno([]))

    def _oserror_errno(self, error):
        """Map a host OSError to the CRT errno value."""
        mapping = {
            getattr(__import__('errno'), name): value
            for name, value in (('ENOENT', 2), ('EACCES', 13), ('EPERM', 13),
                                ('EEXIST', 17), ('ENOTDIR', 20), ('EISDIR', 13),
                                ('ENOTEMPTY', 41), ('EINVAL', 22))
        }
        return mapping.get(error.errno, self.EACCES)

    def _va_args(self, va_list, count=32):
        """Read up to count DWORD arguments from a va_list pointer."""
        values = []
        for i in range(count):
            try:
                values.append(struct.unpack('<I', self.emu.uc.mem_read(va_list + 4 * i, 4))[0])
            except UcError:
                break
        return values + [0] * (count - len(values))

    def _crt_extra_api_map(self):
        """Handlers whose names start with '__' or are generated from tables."""
        api = {
            '__setusermatherr': self._crt_noop,
            '__p__environ': lambda args: self._ensure_env_ptr('_environ_ptr_addr'),
            '__p__wenviron': lambda args: self._ensure_env_ptr('_wenviron_ptr_addr', wide=True),
            '__stdio_common_vfprintf': self.api__stdio_common_vfprintf,
            '__stdio_common_vfwprintf': self.api__stdio_common_vfwprintf,
            '__stdio_common_vsprintf': self.api__stdio_common_vsprintf,
            '__stdio_common_vswprintf': self.api__stdio_common_vswprintf,
            '__stdio_common_vsprintf_s': self.api__stdio_common_vsprintf_s,
            '__stdio_common_vswprintf_s': self.api__stdio_common_vswprintf_s,
            '__stdio_common_vsnprintf_s': self.api__stdio_common_vsnprintf_s,
            '__stdio_common_vsscanf': self.api__stdio_common_vsscanf,
            '__stdio_common_vswscanf': self.api__stdio_common_vswscanf,
            '__stdio_common_vfscanf': self.api__stdio_common_vfscanf,
            'raise': self._crt_raise,  # Python keyword
            # vcruntime140.dll
            '__current_exception': lambda args: self._vcrt_exception_cells(),
            '__current_exception_context': lambda args: self._vcrt_exception_cells() + 4,
            '__std_exception_copy': self._std_exception_copy,
            '__std_exception_destroy': self._std_exception_destroy,
            '__std_terminate': self.abort,
            '__std_type_info_compare': self._std_type_info_compare,
            '__std_type_info_destroy_list': self._crt_noop,  # names are never freed
            '__std_type_info_name': self._std_type_info_name,
            '__telemetry_main_invoke_trigger': self._crt_noop,
            '__telemetry_main_return_trigger': self._crt_noop,
            '__uncaught_exception': self._crt_noop,
            '__uncaught_exceptions': self._crt_noop,
            '__vcrt_GetModuleFileNameW': self.GetModuleFileNameW,
            '__vcrt_GetModuleHandleW': self.GetModuleHandleW,
            '__vcrt_InitializeCriticalSectionEx': self.InitializeCriticalSectionEx,
            '__vcrt_LoadLibraryExW': self.LoadLibraryExW,
        }
        # Double math functions: cdecl versions take stack arguments, the
        # MSVC _CI* intrinsics take them in x87 registers
        for name, (func, argc) in self._MATH_FUNCTIONS.items():
            api[name] = self._make_math_handler(name, func, argc, x87=False)
            ci_name = '_CI' + name
            if ci_name in self.X87_ARG_FUNCTIONS:
                api[ci_name] = self._make_math_handler(ci_name, func, argc, x87=True)
        api['_hypot'] = api['hypot']
        # Wide character classification (wctype) functions
        for name, test in self._WCTYPE_TESTS.items():
            api[name] = (lambda t: lambda args: 1 if t(chr(args[0] & 0xFFFF)) else 0)(test)
        return api

    def _crt_noop(self, args):
        return 0

    # ---- vcruntime140: exception and type_info helpers ----

    def _vcrt_exception_cells(self):
        """The calling thread's {EXCEPTION_RECORD*, CONTEXT*} of the C++
        exception being handled (__current_exception/_context)"""
        thread = self.emu.current_thread
        cells = getattr(thread, 'vcrt_exception_cells', 0)
        if not cells:
            cells = thread.vcrt_exception_cells = self.emu.heap_alloc(8)
        current = (getattr(thread, 'cxx_exceptions', None) or [None])[-1]
        record = current['record'] if current else 0
        self._mem_write(cells, struct.pack('<II', record, record + 0x50 if record else 0))
        return cells

    def _std_exception_copy(self, args):
        """__std_exception_copy(from, to): __std_exception_data is {_What, _DoFree}"""
        source, target = args[0], args[1]
        what = self._read_u32(source)
        try:
            do_free = self.emu.uc.mem_read(source + 4, 1)[0]
        except UcError:
            do_free = 0
        if do_free and what:
            text = self.read_cstring(what)
            copy = self.emu.heap_alloc(len(text) + 1)
            self._mem_write(copy, text + b'\x00')
            self._mem_write(target, struct.pack('<IB', copy, 1))
        else:
            self._mem_write(target, struct.pack('<IB', what, 0))
        return 0

    def _std_exception_destroy(self, args):
        """__std_exception_destroy(data): frees an owned message"""
        what = self._read_u32(args[0])
        try:
            do_free = self.emu.uc.mem_read(args[0] + 4, 1)[0]
        except UcError:
            return 0
        if do_free and what:
            self.emu.heap_free(what)
        self._mem_write(args[0], struct.pack('<IB', 0, 0))
        return 0

    def _std_type_info_compare(self, args):
        """__std_type_info_compare(lhs, rhs): the data is {_UndecoratedName,
        _DecoratedName[]}; compares the decorated names without the leading '.'"""
        if args[0] == args[1]:
            return 0
        lhs, rhs = self.read_cstring(args[0] + 5), self.read_cstring(args[1] + 5)
        return 0 if lhs == rhs else 0xFFFFFFFF if lhs < rhs else 1

    _BASIC_TYPE_NAMES = {
        '.C': 'signed char', '.D': 'char', '.E': 'unsigned char', '.F': 'short',
        '.G': 'unsigned short', '.H': 'int', '.I': 'unsigned int', '.J': 'long',
        '.K': 'unsigned long', '.M': 'float', '.N': 'double', '.O': 'long double',
        '.X': 'void', '._J': '__int64', '._K': 'unsigned __int64', '._N': 'bool',
        '._W': 'wchar_t',
    }

    def _undecorate_type_name(self, name):
        """'.?AVFoo@ns@@' -> 'class ns::Foo' (other names stay decorated)"""
        if name in self._BASIC_TYPE_NAMES:
            return self._BASIC_TYPE_NAMES[name]
        match = re.fullmatch(r'\.\?A([VUTW])(.+)@@', name)
        if not match or '?' in match.group(2) or '$' in match.group(2):
            return name
        kind = {'V': 'class', 'U': 'struct', 'T': 'union', 'W': 'enum'}[match.group(1)]
        body = match.group(2)
        if kind == 'enum':
            body = body[1:]  # the underlying type ("W4": int)
        return f"{kind} {'::'.join(reversed(body.split('@')))}"

    def _std_type_info_name(self, args):
        """__std_type_info_name(data, list): type_info::name(), cached in the data"""
        cached = self._read_u32(args[0])
        if cached:
            return cached
        decorated = self.read_cstring(args[0] + 4).decode('ascii', errors='replace')
        text = self._undecorate_type_name(decorated).encode('ascii', errors='replace')
        address = self.emu.heap_alloc(len(text) + 1)
        self._mem_write(address, text + b'\x00')
        self._mem_write(args[0], struct.pack('<I', address))
        return address

    # ---- Math (double results are returned in ST(0)) ----

    @staticmethod
    def _c_floor(x):
        return float(math.floor(x)) if math.isfinite(x) else x

    @staticmethod
    def _c_ceil(x):
        return float(math.ceil(x)) if math.isfinite(x) else x

    class _MathRange(Exception):
        """Range error with a defined C result (e.g. log(0) == -HUGE_VAL)."""
        def __init__(self, value):
            super().__init__(value)
            self.value = value

    @staticmethod
    def _c_log(x, log_func=math.log):
        if x == 0:
            raise winapi.WinAPIHandler._MathRange(-math.inf)
        return log_func(x)

    @staticmethod
    def _c_pow(x, y):
        odd_int = float(y).is_integer() and int(y) % 2 == 1
        if x == 0 and y < 0:
            raise winapi.WinAPIHandler._MathRange(math.copysign(math.inf, x) if odd_int else math.inf)
        try:
            return math.pow(x, y)
        except OverflowError:
            raise winapi.WinAPIHandler._MathRange(-math.inf if x < 0 and odd_int else math.inf)

    _MATH_FUNCTIONS = {
        'sin': (math.sin, 1), 'cos': (math.cos, 1), 'tan': (math.tan, 1),
        'asin': (math.asin, 1), 'acos': (math.acos, 1), 'atan': (math.atan, 1),
        'sinh': (math.sinh, 1), 'cosh': (math.cosh, 1), 'tanh': (math.tanh, 1),
        'exp': (math.exp, 1), 'sqrt': (math.sqrt, 1), 'fabs': (math.fabs, 1),
        'log': (lambda x: winapi.WinAPIHandler._c_log(x), 1),
        'log10': (lambda x: winapi.WinAPIHandler._c_log(x, math.log10), 1),
        'floor': (lambda x: winapi.WinAPIHandler._c_floor(x), 1),
        'ceil': (lambda x: winapi.WinAPIHandler._c_ceil(x), 1),
        'atan2': (math.atan2, 2), 'fmod': (math.fmod, 2), 'hypot': (math.hypot, 2),
        'pow': (lambda x, y: winapi.WinAPIHandler._c_pow(x, y), 2),
        '_copysign': (math.copysign, 2),
    }

    def _math_call(self, func, values):
        """Run a math function with C error semantics (errno, NaN, HUGE_VAL)."""
        try:
            return func(*values)
        except ValueError:
            self._store_errno(self.EDOM)
            return math.nan
        except winapi.WinAPIHandler._MathRange as e:
            self._store_errno(self.ERANGE)
            return e.value
        except OverflowError:
            self._store_errno(self.ERANGE)
            if func is math.sinh:
                return math.copysign(math.inf, values[0])
            return math.inf

    def _make_math_handler(self, name, func, argc, x87):
        def handler(args):
            if x87:
                values = self._x87_args(argc)
            else:
                values = [self._arg_double(args, 2 * i) for i in range(argc)]
            result = self._math_call(func, values)
            log.debug(f"{name}{tuple(values)} -> {result}")
            return X87Result(result)
        return handler

    def ldexp(self, args):
        """ldexp emulation (x * 2^exp)"""
        x = self._arg_double(args, 0)
        try:
            return X87Result(math.ldexp(x, self._signed32(args[2])))
        except OverflowError:
            self._store_errno(self.ERANGE)
            return X87Result(math.copysign(math.inf, x))

    def frexp(self, args):
        """frexp emulation (mantissa, *exp)"""
        x = self._arg_double(args, 0)
        mantissa, exponent = math.frexp(x) if math.isfinite(x) else (x, 0)
        if args[2]:
            self._mem_write(args[2], struct.pack('<i', exponent))
        return X87Result(mantissa)

    def modf(self, args):
        """modf emulation (fractional part, *integer part)"""
        x = self._arg_double(args, 0)
        if math.isinf(x):
            frac, whole = math.copysign(0.0, x), x
        else:
            frac, whole = math.modf(x)
        if args[2]:
            self._mem_write(args[2], struct.pack('<d', whole))
        return X87Result(frac)

    def _chgsign(self, args):
        """_chgsign emulation"""
        return X87Result(-self._arg_double(args, 0))

    def _isnan(self, args):
        """_isnan emulation"""
        return 1 if math.isnan(self._arg_double(args, 0)) else 0

    def _finite(self, args):
        """_finite emulation"""
        return 1 if math.isfinite(self._arg_double(args, 0)) else 0

    def _ftol_common(self):
        value = self._x87_args(1)[0]
        if not math.isfinite(value) or not -(1 << 63) <= value < (1 << 63):
            return QWordResult(1 << 63)  # integer indefinite
        return QWordResult(int(value))  # truncation toward zero

    def _ftol(self, args):
        """_ftol emulation - ST(0) truncated to a 64-bit integer in EDX:EAX"""
        return self._ftol_common()

    def _ftol2(self, args):
        return self._ftol_common()

    def _ftol2_sse(self, args):
        return self._ftol_common()

    def _fpreset(self, args):
        """_fpreset emulation (the stub already executed FNINIT)"""
        return 0

    def _clearfp(self, args):
        """_clearfp emulation - no exception flags are tracked"""
        return 0

    def _statusfp(self, args):
        """_statusfp emulation"""
        return 0

    def _controlfp_s(self, args):
        """_controlfp_s emulation"""
        if args[0]:
            self._mem_write(args[0], struct.pack('<I', 0x9001F))
        return 0

    def _control87(self, args):
        return self._controlfp(args)
