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

"""WinAPIHandler mixin: oleaut32 VARIANT conversions (VariantChangeType,
Var...From...), error information objects, name hashes and the IDispatch
helpers (DispGetIDsOfNames, DispInvoke)"""

import datetime
import math
import re
import struct

from unicorn import UcError

from ..logger import log
from .com import ComMixin

ComMixin.COM_INTERFACES.update({
    'error_info': [
        ('QueryInterface', 3), ('AddRef', 1), ('Release', 1), ('GetGUID', 2),
        ('GetSource', 2), ('GetDescription', 2), ('GetHelpFile', 2),
        ('GetHelpContext', 2)],
    'create_error_info': [
        ('QueryInterface', 3), ('AddRef', 1), ('Release', 1), ('SetGUID', 2),
        ('SetSource', 2), ('SetDescription', 2), ('SetHelpFile', 2),
        ('SetHelpContext', 2)],
})

VT_EMPTY, VT_NULL, VT_I2, VT_I4, VT_R4, VT_R8, VT_CY, VT_DATE = 0, 1, 2, 3, 4, 5, 6, 7
VT_BSTR, VT_DISPATCH, VT_ERROR, VT_BOOL, VT_VARIANT, VT_UNKNOWN = 8, 9, 10, 11, 12, 13
VT_DECIMAL, VT_I1, VT_UI1, VT_UI2, VT_UI4, VT_I8, VT_UI8 = 14, 16, 17, 18, 19, 20, 21
VT_INT, VT_UINT, VT_VOID, VT_HRESULT = 22, 23, 24, 25
VT_ARRAY, VT_BYREF = 0x2000, 0x4000
DISP_E_TYPEMISMATCH, DISP_E_OVERFLOW, DISP_E_BADVARTYPE = 0x80020005, 0x8002000A, 0x80020008
DISP_E_PARAMNOTFOUND = 0x80020004
VARIANT_ALPHABOOL = 0x2
OLE_EPOCH = datetime.datetime(1899, 12, 30)
INT_RANGES = {VT_I2: (-0x8000, 0x7FFF), VT_I4: (-0x80000000, 0x7FFFFFFF),
              VT_I1: (-0x80, 0x7F), VT_UI1: (0, 0xFF), VT_UI2: (0, 0xFFFF),
              VT_UI4: (0, 0xFFFFFFFF), VT_INT: (-0x80000000, 0x7FFFFFFF),
              VT_UINT: (0, 0xFFFFFFFF), VT_I8: (-(1 << 63), (1 << 63) - 1),
              VT_UI8: (0, (1 << 64) - 1), VT_ERROR: (0, 0xFFFFFFFF)}
INT_FORMATS = {VT_I2: '<h', VT_I4: '<i', VT_I1: '<b', VT_UI1: '<B', VT_UI2: '<H',
               VT_UI4: '<I', VT_INT: '<i', VT_UINT: '<I', VT_I8: '<q', VT_UI8: '<Q',
               VT_ERROR: '<I'}


class VariantError(Exception):
    """A conversion failed with this HRESULT"""

    def __init__(self, hresult):
        super().__init__(hex(hresult))
        self.hresult = hresult


class Cy:
    """A CURRENCY value (int64 ten-thousandths)"""

    def __init__(self, units):
        self.units = units


class Date:
    """A DATE value (days since 1899-12-30)"""

    def __init__(self, days):
        self.days = days


class Interface:
    """A VT_DISPATCH / VT_UNKNOWN pointer"""

    def __init__(self, vt, pointer):
        self.vt, self.pointer = vt, pointer


def format_double(value, digits=15):
    """A number the way VarBstrFromR8 writes it: up to 15 significant digits,
    exponents like 1E+20"""
    if value == 0:
        return '0'
    text = format(value, f'.{digits}G')
    if 'E' in text:
        mantissa, exponent = text.split('E')
        sign, number = exponent[0], exponent[1:].lstrip('0') or '0'
        text = f"{mantissa}E{sign}{number.zfill(2)}"
    return text


def format_date(days):
    """A DATE the way VarBstrFromDate writes it (US English)"""
    whole = math.floor(days) if days >= 0 else math.ceil(days)
    fraction = abs(days - whole)
    seconds = round(fraction * 86400)
    if seconds >= 86400:
        seconds = 86399
    date = OLE_EPOCH + datetime.timedelta(days=whole)
    hours, rest = divmod(seconds, 3600)
    minutes, secs = divmod(rest, 60)
    time_text = f"{(hours % 12) or 12}:{minutes:02d}:{secs:02d} {'AM' if hours < 12 else 'PM'}"
    if whole == 0:
        return time_text
    date_text = f"{date.month}/{date.day}/{date.year}"
    return date_text if seconds == 0 else f"{date_text} {time_text}"


_DATE_RE = re.compile(r'^\s*(?:(\d{1,4})[/.-](\d{1,2})(?:[/.-](\d{1,4}))?)?\s*'
                      r'(?:(\d{1,2}):(\d{2})(?::(\d{2}))?\s*([AaPp][Mm])?)?\s*$')


def parse_date(text):
    """Days since 1899-12-30 of a date and/or time text, or None"""
    match = _DATE_RE.match(text)
    if not match or not text.strip():
        return None
    first, second, third, hour, minute, second_t, ampm = match.groups()
    days = 0.0
    if first:
        a, b = int(first), int(second)
        if third is None:  # Month/day of this year
            year, month, day = datetime.date.today().year, a, b
        elif len(first) == 4:  # yyyy-mm-dd
            year, month, day = a, b, int(third)
        else:
            year, month, day = int(third), a, b
            if len(third) <= 2:
                year += 1900 if year >= 30 else 2000
        try:
            days = float((datetime.datetime(year, month, day) - OLE_EPOCH).days)
        except ValueError:
            return None
    if hour is not None:
        h, m, s = int(hour), int(minute), int(second_t or 0)
        if ampm:
            h = h % 12 + (12 if ampm.lower() == 'pm' else 0)
        if h > 23 or m > 59 or s > 59:
            return None
        fraction = (h * 3600 + m * 60 + s) / 86400.0
        days = days + fraction if days >= 0 else days - fraction
    return days


def parse_number(text):
    """A number of a string (VB rules: &H hex, &O octal), or None"""
    stripped = text.strip()
    if not stripped:
        return None
    lower = stripped.lower()
    try:
        if lower.startswith('&h'):
            return int(lower[2:], 16)
        if lower.startswith('&o'):
            return int(lower[2:], 8)
        cleaned = stripped.replace(',', '').replace('$', '')
        if re.fullmatch(r'[+-]?\d+', cleaned):
            return int(cleaned)
        return float(cleaned)
    except ValueError:
        return None


class OleAutVariantMixin:
    """VARIANT conversions, error information, IDispatch helpers"""

    # ---------- Reading and writing VARIANT values ----------

    def _variant_load(self, address):
        """(vt, Python value) of the VARIANT at address (references followed)"""
        data = bytes(self.emu.uc.mem_read(address, 16))
        vt = struct.unpack_from('<H', data)[0]
        if vt & VT_BYREF:
            pointer = struct.unpack_from('<I', data, 8)[0]
            base = vt & ~VT_BYREF
            if base == VT_VARIANT:
                return self._variant_load(pointer)
            size = 8 if base in (VT_R8, VT_CY, VT_DATE, VT_I8, VT_UI8) else 4
            raw = bytes(self.emu.uc.mem_read(pointer, size)) + b'\x00' * (8 - size)
            return base, self._variant_decode(base, raw)
        return vt, self._variant_decode(vt, data[8:16])

    def _variant_decode(self, vt, raw):
        if vt == VT_EMPTY:
            return None
        if vt == VT_NULL:
            return 'null'
        if vt in INT_FORMATS:
            return struct.unpack_from(INT_FORMATS[vt], raw)[0]
        if vt == VT_R4:
            return struct.unpack_from('<f', raw)[0]
        if vt == VT_R8:
            return struct.unpack_from('<d', raw)[0]
        if vt == VT_CY:
            return Cy(struct.unpack_from('<q', raw)[0])
        if vt == VT_DATE:
            return Date(struct.unpack_from('<d', raw)[0])
        if vt == VT_BOOL:
            return struct.unpack_from('<h', raw)[0] != 0
        if vt == VT_BSTR:
            pointer = struct.unpack_from('<I', raw)[0]
            return self._bstr_text(pointer)
        if vt in (VT_DISPATCH, VT_UNKNOWN):
            return Interface(vt, struct.unpack_from('<I', raw)[0])
        raise VariantError(DISP_E_BADVARTYPE)

    def _bstr_text(self, pointer):
        if not pointer:
            return ''
        length = struct.unpack('<I', self.emu.uc.mem_read(pointer - 4, 4))[0]
        return bytes(self.emu.uc.mem_read(pointer, length)).decode('utf-16-le', 'replace')

    def _variant_number(self, value):
        """A Python int/float of a value for a numeric conversion"""
        if value is None:
            return 0
        if isinstance(value, bool):
            return -1 if value else 0
        if isinstance(value, (int, float)):
            return value
        if isinstance(value, Cy):
            return value.units / 10000.0
        if isinstance(value, Date):
            return value.days
        if isinstance(value, str):
            number = parse_number(value)
            if number is None:
                if value.strip().lower() in ('true', '#true#'):
                    return -1
                if value.strip().lower() in ('false', '#false#'):
                    return 0
                raise VariantError(DISP_E_TYPEMISMATCH)
            return number
        raise VariantError(DISP_E_TYPEMISMATCH)

    def _variant_text(self, value, flags=0):
        if value is None:
            return ''
        if isinstance(value, bool):
            return 'True' if value else 'False'
        if isinstance(value, int):
            return str(value)
        if isinstance(value, float):
            return format_double(value)
        if isinstance(value, Cy):
            whole, rest = divmod(abs(value.units), 10000)
            text = str(whole) + (f".{rest:04d}".rstrip('0') if rest else '')
            return ('-' if value.units < 0 else '') + text
        if isinstance(value, Date):
            return format_date(value.days)
        if isinstance(value, str):
            return value
        raise VariantError(DISP_E_TYPEMISMATCH)

    def _variant_convert(self, value, vt, flags=0):
        """(vt, value) of value converted to vt; VariantError if it cannot be"""
        if value == 'null':
            if vt in (VT_NULL, VT_VARIANT):
                return VT_NULL, 'null'
            if vt == VT_EMPTY:
                return VT_EMPTY, None
            raise VariantError(DISP_E_TYPEMISMATCH)
        if isinstance(value, Interface):
            if vt in (VT_DISPATCH, VT_UNKNOWN):
                return vt, Interface(vt, value.pointer)
            raise VariantError(DISP_E_TYPEMISMATCH)
        if vt == VT_EMPTY:
            return VT_EMPTY, None
        if vt == VT_NULL:
            return VT_NULL, 'null'
        if vt == VT_BSTR:
            return VT_BSTR, self._variant_text(value, flags)
        if vt == VT_BOOL:
            if isinstance(value, str):
                lower = value.strip().lower()
                if lower in ('true', '#true#', 'yes', 'on'):
                    return VT_BOOL, True
                if lower in ('false', '#false#', 'no', 'off'):
                    return VT_BOOL, False
            return VT_BOOL, self._variant_number(value) != 0
        if vt == VT_DATE:
            if isinstance(value, str):
                days = parse_date(value)
                if days is None:
                    number = parse_number(value)
                    if number is None:
                        raise VariantError(DISP_E_TYPEMISMATCH)
                    days = float(number)
                return VT_DATE, Date(days)
            days = float(self._variant_number(value))
            if not -657434 <= days < 2958466:
                raise VariantError(DISP_E_OVERFLOW)
            return VT_DATE, Date(days)
        number = self._variant_number(value)
        if vt in (VT_R4, VT_R8):
            number = float(number)
            if vt == VT_R4 and abs(number) > 3.402823466e38 and not math.isinf(number):
                raise VariantError(DISP_E_OVERFLOW)
            return vt, number
        if vt == VT_CY:
            units = round(number * 10000) if isinstance(number, float) else number * 10000
            if not -(1 << 63) <= units < (1 << 63):
                raise VariantError(DISP_E_OVERFLOW)
            return VT_CY, Cy(int(units))
        if vt in INT_RANGES:
            if isinstance(number, float):
                if math.isnan(number) or math.isinf(number):
                    raise VariantError(DISP_E_OVERFLOW)
                number = round(number)  # Banker's rounding, like oleaut32
            low, high = INT_RANGES[vt]
            if not low <= number <= high:
                raise VariantError(DISP_E_OVERFLOW)
            return vt, int(number)
        raise VariantError(DISP_E_BADVARTYPE)

    def _variant_encode(self, vt, value):
        """The 8 value bytes of a VARIANT; BSTRs are allocated"""
        if vt in (VT_EMPTY, VT_NULL):
            return b'\x00' * 8
        if vt in INT_FORMATS:
            return struct.pack(INT_FORMATS[vt], value).ljust(8, b'\x00')
        if vt == VT_R4:
            return struct.pack('<f', value).ljust(8, b'\x00')
        if vt == VT_R8:
            return struct.pack('<d', value)
        if vt == VT_CY:
            return struct.pack('<q', value.units)
        if vt == VT_DATE:
            return struct.pack('<d', value.days)
        if vt == VT_BOOL:
            return struct.pack('<h', -1 if value else 0).ljust(8, b'\x00')
        if vt == VT_BSTR:
            return struct.pack('<I', self._alloc_bstr(value.encode('utf-16-le'))).ljust(
                8, b'\x00')
        if vt in (VT_DISPATCH, VT_UNKNOWN):
            if value.pointer:
                self._com_call(value.pointer, 1)  # AddRef
            return struct.pack('<I', value.pointer).ljust(8, b'\x00')
        raise VariantError(DISP_E_BADVARTYPE)

    def _variant_store(self, address, vt, value):
        self._mem_write(address, struct.pack('<HHHH', vt, 0, 0, 0) +
                        self._variant_encode(vt, value))

    # ---------- VariantChangeType and friends ----------

    def VariantChangeTypeEx(self, args):
        """VariantChangeTypeEx(dest, src, lcid, flags, vt)"""
        return self.VariantChangeType([args[0], args[1], args[3], args[4]])

    def VariantChangeType(self, args):
        """VariantChangeType(dest, src, flags, vt)"""
        dest, src, flags, vt = args[0], args[1], args[2] & 0xFFFF, args[3] & 0xFFFF
        if not dest or not src:
            return 0x80070057  # E_INVALIDARG
        try:
            source_vt = struct.unpack('<H', self.emu.uc.mem_read(src, 2))[0]
            if vt == VT_VARIANT or (source_vt == vt and not vt & VT_BYREF):
                return self.VariantCopy([dest, src]) if dest != src else 0
            if vt & (VT_ARRAY | VT_BYREF):
                return DISP_E_TYPEMISMATCH
            _, value = self._variant_load(src)
            new_vt, new_value = self._variant_convert(value, vt, flags)
            raw = self._variant_encode(new_vt, new_value)
        except VariantError as e:
            return e.hresult
        except UcError:
            return 0x80070057
        if dest == src or not struct.unpack('<H', self.emu.uc.mem_read(dest, 2))[0] & VT_BYREF:
            self.VariantClear([dest])
        self._mem_write(dest, struct.pack('<HHHH', new_vt, 0, 0, 0) + raw)
        return 0

    def VariantCopyInd(self, args):
        """VariantCopyInd(dest, src) - a copy with the reference followed"""
        dest, src = args[0], args[1]
        vt = struct.unpack('<H', self.emu.uc.mem_read(src, 2))[0]
        if not vt & VT_BYREF:
            return self.VariantCopy([dest, src])
        base = vt & ~VT_BYREF
        pointer = struct.unpack('<I', self.emu.uc.mem_read(src + 8, 4))[0]
        if base == VT_VARIANT:
            return self.VariantCopyInd([dest, pointer])
        if base & VT_ARRAY:
            array = struct.unpack('<I', self.emu.uc.mem_read(pointer, 4))[0]
            temp = self.emu.heap_alloc(16)
            self._mem_write(temp, struct.pack('<HHHHI', base, 0, 0, 0, array) + b'\x00' * 4)
            result = self.VariantCopy([dest, temp])
            self.emu.heap_free(temp)
            return result
        try:
            _, value = self._variant_load(src)
            raw = self._variant_encode(base, value)
        except VariantError as e:
            return e.hresult
        if dest != src:
            self.VariantClear([dest])
        self._mem_write(dest, struct.pack('<HHHH', base, 0, 0, 0) + raw)
        return 0

    # Var<To>From<From>: (from VARTYPE, argument DWORDs of the value)
    _VAR_FROM_SIZES = {VT_R8: 2, VT_DATE: 2, VT_CY: 2, VT_I8: 2, VT_UI8: 2}
    _VAR_NAMES = {'I2': VT_I2, 'I4': VT_I4, 'R4': VT_R4, 'R8': VT_R8, 'Cy': VT_CY,
                  'Date': VT_DATE, 'Str': VT_BSTR, 'Bstr': VT_BSTR, 'Bool': VT_BOOL,
                  'UI1': VT_UI1, 'I1': VT_I1, 'UI2': VT_UI2, 'UI4': VT_UI4, 'I8': VT_I8,
                  'UI8': VT_UI8, 'Int': VT_INT, 'UInt': VT_UINT}

    def _var_from(self, to_name, from_name, args):
        """Var<to>From<from>(value, [lcid, flags,] pOut)"""
        source, target = self._VAR_NAMES[from_name], self._VAR_NAMES[to_name]
        words = self._VAR_FROM_SIZES.get(source, 1)
        raw = struct.pack(f'<{words}I', *args[:words]).ljust(8, b'\x00')
        rest = args[words:]
        # (value, pOut) or (value, lcid, dwFlags, pOut)
        flags = rest[1] if len(rest) >= 3 else 0
        out = rest[-1]
        if from_name == 'Str':
            value = self.read_wide_string(args[0]) if args[0] else ''
        else:
            if source == VT_R4:
                raw = struct.pack('<I', args[0]).ljust(8, b'\x00')
            value = self._variant_decode(source, raw)
        try:
            vt, converted = self._variant_convert(value, target, flags)
            data = self._variant_encode(vt, converted)
        except VariantError as e:
            return e.hresult
        size = {VT_I2: 2, VT_BOOL: 2, VT_UI1: 1, VT_I1: 1, VT_UI2: 2, VT_R8: 8, VT_CY: 8,
                VT_DATE: 8, VT_I8: 8, VT_UI8: 8}.get(target, 4)
        self._mem_write(out, data[:size])
        return 0

    def VarBstrFromI2(self, args):
        return self._var_from('Bstr', 'I2', args)

    def VarBstrFromI4(self, args):
        return self._var_from('Bstr', 'I4', args)

    def VarBstrFromR4(self, args):
        return self._var_from('Bstr', 'R4', args)

    def VarBstrFromR8(self, args):
        return self._var_from('Bstr', 'R8', args)

    def VarBstrFromCy(self, args):
        return self._var_from('Bstr', 'Cy', args)

    def VarBstrFromDate(self, args):
        return self._var_from('Bstr', 'Date', args)

    def VarBstrFromBool(self, args):
        return self._var_from('Bstr', 'Bool', args)

    def VarI2FromStr(self, args):
        return self._var_from('I2', 'Str', args)

    def VarI4FromStr(self, args):
        return self._var_from('I4', 'Str', args)

    def VarR4FromStr(self, args):
        return self._var_from('R4', 'Str', args)

    def VarR8FromStr(self, args):
        return self._var_from('R8', 'Str', args)

    def VarCyFromStr(self, args):
        return self._var_from('Cy', 'Str', args)

    def VarDateFromStr(self, args):
        return self._var_from('Date', 'Str', args)

    def VarBoolFromStr(self, args):
        return self._var_from('Bool', 'Str', args)

    def VarUI1FromI2(self, args):
        return self._var_from('UI1', 'I2', args)

    def VarR4FromR8(self, args):
        return self._var_from('R4', 'R8', args)

    def VarI2FromI4(self, args):
        return self._var_from('I2', 'I4', args)

    def VarI4FromR8(self, args):
        return self._var_from('I4', 'R8', args)

    def VarCyFromI4(self, args):
        return self._var_from('Cy', 'I4', args)

    def VarCyFromR8(self, args):
        return self._var_from('Cy', 'R8', args)

    def VarR8FromCy(self, args):
        return self._var_from('R8', 'Cy', args)

    def VariantTimeToDosDateTime(self, args):
        """VariantTimeToDosDateTime(DATE, pwDosDate, pwDosTime)"""
        days = struct.unpack('<d', struct.pack('<II', args[0], args[1]))[0]
        try:
            moment = OLE_EPOCH + datetime.timedelta(days=days)
        except OverflowError:
            return 0
        if not 1980 <= moment.year <= 2107:
            return 0
        date = ((moment.year - 1980) << 9) | (moment.month << 5) | moment.day
        dos_time = (moment.hour << 11) | (moment.minute << 5) | (moment.second // 2)
        self._mem_write(args[2], struct.pack('<H', date))
        self._mem_write(args[3], struct.pack('<H', dos_time))
        return 1

    def DosDateTimeToVariantTime(self, args):
        """DosDateTimeToVariantTime(wDosDate, wDosTime, pvtime)"""
        date, dos_time = args[0] & 0xFFFF, args[1] & 0xFFFF
        try:
            moment = datetime.datetime(1980 + (date >> 9), (date >> 5) & 0xF, date & 0x1F,
                                       dos_time >> 11, (dos_time >> 5) & 0x3F,
                                       (dos_time & 0x1F) * 2)
        except ValueError:
            return 0
        delta = moment - OLE_EPOCH
        self._mem_write(args[2], struct.pack('<d', delta.days + delta.seconds / 86400.0))
        return 1

    # ---------- Name hashes ----------

    @staticmethod
    def name_hash(syskind, lcid, data):
        """LHashValOfNameSysA: oleaut32's case-insensitive hash of a name
        (latin languages: the high word is 0x10)"""
        mask = 1 if syskind == 2 else 0  # SYS_MAC
        low = 0x0DEADBEE
        for byte in data:
            if 0x61 <= byte <= 0x7A:
                byte -= 0x20
            low = (31 * low + byte) & 0xFFFFFFFF
        low = (low % 65599) & 0xFFFF
        return ((16 | mask) << 16) | low

    def LHashValOfNameSysA(self, args):
        """LHashValOfNameSysA(syskind, lcid, szName)"""
        if not args[2]:
            return 0
        return self.name_hash(args[0], args[1], self.read_cstring(args[2]))

    def LHashValOfNameSys(self, args):
        """LHashValOfNameSys(syskind, lcid, szName) - the hash of the ANSI name"""
        if not args[2]:
            return 0
        text = self.read_wide_string(args[2])
        return self.name_hash(args[0], args[1], text.encode('cp1252', errors='replace'))

    # ---------- Error information ----------

    IID_IERRORINFO = '1cf2b120-547d-101b-8e65-08002b2bd119'
    IID_ICREATEERRORINFO = '22f03340-547d-101b-8e65-08002b2bd119'

    def CreateErrorInfo(self, args):
        """CreateErrorInfo(ppcerrinfo) - an ICreateErrorInfo (also IErrorInfo) object"""
        if not args[0]:
            return 0x80004003
        pointers = self._com_new_object(
            [((self.IID_ICREATEERRORINFO, self.IID_IUNKNOWN),
              self._com_vtable('ICreateErrorInfo', 'create_error_info')),
             ((self.IID_IERRORINFO,), self._com_vtable('IErrorInfo', 'error_info'))],
            {'guid': b'\x00' * 16, 'source': '', 'description': '', 'helpfile': '',
             'context': 0})
        self._mem_write(args[0], struct.pack('<I', pointers[self.IID_ICREATEERRORINFO]))
        return 0

    def _com_create_error_info(self, method, wide, args):
        result = self._com_unknown(method, args)
        if result is not None:
            return result
        state = self.com_objects[args[0]]
        if method == 'SetGUID':
            state['guid'] = bytes(self.emu.uc.mem_read(args[1], 16)) if args[1] else b'\0' * 16
        elif method == 'SetHelpContext':
            state['context'] = args[1]
        else:
            key = {'SetSource': 'source', 'SetDescription': 'description',
                   'SetHelpFile': 'helpfile'}[method]
            state[key] = self.read_wide_string(args[1]) if args[1] else ''
            log.debug(f"ICreateErrorInfo::{method}(\"{state[key]}\")")
        return 0

    def _com_error_info(self, method, wide, args):
        result = self._com_unknown(method, args)
        if result is not None:
            return result
        state = self.com_objects[args[0]]
        if not args[1]:
            return 0x80070057
        if method == 'GetGUID':
            self._mem_write(args[1], state['guid'])
        elif method == 'GetHelpContext':
            self._mem_write(args[1], struct.pack('<I', state['context']))
        else:
            key = {'GetSource': 'source', 'GetDescription': 'description',
                   'GetHelpFile': 'helpfile'}[method]
            self._mem_write(args[1], struct.pack(
                '<I', self._alloc_bstr(state[key].encode('utf-16-le'))))
        return 0

    def SetErrorInfo(self, args):
        """SetErrorInfo(reserved, perrinfo) - the thread's error object"""
        errors = self.__dict__.setdefault('_error_infos', {})
        tid = self.emu.current_thread.tid
        old = errors.pop(tid, 0)
        if args[1]:
            self._com_call(args[1], 1)  # AddRef
            errors[tid] = args[1]
        if old:
            self._com_call(old, 2)  # Release
        return 0

    def GetErrorInfo(self, args):
        """GetErrorInfo(reserved, pperrinfo) - takes the thread's error object
        (S_FALSE if there is none)"""
        if not args[1]:
            return 0x80070057
        pointer = self.__dict__.get('_error_infos', {}).pop(self.emu.current_thread.tid, 0)
        if pointer:
            # The object as IErrorInfo (its reference goes to the caller)
            state = self.com_objects.get(pointer)
            if state is not None and self.IID_IERRORINFO in state['pointers']:
                pointer = state['pointers'][self.IID_IERRORINFO]
        self._mem_write(args[1], struct.pack('<I', pointer))
        return 0 if pointer else 1

    # ---------- IDispatch helpers ----------

    def DispGetIDsOfNames(self, args):
        """DispGetIDsOfNames(ptinfo, rgszNames, cNames, rgdispid)"""
        return self._com_call(args[0], 10, args[1], args[2], args[3])  # GetIDsOfNames

    def DispInvoke(self, args):
        """DispInvoke(this, ptinfo, dispid, wFlags, pparams, pvarResult,
        pexcepinfo, puArgErr) - ITypeInfo::Invoke"""
        this, tinfo = args[0], args[1]
        log.debug(f"DispInvoke(0x{this:x}, dispid 0x{args[2]:x}, flags {args[3]})")
        return self._com_call(tinfo, 11, this, *args[2:8])  # Invoke
