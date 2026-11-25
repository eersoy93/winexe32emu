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

"""WinAPIHandler mixin: oleaut32 SAFEARRAYs"""

import struct

from unicorn import UcError

from ..logger import log


class SafeArrayMixin:
    """oleaut32 SAFEARRAYs.

    A SAFEARRAY (cDims, fFeatures, cbElements, cLocks, pvData, then the
    bounds, the last dimension first) is allocated with 16 bytes before it,
    like oleaut32: the VARTYPE (FADF_HAVEVARTYPE) sits in the DWORD before
    the descriptor, the IID (FADF_HAVEIID) in the 16 bytes before it.
    """

    FADF_AUTO, FADF_STATIC, FADF_EMBEDDED, FADF_FIXEDSIZE = 0x1, 0x2, 0x4, 0x10
    FADF_RECORD, FADF_HAVEIID, FADF_HAVEVARTYPE = 0x20, 0x40, 0x80
    FADF_BSTR, FADF_UNKNOWN, FADF_DISPATCH, FADF_VARIANT = 0x100, 0x200, 0x400, 0x800
    DISP_E_BADINDEX, DISP_E_ARRAYISLOCKED = 0x8002000B, 0x8002000D
    E_INVALIDARG_SA, E_OUTOFMEMORY_SA, E_UNEXPECTED_SA = 0x80070057, 0x8007000E, 0x8000FFFF
    DISP_E_BADVARTYPE = 0x80020008
    # VARTYPE -> element size
    VT_SIZES = {2: 2, 3: 4, 4: 4, 5: 8, 6: 8, 7: 8, 8: 4, 9: 4, 10: 4, 11: 2, 12: 16,
                13: 4, 14: 16, 16: 1, 17: 1, 18: 2, 19: 4, 20: 8, 21: 8, 22: 4, 23: 4}

    def _sa_header(self, psa):
        """(cDims, fFeatures, cbElements, cLocks, pvData) or None"""
        if not psa:
            return None
        try:
            return struct.unpack('<HHIII', self.emu.uc.mem_read(psa, 16))
        except UcError:
            return None

    def _sa_bounds(self, psa, dims):
        """[(cElements, lLbound)] as stored (the last dimension first)"""
        data = self.emu.uc.mem_read(psa + 16, 8 * dims)
        return [struct.unpack_from('<Ii', data, 8 * i) for i in range(dims)]

    def _sa_count(self, psa, dims):
        count = 1
        for elements, _ in self._sa_bounds(psa, dims):
            count *= elements
        return count

    def _sa_features_of(self, vt):
        return {8: self.FADF_BSTR, 13: self.FADF_UNKNOWN, 9: self.FADF_DISPATCH,
                12: self.FADF_VARIANT}.get(vt, 0)

    def _sa_alloc_descriptor(self, dims, extra_features=0):
        block = self.emu.heap_alloc(16 + 16 + 8 * max(dims, 1))
        if not block:
            return 0
        psa = block + 16
        self._mem_write(block, b'\x00' * (32 + 8 * max(dims, 1)))
        self._mem_write(psa, struct.pack('<HH', dims, extra_features))
        return psa

    def _sa_set_vartype(self, psa, vt):
        dims, features = struct.unpack('<HH', self.emu.uc.mem_read(psa, 4))
        features = (features & ~0xF00) | self._sa_features_of(vt) | self.FADF_HAVEVARTYPE
        self._mem_write(psa + 2, struct.pack('<H', features))
        self._mem_write(psa - 4, struct.pack('<I', vt))
        self._mem_write(psa + 4, struct.pack('<I', self.VT_SIZES.get(vt, 4)))

    def _sa_create(self, vt, bounds_in_order):
        """A SAFEARRAY of vt with its data; bounds [(elements, lower)] in the
        caller's order (the first dimension first)"""
        if vt not in self.VT_SIZES:
            return 0
        dims = len(bounds_in_order)
        psa = self._sa_alloc_descriptor(dims)
        if not psa:
            return 0
        self._sa_set_vartype(psa, vt)
        stored = list(reversed(bounds_in_order))
        self._mem_write(psa + 16, b''.join(struct.pack('<Ii', e, lb) for e, lb in stored))
        if self.SafeArrayAllocData([psa]) != 0:
            self.SafeArrayDestroyDescriptor([psa])
            return 0
        return psa

    def SafeArrayCreate(self, args):
        """SafeArrayCreate(vt, cDims, rgsabound)"""
        vt, dims, bounds = args[0] & 0xFFFF, args[1], args[2]
        if not bounds or dims == 0:
            return 0
        data = self.emu.uc.mem_read(bounds, 8 * dims)
        psa = self._sa_create(vt, [struct.unpack_from('<Ii', data, 8 * i) for i in range(dims)])
        log.debug(f"SafeArrayCreate(vt={vt}, {dims} dims) -> 0x{psa:x}")
        return psa

    def SafeArrayCreateEx(self, args):
        return self.SafeArrayCreate(args[:3])

    def SafeArrayCreateVector(self, args):
        """SafeArrayCreateVector(vt, lLbound, cElements)"""
        lower = struct.unpack('<i', struct.pack('<I', args[1]))[0]
        return self._sa_create(args[0] & 0xFFFF, [(args[2], lower)])

    def SafeArrayCreateVectorEx(self, args):
        return self.SafeArrayCreateVector(args[:3])

    def SafeArrayAllocDescriptor(self, args):
        """SafeArrayAllocDescriptor(cDims, ppsaOut)"""
        if not args[0] or not args[1]:
            return self.E_INVALIDARG_SA
        psa = self._sa_alloc_descriptor(args[0])
        if not psa:
            return self.E_OUTOFMEMORY_SA
        self._mem_write(args[1], struct.pack('<I', psa))
        return 0

    def SafeArrayAllocDescriptorEx(self, args):
        """SafeArrayAllocDescriptorEx(vt, cDims, ppsaOut)"""
        result = self.SafeArrayAllocDescriptor(args[1:3])
        if result == 0:
            psa = struct.unpack('<I', self.emu.uc.mem_read(args[2], 4))[0]
            self._sa_set_vartype(psa, args[0] & 0xFFFF)
        return result

    def SafeArrayAllocData(self, args):
        """SafeArrayAllocData(psa) - zeroed room for the elements"""
        psa = args[0]
        header = self._sa_header(psa)
        if header is None:
            return self.E_INVALIDARG_SA
        dims, _, size, _, _ = header
        total = self._sa_count(psa, dims) * size
        data = self.emu.heap_alloc(max(total, 4))
        if not data:
            return self.E_OUTOFMEMORY_SA
        self._mem_write(data, b'\x00' * max(total, 4))
        self._mem_write(psa + 12, struct.pack('<I', data))
        return 0

    def _sa_clear_elements(self, psa, header):
        """Free the BSTRs, release the interfaces, clear the VARIANTs"""
        dims, features, size, _, data = header
        if not data:
            return
        count = self._sa_count(psa, dims)
        for index in range(count):
            address = data + index * size
            if features & self.FADF_BSTR:
                value = struct.unpack('<I', self.emu.uc.mem_read(address, 4))[0]
                if value:
                    self.SysFreeString([value])
            elif features & (self.FADF_UNKNOWN | self.FADF_DISPATCH):
                value = struct.unpack('<I', self.emu.uc.mem_read(address, 4))[0]
                if value:
                    self._com_call(value, 2)  # Release
            elif features & self.FADF_VARIANT:
                self.VariantClear([address])
        self._mem_write(data, b'\x00' * (count * size))

    def SafeArrayDestroyData(self, args):
        """SafeArrayDestroyData(psa) - frees the elements (a static array keeps its room)"""
        header = self._sa_header(args[0])
        if header is None:
            return self.E_INVALIDARG_SA
        if header[3]:
            return self.DISP_E_ARRAYISLOCKED
        self._sa_clear_elements(args[0], header)
        if not header[1] & (self.FADF_STATIC | self.FADF_EMBEDDED | self.FADF_AUTO) \
                and header[4]:
            self.emu.heap_free(header[4])
            self._mem_write(args[0] + 12, struct.pack('<I', 0))
        return 0

    def SafeArrayDestroyDescriptor(self, args):
        header = self._sa_header(args[0])
        if header is None:
            return self.E_INVALIDARG_SA
        if header[3]:
            return self.DISP_E_ARRAYISLOCKED
        self.emu.heap_free(args[0] - 16)
        return 0

    def SafeArrayDestroy(self, args):
        """SafeArrayDestroy(psa) - the elements, the data and the descriptor"""
        if not args[0]:
            return 0
        result = self.SafeArrayDestroyData(args)
        if result:
            return result
        return self.SafeArrayDestroyDescriptor(args)

    def SafeArrayGetDim(self, args):
        header = self._sa_header(args[0])
        return header[0] if header else 0

    def SafeArrayGetElemsize(self, args):
        header = self._sa_header(args[0])
        return header[2] if header else 0

    def _sa_dimension_bounds(self, psa, dim):
        """(elements, lower) of dimension dim (1 = the first), or None"""
        header = self._sa_header(psa)
        if header is None or not 1 <= dim <= header[0]:
            return None
        return self._sa_bounds(psa, header[0])[header[0] - dim]

    def SafeArrayGetUBound(self, args):
        bounds = self._sa_dimension_bounds(args[0], args[1])
        if bounds is None:
            return self.DISP_E_BADINDEX
        self._mem_write(args[2], struct.pack('<i', bounds[1] + bounds[0] - 1))
        return 0

    def SafeArrayGetLBound(self, args):
        bounds = self._sa_dimension_bounds(args[0], args[1])
        if bounds is None:
            return self.DISP_E_BADINDEX
        self._mem_write(args[2], struct.pack('<i', bounds[1]))
        return 0

    def SafeArrayLock(self, args):
        header = self._sa_header(args[0])
        if header is None:
            return self.E_INVALIDARG_SA
        self._mem_write(args[0] + 8, struct.pack('<I', header[3] + 1))
        return 0

    def SafeArrayUnlock(self, args):
        header = self._sa_header(args[0])
        if header is None:
            return self.E_INVALIDARG_SA
        if not header[3]:
            return self.E_UNEXPECTED_SA
        self._mem_write(args[0] + 8, struct.pack('<I', header[3] - 1))
        return 0

    def SafeArrayAccessData(self, args):
        """SafeArrayAccessData(psa, ppvData) - locks it"""
        result = self.SafeArrayLock(args[:1])
        if result == 0:
            self._mem_write(args[1], struct.pack('<I', self._sa_header(args[0])[4]))
        return result

    def SafeArrayUnaccessData(self, args):
        return self.SafeArrayUnlock(args[:1])

    def _sa_element_address(self, psa, indices_address):
        """Address of the element at the indices (the first dimension first), or None"""
        header = self._sa_header(psa)
        if header is None or not indices_address:
            return None
        dims, _, size, _, data = header
        indices = struct.unpack(f'<{dims}i', self.emu.uc.mem_read(indices_address, 4 * dims))
        bounds = list(reversed(self._sa_bounds(psa, dims)))  # The first dimension first
        offset, stride = 0, 1
        for index, (elements, lower) in zip(indices, bounds, strict=True):
            if not lower <= index < lower + elements:
                return None
            offset += (index - lower) * stride
            stride *= elements
        return data + offset * size

    def SafeArrayPtrOfIndex(self, args):
        address = self._sa_element_address(args[0], args[1])
        if address is None:
            return self.DISP_E_BADINDEX
        self._mem_write(args[2], struct.pack('<I', address))
        return 0

    def SafeArrayGetElement(self, args):
        """SafeArrayGetElement(psa, rgIndices, pv) - a copy of the element"""
        psa, indices, out = args[:3]
        address = self._sa_element_address(psa, indices)
        if address is None:
            return self.DISP_E_BADINDEX
        _, features, size, _, _ = self._sa_header(psa)
        if features & self.FADF_VARIANT:
            self._mem_write(out, b'\x00' * 16)
            return self.VariantCopy([out, address])
        value = bytes(self.emu.uc.mem_read(address, size))
        if features & self.FADF_BSTR:
            bstr = struct.unpack('<I', value)[0]
            copy = self._alloc_bstr(bytes(self.emu.uc.mem_read(
                bstr, self.SysStringByteLen([bstr])))) if bstr else 0
            value = struct.pack('<I', copy)
        elif features & (self.FADF_UNKNOWN | self.FADF_DISPATCH):
            pointer = struct.unpack('<I', value)[0]
            if pointer:
                self._com_call(pointer, 1)  # AddRef
        self._mem_write(out, value)
        return 0

    def SafeArrayPutElement(self, args):
        """SafeArrayPutElement(psa, rgIndices, pv) - stores a copy (pv is the
        BSTR or interface itself, else points to the value)"""
        psa, indices, value = args[:3]
        address = self._sa_element_address(psa, indices)
        if address is None:
            return self.DISP_E_BADINDEX
        _, features, size, _, _ = self._sa_header(psa)
        if features & self.FADF_VARIANT:
            return self.VariantCopy([address, value])
        if features & self.FADF_BSTR:
            old = struct.unpack('<I', self.emu.uc.mem_read(address, 4))[0]
            if old:
                self.SysFreeString([old])
            copy = self._alloc_bstr(bytes(self.emu.uc.mem_read(
                value, self.SysStringByteLen([value])))) if value else 0
            self._mem_write(address, struct.pack('<I', copy))
            return 0
        if features & (self.FADF_UNKNOWN | self.FADF_DISPATCH):
            old = struct.unpack('<I', self.emu.uc.mem_read(address, 4))[0]
            if value:
                self._com_call(value, 1)  # AddRef
            if old:
                self._com_call(old, 2)  # Release
            self._mem_write(address, struct.pack('<I', value))
            return 0
        self._mem_write(address, bytes(self.emu.uc.mem_read(value, size)))
        return 0

    def SafeArrayGetVartype(self, args):
        """SafeArrayGetVartype(psa, pvt)"""
        header = self._sa_header(args[0])
        if header is None or not args[1]:
            return self.E_INVALIDARG_SA
        features = header[1]
        if features & self.FADF_HAVEVARTYPE:
            vt = struct.unpack('<I', self.emu.uc.mem_read(args[0] - 4, 4))[0] & 0xFFFF
        elif features & self.FADF_BSTR:
            vt = 8
        elif features & self.FADF_UNKNOWN:
            vt = 13
        elif features & self.FADF_DISPATCH:
            vt = 9
        elif features & self.FADF_VARIANT:
            vt = 12
        elif features & self.FADF_RECORD:
            vt = 36
        else:
            return self.DISP_E_BADVARTYPE
        self._mem_write(args[1], struct.pack('<H', vt))
        return 0

    def SafeArrayCopyData(self, args):
        """SafeArrayCopyData(source, dest) - the elements into an array of the same shape"""
        source, dest = args[:2]
        header, other = self._sa_header(source), self._sa_header(dest)
        if header is None or other is None or header[0] != other[0] or header[2] != other[2]:
            return self.E_INVALIDARG_SA
        self._sa_clear_elements(dest, other)
        count = self._sa_count(source, header[0])
        size, features = header[2], header[1]
        for index in range(count):
            src, dst = header[4] + index * size, other[4] + index * size
            if features & self.FADF_VARIANT:
                self.VariantCopy([dst, src])
                continue
            value = bytes(self.emu.uc.mem_read(src, size))
            if features & self.FADF_BSTR:
                bstr = struct.unpack('<I', value)[0]
                value = struct.pack('<I', self._alloc_bstr(bytes(self.emu.uc.mem_read(
                    bstr, self.SysStringByteLen([bstr])))) if bstr else 0)
            elif features & (self.FADF_UNKNOWN | self.FADF_DISPATCH):
                pointer = struct.unpack('<I', value)[0]
                if pointer:
                    self._com_call(pointer, 1)
            self._mem_write(dst, value)
        return 0

    def SafeArrayCopy(self, args):
        """SafeArrayCopy(psa, ppsaOut) - a new array with copies of the elements"""
        psa, out = args[:2]
        header = self._sa_header(psa)
        if header is None or not out:
            if out:
                self._mem_write(out, struct.pack('<I', 0))
            return 0 if not psa else self.E_INVALIDARG_SA
        dims, features, size = header[:3]
        copy = self._sa_alloc_descriptor(dims)
        if not copy:
            return self.E_OUTOFMEMORY_SA
        prefix = bytes(self.emu.uc.mem_read(psa - 16, 16))
        self._mem_write(copy - 16, prefix)
        keep = features & ~(self.FADF_AUTO | self.FADF_STATIC | self.FADF_EMBEDDED |
                            self.FADF_FIXEDSIZE)
        self._mem_write(copy, struct.pack('<HHII', dims, keep, size, 0))
        self._mem_write(copy + 16, bytes(self.emu.uc.mem_read(psa + 16, 8 * dims)))
        result = self.SafeArrayAllocData([copy])
        if result == 0:
            result = self.SafeArrayCopyData([psa, copy])
        self._mem_write(out, struct.pack('<I', copy if result == 0 else 0))
        return result

    def SafeArrayRedim(self, args):
        """SafeArrayRedim(psa, psaboundNew) - a new size of the last dimension"""
        psa, bound = args[:2]
        header = self._sa_header(psa)
        if header is None or not bound:
            return self.E_INVALIDARG_SA
        dims, features, size, locks, data = header
        if locks or features & self.FADF_FIXEDSIZE:
            return self.DISP_E_ARRAYISLOCKED
        old_count = self._sa_count(psa, dims)
        elements, lower = struct.unpack('<Ii', self.emu.uc.mem_read(bound, 8))
        self._mem_write(psa + 16, struct.pack('<Ii', elements, lower))  # The last dimension
        new_count = self._sa_count(psa, dims)
        new_data = self.emu.heap_alloc(max(new_count * size, 4))
        if not new_data:
            return self.E_OUTOFMEMORY_SA
        self._mem_write(new_data, b'\x00' * max(new_count * size, 4))
        keep = min(old_count, new_count) * size
        if data and keep:
            self._mem_write(new_data, bytes(self.emu.uc.mem_read(data, keep)))
        if data:
            self.emu.heap_free(data)
        self._mem_write(psa + 12, struct.pack('<I', new_data))
        return 0
