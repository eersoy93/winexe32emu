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

"""WinAPIHandler mixin: ITypeComp, the name binding of type libraries and
their types (ITypeLib::GetTypeComp, ITypeInfo::GetTypeComp)

A compiler binds the names in its source with it: VBA in Access 95 resolves
the functions of its wizard libraries and the members of Access's objects so.
Names are compared without case, like the libraries' own lookups."""

import os
import struct

from ..logger import log
from .com import ComMixin
from . import typelib_reader as tlr

ComMixin.COM_INTERFACES.update({
    'type_comp': [('QueryInterface', 3), ('AddRef', 1), ('Release', 1), ('Bind', 7),
                  ('BindType', 5)],
})

IID_ITYPECOMP = '00020403-0000-0000-c000-000000000046'
DESCKIND_NONE, DESCKIND_FUNCDESC, DESCKIND_VARDESC = 0, 1, 2
DESCKIND_TYPECOMP, DESCKIND_IMPLICITAPPOBJ = 3, 4
TYPEFLAG_FAPPOBJECT = 0x0001
TYPE_E_TYPEMISMATCH = 0x80028CA0
ID_DEFAULTINST = 0xFFFFFFFE


class TypeCompMixin:
    """ITypeComp objects of the emulated type libraries and types"""

    def _new_typecomp_object(self, model, info=None, view=None):
        """An ITypeComp of a library (info None) or of one of its types"""
        pointers = self._com_new_object(
            [((IID_ITYPECOMP, self.IID_IUNKNOWN), self._com_vtable('ITypeComp', 'type_comp'))],
            {'lib': model, 'type': info, 'view': view})
        return pointers[IID_ITYPECOMP]

    def _com_type_comp(self, method, wide, args):
        """ITypeComp methods"""
        result = self._com_unknown(method, args)
        if result is not None:
            return result
        state = self.com_objects[args[0]]
        name = self.read_wide_string(args[1]) if args[1] else ''
        if method == 'Bind':
            out_info, out_kind, out_bind = args[4], args[5], args[6]
            self._write_pointer(out_info, 0)
            self._write_pointer(out_bind, 0)
            if state['type'] is None:
                found = self._bind_in_library(state['lib'], name, args[3] & 0xFFFF)
            else:
                found = self._bind_in_type(state['lib'], state['type'], state['view'],
                                           name, args[3] & 0xFFFF)
            if isinstance(found, int):  # An HRESULT
                self._mem_write(out_kind, struct.pack('<I', DESCKIND_NONE))
                return found
            kind, info_pointer, bind = found
            log.debug(f"ITypeComp::Bind({name!r}, 0x{args[3] & 0xFFFF:x}) in "
                      f"{(state['type'] or state['lib']).name} -> DESCKIND {kind}")
            self._mem_write(out_kind, struct.pack('<I', kind))
            self._write_pointer(out_info, info_pointer)
            self._write_pointer(out_bind, bind)
            return self.S_OK
        if method == 'BindType':
            out_info, out_comp = args[3], args[4]
            self._write_pointer(out_comp, 0)
            self._write_pointer(out_info, 0)
            if state['type'] is not None:
                return self.S_OK  # Types inside a type: none in these libraries
            lower = name.lower()
            info = next((t for t in state['lib'].types if t.name.lower() == lower), None)
            if info is not None:
                self._write_pointer(out_info, self._new_typeinfo_object(state['lib'], info))
            return self.S_OK
        return self.E_NOTIMPL

    def _bound_member(self, model, info, view, member):
        """(DESCKIND, ITypeInfo, FUNCDESC/VARDESC) of a member of a type; the
        description belongs to that ITypeInfo (ReleaseFuncDesc)"""
        pointer = self._new_typeinfo_object(model, info, view)
        info_state = self.com_objects[pointer]
        if isinstance(member, tlr.FuncInfo):
            return DESCKIND_FUNCDESC, pointer, self._ti_func_desc(info_state, member)
        return DESCKIND_VARDESC, pointer, self._ti_var_desc(info_state, member)

    def _bind_in_type(self, model, info, view, name, flags, depth=0):
        """Bind name to a member of a type or of the interfaces it derives from:
        (DESCKIND, ITypeInfo, description), DESCKIND_NONE or an HRESULT"""
        lower = name.lower()
        mismatch = False
        for func in info.funcs:
            if func.name.lower() == lower:
                if flags and not func.invkind & flags:
                    mismatch = True  # A property put when a get is wanted
                    continue
                return self._bound_member(model, info, view, func)
        for var in info.vars:
            if var.name.lower() == lower:
                return self._bound_member(model, info, view, var)
        if depth < 8 and info.typekind in (tlr.TKIND_INTERFACE, tlr.TKIND_DISPATCH):
            state = {'lib': model, 'type': info, 'view': view}
            for href, _ in info.impls:
                target = self._ti_resolve(state, self._ti_href(model, href))
                if target is None:
                    continue
                found = self._bind_in_type(*target, name, flags, depth + 1)
                if found != (DESCKIND_NONE, 0, 0):
                    return found
        return TYPE_E_TYPEMISMATCH if mismatch else (DESCKIND_NONE, 0, 0)

    def _bind_in_library(self, model, name, flags):
        """Bind name in a library: a module's or an enumeration's member, the
        name of such a type (its ITypeComp), an application object or one of
        its members (the object is then implied)"""
        lower = name.lower()
        for info in model.types:
            if info.typekind in (tlr.TKIND_MODULE, tlr.TKIND_ENUM):
                if info.name.lower() == lower:
                    return DESCKIND_TYPECOMP, 0, self._new_typecomp_object(model, info)
                found = self._bind_in_type(model, info, None, name, flags)
                if found != (DESCKIND_NONE, 0, 0):
                    return found
        for info in model.types:
            if info.typekind != tlr.TKIND_COCLASS or not info.flags & TYPEFLAG_FAPPOBJECT \
                    or not info.impls:
                continue
            if info.name.lower() == lower:
                return self._app_object(model, info, DESCKIND_VARDESC)
            target = self._ti_resolve({'lib': model, 'type': info, 'view': None},
                                      self._ti_href(model, info.impls[0][0]))
            if target is not None and self._has_member(target[1], name):
                return self._app_object(model, info, DESCKIND_IMPLICITAPPOBJ)
        return DESCKIND_NONE, 0, 0

    def _inherited_member(self, model, info, view, name, depth=0):
        """The FuncInfo/VarInfo called name in the interfaces info derives
        from, or None"""
        if depth >= 8 or info.typekind not in (tlr.TKIND_INTERFACE, tlr.TKIND_DISPATCH):
            return None
        lower = name.lower()
        state = {'lib': model, 'type': info, 'view': view}
        for href, _ in info.impls:
            target = self._ti_resolve(state, self._ti_href(model, href))
            if target is None:
                continue
            other_model, other, other_view = target
            member = next((m for m in other.funcs + other.vars if m.name.lower() == lower),
                          None) or self._inherited_member(other_model, other, other_view,
                                                          name, depth + 1)
            if member is not None:
                return member
        return None

    def _search_typelib_file(self, name):
        """The file LoadTypeLib loads for name: one without a path is looked
        for like LoadLibrary does, so a DLL the process has loaded is found
        (VBA in Access 95 refers to DAO's library as just "dao3032.dll")"""
        if not name or '\\' in name or '/' in name or ':' in name:
            return name
        full = self.full_windows_path(name)
        host = self.resolve_drive_path(full) if full else None
        if host and os.path.isfile(host):
            return name
        module = self.emu.find_dll(name) if hasattr(self.emu, 'find_dll') else None
        if module is not None:
            return module['path']
        for folder in ('C:\\Windows\\System32', 'C:\\Windows'):
            path = f"{folder}\\{name}"
            host = self.resolve_drive_path(path)
            if host and os.path.isfile(host):
                return path
        return name

    @staticmethod
    def _has_member(info, name):
        lower = name.lower()
        return any(m.name.lower() == lower for m in info.funcs + info.vars)

    def _app_object(self, model, coclass, kind):
        """(kind, ITypeInfo of the coclass, VARDESC of its application object:
        a static variable of its default interface's type)"""
        pointer = self._new_typeinfo_object(model, coclass)
        variable = tlr.VarInfo()
        variable.memid = ID_DEFAULTINST
        variable.name = coclass.name
        variable.type = ('user', coclass.impls[0][0])
        variable.varkind = tlr.VAR_STATIC
        return kind, pointer, self._ti_var_desc(self.com_objects[pointer], variable)
