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

"""WinAPIHandler mixin: OLE32, COM objects, shell namespace (IShellFolder, IContextMenu);
CRT startup data (__getmainargs and the like)"""

import os
import shutil
import struct
import datetime
import ntpath

from unicorn import UcError

from .. import config, resources
from ..config import DRIVES
from ..logger import log
from .registry import registry_locked
from .typelib import guid_text, type_library_attributes, type_library_data


class ComMixin:
    """OLE32, COM objects, shell namespace (IShellFolder, IContextMenu);
    CRT startup data (__getmainargs and the like)"""

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

    # ---------- COM objects ----------

    S_OK, S_FALSE = 0, 1
    E_NOINTERFACE, E_POINTER, E_FAIL = 0x80004002, 0x80004003, 0x80004005
    E_INVALIDARG = 0x80070057
    CLASS_E_NOAGGREGATION, REGDB_E_CLASSNOTREG = 0x80040110, 0x80040154

    CLSID_SHELLLINK = '00021401-0000-0000-c000-000000000046'
    IID_IUNKNOWN = '00000000-0000-0000-c000-000000000046'
    IID_IPERSIST = '0000010c-0000-0000-c000-000000000046'
    IID_IPERSISTFILE = '0000010b-0000-0000-c000-000000000046'
    IID_ISHELLLINKA = '000214ee-0000-0000-c000-000000000046'
    IID_ISHELLLINKW = '000214f9-0000-0000-c000-000000000046'
    CLSID_TASKBARLIST = '56fdf344-fd6d-11d0-958a-006097c9a090'
    IID_ITASKBARLIST = '56fdf342-fd6d-11d0-958a-006097c9a090'
    IID_ITASKBARLIST2 = '602d4995-b13a-429b-a66e-1935e44f4317'
    IID_ITASKBARLIST3 = 'ea1afb91-9e28-4b86-90e9-9e9f8a5eefaf'
    IID_ITASKBARLIST4 = 'c43dc798-95d1-4bea-9030-bb99e2983a1a'

    # Interface kind -> methods (name, argument count with "this") in vtable order
    COM_INTERFACES = {
        'shell_link': [
            ('QueryInterface', 3), ('AddRef', 1), ('Release', 1), ('GetPath', 5),
            ('GetIDList', 2), ('SetIDList', 2), ('GetDescription', 3), ('SetDescription', 2),
            ('GetWorkingDirectory', 3), ('SetWorkingDirectory', 2), ('GetArguments', 3),
            ('SetArguments', 2), ('GetHotkey', 2), ('SetHotkey', 2), ('GetShowCmd', 2),
            ('SetShowCmd', 2), ('GetIconLocation', 4), ('SetIconLocation', 3),
            ('SetRelativePath', 3), ('Resolve', 3), ('SetPath', 2)],
        'persist_file': [
            ('QueryInterface', 3), ('AddRef', 1), ('Release', 1), ('GetClassID', 2),
            ('IsDirty', 1), ('Load', 3), ('Save', 3), ('SaveCompleted', 2),
            ('GetCurFile', 2)],
        'extract_icon': [
            ('QueryInterface', 3), ('AddRef', 1), ('Release', 1), ('GetIconLocation', 6),
            ('Extract', 6)],
        'class_factory': [
            ('QueryInterface', 3), ('AddRef', 1), ('Release', 1), ('CreateInstance', 4),
            ('LockServer', 2)],
        # ITaskbarList4 (and the ITaskbarList..3 prefixes of its vtable);
        # SetProgressValue takes two ULONGLONGs
        'taskbar_list': [
            ('QueryInterface', 3), ('AddRef', 1), ('Release', 1), ('HrInit', 1),
            ('AddTab', 2), ('DeleteTab', 2), ('ActivateTab', 2), ('SetActiveAlt', 2),
            ('MarkFullscreenWindow', 3), ('SetProgressValue', 6), ('SetProgressState', 3),
            ('RegisterTab', 3), ('UnregisterTab', 2), ('SetTabOrder', 3), ('SetTabActive', 4),
            ('ThumbBarAddButtons', 4), ('ThumbBarUpdateButtons', 4),
            ('ThumbBarSetImageList', 3), ('SetOverlayIcon', 4), ('SetThumbnailTooltip', 3),
            ('SetThumbnailClip', 3), ('SetTabProperties', 3)],
    }

    def _read_guid(self, address):
        """GUID in memory -> lower-case "xxxxxxxx-xxxx-..." string ('' if unreadable)"""
        try:
            data1, data2, data3, data4 = struct.unpack('<IHH8s', self.emu.uc.mem_read(address, 16))
        except UcError:
            return ''
        return f'{data1:08x}-{data2:04x}-{data3:04x}-{data4[:2].hex()}-{data4[2:].hex()}'

    @staticmethod
    def _guid_bytes(guid):
        parts = guid.split('-')
        return (struct.pack('<IHH', int(parts[0], 16), int(parts[1], 16), int(parts[2], 16))
                + bytes.fromhex(parts[3] + parts[4]))

    def _com_vtable(self, interface, kind, wide=False):
        """vtable of API stubs for an interface; method calls go to
        self._com_<kind>(method, wide, args)"""
        key = (interface, wide)
        if key in self._com_vtables:
            return self._com_vtables[key]
        target = getattr(self, f'_com_{kind}')
        stubs = []
        for method, argc in self.COM_INTERFACES[kind]:
            name = f"{interface}::{method}"
            self._api_map[name] = (lambda m: lambda args: target(m, wide, args))(method)
            self.com_arg_counts[name] = argc
            stubs.append(self.emu._create_api_stub('ole32.dll', name))
        vtable = self.emu.heap_alloc(4 * len(stubs))
        self._mem_write(vtable, struct.pack(f'<{len(stubs)}I', *stubs))
        self._com_vtables[key] = vtable
        return vtable

    def _com_new_object(self, interfaces, state):
        """Allocate a COM object: one vtable pointer per interface, all sharing
        state; returns {IID: interface pointer}"""
        base = self.emu.heap_alloc(4 * len(interfaces))
        state.update({'refs': 1, 'base': base, 'pointers': {}})
        for index, (iids, vtable) in enumerate(interfaces):
            pointer = base + 4 * index
            self._mem_write(pointer, struct.pack('<I', vtable))
            self.com_objects[pointer] = state
            for iid in iids:
                state['pointers'].setdefault(iid, pointer)
        return state['pointers']

    def _com_unknown(self, method, args):
        """IUnknown methods shared by every emulated COM object (None: not one)"""
        state = self.com_objects.get(args[0])
        if state is None:
            return 0 if method in ('AddRef', 'Release') else self.E_POINTER
        if method == 'QueryInterface':
            pointer = state['pointers'].get(self._read_guid(args[1]))
            if not args[2]:
                return self.E_POINTER
            self._mem_write(args[2], struct.pack('<I', pointer or 0))
            if not pointer:
                return self.E_NOINTERFACE
            state['refs'] += 1
            return self.S_OK
        if method == 'AddRef':
            state['refs'] += 1
            return state['refs']
        if method == 'Release':
            state['refs'] -= 1
            if state['refs'] <= 0:
                for pointer in set(state['pointers'].values()):
                    self.com_objects.pop(pointer, None)
                self.emu.heap_free(state['base'])
                return 0
            return state['refs']
        return None

    def CoCreateInstance(self, args):
        """CoCreateInstance emulation - the shell link object (CLSID_ShellLink)
        and the taskbar list (CLSID_TaskbarList)"""
        rclsid, pUnkOuter, _, riid, ppv = args[:5]
        clsid, iid = self._read_guid(rclsid), self._read_guid(riid)
        log.debug(f"CoCreateInstance({{{clsid}}}, {{{iid}}})")
        if not ppv:
            return self.E_POINTER
        self._mem_write(ppv, struct.pack('<I', 0))
        if pUnkOuter:
            return self.CLASS_E_NOAGGREGATION
        if clsid == self.CLSID_TASKBARLIST:
            pointers = self._com_new_object(
                [((self.IID_ITASKBARLIST4, self.IID_ITASKBARLIST3, self.IID_ITASKBARLIST2,
                   self.IID_ITASKBARLIST, self.IID_IUNKNOWN),
                  self._com_vtable('ITaskbarList4', 'taskbar_list'))],
                {})
            unknown = pointers[self.IID_IUNKNOWN]
            result = self._com_unknown('QueryInterface', [unknown, riid, ppv])
            self._com_unknown('Release', [unknown])
            return result
        if clsid != self.CLSID_SHELLLINK:
            result = self._create_from_class_object(rclsid, riid, ppv)
            if result == self.REGDB_E_CLASSNOTREG:
                log.warning(f"CoCreateInstance: COM class {{{clsid}}} is not emulated")
            return result
        pointers = self._com_new_object(
            [((self.IID_ISHELLLINKW, self.IID_IUNKNOWN),
              self._com_vtable('IShellLinkW', 'shell_link', wide=True)),
             ((self.IID_ISHELLLINKA,), self._com_vtable('IShellLinkA', 'shell_link')),
             ((self.IID_IPERSISTFILE, self.IID_IPERSIST),
              self._com_vtable('IPersistFile', 'persist_file'))],
            {'path': '', 'description': '', 'workdir': '', 'arguments': '',
             'relative': '', 'icon': '', 'icon_index': 0, 'show': 1, 'hotkey': 0,
             'file': None, 'dirty': False})
        unknown = pointers[self.IID_IUNKNOWN]
        result = self._com_unknown('QueryInterface', [unknown, riid, ppv])
        self._com_unknown('Release', [unknown])
        return result

    IID_ICLASSFACTORY = '00000001-0000-0000-c000-000000000046'

    def _create_from_class_object(self, rclsid, riid, ppv):
        """CoCreateInstance of a class the process registered or an
        in-process server DLL serves: its IClassFactory::CreateInstance"""
        cell = self.emu.heap_alloc(20)
        try:
            self._mem_write(cell, self._guid_bytes(self.IID_ICLASSFACTORY))
            result = self.CoGetClassObject([rclsid, 1, 0, cell, cell + 16])
            factory = struct.unpack('<I', self.emu.uc.mem_read(cell + 16, 4))[0]
            if result & 0x80000000 or not factory:
                return result or self.REGDB_E_CLASSNOTREG
            vtable = struct.unpack('<I', self.emu.uc.mem_read(factory, 4))[0]
            release, create = struct.unpack('<II', self.emu.uc.mem_read(vtable + 8, 8))
            result = self.emu.call_callback(create, [factory, 0, riid, ppv])
            self.emu.call_callback(release, [factory])
            return result
        finally:
            self.emu.heap_free(cell)

    def _com_taskbar_list(self, method, wide, args):
        """ITaskbarList..4 methods: the fake taskbar has no tab thumbnails,
        overlays or progress bars, so every call just succeeds"""
        result = self._com_unknown(method, args)
        if result is not None:
            return result
        if method == 'SetProgressValue':
            completed = args[2] | (args[3] << 32)
            total = args[4] | (args[5] << 32)
            log.debug(f"ITaskbarList3::SetProgressValue(0x{args[1]:x}, {completed}, {total})")
        return self.S_OK

    # ---------- Shell namespace: IShellFolder, IContextMenu ----------

    IID_ISHELLFOLDER = '000214e6-0000-0000-c000-000000000046'
    IID_ICONTEXTMENU = '000214e4-0000-0000-c000-000000000046'
    IID_ICONTEXTMENU2 = '000214f4-0000-0000-c000-000000000046'
    IID_ICONTEXTMENU3 = 'bcfce0a0-ec17-11d0-8d10-00a0c90f2719'
    E_NOTIMPL = 0x80004001
    HRESULT_FILE_NOT_FOUND = 0x80070002  # HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)

    COM_INTERFACES.update({
        'shell_folder': [
            ('QueryInterface', 3), ('AddRef', 1), ('Release', 1), ('ParseDisplayName', 7),
            ('EnumObjects', 4), ('BindToObject', 5), ('BindToStorage', 5),
            ('CompareIDs', 4), ('CreateViewObject', 4), ('GetAttributesOf', 4),
            ('GetUIObjectOf', 7), ('GetDisplayNameOf', 4), ('SetNameOf', 6)],
        # IContextMenu3 (IContextMenu and IContextMenu2 are prefixes of its vtable)
        'context_menu': [
            ('QueryInterface', 3), ('AddRef', 1), ('Release', 1), ('QueryContextMenu', 6),
            ('InvokeCommand', 2), ('GetCommandString', 6), ('HandleMenuMsg', 4),
            ('HandleMenuMsg2', 5)],
        'enum_idlist': [
            ('QueryInterface', 3), ('AddRef', 1), ('Release', 1), ('Next', 4),
            ('Skip', 2), ('Reset', 1), ('Clone', 2)],
        'malloc': [
            ('QueryInterface', 3), ('AddRef', 1), ('Release', 1), ('Alloc', 2),
            ('Realloc', 3), ('Free', 2), ('GetSize', 2), ('DidAlloc', 2),
            ('HeapMinimize', 1)],
    })

    # SFGAO_CANCOPY | CANMOVE | CANLINK | CANDELETE | HASPROPSHEET | FILESYSTEM;
    # SFGAO_FOLDER | FILESYSANCESTOR | HASSUBFOLDER for folders
    SFGAO_FILE = 0x1 | 0x2 | 0x4 | 0x20 | 0x40 | 0x40000000
    SFGAO_DIRECTORY = 0x20000000 | 0x10000000 | 0x80000000

    def _shell_folder_object(self, path):
        """New IShellFolder of a folder ('' is the desktop); returns its pointer"""
        pointers = self._com_new_object(
            [((self.IID_ISHELLFOLDER, self.IID_IUNKNOWN),
              self._com_vtable('IShellFolder', 'shell_folder', wide=True))],
            {'path': path})
        return pointers[self.IID_IUNKNOWN]

    def _com_query_new(self, unknown, riid, ppv):
        """QueryInterface a new object for the caller, dropping the creation reference"""
        result = self._com_unknown('QueryInterface', [unknown, riid, ppv])
        self._com_unknown('Release', [unknown])
        return result

    def SHGetDesktopFolder(self, args):
        """SHGetDesktopFolder emulation - the desktop's IShellFolder: it parses
        file system paths of the sandbox into PIDLs and makes the shell's
        context menu of files (GetUIObjectOf IContextMenu)"""
        if not args[0]:
            return self.E_INVALIDARG
        self._mem_write(args[0], struct.pack('<I', self._shell_folder_object('')))
        return self.S_OK

    IID_IENUMIDLIST = '000214f2-0000-0000-c000-000000000046'
    SHCONTF_FOLDERS, SHCONTF_NONFOLDERS, SHCONTF_INCLUDEHIDDEN = 0x20, 0x40, 0x80

    def _shell_folder_items(self, path, flags):
        """Full paths of the items of a shell folder for EnumObjects: My
        Computer holds the drives, the desktop My Computer and the Desktop
        folder's items"""
        folders, files = flags & self.SHCONTF_FOLDERS, flags & self.SHCONTF_NONFOLDERS
        if self._is_my_computer(path):
            return [f"{letter}:\\" for letter in self.LOGICAL_DRIVES] if folders else []
        items = []
        if not path:
            if folders:
                items.append(self.MY_COMPUTER_PATH)
            path = self._shell_folder(0x10)  # CSIDL_DESKTOPDIRECTORY
        host = self.resolve_drive_path(path.rstrip('\\') + '\\') if path else None
        try:
            names = sorted(os.listdir(host), key=str.lower) if host else []
        except OSError:
            names = []
        for name in names:
            if name.startswith('.') and not flags & self.SHCONTF_INCLUDEHIDDEN:
                continue
            is_dir = os.path.isdir(os.path.join(host, name))
            if folders if is_dir else files:
                items.append(ntpath.join(path, name))
        return items

    def _enum_idlist_object(self, paths):
        """New IEnumIDList over PIDLs of paths; returns its pointer"""
        pointers = self._com_new_object(
            [((self.IID_IENUMIDLIST, self.IID_IUNKNOWN),
              self._com_vtable('IEnumIDList', 'enum_idlist'))],
            {'paths': list(paths), 'next': 0})
        return pointers[self.IID_IUNKNOWN]

    def _com_enum_idlist(self, method, wide, args):
        """IEnumIDList of EnumObjects: each Next hands out new PIDLs"""
        result = self._com_unknown(method, args)
        if result is not None:
            return result
        state = self.com_objects[args[0]]
        paths = state['paths']
        if method == 'Next':
            _, count, rgelt, fetched = args[:4]
            if not rgelt:
                return self.E_POINTER
            taken = paths[state['next']:state['next'] + count]
            state['next'] += len(taken)
            for index, path in enumerate(taken):
                self._mem_write(rgelt + 4 * index, struct.pack('<I', self._make_pidl(path)))
            if fetched:
                self._mem_write(fetched, struct.pack('<I', len(taken)))
            return self.S_OK if len(taken) == count else 1  # S_FALSE
        if method == 'Skip':
            skipped = min(args[1], len(paths) - state['next'])
            state['next'] += skipped
            return self.S_OK if skipped == args[1] else 1
        if method == 'Reset':
            state['next'] = 0
            return self.S_OK
        if method == 'Clone':
            if not args[1]:
                return self.E_POINTER
            clone = self._enum_idlist_object(paths)
            self.com_objects[clone]['next'] = state['next']
            self._mem_write(args[1], struct.pack('<I', clone))
            return self.S_OK
        return self.E_NOTIMPL

    # Explorer's names of the drive types (GetDriveType)
    DRIVE_TYPE_NAMES = {2: '3\u00bd Floppy', 3: 'Local Disk', 5: 'CD Drive'}

    def _drive_display_name(self, path):
        """Explorer's name of a drive root like C:\\ ("Local Disk (C:)"), or None"""
        if len(path) <= 3 and path[1:2] == ':' and path.rstrip('\\')[2:] == '':
            letter = path[0].upper()
            if letter not in DRIVES:
                return None
            label = self._volume_label(letter) or self.DRIVE_TYPE_NAMES[DRIVES[letter][0]]
            return f"{label} ({letter}:)"
        return None

    def _shell_item_attributes(self, path):
        if self._is_my_computer(path):
            return self.SFGAO_DIRECTORY  # A folder, not in the file system
        host = self.resolve_drive_path(path)
        if host is None or not os.path.exists(host):
            return 0
        return self.SFGAO_FILE | (self.SFGAO_DIRECTORY if os.path.isdir(host) else 0)

    def _com_shell_folder(self, method, wide, args):
        """IShellFolder of a sandbox folder; its PIDLs hold full Windows paths
        (self.pidls), relative ones too"""
        result = self._com_unknown(method, args)
        if result is not None:
            return result
        state = self.com_objects[args[0]]
        if method == 'ParseDisplayName':
            _, _, _, name_ptr, eaten, ppidl, attributes = args[:7]
            if not ppidl or not name_ptr:
                return self.E_INVALIDARG
            self._mem_write(ppidl, struct.pack('<I', 0))
            name = self._read_text(name_ptr, True)
            if self._is_my_computer(name):
                if eaten:
                    self._mem_write(eaten, struct.pack('<I', len(name)))
                if attributes:
                    wanted = struct.unpack('<I', self.emu.uc.mem_read(attributes, 4))[0]
                    self._mem_write(attributes, struct.pack('<I', wanted & self.SFGAO_DIRECTORY))
                self._mem_write(ppidl, struct.pack('<I', self._make_pidl(self.MY_COMPUTER_PATH)))
                return self.S_OK
            full = self.full_windows_path(ntpath.join(state['path'], name) if state['path']
                                          else name)
            host = self.resolve_drive_path(full) if full else None
            if host is None or not os.path.exists(host):
                return self.HRESULT_FILE_NOT_FOUND
            if len(full) > 3:
                full = full.rstrip('\\')
            if eaten:
                self._mem_write(eaten, struct.pack('<I', len(name)))
            if attributes:
                wanted = struct.unpack('<I', self.emu.uc.mem_read(attributes, 4))[0]
                self._mem_write(attributes, struct.pack(
                    '<I', wanted & self._shell_item_attributes(full)))
            self._mem_write(ppidl, struct.pack('<I', self._make_pidl(full)))
            return self.S_OK
        if method == 'BindToObject':
            _, pidl, _, riid, ppv = args[:5]
            if not ppv:
                return self.E_POINTER
            self._mem_write(ppv, struct.pack('<I', 0))
            path = self._pidl_path(pidl)
            if path == '':  # The empty list: this folder itself
                return self._com_query_new(self._shell_folder_object(state['path']), riid, ppv)
            if self._is_my_computer(path):
                return self._com_query_new(self._shell_folder_object(self.MY_COMPUTER_PATH),
                                           riid, ppv)
            host = self.resolve_drive_path(path) if path else None
            if host is None or not os.path.isdir(host):
                return self.E_INVALIDARG
            return self._com_query_new(self._shell_folder_object(path), riid, ppv)
        if method == 'EnumObjects':
            _, _, flags, ppenum = args[:4]
            if not ppenum:
                return self.E_POINTER
            enum = self._enum_idlist_object(self._shell_folder_items(state['path'], flags))
            self._mem_write(ppenum, struct.pack('<I', enum))
            return self.S_OK
        if method == 'CompareIDs':
            first = (self._pidl_path(args[2]) or '').lower()
            second = (self._pidl_path(args[3]) or '').lower()
            return (first > second) - (first < second) & 0xFFFF
        if method == 'GetAttributesOf':
            _, count, apidl, inout = args[:4]
            if not inout:
                return self.E_INVALIDARG
            wanted = struct.unpack('<I', self.emu.uc.mem_read(inout, 4))[0]
            for pidl in self._read_struct(apidl, f'<{count}I') if count else ():
                wanted &= self._shell_item_attributes(self._pidl_file_path(pidl) or '')
            self._mem_write(inout, struct.pack('<I', wanted))
            return self.S_OK
        if method == 'GetUIObjectOf':
            _, hwnd, count, apidl, riid, _, ppv = args[:7]
            if not ppv:
                return self.E_POINTER
            self._mem_write(ppv, struct.pack('<I', 0))
            paths = [self._pidl_file_path(pidl) for pidl in
                     (self._read_struct(apidl, f'<{count}I') if count and apidl else ())]
            if not paths or None in paths:
                return self.E_INVALIDARG
            iid = self._read_guid(riid)
            if iid in (self.IID_IEXTRACTICONA, self.IID_IEXTRACTICONW) and count == 1:
                return self._com_query_new(self._extract_icon_object(paths[0]), riid, ppv)
            if iid not in (self.IID_ICONTEXTMENU, self.IID_ICONTEXTMENU2,
                           self.IID_ICONTEXTMENU3):
                return self.E_NOINTERFACE
            pointers = self._com_new_object(
                [((self.IID_ICONTEXTMENU3, self.IID_ICONTEXTMENU2, self.IID_ICONTEXTMENU,
                   self.IID_IUNKNOWN), self._com_vtable('IContextMenu3', 'context_menu'))],
                {'paths': paths, 'folder': state['path'], 'hwnd': hwnd})
            return self._com_query_new(pointers[self.IID_IUNKNOWN], riid, ppv)
        if method == 'GetDisplayNameOf':
            _, pidl, flags, strret = args[:4]
            path = self._pidl_path(pidl)
            if path is None or not strret:
                return self.E_INVALIDARG
            if path == '':  # The desktop
                path = state['path'] or self._shell_folder(0)
            # SHGDN_FORPARSING without SHGDN_INFOLDER: the full path
            if flags & 0x8000 and not flags & 0x1:
                name = path
            elif self._is_my_computer(path):
                name = self.MY_COMPUTER_NAME
            elif self._drive_display_name(path):
                name = self._drive_display_name(path)
            else:
                name = ntpath.basename(path.rstrip('\\')) or path
                if name.lower().endswith(self.NEVER_SHOW_EXTENSIONS):
                    name = name.rsplit('.', 1)[0]  # Shortcuts never show their extension
            text = self.emu.heap_alloc((len(name) + 1) * 2)
            self._write_text(text, name, True)
            self._mem_write(strret, struct.pack('<II', 0, text))  # STRRET_WSTR
            return self.S_OK
        return self.E_NOTIMPL  # BindToStorage, CreateViewObject, SetNameOf

    # The shell's own verbs of files: (verb, menu text, help text); the offset
    # of a command is its index here
    SHELL_VERBS = [('open', '&Open', 'Opens the selected item.'),
                   ('link', 'Create &Shortcut', 'Creates a shortcut to the selected item.'),
                   ('delete', '&Delete', 'Deletes the selected items.'),
                   ('properties', 'P&roperties', 'Displays the properties of the selected '
                                                 'items.')]

    def _shell_menu_verbs(self, paths):
        """Offsets of the shell verbs that apply to the items (None: separator)"""
        runnable = all(path.lower().endswith(('.exe', '.com', '.lnk')) and
                       os.path.isfile(self.resolve_drive_path(path) or '') for path in paths)
        return ([0, None] if runnable else []) + [1, None, 2, None, 3]

    def _com_context_menu(self, method, wide, args):
        """IContextMenu..3 of files and folders: Open (programs), Create
        Shortcut, Delete and Properties"""
        result = self._com_unknown(method, args)
        if result is not None:
            return result
        state = self.com_objects[args[0]]
        if method == 'QueryContextMenu':
            _, hmenu, index, first, last, flags = args[:6]
            items = self.menus.get(hmenu)
            if items is None:
                return self.E_INVALIDARG
            verbs = self._shell_menu_verbs(state['paths'])
            if flags & 0x1:  # CMF_DEFAULTONLY
                verbs = verbs[:1]
            new, top = [], 0
            for offset in verbs:
                if offset is None:
                    if new and not new[-1]['flags'] & self.MF_SEPARATOR:
                        new.append({'flags': self.MF_SEPARATOR, 'id': 0, 'text': '',
                                    'submenu': 0})
                    continue
                if first + offset > last:
                    continue
                new.append({'flags': self.MF_DEFAULT if not new else 0, 'id': first + offset,
                            'text': self.SHELL_VERBS[offset][1], 'submenu': 0})
                top = max(top, offset + 1)
            if new and new[-1]['flags'] & self.MF_SEPARATOR:
                new.pop()
            index = len(items) if index >= len(items) else index
            self.menus[hmenu] = list(items[:index]) + new + list(items[index:])
            self._menus_changed()
            return top  # MAKE_HRESULT(SEVERITY_SUCCESS, 0, largest offset + 1)
        if method == 'GetCommandString':
            _, offset, kind, _, buffer, size = args[:6]
            if not 0 <= offset < len(self.SHELL_VERBS):
                return self.E_INVALIDARG
            verb, _, help_text = self.SHELL_VERBS[offset]
            if kind & 0x3 == 2:  # GCS_VALIDATEA/W
                return self.S_OK
            text = help_text if kind & 0x3 == 1 else verb  # GCS_HELPTEXT / GCS_VERB
            if not self._com_write_text(buffer, size, text, bool(kind & 0x4)):
                return self.E_INVALIDARG
            return self.S_OK
        if method == 'InvokeCommand':
            return self._shell_invoke(state, args[1])
        if method == 'HandleMenuMsg2' and args[4]:
            self._mem_write(args[4], struct.pack('<I', 0))
        return self.S_OK  # HandleMenuMsg(2): nothing is owner-drawn

    def _shell_invoke(self, state, info):
        """IContextMenu::InvokeCommand: CMINVOKECOMMANDINFO(EX) names the
        command by its offset or by its verb"""
        size, mask, hwnd, verb_ptr = self._read_struct(info, '<4I')
        if mask & 0x4000 and size >= 0x3C:  # CMIC_MASK_UNICODE: CMINVOKECOMMANDINFOEX
            verb_w = self._read_struct(info + 40, '<I')[0]
            if verb_w >> 16:
                verb_ptr, wide = verb_w, True
            else:
                wide = False
        else:
            wide = False
        if verb_ptr >> 16:
            verb = self._read_text(verb_ptr, wide).lower()
        else:
            verb = self.SHELL_VERBS[verb_ptr][0] if verb_ptr < len(self.SHELL_VERBS) else ''
        paths = state['paths']
        log.info(f"IContextMenu::InvokeCommand(\"{verb}\", {paths})")
        if verb == 'open':
            for path in paths:
                code, _ = self._shell_execute('open', path, '', ntpath.dirname(path), hwnd)
                if code <= 32:
                    return self.E_FAIL
            return self.S_OK
        if verb == 'link':
            return self._shell_create_shortcuts(paths)
        if verb == 'delete':
            hosts = [self.resolve_drive_path(path) for path in paths]
            if None in hosts or not all(os.path.exists(host) for host in hosts):
                return self.HRESULT_FILE_NOT_FOUND
            if self._write_protected(*hosts):
                return 0x80070005  # E_ACCESSDENIED: on the CD-ROM D:
            if not mask & 0x400 and not self._confirm_delete(paths, hosts):  # CMIC_MASK_FLAG_NO_UI
                return self.S_OK  # Not an error (the host would report one): nothing is done
            try:
                for host in hosts:
                    shutil.rmtree(host) if os.path.isdir(host) else os.remove(host)
            except OSError as e:
                log.warning(f"Delete failed: {e}")
                return self.E_FAIL
            return self.S_OK
        if verb == 'properties':
            for path in paths:
                self._shell_properties(path)
            return self.S_OK
        return self.E_INVALIDARG

    def _shell_create_shortcuts(self, paths):
        """'Create Shortcut': "Shortcut to <name>.lnk" next to each item"""
        for path in paths:
            folder, name = ntpath.split(path.rstrip('\\'))
            is_file = os.path.isfile(self.resolve_drive_path(path) or '')
            base = f"Shortcut to {ntpath.splitext(name)[0] if is_file else name}"
            target, number = ntpath.join(folder, base + '.lnk'), 2
            while os.path.exists(self.resolve_drive_path(target) or ''):
                target, number = ntpath.join(folder, f"{base} ({number}).lnk"), number + 1
            host = self.resolve_drive_path(target)
            if host is None or self._write_protected(host):
                continue
            state = {'path': path, 'description': '', 'workdir': folder, 'arguments': '',
                     'relative': '', 'icon': '', 'icon_index': 0, 'show': 1, 'hotkey': 0}
            try:
                with open(host, 'wb') as f:
                    f.write(self._shell_link_data(state))
            except (OSError, TypeError) as e:
                log.warning(f"Create Shortcut failed: {e}")
                return self.E_FAIL
        return self.S_OK

    def _shell_properties(self, path):
        """'Properties': the item's type, location, size, times and attributes"""
        host = self.resolve_drive_path(path)
        try:
            info = os.stat(host)
        except (OSError, TypeError):
            return
        name = ntpath.basename(path.rstrip('\\')) or path
        folder = os.path.isdir(host)
        lines = [f"Type: {'File Folder' if folder else self._shell_type_name(name)}",
                 f"Location: {ntpath.dirname(path.rstrip(chr(92))) or path}"]
        if folder:
            files = dirs = size = 0
            for root, subdirs, names in os.walk(host):
                dirs += len(subdirs)
                files += len(names)
                for file in names:
                    try:
                        size += os.path.getsize(os.path.join(root, file))
                    except OSError:
                        pass
            lines.append(f"Size: {self._shell_size(size)}")
            lines.append(f"Contains: {files:,} Files, {dirs:,} Folders")
        else:
            lines.append(f"Size: {self._shell_size(info.st_size)}")
        stamp = '%A, %B %d, %Y, %I:%M:%S %p'
        lines.append('')
        lines.append(f"Modified: {datetime.datetime.fromtimestamp(info.st_mtime).strftime(stamp)}")
        lines.append(f"Accessed: {datetime.datetime.fromtimestamp(info.st_atime).strftime(stamp)}")
        lines.append('')
        attributes = [label for flag, label in ((self._host_read_only(host), 'Read-only'),
                                                (name.startswith('.'), 'Hidden'))
                      if flag]
        lines.append(f"Attributes: {', '.join(attributes) or 'None'}")
        self._message_box('\n'.join(lines), f"{name} Properties", 0x40)  # MB_ICONINFORMATION

    @staticmethod
    def _shell_size(size):
        for unit, scale in (('GB', 1 << 30), ('MB', 1 << 20), ('KB', 1 << 10)):
            if size >= scale:
                return f"{size / scale:.2f} {unit} ({size:,} bytes)"
        return f"{size:,} bytes"

    @staticmethod
    def _shell_type_name(name):
        extension = ntpath.splitext(name)[1][1:].upper()
        return {'EXE': 'Application', 'DLL': 'Application Extension', 'TXT': 'Text Document',
                'LNK': 'Shortcut'}.get(extension, f"{extension} File" if extension else 'File')

    def _com_write_text(self, address, size, text, wide):
        """Copy text to a caller buffer of size characters (truncated)"""
        if not address or not size:
            return False
        units = self._text_units(text, wide)[:size - 1]
        return self._write_units(address, units, wide)

    # Fields of the IShellLink string getters/setters
    SHELL_LINK_TEXT_FIELDS = {'Description': 'description', 'WorkingDirectory': 'workdir',
                              'Arguments': 'arguments'}

    def _com_shell_link(self, method, wide, args):
        """IShellLinkA/W methods"""
        result = self._com_unknown(method, args)
        if result is not None:
            return result
        state = self.com_objects[args[0]]
        field = self.SHELL_LINK_TEXT_FIELDS.get(method[3:])
        if field and method.startswith('Get'):
            return self.S_OK if self._com_write_text(args[1], args[2], state[field],
                                                     wide) else self.E_INVALIDARG
        if field:
            state[field] = self._read_text(args[1], wide) if args[1] else ''
            state['dirty'] = True
            return self.S_OK
        if method == 'GetPath':
            if not self._com_write_text(args[1], args[2], state['path'], wide):
                return self.E_INVALIDARG
            if args[3]:  # WIN32_FIND_DATA of the target
                self._mem_write(args[3], bytes(592 if wide else 320))
                path = self.resolve_drive_path(state['path']) if state['path'] else None
                if path and os.path.exists(path):
                    attributes = 0x10 if os.path.isdir(path) else 0x20
                    self._mem_write(args[3], struct.pack('<I', attributes))
                    self._com_write_text(args[3] + 44, 260, ntpath.basename(state['path']),
                                         wide)
            return self.S_OK if state['path'] else self.S_FALSE
        if method == 'SetPath':
            state['path'] = self._read_text(args[1], wide) if args[1] else ''
            state['dirty'] = True
            return self.S_OK
        if method == 'GetIDList':
            if not args[1]:
                return self.E_POINTER
            pidl = self._make_pidl(state['path']) if state['path'] else 0
            self._mem_write(args[1], struct.pack('<I', pidl))
            return self.S_OK if pidl else self.S_FALSE
        if method == 'SetIDList':
            path = self._pidl_file_path(args[1])
            if path is None:
                return self.E_INVALIDARG
            state['path'], state['dirty'] = path, True
            return self.S_OK
        if method == 'GetHotkey':
            return self.S_OK if self._mem_write(args[1], struct.pack(
                '<H', state['hotkey'])) else self.E_POINTER
        if method == 'SetHotkey':
            state['hotkey'], state['dirty'] = args[1] & 0xFFFF, True
            return self.S_OK
        if method == 'GetShowCmd':
            return self.S_OK if self._mem_write(args[1], struct.pack(
                '<i', state['show'])) else self.E_POINTER
        if method == 'SetShowCmd':
            state['show'], state['dirty'] = args[1], True
            return self.S_OK
        if method == 'GetIconLocation':
            if not self._com_write_text(args[1], args[2], state['icon'], wide):
                return self.E_INVALIDARG
            self._mem_write(args[3], struct.pack('<i', state['icon_index']))
            return self.S_OK
        if method == 'SetIconLocation':
            state['icon'] = self._read_text(args[1], wide) if args[1] else ''
            state['icon_index'] = struct.unpack('<i', struct.pack('<I', args[2]))[0]
            state['dirty'] = True
            return self.S_OK
        if method == 'SetRelativePath':
            state['relative'] = self._read_text(args[1], wide) if args[1] else ''
            state['dirty'] = True
            return self.S_OK
        return self.S_OK  # Resolve: the target is not searched for

    def _shell_link_data(self, state):
        """Shell link (.lnk, MS-SHLLINK) file contents: header, LinkInfo with the
        local target path, string data"""
        flags = 0x2 | 0x80  # HasLinkInfo | IsUnicode
        strings = b''
        for flag, text in ((0x4, state['description']), (0x8, state['relative']),
                           (0x10, state['workdir']), (0x20, state['arguments']),
                           (0x40, state['icon'])):
            if text:
                flags |= flag
                data = text.encode('utf-16-le')
                strings += struct.pack('<H', len(data) // 2) + data
        target = self.full_windows_path(state['path']) or state['path']
        host = self.resolve_drive_path(target) if target else None
        attributes, size, filetime = 0, 0, 0
        if host and os.path.exists(host):
            info = os.stat(host)
            attributes = 0x10 if os.path.isdir(host) else 0x20
            size = info.st_size & 0xFFFFFFFF if not os.path.isdir(host) else 0
            filetime = int((info.st_mtime + 11644473600) * 10000000)
        header = struct.pack('<I16sIIQQQIiIHHII', 0x4C, self._guid_bytes(self.CLSID_SHELLLINK),
                             flags, attributes, filetime, filetime, filetime, size,
                             state['icon_index'], state['show'], state['hotkey'], 0, 0, 0)
        volume = struct.pack('<IIII', 0x11, 3, 0x1E3A5C07, 0x10) + b'\x00'  # DRIVE_FIXED
        base = target.encode(config.ANSI_CODEPAGE, errors='replace') + b'\x00'
        link_info = struct.pack('<7I', 0x1C + len(volume) + len(base) + 1, 0x1C, 1, 0x1C,
                                0x1C + len(volume), 0, 0x1C + len(volume) + len(base))
        link_info += volume + base + b'\x00'
        return header + link_info + strings + b'\x00' * 4

    @staticmethod
    def _load_shell_link(state, data):
        """Fill a shell link's state from .lnk file contents; False if not one"""
        link = resources.parse_shell_link(data)
        if link is None:
            return False
        state.update(link)
        state['dirty'] = False
        return True

    def _com_persist_file(self, method, wide, args):
        """IPersistFile methods (file names are always UTF-16)"""
        result = self._com_unknown(method, args)
        if result is not None:
            return result
        state = self.com_objects[args[0]]
        if method == 'GetClassID':
            return self.S_OK if self._mem_write(args[1], self._guid_bytes(
                self.CLSID_SHELLLINK)) else self.E_POINTER
        if method == 'IsDirty':
            return self.S_OK if state['dirty'] else self.S_FALSE
        if method == 'SaveCompleted':
            return self.S_OK
        if method == 'GetCurFile':
            name = state['file'] or '*.lnk'
            address = self._alloc_units(self._text_units(name, True), True)
            self._mem_write(args[1], struct.pack('<I', address))
            return self.S_OK if state['file'] else self.S_FALSE
        filename = self.read_wide_string(args[1]) if args[1] else state['file']
        if not filename:
            return self.E_INVALIDARG
        path = self.resolve_drive_path(filename)
        if path is None:
            return 0x80070005  # E_ACCESSDENIED
        if method == 'Load':
            try:
                with open(path, 'rb') as f:
                    data = f.read()
            except FileNotFoundError:
                return 0x80070002  # HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)
            except OSError:
                return 0x80070005
            if not self._load_shell_link(state, data):
                return self.E_FAIL
            state['file'] = filename
            log.debug(f"IPersistFile::Load(\"{filename}\") -> \"{state['path']}\"")
            return self.S_OK
        # Save
        if self._write_protected(path):
            return 0x80070005  # E_ACCESSDENIED: on the CD-ROM D:
        try:
            with open(path, 'wb') as f:
                f.write(self._shell_link_data(state))
        except FileNotFoundError:
            return 0x80070003  # HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND)
        except OSError:
            return 0x80070005
        log.info(f"Shell link saved: \"{filename}\" -> \"{state['path']}\"")
        if args[2] or not state['file']:  # fRemember
            state['file'] = filename
        state['dirty'] = False
        return self.S_OK

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

    def _ensure_adjust_fdiv_addr(self):
        """Memory of the _adjust_fdiv variable: 0, no Pentium FDIV bug workaround"""
        if not self._crt_static.get('_adjust_fdiv'):
            self._crt_static['_adjust_fdiv'] = self.emu.heap_alloc(4)
            self._mem_write(self._crt_static['_adjust_fdiv'], struct.pack('<I', 0))
        return self._crt_static['_adjust_fdiv']

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
        self.crt_app_type = app_type
        return 0

    def _query_app_type(self, args):
        """_query_app_type emulation - the __set_app_type value (default: console)"""
        return getattr(self, 'crt_app_type', 1)  # _crt_console_app

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

        self._run_initializers(pfbegin, pfend, stop_on_error=False)
        return 0

    def _run_initializers(self, pfbegin, pfend, stop_on_error):
        current = pfbegin
        while current < pfend and not self.emu.stop_emulation:
            try:
                func_ptr = struct.unpack('<I', self.emu.uc.mem_read(current, 4))[0]
            except UcError:
                break
            current += 4
            if func_ptr in (0, 0xFFFFFFFF):
                continue
            log.debug(f"  _initterm: calling 0x{func_ptr:08x}")
            result = self.emu.call_callback(func_ptr, [])
            if stop_on_error and result != 0:
                return result
        return 0

    def _initterm_e(self, args):
        """_initterm_e emulation - stops at the first initializer returning non-zero"""
        log.debug(f"_initterm_e(0x{args[0]:08x}, 0x{args[1]:08x})")
        return self._run_initializers(args[0], args[1], stop_on_error=True)

    @staticmethod
    def split_command_line(command_line):
        """Split a command line into argv like the Microsoft C runtime:
        argv[0] ends at the next quote (if quoted) or whitespace; in the
        arguments 2n backslashes + '"' give n backslashes and toggle quoting,
        2n+1 backslashes + '"' give n backslashes and a '"', other
        backslashes are literal, and "" inside quotes is a '"'."""
        argv = []
        text = command_line
        i, n = 0, len(text)
        # Program name: no escapes
        if text.startswith('"'):
            end = text.find('"', 1)
            end = n if end < 0 else end
            argv.append(text[1:end])
            i = end + 1
        else:
            while i < n and text[i] not in ' \t':
                i += 1
            argv.append(text[:i])
        while True:
            while i < n and text[i] in ' \t':
                i += 1
            if i >= n:
                break
            arg = []
            in_quotes = False
            while i < n and (in_quotes or text[i] not in ' \t'):
                if text[i] == '\\':
                    start = i
                    while i < n and text[i] == '\\':
                        i += 1
                    count = i - start
                    if i < n and text[i] == '"':
                        arg.append('\\' * (count // 2))
                        if count % 2:
                            arg.append('"')
                            i += 1
                    else:
                        arg.append('\\' * count)
                elif text[i] == '"':
                    if in_quotes and i + 1 < n and text[i + 1] == '"':
                        arg.append('"')
                        i += 2
                    else:
                        in_quotes = not in_quotes
                        i += 1
                else:
                    arg.append(text[i])
                    i += 1
            argv.append(''.join(arg))
        return argv

    def _argv_array(self, wide):
        """Address of the NULL-terminated argv (or wargv) array of the
        command line (built once)"""
        attr = '_wargv_addr' if wide else '_argv_addr'
        if getattr(self, attr) == 0:
            argv = self.split_command_line(self.windows_command_line())
            pointers = []
            for arg in argv:
                units = self._text_units(arg, wide) + [0]
                address = self.emu.heap_alloc(len(units) * (2 if wide else 1))
                self._write_units(address, units, wide, terminate=False)
                pointers.append(address)
            array = self.emu.heap_alloc(4 * (len(pointers) + 1))
            self._mem_write(array, struct.pack(f'<{len(pointers) + 1}I', *pointers, 0))
            setattr(self, attr, array)
            self._argc_value = len(argv)
        return getattr(self, attr)

    def _argc_count(self):
        self._argv_array(False)
        return self._argc_value

    def api__getmainargs(self, args):
        """__getmainargs emulation - Returns argc, argv, environ"""
        p_argc = args[0]
        p_argv = args[1]
        p_env = args[2]
        do_wildcard = args[3]
        # startinfo = args[4]  # Optional

        log.debug(f"__getmainargs(0x{p_argc:08x}, 0x{p_argv:08x}, 0x{p_env:08x}, {do_wildcard})")

        argv = self._argv_array(False)
        self.emu.uc.mem_write(p_argc, struct.pack('<I', self._argc_count()))
        self.emu.uc.mem_write(p_argv, struct.pack('<I', argv))
        # The environment: the current _environ
        self.emu.uc.mem_write(p_env, struct.pack(
            '<I', self._read_u32(self._ensure_env_ptr('_environ_ptr_addr'))))
        return 0

    def api__wgetmainargs(self, args):
        """__wgetmainargs emulation - wide char version"""
        p_argc = args[0]
        p_argv = args[1]
        p_env = args[2]
        do_wildcard = args[3]

        log.debug(f"__wgetmainargs(0x{p_argc:08x}, 0x{p_argv:08x}, 0x{p_env:08x}, {do_wildcard})")

        wargv = self._argv_array(True)
        self.emu.uc.mem_write(p_argc, struct.pack('<I', self._argc_count()))
        self.emu.uc.mem_write(p_argv, struct.pack('<I', wargv))
        self.emu.uc.mem_write(p_env, struct.pack(
            '<I', self._read_u32(self._ensure_env_ptr('_wenviron_ptr_addr', wide=True))))
        return 0

    def api__p___argc(self, args):
        """__p___argc emulation"""
        if self._argc == 0:
            self._argc = self.emu.heap_alloc(4)
            self.emu.uc.mem_write(self._argc, struct.pack('<I', self._argc_count()))
        log.debug(f"__p___argc() -> 0x{self._argc:08x}")
        return self._argc

    def _argv_variable(self, wide):
        """Address of the __argv (or __wargv) variable (one per process, so a
        program changing it sees its change everywhere)"""
        attr = '_wargv_var' if wide else '_argv_var'
        if not getattr(self, attr, 0):
            variable = self.emu.heap_alloc(4)
            self.emu.uc.mem_write(variable, struct.pack('<I', self._argv_array(wide)))
            setattr(self, attr, variable)
        return getattr(self, attr)

    def api__p___argv(self, args):
        """__p___argv emulation - address of __argv"""
        address = self._argv_variable(False)
        log.debug(f"__p___argv() -> 0x{address:08x}")
        return address

    def api__p___wargv(self, args):
        """__p___wargv emulation - address of __wargv"""
        address = self._argv_variable(True)
        log.debug(f"__p___wargv() -> 0x{address:08x}")
        return address

    def _amsg_exit(self, args):
        """_amsg_exit emulation - runtime error message and exit"""
        errnum = args[0]
        log.error(f"_amsg_exit({errnum}) - Runtime error!")
        self._set_exit_code(255)
        self.flush_std_streams()
        self.emu.stop_emulation = True
        return 0

    def _cexit(self, args):
        """_cexit emulation - run exit handlers without terminating"""
        log.debug("_cexit()")
        self.run_exit_handlers()
        self.flush_std_streams()
        return 0

    def _exit(self, args):
        """_exit emulation - terminate without running exit handlers"""
        code = args[0]
        log.debug(f"_exit({code})")
        self._set_exit_code(code)
        self.flush_std_streams()
        self.emu.detach_process()  # Ends with ExitProcess: the DLLs' DllMain
        self.emu.stop_emulation = True
        return 0

    def exit(self, args):
        """exit emulation - run atexit handlers, flush, terminate"""
        code = args[0]
        log.debug(f"exit({code})")
        self.run_exit_handlers()
        self._set_exit_code(code)
        self.flush_std_streams()
        self.emu.detach_process()  # Ends with ExitProcess: the DLLs' DllMain
        self.flush_std_streams()
        self.emu.stop_emulation = True
        return 0

    def _XcptFilter(self, args):
        """_XcptFilter emulation - the CRT's last chance filter lets unhandled
        exceptions through (the emulator reports them)"""
        log.debug("_XcptFilter()")
        return 0  # EXCEPTION_CONTINUE_SEARCH

    def _except_handler3(self, args):
        """_except_handler3(record, frame, context, dispatcher) emulation - when
        called directly (the exception dispatcher handles its frames itself)"""
        record, node, context = args[0], args[1], args[2]
        return self._frame_handler(record, node, context, lambda exc: (
            self._seh3_handle(node, exc) if exc else self._seh3_unwind_to(node, -1)))

    def api__CxxFrameHandler3(self, args):
        """__CxxFrameHandler emulation - called directly (not by the exception
        dispatcher, which handles C++ frames itself): continue the search"""
        return 1  # ExceptionContinueSearch

    # ---------- Type libraries (oleaut32: LoadTypeLib, RegisterTypeLib) ----------

    IID_ITYPELIB = '00020402-0000-0000-c000-000000000046'
    TYPE_E_CANTLOADLIBRARY = 0x80029C4A

    COM_INTERFACES.update({
        'type_lib': [
            ('QueryInterface', 3), ('AddRef', 1), ('Release', 1), ('GetTypeInfoCount', 1),
            ('GetTypeInfo', 3), ('GetTypeInfoType', 3), ('GetTypeInfoOfGuid', 3),
            ('GetLibAttr', 2), ('GetTypeComp', 2), ('GetDocumentation', 6), ('IsName', 4),
            ('FindName', 6), ('ReleaseTLibAttr', 2)],
    })

    def _type_library_attributes(self, name):
        """Library attributes of a type library file ("FILE.DLL\\2": its
        TYPELIB resource 2); None if there is no such file"""
        candidates = [(name, None)]
        head, _, tail = name.rpartition('\\')
        if head and tail.isdigit():
            candidates.append((head, int(tail)))
        for candidate, index in candidates:
            full = self.full_windows_path(candidate)
            host = self.resolve_drive_path(full) if full else None
            if host and os.path.isfile(host):
                attributes = type_library_attributes(type_library_data(host, index))
                return attributes or {'guid': '00000000-0000-0000-0000-000000000000',
                                      'lcid': 0, 'syskind': 1, 'major': 0, 'minor': 0,
                                      'flags': 0, 'name': '', 'doc': ''}
        return None

    def LoadTypeLib(self, args):
        """LoadTypeLib(szFile, pptlib) - an ITypeLib object with the library's
        attributes but no type information: enough for setup programs and
        DllRegisterServer functions that register libraries"""
        name = self.read_wide_string(args[0]) if args[0] else ''
        if args[1]:
            self._mem_write(args[1], struct.pack('<I', 0))
        attributes = self._type_library_attributes(name) if name else None
        if attributes is None:
            builtin = self._builtin_typelib(name)
            if builtin is not None:  # OLE Automation (stdole32.tlb) comes with oleaut32
                return self.S_OK if self._mem_write(args[1], struct.pack(
                    '<I', self._new_typelib_object(builtin, name))) else self.E_POINTER
            log.debug(f"LoadTypeLib(\"{name}\"): not found")
            return self.TYPE_E_CANTLOADLIBRARY
        pointers = self._com_new_object(
            [((self.IID_ITYPELIB, self.IID_IUNKNOWN), self._com_vtable('ITypeLib', 'type_lib'))],
            {'file': name, 'attr': None, 'library': attributes})
        log.debug(f"LoadTypeLib(\"{name}\") -> {{{attributes['guid']}}} "
                  f"{attributes['major']}.{attributes['minor']}")
        return self.S_OK if self._mem_write(args[1], struct.pack(
            '<I', pointers[self.IID_ITYPELIB])) else self.E_POINTER

    def LoadTypeLibEx(self, args):
        """LoadTypeLibEx(szFile, regkind, pptlib)"""
        return self.LoadTypeLib([args[0], args[2]])

    @registry_locked
    def RegisterTypeLib(self, args):
        """RegisterTypeLib(ptlib, szFullPath, szHelpDir) - enters the library
        in HKEY_CLASSES_ROOT\\TypeLib\\{LIBID}\\major.minor"""
        state = self.com_objects.get(args[0])
        if state is None or 'library' not in state:
            return self.E_INVALIDARG
        library = state['library']
        path = self.read_wide_string(args[1]) if args[1] else state['file']
        help_dir = self.read_wide_string(args[2]) if args[2] else ''
        version = f"TypeLib\\{{{library['guid'].upper()}}}\\{library['major']}.{library['minor']:x}"
        values = [(version, '', library.get('doc') or library['name']),
                  (f"{version}\\{library['lcid']:x}\\win32", '', path),
                  (f"{version}\\FLAGS", '', str(library['flags'])),
                  (f"{version}\\HELPDIR", '', help_dir)]
        for key, value_name, text in values:
            node, _ = self._registry_walk(self.HKEY_CLASSES_ROOT, key, create=True)
            if node is None:
                return 0x80029C83  # TYPE_E_REGISTRYACCESS
            node['values'][value_name.lower()] = {'name': value_name, 'type': 1,
                                                  'data': text + '\x00'}
        self._save_registry()
        log.debug(f"RegisterTypeLib: {version} -> \"{path}\"")
        return self.S_OK

    def UnRegisterTypeLib(self, args):
        return self.S_OK

    def QueryPathOfRegTypeLib(self, args):
        """QueryPathOfRegTypeLib(guid, major, minor, lcid, lpbstrPath) - the
        file HKEY_CLASSES_ROOT\\TypeLib\\{LIBID}\\major.minor\\lcid\\win32
        names, as a BSTR. Like oleaut32, a higher minor version of the same
        major one will do, and the language falls back to its primary
        language, then to the neutral one (0)."""
        guid = self._read_guid(args[0])
        major, minor, lcid, out = args[1] & 0xFFFF, args[2] & 0xFFFF, args[3], args[4]
        if out:
            self._mem_write(out, struct.pack('<I', 0))
        library, _ = self._registry_walk(self.HKEY_CLASSES_ROOT, f"TypeLib\\{{{guid}}}")
        if not out:
            return 0x8002801D  # TYPE_E_LIBNOTREGISTERED
        versions = []
        for key in (library['keys'].values() if library is not None else ()):
            text_major, _, text_minor = key['name'].partition('.')
            try:
                version = (int(text_major, 16), int(text_minor or '0', 16))
            except ValueError:
                continue
            if version[0] == major and version[1] >= minor:
                versions.append((version, key))
        for _version, key in sorted(versions, key=lambda item: item[0][1]):
            for language in (lcid, lcid & 0x3FF, 0):
                node = key['keys'].get(f"{language:x}")
                win32 = node['keys'].get('win32') if node else None
                value = win32['values'].get('') if win32 else None
                if value is not None:
                    path = str(value['data']).rstrip('\x00')
                    log.debug(f"QueryPathOfRegTypeLib({{{guid}}} {major}.{minor}) -> \"{path}\"")
                    bstr = self._alloc_bstr(path.encode('utf-16-le'))
                    return self.S_OK if self._mem_write(out, struct.pack('<I', bstr)) \
                        else self.E_POINTER
        builtin = self._builtin_typelib_path(guid, major)
        if builtin:
            bstr = self._alloc_bstr(builtin.encode('utf-16-le'))
            return self.S_OK if self._mem_write(out, struct.pack('<I', bstr)) else self.E_POINTER
        log.debug(f"QueryPathOfRegTypeLib({{{guid}}} {major}.{minor}): not registered")
        return 0x8002801D  # TYPE_E_LIBNOTREGISTERED

    def LoadRegTypeLib(self, args):
        """LoadRegTypeLib(guid, major, minor, lcid, pptlib) - LoadTypeLib of
        the file the registry names for the library (QueryPathOfRegTypeLib)"""
        if args[4]:
            self._mem_write(args[4], struct.pack('<I', 0))
        cell = self.emu.heap_alloc(4)
        try:
            result = self.QueryPathOfRegTypeLib(list(args[:4]) + [cell])
            if result != self.S_OK:
                return result
            bstr = struct.unpack('<I', self.emu.uc.mem_read(cell, 4))[0]
            try:
                return self.LoadTypeLib([bstr, args[4]])
            finally:
                self.emu.heap_free(bstr - 4)
        finally:
            self.emu.heap_free(cell)

    def _com_type_lib(self, method, wide, args):
        """ITypeLib methods: the types of a library typelib_reader reads (see
        TypeInfoMixin), else a library without type information"""
        result = self._com_unknown(method, args)
        if result is not None:
            return result
        state = self.com_objects[args[0]]
        result = self._typelib_model_method(method, state, args)
        if result is not None:
            return result
        if method == 'GetTypeInfoCount':
            return 0
        if method == 'GetLibAttr':  # TLIBATTR: GUID, lcid, syskind (SYS_WIN32), version, flags
            if state['attr'] is None:
                library = state['library']
                state['attr'] = self.emu.heap_alloc(32)
                self._mem_write(state['attr'], self._guid_bytes(library['guid']) + struct.pack(
                    '<IIHHH', library['lcid'], library['syskind'], library['major'],
                    library['minor'], library['flags']))
            return self.S_OK if self._mem_write(args[1], struct.pack(
                '<I', state['attr'])) else self.E_POINTER
        if method == 'ReleaseTLibAttr':
            return self.S_OK
        if method == 'IsName':
            if args[3]:
                self._mem_write(args[3], struct.pack('<i', 0))
            return self.S_OK
        if method in ('GetTypeInfo', 'GetTypeInfoType', 'GetTypeInfoOfGuid'):
            return 0x8002802B  # TYPE_E_ELEMENTNOTFOUND
        return self.E_NOTIMPL

    # ---------- ole32: classes of files, automatic conversion ----------

    MK_E_CANTOPENFILE = 0x800401EA
    MK_E_INVALIDEXTENSION = 0x800401E6
    ZERO_GUID = '00000000-0000-0000-0000-000000000000'

    def _registry_default_text(self, key):
        """Default value text of HKEY_CLASSES_ROOT\\key ('' if none)"""
        node, _ = self._registry_walk(self.HKEY_CLASSES_ROOT, key)
        value = node['values'].get('') if node else None
        data = value.get('data') if value else ''
        return data.rstrip('\x00') if isinstance(data, str) else ''

    @staticmethod
    def _storage_clsid(data):
        """CLSID of the root storage of a compound file (OLE structured
        storage), None if data is not one"""
        if data[:8] != b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1' or len(data) < 512:
            return None
        sector_size = 1 << struct.unpack_from('<H', data, 0x1E)[0]
        first_directory = struct.unpack_from('<I', data, 0x30)[0]
        root = 512 + first_directory * sector_size if sector_size >= 512 else None
        if root is None or root + 0x60 > len(data):
            return None
        clsid = data[root + 0x50:root + 0x60]
        return guid_text(clsid)

    @registry_locked
    def GetClassFile(self, args):
        """GetClassFile(szFilename, pclsid) - the CLSID of a compound file's
        root storage, else the class registered for its extension"""
        name = self.read_wide_string(args[0]) if args[0] else ''
        host = self.resolve_drive_path(name) if name else None
        self._mem_write(args[1], self._guid_bytes(self.ZERO_GUID))
        try:
            with open(host, 'rb') as f:
                header = f.read(0x10000)
        except (OSError, TypeError):
            return self.MK_E_CANTOPENFILE
        clsid = self._storage_clsid(header)
        if clsid is None or clsid == self.ZERO_GUID:
            extension = ntpath.splitext(name)[1]
            prog_id = self._registry_default_text(extension) if extension else ''
            text = self._registry_default_text(prog_id + '\\CLSID') if prog_id else ''
            clsid = text.strip('{}').lower() if len(text.strip('{}')) == 36 else None
        if clsid is None:
            return self.MK_E_INVALIDEXTENSION
        self._mem_write(args[1], self._guid_bytes(clsid))
        return self.S_OK

    @registry_locked
    def OleSetAutoConvert(self, args):
        """OleSetAutoConvert(clsidOld, clsidNew) - HKEY_CLASSES_ROOT\\CLSID\\
        {old}\\AutoConvertTo; a NULL new class removes it"""
        old = self._read_guid(args[0])
        if not old:
            return self.E_INVALIDARG
        key = f'CLSID\\{{{old.upper()}}}'
        node, _ = self._registry_walk(self.HKEY_CLASSES_ROOT, key, create=True)
        if node is None:
            return 0x80040152  # REGDB_E_WRITEREGDB
        auto = node['keys'].get('autoconvertto')
        if not args[1]:
            if auto is not None:
                self._mark_deleted(auto)
                del node['keys']['autoconvertto']
            self._save_registry()
            return self.S_OK
        new = self._read_guid(args[1])
        auto, _ = self._registry_walk(self.HKEY_CLASSES_ROOT, key + '\\AutoConvertTo', create=True)
        auto['values'][''] = {'name': '', 'type': 1, 'data': f'{{{new.upper()}}}\x00'}
        self._save_registry()
        return self.S_OK

    @registry_locked
    def OleGetAutoConvert(self, args):
        """OleGetAutoConvert(clsidOld, pClsidNew)"""
        old = self._read_guid(args[0])
        text = self._registry_default_text(f'CLSID\\{{{old.upper()}}}\\AutoConvertTo')
        clsid = text.strip('{}').lower()
        if len(clsid) != 36:
            self._mem_write(args[1], bytes(self.emu.uc.mem_read(args[0], 16)))
            return 0x80040155  # REGDB_E_KEYMISSING
        self._mem_write(args[1], self._guid_bytes(clsid))
        return self.S_OK
