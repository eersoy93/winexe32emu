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

"""WinAPIHandler mixin: ADVAPI32 registry: one tree shared by the emulated programs"""

import os
import struct
import threading
import time
import json
from functools import wraps

from unicorn import *

from .. import config, winapi
from ..config import C_DRIVE_PATH, PROGRAM_FILES_FOLDER
from ..logger import log


def registry_locked(method):
    """Run a registry API under the lock of the registry the emulated
    programs share (they run on their own host threads)"""
    @wraps(method)
    def wrapper(self, *args, **kwargs):
        with winapi.WinAPIHandler._registry_lock:
            return method(self, *args, **kwargs)
    return wrapper


class RegistryMixin:
    """ADVAPI32 registry: one tree shared by the emulated programs"""

    # ADVAPI32.DLL APIs - registry: one tree shared by the emulated programs
    # (like the machine's registry), saved to REGISTRY_FILE after each change;
    # volatile keys (REG_OPTION_VOLATILE) are not saved

    # Predefined keys (HKEY_CLASSES_ROOT ... HKEY_CURRENT_CONFIG)
    REGISTRY_ROOTS = {0x80000000: 'HKEY_CLASSES_ROOT', 0x80000001: 'HKEY_CURRENT_USER',
                      0x80000002: 'HKEY_LOCAL_MACHINE', 0x80000003: 'HKEY_USERS',
                      0x80000005: 'HKEY_CURRENT_CONFIG'}
    HKEY_CLASSES_ROOT = 0x80000000  # a view of HKEY_LOCAL_MACHINE\SOFTWARE\Classes
    REGISTRY_FILE = os.path.join(C_DRIVE_PATH, 'Windows', 'System32', 'config',
                                 'registry.json')
    _registry_lock = threading.RLock()
    _shared_registry = None  # predefined HKEY -> root key node

    @classmethod
    def _shared_registry_roots(cls):
        """The registry tree: the saved one, or the default keys of Windows"""
        with cls._registry_lock:
            if cls._shared_registry is None:
                roots = cls._default_registry()
                saved = cls._load_registry_file()
                for hkey, name in cls.REGISTRY_ROOTS.items():
                    if hkey != cls.HKEY_CLASSES_ROOT and name in saved:
                        roots[hkey] = saved[name]
                node = roots[0x80000002]
                for part in ('SOFTWARE', 'Classes'):
                    node = node['keys'].setdefault(part.lower(), cls._new_registry_key(part))
                roots[cls.HKEY_CLASSES_ROOT] = node
                cls._shared_registry = roots
            return cls._shared_registry

    @classmethod
    def _default_registry(cls):
        roots = {hkey: cls._new_registry_key(name) for hkey, name in cls.REGISTRY_ROOTS.items()}
        for hkey, name in ((0x80000001, 'Software'), (0x80000002, 'SOFTWARE')):
            roots[hkey]['keys'][name.lower()] = cls._new_registry_key(name)
        # Default values of a Windows installation
        node = roots[0x80000002]
        for part in ('SOFTWARE', 'Microsoft', 'Windows', 'CurrentVersion'):
            node = node['keys'].setdefault(part.lower(), cls._new_registry_key(part))
        for name, folder in (('ProgramFilesDir', PROGRAM_FILES_FOLDER),
                             ('CommonFilesDir', PROGRAM_FILES_FOLDER + '\\Common Files')):
            node['values'][name.lower()] = {'name': name, 'type': 1, 'data': folder + '\x00'}
        return roots

    @classmethod
    def _registry_to_json(cls, node):
        values = []
        for value in node['values'].values():
            item = {'name': value['name'], 'type': value['type']}
            if isinstance(value['data'], str):
                item['text'] = value['data']
            else:
                item['hex'] = bytes(value['data']).hex()
            values.append(item)
        return {'name': node['name'], 'time': node['time'], 'values': values,
                'keys': [cls._registry_to_json(child) for child in node['keys'].values()
                         if not child.get('volatile')]}

    @classmethod
    def _registry_from_json(cls, item):
        node = cls._new_registry_key(str(item['name']))
        node['time'] = int(item.get('time', node['time']))
        for value in item.get('values', []):
            data = value['text'] if 'text' in value else bytes.fromhex(value.get('hex', ''))
            node['values'][value['name'].lower()] = {
                'name': value['name'], 'type': int(value['type']), 'data': data}
        for child in item.get('keys', []):
            child_node = cls._registry_from_json(child)
            node['keys'][child_node['name'].lower()] = child_node
        return node

    @classmethod
    def _load_registry_file(cls):
        """Saved root key nodes by name ({} if there is no valid file)"""
        try:
            with open(cls.REGISTRY_FILE, encoding='utf-8') as f:
                data = json.load(f)
            return {name: cls._registry_from_json(item)
                    for name, item in data.get('roots', {}).items()}
        except FileNotFoundError:
            return {}
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
            log.warning(f"Registry file {cls.REGISTRY_FILE} is not valid ({e}); "
                        f"starting with the default registry")
            return {}

    def _save_registry(self):
        """Write the registry to REGISTRY_FILE (atomically)"""
        cls = winapi.WinAPIHandler
        with cls._registry_lock:
            roots = {cls.REGISTRY_ROOTS[hkey]: cls._registry_to_json(node)
                     for hkey, node in cls._shared_registry.items()
                     if hkey != cls.HKEY_CLASSES_ROOT}
            temp = cls.REGISTRY_FILE + '.tmp'
            try:
                os.makedirs(os.path.dirname(cls.REGISTRY_FILE), exist_ok=True)
                with open(temp, 'w', encoding='utf-8') as f:
                    json.dump({'version': 1, 'roots': roots}, f, ensure_ascii=False, indent=1)
                os.replace(temp, cls.REGISTRY_FILE)
            except OSError as e:
                log.warning(f"Cannot save the registry to {cls.REGISTRY_FILE}: {e}")
    REG_STRING_TYPES = (1, 2, 7)  # REG_SZ, REG_EXPAND_SZ, REG_MULTI_SZ

    ERROR_SUCCESS = 0
    ERROR_FILE_NOT_FOUND = 2
    ERROR_ACCESS_DENIED = 5
    ERROR_INVALID_HANDLE = 6
    ERROR_INVALID_PARAMETER = 87
    ERROR_MORE_DATA = 234
    ERROR_NO_MORE_ITEMS = 259
    ERROR_KEY_DELETED = 1018

    @staticmethod
    def _new_registry_key(name, volatile=False):
        return {'name': name, 'keys': {}, 'values': {}, 'deleted': False,
                'volatile': volatile, 'time': int((time.time() + 11644473600) * 10000000)}

    def _registry_key(self, hkey):
        """(key node, error code) of an open or predefined HKEY"""
        node = self.registry_roots.get(hkey) or self.registry_handles.get(hkey)
        if node is None:
            return None, self.ERROR_INVALID_HANDLE
        if node['deleted']:
            return None, self.ERROR_KEY_DELETED
        return node, self.ERROR_SUCCESS

    @staticmethod
    def _registry_path(subkey):
        return [part for part in subkey.split('\\') if part]

    def _registry_open_common(self, hKey, subkey, phkResult, create, lpdwDisposition=0,
                              volatile=False):
        node, error = self._registry_key(hKey)
        if node is None:
            return error
        if not phkResult:
            return self.ERROR_INVALID_PARAMETER
        disposition = 2  # REG_OPENED_EXISTING_KEY
        for part in self._registry_path(subkey):
            child = node['keys'].get(part.lower())
            if child is None:
                if not create:
                    return self.ERROR_FILE_NOT_FOUND
                # A volatile key's subkeys are volatile too
                child = self._new_registry_key(part, volatile or node.get('volatile', False))
                node['keys'][part.lower()] = child
                disposition = 1  # REG_CREATED_NEW_KEY
            node = child
        if disposition == 1 and not node['volatile']:
            self._save_registry()
        handle = self.get_next_handle()
        self.registry_handles[handle] = node
        self.emu.uc.mem_write(phkResult, struct.pack('<I', handle))
        if lpdwDisposition:
            self.emu.uc.mem_write(lpdwDisposition, struct.pack('<I', disposition))
        return self.ERROR_SUCCESS

    @registry_locked
    def RegOpenKeyExA(self, args, wide=False):
        """RegOpenKeyExA/W emulation"""
        hKey, lpSubKey, phkResult = args[0], args[1], args[4]
        subkey = self._read_text(lpSubKey, wide) if lpSubKey else ""
        result = self._registry_open_common(hKey, subkey, phkResult, create=False)
        log.debug(f"RegOpenKeyEx{'W' if wide else 'A'}(0x{hKey:x}, \"{subkey}\") -> {result}")
        return result

    def RegOpenKeyExW(self, args):
        return self.RegOpenKeyExA(args, wide=True)

    @registry_locked
    def RegCreateKeyExA(self, args, wide=False):
        """RegCreateKeyExA/W emulation (REG_OPTION_VOLATILE keys are not saved)"""
        hKey, lpSubKey, phkResult, lpdwDisposition = args[0], args[1], args[7], args[8]
        subkey = self._read_text(lpSubKey, wide) if lpSubKey else ""
        result = self._registry_open_common(hKey, subkey, phkResult, True, lpdwDisposition,
                                            volatile=bool(args[4] & 1))
        log.debug(f"RegCreateKeyEx{'W' if wide else 'A'}(0x{hKey:x}, \"{subkey}\") -> {result}")
        return result

    def RegCreateKeyExW(self, args):
        return self.RegCreateKeyExA(args, wide=True)

    def RegCloseKey(self, args):
        """RegCloseKey emulation"""
        hKey = args[0]
        log.debug(f"RegCloseKey(0x{hKey:x})")
        if hKey in self.registry_roots or self.registry_handles.pop(hKey, None) is not None:
            return self.ERROR_SUCCESS
        return self.ERROR_INVALID_HANDLE

    @registry_locked
    def RegFlushKey(self, args):
        """RegFlushKey emulation - the registry is already saved after each change"""
        node, error = self._registry_key(args[0])
        return error

    @registry_locked
    def RegSetValueExA(self, args, wide=False):
        """RegSetValueExA/W emulation"""
        hKey, lpValueName, dwType, lpData, cbData = args[0], args[1], args[3], args[4], args[5]
        name = self._read_text(lpValueName, wide) if lpValueName else ""
        log.debug(f"RegSetValueEx{'W' if wide else 'A'}(0x{hKey:x}, \"{name}\", type={dwType})")
        node, error = self._registry_key(hKey)
        if node is None:
            return error
        try:
            data = bytes(self.emu.uc.mem_read(lpData, cbData)) if cbData else b''
        except UcError:
            return self.ERROR_INVALID_PARAMETER
        if dwType in self.REG_STRING_TYPES:
            # Strings are kept as text so the A and W APIs can both read them
            data = data.decode('utf-16-le' if wide else config.ANSI_CODEPAGE, errors='replace')
        node['values'][name.lower()] = {'name': name, 'type': dwType, 'data': data}
        node['time'] = int((time.time() + 11644473600) * 10000000)
        if not node['volatile']:
            self._save_registry()
        return self.ERROR_SUCCESS

    def RegSetValueExW(self, args):
        return self.RegSetValueExA(args, wide=True)

    def _registry_value_bytes(self, value, wide):
        data = value['data']
        if isinstance(data, str):
            return data.encode('utf-16-le') if wide else \
                data.encode(config.ANSI_CODEPAGE, errors='replace')
        return data

    def _registry_store_data(self, value, wide, lpType, lpData, lpcbData):
        """Copy a value's type and data out (RegQueryValueEx/RegEnumValue)"""
        data = self._registry_value_bytes(value, wide)
        if lpType:
            self.emu.uc.mem_write(lpType, struct.pack('<I', value['type']))
        if not lpcbData:
            return self.ERROR_INVALID_PARAMETER if lpData else self.ERROR_SUCCESS
        size = self._read_u32(lpcbData)
        self.emu.uc.mem_write(lpcbData, struct.pack('<I', len(data)))
        if lpData:
            if size < len(data):
                return self.ERROR_MORE_DATA
            self.emu.uc.mem_write(lpData, data)
        return self.ERROR_SUCCESS

    @registry_locked
    def RegQueryValueExA(self, args, wide=False):
        """RegQueryValueExA/W emulation"""
        hKey, lpValueName = args[0], args[1]
        lpType, lpData, lpcbData = args[3], args[4], args[5]
        name = self._read_text(lpValueName, wide) if lpValueName else ""
        node, error = self._registry_key(hKey)
        if node is not None:
            value = node['values'].get(name.lower())
            error = self.ERROR_FILE_NOT_FOUND if value is None else \
                self._registry_store_data(value, wide, lpType, lpData, lpcbData)
        log.debug(f"RegQueryValueEx{'W' if wide else 'A'}(0x{hKey:x}, \"{name}\") -> {error}")
        return error

    def RegQueryValueExW(self, args):
        return self.RegQueryValueExA(args, wide=True)

    @registry_locked
    def RegDeleteValueA(self, args, wide=False):
        """RegDeleteValueA/W emulation"""
        hKey = args[0]
        name = self._read_text(args[1], wide) if args[1] else ""
        log.debug(f"RegDeleteValue{'W' if wide else 'A'}(0x{hKey:x}, \"{name}\")")
        node, error = self._registry_key(hKey)
        if node is None:
            return error
        if node['values'].pop(name.lower(), None) is None:
            return self.ERROR_FILE_NOT_FOUND
        if not node['volatile']:
            self._save_registry()
        return self.ERROR_SUCCESS

    def RegDeleteValueW(self, args):
        return self.RegDeleteValueA(args, wide=True)

    @registry_locked
    def RegDeleteKeyA(self, args, wide=False):
        """RegDeleteKeyA/W emulation - the key must have no subkeys"""
        hKey = args[0]
        subkey = self._read_text(args[1], wide) if args[1] else ""
        log.debug(f"RegDeleteKey{'W' if wide else 'A'}(0x{hKey:x}, \"{subkey}\")")
        node, error = self._registry_key(hKey)
        if node is None:
            return error
        path = self._registry_path(subkey)
        if not path:
            return self.ERROR_ACCESS_DENIED
        for part in path[:-1]:
            node = node['keys'].get(part.lower())
            if node is None:
                return self.ERROR_FILE_NOT_FOUND
        target = node['keys'].get(path[-1].lower())
        if target is None:
            return self.ERROR_FILE_NOT_FOUND
        if target['keys']:
            return self.ERROR_ACCESS_DENIED
        del node['keys'][path[-1].lower()]
        target['deleted'] = True  # Open handles to it now fail
        if not target['volatile']:
            self._save_registry()
        return self.ERROR_SUCCESS

    def RegDeleteKeyW(self, args):
        return self.RegDeleteKeyA(args, wide=True)

    def _registry_store_name(self, name, lpName, lpcchName, wide=False):
        """Copy a key/value name; *lpcchName is in/out (TCHARs, without the NUL)"""
        units = self._text_units(name, wide)
        if not lpName or not lpcchName:
            return self.ERROR_INVALID_PARAMETER
        if self._read_u32(lpcchName) <= len(units):
            return self.ERROR_MORE_DATA
        self._write_units(lpName, units, wide)
        self.emu.uc.mem_write(lpcchName, struct.pack('<I', len(units)))
        return self.ERROR_SUCCESS

    @registry_locked
    def RegEnumKeyExA(self, args, wide=False):
        """RegEnumKeyExA/W emulation - subkeys in alphabetical order"""
        hKey, dwIndex, lpName, lpcchName = args[0], args[1], args[2], args[3]
        lpClass, lpcchClass, lpftLastWriteTime = args[5], args[6], args[7]
        node, error = self._registry_key(hKey)
        if node is None:
            return error
        keys = sorted(node['keys'].values(), key=lambda k: k['name'].lower())
        if dwIndex >= len(keys):
            return self.ERROR_NO_MORE_ITEMS
        key = keys[dwIndex]
        error = self._registry_store_name(key['name'], lpName, lpcchName, wide)
        if error:
            return error
        if lpClass:
            self.emu.uc.mem_write(lpClass, b'\x00\x00' if wide else b'\x00')
        if lpcchClass:
            self.emu.uc.mem_write(lpcchClass, struct.pack('<I', 0))
        if lpftLastWriteTime:
            self.emu.uc.mem_write(lpftLastWriteTime, struct.pack('<Q', key['time']))
        return self.ERROR_SUCCESS

    def RegEnumKeyExW(self, args):
        return self.RegEnumKeyExA(args, wide=True)

    def RegEnumKeyA(self, args, wide=False):
        """RegEnumKeyA/W emulation (cchName is a value: RegEnumKeyEx's count)"""
        size = self.emu.heap_alloc(4)
        try:
            self.emu.uc.mem_write(size, struct.pack('<I', args[3]))
            return self.RegEnumKeyExA([args[0], args[1], args[2], size, 0, 0, 0, 0], wide)
        finally:
            self.emu.heap_free(size)

    def RegEnumKeyW(self, args):
        return self.RegEnumKeyA(args, wide=True)

    @registry_locked
    def RegEnumValueA(self, args, wide=False):
        """RegEnumValueA/W emulation - values in creation order"""
        hKey, dwIndex, lpValueName, lpcchValueName = args[0], args[1], args[2], args[3]
        lpType, lpData, lpcbData = args[5], args[6], args[7]
        node, error = self._registry_key(hKey)
        if node is None:
            return error
        values = list(node['values'].values())
        if dwIndex >= len(values):
            return self.ERROR_NO_MORE_ITEMS
        value = values[dwIndex]
        error = self._registry_store_name(value['name'], lpValueName, lpcchValueName, wide)
        if error:
            return error
        return self._registry_store_data(value, wide, lpType, lpData, lpcbData)

    def RegEnumValueW(self, args):
        return self.RegEnumValueA(args, wide=True)
    
