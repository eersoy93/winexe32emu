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
import re
from functools import wraps

from unicorn import UcError

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
                        # The default keys and values a saved registry lacks
                        # (an older emulator did not make them) are added
                        roots[hkey] = cls._merge_registry_defaults(saved[name], roots[hkey])
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
        # The special folders under Explorer\Shell Folders (setup programs
        # like Microsoft Office 95's read the Start menu's Programs from there)
        folders = getattr(cls, 'SHELL_FOLDERS', {})
        for hkey, root, names in ((0x80000001, 'Software', cls.USER_SHELL_FOLDER_NAMES),
                                  (0x80000002, 'SOFTWARE', cls.COMMON_SHELL_FOLDER_NAMES)):
            node = roots[hkey]
            for part in (root, 'Microsoft', 'Windows', 'CurrentVersion', 'Explorer',
                         'Shell Folders'):
                node = node['keys'].setdefault(part.lower(), cls._new_registry_key(part))
            for name, csidl in names:
                if csidl in folders:
                    node['values'][name.lower()] = {'name': name, 'type': 1,
                                                    'data': folders[csidl] + '\x00'}
        return roots

    # Explorer\Shell Folders value -> CSIDL: the user's (HKEY_CURRENT_USER) and
    # the shared ones (HKEY_LOCAL_MACHINE)
    USER_SHELL_FOLDER_NAMES = (
        ('AppData', 0x1A), ('Cache', 0x20), ('Cookies', 0x21), ('Desktop', 0x10),
        ('Favorites', 0x06), ('Fonts', 0x14), ('History', 0x22), ('Local AppData', 0x1C),
        ('My Music', 0x0D), ('My Pictures', 0x27), ('My Video', 0x0E), ('Personal', 0x05),
        ('Programs', 0x02), ('Recent', 0x08), ('SendTo', 0x09), ('Start Menu', 0x0B),
        ('Startup', 0x07), ('Templates', 0x15), ('Administrative Tools', 0x30))
    COMMON_SHELL_FOLDER_NAMES = (
        ('Common AppData', 0x23), ('Common Desktop', 0x19), ('Common Documents', 0x2E),
        ('Common Programs', 0x17), ('Common Start Menu', 0x16), ('Common Startup', 0x18),
        ('Common Templates', 0x2D), ('Common Administrative Tools', 0x2F),
        ('CommonMusic', 0x35), ('CommonPictures', 0x36), ('CommonVideo', 0x37))

    @classmethod
    def _merge_registry_defaults(cls, saved, default):
        """saved (a key node) with the keys and values of default it does not have"""
        for name, value in default['values'].items():
            saved['values'].setdefault(name, value)
        for name, child in default['keys'].items():
            if name in saved['keys']:
                cls._merge_registry_defaults(saved['keys'][name], child)
            else:
                saved['keys'][name] = child
        return saved

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


    # ---------- Key trees and the older and newer registry APIs ----------

    def _registry_walk(self, hkey, subkey, create=False):
        """(key node, error) of hkey\\subkey, created if create is True"""
        node, error = self._registry_key(hkey)
        if node is None:
            return None, error
        created = False
        for part in self._registry_path(subkey):
            child = node['keys'].get(part.lower())
            if child is None:
                if not create:
                    return None, self.ERROR_FILE_NOT_FOUND
                child = self._new_registry_key(part, node.get('volatile', False))
                node['keys'][part.lower()] = child
                created = True
            node = child
        if created and not node['volatile']:
            self._save_registry()
        return node, self.ERROR_SUCCESS

    @staticmethod
    def _mark_deleted(node):
        """A deleted key and its subkeys: their open handles now fail"""
        node['deleted'] = True
        for child in node['keys'].values():
            RegistryMixin._mark_deleted(child)

    @registry_locked
    def _registry_delete_tree(self, hkey, subkey, only_if_empty=False):
        """Delete hkey\\subkey with its subkeys (only an empty key if only_if_empty)"""
        path = self._registry_path(subkey)
        if not path:
            return self.ERROR_ACCESS_DENIED
        parent, error = self._registry_walk(hkey, '\\'.join(path[:-1]))
        if parent is None:
            return error
        target = parent['keys'].get(path[-1].lower())
        if target is None:
            return self.ERROR_FILE_NOT_FOUND
        if only_if_empty and (target['keys'] or target['values']):
            return self.ERROR_ACCESS_DENIED
        del parent['keys'][path[-1].lower()]
        self._mark_deleted(target)
        if not target['volatile']:
            self._save_registry()
        return self.ERROR_SUCCESS

    def _temporary_hkey(self, node):
        handle = self.get_next_handle()
        self.registry_handles[handle] = node
        return handle

    @registry_locked
    def RegOpenKeyA(self, args, wide=False):
        """RegOpenKeyA/W(hkey, subkey, &result) - no subkey: the same handle"""
        subkey = self._read_text(args[1], wide) if args[1] else ""
        if not self._registry_path(subkey):
            node, error = self._registry_key(args[0])
            if node is not None:
                self._mem_write(args[2], struct.pack('<I', args[0]))
            return error
        return self._registry_open_common(args[0], subkey, args[2], create=False)

    def RegOpenKeyW(self, args):
        return self.RegOpenKeyA(args, wide=True)

    @registry_locked
    def RegCreateKeyA(self, args, wide=False):
        """RegCreateKeyA/W(hkey, subkey, &result)"""
        subkey = self._read_text(args[1], wide) if args[1] else ""
        return self._registry_open_common(args[0], subkey, args[2], create=True)

    def RegCreateKeyW(self, args):
        return self.RegCreateKeyA(args, wide=True)

    def RegOpenCurrentUser(self, args):
        """RegOpenCurrentUser(access, &result) - HKEY_CURRENT_USER"""
        return self.ERROR_SUCCESS if self._mem_write(args[1], struct.pack('<I', 0x80000001)) \
            else self.ERROR_INVALID_PARAMETER

    def RegConnectRegistryA(self, args, wide=False):
        """RegConnectRegistryA/W(machine, hkey, &result) - only this computer"""
        machine = self._read_text(args[0], wide).strip('\\') if args[0] else ''
        if machine and machine.upper() != self.COMPUTER_NAME:
            return 53  # ERROR_BAD_NETPATH
        if args[1] not in self.registry_roots:
            return self.ERROR_INVALID_HANDLE
        self._mem_write(args[2], struct.pack('<I', args[1]))
        return self.ERROR_SUCCESS

    def RegConnectRegistryW(self, args):
        return self.RegConnectRegistryA(args, wide=True)

    @registry_locked
    def RegQueryValueA(self, args, wide=False):
        """RegQueryValueA/W(hkey, subkey, data, &size) - the default value of a
        subkey (an empty string if it has none)"""
        subkey = self._read_text(args[1], wide) if args[1] else ""
        node, error = self._registry_walk(args[0], subkey)
        if node is None:
            return error
        value = node['values'].get('')
        if value is None or value['type'] not in self.REG_STRING_TYPES:
            value = {'type': 1, 'data': '\x00'}
        return self._registry_store_data(value, wide, 0, args[2], args[3])

    def RegQueryValueW(self, args):
        return self.RegQueryValueA(args, wide=True)

    @registry_locked
    def RegSetValueA(self, args, wide=False):
        """RegSetValueA/W(hkey, subkey, REG_SZ, text, size) - sets a subkey's
        default value (the size is ignored)"""
        if args[2] != 1:  # REG_SZ
            return self.ERROR_INVALID_PARAMETER
        subkey = self._read_text(args[1], wide) if args[1] else ""
        node, error = self._registry_walk(args[0], subkey, create=True)
        if node is None:
            return error
        text = self._read_text(args[3], wide) if args[3] else ''
        node['values'][''] = {'name': '', 'type': 1, 'data': text + '\x00'}
        node['time'] = int((time.time() + 11644473600) * 10000000)
        if not node['volatile']:
            self._save_registry()
        return self.ERROR_SUCCESS

    def RegSetValueW(self, args):
        return self.RegSetValueA(args, wide=True)

    @registry_locked
    def RegQueryInfoKeyA(self, args, wide=False):
        """RegQueryInfoKeyA/W(hkey, class, &class size, reserved, &subkeys,
        &longest subkey, &longest class, &values, &longest value name,
        &largest value, &security descriptor size, &last write time)"""
        node, error = self._registry_key(args[0])
        if node is None:
            return error
        if args[1] and args[2]:
            if self._read_u32(args[2]) < 1:
                return self.ERROR_MORE_DATA
            self._write_text(args[1], '', wide)
        if args[2]:
            self._mem_write(args[2], struct.pack('<I', 0))
        keys = list(node['keys'].values())
        values = list(node['values'].values())
        counts = (len(keys), max((len(self._text_units(k['name'], wide)) for k in keys),
                                 default=0), 0,
                  len(values), max((len(self._text_units(v['name'], wide)) for v in values),
                                   default=0),
                  max((len(self._registry_value_bytes(v, wide)) for v in values), default=0),
                  0)
        for address, count in zip(args[4:11], counts, strict=True):
            if address:
                self._mem_write(address, struct.pack('<I', count))
        if args[11]:
            self._mem_write(args[11], struct.pack('<Q', node['time']))
        return self.ERROR_SUCCESS

    def RegQueryInfoKeyW(self, args):
        return self.RegQueryInfoKeyA(args, wide=True)

    # RRF_RT_* flag of each value type (RegGetValue)
    RRF_TYPE_FLAGS = {0: 0x1, 1: 0x2, 2: 0x4, 3: 0x8, 4: 0x10, 7: 0x20, 11: 0x40}

    def _expand_registry_text(self, text):
        return re.sub(r'%([^%]+)%',
                      lambda m: self.environment.get(m.group(1).upper(), m.group(0)), text)

    @registry_locked
    def RegGetValueA(self, args, wide=False):
        """RegGetValueA/W(hkey, subkey, value, flags, &type, data, &size) -
        RRF_RT_* type filters; REG_EXPAND_SZ is expanded unless RRF_NOEXPAND"""
        hkey, flags, type_addr, data_addr, size_addr = args[0], args[3], args[4], args[5], args[6]
        subkey = self._read_text(args[1], wide) if args[1] else ""
        name = self._read_text(args[2], wide) if args[2] else ""
        if data_addr and not size_addr:
            return self.ERROR_INVALID_PARAMETER
        # The caller's buffer size: _registry_store_data replaces *size with
        # the size needed, which RRF_ZEROONFAILURE must not zero
        buffer_size = self._read_u32(size_addr) if data_addr and size_addr else 0
        node, error = self._registry_walk(hkey, subkey)
        value = node['values'].get(name.lower()) if node is not None else None
        if node is not None and value is None:
            error = self.ERROR_FILE_NOT_FOUND
        if value is not None:
            value_type, data = value['type'], value['data']
            if value_type == 2 and not flags & 0x10000000:  # RRF_NOEXPAND
                data = self._expand_registry_text(data)
                value_type = 1  # Returned as REG_SZ
                if not flags & 0x2:  # RRF_RT_REG_SZ is needed for an expanded string
                    error = 1630  # ERROR_UNSUPPORTED_TYPE
            if not flags & self.RRF_TYPE_FLAGS.get(value_type, 0) and error == 0:
                error = 1630
            if error == 0:
                if isinstance(data, str) and not data.endswith('\x00'):
                    data += '\x00'
                error = self._registry_store_data({'type': value_type, 'data': data}, wide,
                                                  type_addr, data_addr, size_addr)
        if error and flags & 0x20000000 and data_addr and size_addr:  # RRF_ZEROONFAILURE
            self._mem_write(data_addr, b'\x00' * buffer_size)
        return error

    def RegGetValueW(self, args):
        return self.RegGetValueA(args, wide=True)

    def RegDeleteKeyExA(self, args):
        """RegDeleteKeyExA/W(hkey, subkey, WOW64 view, reserved) - 32-bit
        Windows has one registry view: KEY_WOW64_32KEY/64KEY are ignored"""
        return self.RegDeleteKeyA(args)

    def RegDeleteKeyExW(self, args):
        return self.RegDeleteKeyW(args)

    @registry_locked
    def RegDeleteTreeA(self, args, wide=False):
        """RegDeleteTreeA/W(hkey, subkey) - the subkey and its subkeys; with
        no subkey, the key's own subkeys and values"""
        subkey = self._read_text(args[1], wide) if args[1] else ""
        if self._registry_path(subkey):
            return self._registry_delete_tree(args[0], subkey)
        node, error = self._registry_key(args[0])
        if node is None:
            return error
        for child in node['keys'].values():
            self._mark_deleted(child)
        node['keys'].clear()
        node['values'].clear()
        if not node['volatile']:
            self._save_registry()
        return self.ERROR_SUCCESS

    def RegDeleteTreeW(self, args):
        return self.RegDeleteTreeA(args, wide=True)

    @registry_locked
    def RegDeleteKeyValueA(self, args, wide=False):
        """RegDeleteKeyValueA/W(hkey, subkey, value)"""
        subkey = self._read_text(args[1], wide) if args[1] else ""
        node, error = self._registry_walk(args[0], subkey)
        if node is None:
            return error
        handle = self._temporary_hkey(node)
        try:
            return self.RegDeleteValueA([handle, args[2]], wide)
        finally:
            del self.registry_handles[handle]

    def RegDeleteKeyValueW(self, args):
        return self.RegDeleteKeyValueA(args, wide=True)

    @registry_locked
    def RegSetKeyValueA(self, args, wide=False):
        """RegSetKeyValueA/W(hkey, subkey, value, type, data, size) - creates the subkey"""
        subkey = self._read_text(args[1], wide) if args[1] else ""
        node, error = self._registry_walk(args[0], subkey, create=True)
        if node is None:
            return error
        handle = self._temporary_hkey(node)
        try:
            return self.RegSetValueExA([handle, args[2], 0, args[3], args[4], args[5]], wide)
        finally:
            del self.registry_handles[handle]

    def RegSetKeyValueW(self, args):
        return self.RegSetKeyValueA(args, wide=True)

    def RegNotifyChangeKeyValue(self, args):
        """RegNotifyChangeKeyValue - changes are never signaled"""
        node, error = self._registry_key(args[0])
        return error

    def RegDisablePredefinedCache(self, args):
        return self.ERROR_SUCCESS

    def RegDisablePredefinedCacheEx(self, args):
        return self.ERROR_SUCCESS
