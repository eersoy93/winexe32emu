# Copyright 2026 Erdem Ersoy (eersoy93)
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

"""WinAPIHandler mixin: the DDE Management Library (DDEML) of user32, with an
emulated Program Manager DDE server (PROGMAN) that turns the CreateGroup and
AddItem commands of setup programs into Start menu folders and shortcuts"""

import ntpath
import os
import re
import shutil
import struct

from unicorn import UcError

from .. import config
from ..logger import log


# DMLERR_* error codes
DMLERR_NO_ERROR = 0
DMLERR_DLL_NOT_INITIALIZED = 0x4003
DMLERR_INVALIDPARAMETER = 0x4006
DMLERR_NO_CONV_ESTABLISHED = 0x400A
DMLERR_NOTPROCESSED = 0x4009

# Transaction types
XTYP_EXECUTE = 0x4050
XTYP_REQUEST = 0x20B0
XTYP_POKE = 0x4090

DDE_FACK = 0x8000
CF_TEXT = 1
CF_UNICODETEXT = 13

# Characters that cannot be in a file name (of a group folder or a shortcut)
_INVALID_NAME_CHARS = re.compile(r'[\\/:*?"<>|\x00-\x1f]')


def parse_progman_commands(text):
    """Program Manager DDE commands, "[Name(arg1,arg2)][Name2]...", as
    [(lower-case name, [arguments])]; quoted arguments may hold commas and
    brackets"""
    commands = []
    i, n = 0, len(text)
    while i < n:
        if text[i] != '[':
            i += 1
            continue
        i += 1
        start = i
        while i < n and text[i] not in '(]':
            i += 1
        name = text[start:i].strip().lower()
        arguments = []
        if i < n and text[i] == '(':
            i += 1
            current, quoted = '', False
            while i < n:
                char = text[i]
                if char == '"':
                    quoted = not quoted
                elif char == ',' and not quoted:
                    arguments.append(current.strip())
                    current = ''
                elif char == ')' and not quoted:
                    break
                else:
                    current += char
                i += 1
            arguments.append(current.strip())
            if arguments == ['']:
                arguments = []
            while i < n and text[i] != ']':
                i += 1
        i += 1
        if name:
            commands.append((name, arguments))
    return commands


def split_command_line(command_line):
    """(program, arguments) of a command line; the program may be quoted"""
    command_line = command_line.strip()
    if command_line.startswith('"'):
        end = command_line.find('"', 1)
        if end < 0:
            return command_line[1:], ''
        return command_line[1:end], command_line[end + 1:].strip()
    program, _, arguments = command_line.partition(' ')
    return program, arguments.strip()


def _file_name(name):
    """A group or item name made valid as a file name"""
    return _INVALID_NAME_CHARS.sub('_', name).strip(' .') or '_'


class DdeMixin:
    """DDEML: instances, string and data handles, conversations, transactions"""

    PROGMAN_SERVICES = ('progman', 'folders')

    def _dde_state(self):
        state = self.__dict__.get('_dde')
        if state is None:
            state = self._dde = {
                'instances': {}, 'strings': {}, 'data': {}, 'conversations': {},
                'next_handle': 0x5D000004, 'group': None,
            }
        return state

    def _dde_new_handle(self):
        state = self._dde_state()
        handle = state['next_handle']
        state['next_handle'] += 4
        return handle

    def _dde_set_error(self, inst, error):
        instance = self._dde_state()['instances'].get(inst)
        if instance is not None:
            instance['error'] = error

    # ---------- Instances ----------

    def DdeInitializeA(self, args, wide=False):
        """DdeInitialize(pidInst, pfnCallback, afCmd, ulRes)"""
        pid_inst, callback, flags = args[0], args[1], args[2]
        if not pid_inst:
            return DMLERR_INVALIDPARAMETER
        state = self._dde_state()
        inst = self._read_u32(pid_inst)
        if inst and inst in state['instances']:
            # Reinitializing an instance changes its flags (APPCMD_* bits)
            state['instances'][inst]['flags'] = flags
            return DMLERR_NO_ERROR
        inst = self._dde_new_handle()
        state['instances'][inst] = {'callback': callback, 'flags': flags,
                                    'wide': wide, 'error': DMLERR_NO_ERROR}
        self._mem_write(pid_inst, struct.pack('<I', inst))
        log.debug(f"DdeInitialize{'W' if wide else 'A'} -> instance 0x{inst:08x}")
        return DMLERR_NO_ERROR

    def DdeInitializeW(self, args):
        return self.DdeInitializeA(args, wide=True)

    def DdeUninitialize(self, args):
        state = self._dde_state()
        if state['instances'].pop(args[0], None) is None:
            return 0
        for conv in [c for c, info in state['conversations'].items()
                     if info['inst'] == args[0]]:
            del state['conversations'][conv]
        return 1

    def DdeGetLastError(self, args):
        """DdeGetLastError(idInst) - the last error, which it then clears"""
        instance = self._dde_state()['instances'].get(args[0])
        if instance is None:
            return DMLERR_DLL_NOT_INITIALIZED
        error, instance['error'] = instance['error'], DMLERR_NO_ERROR
        return error

    # ---------- String handles (atoms: case-insensitive) ----------

    def _dde_string(self, hsz):
        return self._dde_state()['strings'].get(hsz, '')

    def DdeCreateStringHandleA(self, args, wide=False):
        """DdeCreateStringHandle(idInst, psz, iCodePage)"""
        if not args[1]:
            return 0
        text = self._read_text(args[1], wide or args[2] == 1200)  # CP_WINUNICODE
        if not text:
            return 0
        strings = self._dde_state()['strings']
        for hsz, value in strings.items():
            if value.lower() == text.lower():
                return hsz
        hsz = self._dde_new_handle()
        strings[hsz] = text
        return hsz

    def DdeCreateStringHandleW(self, args):
        return self.DdeCreateStringHandleA(args, wide=True)

    def DdeFreeStringHandle(self, args):
        return 1 if args[1] in self._dde_state()['strings'] else 0

    def DdeKeepStringHandle(self, args):
        return 1 if args[1] in self._dde_state()['strings'] else 0

    def DdeQueryStringA(self, args, wide=False):
        """DdeQueryString(idInst, hsz, psz, cchMax, iCodePage) - length in characters"""
        hsz, buffer, cch_max = args[1], args[2], args[3]
        if hsz not in self._dde_state()['strings']:
            return 0
        text = self._dde_string(hsz)
        wide = wide or args[4] == 1200
        if not buffer:
            return len(text)
        if cch_max == 0:
            return 0
        text = text[:cch_max - 1]
        self._write_text(buffer, text, wide)
        return len(text)

    def DdeQueryStringW(self, args):
        return self.DdeQueryStringA(args, wide=True)

    def DdeCmpStringHandles(self, args):
        first, second = self._dde_string(args[0]).lower(), self._dde_string(args[1]).lower()
        if not args[0] or not args[1]:
            first, second = args[0], args[1]
        return 0 if first == second else (0xFFFFFFFF if first < second else 1)

    # ---------- Data handles ----------

    def DdeCreateDataHandle(self, args):
        """DdeCreateDataHandle(idInst, pSrc, cb, cbOff, hszItem, wFmt, afCmd)"""
        source, size, offset = args[1], args[2], args[3]
        data = bytearray(offset + size)
        if source and size:
            try:
                data[offset:] = self.emu.uc.mem_read(source, size)
            except UcError:
                self._dde_set_error(args[0], DMLERR_INVALIDPARAMETER)
                return 0
        handle = self._dde_new_handle()
        self._dde_state()['data'][handle] = {'bytes': data, 'item': args[4],
                                             'format': args[5], 'access': None}
        return handle

    def DdeAddData(self, args):
        """DdeAddData(hData, pSrc, cb, cbOff)"""
        info = self._dde_state()['data'].get(args[0])
        if info is None:
            return 0
        source, size, offset = args[1], args[2], args[3]
        data = info['bytes']
        if len(data) < offset + size:
            data.extend(b'\x00' * (offset + size - len(data)))
        if source and size:
            data[offset:offset + size] = self.emu.uc.mem_read(source, size)
        return args[0]

    def DdeGetData(self, args):
        """DdeGetData(hData, pDst, cbMax, cbOff) - bytes copied, or the size if pDst is NULL"""
        info = self._dde_state()['data'].get(args[0])
        if info is None:
            return 0
        data = bytes(info['bytes'][args[3]:])
        if not args[1]:
            return len(data)
        data = data[:args[2]]
        return len(data) if self._mem_write(args[1], data) else 0

    def DdeAccessData(self, args):
        """DdeAccessData(hData, pcbDataSize) - a pointer to the data"""
        info = self._dde_state()['data'].get(args[0])
        if info is None:
            return 0
        if info['access'] is None:
            address = self.emu.heap_alloc(max(len(info['bytes']), 1))
            self._mem_write(address, info['bytes'])
            info['access'] = address
        if args[1]:
            self._mem_write(args[1], struct.pack('<I', len(info['bytes'])))
        return info['access']

    def DdeUnaccessData(self, args):
        info = self._dde_state()['data'].get(args[0])
        if info is None:
            return 0
        if info['access'] is not None and info['bytes']:
            info['bytes'] = bytearray(self.emu.uc.mem_read(info['access'], len(info['bytes'])))
        return 1

    def DdeFreeDataHandle(self, args):
        return 1 if self._dde_state()['data'].pop(args[0], None) is not None else 0

    # ---------- Conversations ----------

    def DdeConnect(self, args):
        """DdeConnect(idInst, hszService, hszTopic, pCC) - only the emulated
        Program Manager (PROGMAN) answers"""
        inst, service, topic = args[0], self._dde_string(args[1]), self._dde_string(args[2])
        state = self._dde_state()
        if inst not in state['instances']:
            return 0
        if service.lower() in self.PROGMAN_SERVICES or (not service and
                                                         topic.lower() in self.PROGMAN_SERVICES):
            conv = self._dde_new_handle()
            state['conversations'][conv] = {'inst': inst, 'service': service or 'PROGMAN',
                                            'topic': topic or 'PROGMAN'}
            log.debug(f"DdeConnect('{service}', '{topic}') -> 0x{conv:08x}")
            return conv
        log.debug(f"DdeConnect('{service}', '{topic}'): no server")
        self._dde_set_error(inst, DMLERR_NO_CONV_ESTABLISHED)
        return 0

    def DdeReconnect(self, args):
        return args[0] if args[0] in self._dde_state()['conversations'] else 0

    def DdeDisconnect(self, args):
        return 1 if self._dde_state()['conversations'].pop(args[0], None) is not None else 0

    def DdeConnectList(self, args):
        """DdeConnectList(idInst, hszService, hszTopic, hConvList, pCC) - not supported"""
        self._dde_set_error(args[0], DMLERR_NO_CONV_ESTABLISHED)
        return 0

    def DdeDisconnectList(self, args):
        return 1

    def DdeQueryNextServer(self, args):
        return 0

    def DdeQueryConvInfo(self, args):
        return 0

    def DdeNameService(self, args):
        """DdeNameService(idInst, hsz1, hszRes, afCmd) - servers are not
        reachable by other programs; registering one succeeds"""
        return 1 if args[0] in self._dde_state()['instances'] else 0

    def DdeEnableCallback(self, args):
        return 1

    def DdePostAdvise(self, args):
        return 1

    def DdeAbandonTransaction(self, args):
        return 1

    def DdeSetUserHandle(self, args):
        return 1 if args[0] in self._dde_state()['conversations'] else 0

    def DdeImpersonateClient(self, args):
        return 1

    # ---------- Transactions ----------

    def _dde_transaction_data(self, pointer, size):
        """Bytes of a transaction's data: a buffer or (size -1) a data handle"""
        if size == 0xFFFFFFFF:
            info = self._dde_state()['data'].get(pointer)
            return bytes(info['bytes']) if info else b''
        if not pointer or not size:
            return b''
        try:
            return bytes(self.emu.uc.mem_read(pointer, size))
        except UcError:
            return b''

    @staticmethod
    def _dde_decode(data, wide):
        """Text of DDE data: UTF-16 for Unicode instances (or if it looks like it)"""
        if wide or (len(data) >= 2 and data[1] == 0 and data[0] != 0):
            text = data.decode('utf-16-le', errors='replace')
        else:
            text = data.decode(config.ANSI_CODEPAGE, errors='replace')
        return text.split('\x00', 1)[0]

    def DdeClientTransaction(self, args):
        """DdeClientTransaction(pData, cbData, hConv, hszItem, wFmt, wType,
        dwTimeout, pdwResult)"""
        pointer, size, conv, item, fmt, xtype, result_ptr = (
            args[0], args[1], args[2], args[3], args[4], args[5], args[7])
        state = self._dde_state()
        info = state['conversations'].get(conv)
        if info is None:
            return 0
        instance = state['instances'].get(info['inst'], {})
        if result_ptr:
            self._mem_write(result_ptr, struct.pack('<I', 0))
        if xtype == XTYP_EXECUTE:
            data = self._dde_transaction_data(pointer, size)
            text = self._dde_decode(data, instance.get('wide', False))
            if not self._progman_execute(text):
                self._dde_set_error(info['inst'], DMLERR_NOTPROCESSED)
                return 0
            if result_ptr:
                self._mem_write(result_ptr, struct.pack('<I', DDE_FACK))
            return 1
        if xtype == XTYP_REQUEST:
            text = self._progman_request(self._dde_string(item))
            if text is None:
                self._dde_set_error(info['inst'], DMLERR_NOTPROCESSED)
                return 0
            wide = fmt == CF_UNICODETEXT
            data = (text.encode('utf-16-le') + b'\x00\x00' if wide else
                    text.encode(config.ANSI_CODEPAGE, errors='replace') + b'\x00')
            handle = self._dde_new_handle()
            state['data'][handle] = {'bytes': bytearray(data), 'item': item,
                                     'format': fmt or CF_TEXT, 'access': None}
            return handle
        if xtype == XTYP_POKE:
            if result_ptr:
                self._mem_write(result_ptr, struct.pack('<I', DDE_FACK))
            return 1
        log.debug(f"DdeClientTransaction: transaction type 0x{xtype:04x} not supported")
        self._dde_set_error(info['inst'], DMLERR_NOTPROCESSED)
        return 0

    # ---------- The emulated Program Manager ----------

    def _progman_folder(self, common=False):
        """Windows path of the Start menu's Programs folder (the user's, or
        all users' for common groups)"""
        return self.SHELL_FOLDERS[0x17 if common else 0x02]

    def _progman_group_path(self, name, common=None):
        """Windows path of a group (an existing one of either folder first)"""
        folder_name = _file_name(name)
        if common is None:
            for is_common in (False, True):
                path = self._progman_folder(is_common) + '\\' + folder_name
                host = self.resolve_drive_path(path)
                if host and os.path.isdir(host):
                    return path
            common = False
        return self._progman_folder(common) + '\\' + folder_name

    def _progman_groups(self):
        names = {}
        for common in (False, True):
            host = self.resolve_drive_path(self._progman_folder(common))
            if host and os.path.isdir(host):
                for name in os.listdir(host):
                    if os.path.isdir(os.path.join(host, name)):
                        names.setdefault(name.lower(), name)
        return [names[key] for key in sorted(names)]

    def _progman_request(self, item):
        """XTYP_REQUEST: "Groups" (the group names) or a group (its items)"""
        if item.lower() in ('groups', 'progman', ''):
            return ''.join(name + '\r\n' for name in self._progman_groups())
        path = self._progman_group_path(item)
        host = self.resolve_drive_path(path)
        if not host or not os.path.isdir(host):
            return None
        items = sorted(name for name in os.listdir(host) if name.lower().endswith('.lnk'))
        lines = [f'"{item}",{path},{len(items)},0,0,0,0,0,0']
        lines += [f'"{os.path.splitext(name)[0]}","",,,0,0,0,0,0' for name in items]
        return ''.join(line + '\r\n' for line in lines)

    def _progman_execute(self, text):
        """Run Program Manager DDE commands; False if one of them failed"""
        log.info(f"Program Manager DDE: {text}")
        for name, arguments in parse_progman_commands(text):
            handler = getattr(self, '_progman_' + name, None)
            if handler is None:
                log.debug(f"Program Manager DDE: [{name}] ignored")
                continue
            if not handler(arguments):
                log.warning(f"Program Manager DDE: [{name}({','.join(arguments)})] failed")
                return False
        return True

    def _progman_make_group(self, name, common):
        path = self._progman_group_path(name, None if common is None else common)
        host = self.resolve_drive_path(path)
        if host is None or self._write_protected(host):
            return None
        try:
            os.makedirs(host, exist_ok=True)
        except OSError:
            return None
        self._dde_state()['group'] = path
        return path

    def _progman_creategroup(self, arguments):
        """CreateGroup(name[, path]) - also makes it the current group"""
        if not arguments or not arguments[0]:
            return False
        return self._progman_make_group(arguments[0], None) is not None

    def _progman_showgroup(self, arguments):
        """ShowGroup(name, command[, common]) - makes it the current group"""
        if not arguments or not arguments[0]:
            return False
        common = len(arguments) > 2 and arguments[2] == '1'
        return self._progman_make_group(arguments[0], common if common else None) is not None

    def _progman_deletegroup(self, arguments):
        """DeleteGroup(name[, common])"""
        if not arguments or not arguments[0]:
            return False
        host = self.resolve_drive_path(self._progman_group_path(arguments[0]))
        if host and os.path.isdir(host) and not self._write_protected(host):
            shutil.rmtree(host, ignore_errors=True)
        return True

    def _progman_item_host(self, name):
        group = self._dde_state()['group']
        if group is None:
            return None
        return self.resolve_drive_path(group + '\\' + _file_name(name) + '.lnk')

    def _progman_additem(self, arguments):
        """AddItem(command line[, name[, icon path[, icon index[, x, y[,
        working directory[, hotkey[, minimized]]]]]]]) - a shortcut in the
        current group"""
        if not arguments or not arguments[0] or self._dde_state()['group'] is None:
            return False
        program, program_arguments = split_command_line(arguments[0])
        name = (arguments[1] if len(arguments) > 1 and arguments[1] else
                os.path.splitext(ntpath.basename(program))[0])
        icon = arguments[2] if len(arguments) > 2 else ''
        try:
            icon_index = int(arguments[3]) if len(arguments) > 3 and arguments[3] else 0
        except ValueError:
            icon_index = 0
        workdir = arguments[6] if len(arguments) > 6 else ''
        minimized = len(arguments) > 8 and arguments[8] == '1'
        host = self._progman_item_host(name)
        if host is None or self._write_protected(host):
            return False
        link = {'path': program, 'arguments': program_arguments, 'workdir': workdir,
                'description': '', 'relative': '', 'icon': icon,
                'icon_index': icon_index, 'show': 7 if minimized else 1, 'hotkey': 0}
        try:
            with open(host, 'wb') as f:
                f.write(self._shell_link_data(link))
        except OSError:
            return False
        log.info(f"Program Manager: shortcut \"{name}\" -> \"{arguments[0]}\"")
        return True

    def _progman_replaceitem(self, arguments):
        """ReplaceItem(name) - deletes the item; the next AddItem replaces it"""
        return self._progman_deleteitem(arguments)

    def _progman_deleteitem(self, arguments):
        """DeleteItem(name)"""
        if not arguments or not arguments[0]:
            return False
        host = self._progman_item_host(arguments[0])
        if host and os.path.isfile(host) and not self._write_protected(host):
            try:
                os.remove(host)
            except OSError:
                return False
        return True

    def _progman_reload(self, arguments):
        return True

    def _progman_exitprogman(self, arguments):
        return True

    # ---------- Packed lParams of the DDE messages ----------

    def _dde_lparams(self):
        return self.__dict__.setdefault('_dde_packed', {})

    def PackDDElParam(self, args):
        """PackDDElParam(msg, uiLo, uiHi) - an lParam holding two 32-bit values"""
        packed = self._dde_lparams()
        handle = 0x5E000004 + 4 * len(packed)
        while handle in packed:
            handle += 4
        packed[handle] = (args[1], args[2])
        return handle

    def UnpackDDElParam(self, args):
        """UnpackDDElParam(msg, lParam, puiLo, puiHi)"""
        low, high = self._dde_lparams().get(args[1], (args[1] & 0xFFFF, args[1] >> 16))
        if args[2]:
            self._mem_write(args[2], struct.pack('<I', low))
        if args[3]:
            self._mem_write(args[3], struct.pack('<I', high))
        return 1

    def FreeDDElParam(self, args):
        self._dde_lparams().pop(args[1], None)
        return 1

    def ReuseDDElParam(self, args):
        """ReuseDDElParam(lParam, msgIn, msgOut, uiLo, uiHi)"""
        self._dde_lparams().pop(args[0], None)
        return self.PackDDElParam([args[2], args[3], args[4]])
