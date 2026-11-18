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

"""WinAPIHandler mixin: ADVAPI32 security (SIDs, tokens, security
descriptors, ACLs), CryptoAPI and BCrypt hashes and random numbers, the
service control manager, the event log and ETW"""

import hashlib
import hmac
import os
import struct

from unicorn import *

from ..logger import log


class SecurityMixin:
    """ADVAPI32 security, CryptoAPI/BCrypt, services, event log, ETW"""

    # ---------- SIDs ----------

    # The user's SID (a local account of the emulated computer)
    USER_DOMAIN_SID = 'S-1-5-21-3623811015-3361044348-30300820'
    USER_SID = USER_DOMAIN_SID + '-1000'

    # WELL_KNOWN_SID_TYPE -> SID (CreateWellKnownSid)
    WELL_KNOWN_SIDS = {
        0: 'S-1-0-0', 1: 'S-1-1-0', 2: 'S-1-2-0', 3: 'S-1-3-0', 4: 'S-1-3-1',
        9: 'S-1-5-1', 10: 'S-1-5-2', 11: 'S-1-5-4', 12: 'S-1-5-6', 13: 'S-1-5-7',
        17: 'S-1-5-11', 18: 'S-1-5-12', 22: 'S-1-5-18', 23: 'S-1-5-19', 24: 'S-1-5-20',
        25: 'S-1-5-32', 26: 'S-1-5-32-544', 27: 'S-1-5-32-545', 28: 'S-1-5-32-546',
        29: 'S-1-5-32-547', 66: 'S-1-16-4096', 67: 'S-1-16-8192', 68: 'S-1-16-12288',
        69: 'S-1-16-16384',
    }

    # SDDL abbreviations of SIDs (ConvertStringSidToSid)
    SDDL_SIDS = {
        'WD': 'S-1-1-0', 'CO': 'S-1-3-0', 'CG': 'S-1-3-1', 'NU': 'S-1-5-2',
        'IU': 'S-1-5-4', 'SU': 'S-1-5-6', 'AN': 'S-1-5-7', 'AU': 'S-1-5-11',
        'SY': 'S-1-5-18', 'LS': 'S-1-5-19', 'NS': 'S-1-5-20', 'BA': 'S-1-5-32-544',
        'BU': 'S-1-5-32-545', 'BG': 'S-1-5-32-546', 'PU': 'S-1-5-32-547',
        'LW': 'S-1-16-4096', 'ME': 'S-1-16-8192', 'HI': 'S-1-16-12288', 'SI': 'S-1-16-16384',
    }

    # SID -> (account name, domain, SID_NAME_USE) of LookupAccountSid
    @property
    def _known_accounts(self):
        return {
            self.USER_SID: (self.USER_NAME, self.COMPUTER_NAME, 1),  # SidTypeUser
            self.USER_DOMAIN_SID + '-513': ('None', self.COMPUTER_NAME, 2),  # SidTypeGroup
            'S-1-1-0': ('Everyone', '', 5),  # SidTypeWellKnownGroup
            'S-1-2-0': ('LOCAL', '', 5),
            'S-1-3-0': ('CREATOR OWNER', '', 5),
            'S-1-5-4': ('INTERACTIVE', 'NT AUTHORITY', 5),
            'S-1-5-11': ('Authenticated Users', 'NT AUTHORITY', 5),
            'S-1-5-18': ('SYSTEM', 'NT AUTHORITY', 5),
            'S-1-5-19': ('LOCAL SERVICE', 'NT AUTHORITY', 5),
            'S-1-5-20': ('NETWORK SERVICE', 'NT AUTHORITY', 5),
            'S-1-5-32-544': ('Administrators', 'BUILTIN', 4),  # SidTypeAlias
            'S-1-5-32-545': ('Users', 'BUILTIN', 4),
            'S-1-5-32-546': ('Guests', 'BUILTIN', 4),
            'S-1-16-8192': ('Medium Mandatory Level', 'Mandatory Label', 10),
            'S-1-16-12288': ('High Mandatory Level', 'Mandatory Label', 10),
        }

    # Groups of the user's token: (SID, attributes)
    TOKEN_GROUPS = [('S-1-1-0', 0x7), ('S-1-5-32-544', 0xF), ('S-1-5-32-545', 0x7),
                    ('S-1-5-4', 0x7), ('S-1-5-11', 0x7), ('S-1-2-0', 0x7)]

    @staticmethod
    def _sid_bytes(text):
        """Binary SID of "S-1-5-32-544" (None if it isn't a valid SID string)"""
        parts = text.upper().split('-')
        if len(parts) < 3 or parts[0] != 'S' or parts[1] != '1':
            return None
        try:
            authority = int(parts[2], 0)
            subs = [int(p) for p in parts[3:]]
        except ValueError:
            return None
        if len(subs) > 15 or authority >= 1 << 48 or any(s >= 1 << 32 for s in subs):
            return None
        return (bytes([1, len(subs)]) + authority.to_bytes(6, 'big') +
                struct.pack(f'<{len(subs)}I', *subs))

    def _read_sid(self, address):
        """String form of a SID in memory (None if invalid)"""
        if not address:
            return None
        try:
            revision, count = self.emu.uc.mem_read(address, 2)
            if revision != 1 or count > 15:
                return None
            data = bytes(self.emu.uc.mem_read(address, 8 + 4 * count))
        except UcError:
            return None
        authority = int.from_bytes(data[2:8], 'big')
        subs = struct.unpack(f'<{count}I', data[8:])
        text = f'S-1-{authority}' if authority < 1 << 32 else f'S-1-0x{authority:012X}'
        return text + ''.join(f'-{s}' for s in subs)

    def _sid_length(self, address):
        try:
            return 8 + 4 * self.emu.uc.mem_read(address + 1, 1)[0]
        except UcError:
            return 0

    def _local_sid(self, text):
        """LocalAlloc copy of a SID"""
        data = self._sid_bytes(text)
        address = self.emu.heap_alloc(len(data))
        self._mem_write(address, data)
        return address

    def AllocateAndInitializeSid(self, args):
        """AllocateAndInitializeSid(authority, count, sub0..sub7, &sid)"""
        authority_addr, count = args[0], args[1]
        if count > 8 or not args[10]:
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0
        try:
            authority = bytes(self.emu.uc.mem_read(authority_addr, 6))
        except UcError:
            self._last_error = 998  # ERROR_NOACCESS
            return 0
        data = bytes([1, count]) + authority + struct.pack(f'<{count}I', *args[2:2 + count])
        address = self.emu.heap_alloc(len(data))
        self._mem_write(address, data)
        self._mem_write(args[10], struct.pack('<I', address))
        return 1

    def FreeSid(self, args):
        """FreeSid - NULL on success"""
        if args[0]:
            self.emu.heap_free(args[0])
        return 0

    def InitializeSid(self, args):
        """InitializeSid(sid, authority, count) - sub-authorities are zero"""
        try:
            authority = bytes(self.emu.uc.mem_read(args[1], 6))
        except UcError:
            return 0
        if args[2] > 15:
            return 0
        return 1 if self._mem_write(args[0], bytes([1, args[2]]) + authority +
                                    b'\x00' * 4 * args[2]) else 0

    def GetSidLengthRequired(self, args):
        return 8 + 4 * (args[0] & 0xFF)

    def IsValidSid(self, args):
        return 1 if self._read_sid(args[0]) is not None else 0

    def GetLengthSid(self, args):
        return self._sid_length(args[0]) if args[0] else 0

    def EqualSid(self, args):
        """EqualSid - same revision, authority and sub-authorities"""
        first, second = self._read_sid(args[0]), self._read_sid(args[1])
        self._last_error = 0
        return 1 if first is not None and first == second else 0

    def EqualPrefixSid(self, args):
        """EqualPrefixSid - equal without the last sub-authority"""
        first, second = self._read_sid(args[0]), self._read_sid(args[1])
        if first is None or second is None:
            return 0
        return 1 if first.rsplit('-', 1)[0] == second.rsplit('-', 1)[0] and \
            first.count('-') == second.count('-') else 0

    def CopySid(self, args):
        """CopySid(length, dest, src)"""
        length = self._sid_length(args[2])
        if not length:
            self._last_error = 87
            return 0
        if args[0] < length:
            self._last_error = 122  # ERROR_INSUFFICIENT_BUFFER
            return 0
        return 1 if self._mem_write(args[1], self.emu.uc.mem_read(args[2], length)) else 0

    def GetSidSubAuthority(self, args):
        return args[0] + 8 + 4 * args[1]

    def GetSidSubAuthorityCount(self, args):
        return args[0] + 1

    def GetSidIdentifierAuthority(self, args):
        return args[0] + 2

    def CreateWellKnownSid(self, args):
        """CreateWellKnownSid(type, domain SID, sid, &size)"""
        sid_type, sid, size_addr = args[0], args[2], args[3]
        text = self.WELL_KNOWN_SIDS.get(sid_type)
        if text is None:
            self._last_error = 87
            return 0
        data = self._sid_bytes(text)
        if not size_addr:
            self._last_error = 87
            return 0
        size = self._read_u32(size_addr)
        self._mem_write(size_addr, struct.pack('<I', len(data)))
        if not sid or size < len(data):
            self._last_error = 122
            return 0
        return 1 if self._mem_write(sid, data) else 0

    def IsWellKnownSid(self, args):
        """IsWellKnownSid(sid, type)"""
        text = self.WELL_KNOWN_SIDS.get(args[1])
        return 1 if text is not None and text == self._read_sid(args[0]) else 0

    def ConvertSidToStringSidA(self, args, wide=False):
        """ConvertSidToStringSidA/W(sid, &LocalAlloc'ed string)"""
        text = self._read_sid(args[0])
        if text is None or not args[1]:
            self._last_error = 1337  # ERROR_INVALID_SID
            return 0
        address = self._alloc_units(self._text_units(text, wide), wide)
        self._mem_write(args[1], struct.pack('<I', address))
        return 1

    def ConvertSidToStringSidW(self, args):
        return self.ConvertSidToStringSidA(args, wide=True)

    def ConvertStringSidToSidA(self, args, wide=False):
        """ConvertStringSidToSidA/W(string, &LocalAlloc'ed SID) - also SDDL names"""
        text = self._read_text(args[0], wide).strip() if args[0] else ''
        text = self.SDDL_SIDS.get(text.upper(), text)
        if self._sid_bytes(text) is None or not args[1]:
            self._last_error = 1337  # ERROR_INVALID_SID
            return 0
        self._mem_write(args[1], struct.pack('<I', self._local_sid(text)))
        return 1

    def ConvertStringSidToSidW(self, args):
        return self.ConvertStringSidToSidA(args, wide=True)

    def _store_account_text(self, text, buffer, size_addr, wide):
        """Write a name of LookupAccountSid/Name: (fits?, needed with the NUL)"""
        needed = len(self._text_units(text, wide)) + 1
        size = self._read_u32(size_addr) if size_addr else 0
        if not buffer or size < needed:
            return False, needed
        self._write_text(buffer, text, wide)
        return True, needed

    def _lookup_account_result(self, account, name_buf, name_size, domain_buf, domain_size,
                               use_addr, wide):
        name, domain, use = account
        name_ok, name_needed = self._store_account_text(name, name_buf, name_size, wide)
        domain_ok, domain_needed = self._store_account_text(domain, domain_buf, domain_size,
                                                            wide)
        if not (name_ok and domain_ok):
            if name_size:
                self._mem_write(name_size, struct.pack('<I', name_needed))
            if domain_size:
                self._mem_write(domain_size, struct.pack('<I', domain_needed))
            self._last_error = 122  # ERROR_INSUFFICIENT_BUFFER
            return False
        self._mem_write(name_size, struct.pack('<I', name_needed - 1))
        self._mem_write(domain_size, struct.pack('<I', domain_needed - 1))
        if use_addr:
            self._mem_write(use_addr, struct.pack('<I', use))
        return True

    def LookupAccountSidA(self, args, wide=False):
        """LookupAccountSidA/W(system, sid, name, &cch, domain, &cch, &use)"""
        account = self._known_accounts.get(self._read_sid(args[1]))
        if account is None:
            self._last_error = 1332  # ERROR_NONE_MAPPED
            return 0
        return 1 if self._lookup_account_result(account, args[2], args[3], args[4], args[5],
                                                args[6], wide) else 0

    def LookupAccountSidW(self, args):
        return self.LookupAccountSidA(args, wide=True)

    def LookupAccountNameA(self, args, wide=False):
        """LookupAccountNameA/W(system, name, sid, &cb, domain, &cch, &use)"""
        wanted = self._read_text(args[1], wide).lower() if args[1] else ''
        for sid, account in self._known_accounts.items():
            names = {account[0].lower()}
            if account[1]:
                names.add(f'{account[1]}\\{account[0]}'.lower())
            if wanted in names:
                break
        else:
            self._last_error = 1332  # ERROR_NONE_MAPPED
            return 0
        data = self._sid_bytes(sid)
        sid_size = self._read_u32(args[3]) if args[3] else 0
        domain_ok, domain_needed = self._store_account_text(account[1], args[4], args[5],
                                                            wide)
        if not args[2] or sid_size < len(data) or not domain_ok:
            if args[3]:
                self._mem_write(args[3], struct.pack('<I', len(data)))
            if args[5]:
                self._mem_write(args[5], struct.pack('<I', domain_needed))
            self._last_error = 122
            return 0
        self._mem_write(args[2], data)
        self._mem_write(args[3], struct.pack('<I', len(data)))
        self._mem_write(args[5], struct.pack('<I', domain_needed - 1))
        if args[6]:
            self._mem_write(args[6], struct.pack('<I', account[2]))
        return 1

    def LookupAccountNameW(self, args):
        return self.LookupAccountNameA(args, wide=True)

    def LookupPrivilegeNameA(self, args, wide=False):
        """LookupPrivilegeNameA/W(system, &luid, name, &cch)"""
        try:
            luid = struct.unpack('<I', self.emu.uc.mem_read(args[1], 4))[0]
        except UcError:
            self._last_error = 998
            return 0
        for key, value in self.PRIVILEGE_LUIDS.items():
            if value == luid:
                name = self.PRIVILEGE_NAMES[key]
                break
        else:
            self._last_error = 1313  # ERROR_NO_SUCH_PRIVILEGE
            return 0
        units = self._text_units(name, wide)
        size = self._read_u32(args[3])
        if not args[2] or size <= len(units):
            self._mem_write(args[3], struct.pack('<I', len(units) + 1))
            self._last_error = 122
            return 0
        self._write_units(args[2], units, wide)
        self._mem_write(args[3], struct.pack('<I', len(units)))
        return 1

    def LookupPrivilegeNameW(self, args):
        return self.LookupPrivilegeNameA(args, wide=True)

    # Lower-case privilege name -> its proper spelling
    PRIVILEGE_NAMES = {
        'secreatetokenprivilege': 'SeCreateTokenPrivilege',
        'seassignprimarytokenprivilege': 'SeAssignPrimaryTokenPrivilege',
        'selockmemoryprivilege': 'SeLockMemoryPrivilege',
        'seincreasequotaprivilege': 'SeIncreaseQuotaPrivilege',
        'semachineaccountprivilege': 'SeMachineAccountPrivilege',
        'setcbprivilege': 'SeTcbPrivilege', 'sesecurityprivilege': 'SeSecurityPrivilege',
        'setakeownershipprivilege': 'SeTakeOwnershipPrivilege',
        'seloaddriverprivilege': 'SeLoadDriverPrivilege',
        'sesystemprofileprivilege': 'SeSystemProfilePrivilege',
        'sesystemtimeprivilege': 'SeSystemtimePrivilege',
        'seprofilesingleprocessprivilege': 'SeProfileSingleProcessPrivilege',
        'seincreasebasepriorityprivilege': 'SeIncreaseBasePriorityPrivilege',
        'secreatepagefileprivilege': 'SeCreatePagefilePrivilege',
        'secreatepermanentprivilege': 'SeCreatePermanentPrivilege',
        'sebackupprivilege': 'SeBackupPrivilege', 'serestoreprivilege': 'SeRestorePrivilege',
        'seshutdownprivilege': 'SeShutdownPrivilege', 'sedebugprivilege': 'SeDebugPrivilege',
        'seauditprivilege': 'SeAuditPrivilege',
        'sesystemenvironmentprivilege': 'SeSystemEnvironmentPrivilege',
        'sechangenotifyprivilege': 'SeChangeNotifyPrivilege',
        'seremoteshutdownprivilege': 'SeRemoteShutdownPrivilege',
        'seundockprivilege': 'SeUndockPrivilege',
    }

    # ---------- Access tokens ----------

    # Pseudo handles of GetCurrentProcessToken/ThreadToken/ThreadEffectiveToken
    PSEUDO_TOKENS = (0xFFFFFFFC, 0xFFFFFFFB, 0xFFFFFFFA)

    def _token_info(self, handle):
        if handle in self.PSEUDO_TOKENS:
            return {'type': 'token'}
        info = self.handles.get(handle)
        return info if info and info.get('type') == 'token' else None

    def _new_token(self, out_addr, access=0):
        handle = self.get_next_handle()
        self.handles[handle] = {'type': 'token', 'access': access}
        if not self._mem_write(out_addr, struct.pack('<I', handle)):
            del self.handles[handle]
            self._last_error = 998  # ERROR_NOACCESS
            return 0
        return 1

    def _sid_and_attributes(self, base, entries, offset):
        """SID_AND_ATTRIBUTES array at base followed by the SIDs (at offset)"""
        array, sids = b'', b''
        for sid, attributes in entries:
            array += struct.pack('<II', base + offset + len(sids), attributes)
            sids += self._sid_bytes(sid)
        return array, sids

    def _token_information(self, token_class, base):
        """Bytes of a TOKEN_INFORMATION_CLASS structure placed at base (None:
        unsupported class)"""
        if token_class == 1:  # TokenUser
            array, sids = self._sid_and_attributes(base, [(self.USER_SID, 0)], 8)
            return array + sids
        if token_class == 2:  # TokenGroups
            offset = 4 + 8 * len(self.TOKEN_GROUPS)
            array, sids = self._sid_and_attributes(base, self.TOKEN_GROUPS, offset)
            return struct.pack('<I', len(self.TOKEN_GROUPS)) + array + sids
        if token_class == 3:  # TokenPrivileges: every privilege, change notify enabled
            entries = sorted(self.PRIVILEGE_LUIDS.values())
            data = struct.pack('<I', len(entries))
            for luid in entries:
                data += struct.pack('<IiI', luid, 0, 3 if luid == 23 else 0)
            return data
        if token_class in (4, 5):  # TokenOwner, TokenPrimaryGroup
            sid = self.USER_SID if token_class == 4 else self.USER_DOMAIN_SID + '-513'
            return struct.pack('<I', base + 4) + self._sid_bytes(sid)
        if token_class == 6:  # TokenDefaultDacl: NULL (everyone has access)
            return struct.pack('<I', 0)
        if token_class == 7:  # TokenSource
            return b'User32 \x00' + struct.pack('<Ii', 0x3E7, 0)
        if token_class == 8:  # TokenType: TokenPrimary
            return struct.pack('<I', 1)
        if token_class == 10:  # TokenStatistics
            return struct.pack('<IiIiqIIIIIIi', 0x1000, 0, 0x3E7, 0, 0x7FFFFFFFFFFFFFFF,
                               1, 2, 0, len(self.TOKEN_GROUPS), len(self.PRIVILEGE_LUIDS),
                               0x2000, 0)
        if token_class == 12:  # TokenSessionId
            return struct.pack('<I', 1)
        if token_class == 18:  # TokenElevationType: TokenElevationTypeDefault
            return struct.pack('<I', 1)
        if token_class == 20:  # TokenElevation: elevated (the user is an administrator)
            return struct.pack('<I', 1)
        if token_class in (21, 22, 23, 24, 26, 29):
            # TokenHasRestrictions, TokenAccessInformation (not supported here:
            # handled below), TokenVirtualizationAllowed/Enabled, TokenUIAccess,
            # TokenIsAppContainer
            return None if token_class == 22 else struct.pack('<I', 0)
        if token_class == 25:  # TokenIntegrityLevel: high
            array, sids = self._sid_and_attributes(base, [('S-1-16-12288', 0x20)], 8)
            return array + sids
        return None

    def GetTokenInformation(self, args):
        """GetTokenInformation(token, class, buffer, size, &needed)"""
        token, token_class, buffer, size, needed_addr = args[:5]
        if self._token_info(token) is None:
            self._last_error = 6  # ERROR_INVALID_HANDLE
            return 0
        data = self._token_information(token_class, buffer)
        if data is None:
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0
        if needed_addr:
            self._mem_write(needed_addr, struct.pack('<I', len(data)))
        if not buffer or size < len(data):
            self._last_error = 122  # ERROR_INSUFFICIENT_BUFFER
            return 0
        return 1 if self._mem_write(buffer, data) else 0

    def SetTokenInformation(self, args):
        return 1 if self._token_info(args[0]) is not None else 0

    def OpenThreadToken(self, args):
        """OpenThreadToken - threads don't impersonate: ERROR_NO_TOKEN"""
        if self.emu.current_thread.tid in self.__dict__.get('_impersonating', ()):
            return self._new_token(args[3], args[1])
        self._last_error = 1008  # ERROR_NO_TOKEN
        return 0

    def DuplicateToken(self, args):
        """DuplicateToken(token, level, &new)"""
        if self._token_info(args[0]) is None:
            self._last_error = 6
            return 0
        return self._new_token(args[2])

    def DuplicateTokenEx(self, args):
        """DuplicateTokenEx(token, access, attributes, level, type, &new)"""
        if self._token_info(args[0]) is None:
            self._last_error = 6
            return 0
        return self._new_token(args[5], args[1])

    def ImpersonateSelf(self, args):
        self.__dict__.setdefault('_impersonating', set()).add(self.emu.current_thread.tid)
        return 1

    def ImpersonateLoggedOnUser(self, args):
        return self.ImpersonateSelf(args)

    def RevertToSelf(self, args):
        self.__dict__.get('_impersonating', set()).discard(self.emu.current_thread.tid)
        return 1

    def CheckTokenMembership(self, args):
        """CheckTokenMembership(token, sid, &is member)"""
        if args[0] and self._token_info(args[0]) is None:
            self._last_error = 6
            return 0
        sid = self._read_sid(args[1])
        if sid is None:
            self._last_error = 1337  # ERROR_INVALID_SID
            return 0
        member = sid == self.USER_SID or any(sid == group for group, _ in self.TOKEN_GROUPS)
        return 1 if self._mem_write(args[2], struct.pack('<I', 1 if member else 0)) else 0

    def IsUserAnAdmin(self, args):
        """IsUserAnAdmin (shell32) - the user is an administrator"""
        return 1

    def GetCurrentHwProfileA(self, args, wide=False):
        """GetCurrentHwProfileA/W(HW_PROFILE_INFO)"""
        guid = '{d0f9a1f0-3c39-11e0-8f6a-806d6172696f}'
        unit = 2 if wide else 1
        data = struct.pack('<I', 2)  # DOCKINFO_DOCKED
        data += self._pack_units(self._text_units(guid, wide), wide).ljust(39 * unit, b'\x00')
        data += self._pack_units(self._text_units('Profile 1', wide),
                                 wide).ljust(80 * unit, b'\x00')
        return 1 if self._mem_write(args[0], data) else 0

    def GetCurrentHwProfileW(self, args):
        return self.GetCurrentHwProfileA(args, wide=True)

    # ---------- Security descriptors and ACLs ----------

    SE_OWNER_DEFAULTED, SE_GROUP_DEFAULTED, SE_DACL_PRESENT = 0x1, 0x2, 0x4
    SE_DACL_DEFAULTED, SE_SELF_RELATIVE = 0x8, 0x8000

    def _sd_header(self, address):
        """(revision, control, owner, group, sacl, dacl) of a security
        descriptor; the pointers are addresses even if it's self-relative"""
        try:
            revision, _, control, owner, group, sacl, dacl = struct.unpack(
                '<BBHIIII', self.emu.uc.mem_read(address, 20))
        except UcError:
            return None
        if control & self.SE_SELF_RELATIVE:
            owner, group, sacl, dacl = (address + p if p else 0
                                        for p in (owner, group, sacl, dacl))
        return revision, control, owner, group, sacl, dacl

    def InitializeSecurityDescriptor(self, args):
        """InitializeSecurityDescriptor(sd, revision) - an empty absolute descriptor"""
        if args[1] != 1:
            self._last_error = 1338  # ERROR_INVALID_SECURITY_DESCR
            return 0
        return 1 if self._mem_write(args[0], struct.pack('<BBH4I', 1, 0, 0, 0, 0, 0, 0)) else 0

    def IsValidSecurityDescriptor(self, args):
        header = self._sd_header(args[0])
        return 1 if header and header[0] == 1 else 0

    def GetSecurityDescriptorLength(self, args):
        """GetSecurityDescriptorLength - the header and what it points to"""
        header = self._sd_header(args[0])
        if not header:
            return 0
        length = 20
        for sid in header[2:4]:
            if sid:
                length += self._sid_length(sid)
        for acl in header[4:6]:
            if acl:
                length += self._acl_header(acl)[1]
        return length

    def GetSecurityDescriptorControl(self, args):
        """GetSecurityDescriptorControl(sd, &control, &revision)"""
        header = self._sd_header(args[0])
        if not header:
            self._last_error = 1338
            return 0
        self._mem_write(args[1], struct.pack('<H', header[1]))
        self._mem_write(args[2], struct.pack('<I', header[0]))
        return 1

    def _sd_set(self, address, offset, value, set_bits, clear_bits):
        header = self._sd_header(address)
        if not header or header[1] & self.SE_SELF_RELATIVE:
            self._last_error = 1338  # ERROR_INVALID_SECURITY_DESCR
            return 0
        control = (header[1] & ~clear_bits) | set_bits
        self._mem_write(address + 2, struct.pack('<H', control))
        self._mem_write(address + offset, struct.pack('<I', value))
        return 1

    def SetSecurityDescriptorDacl(self, args):
        """SetSecurityDescriptorDacl(sd, present, dacl, defaulted)"""
        bits = (self.SE_DACL_PRESENT if args[1] else 0) | \
            (self.SE_DACL_DEFAULTED if args[3] else 0)
        return self._sd_set(args[0], 16, args[2] if args[1] else 0, bits,
                            self.SE_DACL_PRESENT | self.SE_DACL_DEFAULTED)

    def SetSecurityDescriptorSacl(self, args):
        bits = (0x10 if args[1] else 0) | (0x20 if args[3] else 0)
        return self._sd_set(args[0], 12, args[2] if args[1] else 0, bits, 0x30)

    def SetSecurityDescriptorOwner(self, args):
        """SetSecurityDescriptorOwner(sd, sid, defaulted)"""
        return self._sd_set(args[0], 4, args[1], self.SE_OWNER_DEFAULTED if args[2] else 0,
                            self.SE_OWNER_DEFAULTED)

    def SetSecurityDescriptorGroup(self, args):
        return self._sd_set(args[0], 8, args[1], self.SE_GROUP_DEFAULTED if args[2] else 0,
                            self.SE_GROUP_DEFAULTED)

    def GetSecurityDescriptorDacl(self, args):
        """GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted)"""
        header = self._sd_header(args[0])
        if not header:
            self._last_error = 1338
            return 0
        present = 1 if header[1] & self.SE_DACL_PRESENT else 0
        self._mem_write(args[1], struct.pack('<I', present))
        if present:
            self._mem_write(args[2], struct.pack('<I', header[5]))
            self._mem_write(args[3], struct.pack(
                '<I', 1 if header[1] & self.SE_DACL_DEFAULTED else 0))
        return 1

    def GetSecurityDescriptorSacl(self, args):
        header = self._sd_header(args[0])
        if not header:
            self._last_error = 1338
            return 0
        present = 1 if header[1] & 0x10 else 0
        self._mem_write(args[1], struct.pack('<I', present))
        if present:
            self._mem_write(args[2], struct.pack('<I', header[4]))
            self._mem_write(args[3], struct.pack('<I', 1 if header[1] & 0x20 else 0))
        return 1

    def GetSecurityDescriptorOwner(self, args):
        """GetSecurityDescriptorOwner(sd, &owner, &defaulted)"""
        header = self._sd_header(args[0])
        if not header:
            self._last_error = 1338
            return 0
        self._mem_write(args[1], struct.pack('<I', header[2]))
        self._mem_write(args[2], struct.pack('<I', header[1] & self.SE_OWNER_DEFAULTED))
        return 1

    def GetSecurityDescriptorGroup(self, args):
        header = self._sd_header(args[0])
        if not header:
            self._last_error = 1338
            return 0
        self._mem_write(args[1], struct.pack('<I', header[3]))
        self._mem_write(args[2], struct.pack('<I', 1 if header[1] & 2 else 0))
        return 1

    def _acl_header(self, acl):
        """(revision, size, ACE count) of an ACL"""
        try:
            revision, _, size, count, _ = struct.unpack('<BBHHH', self.emu.uc.mem_read(acl, 8))
        except UcError:
            return 0, 0, 0
        return revision, size, count

    def _acl_end(self, acl):
        """Offset after the last ACE of an ACL"""
        _, _, count = self._acl_header(acl)
        offset = 8
        for _ in range(count):
            offset += struct.unpack('<H', self.emu.uc.mem_read(acl + offset + 2, 2))[0]
        return offset

    def InitializeAcl(self, args):
        """InitializeAcl(acl, size, revision)"""
        if args[1] < 8 or args[2] not in (2, 4):
            self._last_error = 87
            return 0
        return 1 if self._mem_write(args[0], struct.pack('<BBHHH', args[2], 0, args[1] & ~3,
                                                          0, 0)) else 0

    def IsValidAcl(self, args):
        revision, size, _ = self._acl_header(args[0])
        return 1 if revision in (2, 4) and size >= 8 else 0

    def _add_ace(self, acl, ace_type, flags, mask, sid_addr):
        sid = self._read_sid(sid_addr)
        if sid is None:
            self._last_error = 1337  # ERROR_INVALID_SID
            return 0
        revision, size, count = self._acl_header(acl)
        if revision not in (2, 4):
            self._last_error = 1336  # ERROR_INVALID_ACL
            return 0
        sid_data = self._sid_bytes(sid)
        ace = struct.pack('<BBHI', ace_type, flags, 8 + len(sid_data), mask) + sid_data
        end = self._acl_end(acl)
        if end + len(ace) > size:
            self._last_error = 1344  # ERROR_ALLOTTED_SPACE_EXCEEDED
            return 0
        self._mem_write(acl + end, ace)
        self._mem_write(acl + 4, struct.pack('<H', count + 1))
        return 1

    def AddAccessAllowedAce(self, args):
        """AddAccessAllowedAce(acl, revision, mask, sid)"""
        return self._add_ace(args[0], 0, 0, args[2], args[3])

    def AddAccessAllowedAceEx(self, args):
        """AddAccessAllowedAceEx(acl, revision, flags, mask, sid)"""
        return self._add_ace(args[0], 0, args[2], args[3], args[4])

    def AddAccessDeniedAce(self, args):
        return self._add_ace(args[0], 1, 0, args[2], args[3])

    def AddAccessDeniedAceEx(self, args):
        return self._add_ace(args[0], 1, args[2], args[3], args[4])

    def GetAce(self, args):
        """GetAce(acl, index, &ace)"""
        _, _, count = self._acl_header(args[0])
        if args[1] >= count:
            self._last_error = 87
            return 0
        offset = 8
        for _ in range(args[1]):
            offset += struct.unpack('<H', self.emu.uc.mem_read(args[0] + offset + 2, 2))[0]
        return 1 if self._mem_write(args[2], struct.pack('<I', args[0] + offset)) else 0

    def GetAclInformation(self, args):
        """GetAclInformation(acl, info, size, class) - revision or size information"""
        revision, size, count = self._acl_header(args[0])
        if args[3] == 1:  # AclRevisionInformation
            data = struct.pack('<I', revision)
        elif args[3] == 2:  # AclSizeInformation
            used = self._acl_end(args[0])
            data = struct.pack('<III', count, used, size - used)
        else:
            self._last_error = 87
            return 0
        if args[2] < len(data):
            self._last_error = 122
            return 0
        return 1 if self._mem_write(args[1], data) else 0

    def _new_acl(self, aces):
        """LocalAlloc'ed ACL with (type, flags, mask, SID string) ACEs"""
        body = b''
        for ace_type, flags, mask, sid in aces:
            sid_data = self._sid_bytes(sid)
            body += struct.pack('<BBHI', ace_type, flags, 8 + len(sid_data), mask) + sid_data
        data = struct.pack('<BBHHH', 2, 0, 8 + len(body), len(aces), 0) + body
        address = self.emu.heap_alloc(len(data))
        self._mem_write(address, data)
        return address

    def _acl_aces(self, acl):
        """(type, flags, mask, SID string) of the ACEs of an ACL"""
        aces = []
        if not acl:
            return aces
        _, _, count = self._acl_header(acl)
        offset = 8
        for _ in range(count):
            ace_type, flags, size, mask = struct.unpack(
                '<BBHI', self.emu.uc.mem_read(acl + offset, 8))
            sid = self._read_sid(acl + offset + 8)
            if sid is not None:
                aces.append((ace_type, flags, mask, sid))
            offset += size
        return aces

    def _trustee_sid(self, trustee, wide):
        """SID string of a TRUSTEE (by SID or by account name)"""
        # TRUSTEE: pMultipleTrustee, MultipleTrusteeOperation, TrusteeForm,
        # TrusteeType, ptstrName
        _, _, form, _, name = struct.unpack('<5I', self.emu.uc.mem_read(trustee, 20))
        if form == 0:  # TRUSTEE_IS_SID
            return self._read_sid(name)
        if form == 1:  # TRUSTEE_IS_NAME
            text = self._read_text(name, wide).lower()
            if text == 'current_user':
                return self.USER_SID
            for sid, account in self._known_accounts.items():
                if text in (account[0].lower(), f'{account[1]}\\{account[0]}'.lower()):
                    return sid
        return None

    def SetEntriesInAclA(self, args, wide=False):
        """SetEntriesInAclA/W(count, EXPLICIT_ACCESS[], old ACL, &new ACL)"""
        aces = self._acl_aces(args[2])
        for i in range(args[0]):
            entry = args[1] + 32 * i
            try:
                mask, mode, inheritance = struct.unpack('<III',
                                                        self.emu.uc.mem_read(entry, 12))
                sid = self._trustee_sid(entry + 12, wide)
            except UcError:
                return 87  # ERROR_INVALID_PARAMETER
            if sid is None:
                return 1332  # ERROR_NONE_MAPPED
            if mode in (2, 4):  # SET_ACCESS, REVOKE_ACCESS: drop the trustee's ACEs
                aces = [ace for ace in aces if ace[3] != sid]
            if mode in (1, 2):  # GRANT_ACCESS, SET_ACCESS
                aces.append((0, inheritance & 0xFF, mask, sid))
            elif mode == 3:  # DENY_ACCESS: denials come first
                aces.insert(0, (1, inheritance & 0xFF, mask, sid))
        if not self._mem_write(args[3], struct.pack('<I', self._new_acl(aces))):
            return 87
        return 0

    def SetEntriesInAclW(self, args):
        return self.SetEntriesInAclA(args, wide=True)

    def _new_security_descriptor(self, out_owner, out_group, out_dacl, out_sacl, out_sd):
        """A LocalAlloc'ed self-relative descriptor: the user owns the object,
        Everyone and the user have full access (GetNamedSecurityInfo)"""
        owner = self._sid_bytes(self.USER_SID)
        group = self._sid_bytes(self.USER_DOMAIN_SID + '-513')
        acl_body = b''
        for sid in ('S-1-1-0', self.USER_SID):
            data = self._sid_bytes(sid)
            acl_body += struct.pack('<BBHI', 0, 0, 8 + len(data), 0x1F01FF) + data
        dacl = struct.pack('<BBHHH', 2, 0, 8 + len(acl_body), 2, 0) + acl_body
        owner_off, group_off = 20, 20 + len(owner)
        dacl_off = group_off + len(group)
        data = struct.pack('<BBHIIII', 1, 0, self.SE_SELF_RELATIVE | self.SE_DACL_PRESENT,
                           owner_off, group_off, 0, dacl_off) + owner + group + dacl
        address = self.emu.heap_alloc(len(data))
        self._mem_write(address, data)
        for out, offset in ((out_owner, owner_off), (out_group, group_off),
                            (out_dacl, dacl_off)):
            if out:
                self._mem_write(out, struct.pack('<I', address + offset))
        if out_sacl:
            self._mem_write(out_sacl, struct.pack('<I', 0))
        if out_sd:
            self._mem_write(out_sd, struct.pack('<I', address))
        return 0

    def GetNamedSecurityInfoA(self, args, wide=False):
        """GetNamedSecurityInfoA/W(name, type, info, &owner, &group, &dacl, &sacl, &sd)"""
        name = self._read_text(args[0], wide) if args[0] else ''
        if args[1] == 1:  # SE_FILE_OBJECT
            path = self.resolve_drive_path(name)
            if path is None:
                return 5  # ERROR_ACCESS_DENIED
            if not os.path.exists(path):
                return 2  # ERROR_FILE_NOT_FOUND
        return self._new_security_descriptor(*args[3:8])

    def GetNamedSecurityInfoW(self, args):
        return self.GetNamedSecurityInfoA(args, wide=True)

    def GetSecurityInfo(self, args):
        """GetSecurityInfo(handle, type, info, &owner, &group, &dacl, &sacl, &sd)"""
        return self._new_security_descriptor(*args[3:8])

    def SetNamedSecurityInfoA(self, args, wide=False):
        """SetNamedSecurityInfoA/W - the files have no security: ERROR_SUCCESS"""
        if args[1] == 1:
            path = self.resolve_drive_path(self._read_text(args[0], wide) if args[0] else '')
            if path is None:
                return 5
            if not os.path.exists(path):
                return 2
        return 0

    def SetNamedSecurityInfoW(self, args):
        return self.SetNamedSecurityInfoA(args, wide=True)

    def SetSecurityInfo(self, args):
        return 0

    def ConvertStringSecurityDescriptorToSecurityDescriptorA(self, args, wide=False):
        """ConvertStringSecurityDescriptorToSecurityDescriptorA/W(sddl, revision,
        &sd, &size) - a self-relative descriptor with a NULL DACL (full access)"""
        if args[1] != 1 or not args[2]:
            self._last_error = 87
            return 0
        data = struct.pack('<BBHIIII', 1, 0, self.SE_SELF_RELATIVE | self.SE_DACL_PRESENT,
                           0, 0, 0, 0)
        address = self.emu.heap_alloc(len(data))
        self._mem_write(address, data)
        self._mem_write(args[2], struct.pack('<I', address))
        if args[3]:
            self._mem_write(args[3], struct.pack('<I', len(data)))
        return 1

    def ConvertStringSecurityDescriptorToSecurityDescriptorW(self, args):
        return self.ConvertStringSecurityDescriptorToSecurityDescriptorA(args, wide=True)

    def GetFileSecurityA(self, args):
        return self.GetFileSecurityW(args)

    def SetFileSecurityA(self, args):
        return self.SetFileSecurityW(args)

    # ---------- CryptoAPI ----------

    # ALG_ID -> hashlib name
    CRYPT_HASHES = {0x8001: 'md2', 0x8002: 'md4', 0x8003: 'md5', 0x8004: 'sha1',
                    0x800C: 'sha256', 0x800D: 'sha384', 0x800E: 'sha512'}
    NTE_BAD_ALGID = 0x80090008
    NTE_BAD_HASH = 0x80090002
    NTE_BAD_KEYSET = 0x80090016

    def CryptAcquireContextA(self, args, wide=False):
        """CryptAcquireContextA/W(&prov, container, provider, type, flags)"""
        flags = args[4]
        if flags & 0x10:  # CRYPT_DELETEKEYSET
            return 1
        handle = self.get_next_handle()
        self.handles[handle] = {'type': 'crypt_prov', 'refs': 1}
        if not self._mem_write(args[0], struct.pack('<I', handle)):
            del self.handles[handle]
            self._last_error = 87
            return 0
        return 1

    def CryptAcquireContextW(self, args):
        return self.CryptAcquireContextA(args, wide=True)

    def _crypt_handle(self, handle, kind):
        info = self.handles.get(handle)
        if not info or info.get('type') != kind:
            self._last_error = 6  # ERROR_INVALID_HANDLE
            return None
        return info

    def CryptReleaseContext(self, args):
        info = self._crypt_handle(args[0], 'crypt_prov')
        if info is None:
            return 0
        info['refs'] -= 1
        if info['refs'] <= 0:
            del self.handles[args[0]]
        return 1

    def CryptContextAddRef(self, args):
        info = self._crypt_handle(args[0], 'crypt_prov')
        if info is None:
            return 0
        info['refs'] += 1
        return 1

    def CryptGenRandom(self, args):
        """CryptGenRandom(prov, length, buffer)"""
        if self._crypt_handle(args[0], 'crypt_prov') is None:
            return 0
        return 1 if self._mem_write(args[2], os.urandom(args[1])) else 0

    def _new_hash(self, algorithm, key=None):
        try:
            state = hmac.new(key, digestmod=algorithm) if key is not None else \
                hashlib.new(algorithm)
        except (ValueError, TypeError):
            return None
        return state

    def CryptCreateHash(self, args):
        """CryptCreateHash(prov, algid, key, flags, &hash)"""
        if self._crypt_handle(args[0], 'crypt_prov') is None:
            return 0
        name = self.CRYPT_HASHES.get(args[1])
        state = self._new_hash(name) if name else None
        if state is None:
            self._last_error = self.NTE_BAD_ALGID
            return 0
        handle = self.get_next_handle()
        self.handles[handle] = {'type': 'crypt_hash', 'algid': args[1], 'state': state,
                                'done': False}
        self._mem_write(args[4], struct.pack('<I', handle))
        return 1

    def CryptHashData(self, args):
        """CryptHashData(hash, data, length, flags)"""
        info = self._crypt_handle(args[0], 'crypt_hash')
        if info is None:
            return 0
        if info['done']:
            self._last_error = self.NTE_BAD_HASH
            return 0
        try:
            info['state'].update(bytes(self.emu.uc.mem_read(args[1], args[2])) if args[2]
                                 else b'')
        except UcError:
            self._last_error = 998
            return 0
        return 1

    def CryptGetHashParam(self, args):
        """CryptGetHashParam(hash, param, data, &length, flags)"""
        info = self._crypt_handle(args[0], 'crypt_hash')
        if info is None:
            return 0
        if args[1] == 1:  # HP_ALGID
            data = struct.pack('<I', info['algid'])
        elif args[1] == 2:  # HP_HASHVAL: the hash can't take more data afterwards
            data = info['state'].copy().digest()
            info['done'] = True
        elif args[1] == 4:  # HP_HASHSIZE
            data = struct.pack('<I', info['state'].digest_size)
        else:
            self._last_error = 0x80090009  # NTE_BAD_TYPE
            return 0
        size = self._read_u32(args[3])
        self._mem_write(args[3], struct.pack('<I', len(data)))
        if not args[2]:
            return 1
        if size < len(data):
            self._last_error = 234  # ERROR_MORE_DATA
            return 0
        return 1 if self._mem_write(args[2], data) else 0

    def CryptDestroyHash(self, args):
        if self._crypt_handle(args[0], 'crypt_hash') is None:
            return 0
        del self.handles[args[0]]
        return 1

    def CryptDuplicateHash(self, args):
        """CryptDuplicateHash(hash, reserved, flags, &new)"""
        info = self._crypt_handle(args[0], 'crypt_hash')
        if info is None:
            return 0
        handle = self.get_next_handle()
        self.handles[handle] = dict(info, state=info['state'].copy())
        self._mem_write(args[3], struct.pack('<I', handle))
        return 1

    # ---------- BCrypt (CNG) ----------

    STATUS_SUCCESS = 0
    STATUS_INVALID_HANDLE = 0xC0000008
    STATUS_INVALID_PARAMETER = 0xC000000D
    STATUS_NOT_FOUND = 0xC0000225
    STATUS_BUFFER_TOO_SMALL = 0xC0000023
    STATUS_NOT_SUPPORTED = 0xC00000BB

    BCRYPT_HASHES = {'MD2': 'md2', 'MD4': 'md4', 'MD5': 'md5', 'SHA1': 'sha1',
                     'SHA256': 'sha256', 'SHA384': 'sha384', 'SHA512': 'sha512'}
    BCRYPT_RNG = ('RNG', 'FIPS186DSARNG', 'DUALECRNG')

    def BCryptOpenAlgorithmProvider(self, args):
        """BCryptOpenAlgorithmProvider(&alg, id, implementation, flags)"""
        name = self.read_wide_string(args[1]).upper() if args[1] else ''
        if name not in self.BCRYPT_HASHES and name not in self.BCRYPT_RNG:
            return self.STATUS_NOT_FOUND
        handle = self.get_next_handle()
        self.handles[handle] = {'type': 'bcrypt_alg', 'name': name,
                                'hmac': bool(args[3] & 0x8)}  # BCRYPT_ALG_HANDLE_HMAC_FLAG
        if not self._mem_write(args[0], struct.pack('<I', handle)):
            del self.handles[handle]
            return self.STATUS_INVALID_PARAMETER
        return self.STATUS_SUCCESS

    def BCryptCloseAlgorithmProvider(self, args):
        info = self.handles.get(args[0])
        if not info or info.get('type') != 'bcrypt_alg':
            return self.STATUS_INVALID_HANDLE
        del self.handles[args[0]]
        return self.STATUS_SUCCESS

    def BCryptGenRandom(self, args):
        """BCryptGenRandom(alg, buffer, length, flags) - also with
        BCRYPT_USE_SYSTEM_PREFERRED_RNG and no algorithm"""
        if args[0]:
            info = self.handles.get(args[0])
            if not info or info.get('type') != 'bcrypt_alg':
                return self.STATUS_INVALID_HANDLE
        elif not args[3] & 0x2:
            return self.STATUS_INVALID_HANDLE
        if args[2] and not self._mem_write(args[1], os.urandom(args[2])):
            return self.STATUS_INVALID_PARAMETER
        return self.STATUS_SUCCESS

    def BCryptGetProperty(self, args):
        """BCryptGetProperty(object, property, output, size, &result, flags)"""
        info = self.handles.get(args[0])
        if not info or info.get('type') not in ('bcrypt_alg', 'bcrypt_hash'):
            return self.STATUS_INVALID_HANDLE
        prop = self.read_wide_string(args[1]) if args[1] else ''
        algorithm = self.BCRYPT_HASHES.get(info['name'])
        if prop == 'HashDigestLength' and algorithm:
            data = struct.pack('<I', hashlib.new(algorithm).digest_size)
        elif prop == 'ObjectLength':
            data = struct.pack('<I', 64)
        elif prop == 'HashBlockLength' and algorithm:
            data = struct.pack('<I', hashlib.new(algorithm).block_size)
        elif prop == 'AlgorithmName':
            data = (info['name'] + '\x00').encode('utf-16-le')
        else:
            return self.STATUS_NOT_SUPPORTED
        if args[4]:
            self._mem_write(args[4], struct.pack('<I', len(data)))
        if not args[2]:
            return self.STATUS_SUCCESS
        if args[3] < len(data):
            return self.STATUS_BUFFER_TOO_SMALL
        self._mem_write(args[2], data)
        return self.STATUS_SUCCESS

    def BCryptCreateHash(self, args):
        """BCryptCreateHash(alg, &hash, object, object size, secret, secret size, flags)"""
        info = self.handles.get(args[0])
        if not info or info.get('type') != 'bcrypt_alg':
            return self.STATUS_INVALID_HANDLE
        algorithm = self.BCRYPT_HASHES.get(info['name'])
        if not algorithm:
            return self.STATUS_NOT_SUPPORTED
        key = None
        if info['hmac']:
            try:
                key = bytes(self.emu.uc.mem_read(args[4], args[5])) if args[5] else b''
            except UcError:
                return self.STATUS_INVALID_PARAMETER
        state = self._new_hash(algorithm, key)
        if state is None:
            return self.STATUS_NOT_SUPPORTED
        handle = self.get_next_handle()
        self.handles[handle] = {'type': 'bcrypt_hash', 'name': info['name'], 'state': state}
        if not self._mem_write(args[1], struct.pack('<I', handle)):
            del self.handles[handle]
            return self.STATUS_INVALID_PARAMETER
        return self.STATUS_SUCCESS

    def BCryptHashData(self, args):
        """BCryptHashData(hash, input, length, flags)"""
        info = self.handles.get(args[0])
        if not info or info.get('type') != 'bcrypt_hash':
            return self.STATUS_INVALID_HANDLE
        try:
            info['state'].update(bytes(self.emu.uc.mem_read(args[1], args[2])) if args[2]
                                 else b'')
        except UcError:
            return self.STATUS_INVALID_PARAMETER
        return self.STATUS_SUCCESS

    def BCryptFinishHash(self, args):
        """BCryptFinishHash(hash, output, length, flags) - length must be the digest size"""
        info = self.handles.get(args[0])
        if not info or info.get('type') != 'bcrypt_hash':
            return self.STATUS_INVALID_HANDLE
        digest = info['state'].digest()
        if args[2] != len(digest):
            return self.STATUS_INVALID_PARAMETER
        self._mem_write(args[1], digest)
        return self.STATUS_SUCCESS

    def BCryptDestroyHash(self, args):
        info = self.handles.get(args[0])
        if not info or info.get('type') != 'bcrypt_hash':
            return self.STATUS_INVALID_HANDLE
        del self.handles[args[0]]
        return self.STATUS_SUCCESS

    # ---------- Service control manager: no services are installed ----------

    def OpenSCManagerA(self, args, wide=False):
        """OpenSCManagerA/W(machine, database, access)"""
        if args[0] and self._read_text(args[0], wide).strip('\\').upper() not in (
                '', self.COMPUTER_NAME):
            self._last_error = 1722  # RPC_S_SERVER_UNAVAILABLE
            return 0
        handle = self.get_next_handle()
        self.handles[handle] = {'type': 'scm'}
        return handle

    def OpenSCManagerW(self, args):
        return self.OpenSCManagerA(args, wide=True)

    def OpenServiceA(self, args, wide=False):
        """OpenServiceA/W - no service is installed"""
        if self._crypt_handle(args[0], 'scm') is None:
            return 0
        log.debug(f"OpenService(\"{self._read_text(args[1], wide)}\") -> not installed")
        self._last_error = 1060  # ERROR_SERVICE_DOES_NOT_EXIST
        return 0

    def OpenServiceW(self, args):
        return self.OpenServiceA(args, wide=True)

    def CreateServiceA(self, args):
        """CreateServiceA/W - installing services needs a real machine"""
        self._last_error = 5  # ERROR_ACCESS_DENIED
        return 0

    def CreateServiceW(self, args):
        return self.CreateServiceA(args)

    def CloseServiceHandle(self, args):
        if self._crypt_handle(args[0], 'scm') is None:
            return 0
        del self.handles[args[0]]
        return 1

    def _no_service(self, args):
        self._last_error = 6  # ERROR_INVALID_HANDLE
        return 0

    QueryServiceStatus = ControlService = DeleteService = _no_service
    StartServiceA = StartServiceW = SetServiceStatus = _no_service
    QueryServiceStatusEx = ChangeServiceConfigA = ChangeServiceConfigW = _no_service
    ChangeServiceConfig2A = ChangeServiceConfig2W = _no_service
    QueryServiceConfigA = QueryServiceConfigW = _no_service

    def EnumServicesStatusA(self, args):
        """EnumServicesStatusA/W(scm, type, state, buffer, size, &needed,
        &returned, &resume) - no services"""
        if self._crypt_handle(args[0], 'scm') is None:
            return 0
        for address in (args[5], args[6], args[7]):
            if address:
                self._mem_write(address, struct.pack('<I', 0))
        return 1

    def EnumServicesStatusW(self, args):
        return self.EnumServicesStatusA(args)

    def StartServiceCtrlDispatcherA(self, args):
        """StartServiceCtrlDispatcherA/W - not started by the service manager"""
        self._last_error = 1063  # ERROR_FAILED_SERVICE_CONTROLLER_CONNECT
        return 0

    def StartServiceCtrlDispatcherW(self, args):
        return self.StartServiceCtrlDispatcherA(args)

    def RegisterServiceCtrlHandlerA(self, args):
        self._last_error = 1060  # ERROR_SERVICE_DOES_NOT_EXIST
        return 0

    RegisterServiceCtrlHandlerW = RegisterServiceCtrlHandlerA
    RegisterServiceCtrlHandlerExA = RegisterServiceCtrlHandlerA
    RegisterServiceCtrlHandlerExW = RegisterServiceCtrlHandlerA

    # ---------- Event log: events go to the emulator's log ----------

    def RegisterEventSourceA(self, args, wide=False):
        """RegisterEventSourceA/W(server, source)"""
        handle = self.get_next_handle()
        self.handles[handle] = {'type': 'event_source',
                                'name': self._read_text(args[1], wide) if args[1] else ''}
        return handle

    def RegisterEventSourceW(self, args):
        return self.RegisterEventSourceA(args, wide=True)

    def ReportEventA(self, args, wide=False):
        """ReportEventA/W(source, type, category, id, sid, count, data size,
        strings, data) - logged"""
        info = self._crypt_handle(args[0], 'event_source')
        if info is None:
            return 0
        strings = []
        for i in range(args[5] & 0xFFFF):
            pointer = self._read_u32(args[7] + 4 * i)
            strings.append(self._read_text(pointer, wide) if pointer else '')
        log.info(f"Event log ({info['name']}, type {args[1]}, id {args[3] & 0xFFFF}): "
                 f"{' | '.join(strings)}")
        return 1

    def ReportEventW(self, args):
        return self.ReportEventA(args, wide=True)

    def DeregisterEventSource(self, args):
        if self._crypt_handle(args[0], 'event_source') is None:
            return 0
        del self.handles[args[0]]
        return 1

    def OpenEventLogA(self, args, wide=False):
        """OpenEventLogA/W(server, source) - an empty log"""
        handle = self.get_next_handle()
        self.handles[handle] = {'type': 'event_log'}
        return handle

    def OpenEventLogW(self, args):
        return self.OpenEventLogA(args, wide=True)

    def CloseEventLog(self, args):
        if self._crypt_handle(args[0], 'event_log') is None:
            return 0
        del self.handles[args[0]]
        return 1

    def GetNumberOfEventLogRecords(self, args):
        if self._crypt_handle(args[0], 'event_log') is None:
            return 0
        return 1 if self._mem_write(args[1], struct.pack('<I', 0)) else 0

    def GetOldestEventLogRecord(self, args):
        return self.GetNumberOfEventLogRecords(args)

    def ReadEventLogA(self, args):
        if self._crypt_handle(args[0], 'event_log') is None:
            return 0
        self._last_error = 38  # ERROR_HANDLE_EOF
        return 0

    ReadEventLogW = ReadEventLogA

    # ---------- Event Tracing for Windows: nobody listens ----------

    def EventRegister(self, args):
        """EventRegister(provider GUID, callback, context, &REGHANDLE)"""
        if not args[3]:
            return 87  # ERROR_INVALID_PARAMETER
        self._mem_write(args[3], struct.pack('<Q', self.get_next_handle()))
        return 0

    def EventUnregister(self, args):
        return 0

    def EventWrite(self, args):
        return 0

    def EventWriteTransfer(self, args):
        return 0

    def EventWriteString(self, args):
        return 0

    def EventSetInformation(self, args):
        return 0

    def EventEnabled(self, args):
        return 0

    def EventProviderEnabled(self, args):
        return 0

    def EventActivityIdControl(self, args):
        """EventActivityIdControl(code, &GUID) - a zero activity ID"""
        if args[1]:
            self._mem_write(args[1], b'\x00' * 16)
        return 0

    # ---------- secur32 ----------

    def GetUserNameExA(self, args, wide=False):
        """GetUserNameExA/W(format, buffer, &size)"""
        names = {2: f'{self.COMPUTER_NAME}\\{self.USER_NAME}',  # NameSamCompatible
                 3: self.USER_NAME}  # NameDisplay
        text = names.get(args[0])
        if text is None:
            self._last_error = 1332  # ERROR_NONE_MAPPED
            return 0
        units = self._text_units(text, wide)
        size = self._read_u32(args[2])
        if not args[1] or size <= len(units):
            self._mem_write(args[2], struct.pack('<I', len(units) + 1))
            self._last_error = 234  # ERROR_MORE_DATA
            return 0
        self._write_units(args[1], units, wide)
        self._mem_write(args[2], struct.pack('<I', len(units)))
        return 1

    def GetUserNameExW(self, args):
        return self.GetUserNameExA(args, wide=True)
