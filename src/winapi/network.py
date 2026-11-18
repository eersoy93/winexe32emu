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

"""WinAPIHandler mixin: Windows Sockets (ws2_32/wsock32), wininet,
iphlpapi, sensapi and urlmon. The emulated computer is offline, like the
drives sandbox it never reaches the host: names resolve only to itself
(localhost), sockets can't be created and downloads fail."""

import ipaddress
import struct

from unicorn import *


class NetworkMixin:
    """Windows Sockets and the other network APIs of an offline computer"""

    SOCKET_ERROR = 0xFFFFFFFF
    INVALID_SOCKET = 0xFFFFFFFF
    WSAEFAULT = 10014
    WSAEINVAL = 10022
    WSAENOTSOCK = 10038
    WSAEAFNOSUPPORT = 10047
    WSAENETDOWN = 10050
    WSAVERNOTSUPPORTED = 10092
    WSANOTINITIALISED = 10093
    WSAHOST_NOT_FOUND = 11001
    WSANO_DATA = 11004
    AF_INET, AF_INET6 = 2, 23

    # ---------- Startup ----------

    def WSAStartup(self, args):
        """WSAStartup(version, WSADATA) - Windows Sockets 2.2"""
        requested = args[0] & 0xFFFF
        if requested & 0xFF == 0:
            return self.WSAVERNOTSUPPORTED
        version = min((requested & 0xFF, requested >> 8), (2, 2))
        version_word = version[0] | (version[1] << 8)
        data = struct.pack('<HH', version_word, 0x0202)
        data += b'WinSock 2.0'.ljust(257, b'\x00') + b'Running'.ljust(129, b'\x00')
        data += struct.pack('<HHHI', 0, 0, 0, 0)  # iMaxSockets, iMaxUdpDg, padding, vendor
        if not self._mem_write(args[1], data):
            return self.WSAEFAULT
        self.__dict__['_wsa_started'] = self.__dict__.get('_wsa_started', 0) + 1
        return 0

    def WSACleanup(self, args):
        if not self.__dict__.get('_wsa_started'):
            self._last_error = self.WSANOTINITIALISED
            return self.SOCKET_ERROR
        self.__dict__['_wsa_started'] -= 1
        return 0

    def _wsa_ready(self):
        if self.__dict__.get('_wsa_started'):
            return True
        self._last_error = self.WSANOTINITIALISED
        return False

    def WSAGetLastError(self, args):
        return self._last_error

    def WSASetLastError(self, args):
        self._last_error = args[0]
        return 0

    # ---------- Byte order and addresses ----------

    def htons(self, args):
        value = args[0] & 0xFFFF
        return ((value & 0xFF) << 8) | (value >> 8)

    ntohs = htons

    def htonl(self, args):
        return struct.unpack('>I', struct.pack('<I', args[0]))[0]

    ntohl = htonl

    @staticmethod
    def _parse_ipv4(text):
        """IPv4 address of inet_addr's forms ("a.b.c.d", "a.b.c", "a.b", "a"
        with decimal, octal or hex parts) as 4 bytes, or None"""
        parts = text.strip().split('.')
        if not 1 <= len(parts) <= 4 or not all(parts):
            return None
        try:
            values = [int(p, 16) if p.lower().startswith('0x') else
                      int(p, 8) if p.startswith('0') and len(p) > 1 else int(p) for p in parts]
        except ValueError:
            return None
        limits = [256] * (len(values) - 1) + [256 ** (5 - len(values))]
        if any(v < 0 or v >= limit for v, limit in zip(values, limits)):
            return None
        number = 0
        for value in values[:-1]:
            number = (number << 8) | value
        number = (number << (8 * (5 - len(values)))) | values[-1]
        return struct.pack('>I', number)

    def inet_addr(self, args):
        """inet_addr(text) - the address in network order, INADDR_NONE if invalid"""
        data = self._parse_ipv4(self.read_string(args[0])) if args[0] else None
        return 0xFFFFFFFF if data is None else struct.unpack('<I', data)[0]

    def inet_ntoa(self, args):
        """inet_ntoa(in_addr) - a static buffer"""
        text = '.'.join(str(b) for b in struct.pack('<I', args[0]))
        buffer = self._static_buffer('inet_ntoa', 16)
        self._write_text(buffer, text, False)
        return buffer

    def inet_pton(self, args, wide=False):
        """inet_pton/InetPtonW(family, text, address) - 1, 0 if invalid, -1 for a bad family"""
        text = self._read_text(args[1], wide) if args[1] else ''
        try:
            if args[0] == self.AF_INET:
                data = ipaddress.IPv4Address(text).packed
            elif args[0] == self.AF_INET6:
                data = ipaddress.IPv6Address(text).packed
            else:
                self._last_error = self.WSAEAFNOSUPPORT
                return 0xFFFFFFFF
        except ValueError:
            return 0
        self._mem_write(args[2], data)
        return 1

    def InetPtonW(self, args):
        return self.inet_pton(args, wide=True)

    def inet_ntop(self, args, wide=False):
        """inet_ntop/InetNtopW(family, address, buffer, size) - the buffer, NULL on failure"""
        try:
            if args[0] == self.AF_INET:
                text = str(ipaddress.IPv4Address(bytes(self.emu.uc.mem_read(args[1], 4))))
            elif args[0] == self.AF_INET6:
                text = str(ipaddress.IPv6Address(bytes(self.emu.uc.mem_read(args[1], 16))))
            else:
                self._last_error = self.WSAEAFNOSUPPORT
                return 0
        except UcError:
            self._last_error = self.WSAEFAULT
            return 0
        if len(text) >= args[3]:
            self._last_error = self.WSAEINVAL
            return 0
        self._write_text(args[2], text, wide)
        return args[2]

    def InetNtopW(self, args):
        return self.inet_ntop(args, wide=True)

    # ---------- Names: only this computer (127.0.0.1) ----------

    def _local_address(self, name):
        """4 bytes of the address of a name that resolves here, else None"""
        name = name.strip().lower()
        if name in ('localhost', self.COMPUTER_NAME.lower(), ''):
            return b'\x7f\x00\x00\x01'
        try:
            return ipaddress.IPv4Address(name).packed
        except ValueError:
            return None

    def gethostname(self, args):
        """gethostname(buffer, size)"""
        if not self._wsa_ready():
            return self.SOCKET_ERROR
        name = self.COMPUTER_NAME.lower().encode('ascii')
        if len(name) >= args[1]:
            self._last_error = self.WSAEFAULT
            return self.SOCKET_ERROR
        self._mem_write(args[0], name + b'\x00')
        return 0

    def GetHostNameW(self, args):
        if not self._wsa_ready():
            return self.SOCKET_ERROR
        name = self.COMPUTER_NAME.lower()
        if len(name) >= args[1]:
            self._last_error = self.WSAEFAULT
            return self.SOCKET_ERROR
        self._write_text(args[0], name, True)
        return 0

    def _hostent(self, name, address):
        """A static HOSTENT: name, no aliases, one IPv4 address"""
        buffer = self._static_buffer('hostent', 512)
        name_bytes = name.encode('ascii', errors='replace')[:255] + b'\x00'
        # HOSTENT, alias list (empty), address list, the address, the name
        aliases, addresses, address_at, name_at = (buffer + 16, buffer + 20, buffer + 28,
                                                   buffer + 32)
        data = struct.pack('<IIhhI', name_at, aliases, self.AF_INET, 4, addresses)
        data += struct.pack('<I', 0) + struct.pack('<II', address_at, 0) + address + name_bytes
        self._mem_write(buffer, data)
        return buffer

    def gethostbyname(self, args):
        """gethostbyname(name) - this computer or a dotted address"""
        if not self._wsa_ready():
            return 0
        name = self.read_string(args[0]) if args[0] else ''
        address = self._local_address(name)
        if address is None:
            self._last_error = self.WSAHOST_NOT_FOUND
            return 0
        return self._hostent(name or self.COMPUTER_NAME.lower(), address)

    def gethostbyaddr(self, args):
        """gethostbyaddr(address, length, family) - 127.0.0.1 is localhost"""
        if not self._wsa_ready():
            return 0
        try:
            address = bytes(self.emu.uc.mem_read(args[0], 4))
        except UcError:
            self._last_error = self.WSAEFAULT
            return 0
        if args[2] != self.AF_INET or address[0] != 127:
            self._last_error = self.WSAHOST_NOT_FOUND
            return 0
        return self._hostent('localhost', address)

    SERVICES = {'echo': 7, 'ftp-data': 20, 'ftp': 21, 'ssh': 22, 'telnet': 23, 'smtp': 25,
                'domain': 53, 'http': 80, 'pop3': 110, 'nntp': 119, 'ntp': 123,
                'imap': 143, 'snmp': 161, 'ldap': 389, 'https': 443, 'imaps': 993,
                'pop3s': 995}
    PROTOCOLS = {'ip': 0, 'icmp': 1, 'tcp': 6, 'udp': 17}

    def _servent(self, name, port, protocol):
        """A static SERVENT: s_name, s_aliases, s_port (network order), s_proto"""
        buffer = self._static_buffer('servent', 128)
        data = struct.pack('<IIHxxI', buffer + 20, buffer + 16, self.htons([port]), buffer + 52)
        data += struct.pack('<I', 0)  # The alias list is empty
        data += name.encode('ascii')[:31].ljust(32, b'\x00')
        data += (protocol or 'tcp').encode('ascii', errors='replace')[:15].ljust(16, b'\x00')
        self._mem_write(buffer, data)
        return buffer

    def getservbyname(self, args):
        """getservbyname(name, protocol) - the well-known services"""
        name = self.read_string(args[0]).lower() if args[0] else ''
        protocol = self.read_string(args[1]) if args[1] else None
        port = self.SERVICES.get(name)
        if port is None:
            self._last_error = self.WSANO_DATA
            return 0
        return self._servent(name, port, protocol)

    def getservbyport(self, args):
        """getservbyport(port in network order, protocol)"""
        port = self.htons([args[0]])
        protocol = self.read_string(args[1]) if args[1] else None
        for name, number in self.SERVICES.items():
            if number == port:
                return self._servent(name, port, protocol)
        self._last_error = self.WSANO_DATA
        return 0

    def getprotobyname(self, args):
        """getprotobyname(name) - ip, icmp, tcp, udp"""
        name = self.read_string(args[0]).lower() if args[0] else ''
        number = self.PROTOCOLS.get(name)
        if number is None:
            self._last_error = self.WSANO_DATA
            return 0
        buffer = self._static_buffer('protoent', 32)
        self._mem_write(buffer, struct.pack('<IIhxx', buffer + 16, buffer + 12, number) +
                        struct.pack('<I', 0) + name.encode('ascii').ljust(16, b'\x00'))
        return buffer

    def getprotobynumber(self, args):
        for name, number in self.PROTOCOLS.items():
            if number == args[0]:
                text = self._alloc_units(self._text_units(name, False), False)
                try:
                    return self.getprotobyname([text])
                finally:
                    self.emu.heap_free(text)
        self._last_error = self.WSANO_DATA
        return 0

    def getaddrinfo(self, args, wide=False):
        """getaddrinfo/GetAddrInfoW(node, service, hints, &result) - IPv4
        addresses of this computer (numeric ports and the known services)"""
        node = self._read_text(args[0], wide) if args[0] else 'localhost'
        service = self._read_text(args[1], wide) if args[1] else '0'
        family, socktype, protocol, flags = 0, 0, 0, 0
        if args[2]:
            flags, family, socktype, protocol = struct.unpack(
                '<4i', self.emu.uc.mem_read(args[2], 16))
        if family not in (0, self.AF_INET):
            return self.WSAEAFNOSUPPORT
        address = self._local_address(node)
        if address is None or (flags & 0x4 and node.lower() == 'localhost'):  # AI_NUMERICHOST
            return self.WSAHOST_NOT_FOUND
        if service.isdigit():
            port = int(service)
        elif service.lower() in self.SERVICES:
            port = self.SERVICES[service.lower()]
        else:
            return 10109  # WSATYPE_NOT_FOUND
        unit = 2 if wide else 1
        name_units = self._text_units(node, wide) + [0]
        # ADDRINFO, SOCKADDR_IN, canonical name
        block = self.emu.heap_alloc(32 + 16 + len(name_units) * unit)
        sockaddr = block + 32
        canonical = block + 48 if flags & 0x2 else 0  # AI_CANONNAME
        self._mem_write(block, struct.pack('<4iIIII', flags, self.AF_INET, socktype, protocol,
                                           16, canonical, sockaddr, 0))
        self._mem_write(sockaddr, struct.pack('<hH4s8x', self.AF_INET, self.htons([port]),
                                              address))
        if canonical:
            self._write_units(canonical, name_units, wide, terminate=False)
        self._mem_write(args[3], struct.pack('<I', block))
        return 0

    def GetAddrInfoW(self, args):
        return self.getaddrinfo(args, wide=True)

    def freeaddrinfo(self, args):
        """freeaddrinfo/FreeAddrInfoW(list)"""
        address = args[0]
        while address:
            following = self._read_u32(address + 28)
            self.emu.heap_free(address)
            address = following
        return 0

    FreeAddrInfoW = freeaddrinfo

    def getnameinfo(self, args):
        """getnameinfo(address, length, host, host size, service, service size, flags)"""
        try:
            family, port, address = struct.unpack('<hH4s', self.emu.uc.mem_read(args[0], 8))
        except UcError:
            return self.WSAEFAULT
        if family != self.AF_INET:
            return self.WSAEAFNOSUPPORT
        if args[2] and args[3]:
            host = '.'.join(str(b) for b in address)
            if not args[6] & 0x2 and address[0] == 127:  # NI_NUMERICHOST
                host = 'localhost'
            if len(host) >= args[3]:
                return self.WSAEFAULT
            self._write_text(args[2], host, False)
        if args[4] and args[5]:
            text = str(self.htons([port]))
            if len(text) >= args[5]:
                return self.WSAEFAULT
            self._write_text(args[4], text, False)
        return 0

    # ---------- Sockets: none can be created ----------

    def socket(self, args):
        """socket(family, type, protocol) - the network is down"""
        if not self._wsa_ready():
            return self.INVALID_SOCKET
        self._last_error = self.WSAENETDOWN
        return self.INVALID_SOCKET

    def WSASocketA(self, args):
        return self.socket(args)

    WSASocketW = WSASocketA

    def _not_a_socket(self, args):
        """Socket operations: no socket exists"""
        if not self._wsa_ready():
            return self.SOCKET_ERROR
        self._last_error = self.WSAENOTSOCK
        return self.SOCKET_ERROR

    closesocket = connect = bind = listen = send = recv = sendto = recvfrom = _not_a_socket
    shutdown = ioctlsocket = setsockopt = getsockopt = getsockname = _not_a_socket
    getpeername = select = WSAIoctl = WSASend = WSARecv = WSASendTo = _not_a_socket
    WSARecvFrom = WSAEventSelect = WSAAsyncSelect = WSAEnumNetworkEvents = _not_a_socket
    WSAConnect = WSAAccept = _not_a_socket

    def accept(self, args):
        if self._wsa_ready():
            self._last_error = self.WSAENOTSOCK
        return self.INVALID_SOCKET

    def _wsa_fd_is_set(self, args):
        """__WSAFDIsSet(socket, fd_set) - no socket is ever in a set"""
        return 0

    def WSACreateEvent(self, args):
        """WSACreateEvent - a manual-reset event"""
        return self.CreateEventA([0, 1, 0, 0])

    def WSACloseEvent(self, args):
        return self.CloseHandle(args)

    def WSASetEvent(self, args):
        return self.SetEvent(args)

    def WSAResetEvent(self, args):
        return self.ResetEvent(args)

    def WSAWaitForMultipleEvents(self, args):
        """WSAWaitForMultipleEvents(count, events, wait all, ms, alertable)"""
        return self.WaitForMultipleObjectsEx(args[:5])

    def WSAAddressToStringA(self, args, wide=False):
        """WSAAddressToStringA/W(address, length, protocol info, buffer, &size)"""
        try:
            family, port, address = struct.unpack('<hH4s', self.emu.uc.mem_read(args[0], 8))
        except UcError:
            self._last_error = self.WSAEFAULT
            return self.SOCKET_ERROR
        if family != self.AF_INET:
            self._last_error = self.WSAEINVAL
            return self.SOCKET_ERROR
        text = '.'.join(str(b) for b in address)
        port = self.htons([port])
        if port:
            text += f':{port}'
        size = self._read_u32(args[4])
        self._mem_write(args[4], struct.pack('<I', len(text) + 1))
        if len(text) + 1 > size:
            self._last_error = self.WSAEFAULT
            return self.SOCKET_ERROR
        self._write_text(args[3], text, wide)
        return 0

    def WSAAddressToStringW(self, args):
        return self.WSAAddressToStringA(args, wide=True)

    def WSAStringToAddressA(self, args, wide=False):
        """WSAStringToAddressA/W(text, family, protocol info, address, &length)"""
        text = self._read_text(args[0], wide) if args[0] else ''
        host, _, port = text.partition(':')
        address = self._parse_ipv4(host) if args[1] == self.AF_INET else None
        if address is None or (port and not port.isdigit()):
            self._last_error = self.WSAEINVAL
            return self.SOCKET_ERROR
        if self._read_u32(args[4]) < 16:
            self._mem_write(args[4], struct.pack('<I', 16))
            self._last_error = self.WSAEFAULT
            return self.SOCKET_ERROR
        self._mem_write(args[3], struct.pack('<hH4s8x', self.AF_INET,
                                             self.htons([int(port or 0)]), address))
        self._mem_write(args[4], struct.pack('<I', 16))
        return 0

    def WSAStringToAddressW(self, args):
        return self.WSAStringToAddressA(args, wide=True)

    # ---------- iphlpapi, sensapi, wininet, urlmon ----------

    def GetAdaptersInfo(self, args):
        """GetAdaptersInfo(buffer, &size) - no network adapters"""
        return 232  # ERROR_NO_DATA

    def GetAdaptersAddresses(self, args):
        return 232

    def GetNumberOfInterfaces(self, args):
        return 0 if self._mem_write(args[0], struct.pack('<I', 0)) else 87

    def GetBestInterface(self, args):
        return 1231  # ERROR_NETWORK_UNREACHABLE

    def IsNetworkAlive(self, args):
        """IsNetworkAlive(&flags) - no connection"""
        if args[0]:
            self._mem_write(args[0], struct.pack('<I', 0))
        self._last_error = 0
        return 0

    def IsDestinationReachableA(self, args):
        self._last_error = 0
        return 0

    IsDestinationReachableW = IsDestinationReachableA

    def InternetGetConnectedState(self, args):
        """InternetGetConnectedState(&flags, reserved) - offline"""
        if args[0]:
            self._mem_write(args[0], struct.pack('<I', 0x20))  # INTERNET_CONNECTION_OFFLINE
        return 0

    def InternetGetConnectedStateExA(self, args):
        return self.InternetGetConnectedState(args)

    InternetGetConnectedStateExW = InternetGetConnectedStateExA

    def InternetAttemptConnect(self, args):
        return 12029  # ERROR_INTERNET_CANNOT_CONNECT

    def InternetCheckConnectionA(self, args):
        self._last_error = 12029
        return 0

    InternetCheckConnectionW = InternetCheckConnectionA

    def InternetOpenA(self, args):
        """InternetOpenA/W - a session handle (no request will connect)"""
        handle = self.get_next_handle()
        self.handles[handle] = {'type': 'internet'}
        return handle

    InternetOpenW = InternetOpenA

    def InternetOpenUrlA(self, args):
        self._last_error = 12007  # ERROR_INTERNET_NAME_NOT_RESOLVED
        return 0

    InternetOpenUrlW = InternetConnectA = InternetConnectW = InternetOpenUrlA

    def InternetCloseHandle(self, args):
        info = self.handles.get(args[0])
        if not info or info.get('type') != 'internet':
            self._last_error = 6
            return 0
        del self.handles[args[0]]
        return 1

    def InternetReadFile(self, args):
        self._last_error = 12018  # ERROR_INTERNET_INCORRECT_HANDLE_TYPE
        return 0

    def URLDownloadToFileA(self, args):
        return 0x800C0008  # INET_E_DOWNLOAD_FAILURE

    URLDownloadToFileW = URLDownloadToCacheFileA = URLDownloadToCacheFileW = URLDownloadToFileA


# A method named __WSAFDIsSet would be name-mangled in the class body
setattr(NetworkMixin, '__WSAFDIsSet', NetworkMixin._wsa_fd_is_set)
