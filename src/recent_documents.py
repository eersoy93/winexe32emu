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

"""The recently opened documents of the Start menu's Documents submenu.

Like Windows they are shortcuts (.lnk) in the user's Recent folder
(CSIDL_RECENT), one per document name: SHAddToRecentDocs writes them, the
emulated programs can list the folder, and they survive the emulator's
restart. The newest shortcut (its modification time) comes first."""

import ntpath
import os
import struct
import threading
import time

from . import config
from .paths import resolve_drive_path
from .resources import parse_shell_link

RECENT_LIMIT = 15  # Entries of the Documents menu (and shortcuts kept)
CLSID_SHELLLINK = bytes.fromhex('0114020000000000c000000000000046')
_lock = threading.Lock()


def recent_folder():
    """Windows path of the user's Recent folder (CSIDL_RECENT)"""
    from . import winapi  # Late: src.winapi imports this module too
    return winapi.WinAPIHandler.SHELL_FOLDERS[0x08]


def _filetime(seconds):
    return int((seconds + 11644473600) * 10000000) & 0xFFFFFFFFFFFFFFFF


def build_shell_link(target, workdir=''):
    """Contents of a shell link (.lnk, MS-SHLLINK) file pointing at a local
    target: the header with the target's attributes and times, a LinkInfo
    with the path (ANSI and Unicode) and the working folder"""
    host = resolve_drive_path(target)
    attributes, size, mtime = 0x20, 0, time.time()
    if host and os.path.exists(host):
        info = os.stat(host)
        attributes = 0x10 if os.path.isdir(host) else 0x20
        size = 0 if os.path.isdir(host) else info.st_size & 0xFFFFFFFF
        mtime = info.st_mtime
    flags = 0x2 | 0x80  # HasLinkInfo, IsUnicode
    strings = b''
    if workdir:
        flags |= 0x10  # HasWorkingDir
        data = workdir.encode('utf-16-le')
        strings += struct.pack('<H', len(data) // 2) + data
    stamp = _filetime(mtime)
    header = struct.pack('<I16sIIQQQIiIHHII', 0x4C, CLSID_SHELLLINK, flags, attributes,
                         stamp, stamp, stamp, size, 0, 1, 0, 0, 0, 0)  # SW_SHOWNORMAL
    drive = config.DRIVES.get(target[:1].upper(), (config.DRIVE_FIXED, '', 0))
    volume = struct.pack('<IIII', 17, drive[0], drive[2], 0x10) + b'\x00'
    base = target.encode(config.ANSI_CODEPAGE, errors='replace') + b'\x00'
    base_wide = target.encode('utf-16-le') + b'\x00\x00'
    header_size = 0x24  # With the Unicode path offsets
    base_offset = header_size + len(volume)
    suffix_offset = base_offset + len(base)
    wide_offset = suffix_offset + 1
    wide_suffix_offset = wide_offset + len(base_wide)
    total = wide_suffix_offset + 2
    link_info = struct.pack('<9I', total, header_size, 1, header_size, base_offset, 0,
                            suffix_offset, wide_offset, wide_suffix_offset)
    link_info += volume + base + b'\x00' + base_wide + b'\x00\x00'
    return header + link_info + strings + b'\x00' * 4


def _link_host_paths():
    """Host paths of the shortcuts in the Recent folder, the newest first"""
    host = resolve_drive_path(recent_folder())
    try:
        names = [n for n in os.listdir(host) if n.lower().endswith('.lnk')]
    except (OSError, TypeError):
        return []
    entries = []
    for name in names:
        path = os.path.join(host, name)
        try:
            entries.append((-os.stat(path).st_mtime_ns, name.lower(), path))
        except OSError:
            pass
    return [path for _, _, path in sorted(entries)]


def add_recent_document(path):
    """Add a file or folder (a full Windows path) to the recent documents:
    its shortcut in the Recent folder is written (again) and becomes the
    newest; the oldest shortcuts beyond RECENT_LIMIT go. Returns True if added."""
    if not path or len(path) < 4 or path[1:3] != ':\\':
        return False
    host = resolve_drive_path(path)
    folder = resolve_drive_path(recent_folder())
    if not host or not os.path.exists(host) or not folder:
        return False
    name = ntpath.basename(path.rstrip('\\'))
    if not name:
        return False
    data = build_shell_link(path, ntpath.dirname(path))
    with _lock:
        try:
            os.makedirs(folder, exist_ok=True)
            link = os.path.join(folder, name + '.lnk')
            # A shortcut of another letter case is the same name on Windows
            for existing in os.listdir(folder):
                if existing.lower() == (name + '.lnk').lower() and existing != name + '.lnk':
                    os.remove(os.path.join(folder, existing))
            temp = link + '.tmp'
            with open(temp, 'wb') as f:
                f.write(data)
            os.replace(temp, link)
            now = time.time_ns()
            # Strictly newer than every other shortcut, even within one clock tick
            newest = max((os.stat(p).st_mtime_ns for p in _link_host_paths() if p != link),
                         default=0)
            stamp = max(now, newest + 1)
            os.utime(link, ns=(stamp, stamp))
            for old in _link_host_paths()[RECENT_LIMIT:]:
                os.remove(old)
        except OSError:
            return False
    return True


def clear_recent_documents():
    """Empty the recent documents (SHAddToRecentDocs with NULL): the shortcuts
    of the Recent folder are deleted"""
    with _lock:
        for path in _link_host_paths():
            try:
                os.remove(path)
            except OSError:
                pass


def recent_documents(limit=RECENT_LIMIT):
    """[(label, target Windows path)] of the recent documents, the newest
    first; shortcuts whose target no longer exists are skipped"""
    result = []
    for path in _link_host_paths():
        try:
            with open(path, 'rb') as f:
                link = parse_shell_link(f.read(65536))
        except OSError:
            continue
        if not link or not link['path']:
            continue
        target_host = resolve_drive_path(link['path'])
        if not target_host or not os.path.exists(target_host):
            continue
        result.append((os.path.basename(path)[:-4], link['path']))
        if len(result) >= limit:
            break
    return result
