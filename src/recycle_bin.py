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

"""The Recycle Bin store of the virtual drives.

Deleted files are kept on their own drive, in a hidden folder at its root
(X:\\$Recycle), so that sending a file to the bin is a cheap rename that
never leaves the drive's sandbox. Only the writable hard disk drives have
a bin: the CD-ROM D: is read-only and the floppy A: deletes for good, like
on Windows.

On-disk format (written by this module, read by Explorer, apps/explorer):

    X:\\$Recycle\\INDEX.TXT   UTF-8 text, one line per item, CR LF line ends
        line 1:   "winexe32emu recycle bin 1"
        an item:  stored name TAB deletion time TAB size TAB kind TAB original path
                  - stored name: the item's name in X:\\$Recycle: "R" and a
                    6-digit number, then a file's own extension (R000007.txt)
                    so that it keeps its type and icon
                  - deletion time: a FILETIME (100 ns units since 1601, UTC)
                    in decimal
                  - size: bytes in decimal (a folder: all its files)
                  - kind: "F" a file, "D" a folder
                  - original path: the full Windows path it was deleted from
                    (last, as the only field that may hold any character a
                    file name can: a Windows path never holds a TAB or a
                    line break)
    X:\\$Recycle\\R000007.txt  the deleted file or folder itself

Index lines whose stored item is gone are dropped when the index is read;
stored items without a line are not listed (Empty Recycle Bin removes them).
The store is changed by the emulated programs' threads and by the desktop's
thread: one lock keeps the index consistent.
"""

import os
import re
import shutil
import threading
import time
from dataclasses import dataclass

from . import config
from .paths import drive_letter_of_host, resolve_drive_path, windows_path_of_host

STORE_FOLDER = '$Recycle'
INDEX_NAME = 'INDEX.TXT'
INDEX_HEADER = 'winexe32emu recycle bin 1'
STORED_NAME = re.compile(r'R(\d{6,})', re.IGNORECASE)

_lock = threading.RLock()


@dataclass
class RecycledItem:
    """One deleted file or folder of a drive's bin"""
    drive: str          # Drive letter ('C')
    stored_name: str    # Its name in the store (R000007.txt)
    deleted: int        # FILETIME of the deletion
    size: int           # Bytes
    is_dir: bool
    original: str       # Windows path it was deleted from

    @property
    def stored_host(self):
        return os.path.join(store_host(self.drive), self.stored_name)

    @property
    def stored_path(self):
        """Windows path of the stored item (X:\\$Recycle\\R000007.txt)"""
        return f"{self.drive}:\\{STORE_FOLDER}\\{self.stored_name}"

    @property
    def name(self):
        """The name it had before it was deleted"""
        return self.original.rstrip('\\').rsplit('\\', 1)[-1]


def bin_drives():
    """Letters of the drives with a Recycle Bin: the writable hard disks"""
    return [letter for letter, (kind, _, _) in sorted(config.DRIVES.items())
            if kind == config.DRIVE_FIXED and letter not in config.READ_ONLY_DRIVES]


def store_host(letter):
    """Host folder of a drive's bin store (it may not exist yet)"""
    return os.path.join(config.drive_host_path(letter), STORE_FOLDER)


def _index_host(letter):
    return os.path.join(store_host(letter), INDEX_NAME)


def store_letter(host_path):
    """Drive letter if host_path is a drive's bin store or inside it, else None"""
    letter = drive_letter_of_host(host_path)
    if letter is None:
        return None
    store = os.path.realpath(store_host(letter))
    path = os.path.realpath(host_path)
    return letter if path == store or path.startswith(store + os.sep) else None


def is_store_folder(host_path):
    """Is host_path the store folder itself (hidden at the drive root)?"""
    letter = drive_letter_of_host(host_path)
    return letter is not None and \
        os.path.realpath(host_path) == os.path.realpath(store_host(letter))


def store_attributes(host_path):
    """FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM for the store folder
    (like the bin folders of Windows, Explorer and DIR do not show it), else 0.
    The name is compared first: this runs for every file a program lists."""
    if os.path.basename(host_path).lower() != STORE_FOLDER.lower():
        return 0
    return 0x6 if is_store_folder(host_path) else 0


def can_recycle(host_path):
    """Can this file or folder go to a Recycle Bin (not deleted for good)?"""
    letter = drive_letter_of_host(host_path)
    if letter not in bin_drives() or store_letter(host_path):
        return False
    return os.path.realpath(host_path) != os.path.realpath(config.drive_host_path(letter))


def filetime_now():
    """The current time as a FILETIME"""
    return int((time.time() + 11644473600) * 10000000)


def _tree_size(host_path):
    if not os.path.isdir(host_path):
        return os.path.getsize(host_path)
    total = 0
    for folder, _, files in os.walk(host_path):
        for name in files:
            try:
                total += os.path.getsize(os.path.join(folder, name))
            except OSError:
                pass
    return total


def _read_index(letter):
    """Items of a drive's index (lines of vanished items left out)"""
    try:
        with open(_index_host(letter), encoding='utf-8', errors='replace') as f:
            lines = f.read().splitlines()
    except OSError:
        return []
    if not lines or lines[0].strip() != INDEX_HEADER:
        return []
    items = []
    store = store_host(letter)
    for line in lines[1:]:
        fields = line.split('\t', 4)
        if len(fields) != 5 or not STORED_NAME.match(fields[0]):
            continue
        try:
            deleted, size = int(fields[1]), int(fields[2])
        except ValueError:
            continue
        if os.path.lexists(os.path.join(store, fields[0])):
            items.append(RecycledItem(letter, fields[0], deleted, size, fields[3] == 'D',
                                      fields[4]))
    return items


def _write_index(letter, items):
    """Write a drive's index (atomically: a half-written index never shows)"""
    store = store_host(letter)
    os.makedirs(store, exist_ok=True)
    lines = [INDEX_HEADER] + [
        f"{i.stored_name}\t{i.deleted}\t{i.size}\t{'D' if i.is_dir else 'F'}\t{i.original}"
        for i in items]
    temporary = os.path.join(store, INDEX_NAME + '.new')
    with open(temporary, 'w', encoding='utf-8', newline='\r\n') as f:
        f.write('\n'.join(lines) + '\n')
    os.replace(temporary, _index_host(letter))


def _next_stored_name(letter, items, host_path):
    """A new store name: the next number, a file's own extension"""
    numbers = [0]
    try:
        names = os.listdir(store_host(letter))
    except OSError:
        names = []
    for name in names + [i.stored_name for i in items]:
        match = STORED_NAME.match(name)
        if match:
            numbers.append(int(match.group(1)))
    extension = '' if os.path.isdir(host_path) else os.path.splitext(host_path)[1]
    return f"R{max(numbers) + 1:06d}{extension}"


def recycle(host_path):
    """Move a file or folder into its drive's bin; returns its RecycledItem.
    Raises ValueError if it cannot go to a bin, OSError if the move fails."""
    if not can_recycle(host_path) or not os.path.lexists(host_path):
        raise ValueError(f"{host_path} cannot go to a Recycle Bin")
    letter = drive_letter_of_host(host_path)
    with _lock:
        items = _read_index(letter)
        original = windows_path_of_host(host_path)
        item = RecycledItem(letter, _next_stored_name(letter, items, host_path),
                            filetime_now(), _tree_size(host_path),
                            os.path.isdir(host_path), original)
        os.makedirs(store_host(letter), exist_ok=True)
        shutil.move(host_path, item.stored_host)
        _write_index(letter, items + [item])
    return item


def items(letters=None):
    """The items in the bins of the given drives (default: all), oldest first"""
    with _lock:
        found = []
        for letter in letters or bin_drives():
            found += _read_index(letter)
    return sorted(found, key=lambda i: (i.deleted, i.drive, i.stored_name))


def find(host_path):
    """The RecycledItem stored at host_path (a top-level store entry), or None"""
    letter = store_letter(host_path)
    if letter is None:
        return None
    name = os.path.basename(os.path.realpath(host_path))
    for item in items([letter]):
        if item.stored_name.lower() == name.lower():
            return item
    return None


def forget(host_path):
    """Drop the index line of a stored item that was moved out of the store
    or deleted (restored or deleted for good by a file operation)"""
    letter = store_letter(host_path)
    path = os.path.realpath(host_path)
    if letter is None or os.path.dirname(path) != os.path.realpath(store_host(letter)):
        return  # Not a top-level item (a file inside a deleted folder)
    name = os.path.basename(path).lower()
    with _lock:
        # (written even if the item was already left out: it is usually gone
        # by now, and reading the index skips the lines of vanished items)
        _write_index(letter, [i for i in _read_index(letter) if i.stored_name.lower() != name])


def _remove(host_path):
    if os.path.isdir(host_path) and not os.path.islink(host_path):
        shutil.rmtree(host_path)
    elif os.path.lexists(host_path):
        os.remove(host_path)


def purge(item):
    """Delete one item of the bin for good"""
    with _lock:
        _remove(item.stored_host)
        forget(item.stored_host)


def restore(item, replace=False):
    """Move an item back to where it was deleted from (its folders are made
    again if needed); returns the host path. Raises FileExistsError if
    something has its name there now (unless replace), OSError if it fails."""
    target = resolve_drive_path(item.original)
    if target is None:
        raise OSError(f"Cannot restore to {item.original}")
    with _lock:
        if os.path.lexists(target):
            if not replace:
                raise FileExistsError(target)
            _remove(target)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        shutil.move(item.stored_host, target)
        forget(item.stored_host)
    return target


def empty(letters=None):
    """Empty the bins of the given drives (default: all), also stored items
    the index does not list; returns the number of items deleted"""
    count = 0
    with _lock:
        for letter in letters or bin_drives():
            store = store_host(letter)
            try:
                names = os.listdir(store)
            except OSError:
                continue
            for name in names:
                if name.upper().startswith(INDEX_NAME):
                    continue  # (and a half-written INDEX.TXT.new)
                try:
                    _remove(os.path.join(store, name))
                    count += 1
                except OSError:
                    pass
            _write_index(letter, [])
    return count


def query(letters=None):
    """(total bytes, number of items) of the bins of the given drives"""
    found = items(letters)
    return sum(i.size for i in found), len(found)


def state_token():
    """Something that changes whenever a bin changes (the index files'
    times and sizes): the desktop redraws its bin icon only then"""
    token = []
    for letter in bin_drives():
        try:
            st = os.stat(_index_host(letter))
            token.append((letter, st.st_mtime_ns, st.st_size))
        except OSError:
            token.append((letter, None, None))
    return tuple(token)


def drive_of_root(root):
    """Drive letter of a root path argument ("C:\\", "c:", "C:\\x"), or None"""
    if root and len(root) >= 2 and root[1] == ':' and root[0].isalpha():
        return root[0].upper()
    return None
