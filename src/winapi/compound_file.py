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

"""Compound files (OLE structured storage, MS-CFB): a tree of storages and
streams read from and written to the bytes of a file (.doc, .dot, .xls...)"""

import struct

SIGNATURE = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
FREESECT, ENDOFCHAIN, FATSECT, DIFSECT = 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD, 0xFFFFFFFC
NOSTREAM = 0xFFFFFFFF
STGTY_STORAGE, STGTY_STREAM, STGTY_ROOT = 1, 2, 5
MINI_STREAM_CUTOFF = 4096
MINI_SECTOR = 64
SECTOR = 512  # Written files are version 3: 512-byte sectors


class CompoundFileError(Exception):
    """The bytes are not a valid compound file"""


class Entry:
    """A storage (with children) or a stream (with data) of a compound file"""

    def __init__(self, name, storage, clsid=b'\x00' * 16):
        self.name = name
        self.storage = storage
        self.clsid = clsid
        self.state_bits = 0
        self.ctime = self.mtime = 0  # FILETIMEs (storages only)
        self.children = {} if storage else None  # upper-case name -> Entry
        self.data = None if storage else bytearray()

    def child(self, name):
        return self.children.get(name.upper())

    def add(self, entry):
        self.children[entry.name.upper()] = entry
        return entry

    def copy(self):
        """A deep copy of the subtree"""
        clone = Entry(self.name, self.storage, self.clsid)
        clone.state_bits, clone.ctime, clone.mtime = self.state_bits, self.ctime, self.mtime
        if self.storage:
            for child in self.children.values():
                clone.add(child.copy())
        else:
            clone.data = bytearray(self.data)
        return clone


def is_compound_file(data):
    return data[:8] == SIGNATURE


def _compare_key(name):
    """The directory's sort order: shorter names first, then by upper case"""
    return (len(name), name.upper())


def load(data):
    """The root storage of the compound file in data (CompoundFileError if
    it is not one)"""
    if len(data) < 512 or not is_compound_file(data):
        raise CompoundFileError("no compound file signature")
    major, byte_order, shift, mini_shift = struct.unpack_from('<HHHH', data, 0x1A)
    if byte_order != 0xFFFE or shift not in (9, 12):
        raise CompoundFileError("bad compound file header")
    sector_size = 1 << shift
    (fat_count, first_dir, _, cutoff, first_minifat, minifat_count,
     first_difat, difat_count) = struct.unpack_from('<IIIIIIII', data, 0x2C)
    mini_size = 1 << mini_shift

    def sector(sid):
        start = (sid + 1) * sector_size
        return data[start:start + sector_size]

    # The FAT sectors: 109 in the header, the others in the DIFAT chain
    fat_sectors = list(struct.unpack_from('<109I', data, 0x4C))
    sid, seen = first_difat, set()
    while sid not in (ENDOFCHAIN, FREESECT) and len(seen) < difat_count + 1 and sid not in seen:
        seen.add(sid)
        values = struct.unpack(f'<{sector_size // 4}I', sector(sid).ljust(sector_size, b'\xff'))
        fat_sectors += values[:-1]
        sid = values[-1]
    fat = []
    for sid in fat_sectors[:fat_count]:
        if sid in (FREESECT, ENDOFCHAIN):
            continue
        fat += struct.unpack(f'<{sector_size // 4}I', sector(sid).ljust(sector_size, b'\xff'))

    def chain(start, table):
        sids, sid = [], start
        while sid < len(table) and sid not in (ENDOFCHAIN, FREESECT) and len(sids) <= len(table):
            sids.append(sid)
            sid = table[sid]
        return sids

    def read_chain(start):
        return b''.join(sector(sid) for sid in chain(start, fat))

    directory = read_chain(first_dir)
    entries = [directory[i:i + 128] for i in range(0, len(directory) - 127, 128)]
    if not entries:
        raise CompoundFileError("no directory")
    minifat_data = read_chain(first_minifat) if minifat_count else b''
    minifat = list(struct.unpack(f'<{len(minifat_data) // 4}I', minifat_data))
    root_start, root_size = struct.unpack_from('<II', entries[0], 116)
    mini_stream = read_chain(root_start)[:root_size] if root_start != ENDOFCHAIN else b''

    def stream_data(raw):
        start = struct.unpack_from('<I', raw, 116)[0]
        size = struct.unpack_from('<I', raw, 120)[0]
        if major == 4:
            size |= struct.unpack_from('<I', raw, 124)[0] << 32
        if size < cutoff:
            return b''.join(mini_stream[sid * mini_size:(sid + 1) * mini_size]
                            for sid in chain(start, minifat))[:size]
        return read_chain(start)[:size]

    def make(index):
        raw = entries[index]
        name_size = struct.unpack_from('<H', raw, 64)[0]
        name = raw[:max(0, min(name_size, 64) - 2)].decode('utf-16-le', errors='replace')
        kind = raw[66]
        entry = Entry(name, kind != STGTY_STREAM, raw[80:96])
        entry.state_bits = struct.unpack_from('<I', raw, 96)[0]
        entry.ctime, entry.mtime = struct.unpack_from('<QQ', raw, 100)
        if kind == STGTY_STREAM:
            entry.data = bytearray(stream_data(raw))
        return entry

    def add_children(storage, index, visited):
        # The children of a storage: the red-black tree under its child entry
        pending = [struct.unpack_from('<I', entries[index], 76)[0]]
        while pending:
            child = pending.pop()
            if child == NOSTREAM or child >= len(entries) or child in visited:
                continue
            visited.add(child)
            raw = entries[child]
            left, right = struct.unpack_from('<II', raw, 68)
            pending += [left, right]
            if raw[66] not in (STGTY_STORAGE, STGTY_STREAM):
                continue
            entry = storage.add(make(child))
            if entry.storage:
                add_children(entry, child, visited)

    root = make(0)
    add_children(root, 0, {0})
    return root


def save(root):
    """The bytes of a version 3 compound file holding root's tree"""
    # Directory entries in depth-first order; each storage's children become
    # a balanced binary tree (its deepest level red, the others black)
    order = [root]
    links = {}  # id(entry) -> (left, right, child, color)

    def build_tree(children):
        """Index of the subtree root of the sorted children; sets their links"""
        def build(items, depth, max_depth):
            if not items:
                return NOSTREAM
            middle = len(items) // 2
            entry = items[middle]
            index = len(order)
            order.append(entry)
            left = build(items[:middle], depth + 1, max_depth)
            right = build(items[middle + 1:], depth + 1, max_depth)
            red = depth == max_depth and depth > 0 and not perfect
            links[id(entry)] = [left, right, NOSTREAM, 0 if red else 1]
            return index
        items = sorted(children, key=lambda e: _compare_key(e.name))
        max_depth = max(0, len(items).bit_length() - 1)
        perfect = len(items) == (1 << (max_depth + 1)) - 1
        return build(items, 0, max_depth)

    links[id(root)] = [NOSTREAM, NOSTREAM, NOSTREAM, 1]
    pending = [root]
    while pending:
        storage = pending.pop(0)
        links[id(storage)][2] = build_tree(list(storage.children.values()))
        pending += [c for c in storage.children.values() if c.storage]
        # Storages found later are built after the ones before them
    # Stream data: small streams in the mini stream, the others in sectors
    sectors = []  # sector contents in file order
    starts, sizes = {}, {}
    mini = bytearray()
    minifat = []
    for entry in order:
        if entry.storage:
            continue
        data = bytes(entry.data)
        sizes[id(entry)] = len(data)
        if not data:
            starts[id(entry)] = ENDOFCHAIN
        elif len(data) < MINI_STREAM_CUTOFF:
            first = len(mini) // MINI_SECTOR
            count = (len(data) + MINI_SECTOR - 1) // MINI_SECTOR
            mini += data.ljust(count * MINI_SECTOR, b'\x00')
            minifat += list(range(first + 1, first + count)) + [ENDOFCHAIN]
            starts[id(entry)] = first
        else:
            starts[id(entry)] = len(sectors)
            sectors += [data[i:i + SECTOR].ljust(SECTOR, b'\x00')
                        for i in range(0, len(data), SECTOR)]
    chains = []  # (first sector, count) of every chain, for the FAT

    def add_chain(blob):
        first = len(sectors)
        count = (len(blob) + SECTOR - 1) // SECTOR
        sectors.extend(bytes(blob[i:i + SECTOR]).ljust(SECTOR, b'\x00')
                       for i in range(0, count * SECTOR, SECTOR))
        return first, count

    for entry in order:
        if not entry.storage and starts[id(entry)] not in (ENDOFCHAIN,) and \
                sizes[id(entry)] >= MINI_STREAM_CUTOFF:
            chains.append((starts[id(entry)], (sizes[id(entry)] + SECTOR - 1) // SECTOR))
    mini_first, mini_count = add_chain(mini) if mini else (ENDOFCHAIN, 0)
    if mini_count:
        chains.append((mini_first, mini_count))
    minifat_blob = struct.pack(f'<{len(minifat)}I', *minifat) if minifat else b''
    if minifat_blob:
        minifat_blob = minifat_blob.ljust(-(-len(minifat_blob) // SECTOR) * SECTOR, b'\xff')
    minifat_first, minifat_count = add_chain(minifat_blob) if minifat_blob else (ENDOFCHAIN, 0)
    if minifat_count:
        chains.append((minifat_first, minifat_count))

    directory = bytearray()
    for entry in order:
        name = entry.name.encode('utf-16-le')[:62]
        left, right, child, color = links[id(entry)]
        if entry is root:
            kind, start, size = STGTY_ROOT, mini_first, len(mini)
        elif entry.storage:
            kind, start, size = STGTY_STORAGE, 0, 0
        else:
            kind, start, size = STGTY_STREAM, starts[id(entry)], sizes[id(entry)]
        directory += (name.ljust(64, b'\x00') +
                      struct.pack('<HBBIII', len(name) + 2, kind, color, left, right,
                                  child if entry.storage else NOSTREAM) +
                      entry.clsid + struct.pack('<IQQIII', entry.state_bits,
                                                entry.ctime if entry.storage else 0,
                                                entry.mtime if entry.storage else 0,
                                                start, size, 0))
    while len(directory) % SECTOR:  # Unused entries
        directory += b'\x00' * 64 + struct.pack('<HBBIII', 0, 0, 0, NOSTREAM, NOSTREAM,
                                                NOSTREAM) + b'\x00' * 48
    dir_first, dir_count = add_chain(directory)
    chains.append((dir_first, dir_count))

    # The FAT (and DIFAT) sectors come last; their count depends on itself
    per_sector = SECTOR // 4
    fat_count = difat_count = 0
    while True:
        total = len(sectors) + fat_count + difat_count
        needed_fat = -(-total // per_sector)
        needed_difat = 0 if needed_fat <= 109 else -(-(needed_fat - 109) // (per_sector - 1))
        if (needed_fat, needed_difat) == (fat_count, difat_count):
            break
        fat_count, difat_count = needed_fat, needed_difat
    fat_first = len(sectors)
    difat_first = fat_first + fat_count
    fat = [FREESECT] * (fat_count * per_sector)
    for first, count in chains:
        for i in range(count):
            fat[first + i] = first + i + 1 if i < count - 1 else ENDOFCHAIN
    for i in range(fat_count):
        fat[fat_first + i] = FATSECT
    for i in range(difat_count):
        fat[difat_first + i] = DIFSECT
    fat_sectors = list(range(fat_first, fat_first + fat_count))
    sectors += [struct.pack(f'<{per_sector}I', *fat[i:i + per_sector])
                for i in range(0, len(fat), per_sector)]
    extra = fat_sectors[109:]
    for i in range(difat_count):
        values = extra[i * (per_sector - 1):(i + 1) * (per_sector - 1)]
        values += [FREESECT] * (per_sector - 1 - len(values))
        values.append(difat_first + i + 1 if i < difat_count - 1 else ENDOFCHAIN)
        sectors.append(struct.pack(f'<{per_sector}I', *values))
    header_difat = fat_sectors[:109] + [FREESECT] * (109 - min(109, fat_count))
    header = (SIGNATURE + b'\x00' * 16 +
              struct.pack('<HHHHH', 0x3E, 3, 0xFFFE, 9, 6) + b'\x00' * 6 +
              struct.pack('<IIIIIIIII', 0, fat_count, dir_first, 0, MINI_STREAM_CUTOFF,
                          minifat_first, minifat_count,
                          difat_first if difat_count else ENDOFCHAIN, difat_count) +
              struct.pack('<109I', *header_difat))
    return header + b''.join(sectors)
