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

"""The desktop's folder icons (the user's folder, the network, the Recycle
Bin), the Recycle Bin store (src/recycle_bin.py) and its shell APIs
(SHFileOperation with FOF_ALLOWUNDO, SHQueryRecycleBin, SHEmptyRecycleBin).
Every test works on temporary drives, never on drives/.

Run from the repository root:
    python3 -m unittest discover -s tests/python -v
"""

import os
import struct
import sys
import tempfile
import unittest
from unittest import mock

os.environ.setdefault('SDL_VIDEODRIVER', 'dummy')
os.environ.setdefault('SDL_AUDIODRIVER', 'dummy')

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
from src import config, recycle_bin  # noqa: E402
from src.config import PYGAME_AVAILABLE  # noqa: E402
from src.logger import DebugLogger  # noqa: E402
from src.winapi import WinAPIHandler  # noqa: E402
from tests.python.test_word95_support import FakeEmulator  # noqa: E402

if PYGAME_AVAILABLE:
    from src.gui import PseudoWindowsGUI  # noqa: E402

DebugLogger.level = DebugLogger.WARNING + 1


class TempDrivesTest(unittest.TestCase):
    """Drives A:, C: and D: in a temporary folder"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patcher = mock.patch.object(config, 'DRIVES_PATH', self.tmp.name)
        patcher.start()
        self.addCleanup(patcher.stop)
        for letter in 'ACD':
            os.makedirs(self.host(letter + ':\\'), exist_ok=True)

    def host(self, path):
        """Host path of a Windows path on the temporary drives"""
        letter, rest = path[0].upper(), path[3:]
        return os.path.join(self.tmp.name, letter, *[p for p in rest.split('\\') if p])

    def make(self, path, text='data'):
        host = self.host(path)
        os.makedirs(os.path.dirname(host), exist_ok=True)
        with open(host, 'w') as f:
            f.write(text)
        return host


class RecycleBinStoreTest(TempDrivesTest):
    def test_recycle_lists_and_restores(self):
        file_host = self.make('C:\\Work\\notes.txt', 'hello')
        self.make('C:\\Work\\Folder\\inner.bin', '12345678')
        item = recycle_bin.recycle(file_host)
        folder = recycle_bin.recycle(self.host('C:\\Work\\Folder'))
        self.assertFalse(os.path.exists(file_host))
        self.assertEqual(item.stored_name, 'R000001.txt')  # The extension is kept
        self.assertEqual((folder.stored_name, folder.is_dir, folder.size), ('R000002', True, 8))
        self.assertEqual(item.original, 'C:\\Work\\notes.txt')
        self.assertEqual(item.name, 'notes.txt')
        self.assertEqual([i.stored_name for i in recycle_bin.items()],
                         ['R000001.txt', 'R000002'])
        self.assertEqual(recycle_bin.query(), (13, 2))
        # The index: a header, then the fields separated by TABs
        with open(self.host('C:\\$Recycle\\INDEX.TXT'), encoding='utf-8') as f:
            lines = f.read().splitlines()
        self.assertEqual(lines[0], recycle_bin.INDEX_HEADER)
        name, deleted, size, kind, original = lines[1].split('\t')
        self.assertEqual((name, size, kind, original),
                         ('R000001.txt', '5', 'F', 'C:\\Work\\notes.txt'))
        self.assertGreater(int(deleted), 130000000000000000)  # A FILETIME of this century
        # Restore makes the folders again
        os.rmdir(self.host('C:\\Work'))
        self.assertEqual(recycle_bin.restore(item), file_host)
        with open(file_host) as f:
            self.assertEqual(f.read(), 'hello')
        self.assertEqual(recycle_bin.query(), (8, 1))

    def test_restore_does_not_replace_without_asking(self):
        item = recycle_bin.recycle(self.make('C:\\a.txt', 'old'))
        self.make('C:\\a.txt', 'new')
        with self.assertRaises(FileExistsError):
            recycle_bin.restore(item)
        recycle_bin.restore(item, replace=True)
        with open(self.host('C:\\a.txt')) as f:
            self.assertEqual(f.read(), 'old')

    def test_purge_and_empty(self):
        first = recycle_bin.recycle(self.make('C:\\one.txt'))
        recycle_bin.recycle(self.make('C:\\two.txt'))
        recycle_bin.recycle(self.make('C:\\three.txt'))
        recycle_bin.purge(first)
        self.assertFalse(os.path.exists(first.stored_host))
        self.assertEqual(recycle_bin.query()[1], 2)
        # An item the index does not list goes too
        self.make('C:\\$Recycle\\R000099.txt')
        token = recycle_bin.state_token()
        self.assertEqual(recycle_bin.empty(), 3)
        self.assertEqual(recycle_bin.query(), (0, 0))
        self.assertNotEqual(recycle_bin.state_token(), token)
        self.assertEqual(os.listdir(self.host('C:\\$Recycle')), ['INDEX.TXT'])

    def test_what_can_be_recycled(self):
        self.assertTrue(recycle_bin.can_recycle(self.make('C:\\x.txt')))
        self.assertFalse(recycle_bin.can_recycle(self.make('A:\\x.txt')))  # Floppy: for good
        self.assertFalse(recycle_bin.can_recycle(self.make('D:\\x.txt')))  # CD-ROM
        self.assertFalse(recycle_bin.can_recycle(self.host('C:\\')))
        item = recycle_bin.recycle(self.host('C:\\x.txt'))
        self.assertFalse(recycle_bin.can_recycle(item.stored_host))  # Already in the bin
        self.assertEqual(recycle_bin.bin_drives(), ['C'])
        with self.assertRaises(ValueError):
            recycle_bin.recycle(self.host('A:\\x.txt'))

    def test_store_is_hidden(self):
        recycle_bin.recycle(self.make('C:\\x.txt'))
        self.assertEqual(recycle_bin.store_attributes(self.host('C:\\$Recycle')), 0x6)
        self.assertEqual(recycle_bin.store_attributes(self.host('C:\\Windows')), 0)
        os.makedirs(self.host('C:\\Sub\\$Recycle'))
        self.assertEqual(recycle_bin.store_attributes(self.host('C:\\Sub\\$Recycle')), 0)

    def test_forget_only_top_level_items(self):
        folder = self.host('C:\\F')
        os.makedirs(folder)
        item = recycle_bin.recycle(folder)
        # A file inside the deleted folder named like a top-level item
        nested = self.make(f'C:\\$Recycle\\{item.stored_name}\\{item.stored_name}')
        recycle_bin.forget(nested)
        self.assertEqual(recycle_bin.query()[1], 1)

    def test_broken_index_lists_nothing(self):
        self.make('C:\\$Recycle\\INDEX.TXT', 'something else\nR000001.txt\t1\t2\tF\tC:\\x\n')
        self.make('C:\\$Recycle\\R000001.txt')
        self.assertEqual(recycle_bin.items(), [])


class ShellApiTest(TempDrivesTest):
    """SHFileOperation, SHQueryRecycleBin, SHEmptyRecycleBin, the virtual folders"""
    FO_MOVE, FO_DELETE = 1, 3
    FOF_MULTIDESTFILES, FOF_NOCONFIRMATION, FOF_ALLOWUNDO = 0x1, 0x10, 0x40

    def setUp(self):
        super().setUp()
        self.handler = WinAPIHandler.__new__(WinAPIHandler)
        self.handler.emu = FakeEmulator()
        self.handler.current_directory = 'C:\\'
        self.handler.gui = None
        self.handler.pidls = {}
        self.uc = self.handler.emu.uc
        self.free = FakeEmulator.BASE + 0x80000

    def put(self, data):
        address = self.free
        self.uc.mem_write(address, data)
        self.free += (len(data) + 15) & ~15
        return address

    def paths(self, *paths):
        return self.put(b''.join(p.encode() + b'\x00' for p in paths) + b'\x00')

    def file_operation(self, func, sources, targets=(), flags=0):
        op = struct.pack('<IIIIHII', 0, func, self.paths(*sources),
                         self.paths(*targets) if targets else 0,
                         flags | self.FOF_NOCONFIRMATION, 0, 0) + b'\x00' * 8
        return self.handler.SHFileOperationA([self.put(op)])

    def query(self, root=None, wide=False):
        info = self.put(struct.pack('<Iqq', 20, -1, -1))
        p_root = 0
        if root is not None:
            p_root = self.put(root.encode('utf-16-le' if wide else 'ascii') + b'\x00\x00')
        call = self.handler.SHQueryRecycleBinW if wide else self.handler.SHQueryRecycleBinA
        result = call([p_root, info])
        return result, struct.unpack('<qq', bytes(self.uc.mem_read(info + 4, 16)))

    def test_delete_restore_purge(self):
        self.make('C:\\Docs\\a.txt', 'aaa')
        self.make('C:\\Docs\\b.txt', 'bb')
        self.assertEqual(self.file_operation(self.FO_DELETE, ['C:\\Docs\\a.txt', 'C:\\Docs\\b.txt'],
                                             flags=self.FOF_ALLOWUNDO), 0)
        self.assertFalse(os.path.exists(self.host('C:\\Docs\\a.txt')))
        self.assertEqual(self.query(), (0, (5, 2)))
        self.assertEqual(self.query('C:\\', wide=True), (0, (5, 2)))
        self.assertEqual(self.query('D:\\'), (0, (0, 0)))  # No bin on the CD-ROM
        self.assertEqual(self.query('Q:\\')[0], 0x80070057)  # E_INVALIDARG
        # Restore (Explorer): a move out of the store to the original name
        a, b = recycle_bin.items()
        os.rmdir(self.host('C:\\Docs'))
        self.assertEqual(self.file_operation(self.FO_MOVE, [a.stored_path], [a.original],
                                             self.FOF_MULTIDESTFILES), 0)
        with open(self.host('C:\\Docs\\a.txt')) as f:
            self.assertEqual(f.read(), 'aaa')
        self.assertEqual(self.query(), (0, (2, 1)))
        with open(self.host('C:\\$Recycle\\INDEX.TXT')) as f:
            self.assertEqual(len(f.read().splitlines()), 2)  # Its line is gone
        # Delete from the bin: for good, its index line goes
        self.assertEqual(self.file_operation(self.FO_DELETE, [b.stored_path],
                                             flags=self.FOF_ALLOWUNDO), 0)
        self.assertFalse(os.path.exists(b.stored_host))
        self.assertEqual(self.query(), (0, (0, 0)))

    def test_move_to_a_folder_takes_the_original_name(self):
        self.make('C:\\report.doc')
        self.file_operation(self.FO_DELETE, ['C:\\report.doc'], flags=self.FOF_ALLOWUNDO)
        (item,) = recycle_bin.items()
        os.makedirs(self.host('C:\\Back'))
        self.assertEqual(self.file_operation(self.FO_MOVE, [item.stored_path], ['C:\\Back']), 0)
        self.assertTrue(os.path.isfile(self.host('C:\\Back\\report.doc')))
        self.assertEqual(recycle_bin.items(), [])

    def test_without_allowundo_and_on_the_floppy(self):
        self.make('C:\\gone.txt')
        self.make('A:\\floppy.txt')
        self.assertEqual(self.file_operation(self.FO_DELETE, ['C:\\gone.txt']), 0)
        self.assertEqual(self.file_operation(self.FO_DELETE, ['A:\\floppy.txt'],
                                             flags=self.FOF_ALLOWUNDO), 0)
        self.assertFalse(os.path.exists(self.host('A:\\floppy.txt')))
        self.assertFalse(os.path.exists(self.host('A:\\$Recycle')))
        self.assertEqual(recycle_bin.items(), [])

    def test_empty_recycle_bin(self):
        self.make('C:\\x.txt')
        recycle_bin.recycle(self.host('C:\\x.txt'))
        self.assertEqual(self.handler.SHEmptyRecycleBinA([0, 0, 1]), 0)  # SHERB_NOCONFIRMATION
        self.assertEqual(self.query(), (0, (0, 0)))
        self.assertEqual(self.handler.SHEmptyRecycleBinW([0, 0, 1]), 0)  # Already empty
        root = self.put('Z:\\'.encode('utf-16-le') + b'\x00\x00')
        self.assertEqual(self.handler.SHEmptyRecycleBinW([0, root, 1]), 0x80070057)

    def test_virtual_folders(self):
        handler = self.handler
        for csidl, path in ((0x0A, handler.RECYCLE_BIN_PATH), (0x12, handler.NETWORK_PATH)):
            out = self.put(b'\x00' * 4)
            self.assertEqual(handler.SHGetSpecialFolderLocation([0, csidl, out]), 0)
            pidl = struct.unpack('<I', bytes(self.uc.mem_read(out, 4)))[0]
            self.assertEqual(handler._pidl_path(pidl), path)
            # Not a file system folder
            buffer = self.put(b'\xff' * 260)
            self.assertEqual(handler.SHGetPathFromIDListA([pidl, buffer]), 0)
        self.assertTrue(handler._is_virtual_folder(handler.RECYCLE_BIN_PATH.lower()))
        self.assertFalse(handler._is_virtual_folder(handler.MY_COMPUTER_PATH))

    def test_find_shows_the_store_hidden(self):
        recycle_bin.recycle(self.make('C:\\x.txt'))
        entry = self.handler._find_entry(self.host('C:\\$Recycle'), '$Recycle')
        self.assertEqual(entry[1] & 0x16, 0x16)  # DIRECTORY | SYSTEM | HIDDEN
        path = self.put(b'C:\\$Recycle\x00')
        self.assertEqual(self.handler.GetFileAttributesA([path]) & 0x16, 0x16)


@unittest.skipUnless(PYGAME_AVAILABLE, "Pygame is not installed")
class DesktopFolderIconsTest(TempDrivesTest):
    def setUp(self):
        super().setUp()
        self.make(config.EXPLORER_PATH, 'MZ')  # Explorer "compiled": the icons show
        self.gui = PseudoWindowsGUI(800, 600)
        self.launched = []
        self.gui.launcher = lambda *args: self.launched.append(args)

    def test_icons_after_my_computer(self):
        self.gui._refresh_desktop_icons()
        labels = [label for label, _ in self.gui.desktop_icons[:4]]
        self.assertEqual(labels, ['My Computer', config.USER_NAME, 'Network', 'Recycle Bin'])
        for _, data in self.gui.desktop_icons[1:4]:
            normal, selected = self.gui._program_icon(data, None, 32)
            self.assertEqual(normal.get_size(), (32, 32))
            self.assertNotEqual(normal.get_at((16, 20)), selected.get_at((16, 20)))

    def test_bin_icon_shows_full(self):
        gui, handler = self.gui, WinAPIHandler
        empty = gui._shell_icon_images(handler.SYS_ICON_BIN_EMPTY, 32)[0]
        full = gui._shell_icon_images(handler.SYS_ICON_BIN_FULL, 32)[0]
        self.assertNotEqual(bytes(empty.get_view('2')), bytes(full.get_view('2')))
        self.assertFalse(gui._recycle_bin_full())
        recycle_bin.recycle(self.make('C:\\x.txt'))
        gui._bin_state['time'] = 0  # (looked at twice a second)
        self.assertTrue(gui._recycle_bin_full())
        self.assertIs(gui._special_desktop_icon(gui.SPECIAL_BIN, 32)[0],
                      gui._shell_icon_images(handler.SYS_ICON_BIN_FULL, 32)[0])

    def test_icons_open_explorer(self):
        gui = self.gui
        gui._refresh_desktop_icons()
        for index, target in ((1, config.USER_PROFILE_FOLDER),
                              (2, WinAPIHandler.NETWORK_PATH),
                              (3, WinAPIHandler.RECYCLE_BIN_PATH)):
            gui._launch_icon(index)
            program, command_line, _ = self.launched[-1]
            self.assertEqual(program, config.EXPLORER_PATH)
            self.assertTrue(command_line.endswith(f' "{target}"'), command_line)
        self.assertTrue(os.path.isdir(self.host(config.USER_PROFILE_FOLDER)))

    def test_empty_from_the_menu(self):
        gui = self.gui
        recycle_bin.recycle(self.make('C:\\x.txt'))
        labels = [item[0] for item in gui._special_menu_items(gui.SPECIAL_BIN) if item]
        self.assertEqual(labels, ['Open', 'Empty Recycle Bin'])
        shown = []
        gui._show_messagebox = lambda caption, text, kind, request=None: shown.append(
            (caption, request))
        gui._ask_empty_recycle_bin()
        (caption, request), = shown
        self.assertEqual(caption, 'Confirm File Delete')
        gui._check_desktop_questions()
        self.assertEqual(recycle_bin.query()[1], 1)  # Not answered yet
        request['result'] = 6  # IDYES
        gui._check_desktop_questions()
        self.assertEqual(recycle_bin.query(), (0, 0))


if __name__ == '__main__':
    unittest.main()
