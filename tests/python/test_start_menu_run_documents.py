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

"""The Start menu's Run dialog and Documents submenu: finding programs and
file associations (src/shell_open.py), the Run MRU list, the recent documents
in the Recent folder (src/recent_documents.py), SHAddToRecentDocs and the
dialog itself on the fake desktop (SDL's dummy video driver).

Every test works on drives and a registry file in a temporary folder.

Run from the repository root:
    python3 -m unittest discover -s tests/python -v
"""

import os
import shutil
import sys
import tempfile
import threading
import time
import unittest

os.environ.setdefault('SDL_VIDEODRIVER', 'dummy')
os.environ.setdefault('SDL_AUDIODRIVER', 'dummy')

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
from src import config, recent_documents, shell_open  # noqa: E402
from src.config import PYGAME_AVAILABLE  # noqa: E402
from src.logger import DebugLogger  # noqa: E402
from src.resources import parse_shell_link  # noqa: E402
from src.winapi import WinAPIHandler  # noqa: E402
from src.winapi.shell_extra import ShellExtraMixin  # noqa: E402

if PYGAME_AVAILABLE:
    import pygame  # noqa: E402

    from src.gui import PseudoWindowsGUI  # noqa: E402


class ScratchDrives(unittest.TestCase):
    """Base: drives/ and the shared registry of a temporary folder"""

    def setUp(self):
        self.temp = tempfile.mkdtemp(prefix='winexe32emu-run-')
        self.saved = (config.DRIVES_PATH, WinAPIHandler.REGISTRY_FILE,
                      WinAPIHandler._shared_registry)
        config.DRIVES_PATH = os.path.join(self.temp, 'drives')
        WinAPIHandler.REGISTRY_FILE = os.path.join(self.temp, 'registry.json')
        WinAPIHandler._shared_registry = None
        self.previous_level = DebugLogger.level
        DebugLogger.level = DebugLogger.WARNING + 1
        for folder in ('Windows\\System32', 'Users\\User\\Documents'):
            os.makedirs(self.host('C:\\' + folder), exist_ok=True)
        os.makedirs(os.path.join(config.DRIVES_PATH, 'D'), exist_ok=True)

    def tearDown(self):
        (config.DRIVES_PATH, WinAPIHandler.REGISTRY_FILE,
         WinAPIHandler._shared_registry) = self.saved
        DebugLogger.level = self.previous_level
        shutil.rmtree(self.temp, ignore_errors=True)

    def host(self, path):
        """Host path of a Windows path in the scratch drives"""
        return os.path.join(config.DRIVES_PATH, path[0], *path[3:].split('\\'))

    def make_file(self, path, data=b'x'):
        os.makedirs(os.path.dirname(self.host(path)), exist_ok=True)
        with open(self.host(path), 'wb') as f:
            f.write(data)
        return path

    def set_classes_value(self, key, text, name=''):
        with shell_open.registry_lock():
            node = shell_open.registry_node(shell_open.HKEY_CLASSES_ROOT, key, create=True)
            shell_open.set_value_text(node, name, text)

    def register_type(self, extension, prog_id, command, verb='open'):
        self.set_classes_value(extension, prog_id)
        self.set_classes_value(f'{prog_id}\\shell\\{verb}\\command', command)


class FindAndAssociationTest(ScratchDrives):
    def test_bare_name_searched_with_exe(self):
        self.make_file('C:\\Windows\\System32\\Tool.exe')
        self.assertEqual(shell_open.find_file('tool'), 'C:\\Windows\\System32\\Tool.exe')
        self.assertIsNone(shell_open.find_file('nosuchprogram'))

    def test_app_paths(self):
        self.make_file('C:\\Office\\WINWORD.EXE')
        with shell_open.registry_lock():
            node = shell_open.registry_node(shell_open.HKEY_LOCAL_MACHINE,
                                            shell_open.APP_PATHS_KEY + '\\winword.exe', True)
            shell_open.set_value_text(node, '', 'C:\\Office\\WINWORD.EXE')
        self.assertEqual(shell_open.find_file('winword'), 'C:\\Office\\WINWORD.EXE')

    def test_split_command_unquoted_path_with_spaces(self):
        self.make_file('C:\\Program Files\\My App\\app.exe')
        self.assertEqual(shell_open.split_command('C:\\Program Files\\My App\\app.exe -x a b'),
                         ('C:\\Program Files\\My App\\app.exe', '-x a b'))
        self.assertEqual(shell_open.split_command('"C:\\Program Files\\My App\\app.exe" -y'),
                         ('C:\\Program Files\\My App\\app.exe', '-y'))
        self.assertEqual(shell_open.split_command('missing.exe arg'), (None, 'missing.exe'))
        self.assertEqual(shell_open.split_command('C:'), ('C:\\', ''))

    def test_document_opens_with_association(self):
        self.make_file('C:\\Apps\\writer.exe')
        doc = self.make_file('C:\\Users\\User\\Documents\\My Letter.wrt')
        self.register_type('.wrt', 'Writer.Document', 'C:\\Apps\\writer.exe /n')
        program, command, directory = shell_open.open_command(doc)
        self.assertEqual(program, 'C:\\Apps\\writer.exe')
        # Without %1 the document is added at the end, quoted for its space
        self.assertEqual(command, f'C:\\Apps\\writer.exe /n "{doc}"')
        self.assertEqual(directory, 'C:\\Users\\User\\Documents')

    def test_expand_command(self):
        path = 'C:\\A B\\x.doc'
        self.assertEqual(shell_open.expand_command('app.exe "%1"', path), f'app.exe "{path}"')
        self.assertEqual(shell_open.expand_command('app.exe %1 %2', path),
                         f'app.exe "{path}"')
        self.assertEqual(shell_open.expand_command('app.exe -o %L %*', 'C:\\x.txt', '-q'),
                         'app.exe -o C:\\x.txt -q')
        self.assertEqual(shell_open.expand_command('%WINDIR%\\app.exe', 'C:\\x.txt'),
                         'C:\\Windows\\app.exe C:\\x.txt')

    def test_default_verb_and_errors(self):
        self.make_file('C:\\Apps\\viewer.exe')
        doc = self.make_file('C:\\pic.img')
        self.register_type('.img', 'Viewer.Image', 'C:\\Apps\\viewer.exe "%1"', verb='view')
        self.set_classes_value('Viewer.Image\\shell', 'view')
        self.assertEqual(shell_open.open_command(doc)[1], f'C:\\Apps\\viewer.exe "{doc}"')
        self.assertEqual(shell_open.open_command(self.make_file('C:\\a.zzz')), (None, 31, None))
        self.assertEqual(shell_open.open_command('C:\\gone.img'), (None, 2, None))

    def test_win_ini_extensions(self):
        self.make_file('C:\\Windows\\oldedit.exe')
        self.make_file('C:\\Windows\\win.ini', b'[Extensions]\r\nold=oldedit.exe ^.old\r\n')
        doc = self.make_file('C:\\notes.old')
        self.assertEqual(shell_open.open_command(doc)[:2],
                         ('C:\\Windows\\oldedit.exe', 'oldedit.exe C:\\notes.old'))

    def test_folder_opens_in_explorer(self):
        self.make_file(config.EXPLORER_PATH)
        program, command, _ = shell_open.open_command('C:\\Users')
        self.assertEqual(program, config.EXPLORER_PATH)
        self.assertEqual(command, f'"{config.EXPLORER_PATH}" "C:\\Users"')


class RunMruTest(ScratchDrives):
    def test_order_duplicates_and_saving(self):
        for command in ('notepad', 'calc', 'NOTEPAD'):
            shell_open.add_run_mru(command)
        self.assertEqual(shell_open.run_mru(), ['notepad', 'calc'])
        with open(WinAPIHandler.REGISTRY_FILE, encoding='utf-8') as f:
            self.assertIn('RunMRU', f.read())
        # Read back from the file, like the next start of the emulator
        WinAPIHandler._shared_registry = None
        self.assertEqual(shell_open.run_mru(), ['notepad', 'calc'])
        with shell_open.registry_lock():
            node = shell_open.registry_node(shell_open.HKEY_CURRENT_USER,
                                            shell_open.RUN_MRU_KEY)
            self.assertEqual(shell_open.value_text(node, 'a'), 'notepad\\1')
            self.assertEqual(shell_open.value_text(node, 'MRUList'), 'ab')

    def test_oldest_makes_room(self):
        for i in range(30):
            shell_open.add_run_mru(f'program{i}')
        history = shell_open.run_mru()
        self.assertEqual(len(history), 26)
        self.assertEqual(history[0], 'program29')
        self.assertNotIn('program3', history)


class RecentDocumentsTest(ScratchDrives):
    def test_add_order_limit_and_missing(self):
        paths = [self.make_file(f'C:\\Users\\User\\Documents\\doc{i}.txt') for i in range(17)]
        for path in paths:
            self.assertTrue(recent_documents.add_recent_document(path))
        recent = recent_documents.recent_documents()
        self.assertEqual(len(recent), 15)
        self.assertEqual(recent[0], ('doc16.txt', paths[16]))
        # Opening an older one again makes it the newest
        recent_documents.add_recent_document(paths[5])
        self.assertEqual(recent_documents.recent_documents()[0][1], paths[5])
        os.remove(self.host(paths[5]))
        self.assertNotIn(paths[5], [p for _, p in recent_documents.recent_documents()])
        self.assertFalse(recent_documents.add_recent_document('C:\\nothing.txt'))

    def test_shortcut_file_and_clear(self):
        path = self.make_file('D:\\Data\\report.doc')
        recent_documents.add_recent_document(path)
        folder = self.host(recent_documents.recent_folder())
        with open(os.path.join(folder, 'report.doc.lnk'), 'rb') as f:
            link = parse_shell_link(f.read())
        self.assertEqual(link['path'], path)
        self.assertEqual(link['workdir'], 'D:\\Data')
        recent_documents.clear_recent_documents()
        self.assertEqual(recent_documents.recent_documents(), [])
        self.assertEqual(os.listdir(folder), [])


class FakeShellHandler:
    """Just what SHAddToRecentDocs uses of a WinAPIHandler"""

    def __init__(self, memory):
        self.memory = memory

    def _read_text(self, address, wide):
        return self.memory[(address, wide)]

    def _pidl_file_path(self, pidl):
        return self.memory[(pidl, 'pidl')]

    @staticmethod
    def full_windows_path(path):
        return path


class AddToRecentDocsTest(ScratchDrives):
    def test_flags_and_null(self):
        first = self.make_file('C:\\one.txt')
        second = self.make_file('C:\\two.txt')
        third = self.make_file('C:\\three.txt')
        handler = FakeShellHandler({(0x1000, False): first, (0x2000, True): second,
                                    (0x3000, 'pidl'): third})
        ShellExtraMixin.SHAddToRecentDocs(handler, [2, 0x1000])  # SHARD_PATHA
        ShellExtraMixin.SHAddToRecentDocs(handler, [3, 0x2000])  # SHARD_PATHW
        ShellExtraMixin.SHAddToRecentDocs(handler, [1, 0x3000])  # SHARD_PIDL
        self.assertEqual([p for _, p in recent_documents.recent_documents()],
                         [third, second, first])
        ShellExtraMixin.SHAddToRecentDocs(handler, [2, 0])
        self.assertEqual(recent_documents.recent_documents(), [])


@unittest.skipUnless(PYGAME_AVAILABLE, "Pygame is not installed")
class StartMenuRunDialogTest(ScratchDrives):
    def setUp(self):
        super().setUp()
        self.errors = []
        self.previous_hook = threading.excepthook
        threading.excepthook = lambda info: self.errors.append(info.exc_value)
        self.launched = []
        self.gui = PseudoWindowsGUI(800, 600)
        self.gui.launcher = lambda *args: self.launched.append(args)
        self.assertTrue(self.gui.start())

    def tearDown(self):
        self.gui.stop()
        threading.excepthook = self.previous_hook
        super().tearDown()
        self.assertEqual(self.errors, [])

    def post_key(self, key, unicode='', mod=0):
        for kind in (pygame.KEYDOWN, pygame.KEYUP):
            pygame.event.post(pygame.event.Event(kind, {'key': key, 'mod': mod,
                                                        'unicode': unicode, 'scancode': 0}))

    def wait(self):
        time.sleep(0.3)

    def run_dialogs(self):
        return [hwnd for hwnd, state in self.gui._host_dialogs().items()
                if state['kind'] == 'run' and hwnd in self.gui.windows]

    def test_menu_rows(self):
        with self.gui.lock:
            self.gui._fill_start_menu()
            labels = [label for _, label, _ in self.gui.start_menu_rows]
            documents = dict((label, rows) for kind, label, rows in self.gui.start_menu_rows
                             if kind == 'submenu')['Documents']
        for earlier, later in (('Programs', 'Documents'), ('Documents', 'Run...'),
                               ('Run...', 'Exit')):
            self.assertLess(labels.index(earlier), labels.index(later))
        self.assertEqual(documents, [('empty', '(Empty)', None)])
        path = self.make_file('C:\\Users\\User\\Documents\\plan.txt')
        recent_documents.add_recent_document(path)
        with self.gui.lock:
            self.gui._fill_start_menu()
            documents = dict((label, rows) for kind, label, rows in self.gui.start_menu_rows
                             if kind == 'submenu')['Documents']
            icon = self.gui._document_icon(path, 16)
        self.assertEqual(documents, [('document', 'plan.txt', path)])
        self.assertEqual(icon.get_size(), (16, 16))

    def test_typed_program_runs_and_joins_mru(self):
        self.make_file('C:\\Windows\\tool.exe')
        self.post_key(pygame.K_r, 'r', pygame.KMOD_LGUI)  # Win+R
        self.wait()
        with self.gui.lock:
            (hwnd,) = self.run_dialogs()
            self.assertEqual(self.gui.windows[hwnd].title, "Run")
            self.assertEqual(self.gui.active_window, hwnd)
        for char in 'tool -v':
            key = {' ': pygame.K_SPACE, '-': pygame.K_MINUS}.get(char) or \
                pygame.key.key_code(char)
            self.post_key(key, char)
        self.post_key(pygame.K_RETURN, '\r')
        self.wait()
        self.assertEqual(self.launched, [('C:\\Windows\\tool.exe',
                                          'C:\\Windows\\tool.exe -v', 'C:\\Windows')])
        self.assertEqual(self.run_dialogs(), [])
        self.assertEqual(shell_open.run_mru(), ['tool -v'])
        # The next Run dialog starts with it
        with self.gui.lock:
            hwnd = self.gui._open_run_dialog()
            combo = self.gui.controls[self.gui._host_dialogs()[hwnd]['edit']]
            self.assertEqual((combo.text, combo.items), ('tool -v', ['tool -v']))
        self.post_key(pygame.K_ESCAPE, '\x1b')
        self.wait()
        self.assertEqual(self.run_dialogs(), [])

    def test_document_and_bad_name(self):
        self.make_file('C:\\Apps\\writer.exe')
        doc = self.make_file('C:\\Users\\User\\Documents\\memo.wrt')
        self.register_type('.wrt', 'Writer.Document', 'C:\\Apps\\writer.exe "%1"')
        with self.gui.lock:
            self.assertTrue(self.gui.run_command(doc))
        self.assertEqual(self.launched[-1][:2], ('C:\\Apps\\writer.exe',
                                                 f'C:\\Apps\\writer.exe "{doc}"'))
        self.assertEqual(recent_documents.recent_documents(), [('memo.wrt', doc)])
        with self.gui.lock:
            hwnd = self.gui._open_run_dialog()
            combo = self.gui.controls[self.gui._host_dialogs()[hwnd]['edit']]
            combo.text = 'nosuchthing'
            self.gui._run_dialog_ok(hwnd)
            boxes = [self.gui.windows[h].title for h in self.gui.messageboxes]
            self.assertIn(hwnd, self.gui.windows, "the dialog stays open")
        self.assertEqual(boxes, ['nosuchthing'])
        self.assertEqual(len(self.launched), 1)

    def test_browse_fills_the_command(self):
        self.make_file('C:\\Program Files\\App\\app.exe')
        with self.gui.lock:
            run = self.gui._open_run_dialog()
            browse = self.gui._open_browse_dialog(run)
            state = self.gui._host_dialogs()[browse]
            labels = [label for _, label, _ in state['entries']]
            self.gui._browse_list_click(browse, labels.index('[Program Files]'), True)
            labels = [label for _, label, _ in state['entries']]
            self.gui._browse_list_click(browse, labels.index('[App]'), True)
            labels = [label for _, label, _ in state['entries']]
            self.gui._browse_list_click(browse, labels.index('app.exe'), False)
            self.gui._browse_open(browse)
            combo = self.gui.controls[self.gui._host_dialogs()[run]['edit']]
            self.assertNotIn(browse, self.gui.windows)
            self.assertEqual(combo.text, '"C:\\Program Files\\App\\app.exe"')
            self.assertEqual(self.gui.active_window, run)


if __name__ == '__main__':
    unittest.main()
