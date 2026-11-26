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

"""The Command Prompt (apps/cmd -> C:\\Windows\\System32\\cmd.exe) and the
emulator parts it needs: it is compiled into drives of a temporary folder and
run without the GUI, its commands typed into its standard input (the tests
need i686-w64-mingw32-gcc). Also the console window's line editing and the
per-drive current directories ("=D:") of path resolution.

Run from the repository root:
    python3 -m unittest discover -s tests/python -v
"""

import glob
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

os.environ.setdefault('SDL_VIDEODRIVER', 'dummy')
os.environ.setdefault('SDL_AUDIODRIVER', 'dummy')

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
sys.path.insert(0, REPO)
from src.config import PYGAME_AVAILABLE  # noqa: E402
from src.windows import FakeConsole  # noqa: E402
from src.winapi import WinAPIHandler  # noqa: E402

COMPILER = shutil.which('i686-w64-mingw32-gcc')

# Runs the emulator on the drives of the folder given first: the drive paths
# must change before any other module of src/ binds them
RUNNER = '''
import sys
sys.path.insert(0, {repo!r})
import src.config as config
config.DRIVES_PATH = sys.argv[1]
config.C_DRIVE_PATH = config.drive_host_path('C')
from src.main import main
sys.argv = ['winexe32emu.py', '--no-gui', '--no-create-environment', '--no-apps', '-q',
            '--codepage', 'cp1252'] + sys.argv[2:]
main()
'''


@unittest.skipUnless(COMPILER, "i686-w64-mingw32-gcc is needed to compile cmd.exe")
class CommandPromptTest(unittest.TestCase):
    """cmd.exe on scratch drives: internal commands, programs, batch files"""

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.mkdtemp(prefix='winexe32emu-cmd-')
        cls.drives = os.path.join(cls.temp, 'drives')
        system32 = os.path.join(cls.drives, 'C', 'Windows', 'System32')
        os.makedirs(system32)
        for letter in 'AD':
            os.makedirs(os.path.join(cls.drives, letter))
        sources = sorted(glob.glob(os.path.join(REPO, 'apps', 'cmd', '*.c')))
        subprocess.run([COMPILER, '-Wall', '-Wextra', '-Wno-unused-parameter', '-o',
                        os.path.join(system32, 'cmd.exe'), *sources, '-lkernel32',
                        '-luser32', '-lshell32', '-mconsole'], check=True)
        cls.runner = os.path.join(cls.temp, 'runner.py')
        with open(cls.runner, 'w') as f:
            f.write(RUNNER.format(repo=REPO))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp, ignore_errors=True)

    def run_cmd(self, commands, *args):
        """Output (stdout and stderr, without the log tags) and exit code of
        cmd.exe run with args, commands typed into it"""
        result = subprocess.run(
            [sys.executable, self.runner, self.drives, 'C:\\Windows\\System32\\cmd.exe', *args],
            input='\n'.join(commands) + '\n', capture_output=True, text=True, timeout=180,
            cwd=self.temp)
        output = (result.stdout + result.stderr).replace('[STDOUT] ', '')
        return output.replace('[STDERR] ', ''), result.returncode

    def write(self, path, text):
        host = os.path.join(self.drives, 'C', *path.split('\\'))
        os.makedirs(os.path.dirname(host), exist_ok=True)
        with open(host, 'w', newline='\r\n') as f:
            f.write(text)

    def test_file_and_variable_commands(self):
        output, code = self.run_cmd([
            'cd \\', 'md work\\sub', 'cd work',
            'echo first line> a.txt', 'echo second line>> a.txt', 'type a.txt',
            'copy a.txt b.txt', 'ren b.txt *.bak', 'move a.txt sub', 'dir /b /s',
            'del *.bak', 'if not exist b.bak echo b.bak deleted',
            'set GREETING=Hello there', 'echo [%GREETING%] [%NOT_SET%]',
            'set /a (1+2)*7', 'for %x in (one two) do echo item %x',
            'echo a && echo b || echo c', 'nosuchprogram', 'echo level %ERRORLEVEL%',
            'cd ..', 'rd /s /q work', 'if not exist work echo work removed',
            'cd \\..\\..', 'cd', 'exit 3'])
        self.assertEqual(code, 3, output)
        for text in ('first line\nsecond line', '1 file(s) copied.', '1 file(s) moved.',
                     'C:\\work\\b.bak', 'C:\\work\\sub\\a.txt', 'b.bak deleted',
                     '[Hello there] [%NOT_SET%]', '21', 'item one', 'item two', 'a\nb',
                     "'nosuchprogram' is not recognized", 'level 9009', 'work removed'):
            self.assertIn(text, output)
        self.assertNotIn('\nc\n', output)
        # ".." stops at the drive's root: the sandbox holds
        self.assertIn('C:\\>C:\\\n', output)

    def test_programs_redirection_and_batch_files(self):
        self.write('bin\\test.bat', '\n'.join([
            '@echo off', 'echo args: %1 %~2', 'set N=0', ':again', 'set /a N+=1',
            'if %N% LSS 3 goto again', 'echo N=%N%',
            'if "%1"=="go" (echo went) else (echo stayed)',
            'call :sub x', 'cmd /c exit 4', 'if errorlevel 4 echo child exit 4',
            'cmd /c echo from child> child.txt', 'type child.txt', 'goto :eof',
            ':sub', 'echo sub got %1', '']))
        output, code = self.run_cmd(['cd \\bin', 'test go "two words"', 'echo done'])
        self.assertEqual(code, 0, output)
        for text in ('args: go two words', 'N=3', 'went', 'sub got x', 'child exit 4',
                     'from child', 'done'):
            self.assertIn(text, output)
        self.assertNotIn('stayed', output)

    def test_slash_c(self):
        output, code = self.run_cmd([], '/c', 'echo one & ver & exit 6')
        self.assertEqual(code, 6, output)
        self.assertIn('one', output)
        self.assertIn('winexe32emu Command Prompt', output)


@unittest.skipUnless(PYGAME_AVAILABLE, "pygame is needed for the console window")
class ConsoleLineEditingTest(unittest.TestCase):
    """The keys of a line typed into a console window"""

    def setUp(self):
        import pygame
        from src.gui.console import ConsoleMixin
        self.pygame = pygame
        self.gui = ConsoleMixin()
        self.console = FakeConsole(1)

    def keys(self, *keys):
        for key in keys:
            if isinstance(key, str):
                self.gui.console_edit_key(self.console, self.pygame.K_a, key)
            else:
                self.gui.console_edit_key(self.console, key, '')

    def test_cursor_keys_insert_and_delete(self):
        k = self.pygame
        self.keys('d', 'r', k.K_LEFT, 'i', k.K_HOME, 'c', k.K_END, '!', k.K_LEFT,
                  k.K_BACKSPACE, k.K_DELETE)
        self.assertEqual(self.console.input, 'cdi')
        self.assertEqual(self.console.input_cursor, 3)

    def test_history(self):
        k = self.pygame
        for line in ('dir', 'dir', '', 'ver'):
            self.gui.console_line_entered(self.console, line)
        self.assertEqual(self.console.history, ['dir', 'ver'])
        self.console.history_pos = len(self.console.history)
        self.keys(k.K_UP)
        self.assertEqual(self.console.input, 'ver')
        self.keys(k.K_UP, k.K_UP)
        self.assertEqual(self.console.input, 'dir')
        self.keys(k.K_DOWN, k.K_DOWN)
        self.assertEqual(self.console.input, '')


class DriveDirectoryTest(unittest.TestCase):
    """"D:name" is relative to D:'s current directory, kept in "=D:" by cmd"""

    def test_drive_relative_names(self):
        handler = WinAPIHandler.__new__(WinAPIHandler)
        handler.current_directory = 'C:\\Windows'
        handler.environment = {'=D:': 'D:\\Data'}
        self.assertEqual(handler.full_windows_path('D:file.txt'), 'D:\\Data\\file.txt')
        self.assertEqual(handler.full_windows_path('C:file.txt'), 'C:\\Windows\\file.txt')
        self.assertEqual(handler.full_windows_path('A:file.txt'), 'A:\\file.txt')


if __name__ == '__main__':
    unittest.main()
