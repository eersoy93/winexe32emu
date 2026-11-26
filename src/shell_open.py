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

"""How the shell opens things: the file associations of the registry
(HKEY_CLASSES_ROOT\\.ext -> ProgID\\shell\\verb\\command), finding a program by
name like the Run dialog (the Windows folders, PATH, App Paths), and the Run
dialog's most-recently-used list (Explorer\\RunMRU).

Both the emulated APIs (ShellExecute) and the fake desktop (Start menu, Run
dialog) use it, so it works on the registry tree the programs share without
a WinAPIHandler instance."""

import ntpath
import os
import re

from .config import DEFAULT_ENVIRONMENT, EXPLORER_PATH
from .paths import find_program, resolve_drive_path, windows_path_of_host
from .resources import parse_shell_link

HKEY_CLASSES_ROOT = 0x80000000
HKEY_CURRENT_USER = 0x80000001
HKEY_LOCAL_MACHINE = 0x80000002

CURRENT_VERSION_KEY = 'Software\\Microsoft\\Windows\\CurrentVersion'
RUN_MRU_KEY = CURRENT_VERSION_KEY + '\\Explorer\\RunMRU'
APP_PATHS_KEY = CURRENT_VERSION_KEY + '\\App Paths'

# Extensions of the files that run by themselves rather than through an
# association; .bat and .cmd need the command interpreter (COMSPEC)
PROGRAM_EXTENSIONS = ('.exe', '.com', '.bat', '.cmd', '.pif', '.scr')
# What the Run dialog appends to a name without an extension, in this order
RUN_EXTENSIONS = ('.exe', '.bat', '.cmd')
RUN_MRU_LIMIT = 26  # One value per letter a..z


# ---------- The shared registry tree ----------

def _handler():
    # Imported late: src.winapi imports this module too
    from . import winapi
    return winapi.WinAPIHandler


def registry_node(hkey, subkey, create=False):
    """Key node of hkey\\subkey in the shared registry (None if it does not
    exist and create is False). The caller holds registry_lock()."""
    cls = _handler()
    node = cls._shared_registry_roots().get(hkey)
    created = False
    for part in (p for p in subkey.split('\\') if p):
        if node is None or node.get('deleted'):
            return None
        child = node['keys'].get(part.lower())
        if child is None:
            if not create:
                return None
            child = cls._new_registry_key(part, node.get('volatile', False))
            node['keys'][part.lower()] = child
            created = True
        node = child
    if created:
        save_registry()
    return None if node is None or node.get('deleted') else node


def registry_lock():
    return _handler()._registry_lock


def save_registry():
    """Write the shared registry to its file (what RegSetValueEx does)"""
    cls = _handler()
    cls._save_registry(cls)  # Only uses the class's tree and file


def value_text(node, name=''):
    """Text of a string value of a key node ('' if it has none)"""
    value = node['values'].get(name.lower()) if node else None
    data = value.get('data') if value else ''
    if isinstance(data, bytes):
        data = data.decode('latin-1')
    text = data.split('\x00', 1)[0]
    if value and value.get('type') == 2:  # REG_EXPAND_SZ
        text = expand_environment(text)
    return text


def set_value_text(node, name, text):
    node['values'][name.lower()] = {'name': name, 'type': 1, 'data': text + '\x00'}


def classes_text(subkey, name=''):
    """A value of HKEY_CLASSES_ROOT\\subkey ('' if there is none)"""
    with registry_lock():
        return value_text(registry_node(HKEY_CLASSES_ROOT, subkey), name)


def expand_environment(text):
    """%NAME% of the emulated programs' environment replaced by its value;
    unknown names stay as they are, like ExpandEnvironmentStrings"""
    environment = {k.upper(): v for k, v in DEFAULT_ENVIRONMENT.items()}

    def replace(match):
        return environment.get(match.group(1).upper(), match.group(0))
    return re.sub(r'%([^%\s]+)%', replace, text)


# ---------- Paths ----------

def canonical_path(full):
    """Windows path of an existing file or folder in the letter case it has
    on its drive (C:\\Windows\\EXPLORER.EXE -> C:\\Windows\\explorer.exe), or
    None if it does not exist"""
    host = resolve_drive_path(full)
    if not host or not os.path.exists(host):
        return None
    return windows_path_of_host(host) or full


def absolute_path(name, directory='C:\\'):
    """name as an absolute Windows path: relative names are in directory, a
    name starting with a backslash on directory's drive"""
    name = name.replace('/', '\\')
    if len(name) == 2 and name[1] == ':':
        return name.upper() + '\\'
    if len(name) >= 3 and name[1] == ':' and name[2] == '\\':
        return ntpath.normpath(name)
    if name.startswith('\\'):
        return ntpath.normpath(directory[:2] + name)
    return ntpath.normpath(ntpath.join(directory, name))


def is_program(path):
    return path.lower().endswith(PROGRAM_EXTENSIONS)


def search_folders():
    """Folders searched for a program name: the Windows and system folders,
    then the folders of PATH (each once)"""
    folders = ['C:\\Windows', 'C:\\Windows\\System32']
    for entry in DEFAULT_ENVIRONMENT.get('PATH', '').split(';'):
        entry = entry.strip()
        if entry and entry.lower() not in (f.lower() for f in folders):
            folders.append(entry)
    return folders


def app_path(name):
    """Program registered under App Paths for a file name (WINWORD.EXE), or None"""
    for hkey in (HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE):
        with registry_lock():
            text = value_text(registry_node(hkey, APP_PATHS_KEY + '\\' + name))
        text = text.strip().strip('"')
        if text:
            found = canonical_path(absolute_path(text))
            if found and os.path.isfile(resolve_drive_path(found)):
                return found
    return None


def _find_in_folder(folder, name):
    """name (or name plus a Run extension) in folder: its canonical path or None"""
    candidates = [name] if ntpath.splitext(name)[1] else []
    candidates += [name + ext for ext in RUN_EXTENSIONS]
    for candidate in candidates:
        found = canonical_path(absolute_path(candidate, folder))
        if found and os.path.isfile(resolve_drive_path(found)):
            return found
    return None


def find_file(name, directory='C:\\'):
    """Windows path of the file or folder a typed name means, or None: a path
    (absolute, or relative to directory); a bare name is searched in
    directory, the Windows folders and PATH (adding .exe if it has no
    extension), then in App Paths"""
    name = name.strip()
    if not name or any(c in name for c in '*?<>|"'):
        return None
    if any(sep in name for sep in '\\/:'):
        full = absolute_path(name, directory)
        found = canonical_path(full)
        if found and os.path.isdir(resolve_drive_path(found)):
            return found
        folder, base = ntpath.split(full)
        return _find_in_folder(folder, base) if base else None
    for folder in [directory] + search_folders():
        found = _find_in_folder(folder, name)
        if found:
            return found
    candidates = [name] + ([name + '.exe'] if not ntpath.splitext(name)[1] else [])
    for candidate in candidates:
        found = app_path(candidate)
        if found:
            return found
    # Last, where the emulator's own command line looks for a program name
    # (the test programs in their folders of C:\Windows\Tests)
    for candidate in candidates:
        host = find_program(candidate)
        if host:
            return windows_path_of_host(host)
    return None


def split_command(text, directory='C:\\'):
    """(file, arguments) of a command line: a quoted first word, else the
    longest run of words naming an existing file or folder (Windows lets
    "C:\\Program Files\\x\\y.exe" go unquoted); (None, first word) if
    nothing is found"""
    text = text.strip()
    if text.startswith('"'):
        name, _, rest = text[1:].partition('"')
        return find_file(name, directory), rest.strip()
    words = text.split(' ')
    for count in range(len(words), 0, -1):
        found = find_file(' '.join(words[:count]), directory)
        if found:
            return found, ' '.join(words[count:]).strip()
    return None, words[0] if words else ''


# ---------- File associations ----------

def file_class(path):
    """ProgID of a file's extension (Word.Document.6 for .doc), or ''"""
    extension = ntpath.splitext(path)[1]
    return classes_text(extension) if extension else ''


def document_icon_location(path):
    """(file, index) of a document type's icon: the DefaultIcon of its ProgID
    (or of the ProgID's CLSID), else the program that opens it; None if the
    type has neither"""
    prog_id = file_class(path)
    location = classes_text(prog_id + '\\DefaultIcon') if prog_id else ''
    if not location and prog_id:
        clsid = classes_text(prog_id + '\\CLSID')
        location = classes_text(f'CLSID\\{clsid}\\DefaultIcon') if clsid else ''
    if location:
        file, comma, index = location.rpartition(',')
        if not comma:
            file, index = location, '0'
        try:
            return file.strip().strip('"'), int(index)
        except ValueError:
            return file.strip().strip('"'), 0
    template = association_command(path)
    program = split_command(expand_command(template, path))[0] if template else None
    return (program, 0) if program else None


def association_command(path, verb=''):
    """Command line template of a verb ('' is the default verb) of a document's
    type: HKEY_CLASSES_ROOT\\ProgID\\shell\\verb\\command, else the [Extensions]
    line of WIN.INI ("txt=notepad.exe ^.txt") of the Windows 3.1 programs.
    None if the type has no such verb."""
    prog_id = file_class(path)
    if prog_id:
        with registry_lock():
            shell = registry_node(HKEY_CLASSES_ROOT, prog_id + '\\shell')
            if shell is not None:
                names = [verb] if verb else []
                if not verb:
                    # The shell key's default value names the default verb,
                    # else "open", else its first verb
                    names += [n for n in (value_text(shell), 'open') if n]
                    names += [child['name'] for child in shell['keys'].values()]
                for name in names:
                    command = registry_node(HKEY_CLASSES_ROOT,
                                            f'{prog_id}\\shell\\{name}\\command')
                    text = value_text(command)
                    if text.strip():
                        return text.strip()
    if verb.lower() in ('', 'open'):
        return _win_ini_extension(path)
    return None


def _win_ini_extension(path):
    """Command of a document's extension in the [Extensions] section of
    C:\\Windows\\WIN.INI ("notepad.exe ^.txt" becomes "notepad.exe %1")"""
    extension = ntpath.splitext(path)[1][1:].lower()
    host = resolve_drive_path('C:\\Windows\\win.ini')
    if not extension or not host or not os.path.isfile(host):
        return None
    section = None
    try:
        with open(host, encoding='latin-1') as f:
            lines = f.read().splitlines()
    except OSError:
        return None
    for line in lines:
        line = line.strip()
        if line.startswith('['):
            section = line[1:].split(']', 1)[0].strip().lower()
        elif section == 'extensions' and '=' in line:
            key, _, value = line.partition('=')
            if key.strip().lower() == extension and value.strip():
                command = value.strip()
                if '^' in command:
                    return command.split('^', 1)[0].rstrip() + ' %1'
                return command + ' %1'
    return None


def expand_command(template, path, arguments=''):
    """Command line of an association template for a document: %1 and %L are
    the document (quoted when it has spaces and the template does not
    quote it), %* the arguments, %2..%9 empty; without %1 the document is
    added at the end, like Windows does"""
    has_file = re.search(r'%[1lL]', template) is not None
    quoted_path = f'"{path}"' if ' ' in path else path

    def replace(match):
        code = match.group(0)
        if code == '%%':
            return '%'
        if code in ('%1', '%l', '%L'):
            start, end = match.span()
            quoted = (template[start - 1:start] == '"' and template[end:end + 1] == '"')
            return path if quoted else quoted_path
        if code == '%*':
            return arguments
        return ''  # %0, %2...%9: printer names and other verb arguments
    command = re.sub(r'%[0-9*lL%]', replace, expand_environment(template)).strip()
    if not has_file:
        command += ' ' + quoted_path
    if arguments and '%*' not in template:
        command += ' ' + arguments
    return command


def open_command(path, verb='', arguments='', directory=None):
    """How to open a file or folder: (program, command line, current
    directory) for the launcher, or (None, error code, None) with
    SE_ERR_FNF (2) for a missing file or SE_ERR_NOASSOC (31) when no
    program opens it. A program runs itself, a folder opens in Explorer, a
    shortcut opens its target, a document opens with its associated program."""
    host = resolve_drive_path(path)
    if not host or not os.path.exists(host):
        return None, 2, None
    if os.path.isdir(host):
        explorer = resolve_drive_path(EXPLORER_PATH)
        if verb.lower() not in ('', 'open', 'explore') or not explorer or \
                not os.path.isfile(explorer):
            return None, 31, None
        return EXPLORER_PATH, f'"{EXPLORER_PATH}" "{path}"', path
    lower = path.lower()
    if lower.endswith('.lnk'):
        try:
            with open(host, 'rb') as f:
                link = parse_shell_link(f.read(65536))
        except OSError:
            link = None
        if not link or not link['path'] or link['path'].lower().endswith('.lnk'):
            return None, 31, None
        arguments = ' '.join(part for part in (link['arguments'], arguments) if part)
        return open_command(link['path'], verb, arguments, link['workdir'] or directory)
    if lower.endswith(('.exe', '.com')):
        if verb.lower() not in ('', 'open'):
            return None, 31, None
        quoted = f'"{path}"' if ' ' in path else path
        return path, quoted + (' ' + arguments if arguments else ''), \
            directory or ntpath.dirname(path)
    if lower.endswith(('.bat', '.cmd')):
        comspec = DEFAULT_ENVIRONMENT.get('COMSPEC', '')
        comspec_host = resolve_drive_path(comspec) if comspec else None
        if verb.lower() not in ('', 'open') or not comspec_host or \
                not os.path.isfile(comspec_host):
            return None, 31, None
        command = f'"{comspec}" /c "{path}"' + (' ' + arguments if arguments else '')
        return comspec, command, directory or ntpath.dirname(path)
    template = association_command(path, verb)
    if not template:
        return None, 31, None
    command = expand_command(template, path, arguments)
    program, _ = split_command(command)
    if program is None or not program.lower().endswith(('.exe', '.com')):
        return None, 31, None
    # The program sees the command line as the association wrote it
    return program, command, directory or ntpath.dirname(path)


# ---------- The Run dialog's most-recently-used list ----------

def run_mru():
    """Commands typed in the Run dialog, the newest first
    (HKEY_CURRENT_USER\\...\\Explorer\\RunMRU: values a..z and MRUList)"""
    with registry_lock():
        node = registry_node(HKEY_CURRENT_USER, RUN_MRU_KEY)
        if node is None:
            return []
        commands = []
        for letter in value_text(node, 'MRUList'):
            text = value_text(node, letter)
            # Explorer ends each entry with "\1"
            if text.endswith('\\1'):
                text = text[:-2]
            if text and text.lower() not in (c.lower() for c in commands):
                commands.append(text)
        return commands


def add_run_mru(command):
    """Put a command first in the Run dialog's list (the oldest one makes
    room when all 26 letters are used)"""
    command = command.strip()
    if not command:
        return
    with registry_lock():
        node = registry_node(HKEY_CURRENT_USER, RUN_MRU_KEY, create=True)
        if node is None:
            return
        order = [c for c in value_text(node, 'MRUList') if 'a' <= c <= 'z']
        letter = next((c for c in order
                       if value_text(node, c).removesuffix('\\1').lower() == command.lower()),
                      None)
        if letter is None:
            unused = [chr(ord('a') + i) for i in range(RUN_MRU_LIMIT)
                      if chr(ord('a') + i) not in order]
            letter = unused[0] if unused else order[-1]
            set_value_text(node, letter, command + '\\1')
        order = [letter] + [c for c in order if c != letter]
        set_value_text(node, 'MRUList', ''.join(order[:RUN_MRU_LIMIT]))
        save_registry()
