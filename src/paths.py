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

"""Paths of the emulated drives (drives/), environment folders, setup scripts
and program lookup"""

import os
import subprocess

from .config import (C_DRIVE_PATH, DEFAULT_ENVIRONMENT, DRIVES, DRIVES_PATH,
                     ENVIRONMENT_FILE_VARIABLES, OLD_C_DRIVE_PATH, PROGRAM_FOLDERS,
                     SCRIPT_DIR, drive_host_path)
from .logger import log


def strip_win32_path_prefix(name):
    """Drop a Win32 file namespace prefix ("\\\\?\\C:\\x", "\\\\.\\C:\\x", "\\??\\C:\\x")
    in front of a drive path. Returns name unchanged without a prefix, or
    None for prefixed paths that are not on a drive (UNC shares, devices)."""
    if name[:4].replace('/', '\\') not in ('\\\\?\\', '\\\\.\\', '\\??\\'):
        return name
    rest = name[4:]
    if len(rest) >= 2 and rest[1] == ':' and rest[0].isalpha():
        return rest
    return None


# DOS device names: reserved in every folder and with any extension
# ("C:\x\nul.txt" is NUL too); CONIN$ and CONOUT$ only as the whole name
DOS_DEVICES = frozenset(['CON', 'PRN', 'AUX', 'NUL'] + [f'COM{i}' for i in range(1, 10)] +
                        [f'LPT{i}' for i in range(1, 10)])
CONSOLE_DEVICES = frozenset(['CONIN$', 'CONOUT$'])
# Characters a Windows file name cannot contain (wildcards included: only
# the Find APIs take patterns, and they resolve the folder, not the pattern)
INVALID_NAME_CHARACTERS = frozenset('<>:"|?*' + ''.join(map(chr, range(32))))

ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_ACCESS_DENIED = 2, 3, 5
ERROR_INVALID_NAME = 123


def device_name(filename):
    """Upper-case DOS device a file name opens ("NUL", "CON", "CONOUT$",
    "COM1"...), or None for an ordinary file name"""
    if not filename:
        return None
    name = filename.replace('/', '\\')
    if name[:4] in ('\\\\.\\', '\\\\?\\', '\\??\\'):
        name = name[4:]
    last = name.rsplit('\\', 1)[-1]
    if len(last) >= 2 and last[1] == ':' and '\\' not in name:
        last = last[2:]  # "C:nul"
    if last.upper() in CONSOLE_DEVICES:
        return last.upper()
    base = last.rstrip(' .').split('.', 1)[0].split(':', 1)[0].rstrip(' ').upper()
    return base if base in DOS_DEVICES else None


def _windows_component(part):
    """A path component as Windows stores it: trailing dots and spaces are
    dropped ("a.txt." is "a.txt"). Returns '' for a component that
    disappears and None for an invalid name."""
    if part in ('.', '..'):
        return part
    if any(ch in INVALID_NAME_CHARACTERS for ch in part):
        return None
    return part.rstrip(' .')


def _existing_entry(directory, part):
    """Name of the entry of a host directory that the Windows name part
    names: Windows file names are case-insensitive, the host's may not
    be. An exact match wins; None if there is no such entry."""
    if os.path.lexists(os.path.join(directory, part)):
        return part
    try:
        entries = os.listdir(directory)
    except OSError:
        return None
    folded = part.casefold()
    matches = sorted(e for e in entries if e.casefold() == folded)
    return matches[0] if matches else None


def drive_path_error(filename):
    """Win32 error code explaining why resolve_drive_path(filename) is None:
    ERROR_INVALID_NAME for names Windows rejects (or a device name),
    ERROR_PATH_NOT_FOUND for a drive that does not exist, otherwise
    ERROR_ACCESS_DENIED (the name escapes its drive's folder)"""
    name = strip_win32_path_prefix(filename or '')
    if not name:
        return ERROR_PATH_NOT_FOUND
    name = name.replace('/', '\\')
    if len(name) >= 2 and name[1] == ':':
        if name[0].upper() not in DRIVES:
            return ERROR_PATH_NOT_FOUND
        name = name[2:]
    if device_name(filename) or any(_windows_component(p) is None for p in name.split('\\')):
        return ERROR_INVALID_NAME
    return ERROR_ACCESS_DENIED


def resolve_drive_path(filename):
    """Map a Windows-style filename into the drives/ sandbox.

    Each drive letter is a folder of drives/ (C: is drives/C); a name
    without a drive letter is on C:. The emulated program may only ever
    touch files inside its drive's folder: any path that would escape it
    (via "..", symlinks...) or names a drive that does not exist is
    rejected and this returns None. On success it returns the absolute
    host path, which is guaranteed to live under the drive's folder.

    Like on Windows, names are case-insensitive (C:\\WINDOWS is the host's
    drives/C/Windows), trailing dots and spaces of each name are dropped,
    and names with invalid characters (":" of an alternate data stream,
    wildcards...) or of a DOS device (NUL, CON...: see device_name) never
    name a host file: None (drive_path_error tells why).
    """
    if not filename:
        return None
    if device_name(filename):
        return None

    # Normalise Windows path syntax to a relative POSIX-ish path.
    name = strip_win32_path_prefix(filename)
    if name is None:
        return None
    name = name.replace('\\', '/')

    # The drive-letter prefix ("C:/...", "d:foo") picks the drive's folder
    letter = 'C'
    if len(name) >= 2 and name[1] == ':':
        letter = name[0].upper()
        name = name[2:]
    if letter not in DRIVES:
        return None

    # Make sure the drive's folder exists so real I/O can happen.
    root = drive_host_path(letter)
    try:
        os.makedirs(root, exist_ok=True)
    except OSError as e:
        log.error(f"Cannot create the {letter}: drive folder {root}: {e}")
        return None

    # Drop UNC / leading-slash roots so they are taken relative to the
    # drive's folder instead of the host filesystem root.
    name = name.lstrip('/')

    # Resolve against the drive's folder and confirm containment. Using
    # realpath collapses any "..", symlinks, etc. before the check so a
    # crafted name cannot climb out of it.
    root = os.path.realpath(root)
    if not name:
        return root

    # Each existing folder or file is looked up case-insensitively; from the
    # first missing one on, the names stay as given (a file to create)
    current = root
    exists = True
    for part in name.split('/'):
        part = _windows_component(part)
        if part is None:
            return None
        if part in ('', '.'):
            continue
        if part == '..':
            if current == root:
                log.warning(f"Blocked sandbox escape attempt: \"{filename}\"")
                return None
            current = os.path.dirname(current)
            exists = os.path.isdir(current)
            continue
        if exists:
            entry = _existing_entry(current, part)
            exists = entry is not None
            part = entry if exists else part
        current = os.path.join(current, part)
    candidate = os.path.realpath(current)

    if candidate != root and not candidate.startswith(root + os.sep):
        log.warning(f"Blocked sandbox escape attempt: \"{filename}\"")
        return None

    return candidate


def windows_path_of_host(path):
    """Windows path (D:\\x\\y.exe) of a host path inside a drive's folder,
    or None outside drives/"""
    path = os.path.realpath(path)
    for letter in DRIVES:
        root = os.path.realpath(drive_host_path(letter))
        if path == root or path.startswith(root + os.sep):
            rel = os.path.relpath(path, root)
            return f"{letter}:\\" + ('' if rel == '.' else rel.replace(os.sep, '\\'))
    return None


def drive_letter_of_host(path):
    """Drive letter whose folder holds a host path (None outside drives/)"""
    windows = windows_path_of_host(path)
    return windows[0] if windows else None


def move_old_c_drive():
    """Move c_drive/ of the versions before drives/ to drives/C (once; an
    empty drives/C is replaced)"""
    if not os.path.isdir(OLD_C_DRIVE_PATH):
        return
    try:
        if os.path.isdir(C_DRIVE_PATH) and not os.listdir(C_DRIVE_PATH):
            os.rmdir(C_DRIVE_PATH)
        if os.path.exists(C_DRIVE_PATH):
            log.warning(f"{OLD_C_DRIVE_PATH} is not moved: {C_DRIVE_PATH} exists")
            return
        os.makedirs(DRIVES_PATH, exist_ok=True)
        os.rename(OLD_C_DRIVE_PATH, C_DRIVE_PATH)
        log.info(f"Moved {OLD_C_DRIVE_PATH} to {C_DRIVE_PATH}")
    except OSError as e:
        log.warning(f"Cannot move {OLD_C_DRIVE_PATH} to {C_DRIVE_PATH}: {e}")


def create_drive_folders():
    """drives/ with a folder for each drive letter (drives/A, drives/C...)"""
    move_old_c_drive()
    for letter in DRIVES:
        try:
            os.makedirs(drive_host_path(letter), exist_ok=True)
        except OSError as e:
            log.warning(f"Cannot create the {letter}: drive folder: {e}")


def environment_folders(environment):
    """Windows folders named by environment variables (deduplicated)."""
    folders = []
    for name, value in environment.items():
        for entry in value.split(';'):
            entry = entry.strip()
            if len(entry) < 3 or entry[1] != ':':
                continue  # only absolute drive paths name folders (not "C:" alone)
            if name.upper() in ENVIRONMENT_FILE_VARIABLES:
                entry = entry.replace('/', '\\').rsplit('\\', 1)[0]
            if entry.lower() not in (f.lower() for f in folders):
                folders.append(entry)
    return folders


def create_environment_folders(environment=DEFAULT_ENVIRONMENT):
    """Create the folders named by the environment (C:\\Windows, ...) in drives/."""
    for folder in environment_folders(environment):
        path = resolve_drive_path(folder)
        if path is None:
            continue
        try:
            os.makedirs(path, exist_ok=True)
            log.debug(f"Environment folder ready: {folder} -> {path}")
        except OSError as e:
            log.warning(f"Cannot create environment folder {folder}: {e}")


# Scripts: drives/ folders and the apps (apps/ into C:\Windows) at startup, and the test programs (--tests: compiled
# into C:\Windows\Tests and run without the GUI)
CREATE_DRIVES_SCRIPT = os.path.join(SCRIPT_DIR, "scripts", "create_drives_environment.sh")
COMPILE_APPS_SCRIPT = os.path.join(SCRIPT_DIR, "scripts", "compile_apps.sh")
RUN_TESTS_SCRIPT = os.path.join(SCRIPT_DIR, "scripts", "run_tests.sh")
REMOVE_DRIVES_SCRIPT = os.path.join(SCRIPT_DIR, "scripts", "remove_drives_environment.sh")


def run_setup_script(script, title):
    """Run a startup shell script; failures are reported, not fatal."""
    if not os.path.isfile(script):
        log.warning(f"Script not found: {script}")
        return
    log.header(title)
    try:
        result = subprocess.run(['sh', script], cwd=SCRIPT_DIR,
                                capture_output=True, text=True, timeout=600)
    except (OSError, subprocess.TimeoutExpired) as e:
        log.warning(f"{os.path.basename(script)} failed: {e}")
        return
    for line in (result.stdout + result.stderr).splitlines():
        if line.startswith('OK:'):
            log.info(line)
        elif line.strip():
            log.warning(line)


def _program_folder_host_path(folder):
    """Host directory of an emulated program folder (C:\\ is drives/C itself)."""
    return resolve_drive_path(folder)


def _program_subfolders(directory):
    """Names of the folders directly inside a host directory, sorted."""
    try:
        return sorted((d for d in os.listdir(directory)
                       if os.path.isdir(os.path.join(directory, d))), key=str.lower)
    except (OSError, TypeError):
        return []


def find_program(name):
    """Host path of the EXE to run, or None if it does not exist.

    A Windows path (C:\\Windows\\Tests\\api_test\\api_test.exe, ...)
    is resolved on its drive (drives/); a bare file name is searched in
    PROGRAM_FOLDERS (C:\\ first, then C:\\Windows\\Tests) and in their
    subfolders (each test program lives in its own folder).
    """
    if not name:
        return None
    if any(sep in name for sep in '\\/:'):
        path = resolve_drive_path(name)
        return path if path and os.path.isfile(path) else None
    for folder in PROGRAM_FOLDERS:
        directory = _program_folder_host_path(folder)
        if not directory:
            continue
        for sub in [''] + _program_subfolders(directory):
            path = os.path.join(directory, sub, name)
            if os.path.isfile(path):
                return path
    return None
