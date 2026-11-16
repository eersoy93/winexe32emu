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

"""Paths of the emulated C: drive, environment folders, setup scripts
and program lookup"""

import os
import subprocess

from .config import (C_DRIVE_PATH, DEFAULT_ENVIRONMENT, ENVIRONMENT_FILE_VARIABLES,
                     PROGRAM_FOLDERS, SCRIPT_DIR)
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


def resolve_c_drive_path(filename):
    """Map a Windows-style filename into the c_drive/ sandbox.

    The emulated program may only ever touch files inside c_drive/.
    Any path that would escape that directory (via "..", an absolute
    path, or a drive letter pointing elsewhere) is rejected and this
    returns None. On success it returns the absolute host path, which is
    guaranteed to live under C_DRIVE_PATH.
    """
    if not filename:
        return None

    # Make sure the sandbox root exists so real I/O can happen.
    try:
        os.makedirs(C_DRIVE_PATH, exist_ok=True)
    except OSError as e:
        log.error(f"Cannot create c_drive/ sandbox: {e}")
        return None

    # Normalise Windows path syntax to a relative POSIX-ish path.
    name = strip_win32_path_prefix(filename)
    if name is None:
        return None
    name = name.replace('\\', '/')

    # Strip a drive-letter prefix ("C:/...", "c:foo"). Everything is
    # treated as living on the emulated C: drive regardless of letter.
    if len(name) >= 2 and name[1] == ':':
        name = name[2:]

    # Drop UNC / leading-slash roots so they are taken relative to the
    # sandbox instead of the host filesystem root.
    name = name.lstrip('/')

    if not name:
        return None

    # Resolve against the sandbox root and confirm containment. Using
    # realpath collapses any "..", symlinks, etc. before the check so a
    # crafted name cannot climb out of c_drive/.
    root = os.path.realpath(C_DRIVE_PATH)
    candidate = os.path.realpath(os.path.join(root, name))

    if candidate != root and not candidate.startswith(root + os.sep):
        log.warning(f"Blocked sandbox escape attempt: \"{filename}\"")
        return None

    return candidate


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
    """Create the folders named by the environment (C:\\Windows, ...) in c_drive/."""
    for folder in environment_folders(environment):
        path = resolve_c_drive_path(folder)
        if path is None:
            continue
        try:
            os.makedirs(path, exist_ok=True)
            log.debug(f"Environment folder ready: {folder} -> {path}")
        except OSError as e:
            log.warning(f"Cannot create environment folder {folder}: {e}")


# Scripts: c_drive/ folders and the apps (apps/ into C:\Windows) at startup, and the test programs (--tests: compiled
# into C:\Windows\Tests and run without the GUI)
CREATE_C_DRIVE_SCRIPT = os.path.join(SCRIPT_DIR, "scripts", "create_c_drive_environment.sh")
COMPILE_APPS_SCRIPT = os.path.join(SCRIPT_DIR, "scripts", "compile_apps.sh")
RUN_TESTS_SCRIPT = os.path.join(SCRIPT_DIR, "scripts", "run_tests.sh")
REMOVE_C_DRIVE_SCRIPT = os.path.join(SCRIPT_DIR, "scripts", "remove_c_drive_environment.sh")


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
    """Host directory of an emulated program folder (C:\\ is c_drive/ itself)."""
    if folder.rstrip('\\/') in ('C:', 'c:'):
        return os.path.realpath(C_DRIVE_PATH)
    return resolve_c_drive_path(folder)


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
    is resolved inside c_drive/; a bare file name is searched in
    PROGRAM_FOLDERS (C:\\ first, then C:\\Windows\\Tests) and in their
    subfolders (each test program lives in its own folder).
    """
    if not name:
        return None
    if any(sep in name for sep in '\\/:'):
        path = resolve_c_drive_path(name)
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
