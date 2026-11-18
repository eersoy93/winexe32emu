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

"""Configuration: version, folders, environment, ANSI code page"""

import os


# Version info
WINEXE32EMU_VERSION = "0.3.0"

# The emulated drives: one folder per drive letter in drives/ (in the
# repository root, the parent of src/); drives/C is C:\, the default EXE folder
SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DRIVES_PATH = os.path.join(SCRIPT_DIR, "drives")
# Drive letter -> (GetDriveType, file system, volume serial number), like a
# classic PC: A: a floppy disk, C: the hard disk, D: a CD-ROM (read-only for
# the programs; put files in drives/D on the host)
DRIVE_REMOVABLE, DRIVE_FIXED, DRIVE_CDROM = 2, 3, 5
DRIVES = {
    'A': (DRIVE_REMOVABLE, 'FAT', 0x2A1B0C11),
    'C': (DRIVE_FIXED, 'FAT32', 0x1E3A5C07),
    'D': (DRIVE_CDROM, 'CDFS', 0x0D5C3A1E),
}
READ_ONLY_DRIVES = ('D',)
FLOPPY_BYTES = 1474560  # 1.44 MB


def drive_host_path(letter):
    """Host folder of a drive letter (drives/C for C:)"""
    return os.path.join(DRIVES_PATH, letter.upper())


C_DRIVE_PATH = drive_host_path('C')
# c_drive/ of the versions before drives/: moved to drives/C at startup
OLD_C_DRIVE_PATH = os.path.join(SCRIPT_DIR, "c_drive")

# User account of the emulated programs and the Windows Vista+ folder layout:
# per-user files in the profile under C:\Users, shared ones in C:\Users\Public
# and C:\ProgramData (C:\Windows holds only the system)
USER_NAME = "User"
USERS_FOLDER = 'C:\\Users'
USER_PROFILE_FOLDER = USERS_FOLDER + '\\' + USER_NAME
USER_APPDATA_FOLDER = USER_PROFILE_FOLDER + '\\AppData\\Roaming'
USER_LOCAL_APPDATA_FOLDER = USER_PROFILE_FOLDER + '\\AppData\\Local'
PUBLIC_FOLDER = USERS_FOLDER + '\\Public'
PROGRAM_DATA_FOLDER = 'C:\\ProgramData'

# Environment variables seen by the emulated program. The folders they name
# are created inside drives/C at startup.
PROGRAM_FILES_FOLDER = 'C:\\Program Files'
DEFAULT_ENVIRONMENT = {
    'PATH': 'C:\\Windows\\System32;C:\\Windows',
    'TEMP': 'C:\\Windows\\Temp',
    'TMP': 'C:\\Windows\\Temp',
    'WINDIR': 'C:\\Windows',
    'SYSTEMROOT': 'C:\\Windows',
    'COMSPEC': 'C:\\Windows\\System32\\cmd.exe',
    'PROGRAMFILES': PROGRAM_FILES_FOLDER,
    'COMMONPROGRAMFILES': PROGRAM_FILES_FOLDER + '\\Common Files',
    # A 32-bit Windows: no WOW64 (no PROCESSOR_ARCHITEW6432, no ProgramFiles(x86))
    'PROCESSOR_ARCHITECTURE': 'x86',
    'USERNAME': USER_NAME,
    'USERPROFILE': USER_PROFILE_FOLDER,
    'HOMEDRIVE': 'C:',
    'HOMEPATH': USER_PROFILE_FOLDER[2:],
    'APPDATA': USER_APPDATA_FOLDER,
    'LOCALAPPDATA': USER_LOCAL_APPDATA_FOLDER,
    'PUBLIC': PUBLIC_FOLDER,
    'ALLUSERSPROFILE': PROGRAM_DATA_FOLDER,
    'PROGRAMDATA': PROGRAM_DATA_FOLDER,
}
# Variables whose value is a file path; only its parent folder is created
ENVIRONMENT_FILE_VARIABLES = {'COMSPEC'}

# Explorer app (the desktop's My Computer) compiled from apps/explorer/ at every start (compile_apps.sh)
EXPLORER_PATH = 'C:\\Windows\\explorer.exe'

# Emulated folder holding the test programs compiled with --tests (drives/C/Windows/Tests/)
TESTS_FOLDER = 'C:\\Windows\\Tests'

# Folders searched for a bare EXE name (command line), in this order
PROGRAM_FOLDERS = ('C:\\', TESTS_FOLDER)

# Code page used for the "A" (ANSI) APIs and CRT narrow strings: cp1252 by
# default, like the English (United States) Windows the emulator reports
# (LCID 0x0409); set via --codepage (e.g. cp1254 for a Turkish Windows, or
# utf-8 for programs that use UTF-8 narrow strings, like MinGW literals).
ANSI_CODEPAGE = "cp1252"


# Pygame import (optional for GUI)
os.environ["PYGAME_HIDE_SUPPORT_PROMPT"] = "1"
try:
    import pygame  # noqa: F401 (the modules import it if available)
    PYGAME_AVAILABLE = True
except ImportError:
    PYGAME_AVAILABLE = False
    print("Pygame not found, GUI support disabled!")
