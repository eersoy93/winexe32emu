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
WINEXE32EMU_VERSION = "0.2.0"

# Default EXE directory (c_drive/ in the repository root, the parent of src/)
SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
C_DRIVE_PATH = os.path.join(SCRIPT_DIR, "c_drive")

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
# are created inside c_drive/ at startup.
PROGRAM_FILES_FOLDER = 'C:\\Program Files'
DEFAULT_ENVIRONMENT = {
    'PATH': 'C:\\Windows\\System32;C:\\Windows',
    'TEMP': 'C:\\Windows\\Temp',
    'TMP': 'C:\\Windows\\Temp',
    'WINDIR': 'C:\\Windows',
    'SYSTEMROOT': 'C:\\Windows',
    'COMSPEC': 'C:\\Windows\\System32\\cmd.exe',
    'PROGRAMFILES': PROGRAM_FILES_FOLDER,
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

# Emulated folder holding the test programs compiled with --tests (c_drive/Windows/Tests/)
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
