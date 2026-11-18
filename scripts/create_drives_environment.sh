#!/bin/sh
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

# Paths are relative to the repository root
cd "$(dirname "$0")/.." || exit 1

# Emulated drives: a folder per drive letter in drives/ (A: floppy disk,
# C: hard disk, D: CD-ROM). c_drive/ of the versions before drives/ becomes
# drives/C once.
DRIVES=drives
C_DRIVE=${DRIVES}/C
# (an empty drives/C is replaced)
if [ -d c_drive ]; then
    rmdir "$C_DRIVE" 2>/dev/null
fi
if [ -d c_drive ] && [ ! -e "$C_DRIVE" ]; then
    mkdir -p "$DRIVES" && mv c_drive "$C_DRIVE" || exit 1
    echo "OK: c_drive/ moved to ${C_DRIVE}/"
fi
for drive in A C D; do
    mkdir -p "${DRIVES}/${drive}" || exit 1
done

# The folders the default environment names on C: (WINDIR/SYSTEMROOT, PATH,
# TEMP/TMP, PROGRAMFILES, USERPROFILE, APPDATA, LOCALAPPDATA, PUBLIC,
# PROGRAMDATA); user files are in Users/, not in Windows/
for dir in Windows Windows/System32 Windows/Temp "Program Files" \
           Users/User/AppData/Roaming Users/User/AppData/Local Users/Public ProgramData; do
    mkdir -p "${C_DRIVE}/${dir}" || exit 1
done
echo "OK: ${DRIVES}/ directory tree"
