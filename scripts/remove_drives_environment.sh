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

# Undoes create_drives_environment.sh, compile_apps.sh and compile_tests.sh. Other files
# in drives/ are kept (folders holding them stay); --all deletes the whole
# drives/ (every drive: A:, C:, D:) after a confirmation.

# Paths are relative to the repository root
cd "$(dirname "$0")/.." || exit 1

DRIVES=drives
C_DRIVE=${DRIVES}/C

if [ ! -d "$DRIVES" ]; then
    echo "OK: ${DRIVES}/ does not exist"
    exit 0
fi

if [ "$1" = "--all" ]; then
    printf "Delete %s/ (drives A:, C:, D:) and everything in it? [y/N] " "$DRIVES"
    read -r answer
    case "$answer" in
        y|Y|yes|YES)
            rm -rf "$DRIVES" || exit 1
            echo "OK: ${DRIVES}/ removed"
            ;;
        *)
            echo "Cancelled"
            ;;
    esac
    exit 0
fi

# Compiled apps and tests
for dir in apps/*/; do
    [ -d "$dir" ] || continue
    rm -f "${C_DRIVE}/Windows/$(basename "$dir").exe" || exit 1
done
sh scripts/remove_tests.sh >/dev/null || exit 1

# Deepest folders first; rmdir only removes empty ones
START_MENU="Users/User/AppData/Roaming/Microsoft/Windows/Start Menu"
for dir in Windows/Temp Windows/System32 Windows "Program Files" \
           "${START_MENU}/Programs" "${START_MENU}" Users/User/AppData/Roaming/Microsoft/Windows \
           Users/User/AppData/Roaming/Microsoft Users/User/AppData/Roaming \
           Users/User/AppData/Local Users/User/AppData Users/User Users/Public Users \
           ProgramData ""; do
    rmdir "${C_DRIVE}/${dir}" 2>/dev/null
done
for drive in A D ""; do
    rmdir "${DRIVES}/${drive}" 2>/dev/null
done

if [ -d "$DRIVES" ]; then
    echo "OK: environment removed; ${DRIVES}/ kept because of these files:"
    find "$DRIVES" -type f
else
    echo "OK: ${DRIVES}/ removed"
fi
