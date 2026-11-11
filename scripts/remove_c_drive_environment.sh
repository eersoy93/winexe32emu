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

# Undoes create_c_drive_environment.sh and compile_tests.sh. Other files
# in c_drive/ are kept (folders holding them stay); --all deletes the whole
# c_drive/ after a confirmation.

# Paths are relative to the repository root
cd "$(dirname "$0")/.." || exit 1

C_DRIVE=c_drive

if [ ! -d "$C_DRIVE" ]; then
    echo "OK: ${C_DRIVE}/ does not exist"
    exit 0
fi

if [ "$1" = "--all" ]; then
    printf "Delete %s/ and everything in it? [y/N] " "$C_DRIVE"
    read -r answer
    case "$answer" in
        y|Y|yes|YES)
            rm -rf "$C_DRIVE" || exit 1
            echo "OK: ${C_DRIVE}/ removed"
            ;;
        *)
            echo "Cancelled"
            ;;
    esac
    exit 0
fi

# Compiled tests
sh scripts/remove_tests.sh >/dev/null || exit 1

# Deepest folders first; rmdir only removes empty ones
for dir in Windows/Temp Windows/System32 Windows ""; do
    rmdir "${C_DRIVE}/${dir}" 2>/dev/null
done

if [ -d "$C_DRIVE" ]; then
    echo "OK: environment removed; ${C_DRIVE}/ kept because of these files:"
    find "$C_DRIVE" -type f
else
    echo "OK: ${C_DRIVE}/ removed"
fi
