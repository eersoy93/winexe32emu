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

# Compiles each app in apps/ (apps/NAME/*.c, and apps/NAME/*.rc resources like
# the icon) into C:\Windows\NAME.exe of the emulated C drive
# (C:\Windows\filemanager.exe). Exit code: number of failed apps.

# Paths are relative to the repository root
cd "$(dirname "$0")/.." || exit 1

APPS_DIR=c_drive/Windows
mkdir -p "$APPS_DIR" || exit 1

CFLAGS="-Wall -Wextra -Wno-unused-parameter"

failed=0

for dir in apps/*/; do
    [ -d "$dir" ] || continue
    name=$(basename "$dir")

    # Resources (.rc) are compiled into objects linked with the sources
    objects=""
    ok=1
    for rc in "$dir"*.rc; do
        [ -f "$rc" ] || continue
        obj=$(mktemp) || exit 1
        objects="$objects $obj"
        i686-w64-mingw32-windres -I "$dir" -O coff -o "$obj" "$rc" || ok=0
    done

    # GUI applications
    # shellcheck disable=SC2086
    if [ "$ok" -eq 1 ] && i686-w64-mingw32-gcc $CFLAGS -o "${APPS_DIR}/${name}.exe" \
        "$dir"*.c $objects -lkernel32 -luser32 -lgdi32 -mwindows; then
        echo "OK: ${name}.exe"
    else
        echo "ERROR: ${name}.exe compilation failed!"
        failed=$((failed + 1))
    fi
    # shellcheck disable=SC2086
    [ -z "$objects" ] || rm -f $objects
done

exit "$failed"
