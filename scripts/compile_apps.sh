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
# (C:\Windows\explorer.exe). An app with an install_dir file goes to the
# folder of C: that file names instead, where Windows keeps that program
# (apps/msinfo32: Windows/System32); an EXE of the same name in another
# letter case there is replaced. An app with a console file is a console
# program (-mconsole, apps/cmd); the others are GUI programs (-mwindows).
# An app whose EXE is newer than its files and this script is up to date and
# not compiled again (--force compiles all).
# Exit code: number of failed apps.

# Paths are relative to the repository root
cd "$(dirname "$0")/.." || exit 1

APPS_DIR=drives/C/Windows
mkdir -p "$APPS_DIR" || exit 1

CFLAGS="-Wall -Wextra -Wno-unused-parameter"

force=0
[ "$1" = "--force" ] && force=1

failed=0

for dir in apps/*/; do
    [ -d "$dir" ] || continue
    name=$(basename "$dir")
    target_dir=$APPS_DIR
    if [ -f "${dir}install_dir" ]; then
        target_dir="drives/C/$(head -n 1 "${dir}install_dir")"
        mkdir -p "$target_dir" || exit 1
    fi
    # The EXE that is there under another letter case (MSINFO32.EXE)
    exe=$(find "$target_dir" -maxdepth 1 -type f -iname "${name}.exe" | head -n 1)
    [ -n "$exe" ] || exe="${target_dir}/${name}.exe"

    # Up to date: the EXE exists and no file of the app (nor this script) is newer
    if [ "$force" -eq 0 ] && [ -f "$exe" ] && ! [ scripts/compile_apps.sh -nt "$exe" ] &&
            [ -z "$(find "$dir" -type f -newer "$exe" | head -n 1)" ]; then
        echo "OK: $(basename "$exe") (up to date)"
        continue
    fi

    # Resources (.rc) are compiled into objects linked with the sources
    objects=""
    ok=1
    for rc in "$dir"*.rc; do
        [ -f "$rc" ] || continue
        obj=$(mktemp) || exit 1
        objects="$objects $obj"
        i686-w64-mingw32-windres -I "$dir" -O coff -o "$obj" "$rc" || ok=0
    done

    # GUI applications, or console ones
    subsystem=-mwindows
    [ -f "${dir}console" ] && subsystem=-mconsole
    # shellcheck disable=SC2086
    if [ "$ok" -eq 1 ] && i686-w64-mingw32-gcc $CFLAGS -o "$exe" \
        "$dir"*.c $objects -lkernel32 -luser32 -lgdi32 -lcomctl32 -lshell32 -lole32 \
        "$subsystem"; then
        echo "OK: $(basename "$exe")"
    else
        echo "ERROR: $(basename "$exe") compilation failed!"
        failed=$((failed + 1))
    fi
    # shellcheck disable=SC2086
    [ -z "$objects" ] || rm -f $objects
done

exit "$failed"
