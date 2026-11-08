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

# Example programs live in their own folders in C:\Windows\Examples of the
# emulated C drive (C:\Windows\Examples\gui_example\gui_example.exe)
EXAMPLES_DIR=c_drive/Windows/Examples
mkdir -p "$EXAMPLES_DIR" || exit 1

CFLAGS="-Wall -Wextra -Wno-unused-parameter"

# Compile each example with appropriate flags
for src in examples/*.c; do
    name=$(basename "$src" .c)
    OUT_DIR="${EXAMPLES_DIR}/${name}"
    mkdir -p "$OUT_DIR" || exit 1
    # Left over from the old layout (all EXEs directly in C:\Windows\Examples)
    rm -f "${EXAMPLES_DIR}/${name}.exe"

    case "$name" in
        console_example)
            # Console application - uses AllocConsole, kernel32 only
            i686-w64-mingw32-gcc $CFLAGS -o "${OUT_DIR}/${name}.exe" "$src" \
                -lkernel32 -mwindows
            ;;
        file_example)
            # Console application - sandboxed file I/O (kernel32 + user32 + msvcrt)
            i686-w64-mingw32-gcc $CFLAGS -o "${OUT_DIR}/${name}.exe" "$src" \
                -lkernel32 -luser32 -mconsole
            ;;
        sound_example)
            # Console application - Beep / MessageBeep / PlaySound (winmm)
            i686-w64-mingw32-gcc $CFLAGS -o "${OUT_DIR}/${name}.exe" "$src" \
                -lkernel32 -luser32 -lwinmm -mconsole
            ;;
        sysinfo_example)
            # Console application - system information APIs
            i686-w64-mingw32-gcc $CFLAGS -o "${OUT_DIR}/${name}.exe" "$src" \
                -lkernel32 -luser32 -ladvapi32 -mconsole
            ;;
        crt_example)
            # Console application - C runtime (msvcrt) coverage tests
            i686-w64-mingw32-gcc $CFLAGS -o "${OUT_DIR}/${name}.exe" "$src" \
                -lkernel32 -mconsole
            ;;
        api_example)
            # Console application - kernel32/user32/gdi32/advapi32 API tests
            i686-w64-mingw32-gcc $CFLAGS -o "${OUT_DIR}/${name}.exe" "$src" \
                -lkernel32 -luser32 -lgdi32 -ladvapi32 -mconsole
            ;;
        *)
            # Default: GUI application
            i686-w64-mingw32-gcc $CFLAGS -o "${OUT_DIR}/${name}.exe" "$src" \
                -lkernel32 -luser32 -lgdi32 -mwindows
            ;;
    esac

    if [ $? -eq 0 ]; then
        echo "OK: ${name}.exe"
    else
        echo "ERROR: ${name}.exe compilation failed!"
    fi
done
