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

# Test programs live in their own folders in C:\Windows\Tests of the
# emulated C drive (C:\Windows\Tests\api_test\api_test.exe)
TESTS_DIR=c_drive/Windows/Tests
mkdir -p "$TESTS_DIR" || exit 1

CFLAGS="-Wall -Wextra -Wno-unused-parameter"

failed=0

# Compile each test program with appropriate flags
for src in tests/*.c; do
    name=$(basename "$src" .c)

    case "$name" in
        *_dll)
            # DLL of a test program (NAME_dll.c): next to NAME.exe. Its preferred
            # base is in the emulator's heap (like 7z.dll), so it gets relocated.
            OUT_DIR="${TESTS_DIR}/${name%_dll}"
            mkdir -p "$OUT_DIR" || exit 1
            # shellcheck disable=SC2086
            if i686-w64-mingw32-gcc $CFLAGS -shared -Wl,--image-base,0x10000000 \
                    -o "${OUT_DIR}/${name}.dll" "$src" -lkernel32; then
                echo "OK: ${name}.dll"
            else
                echo "ERROR: ${name}.dll compilation failed!"
                failed=$((failed + 1))
            fi
            continue
            ;;
    esac

    OUT_DIR="${TESTS_DIR}/${name}"
    mkdir -p "$OUT_DIR" || exit 1

    case "$name" in
        console_test)
            # Console application - uses AllocConsole, kernel32 only
            LIBS="-lkernel32 -mwindows"
            ;;
        file_test)
            # Console application - sandboxed file I/O (kernel32 + user32 + msvcrt)
            LIBS="-lkernel32 -luser32 -mconsole"
            ;;
        sound_test)
            # Console application - Beep / MessageBeep / PlaySound (winmm)
            LIBS="-lkernel32 -luser32 -lwinmm -mconsole"
            ;;
        sysinfo_test)
            # Console application - system information APIs
            LIBS="-lkernel32 -luser32 -ladvapi32 -mconsole"
            ;;
        thread_test)
            # Console application - threads, synchronization, file mappings, DLL loading
            LIBS="-lkernel32 -mconsole"
            ;;
        api_test)
            # Console application - kernel32/user32/gdi32/advapi32/shell32/ole32/oleaut32 API tests
            LIBS="-lkernel32 -luser32 -lgdi32 -ladvapi32 -lshell32 -lole32 -loleaut32 -luuid -mconsole"
            ;;
        *)
            # Default: console application - C runtime (msvcrt) and kernel32
            LIBS="-lkernel32 -mconsole"
            ;;
    esac

    # shellcheck disable=SC2086
    if i686-w64-mingw32-gcc $CFLAGS -o "${OUT_DIR}/${name}.exe" "$src" $LIBS; then
        echo "OK: ${name}.exe"
    else
        echo "ERROR: ${name}.exe compilation failed!"
        failed=$((failed + 1))
    fi
done

exit "$failed"
