#!/bin/sh
# Copyright 2025 Erdem Ersoy (eersoy93)
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

mkdir -p c_drive

# Compile each example with appropriate flags
for src in examples/*.c; do
    name=$(basename "$src" .c)
    
    case "$name" in
        hello_console)
            # Console application - uses AllocConsole
            i686-w64-mingw32-gcc -o "c_drive/${name}.exe" "$src" \
                -lkernel32 -mwindows
            ;;
        console_input)
            # Minimal console application - WinMain entry
            i686-w64-mingw32-gcc -o "c_drive/${name}.exe" "$src" \
                -nostartfiles -lkernel32 -mwindows -e_WinMain@16
            ;;
        hello_messagebox)
            # MessageBox - minimal startup, WinMain entry
            i686-w64-mingw32-gcc -o "c_drive/${name}.exe" "$src" \
                -nostartfiles -lkernel32 -luser32 -mwindows -e_WinMain@16
            ;;
        hello_empty_window|empty_window)
            # Full Win32 window application - with standard CRT
            i686-w64-mingw32-gcc -o "c_drive/${name}.exe" "$src" \
                -lkernel32 -luser32 -lgdi32 -mwindows
            ;;
        *)
            # Default: GUI application
            i686-w64-mingw32-gcc -o "c_drive/${name}.exe" "$src" \
                -lkernel32 -luser32 -lgdi32 -mwindows
            ;;
    esac
    
    if [ $? -eq 0 ]; then
        echo "OK: ${name}.exe"
    else
        echo "ERROR: ${name}.exe compilation failed!"
    fi
done
