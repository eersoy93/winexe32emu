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

# Undoes compile_tests.sh: deletes the compiled test EXEs and DLLs. Other files
# in C:\Windows\Tests and the test folders are kept (folders stay if any remain).

# Paths are relative to the repository root
cd "$(dirname "$0")/.." || exit 1

OUT_DIR=c_drive/Windows/Tests

for src in tests/*.c; do
    name=$(basename "$src" .c)
    case "$name" in
        *_dll)
            # A test program's DLL (compiled next to NAME.exe)
            rm -f "${OUT_DIR}/${name%_dll}/${name}.dll" || exit 1
            rmdir "${OUT_DIR}/${name%_dll}" 2>/dev/null
            continue
            ;;
    esac
    rm -f "${OUT_DIR}/${name}/${name}.exe" || exit 1
    rmdir "${OUT_DIR}/${name}" 2>/dev/null
done
rmdir "$OUT_DIR" 2>/dev/null

echo "OK: compiled tests removed"
