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

# Undoes compile_examples.sh: deletes the compiled example EXEs. Other files
# in C:\Windows\Examples are kept (the folder stays if any remain).

# Paths are relative to the repository root
cd "$(dirname "$0")/.." || exit 1

OUT_DIR=c_drive/Windows/Examples

for src in examples/*.c; do
    rm -f "${OUT_DIR}/$(basename "$src" .c).exe" || exit 1
done
rmdir "$OUT_DIR" 2>/dev/null

echo "OK: compiled examples removed"
