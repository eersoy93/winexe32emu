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

# Emulated C drive and the folders the default environment names
# (WINDIR/SYSTEMROOT, PATH, TEMP/TMP); demos live in C:\Windows\Demos
C_DRIVE=c_drive
for dir in Windows Windows/System32 Windows/Temp Windows/Demos; do
    mkdir -p "${C_DRIVE}/${dir}" || exit 1
done
echo "OK: ${C_DRIVE}/ directory tree"
