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

# Compiles the examples and runs each one in the emulator without the GUI.
# An example passes if it exits with 0 and prints its expected output.
# The exit code is the number of failed examples.

# Paths are relative to the repository root
cd "$(dirname "$0")/.." || exit 1

PYTHON=${PYTHON:-python3}
TIMEOUT=${TIMEOUT:-120}

sh scripts/create_c_drive_environment.sh || exit 1
sh scripts/compile_examples.sh || exit 1

# No sound card needed for sound_example
export SDL_AUDIODRIVER=dummy

passed=0
failed=0

# run_example NAME EXPECTED [INPUT]: EXPECTED is a fixed string the output must contain
run_example() {
    name=$1
    expected=$2
    input=$3
    output=$(printf '%s\n' "$input" | timeout "$TIMEOUT" "$PYTHON" winexe32emu.py \
        --no-gui --no-create-environment --no-examples -q "${name}.exe" 2>&1)
    code=$?
    if [ "$code" -eq 0 ] && printf '%s' "$output" | grep -qF -- "$expected"; then
        echo "PASS: ${name}"
        passed=$((passed + 1))
    else
        echo "FAIL: ${name} (exit code ${code})"
        printf '%s\n' "$output" | tail -n 10 | sed 's/^/    /'
        failed=$((failed + 1))
    fi
}

# Console examples check their own results
run_example crt_example "== 0 failure(s) =="
run_example api_example "== 0 failure(s) =="
run_example file_example "was blocked! Good!"
run_example sysinfo_example "Escape attempt (copy)   : 0, error 5"
run_example console_example "Hello, Tester!" "Tester"
run_example sound_example "Done!"

# GUI examples: without the GUI their message loop gets WM_QUIT at once,
# so this checks that they start and end cleanly
for name in ball_example gdi_example gui_example paint_example scroll_example; do
    run_example "$name" ""
done

echo "== ${passed} passed, ${failed} failed =="
exit "$failed"
