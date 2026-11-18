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

# Compiles the test programs and runs each one in the emulator without the
# GUI. A test passes if it exits with 0 and prints its expected output.
# The exit code is the number of failed tests.

# Paths are relative to the repository root
cd "$(dirname "$0")/.." || exit 1

PYTHON=${PYTHON:-python3}
TIMEOUT=${TIMEOUT:-120}

sh scripts/create_drives_environment.sh || exit 1
sh scripts/compile_tests.sh

# No sound card needed for sound_test
export SDL_AUDIODRIVER=dummy

passed=0
failed=0

# run_test NAME EXPECTED [INPUT [CODEPAGE]]: EXPECTED is a fixed string the
# output must contain; CODEPAGE is the --codepage option (default: cp1252)
run_test() {
    name=$1
    expected=$2
    input=$3
    codepage=${4:-cp1252}
    label=$name
    [ -n "$4" ] && label="${name} (${codepage})"
    output=$(printf '%s\n' "$input" | timeout "$TIMEOUT" "$PYTHON" winexe32emu.py \
        --no-gui --no-create-environment --no-apps -q --codepage "$codepage" \
        "${name}.exe" 2>&1)
    code=$?
    if [ "$code" -eq 0 ] && printf '%s' "$output" | grep -qF -- "$expected"; then
        echo "PASS: ${label}"
        passed=$((passed + 1))
    else
        echo "FAIL: ${label} (exit code ${code})"
        printf '%s\n' "$output" | tail -n 10 | sed 's/^/    /'
        failed=$((failed + 1))
    fi
}

# run_crash_test NAME ARG EXPECTED: "NAME.exe ARG" must end the process
# (nonzero exit code) and print EXPECTED
run_crash_test() {
    name=$1
    arg=$2
    expected=$3
    output=$(timeout "$TIMEOUT" "$PYTHON" winexe32emu.py \
        --no-gui --no-create-environment --no-apps -q "${name}.exe" "$arg" 2>&1 </dev/null)
    code=$?
    if [ "$code" -ne 0 ] && [ "$code" -ne 124 ] &&
            printf '%s' "$output" | grep -qF -- "$expected"; then
        echo "PASS: ${name} ${arg}"
        passed=$((passed + 1))
    else
        echo "FAIL: ${name} ${arg} (exit code ${code})"
        printf '%s\n' "$output" | tail -n 10 | sed 's/^/    /'
        failed=$((failed + 1))
    fi
}

# run_args_test NAME EXPECTED ARGS...: like run_test, with command-line arguments
run_args_test() {
    name=$1
    expected=$2
    shift 2
    output=$(timeout "$TIMEOUT" "$PYTHON" winexe32emu.py \
        --no-gui --no-create-environment --no-apps -q "${name}.exe" "$@" 2>&1 </dev/null)
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

run_test crt_test "== 0 failure(s) =="
run_test api_test "== 0 failure(s) =="
run_test api_test "== 0 failure(s) ==" "" utf-8
run_test file_test "was blocked! Good!"
run_test sysinfo_test "Escape attempt (copy)   : 0, error 5"
run_test console_test "Hello, Tester!" "Tester"
run_test sound_test "Done!"
run_test thread_test "== 0 failure(s) =="
run_test vista_api_test "== 0 failure(s) =="
run_test ext_api_test "== 0 failure(s) =="
run_test exception_test "== 0 failure(s) =="
run_args_test argv_test "== 0 failure(s) ==" plain "two words" 'a\b' 'q"uote' '' end
# Two processes: the second one finds what the first one saved
run_args_test registry_test "== 0 failure(s) ==" write
run_args_test registry_test "== 0 failure(s) ==" read
run_crash_test exception_test fastfail "__fastfail(7)"
run_crash_test exception_test int3 "Unhandled exception 0x80000003"
run_test seh_test "== 0 failure(s) =="
run_crash_test seh_test av "Unhandled exception 0xc0000005"

echo "== ${passed} passed, ${failed} failed =="
exit "$failed"
