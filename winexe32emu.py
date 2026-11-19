#!/usr/bin/env python3
#
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

"""
Windows 32-bit EXE Emulator
PE file loading, analysis and CPU emulation module
Fake Windows GUI environment with Pygame

The code is in the src/ package (see src/__init__.py); this script runs it.
"""

import sys

if sys.version_info < (3, 11):
    sys.exit("winexe32emu needs Python 3.11 or newer")

from src.main import main  # noqa: E402

if __name__ == "__main__":
    main()
