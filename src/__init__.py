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

"""Windows 32-bit EXE Emulator: the modules run by winexe32emu.py

config      version, folders, environment, ANSI code page (--codepage)
logger      DebugLogger, log, LogFileTee
pe_loader   PELoader: PE file loading and analysis
guest       helpers of the API emulation and the CPU emulator
paths       the emulated C: drive, setup scripts, program lookup
resources   shell links, icons, standard cursors
sound       SoundPlayer
winapi/     WinAPIHandler: one mixin module per area of the emulated APIs
windows     FakeWindow, FakeControl, FakeConsole of the pseudo GUI
gui         PseudoWindowsGUI: the pygame desktop
cpu         GuestThread, CPUEmulator (unicorn)
main        the command line

ANSI_CODEPAGE changes at startup (--codepage), so the modules read it as
config.ANSI_CODEPAGE. winapi, resources, windows and gui refer to each other
as module attributes (e.g. winapi.WinAPIHandler), so they load in any order.
"""
