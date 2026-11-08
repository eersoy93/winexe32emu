# winexe32emu

32-bit Windows EXE emulator in Python. Written with GitHub Copilot and Claude AI.

![winexe32emu 0.0.20 Fake Desktop Image](doc/winexe32emu_0_0_20.png)

## Installation

```bash
pip install -r requirements.txt
```

## Usage

Put EXE files in the c_drive/ folder (the emulated `C:\`) or compile the examples with `./compile-examples.sh`; the demo EXEs are placed in `c_drive/Windows/Demos/`, which the program sees as `C:\Windows\Demos`. After that, run:

```bash
python3 winexe32emu.py gdi_demo.exe
```

A bare EXE name is searched in `C:\` first and then in `C:\Windows\Demos`; a Windows path inside the emulated drive (e.g. `"C:\Windows\Demos\gdi_demo.exe"`) works too.

Use `-h` parameter for command-line help. For programs using a legacy ANSI code page (e.g. Turkish text), add `--codepage cp1254` (default: `utf-8`).

Use `-v` to see every API call and other debug output, or `-q` to see only the program output, warnings and errors.

With the GUI, the EXE name is optional: the Start menu on the fake desktop lists the EXE files in `C:\` and `C:\Windows\Demos` and runs the selected one (replacing the running program).

The emulator exits with the program's exit code (1 if the emulated program crashes).

## Folder Structure

- `c_drive/` - Put your EXE files here (emulation path, `C:\`)
- `c_drive/Windows/Demos/` - Compiled example EXEs (`C:\Windows\Demos`)
- `examples/` - Example C source codes
- `compile-examples.sh` - Script to compile examples into `c_drive/Windows/Demos/`
- `winexe32emu.py` - The main script

## Features

- PE file loading and analysis
- x86 CPU emulation (Unicorn)
- Fake Windows desktop with Pygame
- Basic Win32 API support (user32, kernel32, gdi32, advapi32, winmm, msvcrt)
- Sound output with Pygame: `Beep` plays a PC-speaker style tone (and blocks for its duration), `MessageBeep` plays system sounds, `PlaySound`/`sndPlaySound` play WAV files from the emulated drive, WAV images in memory and system sound aliases (see `examples/sound_demo.c`); without an audio device sounds are silent but keep their timing
- System information APIs (computer/user name, system info, memory status, code pages, system colors, high resolution timers) and wide/copy/move file APIs (see `examples/sysinfo_demo.c`)
- Folders named by the emulated environment variables (`C:\Windows`, `C:\Windows\System32`, `C:\Windows\Temp`) and the demo folder `C:\Windows\Demos` are created inside `c_drive/` at startup
- Broad C runtime support (msvcrt, crtdll, msvcr*, ucrtbase / api-ms-win-crt-*): printf/scanf families (narrow, wide, secure and UCRT `__stdio_common_*`), string and wide string functions, number conversions, math (including x87 `_CI*` and `_ftol` helpers), time, environment, sandboxed file system calls, signals and setjmp/longjmp (see `examples/crt_demo.c`)

## Versioning

- First version is 0.0.1, every major changes version is bumped to 0.0.5, 0.0.10, 0.0.15 etc, every minor changes version is bumped to 0.0.16, 0.0.17, etc.

## Disclaimer

This project is not endorsed by, affiliated with, or sponsored by Microsoft Corporation in any way. Windows, Win32, and related trademarks are the property of Microsoft Corporation. This is an independent, educational emulation project.

## Copyright and License

Copyright 2025-2026 Erdem Ersoy (eersoy93)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
