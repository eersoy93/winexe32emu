# winexe32emu

32-bit Windows EXE emulator in Python. Written with GitHub Copilot and Claude AI.

![winexe32emu 0.2.0 Fake Desktop Image](doc/winexe32emu_0_2_0.png)

## Installation

```bash
pip install -r requirements.txt
```

Pygame (`pygame-ce`) is optional: it is only needed for the fake desktop and sound.

The apps (like Explorer) and the test programs are compiled with the 32-bit MinGW-w64 toolchain (`i686-w64-mingw32-gcc` and `i686-w64-mingw32-windres`):

| System | Command |
| --- | --- |
| Debian / Ubuntu | `sudo apt install gcc-mingw-w64-i686` |
| Fedora | `sudo dnf install mingw32-gcc` |
| Arch Linux | `sudo pacman -S mingw-w64-gcc` |
| macOS (Homebrew) | `brew install mingw-w64` |

## Usage

Put EXE files in the c_drive/ folder (the emulated `C:\`). Then run:

```bash
python3 winexe32emu.py
```

Use `-h` parameter for command-line help.

## Tested Programs

- 7-Zip 4.65 (x86, NSIS setup only)
- 7-Zip 9.20 (x86, NSIS setup only)
- 7-Zip 26.06 (x86, setup and program)
- Ants (setup and program)
- Ski32

## Features

- PE file loading and analysis
- x86 CPU emulation (Unicorn)
- Fake Windows desktop with sound support with Pygame
- Basic Win32 API support
- Loading the programs' own DLLs
- Structured exception handling
- A registry shared by the emulated programs
- Fake C drive environment support

## Versioning

- First version is 0.0.1, every major changes version is bumped to 0.0.5, 0.0.10, 0.0.15 etc, every minor changes version is bumped to 0.0.16, 0.0.17, etc. Every bigger changes version is bumped to 0.1.0, 0.2.0 etc. Every biggest changes for each stable version is bumped to 1.0.0, 2.0.0 etc.

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
