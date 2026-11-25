# winexe32emu

[![CI](https://github.com/eersoy93/winexe32emu/actions/workflows/ci.yml/badge.svg)](https://github.com/eersoy93/winexe32emu/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)

**A 32-bit Windows EXE emulator written in Python.** It loads classic Windows programs, runs their code on an emulated x86 CPU and shows their windows on its own fake Windows desktop — no Windows needed.

Written with GitHub Copilot and Claude AI.

![winexe32emu 0.3.0 Fake Desktop Image](doc/winexe32emu_0_3_0.png)

## Contents

- [Features](#features)
- [Supported Programs](#supported-programs)
- [Getting Started](#getting-started)
- [Usage](#usage)
- [Running the Tests](#running-the-tests)
- [Not Supported (Currently)](#not-supported-currently)
- [Versioning](#versioning)
- [Contributing](#contributing)
- [Disclaimer](#disclaimer)
- [Copyright and License](#copyright-and-license)

## Features

- 🖥️ **Fake Windows desktop** with a taskbar, a Start menu, windows, dialogs and sound
- 📦 **Runs real programs**: setups and applications, several of them side by side
- 💾 **Virtual drives**: A: (floppy disk), C: (hard disk) and D: (CD-ROM) are plain folders in `drives/`
- 🔒 **Sandboxed**: programs can only reach the files inside their virtual drives
- 🗂️ **A shared registry** that the emulated programs keep between runs
- 🌐 **Offline by design**: programs see a PC without a network
- 🧩 **Built-in apps**: Explorer (`explorer.exe`) and a Windows Help stub (`winhlp32.exe`)
- 🔍 **Missing API report**: see what a program needs that is not emulated yet

## Supported Programs

These are playable, but may not be supported 100%:

| Program | What works |
| --- | --- |
| 7-Zip 4.65 (x86) | NSIS setup and programs |
| 7-Zip 9.20 (x86) | NSIS setup and programs |
| 7-Zip 26.06 (x86) | Setup and programs |
| Ants | Setup and program |
| Microsoft Office 95 Professional | Installer, Word, Excel, PowerPoint, Access, Schedule+, Binder, Office Shortcut Bar, Find Fast
| Ski32 | Program |

## Getting Started

You need **Python 3.11 or newer**. winexe32emu runs from its repository folder; it is not installed as a package.

```bash
git clone https://github.com/eersoy93/winexe32emu.git
cd winexe32emu
pip install -r requirements.txt
```

Pygame (`pygame-ce`) is optional: it is only needed for the fake desktop and sound.

The built-in apps (like Explorer) and the test programs are compiled with the 32-bit MinGW-w64 toolchain:

| System | Command |
| --- | --- |
| Debian / Ubuntu | `sudo apt install gcc-mingw-w64-i686` |
| Fedora | `sudo dnf install mingw32-gcc` |
| Arch Linux | `sudo pacman -S mingw-w64-gcc` |
| macOS (Homebrew) | `brew install mingw-w64` |

## Usage

1. Put your EXE files in one of the virtual drives:

   | Folder | Drive |
   | --- | --- |
   | `drives/A` | A: (floppy disk) |
   | `drives/C` | C: (hard disk) |
   | `drives/D` | D: (CD-ROM, read-only for the programs) |

2. Start the fake desktop and run your programs from the Start menu:

   ```bash
   python3 winexe32emu.py
   ```

   Or run a program directly:

   ```bash
   python3 winexe32emu.py myprogram.exe
   ```

Useful options:

| Option | What it does |
| --- | --- |
| `-h` | Shows all the options |
| `--no-gui` | Runs a console program without the fake desktop |
| `--codepage cp1254` | Uses another ANSI code page (e.g. Turkish) |
| `--missing-apis [FILE]` | Collects the APIs a program needs but the emulator lacks |
| `--clean` | Deletes the virtual drives (asks first) |

## Running the Tests

```bash
# Lint and unit tests (no MinGW-w64 needed)
pip install ruff
ruff check .
SDL_VIDEODRIVER=dummy python3 -m unittest discover -s tests/python -v

# Emulator tests: compiles the C programs in tests/ and runs each one
python3 winexe32emu.py --tests
```

A single test program can be run on its own, e.g. `python3 winexe32emu.py --no-gui api_test.exe`. GitHub Actions runs all of these on every push.

## Not Supported (Currently)

- 64-bit (x64) programs, and 16-bit DOS and Windows 3.x programs
- .NET programs
- DirectX, OpenGL and other hardware graphics
- A real network
- OLE and DDE between two running programs (embedding a Word document in Binder, opening a template from the Office Shortcut Bar)
- Drivers, services and other system components
- APIs the emulator does not emulate yet (see `--missing-apis`)

## Versioning

| Change | Version examples |
| --- | --- |
| Minor | 0.0.16, 0.0.17… |
| Major | 0.0.5, 0.0.10, 0.0.15… |
| Bigger | 0.1.0, 0.2.0… |
| Stable release | 1.0.0, 2.0.0… |

## Contributing

Contributions are welcome: see [CONTRIBUTING.md](CONTRIBUTING.md). Contributions must be based only on legally obtained information, never on Windows source code. The changes of each version are in [CHANGELOG.md](CHANGELOG.md).

## Disclaimer

This project is not endorsed by, affiliated with, or sponsored by Microsoft Corporation in any way. Windows, Win32, and related trademarks are the property of Microsoft Corporation. This is an independent, educational emulation project.

## Copyright and License

Copyright 2025-2026 Erdem Ersoy (eersoy93)

Licensed under the [Apache License, Version 2.0](LICENSE). The software is distributed on an "AS IS" basis, without warranties or conditions of any kind.
