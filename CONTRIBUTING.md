# Contributing to winexe32emu

Thank you for your interest! Bug reports, missing API reports, fixes and new emulated APIs are all welcome.

## Legal Sources Only

winexe32emu is an independent reimplementation. **Every contribution must be based only on legally obtained information.**

Allowed sources:

- Public documentation: Microsoft Learn (MSDN), published specifications and file format documents, books and articles
- The public Windows API headers and import libraries of MinGW-w64
- The behavior you observe yourself when running your own test programs on a legally licensed Windows
- The behavior of the programs you test in the emulator (which APIs they call and what they expect)

Not allowed:

- **Windows source code of any kind**: leaked, stolen or "shared source" code, whatever its age or version
- Code or knowledge obtained by decompiling or disassembling Microsoft's binaries
- Confidential material, or anything you got under a non-disclosure agreement or a license that forbids this use
- Code copied from other projects whose license is not compatible with the Apache License 2.0

If you have ever seen Windows source code, please do not contribute to the parts of the emulator that reimplement what you saw.

Do not add copyrighted files to the repository either: no Windows DLLs, no program EXEs or setups, no CD images, no fonts or sounds taken from Windows. Test with your own legally obtained copies and keep them in `drives/` (it is ignored by Git).

By sending a contribution you confirm that it is your own work, that it follows these rules, and that it is licensed under the [Apache License, Version 2.0](LICENSE).

## Reporting Problems

Open an issue and include:

- The program and its version (please do not attach the program itself)
- The command you ran and what happened
- The missing APIs summary shown at the end of the run, or the file made with `--missing-apis`

## Sending Changes

1. Fork the repository and create a branch for your change.
2. Set up the project as described in [README.md](README.md#getting-started).
   The 32-bit MinGW-w64 compiler builds the built-in apps and the C test programs:

   | System | Command |
   | --- | --- |
   | Debian / Ubuntu | `sudo apt install gcc-mingw-w64-i686` |
   | Fedora | `sudo dnf install mingw32-gcc` |
   | Arch Linux | `sudo pacman -S mingw-w64-gcc` |
   | macOS (Homebrew) | `brew install mingw-w64` |

3. Make your change. Keep it focused: one topic per pull request.
4. Add or extend a test where it is possible: a unit test in `tests/python/`, or a check in one of the C test programs in `tests/`.
5. Run the checks (`pip install ruff` first; the unit tests need no MinGW-w64):

   ```bash
   ruff check .
   SDL_VIDEODRIVER=dummy python3 -m unittest discover -s tests/python -v
   python3 winexe32emu.py --tests
   ```

6. Add a line to the "Unreleased" section of [CHANGELOG.md](CHANGELOG.md).
7. Open a pull request that says what the change does, which program needed it, and where the information came from (e.g. a link to the documentation).

## Code Style

- Python 3.11 or newer; lines of at most 100 columns; `ruff check .` must pass
- Every new file starts with the Apache License header of the existing files
- Comments and messages are in English and explain why, not what
- An emulated API behaves like the Windows API, including its error codes
