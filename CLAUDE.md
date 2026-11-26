# CLAUDE.md

Guidance for Claude Code when working in this repository. Follow the rules in [CONTRIBUTING.md](CONTRIBUTING.md); they are summarized here, and when the two differ, CONTRIBUTING.md wins.

## Legal sources only

winexe32emu is an independent, clean room reimplementation. Base every change only on legally obtained information.

Allowed:

- Public documentation: Microsoft Learn (MSDN), published specifications and file format documents, books and articles
- The public Windows API headers and import libraries of MinGW-w64
- The behavior of test programs run on a legally licensed Windows
- The behavior of the programs tested in the emulator (which APIs they call and what they expect)

Not allowed:

- Windows source code of any kind (leaked, stolen or "shared source")
- Code or knowledge from decompiling or disassembling Microsoft's binaries
- Confidential or NDA material
- Code copied from projects whose license is not compatible with the Apache License 2.0

Tell every subagent these rules in its prompt.

Never add copyrighted files to the repository: no Windows DLLs, program EXEs or setups, CD images, or fonts and sounds taken from Windows. Test copies stay in `drives/`, which Git ignores.

## Making a change

- Keep each change focused on one topic.
- Add or extend a test where possible: a unit test in `tests/python/`, or a check in one of the C test programs in `tests/`.
- Run the checks before finishing (the C tests need the 32-bit MinGW-w64 compiler):

  ```bash
  ruff check .
  SDL_VIDEODRIVER=dummy python3 -m unittest discover -s tests/python -v
  python3 winexe32emu.py --tests
  ```

- Add a line to the "Unreleased" section of [CHANGELOG.md](CHANGELOG.md). If that section is missing, add it above the newest version.
- A pull request says what the change does, which program needed it, and where the information came from.

## Code style

- Python 3.11 or newer; lines of at most 100 columns; `ruff check .` must pass
- Every new file starts with the Apache License header of the existing files
- Comments and messages are in English and explain why, not what
- An emulated API behaves like the Windows API, including its error codes
