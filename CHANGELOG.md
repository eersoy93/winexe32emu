# Changelog

The notable changes of winexe32emu, newest first. The version numbers follow the scheme in [README.md](README.md#versioning).

Every change must be made with clean room techniques: it is based only on public documentation and the behavior observed from running programs, never on Windows source code or disassembled code (see [CONTRIBUTING.md](CONTRIBUTING.md)).

## 0.4.1 - 2026-11-26

### Added

- DOSBox 0.74-3: the NSIS setup and DOSBox run; the DOS prompt, `mount`, `keyb` and the keymapper (Ctrl+F1) work, and the close button ends it
- Rich edit controls (`RichEdit20A` and others) as plain text edit controls, with RTF text streamed in
- The CRT's file descriptor I/O (`_read`, `_write`, `_lseek`, `_fstat`, `_stat`, `_fdopen`, `_chsize`) and `freopen`
- `MapVirtualKeyEx`, the gamma ramp, palette and DIB color table APIs, and "no device" answers of the joystick and MIDI APIs

### Fixed

- Keys of non-US host keyboards (e.g. ş, ğ, ü, ö, ç of Turkish Q) and the punctuation, Insert, lock and keypad keys reach programs as key messages
- Edit controls draw tabs as gaps up to the tab stops
- A WM_QUIT the program took from its queue no longer stays: SDL 1.2 programs went on to quit
- Played wave buffers come back while a thread waits, so SDL 1.2 programs no longer hang when they quit

## 0.4.0 - 2026-11-26

### Added

- Microsoft Office 95 Professional:
  - Setup runs to the end
  - Word 95 opens, edits and saves documents
  - Excel 95 takes cell entries and formulas, saves and opens workbooks
  - PowerPoint 95 makes slides with text, saves and opens presentations
  - Access 95 creates databases, tables and queries (form design and the wizards do not work yet)
  - Schedule+ 7.0 keeps appointments, tasks and contacts
  - Office Binder 95 makes, saves and opens binders (sections cannot be edited inside Binder yet)
  - The Office Shortcut Bar docks on the desktop and starts programs; Find Fast runs
  - Bookshelf 95 starts and asks for its own CD
- Desktop icons for the user's folder, Network and the Recycle Bin
- Recycle Bin: deleted files can be restored or deleted for good
- Explorer: delete to the Recycle Bin, a Recycle Bin view, a Network view, opening documents with their program
- Command Prompt (`cmd.exe`) with the common commands, redirection and simple batch files
- Notepad (`notepad.exe`) with many text encodings, Find/Replace and word wrap
- Start menu: a Run... dialog (also Win+R) and a Documents submenu of recently opened files
- Documents open with their associated program
- What 7-Zip File Manager needs to browse and manage files
- Many more emulated Windows APIs and controls
- `--missing-apis` works without a file name
- `CHANGELOG.md`, `CONTRIBUTING.md`, `pyproject.toml`, more unit tests and faster CI

### Changed

- The fake desktop draws faster, and some images load about 10 times faster
- Office 95's type libraries are read by a newly written reader
- The fake desktop's code is split into smaller modules
- Stricter lint checks
- README.md is restructured

### Fixed

- Many bugs in windows, dialogs, menus, list boxes and edit controls
- Wrong values and crashes in Access, Excel and Binder
- Programs made with Delphi and Borland tools load and handle errors correctly
- File, registry and text API bugs
- A busy thread no longer stops the other threads
- Threads free their memory when they end

## 0.3.0 - 2026-11-18

### Added

- The drives A: (floppy disk) and D: (CD-ROM, read-only) next to C:
- Explorer (`explorer.exe`) with a folder tree, file operations and a My Computer drive list
- TreeView control; My Computer as a virtual shell folder
- The shell's context menu of files; list view grid lines and column resizing
- The Desktop folder's shortcuts on the fake desktop
- The 7-Zip 9.20 and 4.65 NSIS setups run end to end

### Changed

- `c_drive/` became `drives/C` (moved automatically at the first start)
- The desktop has the classic Windows 2000 look
- The single `winexe32emu.py` is split into the `src/` package
- Small `malloc`/`free` calls run as guest code; the API call path is faster

### Fixed

- A program's message boxes are closed when it exits
- `WM_SETCURSOR` goes to the child window under the mouse
- The msvcrt variables older MinGW-w64 versions import

## 0.2.0 and older

The versions 0.0.1, 0.0.5, 0.0.10, 0.0.15, 0.0.20, 0.1.0, 0.1.5 and 0.2.0 were made before this changelog was kept; their changes are not recorded here. A screenshot of each one is in [doc/](doc/).
