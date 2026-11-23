# Changelog

The notable changes of winexe32emu, newest first. The version numbers follow the scheme in [README.md](README.md#versioning).

## Unreleased

### Added

- Microsoft Office 95 Setup runs to the end: dialog frames, owner-drawn controls, the progress bar, Jet, the Change Folder dialog
- Word 95 starts, opens and edits documents: font APIs, compound files (OLE storage), its dialogs and menus
- The network and stream APIs 7-Zip File Manager needs; `\\server` paths are network paths
- More API groups: shlwapi, security, crypto, psapi, sockets (offline), themes
- Scroll bars for list boxes and the lists of combo boxes
- Page protections and DEP for NX-compatible programs; a reworked DLL loader; unique process ids
- A 32-bit Windows without WOW64; the known folders (`C:\Users`, `C:\ProgramData`...) are created at start
- `--missing-apis` works without a FILE (`missing_apis.txt`)
- `pyproject.toml`, more unit tests, and CI that caches its downloads
- `CHANGELOG.md` and `CONTRIBUTING.md`

### Changed

- The fake desktop keeps the texts it rendered instead of rendering them again every frame
- 16 and 32 bpp DIBs with color masks (`BI_BITFIELDS`, 16 bpp DIB sections) decode about 10 times faster
- More unit tests: wildcards, time conversions, INI files, the printf engine, `VerQueryValue`, share modes, the DIB decoder
- The fake desktop's code (`gui.py`) is a package of smaller modules
- Lint also checks the pycodestyle and bugbear rules (100 columns)
- Heap blocks shrink in place, like on Windows
- README.md is restructured

### Fixed

- Windows file name rules, path buffer sizes, the PEB, system DLL images and static TLS
- `GetDlgItem`, `GCL_WNDPROC`, `CharUpperA` on cp1252, the `=C:` environment variables
- The `lpIDList` read of `ShellExecuteEx`
- Several window bugs
- EXEs that import a DLL in several import descriptors (Delphi, Borland) get all their imports bound
- Exception handlers that unwind and continue in their frame without returning (Delphi) no longer use up the exception nesting limit
- Ended threads free their stack, TEB and GDT; freed aligned heap blocks are reused
- `scanf` with a float conversion before other conversions; `_strupr`/`_strlwr` keep the string's length ("C" locale)
- `VerQueryValue` no longer hangs on a malformed version block
- `RegGetValue` with `RRF_ZEROONFAILURE` zeroes only the caller's buffer
- Owner-draw list boxes and combo boxes without `*S_HASSTRINGS`; `LB_GETITEMDATA`, `LB_SETITEMDATA`, `LB_FINDSTRING(EXACT)`
- `GetObject` of a DIB section: its own format and bits, and `DIBSECTION`
- A failing registry API or COM method no longer reports success
- `SetWindowsHookEx(WH_CBT)` hooks are called (`HCBT_CREATEWND`, `HCBT_DESTROYWND`, `CallNextHookEx`), and a subclassed dialog's messages go through its new window procedure to `DefDlgProc`, as MFC needs
- ANSI text in subclassed controls (`CallWindowProcA`); messages posted to a dialog's control reach the control
- Posted and input messages come before `WM_PAINT`; Enter, Backspace, Tab, Esc and Ctrl+letter give `WM_CHAR`, in the ANSI code page for `GetMessageA`
- `ShowWindow`: minimizing and showing without activation, the previous visibility; `IsWindowVisible` of a minimized window
- `CreateFile`: `ERROR_ALREADY_EXISTS`, share modes (`ERROR_SHARING_VIOLATION`), `ERROR_PATH_NOT_FOUND`; `ReadFile` reads the console input and fails for invalid handles
- A thread that spins without API calls no longer keeps the other threads from running
- `CreateHardLink` cannot link files of the read-only D: or across drives (`ERROR_NOT_SAME_DEVICE`)
- Opening a file without read, write or delete access takes no part in the share modes

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
