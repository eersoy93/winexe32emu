# Changelog

The notable changes of winexe32emu, newest first. The version numbers follow the scheme in [README.md](README.md#versioning).

## Unreleased

### Added

- Microsoft Office 95 Setup runs to the end: dialog frames, owner-drawn controls, the progress bar, Jet, the Change Folder dialog
- Word 95 starts, opens and edits documents: font APIs, compound files (OLE storage), its dialogs and menus
- Excel 95 starts, takes cell entries and formulas, selects cells, saves and opens workbooks:
  - Drawing is clipped to the DC's clip region (`SelectClipRgn`, `IntersectClipRect`...), which is kept in device coordinates
  - Update rectangles: `InvalidateRect` with a rectangle repaints only that part (`GetUpdateRgn`, `GetUpdateRect`, `rcPaint`); a hidden, moved or destroyed child window invalidates what it covered; `UpdateWindow` sends `WM_PAINT` at once
  - Private DCs of `CS_OWNDC` window classes
  - Raster operations into memory bitmaps (`SRCAND`, `SRCPAINT`, `DSTINVERT`...) are done on the pixels
  - `WM_ACTIVATEAPP`, and `WM_SETFOCUS` / `WM_KILLFOCUS` for the activated top-level window
  - The caret: `CreateCaret`, `SetCaretPos`, `ShowCaret`, `HideCaret`, `DestroyCaret`, drawn blinking
  - Child windows are drawn in their Z order (the first one on top), which `SetWindowPos` changes
  - Scan codes in the key messages; `FixBrushOrgEx`, `CreateDIBPatternBrush(Pt)`, `GetDeviceCaps(RASTERCAPS)`
- PowerPoint 95 starts, makes slides with text, switches between its views, saves and opens presentations
- Schedule+ 7.0 starts without a network, keeps appointments, tasks and contacts in its schedule file
- Office Binder 95 starts, makes binders from templates, adds sections from files, saves and opens binders (sections cannot be edited in place: no OLE between processes)
- The Office Shortcut Bar docks on the desktop, shows its buttons and tooltips and starts programs; Find Fast and the Fast Start preloader run
- Access 95 starts, creates a blank database and shows the database window (a workgroup file written by an older Setup run has to be made again with `WRKGADM.EXE`)
- Bookshelf 95 starts and asks for its own CD (the Office 95 CD does not hold its content)
- For these programs:
  - MDI windows (`MDICLIENT`, `DefFrameProc`, `DefMDIChildProc`), tab controls and tooltip controls
  - Application desktop toolbars (`SHAppBarMessage`): docked bars shrink the work area of maximized windows
  - Shortcut (`.lnk`) files: icons through shell32's class factory, `ShellExecute` follows them to their target
  - Byte-range file locks (`LockFile`, `UnlockFile` and the `Ex` versions) that really exclude each other
  - Thread messages have a target thread (`PostThreadMessage`, `PostMessage(NULL)`); messages of destroyed windows are dropped
  - RLE4 and RLE8 bitmaps, pattern brushes, pen styles (dashed and dotted lines), `TA_UPDATECP`, `GetPixel` sees drawn text
  - DIB sections get what GDI drew into them (`GdiFlush`), bitmap menu items (`MF_BITMAP`), list box tab stops
  - winmm: multimedia file I/O (`mmioOpen`, `mmioInstallIOProc`...), `mciSendString`
  - `ILockBytes` and compound files on them, more oleaut32 (variants, safe arrays, type libraries, the running object table)
  - `FindResourceW`, `FindResourceEx`, `GetFileTitle`, `PrintDlg` and `PageSetupDlg` (no printer), `TabbedTextOut`, `PropertySheet`, the ToolHelp process and module lists
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

- `AppendMenuA` with `MF_BITMAP` or `MF_OWNERDRAW` no longer reads the item data as a string (Excel 95 stopped at startup)
- `EnableWindow` returns whether the window was disabled before
- The desktop window's handle is no longer given to a program's window (the fifth window a program made got it)
- Child and pop-up windows get their first `WM_SIZE` right after `WM_CREATE`, not from `ShowWindow`
- Threads start with the Win32 floating-point control word instead of every exception unmasked
- Subclassed edit controls get their keys through the message queue; `WM_CLOSE` destroys a control
- A dialog's owner is activated when the dialog closes, and owned windows stay above their owner
- Overlapping child windows without `WS_CLIPSIBLINGS` paint in the Windows order
- The caption's close button works in MFC dialogs; `GetMessagePos` and `GetMessageTime` are right in modal dialogs
- `GetDeviceCaps` gives the aspect values (a division by zero in Binder)
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
