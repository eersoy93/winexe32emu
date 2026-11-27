# Changelog

The notable changes of winexe32emu, newest first. The version numbers follow the scheme in [README.md](README.md#versioning).

Every change must be made with clean room techniques: it is based only on public documentation and the behavior observed from running programs, never on Windows source code or disassembled code (see [CONTRIBUTING.md](CONTRIBUTING.md)).

## Unreleased

### Fixed

- A click on a subclassed list box in a dialog goes to the program's procedure too: Red Alert 2's movie list (Movies & Credits > Play Movies) selected nothing, so Play Movie did not play

## 0.5.0 - 2026-11-27

### Added

- Command & Conquer: Red Alert 2: the CD's Setup (`Setup.exe`) runs to the end, its Autorun menu (`AUTORUN.EXE`) works and the 1.006 patch (`RA21006EN.EXE`) updates the installed game
- DirectDraw in software (`DirectDrawCreate`, surfaces, palettes, clippers, color keys, flipping, full-screen display modes); the primary surface is shown in the program's window
- DirectSound through the mixer (`DirectSoundCreate`, static and streaming sound buffers)
- Volume labels of the drives: the first line of `drives/D.label` is the label of D: (setup programs recognize their CD by it); `SetVolumeLabel` is kept there
- Placeholder files with a version resource for the emulated system DLLs in `C:\Windows\System32` (setup programs look for them and read their version)
- `PlaySound` plays `WAVE` resources; `timeGetDevCaps` and the IMM queries of a PC without an input method editor
- Command & Conquer: Red Alert 2: the installed game (`Ra2.exe`, which starts `GAME.EXE`) plays its intro videos and shows its main, single player and campaign menus
- `EnumProtocols` lists the installed network transports (TCP/IP and UDP/IP)
- The trackbar control (`msctls_trackbar32`) keeps its range, position and step sizes (`TBM_*` messages); it is not drawn or moved with the mouse yet

### Fixed

- File mappings are the mapped file itself: what a program writes to a writable view is in the file, a mapping larger than its file makes the file grow, and files up to 1 GB can be mapped (they were copied, and limited to 256 MB)
- A mapping is taken out of the address space when its handle is closed and its views are unmapped; two mappings can no longer be mistaken for each other
- A repaint between `BeginPaint` and `EndPaint` appears on the screen when it is complete: windows that repaint themselves often no longer flicker
- `StretchBlt` on a window draws nothing outside the update region of a partial `WM_PAINT`
- An `InvalidateRect` made while the background is erased no longer repaints the window forever
- A program's dialog gets the mouse messages of its client area (dialogs that paint their own buttons)
- A subclassed control gets `WM_PAINT` in the program's window procedure: a control the program paints itself is no longer drawn over by the emulator, and an owner-draw control that is invalidated while it is drawn no longer repaints forever
- What an exclusive full-screen DirectDraw program writes on the primary surface covers its child windows too (menus made of dialogs whose controls the program paints)
- `CoRegisterClassObject` holds a reference to the class object until `CoRevokeClassObject`: a program's own class factory is no longer destroyed by the first `CoCreateInstance`
- `WriteFile` on a handle opened without write access fails with `ERROR_ACCESS_DENIED` and no longer logs an error for every call
- `PeekMessage` with `PM_NOREMOVE` sees a due timer (`WM_TIMER`): the animations of Red Alert 2's main menu run (its message loop only fetches a message after peeking one); `GetQueueStatus` reports it as `QS_TIMER`
- A drop-down combo box's window is only its selection field (`GetWindowRect`, `GetClientRect`), and `CB_SETITEMHEIGHT`/`CB_GETITEMHEIGHT` set and tell the height of the field and the items (an owner-draw combo box asks its parent with `WM_MEASUREITEM`): the texts of Red Alert 2's skirmish settings are inside their boxes
- A click on a subclassed combo box goes to the program's window procedure first; the list opens only if it passes the click on (Red Alert 2 shows lists of its own)
- `UpdateWindow` paints a subclassed or owner-draw control at once, and hiding, moving or destroying a control repaints what was under it (also in a subclassed dialog): the frames Red Alert 2 draws around its controls and the area under its closed lists appear
- `DestroyWindow` of a subclassed control sends `WM_DESTROY` and `WM_NCDESTROY` to its window procedure: Red Alert 2's skirmish screen no longer freezes after a list closes
- DirectDraw copies a surface's pixels between the program and the emulator only when the other side needs them (`Lock` after a Blt or GDI drawing; Blt, GDI or the screen after `Unlock`), and shows the primary surface from one thread instead of a timer thread per picture: Red Alert 2 locks its surfaces hundreds of times a second
- The Interlocked APIs and `IDirectDrawSurface::IsLost` run as guest code, without a call into the emulator
- A guest thread gives its turn away only when another thread wants to run, and gets it back as soon as that one blocks again: Red Alert 2 runs about 17% faster in a skirmish game
- A click on a subclassed button or check box goes to the program's window procedure; the button procedure it passes the click on checks the box with `BM_SETCHECK` sent to it and notifies the parent: Red Alert 2's skirmish options (Short Game, Crates Appear...) can be changed
- `PostThreadMessage` reaches a thread of another emulated process, and `CreateProcess` with `bInheritHandles` gives the child the inheritable handles (`SECURITY_ATTRIBUTES.bInheritHandle`, `DuplicateHandle`, `SetHandleInformation`) with the same values: Red Alert 2's launcher hands `GAME.EXE` a shared memory block this way, and without it a skirmish ended in defeat after about half a minute
- A looping DirectSound buffer plays as a looping copy in the mixer that what the program writes (`Unlock`) goes into, like a sound card playing the ring: the music and sounds of Red Alert 2 no longer stutter while it computes a frame
- A looping DirectSound buffer played at a rate that does not divide the mixer's (Red Alert 2 varies the rate of its sound effects) is played as a ring too: the effects were cut
- A DirectSound buffer whose sound ended no longer stops or changes the volume of the sound that took its mixer channel next; the mixer has 32 channels instead of 8
- `CB_GETDROPPEDCONTROLRECT` gives the combo box's dropped-down rectangle, and a drop-down combo box sized with only its field's height keeps the height of its list: Red Alert 2's keyboard options froze when their category list was opened
- `ValidateRect` with a rectangle takes only that rectangle out of the update region (it validated the whole window): a closed drop-down list no longer stays on the screen
- A parent window without `WS_CLIPCHILDREN` paints again where a child window was shown: the drop-down lists of Red Alert 2's combo boxes have their frame
- A window's timer keeps the id the program gives it, 0 too, so `KillTimer` with that id stops it; a destroyed window's timers are gone, like on Windows, and a `SetTimer` period is rounded up to the system clock tick (15.625 ms): the animations of Red Alert 2's menus ran too fast

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
