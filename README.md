# winexe32emu.py

32-bit Windows EXE emulator in Python.

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Put EXE files in the c_drive/ folder
python winexe32emu.py hello_messagebox.exe

# With maximum instruction count
python winexe32emu.py hello_messagebox.exe 10000

# Set memory amount (MiB)
python winexe32emu.py hello_console.exe -m 256

# Run without GUI
python winexe32emu.py hello_console.exe --no-gui

# Also works with full path
python winexe32emu.py /path/to/file.exe
```

## Folder Structure

- `c_drive/` - Put your EXE files here (default search path)
- `examples/` - Example C source codes
- `compile-examples.sh` - Script to compile examples

## Features

- PE file loading and analysis
- x86 CPU emulation (Unicorn)
- Fake Windows desktop with Pygame
- Basic Win32 API support (user32, kernel32, gdi32)
- Console and GUI application support
