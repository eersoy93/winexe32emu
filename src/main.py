# Copyright 2025-2026 Erdem Ersoy (eersoy93)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Command line entry point"""

import sys
import os
import codecs
import threading
import subprocess
import time

from colorama import Fore, Style

from . import config
from .config import PYGAME_AVAILABLE, SCRIPT_DIR, WINEXE32EMU_VERSION
from .cpu import CPUEmulator
from .gui import PseudoWindowsGUI
from .logger import DebugLogger, log, LogFileTee
from .paths import (COMPILE_APPS_SCRIPT, CREATE_DRIVES_SCRIPT, create_drive_folders,
                    create_environment_folders, find_program, REMOVE_DRIVES_SCRIPT,
                    run_setup_script, RUN_TESTS_SCRIPT)
from .pe_loader import PELoader
from .sound import SoundPlayer
from .winapi import WinAPIHandler


def main():
    """Main function"""
    import argparse
    parser = argparse.ArgumentParser(
        description="Windows 32-bit EXE Emulator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="The drives A: (floppy disk), C: and D: (CD-ROM) are the folders drives/A, "
               "drives/C and drives/D.\n"
               "EXE files are searched in drives/C (C:\\) and then in drives/C/Windows/Tests/ "
               "(C:\\Windows\\Tests).\nExample: python3 winexe32emu.py api_test.exe\n"
               "Example: python3 winexe32emu.py --no-gui \"C:\\Program Files\\7-Zip\\7z.exe\" "
               "l \"C:\\Windows\\Temp\\test.7z\""
    )
    parser.add_argument("exe", nargs="?",
                        help="PE file to run: a name in C:\\ or C:\\Windows\\Tests, or a "
                             "Windows path on a drive (drives/); optional with the GUI, "
                             "programs can also be started from the Start menu")
    parser.add_argument("program_args", nargs=argparse.REMAINDER, metavar="args",
                        help="Command-line arguments passed to the program "
                             "(everything after the EXE name)")
    parser.add_argument("-n", "--max-instructions", type=int, default=0,
                        help="Maximum instructions to execute "
                             "(default: 0 = unlimited)")
    parser.add_argument("-m", "--memory", type=int, default=128,
                        help="Heap memory amount in MiB (default: 128)")
    parser.add_argument("--no-gui", action="store_true",
                        help="Run without GUI")
    parser.add_argument("--codepage", default="cp1252",
                        help="ANSI code page for 'A' APIs and CRT strings "
                             "(default: cp1252 like an English Windows; e.g. cp1254, "
                             "or utf-8 for UTF-8 narrow strings)")
    parser.add_argument("--clean", action="store_true",
                        help="Only delete drives/, every drive "
                             "(scripts/remove_drives_environment.sh --all, asks for "
                             "confirmation) and exit")
    parser.add_argument("--no-apps", action="store_true",
                        help="Don't compile the apps in apps/ (compile_apps.sh) into "
                             "C:\\Windows, like Explorer (explorer.exe)")
    parser.add_argument("--tests", action="store_true",
                        help="Only compile the test programs into C:\\Windows\\Tests, run "
                             "each one without the GUI (scripts/run_tests.sh) and exit "
                             "(exit code: number of failed tests)")
    parser.add_argument("--no-create-environment", "--no_create_environment",
                        action="store_true",
                        help="Don't run create_drives_environment.sh at startup")
    parser.add_argument("--missing-apis", metavar="FILE",
                        help="Append the APIs the programs needed but the emulator "
                             "does not emulate to FILE (one line per API and program; "
                             "a summary is always shown at the end)")
    parser.add_argument("--logfile", metavar="FILE",
                        help="Also write the console output to FILE (without colors)")
    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument("-v", "--verbose", action="store_true",
                           help="Show debug output (every API call, disassembly)")
    verbosity.add_argument("-q", "--quiet", action="store_true",
                           help="Show only program output, warnings and errors")

    args = parser.parse_args()

    if args.logfile:
        try:
            logfile = open(args.logfile, 'w', encoding='utf-8', errors='replace',
                           buffering=1)
        except OSError as e:
            log.error(f"Cannot open log file {args.logfile}: {e}")
            sys.exit(1)
        lock = threading.Lock()
        sys.stdout = LogFileTee(sys.stdout, logfile, lock)
        sys.stderr = LogFileTee(sys.stderr, logfile, lock)

    print(f"{Fore.CYAN}{Style.BRIGHT}╔══════════════════════════════════════════════════════════╗")
    print(f"{Fore.CYAN}{Style.BRIGHT}║                                                          ║")
    print(f"{Fore.CYAN}{Style.BRIGHT}║{f'Windows 32-bit EXE Emulator v{WINEXE32EMU_VERSION}':^58}║")
    print(f"{Fore.CYAN}{Style.BRIGHT}║                                                          ║")
    print(f"{Fore.CYAN}{Style.BRIGHT}╚══════════════════════════════════════════════════════════╝")
    print(f"{Style.RESET_ALL}")

    if args.verbose:
        DebugLogger.level = DebugLogger.DEBUG
    elif args.quiet:
        DebugLogger.level = DebugLogger.WARNING

    try:
        config.ANSI_CODEPAGE = codecs.lookup(args.codepage).name
    except LookupError:
        log.error(f"Unknown code page: {args.codepage}")
        sys.exit(1)

    if args.clean:
        # Interactive: the script asks before deleting everything in drives/
        try:
            result = subprocess.run(['sh', REMOVE_DRIVES_SCRIPT, '--all'], cwd=SCRIPT_DIR)
        except OSError as e:
            log.error(f"Cannot run {REMOVE_DRIVES_SCRIPT}: {e}")
            sys.exit(1)
        sys.exit(result.returncode)

    # drives/A, drives/C, drives/D (c_drive/ of older versions becomes drives/C)
    create_drive_folders()

    if args.tests:
        log.header("Compiling and Running Tests")
        try:
            result = subprocess.run(['sh', RUN_TESTS_SCRIPT], cwd=SCRIPT_DIR,
                                    env=dict(os.environ, PYTHON=sys.executable))
        except OSError as e:
            log.error(f"Cannot run {RUN_TESTS_SCRIPT}: {e}")
            sys.exit(1)
        sys.exit(result.returncode)

    use_gui = not args.no_gui

    if not args.no_create_environment:
        run_setup_script(CREATE_DRIVES_SCRIPT, "Creating Drives Environment")
    if not args.no_apps:
        run_setup_script(COMPILE_APPS_SCRIPT, "Compiling Apps")
    create_environment_folders()
    WinAPIHandler.create_known_folders()

    if args.exe is None and not (use_gui and PYGAME_AVAILABLE):
        log.error("An EXE name is required when the GUI is not available")
        sys.exit(1)
    if args.exe is not None and find_program(args.exe) is None:
        log.error(f"File not found on the emulated drives: {args.exe}")
        sys.exit(1)

    max_instr = args.max_instructions
    heap_size_mib = args.memory
    # The heap must end below the callback/API stub/stack regions
    max_heap_mib = (CPUEmulator.CALLBACK_RETURN_ADDR - CPUEmulator.HEAP_BASE) // (1024 * 1024)
    if not 1 <= heap_size_mib <= max_heap_mib:
        log.error(f"Heap size must be between 1 and {max_heap_mib} MiB")
        sys.exit(1)

    if args.missing_apis:
        CPUEmulator.missing_apis_file = os.path.abspath(args.missing_apis)

    # Update heap size
    CPUEmulator.HEAP_SIZE = heap_size_mib * 1024 * 1024
    log.info(f"Heap size: {heap_size_mib} MiB ({CPUEmulator.HEAP_SIZE} bytes)")

    # Start GUI (optional)
    gui = None
    if use_gui and PYGAME_AVAILABLE:
        log.header("Starting Pygame GUI")
        gui = PseudoWindowsGUI(1024, 768)
        if gui.start():
            log.success("Pygame GUI window opened!")
        else:
            log.warning("Failed to start GUI, continuing without GUI...")
            gui = None
    elif use_gui and not PYGAME_AVAILABLE:
        log.warning("Pygame not installed, continuing without GUI...")

    # Started programs: [(CPUEmulator, emulation thread)]; they run side by side
    programs = []

    def load_program(name, command_line=None, current_directory=None, program_args=None):
        """Load an EXE from the emulated C drive and emulate it in a new thread.
        Returns the CPUEmulator, or None on failure."""
        exe_path = find_program(name)
        if exe_path is None:
            log.error(f"File not found in emulation C drive: {name}")
            return None
        log.info(f"Loading EXE from emulation C drive: {exe_path}")
        loader = PELoader(exe_path)
        if not loader.load():
            log.error("Failed to load PE file!")
            return None
        loader.print_summary()

        emulator = CPUEmulator(loader, gui)
        emulator.command_line = command_line
        emulator.program_args = program_args
        if not emulator.initialize():
            log.error("Failed to initialize CPU emulator!")
            return None
        if current_directory:
            emulator.api_handler.current_directory = current_directory
        emulator.disassemble(loader.image_base + loader.entry_point, 20)

        def run_emulation():
            try:
                emulator.run(max_instr)
            except Exception as e:
                log.error(f"Emulation error: {e}")
                emulator.crashed = True
            finally:
                # Sounds do not outlive their process
                SoundPlayer.stop_owned_by(emulator.api_handler)
                log.success("Emulation completed!")

        # Separate thread so the GUI stays responsive
        thread = threading.Thread(target=run_emulation, daemon=True)
        emulator.thread = thread
        programs.append((emulator, thread))
        thread.start()
        return emulator

    # CreateProcessA starts child programs the same way
    WinAPIHandler.process_starter = staticmethod(load_program)

    def launch(name, command_line=None, current_directory=None):
        """Start menu: run the EXE at Windows path name next to the running programs"""
        # Loading takes a while: keep it off the GUI thread
        threading.Thread(target=load_program, args=(name, command_line, current_directory),
                         daemon=True).start()

    if gui:
        gui.launcher = launch
        log.info("GUI window is open, close the window to exit!")

    if args.exe is not None and not load_program(args.exe,
                                                 program_args=args.program_args):
        if gui:
            gui.stop()
        sys.exit(1)
    
    def stop_programs():
        """Stop the running programs and wait for their emulation threads: the
        interpreter must not free a Unicorn instance that is still running"""
        for emulator, thread in list(programs):
            if thread.is_alive() and emulator.api_handler:
                emulator.api_handler.request_termination()
        for emulator, thread in list(programs):
            thread.join(timeout=3)
            for guest in list(emulator.threads.values()):
                if guest.python_thread is not None:
                    guest.python_thread.join(timeout=1)

    # Wait while GUI is open
    try:
        if gui:
            while gui.running:
                time.sleep(0.1)
            gui.stop()
            stop_programs()
        else:
            # If no GUI, wait for emulation to finish
            programs[0][1].join()
            stop_programs()
    except KeyboardInterrupt:
        log.warning("Stopped by user (Ctrl+C)!")
        if gui:
            gui.running = False
            gui.stop()
        stop_programs()
        sys.exit(130)

    # Exit code of the program named on the command line (Start menu ones don't count)
    if args.exe is None:
        return
    emulator, emu_thread = programs[0]

    # Propagate the guest's exit code (like a real process would)
    if emu_thread.is_alive():
        return
    if emulator.crashed:
        sys.exit(1)
    exit_code = emulator.api_handler.exit_code if emulator.api_handler else None
    if exit_code:
        sys.exit(exit_code & 0xFF)
