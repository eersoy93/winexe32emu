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

"""WinAPIHandler mixin: psapi process and module information, visual
styles (uxtheme) and the desktop window manager (dwmapi): both off, version
language names"""

import ntpath
import struct


class SystemExtraMixin:
    """psapi, uxtheme, dwmapi and version.dll extras"""

    # ---------- psapi (also kernel32's K32* exports) ----------

    def _is_this_process(self, handle):
        if handle == 0xFFFFFFFF:
            return True
        info = self.handles.get(handle)
        return bool(info and info.get('type') == 'process' and info.get('current'))

    def _process_modules(self):
        """(base, size, Windows path) of the EXE and its loaded DLL files"""
        pe = self.emu.pe_loader.pe
        size = pe.OPTIONAL_HEADER.SizeOfImage if pe is not None else 0
        modules = [(self.emu.pe_loader.image_base, size, self.windows_exe_path())]
        for base, module in sorted(self.emu.dlls.items()):
            modules.append((base, module['size'], module['path']))
        for module in sorted(self.emu.system_modules.values(), key=lambda m: m['base']):
            modules.append((module['base'], module['size'], module['path']))
        return modules

    def _module_path(self, handle):
        """Windows path of a module handle (also the emulated DLLs' handles)"""
        if not handle or handle == self.emu.pe_loader.image_base:
            return self.windows_exe_path()
        module = self.emu.find_dll(handle)
        if module is not None:
            return module['path']
        for name, fake in self.module_handles.items():
            if fake == handle:
                return 'C:\\Windows\\System32\\' + name
        name = self._system_module_name(handle)
        return 'C:\\Windows\\System32\\' + name if name else None

    def EnumProcesses(self, args):
        """EnumProcesses(IDs, size, &needed) - this process"""
        if args[1] >= 4:
            self._mem_write(args[0], struct.pack('<I', self.GetCurrentProcessId([])))
        self._mem_write(args[2], struct.pack('<I', 4 if args[1] >= 4 else 0))
        return 1

    def EnumProcessModules(self, args):
        """EnumProcessModules(process, modules, size, &needed)"""
        if not self._is_this_process(args[0]):
            self._last_error = 5  # ERROR_ACCESS_DENIED
            return 0
        bases = [base for base, _, _ in self._process_modules()]
        count = min(len(bases), args[2] // 4)
        if count and args[1]:
            self._mem_write(args[1], struct.pack(f'<{count}I', *bases[:count]))
        self._mem_write(args[3], struct.pack('<I', 4 * len(bases)))
        return 1

    def EnumProcessModulesEx(self, args):
        return self.EnumProcessModules(args[:4])

    def GetModuleBaseNameA(self, args, wide=False):
        """GetModuleBaseNameA/W(process, module, buffer, size)"""
        path = self._module_path(args[1]) if self._is_this_process(args[0]) else None
        if path is None or not args[3]:
            self._last_error = 6  # ERROR_INVALID_HANDLE
            return 0
        units = self._text_units(ntpath.basename(path), wide)[:args[3] - 1]
        self._write_units(args[2], units, wide)
        return len(units)

    def GetModuleBaseNameW(self, args):
        return self.GetModuleBaseNameA(args, wide=True)

    def GetModuleFileNameExA(self, args, wide=False):
        """GetModuleFileNameExA/W(process, module, buffer, size)"""
        path = self._module_path(args[1]) if self._is_this_process(args[0]) else None
        if path is None or not args[3]:
            self._last_error = 6
            return 0
        units = self._text_units(path, wide)[:args[3] - 1]
        self._write_units(args[2], units, wide)
        return len(units)

    def GetModuleFileNameExW(self, args):
        return self.GetModuleFileNameExA(args, wide=True)

    def GetProcessImageFileNameA(self, args, wide=False):
        """GetProcessImageFileNameA/W(process, buffer, size) - the device path"""
        if not self._is_this_process(args[0]):
            self._last_error = 5
            return 0
        path = self.windows_exe_path()
        device = '\\Device\\HarddiskVolume1' + path[2:]
        units = self._text_units(device, wide)
        if len(units) >= args[2]:
            self._last_error = 122
            return 0
        self._write_units(args[1], units, wide)
        return len(units)

    def GetProcessImageFileNameW(self, args):
        return self.GetProcessImageFileNameA(args, wide=True)

    def QueryFullProcessImageNameA(self, args, wide=False):
        """QueryFullProcessImageNameA/W(process, flags, buffer, &size)"""
        if not self._is_this_process(args[0]):
            self._last_error = 5
            return 0
        path = self.windows_exe_path()
        if args[1] & 1:  # PROCESS_NAME_NATIVE
            path = '\\Device\\HarddiskVolume1' + path[2:]
        units = self._text_units(path, wide)
        if len(units) >= self._read_u32(args[3]):
            self._last_error = 122
            return 0
        self._write_units(args[2], units, wide)
        self._mem_write(args[3], struct.pack('<I', len(units)))
        return 1

    def QueryFullProcessImageNameW(self, args):
        return self.QueryFullProcessImageNameA(args, wide=True)

    def GetModuleInformation(self, args):
        """GetModuleInformation(process, module, MODULEINFO, size)"""
        if args[3] < 12 or not self._is_this_process(args[0]):
            self._last_error = 87
            return 0
        for base, size, _ in self._process_modules():
            if base == (args[1] or self.emu.pe_loader.image_base):
                if base == self.emu.pe_loader.image_base:
                    pe = self.emu.pe_loader.pe
                else:
                    pe = self.emu.dlls[base]['pe']
                entry = base + pe.OPTIONAL_HEADER.AddressOfEntryPoint if pe is not None else 0
                return 1 if self._mem_write(args[2], struct.pack('<III', base, size,
                                                                  entry)) else 0
        self._last_error = 6
        return 0

    def GetProcessMemoryInfo(self, args):
        """GetProcessMemoryInfo(process, PROCESS_MEMORY_COUNTERS(_EX), size)"""
        if args[2] < 40:
            self._last_error = 24  # ERROR_BAD_LENGTH
            return 0
        total, available = self._memory_status()
        used = max(0, total - available)
        values = [40 if args[2] < 44 else 44, 0, used, used, 0, 0, 0, 0, used, used]
        if args[2] >= 44:
            values.append(used)  # PrivateUsage
        return 1 if self._mem_write(args[1], struct.pack(f'<{len(values)}I', *values)) else 0

    def GetPerformanceInfo(self, args):
        """GetPerformanceInfo(PERFORMANCE_INFORMATION, size) - counts of 4 KiB pages"""
        if args[1] < 56:
            self._last_error = 24
            return 0
        total, available = self._memory_status()
        pages, free = total // 0x1000, available // 0x1000
        data = struct.pack('<14I', 56, pages - free, pages, pages, pages, free, 0, 0x1000,
                           0, 0, 0, 0x1000, 1, 1)
        return 1 if self._mem_write(args[0], data) else 0

    def EmptyWorkingSet(self, args):
        return 1

    def GetMappedFileNameA(self, args):
        self._last_error = 87
        return 0

    GetMappedFileNameW = GetMappedFileNameA

    # kernel32 exports of the psapi functions (PSAPI_VERSION 2)
    K32EnumProcesses = EnumProcesses
    K32EnumProcessModules = EnumProcessModules
    K32EnumProcessModulesEx = EnumProcessModulesEx
    K32GetModuleBaseNameA = GetModuleBaseNameA
    K32GetModuleBaseNameW = GetModuleBaseNameW
    K32GetModuleFileNameExA = GetModuleFileNameExA
    K32GetModuleFileNameExW = GetModuleFileNameExW
    K32GetProcessImageFileNameA = GetProcessImageFileNameA
    K32GetProcessImageFileNameW = GetProcessImageFileNameW
    K32GetModuleInformation = GetModuleInformation
    K32GetProcessMemoryInfo = GetProcessMemoryInfo
    K32GetPerformanceInfo = GetPerformanceInfo
    K32EmptyWorkingSet = EmptyWorkingSet

    # ---------- uxtheme: visual styles are off ----------

    E_HANDLE = 0x80070006

    def IsThemeActive(self, args):
        return 0

    def IsAppThemed(self, args):
        return 0

    def IsCompositionActive(self, args):
        return 0

    def OpenThemeData(self, args):
        """OpenThemeData - NULL: draw the classic look"""
        return 0

    def OpenThemeDataEx(self, args):
        return 0

    def OpenThemeDataForDpi(self, args):
        return 0

    def CloseThemeData(self, args):
        return 0

    def SetWindowTheme(self, args):
        return 0

    def EnableThemeDialogTexture(self, args):
        return 0

    def IsThemeDialogTextureEnabled(self, args):
        return 0

    def GetThemeAppProperties(self, args):
        return 0

    def SetThemeAppProperties(self, args):
        return 0

    def IsThemePartDefined(self, args):
        return 0

    def IsThemeBackgroundPartiallyTransparent(self, args):
        return 0

    def DrawThemeParentBackground(self, args):
        return 0

    def GetWindowTheme(self, args):
        return 0

    def _no_theme(self, args):
        """Drawing and metrics with a theme handle: there are no themes"""
        return self.E_HANDLE

    DrawThemeBackground = DrawThemeBackgroundEx = DrawThemeText = DrawThemeEdge = _no_theme
    DrawThemeIcon = GetThemeColor = GetThemePartSize = GetThemeBackgroundContentRect = _no_theme
    GetThemeBackgroundExtent = GetThemeTextExtent = GetThemeFont = GetThemeInt = _no_theme
    GetThemeMargins = GetThemeMetric = GetThemeRect = GetThemeSysFont = _no_theme
    GetThemeTextMetrics = GetThemePosition = GetThemeBool = GetThemeEnumValue = _no_theme
    GetThemeSysColor = _no_theme

    def GetCurrentThemeName(self, args):
        return 0x80004005  # E_FAIL: no theme

    def BufferedPaintInit(self, args):
        return 0

    def BufferedPaintUnInit(self, args):
        return 0

    def BeginBufferedPaint(self, args):
        return 0

    def EndBufferedPaint(self, args):
        return self.E_HANDLE

    # ---------- dwmapi: desktop composition is off ----------

    DWM_E_COMPOSITIONDISABLED = 0x80263001

    def DwmIsCompositionEnabled(self, args):
        """DwmIsCompositionEnabled(&enabled) - FALSE"""
        return 0 if self._mem_write(args[0], struct.pack('<I', 0)) else 0x80070057

    def DwmEnableComposition(self, args):
        return 0

    def DwmExtendFrameIntoClientArea(self, args):
        return self.DWM_E_COMPOSITIONDISABLED

    def DwmEnableBlurBehindWindow(self, args):
        return self.DWM_E_COMPOSITIONDISABLED

    def DwmFlush(self, args):
        return self.DWM_E_COMPOSITIONDISABLED

    def DwmDefWindowProc(self, args):
        """DwmDefWindowProc(hwnd, msg, wParam, lParam, &result) - not handled"""
        return 0

    def DwmGetColorizationColor(self, args):
        """DwmGetColorizationColor(&color, &opaque blend)"""
        self._mem_write(args[0], struct.pack('<I', 0xFF6B8FBF))
        self._mem_write(args[1], struct.pack('<I', 1))
        return 0

    def DwmGetWindowAttribute(self, args):
        """DwmGetWindowAttribute(hwnd, attribute, value, size)"""
        if not self.IsWindow([args[0]]):
            return self.E_HANDLE
        if args[1] == 9:  # DWMWA_EXTENDED_FRAME_BOUNDS: the window rectangle
            if args[3] < 16:
                return 0x80070057
            return 0 if self.GetWindowRect([args[0], args[2]]) else self.E_HANDLE
        if args[1] in (1, 14):  # DWMWA_NCRENDERING_ENABLED, DWMWA_CLOAKED
            if args[3] < 4:
                return 0x80070057
            self._mem_write(args[2], struct.pack('<I', 0))
            return 0
        return 0x80070057  # E_INVALIDARG

    def DwmSetWindowAttribute(self, args):
        return 0 if self.IsWindow([args[0]]) else self.E_HANDLE

    # ---------- version.dll ----------

    LANGUAGE_NAMES = {
        0x0000: 'Language Neutral', 0x0007: 'German', 0x0009: 'English',
        0x0401: 'Arabic (Saudi Arabia)', 0x0402: 'Bulgarian', 0x0404: 'Chinese (Taiwan)',
        0x0405: 'Czech', 0x0406: 'Danish', 0x0407: 'German (Germany)', 0x0408: 'Greek',
        0x0409: 'English (United States)', 0x040A: 'Spanish (Traditional Sort)',
        0x040B: 'Finnish', 0x040C: 'French (France)', 0x040D: 'Hebrew',
        0x040E: 'Hungarian', 0x0410: 'Italian (Italy)', 0x0411: 'Japanese',
        0x0412: 'Korean', 0x0413: 'Dutch (Netherlands)', 0x0414: 'Norwegian (Bokmal)',
        0x0415: 'Polish', 0x0416: 'Portuguese (Brazil)', 0x0418: 'Romanian',
        0x0419: 'Russian', 0x041A: 'Croatian', 0x041B: 'Slovak', 0x041D: 'Swedish',
        0x041E: 'Thai', 0x041F: 'Turkish', 0x0422: 'Ukrainian', 0x0424: 'Slovenian',
        0x0425: 'Estonian', 0x0426: 'Latvian', 0x0427: 'Lithuanian',
        0x0804: 'Chinese (PRC)', 0x0809: 'English (United Kingdom)',
        0x0816: 'Portuguese (Portugal)', 0x0C0A: 'Spanish (Modern Sort)',
        0x0800: 'Process Default Language',
    }

    def VerLanguageNameA(self, args, wide=False):
        """VerLanguageNameA/W(language, buffer, size) - the name's length"""
        name = self.LANGUAGE_NAMES.get(args[0] & 0xFFFF, 'Language Neutral')
        units = self._text_units(name, wide)
        if args[1] and args[2]:
            self._write_units(args[1], units[:args[2] - 1], wide)
            return min(len(units), args[2] - 1)
        return len(units)

    def VerLanguageNameW(self, args):
        return self.VerLanguageNameA(args, wide=True)

    def GetFileVersionInfoSizeExA(self, args):
        """GetFileVersionInfoSizeExA/W(flags, file, &handle)"""
        return self.GetFileVersionInfoSizeA(args[1:3])

    def GetFileVersionInfoSizeExW(self, args):
        return self.GetFileVersionInfoSizeW(args[1:3])

    def GetFileVersionInfoExA(self, args):
        """GetFileVersionInfoExA/W(flags, file, handle, size, data)"""
        return self.GetFileVersionInfoA(args[1:5])

    def GetFileVersionInfoExW(self, args):
        return self.GetFileVersionInfoW(args[1:5])
