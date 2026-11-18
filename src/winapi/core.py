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

"""WinAPIHandler mixin: DLL lists, calling conventions, API dispatch and process state"""

import os
import struct
import threading
import subprocess
import time
import inspect

from ..config import DEFAULT_ENVIRONMENT
from ..paths import windows_path_of_host
from ..guest import ConsoleStream


class CoreMixin:
    """DLL lists, calling conventions, API dispatch and process state"""

    # Imports from these DLLs use cdecl (caller cleans the stack)
    CDECL_DLL_PREFIXES = ('msvcr', 'msvcp', 'crtdll', 'ucrtbase', 'api-ms-win-crt-',
                          'vcruntime')

    # The stdcall exceptions among the exports of the cdecl CRT DLLs
    CRT_STDCALL_ARG_COUNTS = {
        '_CxxThrowException': 2, '__vcrt_GetModuleFileNameW': 3,
        '__vcrt_GetModuleHandleW': 1, '__vcrt_InitializeCriticalSectionEx': 3,
        '__vcrt_LoadLibraryExW': 3,
    }

    # Variadic functions exported by stdcall DLLs are cdecl
    CDECL_FUNCTIONS = {'wsprintfA', 'wsprintfW'}

    # Argument counts (DWORDs) for emulated stdcall APIs. The callee must pop
    # these from the stack before returning, exactly like the real DLLs do.
    STDCALL_ARG_COUNTS = {
        # advapi32
        'AdjustTokenPrivileges': 6, 'GetFileSecurityW': 5, 'GetUserNameA': 2,
        'GetUserNameW': 2, 'LookupAccountNameW': 7, 'LookupPrivilegeValueA': 3,
        'LookupPrivilegeValueW': 3, 'LsaAddAccountRights': 4, 'LsaClose': 1,
        'LsaOpenPolicy': 4, 'OpenProcessToken': 3, 'RegCloseKey': 1, 'RegCreateKeyExA': 9,
        'RegCreateKeyExW': 9, 'RegDeleteKeyA': 2, 'RegDeleteKeyW': 2, 'RegDeleteValueA': 2,
        'RegDeleteValueW': 2, 'RegEnumKeyExA': 8, 'RegEnumKeyExW': 8, 'RegEnumValueA': 8,
        'RegEnumValueW': 8, 'RegFlushKey': 1, 'RegEnumKeyA': 4, 'RegEnumKeyW': 4,
        'RegOpenKeyExA': 5, 'RegOpenKeyExW': 5, 'RegQueryValueExA': 6, 'RegQueryValueExW': 6,
        'RegSetValueExA': 6, 'RegSetValueExW': 6, 'SetFileSecurityW': 3,
        # comctl32
        'CreateStatusWindowA': 4, 'CreateStatusWindowW': 4, 'CreateToolbarEx': 13,
        'DllGetVersion': 1, 'ImageList_Add': 3, 'ImageList_AddMasked': 3,
        'ImageList_Create': 5, 'ImageList_Destroy': 1, 'ImageList_Draw': 6,
        'ImageList_GetIcon': 3, 'ImageList_GetIconSize': 3, 'ImageList_GetImageCount': 1,
        'ImageList_Remove': 2, 'ImageList_ReplaceIcon': 3, 'ImageList_SetBkColor': 2,
        'ImageList_SetImageCount': 2, 'InitCommonControls': 0, 'InitCommonControlsEx': 1,
        'PropertySheetA': 1, 'PropertySheetW': 1,
        # comdlg32
        'CommDlgExtendedError': 0, 'FindTextA': 1, 'GetOpenFileNameA': 1,
        'GetOpenFileNameW': 1, 'GetSaveFileNameA': 1, 'GetSaveFileNameW': 1,
        # gdi32
        'CombineRgn': 4, 'CreateRectRgn': 4, 'CreateRectRgnIndirect': 1, 'GetRgnBox': 2,
        'Arc': 9, 'BitBlt': 9, 'Chord': 9, 'CreateBitmap': 5, 'CreateBrushIndirect': 1,
        'CreateCompatibleBitmap': 3, 'CreateCompatibleDC': 1, 'CreateDCA': 4,
        'CreateFontA': 14, 'CreateFontIndirectA': 1, 'CreateHatchBrush': 2,
        'CreatePalette': 1, 'CreatePen': 3, 'CreatePenIndirect': 1, 'CreateSolidBrush': 1,
        'DeleteDC': 1, 'DeleteObject': 1, 'Ellipse': 5, 'EnumFontFamiliesA': 4,
        'GetBkColor': 1, 'GetDeviceCaps': 2, 'GetDIBits': 7, 'GetObjectA': 3, 'GetPixel': 3,
        'GetStockObject': 1, 'GetTextColor': 1, 'GetTextExtentPoint32A': 4,
        'GetTextMetricsA': 2, 'LineTo': 3, 'MoveToEx': 4, 'PatBlt': 6, 'Pie': 9, 'Polygon': 3,
        'Polyline': 3, 'RealizePalette': 1, 'Rectangle': 5, 'RoundRect': 7, 'SelectObject': 2,
        'SelectPalette': 3, 'SetBkColor': 2, 'SetBkMode': 2, 'SetPixel': 4, 'SetROP2': 2,
        'SetStretchBltMode': 2, 'SetTextAlign': 2, 'SetTextColor': 2, 'StretchBlt': 11,
        'StretchDIBits': 13, 'TextOutA': 5, 'TextOutW': 5,
        # kernel32
        'AllocConsole': 0, 'Beep': 2, 'CloseHandle': 1, 'CompareStringA': 6, 'CopyFileA': 3,
        'CopyFileW': 3, 'CreateDirectoryA': 2, 'CreateDirectoryW': 2, 'CreateFileA': 7,
        'CreateFileW': 7, 'CreateProcessA': 10, 'DeleteCriticalSection': 1, 'DeleteFileA': 1,
        'DeleteFileW': 1, 'EnterCriticalSection': 1, 'ExitProcess': 1,
        'ExpandEnvironmentStringsA': 3, 'FileTimeToLocalFileTime': 2,
        'FileTimeToSystemTime': 2, 'FindClose': 1, 'FindFirstFileA': 2, 'FindFirstFileW': 2,
        'FindNextFileA': 2, 'FindNextFileW': 2, 'FindResourceA': 3, 'FlushFileBuffers': 1,
        'FormatMessageA': 7, 'FormatMessageW': 7, 'FreeConsole': 0,
        'FreeEnvironmentStringsA': 1, 'FreeEnvironmentStringsW': 1, 'FreeLibrary': 1,
        'FreeResource': 1, 'GetACP': 0, 'GetCommandLineA': 0, 'GetCommandLineW': 0,
        'GetComputerNameA': 2, 'GetComputerNameW': 2, 'GetCPInfo': 2,
        'GetCurrentDirectoryA': 2, 'GetCurrentDirectoryW': 2, 'GetCurrentProcess': 0,
        'GetCurrentProcessId': 0, 'GetCurrentThreadId': 0, 'GetDiskFreeSpaceA': 5,
        'GetDriveTypeA': 1, 'GetEnvironmentStrings': 0, 'GetEnvironmentStringsA': 0,
        'GetEnvironmentStringsW': 0, 'GetEnvironmentVariableA': 3,
        'GetEnvironmentVariableW': 3, 'GetExitCodeProcess': 2, 'GetFileAttributesA': 1,
        'GetFileAttributesW': 1, 'GetFileSize': 2, 'GetFileType': 1, 'GetFullPathNameA': 4,
        'GetLastError': 0, 'GetLocalTime': 1, 'GetLogicalDrives': 0, 'GetModuleFileNameA': 3,
        'GetModuleFileNameW': 3, 'GetModuleHandleA': 1, 'GetModuleHandleW': 1, 'GetOEMCP': 0,
        'GetPrivateProfileStringA': 6, 'GetProcAddress': 2, 'GetProcessHeap': 0,
        'GetStartupInfoA': 1, 'GetStartupInfoW': 1, 'GetStdHandle': 1, 'GetStringTypeA': 5,
        'GetStringTypeW': 4, 'GetSystemDirectoryA': 2, 'GetSystemDirectoryW': 2,
        'GetSystemInfo': 1, 'GetSystemTime': 1, 'GetSystemTimeAsFileTime': 1,
        'GetTempFileNameA': 4, 'GetTempPathA': 2, 'GetTickCount': 0, 'GetTickCount64': 0,
        'GetUserDefaultLangID': 0, 'GetVersion': 0, 'GetVersionExA': 1, 'GetVersionExW': 1,
        'GetVolumeInformationA': 8, 'GetWindowsDirectoryA': 2, 'GetWindowsDirectoryW': 2,
        'GlobalAlloc': 2, 'GlobalFree': 1, 'GlobalLock': 1, 'GlobalMemoryStatus': 1,
        'GlobalUnlock': 1, 'HeapAlloc': 3, 'HeapCreate': 3, 'HeapDestroy': 1, 'HeapFree': 3,
        'HeapReAlloc': 4, 'HeapSize': 3, 'InitializeCriticalSection': 1,
        'InitializeCriticalSectionAndSpinCount': 2, 'IsDBCSLeadByteEx': 2,
        'IsDebuggerPresent': 0, 'LCMapStringA': 6, 'LCMapStringW': 6,
        'LeaveCriticalSection': 1, 'LoadLibraryA': 1, 'LoadLibraryExA': 3,
        'LoadLibraryExW': 3, 'LoadLibraryW': 1, 'LoadResource': 2, 'LocalAlloc': 2,
        'LocalFileTimeToFileTime': 2, 'LocalFree': 1, 'LockResource': 1, 'lstrcatA': 2,
        'lstrcatW': 2, 'lstrcmpA': 2, 'lstrcmpiA': 2, 'lstrcmpiW': 2, 'lstrcmpW': 2,
        'lstrcpyA': 2, 'lstrcpynA': 3, 'lstrcpyW': 2, 'lstrlenA': 1, 'lstrlenW': 1,
        'MoveFileA': 2, 'MoveFileExA': 3, 'MoveFileExW': 3, 'MoveFileW': 2, 'MulDiv': 3,
        'MultiByteToWideChar': 6, 'QueryPerformanceCounter': 1,
        'QueryPerformanceFrequency': 1, 'RaiseException': 4, 'ReadConsoleA': 5, 'ReadFile': 5,
        'RemoveDirectoryA': 1, 'RemoveDirectoryW': 1, 'RtlUnwind': 4, 'SetConsoleTitleA': 1,
        'SetConsoleTitleW': 1, 'SetCurrentDirectoryA': 1, 'SetCurrentDirectoryW': 1,
        'SetEndOfFile': 1, 'SetEnvironmentVariableA': 2, 'SetEnvironmentVariableW': 2,
        'SetErrorMode': 1, 'SetFileAttributesA': 2, 'SetFileAttributesW': 2,
        'SetFilePointer': 4, 'SetFileTime': 4, 'SetHandleCount': 1, 'SetLastError': 1,
        'SetLocalTime': 1, 'SetUnhandledExceptionFilter': 1, 'SetVolumeLabelA': 2, 'SetVolumeLabelW': 2,
        'SizeofResource': 2, 'Sleep': 1, 'SystemTimeToFileTime': 2, 'TerminateProcess': 2,
        'TryEnterCriticalSection': 1, 'UnhandledExceptionFilter': 1, 'VirtualAlloc': 4,
        'VirtualFree': 3, 'WaitForSingleObject': 2, 'WideCharToMultiByte': 8,
        'WriteConsoleA': 5, 'WriteConsoleW': 5, 'WriteFile': 5,
        'WritePrivateProfileStringA': 4,
        # kernel32: files, drives, time, memory
        'AreFileApisANSI': 0, 'CompareFileTime': 2, 'CopyFileExW': 6, 'CreateFileMappingA': 6,
        'CreateFileMappingW': 6, 'CreateFontIndirectW': 1, 'CreateHardLinkA': 3,
        'CreateHardLinkW': 3, 'CreateProcessW': 10, 'CreateToolhelp32Snapshot': 2,
        'DeviceIoControl': 8, 'DosDateTimeToFileTime': 3, 'ExpandEnvironmentStringsW': 3,
        'FileTimeToDosDateTime': 3, 'FindCloseChangeNotification': 1,
        'FindFirstChangeNotificationA': 3, 'FindFirstChangeNotificationW': 3,
        'FindNextChangeNotification': 1, 'GetCompressedFileSizeA': 2,
        'GetCompressedFileSizeW': 2, 'GetConsoleMode': 2, 'GetConsoleScreenBufferInfo': 2,
        'GetDiskFreeSpaceExA': 4, 'GetDiskFreeSpaceExW': 4, 'GetDiskFreeSpaceW': 5,
        'GetDriveTypeW': 1, 'GetFileInformationByHandle': 2, 'GetFileSizeEx': 2,
        'GetLogicalDriveStringsA': 2, 'GetLogicalDriveStringsW': 2, 'GetProcessTimes': 5,
        'GetSystemDefaultLangID': 0, 'GetSystemDefaultLCID': 0, 'GetTempPathW': 2,
        'GetUserDefaultLCID': 0, 'GetVolumeInformationW': 8, 'GlobalMemoryStatusEx': 1,
        'GlobalSize': 1, 'IsProcessorFeaturePresent': 1, 'MapViewOfFile': 5,
        'MapViewOfFileEx': 6, 'MoveFileWithProgressW': 5, 'OpenEventA': 3, 'OpenEventW': 3,
        'OpenFileMappingA': 3, 'OpenFileMappingW': 3, 'OpenMutexA': 3, 'OpenMutexW': 3,
        'OpenProcess': 3, 'OpenSemaphoreA': 3, 'OpenSemaphoreW': 3, 'Process32FirstW': 2,
        'Process32NextW': 2, 'SetConsoleCtrlHandler': 2, 'SetConsoleMode': 2,
        'SetFileApisToANSI': 0, 'SetFileApisToOEM': 0, 'SetFilePointerEx': 5,
        'SetProcessAffinityMask': 2, 'UnmapViewOfFile': 1,
        # kernel32: threads and synchronization
        'CreateEventA': 4, 'CreateEventExW': 4, 'CreateEventW': 4, 'CreateMutexA': 3,
        'CreateMutexW': 3, 'CreateSemaphoreA': 4, 'CreateSemaphoreW': 4, 'CreateThread': 6,
        'ExitThread': 1, 'GetCurrentThread': 0, 'GetExitCodeThread': 2, 'GetPriorityClass': 1,
        'GetProcessAffinityMask': 3, 'GetThreadPriority': 1, 'InitializeCriticalSectionEx': 3,
        'InterlockedCompareExchange': 3, 'InterlockedDecrement': 1, 'InterlockedExchange': 2,
        'InterlockedExchangeAdd': 2, 'InterlockedIncrement': 1, 'PulseEvent': 1,
        'ReleaseMutex': 1, 'ReleaseSemaphore': 3, 'ResetEvent': 1, 'ResumeThread': 1,
        'SetEvent': 1, 'SetPriorityClass': 2, 'SetThreadAffinityMask': 2,
        'SetThreadPriority': 2, 'SuspendThread': 1, 'SwitchToThread': 0, 'TlsAlloc': 0,
        'TlsFree': 1, 'TlsGetValue': 1, 'TlsSetValue': 2, 'WaitForMultipleObjects': 4,
        'WaitForMultipleObjectsEx': 5, 'WaitForSingleObjectEx': 3,
        # kernel32: Vista+ APIs of the Visual C++ 2015+ runtime
        'AcquireSRWLockExclusive': 1, 'AcquireSRWLockShared': 1,
        'AddVectoredExceptionHandler': 2, 'CompareStringEx': 9, 'CompareStringOrdinal': 5,
        'CompareStringW': 6, 'CreateMutexExW': 4, 'CreateSemaphoreExW': 6,
        'DecodePointer': 1, 'DecodeSystemPointer': 1, 'EncodePointer': 1,
        'EncodeSystemPointer': 1, 'EnumSystemLocalesA': 2, 'EnumSystemLocalesEx': 4,
        'EnumSystemLocalesW': 2, 'FindFirstFileExA': 6, 'FindFirstFileExW': 6, 'FlsAlloc': 1,
        'FlsFree': 1, 'FlsGetValue': 1, 'FlsSetValue': 2, 'GetConsoleCP': 0,
        'GetConsoleOutputCP': 0, 'GetDateFormatA': 6, 'GetDateFormatEx': 7,
        'GetDateFormatW': 6, 'GetFullPathNameW': 4, 'GetLocaleInfoA': 4, 'GetLocaleInfoEx': 4,
        'GetLocaleInfoW': 4, 'GetModuleHandleExA': 3, 'GetModuleHandleExW': 3,
        'GetNativeSystemInfo': 1, 'GetSystemDefaultLocaleName': 2,
        'GetSystemTimePreciseAsFileTime': 1, 'GetTimeFormatA': 6, 'GetTimeFormatEx': 6,
        'GetTimeFormatW': 6, 'GetTimeZoneInformation': 1, 'GetUserDefaultLocaleName': 2,
        'InitializeConditionVariable': 1, 'InitializeSListHead': 1, 'InitializeSRWLock': 1,
        'InitOnceExecuteOnce': 4, 'InitOnceInitialize': 1, 'InterlockedFlushSList': 1,
        'InterlockedPopEntrySList': 1, 'InterlockedPushEntrySList': 2, 'IsValidCodePage': 1,
        'IsValidLocale': 2, 'IsValidLocaleName': 1, 'LCIDToLocaleName': 4,
        'LCMapStringEx': 9, 'LocaleNameToLCID': 2, 'OutputDebugStringA': 1,
        'OutputDebugStringW': 1, 'QueryDepthSList': 1, 'ReadConsoleW': 5,
        'ReleaseSRWLockExclusive': 1, 'ReleaseSRWLockShared': 1,
        'RemoveVectoredExceptionHandler': 1, 'RtlCaptureContext': 1, 'RtlPcToFileHeader': 2,
        'SetStdHandle': 2, 'SetThreadStackGuarantee': 1, 'SleepConditionVariableCS': 3,
        'SleepConditionVariableSRW': 4, 'TryAcquireSRWLockExclusive': 1,
        'TryAcquireSRWLockShared': 1, 'VirtualProtect': 4, 'VirtualProtectEx': 5,
        'VirtualQuery': 3, 'VirtualQueryEx': 4, 'WakeAllConditionVariable': 1,
        'WakeConditionVariable': 1,
        # advapi32: RtlGenRandom
        'SystemFunction036': 2,
        # msacm32
        'acmFormatSuggest': 5, 'acmStreamClose': 2, 'acmStreamConvert': 3, 'acmStreamOpen': 8,
        'acmStreamPrepareHeader': 3, 'acmStreamSize': 4, 'acmStreamUnprepareHeader': 3,
        # ole32
        'CoCreateInstance': 5, 'CoInitialize': 1, 'CoTaskMemAlloc': 1, 'CoTaskMemFree': 1,
        'CoTaskMemRealloc': 2,
        'CoUninitialize': 0, 'DoDragDrop': 4, 'OleInitialize': 1, 'OleUninitialize': 0,
        'RegisterDragDrop': 2, 'ReleaseStgMedium': 1, 'RevokeDragDrop': 1,
        # oleaut32
        'SysAllocString': 1, 'SysAllocStringByteLen': 2, 'SysAllocStringLen': 2,
        'SysFreeString': 1, 'SysReAllocString': 2, 'SysReAllocStringLen': 3,
        'SysStringByteLen': 1, 'SysStringLen': 1, 'VariantClear': 1, 'VariantCopy': 2,
        'VariantInit': 1,
        # shell32
        'ExtractIconA': 3, 'ExtractIconExA': 5, 'ExtractIconExW': 5, 'SHBrowseForFolderA': 1,
        'SHBrowseForFolderW': 1, 'SHChangeNotify': 4, 'ShellExecuteA': 6,
        'ShellExecuteExA': 1, 'ShellExecuteExW': 1, 'ShellExecuteW': 6, 'SHFileOperationA': 1,
        'SHFileOperationW': 1, 'SHGetDesktopFolder': 1, 'SHGetFileInfoA': 5,
        'SHGetFileInfoW': 5, 'SHGetFolderPathA': 5, 'SHGetFolderPathW': 5,
        'SHGetMalloc': 1,
        'SHGetPathFromIDListA': 2, 'SHGetPathFromIDListW': 2, 'SHGetSpecialFolderLocation': 3,
        'SHGetSpecialFolderPathA': 4, 'SHGetSpecialFolderPathW': 4,
        # user32
        'AdjustWindowRect': 3, 'AdjustWindowRectEx': 4, 'AppendMenuA': 4, 'BeginPaint': 2,
        'BringWindowToTop': 1, 'ChangeDisplaySettingsA': 2, 'CharLowerA': 1, 'CharLowerW': 1,
        'CharNextA': 1, 'CharPrevA': 2, 'CharToOemBuffA': 3, 'CharUpperA': 1, 'CharUpperW': 1,
        'CheckDlgButton': 3, 'ClientToScreen': 2, 'CopyRect': 2, 'CreateCursor': 7,
        'CreateDialogParamA': 5, 'CreateDialogParamW': 5, 'CreateMenu': 0,
        'CreatePopupMenu': 0, 'CreateWindowExA': 12, 'CreateWindowExW': 12,
        'DefWindowProcA': 4, 'DefWindowProcW': 4, 'DestroyCursor': 1, 'DestroyIcon': 1,
        'DestroyMenu': 1, 'DestroyWindow': 1, 'DialogBoxParamA': 5, 'DialogBoxParamW': 5,
        'DispatchMessageA': 1, 'DispatchMessageW': 1, 'DrawMenuBar': 1, 'DrawTextA': 5,
        'DrawTextW': 5, 'EnableWindow': 2, 'EndDialog': 2, 'EndPaint': 2,
        'EnumDisplaySettingsA': 3, 'EqualRect': 2, 'ExitWindowsEx': 2, 'FillRect': 3,
        'FindWindowA': 2, 'FrameRect': 3, 'GetActiveWindow': 0, 'GetAsyncKeyState': 1,
        'GetCapture': 0, 'GetClassNameA': 3, 'GetClientRect': 2, 'GetCursor': 0,
        'GetCursorPos': 1, 'GetDC': 1, 'GetDesktopWindow': 0, 'GetDlgCtrlID': 1,
        'GetDlgItem': 2, 'GetDlgItemInt': 4, 'GetDlgItemTextA': 4, 'GetDlgItemTextW': 4,
        'GetDoubleClickTime': 0, 'GetFocus': 0, 'GetForegroundWindow': 0,
        'GetKeyboardState': 1, 'GetKeyState': 1, 'GetMessageA': 4, 'GetMessageW': 4,
        'GetParent': 1, 'GetScrollInfo': 3, 'GetScrollPos': 2, 'GetScrollRange': 4,
        'GetSysColor': 1, 'GetSysColorBrush': 1, 'GetSystemMetrics': 1, 'GetWindow': 2,
        'GetWindowLongA': 2, 'GetWindowLongW': 2, 'GetWindowPlacement': 2, 'GetWindowRect': 2,
        'GetWindowTextA': 3, 'GetWindowTextLengthA': 1, 'GetWindowTextW': 3, 'InflateRect': 3,
        'IntersectRect': 3, 'InvalidateRect': 3, 'IsCharAlphaA': 1, 'IsCharAlphaNumericA': 1,
        'IsCharLowerA': 1, 'IsCharUpperA': 1, 'IsDialogMessageA': 2, 'IsDialogMessageW': 2,
        'IsDlgButtonChecked': 2, 'IsIconic': 1, 'IsRectEmpty': 1, 'IsWindow': 1,
        'IsWindowEnabled': 1, 'IsWindowVisible': 1, 'IsZoomed': 1, 'KillTimer': 2,
        'LoadBitmapA': 2, 'LoadCursorA': 2, 'LoadCursorW': 2, 'LoadIconA': 2, 'LoadIconW': 2,
        'LoadKeyboardLayoutA': 2, 'LoadStringA': 4, 'MessageBeep': 1, 'MessageBoxA': 4,
        'MessageBoxW': 4, 'MoveWindow': 6, 'OemToCharBuffA': 3, 'OffsetRect': 3,
        'OpenIcon': 1, 'PeekMessageA': 5, 'PeekMessageW': 5, 'PostMessageA': 4,
        'PostMessageW': 4, 'PostQuitMessage': 1, 'PtInRect': 3, 'RegisterClassA': 1,
        'RegisterClassExA': 1, 'RegisterClassExW': 1, 'RegisterClassW': 1,
        'RegisterWindowMessageA': 1, 'ReleaseCapture': 0, 'ReleaseDC': 2, 'ScreenToClient': 2,
        'SendMessageA': 4, 'SendMessageW': 4, 'SetCapture': 1, 'SetCursor': 1,
        'SetCursorPos': 2, 'SetDlgItemInt': 4, 'SetDlgItemTextA': 3, 'SetDlgItemTextW': 3,
        'SetFocus': 1, 'SetForegroundWindow': 1, 'SetKeyboardState': 1, 'SetMenu': 2,
        'SetRect': 5, 'SetRectEmpty': 1, 'SetScrollInfo': 4, 'SetScrollPos': 4,
        'SetScrollRange': 5, 'SetTimer': 4, 'SetWindowLongA': 3, 'SetWindowLongW': 3,
        'SetWindowPlacement': 2, 'SetWindowPos': 7, 'SetWindowTextA': 2, 'SetWindowTextW': 2,
        'ShowCursor': 1, 'ShowWindow': 2, 'SystemParametersInfoA': 4, 'TranslateMessage': 1,
        'UnionRect': 3, 'UpdateWindow': 1, 'ValidateRect': 2, 'wvsprintfA': 3,
        # user32: emulated controls, menus, resources, clipboard
        'AppendMenuW': 4, 'CallWindowProcA': 5, 'CallWindowProcW': 5, 'CharNextExA': 3,
        'CharPrevExA': 4, 'CheckMenuItem': 3, 'CheckMenuRadioItem': 5, 'CheckRadioButton': 4,
        'ChildWindowFromPoint': 3, 'ChildWindowFromPointEx': 4, 'CloseClipboard': 0,
        'CreateAcceleratorTableW': 2, 'DeleteMenu': 3, 'DestroyAcceleratorTable': 1,
        'EmptyClipboard': 0, 'EnableMenuItem': 3, 'GetClassInfoA': 3, 'GetClassInfoExA': 3,
        'GetClassInfoExW': 3, 'GetClassInfoW': 3, 'GetClassNameW': 3, 'GetClipboardData': 1,
        'GetDialogBaseUnits': 0, 'GetMenu': 1, 'GetMenuItemCount': 1, 'GetMenuItemID': 2,
        'GetMenuItemInfoA': 4, 'GetMenuItemInfoW': 4, 'GetMenuState': 3, 'GetMenuStringW': 5,
        'GetMonitorInfoA': 2, 'GetMonitorInfoW': 2, 'GetSubMenu': 2,
        'GetWindowTextLengthW': 1, 'InsertMenuA': 5, 'InsertMenuItemA': 4,
        'InsertMenuItemW': 4, 'InsertMenuW': 5, 'IsClipboardFormatAvailable': 1,
        'LoadAcceleratorsA': 2, 'LoadAcceleratorsW': 2, 'LoadBitmapW': 2, 'LoadMenuA': 2,
        'LoadMenuW': 2, 'LoadStringW': 4, 'MapDialogRect': 2, 'MapVirtualKeyA': 2,
        'MapVirtualKeyW': 2, 'ModifyMenuW': 5, 'MonitorFromPoint': 3, 'MonitorFromRect': 2,
        'MonitorFromWindow': 2, 'NativeWndProc': 4, 'OpenClipboard': 1,
        'RegisterClipboardFormatA': 1, 'RegisterClipboardFormatW': 1, 'RemoveMenu': 3,
        'SendDlgItemMessageA': 5, 'SendDlgItemMessageW': 5, 'SetClipboardData': 2,
        'SetMenuItemInfoA': 4, 'SetMenuItemInfoW': 4, 'SetParent': 2,
        'SystemParametersInfoW': 4, 'TrackPopupMenu': 7, 'TrackPopupMenuEx': 6,
        'TranslateAcceleratorA': 3, 'TranslateAcceleratorW': 3, 'WindowFromPoint': 2,
        # user32: window classes, messages, images, regions (NSIS installers)
        'DrawFocusRect': 2, 'FindWindowExA': 4, 'FindWindowExW': 4, 'GetClassLongA': 2,
        'GetClassLongW': 2, 'GetMessagePos': 0, 'GetSystemMenu': 2, 'LoadImageA': 6,
        'LoadImageW': 6, 'MapWindowPoints': 4, 'MessageBoxIndirectA': 1,
        'MessageBoxIndirectW': 1, 'SendMessageTimeoutA': 7, 'SendMessageTimeoutW': 7,
        'SetClassLongA': 3, 'SetClassLongW': 3, 'SetWindowRgn': 3,
        # kernel32: paths and INI files
        'GetLongPathNameA': 3, 'GetLongPathNameW': 3, 'GetPrivateProfileIntA': 4,
        'GetPrivateProfileIntW': 4, 'GetShortPathNameA': 3, 'GetShortPathNameW': 3,
        'SearchPathA': 6, 'SearchPathW': 6,
        # version
        'GetFileVersionInfoA': 4, 'GetFileVersionInfoSizeA': 2,
        'GetFileVersionInfoSizeW': 2, 'GetFileVersionInfoW': 4, 'VerQueryValueA': 4,
        'VerQueryValueW': 4,
        # winmm
        'joyGetDevCapsA': 3, 'joyGetPos': 2, 'mciSendCommandA': 4, 'PlaySoundA': 3,
        'PlaySoundW': 3, 'sndPlaySoundA': 2, 'sndPlaySoundW': 2, 'timeBeginPeriod': 1,
        'timeEndPeriod': 1, 'timeGetTime': 0, 'waveOutClose': 1, 'waveOutGetPosition': 3,
        'waveOutOpen': 6, 'waveOutPause': 1, 'waveOutPrepareHeader': 3, 'waveOutReset': 1,
        'waveOutRestart': 1, 'waveOutUnprepareHeader': 3, 'waveOutWrite': 3,
    }

    # Windows message constants
    WM_CREATE = 0x0001
    WM_DESTROY = 0x0002
    WM_PAINT = 0x000F
    WM_CLOSE = 0x0010
    WM_QUIT = 0x0012
    WM_SHOWWINDOW = 0x0018
    WM_KEYDOWN = 0x0100
    WM_KEYUP = 0x0101
    WM_CHAR = 0x0102
    WM_SYSKEYDOWN = 0x0104
    WM_SYSKEYUP = 0x0105
    WM_SYSCHAR = 0x0106
    WM_SYSCOMMAND = 0x0112
    SC_CLOSE = 0xF060
    WM_COMMAND = 0x0111
    WM_DRAWITEM = 0x002B
    WM_TIMER = 0x0113
    WM_MOUSEMOVE = 0x0200
    WM_LBUTTONDOWN = 0x0201
    WM_LBUTTONUP = 0x0202
    WM_RBUTTONDOWN = 0x0204
    WM_RBUTTONUP = 0x0205

    # Mouse key state flags (wParam for mouse messages)
    MK_LBUTTON = 0x0001
    MK_RBUTTON = 0x0002

    # Button notification codes (high word of WM_COMMAND wParam)
    BN_CLICKED = 0

    # Control notification codes (high word of WM_COMMAND wParam)
    LBN_SELCHANGE = 1
    LBN_DBLCLK = 2
    CBN_SELCHANGE = 1

    # Button control messages
    BM_GETCHECK = 0x00F0
    BM_SETCHECK = 0x00F1
    # BS_CHECKBOX, BS_AUTOCHECKBOX, BS_RADIOBUTTON, BS_3STATE, BS_AUTO3STATE,
    # BS_AUTORADIOBUTTON
    CHECK_BUTTON_STYLES = (0x2, 0x3, 0x4, 0x5, 0x6, 0x9)

    # Listbox control messages
    LB_ADDSTRING = 0x0180
    LB_INSERTSTRING = 0x0181
    LB_DELETESTRING = 0x0182
    LB_RESETCONTENT = 0x0184
    LB_SETCURSEL = 0x0186
    LB_GETCURSEL = 0x0188
    LB_GETTEXT = 0x0189
    LB_GETTEXTLEN = 0x018A
    LB_GETCOUNT = 0x018B
    LB_ERR = 0xFFFFFFFF  # -1 as unsigned

    # Combobox control messages
    CB_ADDSTRING = 0x0143
    CB_DELETESTRING = 0x0144
    CB_GETCOUNT = 0x0146
    CB_GETCURSEL = 0x0147
    CB_GETLBTEXT = 0x0148
    CB_GETLBTEXTLEN = 0x0149
    CB_RESETCONTENT = 0x014B
    CB_SETCURSEL = 0x014E
    CB_ERR = 0xFFFFFFFF

    # PeekMessage removal flags
    PM_NOREMOVE = 0x0000
    PM_REMOVE = 0x0001

    # Scrollbar messages and notification codes
    WM_HSCROLL = 0x0114
    WM_VSCROLL = 0x0115
    SB_LINEUP = 0        # Also SB_LINELEFT
    SB_LINEDOWN = 1      # Also SB_LINERIGHT
    SB_PAGEUP = 2        # Also SB_PAGELEFT
    SB_PAGEDOWN = 3      # Also SB_PAGERIGHT
    SB_THUMBPOSITION = 4
    SB_THUMBTRACK = 5
    SB_ENDSCROLL = 8

    # Scrollbar selectors (nBar) and control style
    SB_HORZ = 0
    SB_VERT = 1
    SB_CTL = 2
    SBS_VERT = 0x0001

    # Scrollbar control messages (SBM_*)
    SBM_SETPOS = 0x00E0
    SBM_GETPOS = 0x00E1
    SBM_SETRANGE = 0x00E2
    SBM_GETRANGE = 0x00E3

    def __init__(self, emulator, gui=None):
        self.emu = emulator
        self.gui = gui  # PseudoWindowsGUI reference
        self.handles = {}
        self.critical_sections = {}  # CRITICAL_SECTION address -> [owner tid, count]
        self.tls_used = set()  # Allocated TLS slot indexes
        self.fls_callbacks = {}  # FLS index (a TLS slot) -> its FlsAlloc callback
        self.srw_locks = {}  # SRWLOCK address -> {'owner': tid or None, 'shared': count}
        self.condition_variables = {}  # CONDITION_VARIABLE address -> [waiter tokens]
        self.page_protections = []  # [(start, end, protection)] set by VirtualProtect
        self.vectored_handlers = {}  # AddVectoredExceptionHandler handle -> handler
        self.unhandled_exception_filter = 0  # SetUnhandledExceptionFilter
        self.std_handles = {}  # SetStdHandle: STD_*_HANDLE -> handle
        self.module_handles = {}  # lowercase DLL name -> fake HMODULE
        self.virtual_allocs = {}  # VirtualAlloc base -> reserved size
        self.mapped_virtual_allocs = set()  # Bases mapped at a requested address
        self.next_handle = 0x1000
        self.console_output = []
        # Own console: has_console follows AllocConsole/FreeConsole, console is
        # the GUI console window (FakeConsole) when the GUI is running
        self.has_console = False
        self.console = None
        # msvcrt FILE* streams: fake FILE pointer -> {'fp': python file, 'path': str}
        self.file_streams = {}
        self.next_file_ptr = 0x0F000000  # dedicated range for fake FILE* pointers
        self.registered_classes = {}  # Registered window classes
        self.system_class_data = {}  # System class name -> fields changed by SetClassLong
        self.system_menus = {}  # hwnd -> window menu (GetSystemMenu)
        self.shell_malloc = 0  # IMalloc of SHGetMalloc
        self.last_message_pos = (0, 0)  # Cursor position of the last message (GetMessagePos)
        self.atoms = {}  # RegisterClass atoms
        self.next_atom = 0xC000

        # Message queue system
        self.message_queue = []
        self.message_lock = threading.Lock()  # Guards message_queue (GUI thread is producer)
        self.sent_messages = {}  # Guest thread id -> SendMessage requests from other threads
        self.painted_windows = set()  # Windows that received WM_PAINT
        self.dirty_controls = {}  # Owner-draw controls waiting for WM_DRAWITEM (ordered)
        self._drawitem_buf = 0
        self.quit_requested = False
        # True once the emulated process is gone (ExitProcess or emulation end).
        # After that no window can consume messages, so the GUI must stop
        # treating windows as live app windows (e.g. X click posts WM_CLOSE).
        self.process_exited = False

        # GDI object/DC state (all touched only on the emulation thread)
        self.gdi_objects = {}  # handle -> {'type': 'pen'|'brush', 'color': (r,g,b), 'width': int}
        self._bits_cache = {}  # (width, height, bpp, bits) -> RGB of CreateBitmap
        self._dib_cache = {}   # GetDIBits request + display list -> (bits, data refs)
        self.dc_map = {}       # hdc -> hwnd the DC draws into
        self.dc_state = {}     # hdc -> {'pen','brush','pos','text_color','bk_mode','bk_color'}
        self._stock_objects = {}  # GetStockObject index -> handle
        self._sys_color_brushes = {}  # GetSysColorBrush index -> handle

        # Timers: (hwnd, timer_id) -> {'elapse': sec, 'callback': addr, 'next_fire': time}
        self.timers = {}
        self.next_timer_id = 1

        # Menus: hmenu -> list of items
        # item = {'flags': int, 'id': int, 'text': str, 'submenu': hmenu or 0}
        self.menus = {}

        # GetWindowLong/SetWindowLong storage: hwnd -> {index: value}
        self.window_longs = {}

        # Mouse capture (SetCapture/ReleaseCapture) - hwnd or 0
        self.capture_hwnd = 0

        # Dialogs (DialogBoxParam, common dialogs): hwnd -> {'proc', 'handler',
        # 'owner', 'result', 'ended'}
        self.dialogs = {}

        # Cursor (SetCursor/ShowCursor) and keyboard toggle state (SetKeyboardState)
        # current_cursor: SetCursor handle (None until the first SetCursor or
        # WM_SETCURSOR); cursors: handle -> {'system': IDC_*} or
        # {'hotspot': (x, y), 'size': (w, h), 'rgba': bytes}
        self.current_cursor = None
        self.cursor_count = 0
        self.cursors = {}
        self._system_cursors = {}
        self.keyboard_toggles = bytearray(256)

        # Multimedia: wave output devices, ACM streams, MCI devices (by handle/id)
        self.wave_outs = {}
        self.acm_streams = {}
        self.mci_devices = {}
        self.next_mci_id = 1

        # MSVCRT rand() state (MSVC-compatible LCG) and clock() epoch
        self._rand_seed = 1
        self._clock_epoch = time.time()

        # Process environment (GetEnvironmentVariable, getenv, _putenv);
        # keys are upper-case since Windows names are case-insensitive
        self.environment = dict(DEFAULT_ENVIRONMENT)

        # Current directory (SetCurrentDirectory); relative paths resolve against it.
        # Programs start in their EXE's folder, like when launched from Explorer.
        exe_dir = self.windows_exe_path().rsplit('\\', 1)[0]
        self.current_directory = exe_dir if len(exe_dir) > 2 else exe_dir + "\\"

        # (type, name) -> (RVA, size) of the EXE's resources, built on first use
        self._resource_index = None

        # MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT): (host src, host dst or None, flags)
        self.pending_file_operations = []

        # COM: interface name -> vtable address, object base -> state dict,
        # COM method stub name -> argument count (including "this")
        self._com_vtables = {}
        self.com_objects = {}
        self.com_arg_counts = {}

        # Shell item ID lists (SHBrowseForFolder): PIDL address -> Windows path
        self.pidls = {}

        # Common controls: image lists (handle -> {'cx', 'cy', 'images'}),
        # the system image lists, icons, accelerator tables
        self.imagelists = {}
        self._sys_imagelists = {}
        # Icons added to the system image lists for files (see _sys_file_icon)
        self._sys_file_icons = []
        self._sys_file_icon_indexes = {}
        self.icons = {}
        self._dialog_fonts = {}  # (face, size) of a dialog template -> GDI font handle
        self.accelerators = {}
        self.clipboard_open = False
        self.mapping_views = {}  # id(file mapping info) -> its address here

        # Registry: predefined HKEY -> key node (shared by the emulated
        # programs and saved to REGISTRY_FILE), open HKEY -> key node
        self.registry_roots = self._shared_registry_roots()
        self.registry_handles = {}

        # Additional CRT state (strtok, getenv strings, signals, time buffers)
        self.next_fd = 3  # CRT file descriptors handed out by fopen
        self._strtok_next = {}  # unit size -> next strtok/wcstok position
        self._getenv_cache = {}  # (name, wide) -> (value, heap address)
        self._signal_handlers = {}
        self._crt_static = {}  # name -> static CRT buffer (strerror, asctime...)

        # MSVCRT global variable memory addresses (lazy init)
        self._fmode_addr = 0
        self._commode_addr = 0
        self._acmdln_addr = 0
        self._wcmdln_addr = 0
        self._environ_addr = 0
        self._wenviron_addr = 0
        self._argc = 0
        self._argc_value = 0  # argc of the command line (set with the argv arrays)
        self._argv_addr = 0
        self.exit_handlers = []
        self.exit_code = None
        self._exit_handlers_ran = False
        self._wargv_addr = 0
        self._environ_ptr_addr = 0
        self._wenviron_ptr_addr = 0
        self._initenv_addr = 0
        self._winitenv_addr = 0

        # CRT stdio: _iob[3] FILE structs backed by ConsoleStream objects
        self._iob_addr = 0
        self.std_streams = []
        self._errno_addr = 0
        self._lconv_addr = 0
        self._c_locale_addr = 0

        # API name mapping (for functions starting with double underscore)
        self._api_map = {
            '__p__fmode': self.api__p__fmode,
            '__p__commode': self.api__p__commode,
            '__p__acmdln': self.api__p__acmdln,
            '__p__wcmdln': self.api__p__wcmdln,
            '__set_app_type': self.api__set_app_type,
            '__getmainargs': self.api__getmainargs,
            '__wgetmainargs': self.api__wgetmainargs,
            '__p___argc': self.api__p___argc,
            '__p___initenv': lambda args: self._ensure_env_ptr('_initenv_addr'),
            '__p___winitenv': lambda args: self._ensure_env_ptr('_winitenv_addr', wide=True),
            '__p___argv': self.api__p___argv,
            '__p___wargv': self.api__p___wargv,
            '__CxxFrameHandler3': self.api__CxxFrameHandler3,
            '__CxxFrameHandler': self.api__CxxFrameHandler3,
            '__CxxFrameHandler2': self.api__CxxFrameHandler3,
            '__dllonexit': self.api__dllonexit,
            '__security_init_cookie': self.api__security_init_cookie,
            '__security_check_cookie': self.api__security_check_cookie,
            '__iob_func': self.api__iob_func,
            '__acrt_iob_func': self.api__acrt_iob_func,
            '?terminate@@YAXXZ': self.abort,
            '??1type_info@@UAE@XZ': lambda args: 0,  # thiscall, nothing to free
        }
        self._api_map.update(self._crt_extra_api_map())
        self._api_map.update(self._crt_variable_api_map())

    @property
    def _last_error(self):
        """GetLastError/SetLastError value of the calling thread"""
        return self.emu.current_thread.last_error

    @_last_error.setter
    def _last_error(self, value):
        self.emu.current_thread.last_error = value

    # Methods with an API handler's signature that are helpers, not exports
    INTERNAL_HANDLER_NAMES = frozenset({
        '_crt_noop', '_crt_raise', '_std_exception_copy', '_std_exception_destroy',
        '_std_type_info_compare', '_std_type_info_name',
    })
    _handler_names = None  # cache of _api_method_names()

    @classmethod
    def _api_method_names(cls):
        """Names of the methods that emulate an API: they are called as
        handler(args), so their only required parameter is "args" (helpers
        with other parameters, properties and the like never match an
        imported name)"""
        if cls._handler_names is None:
            names = set()
            for name, func in inspect.getmembers(cls, inspect.isfunction):
                params = list(inspect.signature(func).parameters.values())
                if (len(params) >= 2 and params[0].name == 'self' and
                        params[1].name == 'args' and
                        all(p.default is not p.empty for p in params[2:])):
                    names.add(name)
            cls._handler_names = frozenset(names - cls.INTERNAL_HANDLER_NAMES)
        return cls._handler_names

    # Windows DLLs without an emulated API of their own whose exports may
    # still be emulated by name (besides EMULATED_DLLS, SYSTEM_DLLS and the C
    # runtime DLLs)
    OTHER_SYSTEM_DLLS = {
        'msimg32.dll', 'gdiplus.dll', 'wininet.dll', 'urlmon.dll', 'netapi32.dll',
        'msvfw32.dll', 'avifil32.dll', 'ddraw.dll', 'dsound.dll', 'dinput.dll',
        'dinput8.dll', 'd3d8.dll', 'd3d9.dll', 'opengl32.dll', 'glu32.dll', 'lz32.dll',
        'olepro32.dll', 'oledlg.dll', 'riched20.dll', 'riched32.dll', 'msftedit.dll',
        'iphlpapi.dll', 'wintrust.dll', 'cabinet.dll', 'powrprof.dll', 'wtsapi32.dll',
        'normaliz.dll', 'bcrypt.dll', 'ncrypt.dll', 'dnsapi.dll', 'winhttp.dll',
        'mscoree.dll', 'msi.dll', 'usp10.dll', 'hhctrl.ocx', 'oleacc.dll', 'mapi32.dll',
        'odbc32.dll', 'avrt.dll', 'xinput1_3.dll', 'shfolder.dll', 'sensapi.dll',
    }

    def is_system_dll_name(self, dll_name):
        """Is dll_name a Windows DLL (whose exports the emulator may emulate)?
        The emulated API of a name never stands in for another DLL's export."""
        key = dll_name.replace('/', '\\').rsplit('\\', 1)[-1].lower()
        if '.' not in key:
            key += '.dll'
        return (self._is_system_dll(key) or key in self.OTHER_SYSTEM_DLLS or
                key.startswith(self.CDECL_DLL_PREFIXES) or key.startswith('msvcirt'))

    def get_api_handler(self, func_name, dll_name=None):
        """Handler of an emulated API (None if not emulated). With dll_name,
        only the exports of Windows DLLs are emulated."""
        if dll_name is not None and not self.is_system_dll_name(dll_name):
            return None
        handler = self._api_map.get(func_name)
        if handler is not None:
            return handler
        if func_name in self._api_method_names():
            return getattr(self, func_name)
        return None

    # ntdll's C runtime exports are cdecl, except these helpers of 64-bit
    # arithmetic (stdcall: number of DWORD arguments; the shifts take registers)
    NTDLL_STDCALL_HELPERS = {'_alldiv': 4, '_alldvrm': 4, '_allmul': 4, '_allrem': 4,
                             '_aulldiv': 4, '_aulldvrm': 4, '_aullrem': 4,
                             '_allshl': 0, '_allshr': 0, '_aullshr': 0}

    def stack_cleanup_bytes(self, dll_name, func_name):
        """Bytes of arguments the callee pops on return (stdcall).

        Returns 0 for cdecl functions and None when the function is stdcall
        but its argument count is unknown.
        """
        dll = dll_name.lower()
        if dll.startswith(self.CDECL_DLL_PREFIXES):
            return 4 * self.CRT_STDCALL_ARG_COUNTS.get(func_name, 0)
        if dll in ('ntdll.dll', 'ntdll') and (func_name[:1].islower() or
                                              func_name[:1] == '_'):
            return 4 * self.NTDLL_STDCALL_HELPERS.get(func_name, 0)
        if func_name in self.CDECL_FUNCTIONS:
            return 0
        argc = self.STDCALL_ARG_COUNTS.get(func_name, self.com_arg_counts.get(func_name))
        return None if argc is None else argc * 4

    # MSVCRT FILE layout: _ptr, _cnt, _base, _flag, _file, _charbuf, _bufsiz, _tmpfname
    _FILE_SIZE = 0x20
    _IOREAD = 0x0001
    _IOWRT = 0x0002

    def _ensure_iob(self):
        """Allocate the CRT _iob[3] array and bind stdin/stdout/stderr to it."""
        if self._iob_addr:
            return self._iob_addr
        self._iob_addr = self.emu.heap_alloc(self._FILE_SIZE * 3)
        for fd, kind in enumerate(('stdin', 'stdout', 'stderr')):
            ptr = self._iob_addr + fd * self._FILE_SIZE
            flag = self._IOREAD if fd == 0 else self._IOWRT
            file_struct = struct.pack('<IIIIIIII', 0, 0, 0, flag, fd, 0, 0, 0)
            self.emu.uc.mem_write(ptr, file_struct)
            stream = ConsoleStream(self, kind)
            self.std_streams.append(stream)
            self.file_streams[ptr] = {'fp': stream, 'path': kind}
        return self._iob_addr

    def flush_std_streams(self):
        """Flush buffered console output (called at exit and before input)."""
        for stream in self.std_streams:
            if stream.kind != 'stdin':
                stream.flush()

    def _environ_array(self, wide):
        """New NULL-terminated array of "NAME=value" strings of the
        environment (the C runtime's environ/_wenviron)"""
        pointers = []
        for name, value in sorted(self.environment.items()):
            units = self._text_units(f"{name}={value}", wide) + [0]
            address = self.emu.heap_alloc(len(units) * (2 if wide else 1))
            self._write_units(address, units, wide, terminate=False)
            pointers.append(address)
        array = self.emu.heap_alloc(4 * (len(pointers) + 1))
        self._mem_write(array, struct.pack(f'<{len(pointers) + 1}I', *pointers, 0))
        return array

    def _initial_environ(self, wide):
        """environ array of the environment at the program's start (also
        __initenv; _putenv makes a new one for environ)"""
        attr = '_wenviron_addr' if wide else '_environ_addr'
        if getattr(self, attr) == 0:
            setattr(self, attr, self._environ_array(wide))
        return getattr(self, attr)

    def _ensure_env_ptr(self, attr, wide=False):
        """Address of a C runtime environment variable (_environ, _wenviron,
        __initenv, __winitenv): it points to the initial environ array"""
        if getattr(self, attr) == 0:
            var = self.emu.heap_alloc(4)
            self.emu.uc.mem_write(var, struct.pack('<I', self._initial_environ(wide)))
            setattr(self, attr, var)
        return getattr(self, attr)

    def _update_environ(self):
        """_putenv changed the environment: _environ and _wenviron get new
        arrays (__initenv keeps the initial one; like on Windows,
        SetEnvironmentVariable does not change them)"""
        for attr, wide in (('_environ_ptr_addr', False), ('_wenviron_ptr_addr', True)):
            if getattr(self, attr):
                self._mem_write(getattr(self, attr),
                                struct.pack('<I', self._environ_array(wide)))

    def windows_exe_path(self):
        """Path of the main EXE as the program sees it (C:\\..., D:\\...)."""
        path = windows_path_of_host(self.emu.pe_loader.filepath)
        return path or "C:\\" + os.path.basename(self.emu.pe_loader.filepath)

    def windows_command_line(self):
        command_line = getattr(self.emu, 'command_line', None)
        if command_line:
            return command_line
        path = self.windows_exe_path()
        command_line = f'"{path}"' if ' ' in path else path
        program_args = getattr(self.emu, 'program_args', None)
        if program_args:
            command_line += ' ' + subprocess.list2cmdline(program_args)
        return command_line
