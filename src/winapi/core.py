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
    CDECL_FUNCTIONS = {'wsprintfA', 'wsprintfW', 'wnsprintfA', 'wnsprintfW'}

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
        'ImageList_LoadImageA': 7, 'ImageList_LoadImageW': 7, 'ImageList_LoadImage': 7,
        'ImageList_DrawEx': 10,
        'ImageList_GetIcon': 3, 'ImageList_GetIconSize': 3, 'ImageList_GetImageCount': 1,
        'ImageList_Remove': 2, 'ImageList_ReplaceIcon': 3, 'ImageList_SetBkColor': 2,
        'ImageList_SetImageCount': 2, 'InitCommonControls': 0, 'InitCommonControlsEx': 1,
        'PropertySheetA': 1, 'PropertySheetW': 1, 'PropertySheet': 1,
        # comdlg32
        'CommDlgExtendedError': 0, 'FindTextA': 1, 'FindTextW': 1, 'ReplaceTextA': 1,
        'ReplaceTextW': 1, 'GetFileTitleA': 3, 'GetFileTitleW': 3,
        'GetOpenFileNameA': 1,
        'GetOpenFileNameW': 1, 'GetSaveFileNameA': 1, 'GetSaveFileNameW': 1,
        'PrintDlgA': 1, 'PrintDlgW': 1, 'PageSetupDlgA': 1, 'PageSetupDlgW': 1,
        # gdi32
        'CombineRgn': 4, 'CreateRectRgn': 4, 'CreateRectRgnIndirect': 1, 'GetRgnBox': 2,
        'ExcludeClipRect': 5, 'GetClipBox': 2, 'IntersectClipRect': 5, 'SelectClipRgn': 2,
        'AddFontResourceA': 1, 'AddFontResourceExA': 3, 'AddFontResourceExW': 3,
        'AddFontResourceW': 1, 'RemoveFontResourceA': 1, 'RemoveFontResourceExA': 3,
        'RemoveFontResourceExW': 3, 'RemoveFontResourceW': 1,
        'Arc': 9, 'BitBlt': 9, 'Chord': 9, 'CreateBitmap': 5, 'CreateBrushIndirect': 1,
        'CreateCompatibleBitmap': 3, 'CreateCompatibleDC': 1, 'CreateDCA': 4,
        'CreateFontA': 14, 'CreateFontIndirectA': 1, 'CreateHatchBrush': 2,
        'CreatePalette': 1, 'CreatePen': 3, 'CreatePenIndirect': 1, 'CreatePatternBrush': 1,
        'CreateDIBPatternBrush': 2, 'CreateDIBPatternBrushPt': 2,
        'CreateSolidBrush': 1,
        'DeleteDC': 1, 'DeleteObject': 1, 'Ellipse': 5, 'EnumFontFamiliesA': 4, 'EnumFontsA': 4,
        'GetBkColor': 1, 'GetCharABCWidthsA': 4, 'GetCharABCWidthsW': 4,
        'GetCharWidth32A': 4, 'GetCharWidth32W': 4, 'GetCharWidthA': 4, 'GetCharWidthW': 4,
        'GetDIBColorTable': 4, 'SetDIBColorTable': 4, 'SetPaletteEntries': 4,
        'SetSystemPaletteUse': 2, 'GetDeviceCaps': 2, 'GetDeviceGammaRamp': 2,
        'SetDeviceGammaRamp': 2, 'GetDIBits': 7, 'GetNearestColor': 2,
        'GetObjectA': 3, 'GetPixel': 3, 'RestoreDC': 2, 'SaveDC': 1,
        'GetStockObject': 1, 'GetTextColor': 1, 'GetTextExtentPoint32A': 4,
        'GetTextExtentPoint32W': 4, 'GetTextExtentPointA': 4, 'GetTextExtentPointW': 4,
        'GetTextMetricsA': 2, 'LineTo': 3, 'MoveToEx': 4, 'PatBlt': 6, 'Pie': 9, 'Polygon': 3,
        'Polyline': 3, 'RealizePalette': 1, 'Rectangle': 5, 'RoundRect': 7, 'SelectObject': 2,
        'SelectPalette': 3, 'SetBkColor': 2, 'SetBkMode': 2, 'SetPixel': 4, 'SetROP2': 2,
        'SetStretchBltMode': 2, 'SetTextAlign': 2, 'SetTextColor': 2, 'StretchBlt': 11,
        'StretchDIBits': 13, 'TextOutA': 5, 'TextOutW': 5,
        'ExtTextOutA': 8, 'ExtTextOutW': 8,
        'TabbedTextOutA': 8, 'TabbedTextOutW': 8,
        'GetTabbedTextExtentA': 5, 'GetTabbedTextExtentW': 5,
        # kernel32
        'AllocConsole': 0, 'Beep': 2, 'CloseHandle': 1, 'CompareStringA': 6, 'CopyFileA': 3,
        'CopyFileW': 3, 'CreateDirectoryA': 2, 'CreateDirectoryW': 2, 'CreateFileA': 7,
        'CreateFileW': 7, 'CreateProcessA': 10, 'DeleteCriticalSection': 1, 'DeleteFileA': 1,
        'DeleteFileW': 1, 'EnterCriticalSection': 1, 'ExitProcess': 1,
        'ExpandEnvironmentStringsA': 3, 'FileTimeToLocalFileTime': 2,
        'FileTimeToSystemTime': 2, 'FindClose': 1, 'FindFirstFileA': 2, 'FindFirstFileW': 2,
        'FindNextFileA': 2, 'FindNextFileW': 2,
        'FindFirstStreamW': 4, 'FindNextStreamW': 2, 'FindResourceA': 3, 'FindResourceW': 3,
        'FindResourceExA': 4, 'FindResourceExW': 4, 'FlushFileBuffers': 1,
        'FormatMessageA': 7, 'FormatMessageW': 7, 'FreeConsole': 0,
        'FreeEnvironmentStringsA': 1, 'FreeEnvironmentStringsW': 1, 'FreeLibrary': 1,
        'FreeLibraryAndExitThread': 2, 'DisableThreadLibraryCalls': 1,
        'FreeResource': 1, 'GetACP': 0, 'GetCommandLineA': 0, 'GetCommandLineW': 0,
        'GetComputerNameA': 2, 'GetComputerNameW': 2, 'GetCPInfo': 2, 'GetCPInfoExA': 3,
        'GetCPInfoExW': 3, 'EnumSystemCodePagesA': 2, 'EnumSystemCodePagesW': 2,
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
        'InitializeCriticalSectionAndSpinCount': 2, 'IsDBCSLeadByte': 1, 'IsDBCSLeadByteEx': 2,
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
        'SetLocalTime': 1, 'SetUnhandledExceptionFilter': 1, 'SetVolumeLabelA': 2,
        'SetVolumeLabelW': 2,
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
        'Process32NextW': 2, 'Process32First': 2, 'Process32Next': 2, 'Module32First': 2,
        'Module32Next': 2, 'Module32FirstW': 2, 'Module32NextW': 2,
        'SetConsoleCtrlHandler': 2, 'SetConsoleMode': 2,
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
        'SafeArrayCreate': 3, 'SafeArrayCreateEx': 4, 'SafeArrayCreateVector': 3,
        'SafeArrayCreateVectorEx': 4, 'SafeArrayAllocDescriptor': 2,
        'SafeArrayAllocDescriptorEx': 3, 'SafeArrayAllocData': 1, 'SafeArrayDestroy': 1,
        'SafeArrayDestroyData': 1, 'SafeArrayDestroyDescriptor': 1, 'SafeArrayGetDim': 1,
        'SafeArrayGetElemsize': 1, 'SafeArrayGetUBound': 3, 'SafeArrayGetLBound': 3,
        'SafeArrayLock': 1, 'SafeArrayUnlock': 1, 'SafeArrayAccessData': 2,
        'SafeArrayUnaccessData': 1, 'SafeArrayPtrOfIndex': 3, 'SafeArrayGetElement': 3,
        'SafeArrayPutElement': 3, 'SafeArrayGetVartype': 2, 'SafeArrayCopyData': 2,
        'SafeArrayCopy': 2, 'SafeArrayRedim': 2,
        'VariantChangeTypeEx': 5, 'VariantChangeType': 4, 'VariantCopyInd': 2,
        'VarBstrFromI2': 4, 'VarBstrFromI4': 4, 'VarBstrFromR4': 4, 'VarBstrFromR8': 5,
        'VarBstrFromCy': 5, 'VarBstrFromDate': 5, 'VarBstrFromBool': 4, 'VarI2FromStr': 4,
        'VarI4FromStr': 4, 'VarR4FromStr': 4, 'VarR8FromStr': 4, 'VarCyFromStr': 4,
        'VarDateFromStr': 4, 'VarBoolFromStr': 4, 'VarUI1FromI2': 2, 'VarR4FromR8': 3,
        'VarI2FromI4': 2, 'VarI4FromR8': 3, 'VarCyFromI4': 2, 'VarCyFromR8': 3,
        'VarR8FromCy': 3, 'VariantTimeToDosDateTime': 4, 'DosDateTimeToVariantTime': 3,
        'LHashValOfNameSysA': 3, 'LHashValOfNameSys': 3, 'CreateErrorInfo': 1,
        'SetErrorInfo': 2, 'GetErrorInfo': 2, 'DispGetIDsOfNames': 4, 'DispInvoke': 8,
        'CreateILockBytesOnHGlobal': 3, 'GetHGlobalFromILockBytes': 2,
        'StgCreateDocfileOnILockBytes': 4, 'StgOpenStorageOnILockBytes': 6,
        'StgIsStorageILockBytes': 1,
        # shell32
        'ExtractIconA': 3, 'ExtractIconExA': 5, 'ExtractIconExW': 5, 'SHBrowseForFolderA': 1,
        # (the shell32 names without A/W are the ANSI functions)
        'ExtractIconEx': 5, 'SHGetFileInfo': 5, 'SHGetPathFromIDList': 2,
        'DllGetClassObject': 3, 'DllCanUnloadNow': 0,
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
        'DefFrameProcA': 5, 'DefFrameProcW': 5, 'DefMDIChildProcA': 4, 'DefMDIChildProcW': 4,
        'CreateMDIWindowA': 10, 'CreateMDIWindowW': 10, 'TranslateMDISysAccel': 2,
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
        'RegisterWindowMessageA': 1, 'RegisterWindowMessageW': 1, 'ReleaseCapture': 0,
        'ReleaseDC': 2, 'ScreenToClient': 2,
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
        'MapVirtualKeyExA': 3, 'MapVirtualKeyExW': 3, 'MapVirtualKeyW': 2,
        'ModifyMenuW': 5, 'MonitorFromPoint': 3, 'MonitorFromRect': 2,
        'MonitorFromWindow': 2, 'NativeWndProc': 4, 'NativeEditProc': 4, 'NativeButtonProc': 4,
        'NativeStaticProc': 4, 'NativeListBoxProc': 4, 'NativeComboBoxProc': 4, 'OpenClipboard': 1,
        'RegisterClipboardFormatA': 1, 'RegisterClipboardFormatW': 1, 'RemoveMenu': 3,
        'SendDlgItemMessageA': 5, 'SendDlgItemMessageW': 5, 'SetClipboardData': 2,
        'SetMenuItemInfoA': 4, 'SetMenuItemInfoW': 4, 'SetParent': 2,
        'SystemParametersInfoW': 4, 'TrackPopupMenu': 7, 'TrackPopupMenuEx': 6,
        'TranslateAcceleratorA': 3, 'TranslateAcceleratorW': 3, 'UnregisterClassA': 2,
        'UnregisterClassW': 2, 'WindowFromPoint': 2, 'WinHelpA': 4, 'WinHelpW': 4,
        # user32: window classes, messages, images, regions (NSIS installers)
        'DrawFocusRect': 2, 'FindWindowExA': 4, 'FindWindowExW': 4, 'GetClassLongA': 2,
        'GetClassLongW': 2, 'GetMessagePos': 0, 'GetSystemMenu': 2, 'LoadImageA': 6,
        'LoadImageW': 6, 'MapWindowPoints': 4, 'MessageBoxIndirectA': 1,
        'MessageBoxIndirectW': 1, 'SendMessageTimeoutA': 7, 'SendMessageTimeoutW': 7,
        'SetClassLongA': 3, 'SetClassLongW': 3, 'SetWindowRgn': 3,
        # Setup programs: lz32, mpr, version, and their gdi32, kernel32, user32 extras
        'CopyLZFile': 2, 'GetExpandedNameA': 2, 'GetExpandedNameW': 2, 'LZClose': 1,
        'LZCopy': 2, 'LZDone': 0, 'LZInit': 1, 'LZOpenFileA': 3, 'LZOpenFileW': 3,
        'LZRead': 3, 'LZSeek': 3, 'LZStart': 0,
        'WNetAddConnection2A': 4, 'WNetAddConnectionA': 3, 'WNetCancelConnection2A': 3,
        'WNetCancelConnectionA': 2, 'WNetConnectionDialog': 2, 'WNetGetConnectionA': 3,
        'WNetGetLastErrorA': 5, 'WNetAddConnection2W': 4, 'WNetAddConnectionW': 3,
        'WNetAddConnection3A': 5, 'WNetAddConnection3W': 5, 'WNetUseConnectionA': 8,
        'WNetUseConnectionW': 8, 'WNetCancelConnection2W': 3, 'WNetCancelConnectionW': 2,
        'WNetGetConnectionW': 3, 'WNetGetLastErrorW': 5, 'WNetOpenEnumA': 5,
        'WNetOpenEnumW': 5, 'WNetEnumResourceA': 4, 'WNetEnumResourceW': 4,
        'WNetCloseEnum': 1, 'WNetGetResourceParentA': 3, 'WNetGetResourceParentW': 3,
        'WNetGetResourceInformationA': 4, 'WNetGetResourceInformationW': 4,
        'WNetGetNetworkInformationA': 2, 'WNetGetNetworkInformationW': 2,
        'VerFindFileA': 8, 'VerInstallFileA': 8,
        'CreateDIBitmap': 6, 'CreateDiscardableBitmap': 3, 'CreateScalableFontResourceA': 4,
        'CreateScalableFontResourceW': 4, 'DPtoLP': 3, 'GetMapMode': 1, 'LPtoDP': 3,
        'SetMapMode': 2, 'SetMapperFlags': 2,
        'CreatePipe': 4, 'FlushViewOfFile': 2, 'PeekConsoleInputA': 4,
        'PeekConsoleInputW': 4, 'ReadConsoleInputA': 4, 'ReadConsoleInputW': 4, 'WinExec': 2,
        'DefDlgProcA': 4, 'DefDlgProcW': 4, 'ExcludeUpdateRgn': 2, 'FreeDDElParam': 2,
        'HideCaret': 1, 'PackDDElParam': 3, 'ReuseDDElParam': 5, 'SetActiveWindow': 1,
        'ShowCaret': 1, 'UnpackDDElParam': 4,
        'CreateCaret': 4, 'DestroyCaret': 0, 'SetCaretPos': 2, 'GetCaretPos': 1,
        'SetCaretBlinkTime': 1,
        'GetClassFile': 2, 'OleGetAutoConvert': 2, 'OleSetAutoConvert': 2,
        'LoadTypeLib': 2, 'LoadTypeLibEx': 3, 'RegisterTypeLib': 3, 'UnRegisterTypeLib': 5,
        'QueryPathOfRegTypeLib': 5, 'LoadRegTypeLib': 5,
        # user32: DDEML
        'DdeAbandonTransaction': 3, 'DdeAccessData': 2, 'DdeAddData': 4,
        'DdeClientTransaction': 8, 'DdeCmpStringHandles': 2, 'DdeConnect': 4,
        'DdeConnectList': 5, 'DdeCreateDataHandle': 7, 'DdeCreateStringHandleA': 3,
        'DdeCreateStringHandleW': 3, 'DdeDisconnect': 1, 'DdeDisconnectList': 1,
        'DdeEnableCallback': 3, 'DdeFreeDataHandle': 1, 'DdeFreeStringHandle': 2,
        'DdeGetData': 4, 'DdeGetLastError': 1, 'DdeImpersonateClient': 1,
        'DdeInitializeA': 4, 'DdeInitializeW': 4, 'DdeKeepStringHandle': 2,
        'DdeNameService': 4, 'DdePostAdvise': 3, 'DdeQueryConvInfo': 3,
        'DdeQueryNextServer': 2, 'DdeQueryStringA': 5, 'DdeQueryStringW': 5,
        'DdeReconnect': 1, 'DdeSetUserHandle': 3, 'DdeUnaccessData': 1,
        'DdeUninitialize': 1,
        # kernel32: paths and INI files
        'GetLongPathNameA': 3, 'GetLongPathNameW': 3, 'GetPrivateProfileIntA': 4,
        'GetPrivateProfileIntW': 4, 'GetShortPathNameA': 3, 'GetShortPathNameW': 3,
        'SearchPathA': 6, 'SearchPathW': 6,
        # version
        'GetFileVersionInfoA': 4, 'GetFileVersionInfoSizeA': 2,
        'GetFileVersionInfoSizeW': 2, 'GetFileVersionInfoW': 4, 'VerQueryValueA': 4,
        'VerQueryValueW': 4,
        # winmm
        'joyGetDevCapsA': 3, 'joyGetDevCapsW': 3, 'joyGetNumDevs': 0, 'joyGetPos': 2,
        'joyGetPosEx': 2, 'mciGetDeviceIDA': 1, 'mciGetErrorStringA': 3,
        'mciSendCommandA': 4, 'mciSendStringA': 4, 'midiOutClose': 1,
        'midiOutGetDevCapsA': 3, 'midiOutGetDevCapsW': 3, 'midiOutGetNumDevs': 0,
        'midiOutLongMsg': 3, 'midiOutOpen': 5, 'midiOutPrepareHeader': 3, 'midiOutReset': 1,
        'midiOutShortMsg': 2, 'midiOutUnprepareHeader': 3, 'mmioClose': 2, 'mmioInstallIOProcA': 3,
        'mmioInstallIOProcW': 3,
        'mmioOpenA': 3, 'mmioRead': 3, 'mmioSeek': 3, 'mmioStringToFOURCCA': 2, 'mmioWrite': 3,
        'waveOutGetNumDevs': 0, 'PlaySoundA': 3, 'PlaySound': 3,
        'PlaySoundW': 3, 'sndPlaySoundA': 2, 'sndPlaySoundW': 2, 'timeBeginPeriod': 1,
        'timeGetDevCaps': 2,
        'timeEndPeriod': 1, 'timeGetTime': 0, 'timeSetEvent': 5, 'timeKillEvent': 1,
        'MmTimerThreadProc': 1, 'waveOutClose': 1, 'waveOutGetPosition': 3,
        'waveOutOpen': 6, 'waveOutPause': 1, 'waveOutPrepareHeader': 3, 'waveOutReset': 1,
        'waveOutRestart': 1, 'waveOutUnprepareHeader': 3, 'waveOutWrite': 3,
        # advapi32: security, CryptoAPI, services, event log, ETW, more registry
        'AddAccessAllowedAce': 4, 'AddAccessAllowedAceEx': 5, 'AddAccessDeniedAce': 4,
        'AddAccessDeniedAceEx': 5, 'AllocateAndInitializeSid': 11, 'ChangeServiceConfig2A': 3,
        'ChangeServiceConfig2W': 3, 'ChangeServiceConfigA': 11, 'ChangeServiceConfigW': 11,
        'CheckTokenMembership': 3, 'CloseEventLog': 1, 'CloseServiceHandle': 1,
        'ControlService': 3, 'ConvertSidToStringSidA': 2, 'ConvertSidToStringSidW': 2,
        'ConvertStringSecurityDescriptorToSecurityDescriptorA': 4,
        'ConvertStringSecurityDescriptorToSecurityDescriptorW': 4, 'ConvertStringSidToSidA': 2,
        'ConvertStringSidToSidW': 2, 'CopySid': 3, 'CreateServiceA': 13, 'CreateServiceW': 13,
        'CreateWellKnownSid': 4, 'CryptAcquireContextA': 5, 'CryptAcquireContextW': 5,
        'CryptContextAddRef': 3, 'CryptCreateHash': 5, 'CryptDestroyHash': 1,
        'CryptDuplicateHash': 4, 'CryptGenRandom': 3, 'CryptGetHashParam': 5,
        'CryptHashData': 4, 'CryptReleaseContext': 2, 'DeleteService': 1,
        'DeregisterEventSource': 1, 'DuplicateToken': 3, 'DuplicateTokenEx': 6,
        'EnumServicesStatusA': 8, 'EnumServicesStatusW': 8, 'EqualPrefixSid': 2, 'EqualSid': 2,
        'EventActivityIdControl': 2, 'EventEnabled': 3, 'EventProviderEnabled': 5,
        'EventRegister': 4, 'EventSetInformation': 5, 'EventUnregister': 2, 'EventWrite': 5,
        'EventWriteString': 6, 'EventWriteTransfer': 7, 'FreeSid': 1, 'GetAce': 3,
        'GetAclInformation': 4, 'GetCurrentHwProfileA': 1, 'GetCurrentHwProfileW': 1,
        'GetFileSecurityA': 5, 'GetLengthSid': 1, 'GetNamedSecurityInfoA': 8,
        'GetNamedSecurityInfoW': 8, 'GetNumberOfEventLogRecords': 2,
        'GetOldestEventLogRecord': 2, 'GetSecurityDescriptorControl': 3,
        'GetSecurityDescriptorDacl': 4, 'GetSecurityDescriptorGroup': 3,
        'GetSecurityDescriptorLength': 1, 'GetSecurityDescriptorOwner': 3,
        'GetSecurityDescriptorSacl': 4, 'GetSecurityInfo': 8, 'GetSidIdentifierAuthority': 1,
        'GetSidLengthRequired': 1, 'GetSidSubAuthority': 2, 'GetSidSubAuthorityCount': 1,
        'GetTokenInformation': 5, 'ImpersonateLoggedOnUser': 1, 'ImpersonateSelf': 1,
        'InitializeAcl': 3, 'InitializeSecurityDescriptor': 2, 'InitializeSid': 3,
        'IsValidAcl': 1, 'IsValidSecurityDescriptor': 1, 'IsValidSid': 1, 'IsWellKnownSid': 2,
        'LookupAccountNameA': 7, 'LookupAccountSidA': 7, 'LookupAccountSidW': 7,
        'LookupPrivilegeNameA': 4, 'LookupPrivilegeNameW': 4, 'OpenEventLogA': 2,
        'OpenEventLogW': 2, 'OpenSCManagerA': 3, 'OpenSCManagerW': 3, 'OpenServiceA': 3,
        'OpenServiceW': 3, 'OpenThreadToken': 4, 'QueryServiceConfigA': 4,
        'QueryServiceConfigW': 4, 'QueryServiceStatus': 2, 'QueryServiceStatusEx': 5,
        'ReadEventLogA': 7, 'ReadEventLogW': 7, 'RegConnectRegistryA': 3,
        'RegConnectRegistryW': 3, 'RegCreateKeyA': 3, 'RegCreateKeyW': 3, 'RegDeleteKeyExA': 4,
        'RegDeleteKeyExW': 4, 'RegDeleteKeyValueA': 3, 'RegDeleteKeyValueW': 3,
        'RegDeleteTreeA': 2, 'RegDeleteTreeW': 2, 'RegDisablePredefinedCache': 0,
        'RegDisablePredefinedCacheEx': 0, 'RegGetValueA': 7, 'RegGetValueW': 7,
        'RegNotifyChangeKeyValue': 5, 'RegOpenCurrentUser': 2, 'RegOpenKeyA': 3,
        'RegOpenKeyW': 3, 'RegQueryInfoKeyA': 12, 'RegQueryInfoKeyW': 12, 'RegQueryValueA': 4,
        'RegQueryValueW': 4, 'RegSetKeyValueA': 6, 'RegSetKeyValueW': 6, 'RegSetValueA': 5,
        'RegSetValueW': 5, 'RegisterEventSourceA': 2, 'RegisterEventSourceW': 2,
        'RegisterServiceCtrlHandlerA': 2, 'RegisterServiceCtrlHandlerW': 2,
        'RegisterServiceCtrlHandlerExA': 3, 'RegisterServiceCtrlHandlerExW': 3,
        'ReportEventA': 9, 'ReportEventW': 9, 'RevertToSelf': 0, 'SetEntriesInAclA': 4,
        'SetEntriesInAclW': 4, 'SetFileSecurityA': 3, 'SetNamedSecurityInfoA': 7,
        'SetNamedSecurityInfoW': 7, 'SetSecurityDescriptorDacl': 4,
        'SetSecurityDescriptorGroup': 3, 'SetSecurityDescriptorOwner': 3,
        'SetSecurityDescriptorSacl': 4, 'SetSecurityInfo': 7, 'SetServiceStatus': 2,
        'SetTokenInformation': 4, 'StartServiceA': 3, 'StartServiceW': 3,
        'StartServiceCtrlDispatcherA': 1, 'StartServiceCtrlDispatcherW': 1,
        # bcrypt
        'BCryptCloseAlgorithmProvider': 2, 'BCryptCreateHash': 7, 'BCryptDestroyHash': 1,
        'BCryptFinishHash': 4, 'BCryptGenRandom': 4, 'BCryptGetProperty': 6,
        'BCryptHashData': 4, 'BCryptOpenAlgorithmProvider': 4,
        # comctl32
        'DefSubclassProc': 4, 'GetWindowSubclass': 4, 'RemoveWindowSubclass': 3,
        'SetWindowSubclass': 4, 'SubclassWndProc': 4, '_TrackMouseEvent': 1,
        # dwmapi
        'DwmDefWindowProc': 5, 'DwmEnableBlurBehindWindow': 2, 'DwmEnableComposition': 1,
        'DwmExtendFrameIntoClientArea': 2, 'DwmFlush': 0, 'DwmGetColorizationColor': 2,
        'DwmGetWindowAttribute': 4, 'DwmIsCompositionEnabled': 1, 'DwmSetWindowAttribute': 4,
        # iphlpapi, sensapi, wininet, urlmon
        'GetAdaptersAddresses': 5, 'GetAdaptersInfo': 2, 'GetBestInterface': 2,
        'GetNumberOfInterfaces': 1, 'IsNetworkAlive': 1, 'IsDestinationReachableA': 2,
        'IsDestinationReachableW': 2, 'InternetAttemptConnect': 1,
        'InternetCheckConnectionA': 3, 'InternetCheckConnectionW': 3, 'InternetCloseHandle': 1,
        'InternetConnectA': 8, 'InternetConnectW': 8, 'InternetGetConnectedState': 2,
        'InternetGetConnectedStateExA': 4, 'InternetGetConnectedStateExW': 4,
        'InternetOpenA': 5, 'InternetOpenW': 5, 'InternetOpenUrlA': 6, 'InternetOpenUrlW': 6,
        'InternetReadFile': 4, 'URLDownloadToCacheFileA': 6, 'URLDownloadToCacheFileW': 6,
        'URLDownloadToFileA': 5, 'URLDownloadToFileW': 5,
        # kernel32: atoms, versions, system information, files, handles, memory, console
        'AddAtomA': 1, 'AddAtomW': 1, 'AttachConsole': 1, 'CreateDirectoryExA': 3,
        'CreateDirectoryExW': 3, 'DeleteAtom': 1, 'DuplicateHandle': 7,
        'FillConsoleOutputAttribute': 5, 'FillConsoleOutputCharacterA': 5,
        'FillConsoleOutputCharacterW': 5, 'FindAtomA': 1, 'FindAtomW': 1,
        'FlushConsoleInputBuffer': 1, 'FlushInstructionCache': 3,
        'GenerateConsoleCtrlEvent': 2, 'GetActiveProcessorCount': 1,
        'GetActiveProcessorGroupCount': 0, 'GetAtomNameA': 3, 'GetAtomNameW': 3,
        'GetComputerNameExA': 3, 'GetComputerNameExW': 3, 'GetConsoleCursorInfo': 2,
        'GetConsoleTitleA': 2, 'GetConsoleTitleW': 2, 'GetConsoleWindow': 0,
        'GetCurrentProcessorNumber': 0, 'GetFileAttributesExA': 3, 'GetFileAttributesExW': 3,
        'GetFileTime': 4, 'GetHandleInformation': 2, 'GetLargestConsoleWindowSize': 1,
        'GetLogicalProcessorInformation': 2, 'GetMaximumProcessorCount': 1,
        'GetNumberOfConsoleInputEvents': 2, 'GetPrivateProfileSectionA': 4,
        'GetPrivateProfileSectionW': 4, 'GetPrivateProfileSectionNamesA': 3,
        'GetPrivateProfileSectionNamesW': 3, 'GetPrivateProfileStringW': 6,
        'GetPrivateProfileStructA': 5, 'GetPrivateProfileStructW': 5, 'GetProcessHeaps': 2,
        'GetProcessId': 1, 'GetProcessIdOfThread': 1, 'GetProcessVersion': 1,
        'GetProcessWorkingSetSize': 3, 'GetProcessWorkingSetSizeEx': 4, 'GetProductInfo': 5,
        'GetProfileIntA': 3, 'GetProfileIntW': 3, 'GetProfileSectionA': 3,
        'GetProfileSectionW': 3, 'GetProfileStringA': 5, 'GetProfileStringW': 5,
        'GetSystemDefaultUILanguage': 0, 'GetSystemPowerStatus': 1, 'GetSystemTimes': 3,
        'GetSystemWindowsDirectoryA': 2, 'GetSystemWindowsDirectoryW': 2,
        'GetSystemWow64DirectoryA': 2, 'GetSystemWow64DirectoryW': 2, 'GetThreadId': 1,
        'GetThreadLocale': 0, 'GetThreadTimes': 5, 'GetThreadUILanguage': 0,
        'GetUserDefaultUILanguage': 0, 'GlobalAddAtomA': 1, 'GlobalAddAtomW': 1,
        'GlobalCompact': 1, 'GlobalDeleteAtom': 1, 'GlobalFindAtomA': 1, 'GlobalFindAtomW': 1,
        'GlobalFix': 1, 'GlobalFlags': 1, 'GlobalGetAtomNameA': 3, 'GlobalGetAtomNameW': 3,
        'GlobalHandle': 1, 'GlobalReAlloc': 3, 'GlobalUnWire': 1, 'GlobalUnfix': 1,
        'GlobalWire': 1, 'HeapCompact': 2, 'HeapLock': 1, 'HeapQueryInformation': 5,
        'HeapSetInformation': 4, 'HeapUnlock': 1, 'HeapValidate': 3, 'HeapWalk': 2,
        'InitAtomTable': 1, 'IsBadCodePtr': 1, 'IsBadHugeReadPtr': 2, 'IsBadHugeWritePtr': 2,
        'IsBadReadPtr': 2, 'IsBadStringPtrA': 2, 'IsBadStringPtrW': 2, 'IsBadWritePtr': 2,
        'IsWow64Process': 2, 'IsWow64Process2': 3, 'K32EmptyWorkingSet': 1,
        'K32EnumProcessModules': 4, 'K32EnumProcessModulesEx': 5, 'K32EnumProcesses': 3,
        'K32GetModuleBaseNameA': 4, 'K32GetModuleBaseNameW': 4, 'K32GetModuleFileNameExA': 4,
        'K32GetModuleFileNameExW': 4, 'K32GetModuleInformation': 4, 'K32GetPerformanceInfo': 2,
        'K32GetProcessImageFileNameA': 3, 'K32GetProcessImageFileNameW': 3,
        'K32GetProcessMemoryInfo': 3, 'LocalCompact': 1, 'LocalFlags': 1, 'LocalHandle': 1,
        'LocalLock': 1, 'LocalReAlloc': 3, 'LocalShrink': 2, 'LocalSize': 1, 'LocalUnlock': 1,
        'LockFile': 5, 'LockFileEx': 6, 'OpenFile': 3, 'QueryFullProcessImageNameA': 4,
        'QueryFullProcessImageNameW': 4, 'SetConsoleCP': 1, 'SetConsoleCursorInfo': 2,
        'SetConsoleCursorPosition': 2, 'SetConsoleOutputCP': 1,
        'SetConsoleScreenBufferSize': 2, 'SetConsoleTextAttribute': 2,
        'SetConsoleWindowInfo': 3, 'SetHandleInformation': 3, 'SetProcessWorkingSetSize': 3,
        'SetProcessWorkingSetSizeEx': 4, 'SetThreadExecutionState': 1, 'SetThreadLocale': 1,
        'SetThreadUILanguage': 1, 'SleepEx': 2, 'UnlockFile': 5, 'UnlockFileEx': 5,
        'VerSetConditionMask': 4, 'VerifyVersionInfoA': 4, 'VerifyVersionInfoW': 4,
        'VirtualLock': 2, 'VirtualUnlock': 2, 'Wow64DisableWow64FsRedirection': 1,
        'Wow64EnableWow64FsRedirection': 1,
        'Wow64RevertWow64FsRedirection': 1, 'WritePrivateProfileSectionA': 3,
        'WritePrivateProfileSectionW': 3, 'WritePrivateProfileStringW': 4,
        'WritePrivateProfileStructA': 5, 'WritePrivateProfileStructW': 5,
        'WriteProfileSectionA': 2, 'WriteProfileSectionW': 2, 'WriteProfileStringA': 3,
        'WriteProfileStringW': 3, '_hread': 3, '_hwrite': 3, '_lclose': 1, '_lcreat': 2,
        '_llseek': 3, '_lopen': 2, '_lread': 3, '_lwrite': 3, 'lstrcpynW': 3,
        # Word 95: kernel32, user32 and winspool (WindowsExtraMixin)
        'TerminateThread': 2, 'DebugBreak': 0, 'QueryDosDeviceA': 3, 'QueryDosDeviceW': 3,
        'BeginDeferWindowPos': 1, 'DeferWindowPos': 8, 'EndDeferWindowPos': 1,
        'ArrangeIconicWindows': 1, 'ScrollWindow': 5, 'ScrollWindowEx': 8, 'ScrollDC': 7,
        'ChangeMenuA': 5, 'ChangeMenuW': 5, 'CallMsgFilterA': 2, 'CallMsgFilterW': 2,
        'GetCaretBlinkTime': 0, 'GetClipboardOwner': 0, 'GetClipboardFormatNameA': 3,
        'GetClipboardFormatNameW': 3, 'CreateAcceleratorTableA': 2,
        'OpenPrinterA': 3, 'OpenPrinterW': 3, 'ClosePrinter': 1, 'GetPrinterA': 5,
        'GetPrinterW': 5, 'GetPrinterDriverA': 6, 'GetPrinterDriverW': 6,
        'DocumentPropertiesA': 6, 'DocumentPropertiesW': 6, 'DeviceCapabilitiesA': 5,
        'DeviceCapabilitiesW': 5,
        # Word 95: gdi32 (GdiExtraMixin)
        'SetWindowOrgEx': 4, 'SetViewportOrgEx': 4, 'SetWindowExtEx': 4, 'SetViewportExtEx': 4,
        'GetWindowOrgEx': 2, 'GetViewportOrgEx': 2, 'GetWindowExtEx': 2, 'GetViewportExtEx': 2,
        'OffsetViewportOrgEx': 4, 'OffsetWindowOrgEx': 4, 'ScaleViewportExtEx': 6,
        'SetBrushOrgEx': 4, 'FixBrushOrgEx': 4, 'GetBrushOrgEx': 2, 'GetBkMode': 1,
        'RectVisible': 2,
        'GdiFlush': 0, 'GdiSetBatchLimit': 1, 'GdiGetBatchLimit': 0, 'UnrealizeObject': 1,
        'GetObjectType': 1, 'SetRectRgn': 5,
        'OffsetRgn': 3, 'CreatePolygonRgn': 3, 'FillRgn': 3, 'InvertRgn': 2,
        'CreateBitmapIndirect': 1, 'GetBitmapBits': 3, 'SetBitmapBits': 3,
        'SetBitmapDimensionEx': 4, 'GetBitmapDimensionEx': 2, 'SetDIBitsToDevice': 12,
        'TranslateCharsetInfo': 3,
        'GetTextFaceA': 3, 'GetTextFaceW': 3, 'GetKerningPairsA': 3, 'GetKerningPairsW': 3,
        'GetOutlineTextMetricsA': 3, 'GetOutlineTextMetricsW': 3, 'GetGlyphOutlineA': 7,
        'GetGlyphOutlineW': 7, 'CreateICA': 4, 'ResetDCA': 2, 'ResetDCW': 2, 'StartDocA': 2,
        'StartDocW': 2, 'EndDoc': 1, 'StartPage': 1, 'EndPage': 1, 'AbortDoc': 1,
        'SetAbortProc': 2, 'Escape': 5, 'ExtEscape': 6, 'CreateMetaFileA': 1,
        'CreateMetaFileW': 1, 'CloseMetaFile': 1, 'SetMetaFileBitsEx': 2,
        'GetMetaFileBitsEx': 3, 'DeleteMetaFile': 1, 'PlayMetaFile': 2, 'EnumMetaFile': 4,
        'PlayMetaFileRecord': 4,
        # Word 95: ole32 structured storage (OleStorageMixin)
        'StgCreateDocfile': 4, 'StgOpenStorage': 6, 'StgIsStorageFile': 1,
        'CreateStreamOnHGlobal': 3, 'GetHGlobalFromStream': 2, 'WriteClassStm': 2,
        'ReadClassStm': 2, 'WriteClassStg': 2, 'ReadClassStg': 2, 'WriteFmtUserTypeStg': 3,
        'ReadFmtUserTypeStg': 3, 'GetConvertStg': 1, 'SetConvertStg': 2, 'OleSave': 3,
        'OleSaveToStream': 2,
        # Word 95: more of ole32 (OleMiscMixin)
        'OleBuildVersion': 0, 'CoIsOle1Class': 1, 'CoDisconnectObject': 2,
        'OleQueryCreateFromData': 1, 'OleQueryLinkFromData': 1, 'CoGetTreatAsClass': 2,
        'CoTreatAsClass': 2, 'OleRegGetMiscStatus': 3, 'OleRegEnumVerbs': 2,
        'OleRegEnumFormatEtc': 3, 'OleRun': 1, 'OleIsRunning': 1, 'OleCreate': 7,
        'OleCreateFromFile': 8, 'OleCreateLink': 7, 'OleCreateLinkToFile': 7,
        'OleCreateFromData': 7, 'OleCreateLinkFromData': 7, 'OleLoad': 4, 'BindMoniker': 4,
        'OleCreateDefaultHandler': 4, 'CreateDataCache': 4, 'OleConvertOLESTREAMToIStorage': 3,
        'OleConvertIStorageToOLESTREAM': 2, 'OleCreateMenuDescriptor': 2,
        'OleDestroyMenuDescriptor': 1, 'OleSetMenuDescriptor': 5, 'OleTranslateAccelerator': 3,
        'OleDuplicateData': 3, 'OleSetClipboard': 1, 'OleFlushClipboard': 0,
        'OleIsCurrentClipboard': 1, 'OleGetClipboard': 1, 'CreateDataAdviseHolder': 1,
        'CreateOleAdviseHolder': 1, 'CreateBindCtx': 2, 'GetRunningObjectTable': 2,
        'CreateFileMoniker': 2, 'CreateItemMoniker': 3, 'CreateGenericComposite': 3,
        'MkParseDisplayName': 4,
        # Word 95's MSO95.DLL
        'CreateDIBSection': 6, 'CreateHalftonePalette': 1, 'GetPaletteEntries': 4,
        'GetNearestPaletteIndex': 2, 'GetSystemPaletteEntries': 4, 'GetSystemPaletteUse': 1,
        'GetCurrentObject': 2, 'SetTextCharacterExtra': 2, 'GetTextCharacterExtra': 1,
        'GetTextExtentExPointA': 7, 'GetTextExtentExPointW': 7, 'GetMetaFileA': 1,
        'GetMetaFileW': 1, 'SetWinMetaFileBits': 4, 'GetEnhMetaFileA': 1, 'GetEnhMetaFileW': 1,
        'DeleteEnhMetaFile': 1, 'GetEnhMetaFilePaletteEntries': 3, 'PlayEnhMetaFile': 3,
        'GetBinaryTypeA': 2, 'GetBinaryTypeW': 2, 'CreateIconFromResourceEx': 7,
        'CreateIconFromResource': 4, 'CreateIconIndirect': 1, 'PostThreadMessageA': 4,
        'PostThreadMessageW': 4, 'WindowFromDC': 1, 'OleGetIconOfClass': 3,
        # ntdll
        'NtClose': 1, 'NtDelayExecution': 2, 'NtQuerySystemTime': 1,
        'NtSetInformationFile': 5, 'NtYieldExecution': 0,
        'RtlCompareMemory': 3, 'RtlCopyMemory': 3, 'RtlFillMemory': 3,
        'RtlGetLastWin32Error': 0, 'RtlGetNtVersionNumbers': 3, 'RtlGetVersion': 1,
        'RtlInitAnsiString': 2, 'RtlInitString': 2, 'RtlInitUnicodeString': 2,
        'RtlMoveMemory': 3, 'RtlNtStatusToDosError': 1, 'RtlRandom': 1, 'RtlRandomEx': 1,
        'RtlSetLastWin32Error': 1, 'RtlUniform': 1, 'RtlZeroMemory': 2,
        # ole32
        'CLSIDFromProgID': 2, 'CLSIDFromProgIDEx': 2, 'CLSIDFromString': 2,
        'CoAddRefServerProcess': 0, 'CoCreateGuid': 1, 'CoFileTimeNow': 1,
        'CoFreeAllLibraries': 0, 'CoFreeUnusedLibraries': 0, 'CoFreeUnusedLibrariesEx': 2,
        'CoGetCurrentProcess': 0, 'CoGetMalloc': 2, 'CoInitializeEx': 2,
        'CoInitializeSecurity': 9, 'CoLockObjectExternal': 3, 'CoRegisterClassObject': 5,
        'CoGetClassObject': 5,
        'CoRegisterMessageFilter': 2, 'CoReleaseServerProcess': 0, 'CoRevokeClassObject': 1,
        'CoSetProxyBlanket': 8, 'CoWaitForMultipleHandles': 5, 'IIDFromString': 2,
        'ProgIDFromCLSID': 2, 'StringFromCLSID': 2, 'StringFromGUID2': 3, 'StringFromIID': 2,
        # psapi
        'EmptyWorkingSet': 1, 'EnumProcessModules': 4, 'EnumProcessModulesEx': 5,
        'EnumProcesses': 3, 'GetMappedFileNameA': 4, 'GetMappedFileNameW': 4,
        'GetModuleBaseNameA': 4, 'GetModuleBaseNameW': 4, 'GetModuleFileNameExA': 4,
        'GetModuleFileNameExW': 4, 'GetModuleInformation': 4, 'GetPerformanceInfo': 2,
        'GetProcessImageFileNameA': 3, 'GetProcessImageFileNameW': 3,
        'GetProcessMemoryInfo': 3,
        # rpcrt4
        'RpcStringFreeA': 1, 'RpcStringFreeW': 1, 'UuidCompare': 3, 'UuidCreate': 1,
        'UuidCreateNil': 1, 'UuidCreateSequential': 1, 'UuidEqual': 3, 'UuidFromStringA': 2,
        'UuidFromStringW': 2, 'UuidHash': 2, 'UuidIsNil': 2, 'UuidToStringA': 2,
        'UuidToStringW': 2,
        # secur32
        'GetUserNameExA': 3, 'GetUserNameExW': 3,
        # shcore
        'GetDpiForMonitor': 4, 'GetProcessDpiAwareness': 2, 'GetScaleFactorForMonitor': 2,
        'SetProcessDpiAwareness': 1,
        # shell32
        'CommandLineToArgvW': 2, 'DragAcceptFiles': 2, 'DragFinish': 1, 'DragQueryFileA': 4,
        'DragQueryFileW': 4, 'DragQueryPoint': 2, 'DuplicateIcon': 2,
        'ExtractAssociatedIconA': 3, 'ExtractAssociatedIconW': 3, 'FindExecutableA': 3,
        'FindExecutableW': 3, 'ILClone': 1, 'ILCreateFromPathA': 1, 'ILCreateFromPathW': 1,
        'ILFindLastID': 1, 'ILFree': 1, 'ILGetSize': 1, 'IsUserAnAdmin': 0,
        'SHAddToRecentDocs': 2, 'SHAppBarMessage': 2, 'SHCreateDirectory': 2,
        'SHCreateDirectoryExA': 3, 'SHCreateDirectoryExW': 3, 'SHEmptyRecycleBinA': 3,
        'SHEmptyRecycleBinW': 3, 'SHFreeNameMappings': 1, 'SHGetDiskFreeSpaceExA': 4,
        'SHGetDiskFreeSpaceExW': 4, 'SHGetFolderLocation': 5, 'SHGetFolderPathAndSubDirA': 6,
        'SHGetFolderPathAndSubDirW': 6, 'SHGetFolderPathEx': 5, 'SHGetKnownFolderIDList': 4,
        'SHGetKnownFolderPath': 4, 'SHGetSetSettings': 3, 'SHGetSettings': 2,
        'SHGetStockIconInfo': 3, 'SHILCreateFromPath': 3, 'SHParseDisplayName': 5,
        'SHQueryRecycleBinA': 2, 'SHQueryRecycleBinW': 2, 'ShellAboutA': 4, 'ShellAboutW': 4,
        'Shell_NotifyIconA': 2, 'Shell_NotifyIconW': 2,
        # shlwapi
        'ColorRGBToHLS': 4, 'GetMenuPosFromID': 2, 'PathAddBackslashA': 1,
        'PathAddBackslashW': 1, 'PathAddExtensionA': 2, 'PathAddExtensionW': 2,
        'PathAppendA': 2, 'PathAppendW': 2, 'PathBuildRootA': 2, 'PathBuildRootW': 2,
        'PathCanonicalizeA': 2, 'PathCanonicalizeW': 2, 'PathCombineA': 3, 'PathCombineW': 3,
        'PathFileExistsA': 1, 'PathFileExistsW': 1, 'PathFindExtensionA': 1,
        'PathFindExtensionW': 1, 'PathFindFileNameA': 1, 'PathFindFileNameW': 1,
        'PathFindNextComponentA': 1, 'PathFindNextComponentW': 1, 'PathGetArgsA': 1,
        'PathGetArgsW': 1, 'PathGetDriveNumberA': 1, 'PathGetDriveNumberW': 1,
        'PathIsDirectoryA': 1, 'PathIsDirectoryW': 1, 'PathIsFileSpecA': 1,
        'PathIsFileSpecW': 1, 'PathIsRelativeA': 1, 'PathIsRelativeW': 1, 'PathIsRootA': 1,
        'PathIsRootW': 1, 'PathIsUNCA': 1, 'PathIsUNCW': 1, 'PathIsURLA': 1, 'PathIsURLW': 1,
        'PathMatchSpecA': 2, 'PathMatchSpecW': 2, 'PathQuoteSpacesA': 1, 'PathQuoteSpacesW': 1,
        'PathRemoveBackslashA': 1, 'PathRemoveBackslashW': 1, 'PathRemoveExtensionA': 1,
        'PathRemoveExtensionW': 1, 'PathRemoveFileSpecA': 1, 'PathRemoveFileSpecW': 1,
        'PathRenameExtensionA': 2, 'PathRenameExtensionW': 2, 'PathSkipRootA': 1,
        'PathSkipRootW': 1, 'PathStripPathA': 1, 'PathStripPathW': 1, 'PathStripToRootA': 1,
        'PathStripToRootW': 1, 'PathUnquoteSpacesA': 1, 'PathUnquoteSpacesW': 1,
        'SHAutoComplete': 2, 'SHDeleteEmptyKeyA': 2, 'SHDeleteEmptyKeyW': 2, 'SHDeleteKeyA': 2,
        'SHDeleteKeyW': 2, 'SHDeleteValueA': 3, 'SHDeleteValueW': 3, 'SHGetValueA': 6,
        'SHGetValueW': 6, 'SHQueryValueExA': 6, 'SHQueryValueExW': 6, 'SHSetValueA': 6,
        'SHSetValueW': 6, 'SHStrDupA': 2, 'SHStrDupW': 2, 'StrCSpnA': 2, 'StrCSpnIA': 2,
        'StrCSpnIW': 2, 'StrCSpnW': 2, 'StrCatBuffA': 3, 'StrCatBuffW': 3, 'StrCatW': 2,
        'StrChrA': 2, 'StrChrIA': 2, 'StrChrIW': 2, 'StrChrW': 2, 'StrCmpIW': 2,
        'StrCmpLogicalW': 2, 'StrCmpNA': 3, 'StrCmpNIA': 3, 'StrCmpNIW': 3, 'StrCmpNW': 3,
        'StrCmpW': 2, 'StrCpyNW': 3, 'StrCpyW': 2, 'StrDupA': 1, 'StrDupW': 1,
        'StrFormatByteSize64A': 4, 'StrFormatByteSizeA': 3, 'StrFormatByteSizeEx': 5,
        'StrFormatByteSizeW': 4, 'StrFormatKBSizeA': 4, 'StrFormatKBSizeW': 4, 'StrNCatA': 3,
        'StrNCatW': 3, 'StrPBrkA': 2, 'StrPBrkW': 2, 'StrRChrA': 3, 'StrRChrIA': 3,
        'StrRChrIW': 3, 'StrRChrW': 3, 'StrSpnA': 2, 'StrSpnW': 2, 'StrStrA': 2, 'StrStrIA': 2,
        'StrStrIW': 2, 'StrStrW': 2, 'StrToInt64ExA': 3, 'StrToInt64ExW': 3, 'StrToIntA': 1,
        'StrToIntExA': 3, 'StrToIntExW': 3, 'StrToIntW': 1, 'StrTrimA': 2, 'StrTrimW': 2,
        'wvnsprintfA': 4, 'wvnsprintfW': 4,
        # imm32
        'ImmGetDefaultIMEWnd': 1, 'ImmGetContext': 1, 'ImmReleaseContext': 2,
        'ImmAssociateContext': 2, 'ImmIsIME': 1, 'ImmDisableIME': 1,
        'ImmGetOpenStatus': 1, 'ImmSetOpenStatus': 2,
        # user32
        'ActivateKeyboardLayout': 2, 'AdjustWindowRectExForDpi': 5, 'AnimateWindow': 3,
        'AreDpiAwarenessContextsEqual': 2, 'AttachThreadInput': 3, 'BlockInput': 1,
        'CallNextHookEx': 4, 'ChangeDisplaySettingsExA': 5, 'ChangeDisplaySettingsExW': 5,
        'ChangeDisplaySettingsW': 2, 'CharLowerBuffA': 2, 'CharLowerBuffW': 2, 'CharNextW': 1,
        'CharPrevW': 2, 'CharToOemA': 2, 'CharToOemBuffW': 3, 'CharToOemW': 2,
        'CharUpperBuffA': 2, 'CharUpperBuffW': 2, 'ClipCursor': 1, 'CloseDesktop': 1,
        'CloseWindowStation': 1, 'CopyIcon': 1, 'CreateDialogIndirectParamA': 5,
        'CreateDialogIndirectParamW': 5, 'DialogBoxIndirectParamA': 5,
        'DialogBoxIndirectParamW': 5, 'DragDetect': 3, 'DrawCaption': 4, 'DrawEdge': 4,
        'DrawFrameControl': 4, 'DrawIcon': 4, 'DrawIconEx': 9, 'DrawStateA': 10,
        'DrawStateW': 10, 'EnableNonClientDpiScaling': 1, 'EnableScrollBar': 3, 'EndMenu': 0,
        'EnumChildWindows': 3, 'EnumDesktopWindows': 3, 'EnumDisplayDevicesA': 4,
        'EnumDisplayDevicesW': 4, 'EnumDisplayMonitors': 4, 'EnumDisplaySettingsExA': 4,
        'EnumDisplaySettingsExW': 4, 'EnumDisplaySettingsW': 3, 'EnumPropsA': 2,
        'EnumPropsExA': 3, 'EnumPropsExW': 3, 'EnumPropsW': 2, 'EnumThreadWindows': 3,
        'EnumWindows': 2, 'FlashWindow': 2, 'FlashWindowEx': 1, 'GetAncestor': 2,
        'GetAwarenessFromDpiAwarenessContext': 1, 'GetClassWord': 2, 'GetClipCursor': 1,
        'GetComboBoxInfo': 2, 'GetCursorInfo': 1, 'GetDpiForSystem': 0, 'GetDpiForWindow': 1,
        'GetGUIThreadInfo': 2, 'GetIconInfo': 2, 'GetInputState': 0, 'GetKeyNameTextA': 3,
        'GetKeyNameTextW': 3, 'GetKeyboardLayout': 1, 'GetKeyboardLayoutList': 2,
        'GetKeyboardLayoutNameA': 1, 'GetKeyboardLayoutNameW': 1, 'GetKeyboardType': 1,
        'GetLastActivePopup': 1, 'GetLastInputInfo': 1, 'GetLayeredWindowAttributes': 4,
        'GetMenuCheckMarkDimensions': 0, 'GetMenuDefaultItem': 3, 'GetMenuInfo': 2,
        'GetMenuItemRect': 4, 'GetMenuStringA': 5, 'GetMessageExtraInfo': 0,
        'GetMessageTime': 0, 'GetNextDlgGroupItem': 3, 'GetNextDlgTabItem': 3,
        'GetProcessWindowStation': 0, 'GetPropA': 2, 'GetPropW': 2, 'GetQueueStatus': 1,
        'GetSystemDpiForProcess': 1, 'GetSystemMetricsForDpi': 2, 'GetThreadDesktop': 1,
        'GetThreadDpiAwarenessContext': 0, 'GetTopWindow': 1, 'GetUpdateRect': 3,
        'GetUpdateRgn': 3, 'GetUserObjectInformationA': 5, 'GetUserObjectInformationW': 5,
        'GetWindowContextHelpId': 1, 'GetWindowDC': 1, 'GetWindowDpiAwarenessContext': 1,
        'GetWindowInfo': 2, 'GetWindowThreadProcessId': 2, 'GetWindowWord': 2,
        'GrayStringA': 9, 'GrayStringW': 9, 'HiliteMenuItem': 4, 'InSendMessage': 0,
        'InSendMessageEx': 1, 'InvalidateRgn': 3, 'InvertRect': 2, 'IsCharAlphaNumericW': 1,
        'IsCharAlphaW': 1, 'IsCharLowerW': 1, 'IsCharUpperW': 1, 'IsChild': 2,
        'IsHungAppWindow': 1, 'IsMenu': 1, 'IsProcessDPIAware': 0,
        'IsValidDpiAwarenessContext': 1, 'LoadKeyboardLayoutW': 2, 'LoadMenuIndirectA': 1,
        'LoadMenuIndirectW': 1, 'LockWindowUpdate': 1, 'LockWorkStation': 0,
        'LogicalToPhysicalPoint': 2, 'LogicalToPhysicalPointForPerMonitorDPI': 2,
        'MenuItemFromPoint': 4, 'ModifyMenuA': 5, 'MsgWaitForMultipleObjects': 5,
        'MsgWaitForMultipleObjectsEx': 5, 'NotifyWinEvent': 4, 'OemKeyScan': 1,
        'OemToCharA': 2, 'OemToCharBuffW': 3, 'OemToCharW': 2, 'OpenDesktopA': 4,
        'OpenDesktopW': 4, 'OpenInputDesktop': 3, 'OpenWindowStationA': 3,
        'OpenWindowStationW': 3, 'PhysicalToLogicalPoint': 2,
        'PhysicalToLogicalPointForPerMonitorDPI': 2, 'RedrawWindow': 4, 'RegisterHotKey': 4,
        'RemovePropA': 2, 'RemovePropW': 2, 'ReplyMessage': 1, 'SendInput': 3,
        'SetClassWord': 3, 'SetDoubleClickTime': 1, 'SetLayeredWindowAttributes': 4,
        'SetMenuDefaultItem': 3, 'SetMenuInfo': 2, 'SetMenuItemBitmaps': 5,
        'SetMessageExtraInfo': 1, 'SetProcessDPIAware': 0, 'SetProcessDpiAwarenessContext': 1,
        'SetProcessWindowStation': 1, 'SetPropA': 3, 'SetPropW': 3, 'SetThreadDesktop': 1,
        'SetThreadDpiAwarenessContext': 1, 'SetWinEventHook': 7, 'SetWindowContextHelpId': 2,
        'SetWindowWord': 3, 'SetWindowsHookA': 2, 'SetWindowsHookW': 2, 'SetWindowsHookExA': 4,
        'SetWindowsHookExW': 4, 'ShowOwnedPopups': 2, 'ShowScrollBar': 3,
        'ShutdownBlockReasonCreate': 2, 'ShutdownBlockReasonDestroy': 1, 'SubtractRect': 3,
        'SwapMouseButton': 1, 'SwitchDesktop': 1, 'SystemParametersInfoForDpi': 5,
        'ToAscii': 5, 'ToAsciiEx': 6, 'ToUnicode': 6, 'ToUnicodeEx': 7, 'TrackMouseEvent': 1,
        'UnhookWinEvent': 1, 'UnhookWindowsHook': 2, 'UnhookWindowsHookEx': 1,
        'UnloadKeyboardLayout': 1, 'UnregisterHotKey': 2, 'UpdateLayeredWindow': 9,
        'ValidateRgn': 2, 'VkKeyScanA': 1, 'VkKeyScanExA': 2, 'VkKeyScanExW': 2,
        'VkKeyScanW': 1, 'WaitForInputIdle': 2, 'WaitMessage': 0, 'SetMessageQueue': 1,
        'keybd_event': 4,
        'mouse_event': 5, 'wvsprintfW': 3,
        # uxtheme
        'BeginBufferedPaint': 5, 'BufferedPaintInit': 0, 'BufferedPaintUnInit': 0,
        'CloseThemeData': 1, 'DrawThemeBackground': 6, 'DrawThemeBackgroundEx': 6,
        'DrawThemeEdge': 8, 'DrawThemeIcon': 7, 'DrawThemeParentBackground': 3,
        'DrawThemeText': 9, 'EnableThemeDialogTexture': 2, 'EndBufferedPaint': 2,
        'GetCurrentThemeName': 6, 'GetThemeAppProperties': 0,
        'GetThemeBackgroundContentRect': 6, 'GetThemeBackgroundExtent': 6, 'GetThemeBool': 5,
        'GetThemeColor': 5, 'GetThemeEnumValue': 5, 'GetThemeFont': 6, 'GetThemeInt': 5,
        'GetThemeMargins': 7, 'GetThemeMetric': 6, 'GetThemePartSize': 7,
        'GetThemePosition': 5, 'GetThemeRect': 5, 'GetThemeSysColor': 2, 'GetThemeSysFont': 3,
        'GetThemeTextExtent': 9, 'GetThemeTextMetrics': 5, 'GetWindowTheme': 1,
        'IsAppThemed': 0, 'IsCompositionActive': 0, 'IsThemeActive': 0,
        'IsThemeBackgroundPartiallyTransparent': 3, 'IsThemeDialogTextureEnabled': 1,
        'IsThemePartDefined': 3, 'OpenThemeData': 2, 'OpenThemeDataEx': 3,
        'OpenThemeDataForDpi': 3, 'SetThemeAppProperties': 1, 'SetWindowTheme': 3,
        # version
        'GetFileVersionInfoExA': 5, 'GetFileVersionInfoExW': 5, 'GetFileVersionInfoSizeExA': 3,
        'GetFileVersionInfoSizeExW': 3, 'VerLanguageNameA': 3, 'VerLanguageNameW': 3,
        # ws2_32/wsock32
        'EnumProtocolsA': 3, 'EnumProtocolsW': 3,
        'FreeAddrInfoW': 1, 'GetAddrInfoW': 4, 'GetHostNameW': 2, 'InetNtopW': 4,
        'InetPtonW': 3, 'WSAAccept': 5, 'WSAAddressToStringA': 5, 'WSAAddressToStringW': 5,
        'WSAAsyncSelect': 4, 'WSACleanup': 0, 'WSACloseEvent': 1, 'WSAConnect': 7,
        'WSACreateEvent': 0, 'WSAEnumNetworkEvents': 3, 'WSAEventSelect': 3,
        'WSAGetLastError': 0, 'WSAIoctl': 9, 'WSARecv': 7, 'WSARecvFrom': 9,
        'WSAResetEvent': 1, 'WSASend': 7, 'WSASendTo': 9, 'WSASetEvent': 1,
        'WSASetLastError': 1, 'WSASocketA': 6, 'WSASocketW': 6, 'WSAStartup': 2,
        'WSAStringToAddressA': 5, 'WSAStringToAddressW': 5, 'WSAWaitForMultipleEvents': 5,
        '__WSAFDIsSet': 2, 'accept': 3, 'bind': 3, 'closesocket': 1, 'connect': 3,
        'freeaddrinfo': 1, 'getaddrinfo': 4, 'gethostbyaddr': 3, 'gethostbyname': 1,
        'gethostname': 2, 'getnameinfo': 7, 'getpeername': 3, 'getprotobyname': 1,
        'getprotobynumber': 1, 'getservbyname': 2, 'getservbyport': 2, 'getsockname': 3,
        'getsockopt': 5, 'htonl': 1, 'htons': 1, 'inet_addr': 1, 'inet_ntoa': 1,
        'inet_ntop': 4, 'inet_pton': 3, 'ioctlsocket': 3, 'listen': 2, 'ntohl': 1, 'ntohs': 1,
        'recv': 4, 'recvfrom': 6, 'select': 5, 'send': 4, 'sendto': 6, 'setsockopt': 5,
        'shutdown': 2, 'socket': 3,
        # PowerPoint 95
        'GetRasterizerCaps': 2, 'SetClipboardViewer': 1, 'GetClipboardViewer': 0,
        'ChangeClipboardChain': 2, 'RegisterActiveObject': 4, 'RevokeActiveObject': 2,
        'GetActiveObject': 3, 'EnumPrintersA': 7, 'EnumPrintersW': 7,
        'SetTextJustification': 3, 'GetCurrentPositionEx': 2,
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
    LB_FINDSTRING = 0x018F
    LB_GETITEMDATA = 0x0199
    LB_SETITEMDATA = 0x019A
    LB_FINDSTRINGEXACT = 0x01A2
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
        # Mapped regions reserved without MEM_COMMIT: base -> indexes of their
        # committed pages (only those count as used "physical" memory)
        self.virtual_commits = {}
        self.next_handle = 0x1000
        # Handles a child of CreateProcess(bInheritHandles=TRUE) gets
        self.inheritable_handles = set()
        self.console_output = []
        # Own console: has_console follows AllocConsole/FreeConsole, console is
        # the GUI console window (FakeConsole) when the GUI is running
        self.has_console = False
        self.console = None
        # msvcrt FILE* streams: FILE pointer -> {'fp': python file, 'path': str}
        self.file_streams = {}
        self.registered_classes = {}  # Registered window classes
        self.module_classes = {}  # (lower-case name, hInstance) -> registered_classes entry
        self.system_class_data = {}  # System class name -> fields changed by SetClassLong
        self.system_menus = {}  # hwnd -> window menu (GetSystemMenu)
        self.shell_malloc = 0  # IMalloc of SHGetMalloc
        self.last_message_pos = (0, 0)  # Cursor position of the last message (GetMessagePos)
        self.atoms = {}  # RegisterClass atoms
        self.next_atom = 0xC000

        # Message queue system
        self.message_queue = []
        self.message_lock = threading.Lock()  # Guards message_queue (GUI thread is producer)
        # (hwnd, message, wParam, lParam) of the key-down messages taken from
        # the queue -> the (WM_CHAR or WM_SYSCHAR, code) TranslateMessage posts
        self.key_chars = {}
        # Mouse buttons (VK_LBUTTON/VK_RBUTTON/VK_MBUTTON) held as of the last
        # mouse message taken from the queue: GetKeyState's view of them
        self.mouse_buttons = set()
        # WNDCLASS(EX) buffers GetClassInfo(Ex) filled for a system class -> its name
        self.superclass_buffers = {}
        self.combo_edits = {}  # Edit field handle -> its combo box control (see _combo_edit)
        # Plain windows of a class found to superclass a control while they
        # were created (see _class_proc): CreateWindowEx makes them that control
        self.superclass_windows = set()
        self.sent_messages = {}  # Guest thread id -> SendMessage requests from other threads
        self.painted_windows = set()  # Windows that received WM_PAINT
        # Windows whose WM_PAINT is being handled before BeginPaint or
        # ValidateRect: their update region is still the client area
        self.paint_pending = set()
        # Window -> the client rectangle to repaint (InvalidateRect with a
        # rectangle, an area a hidden sibling uncovered); a window to paint
        # that is not here is painted whole
        self.update_rects = {}
        self.top_focus = 0  # Top-level window DefWindowProc gave the focus (WM_SETFOCUS)
        self.own_dcs = {}  # Window of a CS_OWNDC class -> its private DC
        self.updating_windows = set()  # Windows inside UpdateWindow's WM_PAINT
        self.dirty_controls = {}  # Owner-draw controls waiting for WM_DRAWITEM (ordered)
        self._drawitem_buf = 0
        self.quit_requested = False
        self.quit_code = 0  # wParam of WM_QUIT (PostQuitMessage)
        self.quit_message_taken = False  # The program removed the WM_QUIT
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
        # GMEM_MOVEABLE/LMEM_MOVEABLE blocks: handle -> {'ptr', 'locks'}. Like
        # Windows, a moveable handle points to its block's address (code such
        # as the Office 95 spelling checker reads the block through it).
        self.moveable_handles = {}
        self.moveable_by_pointer = {}

        # Common controls: image lists (handle -> {'cx', 'cy', 'images'}),
        # the system image lists, icons, accelerator tables
        self.imagelists = {}
        self._sys_imagelists = {}
        # Icons added to the system image lists for files (see _sys_file_icon)
        self._sys_file_icons = []
        self._sys_file_icon_indexes = {}
        self.icons = {}
        self.system_icons = {}  # HICON of a LoadIcon(NULL, IDI_*) -> message box icon kind
        self._dialog_fonts = {}  # (face, size) of a dialog template -> GDI font handle
        self.accelerators = {}
        self.clipboard_open = False
        self.clipboard_window = 0  # OpenClipboard's window
        self._metafile_tables = {}  # EnumMetaFile handle table -> object handles
        self.mapping_views = {}  # id(file mapping info) -> [its address here, info, views]

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
            # operator new / delete (and the [] forms) of the C runtime DLLs
            '??2@YAPAXI@Z': self.malloc, '??_U@YAPAXI@Z': self.malloc,
            '??3@YAXPAX@Z': self.free, '??_V@YAXPAX@Z': self.free,
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
        '_no_service', '_no_theme', '_not_a_socket', '_wsa_fd_is_set',
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
        'msvfw32.dll', 'avifil32.dll', 'dinput.dll',
        'dinput8.dll', 'd3d8.dll', 'd3d9.dll', 'opengl32.dll', 'glu32.dll', 'lz32.dll',
        'olepro32.dll', 'oledlg.dll', 'riched20.dll', 'riched32.dll', 'msftedit.dll',
        'iphlpapi.dll', 'wintrust.dll', 'cabinet.dll', 'powrprof.dll', 'wtsapi32.dll',
        'normaliz.dll', 'bcrypt.dll', 'ncrypt.dll', 'dnsapi.dll', 'winhttp.dll',
        'mscoree.dll', 'msi.dll', 'usp10.dll', 'hhctrl.ocx', 'oleacc.dll', 'mapi32.dll',
        'odbc32.dll', 'avrt.dll', 'xinput1_3.dll', 'shfolder.dll', 'sensapi.dll',
        'shcore.dll',
    }

    # Registry APIs of shlwapi that return a Win32 error code (LSTATUS)
    SHLWAPI_REGISTRY_APIS = frozenset(
        f'{name}{suffix}' for name in ('SHGetValue', 'SHSetValue', 'SHQueryValueEx',
                                       'SHDeleteValue', 'SHDeleteKey', 'SHDeleteEmptyKey',
                                       'SHEnumKeyEx', 'SHEnumValue', 'SHQueryInfoKey',
                                       'SHCopyKey', 'SHRegGetValue', 'SHRegSetValue')
        for suffix in ('A', 'W'))

    @classmethod
    def failure_result(cls, func_name):
        """EAX of an API whose handler failed with an emulator error. 0 is
        success for the APIs that return an error code, which would make the
        program use outputs that were never written: the registry APIs
        (LSTATUS) get ERROR_NOACCESS, like Windows answers an unusable
        buffer; COM interface methods (HRESULT) get E_FAIL."""
        if '::' in func_name:
            method = func_name.rsplit('::', 1)[1]
            return 0 if method in ('AddRef', 'Release') else 0x80004005  # E_FAIL
        if ((func_name.startswith('Reg') and not func_name.startswith('Register')) or
                func_name in cls.SHLWAPI_REGISTRY_APIS):
            return 998  # ERROR_NOACCESS
        return 0

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
        environment (the C runtime's environ/_wenviron); like the real C
        runtime it leaves out the hidden "=C:" (per-drive directory) variables"""
        pointers = []
        for name, value in sorted(self.environment.items()):
            if name.startswith('='):
                continue
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
