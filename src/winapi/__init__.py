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

"""Windows API emulation: WinAPIHandler combines the mixins of this package,
one module per area of the emulated APIs. The mixins refer to the combined
class as winapi.WinAPIHandler (class attributes shared by the processes)."""

from .core import CoreMixin
from .console import ConsoleMixin
from .files import FilesMixin
from .exe_resources import ExeResourcesMixin
from .processes import ProcessesMixin
from .oleaut import OleAutMixin
from .kernel32_vista import Kernel32VistaMixin
from .locales import LocalesMixin
from .drives_time import DrivesTimeMixin
from .kernel32_misc import Kernel32MiscMixin
from .find_files import FindFilesMixin
from .ini_files import IniFilesMixin
from .user32_windows import User32WindowsMixin
from .user32 import User32Mixin
from .cursors import CursorsMixin
from .shell_folders import ShellFoldersMixin
from .dialogs import DialogsMixin
from .status_bar import StatusBarMixin
from .winmm import WinmmMixin
from .scrollbars import ScrollbarsMixin
from .messages import MessagesMixin
from .device_context import DeviceContextMixin
from .gdi import GdiMixin
from .memory_dc import MemoryDCMixin
from .menus import MenusMixin
from .user32_misc import User32MiscMixin
from .shell32 import Shell32Mixin
from .controls import ControlsMixin
from .listview import ListViewMixin
from .treeview import TreeViewMixin
from .toolbar import ToolbarMixin
from .comboboxex import ComboBoxExMixin
from .registry import RegistryMixin
from .com import ComMixin
from .exceptions import ExceptionsMixin
from .crt_basic import CrtBasicMixin
from .msvcrt import MsvcrtMixin
from .crt import CrtMixin
from .crt_stdio import CrtStdioMixin
from .crt_misc import CrtMiscMixin
from .version_info import VersionInfoMixin
from .shlwapi import ShlwapiMixin
from .security import SecurityMixin
from .kernel32_extra import Kernel32ExtraMixin
from .user32_extra import User32ExtraMixin
from .shell_extra import ShellExtraMixin
from .system_extra import SystemExtraMixin
from .network import NetworkMixin
from .dde import DdeMixin
from .lz32 import Lz32Mixin


class WinAPIHandler(CoreMixin, ConsoleMixin, FilesMixin,
                    ExeResourcesMixin, ProcessesMixin, OleAutMixin,
                    Kernel32VistaMixin, LocalesMixin, DrivesTimeMixin,
                    Kernel32MiscMixin, FindFilesMixin, IniFilesMixin,
                    User32WindowsMixin, User32Mixin, CursorsMixin,
                    ShellFoldersMixin, DialogsMixin, StatusBarMixin,
                    WinmmMixin, ScrollbarsMixin, MessagesMixin,
                    DeviceContextMixin, GdiMixin, MemoryDCMixin,
                    MenusMixin, User32MiscMixin, Shell32Mixin,
                    ControlsMixin, ListViewMixin, TreeViewMixin, ToolbarMixin,
                    ComboBoxExMixin, RegistryMixin, ComMixin,
                    ExceptionsMixin, CrtBasicMixin, MsvcrtMixin,
                    CrtMixin, CrtStdioMixin, CrtMiscMixin, VersionInfoMixin,
                    ShlwapiMixin, SecurityMixin, Kernel32ExtraMixin, User32ExtraMixin,
                    ShellExtraMixin, SystemExtraMixin, NetworkMixin, DdeMixin,
                    Lz32Mixin):
    """Windows API emulation"""
