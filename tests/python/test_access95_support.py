# Copyright 2026 Erdem Ersoy (eersoy93)
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

"""Unit tests of the parts Microsoft Access 95 needs that work without an
emulated program: window class extra bytes, text messages to a program's own
window class, OLE Automation conversions and the screen bits a child window
leaves behind.

Run from the repository root:
    SDL_VIDEODRIVER=dummy python3 -m unittest tests.python.test_access95_support -v
"""

import os
import struct
import sys
import threading
import types
import unittest

from unicorn import Uc, UC_ARCH_X86, UC_MODE_32

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
from src.config import PYGAME_AVAILABLE  # noqa: E402
from src.gui import PseudoWindowsGUI  # noqa: E402
from src.windows import FakeControl, FakeWindow  # noqa: E402
from src.winapi import WinAPIHandler  # noqa: E402
from src.winapi import typelib_reader as tlr  # noqa: E402
from src.winapi.listbox_multisel import click_item, item_selected  # noqa: E402
from src.winapi.owner_draw_list import list_paint_state  # noqa: E402


class FakeEmulator:
    """Just enough of CPUEmulator for the handlers: memory, a heap, a thread"""
    BASE = 0x100000

    def __init__(self):
        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        self.uc.mem_map(self.BASE, 0x100000)
        self.next = self.BASE
        self.current_thread = types.SimpleNamespace(last_error=0, tid=1000)
        self.threads = {1000: None}

    def heap_alloc(self, size, alignment=16):
        address = self.next
        self.next += (max(size, 1) + 15) & ~15
        return address

    def heap_free(self, address):
        pass


def handler_with_memory():
    handler = WinAPIHandler.__new__(WinAPIHandler)
    handler.emu = FakeEmulator()
    handler.gui = None
    handler.registered_classes = {}
    handler.atoms = {}
    handler.module_classes = {}
    handler.superclass_buffers = {}
    handler.next_atom = 0xC100
    return handler


def stack_args(*values):
    """The handlers get the whole stack window (32 slots), not just the
    arguments: the slots after them hold whatever the caller left there"""
    return list(values) + [0xDEAD0000 + i for i in range(32 - len(values))]


class WindowClassExtraBytesTest(unittest.TestCase):
    """Access 95 superclasses its own text box class OFEDT as OKttbx and keeps
    the new class's window bytes after cbWndExtra of the base class (from
    GetClassInfo). With 0 there, both used offset 0: setting OKttbx's field
    cleared the text box's object and design view crashed in its WM_SIZE."""

    def write_string(self, handler, text):
        address = handler.emu.heap_alloc(len(text) + 1)
        handler.emu.uc.mem_write(address, text.encode() + b'\x00')
        return address

    def test_register_class_keeps_the_extra_bytes(self):
        handler = handler_with_memory()
        name = self.write_string(handler, 'OFEDT')
        wndclass = handler.emu.heap_alloc(40)
        handler.emu.uc.mem_write(wndclass, struct.pack(
            '<IIiiIIIIII', 0x2A, 0x50024848, 0, 4, 0x50000000, 0, 0x1038, 0, 0, name))
        self.assertTrue(handler.RegisterClassA([wndclass]))
        out = handler.emu.heap_alloc(40)
        self.assertTrue(handler.GetClassInfoA([0x50000000, name, out]))
        fields = struct.unpack('<IIiiIIIIII', handler.emu.uc.mem_read(out, 40))
        self.assertEqual(fields[1:4], (0x50024848, 0, 4))

    def test_register_class_ex_keeps_the_extra_bytes(self):
        handler = handler_with_memory()
        name = self.write_string(handler, 'OGrid')
        wndclass = handler.emu.heap_alloc(48)
        handler.emu.uc.mem_write(wndclass, struct.pack(
            '<IIIiiIIIIIII', 48, 8, 0x50037BEE, 12, 8, 0x50000000, 0, 0x1034, 6, 0, name, 0))
        self.assertTrue(handler.RegisterClassExA([wndclass]))
        out = handler.emu.heap_alloc(48)
        self.assertTrue(handler.GetClassInfoExA([0x50000000, name, out]))
        fields = struct.unpack('<IIIiiI', handler.emu.uc.mem_read(out, 24))
        self.assertEqual(fields[2:5], (0x50037BEE, 12, 8))

    def test_class_long_indexes(self):
        self.assertEqual(WinAPIHandler.CLASS_LONG_FIELDS[-18], 'wnd_extra')  # GCL_CBWNDEXTRA
        self.assertEqual(WinAPIHandler.CLASS_LONG_FIELDS[-20], 'cls_extra')  # GCL_CBCLSEXTRA


class OwnClassTextMessageTest(unittest.TestCase):
    """Access 95's table design grid reads the field name typed into its cell
    editor (a window of Access's own class that keeps its text itself) with
    SendMessage(WM_GETTEXT): it must reach the window procedure"""

    def setUp(self):
        handler = handler_with_memory()
        handler.gui = types.SimpleNamespace(controls={}, windows={})
        handler.dialogs = {}
        handler._window_thread = lambda hwnd: None
        handler._text_wndproc = lambda hwnd: 0x50024848 if hwnd == 0x10068 else 0
        handler._window_text = lambda hwnd: 'stale caption'
        self.calls = []

        def call_proc(proc, hwnd, msg, wparam, lparam, wide=True):
            self.calls.append((proc, hwnd, msg, wparam, lparam))
            return 4
        handler._call_proc = call_proc
        self.handler = handler

    def test_get_text_goes_to_the_window_procedure(self):
        buffer = self.handler.emu.heap_alloc(0x101)
        self.assertEqual(self.handler.SendMessageA([0x10068, 0x000D, 0x101, buffer]), 4)
        self.assertEqual(self.calls, [(0x50024848, 0x10068, 0x000D, 0x101, buffer)])

    def test_get_text_length_too(self):
        self.assertEqual(self.handler.SendMessageA([0x10068, 0x000E, 0, 0]), 4)
        self.assertEqual(self.calls[0][2], 0x000E)

    def test_other_windows_answer_from_their_caption(self):
        self.assertEqual(self.handler.SendMessageA([0x10070, 0x000E, 0, 0]),
                         len('stale caption'))
        self.assertEqual(self.calls, [])


class VariantConversionTest(unittest.TestCase):
    """Jet 3.0 reads a number field's default value with VarR8FromStr: the
    double went to the last stack slot instead of pdblOut, and Access showed
    2.78514772335116E-314 as the default value of a new Number field"""

    def setUp(self):
        self.handler = handler_with_memory()
        self.uc = self.handler.emu.uc

    def wide_string(self, text):
        address = self.handler.emu.heap_alloc(2 * len(text) + 2)
        self.uc.mem_write(address, text.encode('utf-16-le') + b'\x00\x00')
        return address

    def test_number_from_string_goes_to_the_fourth_argument(self):
        out = self.handler.emu.heap_alloc(8)
        self.uc.mem_write(out, struct.pack('<d', 1e300))
        result = self.handler.VarR8FromStr(stack_args(self.wide_string('0'), 0x409, 0, out))
        self.assertEqual(result, 0)
        self.assertEqual(struct.unpack('<d', self.uc.mem_read(out, 8))[0], 0.0)

    def test_integer_from_string(self):
        out = self.handler.emu.heap_alloc(8)
        self.handler.VarI4FromStr(stack_args(self.wide_string('42'), 0x409, 0, out))
        self.assertEqual(struct.unpack('<i', self.uc.mem_read(out, 4))[0], 42)

    def test_number_to_number_has_no_locale(self):
        # VarR4FromR8(dblIn, pfltOut): the double takes two slots
        out = self.handler.emu.heap_alloc(8)
        low, high = struct.unpack('<II', struct.pack('<d', 2.5))
        self.assertEqual(self.handler.VarR4FromR8(stack_args(low, high, out)), 0)
        self.assertEqual(struct.unpack('<f', self.uc.mem_read(out, 4))[0], 2.5)

    def test_string_from_number(self):
        out = self.handler.emu.heap_alloc(8)
        self.handler.VarBstrFromI2(stack_args(7, 0x409, 0, out))
        bstr = struct.unpack('<I', self.uc.mem_read(out, 4))[0]
        self.assertEqual(self.handler._bstr_text(bstr), '7')


@unittest.skipUnless(PYGAME_AVAILABLE, 'needs pygame for the window images')
class WindowBitsTest(unittest.TestCase):
    """SetWindowPos(SWP_HIDEWINDOW | SWP_NOREDRAW) of a child window leaves its
    image on the screen: Access 95's grids hide their cell editor that way and
    the text it showed is the cell's text"""

    SWP_NOREDRAW, SWP_SHOWWINDOW, SWP_HIDEWINDOW = 0x8, 0x40, 0x80

    def setUp(self):
        gui = PseudoWindowsGUI.__new__(PseudoWindowsGUI)
        gui.lock = threading.RLock()
        parent = FakeWindow(1, '', 0, 0, 200, 100, 0x50000000)
        parent.visible = True
        child = FakeWindow(2, '', 20, 10, 50, 15, 0x44000000)
        child.parent, child.visible = 1, True
        child.bg_color = (255, 255, 255)
        parent.children = [2]
        gui.windows = {1: parent, 2: child}
        gui.controls = {}
        self.parent, self.child = parent, child
        handler = WinAPIHandler.__new__(WinAPIHandler)
        handler.gui = gui
        self.handler = handler
        self.child.drawn_shapes = [{'type': 'rect', 'rect': (0, 0, 10, 10), 'pen': None,
                                    'fill': (255, 0, 0)}]

    def test_hidden_without_redraw_leaves_its_image(self):
        self.handler._window_pos_bits(self.child, self.SWP_HIDEWINDOW | self.SWP_NOREDRAW, False)
        image = self.parent.drawn_shapes[-1]
        self.assertEqual(image['type'], 'image')
        self.assertEqual(image['pos'], (20, 10))
        self.assertEqual(image['size'], (50, 15))

    def test_hidden_with_redraw_leaves_nothing(self):
        self.handler._window_pos_bits(self.child, self.SWP_HIDEWINDOW, False)
        self.assertEqual(self.parent.drawn_shapes, [])

    def test_shown_but_not_drawn_leaves_nothing(self):
        # Shown at a new place without redrawing, its list is the old place's
        self.child.visible = False
        self.handler._window_pos_bits(self.child, self.SWP_SHOWWINDOW | self.SWP_NOREDRAW, True)
        self.child.visible = True
        self.handler._window_pos_bits(self.child, self.SWP_HIDEWINDOW | self.SWP_NOREDRAW, False)
        self.assertEqual(self.parent.drawn_shapes, [])
        # Once it draws again, hiding it leaves the new image
        self.child.drawn_shapes = list(self.child.drawn_shapes)
        self.handler._window_pos_bits(self.child, self.SWP_HIDEWINDOW | self.SWP_NOREDRAW, False)
        self.assertEqual(len(self.parent.drawn_shapes), 1)



def list_handler(style):
    """A handler with one LISTBOX control of style holding four items"""
    handler = handler_with_memory()
    handler.gui = types.SimpleNamespace(controls={}, windows={}, LISTBOX_ITEM_H=18)
    handler.dirty_controls = {}
    control = FakeControl(0x200, 'LISTBOX', '', 0, 0, 100, 80, style)
    control.items = ['*', 'ID', 'Name', 'Age']
    handler.gui.controls[control.hwnd] = control
    return handler, control


class MultipleSelectionListTest(unittest.TestCase):
    """Access 95's Show Table dialog lists the tables in an LBS_EXTENDEDSEL
    list and adds the ones LB_GETSELITEMS gives"""

    LBS_EXTENDEDSEL, LBS_MULTIPLESEL = 0x0800, 0x0008

    def test_select_and_read_back(self):
        handler, control = list_handler(0x50A10809)
        self.assertEqual(handler._control_message(control, 0x0185, 1, 2), 0)  # LB_SETSEL
        self.assertEqual(handler._control_message(control, 0x0185, 1, 0), 0)
        self.assertEqual(handler._control_message(control, 0x0190, 0, 0), 2)  # GETSELCOUNT
        buffer = handler.emu.heap_alloc(16)
        self.assertEqual(handler._control_message(control, 0x0191, 4, buffer), 2)
        self.assertEqual(struct.unpack('<2i', handler.emu.uc.mem_read(buffer, 8)), (0, 2))
        self.assertEqual(handler._control_message(control, 0x0187, 2, 0), 1)  # LB_GETSEL
        self.assertEqual(handler._control_message(control, 0x0187, 1, 0), 0)
        handler._control_message(control, 0x0185, 0, 0xFFFFFFFF)  # Deselect all
        self.assertEqual(handler._control_message(control, 0x0190, 0, 0), 0)

    def test_selection_follows_deleted_items(self):
        handler, control = list_handler(self.LBS_EXTENDEDSEL)
        handler._control_message(control, 0x0185, 1, 3)
        handler._control_message(control, 0x0182, 1, 0)  # LB_DELETESTRING 'ID'
        self.assertTrue(item_selected(control, 2))
        self.assertEqual(control.items[2], 'Age')

    def test_single_selection_lists_refuse(self):
        handler, control = list_handler(0x50A00001)
        self.assertEqual(handler._control_message(control, 0x0190, 0, 0), 0xFFFFFFFF)
        control.sel_index = 1
        self.assertEqual(handler._control_message(control, 0x0187, 1, 0), 1)

    def test_clicks(self):
        _, control = list_handler(self.LBS_EXTENDEDSEL)
        click_item(control, 1)
        click_item(control, 3, shift=True)
        self.assertEqual([i for i in range(4) if item_selected(control, i)], [1, 2, 3])
        click_item(control, 2, ctrl=True)
        self.assertEqual([i for i in range(4) if item_selected(control, i)], [1, 3])
        _, toggling = list_handler(self.LBS_MULTIPLESEL)
        click_item(toggling, 0)
        click_item(toggling, 0)
        self.assertFalse(item_selected(toggling, 0))

    def test_subclassed_list_gets_the_click(self):
        # The click a subclassing procedure passes on selects the item under
        # the mouse and tells the parent (LBN_SELCHANGE, then LBN_DBLCLK)
        handler, control = list_handler(0x0801)
        control.parent_hwnd, control.item_height = 0x100, 16
        sent = []
        handler._send = lambda hwnd, msg, wparam=0, lparam=0: sent.append((hwnd, msg, wparam))
        handler._listbox_mouse_message(control, 0x0203, 1, (40 << 16) | 5)
        self.assertTrue(item_selected(control, 2))
        self.assertEqual(sent, [(0x100, 0x0111, 0x10000), (0x100, 0x0111, 0x20000)])


class OwnerDrawListTest(unittest.TestCase):
    """Access 95's query design lists a table's fields in an owner-draw list"""

    def test_item_height_messages(self):
        handler, control = list_handler(0x50A00D11)
        self.assertEqual(handler._control_message(control, 0x01A0, 0, 16), 0)  # SETITEMHEIGHT
        self.assertEqual(handler._control_message(control, 0x01A1, 0, 0), 16)
        self.assertIn(control.hwnd, handler.dirty_controls)

    def test_changes_paint_the_items_again(self):
        handler, control = list_handler(0x50A00D11)
        control.item_height = 16
        handler._control_message(control, 0x0180, 0, 0x1234)  # LB_ADDSTRING (item data)
        self.assertIn(control.hwnd, handler.dirty_controls)
        self.assertEqual(control.item_data[-1], 0x1234)

    def test_paint_state_follows_the_selection(self):
        _, control = list_handler(0x50A00D11)
        before = list_paint_state(control)
        click_item(control, 2)
        self.assertNotEqual(list_paint_state(control), before)


def small_library():
    """A library with a module, an interface deriving from another one and
    an application object coclass"""
    model = tlr.TypeLibrary()
    model.name = 'Lib'

    def func(name, memid, invkind=1):
        member = tlr.FuncInfo()
        member.name, member.memid, member.invkind = name, memid, invkind
        return member
    module = tlr.TypeInfo(0)
    module.name, module.typekind = 'Strings', tlr.TKIND_MODULE
    module.funcs = [func('Left', 1)]
    base = tlr.TypeInfo(1)
    base.name, base.typekind = '_Base', tlr.TKIND_DISPATCH
    base.funcs = [func('Visible', 5, 2), func('Visible', 5, 4)]
    app = tlr.TypeInfo(2)
    app.name, app.typekind = '_Application', tlr.TKIND_DISPATCH
    app.funcs = [func('DoCmd', 7, 2)]
    app.impls = [(0x100, 0)]
    coclass = tlr.TypeInfo(3)
    coclass.name, coclass.typekind, coclass.flags = 'Application', tlr.TKIND_COCLASS, 1
    coclass.impls = [(0x200, 1)]
    model.types = [module, base, app, coclass]
    model.refs = {0x100: ('internal', 1), 0x200: ('internal', 2)}
    return model


class TypeCompTest(unittest.TestCase):
    """VBA binds names with ITypeComp (ITypeLib/ITypeInfo::GetTypeComp)"""

    def setUp(self):
        handler = handler_with_memory()
        handler.com_objects = {}
        handler._new_typeinfo_object = lambda model, info, view=None: (
            handler.com_objects.setdefault(0x1000 + info.index, {'type': info}) and
            0x1000 + info.index)
        handler._ti_func_desc = lambda state, func: ('func', func.name, func.invkind)
        handler._ti_var_desc = lambda state, var: ('var', var.name, var.memid)
        self.handler, self.model = handler, small_library()

    def test_module_function_and_type_name(self):
        kind, info, desc = self.handler._bind_in_library(self.model, 'left', 0)
        self.assertEqual((kind, info, desc), (1, 0x1000, ('func', 'Left', 1)))
        self.handler._new_typecomp_object = lambda model, info=None, view=None: 0x77
        self.assertEqual(self.handler._bind_in_library(self.model, 'Strings', 0), (3, 0, 0x77))

    def test_application_object_members(self):
        kind, info, desc = self.handler._bind_in_library(self.model, 'DoCmd', 2)
        self.assertEqual((kind, info), (4, 0x1003))  # DESCKIND_IMPLICITAPPOBJ, the coclass
        self.assertEqual(desc, ('var', 'Application', 0xFFFFFFFE))

    def test_inherited_member_with_invoke_kind(self):
        app = self.model.types[2]
        kind, info, desc = self.handler._bind_in_type(self.model, app, None, 'visible', 4)
        self.assertEqual((kind, info, desc), (1, 0x1001, ('func', 'Visible', 4)))
        self.assertEqual(self.handler._bind_in_type(self.model, app, None, 'Nothing', 0),
                         (0, 0, 0))
        self.assertIs(self.handler._inherited_member(self.model, app, None, 'VISIBLE'),
                      self.model.types[1].funcs[0])

    def test_invoke_kind_mismatch(self):
        app = self.model.types[2]
        self.assertEqual(self.handler._bind_in_type(self.model, app, None, 'DoCmd', 4),
                         0x80028CA0)  # TYPE_E_TYPEMISMATCH


class SmallFixesTest(unittest.TestCase):
    def test_type_library_of_a_loaded_dll(self):
        # VBA refers to DAO's type library as just "dao3032.dll": LoadTypeLib
        # finds it like LoadLibrary, among the loaded modules
        handler = handler_with_memory()
        handler.full_windows_path = lambda name: 'C:\\Work\\' + name
        handler.resolve_drive_path = lambda path: None
        dao = 'C:\\Program Files\\Common Files\\Microsoft Shared\\DAO\\DAO3032.DLL'
        handler.emu.find_dll = lambda name: {'path': dao} if name.lower() == 'dao3032.dll' \
            else None
        self.assertEqual(handler._search_typelib_file('dao3032.dll'), dao)
        self.assertEqual(handler._search_typelib_file('other.tlb'), 'other.tlb')
        self.assertEqual(handler._search_typelib_file('C:\\x\\dao3032.dll'),
                         'C:\\x\\dao3032.dll')

    def test_dialog_units_without_a_font(self):
        # Access 95 builds its message boxes without DS_SETFONT, sized for the
        # system font's dialog base units (GetDialogBaseUnits: 8 x 16)
        self.assertEqual(WinAPIHandler._dialog_units({'font': None}), (2.0, 2.0))
        self.assertEqual(WinAPIHandler._dialog_units({'font': ('MS Sans Serif', 8)}),
                         (1.5, 1.625))

    def test_list_view_icon_space_follows_the_small_icons(self):
        handler = handler_with_memory()
        handler.imagelists = {7: {'cx': 24, 'cy': 19, 'flags': 0, 'images': []}}
        win = types.SimpleNamespace(nstate={'imagelists': {1: 7}})
        self.assertEqual(handler.lv_icon_space(win), 28)
        win.nstate['imagelists'] = {}
        self.assertEqual(handler.lv_icon_space(win), 0)


if __name__ == '__main__':
    unittest.main()
