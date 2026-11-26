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

"""Unit tests of the SLTG type library reader (src/winapi/typelib_reader.py).

The pieces of the format are tested on hand-made bytes; a whole library is
read only where the Office 95 CD is in drives/D (it is not in the repository).
"""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))

from src.winapi import typelib_reader as tlr  # noqa: E402

BINDER_TLB = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..',
                          'drives', 'D', 'OFFICE', 'BINDER.TLB')
STDOLE = ('*\\G{00020430-0000-0000-C000-000000000046}#1.0#0#'
          'C:\\WINDOWS\\System32\\STDOLE32.TLB#')


def reader_with_names(*names):
    """A reader whose name table holds these names; returns it and their offsets"""
    table, offsets = b'', []
    for name in names:
        offsets.append(len(table))
        table += b'\xAA' * 8 + name.encode('latin-1') + b'\x00'
        table += b'\x00' * (len(table) & 1)
    reader = tlr._SltgReader(table + b'\x00' * 16)
    reader.names = 0
    return reader, offsets


class WordTreeTest(unittest.TestCase):
    """Help strings are words coded by their path in a binary tree"""

    # A 1 bit leads to the next node, a 0 bit to the node at the offset:
    # "Opens" is 1, "file" is 01, the empty word that ends a string is 00
    TREE = (b'\x80\x00\x0a' + b'\x00Opens\x00' +
            b'\x80\x00\x13' + b'\x00file\x00' + b'\x00\x00')

    def tree(self):
        return tlr._WordTree(b'##' + self.TREE, 2, len(self.TREE))

    def test_words_are_joined_until_the_empty_word(self):
        self.assertEqual(self.tree().decode(bytes([0b10100000])), 'Opens file')

    def test_a_string_may_start_at_an_offset(self):
        self.assertEqual(self.tree().decode(bytes([0xFF, 0b01100000]), 1), 'file Opens')

    def test_data_that_ends_early_keeps_the_words_read(self):
        self.assertEqual(self.tree().decode(bytes([0xFF])), ' '.join(['Opens'] * 8))

    def test_a_library_without_a_tree_has_no_help_strings(self):
        self.assertEqual(tlr._WordTree(b'', 0, 0).decode(b'\xA0'), '')


class TypeWordTest(unittest.TestCase):
    """A type word: VARTYPE, pointer bits, parameter direction"""

    def test_plain_and_pointer_types(self):
        self.assertEqual(tlr._SltgReader.word_type(0x0008), ('vt', 8))
        self.assertEqual(tlr._SltgReader.word_type(0x0E0C), ('ptr', ('vt', 12)))
        self.assertEqual(tlr._SltgReader.word_type(0x4E88), ('ptr', ('vt', 8)))
        # The bit of a constant's type is not part of the VARTYPE
        self.assertEqual(tlr._SltgReader.word_type(0x0056), ('vt', 22))

    def test_parameter_flags(self):
        flags = tlr._SltgReader.param_flags
        self.assertEqual(flags(0x0008), tlr.PARAMFLAG_FIN)
        self.assertEqual(flags(0x4E02), tlr.PARAMFLAG_FOUT)
        self.assertEqual(flags(0x8E02), tlr.PARAMFLAG_FIN | tlr.PARAMFLAG_FOUT)
        self.assertEqual(flags(0xC00C), 0)
        self.assertEqual(flags(0x4E88), tlr.PARAMFLAG_FOUT | tlr.PARAMFLAG_FRETVAL)
        self.assertEqual(flags(0x2003), tlr.PARAMFLAG_FIN | tlr.PARAMFLAG_FLCID)

    def test_described_types(self):
        reader = tlr._SltgReader(b'')
        refs = [(0x40, True), (0x44, True)]
        block = bytes.fromhex('9a44 1d0e 0400'.replace(' ', ''))
        self.assertEqual(reader.read_type_desc(block, 0, refs),
                         ('ptr', ('ptr', ('user', 0x44))))
        # The lowest bit of a reference number: the vtable interface of a dual
        self.assertEqual(reader.read_type_desc(bytes.fromhex('1d000500'), 0, refs),
                         ('user', 0x45))
        # An unknown reference number is not followed
        self.assertEqual(reader.read_type_desc(bytes.fromhex('1d002000'), 0, refs),
                         ('user', 0))

    def test_safe_arrays(self):
        reader = tlr._SltgReader(b'')
        block = bytes(24) + bytes.fromhex('1b0f 0000 1100'.replace(' ', ''))
        self.assertEqual(reader.read_type_desc(block, 24, []),
                         ('ptr', ('safearray', ('vt', 17))))

    def test_endless_types_are_refused(self):
        reader = tlr._SltgReader(b'')
        with self.assertRaises(tlr.TypeLibraryError):
            reader.read_type_desc(bytes.fromhex('1a00') * 40, 0, [])


class ReferenceTest(unittest.TestCase):
    """References to types of this library and of other ones"""

    def test_a_type_of_this_library(self):
        reader, _ = reader_with_names('Lib')
        reader.lib.types = [tlr.TypeInfo(index) for index in range(3)]
        self.assertEqual(reader.read_ref('*\\Rffff*#2'), (8, True))
        self.assertEqual(reader.lib.refs[8], ('internal', 2))

    def test_a_type_of_another_library(self):
        reader, (_, stdole) = reader_with_names('Lib', STDOLE)
        reader.lib.types = [tlr.TypeInfo(index) for index in range(3)]
        href, internal = reader.read_ref(f'*\\R{stdole:x}*#4')
        self.assertFalse(internal)
        self.assertEqual(href, 12)  # After the hrefs of the library's 3 types
        self.assertEqual(reader.lib.refs[href], (
            'external', ('00020430-0000-0000-c000-000000000046', 1, 0, 0,
                         'C:\\WINDOWS\\System32\\STDOLE32.TLB'), 4))
        # The same type again has the same href, another one a new href
        self.assertEqual(reader.read_ref(f'*\\R{stdole:x}*#4')[0], 12)
        self.assertEqual(reader.read_ref(f'*\\R{stdole:x}*#3')[0], 16)

    def test_a_damaged_reference(self):
        reader, _ = reader_with_names('Lib')
        self.assertEqual(reader.read_ref('nonsense'), (None, False))
        self.assertEqual(tlr._SltgReader.href_of([(None, False)], 0), 0)


class MemberTest(unittest.TestCase):
    """Fields of the member records"""

    def test_help_contexts(self):
        reader = tlr._SltgReader(b'')
        block = struct.pack('<HHI', 0x0C75, 0xFFFF, 0x12345)
        context = (block, [], 0x1EBA64)
        self.assertEqual(reader.member_help(context, 0, 0), (0x1EBA64 + 0x31D, ''))
        # Bit 1: the distance is counted down from the base
        block = struct.pack('<HH', 0x1E23, 0xFFFF)
        self.assertEqual(reader.member_help((block, [], 0x1EBA64), 0, 0)[0], 0x1EBA64 - 0x788)
        # An even number is the offset of the whole help context
        block = struct.pack('<HHI', 4, 0xFFFF, 0x12345)
        self.assertEqual(reader.member_help((block, [], 7), 0, 0)[0], 0x12345)
        block = struct.pack('<HH', 0xFFFE, 0xFFFF)
        self.assertEqual(reader.member_help((block, [], 7), 0, 0)[0], 0)

    def test_constant_values(self):
        value = tlr._SltgReader.read_value
        self.assertEqual(value(b'', ('vt', 2), 0x1000, True), (2, 0x1000))
        self.assertEqual(value(b'', ('vt', 2), 0xFFFE, True), (2, -2))
        self.assertEqual(value(b'', ('vt', 18), 0xFFFE, True), (18, 0xFFFE))
        block = b'??' + struct.pack('<i', -5) + struct.pack('<H', 3) + b'abc'
        self.assertEqual(value(block, ('vt', 22), 2, False), (22, -5))
        self.assertEqual(value(block, ('vt', 30), 6, False), (8, 'abc'))

    def test_optional_parameters_come_before_lcid_and_retval(self):
        func = tlr.FuncInfo()
        func.opt = 2
        func.params = [('a', ('vt', 8), 1, None), ('b', ('vt', 12), 1, None),
                       ('c', ('vt', 12), 1, None), ('lcid', ('vt', 3), 5, None),
                       ('ret', ('ptr', ('vt', 11)), 10, None)]
        tlr._SltgReader.mark_optional(func)
        self.assertEqual([p[2] for p in func.params], [1, 17, 17, 5, 10])

    def test_more_optional_parameters_than_parameters(self):
        func = tlr.FuncInfo()
        func.opt = 5
        func.params = [('a', ('vt', 12), 0, None)]
        tlr._SltgReader.mark_optional(func)
        self.assertEqual(func.params[0][2], tlr.PARAMFLAG_FOPT)


class DamagedDataTest(unittest.TestCase):
    def test_other_data_is_not_a_type_library(self):
        for data in (b'', b'SLTG', b'SLTG' + bytes(64), b'MSFT' + bytes(64), bytes(100)):
            with self.assertRaises(tlr.TypeLibraryError):
                tlr.read_type_library(data)


@unittest.skipUnless(os.path.isfile(BINDER_TLB), 'needs the Office 95 CD in drives/D')
class BinderLibraryTest(unittest.TestCase):
    """The Office Binder type library, as its documentation describes it"""

    @classmethod
    def setUpClass(cls):
        with open(BINDER_TLB, 'rb') as f:
            cls.lib = tlr.read_type_library(f.read())

    def test_library(self):
        lib = self.lib
        self.assertEqual((lib.name, lib.major, lib.minor), ('OfficeBinder', 1, 0))
        self.assertEqual(lib.doc, 'Office Binder 1.0 Type Library.')
        self.assertEqual(lib.helpfile, 'VBA_BIN.HLP')
        self.assertEqual(lib.guid, 'd0237635-6a9a-101b-b5a0-00aa004a2f7e')
        self.assertEqual(lib.lcid, 0x409)

    def test_enumeration(self):
        constants = self.lib.find('Constants')
        self.assertEqual(constants.typekind, tlr.TKIND_ENUM)
        values = {var.name: var.value[1] for var in constants.vars}
        self.assertEqual(values['bindPrintActiveSection'], 1)
        self.assertEqual(values['bindPrintSelectedSections'], 3)
        self.assertTrue(all(var.varkind == tlr.VAR_CONST for var in constants.vars))

    def test_dual_interface(self):
        binder = self.lib.find('Binder')
        self.assertEqual(binder.typekind, tlr.TKIND_DISPATCH)
        self.assertTrue(binder.dual_interface)
        self.assertTrue(binder.flags & tlr.TYPEFLAG_FDUAL)
        self.assertEqual(binder.doc, 'Binder Object.')
        self.assertEqual(binder.size_vft, 4 * (7 + len(binder.funcs)))
        # It derives from IDispatch of stdole
        href, _ = binder.impls[0]
        self.assertEqual(self.lib.refs[href][0], 'external')
        self.assertEqual(self.lib.refs[href][1][0], '00020430-0000-0000-c000-000000000046')

    def test_method_with_optional_parameter(self):
        binder = self.lib.find('Binder')
        name = next(f for f in binder.funcs if f.name == 'Name')
        self.assertEqual((name.invkind, name.memid, name.ovft), (2, 0, 28))
        self.assertEqual(name.params, [('pbstrBinderName', ('ptr', ('vt', 8)), 10, None)])
        self.assertEqual(name.doc, 'Returns the name of the Binder.')
        open_ = next(f for f in binder.funcs if f.name == 'Open')
        self.assertEqual(open_.opt, 1)
        self.assertEqual([(p[0], p[1], p[2]) for p in open_.params], [
            ('FileName', ('vt', 8), tlr.PARAMFLAG_FIN),
            ('OpenAsTemplate', ('vt', 12), tlr.PARAMFLAG_FIN | tlr.PARAMFLAG_FOPT)])


if __name__ == '__main__':
    unittest.main()
