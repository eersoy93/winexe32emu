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

"""Consistency of the API emulation's tables: the WinAPIHandler mixins, the
stdcall argument counts and the API handlers.

Run from the repository root:
    python3 -m unittest discover -s tests/python -v
"""

import ast
import collections
import inspect
import os
import sys
import textwrap
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
from src.winapi import WinAPIHandler  # noqa: E402


def bare_handler():
    """A WinAPIHandler without an emulator (for its pure helpers)"""
    handler = WinAPIHandler.__new__(WinAPIHandler)
    handler.com_arg_counts = {}
    handler._api_map = {}
    return handler


def highest_argument(func):
    """Highest args[n] index (or args[:n] end - 1) a handler reads, -1 if none;
    None if its source cannot be read"""
    try:
        tree = ast.parse(textwrap.dedent(inspect.getsource(func)))
    except (OSError, TypeError, SyntaxError):
        return None
    function = tree.body[0]
    if not isinstance(function, ast.FunctionDef) or len(function.args.args) < 2:
        return None
    name = function.args.args[1].arg
    highest = -1
    for node in ast.walk(function):
        if (isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and
                node.value.id == name):
            index = node.slice
            if isinstance(index, ast.Constant) and isinstance(index.value, int):
                highest = max(highest, index.value)
            elif isinstance(index, ast.Slice) and isinstance(index.upper, ast.Constant):
                highest = max(highest, index.upper.value - 1)
    return highest


class MixinTest(unittest.TestCase):
    def test_no_name_in_two_classes(self):
        """A name defined by two mixins would silently use the first one in
        the method resolution order (WinAPIHandler itself only caches)"""
        owners = collections.defaultdict(list)
        for cls in WinAPIHandler.__mro__[1:]:
            if cls is object:
                continue
            for name in vars(cls):
                if not (name.startswith('__') and name.endswith('__')):
                    owners[name].append(cls.__name__)
        twice = {name: classes for name, classes in owners.items() if len(classes) > 1}
        self.assertEqual(twice, {})


class ArgumentCountTest(unittest.TestCase):
    """STDCALL_ARG_COUNTS: the stack bytes a stdcall API pops on return.
    A wrong count corrupts the program's stack."""

    def test_every_count_has_a_handler(self):
        handler = bare_handler()
        missing = [name for name in WinAPIHandler.STDCALL_ARG_COUNTS
                   if handler.get_api_handler(name) is None]
        self.assertEqual(missing, [])

    def test_every_stdcall_handler_has_a_count(self):
        """A Win32 API (an upper-case name) without a count stops the program"""
        handler = bare_handler()
        missing = [name for name in WinAPIHandler._api_method_names()
                   if name[:1].isupper() and name not in WinAPIHandler.CDECL_FUNCTIONS and
                   handler.stack_cleanup_bytes('kernel32.dll', name) is None]
        self.assertEqual(missing, [])

    def test_handlers_read_only_their_arguments(self):
        """A handler that reads args[n] beyond its count reads the caller's
        stack instead of an argument"""
        handler = bare_handler()
        checked, wrong = 0, []
        for name in sorted(WinAPIHandler._api_method_names()):
            cleanup = handler.stack_cleanup_bytes('kernel32.dll', name)
            if not cleanup:
                continue
            highest = highest_argument(getattr(WinAPIHandler, name))
            if highest is None:
                continue
            checked += 1
            if highest >= cleanup // 4:
                wrong.append(f"{name}: {cleanup // 4} argument(s), reads args[{highest}]")
        self.assertGreater(checked, 500)
        self.assertEqual(wrong, [])


if __name__ == '__main__':
    unittest.main()
