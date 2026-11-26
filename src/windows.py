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

"""Windows, controls and consoles of the pseudo Windows GUI"""

import bisect
import threading
from functools import wraps


def gui_locked(method):
    """Run a PseudoWindowsGUI method while holding its lock (shared with the GUI thread)"""
    @wraps(method)
    def wrapper(self, *args, **kwargs):
        with self.lock:
            return method(self, *args, **kwargs)
    return wrapper


# Application desktop toolbars (SHAppBarMessage) of all the programs:
# hwnd -> AppBar. Their docked rectangles are taken out of the work area.
APPBARS = {}


class AppBar:
    """A registered appbar: its callback message, edge and reserved rectangle"""

    def __init__(self, owner, callback_message):
        self.owner = owner  # WinAPIHandler of the process that registered it
        self.callback_message = callback_message
        self.edge = None   # ABE_LEFT, ABE_TOP, ABE_RIGHT, ABE_BOTTOM once ABM_SETPOS
        self.rect = None   # (left, top, right, bottom) it reserved
        self.autohide = set()  # Edges it is the autohide appbar of


def work_area(screen_width, screen_height, taskbar_height=30, exclude=None):
    """(left, top, right, bottom) of the desktop not covered by the taskbar at
    the bottom or by the docked appbars (all except hwnd exclude)"""
    left, top, right, bottom = 0, 0, screen_width, screen_height - taskbar_height
    for hwnd, bar in list(APPBARS.items()):
        if hwnd == exclude or bar.rect is None:
            continue
        bar_left, bar_top, bar_right, bar_bottom = bar.rect
        if bar.edge == 0:
            left = max(left, min(bar_right, right))
        elif bar.edge == 1:
            top = max(top, min(bar_bottom, bottom))
        elif bar.edge == 2:
            right = min(right, max(bar_left, left))
        elif bar.edge == 3:
            bottom = min(bottom, max(bar_top, top))
    return left, top, right, bottom


class FakeWindow:
    """Fake Windows window"""

    def __init__(self, hwnd, title, x, y, width, height, style=0):
        self.hwnd = hwnd
        self.title = title
        self.icon_path = None  # Host path of the EXE whose icon the title bar shows
        self.x = x
        self.y = y
        self.width = width
        self.height = height
        self.style = style
        self.visible = False
        self.enabled = True
        self.parent = None
        self.children = []
        # Owner of a top-level window (hWndParent without WS_CHILD): owned
        # windows stay above their owner and have no taskbar button
        self.owner_hwnd = 0
        self.size_state = None  # (SIZE_* kind, client w, h) last told to the app (WM_SIZE)
        self.controls = []  # Buttons, text boxes, etc.
        self.wndproc = 0
        self.owner = None  # WinAPIHandler of the process that created it (None: emulator's own)
        self.thread_id = None  # Guest thread that created it (gets its messages)
        self.bg_color = (212, 208, 200)  # Classic Windows gray (COLOR_BTNFACE)
        self.text = title
        self.region = None  # SetWindowRgn rectangles (window coordinates)
        self.dialog_brush = None  # Dialog background chosen by WM_CTLCOLORDLG (RGB)
        # A child window whose class has no background brush is not erased:
        # its parent's drawing shows through where it does not paint
        self.transparent = False
        self.wndclass = None  # Registered class (of its module) of a program's window

        # Retained drawing list (GDI display list, redrawn every frame):
        # Rectangle/Ellipse/LineTo/SetPixel/Polygon/TextOut... items
        self.drawn_shapes = []

        # Menu bar: list of {'text', 'id', 'items': [...]} or None
        self.menu = None
        self.menu_handle = 0

        # Emulated common control (WinAPIHandler.NATIVE_CLASSES kind) and its
        # state; control ID of a child window (hMenu of CreateWindowEx)
        self.native = None
        self.nstate = {}
        self.control_id = 0
        self.ex_style = 0

        # Window state
        self.minimized = False
        self.maximized = False
        self.is_dialog = False  # True if Dialog/MessageBox (only close button)

        # Original dimensions for restore
        self.restore_x = x
        self.restore_y = y
        self.restore_width = width
        self.restore_height = height

    def contains_point(self, px, py):
        """Is point inside window?"""
        if self.minimized:
            return False
        return (self.x <= px <= self.x + self.width and
                self.y <= py <= self.y + self.height)

    def get_title_bar_rect(self):
        """Title bar rectangle"""
        return (self.x, self.y, self.width, 25)

    def minimize(self):
        """Minimize window"""
        if not self.minimized:
            self.minimized = True

    def restore(self):
        """Restore window"""
        if self.minimized:
            self.minimized = False
        elif self.maximized:
            self.x = self.restore_x
            self.y = self.restore_y
            self.width = self.restore_width
            self.height = self.restore_height
            self.maximized = False

    def maximize(self, screen_width, screen_height, taskbar_height=30):
        """Maximize window"""
        if not self.maximized:
            # Save original dimensions
            self.restore_x = self.x
            self.restore_y = self.y
            self.restore_width = self.width
            self.restore_height = self.height

            # Fill the work area (the desktop without the taskbar and the appbars)
            left, top, right, bottom = work_area(screen_width, screen_height, taskbar_height)
            self.x = left
            self.y = top
            self.width = right - left
            self.height = bottom - top
            self.maximized = True
        else:
            # Restore
            self.restore()


class FakeControl:
    """Fake Windows control (Button, Edit, Static, etc.)"""

    def __init__(self, hwnd, class_name, text, x, y, width, height, style=0, ex_style=0):
        self.hwnd = hwnd
        self.class_name = class_name.upper()
        self.text = text
        self.x = x
        self.y = y
        self.width = width
        self.height = height
        self.style = style
        self.ex_style = ex_style
        self.visible = True
        self.enabled = True
        self.parent_hwnd = 0
        self.control_id = 0  # Control ID (hMenu in CreateWindowEx) for WM_COMMAND
        self.checked = False  # For Checkbox/Radio
        self.drawn_shapes = []  # GDI drawing on the control's DC (owner-draw)
        self.region = None  # SetWindowRgn rectangles (window coordinates)
        self.items = []       # For Listbox/Combobox (LB_ADDSTRING, CB_ADDSTRING)
        self.item_data = []   # The items' data (LB_SETITEMDATA, CB_SETITEMDATA)
        self.sel_index = -1   # Selected item index (-1 = none)
        self.top_index = 0    # First visible LISTBOX item (mouse wheel scrolling)
        # Scrollbar state (SCROLLBAR class)
        self.scroll_min = 0
        self.scroll_max = 100
        self.scroll_pos = 0
        self.scroll_page = 0  # 0 = no page size set (SetScrollInfo SIF_PAGE)
        self.font = None      # GDI font dict set by WM_SETFONT (None: GUI font)
        self.font_handle = 0
        # Status bar (STATUSBAR class): pane right edges (-1: to the end),
        # texts of panes 1+ (pane 0 is self.text; 255 is the simple-mode text)
        self.parts = [-1]
        self.part_texts = {}
        self.simple = False
        # Progress bar (PROGRESSBAR class): range/position use scroll_min/max/pos
        self.progress_step = 10
        self.progress_bar_color = None  # (r, g, b) of PBM_SETBARCOLOR, None: default
        self.progress_bk_color = None   # (r, g, b) of PBM_SETBKCOLOR, None: default
        # EDIT (and editable COMBOBOX) selection: the anchor and the caret end;
        # character offsets into self.text, clamped when used
        self.sel_anchor = 0
        self.sel_caret = 0
        self.edit_scroll = 0  # Pixels the text is scrolled left (caret kept visible)
        self.edit_top_line = 0  # First visible line of a multiline edit
        self.text_limit = 0  # EM_LIMITTEXT (0: no limit)
        self.icon = None  # SS_ICON static: (width, height, RGBA) of its icon
        self.icon_handle = 0
        self.bitmap = None  # SS_BITMAP static: its bitmap GDI object (dict)
        self.bitmap_handle = 0
        # Colors the parent chose with WM_CTLCOLOR*: {'text', 'bk_mode', 'bk_color',
        # 'brush'} or None for the defaults
        self.ctl_colors = None
        self.modified = False  # EM_GETMODIFY
        # EM_UNDO: (text, anchor, caret) before the last change (None: nothing
        # to undo); a run of typed characters is one change
        self.undo_state = None
        self._typing_at = None  # Offset where the typed run ends
        # edit_lines() cache: the text and wrap width it was made for, the
        # lines and their start offsets
        self._lines_key = None
        self._lines = None
        self._line_starts = None
        # Word wrap (multiline EDIT without ES_AUTOHSCROLL): the text width in
        # pixels and a function giving a character's width, set when drawn
        self.wrap_width = 0
        self.wrap_measure = None
        self._wrap_cache = {}  # Line text -> its wrapped (start, end) pieces
        self.edit_caret_shown = None  # (caret, text) the view was last scrolled to
        self.edit_visible_lines = 1  # Lines the multiline edit shows (when drawn)
        # ES_PASSWORD shows this character instead of the text ('' : plain text)
        self.password_char = '*' if self.class_name == 'EDIT' and style & 0x20 else ''

    # ---------- EDIT selection ----------

    def selection(self):
        """(start, end) of the selection, start <= end"""
        n = len(self.text)
        anchor = min(max(self.sel_anchor, 0), n)
        caret = min(max(self.sel_caret, 0), n)
        return min(anchor, caret), max(anchor, caret)

    def set_selection(self, anchor, caret=None):
        n = len(self.text)
        self.sel_anchor = min(max(anchor, 0), n)
        self.sel_caret = min(max(anchor if caret is None else caret, 0), n)

    def select_all(self):
        self.set_selection(0, len(self.text))

    def replace_selection(self, text):
        """Replace the selection with text (cut to the text limit); the caret
        ends after it. Returns True if the text changed."""
        start, end = self.selection()
        if self.text_limit:
            text = text[:max(0, self.text_limit - (len(self.text) - (end - start)))]
        if not text and start == end:
            return False
        typed = start == end and len(text) == 1 and text not in '\r\n'
        if not (typed and start == self._typing_at and self.undo_state is not None):
            self.undo_state = (self.text, self.sel_anchor, self.sel_caret)
        self.text = self.text[:start] + text + self.text[end:]
        self.set_selection(start + len(text))
        self._typing_at = start + 1 if typed else None
        self.modified = True
        return True

    def undo(self):
        """EM_UNDO: back to the text before the last change; undoing again
        redoes it, like Windows' single-level edit undo. True if undone."""
        if self.undo_state is None:
            return False
        text, anchor, caret = self.undo_state
        self.undo_state = (self.text, self.sel_anchor, self.sel_caret)
        self.text = text
        self.set_selection(anchor, caret)
        self._typing_at = None
        self.modified = True
        return True

    def _wrap_pieces(self, line):
        """(start, end) pieces of one line broken at self.wrap_width pixels,
        after the last blank that fits (else inside the word)"""
        measure, width = self.wrap_measure, self.wrap_width
        pieces, piece_start, x, blank_end = [], 0, 0, None
        for index, char in enumerate(line):
            char_w = measure(char)
            if x + char_w > width and index > piece_start and char not in ' \t':
                cut = blank_end if blank_end is not None and blank_end > piece_start else index
                pieces.append((piece_start, cut))
                piece_start, blank_end = cut, None
                x = sum(measure(c) for c in line[piece_start:index])
            x += char_w
            if char in ' \t':
                blank_end = index + 1
        pieces.append((piece_start, len(line)))
        return pieces

    def _wraps(self):
        return (self.wrap_measure is not None and self.wrap_width > 0 and
                self.class_name == 'EDIT' and self.style & 0x4 and not self.style & 0x80)

    def edit_lines(self):
        """[(start, end)] character ranges of the lines (CR LF or LF breaks; a
        word-wrapped edit control breaks long lines too, with no character
        between the pieces). Cached until the text or the wrap width changes:
        the drawing and the caret keys ask for it all the time."""
        text = self.text
        wrap = self.wrap_width if self._wraps() else 0
        key = self._lines_key
        if key is not None and key[0] is text and key[1] == wrap:
            return self._lines
        lines = []
        start = 0
        if wrap and len(self._wrap_cache) > 20000:
            self._wrap_cache.clear()
        while True:
            newline = text.find('\n', start)
            if newline < 0:
                end = len(text)
            else:
                end = newline - 1 if newline > start and text[newline - 1] == '\r' else newline
            if wrap and end - start > 1:
                line = text[start:end]
                pieces = self._wrap_cache.get(line)
                if pieces is None:
                    pieces = self._wrap_cache[line] = self._wrap_pieces(line)
                lines.extend((start + a, start + b) for a, b in pieces)
            else:
                lines.append((start, end))
            if newline < 0:
                break
            start = newline + 1
        self._lines_key = (text, wrap)
        self._lines = lines
        self._line_starts = [line_start for line_start, _ in lines]
        return lines

    def set_wrap(self, width, measure):
        """Word wrap at width pixels with measure(char) widths (a new font or
        width wraps the lines again)"""
        if width != self.wrap_width or measure is not self.wrap_measure:
            self._wrap_cache.clear()
        self.wrap_width, self.wrap_measure = width, measure

    def line_of(self, offset):
        """Index of the line that contains character offset (at a word wrap
        break: the line that starts there, where the caret shows)"""
        lines = self.edit_lines()
        index = bisect.bisect_right(self._line_starts, offset) - 1
        return max(0, min(index, len(lines) - 1))

    def contains_point(self, px, py, parent_x=0, parent_y=0):
        """Is point inside control?"""
        abs_x = parent_x + self.x
        abs_y = parent_y + self.y
        return (abs_x <= px <= abs_x + self.width and
                abs_y <= py <= abs_y + self.height)


class FakeConsole:
    """Console of one process: its output lines and a pending line read"""

    MAX_LINES = 300  # Like the 300 rows of GetConsoleScreenBufferInfo
    MAX_HISTORY = 50

    def __init__(self, hwnd):
        self.hwnd = hwnd  # Console window
        self.lines = []  # Each line: [(text, color), ...]
        self.line_open = False  # Last line not ended by LF yet (output continues it)
        self.scroll = 0
        self.input = ""  # Line being typed
        self.input_cursor = 0  # Insertion point in it (Left/Right/Home/End)
        self.history = []  # Lines entered before (Up/Down recall them, like doskey)
        self.history_pos = 0
        self.input_active = False  # A ReadConsole/stdin read is waiting
        self.input_result = None
        self.input_ready = threading.Event()
        self.cancelled = False  # Process ending or console closed: reads return None
        self.attached = []  # Child processes sharing it (programs run by cmd)


class _ProcessRouter:
    """GUI-side stand-in for a WinAPIHandler while several programs run at once.

    Window messages go to the process owning the target window; other
    attributes (message constants, scroll_pos_max) come from WinAPIHandler.
    """

    def __init__(self, gui):
        self._gui = gui

    def __getattr__(self, name):
        return getattr(winapi.WinAPIHandler, name)

    def post_window_message(self, hwnd, message, wParam, lParam, char=None):
        owner = self._gui.window_owner(hwnd)
        if owner is not None and not owner.process_exited:
            owner.post_window_message(hwnd, message, wParam, lParam, char=char)

    @property
    def capture_hwnd(self):
        for process in list(self._gui.processes):
            if process.capture_hwnd:
                return process.capture_hwnd
        return 0


# Last: winapi (through gui) imports this module too
from . import winapi  # noqa: E402
