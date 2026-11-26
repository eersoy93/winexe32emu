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

"""Rich edit controls (RICHEDIT, RichEdit20A/W, RICHEDIT50W): a plain text
edit control that also takes the rich edit messages. Text streamed in as
RTF keeps only its characters, without their formatting."""

import struct

from unicorn import UcError

from .. import config

# Window classes of riched32.dll, riched20.dll and msftedit.dll
RICHEDIT_CLASSES = frozenset(('RICHEDIT', 'RICHEDIT20A', 'RICHEDIT20W', 'RICHEDIT50W'))

# RTF destinations whose text is not part of the document (Rich Text Format
# specification): font, color and style tables, document information, pictures
RTF_SKIPPED_DESTINATIONS = frozenset((
    'fonttbl', 'colortbl', 'stylesheet', 'info', 'pict', 'object', 'header', 'footer',
    'headerl', 'headerr', 'headerf', 'footerl', 'footerr', 'footerf', 'listtable',
    'listoverridetable', 'rsidtbl', 'generator', 'themedata', 'colorschememapping',
    'latentstyles', 'datastore', 'xmlnstbl', 'filetbl', 'revtbl', 'pgdsctbl', 'fldinst',
    'footnote', 'field-instruction', 'bkmkstart', 'bkmkend', 'nonshppict', 'blipuid'))

# Control words that stand for a character
RTF_CHARACTER_WORDS = {'par': '\r\n', 'line': '\r\n', 'tab': '\t', 'emdash': '\u2014',
                       'endash': '\u2013', 'bullet': '\u2022', 'lquote': '\u2018',
                       'rquote': '\u2019', 'ldblquote': '\u201c', 'rdblquote': '\u201d',
                       'emspace': '\u2003', 'enspace': '\u2002', 'qmspace': '\u2005'}


def rtf_to_text(data, codepage=None):
    """Plain text of an RTF document (bytes): its characters with CR LF line
    breaks; \\'hh bytes are decoded with the document's \\ansicpg code page
    (else codepage, else the ANSI code page)"""
    encoding = codepage or config.ANSI_CODEPAGE
    out = []
    pending = bytearray()  # \'hh bytes of a multibyte character

    def flush_bytes():
        if pending:
            out.append(pending.decode(encoding, errors='replace'))
            pending.clear()

    # Group state: (skipped, characters to skip after \uN)
    skipped, unicode_skip = False, 1
    stack = []
    skip_chars = 0  # Fallback characters of the last \uN still to skip
    i, n = 0, len(data)
    while i < n:
        c = data[i]
        if c == 0x7B:  # {
            flush_bytes()
            stack.append((skipped, unicode_skip))
            i += 1
            # {\*\dest ...}: an optional destination the reader does not know
            if data[i:i + 2] == b'\\*':
                skipped = True
            continue
        if c == 0x7D:  # }
            flush_bytes()
            if stack:
                skipped, unicode_skip = stack.pop()
            skip_chars = 0
            i += 1
            continue
        if c in (0x0D, 0x0A):
            i += 1  # Line breaks of the RTF source are not text
            continue
        if c != 0x5C:  # A plain character
            i += 1
            if skip_chars:
                skip_chars -= 1
            elif not skipped:
                pending.append(c)
            continue
        # A control word or control symbol
        i += 1
        if i >= n:
            break
        c = data[i]
        if c == 0x27:  # \'hh: a byte in hex
            try:
                value = int(data[i + 1:i + 3], 16)
            except ValueError:
                value = None
            i += 3
            if skip_chars:
                skip_chars -= 1
            elif value is not None and not skipped:
                pending.append(value)
            continue
        if not (0x61 <= c <= 0x7A or 0x41 <= c <= 0x5A):
            # Control symbol: \\ \{ \} \~ (non-breaking space), \_ (hyphen)
            i += 1
            if skipped:
                continue
            symbol = {0x5C: '\\', 0x7B: '{', 0x7D: '}', 0x7E: '\u00a0', 0x5F: '-',
                      0x0D: '\r\n', 0x0A: '\r\n'}.get(c)
            if symbol is not None:
                flush_bytes()
                out.append(symbol)
            continue
        start = i
        while i < n and (0x61 <= data[i] <= 0x7A or 0x41 <= data[i] <= 0x5A):
            i += 1
        word = data[start:i].decode('ascii')
        param = None
        num_start = i
        if i < n and (data[i] == 0x2D or 0x30 <= data[i] <= 0x39):
            i += 1
            while i < n and 0x30 <= data[i] <= 0x39:
                i += 1
            try:
                param = int(data[num_start:i])
            except ValueError:
                param = None
        if i < n and data[i] == 0x20:
            i += 1  # The space that ends a control word
        if word in RTF_SKIPPED_DESTINATIONS:
            skipped = True
        elif word == 'ansicpg' and param:
            flush_bytes()
            encoding = f'cp{param}'
            try:
                b''.decode(encoding)
            except LookupError:
                encoding = codepage or config.ANSI_CODEPAGE
        elif word == 'uc' and param is not None:
            unicode_skip = max(param, 0)
        elif word == 'u' and param is not None:
            if not skipped:
                flush_bytes()
                out.append(chr(param & 0xFFFF))
            skip_chars = unicode_skip
        elif word in RTF_CHARACTER_WORDS and not skipped:
            flush_bytes()
            out.append(RTF_CHARACTER_WORDS[word])
    flush_bytes()
    return ''.join(out)


def text_to_rtf(text, codepage=None):
    """A minimal RTF document (bytes) with the characters of text"""
    encoding = codepage or config.ANSI_CODEPAGE
    cp = encoding[2:] if encoding.lower().startswith('cp') and encoding[2:].isdigit() else '1252'
    parts = [f'{{\\rtf1\\ansi\\ansicpg{cp}\\deff0{{\\fonttbl{{\\f0 MS Sans Serif;}}}}\\f0 ']
    for ch in text.replace('\r\n', '\n').replace('\r', '\n'):
        if ch == '\n':
            parts.append('\\par\n')
        elif ch in '\\{}':
            parts.append('\\' + ch)
        elif ch == '\t':
            parts.append('\\tab ')
        elif ord(ch) < 0x80:
            parts.append(ch)
        else:
            try:
                parts.append(''.join(f"\\'{b:02x}" for b in ch.encode(encoding)))
            except UnicodeEncodeError:
                parts.append(f'\\u{ord(ch) - 0x10000 if ord(ch) > 0x7FFF else ord(ch)}?')
    parts.append('}')
    return ''.join(parts).encode('ascii')


class RichEditMixin:
    """The rich edit messages of an edit control created as a rich edit"""

    EM_EXGETSEL, EM_EXLIMITTEXT, EM_EXLINEFROMCHAR, EM_EXSETSEL = 0x434, 0x435, 0x436, 0x437
    EM_GETCHARFORMAT, EM_GETEVENTMASK, EM_GETPARAFORMAT = 0x43A, 0x43B, 0x43D
    EM_HIDESELECTION, EM_SETBKGNDCOLOR, EM_SETCHARFORMAT = 0x43F, 0x443, 0x444
    EM_SETEVENTMASK, EM_SETOLECALLBACK, EM_SETPARAFORMAT = 0x445, 0x446, 0x447
    EM_SETTARGETDEVICE, EM_STREAMIN, EM_STREAMOUT, EM_GETTEXTRANGE = 0x448, 0x449, 0x44A, 0x44B
    EM_SETOPTIONS, EM_GETOPTIONS, EM_AUTOURLDETECT = 0x44D, 0x44E, 0x45B
    EM_GETTEXTLENGTHEX, EM_SETTEXTEX, EM_SETEDITSTYLE = 0x45F, 0x461, 0x4CC
    SF_TEXT, SF_RTF, SF_UNICODE, SFF_SELECTION = 0x1, 0x2, 0x10, 0x8000
    STREAM_CHUNK = 4096

    @staticmethod
    def is_rich_edit(control):
        return getattr(control, 'rich_edit', False)

    def _rich_text_of(self, data, rtf, unicode):
        """Text of streamed or set bytes: RTF (also when it starts like an RTF
        document, as rich edit controls do), UTF-16 or ANSI text"""
        if rtf or data.lstrip().startswith(b'{\\rtf'):
            return rtf_to_text(data)
        if unicode:
            return data.decode('utf-16-le', errors='replace')
        return data.decode(config.ANSI_CODEPAGE, errors='replace')

    def _rich_stream_in(self, control, flags, editstream):
        """EM_STREAMIN: the program's callback fills buffers until it gives
        no more bytes or returns an error (stored in EDITSTREAM.dwError)"""
        try:
            cookie, _, callback = struct.unpack('<III', self.emu.uc.mem_read(editstream, 12))
        except UcError:
            return 0
        buffer = self.emu.heap_alloc(self.STREAM_CHUNK + 4)
        if not buffer:
            return 0
        count_ptr = buffer + self.STREAM_CHUNK
        data = bytearray()
        error = 0
        try:
            while True:
                self._mem_write(count_ptr, b'\x00' * 4)
                error = self.emu.call_callback(callback, [cookie, buffer, self.STREAM_CHUNK,
                                                          count_ptr]) & 0xFFFFFFFF
                if error:
                    break
                got = struct.unpack('<I', self.emu.uc.mem_read(count_ptr, 4))[0]
                if not got or got > self.STREAM_CHUNK:
                    break
                data += self.emu.uc.mem_read(buffer, got)
        except UcError:
            error = error or 1
        finally:
            self.emu.heap_free(buffer)
        self._mem_write(editstream + 4, struct.pack('<I', error))
        text = self._rich_text_of(bytes(data), flags & self.SF_RTF, flags & self.SF_UNICODE)
        if not flags & self.SFF_SELECTION:
            control.select_all()
        control.replace_selection(text)
        if not flags & self.SFF_SELECTION:
            control.set_selection(0)
            control.edit_top_line = 0
        control.modified = False
        self.dirty_controls[control.hwnd] = True
        return len(text)

    def _rich_stream_out(self, control, flags, editstream):
        """EM_STREAMOUT: the text (or selection) as text or RTF, handed to
        the program's callback in pieces"""
        try:
            cookie, _, callback = struct.unpack('<III', self.emu.uc.mem_read(editstream, 12))
        except UcError:
            return 0
        text = control.text
        if flags & self.SFF_SELECTION:
            start, end = control.selection()
            text = text[start:end]
        if flags & self.SF_RTF:
            data = text_to_rtf(text)
        elif flags & self.SF_UNICODE:
            data = text.encode('utf-16-le')
        else:
            data = text.encode(config.ANSI_CODEPAGE, errors='replace')
        buffer = self.emu.heap_alloc(self.STREAM_CHUNK + 4)
        if not buffer:
            return 0
        count_ptr = buffer + self.STREAM_CHUNK
        error = 0
        try:
            for offset in range(0, len(data), self.STREAM_CHUNK):
                chunk = data[offset:offset + self.STREAM_CHUNK]
                self._mem_write(buffer, chunk)
                self._mem_write(count_ptr, b'\x00' * 4)
                error = self.emu.call_callback(callback, [cookie, buffer, len(chunk),
                                                          count_ptr]) & 0xFFFFFFFF
                if error:
                    break
        finally:
            self.emu.heap_free(buffer)
        self._mem_write(editstream + 4, struct.pack('<I', error))
        return len(text)

    def _rich_edit_message(self, control, Msg, wParam, lParam, wide):
        """Rich edit messages (EM_ above WM_USER); None for the others"""
        if Msg == self.EM_STREAMIN:
            return self._rich_stream_in(control, wParam, lParam) if lParam else 0
        if Msg == self.EM_STREAMOUT:
            return self._rich_stream_out(control, wParam, lParam) if lParam else 0
        if Msg == self.EM_EXLIMITTEXT:
            # 0 is the default limit of a rich edit: 64K characters
            control.text_limit = lParam or 0x10000
            return 0
        if Msg == self.EM_EXGETSEL:
            start, end = control.selection()
            if lParam:
                self._mem_write(lParam, struct.pack('<ii', start, end))
            return 0
        if Msg == self.EM_EXSETSEL:
            try:
                start, end = struct.unpack('<ii', self.emu.uc.mem_read(lParam, 8))
            except UcError:
                return 0
            n = len(control.text)
            if start == 0 and end == -1:
                control.select_all()
            elif start < 0:
                control.set_selection(control.sel_caret)
            else:
                control.set_selection(min(start, n), n if end < 0 else min(end, n))
            return control.selection()[1]
        if Msg == self.EM_EXLINEFROMCHAR:
            offset = lParam - (1 << 32) if lParam & 0x80000000 else lParam
            return control.line_of(control.selection()[0] if offset < 0 else offset)
        if Msg == self.EM_GETTEXTRANGE:
            try:
                start, end, buffer = struct.unpack('<iiI', self.emu.uc.mem_read(lParam, 12))
            except UcError:
                return 0
            text = control.text[max(start, 0):len(control.text) if end < 0 else end]
            units = self._text_units(text, wide)
            self._write_units(buffer, units, wide)
            return len(units)
        if Msg == self.EM_GETTEXTLENGTHEX:
            return len(control.text)
        if Msg == self.EM_SETTEXTEX:
            # SETTEXTEX: flags (ST_SELECTION = 2), code page (1200: UTF-16)
            try:
                flags, codepage = struct.unpack('<II', self.emu.uc.mem_read(wParam, 8))
            except UcError:
                return 0
            unicode = codepage == 1200
            data = b''
            if lParam:
                data = (self._read_long_text(lParam, True).encode('utf-16-le') if unicode
                        else self.read_string(lParam, max_len=1 << 20).encode(
                            config.ANSI_CODEPAGE, errors='replace'))
            text = self._rich_text_of(data, False, unicode)
            if not flags & 2:
                control.select_all()
            control.replace_selection(text)
            self.dirty_controls[control.hwnd] = True
            return 1
        if Msg == self.EM_SETBKGNDCOLOR:
            previous = getattr(control, 'rich_bk_color', 0xFFFFFF)
            # wParam nonzero: the system window color
            control.rich_bk_color = 0xFFFFFF if wParam else lParam & 0xFFFFFF
            return previous
        if Msg == self.EM_SETEVENTMASK:
            previous = getattr(control, 'rich_event_mask', 0)
            control.rich_event_mask = lParam
            return previous
        if Msg == self.EM_GETEVENTMASK:
            return getattr(control, 'rich_event_mask', 0)
        if Msg in (self.EM_SETOPTIONS, self.EM_GETOPTIONS):
            options = getattr(control, 'rich_options', 0)
            if Msg == self.EM_SETOPTIONS:
                options = {1: lParam, 2: options | lParam, 3: options & ~lParam,
                           4: options ^ lParam}.get(wParam, options)  # ECOOP_*
                control.rich_options = options
            return options
        if Msg in (self.EM_SETCHARFORMAT, self.EM_SETPARAFORMAT, self.EM_SETTARGETDEVICE,
                   self.EM_SETOLECALLBACK):
            return 1  # Accepted; the text keeps the control's one font
        if Msg in (self.EM_GETCHARFORMAT, self.EM_GETPARAFORMAT, self.EM_HIDESELECTION,
                   self.EM_AUTOURLDETECT, self.EM_SETEDITSTYLE):
            return 0
        return None
