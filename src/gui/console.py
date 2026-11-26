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

"""PseudoWindowsGUI mixin: Console windows of console programs"""


from ..config import PYGAME_AVAILABLE
from ..windows import FakeConsole, gui_locked

if PYGAME_AVAILABLE:
    import pygame


class ConsoleMixin:
    """Console windows of console programs"""

    # ==================== CONSOLE WINDOW ====================

    @gui_locked
    def create_console(self, title, owner):
        """Open a console window for a process (called on its emulation thread)"""
        offset = 24 * (self.consoles_opened % 8)  # Cascade, so none hides another
        self.consoles_opened += 1
        hwnd = self.create_window(title, 50 + offset, 400 - offset, 600, 280, owner=owner)
        self.windows[hwnd].bg_color = (12, 12, 12)  # Black background
        console = FakeConsole(hwnd)
        self.consoles[hwnd] = console
        self.show_window(hwnd)
        return console

    @gui_locked
    def cancel_console_input(self, console):
        """Unblock a pending read for good (process ending or console closing)"""
        console.cancelled = True
        console.input_active = False
        console.input_result = None
        console.input_ready.set()

    @gui_locked
    def wake_console_input(self, console):
        """End the pending read of a console that stays open (a child process
        sharing its parent's console ends): the read returns None"""
        if console.input_active:
            console.input_active = False
            console.input_result = None
            console.input_ready.set()

    @gui_locked
    def close_console(self, console):
        """Close a console window; like on Windows, the programs sharing it end too"""
        self.cancel_console_input(console)
        for process in list(console.attached):
            process.request_termination()
        self.consoles.pop(console.hwnd, None)
        self._remove_window(console.hwnd)

    @gui_locked
    def clear_console(self, console):
        """Clear a console window (CLS)"""
        console.lines.clear()
        console.line_open = False
        console.scroll = 0

    def _draw_console_window(self, window, console):
        """Draw console window"""
        if not window.visible or window.minimized:
            return

        is_active = (window.hwnd == self.active_window)
        self._draw_window_frame(window, self.BORDER)
        self._draw_title_bar(window, is_active)

        # Content area (console output, the line being typed continues it)
        content_x = window.x + 5
        content_y = window.y + 30
        content_width = window.width - 10
        content_height = window.height - 35

        # Content background
        content_rect = pygame.Rect(content_x, content_y, content_width, content_height)
        self._draw_edge(content_rect.inflate(2, 2), self.COLOR_BUTTON_SHADOW,
                        self.COLOR_BUTTON_BORDER_LIGHT)
        pygame.draw.rect(self.screen, (12, 12, 12), content_rect)

        rows = list(console.lines)
        if console.input_active:
            # Up to the insertion point, then the rest: the cursor goes between
            cursor = min(console.input_cursor, len(console.input))
            color = self.CONSOLE_COLORS['stdin']
            typed = [(console.input[:cursor], color), (console.input[cursor:], color)]
            if console.line_open and rows:
                rows[-1] = rows[-1] + typed
            else:
                rows.append(typed)

        # Draw the last rows that fit (scrolled back by console.scroll)
        line_height = 14
        max_visible_lines = max(1, (content_height - 4) // line_height)
        end_line = max(0, len(rows) - console.scroll)
        start_line = max(0, end_line - max_visible_lines)

        self.screen.set_clip(content_rect)
        y_offset = content_y + 2
        x = cursor_x = content_x + 3
        visible = rows[start_line:end_line]
        for index, row in enumerate(visible):
            x = content_x + 3
            for piece, (text, color) in enumerate(row):
                if (console.input_active and index == len(visible) - 1 and
                        piece == len(row) - 1):
                    cursor_x = x  # Before the typed text after the insertion point
                if text:
                    surface = self.font_console.render(text, True, color)
                    self.screen.blit(surface, (x, y_offset))
                    x += surface.get_width()
            y_offset += line_height

        # Blinking underline cursor at the insertion point
        if console.input_active and self.console_cursor_visible and console.scroll == 0:
            cursor_h = self.font_console.get_height()
            pygame.draw.rect(self.screen, self.CONSOLE_COLORS['stdin'],
                             (cursor_x, y_offset - line_height + cursor_h - 3, 8, 2))
        self.screen.set_clip(None)

    # Console text colors per stream
    CONSOLE_COLORS = {'stdout': (192, 192, 192), 'stderr': (255, 64, 64),
                      'stdin': (192, 192, 192)}

    def console_edit_key(self, console, key, unicode):
        """Edit the line typed into a console like the Windows console does:
        Left/Right/Home/End move, Backspace/Delete remove, Esc clears, Up/Down
        recall the lines entered before. Enter is handled by the caller."""
        text, cursor = console.input, min(console.input_cursor, len(console.input))
        if key == pygame.K_BACKSPACE:
            if cursor > 0:
                text, cursor = text[:cursor - 1] + text[cursor:], cursor - 1
        elif key == pygame.K_DELETE:
            text = text[:cursor] + text[cursor + 1:]
        elif key == pygame.K_LEFT:
            cursor = max(0, cursor - 1)
        elif key == pygame.K_RIGHT:
            cursor = min(len(text), cursor + 1)
        elif key == pygame.K_HOME:
            cursor = 0
        elif key == pygame.K_END:
            cursor = len(text)
        elif key == pygame.K_ESCAPE:
            text, cursor = "", 0
        elif key in (pygame.K_UP, pygame.K_DOWN):
            step = -1 if key == pygame.K_UP else 1
            pos = console.history_pos + step
            if 0 <= pos < len(console.history):
                console.history_pos = pos
                text = console.history[pos]
            elif pos >= len(console.history):
                console.history_pos = len(console.history)
                text = ""
            cursor = len(text)
        elif unicode and unicode.isprintable():
            text, cursor = text[:cursor] + unicode + text[cursor:], cursor + len(unicode)
        console.input, console.input_cursor = text, cursor
        self.console_cursor_visible = True
        self.console_cursor_timer = 0

    def console_line_entered(self, console, line):
        """Keep an entered line for Up/Down (not empty ones, nor a repeat)"""
        if line.strip() and (not console.history or console.history[-1] != line):
            console.history.append(line)
            del console.history[:-FakeConsole.MAX_HISTORY]

    @gui_locked
    def console_write(self, console, text, stream="stdout"):
        """Write to a process's console (thread-safe); text without a final LF
        leaves the line open, so later output (or typed input) continues it"""
        color = self.CONSOLE_COLORS.get(stream, self.CONSOLE_COLORS['stdout'])

        # CR has no glyph; console lines are split on LF only
        text = text.replace('\r\n', '\n').replace('\r', '')

        for i, part in enumerate(text.split('\n')):
            if i > 0:
                # LF: end the open line, or add an empty one at a line start
                if not console.line_open:
                    console.lines.append([])
                console.line_open = False
            if part:
                if console.line_open:
                    console.lines[-1].append((part, color))
                else:
                    console.lines.append([(part, color)])
                    console.line_open = True

        # Check maximum line count
        del console.lines[:-FakeConsole.MAX_LINES]

    def request_console_input(self, console):
        """
        Read a line typed into a console - called from the emulation thread,
        blocks until the GUI thread delivers it. None if the read is cancelled.
        """
        with self.lock:
            if console.cancelled or console.hwnd not in self.consoles:
                return None
            console.input = ""
            console.input_cursor = 0
            console.history_pos = len(console.history)
            console.input_result = None
            console.input_ready.clear()
            console.input_active = True
            self.console_cursor_visible = True
            self.console_cursor_timer = 0
            # Bring the console to the front so typing goes to it
            win = self.windows[console.hwnd]
            win.minimized = False
            if console.hwnd in self.z_order:
                self.z_order.remove(console.hwnd)
            self.z_order.append(console.hwnd)
            self.active_window = console.hwnd

        console.input_ready.wait()  # Blocking wait
        return console.input_result
