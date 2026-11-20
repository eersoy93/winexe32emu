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

"""PseudoWindowsGUI mixin: Dropdown and popup menus with submenus"""


from .. import winapi
from ..config import PYGAME_AVAILABLE

if PYGAME_AVAILABLE:
    import pygame


class MenusMixin:
    """Dropdown and popup menus with submenus"""

    # ---------- Menus: dropdowns with submenus, popup menus ----------

    MENU_ITEM_H = 20
    MENU_SEP_H = 7

    def _menu_panel_rects(self, items, x, y):
        """Panel rect and item rects of a menu panel opened at (x, y); an item
        with a column break (MF_MENUBREAK, MF_MENUBARBREAK) starts a new column"""
        columns = []
        for sub in items:
            if not columns or sub.get('break'):
                columns.append([])
            columns[-1].append(sub)
        widths = []
        for column in columns:
            width = 120 if len(columns) == 1 else 60
            for sub in column:
                if sub.get('text'):
                    shortcut_w = (self.font.size(sub['shortcut'])[0] + 24
                                  if sub.get('shortcut') else 0)
                    width = max(width, self.font.size(sub['text'])[0] + 48 + shortcut_w)
            widths.append(width)
        height = max(sum(self.MENU_SEP_H if sub.get('separator') else self.MENU_ITEM_H
                         for sub in column) for column in columns) + 4 if columns else 4
        total = sum(widths) + 4 * (len(widths) - 1) if widths else 120
        x = max(0, min(x, self.width - total))
        y = max(0, min(y, self.height - height))
        panel = pygame.Rect(x, y, total, height)
        rects = []
        left = x
        for column, width in zip(columns, widths, strict=False):
            top = y + 2
            for sub in column:
                h = self.MENU_SEP_H if sub.get('separator') else self.MENU_ITEM_H
                rects.append(pygame.Rect(left + 2, top, width - 4, h))
                top += h
            left += width + 4
        return panel, rects

    def _menu_panels(self, items, x, y, path):
        """[(items, panel rect, item rects)] of a menu and its open submenus"""
        panels = []
        for level in range(len(path) + 1):
            panel, rects = self._menu_panel_rects(items, x, y)
            panels.append((items, panel, rects))
            if level >= len(path):
                break
            index = path[level]
            if not 0 <= index < len(items) or items[index].get('items') is None:
                break
            x, y = panel.right - 3, rects[index].y - 2
            items = items[index]['items']
        return panels

    def _draw_menu_panels(self, panels):
        mouse = self.mouse_pos
        for items, panel, rects in panels:
            self._draw_menu_panel(panel)
            for index, (sub, rect) in enumerate(zip(items, rects, strict=False)):
                if index and sub.get('break') == 'bar':
                    # Etched vertical line between the columns
                    bar_x = rect.x - 5
                    pygame.draw.line(self.screen, (128, 128, 128), (bar_x, panel.y + 2),
                                     (bar_x, panel.bottom - 3))
                    pygame.draw.line(self.screen, (255, 255, 255), (bar_x + 1, panel.y + 2),
                                     (bar_x + 1, panel.bottom - 3))
                if sub.get('separator'):
                    mid = rect.y + rect.height // 2
                    pygame.draw.line(self.screen, (128, 128, 128), (rect.x + 2, mid),
                                     (rect.right - 2, mid))
                    pygame.draw.line(self.screen, (255, 255, 255), (rect.x + 2, mid + 1),
                                     (rect.right - 2, mid + 1))
                    continue
                hovered = rect.collidepoint(mouse)
                if hovered:
                    pygame.draw.rect(self.screen, self.COLOR_TITLE_BAR, rect)
                if sub.get('grayed'):
                    color = (128, 128, 128) if not hovered else (192, 192, 192)
                else:
                    color = self.COLOR_TITLE_TEXT if hovered else self.COLOR_TEXT
                ty = rect.y + (rect.height - self.font.get_height()) // 2
                if sub.get('checked'):
                    if sub.get('radio'):
                        pygame.draw.circle(self.screen, color, (rect.x + 9, rect.centery), 3)
                    else:
                        pygame.draw.lines(self.screen, color, False,
                                          [(rect.x + 5, rect.centery),
                                           (rect.x + 8, rect.centery + 3),
                                           (rect.x + 13, rect.centery - 3)], 2)
                self.screen.blit(self.font.render(sub['text'], True, color), (rect.x + 20, ty))
                if sub.get('shortcut'):
                    surface = self.font.render(sub['shortcut'], True, color)
                    self.screen.blit(surface, (rect.right - 16 - surface.get_width(), ty))
                if sub.get('items') is not None:
                    ax, ay = rect.right - 9, rect.centery
                    pygame.draw.polygon(self.screen, color,
                                        [(ax, ay - 4), (ax, ay + 4), (ax + 4, ay)])

    def _menu_hover(self, panels, path, notify):
        """Open the submenu under the mouse (closing deeper ones); notify(hmenu,
        index) for a newly opened one"""
        mouse = self.mouse_pos
        for level in range(len(panels) - 1, -1, -1):
            items, panel, rects = panels[level]
            if not panel.collidepoint(mouse):
                continue
            for index, (sub, rect) in enumerate(zip(items, rects, strict=False)):
                if not rect.collidepoint(mouse) or sub.get('separator'):
                    continue
                if sub.get('items') is not None and not sub.get('grayed'):
                    new_path = path[:level] + [index]
                    if path[:level + 1] != new_path:
                        notify(sub.get('hmenu', 0), index)
                        path[:] = new_path
                elif len(path) > level:
                    path[:] = path[:level]
                return
            return

    def _menu_panels_click(self, panels, pos):
        """('command', id) / ('submenu', level, index) / ('inside',) / None"""
        for level in range(len(panels) - 1, -1, -1):
            items, panel, rects = panels[level]
            if not panel.collidepoint(pos):
                continue
            for index, (sub, rect) in enumerate(zip(items, rects, strict=False)):
                if rect.collidepoint(pos) and not sub.get('separator'):
                    if sub.get('grayed'):
                        return ('inside',)
                    if sub.get('items') is not None:
                        return ('submenu', level, index)
                    return ('command', sub['id'])
            return ('inside',)
        return None

    def _menu_root(self):
        """(items, x, y, owner window) of the open menu bar dropdown, or None"""
        if not self.open_menu:
            return None
        hwnd, index = self.open_menu
        win = self.windows.get(hwnd)
        if not win or not win.visible or win.minimized or not win.menu or index >= len(win.menu):
            return None
        rects = self._menu_item_rects(win)
        if index >= len(rects):
            return None
        return win.menu[index].get('items') or [], rects[index].x, rects[index].bottom, win

    def _post_enter_menu(self, win):
        """The menu bar's menu mode starts: WM_INITMENU with the menu bar
        (Word, for one, decides there which commands are available)"""
        if win is not None and win.owner is not None and self._is_app_window(win.hwnd):
            win.owner.post_window_message(win.hwnd, winapi.WinAPIHandler.WM_INITMENU,
                                          win.menu_handle, 0)

    def _post_init_menu(self, win, hmenu, index):
        if hmenu and win is not None and win.owner is not None and self._is_app_window(win.hwnd):
            win.owner.post_window_message(win.hwnd, winapi.WinAPIHandler.WM_INITMENUPOPUP, hmenu,
                                          index & 0xFFFF)

    def _draw_popup_menu(self):
        popup = self.popup_menu
        if popup is None:
            return
        panels = self._menu_panels(popup['tree'], popup['x'], popup['y'], popup['open'])
        owner = popup['owner']

        def notify(hmenu, index):
            if hmenu:
                owner.post_window_message(popup['hwnd'], winapi.WinAPIHandler.WM_INITMENUPOPUP,
                                          hmenu, index & 0xFFFF)
        self._menu_hover(panels, popup['open'], notify)
        panels = self._menu_panels(popup['tree'], popup['x'], popup['y'], popup['open'])
        self._draw_menu_panels(panels)

    def _handle_popup_menu_click(self, pos, button):
        """Click while a popup menu (TrackPopupMenu) is open: always consumed"""
        popup = self.popup_menu
        panels = self._menu_panels(popup['tree'], popup['x'], popup['y'], popup['open'])
        hit = self._menu_panels_click(panels, pos)
        if hit is None:
            popup['done'] = True
            self.popup_menu = None
        elif hit[0] == 'command':
            popup['result'] = hit[1]
            popup['done'] = True
            self.popup_menu = None
        elif hit[0] == 'submenu':
            popup['open'][:] = popup['open'][:hit[1]] + [hit[2]]
        return True
