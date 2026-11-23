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

"""A pygame font that keeps the texts it rendered"""

import threading
from collections import OrderedDict


class CachedFont:
    """Wraps a pygame font: render() gives the surface it made for the same
    text, colors and antialiasing before. The desktop is redrawn 60 times a
    second, and rendering every title, menu, control and program text again
    each frame took most of the frame (with the GUI lock held, which the
    emulation thread waits for). The surfaces are shared: they are only
    blitted, never changed. Everything else goes to the font itself."""

    MAX_TEXTS = 2048  # Per font; the least recently used texts go first

    def __init__(self, font):
        self._font = font
        self._texts = OrderedDict()
        self._lock = threading.Lock()  # Text metrics are read on the emulation thread too

    def render(self, text, antialias, color, background=None):
        key = (text, bool(antialias), tuple(color),
               None if background is None else tuple(background))
        with self._lock:
            surface = self._texts.get(key)
            if surface is not None:
                self._texts.move_to_end(key)
                return surface
        surface = self._font.render(text, antialias, color, background)
        with self._lock:
            self._texts[key] = surface
            if len(self._texts) > self.MAX_TEXTS:
                self._texts.popitem(last=False)
        return surface

    def __getattr__(self, name):
        return getattr(self._font, name)
