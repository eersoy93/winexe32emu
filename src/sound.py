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

"""Sound output (PlaySound, Beep and the like) with pygame"""

import array
import threading

from .config import PYGAME_AVAILABLE
from .logger import log

if PYGAME_AVAILABLE:
    import pygame


class SoundPlayer:
    """Audio output for Beep, MessageBeep and PlaySound (pygame.mixer).

    Without pygame or an audio device every sound is silent; callers still
    keep the right timing (e.g. Beep blocks for its duration).
    """

    _lock = threading.Lock()
    _format = None        # None: not tried yet, False: no audio, else mixer format
    _play_sound = None    # Sound started by PlaySound (only one at a time)
    _play_owner = None    # Process (WinAPIHandler) that started _play_sound

    # Sample packing per mixer sample size: (array typecode, scale, offset)
    _SAMPLE_FORMATS = {-16: ('h', 32767, 0), 16: ('H', 32767, 32768),
                       -8: ('b', 127, 0), 8: ('B', 127, 128),
                       32: ('f', 1.0, 0), -32: ('f', 1.0, 0)}

    @classmethod
    def _mixer(cls):
        """Initialize pygame.mixer once; returns (rate, size, channels) or False."""
        with cls._lock:
            if cls._format is None:
                cls._format = False
                if PYGAME_AVAILABLE:
                    try:
                        if not pygame.mixer.get_init():
                            pygame.mixer.init(frequency=44100, size=-16, channels=1)
                        cls._format = pygame.mixer.get_init() or False
                    except pygame.error as e:
                        log.warning(f"No audio device, sounds are silent: {e}")
            return cls._format

    @classmethod
    def available(cls):
        return bool(cls._mixer())

    @classmethod
    def tone(cls, frequency, duration_ms, volume=0.2):
        """Start a square-wave tone (PC speaker style); returns the Sound or None"""
        fmt = cls._mixer()
        if not fmt or frequency <= 0 or duration_ms <= 0:
            return None
        rate, size, channels = fmt
        packing = cls._SAMPLE_FORMATS.get(size)
        if packing is None:
            return None
        typecode, scale, offset = packing
        count = int(rate * duration_ms / 1000)
        half_period = rate / (2.0 * frequency)
        amplitude = volume * scale
        values = [amplitude if int(i / half_period) % 2 == 0 else -amplitude
                  for i in range(count)]
        # Short linear fade in/out avoids clicks at the edges
        fade = min(count // 2, max(1, rate // 500))
        for i in range(fade):
            k = i / fade
            values[i] *= k
            values[count - 1 - i] *= k
        values = [v + offset for v in values]
        if typecode != 'f':
            values = [int(v) for v in values]
        if channels > 1:
            values = [v for v in values for _ in range(channels)]
        samples = array.array(typecode, values)
        try:
            sound = pygame.mixer.Sound(buffer=samples.tobytes())
            sound.play()
            return sound
        except pygame.error as e:
            log.debug(f"Tone playback failed: {e}")
            return None

    @classmethod
    def play(cls, source, loop=False, owner=None):
        """Play a WAV file path or file-like object as the PlaySound sound.

        Returns the length in seconds, or None if it cannot be decoded.
        """
        if not cls._mixer():
            return 0.0
        try:
            sound = pygame.mixer.Sound(file=source)
        except (pygame.error, OSError) as e:
            log.debug(f"Cannot play sound: {e}")
            return None
        cls.stop()
        cls._play_sound, cls._play_owner = sound, owner
        sound.play(loops=-1 if loop else 0)
        return sound.get_length()

    @classmethod
    def play_tone(cls, frequency, duration_ms, owner=None):
        """Play a tone as the PlaySound sound (system sound aliases)"""
        cls.stop()
        cls._play_sound, cls._play_owner = cls.tone(frequency, duration_ms), owner

    @classmethod
    def playing(cls):
        """True while the PlaySound sound is still playing"""
        sound = cls._play_sound
        return bool(sound and sound.get_num_channels())

    @classmethod
    def stop(cls):
        """Stop the PlaySound sound"""
        sound, cls._play_sound = cls._play_sound, None
        cls._play_owner = None
        if sound is not None:
            try:
                sound.stop()
            except pygame.error:
                pass

    @classmethod
    def stop_owned_by(cls, owner):
        """Stop the PlaySound sound if the given process started it"""
        if cls._play_sound is not None and cls._play_owner is owner:
            cls.stop()
