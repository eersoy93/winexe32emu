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

"""WinAPIHandler mixin: DirectSound (dsound.dll) through the pygame mixer.

A sound buffer is a block of guest memory the program fills between Lock
and Unlock. A buffer played once is converted to the mixer's format and
played as a whole. A looping buffer is a ring the program may keep writing
to ahead of the play cursor (a stream): the cursor follows the clock, and
the mixer plays a copy of the ring in a loop, like a sound card, and what
the program writes (Unlock) is copied into it, so the sound goes on while
the program is busy. A ring whose rate does not divide the mixer's is
handed to the mixer piece by piece a little ahead of the cursor instead.

Interfaces, structures and constants follow the public DirectX header
(dsound.h of MinGW-w64) and the DirectSound documentation.
"""

import struct
import time

from unicorn import UcError

from ..logger import log
from ..sound import SoundPlayer
from .com import ComMixin
from .core import CoreMixin

try:
    import pygame
except ImportError:  # pragma: no cover - sound is optional
    pygame = None

ComMixin.COM_INTERFACES.update({
    'dsound': [
        ('QueryInterface', 3), ('AddRef', 1), ('Release', 1), ('CreateSoundBuffer', 4),
        ('GetCaps', 2), ('DuplicateSoundBuffer', 3), ('SetCooperativeLevel', 3),
        ('Compact', 1), ('GetSpeakerConfig', 2), ('SetSpeakerConfig', 2),
        ('Initialize', 2)],
    'dsbuffer': [
        ('QueryInterface', 3), ('AddRef', 1), ('Release', 1), ('GetCaps', 2),
        ('GetCurrentPosition', 3), ('GetFormat', 4), ('GetVolume', 2), ('GetPan', 2),
        ('GetFrequency', 2), ('GetStatus', 2), ('Initialize', 3), ('Lock', 8), ('Play', 4),
        ('SetCurrentPosition', 2), ('SetFormat', 2), ('SetVolume', 2), ('SetPan', 2),
        ('SetFrequency', 2), ('Stop', 1), ('Unlock', 5), ('Restore', 1)],
})

CoreMixin.STDCALL_ARG_COUNTS.update({
    'DirectSoundCreate': 3, 'DirectSoundCreate8': 3,
    'DirectSoundEnumerateA': 2, 'DirectSoundEnumerateW': 2,
})


class DirectSoundMixin:
    """DirectSound (dsound.dll) through the pygame mixer"""

    IID_IDIRECTSOUND = '279afa83-4981-11ce-a521-0020af0be560'
    IID_IDIRECTSOUNDBUFFER = '279afa85-4981-11ce-a521-0020af0be560'

    DS_OK = 0
    DSERR_INVALIDPARAM = 0x80070057
    DSERR_BADFORMAT = 0x88780064
    DSERR_NODRIVER = 0x88780078
    DSERR_INVALIDCALL = 0x88780032

    DSBCAPS_PRIMARYBUFFER = 0x1
    DSBPLAY_LOOPING = 0x1
    DSBSTATUS_PLAYING, DSBSTATUS_LOOPING = 0x1, 0x4
    DSBLOCK_FROMWRITECURSOR, DSBLOCK_ENTIREBUFFER = 0x1, 0x2
    # DSCAPS_PRIMARYSTEREO | PRIMARY16BIT | EMULDRIVER | SECONDARYSTEREO | SECONDARY16BIT
    DSCAPS_FLAGS = 0x2 | 0x8 | 0x20 | 0x200 | 0x800
    DS_MAX_BUFFER_BYTES = 64 * 1024 * 1024
    DSSPEAKER_STEREO = 4

    def DirectSoundCreate(self, args):
        """DirectSoundCreate(lpGUID, lplpDS, pUnkOuter) - the mixer as the one
        sound device; DSERR_NODRIVER without sound output"""
        if not args[1]:
            return self.DSERR_INVALIDPARAM
        if not SoundPlayer.available():
            self._mem_write(args[1], struct.pack('<I', 0))
            log.debug("DirectSoundCreate() -> DSERR_NODRIVER")
            return self.DSERR_NODRIVER
        state = {'kind': 'dsound'}
        self._com_new_object([((self.IID_IUNKNOWN, self.IID_IDIRECTSOUND),
                               self._com_vtable('IDirectSound', 'dsound'))], state)
        self._mem_write(args[1], struct.pack('<I', state['base']))
        return self.DS_OK

    DirectSoundCreate8 = DirectSoundCreate

    def DirectSoundEnumerateA(self, args):
        """DirectSoundEnumerateA/W(callback, context) - the primary sound driver"""
        if not args[0]:
            return self.DSERR_INVALIDPARAM
        if SoundPlayer.available():
            text = self.emu.heap_alloc(64)
            self._mem_write(text, 'Primary Sound Driver'.encode('utf-16-le') + b'\x00' * 24)
            self._mem_write(text + 48, b'Primary Sound Driver'[:15] + b'\x00')
            # (GUID, description, module, context); both texts are empty or
            # readable in either character width
            self.emu.call_callback(args[0], [0, text + 48, text + 40, args[1]])
            self.emu.heap_free(text)
        return self.DS_OK

    DirectSoundEnumerateW = DirectSoundEnumerateA

    # ---------- IDirectSound ----------

    def _ds_buffers(self):
        buffers = getattr(self, '_ds_buffer_list', None)
        if buffers is None:
            buffers = self._ds_buffer_list = []
        return buffers

    def _ds_new_buffer(self, fmt, size, primary, mem=0):
        state = {'kind': 'dsbuffer', 'format': fmt, 'size': size, 'primary': primary,
                 'mem': mem, 'shared': bool(mem), 'playing': False, 'looping': False,
                 'started': 0.0, 'offset': 0, 'fed': 0, 'channel': None,
                 'volume': 0, 'pan': 0, 'frequency': fmt['rate']}
        if not primary and not mem:
            state['mem'] = self.emu.heap_alloc(size)
            if not state['mem']:
                return None
            self._mem_write(state['mem'], (b'\x80' if fmt['bits'] == 8 else b'\x00') * size)
        self._com_new_object([((self.IID_IUNKNOWN, self.IID_IDIRECTSOUNDBUFFER),
                               self._com_vtable('IDirectSoundBuffer', 'dsbuffer'))], state)
        self._ds_buffers().append(state)
        return state

    DS_DEFAULT_FORMAT = {'tag': 1, 'channels': 2, 'rate': 22050, 'avg': 88200,
                         'align': 4, 'bits': 16, 'extra': b''}

    def _com_dsound(self, method, wide, args):
        result = self._com_unknown(method, args)
        if result is not None:
            return result
        if method == 'CreateSoundBuffer':
            desc, out = args[1], args[2]
            if not desc or not out:
                return self.DSERR_INVALIDPARAM
            try:
                _, flags, size, _, lp_format = struct.unpack(
                    '<5I', self.emu.uc.mem_read(desc, 20))
            except UcError:
                return self.DSERR_INVALIDPARAM
            primary = bool(flags & self.DSBCAPS_PRIMARYBUFFER)
            if primary:
                fmt, size = dict(self.DS_DEFAULT_FORMAT), 0
            else:
                fmt = self._read_waveformat(self.emu.uc, lp_format) if lp_format else None
                if fmt is None or not 0 < size <= self.DS_MAX_BUFFER_BYTES:
                    return self.DSERR_INVALIDPARAM
                if (fmt['tag'] != 1 or fmt['bits'] not in (8, 16) or
                        fmt['channels'] not in (1, 2) or not fmt['rate'] or not fmt['align']):
                    return self.DSERR_BADFORMAT
            state = self._ds_new_buffer(fmt, size, primary)
            if state is None:
                return self.DSERR_INVALIDPARAM
            state['flags'] = flags
            self._mem_write(out, struct.pack('<I', state['base']))
            return self.DS_OK
        if method == 'DuplicateSoundBuffer':
            original = self.com_objects.get(args[1])
            if original is None or original.get('kind') != 'dsbuffer' or not args[2]:
                return self.DSERR_INVALIDPARAM
            # The copy plays the same memory with its own position and volume
            state = self._ds_new_buffer(original['format'], original['size'], False,
                                        original['mem'])
            state['flags'] = original.get('flags', 0)
            original['shared'] = True
            self._mem_write(args[2], struct.pack('<I', state['base']))
            return self.DS_OK
        if method == 'GetCaps':
            size = min(self._read_u32(args[1]), 96) if args[1] else 0
            if size < 8:
                return self.DSERR_INVALIDPARAM
            caps = bytearray(size)
            struct.pack_into('<II', caps, 0, size, self.DSCAPS_FLAGS)
            if size >= 20:
                struct.pack_into('<III', caps, 8, 8000, 48000, 1)  # Rates, primary buffers
            self._mem_write(args[1], bytes(caps))
            return self.DS_OK
        if method == 'GetSpeakerConfig':
            self._mem_write(args[1], struct.pack('<I', self.DSSPEAKER_STEREO))
        return self.DS_OK

    # ---------- IDirectSoundBuffer ----------

    def _ds_released(self, state):
        self._ds_stop(state)
        buffers = self._ds_buffers()
        if state in buffers:
            buffers.remove(state)
        if state['mem'] and not state['shared']:
            self.emu.heap_free(state['mem'])
        state['mem'] = 0

    def _ds_byte_rate(self, state):
        fmt = state['format']
        return max(1, state['frequency'] * fmt['align'])

    def _ds_position(self, state):
        """Play cursor (bytes) from the time the buffer has been playing"""
        if not state['playing'] or not state['size']:
            return state['offset']
        played = int((time.monotonic() - state['started']) * self._ds_byte_rate(state))
        played -= played % state['format']['align']
        position = state['offset'] + played
        if state['looping']:
            return position % state['size']
        if position >= state['size']:
            state['playing'], state['offset'] = False, 0
            return 0
        return position

    def _ds_sound(self, state, data):
        """Mixer sound of buffer bytes, or None without sound output"""
        mixer = SoundPlayer._mixer()
        if not mixer or mixer[1] != -16 or not data:
            return None
        fmt = state['format']
        pcm = self._convert_samples(self._pcm_samples(data, fmt['bits']), fmt['channels'],
                                    state['frequency'], mixer[2], mixer[0], 16)
        try:
            sound = pygame.mixer.Sound(buffer=pcm)
        except pygame.error as e:
            log.debug(f"DirectSound: cannot play buffer: {e}")
            return None
        return sound

    @staticmethod
    def _ds_gain(state):
        """Mixer volume (0..1) of a buffer's attenuation in hundredths of a dB"""
        return 10 ** (max(-10000, min(0, state['volume'])) / 2000)

    def _ds_channel(self, state):
        """Mixer channel of a buffer (None without a free one)"""
        if state['channel'] is None:
            try:
                state['channel'] = pygame.mixer.find_channel()
                if state['channel'] is not None:
                    state['channel'].set_volume(self._ds_gain(state))
            except pygame.error:
                state['channel'] = None
        return state['channel']

    def _ds_start(self, state):
        """(Re)start the mixer playback of a buffer from its play position"""
        self._ds_stop_channel(state)
        if state['primary'] or not state['mem'] or not SoundPlayer.available():
            return
        if state['looping']:
            state['fed'] = 0
            if not self._ds_ring_start(state):
                self._ds_feed(state)
            return
        try:
            data = bytes(self.emu.uc.mem_read(state['mem'], state['size']))
        except UcError:
            return
        sound = self._ds_sound(state, data[state['offset']:])
        channel = self._ds_channel(state) if sound is not None else None
        if channel is not None:
            try:
                channel.play(sound)
            except pygame.error:
                state['channel'] = None

    # A looping buffer is handed to the mixer this far ahead of its play
    # cursor (seconds): programs that stream write further ahead than this
    DS_FEED_AHEAD = 0.1
    DS_FEED_MIN = 0.01

    def _ds_feed(self, state):
        """Give the mixer the next bytes of a looping buffer: those between
        what it already has and a little past the play cursor"""
        channel = self._ds_channel(state)
        if channel is None or not state['size'] or state.get('ring') is not None:
            return
        align, rate = state['format']['align'], self._ds_byte_rate(state)
        played = int((time.monotonic() - state['started']) * rate)
        try:
            busy = channel.get_busy()
            if busy and channel.get_queue() is not None:
                return  # The mixer holds one sound after the playing one
            if not busy and state['fed'] < played:
                state['fed'] = played - played % align  # It ran dry: catch up
            count = played + int(self.DS_FEED_AHEAD * rate) - state['fed']
            count = min(count - count % align, state['size'])
            if count < int(self.DS_FEED_MIN * rate):
                return
            start = (state['offset'] + state['fed']) % state['size']
            first = min(count, state['size'] - start)
            data = bytes(self.emu.uc.mem_read(state['mem'] + start, first))
            if count > first:
                data += bytes(self.emu.uc.mem_read(state['mem'], count - first))
            sound = self._ds_sound(state, data)
            state['fed'] += count
            if sound is None:
                return
            if busy:
                channel.queue(sound)
            else:
                channel.play(sound)
        except (pygame.error, UcError):
            pass

    def _ds_ring_start(self, state):
        """Play a looping buffer as a sound card does: a mixer sound as long
        as the ring loops, and the program's writes are copied into it
        (_ds_ring_copy). Pieces handed over in time ran dry while Red Alert 2
        computed a frame, the music stuttered. False if the buffer's rate does
        not divide the mixer's (its copy would drift from the cursor)."""
        mixer = SoundPlayer._mixer()
        rate, size, align = state['frequency'], state['size'], state['format']['align']
        if not mixer or mixer[1] != -16 or rate <= 0 or mixer[0] % rate or size < align:
            return False
        frame_bytes = mixer[0] // rate * mixer[2] * 2  # Mixer bytes per buffer frame
        try:
            ring = pygame.mixer.Sound(buffer=bytes(size // align * frame_bytes))
        except pygame.error:
            return False
        state['ring'], state['ring_view'] = ring, memoryview(ring).cast('B')
        state['ring_origin'] = state['offset']  # The buffer byte the sound starts with
        self._ds_ring_copy(state, 0, size)
        channel = self._ds_channel(state)
        if channel is not None:
            try:
                channel.play(ring, loops=-1)
            except pygame.error:
                state['channel'] = None
        return True

    def _ds_ring_copy(self, state, start, count):
        """Copy bytes the program wrote to a buffer into its mixer sound"""
        mixer = SoundPlayer._mixer()
        fmt, size, view = state['format'], state['size'], state.get('ring_view')
        if view is None or not mixer:
            return
        align, rate = fmt['align'], state['frequency']
        frame_bytes = mixer[0] // rate * mixer[2] * 2
        start -= start % align
        count = min(size, count + align - 1)
        count -= count % align
        origin = state['ring_origin']
        while count > 0:
            # One piece ends at the end of the buffer or where the sound wraps
            to_end = size - start
            to_origin = (origin - start) % size or size
            n = min(count, to_end, to_origin)
            data = bytes(self.emu.uc.mem_read(state['mem'] + start, n))
            pcm = self._convert_samples(self._pcm_samples(data, fmt['bits']), fmt['channels'],
                                        rate, mixer[2], mixer[0], 16)
            at = (start - origin) % size // align * frame_bytes
            pcm = pcm[:len(view) - at]
            view[at:at + len(pcm)] = pcm
            start, count = (start + n) % size, count - n

    def _ds_stop_channel(self, state):
        state['ring'] = state['ring_view'] = None
        channel, state['channel'] = state['channel'], None
        if channel is not None:
            try:
                channel.stop()
            except pygame.error:
                pass

    def _ds_stop(self, state):
        state['offset'] = self._ds_position(state)
        state['playing'] = False
        self._ds_stop_channel(state)

    def _dsound_pump(self):
        """Keep the looping buffers playing (called with the other audio work
        of the message loop and by the buffers' own methods)"""
        for state in list(getattr(self, '_ds_buffer_list', ())):
            if state['playing'] and state['looping'] and not state['primary'] and \
                    state.get('ring') is None:
                self._ds_feed(state)

    def stop_direct_sound(self):
        """Silence every buffer (the process ended)"""
        for state in list(getattr(self, '_ds_buffer_list', ())):
            state['playing'] = False
            self._ds_stop_channel(state)

    def _com_dsbuffer(self, method, wide, args):
        state = self.com_objects.get(args[0])
        result = self._com_unknown(method, args)
        if result is not None:
            if method == 'Release' and state is not None and args[0] not in self.com_objects:
                self._ds_released(state)
            return result
        if state is None or state.get('kind') != 'dsbuffer':
            return self.DSERR_INVALIDPARAM
        try:
            return self._ds_buffer_method(state, method, args)
        except UcError:
            return self.DSERR_INVALIDPARAM

    def _ds_buffer_method(self, state, method, args):
        fmt = state['format']
        if state['playing'] and state['looping'] and not state['primary']:
            self._ds_feed(state)  # Programs that stream poll their buffer
        if method == 'GetCaps':
            size = self._read_u32(args[1])
            caps = struct.pack('<5I', 20, state.get('flags', 0), state['size'], 0, 0)
            self._mem_write(args[1], caps[:max(8, min(size, 20))])
        elif method == 'GetCurrentPosition':
            position = self._ds_position(state)
            if args[1]:
                self._mem_write(args[1], struct.pack('<I', position))
            if args[2]:
                # The write cursor runs a little ahead of the play cursor
                ahead = self._ds_byte_rate(state) // 50 if state['playing'] else 0
                ahead -= ahead % fmt['align']
                write = (position + ahead) % state['size'] if state['size'] else 0
                self._mem_write(args[2], struct.pack('<I', write))
        elif method == 'GetFormat':
            data = struct.pack('<HHIIHHH', 1, fmt['channels'], fmt['rate'],
                               fmt['rate'] * fmt['align'], fmt['align'], fmt['bits'], 0)
            if args[1]:
                data = data[:args[2]]
                self._mem_write(args[1], data)
            if args[3]:
                self._mem_write(args[3], struct.pack('<I', len(data)))
        elif method in ('GetVolume', 'GetPan', 'GetFrequency'):
            value = state[method[3:].lower()]
            self._mem_write(args[1], struct.pack('<I', value & 0xFFFFFFFF))
        elif method in ('SetVolume', 'SetPan'):
            value = args[1] - (1 << 32) if args[1] & 0x80000000 else args[1]
            if not -10000 <= value <= (0 if method == 'SetVolume' else 10000):
                return self.DSERR_INVALIDPARAM
            state[method[3:].lower()] = value
            if method == 'SetVolume' and state['channel'] is not None:
                try:
                    state['channel'].set_volume(self._ds_gain(state))
                except pygame.error:
                    pass
        elif method == 'SetFrequency':
            # DSBFREQUENCY_ORIGINAL (0): the rate of the buffer's format
            frequency = args[1] or fmt['rate']
            if frequency != state['frequency'] and state['playing']:
                # The cursor goes on from where it is at the new speed
                state['offset'] = self._ds_position(state)
                state['started'] = time.monotonic()
                state['frequency'] = frequency
                if state['looping']:
                    self._ds_start(state)
            state['frequency'] = frequency
        elif method == 'GetStatus':
            self._ds_position(state)
            status = 0
            if state['playing']:
                status = self.DSBSTATUS_PLAYING | (
                    self.DSBSTATUS_LOOPING if state['looping'] else 0)
            self._mem_write(args[1], struct.pack('<I', status))
        elif method == 'SetFormat':
            if not state['primary']:
                return self.DSERR_INVALIDCALL
            new_format = self._read_waveformat(self.emu.uc, args[1]) if args[1] else None
            if new_format is None:
                return self.DSERR_INVALIDPARAM
            state['format'], state['frequency'] = new_format, new_format['rate']
        elif method == 'Lock':
            return self._ds_lock(state, args)
        elif method == 'Unlock':
            return self._ds_unlock(state, args)
        elif method == 'Play':
            state['offset'] = self._ds_position(state)
            state['looping'] = bool(args[3] & self.DSBPLAY_LOOPING)
            state['playing'] = True
            state['started'] = time.monotonic()
            self._ds_start(state)
        elif method == 'Stop':
            self._ds_stop(state)
        elif method == 'SetCurrentPosition':
            if state['size'] and args[1] >= state['size']:
                return self.DSERR_INVALIDPARAM
            state['offset'] = args[1] - args[1] % fmt['align']
            if state['playing']:
                state['started'] = time.monotonic()
                self._ds_start(state)
        return self.DS_OK

    def _ds_lock(self, state, args):
        """Lock(offset, bytes, ptr1, bytes1, ptr2, bytes2, flags): one or two
        pieces of the buffer (the second one after a wrap to its start)"""
        offset, count, ptr1, count1, ptr2, count2, flags = args[1:8]
        size = state['size']
        if state['primary'] or not size or not ptr1 or not count1:
            return self.DSERR_INVALIDCALL if state['primary'] else self.DSERR_INVALIDPARAM
        if flags & self.DSBLOCK_FROMWRITECURSOR:
            offset = self._ds_position(state)
        if flags & self.DSBLOCK_ENTIREBUFFER:
            count = size
        if offset >= size or not 0 < count <= size:
            return self.DSERR_INVALIDPARAM
        first = min(count, size - offset)
        self._mem_write(ptr1, struct.pack('<I', state['mem'] + offset))
        self._mem_write(count1, struct.pack('<I', first))
        if ptr2:
            self._mem_write(ptr2, struct.pack('<I', state['mem'] if count > first else 0))
        if count2:
            self._mem_write(count2, struct.pack('<I', count - first))
        return self.DS_OK

    def _ds_unlock(self, state, args):
        ptr1, count1, ptr2, count2 = args[1:5]
        if state['primary']:
            return self.DSERR_INVALIDCALL
        mem, size = state['mem'], state['size']
        if not mem <= ptr1 <= mem + size or count1 > size or count2 > size:
            return self.DSERR_INVALIDPARAM
        if state.get('ring') is not None:
            self._ds_ring_copy(state, ptr1 - mem, count1)
            if ptr2 and count2:
                self._ds_ring_copy(state, ptr2 - mem, count2)
        elif state['playing'] and state['looping']:
            self._ds_feed(state)
        return self.DS_OK
