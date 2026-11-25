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

"""WinAPIHandler mixin: winmm: timers, PCM / ADPCM conversion, waveOut, msacm32,
joystick, MCI, PlaySound"""

import sys
import os
import io
import array
import struct
import time
import wave

from unicorn import UcError

from .. import config, winapi
from ..config import PYGAME_AVAILABLE
from ..logger import log
from ..sound import SoundPlayer

if PYGAME_AVAILABLE:
    import pygame


class WinmmMixin:
    """winmm: timers, PCM / ADPCM conversion, waveOut, msacm32, joystick, MCI, PlaySound"""

    # ---------- winmm ----------

    def timeGetTime(self, args):
        """timeGetTime emulation - milliseconds, like GetTickCount"""
        self._audio_pump()
        return int(time.time() * 1000) & 0xFFFFFFFF

    def timeBeginPeriod(self, args):
        """timeBeginPeriod emulation - TIMERR_NOERROR"""
        return 0

    def timeEndPeriod(self, args):
        """timeEndPeriod emulation - TIMERR_NOERROR"""
        return 0

    TIME_PERIODIC, TIME_CALLBACK_EVENT_SET, TIME_CALLBACK_EVENT_PULSE = 0x1, 0x10, 0x20

    def timeSetEvent(self, args):
        """timeSetEvent(delay, resolution, proc, user, flags) - a multimedia
        timer: like Windows, its own thread calls proc(id, 0, user, 0, 0) (or
        sets / pulses the event proc) after delay ms, once or periodically.
        Returns the timer id, 0 on failure."""
        delay, _resolution, proc, user, flags = args[:5]
        timers = self.__dict__.setdefault('_mm_timers', {})
        timer_id = self.__dict__.get('_mm_next_timer', 1)
        self._mm_next_timer = timer_id + 1
        timers[timer_id] = {'delay': max(delay, 1), 'proc': proc, 'user': user,
                            'flags': flags}
        stub = self.emu.get_api_stub('winmm.dll', 'MmTimerThreadProc')
        if not stub or self.emu.create_thread(stub, timer_id) is None:
            timers.pop(timer_id, None)
            return 0
        log.debug(f"timeSetEvent({delay} ms, 0x{proc:x}, flags 0x{flags:x}) -> {timer_id}")
        return timer_id

    def timeKillEvent(self, args):
        """timeKillEvent(id) - TIMERR_NOERROR, or MMSYSERR_INVALPARAM"""
        return 0 if self.__dict__.get('_mm_timers', {}).pop(args[0], None) else 11

    def MmTimerThreadProc(self, args):
        """Start routine of a multimedia timer's thread (see timeSetEvent)"""
        timer_id = args[0]
        timers = self.__dict__.get('_mm_timers', {})
        thread = self.emu.current_thread
        while not self.emu.stop_emulation and not getattr(thread, 'stop', False):
            timer = timers.get(timer_id)
            if timer is None:
                break
            self._wait_ms(timer['delay'], until=lambda: timer_id in timers)
            if timers.get(timer_id) is not timer or self.emu.stop_emulation:
                break
            kind = timer['flags'] & 0x30
            if kind == self.TIME_CALLBACK_EVENT_SET:
                self.SetEvent([timer['proc']])
            elif kind == self.TIME_CALLBACK_EVENT_PULSE:
                self.PulseEvent([timer['proc']])
            elif timer['proc']:
                self.emu.call_callback(timer['proc'], [timer_id, 0, timer['user'], 0, 0])
            if not timer['flags'] & self.TIME_PERIODIC:
                timers.pop(timer_id, None)
        return 0

    # ---------- PCM / ADPCM sample conversion ----------

    @staticmethod
    def _read_waveformat(uc, address):
        """WAVEFORMATEX -> dict (tag, channels, rate, avg, align, bits, extra) or None"""
        try:
            tag, channels, rate, avg, align, bits = struct.unpack(
                '<HHIIHH', uc.mem_read(address, 16))
            extra = b''
            if tag != 1:
                cb_size = struct.unpack('<H', uc.mem_read(address + 16, 2))[0]
                extra = bytes(uc.mem_read(address + 18, min(cb_size, 1024))) if cb_size else b''
        except UcError:
            return None
        return {'tag': tag, 'channels': channels, 'rate': rate, 'avg': avg,
                'align': align, 'bits': bits, 'extra': extra}

    @staticmethod
    def _pcm_samples(data, bits):
        """PCM bytes (8-bit unsigned or 16-bit signed) -> array of 16-bit samples"""
        if bits == 8:
            return array.array('h', ((b - 128) << 8 for b in data))
        samples = array.array('h')
        samples.frombytes(bytes(data[:len(data) & ~1]))
        if sys.byteorder != 'little':
            samples.byteswap()
        return samples

    @staticmethod
    def _convert_samples(samples, channels, rate, dst_channels, dst_rate, dst_bits):
        """Interleaved 16-bit samples -> PCM bytes in another layout (nearest
        neighbour resampling, stereo is mixed down by averaging)"""
        if channels == 2 and dst_channels == 1:
            samples = array.array('h', ((a + b) >> 1 for a, b in
                                        zip(samples[0::2], samples[1::2], strict=False)))
        elif channels == 1 and dst_channels == 2:
            stereo = array.array('h', bytes(4 * len(samples)))
            stereo[0::2] = samples
            stereo[1::2] = samples
            samples = stereo
        if rate != dst_rate and rate > 0:
            frames = len(samples) // dst_channels
            count = frames * dst_rate // rate
            if dst_channels == 1:
                samples = array.array('h', (samples[i * rate // dst_rate]
                                            for i in range(count)))
            else:
                resampled = array.array('h', bytes(4 * count))
                for c in range(dst_channels):
                    channel = samples[c::dst_channels]
                    resampled[c::dst_channels] = array.array(
                        'h', (channel[i * rate // dst_rate] for i in range(count)))
                samples = resampled
        if dst_bits == 8:
            return bytes(((v >> 8) + 128) & 0xFF for v in samples)
        if sys.byteorder != 'little':
            samples = array.array('h', samples)
            samples.byteswap()
        return samples.tobytes()

    MS_ADPCM_ADAPT = (230, 230, 230, 230, 307, 409, 512, 614,
                      768, 614, 512, 409, 307, 230, 230, 230)
    MS_ADPCM_COEFS = ((256, 0), (512, -256), (0, 0), (192, 64),
                      (240, 0), (460, -208), (392, -232))
    IMA_INDEX = (-1, -1, -1, -1, 2, 4, 6, 8, -1, -1, -1, -1, 2, 4, 6, 8)
    IMA_STEPS = (
        7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 19, 21, 23, 25, 28, 31, 34, 37, 41, 45,
        50, 55, 60, 66, 73, 80, 88, 97, 107, 118, 130, 143, 157, 173, 190, 209, 230,
        253, 279, 307, 337, 371, 408, 449, 494, 544, 598, 658, 724, 796, 876, 963,
        1060, 1166, 1282, 1411, 1552, 1707, 1878, 2066, 2272, 2499, 2749, 3024, 3327,
        3660, 4026, 4428, 4871, 5358, 5894, 6484, 7132, 7845, 8630, 9493, 10442, 11487,
        12635, 13899, 15289, 16818, 18500, 20350, 22385, 24623, 27086, 29794, 32767)

    @classmethod
    def _decode_ms_adpcm(cls, data, fmt):
        """Microsoft ADPCM blocks -> interleaved 16-bit samples"""
        channels, align = fmt['channels'], fmt['align']
        coefs = list(cls.MS_ADPCM_COEFS)
        extra = fmt['extra']
        if len(extra) >= 4:
            count = struct.unpack_from('<H', extra, 2)[0]
            if len(extra) >= 4 + 4 * count:
                coefs = [struct.unpack_from('<hh', extra, 4 + 4 * i) for i in range(count)]
        out = array.array('h')
        for start in range(0, len(data), align):
            block = data[start:start + align]
            if len(block) < 7 * channels:
                break
            pos = 0
            predictors = list(block[pos:pos + channels])
            pos += channels
            delta = list(struct.unpack_from(f'<{channels}h', block, pos))
            pos += 2 * channels
            s1 = list(struct.unpack_from(f'<{channels}h', block, pos))
            pos += 2 * channels
            s2 = list(struct.unpack_from(f'<{channels}h', block, pos))
            pos += 2 * channels
            out.extend(s2)
            out.extend(s1)
            c1 = [coefs[p][0] if p < len(coefs) else 0 for p in predictors]
            c2 = [coefs[p][1] if p < len(coefs) else 0 for p in predictors]
            ch = 0
            for byte in block[pos:]:
                for nibble in (byte >> 4, byte & 0x0F):
                    signed = nibble - 16 if nibble >= 8 else nibble
                    sample = ((s1[ch] * c1[ch] + s2[ch] * c2[ch]) >> 8) + signed * delta[ch]
                    sample = max(-32768, min(32767, sample))
                    s2[ch], s1[ch] = s1[ch], sample
                    delta[ch] = max(16, (cls.MS_ADPCM_ADAPT[nibble] * delta[ch]) >> 8)
                    out.append(sample)
                    ch = (ch + 1) % channels
        return out

    @classmethod
    def _decode_ima_adpcm(cls, data, fmt):
        """IMA (DVI) ADPCM blocks -> interleaved 16-bit samples"""
        channels, align = fmt['channels'], fmt['align']
        out = array.array('h')
        for start in range(0, len(data), align):
            block = data[start:start + align]
            if len(block) < 4 * channels:
                break
            predictor, index = [], []
            for c in range(channels):
                sample, idx = struct.unpack_from('<hB', block, 4 * c)
                predictor.append(sample)
                index.append(min(88, idx))
            body = block[4 * channels:]
            chunks = len(body) // (4 * channels)
            decoded = [[] for _ in range(channels)]
            for chunk in range(chunks):
                for c in range(channels):
                    base = (chunk * channels + c) * 4
                    for byte in body[base:base + 4]:
                        for nibble in (byte & 0x0F, byte >> 4):
                            step = cls.IMA_STEPS[index[c]]
                            diff = step >> 3
                            if nibble & 4:
                                diff += step
                            if nibble & 2:
                                diff += step >> 1
                            if nibble & 1:
                                diff += step >> 2
                            if nibble & 8:
                                diff = -diff
                            predictor[c] = max(-32768, min(32767, predictor[c] + diff))
                            index[c] = max(0, min(88, index[c] + cls.IMA_INDEX[nibble]))
                            decoded[c].append(predictor[c])
            first = [struct.unpack_from('<h', block, 4 * c)[0] for c in range(channels)]
            out.extend(first)
            for i in range(len(decoded[0])):
                out.extend(decoded[c][i] for c in range(channels))
        return out

    def _decode_audio(self, data, fmt):
        """Audio bytes in a supported WAVEFORMAT -> interleaved 16-bit samples, or None"""
        if fmt['tag'] == 1 and fmt['bits'] in (8, 16):
            return self._pcm_samples(data, fmt['bits'])
        if fmt['tag'] == 2 and fmt['align']:
            return self._decode_ms_adpcm(data, fmt)
        if fmt['tag'] == 0x11 and fmt['align']:
            return self._decode_ima_adpcm(data, fmt)
        return None

    # ---------- Wave output (waveOut*) ----------

    WOM_OPEN, WOM_CLOSE, WOM_DONE = 0x3BB, 0x3BC, 0x3BD
    WHDR_DONE, WHDR_PREPARED, WHDR_INQUEUE = 0x01, 0x02, 0x10

    def _wave_callback(self, hwo, dev, message, param1=0):
        """Notify the waveOut client (window, thread or callback function)"""
        kind, callback = dev['callback_type'], dev['callback']
        if not callback and kind != 0x20000:
            return
        if kind == 0x10000:      # CALLBACK_WINDOW
            self.post_window_message(callback, message, hwo, param1)
        elif kind == 0x20000:    # CALLBACK_THREAD
            self.post_window_message(0, message, hwo, param1)
        elif kind == 0x30000:    # CALLBACK_FUNCTION
            self.emu.call_callback(callback, [hwo, message, dev['instance'], param1, 0])

    def _wave_done(self, hwo, dev, pwh):
        """Hand a played buffer back to the application"""
        try:
            flags = struct.unpack('<I', self.emu.uc.mem_read(pwh + 16, 4))[0]
            flags = (flags | self.WHDR_DONE) & ~self.WHDR_INQUEUE
            self.emu.uc.mem_write(pwh + 16, struct.pack('<I', flags))
        except UcError:
            return
        self._wave_callback(hwo, dev, self.WOM_DONE, pwh)

    def _wave_feed(self, dev):
        """Keep the device's mixer channel supplied with converted buffers"""
        channel = dev['channel']
        while dev['pending'] and channel is not None:
            try:
                if not channel.get_busy():
                    channel.play(dev['pending'].pop(0))
                elif channel.get_queue() is None:
                    channel.queue(dev['pending'].pop(0))
                else:
                    break
            except pygame.error:
                dev['pending'].clear()

    def _audio_pump(self):
        """Advance wave output and MCI playback: completes played buffers
        (WOM_DONE) and reports finished MCI plays (MM_MCINOTIFY)"""
        if getattr(self, '_audio_pumping', False):
            return
        self._audio_pumping = True
        try:
            now = time.time()
            for hwo, dev in list(self.wave_outs.items()):
                self._wave_feed(dev)
                if dev['paused_at'] is not None:
                    continue
                while dev['queue'] and dev['queue'][0]['end'] <= now:
                    entry = dev['queue'].pop(0)
                    dev['done_bytes'] += entry['length']
                    self._wave_done(hwo, dev, entry['hdr'])
            for device_id, device in list(self.mci_devices.items()):
                if device['mode'] == 526 and self._mci_finished(device):
                    device['mode'] = 525
                    device['offset'] = device['length']
                    self._mci_notify(device_id, device, 1)  # MCI_NOTIFY_SUCCESSFUL
        finally:
            self._audio_pumping = False

    def waveOutOpen(self, args):
        """waveOutOpen emulation - PCM output through the pygame mixer"""
        phwo, device_id, pwfx, dwCallback, dwInstance, fdwOpen = args[:6]
        fmt = self._read_waveformat(self.emu.uc, pwfx)
        if fmt is None:
            return 11  # MMSYSERR_INVALPARAM
        log.info(f"waveOutOpen(format {fmt['tag']}, {fmt['channels']} ch, "
                 f"{fmt['rate']} Hz, {fmt['bits']} bit)")
        if device_id not in (0, 0xFFFFFFFF, 0xFFFF):
            return 2  # MMSYSERR_BADDEVICEID
        if (fmt['tag'] != 1 or fmt['bits'] not in (8, 16) or fmt['channels'] not in (1, 2)
                or not fmt['rate'] or not fmt['align']):
            return 32  # WAVERR_BADFORMAT
        if fdwOpen & 0x1:  # WAVE_FORMAT_QUERY
            return 0
        channel = None
        if SoundPlayer.available():
            try:
                channel = pygame.mixer.find_channel()
            except pygame.error:
                channel = None
        hwo = self.get_next_handle()
        dev = {'format': fmt, 'callback': dwCallback, 'instance': dwInstance,
               'callback_type': fdwOpen & 0x70000, 'queue': [], 'pending': [],
               'channel': channel, 'paused_at': None, 'done_bytes': 0}
        self.wave_outs[hwo] = dev
        if phwo and not self._mem_write(phwo, struct.pack('<I', hwo)):
            del self.wave_outs[hwo]
            return 11
        self._wave_callback(hwo, dev, self.WOM_OPEN)
        return 0

    def _wave_header_flags(self, pwh):
        try:
            return struct.unpack('<I', self.emu.uc.mem_read(pwh + 16, 4))[0]
        except UcError:
            return None

    def waveOutPrepareHeader(self, args):
        """waveOutPrepareHeader emulation"""
        if args[0] not in self.wave_outs:
            return 5  # MMSYSERR_INVALHANDLE
        flags = self._wave_header_flags(args[1])
        if flags is None:
            return 11
        self._mem_write(args[1] + 16, struct.pack('<I', flags | self.WHDR_PREPARED))
        return 0

    def waveOutUnprepareHeader(self, args):
        """waveOutUnprepareHeader emulation"""
        if args[0] not in self.wave_outs:
            return 5
        flags = self._wave_header_flags(args[1])
        if flags is None:
            return 11
        if flags & self.WHDR_INQUEUE:
            return 33  # WAVERR_STILLPLAYING
        self._mem_write(args[1] + 16, struct.pack('<I', flags & ~self.WHDR_PREPARED))
        return 0

    def waveOutWrite(self, args):
        """waveOutWrite emulation - queue a buffer; it is done after its play time"""
        hwo, pwh = args[0], args[1]
        dev = self.wave_outs.get(hwo)
        if dev is None:
            return 5
        try:
            lpData, length = struct.unpack('<II', self.emu.uc.mem_read(pwh, 8))
            flags = struct.unpack('<I', self.emu.uc.mem_read(pwh + 16, 4))[0]
            data = bytes(self.emu.uc.mem_read(lpData, length)) if length else b''
        except UcError:
            return 11
        if not flags & self.WHDR_PREPARED:
            return 34  # WAVERR_UNPREPARED
        self._mem_write(pwh + 16, struct.pack(
            '<I', (flags | self.WHDR_INQUEUE) & ~self.WHDR_DONE))
        fmt = dev['format']
        now = dev['paused_at'] if dev['paused_at'] is not None else time.time()
        start = max(now, dev['queue'][-1]['end']) if dev['queue'] else now
        duration = length / (fmt['avg'] or fmt['rate'] * fmt['align'])
        dev['queue'].append({'hdr': pwh, 'start': start, 'end': start + duration,
                             'length': length})
        mixer = SoundPlayer._mixer() if dev['channel'] is not None else None
        if mixer and mixer[1] == -16 and data:
            pcm = self._convert_samples(self._pcm_samples(data, fmt['bits']),
                                        fmt['channels'], fmt['rate'],
                                        mixer[2], mixer[0], 16)
            try:
                dev['pending'].append(pygame.mixer.Sound(buffer=pcm))
            except pygame.error as e:
                log.debug(f"waveOutWrite: cannot play buffer: {e}")
            if dev['paused_at'] is None:
                self._wave_feed(dev)
        return 0

    def _wave_stop_channel(self, dev):
        dev['pending'].clear()
        if dev['channel'] is not None:
            try:
                dev['channel'].stop()
            except pygame.error:
                pass

    def waveOutReset(self, args):
        """waveOutReset emulation - stop and return all buffers"""
        hwo = args[0]
        dev = self.wave_outs.get(hwo)
        if dev is None:
            return 5
        self._wave_stop_channel(dev)
        queue, dev['queue'] = dev['queue'], []
        dev['done_bytes'] = 0
        if dev['paused_at'] is not None:
            dev['paused_at'] = time.time()
        for entry in queue:
            self._wave_done(hwo, dev, entry['hdr'])
        return 0

    def waveOutPause(self, args):
        """waveOutPause emulation"""
        dev = self.wave_outs.get(args[0])
        if dev is None:
            return 5
        if dev['paused_at'] is None:
            dev['paused_at'] = time.time()
            if dev['channel'] is not None:
                dev['channel'].pause()
        return 0

    def waveOutRestart(self, args):
        """waveOutRestart emulation - continue after waveOutPause"""
        dev = self.wave_outs.get(args[0])
        if dev is None:
            return 5
        if dev['paused_at'] is not None:
            shift = time.time() - dev['paused_at']
            for entry in dev['queue']:
                entry['start'] += shift
                entry['end'] += shift
            dev['paused_at'] = None
            if dev['channel'] is not None:
                dev['channel'].unpause()
            self._wave_feed(dev)
        return 0

    def waveOutClose(self, args):
        """waveOutClose emulation"""
        hwo = args[0]
        dev = self.wave_outs.get(hwo)
        if dev is None:
            return 5
        self._audio_pump()
        if dev['queue']:
            return 33  # WAVERR_STILLPLAYING
        self._wave_stop_channel(dev)
        del self.wave_outs[hwo]
        self._wave_callback(hwo, dev, self.WOM_CLOSE)
        return 0

    def waveOutGetPosition(self, args):
        """waveOutGetPosition emulation - bytes, samples or milliseconds played"""
        hwo, pmmt = args[0], args[1]
        dev = self.wave_outs.get(hwo)
        if dev is None:
            return 5
        fmt = dev['format']
        played = dev['done_bytes']
        if dev['queue']:
            entry = dev['queue'][0]
            now = dev['paused_at'] if dev['paused_at'] is not None else time.time()
            span = entry['end'] - entry['start']
            fraction = min(1.0, max(0.0, (now - entry['start']) / span)) if span > 0 else 1.0
            played += int(entry['length'] * fraction) // fmt['align'] * fmt['align']
        try:
            kind = struct.unpack('<I', self.emu.uc.mem_read(pmmt, 4))[0]
        except UcError:
            return 11
        if kind == 2:     # TIME_SAMPLES
            value = played // fmt['align']
        elif kind == 1:   # TIME_MS
            value = played * 1000 // (fmt['avg'] or 1)
        else:
            kind, value = 4, played  # TIME_BYTES
        self._mem_write(pmmt, struct.pack('<II', kind, value & 0xFFFFFFFF))
        return 0

    # ---------- Audio compression manager (msacm32) ----------

    def acmFormatSuggest(self, args):
        """acmFormatSuggest emulation - always suggests 16-bit PCM"""
        pwfxSrc, pwfxDst, cbwfxDst, fdwSuggest = args[1], args[2], args[3], args[4]
        src = self._read_waveformat(self.emu.uc, pwfxSrc)
        if src is None or cbwfxDst < 16:
            return 11  # MMSYSERR_INVALPARAM
        dst = self._read_waveformat(self.emu.uc, pwfxDst) or {}
        channels = dst.get('channels') if fdwSuggest & 0x20000 else src['channels']
        rate = dst.get('rate') if fdwSuggest & 0x40000 else src['rate']
        bits = dst.get('bits') if fdwSuggest & 0x80000 else 16
        if (fdwSuggest & 0x10000 and dst.get('tag') != 1) or bits not in (8, 16) \
                or channels not in (1, 2) or src['channels'] not in (1, 2):
            return 512  # ACMERR_NOTPOSSIBLE
        align = channels * bits // 8
        data = struct.pack('<HHIIHH', 1, channels, rate, rate * align, align, bits)
        if cbwfxDst >= 18:
            data += b'\x00\x00'
        return 0 if self._mem_write(pwfxDst, data) else 11

    def acmStreamOpen(self, args):
        """acmStreamOpen emulation - PCM, MS ADPCM and IMA ADPCM to PCM"""
        phas, _, pwfxSrc, pwfxDst, _, _, _, fdwOpen = args[:8]
        src = self._read_waveformat(self.emu.uc, pwfxSrc)
        dst = self._read_waveformat(self.emu.uc, pwfxDst)
        if src is None or dst is None:
            return 11
        log.info(f"acmStreamOpen(src tag {src['tag']}, {src['channels']} ch, {src['rate']} Hz, "
                 f"{src['bits']} bit -> dst tag {dst['tag']}, {dst['channels']} ch, "
                 f"{dst['rate']} Hz, {dst['bits']} bit)")
        if (src['tag'] not in (1, 2, 0x11) or dst['tag'] != 1 or dst['bits'] not in (8, 16)
                or src['channels'] not in (1, 2) or dst['channels'] not in (1, 2)
                or (src['tag'] == 1 and src['bits'] not in (8, 16))
                or not src['align'] or not dst['align'] or not src['rate']):
            return 512  # ACMERR_NOTPOSSIBLE
        if fdwOpen & 0x1:  # ACM_STREAMOPENF_QUERY
            return 0
        has = self.get_next_handle()
        self.acm_streams[has] = {'src': src, 'dst': dst}
        if phas and not self._mem_write(phas, struct.pack('<I', has)):
            del self.acm_streams[has]
            return 11
        return 0

    def acmStreamClose(self, args):
        """acmStreamClose emulation"""
        return 0 if self.acm_streams.pop(args[0], None) is not None else 5

    def acmStreamSize(self, args):
        """acmStreamSize emulation - output size for an input size or vice versa"""
        stream = self.acm_streams.get(args[0])
        if stream is None:
            return 5
        cb, pdwOutput, flags = args[1], args[2], args[3]
        src, dst = stream['src'], stream['dst']

        def samples_per_block(fmt):
            if fmt['tag'] == 1:
                return 1
            if len(fmt['extra']) >= 2:
                return struct.unpack_from('<H', fmt['extra'])[0] or 1
            return 1

        src_frames = samples_per_block(src)
        if flags & 0x0F == 1:  # ACM_STREAMSIZEF_DESTINATION
            frames = cb // dst['align'] * src['rate'] // dst['rate']
            size = -(-frames // src_frames) * src['align']
        else:                  # ACM_STREAMSIZEF_SOURCE
            frames = -(-cb // src['align']) * src_frames
            size = -(-frames * dst['rate'] // src['rate']) * dst['align']
        return 0 if self._mem_write(pdwOutput, struct.pack('<I', size)) else 11

    def _acm_header_status(self, pash, set_flags=0, clear_flags=0):
        try:
            status = struct.unpack('<I', self.emu.uc.mem_read(pash + 4, 4))[0]
        except UcError:
            return None
        status = (status | set_flags) & ~clear_flags
        self._mem_write(pash + 4, struct.pack('<I', status))
        return status

    def acmStreamPrepareHeader(self, args):
        """acmStreamPrepareHeader emulation"""
        if args[0] not in self.acm_streams:
            return 5
        return 0 if self._acm_header_status(args[1], 0x20000) is not None else 11

    def acmStreamUnprepareHeader(self, args):
        """acmStreamUnprepareHeader emulation"""
        if args[0] not in self.acm_streams:
            return 5
        return 0 if self._acm_header_status(args[1], 0, 0x20000) is not None else 11

    def acmStreamConvert(self, args):
        """acmStreamConvert emulation - decodes/converts a whole source buffer"""
        stream = self.acm_streams.get(args[0])
        if stream is None:
            return 5
        pash = args[1]
        src, dst = stream['src'], stream['dst']
        try:
            (pbSrc, cbSrc, _, _, pbDst, cbDst) = struct.unpack(
                '<IIIIII', self.emu.uc.mem_read(pash + 12, 24))
            data = bytes(self.emu.uc.mem_read(pbSrc, cbSrc)) if cbSrc else b''
        except UcError:
            return 11
        if src['tag'] == 1:
            data = data[:len(data) // src['align'] * src['align']]
        samples = self._decode_audio(data, src)
        out = self._convert_samples(samples, src['channels'], src['rate'], dst['channels'],
                                    dst['rate'], dst['bits']) if samples else b''
        out = out[:cbDst // dst['align'] * dst['align']]
        if out and not self._mem_write(pbDst, out):
            return 11
        self._mem_write(pash + 20, struct.pack('<I', len(data)))
        self._mem_write(pash + 36, struct.pack('<I', len(out)))
        self._acm_header_status(pash, 0x10000)  # ACMSTREAMHEADER_STATUSF_DONE
        return 0

    # ---------- Joystick ----------

    def joyGetPos(self, args):
        """joyGetPos emulation - no joystick is connected"""
        return 167  # JOYERR_UNPLUGGED

    def joyGetDevCapsA(self, args):
        """joyGetDevCapsA emulation - no joystick driver"""
        return 165  # JOYERR_PARMS

    # ---------- Multimedia file I/O (mmio) ----------
    # An HMMIO is the address of its MMIOINFO block in guest memory, which an
    # installed I/O procedure (mmioInstallIOProc) reads and updates itself;
    # the standard DOS procedure reads and writes the host file. No buffering.

    MMIOINFO_SIZE = 72
    MMIOM_READ, MMIOM_WRITE, MMIOM_SEEK, MMIOM_OPEN, MMIOM_CLOSE = 0, 1, 2, 3, 4
    MMIO_RWMODE = 0x3
    MMIO_CREATE, MMIO_PARSE, MMIO_DELETE, MMIO_EXIST = 0x1000, 0x100, 0x200, 0x4000
    MMIOERR_FILENOTFOUND, MMIOERR_CANNOTOPEN, MMIOERR_INVALIDFILE = 257, 259, 288
    FOURCC_DOS = 0x20534F44  # 'DOS '

    def _mmio_state(self):
        """(installed I/O procedures {FOURCC: proc}, open DOS files {HMMIO: file})"""
        if not hasattr(self, 'mmio_procs'):
            self.mmio_procs = {}
            self.mmio_files = {}
        return self.mmio_procs, self.mmio_files

    @staticmethod
    def _fourcc_of(text):
        """FOURCC of up to 4 characters (upper case, padded with blanks)"""
        data = text.upper().encode('ascii', errors='replace')[:4].ljust(4, b' ')
        return struct.unpack('<I', data)[0]

    @staticmethod
    def _fourcc_upper(fcc):
        return struct.unpack('<I', struct.pack('<I', fcc).upper())[0]

    def mmioInstallIOProcA(self, args):
        """mmioInstallIOProcA emulation - install, remove or find the I/O
        procedure of a FOURCC (the file extension it handles)"""
        fcc, proc, flags = args[0], args[1], args[2]
        procs, _ = self._mmio_state()
        fcc = self._fourcc_upper(fcc)
        if flags & 0x10000:  # MMIO_INSTALLPROC
            if not proc:
                return 0
            procs[fcc] = proc
            return proc
        if flags & 0x20000:  # MMIO_REMOVEPROC
            return procs.pop(fcc) if procs.get(fcc) == proc else 0
        return procs.get(fcc, 0)  # MMIO_FINDPROC

    mmioInstallIOProcW = mmioInstallIOProcA

    def mmioStringToFOURCCA(self, args):
        """mmioStringToFOURCCA emulation (MMIO_TOUPPER: 0x10)"""
        text = self.read_string(args[0])[:4] if args[0] else ''
        data = (text.upper() if args[1] & 0x10 else text).encode('ascii', errors='replace')
        return struct.unpack('<I', data.ljust(4, b' ')[:4])[0]

    def _mmio_proc_for(self, filename, fcc, proc):
        """The I/O procedure for mmioOpen: the one given, the one of the FOURCC
        given, or the one of the extension before the first "+" of the name
        (C:\\BOOK.M14+TOPIC: the M14 procedure); 0 means the DOS one"""
        procs, _ = self._mmio_state()
        if proc:
            return proc
        if fcc:
            fcc = self._fourcc_upper(fcc)
            return 0 if fcc == self.FOURCC_DOS else procs.get(fcc, -1)
        if '+' in filename:
            ext = os.path.splitext(filename.split('+', 1)[0])[1][1:]
            if ext:
                return procs.get(self._fourcc_of(ext), -1)
        return 0

    def _mmio_call(self, info, message, param1=0, param2=0):
        proc = struct.unpack('<I', self.emu.uc.mem_read(info + 8, 4))[0]
        result = self.emu.call_callback(proc, [info, message, param1, param2])
        return result - (1 << 32) if result & 0x80000000 else result

    def _mmio_dos_open(self, filename, flags):
        """Open the host file of the DOS I/O procedure: (file, 0) or (None, error)"""
        path = self.resolve_drive_path(filename)
        if path is None:
            return None, self.MMIOERR_CANNOTOPEN
        mode = flags & self.MMIO_RWMODE
        if flags & self.MMIO_CREATE:
            if self._write_protected(path):
                return None, self.MMIOERR_CANNOTOPEN
            py_mode = 'w+b'
        elif mode == 0:
            py_mode = 'rb'
        else:
            if self._write_protected(path):
                return None, self.MMIOERR_CANNOTOPEN
            py_mode = 'r+b'
        if not os.path.isfile(path) and not flags & self.MMIO_CREATE:
            return None, self.MMIOERR_FILENOTFOUND
        try:
            return open(path, py_mode), 0
        except OSError:
            return None, self.MMIOERR_CANNOTOPEN

    def mmioOpenA(self, args):
        """mmioOpenA emulation - open a file through the DOS I/O procedure or
        an installed one; also MMIO_PARSE, MMIO_EXIST and MMIO_DELETE"""
        lpszFile, lpmmioinfo, flags = args[0], args[1], args[2]
        _, files = self._mmio_state()
        filename = self.read_string(lpszFile) if lpszFile else ''
        user = bytes(self.emu.uc.mem_read(lpmmioinfo, self.MMIOINFO_SIZE)) \
            if lpmmioinfo else bytes(self.MMIOINFO_SIZE)
        fcc, proc = struct.unpack_from('<II', user, 4)

        def fail(error):
            if lpmmioinfo:
                self._mem_write(lpmmioinfo + 12, struct.pack('<I', error))
            return 0

        proc = self._mmio_proc_for(filename, fcc, proc)
        log.debug(f"mmioOpenA({filename!r}, flags=0x{flags:x}) -> proc 0x{proc & 0xFFFFFFFF:x}")
        if proc == -1:
            return fail(self.MMIOERR_INVALIDFILE)
        if not proc and flags & (self.MMIO_PARSE | self.MMIO_EXIST | self.MMIO_DELETE):
            full = self.full_windows_path(filename) if filename else None
            path = self.resolve_drive_path(filename) if filename else None
            if flags & self.MMIO_DELETE:
                if path is None or not os.path.isfile(path) or self._write_protected(path):
                    return fail(self.MMIOERR_FILENOTFOUND)
                try:
                    os.remove(path)
                except OSError:
                    return fail(self.MMIOERR_CANNOTOPEN)
                return 1
            if full is None or (flags & self.MMIO_EXIST and
                                (path is None or not os.path.exists(path))):
                return fail(self.MMIOERR_FILENOTFOUND)
            if flags & self.MMIO_PARSE and lpszFile:
                self._mem_write(lpszFile, full.encode(config.ANSI_CODEPAGE,
                                                      errors='replace')[:127] + b'\0')
            return 1
        info = self.emu.heap_alloc(self.MMIOINFO_SIZE)
        if not info:
            return fail(self.MMIOERR_CANNOTOPEN)
        block = bytearray(self.MMIOINFO_SIZE)
        struct.pack_into('<III', block, 0, flags, fcc or self.FOURCC_DOS, proc)
        block[48:60] = user[48:60]  # adwInfo
        struct.pack_into('<I', block, 68, info)
        self.emu.uc.mem_write(info, bytes(block))
        if proc:
            error = self._mmio_call(info, self.MMIOM_OPEN, lpszFile, 0) & 0xFFFF
        else:
            fp, error = self._mmio_dos_open(filename, flags)
            if fp is not None:
                files[info] = fp
        if error:
            self.emu.heap_free(info)
            return fail(error)
        if flags & self.MMIO_EXIST:
            self.mmioClose([info, 0])
            return 1
        if lpmmioinfo:
            self._mem_write(lpmmioinfo + 12, struct.pack('<I', 0))
            self._mem_write(lpmmioinfo + 68, struct.pack('<I', info))
        return info

    def _mmio_dos_seek(self, info, fp, offset, origin):
        if origin not in (0, 1, 2):
            return -1
        try:
            position = fp.seek(offset if origin else max(offset, 0), origin)
        except (OSError, ValueError):
            return -1
        self._mem_write(info + 44, struct.pack('<i', position))
        return position

    def _mmio_check(self, hmmio):
        """True if hmmio is an open HMMIO of this process"""
        if not hmmio:
            return False
        try:
            return struct.unpack('<I', self.emu.uc.mem_read(hmmio + 68, 4))[0] == hmmio
        except UcError:
            return False

    def mmioRead(self, args):
        """mmioRead emulation - bytes read, 0 at the end, -1 on error"""
        hmmio, pch, cch = args[0], args[1], args[2]
        if not self._mmio_check(hmmio):
            return 0xFFFFFFFF
        cch = cch - (1 << 32) if cch & 0x80000000 else cch
        if cch <= 0:
            return 0
        fp = self._mmio_state()[1].get(hmmio)
        if fp is None:
            return self._mmio_call(hmmio, self.MMIOM_READ, pch, cch) & 0xFFFFFFFF
        data = fp.read(cch)
        if data and not self._mem_write(pch, data):
            return 0xFFFFFFFF
        self._mem_write(hmmio + 44, struct.pack('<i', fp.tell()))
        return len(data)

    def mmioWrite(self, args):
        """mmioWrite emulation - bytes written, -1 on error"""
        hmmio, pch, cch = args[0], args[1], args[2]
        if not self._mmio_check(hmmio):
            return 0xFFFFFFFF
        cch = cch - (1 << 32) if cch & 0x80000000 else cch
        if cch <= 0:
            return 0
        fp = self._mmio_state()[1].get(hmmio)
        if fp is None:
            return self._mmio_call(hmmio, self.MMIOM_WRITE, pch, cch) & 0xFFFFFFFF
        try:
            fp.write(bytes(self.emu.uc.mem_read(pch, cch)))
        except (UcError, OSError, ValueError):
            return 0xFFFFFFFF
        self._mem_write(hmmio + 44, struct.pack('<i', fp.tell()))
        return cch

    def mmioSeek(self, args):
        """mmioSeek emulation - the new position, -1 on error"""
        hmmio, offset, origin = args[0], args[1], args[2]
        if not self._mmio_check(hmmio):
            return 0xFFFFFFFF
        offset = offset - (1 << 32) if offset & 0x80000000 else offset
        fp = self._mmio_state()[1].get(hmmio)
        if fp is None:
            return self._mmio_call(hmmio, self.MMIOM_SEEK, offset, origin) & 0xFFFFFFFF
        return self._mmio_dos_seek(hmmio, fp, offset, origin) & 0xFFFFFFFF

    def mmioClose(self, args):
        """mmioClose emulation - close the file and free the HMMIO"""
        hmmio, flags = args[0], args[1]
        if not self._mmio_check(hmmio):
            return 5  # MMSYSERR_INVALHANDLE
        fp = self._mmio_state()[1].pop(hmmio, None)
        result = 0
        if fp is not None:
            fp.close()
        else:
            result = self._mmio_call(hmmio, self.MMIOM_CLOSE, flags, 0) & 0xFFFF
        self._mem_write(hmmio + 68, b'\0\0\0\0')
        self.emu.heap_free(hmmio)
        return result

    def waveOutGetNumDevs(self, args):
        """waveOutGetNumDevs emulation - one wave output device (sound may
        still be silent when the host has no audio)"""
        return 1

    MCI_ERRORS = {
        257: 'The specified device is not open or is not recognized by MCI.',
        261: 'The specified command was not recognized.',
        263: 'The specified device is not open or is not recognized by MCI.',
        274: 'The MCI device you are using does not support the specified command.',
        275: 'Cannot find the specified file. Make sure the path and filename are correct.',
    }

    def mciGetErrorStringA(self, args):
        """mciGetErrorStringA emulation - the text of an MCI error code"""
        error, buffer, size = args[0], args[1], args[2]
        if not buffer or not size:
            return 0
        default = ('Unknown problem while loading the specified device driver.' if error
                   else 'The specified command was carried out.')
        text = self.MCI_ERRORS.get(error, default)
        data = text.encode('ascii')[:size - 1] + b'\0'
        return 1 if self._mem_write(buffer, data) else 0

    def mciGetDeviceIDA(self, args):
        """mciGetDeviceIDA emulation - the ID of an open device by its alias,
        element or type; 0 when not open"""
        return self._mci_device_by_name(self.read_string(args[0]) if args[0] else '')

    def _mci_device_by_name(self, name):
        """The ID of an open MCI device by its alias, element or type; 0 if none"""
        name = name.lower()
        if name == 'all':
            return 0xFFFF
        for device_id, device in self.mci_devices.items():
            path = device['path'] or ''
            if name in (device['alias'].lower(), device['type'], os.path.basename(path).lower()):
                return device_id
        return 0

    # ---------- Media control interface (mciSendCommandA) ----------

    MM_MCINOTIFY = 0x3B9
    MCI_DEVICE_TYPES = {0x201: 'animation', 0x202: 'cdaudio', 0x203: 'dat',
                        0x204: 'digitalvideo', 0x205: 'other', 0x206: 'overlay',
                        0x207: 'scanner', 0x208: 'sequencer', 0x209: 'vcr',
                        0x20A: 'waveaudio', 0x20B: 'mmmovie'}

    def _mci_notify(self, device_id, device, code):
        """Post MM_MCINOTIFY for a pending notification (MCI_NOTIFY_*)"""
        hwnd, device['notify'] = device.get('notify'), None
        if hwnd:
            self.post_window_message(hwnd, self.MM_MCINOTIFY, code, device_id)

    def _mci_position(self, device):
        """Current position of an MCI device (milliseconds)"""
        if device['mode'] == 526:
            position = device['offset'] + (time.time() - device['started']) * 1000
            return int(min(position, device['length'])) if device['length'] else int(position)
        return int(device['offset'])

    def _mci_finished(self, device):
        """True when a playing device reached its end (or its MCI_TO point)"""
        if device.get('to') is not None and self._mci_position(device) >= device['to']:
            self._mci_stop_music(device)
            return True
        if device['music']:
            try:
                return SoundPlayer.available() and not pygame.mixer.music.get_busy()
            except pygame.error:
                return True
        return bool(device['length']) and self._mci_position(device) >= device['length']

    def _mci_stop_music(self, device):
        if device['music'] and getattr(winapi.WinAPIHandler, '_mci_music_owner', None) is device:
            try:
                pygame.mixer.music.stop()
            except pygame.error:
                pass
            winapi.WinAPIHandler._mci_music_owner = None

    @staticmethod
    def _media_length_ms(path):
        """Length of a WAV file (ms); 0 when unknown"""
        try:
            with wave.open(path, 'rb') as wav:
                return wav.getnframes() * 1000 // max(1, wav.getframerate())
        except (wave.Error, OSError, EOFError):
            pass
        if PYGAME_AVAILABLE and SoundPlayer.available():
            try:
                return int(pygame.mixer.Sound(path).get_length() * 1000)
            except (pygame.error, OSError):
                pass
        return 0

    def _mci_open(self, flags, params):
        try:
            _, _, lpType, lpElement, lpAlias = struct.unpack(
                '<5I', self.emu.uc.mem_read(params, 20))
        except UcError:
            return 11
        dev_type = ''
        if flags & 0x2000:  # MCI_OPEN_TYPE
            if flags & 0x1000:  # MCI_OPEN_TYPE_ID
                dev_type = self.MCI_DEVICE_TYPES.get(lpType & 0xFFFF, '')
            elif lpType:
                dev_type = self.read_string(lpType).lower()
        element = self.read_string(lpElement) if flags & 0x200 and lpElement else ''
        alias = self.read_string(lpAlias) if flags & 0x400 and lpAlias else ''
        if not dev_type and element:
            ext = os.path.splitext(element)[1].lower()
            dev_type = {'.wav': 'waveaudio', '.mid': 'sequencer', '.rmi': 'sequencer',
                        '.avi': 'avivideo'}.get(ext, '')
        log.info(f"mciSendCommandA(MCI_OPEN, type={dev_type!r}, element={element!r})")
        if dev_type not in ('waveaudio', 'sequencer'):
            return 263  # MCIERR_INVALID_DEVICE_NAME
        path = None
        if element:
            path = self.resolve_drive_path(element)
            if path is None or not os.path.isfile(path):
                return 275  # MCIERR_FILE_NOT_FOUND
        device_id = self.next_mci_id
        self.next_mci_id += 1
        self.mci_devices[device_id] = {
            'type': dev_type, 'path': path, 'alias': alias, 'mode': 525,
            'offset': 0, 'started': 0, 'to': None, 'notify': None,
            'length': self._media_length_ms(path) if path else 0,
            'music': False, 'time_format': 0}
        self._mem_write(params + 4, struct.pack('<I', device_id))
        return 0

    def _mci_play(self, device_id, device, flags, params):
        try:
            _, start, end = struct.unpack('<3I', self.emu.uc.mem_read(params, 12))
        except UcError:
            start = end = 0
        if not device['path']:
            return 263
        if device.get('notify'):
            self._mci_notify(device_id, device, 2)  # MCI_NOTIFY_SUPERSEDED
        if flags & 0x4:  # MCI_FROM
            device['offset'] = start
        elif device['length'] and device['offset'] >= device['length']:
            device['offset'] = 0
        device['to'] = end if flags & 0x8 else None
        device['music'] = False
        if SoundPlayer.available():
            owner = getattr(winapi.WinAPIHandler, '_mci_music_owner', None)
            if owner is not None and owner is not device:
                owner['offset'] = int(owner['offset'])
                owner['mode'] = 525
            try:
                pygame.mixer.music.load(device['path'])
                try:
                    pygame.mixer.music.play(start=device['offset'] / 1000.0)
                except pygame.error:
                    pygame.mixer.music.play()
                device['music'] = True
                winapi.WinAPIHandler._mci_music_owner = device
            except pygame.error as e:
                log.warning(f"MCI: cannot play {device['path']}: {e}")
        device['mode'] = 526
        device['started'] = time.time()
        return 0

    def mciSendCommandA(self, args):
        """mciSendCommandA emulation - waveaudio/sequencer files via the pygame mixer"""
        device_id, message, flags, params = args[:4]
        notify_hwnd = 0
        if flags & 0x1 and params:  # MCI_NOTIFY
            try:
                notify_hwnd = struct.unpack('<I', self.emu.uc.mem_read(params, 4))[0]
            except UcError:
                pass
        if message == 0x803:  # MCI_OPEN
            result = self._mci_open(flags, params)
            if result == 0 and notify_hwnd:
                opened = struct.unpack('<I', self.emu.uc.mem_read(params + 4, 4))[0]
                self.post_window_message(notify_hwnd, self.MM_MCINOTIFY, 1, opened)
            return result
        if message == 0x804 and device_id == 0xFFFF:  # MCI_CLOSE, MCI_ALL_DEVICE_ID
            for open_id in list(self.mci_devices):
                self.mciSendCommandA([open_id, message, 0, 0])
            return 0
        device = self.mci_devices.get(device_id)
        if device is None:
            return 257  # MCIERR_INVALID_DEVICE_ID
        log.debug(f"mciSendCommandA({device_id}, 0x{message:x}, flags=0x{flags:x})")
        result = 0
        if message == 0x804:  # MCI_CLOSE
            self._mci_stop_music(device)
            if device.get('notify'):
                self._mci_notify(device_id, device, 4)  # MCI_NOTIFY_ABORTED
            del self.mci_devices[device_id]
        elif message == 0x806:  # MCI_PLAY
            result = self._mci_play(device_id, device, flags, params)
            if result == 0 and notify_hwnd:
                device['notify'] = notify_hwnd
                notify_hwnd = 0  # Posted when the play ends
        elif message in (0x808, 0x809):  # MCI_STOP, MCI_PAUSE
            if device['mode'] == 526:
                device['offset'] = self._mci_position(device)
                if device['music'] and message == 0x809:
                    pygame.mixer.music.pause()
                else:
                    self._mci_stop_music(device)
                device['mode'] = 529 if message == 0x809 else 525
                if device.get('notify'):
                    self._mci_notify(device_id, device, 4)
        elif message == 0x855:  # MCI_RESUME
            if device['mode'] == 529:
                owner = getattr(winapi.WinAPIHandler, '_mci_music_owner', None)
                if device['music'] and owner is device:
                    pygame.mixer.music.unpause()
                device['mode'] = 526
                device['started'] = time.time()
        elif message == 0x807:  # MCI_SEEK
            self._mci_stop_music(device)
            if flags & 0x100:    # MCI_SEEK_TO_START
                device['offset'] = 0
            elif flags & 0x200:  # MCI_SEEK_TO_END
                device['offset'] = device['length']
            elif flags & 0x8:    # MCI_TO
                device['offset'] = struct.unpack('<I', self.emu.uc.mem_read(params + 4, 4))[0]
            device['mode'] = 525
        elif message == 0x80D:  # MCI_SET
            if flags & 0x400:  # MCI_SET_TIME_FORMAT
                device['time_format'] = struct.unpack(
                    '<I', self.emu.uc.mem_read(params + 4, 4))[0]
        elif message == 0x814:  # MCI_STATUS
            if not flags & 0x100:  # MCI_STATUS_ITEM
                return 273  # MCIERR_MISSING_PARAMETER
            item = struct.unpack('<I', self.emu.uc.mem_read(params + 8, 4))[0]
            self._audio_pump()
            values = {1: device['length'], 2: self._mci_position(device), 3: 1,
                      4: device['mode'], 5: 1, 6: device['time_format'], 7: 1, 8: 1}
            if item not in values:
                return 290  # MCIERR_BAD_CONSTANT
            self._mem_write(params + 4, struct.pack('<I', values[item] & 0xFFFFFFFF))
        else:
            log.warning(f"mciSendCommandA: command 0x{message:x} is not supported")
            return 274  # MCIERR_UNSUPPORTED_FUNCTION
        if notify_hwnd:
            self.post_window_message(notify_hwnd, self.MM_MCINOTIFY, 1, device_id)
        return result

    MCI_MODE_NAMES = {524: 'not ready', 525: 'stopped', 526: 'playing', 527: 'recording',
                      528: 'seeking', 529: 'paused', 530: 'open'}
    MCI_STRING_COMMANDS = {'close': 0x804, 'play': 0x806, 'seek': 0x807, 'stop': 0x808,
                           'pause': 0x809, 'set': 0x80D, 'status': 0x814, 'resume': 0x855}

    def mciSendStringA(self, args):
        """mciSendStringA emulation - the command strings of the devices
        mciSendCommandA has (open, play, stop, pause, resume, seek, set time
        format, status, close), carried out through mciSendCommandA"""
        lpstrCommand, lpstrReturn, uReturnLength, hwndCallback = args[:4]
        command = self.read_string(lpstrCommand) if lpstrCommand else ''
        log.info(f"mciSendStringA({command!r})")
        tokens = []
        for i, part in enumerate(command.split('"')):
            tokens += [part] if i % 2 else part.lower().split()
        if len(tokens) < 2:
            return 261 if tokens else 263  # MCIERR_UNRECOGNIZED_COMMAND
        verb, name, rest = tokens[0].lower(), tokens[1], tokens[2:]
        flags = (0x1 if 'notify' in rest else 0) | (0x2 if 'wait' in rest else 0)
        block = self.emu.heap_alloc(64)
        strings = []

        def guest_string(text):
            address = self.emu.heap_alloc(len(text) + 1)
            self.emu.uc.mem_write(address, text.encode('ascii', errors='replace') + b'\0')
            strings.append(address)
            return address

        def word_after(word):
            return rest[rest.index(word) + 1] if word in rest[:-1] else None

        try:
            self.emu.uc.mem_write(block, struct.pack('<I', hwndCallback))
            result_text = ''
            if verb == 'open':
                dev_type, element = word_after('type'), name
                if '!' in name:
                    dev_type, element = name.split('!', 1)
                elif not any(c in name for c in '.\\:') and dev_type is None:
                    dev_type, element = name, None
                alias = word_after('alias')
                if dev_type:
                    flags |= 0x2000
                    self.emu.uc.mem_write(block + 8, struct.pack('<I', guest_string(dev_type)))
                if element:
                    flags |= 0x200
                    self.emu.uc.mem_write(block + 12, struct.pack('<I', guest_string(element)))
                if alias:
                    flags |= 0x400
                    self.emu.uc.mem_write(block + 16, struct.pack('<I', guest_string(alias)))
                result = self.mciSendCommandA([0, 0x803, flags, block])
                if result == 0:
                    result_text = str(struct.unpack('<I', self.emu.uc.mem_read(block + 4, 4))[0])
            elif verb in self.MCI_STRING_COMMANDS:
                device_id = 0xFFFF if verb == 'close' and name.lower() == 'all' else \
                    self._mci_device_by_name(name)
                if not device_id:
                    return 263  # MCIERR_INVALID_DEVICE_NAME
                message = self.MCI_STRING_COMMANDS[verb]
                if verb == 'play':
                    for word, flag, offset in (('from', 0x4, 4), ('to', 0x8, 8)):
                        value = word_after(word)
                        if value is not None and value.isdigit():
                            flags |= flag
                            self.emu.uc.mem_write(block + offset, struct.pack('<I', int(value)))
                elif verb == 'seek':
                    target = word_after('to')
                    if target == 'start':
                        flags |= 0x100
                    elif target == 'end':
                        flags |= 0x200
                    elif target is not None and target.isdigit():
                        flags |= 0x8
                        self.emu.uc.mem_write(block + 4, struct.pack('<I', int(target)))
                elif verb == 'set':
                    if word_after('format') is None:
                        return 274  # MCIERR_UNSUPPORTED_FUNCTION
                    flags |= 0x400  # MCI_SET_TIME_FORMAT (ms, the only one kept)
                    self.emu.uc.mem_write(block + 4, struct.pack('<I', 0))
                elif verb == 'status':
                    items = {'length': 1, 'position': 2, 'mode': 4, 'ready': 7}
                    item = next((items[w] for w in rest if w in items), None)
                    if item is None:
                        return 274
                    flags |= 0x100  # MCI_STATUS_ITEM
                    self.emu.uc.mem_write(block + 8, struct.pack('<I', item))
                result = self.mciSendCommandA([device_id, message, flags, block])
                if result == 0 and verb == 'status':
                    value = struct.unpack('<I', self.emu.uc.mem_read(block + 4, 4))[0]
                    result_text = (self.MCI_MODE_NAMES.get(value, 'stopped') if item == 4 else
                                   ('true' if value else 'false') if item == 7 else str(value))
            else:
                return 261  # MCIERR_UNRECOGNIZED_COMMAND
            if lpstrReturn and uReturnLength:
                data = result_text.encode('ascii')[:uReturnLength - 1] + b'\0'
                self._mem_write(lpstrReturn, data)
            return result
        finally:
            for address in strings + [block]:
                self.emu.heap_free(address)

    SND_ASYNC = 0x0001
    SND_NODEFAULT = 0x0002
    SND_MEMORY = 0x0004
    SND_LOOP = 0x0008
    SND_NOSTOP = 0x0010
    SND_PURGE = 0x0040
    SND_ALIAS = 0x00010000
    SND_FILENAME = 0x00020000
    SND_RESOURCE = 0x00040004

    # PlaySound system sound aliases -> MessageBeep sound type
    SOUND_ALIASES = {
        'systemdefault': 0x00, '.default': 0x00, 'systemasterisk': 0x40,
        'systemexclamation': 0x30, 'systemhand': 0x10, 'systemquestion': 0x20,
        'systemstart': 0x40, 'systemexit': 0x40,
    }

    def _read_wav_memory(self, address):
        """Read a RIFF/WAVE image from emulated memory (SND_MEMORY)"""
        try:
            header = bytes(self.emu.uc.mem_read(address, 8))
            if header[:4] != b'RIFF':
                return None
            size = struct.unpack('<I', header[4:8])[0] + 8
            return bytes(self.emu.uc.mem_read(address, min(size, 64 * 1024 * 1024)))
        except UcError:
            return None

    def _play_sound_common(self, pszSound, flags, wide):
        """Shared PlaySound/sndPlaySound logic; returns TRUE/FALSE"""
        if not pszSound or (flags & self.SND_PURGE):
            log.debug("PlaySound(NULL) - stop")
            SoundPlayer.stop_owned_by(self)
            return 1
        if (flags & self.SND_NOSTOP) and SoundPlayer.playing():
            return 0
        loop = bool(flags & self.SND_LOOP) and bool(flags & self.SND_ASYNC)

        length = None
        if (flags & self.SND_RESOURCE) == self.SND_RESOURCE:
            log.debug("PlaySound(SND_RESOURCE) - resources are not supported")
        elif flags & self.SND_MEMORY:
            data = self._read_wav_memory(pszSound)
            log.debug(f"PlaySound(memory 0x{pszSound:08x}, 0x{flags:x})")
            if data is not None:
                length = SoundPlayer.play(io.BytesIO(data), loop, owner=self)
        else:
            name = self._read_text(pszSound, wide)
            log.debug(f"PlaySound(\"{name}\", 0x{flags:x})")
            alias = self.SOUND_ALIASES.get(name.lower())
            if alias is not None and not (flags & self.SND_FILENAME):
                frequency, duration = self.SYSTEM_SOUND_TONES[alias]
                SoundPlayer.play_tone(frequency, duration, owner=self)
                length = duration / 1000.0
            elif not (flags & self.SND_ALIAS):
                path = self.resolve_drive_path(name)
                if path is None or not os.path.isfile(path):
                    # Windows also tries the name with a .wav extension
                    path = self.resolve_drive_path(name + '.wav')
                if path is not None and os.path.isfile(path):
                    length = SoundPlayer.play(path, loop, owner=self)

        if length is None:
            if not (flags & self.SND_NODEFAULT):
                SoundPlayer.tone(*self.SYSTEM_SOUND_TONES[0])
            return 0
        if not (flags & self.SND_ASYNC):
            # SND_SYNC: return once the sound has finished
            self._wait_ms(int(length * 1000),
                          until=SoundPlayer.playing if SoundPlayer.available() else None)
        return 1

    def PlaySoundA(self, args, wide=False):
        """PlaySoundA/W emulation (winmm) - WAV files on the drives (drives/), memory
        images and system sound aliases"""
        return self._play_sound_common(args[0], args[2], wide)

    def PlaySoundW(self, args):
        return self.PlaySoundA(args, wide=True)

    def PlaySound(self, args):
        """PlaySound: winmm's undecorated export, the ANSI one (Word 95 asks
        GetProcAddress for it)"""
        return self.PlaySoundA(args)

    def sndPlaySoundA(self, args, wide=False):
        """sndPlaySoundA/W emulation (winmm) - alias or file name"""
        flags = args[1] & (self.SND_ASYNC | self.SND_NODEFAULT | self.SND_MEMORY |
                           self.SND_LOOP | self.SND_NOSTOP)
        return self._play_sound_common(args[0], flags, wide)

    def sndPlaySoundW(self, args):
        return self.sndPlaySoundA(args, wide=True)
