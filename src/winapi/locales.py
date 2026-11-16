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

"""WinAPIHandler mixin: Locales (only English - United States), string comparison, date formats"""

import re
import struct
import time
import datetime

from unicorn import *


class LocalesMixin:
    """Locales (only English - United States), string comparison, date formats"""

    # ---------- Locales (only English - United States exists) ----------

    LOCALE_DAY_NAMES = ('Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday',
                        'Saturday', 'Sunday')
    LOCALE_MONTH_NAMES = ('January', 'February', 'March', 'April', 'May', 'June', 'July',
                          'August', 'September', 'October', 'November', 'December')
    # LCTYPE -> value (the day and month names and the code pages are added in
    # _locale_value)
    LOCALE_INFO = {
        0x01: '0409', 0x02: 'English (United States)', 0x03: 'ENU', 0x04: 'English',
        0x05: '1', 0x06: 'United States', 0x07: 'USA', 0x08: 'United States', 0x09: '0409',
        0x0A: '1', 0x0C: ',', 0x0D: '1', 0x0E: '.', 0x0F: ',', 0x10: '3;0', 0x11: '2',
        0x12: '1', 0x13: '0123456789', 0x14: '$', 0x15: 'USD', 0x16: '.', 0x17: ',',
        0x18: '3;0', 0x19: '2', 0x1A: '2', 0x1B: '0', 0x1C: '0', 0x1D: '/', 0x1E: ':',
        0x1F: 'M/d/yyyy', 0x20: 'dddd, MMMM d, yyyy', 0x21: '0', 0x22: '0', 0x23: '0',
        0x24: '1', 0x25: '0', 0x26: '0', 0x27: '0', 0x28: 'AM', 0x29: 'PM', 0x50: '',
        0x51: '-', 0x52: '3', 0x53: '0', 0x54: '1', 0x55: '0', 0x56: '1', 0x57: '0',
        0x59: 'en', 0x5A: 'US', 0x5C: 'en-US', 0x5D: 'h:mm:ss', 0x67: 'eng', 0x68: 'USA',
        0x69: 'NaN', 0x6A: 'Infinity', 0x6B: '-Infinity', 0x6D: 'en', 0x6E: 'en-US',
        0x71: '0', 0x72: 'English (United States)', 0x73: 'English (United States)',
        0x76: '%', 0x79: 'h:mm tt', 0x1001: 'English', 0x1002: 'United States',
        0x1003: 'h:mm:ss tt', 0x1005: '0', 0x1006: 'MMMM yyyy', 0x1007: 'US Dollar',
        0x1008: 'US Dollar', 0x1009: '1', 0x100B: '0', 0x100C: '6', 0x100D: '0',
        0x100E: '', 0x100F: '', 0x1010: '1', 0x1011: '10000', 0x1012: '037',
        0x1013: 'Default', 0x1014: '1',
    }
    # LCIDs and locale names that mean English (United States)
    LOCALE_LCIDS = (0x0409, 0x0400, 0x0800, 0x0000)  # also LOCALE_USER/SYSTEM_DEFAULT
    LOCALE_NAMES = ('en-us', 'en', '!x-sys-default-locale')

    def _locale_value(self, lctype):
        """Text of a locale information type, or None if unknown"""
        days, months = self.LOCALE_DAY_NAMES, self.LOCALE_MONTH_NAMES
        if 0x2A <= lctype <= 0x30:  # LOCALE_SDAYNAME1..7 (Monday first)
            return days[lctype - 0x2A]
        if 0x31 <= lctype <= 0x37:  # LOCALE_SABBREVDAYNAME1..7
            return days[lctype - 0x31][:3]
        if 0x60 <= lctype <= 0x66:  # LOCALE_SSHORTESTDAYNAME1..7
            return days[lctype - 0x60][:2]
        if 0x38 <= lctype <= 0x43:  # LOCALE_SMONTHNAME1..12
            return months[lctype - 0x38]
        if 0x44 <= lctype <= 0x4F:  # LOCALE_SABBREVMONTHNAME1..12
            return months[lctype - 0x44][:3]
        if lctype == 0x0B:  # LOCALE_IDEFAULTCODEPAGE (OEM)
            return str(self.GetOEMCP([]))
        if lctype == 0x1004:  # LOCALE_IDEFAULTANSICODEPAGE: like GetACP
            return str(self._ansi_codepage_number())
        return self.LOCALE_INFO.get(lctype)

    def _write_counted_text(self, text, buffer, size, wide):
        """Write text and its NUL to a buffer of size TCHARs; the length
        written (with the NUL), the length needed if size is 0, else 0"""
        units = self._text_units(text, wide) + [0]
        if size == 0:
            return len(units)
        if size < len(units):
            self._last_error = 122  # ERROR_INSUFFICIENT_BUFFER
            return 0
        self._write_units(buffer, units, wide, terminate=False)
        return len(units)

    def _get_locale_info(self, lctype, buffer, size, wide):
        value = self._locale_value(lctype & 0x07FFFFFF)  # without the LOCALE_* flags
        if value is None:
            self._last_error = 1004  # ERROR_INVALID_FLAGS
            return 0
        if lctype & 0x20000000:  # LOCALE_RETURN_NUMBER: a DWORD in the buffer
            try:
                number = int(value)
            except ValueError:
                self._last_error = 1004
                return 0
            count = 2 if wide else 4  # sizeof(DWORD) / sizeof(TCHAR)
            if size == 0:
                return count
            if size < count:
                self._last_error = 122  # ERROR_INSUFFICIENT_BUFFER
                return 0
            self._mem_write(buffer, struct.pack('<I', number))
            return count
        return self._write_counted_text(value, buffer, size, wide)

    def GetLocaleInfoA(self, args, wide=False):
        """GetLocaleInfoA/W emulation (Locale, LCType, lpLCData, cchData)"""
        return self._get_locale_info(args[1], args[2], args[3], wide)

    def GetLocaleInfoW(self, args):
        return self.GetLocaleInfoA(args, wide=True)

    def GetLocaleInfoEx(self, args):
        """GetLocaleInfoEx emulation (lpLocaleName, LCType, lpLCData, cchData)"""
        return self._get_locale_info(args[1], args[2], args[3], True)

    def IsValidLocale(self, args):
        return 1 if args[0] in self.LOCALE_LCIDS + (0x7F,) else 0

    def IsValidLocaleName(self, args):
        name = self.read_wide_string(args[0]).lower() if args[0] else ''
        return 1 if name in self.LOCALE_NAMES + ('',) else 0

    def LocaleNameToLCID(self, args):
        """LocaleNameToLCID emulation - NULL is the user default locale"""
        if not args[0]:
            return 0x0409
        name = self.read_wide_string(args[0]).lower()
        if name == '':
            return 0x7F  # LOCALE_INVARIANT
        if name in self.LOCALE_NAMES:
            return 0x0409
        self._last_error = 87  # ERROR_INVALID_PARAMETER
        return 0

    def LCIDToLocaleName(self, args):
        """LCIDToLocaleName emulation (Locale, lpName, cchName, dwFlags)"""
        if args[0] == 0x7F:
            name = ''
        elif args[0] in self.LOCALE_LCIDS:
            name = 'en-US'
        else:
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0
        return self._write_counted_text(name, args[1], args[2], True)

    def GetUserDefaultLocaleName(self, args):
        """GetUserDefaultLocaleName emulation (lpLocaleName, cchLocaleName)"""
        if not args[1]:
            self._last_error = 122  # ERROR_INSUFFICIENT_BUFFER
            return 0
        return self._write_counted_text('en-US', args[0], args[1], True)

    def GetSystemDefaultLocaleName(self, args):
        return self.GetUserDefaultLocaleName(args)

    def _enum_locales(self, callback, text, extra=()):
        address = self.emu.heap_alloc(2 * (len(text) + 1))
        try:
            self._write_text(address, text, True)
            self.emu.call_callback(callback, [address, *extra])
        finally:
            self.emu.heap_free(address)
        return 1

    def EnumSystemLocalesA(self, args):
        """EnumSystemLocalesA emulation - only 00000409"""
        address = self.emu.heap_alloc(16)
        try:
            self._write_text(address, '00000409', False)
            self.emu.call_callback(args[0], [address])
        finally:
            self.emu.heap_free(address)
        return 1

    def EnumSystemLocalesW(self, args):
        return self._enum_locales(args[0], '00000409')

    def EnumSystemLocalesEx(self, args):
        """EnumSystemLocalesEx emulation (callback, flags, lParam, reserved) - en-US"""
        return self._enum_locales(args[0], 'en-US', (0x1, args[2]))  # LOCALE_WINDOWS

    def LCMapStringEx(self, args):
        """LCMapStringEx emulation - LCMapStringW with the locale name"""
        return self.LCMapStringW([0x0409] + list(args[1:6]))

    def CompareStringW(self, args):
        return self.CompareStringA(args, wide=True)

    def CompareStringEx(self, args):
        """CompareStringEx emulation - CompareStringW with the locale name"""
        return self.CompareStringA([0x0409] + list(args[1:6]), wide=True)

    def CompareStringOrdinal(self, args):
        """CompareStringOrdinal emulation (s1, c1, s2, c2, bIgnoreCase): code unit order"""
        strings = []
        for address, count in ((args[0], args[1]), (args[2], args[3])):
            units = self._counted_units(address, count, True) if address else None
            if units is None:
                self._last_error = 87  # ERROR_INVALID_PARAMETER
                return 0
            if count == 0xFFFFFFFF:
                units = units[:-1]
            text = self._units_text(units, True)
            strings.append(self._text_units(text.upper() if args[4] else text, True))
        return 1 if strings[0] < strings[1] else 3 if strings[0] > strings[1] else 2

    # Date and time formats ("dddd, MMMM d, yyyy", "h:mm:ss tt", ...)

    def _format_picture(self, picture, when, date):
        """Text of a GetDateFormat/GetTimeFormat picture for a datetime"""
        days, months = self.LOCALE_DAY_NAMES, self.LOCALE_MONTH_NAMES
        out = []
        i = 0
        while i < len(picture):
            ch = picture[i]
            if ch == "'":  # quoted text; '' is a quote
                j = picture.find("'", i + 1)
                j = len(picture) if j < 0 else j
                out.append(picture[i + 1:j] or "'")
                i = j + 1
                continue
            j = i
            while j < len(picture) and picture[j] == ch:
                j += 1
            n = j - i
            if date and ch == 'd':
                day = days[when.weekday()]
                out.append(str(when.day) if n == 1 else f'{when.day:02}' if n == 2
                           else day[:3] if n == 3 else day)
            elif date and ch == 'M':
                month = months[when.month - 1]
                out.append(str(when.month) if n == 1 else f'{when.month:02}' if n == 2
                           else month[:3] if n == 3 else month)
            elif date and ch == 'y':
                out.append(str(when.year % 100) if n == 1 else f'{when.year % 100:02}'
                           if n == 2 else str(when.year))
            elif date and ch == 'g':
                out.append('A.D.')
            elif not date and ch in 'hH':
                hour = when.hour if ch == 'H' else when.hour % 12 or 12
                out.append(str(hour) if n == 1 else f'{hour:02}')
            elif not date and ch in 'ms':
                value = when.minute if ch == 'm' else when.second
                out.append(str(value) if n == 1 else f'{value:02}')
            elif not date and ch == 't':
                marker = 'AM' if when.hour < 12 else 'PM'
                out.append(marker[0] if n == 1 else marker)
            else:
                out.append(picture[i:j])
            i = j
        return ''.join(out)

    def _date_time_format(self, flags, lpTime, lpFormat, buffer, size, wide, date):
        """GetDateFormat/GetTimeFormat core (lpTime: SYSTEMTIME or NULL for now)"""
        try:
            if lpTime:
                year, month, _, day, hour, minute, second, _ = struct.unpack(
                    '<8H', self.emu.uc.mem_read(lpTime, 16))
                when = (datetime.datetime(year, month, day) if date else
                        datetime.datetime(2000, 1, 1, hour, minute, second))
            else:
                when = datetime.datetime.now()
        except (UcError, ValueError):
            self._last_error = 87  # ERROR_INVALID_PARAMETER
            return 0
        if lpFormat:
            picture = self._read_text(lpFormat, wide)
        elif date:
            # DATE_LONGDATE (2), DATE_YEARMONTH (8), else DATE_SHORTDATE
            picture = self.LOCALE_INFO[0x20 if flags & 2 else 0x1006 if flags & 8 else 0x1F]
        else:
            picture = self.LOCALE_INFO[0x1003]
        if not date:
            if flags & 1:  # TIME_NOMINUTESORSECONDS
                picture = re.sub(r"[^hHt']*[ms]+", '', picture)
            elif flags & 2:  # TIME_NOSECONDS
                picture = re.sub(r"[^hHmt']*s+", '', picture)
            if flags & 4:  # TIME_NOTIMEMARKER
                picture = re.sub(r"\s*t+", '', picture)
            if flags & 8:  # TIME_FORCE24HOURFORMAT
                picture = picture.replace('h', 'H')
        text = self._format_picture(picture, when, date)
        return self._write_counted_text(text, buffer, size, wide)

    def GetDateFormatA(self, args, wide=False):
        """GetDateFormatA/W emulation (Locale, dwFlags, lpDate, lpFormat, lpDateStr, cchDate)"""
        return self._date_time_format(args[1], args[2], args[3], args[4], args[5], wide, True)

    def GetDateFormatW(self, args):
        return self.GetDateFormatA(args, wide=True)

    def GetDateFormatEx(self, args):
        return self.GetDateFormatA(args, wide=True)  # the calendar argument is ignored

    def GetTimeFormatA(self, args, wide=False):
        """GetTimeFormatA/W emulation (Locale, dwFlags, lpTime, lpFormat, lpTimeStr, cchTime)"""
        return self._date_time_format(args[1], args[2], args[3], args[4], args[5], wide, False)

    def GetTimeFormatW(self, args):
        return self.GetTimeFormatA(args, wide=True)

    def GetTimeFormatEx(self, args):
        return self.GetTimeFormatA(args, wide=True)

    # Time zone of the host

    def _dst_transitions(self, year):
        """(daylight start, standard start) SYSTEMTIMEs of the host time zone in
        "day of month" form (wYear 0), or None without daylight saving time"""
        start = int(datetime.datetime(year, 1, 1, tzinfo=datetime.timezone.utc).timestamp())
        found = {}
        step = 900  # every transition is on a quarter hour
        previous = time.localtime(start).tm_isdst
        for t in range(start + step, start + 366 * 86400, step):
            isdst = time.localtime(t).tm_isdst
            if isdst != previous and isdst >= 0:
                # The wall clock time of the change, in the time before it
                wall = datetime.datetime(*time.localtime(t - step)[:6]) + \
                    datetime.timedelta(seconds=step)
                days_in_month = ((wall.replace(day=28) + datetime.timedelta(days=4))
                                 .replace(day=1) - datetime.timedelta(days=1)).day
                week = 5 if wall.day + 7 > days_in_month else (wall.day - 1) // 7 + 1
                found[isdst] = struct.pack('<8H', 0, wall.month, (wall.weekday() + 1) % 7,
                                           week, wall.hour, wall.minute, 0, 0)
            previous = isdst
        if 0 in found and 1 in found:
            return found[1], found[0]
        return None

    def GetTimeZoneInformation(self, args):
        """GetTimeZoneInformation emulation - the host's time zone and its
        daylight saving time rules for the current year"""
        now = time.localtime()
        cached = getattr(self, '_tz_cache', None)
        if cached is None or cached[0] != now.tm_year:
            transitions = self._dst_transitions(now.tm_year) if time.daylight else None
            cached = self._tz_cache = (now.tm_year, transitions)
        transitions = cached[1]
        bias = time.timezone // 60
        standard_name, daylight_name = time.tzname

        def name(text):
            return text.encode('utf-16-le')[:62].ljust(64, b'\x00')
        if transitions:
            daylight_date, standard_date = transitions
            daylight_bias = (time.altzone - time.timezone) // 60
            result = 2 if now.tm_isdst > 0 else 1  # TIME_ZONE_ID_DAYLIGHT/STANDARD
        else:
            daylight_date = standard_date = b'\x00' * 16
            daylight_bias = 0
            result = 0  # TIME_ZONE_ID_UNKNOWN
        data = (struct.pack('<i', bias) + name(standard_name) + standard_date +
                struct.pack('<i', 0) + name(daylight_name) + daylight_date +
                struct.pack('<i', daylight_bias))
        if not self._mem_write(args[0], data):
            self._last_error = 998  # ERROR_NOACCESS
            return 0xFFFFFFFF  # TIME_ZONE_ID_INVALID
        return result
