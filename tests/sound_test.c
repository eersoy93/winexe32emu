/*
Copyright 2026 Erdem Ersoy (eersoy93)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
Sound test - exercises the emulator's audio output.

  1. Beep: a short melody (each call blocks for its duration).
  2. MessageBeep: the system sound types.
  3. PlaySound: system sound aliases, a WAV file written to
     C:\Windows\Temp and the same WAV image played from memory.
*/

#include <windows.h>
#include <mmsystem.h>
#include <stdio.h>
#include <string.h>

#define WAV_RATE 22050
#define WAV_MS 400

/* Build a 8-bit mono PCM WAV image of a square wave; returns its size */
static DWORD BuildWav(BYTE *buf, DWORD frequency)
{
    DWORD samples = WAV_RATE * WAV_MS / 1000;
    DWORD half = WAV_RATE / (frequency * 2);
    DWORD i;
    DWORD value;

    memcpy(buf, "RIFF", 4);
    value = 36 + samples; memcpy(buf + 4, &value, 4);
    memcpy(buf + 8, "WAVEfmt ", 8);
    value = 16; memcpy(buf + 16, &value, 4);
    *(WORD *)(buf + 20) = 1;            /* PCM */
    *(WORD *)(buf + 22) = 1;            /* mono */
    value = WAV_RATE; memcpy(buf + 24, &value, 4);
    value = WAV_RATE; memcpy(buf + 28, &value, 4);  /* bytes per second */
    *(WORD *)(buf + 32) = 1;            /* block align */
    *(WORD *)(buf + 34) = 8;            /* bits per sample */
    memcpy(buf + 36, "data", 4);
    memcpy(buf + 40, &samples, 4);
    for (i = 0; i < samples; i++)
        buf[44 + i] = ((i / half) % 2) ? 96 : 160;
    return 44 + samples;
}

int main(void)
{
    static const DWORD melody[] = { 523, 587, 659, 698, 784, 880, 988, 1047 };
    static const UINT beeps[] = { MB_OK, MB_ICONHAND, MB_ICONQUESTION,
                                  MB_ICONEXCLAMATION, MB_ICONASTERISK, 0xFFFFFFFF };
    static BYTE wav[44 + WAV_RATE * WAV_MS / 1000];
    const char *path = "C:\\Windows\\Temp\\sound_test.wav";
    DWORD size, start, written, i;
    HANDLE hFile;

    printf("=== Sound test ===\n\n");

    printf("1. Beep: C major scale\n");
    start = timeGetTime();
    for (i = 0; i < sizeof(melody) / sizeof(melody[0]); i++)
        Beep(melody[i], 150);
    printf("   8 notes took about %lu ms (expected ~1200)\n", timeGetTime() - start);
    printf("   Beep(10 Hz) returns %d (invalid frequency)\n\n", Beep(10, 100));

    printf("2. MessageBeep: system sounds\n");
    for (i = 0; i < sizeof(beeps) / sizeof(beeps[0]); i++)
    {
        printf("   MessageBeep(0x%lx) -> %d\n", (unsigned long)beeps[i], MessageBeep(beeps[i]));
        Sleep(400);
    }

    printf("\n3. PlaySound\n");
    printf("   alias SystemExclamation -> %d\n",
           PlaySoundA("SystemExclamation", NULL, SND_ALIAS | SND_SYNC));

    size = BuildWav(wav, 440);
    hFile = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                        FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        WriteFile(hFile, wav, size, &written, NULL);
        CloseHandle(hFile);
    }
    printf("   file %s -> %d\n", path,
           PlaySoundA(path, NULL, SND_FILENAME | SND_SYNC));

    BuildWav(wav, 660);
    printf("   memory image -> %d\n", PlaySoundA((LPCSTR)wav, NULL, SND_MEMORY | SND_SYNC));

    printf("   looping (async) for 1 second...\n");
    PlaySoundA(path, NULL, SND_FILENAME | SND_ASYNC | SND_LOOP);
    Sleep(1000);
    PlaySoundA(NULL, NULL, 0);
    printf("   stopped\n");

    printf("   missing file (SND_NODEFAULT) -> %d\n",
           PlaySoundA("C:\\nothing.wav", NULL, SND_FILENAME | SND_NODEFAULT));
    printf("   sndPlaySound(SystemAsterisk) -> %d\n",
           sndPlaySoundA("SystemAsterisk", SND_SYNC));

    printf("\nDone!\n");
    return 0;
}
