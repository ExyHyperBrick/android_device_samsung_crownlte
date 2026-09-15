#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 The LineageOS Project
# SPDX-License-Identifier: Apache-2.0
#
"""Assemble both FPS fixes and verify the validated payload hashes."""

from hashlib import sha256
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parent
SPECS = {
    'arm': ('thumbv7-linux-android', 0x101998,
            '2f027cddef0503d843572ce861e14b8c'
            '8f0257b1f1631381d6c5549c46126d98', {
        'get_config_mode': 0x101849,
        'get_mode_value': 0x1461fd,
        'set_mode_value': 0x145b61,
        'set_restart_stream': 0x10178b,
        'original_store': 0x101a09,
        'original_exit': 0x101a47,
    }),
    'arm64': ('aarch64-linux-android', 0x166fd0,
            '7a9933ba73689d2449340eb4163dd56e'
            '55d6cba36136c0beee661a8013cd964e', {
        'get_config_mode': 0x166d90,
        'get_mode_value': 0x1ca288,
        'set_mode_value': 0x1c9a28,
        'set_restart_stream': 0x166c18,
        'original_store': 0x16707c,
        'original_exit': 0x1670cc,
    }),
}


def main():
    with TemporaryDirectory(prefix='starlte-camera-fps-') as directory:
        for arch, (target, offset, expected, symbols) in SPECS.items():
            stem = 'restore_fps_mode_' + arch
            output = Path(directory) / stem
            subprocess.run([
                'clang', '--target=' + target, '-c',
                str(ROOT / (stem + '.S')),
                '-o', str(output.with_suffix('.o')),
            ], check=True)
            subprocess.run([
                'ld.lld', '--entry=patch_start', '--image-base=0',
                '--section-start=.text=' + hex(offset),
                '-o', str(output.with_suffix('.elf')),
                str(output.with_suffix('.o')),
                *['--defsym=' + k + '=' + hex(v)
                  for k, v in symbols.items()],
            ], check=True)
            subprocess.run([
                'llvm-objcopy', '--only-section=.text', '-O', 'binary',
                str(output.with_suffix('.elf')),
                str(output.with_suffix('.bin')),
            ], check=True)
            result = output.with_suffix('.bin').read_bytes()
            if sha256(result).hexdigest() != expected:
                raise RuntimeError(f'{arch}: FPS payload mismatch')
            print(f'{arch}: {len(result)} bytes match')


if __name__ == '__main__':
    main()
