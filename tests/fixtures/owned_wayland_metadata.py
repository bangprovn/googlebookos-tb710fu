#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Extract numeric DMA-BUF metadata from an owned diagnostic child's trace.

Unrelated protocol traffic, file descriptor numbers and client strings are
discarded. This neither opens a display nor proves hardware compatibility.
"""
import re

PREFIX = (r'^\[\s*[0-9]+(?:\.[0-9]+)?\]\s*'
          r'(?:\{[A-Za-z0-9 _.:-]{1,40}\}\s*)?->\s*'
          r'zwp_linux_buffer_params_v1[@#][0-9]+\.')
CREATE = re.compile(PREFIX + r'create_immed\(new id (?:wl_buffer|\[unknown\])[@#][0-9]+, '
                    r'([0-9]+), ([0-9]+), ([0-9]+), ([0-9]+)\)\s*$')
ADD = re.compile(PREFIX + r'add\(fd [0-9]+, ([0-9]+), ([0-9]+), ([0-9]+), '
                 r'([0-9]+), ([0-9]+)\)\s*$')
SURFACE = re.compile(r'^\[\s*[0-9]+(?:\.[0-9]+)?\]\s*'
                     r'(?:\{[A-Za-z0-9 _.:-]{1,40}\}\s*)?->\s*'
                     r'wl_surface[@#][0-9]+\.(attach|damage|damage_buffer|commit)\(')
RELEASE = re.compile(r'^\[\s*[0-9]+(?:\.[0-9]+)?\]\s*'
                     r'(?:\{[A-Za-z0-9 _.:-]{1,40}\}\s*)?'
                     r'wl_buffer[@#][0-9]+\.release\(\)\s*$')


def event_kind(line):
    """Count owned producer progress without retaining identifiers or payloads.

    These events prove protocol traffic only, never refreshed screen pixels.
    """
    if not isinstance(line, str) or len(line) > 512 or '\x00' in line:
        return None
    match = SURFACE.match(line)
    if match:
        return match.group(1)
    if RELEASE.fullmatch(line):
        return 'release'
    return None


def parse_line(line):
    if not isinstance(line, str) or len(line) > 512 or '\x00' in line:
        return None
    match = CREATE.fullmatch(line)
    if match:
        width, height, fourcc, flags = map(int, match.groups())
        if not (0 < width <= 16384 and 0 < height <= 16384
                and 0 <= fourcc <= 0xffffffff and 0 <= flags <= 7):
            return None
        return dict(kind='create_immed', width=width, height=height,
                    fourcc=fourcc, flags=flags)
    match = ADD.fullmatch(line)
    if match:
        plane, offset, stride, high, low = map(int, match.groups())
        if not (plane < 4 and 0 < stride <= 0xffffffff
                and all(0 <= v <= 0xffffffff for v in [offset, high, low])):
            return None
        return dict(kind='add', plane=plane, offset=offset, stride=stride,
                    modifier=(high << 32) | low)
    return None
