#!/usr/bin/env python3
"""Generate a quiet known WAV for guest playback; never capture audio or set volume."""
import argparse
import hashlib
import io
import json
import math
import struct
from pathlib import Path
import wave


def pattern_wav():
    rate, segment, fade = 48000, 7680, 240
    pcm = bytearray()
    for part in range(4):
        frequency = (997, 1499)[part % 2]
        for i in range(segment):
            envelope = min(1.0, i / fade, (segment - 1 - i) / fade)
            value = round(655 * envelope * math.sin(2 * math.pi * frequency * i / rate))
            pcm.extend(struct.pack("<h", value))
    output = io.BytesIO()
    with wave.open(output, "wb") as stream:
        stream.setparams((1, 2, rate, segment * 4, "NONE", "not compressed"))
        stream.writeframes(pcm)
    return output.getvalue()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    payload = pattern_wav()
    with args.output.open("xb") as stream:
        stream.write(payload)
    print(json.dumps(dict(schema_version=1, sha256=hashlib.sha256(payload).hexdigest(),
                         bytes=len(payload), sample_rate=48000, frames=30720,
                         amplitude=655, duration_ms=640, raw_recording=False)))
