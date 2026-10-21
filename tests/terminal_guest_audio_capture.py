#!/usr/bin/env python3
"""Host-only detector controls. No recording or device access."""
from array import array
import importlib.util
import io
import math
from pathlib import Path
import random
import sys
import wave

sys.dont_write_bytecode = True
root = Path(__file__).resolve().parent / "fixtures"


def module(name):
    spec = importlib.util.spec_from_file_location(name, root / (name + ".py"))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


capture = module("terminal_guest_audio_capture")
pattern = module("terminal_guest_audio_pattern")
with wave.open(io.BytesIO(pattern.pattern_wav()), "rb") as stream:
    signal = array("h", stream.readframes(stream.getnframes()))
rate = 48000
rng = random.Random(1729)
quiet = array("h", [round(rng.gauss(0, 12)) for _ in range(rate * 6)])
for i, value in enumerate(signal):
    quiet[rate * 4 + i] += value
assert capture.detect(quiet)["matched"], "late quiet guest signal must pass"
assert not capture.detect(array("h", [0] * rate))["matched"]
single = array("h", [round(1000 * math.sin(2 * math.pi * 997 * i / rate)) for i in range(rate)])
assert not capture.detect(single)["matched"]
wrong = array("h", [0] * rate)
segment = len(signal) // 4
for part in range(4):
    wrong[part * segment:(part + 1) * segment] = signal[(part ^ 1) * segment:((part ^ 1) + 1) * segment]
assert not capture.detect(wrong)["matched"]
assert not capture.detect(array("h", [0] * (rate * 6 + 1)))["matched"]
print("PASS: late quiet guest pattern detected; silence, single tone, reversed order and oversized capture rejected")
