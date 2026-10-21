#!/usr/bin/env python3
"""Bounded non-monitor PulseAudio capture; export known-pattern verdicts, never PCM."""
import argparse
from array import array
import json
import math
import os
import re
import selectors
import subprocess
import sys
import time
import urllib.request

RATE = 48000


def detect(samples):
    """Same fixed frequency/timing gate as AudioPattern.java, with a six-second ceiling."""
    if not RATE <= len(samples) <= RATE * 6:
        return dict(matched=False, strong_windows=0, analysed_windows=0)
    length, hop = 1536, 384
    window = [0.5 - 0.5 * math.cos(2 * math.pi * i / (length - 1)) for i in range(length)]
    coefficients = [2 * math.cos(2 * math.pi * f / RATE) for f in (997, 1499, 797, 1197, 1299, 1699)]
    runs = []

    def append(code, first, last):
        if code == 0 or (last - first + 1) * hop < RATE * 0.060:
            return
        if runs and runs[-1][0] == code and (first - runs[-1][2]) * hop < RATE * 0.070:
            runs[-1][2] = last
        else:
            runs.append([code, first, last])

    previous, first, total, strong = 0, 0, 0, 0
    for start in range(0, len(samples) - length + 1, hop):
        energies = []
        for coefficient in coefficients:
            a = b = 0.0
            for i in range(length):
                value = samples[start + i] / 32768.0 * window[i] + coefficient * a - b
                b, a = a, value
            energies.append(max(0.0, (a * a + b * b - coefficient * a * b) / length**2))
        noise = sum(energies[2:]) / 4
        code = 0
        if energies[0] > 1e-10 and energies[0] > energies[1] * 6 and energies[0] > noise * 12:
            code = 1
        if energies[1] > 1e-10 and energies[1] > energies[0] * 6 and energies[1] > noise * 12:
            code = 2
        strong += int(code != 0)
        if code != previous:
            append(previous, first, total - 1)
            previous, first = code, total
        total += 1
    append(previous, first, total - 1)
    matched = False
    for i in range(len(runs) - 3):
        selected = runs[i:i + 4]
        if all(run[0] == part % 2 + 1 and (run[2] - run[1] + 1) * hop <= RATE * 0.270
               and (part == 0 or RATE * 0.100 <= (run[1] - selected[part - 1][1]) * hop <= RATE * 0.240)
               for part, run in enumerate(selected)):
            matched = True
            break
    return dict(matched=matched, strong_windows=strong, analysed_windows=total)


def capture(ready_url):
    if not re.fullmatch(r"http://(?:[0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{1,5}/[a-f0-9]{32}", ready_url):
        raise ValueError("literal test readiness URL required")
    source = subprocess.check_output(["pactl", "get-default-source"], timeout=3, text=True).strip()
    if not re.fullmatch(r"alsa_input\.[A-Za-z0-9_.:-]{1,200}", source) or ".monitor" in source:
        raise ValueError("default source is not a non-monitor ALSA input")
    pcm, samples, child = bytearray(), array("h"), None
    ready_frames = 0
    try:
        child = subprocess.Popen(["parec", "--raw", "--format=s16le", "--rate=48000", "--channels=1",
                                  "--device=" + source], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        os.set_blocking(child.stdout.fileno(), False)
        deadline = time.monotonic() + 7
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            while len(pcm) < RATE * 6 * 2 and time.monotonic() < deadline:
                if not selector.select(timeout=0.05):
                    continue
                chunk = os.read(child.stdout.fileno(), min(8192, RATE * 6 * 2 - len(pcm)))
                if not chunk:
                    break
                pcm.extend(chunk)
                if not ready_frames and len(pcm) >= RATE // 4 * 2:
                    ready_frames = len(pcm) // 2
                    with urllib.request.urlopen(ready_url, timeout=2) as response:
                        if response.status != 200 or response.read(64) != b"GB_GUEST_CAPTURE_READY\n":
                            raise ValueError("readiness acknowledgement mismatch")
        child.terminate()
        child.wait(timeout=2)
        child = None
        samples.frombytes(pcm[:len(pcm) // 2 * 2])
        if sys.byteorder != "little":
            samples.byteswap()
        result = detect(samples)
        return dict(schema_version=1, probe="owned_guest_audio_capture_v1",
                    state="compatible" if result["matched"] else "unknown",
                    source_is_non_monitor_alsa_input=True, rate=RATE, channels=1,
                    frames=len(samples), capture_warmup_frames=ready_frames,
                    detector=result, pcm_saved_or_exported=False, capture_process_stopped=True,
                    guest_microphone_quality_verified=False, full_port_verified=False)
    finally:
        if child is not None:
            child.terminate()
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=2)
        pcm[:] = b"\0" * len(pcm)
        for i in range(len(samples)):
            samples[i] = 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ready-url", required=True)
    args = parser.parse_args()
    try:
        result = capture(args.ready_url)
    except Exception as error:
        result = dict(schema_version=1, state="unknown", error_class=type(error).__name__,
                      pcm_saved_or_exported=False, full_port_verified=False)
    delivered = False
    try:
        # Only this small verdict object crosses the test connection. Never PCM.
        body = json.dumps(result, sort_keys=True).encode("ascii")
        if len(body) > 4096:
            raise ValueError("verdict exceeds budget")
        request = urllib.request.Request(args.ready_url, data=body,
                                         headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(request, timeout=2) as response:
            delivered = response.status == 200 and response.read(64) == b"GB_GUEST_CAPTURE_RESULT_RECEIVED\n"
    except Exception:
        pass
    result["report_delivery_verified"] = delivered
    print("GB_GUEST_AUDIO_CAPTURE:" + json.dumps(result, sort_keys=True), flush=True)
    sys.exit(0 if result["state"] == "compatible" and delivered else 2)
