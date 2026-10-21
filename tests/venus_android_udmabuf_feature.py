#!/usr/bin/env python3
"""Verify the actual config's Android/header boundary and exact patch reversal."""
from pathlib import Path
import hashlib
import json
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
metadata = root / "patches/tb710fu/virglrenderer/android-udmabuf-feature.json"
manifest = json.loads(metadata.read_text())
source = root / manifest["path"]
patch = metadata.with_suffix(".patch")
assert hashlib.sha256(source.read_bytes()).hexdigest() == manifest["result_sha256"]
assert hashlib.sha256(patch.read_bytes()).hexdigest() == manifest["patch_sha256"]
with tempfile.TemporaryDirectory(prefix="gb-android-udmabuf-") as temporary:
    base = Path(temporary)
    original = base / "prebuilt-intermediates/config.h"
    original.parent.mkdir()
    original.write_bytes(source.read_bytes())
    subprocess.run(["patch", "--reverse", "--batch", "--fuzz=0", "-p1", "-d", str(base),
                    "-i", str(patch)], check=True, capture_output=True, timeout=10)
    assert hashlib.sha256(original.read_bytes()).hexdigest() == manifest["sha256"]
    missing_headers = base / "empty-include"
    missing_headers.mkdir()
    # GCC requires at least one search directory even for a negative __has_include.
    cases = [
        ("android-header-present", ["-D__ANDROID__"], True),
        ("host-default", [], False),
        ("android-header-missing", ["-D__ANDROID__", "-nostdinc", "-I" + str(missing_headers)], False),
    ]
    for name, flags, wanted in cases:
        result = subprocess.run(["cc", "-E", "-dM", "-x", "c", *flags, str(source)],
                                capture_output=True, text=True, check=True, timeout=10)
        enabled = "#define HAVE_LINUX_UDMABUF_H 1" in result.stdout
        assert enabled == wanted, name
    print("Android header-present, host-default and Android header-missing cases passed.")
