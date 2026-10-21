#!/usr/bin/env python3
"""Bounded read-only helper tests; all executable code and fixtures are host-owned."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory(prefix="gb-runtime-inspection-") as temp:
    work = Path(temp)
    regular = work / "regular"
    regular.write_bytes((bytes(range(256)) * 4097)[:1048613])
    before = hashlib.sha256(regular.read_bytes()).hexdigest()
    (work / "empty").touch()
    with (work / "oversized").open("wb") as sparse:
        sparse.truncate(64 * 1024 * 1024 + 1)
    (work / "link").symlink_to(regular)
    (work / "directory").mkdir()
    os.mkfifo(work / "fifo")
    subprocess.run([
        "javac", "-proc:none", "-d", str(work),
        str(ROOT / "crates/gb-framework/src/terminal_probe/RuntimeInspection.java"),
        str(ROOT / "tests/java/RuntimeInspectionTest.java"),
    ], check=True, timeout=20)
    subprocess.run(["java", "-cp", str(work),
                    "org.googlebook.port.terminalprobe.RuntimeInspectionTest", str(work), before],
                   check=True, timeout=10)
    assert hashlib.sha256(regular.read_bytes()).hexdigest() == before
    spec = {"bytes": 1, "sha256": "0" * 64}
    request = {
        "schema_version": 1,
        "manifest": {"id": "host-read-only", "android_user": 11,
                     "donor_fingerprint": "host-owned-fixture", "memory_mib": 512,
                     "port": 38601, "action": "inspect_runtime",
                     "payloads": {k: spec for k in ["kernel", "initrd", "rootfs", "instance"]}},
        "tools": {k: {"path": "unused", "sha256": "0" * 64} for k in [
            "android", "aapt2", "java", "javac", "launcher", "security", "r8",
            "apksigner", "zipalign", "key", "certificate"]},
        "sandbox": {"backend": "bubblewrap"},
    }
    config = work / "request.json"
    config.write_text(json.dumps(request))
    sent = subprocess.run([
        str(ROOT / "target/release/examples/terminal_probe"), "send", str(config),
        "invalid-port", "kernel", str(work / "missing"),
    ], capture_output=True, text=True, timeout=10)
    assert sent.returncode != 0 and "runtime inspection does not open a payload receiver" in sent.stderr, sent.stderr
    print("PASS: inspection action refuses payload transfer before port/file/network processing")
    request["manifest"]["action"] = "observe_startup"
    config.write_text(json.dumps(request))
    sent = subprocess.run([
        str(ROOT / "target/release/examples/terminal_probe"), "send", str(config),
        "invalid-port", "kernel", str(work / "missing"),
    ], capture_output=True, text=True, timeout=10)
    assert sent.returncode != 0 and "runtime inspection does not open a payload receiver" in sent.stderr, sent.stderr
    print("PASS: startup observation also refuses payload transfer before port/file/network processing")

    request["manifest"]["action"] = "inspect_console"
    config.write_text(json.dumps(request))
    sent = subprocess.run([
        str(ROOT / "target/release/examples/terminal_probe"), "send", str(config),
        "invalid-port", "kernel", str(work / "missing"),
    ], capture_output=True, text=True, timeout=10)
    assert sent.returncode != 0 and "runtime inspection does not open a payload receiver" in sent.stderr, sent.stderr
    print("PASS: console inspection refuses payload transfer before port/file/network processing")

    request["manifest"]["action"] = "observe_immutable_startup"
    config.write_text(json.dumps(request))
    sent = subprocess.run([
        str(ROOT / "target/release/examples/terminal_probe"), "send", str(config),
        "invalid-port", "kernel", str(work / "missing"),
    ], capture_output=True, text=True, timeout=10)
    assert sent.returncode != 0 and "runtime inspection does not open a payload receiver" in sent.stderr, sent.stderr
    print("PASS: immutable startup refuses payload transfer before port/file/network processing")

    request["manifest"]["action"] = "observe_default_startup"
    config.write_text(json.dumps(request))
    sent = subprocess.run([
        str(ROOT / "target/release/examples/terminal_probe"), "send", str(config),
        "invalid-port", "kernel", str(work / "missing"),
    ], capture_output=True, text=True, timeout=10)
    assert sent.returncode != 0 and "runtime inspection does not open a payload receiver" in sent.stderr, sent.stderr
    print("PASS: default startup refuses payload transfer before port/file/network processing")
