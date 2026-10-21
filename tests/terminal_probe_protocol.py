#!/usr/bin/env python3
"""Run the real Rust sender against the actual Java receiver, host-owned code only.
Prerequisite: cargo build --locked --release -p gb-framework --example terminal_probe.
"""
import hashlib
import json
from pathlib import Path
import selectors
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory(prefix="gb-protocol-test-") as temp:
    work = Path(temp)
    subprocess.run([
        "javac", "-d", str(work),
        str(ROOT / "crates/gb-framework/src/terminal_probe/PayloadReceiver.java"),
        str(ROOT / "tests/java/PayloadReceiverServer.java"),
        str(ROOT / "tests/java/PayloadReceiverTest.java"),
    ], check=True, timeout=20)
    subprocess.run(["java", "-cp", str(work),
                    "org.googlebook.port.terminalprobe.PayloadReceiverTest"], check=True, timeout=20)
    payload = work / "payload.img"
    payload.write_bytes(bytes(range(256)) * 8193 + b"unaligned end")
    sha = hashlib.sha256(payload.read_bytes()).hexdigest()
    spec = {"bytes": payload.stat().st_size, "sha256": sha}
    request = {
        "schema_version": 1,
        "manifest": {"id": "host-test", "android_user": 11,
                     "donor_fingerprint": "host-owned-fixture", "memory_mib": 512,
                     "port": 38601, "payloads": {k: spec for k in ["kernel", "initrd", "rootfs", "instance"]}},
        "tools": {k: {"path": "unused", "sha256": "0" * 64} for k in [
            "android", "aapt2", "java", "javac", "launcher", "security", "r8",
            "apksigner", "zipalign", "key", "certificate"]},
        "sandbox": {"backend": "bubblewrap"},
    }
    config = work / "request.json"
    config.write_text(json.dumps(request))
    output = work / "received"
    output.mkdir()
    server = subprocess.Popen([
        "java", "-cp", str(work), "org.googlebook.port.terminalprobe.PayloadReceiverServer",
        str(output), str(spec["bytes"]), sha,
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        with selectors.DefaultSelector() as ready:
            ready.register(server.stdout, selectors.EVENT_READ)
            assert ready.select(10), "receiver startup deadline"
            port = int(server.stdout.readline())
        sent = subprocess.run([
            str(ROOT / "target/release/examples/terminal_probe"), "send", str(config),
            str(port), "kernel", str(payload),
        ], capture_output=True, text=True, timeout=20, check=True)
        assert sent.stdout.strip() == f"OK kernel {sha}", sent.stdout
        stdout, stderr = server.communicate(timeout=10)
        assert server.returncode == 0, stderr
        assert hashlib.sha256((output / "received.img").read_bytes()).hexdigest() == sha
        print("PASS: Rust sender / Java receiver interoperability across unaligned 2 MiB payload")
    finally:
        if server.poll() is None:
            server.kill()
            server.communicate(timeout=5)
