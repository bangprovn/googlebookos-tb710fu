#!/usr/bin/env python3
"""Exercise the actual read-only shell collector against private host fixtures.

No ADB or device is used; host UID output is not Android runtime qualification.
"""
from pathlib import Path
import hashlib
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
collector = root / "scripts/inspect-android-usb-roles.sh"
with tempfile.TemporaryDirectory(prefix="gb-usb-role-fixture-") as temporary:
    work = Path(temporary)
    sysroot, procroot = work / "sys", work / "proc"

    def write(path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)

    write(procroot / "sys/kernel/random/boot_id", b"00000000-0000-4000-8000-000000000001\n")
    switches = sysroot / "class/usb_role"
    write(switches / "a-private-switch-name/role", b"host\n")
    write(switches / "b-private-switch-name/role", b"OWNER_SECRET=must-not-leave-fixture\n")
    write(switches / "c-private-switch-name/role", b"x" * 256)
    for index in range(7):
        write(switches / ("d" + str(index)) / "role", b"device\n")
    port = sysroot / "class/typec/port0"
    write(port / "data_role", b"host [device]\n")
    write(port / "power_role", b"[source] sink\n")
    write(port / "port_type", b"source sink [dual]\n")
    # Partner and descriptor fields must never be read or exported.
    write(sysroot / "class/typec/port0-partner/data_role", b"OWNER_SECRET=partner\n")
    write(port / "serial", b"OWNER_SECRET=serial\n")
    write(port / "manufacturer", b"OWNER_SECRET=manufacturer\n")
    (sysroot / "class/typec/port1").mkdir()

    def before():
        return {str(p.relative_to(work)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in work.rglob("*") if p.is_file()}

    original = before()
    env = dict(os.environ, GB_USB_SYSFS_ROOT=str(sysroot), GB_USB_PROCFS_ROOT=str(procroot))
    result = subprocess.run(["sh", str(collector)], env=env, capture_output=True,
                            text=True, timeout=5)
    assert result.returncode == 0, result.stderr
    text = result.stdout
    assert text.startswith("GB_USB_ROLE_SNAPSHOT_V1\nuid\t")
    assert len(text) <= 8192 and "OWNER_SECRET" not in text and "private-switch-name" not in text
    assert "role\tusb_role\t0\thost\n" in text
    assert "role\tusb_role\t1\tunrecognized\n" in text
    assert "role\tusb_role\t2\tover_budget\n" in text
    assert "limit\tusb_role\n" in text
    assert "role\tdata_role\t0\thost [device]\n" in text
    assert "role\tpower_role\t0\t[source] sink\n" in text
    assert "role\tport_type\t0\tsource sink [dual]\n" in text
    assert "role\tdata_role\t1\tunreadable\n" in text
    assert len([line for line in text.splitlines() if line.startswith("role\tdata_role")]) == 2
    assert before() == original, "collector changed fixture contents"
    # Empty/missing standard classes are inventory unknowns, not proof of absence.
    env["GB_USB_SYSFS_ROOT"] = str(work / "missing-sys")
    empty = subprocess.run(["sh", str(collector)], env=env, capture_output=True,
                           text=True, timeout=5)
    assert empty.returncode == 0
    assert "class\tusb_role\tmissing\n" in empty.stdout
    assert "class\ttypec\tmissing\n" in empty.stdout
    assert before() == original
    print("PASS: actual collector bounds ports/values, filters private fields, reports missing nodes and preserves fixtures")

    # Model exec-out sh -s while its transport keeps stdin open. The fixture id
    # supplies Android shell UID metadata without contacting or changing a device.
    fixture_bin = work / "fixture-bin"
    fixture_bin.mkdir()
    fake_id = fixture_bin / "id"
    fake_id.write_text("#!/bin/sh\n[ \"$1\" = \"-u\" ] || exit 2\nprintf '2000\\n'\n")
    fake_id.chmod(0o700)
    framed_env = dict(env, GB_USB_SYSFS_ROOT=str(sysroot),
                      PATH=str(fixture_bin) + os.pathsep + os.environ.get("PATH", ""))
    framed_original = before()
    source = collector.read_bytes()
    assert source.endswith(b"exit 0\n"), "collector must terminate without transport EOF"

    def frame(source, expect_completion):
        child = subprocess.Popen(["sh", "-s"], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=framed_env)
        try:
            child.stdin.write(source)
            child.stdin.flush()
            assert not child.stdin.closed  # Do not send EOF to make this pass.
            if expect_completion:
                assert child.wait(timeout=5) == 0
                assert not child.stdin.closed
                output = child.stdout.read().decode()
                assert "uid\t2000\n" in output
                assert "role\tdata_role\t0\thost [device]\n" in output
                assert "OWNER_SECRET" not in output
                assert child.stderr.read() == b""
            else:
                try:
                    child.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    pass
                else:
                    raise AssertionError("unframed control unexpectedly completed with stdin open")
        finally:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=3)
            child.stdin.close()
            child.stdout.close()
            child.stderr.close()

    frame(source.removesuffix(b"exit 0\n"), False)
    frame(source, True)
    assert before() == framed_original
    print("PASS: framed sh -s collector completes with stdin kept open; no-exit control waits for EOF")
