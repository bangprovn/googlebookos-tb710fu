#!/usr/bin/env python3
"""Host-owned JNI-contract fixture; does not execute extracted firmware code."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory(prefix="gb-console-inspection-") as temp:
    subprocess.run([
        "javac", "-proc:none", "-d", temp,
        str(root / "crates/gb-framework/src/terminal_probe/ConsoleInspection.java"),
        str(root / "tests/java/ConsoleInspectionTest.java"),
        str(root / "tests/java/console_fixture/android/system/virtualmachine/VirtualMachine.java"),
    ], check=True, timeout=20)
    subprocess.run([
        "java", "-Dconsole.fixture.root=" + temp, "-cp", temp,
        "org.googlebook.port.terminalprobe.ConsoleInspectionTest",
    ], check=True, timeout=10)
