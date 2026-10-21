#!/usr/bin/env python3
"""Host-only: a corrupt transfer must never execute even the cleanup JAR.

Prerequisite: cargo build --locked -p gb-framework --example android_functional_probe
No real ADB server, device, JDK or firmware is used by this test.
"""
from pathlib import Path
import hashlib
import json
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="gb-functional-runner-") as temporary:
    work = Path(temporary)
    jar = work / "owned-fixture.jar"
    jar.write_bytes(b"owned-corrupt-transfer-fixture-not-executable")
    source = root / "crates/gb-framework/src/functional_probe/AndroidFunctionalProbe.java"
    provenance = work / "build-report.json"
    provenance.write_text(json.dumps({
        "status": "built_not_device_verified",
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "probe_jar_sha256": hashlib.sha256(jar.read_bytes()).hexdigest(),
    }))
    commands = work / "commands.jsonl"
    adb = work / "fake-adb"
    adb.write_text("#!" + sys.executable + "\n" + f'''
import sys,json
from pathlib import Path
args=sys.argv[1:]
assert args[:2]==['-s','fixture-serial']
with Path({str(commands)!r}).open('a') as out: out.write(json.dumps(args[2:])+'\\n')
if args[2]=='push': sys.exit(0)
assert args[2]=='shell' and len(args)==4
c=args[3]
values={{'getprop ro.serialno':'fixture-serial','getprop ro.build.fingerprint':'fixture-fingerprint',
'id -u':'2000','getenforce':'Enforcing','am get-current-user':'11',
'cat /proc/sys/kernel/random/boot_id':'12345678-1234-1234-1234-123456789abc'}}
if c in values: print(values[c])
elif c.startswith('sha256sum '): print('0'*64+'  corrupt-device-copy.jar')
elif c.startswith(('if test -e ','chmod 0400 ','rm -- ')): pass
else: sys.exit(99) # This includes all app_process execution, including cleanup.
''')
    adb.chmod(0o700)

    def pin(path):
        return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}

    request = work / "run.json"
    request.write_text(json.dumps({
        "schema_version": 1, "adb": pin(adb), "probe": pin(jar),
        "build_report": pin(provenance), "serial": "fixture-serial",
        "fingerprint": "fixture-fingerprint", "android_user": 11,
    }))
    output = work / "report.json"
    result = subprocess.run([
        str(root / "target/debug/examples/android_functional_probe"), "run",
        str(request), str(output),
    ], capture_output=True, text=True, timeout=20)
    assert result.returncode == 2, result.stderr
    report = json.loads(output.read_text())
    assert report["status"] == "needs_diagnosis" and report["operations"] is None
    assert "device JAR hash mismatch" in report["execution_error"]
    called = [json.loads(line) for line in commands.read_text().splitlines()]
    assert not any("app_process" in str(args) for args in called)
    assert any(args[0] == "shell" and args[1].startswith("rm -- ") for args in called)
    assert report["host_boot_unchanged"] and not report["firmware_written"]
    print("PASS: corrupt device copy rejected, no probe or cleanup code executed, owned transfer removed")
