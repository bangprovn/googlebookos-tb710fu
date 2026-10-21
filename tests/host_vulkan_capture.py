#!/usr/bin/env python3
"""Host-only Vulkan capture guards; never connects to a real Android device."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="gb-host-vulkan-") as temporary:
    b = Path(temporary)
    mode, commands = b / "mode", b / "commands.jsonl"
    adb = b / "fake-adb"
    adb.write_text("#!" + sys.executable + "\n" + f'''
import sys,json
from pathlib import Path
args=sys.argv[1:];assert args[:3]==['-s','fixture','shell'] and len(args)==4
c=args[3]
with Path({str(commands)!r}).open('a') as f:f.write(json.dumps(c)+'\\n')
mode=Path({str(mode)!r}).read_text()
values={{'getprop ro.serialno':'fixture','getprop ro.build.fingerprint':'fixture-fingerprint','id -u':'2000','getenforce':'Enforcing','am get-current-user':'11'}}
if mode=='wrong-user':values['am get-current-user']='0'
if mode=='permissive':values['getenforce']='Permissive'
if mode=='wrong-fingerprint':values['getprop ro.build.fingerprint']='different'
if c in values:print(values[c])
elif c=='cat /proc/sys/kernel/random/boot_id':
 count=Path({str(b / 'boot-count')!r});n=int(count.read_text()) if count.exists() else 0;count.write_text(str(n+1))
 print('12345678-1234-1234-1234-123456789ab'+('d' if mode=='changed-boot' and n>0 else 'c'))
elif c=='cmd gpu vkjson':
 if mode=='over-budget':sys.stdout.write(' '* (4*1024*1024)+'{{}}')
 else:
  names=['VK_KHR_external_memory_fd','VK_EXT_external_memory_dma_buf','VK_EXT_image_drm_format_modifier','VK_EXT_queue_family_foreign']
  if mode=='missing-extension':names.pop()
  print(json.dumps({{'devices':[{{'properties':{{'apiVersion':4206720.0,'deviceType':1.0,'deviceName':'fixture GPU','vendorID':20803.0,'deviceID':1.0,'pipelineCacheUUID':['fixture-not-exported']}},'extensions':[{{'extensionName':n,'specVersion':1}} for n in names]}}],'ignored_padding':'x'*70000}}))
else:sys.exit(99)
''')
    adb.chmod(0o700)
    request = b / "request.json"
    value = dict(schema_version=1, adb=dict(path=str(adb), sha256=hashlib.sha256(adb.read_bytes()).hexdigest()), serial="fixture", fingerprint="fixture-fingerprint", android_user=11)
    request.write_text(json.dumps(value))

    def run(label):
        mode.write_text(label)
        (b / "boot-count").unlink(missing_ok=True)
        output = b / (label + ".json")
        result = subprocess.run([str(root / "target/debug/examples/inspect_host_vulkan"), str(request), str(output)], capture_output=True, text=True, timeout=15)
        return result, output

    result, output = run("valid")
    assert result.returncode == 0, result.stderr
    report = json.loads(output.read_text())
    assert report["observed"]["source_bytes"] > 65536
    assert report["observed"]["state"] == "compatible" and report["host_boot_unchanged"]
    assert report["observed"]["devices"][0]["properties"]["vendorID"] == 20803
    assert "fixture-not-exported" not in output.read_text() and "pipelineCacheUUID" not in output.read_text()
    assert not report["observed"]["guest_vulkan_verified"] and not report["firmware_written"]
    assert report["enumeration_context"] == "android_gpu_service" and not report["original_vmm_namespace_verified"]
    result, output = run("missing-extension")
    assert result.returncode == 2 and json.loads(output.read_text())["observed"]["state"] == "patch_required"
    for label in ["over-budget", "changed-boot", "wrong-user", "permissive", "wrong-fingerprint"]:
        result, output = run(label)
        assert result.returncode != 0 and not output.exists(), (label, result.stderr)
    previous = commands.read_bytes()
    result, output = run("valid")
    assert result.returncode != 0 and output.exists() and commands.read_bytes() == previous
    previous = commands.read_bytes()
    value["adb"]["sha256"] = "0" * 64
    request.write_text(json.dumps(value))
    result, output = run("bad-pin")
    assert result.returncode != 0 and not output.exists() and commands.read_bytes() == previous
    allowed = {"getprop ro.serialno", "getprop ro.build.fingerprint", "id -u", "getenforce", "am get-current-user", "cat /proc/sys/kernel/random/boot_id", "cmd gpu vkjson"}
    assert all(json.loads(c) in allowed for c in commands.read_text().splitlines())
    print("PASS: complete Vulkan receipt above 64 KiB, integral native doubles, identifier removal, missing requirement, budget, boot and tool-pin guards")
