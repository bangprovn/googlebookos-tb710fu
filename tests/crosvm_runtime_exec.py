#!/usr/bin/env python3
"""Host exec-boundary tests with fixture args, never firmware or a device."""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile

REPO = Path(__file__).resolve().parents[1]
SOURCE = REPO / "crates/gb-boot-logger/examples/crosvm_runtime_adapter.rs"
HELPER = r'''
use std::os::unix::{ffi::OsStrExt, io::FromRawFd};
use std::io::Read;
fn hex(bytes: &[u8]) -> String { bytes.iter().map(|v| format!("{v:02x}")).collect() }
fn main() {
    for (i, a) in std::env::args_os().enumerate() { println!("arg{i}={}", hex(a.as_bytes())); }
    println!("marker={}", std::env::var("GB_EXEC_MARKER").unwrap());
    println!("library={}", std::env::var("LD_LIBRARY_PATH").unwrap());
    println!("parcel={}", std::env::var("DROIDVM_SHIM_PARCEL_MB").unwrap());
    println!("gate={}", std::env::var("DROIDVM_PREPIN_CONTROL_DIR").unwrap_or_else(|_| "unset".into()));
    println!("pipe_gate={}", std::env::var("DROIDVM_PREPIN_PIPE_FD").unwrap_or_else(|_| "unset".into()));
    println!("pool={}", std::env::var("DROIDVM_RAM_POOL_REQUIRED").unwrap_or_else(|_| "unset".into()));
    println!("display={}", std::env::var("GB_AVF_DISPLAY_SERVICE").unwrap_or_else(|_| "unset".into()));
    println!("vulkan_driver={}", std::env::var("ANDROID_EMU_VK_LOADER_PATH").unwrap_or_else(|_| "unset".into()));
    let fd: i32 = std::env::var("GB_EXEC_FD").unwrap().parse().unwrap();
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut bytes = Vec::new(); file.read_to_end(&mut bytes).unwrap();
    println!("fd={}", hex(&bytes));
}
'''


def run(command, **kwargs):
    result = subprocess.run(command, capture_output=True, timeout=30, **kwargs)
    assert result.returncode == 0, result.stderr[:2000]
    assert len(result.stdout) + len(result.stderr) < 65536
    return result


with tempfile.TemporaryDirectory(prefix="gb-runtime-exec-") as temporary:
    base = Path(temporary)
    compiler = Path(run(["rustup", "which", "rustc"]).stdout.decode().strip())
    run([str(compiler), "--edition=2024", str(SOURCE), "-o", str(base / "crosvm")])
    (base / "helper.rs").write_text(HELPER)
    run([str(compiler), "--edition=2024", str(base / "helper.rs"), "-o", str(base / "helper")])
    for name in ["fallback/crosvm", "fallback/crosvm_minimal", "runtime/bin/crosvm"]:
        path = base / name
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(base / "helper", path)
        path.chmod(0o700)
    (base / "runtime/lib64").mkdir()
    shutil.copyfile(base / "crosvm", base / "crosvm_minimal")
    (base / "crosvm_minimal").chmod(0o700)

    for variant in ["crosvm", "crosvm_minimal"]:
        for case in ["passthrough", "default", "display", "display_name", "display_label", "display_struct", "probe64", "probe512"]:
            selected = case != "passthrough"
            name = b"crosvm_gb-runtime-share-probe-64" if case == "probe64" else b"crosvm_gb-runtime-share-probe-1" if case == "probe512" else b"crosvm_debian" if selected else b"unrelated"
            arguments = [b"run", b"--name=" + name,
                         b"--mem=512" if case == "probe512" else b"--mem=2048", b"--irqchip=kernel[allow-vgic-its=true]",
                         b"--force-disable-readonly-mem", b"--gpu=mode=gfxstream",
                         b"--net=tap-fd=12", b"--block=path=/proc/self/fd/9",
                         b"--params", b"fixture-opaque-\xff"]
            display_values = {"display": b"2048", "display_name": b"debian", "display_label": b"android.crosvm.debian/0", "display_struct": b"name=legacy/0,screen=gpu-0,transport-cap=cpu"}
            if case in display_values:
                arguments.extend([b"--cid=2048", b"--android-display-service=" + display_values[case]])
            with (base / "fd-fixture").open("w+b") as descriptor:
                descriptor.write(b"owned-inherited-descriptor"); descriptor.flush(); descriptor.seek(0)
                expected_descriptor=descriptor.fileno()
                arguments.append(b"--serial=type=file,hardware=virtio-console,num=1,input=/proc/self/fd/"+str(descriptor.fileno()).encode())
                environment = os.environ.copy()
                environment.update(GB_EXEC_MARKER="fixture-preserved", GB_EXEC_FD=str(descriptor.fileno()),
                                   LD_LIBRARY_PATH="/fixture/unrelated", DROIDVM_SHIM_PARCEL_MB="128", DROIDVM_PREPIN_CONTROL_DIR="/fixture/unrelated-gate", DROIDVM_PREPIN_PIPE_FD="fixture-unrelated", DROIDVM_RAM_POOL_REQUIRED="fixture-unrelated", GB_AVF_DISPLAY_SERVICE="fixture-unrelated-display", ANDROID_EMU_VK_LOADER_PATH="/fixture/unrelated-vulkan")
                result = run([b"avf-custom-argv0", *arguments], executable=base / variant,
                             env=environment, pass_fds=(descriptor.fileno(),))
            values = dict(line.split("=", 1) for line in result.stdout.decode().splitlines())
            received = [bytes.fromhex(values[f"arg{i}"]) for i in range(sum(k.startswith("arg") for k in values))]
            assert received[0] == b"avf-custom-argv0"
            assert values["marker"] == "fixture-preserved"
            assert bytes.fromhex(values["fd"]) == b"owned-inherited-descriptor"
            if not selected:
                assert received[1:] == arguments
                assert values["library"] == "/fixture/unrelated"
                assert values["parcel"] == "128"
                assert values["gate"] == "/fixture/unrelated-gate"
                assert values["pipe_gate"] == "fixture-unrelated"
                assert values["pool"] == "fixture-unrelated"
                assert values["display"] == "fixture-unrelated-display"
                assert values["vulkan_driver"] == "/fixture/unrelated-vulkan"
                assert result.stderr == b""
            else:
                for opaque in arguments[5:]:
                    if case not in ["probe64", "probe512"] and opaque == b"--gpu=mode=gfxstream":
                        assert b"--gpu=mode=gfxstream,vulkan=true,udmabuf=true,context-types=virgl:virgl2:venus" in received
                        assert opaque not in received
                    elif case in ["display_name", "display_label", "display_struct"] and opaque == b"--android-display-service=" + display_values[case]:
                        expected_display = b"name=2048,screen=gpu-0,transport-cap=cpu" if case == "display_struct" else b"2048"
                        assert b"--android-display-service=" + expected_display in received
                        assert opaque not in received
                    else:
                        assert opaque in received
                assert b"--force-disable-readonly-mem" not in received
                assert b"--irqchip=kernel" in received
                assert b"--hypervisor=gunyah" in received
                assert b"--protected-vm-pseudo-unprotected" in received
                assert values["library"] == str(base / "runtime/lib64") + ":/fixture/unrelated"
                assert values["parcel"] == ("16" if case == "probe512" else "64")
                assert values["pool"] == "1"
                assert values["display"] == ("mica_v17" if case in display_values else "unset")
                assert values["vulkan_driver"] == ("/fixture/unrelated-vulkan" if case in ["probe64", "probe512"] else "/system_ext/lib64/gb-runtime-v1/libvulkan_freedreno.so")
                assert values["gate"] == "unset"
                assert values["pipe_gate"] == (str(expected_descriptor) if case == "probe64" else "unset")
                assert b"fixture-opaque" not in result.stderr

print("16 host exec scenarios passed: full/minimal, selected/passthrough/native64/native512/display/display_name/display_label/display_struct, argv0, opaque bytes, environment and inherited FD.")
