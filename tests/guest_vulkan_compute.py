#!/usr/bin/env python3
"""Verify shader/header correspondence, CPU control and Venus identity refusal."""
from pathlib import Path
import json
import os
import re
import struct
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
fixtures = root / "tests/fixtures"
compiler = root / "artifacts/tools/mesa-host-tools-v1/root/usr/bin/glslangValidator"
with tempfile.TemporaryDirectory(prefix="gb-compute-control-") as temporary:
    base = Path(temporary)
    for kind in ['compute', 'uniform']:
        spirv = base / (kind + '.spv')
        subprocess.run([str(compiler), "-V", "--target-env", "vulkan1.1", "-S", "comp",
                        str(fixtures / ('guest_vulkan_' + kind + '.comp')), "-o", str(spirv)],
                       check=True, capture_output=True, timeout=30)
        words = [int(word, 16) for word in re.findall(
            r"0x([0-9a-f]{8})u", (fixtures / ('guest_vulkan_' + kind + '_spv.h')).read_text())]
        assert struct.pack("<" + "I" * len(words), *words) == spirv.read_bytes()
    executable = base / "compute"
    subprocess.run(["cc", "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
                    "-I", str(fixtures), str(fixtures / "guest_vulkan_compute.c"),
                    "-ldl", "-o", str(executable)], check=True, timeout=30)
    env = os.environ.copy()
    env["LP_NUM_THREADS"] = "2"
    control = subprocess.run([str(executable), "--lavapipe-control"], capture_output=True,
                             text=True, env=env, timeout=25)
    assert len(control.stdout) + len(control.stderr) < 65536
    assert control.returncode == 0, control.stderr
    report = json.loads(control.stdout)
    assert report["status"] == "shader_readback_verified" and report["software_control"] is True
    assert report["venus_compute_verified"] is False and report["dispatches_verified"] == 3
    assert report["words_verified_per_dispatch"] == 1024
    assert report["coherent_cpu_input_verified"] is False
    for mode in ['remap', 'persistent', 'uniform-remap', 'uniform-persistent', 'uniform-reused', 'uniform-reused-implicit']:
        result = subprocess.run([str(executable), '--lavapipe-control'], capture_output=True,
                                text=True, env=dict(env, GB_GUEST_COMPUTE_COHERENT_V1=mode), timeout=25)
        assert result.returncode == 0, result.stderr
        coherent = json.loads(result.stdout)
        assert coherent['software_control'] is True and coherent['venus_compute_verified'] is False
        assert coherent['coherent_cpu_input_verified'] is True
        assert coherent['persistent_mapping'] == (mode.endswith('persistent') or mode.startswith('uniform-reused'))
        assert coherent['uniform_cpu_input_verified'] == mode.startswith('uniform-')
        assert coherent['command_buffer_reused'] == mode.startswith('uniform-reused')
        assert coherent['explicit_host_input_barriers'] == (not mode.endswith('implicit'))
    unknown = subprocess.run([str(executable), '--lavapipe-control'], capture_output=True,
                             text=True, env=dict(env, GB_GUEST_COMPUTE_COHERENT_V1='unknown'), timeout=3)
    assert unknown.returncode == 1
    assert json.loads(unknown.stdout)['stage'] == 'unknown_coherent_input_profile'
    assert 'GB_GUEST_VK_STAGE:' not in unknown.stderr
    negative = subprocess.run([str(executable), "--venus-icd", "/usr/share/vulkan/icd.d/lvp_icd.json"],
                              capture_output=True, text=True, env=env, timeout=25)
    assert negative.returncode == 1
    assert json.loads(negative.stdout)["stage"] == "selected_driver_identity_mismatch"
    print("Both SPIR-V headers match GLSL; storage/uniform CPU-input and command-reuse controls pass; unknown profile and CPU-as-Venus are rejected.")
