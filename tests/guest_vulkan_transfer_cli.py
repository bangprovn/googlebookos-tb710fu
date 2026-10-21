#!/usr/bin/env python3
"""An explicit private ICD must never bypass the Venus device identity check."""
from pathlib import Path
import json
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="gb-transfer-cli-") as temporary:
    executable = Path(temporary) / "transfer"
    subprocess.run(["cc", "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
                    str(root / "tests/fixtures/guest_vulkan_transfer.c"), "-ldl",
                    "-o", str(executable)], check=True, timeout=30)
    env = os.environ.copy()
    env["LP_NUM_THREADS"] = "2"
    for args in [[], ["--venus-icd", "relative.json"], ["--venus-icd"],
                 ["--lavapipe-control", "/absolute.json"], ["--unknown"]]:
        result = subprocess.run([str(executable), *args], capture_output=True,
                                text=True, env=env, timeout=25)
        assert result.returncode == 1
        assert json.loads(result.stdout)["stage"] == "explicit_venus_or_software_control_required"
    icd = Path("/usr/share/vulkan/icd.d/lvp_icd.json")
    if not icd.exists():
        raise SystemExit("Lavapipe control ICD is required for the identity regression check.")
    control = subprocess.run([str(executable), "--lavapipe-control"], capture_output=True,
                             text=True, env=env, timeout=25)
    assert len(control.stdout) + len(control.stderr) < 65536
    assert control.returncode == 0, control.stderr
    report = json.loads(control.stdout)
    assert report["status"] == "transfer_readback_verified" and report["software_control"] is True
    assert report["venus_transfer_verified"] is False and report["custom_icd_explicit"] is False
    negative = subprocess.run([str(executable), "--venus-icd", str(icd)], capture_output=True,
                              text=True, env=env, timeout=25)
    assert negative.returncode == 1
    assert json.loads(negative.stdout)["stage"] == "selected_driver_identity_mismatch"
    print("CLI rejection, explicit CPU control readback and custom-ICD CPU identity refusal passed.")
