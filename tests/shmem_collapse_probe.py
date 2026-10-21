#!/usr/bin/env python3
"""Build/run the owned SHM control; huge-page advice may legitimately fail."""
from pathlib import Path
import json
import resource
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = root / "tests/fixtures/shmem_collapse_probe.c"


def limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_AS, (128 << 20, 128 << 20))


with tempfile.TemporaryDirectory(prefix="gb-owned-shmem-") as temporary:
    executable = Path(temporary) / "control"
    subprocess.run(["cc", "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
                    str(source), "-o", str(executable)], check=True, timeout=30)
    result = subprocess.run([str(executable)], check=True, capture_output=True,
                            text=True, timeout=25, preexec_fn=limits)
    assert len(result.stdout) + len(result.stderr) < 4096
    report = json.loads(result.stdout)
    assert report["status"] == "completed"
    assert report["bytes"] == 8 << 20 and report["content_preserved"] is True
    assert report["firmware_written"] is False and report["gunyah_share_tested"] is False
    assert len(report["collapse_result"]) == len(report["collapse_errno"]) == 4
    assert all((code == 0 and error == 0) or (code == -1 and error > 0)
               for code, error in zip(report["collapse_result"], report["collapse_errno"]))
    assert report["elapsed_ms"] >= 0 and report["rss_kb"] >= 8192
    assert 0 <= report["shmem_pmd_mapped_kb"] <= 8192
    assert report["file_pmd_mapped_kb"] == 0
    print(json.dumps(report))
