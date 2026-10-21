#!/usr/bin/env python3
"""Bounded owner-run guest memory/disk integrity workload; no firmware operations."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import tempfile
import time

MIB = 1024 * 1024


def workload(memory_mib, disk_mib, seconds, directory):
    if not (8 <= memory_mib <= 1024 and 1 <= disk_mib <= 256 and 1 <= seconds <= 600):
        raise ValueError("workload bounds exceeded")
    directory = Path(directory).resolve(strict=True)
    if not directory.is_dir() or shutil.disk_usage(directory).free < (disk_mib + 32) * MIB:
        raise ValueError("insufficient disposable-file space")
    data = bytearray(memory_mib * MIB)
    expected = hashlib.sha256()
    for i in range(memory_mib):
        block = hashlib.sha256(struct.pack("<Q", i)).digest() * (MIB // 32)
        data[i * MIB:(i + 1) * MIB] = block
        expected.update(block)
    expected_memory = expected.hexdigest()
    with tempfile.TemporaryDirectory(prefix="gb-terminal-workload-", dir=directory) as work:
        test_file = Path(work) / "integrity.bin"
        expected = hashlib.sha256()
        with test_file.open("xb") as stream:
            for i in range(disk_mib):
                block = hashlib.sha256(b"disk" + struct.pack("<Q", i)).digest() * (MIB // 32)
                if stream.write(block) != len(block):
                    raise IOError("short disposable-file write")
                expected.update(block)
            stream.flush()
            os.fsync(stream.fileno())
        expected_disk = expected.hexdigest()
        start = time.monotonic()
        rounds = 0
        while rounds < 3 or time.monotonic() - start < seconds:
            if hashlib.sha256(data).hexdigest() != expected_memory:
                raise RuntimeError("memory integrity differs")
            actual = hashlib.sha256()
            with test_file.open("rb") as stream:
                while True:
                    block = stream.read(MIB)
                    if not block:
                        break
                    actual.update(block)
            if actual.hexdigest() != expected_disk or test_file.stat().st_size != disk_mib * MIB:
                raise RuntimeError("disposable-file integrity differs")
            rounds += 1
        elapsed = time.monotonic() - start
    return dict(schema_version=1, status="passed", memory_mib=memory_mib,
                disk_mib=disk_mib, seconds=round(elapsed, 2), rounds=rounds,
                memory_sha256=expected_memory, disk_sha256=expected_disk,
                own_disposable_files_removed=not Path(work).exists())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--memory-mib", type=int, default=768)
    parser.add_argument("--disk-mib", type=int, default=64)
    parser.add_argument("--seconds", type=int, default=60)
    parser.add_argument("--directory", default=".")
    args = parser.parse_args()
    result = workload(args.memory_mib, args.disk_mib, args.seconds, args.directory)
    print("GB_WORKLOAD_RESULT " + json.dumps(result, sort_keys=True), flush=True)
    print("GB_WORKLOAD_PASS memory=%dMiB disk=%dMiB rounds=%d seconds=%.2f cleaned=%s" %
          (result["memory_mib"], result["disk_mib"], result["rounds"], result["seconds"],
           result["own_disposable_files_removed"]), flush=True)
