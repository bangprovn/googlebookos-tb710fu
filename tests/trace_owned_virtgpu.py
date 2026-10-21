#!/usr/bin/env python3
"""Exercise the real tracer with an owned child; no device or GPU is opened."""
from pathlib import Path
import hashlib
import json
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
tracer = root / "target/debug/examples/trace_owned_virtgpu"
with tempfile.TemporaryDirectory(prefix="gb-owned-ioctl-") as temporary:
    base = Path(temporary)
    source = base / "child.c"
    marker = base / "executions"
    source.write_text(r'''
#include <stdint.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
static volatile sig_atomic_t delivered;
static void handled(int signal) { delivered = signal; }
struct blob {
    uint32_t mem, flags, bo, res;
    uint64_t size;
    uint32_t pad, cmd_size;
    uint64_t cmd, id;
};
int main(int argc, char **argv) {
    struct rlimit no_core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &no_core)) return 20;
    if (argc != 2 || strcmp(argv[1], "--venus")) return 21;
    FILE *f = fopen(MARKER, "a");
    if (!f) return 22;
    fputs("executed\n", f); fclose(f);
    if (signal(SIGUSR1, handled) == SIG_ERR) return 23;
    raise(SIGUSR1);
    if (delivered != SIGUSR1) return 24;
    /* No fd is opened. The real kernel must return EBADF for these ioctls. */
    struct blob b = {.mem=2,.flags=1,.size=4096,.id=7};
    if (sizeof(b) != 48) return 25;
    if (ioctl(-1, 0xc030644aUL, &b) != -1 || errno != EBADF) return 26;
    uint64_t value = 0, getparam[2] = {4, (uintptr_t)&value};
    if (ioctl(-1, 0xc0106443UL, &getparam) != -1 || errno != EBADF) return 27;
    /* Unrelated requests with unreadable pointers must never be inspected. */
    ioctl(-1, 0x1234UL, (void *)1);
    return 0;
}
''')
    child = base / "child"
    subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                    '-DMARKER="' + str(marker) + '"', str(source), "-o", str(child)],
                   check=True, timeout=30)
    expected = hashlib.sha256(child.read_bytes()).hexdigest()

    def run(program, sha, name):
        output = base / (name + ".json")
        result = subprocess.run([str(tracer), str(program), sha, str(output)],
                                capture_output=True, text=True, timeout=30)
        return result, json.loads(output.read_text())

    result, report = run(child, expected, "valid")
    assert result.returncode == 0, result.stderr
    assert report["child_exit_code"] == 0 and report["child_signal"] is None
    assert report["guest_auth_argv_collected"] is False
    assert report["events"] == [
        dict(fd=-1, ioctl_return=-9, kind="create_blob", blob_mem=2, blob_flags=1,
             size=4096, blob_id=7, bo_handle=None, resource_handle=None),
        dict(fd=-1, ioctl_return=-9, kind="getparam", param=4, value=None),
    ]
    assert str(marker) not in json.dumps(report)
    assert marker.read_text() == "executed\n"

    result, report = run(child, "0" * 64, "hash-mismatch")
    assert result.returncode != 0 and report["status"] == "trace_failed"
    assert marker.read_text() == "executed\n"

    link = base / "symlink"
    link.symlink_to(child)
    result, report = run(link, expected, "symlink-rejected")
    assert result.returncode != 0 and report["status"] == "trace_failed"
    assert marker.read_text() == "executed\n"

    output = base / "valid.json"
    before = output.read_bytes()
    result = subprocess.run([str(tracer), str(child), expected, str(output)],
                            capture_output=True, timeout=5)
    assert result.returncode != 0 and output.read_bytes() == before
    assert marker.read_text() == "executed\n"
    print("4 owned-tracer cases passed; signal forwarding and unrelated ioctl exclusion verified.")
