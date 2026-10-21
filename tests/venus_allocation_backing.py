#!/usr/bin/env python3
"""Real descriptor lifetime and concurrent budget checks for actual C helpers."""
from pathlib import Path
import hashlib
import json
import resource
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
metadata = root / "patches/tb710fu/virglrenderer/allocation-boundary-and-fd-cleanup.json"
manifest = json.loads(metadata.read_text())
source = root / manifest["path"]
assert hashlib.sha256(source.read_bytes()).hexdigest() == manifest["result_sha256"]
patch = metadata.with_suffix(".patch")
assert hashlib.sha256(patch.read_bytes()).hexdigest() == manifest["patch_sha256"]


def function(text, name):
    position = text.index(name + "(")
    start = text.rfind("static ", 0, position)
    opening = text.index("{", position)
    depth = 0
    for end in range(opening, len(text)):
        if text[end] == "{":
            depth += 1
        elif text[end] == "}":
            depth -= 1
            if not depth:
                return text[start:end + 1]
    raise AssertionError("incomplete helper")


with tempfile.TemporaryDirectory(prefix="gb-allocation-backing-") as temporary:
    base = Path(temporary)
    original = base / "src/venus/vkr_device_memory.c"
    original.parent.mkdir(parents=True)
    original.write_bytes(source.read_bytes())
    subprocess.run(["patch", "--reverse", "--batch", "--fuzz=0", "-p1", "-d", str(base),
                    "-i", str(patch)], check=True, capture_output=True, timeout=10)
    assert hashlib.sha256(original.read_bytes()).hexdigest() == manifest["sha256"]
    text = source.read_text()
    helpers = "\n".join(function(text, name) for name in [
        "vkr_allocation_trace_allowed", "vkr_discard_allocation_backing"])
    harness = base / "backing.c"
    harness.write_text(r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
struct vkr_mtl_shm { int unused; };
static int gbm_released, metal_released;
static int gbm_marker;
static struct vkr_mtl_shm metal_marker;
static void vkr_gbm_bo_destroy(void *value) {
    assert(value == &gbm_marker); gbm_released++;
}
static void vkr_mtl_shm_free(struct vkr_mtl_shm *value) {
    if (value) { assert(value == &metal_marker); metal_released++; }
}
''' + helpers + r'''
static void gone(int fd) {
    errno = 0; assert(fcntl(fd, F_GETFD) == -1 && errno == EBADF);
}
static unsigned approved;
static void *worker(void *value) {
    (void)value;
    for (unsigned i = 0; i < 2048; i++)
        if (vkr_allocation_trace_allowed())
            __atomic_fetch_add(&approved, 1, __ATOMIC_RELAXED);
    return NULL;
}
int main(void) {
    int original[2], unrelated[2];
    assert(pipe(original) == 0 && pipe(unrelated) == 0);
    int retained = dup(original[0]); assert(retained >= 0);
    vkr_discard_allocation_backing(original[0], retained, &gbm_marker, &metal_marker);
    gone(original[0]); gone(retained);
    assert(gbm_released == 1 && metal_released == 1);
    assert(write(unrelated[1], "x", 1) == 1);
    char byte = 0; assert(read(unrelated[0], &byte, 1) == 1 && byte == 'x');
    int alias = dup(original[1]); assert(alias >= 0);
    vkr_discard_allocation_backing(alias, alias, NULL, NULL); gone(alias);
    vkr_discard_allocation_backing(-1, -1, NULL, NULL);
    assert(gbm_released == 1 && metal_released == 1);
    close(original[1]); close(unrelated[0]); close(unrelated[1]);

    unsetenv("GB_VENUS_ALLOCATION_DIAGNOSTICS_V1");
    assert(!vkr_allocation_trace_allowed());
    setenv("GB_VENUS_ALLOCATION_DIAGNOSTICS_V1", "unknown", 1);
    assert(!vkr_allocation_trace_allowed());
    setenv("GB_VENUS_ALLOCATION_DIAGNOSTICS_V1", "1", 1);
    pthread_t threads[16];
    for (unsigned i = 0; i < 16; i++) assert(!pthread_create(&threads[i], NULL, worker, NULL));
    for (unsigned i = 0; i < 16; i++) assert(!pthread_join(threads[i], NULL));
    assert(approved == 16 && !vkr_allocation_trace_allowed());
    unsetenv("GB_VENUS_ALLOCATION_DIAGNOSTICS_V1");
    assert(!vkr_allocation_trace_allowed());
    setenv("GB_VENUS_ALLOCATION_DIAGNOSTICS_V1", "1", 1);
    assert(!vkr_allocation_trace_allowed());
    return 0;
}
''')
    executable = base / "backing"
    subprocess.run(["cc", "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-pthread",
                    str(harness), "-o", str(executable)], check=True, timeout=30)
    subprocess.run([str(executable)], check=True, timeout=5,
                   preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_CORE, (0, 0)))
    print("Owned descriptor release, unrelated descriptor retention and concurrent 16-request budget passed.")
