#!/usr/bin/env python3
"""Compile the real policy and pool allocator; verify growth never truncates."""
from pathlib import Path
import hashlib
import json
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
metadata = root / "patches/tb710fu/mesa/guest-command-pool.json"
manifest = json.loads(metadata.read_text())
source = root / manifest["path"]
patch = metadata.with_suffix(".patch")
assert hashlib.sha256(source.read_bytes()).hexdigest() == manifest["result_sha256"]
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


with tempfile.TemporaryDirectory(prefix="gb-guest-command-pool-") as temporary:
    base = Path(temporary)
    original = base / "src/virtio/vulkan/vn_instance.c"
    original.parent.mkdir(parents=True)
    original.write_bytes(source.read_bytes())
    subprocess.run(["patch", "--reverse", "--batch", "--fuzz=0", "-p1", "-d", str(base),
                    "-i", str(patch)], check=True, capture_output=True, timeout=10)
    assert hashlib.sha256(original.read_bytes()).hexdigest() == manifest["sha256"]
    pool_source = source.with_name("vn_renderer_util.c")
    pool_hash = hashlib.sha256(pool_source.read_bytes()).hexdigest()
    assert pool_hash == manifest["unchanged_pool_allocator_sha256"]
    helpers = function(source.read_text(), "vn_command_shmem_pool_min_size") + "\n" + function(
        pool_source.read_text(), "vn_renderer_shmem_pool_grow_locked")
    harness = base / "pool.c"
    harness.write_text(r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>
#define VN_TRACE_FUNC() ((void)0)
struct vn_renderer { unsigned create_calls, released; size_t last_size; bool fail; };
struct vn_renderer_shmem { size_t bytes; };
struct vn_renderer_shmem_pool {
    size_t min_alloc_size, size, used;
    struct vn_renderer_shmem *shmem;
};
static struct vn_renderer_shmem *vn_renderer_shmem_create(struct vn_renderer *r, size_t size) {
    r->create_calls++; r->last_size = size;
    if (r->fail) return NULL;
    struct vn_renderer_shmem *p = malloc(sizeof(*p)); assert(p); p->bytes = size; return p;
}
static void vn_renderer_shmem_unref(struct vn_renderer *r, struct vn_renderer_shmem *p) {
    assert(p); r->released++; free(p);
}
''' + helpers + r'''
int main(void) {
    struct rlimit core = {0, 0}; assert(!setrlimit(RLIMIT_CORE, &core)); alarm(5);
    struct vn_renderer r = {0};
    const char *policies[] = {NULL, "", "unknown", "1M", "1048576", "1m"};
    for (unsigned i = 0; i < sizeof(policies) / sizeof(policies[0]); i++) {
        if (policies[i]) assert(!setenv("GB_VENUS_COMMAND_POOL_V1", policies[i], 1));
        else assert(!unsetenv("GB_VENUS_COMMAND_POOL_V1"));
        size_t minimum = vn_command_shmem_pool_min_size();
        assert(minimum == (i == 5 ? 1UL << 20 : 8UL << 20));
        struct vn_renderer_shmem_pool p = {.min_alloc_size = minimum};
        assert(vn_renderer_shmem_pool_grow_locked(&r, &p, 16 << 10));
        assert(p.size == minimum && p.shmem->bytes == minimum && !p.used);
        struct vn_renderer_shmem *old = p.shmem;
        p.used = 4096; unsigned released = r.released;
        r.fail = true;
        assert(!vn_renderer_shmem_pool_grow_locked(&r, &p, 2 << 20));
        assert(p.shmem == old && p.size == minimum && p.used == 4096 && r.released == released);
        r.fail = false;
        assert(vn_renderer_shmem_pool_grow_locked(&r, &p, 2 << 20));
        assert(p.size == (minimum < 2UL << 20 ? 2UL << 20 : minimum));
        assert(!p.used && r.released == released + 1);
        assert(vn_renderer_shmem_pool_grow_locked(&r, &p, (8 << 20) + 1));
        assert(p.size == 16UL << 20 && p.shmem->bytes == 16UL << 20);
        old = p.shmem; size_t used = p.used; released = r.released;
        unsigned created = r.create_calls;
        assert(!vn_renderer_shmem_pool_grow_locked(&r, &p, SIZE_MAX));
        assert(r.create_calls == created && p.shmem == old && p.used == used && r.released == released);
        vn_renderer_shmem_unref(&r, p.shmem);
    }
    return 0;
}
''')
    executable = base / "pool"
    subprocess.run(["cc", "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
                    str(harness), "-o", str(executable)], check=True, timeout=30)
    subprocess.run([str(executable)], check=True, timeout=10)
    print("Stock/opt-in selection, command growth, allocation failure preservation and overflow refusal passed.")
