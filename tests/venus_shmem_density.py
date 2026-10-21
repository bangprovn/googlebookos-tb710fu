#!/usr/bin/env python3
"""Exercise actual SHM helpers: ownership, contents, gating and bounded advice."""
from pathlib import Path
import hashlib
import json
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
metadata = root / "patches/tb710fu/virglrenderer/shmem-density.json"
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


with tempfile.TemporaryDirectory(prefix="gb-shmem-density-") as temporary:
    base = Path(temporary)
    original = base / "src/venus/vkr_context.c"
    original.parent.mkdir(parents=True)
    original.write_bytes(source.read_bytes())
    subprocess.run(["patch", "--reverse", "--batch", "--fuzz=0", "-p1", "-d", str(base),
                    "-i", str(patch)], check=True, capture_output=True, timeout=10)
    assert hashlib.sha256(original.read_bytes()).hexdigest() == manifest["sha256"]
    helpers = "\n".join(function(source.read_text(), name) for name in [
        "vkr_shm_dense_map", "vkr_shm_trace_allowed", "vkr_shm_dense_prepare",
        "vkr_context_map_shm"])
    harness = base / "density.c"
    harness.write_text(r'''
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>
#ifndef MADV_COLLAPSE
#define MADV_COLLAPSE 25
#endif
#define VKR_SHM_PMD_BYTES (2UL << 20)
#define VKR_SHM_DENSE_MAX_BYTES (64UL << 20)
static const size_t bytes = 8UL << 20;
static unsigned map_calls, unmap_calls, advice_calls, clock_calls, log_calls;
static unsigned fail_map, fail_unmap, fail_advice, fail_clock;
static int virtual_maps, fail_reservation_once;
static long clock_step_ms;
static uintptr_t unmap_addr[4];
static size_t unmap_size[4];
static char last_log[256];
static void *test_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off) {
    if (virtual_maps) {
        map_calls++;
        if (map_calls == fail_map) { errno = EIO; return MAP_FAILED; }
        if (map_calls == 1) {
            assert(addr == NULL && len == bytes + VKR_SHM_PMD_BYTES && prot == PROT_NONE);
            assert(flags == (MAP_PRIVATE | MAP_ANONYMOUS) && fd == -1 && off == 0);
            return (void *)0x10001000UL;
        }
        assert(map_calls == 2 && addr == (void *)0x10200000UL && len == bytes);
        assert(prot == (PROT_READ | PROT_WRITE) && flags == (MAP_SHARED | MAP_FIXED) && off == 0);
        return addr;
    }
    if (fail_reservation_once && prot == PROT_NONE) {
        fail_reservation_once = 0; errno = ENOMEM; return MAP_FAILED;
    }
    return mmap(addr, len, prot, flags, fd, off);
}
static int test_munmap(void *addr, size_t len) {
    if (!virtual_maps) return munmap(addr, len);
    assert(unmap_calls < 4);
    unmap_addr[unmap_calls] = (uintptr_t)addr;
    unmap_size[unmap_calls++] = len;
    if (unmap_calls == fail_unmap) { errno = EIO; return -1; }
    return 0;
}
static int test_madvise(void *addr, size_t len, int advice) {
    assert((uintptr_t)addr % VKR_SHM_PMD_BYTES == 0);
    assert(len == VKR_SHM_PMD_BYTES && advice == MADV_COLLAPSE);
    advice_calls++;
    if (advice_calls == fail_advice) { errno = EAGAIN; return -1; }
    return 0;
}
static int test_clock(clockid_t id, struct timespec *value) {
    assert(id == CLOCK_MONOTONIC);
    clock_calls++;
    if (clock_calls == fail_clock) { errno = EINVAL; return -1; }
    long ms = (clock_calls - 1) * clock_step_ms;
    value->tv_sec = ms / 1000; value->tv_nsec = ms % 1000 * 1000000;
    return 0;
}
static void vkr_log(const char *format, ...) {
    log_calls++;
    va_list args; va_start(args, format);
    int size = vsnprintf(last_log, sizeof(last_log), format, args); va_end(args);
    assert(size > 0 && (size_t)size < sizeof(last_log));
    assert(strncmp(last_log, "GB-VENUS-SHM: bytes=", 19) == 0);
}
#define mmap test_mmap
#define munmap test_munmap
#define madvise test_madvise
#define clock_gettime test_clock
''' + helpers + r'''
#undef mmap
#undef munmap
#undef madvise
#undef clock_gettime
static void reset(void) {
    map_calls = unmap_calls = advice_calls = clock_calls = 0;
    fail_map = fail_unmap = fail_advice = fail_clock = 0;
    clock_step_ms = 0; virtual_maps = 0;
}
static void simulation(unsigned map_failure, unsigned trim_failure) {
    reset(); virtual_maps = 1; fail_map = map_failure; fail_unmap = trim_failure;
    void *ptr = vkr_shm_dense_map(100, bytes);
    if (!map_failure && !trim_failure) {
        assert(ptr == (void *)0x10200000UL && unmap_calls == 2);
    } else {
        assert(ptr == MAP_FAILED && errno == EIO);
    }
    if (map_failure == 1) assert(unmap_calls == 0);
    if (map_failure == 2) assert(unmap_calls == 1 && unmap_addr[0] == 0x10001000UL && unmap_size[0] == bytes + VKR_SHM_PMD_BYTES);
    if (trim_failure == 1) assert(unmap_calls == 2 && unmap_addr[1] == 0x10001000UL && unmap_size[1] == bytes + VKR_SHM_PMD_BYTES);
    if (trim_failure == 2) assert(unmap_calls == 3 && unmap_addr[2] == 0x10001000UL && unmap_size[2] == bytes + 0x1ff000UL);
    if (!map_failure) {
        assert(unmap_addr[0] == 0x10200000UL + bytes && unmap_size[0] == 4096);
        if (trim_failure != 1) assert(unmap_addr[1] == 0x10001000UL && unmap_size[1] == 0x1ff000UL);
    }
}
int main(void) {
    struct rlimit cores = {0, 0}; assert(!setrlimit(RLIMIT_CORE, &cores)); alarm(10);
    assert(getpagesize() == 4096);
    simulation(0, 0); simulation(1, 0); simulation(2, 0);
    simulation(0, 1); simulation(0, 2); reset();
    size_t bad[] = {0, 4096, VKR_SHM_PMD_BYTES + 1, VKR_SHM_DENSE_MAX_BYTES + 4096, SIZE_MAX};
    for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        errno = 0; assert(vkr_shm_dense_map(-1, bad[i]) == MAP_FAILED && errno == EINVAL);
    }
    assert(vkr_shm_dense_map(-1, bytes) == MAP_FAILED && errno == EBADF);
    int fd = memfd_create("gb-owned-density-unit", MFD_CLOEXEC); assert(fd >= 0);
    assert(!ftruncate(fd, bytes));
    unsigned char pattern[4096], result[4096];
    for (unsigned i = 0; i < sizeof(pattern); i++) pattern[i] = (unsigned char)(i * 17 + i / 29);
    assert(pwrite(fd, pattern, sizeof(pattern), VKR_SHM_PMD_BYTES + 4096) == sizeof(pattern));
    unsetenv("GB_VENUS_ALLOCATION_DIAGNOSTICS_V1");
    const char *policies[] = {NULL, "unknown", "guest"};
    for (unsigned i = 0; i < 3; i++) {
        if (policies[i]) setenv("GB_VENUS_GUEST_VRAM_V1", policies[i], 1);
        else unsetenv("GB_VENUS_GUEST_VRAM_V1");
        void *p = vkr_context_map_shm(fd, bytes); assert(p != MAP_FAILED);
        assert(!advice_calls && !clock_calls); assert(!munmap(p, bytes));
    }
    setenv("GB_VENUS_GUEST_VRAM_V1", "host", 1);
    fail_reservation_once = 1;
    void *fallback = vkr_context_map_shm(fd, bytes);
    assert(fallback != MAP_FAILED && !advice_calls); assert(!munmap(fallback, bytes));
    unsigned char *p = vkr_context_map_shm(fd, bytes);
    assert(p != MAP_FAILED && (uintptr_t)p % VKR_SHM_PMD_BYTES == 0);
    assert(advice_calls == 4 && !log_calls && fcntl(fd, F_GETFD) >= 0);
    assert(!memcmp(p + VKR_SHM_PMD_BYTES + 4096, pattern, sizeof(pattern)));
    p[0] = 0xa7; assert(pread(fd, result, 1, 0) == 1 && result[0] == 0xa7);
    assert(pwrite(fd, "z", 1, bytes - 1) == 1 && p[bytes - 1] == 'z');
    setenv("GB_VENUS_ALLOCATION_DIAGNOSTICS_V1", "1", 1);
    reset(); fail_advice = 2; vkr_shm_dense_prepare(p, bytes);
    assert(advice_calls == 4 && strstr(last_log, "attempted=4 succeeded=3 errno=11 deadline=0"));
    reset(); clock_step_ms = 400; vkr_shm_dense_prepare(p, bytes);
    assert(advice_calls == 2 && strstr(last_log, "attempted=2 succeeded=2 errno=0 deadline=1"));
    reset(); fail_clock = 1; vkr_shm_dense_prepare(p, bytes);
    assert(!advice_calls && strstr(last_log, "attempted=0 succeeded=0 errno=22"));
    reset(); fail_clock = 3; vkr_shm_dense_prepare(p, bytes);
    assert(advice_calls == 1 && strstr(last_log, "attempted=1 succeeded=1 errno=22"));
    reset(); vkr_shm_dense_prepare(p, VKR_SHM_PMD_BYTES + 4096);
    assert(advice_calls == 1); /* A non-PMD tail is never claimed. */
    for (unsigned i = 0; i < 32; i++) vkr_shm_dense_prepare(p, VKR_SHM_PMD_BYTES);
    assert(log_calls == 16 && !vkr_shm_trace_allowed());
    assert(!memcmp(p + VKR_SHM_PMD_BYTES + 4096, pattern, sizeof(pattern)));
    assert(pread(fd, result, sizeof(result), VKR_SHM_PMD_BYTES + 4096) == sizeof(result));
    assert(!memcmp(result, pattern, sizeof(pattern)));
    assert(!munmap(p, bytes) && fcntl(fd, F_GETFD) >= 0);
    reset();
    void *small = vkr_context_map_shm(fd, 4096);
    assert(small != MAP_FAILED && !advice_calls && !clock_calls);
    assert(!munmap(small, 4096));
    assert(!ftruncate(fd, VKR_SHM_DENSE_MAX_BYTES));
    void *maximum = vkr_context_map_shm(fd, VKR_SHM_DENSE_MAX_BYTES);
    assert(maximum != MAP_FAILED && advice_calls == 32 && log_calls == 16);
    assert(!munmap(maximum, VKR_SHM_DENSE_MAX_BYTES) && !close(fd));
    return 0;
}
''')
    executable = base / "density"
    subprocess.run(["cc", "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
                    str(harness), "-o", str(executable)], check=True, timeout=30)
    subprocess.run([str(executable)], check=True, timeout=15)
    print("SHM alignment, owned-range cleanup, alias contents, policy gating and bounded advice passed.")
