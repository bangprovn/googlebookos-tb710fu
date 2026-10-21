#!/usr/bin/env python3
"""Compile actual capset code and compare it bytewise with the reversed patch.

Owned protocol helper stubs isolate allocation-policy selection; no GPU/device.
"""
from pathlib import Path
import hashlib
import json
import resource
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
metadata = root / "patches/tb710fu/virglrenderer/explicit-guest-vram-policy.json"
provenance = json.loads(metadata.read_text())
source = root / provenance["path"]
patch = metadata.with_suffix(".patch")
assert hashlib.sha256(source.read_bytes()).hexdigest() == provenance["result_sha256"]
assert hashlib.sha256(patch.read_bytes()).hexdigest() == provenance["patch_sha256"]


def function(text):
    start = text.index("size_t\nvkr_get_capset(")
    pos = text.index("{", start)
    depth = 0
    for index in range(pos, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[start:index + 1]
    raise AssertionError("incomplete capset function")


with tempfile.TemporaryDirectory(prefix="gb-venus-policy-") as temporary:
    base = Path(temporary)
    old = base / "src/venus/vkr_renderer.c"
    old.parent.mkdir(parents=True)
    old.write_bytes(source.read_bytes())
    subprocess.run(["patch", "--reverse", "--batch", "--fuzz=0", "-p1", "-d", str(base),
                    "-i", str(patch)], check=True, timeout=10, capture_output=True)
    assert hashlib.sha256(old.read_bytes()).hexdigest() == provenance["sha256"]
    baseline = function(old.read_text()).replace("vkr_get_capset(", "baseline_capset(", 1)
    harness = base / "policy.c"
    harness.write_text(r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#define VIRGL_RENDERER_UNSTABLE_APIS
#include "virglrenderer.h"
#include "venus_hw.h"
#define VN_INFO_EXTENSION_MAX_NUMBER 1023
static uint32_t vn_info_wire_format_version(void) { return 1; }
static uint32_t vn_info_vk_xml_version(void) { return 4211031; }
static uint32_t vkr_extension_get_spec_version(const char *name) {
    return !strcmp(name, "VK_MESA_venus_protocol") ? 2 : 1;
}
static void vn_info_extension_mask_init(uint32_t *out) {
    for (unsigned i = 0; i < 32; i++) out[i] = 0x12345678U + i * 2;
}
static void vkr_log(const char *format, ...) { (void)format; }
''' + baseline + "\n" + function(source.read_text()) + r'''
int main(void) {
    struct virgl_renderer_capset_venus original, result, expected;
    const uint32_t flag = VIRGL_RENDERER_USE_GUEST_VRAM;
    const size_t size = sizeof(original);
    unsetenv("GB_VENUS_GUEST_VRAM_V1");
    for (unsigned i = 0; i < 2; i++) {
        uint32_t flags = i ? flag : 0;
        assert(baseline_capset(&original, flags) == size);
        assert(vkr_get_capset(NULL, flags) == size);
        assert(vkr_get_capset(&result, flags) == size);
        assert(!memcmp(&original, &result, size));
    }
    assert(baseline_capset(&original, flag) == size);
    expected = original; expected.use_guest_vram = 0;
    setenv("GB_VENUS_GUEST_VRAM_V1", "host", 1);
    assert(vkr_get_capset(NULL, flag) == size);
    assert(vkr_get_capset(&result, flag) == size);
    assert(!memcmp(&result, &expected, size));
    setenv("GB_VENUS_GUEST_VRAM_V1", "guest", 1);
    assert(vkr_get_capset(NULL, flag) == size);
    assert(vkr_get_capset(&result, flag) == size);
    assert(!memcmp(&result, &original, size));
    memset(&expected, 0, size);
    memset(&result, 0xcc, size);
    assert(vkr_get_capset(NULL, 0) == 0);
    assert(vkr_get_capset(&result, 0) == 0);
    assert(!memcmp(&result, &expected, size));
    const char *bad[] = {"", "automatic", "HOST", "../bad"};
    for (unsigned i = 0; i < sizeof(bad)/sizeof(*bad); i++) {
        setenv("GB_VENUS_GUEST_VRAM_V1", bad[i], 1);
        memset(&result, 0xcc, size);
        assert(vkr_get_capset(NULL, flag) == 0);
        assert(vkr_get_capset(&result, flag) == 0);
        assert(!memcmp(&result, &expected, size));
    }
    /* Explicit host selection must not stick after the environment is reset. */
    unsetenv("GB_VENUS_GUEST_VRAM_V1");
    assert(vkr_get_capset(&result, flag) == size);
    assert(!memcmp(&result, &original, size));
    return 0;
}
''')
    executable = base / "policy"
    compiled = subprocess.run(["cc", "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
                               "-I" + str(source.parent.parent), str(harness), "-o", str(executable)],
                              timeout=30, capture_output=True, text=True)
    assert compiled.returncode == 0, compiled.stderr
    subprocess.run([str(executable)], check=True, timeout=5,
                   preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_CORE, (0, 0)))
    print("9 capset policy cases passed; all unrelated capability bytes unchanged.")
