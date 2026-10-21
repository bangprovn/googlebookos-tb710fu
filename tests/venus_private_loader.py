#!/usr/bin/env python3
"""Compile the pinned actual loader against owned mock drivers; no GPU/device.

The mocks isolate loader selection, Android HAL bridging and cache lifetime.
They are not Vulkan implementations and cannot qualify a real driver.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import resource
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument("--baseline", type=Path)
parser.add_argument("--report", type=Path)
options = parser.parse_args()
provenance = json.loads((ROOT / "patches/tb710fu/virglrenderer/explicit-private-vulkan-loader.json").read_text())
source = ROOT / provenance["path"]
assert hashlib.sha256(source.read_bytes()).hexdigest() == provenance["result_sha256"]
sdk = ROOT / "artifacts/source/crosvm-android16qpr2-backend/external/mesa3d/include"
compiler = Path(shutil.which("cc")).resolve()


def run(args, **kwargs):
    def no_core():
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    result = subprocess.run(args, capture_output=True, text=True, timeout=30, preexec_fn=no_core, **kwargs)
    assert len(result.stdout) + len(result.stderr) < 65536
    return result


with tempfile.TemporaryDirectory(prefix="gb-venus-loader-") as directory:
    b = Path(directory)
    (b / "fallback").mkdir()
    (b / "vkr_common.h").write_text("""
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <vulkan/vulkan.h>
void vkr_log(const char *fmt, ...);
""")
    header = source.with_name("vkr_library.h").read_text()
    (b / "vkr_library.h").write_text(header.replace('"venus-protocol/vulkan.h"', '<vulkan/vulkan.h>'))
    (b / "loader.c").write_bytes(source.read_bytes())
    (b / "direct.c").write_text("""
#include <vulkan/vulkan.h>
#include <stdio.h>
#include <stdlib.h>
static void marker(void) {}
VKAPI_ATTR PFN_vkVoidFunction VKAPI_CALL
vkGetInstanceProcAddr(VkInstance instance, const char *name) {
    (void)instance; (void)name; return marker;
}
__attribute__((constructor)) static void opened(void) {
    const char *path = getenv("GB_VKR_FALLBACK_MARKER");
    if (path) {FILE *f = fopen(path, "w"); if (f) {fputs("opened", f); fclose(f);}}
}
""")
    (b / "hal.c").write_text("""
#include <hardware/hwvulkan.h>
#include <string.h>
static void marker(void) {}
static PFN_vkVoidFunction gipa(VkInstance instance, const char *name) {
    (void)instance; (void)name; return marker;
}
static hwvulkan_device_t device = {.GetInstanceProcAddr = gipa};
static int open_device(const hw_module_t *module, const char *id, hw_device_t **out) {
    if (!module || strcmp(id, HWVULKAN_DEVICE_0)) return -1;
    *out = &device.common; return 0;
}
static hw_module_methods_t methods = {.open = open_device};
hw_module_t HMI = {.id = "vulkan", .methods = &methods};
""")
    (b / "broken.c").write_text("int owned_fixture_symbol(void) {return 1;}\n")
    (b / "harness.c").write_text("""
#define _POSIX_C_SOURCE 200809L
#include "vkr_library.h"
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int explicit_failed, explicit_ready;
void vkr_log(const char *fmt, ...) {
    char message[512]; va_list args; va_start(args, fmt);
    vsnprintf(message, sizeof(message), fmt, args); va_end(args);
    if (strstr(message, "GB-VENUS-LOADER: explicit_driver_load_failed")) ++explicit_failed;
    if (strstr(message, "GB-VENUS-LOADER: explicit_driver_entrypoint_ready=true")) ++explicit_ready;
}
int main(int argc, char **argv) {
    assert(argc == 3);
    if (!strcmp(argv[1], "fallback")) unsetenv("ANDROID_EMU_VK_LOADER_PATH");
    else assert(setenv("ANDROID_EMU_VK_LOADER_PATH", argv[2], 1) == 0);
    struct vulkan_library library = {0};
    bool loaded = vkr_library_load(&library);
    if (!strcmp(argv[1], "missing")) {
        assert(!loaded && !library.handle && explicit_failed == 1); return 0;
    }
    if (!strcmp(argv[1], "broken")) {
        assert(!loaded && !library.handle && !library.GetInstanceProcAddr); return 0;
    }
    assert(loaded && library.handle && library.GetInstanceProcAddr);
    void *original = library.handle;
    PFN_vkGetInstanceProcAddr get = library.GetInstanceProcAddr;
    PFN_vkVoidFunction marker = get(VK_NULL_HANDLE, "owned-fixture"); assert(marker);
    if (strcmp(argv[1], "fallback")) assert(explicit_ready == 1);
    vkr_library_unload(&library);
    assert(!library.handle && !library.GetInstanceProcAddr);
    struct vulkan_library again = {0};
    assert(vkr_library_load(&again) && again.handle == original && again.GetInstanceProcAddr == get);
    assert(again.GetInstanceProcAddr(VK_NULL_HANDLE, "owned-fixture") == marker);
    vkr_library_unload(&again);
    return 0;
}
""")
    flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-I" + str(b), "-I" + str(sdk), "-I" + str(sdk / "android_stub")]
    for name in ["direct", "hal", "broken"]:
        r = run([str(compiler), *flags, "-fPIC", "-shared", str(b / (name + ".c")), "-o", str(b / (name + ".so"))])
        assert r.returncode == 0, r.stderr
    shutil.copyfile(b / "direct.so", b / "fallback/libvulkan.so.1")
    base = [str(compiler), *flags, "-DENABLE_VULKAN_DLOAD=1", str(b / "harness.c")]
    r = run([*base, str(b / "loader.c"), "-ldl", "-o", str(b / "check")])
    assert r.returncode == 0, r.stderr
    results = []
    for case, library in [("missing", b / "does-not-exist.so"), ("broken", b / "broken.so"), ("direct", b / "direct.so"), ("hal", b / "hal.so"), ("fallback", b / "unused")]:
        marker = b / (case + ".opened")
        environment = os.environ.copy()
        environment.update(LD_LIBRARY_PATH=str(b / "fallback"), GB_VKR_FALLBACK_MARKER=str(marker))
        r = run([str(b / "check"), case, str(library)], env=environment)
        assert r.returncode == 0, (case, r.stderr)
        assert marker.exists() == (case in ["direct", "fallback"]), case
        results.append(dict(case=case, passed=True))
    if options.baseline:
        assert hashlib.sha256(options.baseline.read_bytes()).hexdigest() == provenance["sha256"]
        (b / "baseline.c").write_bytes(options.baseline.read_bytes())
        r = run([*base, str(b / "baseline.c"), "-ldl", "-o", str(b / "check-baseline")])
        assert r.returncode == 0, r.stderr
        marker = b / "baseline.opened"
        environment = os.environ.copy()
        environment.update(LD_LIBRARY_PATH=str(b / "fallback"), GB_VKR_FALLBACK_MARKER=str(marker))
        r = run([str(b / "check-baseline"), "missing", str(b / "does-not-exist.so")], env=environment)
        assert r.returncode != 0 and marker.exists(), "baseline must expose the fallback regression"
    report = dict(schema_version=1, status="passed", source_sha256=provenance["result_sha256"], compiler_sha256=hashlib.sha256(compiler.read_bytes()).hexdigest(), compiler_version=run([str(compiler), "--version"]).stdout.splitlines()[0], cases=results, baseline_failure_reproduced=options.baseline is not None, android_namespace_verified=False, guest_vulkan_verified=False)
    if options.report:
        with options.report.open("x") as output:
            json.dump(report, output, indent=2)
            output.write("\n")
    print("PASS: actual loader refuses bad explicit drivers, bridges Android HMI, retains cached lifetime and preserves unselected fallback")
