#!/usr/bin/env python3
"""Exercise the actual native-driver callback, including concurrent log bounds."""
from pathlib import Path
import hashlib
import json
import resource
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
metadata = root / "patches/tb710fu/virglrenderer/bounded-native-allocation-diagnostics.json"
manifest = json.loads(metadata.read_text())
patch = metadata.with_suffix(".patch")
assert hashlib.sha256(patch.read_bytes()).hexdigest() == manifest["patch_sha256"]
with tempfile.TemporaryDirectory(prefix="gb-native-allocation-") as temporary:
    base = Path(temporary)
    for entry in manifest["files"]:
        source = root / entry["path"]
        assert hashlib.sha256(source.read_bytes()).hexdigest() == entry["result_sha256"]
        dest = base / "src/venus" / source.name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(source.read_bytes())
    subprocess.run(["patch", "--reverse", "--batch", "--fuzz=0", "-p1", "-d", str(base),
                    "-i", str(patch)], check=True, timeout=10, capture_output=True)
    for entry in manifest["files"]:
        original = base / "src/venus" / Path(entry["path"]).name
        assert hashlib.sha256(original.read_bytes()).hexdigest() == entry["sha256"]
    source = (root / manifest["files"][0]["path"]).read_text()
    start = source.index("static VkBool32\nvkr_allocation_callback(")
    pos = source.index("{", start)
    depth = 0
    for end in range(pos, len(source)):
        if source[end] == "{":
            depth += 1
        elif source[end] == "}":
            depth -= 1
            if not depth:
                break
    callback = source[start:end + 1]
    harness = base / "callback.c"
    harness.write_text(r'''
#include <assert.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vulkan/vulkan.h>
#define UNUSED __attribute__((unused))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
static unsigned count, imports, infos;
static int unknown;
static void vkr_log(const char *format, ...) {
    assert(!strcmp(format, "GB-VENUS-ALLOC: driver_operation=%s errno_class=%s"));
    char message[256]; va_list args; va_start(args, format);
    int n = vsnprintf(message, sizeof(message), format, args); va_end(args);
    assert(n > 0 && n < 128 && !strstr(message, "SECRET") && !strstr(message, "%"));
    if (unknown) {
        assert(!strcmp(message, "GB-VENUS-ALLOC: driver_operation=import_dmabuf errno_class=unclassified"));
    } else if (!strcmp(message, "GB-VENUS-ALLOC: driver_operation=import_dmabuf errno_class=invalid_argument")) {
        __atomic_fetch_add(&imports, 1, __ATOMIC_RELAXED);
    } else {
        assert(!strcmp(message, "GB-VENUS-ALLOC: driver_operation=get_dmabuf_info errno_class=permission_denied"));
        __atomic_fetch_add(&infos, 1, __ATOMIC_RELAXED);
    }
    __atomic_fetch_add(&count, 1, __ATOMIC_RELAXED);
}
''' + callback + r'''
static void submit(const char *message) {
    VkDebugUtilsMessengerCallbackDataEXT data = {
        .sType = VK_STRUCTURE_TYPE_DEBUG_UTILS_MESSENGER_CALLBACK_DATA_EXT,
        .pMessage = message, .pMessageIdName = "SECRET_APPLICATION_NAME"};
    assert(vkr_allocation_callback(0, 0, &data, NULL) == VK_FALSE);
}
static void *worker(void *arg) {
    (void)arg;
    for (unsigned i = 0; i < 2048; i++) {
        submit("Failed to import dma-buf (Invalid argument)\n (VK_ERROR_OUT_OF_DEVICE_MEMORY)");
        submit("Failed to get dma-buf info (Permission denied)\n (VK_ERROR_OUT_OF_DEVICE_MEMORY)");
    }
    return NULL;
}
int main(int argc, char **argv) {
    (void)argv;
    assert(vkr_allocation_callback(0, 0, NULL, NULL) == VK_FALSE);
    submit(NULL); submit(""); submit("SECRET_ARBITRARY_MESSAGE");
    submit("Failed to import dma-buf SECRET_NEAR_MISS");
    submit("Failed to get dma-buf info SECRET_NEAR_MISS");
    submit("prefix: Failed to import dma-buf (Invalid argument)");
    assert(count == 0);
    if (argc == 2) {
        unknown = 1;
        submit("Failed to import dma-buf (SECRET_UNKNOWN_TEXT %s %n)");
        submit("Failed to import dma-buf (Invalid argument)");
        assert(count == 1);
    } else {
        pthread_t threads[16];
        for (unsigned i = 0; i < ARRAY_SIZE(threads); i++)
            assert(pthread_create(&threads[i], NULL, worker, NULL) == 0);
        for (unsigned i = 0; i < ARRAY_SIZE(threads); i++)
            assert(pthread_join(threads[i], NULL) == 0);
        assert(count == 2 && imports == 1 && infos == 1);
    }
    return 0;
}
''')
    executable = base / "callback"
    subprocess.run(["cc", "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-pthread",
                    str(harness), "-o", str(executable)], check=True, timeout=30)
    for args in [[], ["unknown"]]:
        subprocess.run([str(executable), *args], check=True, timeout=5,
                       preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_CORE, (0, 0)))
    print("Callback filters, constant output and concurrent per-operation bounds passed.")
