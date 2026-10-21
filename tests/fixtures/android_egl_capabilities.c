/* SPDX-License-Identifier: Apache-2.0
 * Default Android EGL/GLES advertisements in this process only. No images,
 * DMA-BUFs, owner surfaces, frame capture, global driver changes or VM access.
 */
#define _POSIX_C_SOURCE 200809L
#include <EGL/egl.h>
#include <GLES2/gl2.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

static void string(const char *s) {
    putchar('"');
    if (s) for (size_t i = 0; i < 256 && s[i]; ++i) {
        unsigned char c = (unsigned char)s[i];
        if (c == '"' || c == '\\') printf("\\%c", c);
        else if (c < 32 || c >= 127) printf("\\u%04x", c);
        else putchar(c);
    }
    putchar('"');
}
static bool has(const char *all, const char *needle) {
    if (!all) return false;
    size_t n = strlen(needle), total = strnlen(all, 131073);
    if (total > 131072) return false;
    for (const char *p = all; *p;) {
        const char *end = strchr(p, ' ');
        size_t length = end ? (size_t)(end - p) : strlen(p);
        if (length == n && !memcmp(p, needle, n)) return true;
        if (!end) break;
        p = end + 1;
    }
    return false;
}
static int failure(const char *stage, unsigned code) {
    printf("{\"schema_version\":1,\"status\":\"failed\",\"stage\":"); string(stage);
    printf(",\"code\":%u,\"memory_import_verified\":false,\"original_vmm_namespace_verified\":false}\n", code);
    return 1;
}
#define EGL_FN(name, type) type name = (type)dlsym(egl_lib, #name); if (!name) return failure("entrypoint_" #name, 0)

int main(int argc, char **argv) {
    if (argc != 2 || strcmp(argv[1], "--probe")) return failure("explicit_probe_required", 0);
    struct rlimit core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &core)) return failure("core_limit", 0);
    alarm(15);
#ifdef __ANDROID__
    void *egl_lib = dlopen("libEGL.so", RTLD_NOW | RTLD_LOCAL);
    void *gles_lib = dlopen("libGLESv2.so", RTLD_NOW | RTLD_LOCAL);
#else
    void *egl_lib = dlopen("libEGL.so.1", RTLD_NOW | RTLD_LOCAL);
    void *gles_lib = dlopen("libGLESv2.so.2", RTLD_NOW | RTLD_LOCAL);
#endif
    if (!egl_lib || !gles_lib) return failure("load_system_egl_gles", 0);
    EGL_FN(eglGetDisplay, PFNEGLGETDISPLAYPROC);
    EGL_FN(eglInitialize, PFNEGLINITIALIZEPROC);
    EGL_FN(eglGetError, PFNEGLGETERRORPROC);
    EGL_FN(eglQueryString, PFNEGLQUERYSTRINGPROC);
    EGL_FN(eglBindAPI, PFNEGLBINDAPIPROC);
    EGL_FN(eglChooseConfig, PFNEGLCHOOSECONFIGPROC);
    EGL_FN(eglCreateContext, PFNEGLCREATECONTEXTPROC);
    EGL_FN(eglCreatePbufferSurface, PFNEGLCREATEPBUFFERSURFACEPROC);
    EGL_FN(eglMakeCurrent, PFNEGLMAKECURRENTPROC);
    EGL_FN(eglDestroyContext, PFNEGLDESTROYCONTEXTPROC);
    EGL_FN(eglDestroySurface, PFNEGLDESTROYSURFACEPROC);
    EGL_FN(eglTerminate, PFNEGLTERMINATEPROC);
    EGL_FN(eglGetProcAddress, PFNEGLGETPROCADDRESSPROC);
    typedef const GLubyte *(*get_string_type)(GLenum);
    get_string_type glGetString = (get_string_type)dlsym(gles_lib, "glGetString");
    if (!glGetString) return failure("glGetString", 0);
    EGLDisplay display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
    EGLint major = 0, minor = 0;
    if (!display || !eglInitialize(display, &major, &minor)) return failure("egl_initialize_default_display", eglGetError());
    EGLConfig config = NULL;
    EGLint count = 0;
    const EGLint attrs[] = {EGL_SURFACE_TYPE, EGL_PBUFFER_BIT, EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT,
        EGL_RED_SIZE, 8, EGL_GREEN_SIZE, 8, EGL_BLUE_SIZE, 8, EGL_ALPHA_SIZE, 8, EGL_NONE};
    const EGLint context_attrs[] = {EGL_CONTEXT_CLIENT_VERSION, 2, EGL_NONE};
    const EGLint surface_attrs[] = {EGL_WIDTH, 1, EGL_HEIGHT, 1, EGL_NONE};
    EGLContext context = EGL_NO_CONTEXT;
    EGLSurface surface = EGL_NO_SURFACE;
    int code = 1;
    if (!eglBindAPI(EGL_OPENGL_ES_API) || !eglChooseConfig(display, attrs, &config, 1, &count) || count != 1) {
        code = failure("egl_rgba8_config", eglGetError()); goto cleanup;
    }
    context = eglCreateContext(display, config, EGL_NO_CONTEXT, context_attrs);
    surface = eglCreatePbufferSurface(display, config, surface_attrs);
    if (!context || !surface || !eglMakeCurrent(display, surface, surface, context)) {
        code = failure("egl_context", eglGetError()); goto cleanup;
    }
    const char *extensions = eglQueryString(display, EGL_EXTENSIONS);
    const char *gl_extensions = (const char *)glGetString(GL_EXTENSIONS);
    printf("{\"schema_version\":1,\"status\":\"host_egl_capability_advertisements\",\"uid\":%u,\"egl_vendor\":", (unsigned)getuid());
    string(eglQueryString(display, EGL_VENDOR)); printf(",\"egl_version\":"); string(eglQueryString(display, EGL_VERSION));
    printf(",\"gles_vendor\":"); string((const char *)glGetString(GL_VENDOR));
    printf(",\"gles_renderer\":"); string((const char *)glGetString(GL_RENDERER));
    printf(",\"gles_version\":"); string((const char *)glGetString(GL_VERSION));
    const char *egl_names[] = {"EGL_EXT_image_dma_buf_import", "EGL_EXT_image_dma_buf_import_modifiers",
        "EGL_ANDROID_image_native_buffer", "EGL_ANDROID_get_native_client_buffer", "EGL_ANDROID_native_fence_sync",
        "EGL_KHR_fence_sync", "EGL_KHR_surfaceless_context", "EGL_KHR_gl_texture_2D_image"};
    printf(",\"egl_extensions\":{");
    for (size_t i = 0; i < sizeof(egl_names)/sizeof(*egl_names); ++i) {
        if (i) putchar(','); string(egl_names[i]); printf(":%s", has(extensions, egl_names[i]) ? "true" : "false");
    }
    const char *gl_names[] = {"GL_OES_EGL_image", "GL_EXT_EGL_image_storage", "GL_EXT_memory_object",
        "GL_EXT_memory_object_fd", "GL_EXT_semaphore", "GL_EXT_semaphore_fd"};
    printf("},\"gles_extensions\":{");
    for (size_t i = 0; i < sizeof(gl_names)/sizeof(*gl_names); ++i) {
        if (i) putchar(','); string(gl_names[i]); printf(":%s", has(gl_extensions, gl_names[i]) ? "true" : "false");
    }
    printf("},\"egl_create_image_entrypoint\":%s,\"egl_native_client_buffer_entrypoint\":%s,"
           "\"memory_import_verified\":false,\"gpu_rendering_verified\":false,"
           "\"original_vmm_namespace_verified\":false,\"owner_content_read\":false,\"full_port_verified\":false}\n",
           eglGetProcAddress("eglCreateImageKHR") ? "true" : "false",
           eglGetProcAddress("eglGetNativeClientBufferANDROID") ? "true" : "false");
    code = 0;
cleanup:
    eglMakeCurrent(display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
    if (surface) eglDestroySurface(display, surface);
    if (context) eglDestroyContext(display, context);
    eglTerminate(display); dlclose(gles_lib); dlclose(egl_lib);
    return code;
}
