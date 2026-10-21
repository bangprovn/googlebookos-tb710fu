#!/usr/bin/env python3
"""Bounded EGL/GLES2 shader draw/readback, with no fixture output files or network requests.

A pass proves the reported GL path rendered the fixture. It does not prove
physical GPU acceleration, Android scanout, Vulkan or guest desktop startup.
"""
import argparse
import ctypes as C
import ctypes.util
import json
import os
import sys


class ProbeError(Exception):
    pass


def function(lib, name, result, *arguments):
    fn = getattr(lib, name)
    fn.restype = result
    fn.argtypes = list(arguments)
    return fn


def probe(frames):
    # Only this process: do not populate the user's Mesa shader cache.
    os.environ["MESA_SHADER_CACHE_DISABLE"] = "true"
    egl_name = ctypes.util.find_library("EGL")
    gl_name = ctypes.util.find_library("GLESv2")
    if not egl_name or not gl_name:
        raise ProbeError("EGL and GLESv2 libraries are required")
    egl, gl = C.CDLL(egl_name), C.CDLL(gl_name)
    ptr, integer, unsigned = C.c_void_p, C.c_int, C.c_uint
    get_proc = function(egl, "eglGetProcAddress", ptr, C.c_char_p)
    initialize = function(egl, "eglInitialize", unsigned, ptr, C.POINTER(integer), C.POINTER(integer))
    choose = function(egl, "eglChooseConfig", unsigned, ptr, C.POINTER(integer), C.POINTER(ptr), integer, C.POINTER(integer))
    bind = function(egl, "eglBindAPI", unsigned, unsigned)
    create_context = function(egl, "eglCreateContext", ptr, ptr, ptr, ptr, C.POINTER(integer))
    create_surface = function(egl, "eglCreatePbufferSurface", ptr, ptr, ptr, C.POINTER(integer))
    make_current = function(egl, "eglMakeCurrent", unsigned, ptr, ptr, ptr, ptr)
    destroy_context = function(egl, "eglDestroyContext", unsigned, ptr, ptr)
    destroy_surface = function(egl, "eglDestroySurface", unsigned, ptr, ptr)
    terminate = function(egl, "eglTerminate", unsigned, ptr)
    egl_error = function(egl, "eglGetError", integer)
    get_string = function(gl, "glGetString", C.c_char_p, unsigned)
    gl_error = function(gl, "glGetError", unsigned)
    create_shader = function(gl, "glCreateShader", unsigned, unsigned)
    shader_source = function(gl, "glShaderSource", None, unsigned, integer, C.POINTER(C.c_char_p), C.POINTER(integer))
    compile_shader = function(gl, "glCompileShader", None, unsigned)
    shader_status = function(gl, "glGetShaderiv", None, unsigned, unsigned, C.POINTER(integer))
    delete_shader = function(gl, "glDeleteShader", None, unsigned)
    create_program = function(gl, "glCreateProgram", unsigned)
    attach = function(gl, "glAttachShader", None, unsigned, unsigned)
    link = function(gl, "glLinkProgram", None, unsigned)
    program_status = function(gl, "glGetProgramiv", None, unsigned, unsigned, C.POINTER(integer))
    delete_program = function(gl, "glDeleteProgram", None, unsigned)
    use_program = function(gl, "glUseProgram", None, unsigned)
    attrib_location = function(gl, "glGetAttribLocation", integer, unsigned, C.c_char_p)
    uniform_location = function(gl, "glGetUniformLocation", integer, unsigned, C.c_char_p)
    uniform = function(gl, "glUniform4f", None, integer, C.c_float, C.c_float, C.c_float, C.c_float)
    enable = function(gl, "glEnableVertexAttribArray", None, unsigned)
    attrib = function(gl, "glVertexAttribPointer", None, unsigned, integer, unsigned, C.c_ubyte, integer, ptr)
    gen_buffers = function(gl, "glGenBuffers", None, integer, C.POINTER(unsigned))
    bind_buffer = function(gl, "glBindBuffer", None, unsigned, unsigned)
    buffer_data = function(gl, "glBufferData", None, unsigned, C.c_ssize_t, ptr, unsigned)
    delete_buffers = function(gl, "glDeleteBuffers", None, integer, C.POINTER(unsigned))
    viewport = function(gl, "glViewport", None, integer, integer, integer, integer)
    draw = function(gl, "glDrawArrays", None, unsigned, integer, integer)
    finish = function(gl, "glFinish", None)
    read_pixels = function(gl, "glReadPixels", None, integer, integer, integer, integer, unsigned, unsigned, ptr)
    address = get_proc(b"eglGetPlatformDisplayEXT")
    if not address:
        raise ProbeError("surfaceless platform-display extension unavailable")
    get_display = C.CFUNCTYPE(ptr, unsigned, ptr, C.POINTER(integer))(address)
    display = get_display(0x31DD, None, None)  # EGL_PLATFORM_SURFACELESS_MESA
    if not display:
        raise ProbeError("surfaceless EGL display unavailable")
    context = surface = None
    shaders, program, buffer = [], 0, unsigned(0)
    ready = False

    def check(ok, step):
        if not ok:
            raise ProbeError(step + ": EGL error " + hex(egl_error()))

    try:
        major, minor = integer(), integer()
        check(initialize(display, C.byref(major), C.byref(minor)), "initialize")
        ready = True
        check(bind(0x30A0), "bind GLES API")
        attrs = (integer * 13)(0x3033, 1, 0x3040, 4, 0x3024, 8, 0x3023, 8, 0x3022, 8, 0x3021, 8, 0x3038)
        config, count = ptr(), integer()
        check(choose(display, attrs, C.byref(config), 1, C.byref(count)) and count.value == 1, "choose RGBA8 pbuffer config")
        context_attrs = (integer * 3)(0x3098, 2, 0x3038)
        context = create_context(display, config, None, context_attrs)
        check(context, "create GLES2 context")
        surface_attrs = (integer * 5)(0x3057, 16, 0x3056, 16, 0x3038)
        surface = create_surface(display, config, surface_attrs)
        check(surface, "create 16x16 pbuffer")
        check(make_current(display, surface, surface, context), "make current")
        strings = {}
        for name, token in [("vendor", 0x1F00), ("renderer", 0x1F01), ("version", 0x1F02)]:
            text = get_string(token)
            if not text or len(text) > 4096:
                raise ProbeError("missing or overlong GL identity")
            strings[name] = text[:256].decode("utf-8", "replace")
        for kind, code in [(0x8B31, b"attribute vec2 a_pos; void main(){gl_Position=vec4(a_pos,0.,1.);}"),
                           (0x8B30, b"precision mediump float; uniform vec4 color; void main(){gl_FragColor=color;}")]:
            shader = create_shader(kind)
            if not shader:
                raise ProbeError("create shader failed")
            shaders.append(shader)
            text = C.c_char_p(code)
            shader_source(shader, 1, C.byref(text), None)
            compile_shader(shader)
            status = integer()
            shader_status(shader, 0x8B81, C.byref(status))
            if not status.value:
                raise ProbeError("fixture shader compilation failed")
        program = create_program()
        if not program:
            raise ProbeError("create program failed")
        for shader in shaders:
            attach(program, shader)
        link(program)
        status = integer()
        program_status(program, 0x8B82, C.byref(status))
        if not status.value:
            raise ProbeError("fixture program link failed")
        use_program(program)
        location = attrib_location(program, b"a_pos")
        color = uniform_location(program, b"color")
        if location < 0 or color < 0:
            raise ProbeError("fixture shader inputs unavailable")
        vertices = (C.c_float * 6)(-1, -1, 3, -1, -1, 3)
        gen_buffers(1, C.byref(buffer))
        if not buffer.value:
            raise ProbeError("create vertex buffer failed")
        bind_buffer(0x8892, buffer.value)
        buffer_data(0x8892, C.sizeof(vertices), C.cast(vertices, ptr), 0x88E4)
        enable(location)
        attrib(location, 2, 0x1406, 0, 0, None)
        viewport(0, 0, 16, 16)
        pixels = (C.c_ubyte * (16 * 16 * 4))()
        colors = [(1, 0, 0, 1), (0, 1, 0, 1), (0, 0, 1, 1), (.25, .5, .75, 1)]
        maximum_error = 0
        for frame in range(frames):
            rgba = colors[frame % len(colors)]
            uniform(color, *rgba)
            draw(4, 0, 3)
            finish()
            read_pixels(0, 0, 16, 16, 0x1908, 0x1401, C.cast(pixels, ptr))
            error = gl_error()
            if error:
                raise ProbeError("GL draw/readback error " + hex(error))
            expected = tuple(round(value * 255) for value in rgba)
            for i, value in enumerate(pixels):
                delta = abs(value - expected[i % 4])
                maximum_error = max(maximum_error, delta)
                if delta > 2:
                    raise ProbeError("shader pixel mismatch at frame " + str(frame))
        renderer = strings["renderer"].lower()
        return dict(state="compatible", scope="GLES2 surfaceless shader draw and RGBA8 readback only",
                    gl=strings, egl_version=f"{major.value}.{minor.value}", frames_verified=frames,
                    pixels_per_frame=256, max_channel_error=maximum_error,
                    renderer_reports_software=any(x in renderer for x in ["llvmpipe", "softpipe", "swiftshader", "software rasterizer"]),
                    physical_gpu_acceleration_verified=False, android_scanout_verified=False,
                    guest_desktop_verified=False, fixture_artifact_files_written=False,
                    mesa_shader_cache_disabled=True)
    finally:
        if context and surface:
            if buffer.value:
                delete_buffers(1, C.byref(buffer))
            if program:
                delete_program(program)
            for shader in shaders:
                delete_shader(shader)
            make_current(display, None, None, None)
        if surface:
            destroy_surface(display, surface)
        if context:
            destroy_context(display, context)
        if ready:
            terminate(display)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--frames", type=int, default=16)
    args = parser.parse_args()
    if not 1 <= args.frames <= 256:
        parser.error("--frames must be in 1..256")
    try:
        result = probe(args.frames)
    except (ProbeError, OSError, AttributeError) as error:
        print(json.dumps(dict(state="unknown", scope="GLES2 draw/readback probe", error=str(error)[:300],
                              physical_gpu_acceleration_verified=False, android_scanout_verified=False)))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
