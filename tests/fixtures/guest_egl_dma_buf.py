#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Import ONLY an inherited owned diagnostic buffer, then check its GLES pixels.

No camera/screen/owner data is captured. The producer passes a 4096-byte allocation
filled by Vulkan with 0xffc08040. This proves one linear buffer case, not WSI.
"""
import ctypes as C
import json
import os
import signal
import socket
import struct
import sys
from terminal_guest_gles import function, ProbeError


class ControlFailure(ProbeError):
    def __init__(self, stage, diagnostic):
        super().__init__(stage)
        self.diagnostic = diagnostic


class PixelMismatch(ProbeError):
    def __init__(self, phase, expected, pixels, direct_match, direct_error):
        super().__init__('imported_pattern_mismatch_phase_%d' % phase)
        self.diagnostic = dict(phase=phase, expected_rgba=expected,
                               observed_first_rgba=list(pixels[:4]),
                               differing_channels=sum(v != expected[i % 4] for i, v in enumerate(pixels)),
                               maximum_channel_error=max(abs(v - expected[i % 4]) for i, v in enumerate(pixels)),
                               independent_cpu_texture_shader_control_verified=True,
                               direct_imported_fbo_matches=direct_match,
                               direct_imported_fbo_gl_error=direct_error,
                               owner_content_read=False)


def parse_layout(raw):
    if not isinstance(raw, str) or len(raw) > 4096:
        raise ProbeError('image_layout_budget')
    value = json.loads(raw)
    fields = {'width', 'height', 'stride', 'offset', 'modifier', 'allocation_bytes', 'rgba'}
    extended = type(value) is dict and 'schema_version' in value
    expected_fields = fields | {'schema_version', 'fourcc', 'source_alpha'} if extended else fields
    if type(value) is not dict or set(value) != expected_fields:
        raise ProbeError('image_layout_fields')
    if extended:
        if (type(value['schema_version']) is not int or value['schema_version'] != 2
                or type(value['fourcc']) is not int
                or value['fourcc'] not in [0x34324241, 0x34325241, 0x34324258, 0x34325258]):
            raise ProbeError('image_layout_format_profile')
        opaque = value['fourcc'] in [0x34324258, 0x34325258]
        alphas = value['source_alpha']
        if (type(alphas) is not list or len(alphas) != 3
                or any(type(v) is not int for v in alphas)
                or alphas != ([0, 73, 127] if opaque else [255, 255, 255])
                or value['rgba'] != [19, 67, 139, 255]):
            raise ProbeError('image_layout_alpha_profile')
    if any(type(value[k]) is not int for k in fields - {'rgba'}):
        raise ProbeError('image_layout_integer_types')
    width, height, stride = (value[k] for k in ['width', 'height', 'stride'])
    offset, size = value['offset'], value['allocation_bytes']
    rgba = value['rgba']
    large_xrgb = extended and value['fourcc'] == 0x34325258 and (width, height) == (640, 480)
    extent_allowed = (1 <= width <= 128 and 1 <= height <= 128) or large_xrgb
    if not (extent_allowed and width * 4 <= stride <= 65536 and stride % 4 == 0
            and 0 <= offset < size <= (4 if large_xrgb else 1) * 1024 * 1024 and offset + (height - 1) * stride + width * 4 <= size
            and value['modifier'] == 0 and type(rgba) is list and len(rgba) == 4
            and all(type(v) is int and 0 <= v <= 255 for v in rgba)):
        raise ProbeError('image_layout_bounds_or_modifier')
    return value


def consume(fd, layout=None, roundtrip_fd=None):
    os.fstat(fd)
    explicit = layout is not None
    protocol = os.environ.get('GB_EGL_LINEAR_IMPORT_V1', 'explicit')
    if protocol not in ['explicit', 'implicit', 'producer_explicit']:
        raise ProbeError('unknown_linear_import_protocol')
    if protocol == 'producer_explicit' and (not explicit or roundtrip_fd is None):
        raise ProbeError('producer_explicit_requires_owned_layout_and_roundtrip')
    sampling = os.environ.get('GB_EGL_DMA_BUF_SAMPLE_V1', 'readback')
    if sampling not in ['readback', 'shader']:
        raise ProbeError('unknown_dma_buf_sampling_protocol')
    sample_target = os.environ.get('GB_EGL_DMA_BUF_SAMPLE_TARGET_V1', 'texture_fbo')
    if sample_target not in ['texture_fbo', 'pbuffer']:
        raise ProbeError('unknown_dma_buf_sampling_target')
    control_mode = os.environ.get('GB_EGL_DMA_BUF_CONTROL_V1')
    if control_mode not in [None, 'no_import', 'create_only', 'target_import'] or (control_mode is not None and sampling != 'shader'):
        raise ProbeError('invalid_image_control_mode')
    control_only = control_mode is not None
    create_external_image = control_mode != 'no_import'
    bind_external_texture = control_mode not in ['no_import', 'create_only']
    use_modifier_protocol = explicit and protocol in ['explicit', 'producer_explicit']
    modifier_query_count = None
    layout = layout or dict(width=16, height=16, stride=64, offset=0, modifier=0,
                            allocation_bytes=4096, rgba=[64, 128, 192, 255])
    width, height = layout['width'], layout['height']
    fourcc = layout.get('fourcc', 0x34324241)
    egl, gl = C.CDLL('libEGL.so.1'), C.CDLL('libGLESv2.so.2')
    ptr, integer, unsigned = C.c_void_p, C.c_int, C.c_uint
    proc = function(egl, 'eglGetProcAddress', ptr, C.c_char_p)
    def extension(name, result, *args):
        address = proc(name.encode())
        if not address:
            raise ProbeError('extension_unavailable_' + name)
        return C.CFUNCTYPE(result, *args)(address)
    get_display = extension('eglGetPlatformDisplayEXT', ptr, unsigned, ptr, C.POINTER(integer))
    initialize = function(egl, 'eglInitialize', unsigned, ptr, C.POINTER(integer), C.POINTER(integer))
    terminate = function(egl, 'eglTerminate', unsigned, ptr)
    choose = function(egl, 'eglChooseConfig', unsigned, ptr, C.POINTER(integer), C.POINTER(ptr), integer, C.POINTER(integer))
    bind = function(egl, 'eglBindAPI', unsigned, unsigned)
    context_create = function(egl, 'eglCreateContext', ptr, ptr, ptr, ptr, C.POINTER(integer))
    surface_create = function(egl, 'eglCreatePbufferSurface', ptr, ptr, ptr, C.POINTER(integer))
    current = function(egl, 'eglMakeCurrent', unsigned, ptr, ptr, ptr, ptr)
    context_destroy = function(egl, 'eglDestroyContext', unsigned, ptr, ptr)
    surface_destroy = function(egl, 'eglDestroySurface', unsigned, ptr, ptr)
    query = function(egl, 'eglQueryString', C.c_char_p, ptr, integer)
    string = function(gl, 'glGetString', C.c_char_p, unsigned)
    create_image = extension('eglCreateImageKHR', ptr, ptr, ptr, unsigned, ptr, C.POINTER(integer))
    destroy_image = extension('eglDestroyImageKHR', unsigned, ptr, ptr)
    target = extension('glEGLImageTargetTexture2DOES', None, unsigned, ptr)
    texture_gen = function(gl, 'glGenTextures', None, integer, C.POINTER(unsigned))
    texture_bind = function(gl, 'glBindTexture', None, unsigned, unsigned)
    texture_delete = function(gl, 'glDeleteTextures', None, integer, C.POINTER(unsigned))
    framebuffer_gen = function(gl, 'glGenFramebuffers', None, integer, C.POINTER(unsigned))
    framebuffer_bind = function(gl, 'glBindFramebuffer', None, unsigned, unsigned)
    framebuffer_delete = function(gl, 'glDeleteFramebuffers', None, integer, C.POINTER(unsigned))
    attach = function(gl, 'glFramebufferTexture2D', None, unsigned, unsigned, unsigned, unsigned, integer)
    complete = function(gl, 'glCheckFramebufferStatus', unsigned, unsigned)
    read = function(gl, 'glReadPixels', None, integer, integer, integer, integer, unsigned, unsigned, ptr)
    error = function(gl, 'glGetError', unsigned)
    egl_error = function(egl, 'eglGetError', integer)
    display = get_display(0x31DD, None, None)
    ready = False
    context = surface = image = None
    texture, framebuffer, control_texture = unsigned(0), unsigned(0), unsigned(0)
    sample_texture, sample_framebuffer = unsigned(0), unsigned(0)
    ipc = None
    shaders, program, solid_program, vertex_buffer = [], 0, 0, unsigned(0)
    delete_program = delete_shader = delete_buffer = None
    if roundtrip_fd is not None:
        if not explicit or layout['rgba'] != [19, 67, 139, 255]:
            raise ProbeError('reuse_layout_profile')
        ipc = socket.fromfd(roundtrip_fd, socket.AF_UNIX, socket.SOCK_SEQPACKET)
        if ipc.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_SEQPACKET or ipc.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) != socket.AF_UNIX:
            raise ProbeError('owned_seqpacket_required')
        pid, uid, _ = struct.unpack('3i', ipc.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if pid != os.getppid() or uid != os.getuid():
            raise ProbeError('producer_peer_identity')
    def require(ok, stage):
        if not ok:
            raise ProbeError(stage)
    try:
        major, minor = integer(), integer()
        require(display and initialize(display, C.byref(major), C.byref(minor)), 'egl_initialize')
        ready = True
        require(b'EGL_EXT_image_dma_buf_import' in (query(display, 0x3055) or b'').split(), 'dma_buf_import_extension')
        if use_modifier_protocol:
            require(b'EGL_EXT_image_dma_buf_import_modifiers' in (query(display, 0x3055) or b'').split(), 'modifier_import_extension')
            modifiers = extension('eglQueryDmaBufModifiersEXT', unsigned, ptr, integer, integer,
                                  C.POINTER(C.c_uint64), C.POINTER(unsigned), C.POINTER(integer))
            count = integer()
            values, external_only = (C.c_uint64 * 256)(), (unsigned * 256)()
            ok = modifiers(display, fourcc, 256, values, external_only, C.byref(count))
            require(ok and 0 <= count.value <= 256,
                    'egl_modifier_count_ok_%d_count_%d_error_%s' % (ok, count.value, hex(egl_error())))
            modifier_query_count = count.value
            if protocol == 'explicit':
                require(any(values[i] == layout['modifier'] and not external_only[i] for i in range(count.value)),
                        'egl_modifier_not_2d_renderable')
            # Diagnostic producer_explicit carries a queried LINEAR layout
            # from the pinned Vulkan producer and an authenticated peer IPC.
            # Attempt its exact attributes even if enumeration is incomplete;
            # eglCreateImage and every pixel/control check must still pass.
        require(bind(0x30A0), 'gles_api')
        attrs = (integer * 13)(0x3033, 1, 0x3040, 4, 0x3024, 8, 0x3023, 8, 0x3022, 8, 0x3021, 8, 0x3038)
        config, count = ptr(), integer()
        require(choose(display, attrs, C.byref(config), 1, C.byref(count)) and count.value == 1, 'rgba_config')
        context = context_create(display, config, None, (integer * 3)(0x3098, 2, 0x3038))
        surface = surface_create(display, config, (integer * 5)(0x3057, width, 0x3056, height, 0x3038))
        require(context and surface and current(display, surface, surface, context), 'gles_context')
        renderer = string(0x1F01)
        require(renderer and len(renderer) <= 256 and b'virgl' in renderer.lower() and b'Adreno' in renderer, 'virgl_adreno_required')
        # The validated producer carries the exact one-plane DRM format.
        values = [0x3057, width, 0x3056, height, 0x3271, fourcc, 0x3272, fd,
                  0x3273, layout['offset'], 0x3274, layout['stride']]
        if use_modifier_protocol:
            values += [0x3443, layout['modifier'] & 0xffffffff, 0x3444, layout['modifier'] >> 32]
        values += [0x3038]
        if create_external_image:
            image = create_image(display, None, 0x3270, None, (integer * len(values))(*values))
            require(image, 'egl_import_owned_dma_buf_' + hex(egl_error()) if not image else 'egl_import_owned_dma_buf')
        texture_gen(1, C.byref(texture)); texture_bind(0x0DE1, texture.value)
        if bind_external_texture:
            target(0x0DE1, image); require(error() == 0, 'gles_import_target')
        if sampling == 'readback':
            framebuffer_gen(1, C.byref(framebuffer)); framebuffer_bind(0x8D40, framebuffer.value)
            attach(0x8D40, 0x8CE0, 0x0DE1, texture.value, 0)
            require(complete(0x8D40) == 0x8CD5, 'imported_framebuffer_complete')
        if sampling == 'shader':
            # Sample the foreign image into the separate pbuffer, rather than
            # reading its attached FBO directly. This exercises compositor-like
            # texture consumption without reading any desktop/owner pixels.
            active = function(gl, 'glActiveTexture', None, unsigned)
            parameter = function(gl, 'glTexParameteri', None, unsigned, unsigned, integer)
            create_shader = function(gl, 'glCreateShader', unsigned, unsigned)
            source = function(gl, 'glShaderSource', None, unsigned, integer, C.POINTER(C.c_char_p), C.POINTER(integer))
            compile_shader = function(gl, 'glCompileShader', None, unsigned)
            shader_status = function(gl, 'glGetShaderiv', None, unsigned, unsigned, C.POINTER(integer))
            delete_shader = function(gl, 'glDeleteShader', None, unsigned)
            create_program = function(gl, 'glCreateProgram', unsigned)
            attach_shader = function(gl, 'glAttachShader', None, unsigned, unsigned)
            link = function(gl, 'glLinkProgram', None, unsigned)
            program_status = function(gl, 'glGetProgramiv', None, unsigned, unsigned, C.POINTER(integer))
            delete_program = function(gl, 'glDeleteProgram', None, unsigned)
            use_program = function(gl, 'glUseProgram', None, unsigned)
            attrib_location = function(gl, 'glGetAttribLocation', integer, unsigned, C.c_char_p)
            uniform_location = function(gl, 'glGetUniformLocation', integer, unsigned, C.c_char_p)
            uniform = function(gl, 'glUniform1i', None, integer, integer)
            gen_buffer = function(gl, 'glGenBuffers', None, integer, C.POINTER(unsigned))
            bind_buffer = function(gl, 'glBindBuffer', None, unsigned, unsigned)
            buffer_data = function(gl, 'glBufferData', None, unsigned, C.c_ssize_t, ptr, unsigned)
            delete_buffer = function(gl, 'glDeleteBuffers', None, integer, C.POINTER(unsigned))
            enable = function(gl, 'glEnableVertexAttribArray', None, unsigned)
            attrib = function(gl, 'glVertexAttribPointer', None, unsigned, integer, unsigned, C.c_ubyte, integer, ptr)
            viewport = function(gl, 'glViewport', None, integer, integer, integer, integer)
            clear_color = function(gl, 'glClearColor', None, C.c_float, C.c_float, C.c_float, C.c_float)
            clear = function(gl, 'glClear', None, unsigned)
            draw = function(gl, 'glDrawArrays', None, unsigned, integer, integer)
            finish = function(gl, 'glFinish', None)
            for kind, code in [(0x8B31, b'attribute vec2 a_pos; varying vec2 uv; void main(){gl_Position=vec4(a_pos,0.,1.);uv=a_pos*.5+.5;}'),
                               (0x8B30, b'precision mediump float; varying vec2 uv; uniform sampler2D image; void main(){gl_FragColor=texture2D(image,uv);}')]:
                shader = create_shader(kind); require(shader, 'sampler_shader_create'); shaders.append(shader)
                text = C.c_char_p(code); source(shader, 1, C.byref(text), None); compile_shader(shader)
                status = integer(); shader_status(shader, 0x8B81, C.byref(status)); require(status.value, 'sampler_shader_compile')
            program = create_program(); require(program, 'sampler_program_create')
            for shader in shaders: attach_shader(program, shader)
            link(program); status = integer(); program_status(program, 0x8B82, C.byref(status)); require(status.value, 'sampler_program_link')
            use_program(program)
            location, sampler = attrib_location(program, b'a_pos'), uniform_location(program, b'image')
            require(location >= 0 and sampler >= 0, 'sampler_inputs')
            uniform(sampler, 0); active(0x84C0); texture_bind(0x0DE1, texture.value)
            for key, value in [(0x2801, 0x2600), (0x2800, 0x2600), (0x2802, 0x812F), (0x2803, 0x812F)]:
                parameter(0x0DE1, key, value)
            vertices = (C.c_float * 6)(-1, -1, 3, -1, -1, 3)
            gen_buffer(1, C.byref(vertex_buffer)); require(vertex_buffer.value, 'sampler_vertex_buffer')
            bind_buffer(0x8892, vertex_buffer.value); buffer_data(0x8892, C.sizeof(vertices), C.cast(vertices, ptr), 0x88E4)
            enable(location); attrib(location, 2, 0x1406, 0, 0, None)
            framebuffer_bind(0x8D40, 0); viewport(0, 0, width, height)
            require(error() == 0, 'sampler_setup')
            # Independent positive control: distinct CPU-authored pixels use
            # the identical sampler, vertices and pbuffer. Never upload to the
            # imported texture or substitute these bytes for a GPU result.
            image_data = function(gl, 'glTexImage2D', None, unsigned, integer, integer,
                                  integer, integer, integer, unsigned, unsigned, ptr)
            if sample_target == 'texture_fbo':
                texture_gen(1, C.byref(sample_texture)); require(sample_texture.value, 'sampler_target_texture')
                texture_bind(0x0DE1, sample_texture.value)
                parameter(0x0DE1, 0x2801, 0x2600); parameter(0x0DE1, 0x2800, 0x2600)
                image_data(0x0DE1, 0, 0x1908, width, height, 0, 0x1908, 0x1401, None)
                framebuffer_gen(1, C.byref(sample_framebuffer)); framebuffer_bind(0x8D40, sample_framebuffer.value)
                attach(0x8D40, 0x8CE0, 0x0DE1, sample_texture.value, 0)
                require(complete(0x8D40) == 0x8CD5, 'sampler_target_framebuffer')
            texture_gen(1, C.byref(control_texture)); require(control_texture.value, 'control_texture_create')
            texture_bind(0x0DE1, control_texture.value)
            for key, value in [(0x2801, 0x2600), (0x2800, 0x2600), (0x2802, 0x812F), (0x2803, 0x812F)]:
                parameter(0x0DE1, key, value)
            # A solid draw uses the same geometry and destination, allowing a
            # failed texture control to be separated from a failed draw setup.
            solid_shader = create_shader(0x8B30); require(solid_shader, 'solid_control_shader'); shaders.append(solid_shader)
            text = C.c_char_p(b'precision mediump float; void main(){gl_FragColor=vec4(1.,0.,1.,1.);}')
            source(solid_shader, 1, C.byref(text), None); compile_shader(solid_shader)
            status = integer(); shader_status(solid_shader, 0x8B81, C.byref(status)); require(status.value, 'solid_control_compile')
            solid_program = create_program(); require(solid_program, 'solid_control_program')
            attach_shader(solid_program, shaders[0]); attach_shader(solid_program, solid_shader); link(solid_program)
            program_status(solid_program, 0x8B82, C.byref(status)); require(status.value, 'solid_control_link')
            use_program(solid_program); solid_location = attrib_location(solid_program, b'a_pos'); require(solid_location >= 0, 'solid_control_position')
            enable(solid_location); attrib(solid_location, 2, 0x1406, 0, 0, None)
            solid_pixels = (C.c_ubyte * (width * height * 4))()
            clear_color(0., 1., 0., 1.); clear(0x4000); draw(4, 0, 3); finish()
            read(0, 0, width, height, 0x1908, 0x1401, solid_pixels); solid_error = error()
            if solid_error or bytes(solid_pixels) != bytes([255, 0, 255, 255]) * (width * height):
                get_integer = function(gl, 'glGetIntegerv', None, unsigned, C.POINTER(integer))
                get_attrib = function(gl, 'glGetVertexAttribiv', None, unsigned, unsigned, C.POINTER(integer))
                state = {}
                for key, token, count in [('viewport', 0x0BA2, 4), ('program', 0x8B8D, 1),
                                          ('framebuffer', 0x8CA6, 1), ('array_buffer', 0x8894, 1),
                                          ('read_framebuffer', 0x8CAA, 1), ('draw_buffer', 0x8825, 1),
                                          ('read_buffer', 0x0C02, 1), ('color_write_mask', 0x0C23, 4),
                                          ('scissor_enabled', 0x0C11, 1), ('scissor_box', 0x0C10, 4),
                                          ('rasterizer_discard', 0x8C89, 1), ('cull_enabled', 0x0B44, 1)]:
                    values = (integer * count)(); get_integer(token, values); state[key] = list(values)
                for key, token in [('attribute_enabled', 0x8622), ('attribute_size', 0x8623),
                                   ('attribute_type', 0x8625), ('attribute_buffer', 0x889F)]:
                    value = integer(); get_attrib(solid_location, token, C.byref(value)); state[key] = value.value
                state['state_query_gl_error'] = error()
                map_buffer = function(gl, 'glMapBufferRange', ptr, unsigned, C.c_ssize_t, C.c_ssize_t, unsigned)
                unmap_buffer = function(gl, 'glUnmapBuffer', C.c_ubyte, unsigned)
                mapped = map_buffer(0x8892, 0, C.sizeof(vertices), 1)
                state['vertex_buffer_readback_equal'] = bool(mapped and C.string_at(mapped, C.sizeof(vertices)) == bytes(vertices))
                if mapped: state['vertex_buffer_unmapped'] = bool(unmap_buffer(0x8892))
                state['vertex_readback_gl_error'] = error()
                state.update(observed_first_rgba=list(solid_pixels[:4]), expected_rgba=[255, 0, 255, 255],
                             draw_gl_error=solid_error, expected_program=solid_program,
                             expected_framebuffer=sample_framebuffer.value, expected_vertex_buffer=vertex_buffer.value,
                             owner_content_read=False)
                raise ControlFailure('independent_solid_control', state)
            use_program(program); enable(location); attrib(location, 2, 0x1406, 0, 0, None)
            control_rgba = [227, 43, 151, 255]
            control = (C.c_ubyte * (width * height * 4)).from_buffer_copy(bytes(control_rgba) * (width * height))
            image_data(0x0DE1, 0, 0x1908, width, height, 0, 0x1908, 0x1401, control)
            clear_color(0., 0., 0., 0.); clear(0x4000); draw(4, 0, 3); finish()
            read(0, 0, width, height, 0x1908, 0x1401, control)
            control_error = error()
            if control_error or bytes(control) != bytes(control_rgba) * (width * height):
                raise ProbeError('independent_sampler_control_gl_%s_first_%s_max_%d' %
                                 (hex(control_error), '_'.join(str(v) for v in control[:4]),
                                  max(abs(v - control_rgba[i % 4]) for i, v in enumerate(control))))
            texture_bind(0x0DE1, texture.value)
            texture_delete(1, C.byref(control_texture)); control_texture.value = 0
        if control_only:
            return dict(schema_version=1, status='independent_gles_controls_verified',
                        renderer=renderer.decode(), solid_control_verified=True,
                        cpu_texture_control_verified=True, destination=sample_target,
                        external_image_import_attempted=create_external_image,
                        external_image_bound_to_texture=bind_external_texture,
                        control_mode=control_mode, dma_buf_verified=False,
                        presentation_verified=False, full_port_verified=False,
                        owner_content_read=False, intentional_exit_code=77)
        colors = [layout['rgba']] if ipc is None else [[19, 67, 139, 255], [203, 37, 91, 255], [47, 181, 113, 255]]
        pixels = (C.c_ubyte * (width * height * 4))()
        for phase, rgba in enumerate(colors):
            if ipc is not None:
                require(ipc.recv(1) == bytes([phase]), 'owned_phase_sequence')
            if sampling == 'shader':
                clear_color(0., 0., 0., 0.); clear(0x4000); draw(4, 0, 3); finish()
                require(error() == 0, 'sample_foreign_image_phase_%d' % phase)
            read(0, 0, width, height, 0x1908, 0x1401, pixels)
            require(error() == 0, 'read_imported_pixels')
            if bytes(pixels) != bytes(rgba) * (width * height):
                if sampling == 'shader':
                    direct = (C.c_ubyte * (width * height * 4))()
                    framebuffer_gen(1, C.byref(framebuffer)); framebuffer_bind(0x8D40, framebuffer.value)
                    attach(0x8D40, 0x8CE0, 0x0DE1, texture.value, 0)
                    require(complete(0x8D40) == 0x8CD5, 'diagnostic_imported_framebuffer')
                    read(0, 0, width, height, 0x1908, 0x1401, direct)
                    raise PixelMismatch(phase, rgba, pixels,
                                        bytes(direct) == bytes(rgba) * (width * height), error())
                raise ProbeError('imported_pattern_mismatch_phase_%d' % phase)
            if ipc is not None:
                require(ipc.send(bytes([0x80 | phase])) == 1, 'owned_phase_ack')
        return dict(schema_version=1, status='owned_dma_buf_pixels_verified',
                    pixels_verified=width * height * len(colors), rounds_verified=len(colors),
                    single_egl_image_reused=ipc is not None, renderer=renderer.decode(),
                    texture_sampling_verified=sampling == 'shader',
                    independent_sampler_control_verified=sampling == 'shader',
                    independent_solid_control_verified=sampling == 'shader',
                    sampling_protocol=sampling, explicit_gles_finish=sampling == 'shader',
                    sampler_destination=sample_target if sampling == 'shader' else None,
                    explicit_image_layout=explicit,
                    modifier_protocol=('producer_explicit_linear' if protocol == 'producer_explicit' else
                                       'explicit' if use_modifier_protocol else 'implicit_linear'),
                    modifier_query_count=modifier_query_count,
                    plane_layout=layout if explicit else None,
                    owner_content_read=False, presentation_verified=False)
    finally:
        if context:
            if vertex_buffer.value and delete_buffer: delete_buffer(1, C.byref(vertex_buffer))
            if solid_program and delete_program: delete_program(solid_program)
            if program and delete_program: delete_program(program)
            if delete_shader:
                for shader in shaders: delete_shader(shader)
            if sample_framebuffer.value: framebuffer_delete(1, C.byref(sample_framebuffer))
            if sample_texture.value: texture_delete(1, C.byref(sample_texture))
            if framebuffer.value: framebuffer_delete(1, C.byref(framebuffer))
            if control_texture.value: texture_delete(1, C.byref(control_texture))
            if texture.value: texture_delete(1, C.byref(texture))
            if image: destroy_image(display, image)
            current(display, None, None, None)
        if surface: surface_destroy(display, surface)
        if context: context_destroy(display, context)
        if ready: terminate(display)
        os.close(fd)
        if ipc is not None: ipc.close()
        if roundtrip_fd is not None: os.close(roundtrip_fd)


if __name__ == '__main__':
    signal.alarm(15)
    try:
        if len(sys.argv) not in [3, 5, 7] or sys.argv[1] != '--owned-dma-buf-fd' or not sys.argv[2].isdigit() or not 3 <= int(sys.argv[2]) <= 4096:
            raise ProbeError('explicit_owned_buffer_fd_required')
        layout = None
        if len(sys.argv) >= 5:
            if sys.argv[3] != '--image-layout-json' or len(sys.argv[4]) > 1024:
                raise ProbeError('explicit_image_layout_required')
            layout = parse_layout(sys.argv[4])
        channel = None
        if len(sys.argv) == 7:
            if sys.argv[5] != '--roundtrip-fd' or not sys.argv[6].isdigit() or not 3 <= int(sys.argv[6]) <= 4096 or int(sys.argv[6]) == int(sys.argv[2]):
                raise ProbeError('explicit_owned_roundtrip_fd_required')
            channel = int(sys.argv[6])
        result = consume(int(sys.argv[2]), layout, channel)
        print(json.dumps(result), flush=True)
        if result.get('intentional_exit_code') == 77: sys.exit(77)
    except Exception as exc:
        result = dict(schema_version=1, status='failed',
                      stage=str(exc) if isinstance(exc, ProbeError) else type(exc).__name__,
                      dma_buf_verified=False)
        if isinstance(exc, PixelMismatch): result['pixel_diagnostic'] = exc.diagnostic
        if isinstance(exc, ControlFailure): result['control_diagnostic'] = exc.diagnostic
        print(json.dumps(result), flush=True)
        sys.exit(1)
