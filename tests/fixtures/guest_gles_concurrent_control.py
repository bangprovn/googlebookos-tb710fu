#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Known GLES draw while the Vulkan producer remains alive; NEVER import its FD.

Exit 77 on a successful control deliberately prevents the parent image producer
from issuing its successful-interoperability receipt. Only our JSON witnesses
this concurrent draw. The inherited owned diagnostic descriptor is just closed.
"""
import json
import os
import signal
import sys
from guest_egl_dma_buf import parse_layout
from terminal_guest_gles import probe, ProbeError


def main():
    signal.alarm(15)
    try:
        if (len(sys.argv) != 5 or sys.argv[1] != '--owned-dma-buf-fd'
                or not sys.argv[2].isdigit() or not 3 <= int(sys.argv[2]) <= 4096
                or sys.argv[3] != '--image-layout-json' or len(sys.argv[4]) > 1024):
            raise ProbeError('explicit_owned_image_control_arguments_required')
        layout = parse_layout(sys.argv[4])
        if layout['width'] != 32 or layout['height'] != 32 or layout['rgba'] != [19, 67, 139, 255]:
            raise ProbeError('bounded_image_control_profile_required')
        fd = int(sys.argv[2]); os.fstat(fd); os.close(fd)
        result = probe(4)
        renderer = result['gl']['renderer']
        if 'virgl' not in renderer.lower() or 'Adreno' not in renderer or result['renderer_reports_software']:
            raise ProbeError('virgl_adreno_control_required')
        print(json.dumps(dict(schema_version=1, status='concurrent_gles_solid_control_verified',
                              gles=result, external_image_import_attempted=False,
                              dma_buf_pixels_read=False, owner_content_read=False,
                              presentation_verified=False, full_port_verified=False,
                              intentional_exit_code=77)), flush=True)
        return 77
    except Exception as exc:
        print(json.dumps(dict(schema_version=1, status='concurrent_gles_control_failed',
                              stage=str(exc) if isinstance(exc, ProbeError) else type(exc).__name__,
                              external_image_import_attempted=False,
                              presentation_verified=False, full_port_verified=False)), flush=True)
        return 1


if __name__ == '__main__':
    sys.exit(main())
