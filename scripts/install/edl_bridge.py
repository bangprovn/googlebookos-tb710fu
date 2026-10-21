#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Subprocess adapter to B. Kerler's GPLv3 EDL client. See third_party/edl-bridge.
"""Private JSON protocol for gb-install. No arbitrary XML, erase or slot commands."""
import json
import os
from pathlib import Path
import re
import runpy
import sys


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def storage_identity(fh):
    result = fh.cmd_getstorageinfo()
    require(result and len(result) == 2, "missing UFS storage report")
    text, response = result
    require(response and response.resp and isinstance(text, str), "storage report NACK")
    info = json.loads(text.removeprefix("INFO:").strip())["storage_info"]
    identity = {
        "serial": str(info["serial_num"]),
        "sector_bytes": int(info["page_size"]),
        "luns": int(info["num_physical"]),
        "memory": str(info["mem_type"]).lower(),
        "product": str(info["prod_name"]),
    }
    require(identity["memory"] == "ufs" and identity["sector_bytes"] == 4096
            and 1 <= identity["luns"] <= 8 and identity["serial"] not in ("", "0"),
            "unsupported or unidentified storage")
    require(fh.cfg.SECTOR_SIZE_IN_BYTES == 4096, "configured sector size differs")
    return identity


def digest(fh, lun, start, sectors):
    xml = ('<?xml version="1.0"?><data><getsha256digest '
           f'SECTOR_SIZE_IN_BYTES="4096" physical_partition_number="{lun}" '
           f'start_sector="{start}" num_partition_sectors="{sectors}"/></data>')
    result = fh.xmlsend(xml)
    require(result.resp, "device digest NACK")
    text = "\n".join(result.log or [])
    if isinstance(result.data, (str, bytes)):
        text += "\n" + (result.data.decode("utf-8", "replace")
                          if isinstance(result.data, bytes) else result.data)
    hashes = set(x.lower() for x in re.findall(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])", text))
    require(len(hashes) == 1, "missing or ambiguous device SHA-256 digest")
    return hashes.pop()


def perform(fh, request):
    """Called only after Sahara + configure. Also exercised without USB by tests."""
    fh.modules = None  # Never run vendor write hooks or bootloader-modifying modules.
    identity = storage_identity(fh)
    op = request["operation"]
    if op == "probe":
        return {"identity": identity}
    require(identity["serial"] == request["serial"], "wrong UFS storage serial; no operation sent")
    if op == "reset":
        require(fh.cmd_reset("reset"), "reset NACK")
        return {"identity": identity}
    lun, start, sectors = (request[k] for k in ("lun", "start_sector", "sectors"))
    require(all(type(x) is int for x in (lun, start, sectors))
            and 0 <= lun < identity["luns"] and 0 <= start < 2**40
            and 0 < sectors <= 2**32 and start + sectors < 2**40, "invalid sector range")
    if op == "read":
        require(sectors * 4096 <= 128 * 1024**2, "readback exceeds bound")
        path = Path(request["path"])
        require(not path.exists(), "readback destination already exists")
        require(fh.cmd_read(lun, start, sectors, str(path), display=False), "read NACK")
        require(path.is_file() and path.stat().st_size == sectors * 4096, "short readback")
        return {"identity": identity}
    if op == "digest":
        return {"identity": identity, "sha256": digest(fh, lun, start, sectors)}
    require(op == "program", "unsupported operation")
    path = Path(request["path"])
    require(path.is_file() and not path.is_symlink() and path.stat().st_size == sectors * 4096,
            "program input is not the exact aligned raw range")
    with path.open("rb") as source:
        require(source.read(4) != b"\x3a\xff\x26\xed", "sparse program input is forbidden")
    require(fh.cmd_program(lun, start, str(path), display=False), "program final NACK")
    # Do not report a completed write without a matching device-side digest.
    actual = digest(fh, lun, start, sectors)
    require(actual == request["sha256"], "post-program device SHA-256 mismatch")
    return {"identity": identity, "sha256": actual}


def guarded_xmlsend(original, fh, data, skipresponse=False):
    encoded = data if isinstance(data, bytes) else data.encode("utf-8")
    previous_read = fh.cdc.read
    if b"<getsha256digest " in encoded:
        def read(length=None, timeout=-1):
            return previous_read(length, 120000 if timeout is None else timeout)
        fh.cdc.read = read
    try:
        result = original(fh, data, skipresponse)
        # Upstream cmd_program otherwise returns True after an initial NACK.
        if b"<program " in encoded:
            require(not skipresponse and result.resp, "program initial NACK")
        return result
    finally:
        fh.cdc.read = previous_read


def main(request, response_path):
    client = Path(request["client"]).resolve()
    sys.path.insert(0, str(client))
    import usb.core
    import usb.backend.libusb1
    from edlclient.Library.Connection.usblib import usb_class
    from edlclient.Library.firehose import firehose
    from edlclient.Library.firehose_client import firehose_client

    library = request.get("libusb")
    backend = usb.backend.libusb1.get_backend(find_library=lambda _: library) if library else usb.backend.libusb1.get_backend()
    require(backend is not None, "libusb-1.0 unavailable; install it or supply --libusb")
    original_connect = usb_class.connect

    def connect(self, *args, **kwargs):
        self.backend = backend
        devices = list(usb.core.find(find_all=True, idVendor=0x05c6, idProduct=0x9008, backend=backend))
        require(len(devices) == 1, "connect exactly one EDL/9008 device; no loader uploaded")
        self.portconfig = [[0x05c6, 0x9008, -1]]
        return original_connect(self, *args, **kwargs)

    usb_class.connect = connect
    original_xmlsend = firehose.xmlsend
    def xmlsend(self, data, skipresponse=False):
        return guarded_xmlsend(original_xmlsend, self, data, skipresponse)
    firehose.xmlsend = xmlsend

    def handle(self, _command, _options):
        result = perform(self.firehose, request)
        with open(response_path, "x", encoding="utf-8") as output:
            json.dump({"schema_version": 1, "ok": True, **result}, output)
            output.flush()
            os.fsync(output.fileno())
        return True

    firehose_client.handle_firehose = handle
    script = client / "edl.py"
    sys.argv = [str(script), "getstorageinfo", "--memory=ufs", "--loader=" + request["loader"],
                "--vid=0x05c6", "--pid=0x9008", "--devicemodel=TB710FU"]
    runpy.run_path(str(script), run_name="__main__")


if __name__ == "__main__":
    try:
        require(len(sys.argv) == 3, "expected request and response paths")
        request_path, response_path = sys.argv[1:]
        require(Path(request_path).stat().st_size <= 65536, "oversized bridge request")
        with open(request_path, encoding="utf-8") as source:
            main(json.load(source), response_path)
    except Exception as error:
        print("EDL bridge blocked: " + str(error), file=sys.stderr)
        sys.exit(1)
