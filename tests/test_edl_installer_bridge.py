"""EDL bridge failure tests. No pyusb import or physical device access."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location("bridge", Path(__file__).resolve().parents[1] / "scripts/install/edl_bridge.py")
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


class Firehose:
    def __init__(self):
        self.cfg = SimpleNamespace(SECTOR_SIZE_IN_BYTES=4096)
        self.modules = object()
        self.calls = []
        self.ok = True
        self.hash = "ab" * 32
        self.cdc = SimpleNamespace(read=lambda length=None, timeout=-1: timeout)

    def cmd_getstorageinfo(self):
        info = dict(serial_num=123, page_size=4096, num_physical=6, mem_type="UFS", prod_name="fixture")
        return "INFO: " + json.dumps(dict(storage_info=info)), SimpleNamespace(resp=True)

    def cmd_program(self, lun, start, path, display):
        self.calls.append("program")
        return self.ok

    def xmlsend(self, xml):
        self.calls.append("digest")
        return SimpleNamespace(resp=self.ok, log=["SHA256: " + self.hash], data=b"")

    def cmd_reset(self, mode):
        self.calls.append("reset")
        return True


class BridgeTests(unittest.TestCase):
    def test_wrong_identity_blocks_read_program_and_reset(self):
        for op in ("read", "program", "reset"):
            f = Firehose()
            with self.assertRaisesRegex(RuntimeError, "wrong UFS"):
                bridge.perform(f, dict(operation=op, serial="OTHER"))
            self.assertEqual(f.calls, [])

    def test_program_requires_exact_raw_size_and_matching_device_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "raw.img"
            path.write_bytes(bytes(4096))
            r = dict(operation="program", serial="123", lun=0, start_sector=1234, sectors=1,
                     path=str(path), sha256="ab" * 32)
            f = Firehose()
            self.assertEqual(bridge.perform(f, r)["sha256"], r["sha256"])
            self.assertEqual(f.calls, ["program", "digest"])
            self.assertIsNone(f.modules)
            for bad in ("short", "sparse", "digest", "nack"):
                f = Firehose()
                path.write_bytes(bytes(4096))
                if bad == "short":
                    path.write_bytes(bytes(1))
                elif bad == "sparse":
                    path.write_bytes(b"\x3a\xff\x26\xed" + bytes(4092))
                elif bad == "digest":
                    f.hash = "cd" * 32
                else:
                    f.ok = False
                with self.assertRaises(RuntimeError):
                    bridge.perform(f, r)
                self.assertNotIn("reset", f.calls)
                if bad in ("short", "sparse"):
                    self.assertEqual(f.calls, [])

    def test_initial_program_nack_is_an_error_even_if_upstream_would_return_true(self):
        f = Firehose()
        for skip in (False, True):
            with self.assertRaisesRegex(RuntimeError, "initial NACK"):
                bridge.guarded_xmlsend(lambda *_: SimpleNamespace(resp=False), f, '<program start_sector="10"/>', skip)

    def test_only_digest_gets_longer_timeout_and_restores_reader_after_error(self):
        f = Firehose()
        original = f.cdc.read
        def call(fh, xml, skip):
            self.assertEqual(fh.cdc.read(timeout=None), 120000)
            raise RuntimeError("USB error")
        with self.assertRaisesRegex(RuntimeError, "USB error"):
            bridge.guarded_xmlsend(call, f, '<getsha256digest start_sector="10"/>')
        self.assertIs(f.cdc.read, original)
        self.assertIsNone(bridge.guarded_xmlsend(lambda fh, *_: fh.cdc.read(timeout=None), f, '<nop/>'))

    def test_missing_or_ambiguous_digest_never_reports_success(self):
        f = Firehose()
        for logs in ([], ["ab" * 32, "cd" * 32]):
            f.xmlsend = lambda _: SimpleNamespace(resp=True, log=logs, data=b"")
            with self.assertRaisesRegex(RuntimeError, "ambiguous"):
                bridge.digest(f, 0, 10, 1)


if __name__ == "__main__":
    unittest.main()
