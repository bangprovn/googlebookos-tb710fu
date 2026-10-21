#!/usr/bin/env python3
"""Artifact-only host adapter boundary tests: fixture native child, no firmware/VM.

The actual adapter body and two std-only support modules execute. Its optional
immutable image-probe module is stubbed disabled, explicitly outside this test.
"""
from pathlib import Path
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / "patches/tb710fu/crosvm/gpu-idle-diagnostic-adapter.patch"
MANIFEST = PATCH.with_suffix(".json")

class DiagnosticAdapter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory(prefix="gb-gpu-trace-adapter-test-")
        cls.path = Path(cls.work.name)
        cls.manifest = json.loads(MANIFEST.read_text())
        cls.base = (ROOT / cls.manifest["base_path"]).read_bytes()
        sha = lambda data: hashlib.sha256(data).hexdigest()
        assert sha(cls.base) == cls.manifest["base_sha256"]
        assert sha(PATCH.read_bytes()) == cls.manifest["patch_sha256"]
        cls.source = cls.path / "crosvm_runtime_adapter.rs"
        cls.source.write_bytes(cls.base)
        for reverse, expected in [(False, cls.manifest["result_sha256"]),
                                  (True, cls.manifest["base_sha256"]),
                                  (False, cls.manifest["result_sha256"])]:
            command = ["patch", "--batch", "--fuzz=0", "-p1", "-i", str(PATCH)]
            if reverse:
                command.append("--reverse")
            result = subprocess.run(command, cwd=cls.path, capture_output=True, text=True, timeout=10)
            assert result.returncode == 0, result.stderr + result.stdout
            assert sha(cls.source.read_bytes()) == expected
        support = cls.path / "support"
        support.mkdir()
        original = ROOT / cls.manifest["base_path"]
        for name in ["android_metadata_log.rs", "venus_gpu.rs"]:
            (support / name).write_bytes((original.parent / "support" / name).read_bytes())
        (support / "host_image_probe.rs").write_text(
            'pub fn run(_: &std::path::Path) -> String { "image_probe outcome=disabled".into() }\n')
        subprocess.run(["rustc", "--edition=2024", "-Dwarnings", str(cls.source), "-o", str(cls.path / "crosvm")],
                       check=True, capture_output=True, text=True, timeout=30)
        helper = cls.path / "helper.rs"
        helper.write_text(r'''
use std::{io::Read, os::fd::FromRawFd};
fn main() {
 println!("pid={}",std::process::id());
 println!("trace={}",std::env::var("GB_GPU_IDLE_TRACE_V1").unwrap_or_else(|_|"unset".into()));
 println!("marker={}",std::env::var("GB_EXEC_MARKER").unwrap());
 let raw=std::env::var("GB_EXEC_FD").unwrap().parse::<i32>().unwrap();
 let mut file=unsafe{std::fs::File::from_raw_fd(raw)};let mut bytes=Vec::new();file.read_to_end(&mut bytes).unwrap();
 assert_eq!(bytes,b"owned-inherited-capability");println!("fd_preserved=true");
}
''')
        subprocess.run(["rustc", "--edition=2024", "-Dwarnings", str(helper), "-o", str(cls.path / "helper")],
                       check=True, capture_output=True, text=True, timeout=30)
        for name in ["fallback/crosvm", "fallback/crosvm_minimal", "runtime/bin/crosvm"]:
            path = cls.path / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(cls.path / "helper", path)
            path.chmod(0o700)
        shutil.copyfile(cls.path / "crosvm", cls.path / "crosvm_minimal")
        (cls.path / "crosvm_minimal").chmod(0o700)

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()

    def test_only_insertions_and_byte_exact_reverse(self):
        source = self.source.read_text()
        stripped = re.sub(r"// GB_GPU_IDLE_DIAGNOSTIC_ADAPTER_BEGIN.*?// GB_GPU_IDLE_DIAGNOSTIC_ADAPTER_END\n\n", "", source, flags=re.S)
        stripped = re.sub(r"    // GB_GPU_IDLE_DIAGNOSTIC_EXEC_BEGIN\n.*?    // GB_GPU_IDLE_DIAGNOSTIC_EXEC_END\n", "", stripped, flags=re.S)
        self.assertEqual(stripped.encode(), self.base)
        self.assertEqual(source.count("configure_gpu_idle_trace(&mut command"), 1)
        self.assertIn('command.env_remove("GB_GPU_IDLE_TRACE_V1")', source)
        self.assertIn('private_venus && name == Some(DEFAULT)', source)
        self.assertIn("let error = command.exec();", source)

    def test_actual_exec_sets_only_private_default_and_preserves_pid_and_fd(self):
        cases = [("default", "crosvm_debian", "2048", True),
                 ("probe", "crosvm_gb-runtime-share-probe-1", "512", False),
                 ("foreign", "unrelated", "2048", False),
                 ("near_name", "crosvm_debian-extra", "2048", False),
                 ("unnamed", None, "2048", False)]
        for variant in ["crosvm", "crosvm_minimal"]:
            for _, name, memory, enabled in cases:
                for inherited in [None, "wrong-token", "worker-counters-v1"]:
                    arguments = ["run", "--mem=" + memory, "--gpu=mode=gfxstream"]
                    if name is not None:
                        arguments.append("--name=" + name)
                    environment = dict(os.environ, GB_EXEC_MARKER="owned-fixture")
                    environment.pop("GB_GPU_IDLE_TRACE_V1", None)
                    if inherited is not None:
                        environment["GB_GPU_IDLE_TRACE_V1"] = inherited
                    with tempfile.TemporaryFile() as descriptor:
                        descriptor.write(b"owned-inherited-capability"); descriptor.seek(0)
                        environment["GB_EXEC_FD"] = str(descriptor.fileno())
                        child = subprocess.Popen([str(self.path / variant), *arguments], env=environment,
                                                 pass_fds=(descriptor.fileno(),), stdout=subprocess.PIPE,
                                                 stderr=subprocess.PIPE)
                        stdout, stderr = child.communicate(timeout=10)
                    self.assertEqual(child.returncode, 0, stderr[:1024])
                    self.assertLess(len(stdout) + len(stderr), 8192)
                    values = dict(line.split("=", 1) for line in stdout.decode().splitlines())
                    self.assertEqual(int(values["pid"]), child.pid)
                    self.assertEqual(values["trace"], "worker-counters-v1" if enabled else "unset")
                    self.assertEqual(values["marker"], "owned-fixture")
                    self.assertEqual(values["fd_preserved"], "true")
                    self.assertNotIn(b"owned-inherited-capability", stderr)

    def test_invalid_selected_profile_is_refused_before_mock_native(self):
        child = subprocess.run([str(self.path / "crosvm"), "run", "--name=crosvm_debian",
                                "--mem=512", "--gpu=mode=gfxstream"],
                               capture_output=True, timeout=10)
        self.assertEqual(child.returncode, 125)
        self.assertEqual(child.stdout, b"")
        self.assertIn(b"selected memory", child.stderr)

if __name__ == "__main__":
    unittest.main(verbosity=2)
