"""Self-contained donor-JS source regression; no device or APK modification.

The actual source fixture executes ONLY inside an offline unprivileged Docker
container. The exact local test image and trusted host Node/libs are prerequisites;
their absence skips execution, never falls back to unsandboxed JavaScript.
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
import uuid

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / 'patches/donors/mica/terminal-websocket-onmessage-registration.patch'
FIXTURE = ROOT / 'tests/fixtures/terminal_websocket_interceptor.js'
MOCK = ROOT / 'tests/fixtures/terminal_websocket_onmessage_mock.js'
BASE = '880df2a09c1f7a82ad9d0e00d660a3e32453dc7e2d3bb27e9ad5504565988e4a'
RESULT = '265ed6763de4a854d0fbaaea7cbcfac9850ad191050491f1843de4205274528d'
IMAGE = 'sha256:a3a951af78a89cb1a771c97cc70c7573663f751a444d728ed9048c1f20ab40c5'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def apply_patch(directory, reverse=False):
    args = ['patch', '--batch', '--fuzz=0', '-p1', '-i', str(PATCH)]
    if reverse:
        args.append('--reverse')
    result = subprocess.run(args, cwd=directory, capture_output=True, timeout=5)
    if result.returncode:
        raise AssertionError('exact patch application failed')


class Tests(unittest.TestCase):
    def stage(self, directory):
        target = directory / 'assets/js/websocket_interceptor.js'
        target.parent.mkdir(parents=True)
        target.write_bytes(FIXTURE.read_bytes())
        self.assertEqual(sha(target), BASE)
        apply_patch(directory)
        self.assertEqual(sha(target), RESULT)
        return target

    def test_exact_source_patch_and_reversal(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            target = self.stage(directory)
            apply_patch(directory, reverse=True)
            self.assertEqual(sha(target), BASE)
        manifest = json.loads(PATCH.with_suffix('.json').read_text())
        self.assertEqual(manifest['patch_sha256'], sha(PATCH))
        self.assertEqual(manifest['files'][0]['sha256'], BASE)
        self.assertEqual(manifest['files'][0]['result_sha256'], RESULT)

    def test_actual_source_in_offline_sandbox(self):
        node = shutil.which('node')
        if not node or not shutil.which('docker') or not shutil.which('ldd'):
            self.skipTest('offline Docker + trusted Node/ldd prerequisites unavailable')
        found = subprocess.run(['docker', 'image', 'inspect', IMAGE], capture_output=True, timeout=5)
        if found.returncode:
            self.skipTest('exact preexisting offline test image unavailable')
        node = Path(node).resolve()
        environment = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'LC_ALL': 'C'}
        dependencies = subprocess.run(['ldd', str(node)], capture_output=True, text=True,
                                      timeout=5, env=environment)
        if dependencies.returncode:
            self.skipTest('trusted Node shared-library discovery unavailable')
        libraries = []
        loader = None
        for line in dependencies.stdout.splitlines():
            matched = re.search(r'=> (/[^\s]+)', line)
            if matched:
                libraries.append(Path(matched.group(1)))
            elif re.match(r'^\s*/[^\s]+', line):
                loader = Path(line.split()[0]).resolve()
        if loader is None or not 1 <= len(libraries) <= 32:
            self.skipTest('trusted Node loader layout unavailable')
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            target = self.stage(directory)
            case = directory / 'case'
            case.mkdir(mode=0o755)
            (case / 'base.js').write_bytes(FIXTURE.read_bytes())
            (case / 'fixed.js').write_bytes(target.read_bytes())
            (case / 'mock.js').write_bytes(MOCK.read_bytes())
            for path in case.iterdir():
                path.chmod(0o444)
            container = 'gb-ttyd-onmessage-test-' + uuid.uuid4().hex[:16]
            command = ['docker', 'run', '--rm', '--name', container, '--network', 'none',
                       '--read-only', '--user', '65534:65534', '--cap-drop', 'ALL',
                       '--security-opt', 'no-new-privileges', '--pids-limit', '32',
                       '--memory', '128m', '--cpus', '1', '--tmpfs', '/tmp:rw,noexec,nosuid,size=8m']
            mounts = [(node, '/tool/node'), (loader, '/tool/ld'), (case, '/case')]
            mounts += [(p, '/tool/lib/' + p.name) for p in libraries]
            for source, destination in mounts:
                command += ['--mount', 'type=bind,src=' + str(source.resolve()) + ',dst=' + destination + ',readonly']
            command += ['--entrypoint', '/tool/ld', IMAGE, '--library-path', '/tool/lib',
                        '/tool/node', '--max-old-space-size=64', '/case/mock.js']
            try:
                result = subprocess.run(command, capture_output=True, timeout=15)
            except subprocess.TimeoutExpired:
                # A unique name belongs solely to this invocation. Never inspect,
                # stop or remove any unrelated container or global build cache.
                subprocess.run(['docker', 'kill', '--signal', 'KILL', container],
                               capture_output=True, timeout=5)
                raise
            self.assertEqual(result.returncode, 0, result.stderr[:4096])
            self.assertLessEqual(len(result.stdout), 16384)
            output = json.loads(result.stdout)
            self.assertEqual(output['passed_cases'], 9)
            self.assertIs(output['host_only'], True)
            self.assertIs(output['installed_frontend_assignment_verified'], False)
            self.assertIs(output['runtime_root_cause_verified'], False)


if __name__ == '__main__':
    unittest.main()
