#!/usr/bin/env python3
"""Prepare/run one fresh owned auth-bound key smoke; importing has no device effects.

`prepare` is offline. `capture-context` and `run` contact the selected tablet only
when the main device owner explicitly executes them after reviewing this case.
The unlock hook is external and main-owned; credentials never enter this program.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import selectors
import signal
import subprocess
import threading
import time
import uuid

PACKAGE = "org.googlebook.port.hardwareprobe"
SUITE = "auth_bound_keys"
LIMIT = 65536


def require(value, message):
    if not value:
        raise RuntimeError(message)


def read_json(path, limit=LIMIT):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), "expected regular JSON file")
    require(path.stat().st_size <= limit, "JSON input budget")
    return json.loads(path.read_text())


def digest(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), "expected regular pinned file")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def pin(path):
    path = Path(path).absolute()
    return dict(path=str(path), sha256=digest(path), bytes=path.stat().st_size)


def verify(item):
    require(re.fullmatch("[a-f0-9]{64}", item["sha256"]) is not None, "invalid pin")
    path = Path(item["path"])
    require(path.is_absolute() and digest(path) == item["sha256"], "pinned input changed")
    if "bytes" in item:
        require(path.stat().st_size == item["bytes"], "pinned size changed")
    return path


def save(path, value):
    path = Path(path)
    with path.open("x") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def bounded(args, timeout=12, limit=8192, cancel=None):
    """Bound retained output and wall time; kill own group and reap own child."""
    result = dict(exit_code=None, timed_out=False, output_budget_exceeded=False, cancelled=False)
    buffers = dict(stdout=bytearray(), stderr=bytearray())
    process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True)
    deadline = time.monotonic() + timeout
    completed = False
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        try:
            while selector.get_map():
                if cancel is not None and cancel.is_set():
                    result["cancelled"] = True
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    result["timed_out"] = True
                    break
                for key, _ in selector.select(min(.1, remaining)):
                    chunk = os.read(key.fileobj.fileno(), 4096)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    room = limit - sum(map(len, buffers.values()))
                    buffers[key.data].extend(chunk[:max(room, 0)])
                    if len(chunk) > room:
                        result["output_budget_exceeded"] = True
                        break
                if result["output_budget_exceeded"]:
                    break
            if not any(result[k] for k in ("timed_out", "output_budget_exceeded", "cancelled")):
                try:
                    process.wait(timeout=max(.001, deadline - time.monotonic()))
                    completed = True
                except subprocess.TimeoutExpired:
                    result["timed_out"] = True
        finally:
            if not completed:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            process.wait(timeout=5)
            process.stdout.close()
            process.stderr.close()
    return dict(result, exit_code=process.returncode,
                stdout=bytes(buffers["stdout"]), stderr=bytes(buffers["stderr"]))


def checked(outcome):
    require(outcome["exit_code"] == 0 and not outcome["timed_out"]
            and not outcome["output_budget_exceeded"] and not outcome["cancelled"],
            "bounded command failed")
    return outcome["stdout"].decode("utf-8", errors="strict").strip()


def profile_read(path, expected):
    require(digest(path) == expected, "profile changed")
    p = read_json(path)
    require(p["schema_version"] == 1 and p["suite"] == SUITE
            and p["authentication_validity_seconds"] == 5, "wrong prepared suite/timeout")
    require(re.fullmatch(r"[A-Za-z0-9._-]{1,64}", p["serial"]) is not None
            and isinstance(p["android_user"], int) and 0 <= p["android_user"] <= 32,
            "invalid device identity")
    require(digest(Path(__file__)) == p["controller"]["sha256"], "controller changed")
    for item in [p["controller"], p["runner"], p["request"], *p["evidence"]]:
        verify(item)
    request = read_json(verify(p["request"]))
    for key in ("adb", "apk", "build_report"):
        verify(request[key])
    require(request["suite"] == SUITE and request["serial"] == p["serial"]
            and request["fingerprint"] == p["fingerprint"]
            and request["android_user"] == p["android_user"], "request identity changed")
    p["_request"] = request
    return p


def shell(p, command):
    return checked(bounded([p["_request"]["adb"]["path"], "-s", p["serial"], "shell", command]))


def guard(p, expected_boot=None):
    require(Path(p["usb_serial_path"]).read_text().strip() == p["serial"], "physical USB mismatch")
    for command, expected in (
        ("getprop ro.serialno", p["serial"]), ("id -u", "2000"),
        ("getenforce", "Enforcing"), ("am get-current-user", str(p["android_user"])),
        (f"am get-started-user-state {p['android_user']}", "RUNNING_UNLOCKED"),
        ("getprop ro.build.fingerprint", p["fingerprint"]),
        ("getprop ro.vendor.build.fingerprint", p["vendor_fingerprint"]),
    ):
        require(shell(p, command) == expected, "device/profile/owner guard failed")
    boot = shell(p, "cat /proc/sys/kernel/random/boot_id")
    require(str(uuid.UUID(boot)) == boot, "invalid Android boot UUID")
    require(expected_boot is None or boot == expected_boot, "Android boot changed")
    return boot


def capture_context(profile_path, profile_sha, output):
    p = profile_read(profile_path, profile_sha)
    boot = guard(p)
    require(guard(p, boot) == boot, "context changed during capture")
    save(output, dict(schema_version=1, profile_sha256=profile_sha, case_id=p["case_id"],
         boot_id=boot, serial=p["serial"], android_user=p["android_user"],
         captured_monotonic=time.monotonic(), vm_or_guest_queried=False,
         firmware_written=False))


def context_read(path, expected, p, profile_sha):
    require(digest(path) == expected, "context changed")
    c = read_json(path, 4096)
    require(c["schema_version"] == 1 and c["profile_sha256"] == profile_sha
            and c["case_id"] == p["case_id"] and c["serial"] == p["serial"]
            and c["android_user"] == p["android_user"]
            and c["vm_or_guest_queried"] is False, "wrong context binding")
    age = time.monotonic() - c["captured_monotonic"]
    require(0 <= age <= 300, "capture a fresh context within five minutes")
    require(str(uuid.UUID(c["boot_id"])) == c["boot_id"], "invalid context boot")
    return c


def validate_runtime(report, p, boot, phases):
    request = p["_request"]
    require(report["status"] == "requested_operation_smoke_passed"
            and report["boot_id"] == boot and report["serial"] == p["serial"]
            and report["android_user"] == p["android_user"] and report["suite"] == SUITE
            and report["apk_sha256"] == request["apk"]["sha256"]
            and report["cleanup_verified"] is True and report["host_boot_unchanged"] is True
            and report["full_port_verified"] is False and report["firmware_written"] is False,
            "runtime status/identity/cleanup mismatch")
    require(phases[:2] == ["waiting_for_normal_unlock", "normal_lock_observed"],
            "actual normal-lock stages missing")
    ops = report["operations"]
    require(ops["suite"] == SUITE and ops["package"] == PACKAGE
            and ops["run_id"] == report["run_id"] and ops["fingerprint"] == p["fingerprint"]
            and ops["uid"] // 100000 == p["android_user"]
            and 10000 <= ops["uid"] % 100000 < 20000
            and ops["user_content_collected"] is False, "owned app identity mismatch")
    rows = ops["keystore"]["results"]
    require(len(rows) == 1, "expected one fresh key operation")
    row = rows[0]
    require(row["state"] == "compatible" and row["phase"] == "authentication_gate_observed"
            and row["authentication_validity_seconds"] == p["authentication_validity_seconds"]
            and row["authentication_type"] == 1 and row["reported_security_level"] in (1, 2),
            "configured authentication gate not observed")
    for key in ("user_authentication_required", "reported_hardware_auth_enforced",
                "before_authentication_rejected", "normal_lock_observed", "normal_unlock_observed",
                "signature_after_unlock_verified", "changed_message_rejected",
                "after_expiry_rejected", "owned_keys_removed"):
        require(row[key] is True, "missing actual auth/sign/expiry/cleanup operation")
    for key in ("credential_received_by_app", "private_material_exported", "attestation_verified"):
        require(row[key] is False, "scope/privacy escalation")
    return row


def cleanup(p, boot):
    guard(p, boot)
    user = p["android_user"]
    present = shell(p, f"pm list packages -u --user {user} {PACKAGE}")
    if present:
        require(present == "package:" + PACKAGE, "unexpected package listing")
        path = shell(p, f"pm path --user {user} {PACKAGE}")
        require(re.fullmatch(r"package:/data/app/[A-Za-z0-9_~=/+.-]+/base\.apk", path) is not None,
                "unexpected owned APK path")
        require(shell(p, "sha256sum " + path[len("package:"):]).split()[0]
                == p["_request"]["apk"]["sha256"], "refuse cleanup of different APK")
        shell(p, f"am force-stop --user {user} {PACKAGE}")
        require(shell(p, f"pm uninstall --user {user} {PACKAGE}") == "Success", "owned uninstall failed")
    require(shell(p, f"pm list packages -u --user {user} {PACKAGE}") == "", "owned namespace remains")
    return True


def run(profile_path, profile_sha, context_path, context_sha, hook, hook_sha):
    base = Path(profile_path).absolute().parent
    # Durable one-shot intent precedes all device calls. Failed preflight is not replayable.
    save(base / "execution-attempt.json", dict(schema_version=1, profile_sha256=profile_sha,
         context_sha256=context_sha, host_monotonic=time.monotonic(), firmware_written=False))
    result = dict(schema_version=1, status="needs_diagnosis", firmware_written=False,
                  full_port_verified=False, vm_or_guest_queried=False, credentials_read_or_logged=False)
    p = None
    boot = None
    started = False
    cancel = threading.Event()
    thread = None
    try:
        p = profile_read(profile_path, profile_sha)
        c = context_read(context_path, context_sha, p, profile_sha)
        boot = guard(p, c["boot_id"])
        require(digest(hook) == hook_sha, "main-owned unlock hook changed")
        require(shell(p, f"pm list packages -u --user {p['android_user']} {PACKAGE}") == "",
                "owned namespace already exists")
        require(not (base / "runtime.json").exists() and not (base / "runtime.context.json").exists(),
                "runtime namespace already exists")
        save(base / "execution-intent.json", dict(schema_version=1, boot_id=boot,
             profile_sha256=profile_sha, context=pin(context_path), normal_unlock_hook_sha256=hook_sha,
             normal_owner_ui_only=True, credentials_received=False, no_vm_lifetime_assumption=True))
        holder = {}
        def execute():
            try:
                holder["outcome"] = bounded([p["runner"]["path"], "run", p["request"]["path"],
                                             str(base / "runtime.json")], 180, LIMIT, cancel)
            except BaseException as error:
                holder["error_class"] = type(error).__name__
        thread = threading.Thread(target=execute, name="owned-hardware-runner")
        thread.start()
        started = True
        deadline = time.monotonic() + 185
        phases = []
        nonce = None
        unlocked = False
        while thread.is_alive():
            require(time.monotonic() < deadline, "hardware coordinator deadline")
            path = base / "runtime.context.json"
            if nonce is None and path.exists():
                context = read_json(path, 4096)
                nonce = context["run_id"]
                require(re.fullmatch("[a-f0-9]{32}", nonce) is not None
                        and context["package"] == PACKAGE and context["suite"] == SUITE
                        and context["android_user"] == p["android_user"]
                        and context["apk_sha256"] == p["_request"]["apk"]["sha256"]
                        and context["namespace_absent_before_install"] is True,
                        "wrong owned runtime context")
            if nonce:
                outcome = bounded([p["_request"]["adb"]["path"], "-s", p["serial"], "shell",
                    f"run-as {PACKAGE} --user {p['android_user']} cat files/auth-stage-{nonce}.json"], 5, 4096)
                require(not outcome["timed_out"] and not outcome["output_budget_exceeded"]
                        and not outcome["cancelled"], "app stage transport budget failed")
                if outcome["exit_code"] == 0:
                    stage = json.loads(checked(outcome))
                    require(set(stage) == {"run_id", "phase", "credential_received_by_app"}
                            and stage["run_id"] == nonce and stage["credential_received_by_app"] is False,
                            "wrong app stage receipt")
                    phase = stage["phase"]
                    require(phase in ("waiting_for_normal_unlock", "normal_lock_observed", "waiting_for_expiry"),
                            "unknown app stage")
                    if phase not in phases:
                        phases.append(phase)
                        save(base / f"stage-{len(phases)}.json", dict(phase=phase, run_id=nonce,
                             host_monotonic=time.monotonic(), credentials_received=False))
                        if phase == "waiting_for_normal_unlock":
                            guard(p, boot)
                            # Normal sleep key only; actual lock must be observed by the app.
                            shell(p, "input keyevent 223")
                        elif phase == "normal_lock_observed":
                            require(phases == ["waiting_for_normal_unlock", "normal_lock_observed"],
                                    "out-of-order normal lock")
                            guard(p, boot)
                            require(not unlocked, "normal unlock hook cannot replay")
                            unlocked = True
                            # Discard all hook output. The hook receives no credential arguments.
                            # Main's wrapper must emit nothing. Reject any output
                            # without retaining even one byte of hook content.
                            h = bounded([str(Path(hook).absolute())], 30, 0)
                            checked(h)
                            save(base / "normal-unlock-ack.json", dict(exit_code=0,
                                 hook_sha256=hook_sha, credential_received_by_controller=False))
            time.sleep(.2)
        thread.join(timeout=1)
        require("outcome" in holder, "runner failed before report")
        outcome = holder["outcome"]
        # Retain no raw command output: only budget/status scalars and app-owned JSON.
        result.update({k: outcome[k] for k in ("exit_code", "timed_out", "output_budget_exceeded", "cancelled")})
        checked(outcome)
        require(unlocked, "main-owned normal unlock was not observed")
        report = read_json(base / "runtime.json")
        validate_runtime(report, p, boot, phases)
        guard(p, boot)
        result.update(status="requested_operation_smoke_passed", boot_id=boot,
             runtime=pin(base / "runtime.json"), phases=phases, configured_authentication_seconds=5,
             authentication_timeout_and_expiry_observed=True, attestation_verified=False,
             strongbox_independently_verified=False)
    except BaseException as error:
        result["error_class"] = type(error).__name__
    finally:
        cancel.set()
        if thread is not None:
            thread.join(timeout=8)
            if thread.is_alive():
                result.update(status="needs_diagnosis", runner_join_failed=True,
                              cleanup_deferred_active_runner=True)
        if started and p is not None and boot is not None and not (thread and thread.is_alive()):
            try:
                result["owned_namespace_cleanup_verified"] = cleanup(p, boot)
            except BaseException as error:
                result.update(status="needs_diagnosis", owned_namespace_cleanup_verified=False,
                              cleanup_error_class=type(error).__name__)
        save(base / "result.json", result)
    return 0 if result["status"] == "requested_operation_smoke_passed" else 2


def prepare(input_path, case):
    """Offline only: pin existing source-specific APK/runner; never launch tools."""
    value = read_json(input_path)
    require(value["schema_version"] == 1 and value["suite"] == SUITE
            and value["authentication_validity_seconds"] == 5, "unsupported prepared suite")
    for item in [value["runner"], *value["evidence"]]:
        verify(item)
    request = read_json(input_path.parent / value["request_template"])
    for key in ("adb", "apk", "build_report"):
        verify(request[key])
    request["suite"] = SUITE
    require(request["serial"] == value["serial"] and request["fingerprint"] == value["fingerprint"]
            and request["android_user"] == value["android_user"], "template profile mismatch")
    require(not case.exists(), "fresh case required")
    case.mkdir(mode=0o700)
    script = case / "controller.py"
    script.write_bytes(Path(__file__).read_bytes())
    save(case / "run-request.json", request)
    profile = {k: v for k, v in value.items() if k != "request_template"}
    profile.update(case_id=uuid.uuid4().hex, controller=pin(script), request=pin(case / "run-request.json"))
    save(case / "profile.json", profile)
    save(case / "preparation.json", dict(schema_version=1, status="prepared_not_executed",
         profile=pin(case / "profile.json"), controller=pin(script), preparation_input=pin(input_path),
         device_contacted=False, runtime_verified=False, firmware_written=False,
         expected_boot_id=None, expected_vm_or_guest_lifetime=None))
    return pin(case / "profile.json")


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    p = sub.add_parser("prepare")
    p.add_argument("input", type=Path)
    p.add_argument("new_case", type=Path)
    for name in ("capture-context", "run"):
        p = sub.add_parser(name)
        p.add_argument("profile", type=Path)
        p.add_argument("profile_sha256")
        if name == "capture-context":
            p.add_argument("new_context", type=Path)
        else:
            p.add_argument("context", type=Path)
            p.add_argument("context_sha256")
            p.add_argument("main_owned_unlock_hook", type=Path)
            p.add_argument("hook_sha256")
    a = parser.parse_args()
    if a.mode == "prepare":
        print(json.dumps(prepare(a.input.absolute(), a.new_case.absolute())))
    elif a.mode == "capture-context":
        capture_context(a.profile, a.profile_sha256, a.new_context)
    else:
        return run(a.profile, a.profile_sha256, a.context, a.context_sha256,
                   a.main_owned_unlock_hook, a.hook_sha256)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
