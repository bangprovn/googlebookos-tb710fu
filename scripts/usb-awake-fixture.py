#!/usr/bin/env python3
"""Main-owned finite configured-power stay-awake fixture. `prepare` is strictly offline.

No child arguments or output are retained. This controls one normal setting,
not CPU policy, credentials, foreground state, suspend or VM behavior.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import re
import shlex
import signal
import subprocess
import threading
import time
import uuid

KEY = "stay_on_while_plugged_in"
HELPER_SHA = "293f8227f8e9c05a1dc8ae8649edb867ab3554f6886b7ed73bee6c2f85ce0401"
PLUG_MASKS = {"ac": 1, "usb": 2}
POWER = "dumpsys power | sed -n '/^  mWakefulness=/p;/^  mIsPowered=/p;/^  mPlugType=/p'"


def configured_plug(p):
    kind, mask = p.get("plug_kind"), p.get("plug_mask")
    if kind not in PLUG_MASKS or type(mask) is not int or mask != PLUG_MASKS[kind]:
        raise RuntimeError("explicit standard plug kind/mask required")
    return kind, str(mask)


def digest(path):
    p = Path(path)
    if not p.is_file() or p.is_symlink():
        raise RuntimeError("expected regular input")
    with p.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def load(profile_path, expected):
    if digest(profile_path) != expected or Path(profile_path).stat().st_size > 65536:
        raise RuntimeError("profile identity/budget")
    p = json.loads(Path(profile_path).read_text())
    if digest(p["helper"]["path"]) != HELPER_SHA or p["helper"]["sha256"] != HELPER_SHA:
        raise RuntimeError("unreviewed host helper")
    spec = importlib.util.spec_from_file_location("reviewed_awake_helpers", p["helper"]["path"])
    h = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(h)
    h.require(p["schema_version"] == 1 and p["kind"] == "normal_power_stay_awake"
              and p["android_user"] in range(33)
              and re.fullmatch(r"[A-Za-z0-9._-]{1,64}", p["serial"]) is not None,
              "fixture profile schema")
    configured_plug(p)
    h.require(digest(__file__) == p["controller"]["sha256"], "controller changed")
    for item in (p["controller"], p["helper"], p["adb"]):
        h.verify(item)
    p["_request"] = {"adb": p["adb"]}
    return h, p


def setting(h, p):
    value = h.shell(p, "settings get global " + KEY)
    listing = h.shell(p, "settings list global | sed -n '/^" + KEY + "=/p'")
    if not listing:
        h.require(value == "null", "unset setting framing mismatch")
        return dict(present=False, value=None)
    h.require(listing == KEY + "=" + value and re.fullmatch(r"-?(0|[1-9][0-9]{0,9})", value),
              "unexpected prior setting framing")
    h.require(-(2**31) <= int(value) < 2**31, "setting integer budget")
    return dict(present=True, value=value)


def power(h, p):
    text = h.shell(p, POWER)
    values = {}
    counts = {}
    for line in text.splitlines():
        match = re.fullmatch(r"\s*m(Wakefulness|IsPowered|PlugType)=(Awake|Asleep|Dozing|Dreaming|true|false|[0-9]+)", line)
        h.require(match is not None, "unknown power scalar framing")
        key, value = match[1], match[2]
        h.require(key not in values or values[key] == value, "conflicting power scalar observations")
        values[key] = value
        counts[key] = counts.get(key, 0) + 1
    h.require(set(values) == {"Wakefulness", "IsPowered", "PlugType"}
              and values["Wakefulness"] in ("Awake", "Asleep", "Dozing", "Dreaming")
              and values["IsPowered"] in ("true", "false")
              and re.fullmatch(r"[0-9]{1,2}", values["PlugType"]), "missing power scalars")
    return dict(wakefulness=values["Wakefulness"], powered=values["IsPowered"] == "true",
                plug_type=int(values["PlugType"]), scalar_observation_counts=counts)


def remote_guard(p, boot):
    # Recheck in the same shell immediately before either setting mutation.
    pairs = [("cat /proc/sys/kernel/random/boot_id", boot), ("getprop ro.serialno", p["serial"]),
             ("id -u", "2000"), ("getenforce", "Enforcing"),
             ("am get-current-user", str(p["android_user"])),
             ("getprop ro.build.fingerprint", p["fingerprint"]),
             ("getprop ro.vendor.build.fingerprint", p["vendor_fingerprint"])]
    return " && ".join('[ "$(' + command + ')" = ' + shlex.quote(expected) + ' ]'
                       for command, expected in pairs)


def restore(h, p, boot, prior, base, write_diagnostic):
    h.guard(p, boot)
    _, wanted = configured_plug(p)
    observed = setting(h, p)
    if observed == prior:
        return dict(setting_restored=True, action="none_already_prior", observed=observed)
    h.require(observed == dict(present=True, value=wanted), "external setting change; refuse overwrite")
    # prior-setting/apply-intent are already durable. Failure to save this
    # additional diagnostic must not strand the setting at our temporary value.
    intent_saved = write_diagnostic("restore-intent.json",
                                   dict(prior=prior, observed_ours=observed, boot_id=boot))
    command = ("settings put global " + KEY + " " + shlex.quote(prior["value"]) if prior["present"]
               else "settings delete global " + KEY)
    # Standard settings CLI offers no transactional CAS; main must be the sole writer.
    guarded = remote_guard(p, boot) + ' && [ "$(settings get global ' + KEY + ')" = ' + wanted + ' ] && ' + command
    h.shell(p, guarded)
    after = setting(h, p)
    h.require(after == prior, "exact setting restoration not observed")
    h.guard(p, boot)
    return dict(setting_restored=True, action="restore_prior_value" if prior["present"] else "delete_prior_unset",
                observed=after, restore_intent_persisted=intent_saved)


def child(command, timeout, cancel, holder):
    started = time.monotonic()
    outcome = dict(exit_code=None, timed_out=False, cancelled=False, direct_child_reaped=False,
                   owned_process_group_cleanup_attempted=False, stdout_stderr_retained_bytes=0)
    process = None
    try:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, start_new_session=True)
        deadline = started + timeout
        while process.poll() is None:
            if cancel.is_set():
                outcome["cancelled"] = True
                break
            if time.monotonic() >= deadline:
                outcome["timed_out"] = True
                break
            cancel.wait(min(.05, max(0, deadline - time.monotonic())))
    except BaseException as error:
        outcome["error_class"] = type(error).__name__
    finally:
        if process is not None:
            # Also retire surviving descendants after a normally completed child.
            outcome["owned_process_group_cleanup_attempted"] = True
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError as error:
                outcome["group_cleanup_error_class"] = type(error).__name__
            try:
                process.wait(timeout=5)
                outcome.update(exit_code=process.returncode, direct_child_reaped=True)
            except BaseException as error:
                outcome["reap_error_class"] = type(error).__name__
        outcome["seconds"] = round(time.monotonic() - started, 3)
        holder["result"] = outcome


def capture(profile_path, profile_sha, destination):
    h, p = load(profile_path, profile_sha)
    boot = h.guard(p)
    h.guard(p, boot)
    h.save(destination, dict(schema_version=1, profile_sha256=profile_sha, case_id=p["case_id"],
           boot_id=boot, serial=p["serial"], android_user=p["android_user"],
           captured_monotonic=time.monotonic(), vm_or_guest_queried=False, firmware_written=False))


def run(profile_path, profile_sha, context, context_sha, command, child_sha, timeout):
    h, p = load(profile_path, profile_sha)
    base = Path(profile_path).absolute().parent
    h.save(base / "fixture-attempt.json", dict(profile_sha256=profile_sha, context_sha256=context_sha,
           child_executable_sha256=child_sha, child_argument_count=max(0, len(command)-1),
           host_monotonic=time.monotonic()))
    result = dict(schema_version=1, status="needs_diagnosis", firmware_written=False,
                  vm_or_guest_queried=False, credentials_requested=False,
                  cpu_or_background_policy_changed=False, suspend_or_idle_verified=False,
                  child_stdout_stderr_or_argv_retained=False, setting_restored=False)
    plug_kind, wanted = configured_plug(p)
    result.update(configured_plug_kind=plug_kind, configured_plug_mask=int(wanted))
    prior = boot = None
    attempted = False
    cancel = threading.Event()
    holder = {}
    thread = None
    diagnostic_attempts = set()
    diagnostic_errors = []
    result_preexisted = (base / "result.json").exists()
    def write_diagnostic(name, value):
        # Never retry a partially written receipt. Record only fixed artifact
        # names/error classes; no exception strings or child arguments/output.
        if name in diagnostic_attempts:
            return name not in {item["artifact"] for item in diagnostic_errors}
        diagnostic_attempts.add(name)
        try:
            h.save(base / name, value)
            return True
        except BaseException as error:
            diagnostic_errors.append(dict(artifact=name, error_class=type(error).__name__))
            return False
    try:
        h.require(not result_preexisted, "result namespace already exists")
        h.require(0 < timeout <= 300 and command, "child timeout/command budget")
        h.require(Path(command[0]).is_absolute() and digest(command[0]) == child_sha, "child executable changed")
        c = h.context_read(context, context_sha, p, profile_sha)
        boot = h.guard(p, c["boot_id"])
        help_text = h.shell(p, "svc power --help 2>&1")
        h.require(re.search(r"svc power stayon \[[^\]\n]*\b" + re.escape(plug_kind) + r"\b[^\]\n]*\]", help_text),
                  "installed configured stay-awake API not advertised")
        prior = setting(h, p)
        h.save(base / "prior-setting.json", dict(boot_id=boot, setting=KEY, prior=prior,
               prior_power=power(h, p), svc_help_sha256=hashlib.sha256(help_text.encode()).hexdigest()))
        h.save(base / "apply-intent.json", dict(boot_id=boot, requested_plug_kind=plug_kind, requested_setting_value=wanted, prior=prior))
        attempted = True  # An ambiguous svc timeout still requires guarded best-effort restoration.
        h.shell(p, remote_guard(p, boot) + " && svc power stayon " + plug_kind)
        h.require(setting(h, p) == dict(present=True, value=wanted), "configured stay-awake setting not observed")
        h.save(base / "apply-ack.json", dict(setting_value=wanted, plug_kind=plug_kind, boot_id=boot))
        samples = []
        def sample():
            h.guard(p, boot)
            h.require(setting(h, p) == dict(present=True, value=wanted), "external setting change during fixture")
            value = power(h, p)
            h.require(value["wakefulness"] == "Awake" and value["powered"] and value["plug_type"] == int(wanted),
                      "display not observed Awake on configured exact power kind")
            samples.append(dict(value, host_monotonic=time.monotonic()))
            h.save(base / ("power-sample-" + str(len(samples)) + ".json"), samples[-1])
        sample()
        h.save(base / "child-intent.json", dict(child_executable_sha256=child_sha,
               child_argument_count=len(command)-1, timeout_seconds=timeout, raw_output_retained=False))
        thread = threading.Thread(target=child, args=(command, timeout, cancel, holder))
        thread.start()
        while thread.is_alive():
            thread.join(timeout=5)
            if thread.is_alive():
                sample()
        h.require("result" in holder, "child result missing")
        write_diagnostic("child-result.json", holder["result"])
        sample()
        h.require(holder["result"]["exit_code"] == 0 and not holder["result"]["timed_out"]
                  and not holder["result"]["cancelled"] and holder["result"]["direct_child_reaped"],
                  "finite child did not complete")
        result.update(status="child_completed_pending_restoration", android_boot_id=boot,
                      sampled_awake_power_observations=len(samples), continuous_awake_proven=False,
                      keyguard_or_application_foreground_queried=False)
    except BaseException as error:
        result["error_class"] = type(error).__name__
    finally:
        # Setting restoration is an independent outer finally: neither optional
        # persistence nor child cleanup bookkeeping may skip it.
        try:
            cancel.set()
            if thread is not None:
                thread.join(timeout=6)
            if "result" in holder:
                result["child"] = holder["result"]
                write_diagnostic("child-result.json", holder["result"])
            if thread is not None and (thread.is_alive() or not holder.get("result", {}).get("direct_child_reaped")):
                result["child_cleanup_incomplete"] = True
        except BaseException as error:
            result["child_cleanup_error_class"] = type(error).__name__
        finally:
            try:
                if attempted and prior is not None:
                    result.update(restore(h, p, boot, prior, base, write_diagnostic))
            except BaseException as error:
                result["restoration_error_class"] = type(error).__name__
        if (result["status"] == "child_completed_pending_restoration" and result["setting_restored"]
                and not diagnostic_errors and not result.get("child_cleanup_incomplete")
                and "child_cleanup_error_class" not in result):
            result["status"] = "finite_child_completed_exact_setting_restored"
        else:
            result["status"] = "needs_diagnosis"
        result["diagnostic_write_errors"] = diagnostic_errors
        if not result_preexisted and not write_diagnostic("result.json", result):
            # Cleanup was already attempted. A failed final receipt cannot be
            # accepted as success, even if bytes were written before fsync failed.
            result["status"] = "needs_diagnosis"
            try:
                path = base / "result.json"
                failed_to_create = diagnostic_errors[-1]["error_class"] == "FileExistsError"
                if not failed_to_create and path.is_file() and not path.is_symlink():
                    path.unlink()
            except OSError:
                pass
    return 0 if result["status"] == "finite_child_completed_exact_setting_restored" else 2


def prepare(input_path, case, helper):
    if Path(input_path).stat().st_size > 65536 or digest(helper) != HELPER_SHA:
        raise RuntimeError("preparation input/helper guard")
    value = json.loads(Path(input_path).read_text())
    if digest(value["adb"]["path"]) != value["adb"]["sha256"] or case.exists():
        raise RuntimeError("fresh namespace/pinned ADB required")
    spec = importlib.util.spec_from_file_location("reviewed_prepare_helpers", helper)
    h = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(h)
    h.require(value["schema_version"] == 1 and value["kind"] == "normal_power_stay_awake",
              "wrong preparation profile")
    configured_plug(value)
    case.mkdir(mode=0o700)
    (case / "controller.py").write_bytes(Path(__file__).read_bytes())
    (case / "helper.py").write_bytes(Path(helper).read_bytes())
    value.update(case_id=uuid.uuid4().hex, controller=h.pin(case / "controller.py"),
                 helper=h.pin(case / "helper.py"))
    h.save(case / "profile.json", value)
    h.save(case / "preparation.json", dict(schema_version=1, status="prepared_not_executed",
           profile=h.pin(case / "profile.json"), source_input=h.pin(input_path),
           device_contacted=False, firmware_written=False, expected_boot_id=None))
    return h.pin(case / "profile.json")


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    p = sub.add_parser("prepare")
    p.add_argument("input", type=Path)
    p.add_argument("new_case", type=Path)
    p.add_argument("reviewed_helper", type=Path)
    for name in ("capture-context", "run"):
        p = sub.add_parser(name)
        p.add_argument("profile", type=Path)
        p.add_argument("profile_sha256")
        p.add_argument("context", type=Path)
        if name == "run":
            p.add_argument("context_sha256")
            p.add_argument("child_sha256")
            p.add_argument("timeout", type=float)
            p.add_argument("command", nargs=argparse.REMAINDER)
    a = parser.parse_args()
    def interrupted(signum, frame):
        raise InterruptedError("fixture interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    if a.mode == "prepare":
        print(json.dumps(prepare(a.input.absolute(), a.new_case.absolute(), a.reviewed_helper.absolute())))
        return 0
    if a.mode == "capture-context":
        capture(a.profile, a.profile_sha256, a.context)
        return 0
    command = a.command[1:] if a.command[:1] == ["--"] else a.command
    return run(a.profile, a.profile_sha256, a.context, a.context_sha256,
               command, a.child_sha256, a.timeout)


if __name__ == "__main__":
    raise SystemExit(main())
