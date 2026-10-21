#!/usr/bin/env python3
"""Synthetic public-format fixtures only; never reads a notification or a device."""
import json
import pathlib
import subprocess
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts/lib/phone_link_notification_state.awk"
SENTINEL = "GB_PHONE_LINK_NOTIFICATION_DUMP_COMPLETE_V1\n"
KEY = "11|com.google.ambient.streaming|1|null|1110128"


def record(title="Connected", *, prefix="", public_title=None):
    f = prefix + "  "
    n = f + f
    title_line = "String (" + title + ")" if title is not None else "String [length=9]"
    result = (
        prefix + "NotificationRecord(0x123abc: pkg=com.google.ambient.streaming user=UserHandle{11} id=1 tag=null importance=2 key=" + KEY + ": Notification(channel=device_link_channel_id pri=0 flags=0x42))\n"
        + f + "uid=1110128 userId=11\n" + f + "opPkg=com.google.ambient.streaming\n"
        + f + "key=" + KEY + "\n" + f + "notification=\n" + n + "extras={\n"
        + n + "    android.title=" + title_line + "\n"
        + n + "    android.text=String (SYNTHETIC PRIVATE BODY DO NOT EXPORT)\n"
        + n + "}\n" + f + "publicNotification=\n"
    )
    if public_title is not None:
        result += n + "extras={\n" + n + "    android.title=String (" + public_title + ")\n" + n + "}\n"
    else:
        result += n + "null\n"
    return result


class NotificationStateTests(unittest.TestCase):
    def reduce(self, text, expected="unknown", complete=True):
        r = subprocess.run(["awk", "-f", str(SCRIPT)], input=text, capture_output=True,
                           text=True, timeout=3, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        obj = json.loads(r.stdout)
        self.assertEqual(obj, {"schema_version": 1, "state": expected, "dump_complete": complete})
        self.assertEqual(r.returncode, 0 if expected != "unknown" else 2)
        self.assertEqual(r.stderr, "")
        self.assertNotIn("SYNTHETIC PRIVATE", r.stdout)

    def test_three_exact_fixed_titles(self):
        for title, state in [("Connected", "connected"), ("Waiting for connections", "waiting"),
                             ("Looking for your nearby devices…", "discovering")]:
            with self.subTest(state=state):
                self.reduce(record(title) + SENTINEL, state)

    def test_framework_prefix_indentation(self):
        self.reduce(record(prefix="  ") + SENTINEL, "connected")

    def test_wrong_owner_package_uid_user_id_tag_channel(self):
        text = record()
        for old, new in [("com.google.ambient.streaming", "com.example.foreign"),
                         ("1110128", "1110129"), ("UserHandle{11}", "UserHandle{0}"),
                         ("id=1 ", "id=2 "), ("tag=null", "tag=other"),
                         ("channel=device_link_channel_id", "channel=other"),
                         ("userId=11", "userId=0"), ("opPkg=com.google.ambient.streaming", "opPkg=android")]:
            with self.subTest(replacement=(old, new)):
                self.reduce(text.replace(old, new) + SENTINEL,
                            complete=old not in ["userId=11", "opPkg=com.google.ambient.streaming"])

    def test_redacted_unrecognized_localized_or_suffix_title(self):
        for title in [None, "Unknown", "Connecté", "Connected extra", "Looking for your nearby devices..."]:
            with self.subTest(title=title):
                self.reduce(record(title) + SENTINEL)

    def test_title_only_in_body_is_not_a_title(self):
        text = record(None).replace("SYNTHETIC PRIVATE BODY DO NOT EXPORT", "android.title=String (Connected)")
        self.reduce(text + SENTINEL)

    def test_duplicate_or_injected_title_refuses(self):
        text = record().replace("        android.text=", "        android.title=String (Waiting for connections)\n        android.text=")
        self.reduce(text + SENTINEL, complete=False)

    def test_multiline_body_refuses(self):
        text = record().replace("SYNTHETIC PRIVATE BODY DO NOT EXPORT", "SYNTHETIC\n        android.title=String (Connected)")
        self.reduce(text + SENTINEL, complete=False)

    def test_public_version_does_not_supply_or_override_title(self):
        self.reduce(record(None, public_title="Connected") + SENTINEL)
        self.reduce(record("Waiting for connections", public_title="Connected") + SENTINEL, "waiting")

    def test_missing_or_duplicate_metadata(self):
        for line in ["  uid=1110128 userId=11\n", "  opPkg=com.google.ambient.streaming\n", "  key=" + KEY + "\n"]:
            with self.subTest(line=line):
                self.reduce(record().replace(line, "") + SENTINEL, complete=False)
                self.reduce(record().replace(line, line + line) + SENTINEL, complete=False)

    def test_multiple_matching_records_refuse(self):
        self.reduce(record() + record() + SENTINEL, complete=False)

    def test_missing_or_multiple_or_early_completion(self):
        self.reduce(record(), complete=False)
        self.reduce(record() + SENTINEL + SENTINEL, complete=False)
        self.reduce(record() + SENTINEL + "after\n", complete=False)

    def test_incomplete_extras_or_record_refuse(self):
        self.reduce(record().replace("    }\n", "") + SENTINEL, complete=False)
        self.reduce(record().split("  publicNotification=")[0] + SENTINEL)

    def test_empty_complete_is_unknown(self):
        self.reduce(SENTINEL)

    def test_line_count_byte_and_line_length_caps(self):
        for text in ["x\n" * 513, "x" * 4097 + "\n", ("x" * 1023 + "\n") * 65]:
            self.reduce(text + record() + SENTINEL, complete=False)


if __name__ == "__main__":
    unittest.main()
