#!/usr/bin/env bash
# Host-only USB permission repair. Does not send any commands to the tablet.
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ "$EUID" -ne 0 ]]; then
  exec sudo -- bash "$script_dir/fix-lenovo-adb.sh"
fi
rule_path=/etc/udev/rules.d/70-lenovo-yoga-adb.rules
if [[ -e "$rule_path" ]] && ! cmp -s "$script_dir/70-lenovo-yoga-adb.rules" "$rule_path"; then
  printf 'Existing rule differs; refusing to overwrite: %s\n' "$rule_path" >&2
  exit 1
fi
install -m 0644 "$script_dir/70-lenovo-yoga-adb.rules" "$rule_path"
udevadm control --reload-rules
udevadm trigger --action=add --subsystem-match=usb --attr-match=idVendor=17ef --attr-match=idProduct=7f58
udevadm settle --timeout=10
printf 'Lenovo USB permissions refreshed. As your normal user, run: adb kill-server; adb start-server; adb devices -l\n'
