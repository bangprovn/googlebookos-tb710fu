#!/system/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Read role enums only. No role swaps, device descriptors, names or identifiers.
# Root overrides are for host fixtures; the Rust inspector still requires UID2000.
set -eu
LC_ALL=C
export LC_ALL
usb_sys_root=${GB_USB_SYSFS_ROOT:-/sys}
usb_proc_root=${GB_USB_PROCFS_ROOT:-/proc}

printf 'GB_USB_ROLE_SNAPSHOT_V1\n'
usb_uid=$(id -u)
case "$usb_uid" in ''|*[!0-9]*) exit 2;; esac
printf 'uid\t%s\n' "$usb_uid"
usb_boot=$(head -c 37 "$usb_proc_root/sys/kernel/random/boot_id" 2>/dev/null)
case "$usb_boot" in *[!0-9a-fA-F-]*) exit 2;; esac
[ "${#usb_boot}" -eq 36 ] || exit 2
printf 'boot_id\t%s\n' "$usb_boot"

usb_class() {
    if [ ! -d "$2" ]; then
        printf 'class\t%s\tmissing\n' "$1"
    elif [ ! -r "$2" ] || [ ! -x "$2" ]; then
        printf 'class\t%s\tunreadable\n' "$1"
    else
        printf 'class\t%s\tpresent\n' "$1"
    fi
}

usb_role() {
    if [ ! -f "$3" ] || [ ! -r "$3" ]; then
        usb_value=unreadable
    elif usb_value=$(head -c 129 "$3" 2>/dev/null); then
        if [ "${#usb_value}" -gt 128 ]; then
            usb_value=over_budget
        else
            # Never echo unrecognized bytes: they could contain unrelated data.
            case "$1:$usb_value" in
                usb_role:none|usb_role:host|usb_role:device) ;;
                'data_role:[host]'|'data_role:[device]'|'data_role:[host] device'|'data_role:host [device]') ;;
                'power_role:[source]'|'power_role:[sink]'|'power_role:[source] sink'|'power_role:source [sink]') ;;
                'port_type:[source]'|'port_type:[sink]'|'port_type:[source] sink dual'|'port_type:source [sink] dual'|'port_type:source sink [dual]') ;;
                *) usb_value=unrecognized;;
            esac
        fi
    else
        usb_value=unreadable
    fi
    printf 'role\t%s\t%s\t%s\n' "$1" "$2" "$usb_value"
}

usb_class usb_role "$usb_sys_root/class/usb_role"
usb_class typec "$usb_sys_root/class/typec"
usb_index=0
for usb_entry in "$usb_sys_root"/class/usb_role/*; do
    [ -d "$usb_entry" ] || continue
    if [ "$usb_index" -ge 8 ]; then printf 'limit\tusb_role\n'; break; fi
    usb_role usb_role "$usb_index" "$usb_entry/role"
    usb_index=$((usb_index + 1))
done
usb_index=0
for usb_entry in "$usb_sys_root"/class/typec/port*; do
    [ -d "$usb_entry" ] || continue
    usb_suffix=${usb_entry##*/port}
    case "$usb_suffix" in ''|*[!0-9]*) continue;; esac
    if [ "$usb_index" -ge 8 ]; then printf 'limit\ttypec\n'; break; fi
    usb_role data_role "$usb_index" "$usb_entry/data_role"
    usb_role power_role "$usb_index" "$usb_entry/power_role"
    usb_role port_type "$usb_index" "$usb_entry/port_type"
    usb_index=$((usb_index + 1))
done
# sh -s can retain its stdin after ADB finishes delivering the script. End the
# owned capture explicitly rather than waiting for transport EOF.
exit 0
