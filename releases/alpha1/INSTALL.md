# TB710FU Alpha 1 installation

This is a manual tester build for the Lenovo TB710FU with 8 GB RAM, based on
Googlebook `CL3B.260622.276.R2`. It contains the same signed image revisions used
on the working development tablet. A clean installation from stock and a second
tablet have not been tested.

## Required starting point

- Exact model **TB710FU**, Qualcomm SM8650Q / pineapple.
- Matching Android 16 vendor base:
  `ZUI_17.5.04.059_260327_ROW` / `BP2A.250605.031.A3`.
- An unlocked bootloader for the fastboot procedure below, working fastbootd,
  and an independently tested stock recovery procedure.
- A complete backup of your own stock firmware and personal files.
- Enough free host space for approximately 14 GB of images plus the downloads.

The development tablet's locked-bootloader test-key behavior is not a general
installation method. Do not assume another unit accepts these keys. EDL needs
an appropriate programmer obtained separately; no programmer or blind sector
flasher is included.

These images carry AVB rollback index **4070908801**, with flags **0**. Review
your device's rollback state before installing. A higher committed index can
prevent returning to an older stock image. Do not disable rollback checks,
change AVB flags, or relock a bootloader around this build.

## Check and unpack

Download all release assets into one directory, including the nine `.img.gz`
images, `kernel-source.tar.gz`, manifests, checksum lists and release documents.
`SHA256SUMS` covers all of them except the checksum list itself.

```sh
sha256sum -c SHA256SUMS
gzip -dk -- *.img.gz
sha256sum -c IMAGES_SHA256SUMS
```

Both checksum checks must pass. Each image is a raw partition image, not an OTA
ZIP or an Android sparse image. Do not copy an `.img.gz` file to a partition.

## Review the partition plan

The package targets **slot A only**. Confirm the active slot, stock firmware
and partition sizes independently before writing. The image sizes are recorded
in `manifest.json`; they must fit the existing partitions exactly.

Keep stock `recovery_a`, `dtbo_a`, `odm_a`, `system_dlkm_a`, `vendor_dlkm_a` and
`pvmfw_a`. Keep the modem, bootloader, calibration/persist, metadata and all slot
B partitions. The package relies on those matching stock components.

The following commands are a manual plan, not a tested installer. Replace
`SERIAL` with the fastboot serial of your tablet. Stop on any failed command,
unknown lock state, mismatched base or unexpected partition layout.

```sh
fastboot -s SERIAL getvar unlocked
fastboot -s SERIAL getvar current-slot
fastboot -s SERIAL reboot fastboot
fastboot -s SERIAL getvar is-userspace

# In fastbootd, after confirming the sizes of each logical partition:
fastboot -s SERIAL flash system_a system.img
fastboot -s SERIAL flash product_a product.img
fastboot -s SERIAL flash system_ext_a system_ext.img
fastboot -s SERIAL flash vendor_a vendor.img

fastboot -s SERIAL reboot bootloader
fastboot -s SERIAL flash boot_a boot.img
fastboot -s SERIAL flash init_boot_a init_boot.img
fastboot -s SERIAL flash vendor_boot_a vendor_boot.img
fastboot -s SERIAL flash vbmeta_system_a vbmeta_system.img
fastboot -s SERIAL flash vbmeta_a vbmeta.img
fastboot -s SERIAL --set-active=a
```

Do not reboot between partial image writes. Do not run these commands on another
model or use them to infer compatibility with another Lenovo firmware version.

## First boot and recovery

A clean installation from stock requires a factory reset, which erases personal
data. Perform that reset through the matching stock recovery after backing up;
this package does not format anything automatically. An in-place update from
an earlier port build has separate data-compatibility risks and is not covered
by the clean-install plan.

Complete Android setup normally. Terminal runs with 2 GiB RAM even if its menu
shows 4 GB. See `KNOWN_ISSUES.md` before testing Phone Link or guest graphics.
There is no supported port OTA channel; do not install donor hardware OTAs.

If an EDL reset starts only the headless system user, authenticated ADB can
select the existing main user, followed by the owner's normal unlock:

```sh
adb -s SERIAL shell cmd user get-main-user
adb -s SERIAL shell am switch-user MAIN_USER_ID
```

Do not create another user or bypass the owner's lock screen as a workaround.

For a failed boot, return to the recovery mode you tested before installation.
Restore a complete, mutually compatible stock image set from your own backup,
subject to the device's actual rollback state. Do not restore random individual
vbmeta or boot images. If recovery is unavailable or rollback compatibility is
unknown, stop before writing more partitions.
