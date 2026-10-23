# Flashing TB710FU with LTBox

Use LTBox's **Advanced → Simple Firmware Flasher** with a folder exported for
your tablet. This stays in EDL/9008 and writes the nine prepared slot-A images.
The Rust tools still handle device readback, partition mapping and AVB preparation.

These instructions were checked against [LTBox v3.3.5](https://github.com/miner7222/LTBox/releases/tag/v3.3.5)
(source `df92912da8aa8df5205395eb633406b3cb9d90b2`). The LTBox route has
**not been tested on a physical tablet**. Its source has been reviewed and the
export/verification helpers have offline tests. Use the regular
[EDL installer](INSTALL.md) if you want per-write digest checks and a separate reset.

LTBox differs from our installer: after flashing, it selects bootable **UFS LUN 1**
and resets the tablet automatically. It does not perform our per-write SHA-256
checks or keep our flash journal. The verification step below checks the final
images afterward; it cannot prevent that first automatic reset.

## 1. Install LTBox and make a backup

Download LTBox from the [upstream release page](https://github.com/miner7222/LTBox/releases/tag/v3.3.5)
and compare its archive's SHA-256 with the matching `.sha256` asset.

| Host | Download and launch |
| --- | --- |
| Windows x64 | Extract `LTBox-win_x86_64-v3.3.5.zip` and run `ltbox.exe`. Use the arm64 ZIP for Windows on ARM. |
| Linux | Extract the matching x86_64/arm64 archive, or install the matching DEB/RPM package. Launch `ltbox`. |
| macOS | Extract `LTBox-macos_universal-v3.3.5.tar.gz` and launch the supplied application. |

Follow LTBox's [USB and platform setup instructions](https://miner7222.github.io/ltbox/en/index.html).
Use the matching stock TB710FU `xbl_s_devprg_ns.melf` programmer described in
[Before starting](INSTALL.md#before-starting). LTBox does not make a mismatched
programmer, firmware base or signing chain compatible.

This ROM supports **TB710FU**, SM8650Q, with the Android 16 global base
`ZUI_17.5.04.059_260327_ROW` / `BP2A.250605.031.A3` and active slot A.
Check the model code, not just the tablet's retail name.

Before changing anything:

1. Back up personal files and retain your complete matching stock firmware.
2. Enter EDL using your tested hardware procedure. Connect only this tablet;
   LTBox should see Qualcomm 9008, USB ID `05c6:9008`.
3. In **Advanced → Dump Partitions**, read and save the original physical
   partitions needed for recovery. At minimum, retain `super`, `boot_a`,
   `init_boot_a`, `vendor_boot_a`, `vbmeta_system_a` and `vbmeta_a`; this minimum
   set is not a complete device backup.
4. For a complete raw storage backup, **Advanced → Dump Physical Storage** can
   dump the reported LUNs. Save all of them, not only LUN 0. Allow space for their
   full reported sizes, including userdata; a full dump can exceed 100 GB.
5. Keep backups private and on another disk. They can contain account data,
   encryption material and device-specific calibration. Do not upload them.

LTBox's dump operations may reset the device when they finish. Re-enter EDL if
needed. **Close LTBox before using our command-line tools** so only one program
owns the USB connection. Do not run both clients at once.

## 2. Prepare images for your tablet

Follow steps [1](INSTALL.md#1-read-the-tablet-identity) and
[2](INSTALL.md#2-prepare-local-images) of the EDL installation guide, using the
current project source. Stop after `prepare` succeeds; do not run `flash`.

This reads your UFS serial, GPT/LP mapping and original AVB images, verifies the
release archives, then prepares `work/images/`. Root vbmeta, system vbmeta and
boot each retain their own device-read rollback value. Values are not incremented.
Protected rollback floors remain unknown.

**Do not send the downloaded `.img.gz` files or zero-index templates directly
to LTBox.** Do not use LTBox's rollback modification, region conversion, rooting
or vbmeta rebuilding tools on these prepared images.

## 3. Export the LTBox folder

Keep the same tablet connected in EDL and LTBox closed. From the project source,
on Linux or macOS:

```sh
./scripts/install/install.sh export-ltbox \
  --work /path/to/new-install-work --serial YOUR_UFS_SERIAL \
  --edl-client /path/to/edl-host \
  --loader /path/to/stock/xbl_s_devprg_ns.melf \
  --python /path/to/edl-python/bin/python
```

On Windows, in Command Prompt:

```bat
scripts\install\install.cmd export-ltbox ^
  --work "C:\ROM\new-install-work" --serial YOUR_UFS_SERIAL ^
  --edl-client "C:\Tools\edl-host" ^
  --loader "C:\Stock\xbl_s_devprg_ns.melf" ^
  --python "C:\Tools\edl-python\Scripts\python.exe"
```

Export rechecks image hashes, the device identity, its GPT/LP mapping and the
original AVB readbacks. It writes host files only; it does not flash or reset.
The new folder is `new-install-work/ltbox/`:

```text
ltbox/
  rawprogram_googlebookos.xml
  xbl_s_devprg_ns.melf
  LTBOX_PLAN.json
  IMAGES_SHA256SUMS
  system.img
  product.img
  system_ext.img
  vendor.img
  boot.img
  init_boot.img
  vendor_boot.img
  vbmeta_system.img
  vbmeta.img
```

The single rawprogram contains exactly nine writes, in the order shown below.
Logical partition addresses come from **this tablet's** LP metadata inside
`super`. No full `super.img`, GPT image, erase entry or patch XML is needed.

| Prepared image | Destination |
| --- | --- |
| `system.img` | `system_a` extent inside `super` |
| `product.img` | `product_a` extent inside `super` |
| `system_ext.img` | `system_ext_a` extent inside `super` |
| `vendor.img` | `vendor_a` extent inside `super` |
| `boot.img` | `boot_a` |
| `init_boot.img` | `init_boot_a` |
| `vendor_boot.img` | `vendor_boot_a` |
| `vbmeta_system.img` | `vbmeta_system_a` |
| `vbmeta.img` | `vbmeta_a` |

Review `LTBOX_PLAN.json` against `install-plan.json`: UFS serial, image hashes,
LUNs, sector counts and start sectors must match. Do not edit the XML or images,
add stock XMLs, rename files or combine folders from different preparations.
LTBox can skip a missing image rather than fail the whole job.

Images are hardlinked when possible to avoid another large copy. Keep the work
folder intact and do not modify its original images. The export, programmer and
rollback values are local prerequisites for **your tablet only**; do not publish
or reuse the folder on another device.

Export records `ltbox-handoff.json` and blocks the native `flash --execute`
command for that work directory. This prevents accidentally replaying a plan
after an external flash. If you change routes, prepare a fresh work directory
from the device's actual state; do not remove the marker to bypass this guard.

## 4. Flash in LTBox

1. Keep the same tablet in EDL. Let the export command finish before opening LTBox.
2. Open **Advanced → Simple Firmware Flasher**. Use this advanced action, not the
   main **Flash Firmware** wizard, which can perform additional image processing.
3. Select **only** the generated `new-install-work/ltbox/` folder. It already
   contains the matching programmer and one `rawprogram*.xml` file. Do not choose
   the downloaded release folder or a stock firmware folder.
4. Review the confirmation page. In v3.3.5, region editing and rollback modification
   are off; region, target and data outcome may say “unknown”. Those labels do
   not replace the model/base and nine-range checks made during preparation.
5. Start the flash only after checking the tablet and folder. Keep USB and host
   power connected until it finishes. The XML has no userdata/metadata erase,
   GPT/LP rewrite, bootloader firmware write or slot-B write.
6. Save the LTBox log. Confirm it attempted all nine images and reported no missing
   image, skipped image, failed transfer or disconnect. LTBox then selects
   bootable UFS LUN 1 and automatically resets the tablet.

If it fails, stop. Do not repeatedly press Start, mix in stock vbmeta images or
use a whole-LUN restore as a shortcut. Keep the exported folder, backups and log
for diagnosis. LTBox may return a failed session to EDL automatically.

## 5. Verify the installed images

After LTBox finishes, put the same tablet back in EDL and **close LTBox**.
Run one read-only verification pass:

```sh
./scripts/install/install.sh verify-ltbox \
  --work /path/to/new-install-work --serial YOUR_UFS_SERIAL \
  --edl-client /path/to/edl-host \
  --loader /path/to/stock/xbl_s_devprg_ns.melf \
  --python /path/to/edl-python/bin/python
```

On Windows, use `scripts\install\install.cmd verify-ltbox` with the same options
and Windows paths shown in the export command.

Verification rechecks the device and GPT/LP layout, then requests one device-side
SHA-256 digest for each of the nine written ranges. It records results in
`ltbox-verification.json`, stops at a mismatch and sends no write or reset.
Success means all nine device images match your prepared plan; it does not prove
that setup, desktop or hardware works. It does not create a native flash journal.

Once verification passes, use LTBox's **Reboot** action when ready to leave EDL.
For a clean install, enter matching stock recovery and factory-reset after
backing up personal data. That reset erases user data. Follow
[First boot](INSTALL.md#4-reset-and-first-boot) for setup and the main-user caveat;
the native installer's `reset` command is reserved for its own verified journal.
Read [known issues](KNOWN_ISSUES.md), including Terminal's 2 GiB policy and the
lack of a port OTA channel.

## Source references

The menu names, folder format and reset behavior above were checked against:

- [Simple Firmware Flasher worker](https://github.com/miner7222/LTBox/blob/df92912da8aa8df5205395eb633406b3cb9d90b2/crates/ltbox-gui/src/workers/flash/simple.rs).
- [Rawprogram selection](https://github.com/miner7222/LTBox/blob/df92912da8aa8df5205395eb633406b3cb9d90b2/crates/ltbox-device/src/edl/firmware_xml.rs) and
  [sector writes](https://github.com/miner7222/LTBox/blob/df92912da8aa8df5205395eb633406b3cb9d90b2/crates/ltbox-device/src/edl/rawprogram.rs).
- [EDL session and bootable-LUN handling](https://github.com/miner7222/LTBox/blob/df92912da8aa8df5205395eb633406b3cb9d90b2/crates/ltbox-device/src/edl.rs).

If a newer LTBox release changes this workflow, check its source and release notes
before using it with a device-specific export.
