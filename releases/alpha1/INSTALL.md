# TB710FU Alpha 1 installation

The installer prepares AVB metadata for the connected tablet. Release images are
zero-index templates and must not be flashed directly. The development tablet's
rollback values are not a release requirement.

This build targets Lenovo **TB710FU**, Qualcomm SM8650Q, 8 GB RAM, with Android 16
base `ZUI_17.5.04.059_260327_ROW` / `BP2A.250605.031.A3`. Other models and bases are
unsupported. Clean installation on a second tablet remains untested.

## Requirements

- An unlocked bootloader and working fastboot/fastbootd partition readback.
- Your own complete stock firmware backup and an independently tested recovery
  method. The installer's three AVB readbacks are not a complete stock backup.
- Rust stable 1.88 or newer, Python 3, OpenSSL on PATH, and Android platform-tools.
- On Windows, the appropriate USB driver and Rust's native build prerequisites.
- Separately obtained, authorized development signing keys matching the template
  public keys. No private signing keys or EDL programmer are distributed here.
- Approximately 15 GB of free host space, in addition to the downloaded assets.

Linux and macOS use `scripts/install/install.sh`. Windows uses
`scripts\install\install.cmd` or the PowerShell launcher alongside it. The
launchers build the Rust installer when a matching local binary is unavailable.
Windows and macOS launchers do not require WSL or a Linux VM. Native USB flashing
has not yet been qualified on those hosts.

The Alpha 1 template keys are the public AOSP AVB development reference keys.
Their source is the [AOSP AVB test-data directory](https://android.googlesource.com/platform/external/avb/+/refs/tags/android-16.0.0_r1/test/data/)
(`testkey_rsa4096.pem` and `testkey_rsa2048.pem`). They are development keys,
not OEM release credentials. The installer checks that the selected keys match
the templates; it does not replace the chain with arbitrary keys.

## Download and prepare

Download all assets from the published release into one directory. Check the
release's `SHA256SUMS` before using the package. Keep the `.img.gz` files
compressed; the installer verifies and extracts them into a new work directory.
A source announcement or GitHub draft is not a published firmware download.

Put the tablet in fastboot/fastbootd with slot A active. The installer accepts
only a device reporting product `TB710FU`, an unlocked bootloader and slot A.
It refuses ambiguous identity, unsupported readback and incompatible retained
AVB descriptors. If the bootloader reports a generic product instead, stop;
a verified device-identification adapter is required before installation.

On Linux or macOS, from the source checkout:

```sh
./scripts/install/install.sh prepare \
  --package /path/to/downloaded-release \
  --work /path/to/new-install-work \
  --serial YOUR_FASTBOOT_SERIAL \
  --root-key /path/to/authorized-rsa4096.pem \
  --system-key /path/to/authorized-rsa2048.pem \
  --avbtool third_party/avb/avbtool.py
```

On Windows, in Command Prompt:

```bat
scripts\install\install.cmd prepare ^
  --package "C:\ROM\download" ^
  --work "C:\ROM\new-install-work" ^
  --serial YOUR_FASTBOOT_SERIAL ^
  --root-key "C:\Keys\authorized-rsa4096.pem" ^
  --system-key "C:\Keys\authorized-rsa2048.pem" ^
  --avbtool third_party\avb\avbtool.py ^
  --python python
```

Preparation reads `vbmeta_a`, `vbmeta_system_a` and `boot_a` from that tablet.
It copies each image's own rollback value separately, using the root chain's
location mapping. It does not add one, substitute a release-wide number, or
write rollback storage. Values and readback hashes stay in the local work
folder. Unknown values cause preparation to stop.

The pinned AOSP `avbtool.py` re-signs copies of the three template containers.
OpenSSL verifies signatures; the installer checks unchanged payload bytes,
descriptors, public keys, AVB flags and locations. Firmware inputs and original
readbacks remain intact. Preparation does not flash or reboot the device.

These are **image-declared indices**, not a readout of protected rollback
storage. The protected floors remain unknown. Standard fastboot has no universal
command for reading them, and many devices cannot fetch these partitions.
An unsupported readback is a blocker, not permission to guess. Already committed
rollback increases cannot be undone by this installer. See the
[AOSP AVB rollback documentation](https://android.googlesource.com/platform/external/avb/+/refs/heads/main/README.md#Rollback-Protection).

## Review and flash

Review `install-plan.json`, particularly the device serial, rollback locations,
readback hashes and nine output images. Preview the commands first:

```sh
./scripts/install/install.sh flash \
  --work /path/to/new-install-work --serial YOUR_FASTBOOT_SERIAL
```

On Windows, use `scripts\install\install.cmd flash` with the same arguments.
This preview performs no device operations. Add `--execute` only when ready to
write. The installer rechecks the device and image integrity and asks you to
type `FLASH YOUR_FASTBOOT_SERIAL` before writing anything.

The plan writes `system_a`, `product_a`, `system_ext_a`, `vendor_a`, `boot_a`,
`init_boot_a`, `vendor_boot_a`, `vbmeta_system_a` and `vbmeta_a`. It preserves
stock recovery, DTBO, ODM, module partitions, pvmfw, modem, bootloader,
calibration/persist, metadata and every slot B partition. Partition resizing is
not automatic. A size mismatch blocks installation.

The installer records progress in `flash-journal.json`. A failed command stops
the process; it does not reboot a partial installation or blindly replay a
previous attempt. Inspect the journal and use your tested recovery procedure.

## First boot

After a complete write, the tablet remains in bootloader fastboot. A clean
installation requires a factory reset through matching stock recovery after
backing up personal data. The installer does not format userdata, unlock or
relock the bootloader, disable verification, or reboot automatically to Android.

Complete setup normally. Terminal receives 2 GiB RAM even if its menu shows 4 GB.
Read `KNOWN_ISSUES.md`; do not install donor hardware OTAs.

If an EDL reset starts only the headless system user, authenticated ADB can
select the existing main user, followed by the owner's normal unlock:

```sh
adb -s SERIAL shell cmd user get-main-user
adb -s SERIAL shell am switch-user MAIN_USER_ID
```

For recovery, restore a complete, compatible stock image set from your own
backup, subject to the device's actual rollback state. Do not restore unrelated
individual vbmeta or boot images.
