# TB710FU Alpha 1 — EDL installation

Installation uses **Qualcomm EDL/9008 only**, following the readback, sector-write
and device-digest method used for this port. There is no fastboot install path.
Release images are zero-index AVB templates: **do not flash them directly**.
The installer first prepares signed copies using your tablet's own indices.

Supported hardware: Lenovo **TB710FU**, SM8650Q, 8 GB RAM, Android 16 global base
`ZUI_17.5.04.059_260327_ROW` / `BP2A.250605.031.A3`. Its retained boot AVB
fingerprint identifies the inherited Android 15 kernel build; this is expected.
Other models, stock bases, active slot B and altered partition layouts are refused.
Clean installation on a second tablet has not been tested.

## Before starting

Keep a complete backup of your tablet's stock partitions and a tested EDL recovery
method. The installer's GPT, logical-partition metadata and three AVB readbacks
are **not** a complete stock backup. Back up personal data separately: a clean
installation requires a factory reset in matching stock recovery afterward.

EDL writing and bootloader signature acceptance are separate requirements.
The development unit boots these development-signed images with its bootloader
locked; this does not establish acceptance on another tablet or firmware version.
The installer does not unlock/relock, change bootloader state, bypass authentication
or change protected rollback storage. Stop if your device cannot run the stock
programmer or accept the configured signing chain.

Required host tools:

- Rust stable 1.88 or newer with the host's native C linker/build prerequisites.
- Git, Python 3 and OpenSSL on PATH.
- A clean [bkerler/edl](https://github.com/bkerler/edl) checkout at
  `2f8e89a848afaaef68997fcbcb5b178d958d497b`, with its Python dependencies installed.
- libusb-1.0 and USB permissions/driver for **05c6:9008**.
- Your stock `xbl_s_devprg_ns.melf` programmer, SHA-256
  `87f8f12681b556258a5c30df95595d4b9fa624e34f0181f25840fdb80b208dc5`.
  Obtain it from your matching stock firmware; it is not bundled or auto-downloaded.
- Matching AOSP development reference keys, obtained separately from the
  [AVB test-data directory](https://android.googlesource.com/platform/external/avb/+/refs/tags/android-16.0.0_r1/test/data/):
  `testkey_rsa4096.pem` for root/boot and `testkey_rsa2048.pem` for system vbmeta.
  These are public development keys, not OEM release credentials. Configured keys
  must match the templates; arbitrary replacement keys are rejected.
- At least 15 GB free space beyond the downloaded assets.

Check out the EDL client **outside this source checkout**, for example:

```sh
git clone https://github.com/bkerler/edl.git edl-host
git -C edl-host checkout 2f8e89a848afaaef68997fcbcb5b178d958d497b
python3 -m venv edl-python
edl-python/bin/python -m pip install -r edl-host/requirements.txt
```

On Windows use `python -m venv edl-python` and
`edl-python\Scripts\python.exe -m pip install -r edl-host\requirements.txt`.
A dedicated virtual environment prevents dependency conflicts. Optional Capstone
or Keystone warnings are not firmware failures.

On Linux, install your distribution's libusb package and grant your user access
to 05c6:9008 using a restricted udev rule; replug after applying it. On macOS,
install libusb, for example with Homebrew. Windows needs the EDL client's supported
libusb driver for the **9008 interface**; follow its driver instructions, taking
care to select the tablet's interface. `--libusb` can name a full DLL/dylib/shared
library path if automatic library discovery fails. Native Windows/macOS USB
installation has not yet been physically qualified.

## 1. Read the tablet identity

Download all release assets, verify `SHA256SUMS`, and extract
`installer-source.zip`. Leave the `.img.gz` files compressed.

Put your TB710FU in EDL using your tested hardware procedure. Disconnect other
EDL devices. The installer requires exactly one 05c6:9008 device before uploading
the matching programmer into RAM. No device firmware is written by `probe`.

Linux/macOS, from the extracted source:

```sh
./scripts/install/install.sh probe \
  --edl-client /path/to/edl-host \
  --loader /path/to/stock/xbl_s_devprg_ns.melf \
  --python /path/to/edl-python/bin/python
```

Windows Command Prompt:

```bat
scripts\install\install.cmd probe ^
  --edl-client "C:\Tools\edl-host" ^
  --loader "C:\Stock\xbl_s_devprg_ns.melf" ^
  --python "C:\Tools\edl-python\Scripts\python.exe"
```

Record the returned **UFS storage serial**. It is not the ADB serial and is not
shared between tablets. Every subsequent EDL operation checks it again before
reading, writing or resetting. Device identification also checks the read-back
signed boot fingerprint and the retained AVB chain; it is not OEM attestation.

## 2. Prepare local images

Linux/macOS:

```sh
./scripts/install/install.sh prepare \
  --package /path/to/downloaded-release \
  --work /path/to/new-install-work \
  --serial YOUR_UFS_SERIAL \
  --edl-client /path/to/edl-host \
  --loader /path/to/stock/xbl_s_devprg_ns.melf \
  --python /path/to/edl-python/bin/python \
  --root-key /path/to/testkey_rsa4096.pem \
  --system-key /path/to/testkey_rsa2048.pem \
  --avbtool third_party/avb/avbtool.py
```

Windows Command Prompt:

```bat
scripts\install\install.cmd prepare ^
  --package "C:\ROM\download" ^
  --work "C:\ROM\new-install-work" ^
  --serial YOUR_UFS_SERIAL ^
  --edl-client "C:\Tools\edl-host" ^
  --loader "C:\Stock\xbl_s_devprg_ns.melf" ^
  --python "C:\Tools\edl-python\Scripts\python.exe" ^
  --root-key "C:\Keys\testkey_rsa4096.pem" ^
  --system-key "C:\Keys\testkey_rsa2048.pem" ^
  --avbtool third_party\avb\avbtool.py
```

The launchers build the current Rust installer, or use a matching binary placed
beside them. `install.ps1` is also available. Neither WSL nor a Linux VM is needed
by the Windows launcher.

Preparation reads primary and backup GPTs, validates CRCs, checks active slot A,
and validates the matching primary/backup LP metadata copies. It obtains logical
partition extents from **your tablet**, not development-unit sector addresses.
Fragmented extents, snapshot/update flags, differing metadata slots or unexpected
sizes stop preparation. No GPT, LP metadata or partition resize is performed.

It reads `vbmeta_a`, `vbmeta_system_a` and `boot_a`, verifies their signatures and
chain bindings, then copies each image's own rollback value separately at its
original chain location. It does not add one or import a release-wide value.
AOSP avbtool signs local copies; payload bytes, descriptors, keys, flags and
locations are checked. Original readbacks remain in `device-backup/`.

These are **image-declared indices**, not measurements of protected rollback
floors. Those floors remain unknown. Already committed increases cannot be undone
by this installer. See [AOSP AVB rollback protection](https://android.googlesource.com/platform/external/avb/+/refs/heads/main/README.md#Rollback-Protection).

Preparation performs no persistent writes and sends no reset. Per-device values
stay in the local work directory; do not publish that directory.

## 3. Review, write and verify

Review `install-plan.json`: UFS identity, readback hashes, rollback locations,
physical ranges and nine output images. Preview without contacting USB:

```sh
./scripts/install/install.sh flash \
  --work /path/to/new-install-work --serial YOUR_UFS_SERIAL
```

When ready, add transport options and `--execute`:

```sh
./scripts/install/install.sh flash \
  --work /path/to/new-install-work --serial YOUR_UFS_SERIAL \
  --edl-client /path/to/edl-host \
  --loader /path/to/stock/xbl_s_devprg_ns.melf \
  --python /path/to/edl-python/bin/python --execute
```

Windows uses `scripts\install\install.cmd flash` with the same options and Windows
paths. Execution checks tools, image hashes, current GPT/LP and AVB readbacks
before asking you to type `FLASH YOUR_UFS_SERIAL`.

The installer writes `system_a`, `product_a`, `system_ext_a`, `vendor_a`, `boot_a`,
`init_boot_a`, `vendor_boot_a`, `vbmeta_system_a` and `vbmeta_a` in that order.
Each write needs Firehose acknowledgement and one matching **device-side
SHA-256 digest** before the next write. There is no full-super rewrite or
repeated multi-gigabyte preflight readback.

Stock recovery, DTBO, ODM, module partitions, pvmfw, modem, bootloader,
calibration/persist, metadata, userdata and every slot-B partition are preserved.
The installer records each pending range before sending it in
`flash-journal.json`. A failure leaves that pending entry for diagnosis and
stops further writes. It never automatically retries a partial installation,
restores stock or resets after failure. Keep the device in EDL and inspect the
journal before using your tested recovery procedure.

## 4. Reset and first boot

After every write passes its digest, the tablet remains in EDL. Reset is separate:

```sh
./scripts/install/install.sh reset \
  --work /path/to/new-install-work --serial YOUR_UFS_SERIAL \
  --edl-client /path/to/edl-host \
  --loader /path/to/stock/xbl_s_devprg_ns.melf \
  --python /path/to/edl-python/bin/python
```

The reset command requires this plan's completed verified flash journal.
For a clean install, use matching stock recovery to factory-reset after backing
up personal data. Formatting is manual and destructive; it is not part of the
installer. Complete setup normally. Terminal receives 2 GiB even if its menu
shows 4 GB. Read `KNOWN_ISSUES.md`; do not install donor hardware OTAs.

If an EDL reset starts only the headless system user, authenticated ADB can
select the existing main user before the owner's normal unlock:

```sh
adb -s SERIAL shell cmd user get-main-user
adb -s SERIAL shell am switch-user MAIN_USER_ID
```

For recovery, restore a complete compatible stock image set from your own backup,
subject to the device's actual rollback state. Do not mix unrelated boot/vbmeta
images. Successful EDL writes and hashes do not prove boot or hardware operation.
