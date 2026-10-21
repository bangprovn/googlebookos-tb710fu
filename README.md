# Googlebook OS for Lenovo TB710FU

Googlebook OS port for the Lenovo TB710FU (Qualcomm SM8650Q).
The donor is the Dell XPS Googlebook, codename `mica`.

The port brings over the Googlebook desktop and system stack while retaining
the tablet's vendor hardware support. The current build uses
`CL3B.260622.276.R2` userspace and a modified Linux 6.1 kernel from the
tablet's Android kernel tree.

This repository contains the Rust tools, device profile, kernel changes and
userspace patches. Firmware images, proprietary apps and libraries, signing
keys, and EDL programmers are not included.

## Working features

Googlebook OS boots on the tablet with the desktop, Android setup and the
original Terminal app. Camera and microphone are working in the owner's R2
installation as well.

| Feature | Status |
| --- | --- |
| Desktop and tablet interaction | Working on TB710FU. |
| Touchscreen | Working for setup and desktop interaction. |
| Android setup | Owner confirms setup completes after a factory reset on R2. |
| Camera | Owner confirms it works; both cameras passed earlier frame-delivery tests. |
| Microphone | Owner confirms it works; earlier speaker/microphone pattern tests passed. |
| Built-in speakers | Playback passed earlier device tests. |
| Wi-Fi / Internet | Validated Wi-Fi and HTTPS worked in earlier device tests. |
| Sensors | Accelerometer, gyroscope, light, game rotation, gravity and linear acceleration delivered events. |
| USB / ADB | Authenticated ADB and development transfers work. |
| Terminal / Debian VM | Boots and runs commands with 2 GiB RAM on R2. |
| Terminal after reset | Firmware maps the app's fresh 4 GiB request to 2 GiB. The menu may still show 4 GB. |

The latest memory change was checked with the original app requesting 4 GiB:
the adapter selected 2 GiB, and a command inside Debian confirmed the allocation.
Earlier hardware results have not all been repeated after the R2 factory reset.

## Known issues

- **Phone Link:** device discovery does not find the peer phone.
- **VM graphics:** GLES and limited Vulkan tests passed on earlier builds;
  broader native presentation, resizing and resume still need fixes.
- **Terminal lifecycle:** a rapid forced stop/restart can hit a resource-busy
  error until teardown finishes. Its memory menu can still display 4 GB.
- **User selection:** some EDL resets require selecting the existing main user.
- **Google services:** donor-specific Perks/serviceability is unsupported;
  Play certification is not established.
- **Updates:** there is no port OTA channel. Do not install donor hardware OTAs.

Bluetooth pairing/audio, external display, stylus and deep suspend/resume are
not fully tested. They are separate from the working features above.

Alpha 1 is being updated to use device-specific AVB preparation on the matching
Android 16 stock base.
Read the [installation plan](releases/alpha1/INSTALL.md) and
[release notes](releases/alpha1/KNOWN_ISSUES.md). Clean installation on a second
tablet has not been tested. There is no one-command port to another device.

## Build the tools

Use a Linux x86_64 host with Rust stable (minimum 1.88).

```sh
git clone https://github.com/bangprovn/googlebookos-tb710fu.git
cd googlebookos-tb710fu
cargo build --release --locked -p gb-cli
target/release/gb --help
```

Firmware processing also needs separately installed Android image tools.
Each image recipe specifies its tool paths, checksums and sandbox settings.
The project uses tools such as `avbtool`, `mkfs.erofs`, `fsck.erofs` and
`mkbootimg` rather than replacing them with custom filesystem writers.

## Install on TB710FU

The device installer has launchers for Windows, Linux and macOS:
`scripts/install/install.cmd`, `install.ps1` and `install.sh`.

Installation uses EDL/9008 only, with partition readback and device-side SHA-256
verification, following the method used for this port. It reads the connected
tablet's AVB images, uses that tablet's rollback values
separately for each chain location, and re-signs local copies before flashing.
Release templates must be personalized; do not flash them directly. A command
preview is the default, and writing requires an explicit option plus typed
confirmation. Unsupported device readback stops the process.

Read the [installation guide](releases/alpha1/INSTALL.md) for host dependencies,
keys, exact stock-base requirements and the current testing limits. The public
installer requires the matching stock programmer and an EDL-capable tablet that
accepts the configured signing chain. The development tablet boots with its
bootloader locked; other units remain unqualified. Protected rollback floors
cannot be inferred from an image header and are reported as unknown.

## Inspect firmware

Provide your own donor recovery image and stock tablet firmware. Inspection
reads the inputs without modifying them.

```sh
target/release/gb donor inspect mica-recovery.zip --out artifacts/mica.json
target/release/gb firmware inspect stock/ --out artifacts/stock.json

target/release/gb compat manifests \
  --donor artifacts/mica.json \
  --target artifacts/stock.json \
  --out artifacts/compatibility.json
```

The CLI supports ZIP, raw and Android sparse images, GPT and dynamic partition
metadata, boot images, and AVB metadata. Filesystem extraction uses configured
external tools. Unknown formats and missing requirements are reported explicitly.

Start with [the TB710FU profile](devices/lenovo-tb710fu.toml),
[the generic device example](devices/example-tablet.toml), and
[the mica donor profile](donors/mica.toml). Input paths are placeholders;
firmware must be acquired separately. The donor profile pins the original R1
recovery input; the running port's R2 userspace was reconstructed from its
incremental OTA.

`gb port --help` lists the image assembly, signing and build commands. They need
recipes for the exact input firmware. The generic build pipeline does not yet
recreate the installed TB710FU ROM from a fresh checkout.

Exit code `0` means the operation completed, `1` means an error, and `2` means
processing completed with outstanding ROM requirements. Read the JSON report
before treating an output as a bootable image.

## Source layout

- `crates/`: firmware inspection, compatibility checks, build/cache orchestration,
  image assembly, AVB, VINTF, SELinux, and runtime test tools.
- `patches/tb710fu/`: kernel, Gunyah, crosvm, graphics and Android integration changes.
- `devices/` and `donors/`: typed profiles with observed facts kept separate from unknowns.
- `tests/`: host tests and small fixtures; no firmware dumps.
- `scripts/`: USB setup and diagnostic helpers.

The [kernel patch notes](patches/tb710fu/kernel/README.md) describe the Gunyah
changes and their source dependencies. Patches are tied to specific upstream
revisions; do not apply the series blindly to another kernel or tablet.

## Tests

```sh
./scripts/check.sh
```

Host tests cover parsers, manifests, compatibility rules, cache behavior and
patch contracts. Hardware tests require the tablet and external firmware inputs.
Some integration tests are ignored by default for that reason.
The installer also has signed-image tests with a simulated EDL backend:

```sh
cargo test --locked -p gb-installer -- --include-ignored
python3 -m unittest discover -s tests -p test_edl_installer_bridge.py
```

Those tests require Python 3 and OpenSSL; they never access a physical USB device.

The main CLI's `gb flash plan` previews changes; it does not flash the tablet.
Keep a stock backup and a tested recovery path before attempting installation.
AVB signatures, rollback indices and partition sizes still apply.

## Credits and license

Thanks to [gbos-vm](https://github.com/skylartaylor/gbos-vm),
[Droid-VM](https://github.com/Droid-VM), and the Android, Linux, crosvm and Mesa
projects for the upstream work this port builds on.

Project code is licensed under [Apache 2.0](LICENSE), except the EDL installer
and Python bridge, which use [GPLv3](third_party/edl-bridge/LICENSE). They use
[B. Kerler's EDL client](https://github.com/bkerler/edl). Third-party code and
patches retain their own licenses, including GPL kernel components, BSD crosvm
code and MIT Mesa code. See the component notices alongside those files.
Googlebook OS and Lenovo firmware remain external dependencies.
