# Googlebook OS for Lenovo TB710FU

An experimental Googlebook OS port for the Lenovo TB710FU (Qualcomm SM8650Q).
The donor is the Dell XPS Googlebook, codename `mica`.

The port brings over the Googlebook desktop and system stack while retaining
the tablet's vendor hardware support. The current build uses
`CL3B.260622.276.R2` userspace and a modified Linux 6.1 kernel from the
tablet's Android kernel tree.

This repository contains the Rust tools, device profile, kernel changes and
userspace patches. Firmware images, proprietary apps and libraries, signing
keys, and EDL programmers are not included.

## Status

| Feature | Current state |
| --- | --- |
| Googlebook desktop | Boots on the TB710FU. |
| Android setup | Owner reports successful setup after a factory reset on R2. |
| Terminal / Debian VM | Boots and runs commands with 2 GiB RAM. |
| Terminal after reset | Firmware maps the app's 4 GiB default request to 2 GiB. The app's settings may still show 4 GB. |
| Guest graphics | Partial. Earlier builds passed GLES and limited Vulkan tests; resize and resume still need work. These results have not all been repeated on R2. |
| Phone Link | Device discovery is not working. |
| Suspend, accessories and long-running workloads | Not fully tested. |

The latest Terminal change was checked with the original app requesting 4 GiB:
the adapter selected 2 GiB, and a command inside Debian confirmed the allocation.
No additional data wipe was performed for that check.

This is a development port for one tablet, not a supported daily-driver ROM.
There is no ready-to-flash release or one-command port to another device.

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

The main CLI's `gb flash plan` previews changes; it does not flash the tablet.
Keep a stock backup and a tested recovery path before attempting installation.
AVB signatures, rollback indices and partition sizes still apply.

## Credits and license

Thanks to [gbos-vm](https://github.com/skylartaylor/gbos-vm),
[Droid-VM](https://github.com/Droid-VM), and the Android, Linux, crosvm and Mesa
projects for the upstream work this port builds on.

Project code is licensed under [Apache 2.0](LICENSE). Third-party code and
patches retain their own licenses, including GPL kernel components, BSD crosvm
code and MIT Mesa code. See the component notices alongside those files.
Googlebook OS and Lenovo firmware remain external dependencies.
