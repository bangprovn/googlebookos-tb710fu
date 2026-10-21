# Alpha 1: working features and known issues

Googlebook OS boots on the Lenovo TB710FU with its desktop and system services.
The release uses R2 userspace and the target tablet's adapted hardware stack.

## Working

- Googlebook desktop and normal tablet interaction.
- Android setup after factory reset: confirmed by the owner on R2.
- Camera and microphone: confirmed by the owner; earlier camera frame-delivery
  and known-pattern speaker/microphone tests also passed.
- Built-in speaker playback, Wi-Fi with validated HTTPS connectivity, and six
  exposed sensor streams passed earlier device tests. They have not all been
  repeated after the R2 factory reset.
- Authenticated USB ADB and development file transfers.
- Original Terminal / Debian VM with 2 GiB RAM. Guest command execution and the
  firmware's handling of a fresh 4 GiB default request were checked on R2.

## Bugs and incomplete features

- Phone Link does not discover the peer phone.
- VM graphics are partial. GLES and limited Vulkan workloads worked on earlier
  builds, but broader native presentation, resizing and resume are unfinished.
- Terminal's memory menu can show 4 GB even though firmware allocates 2 GiB.
  Other custom memory sizes are not supported by the current adapter.
- A rapid forced VM stop/restart can return a resource-busy error. Let teardown
  complete before reopening Terminal; do not repeatedly force-start VMs.
- After some EDL resets, the existing main Android user needs manual selection.
- Donor-specific Perks/serviceability features need GSC/TPM/EC functionality that
  is not implemented on the tablet. Google Play certification is not established.
- There is no port OTA channel. Official donor hardware OTAs are unsupported.

Bluetooth pairing/audio, external display, stylus, deep suspend/resume, charging
regulation and long mixed workloads still need end-to-end testing. A successful
BLE scan, sensor event or battery API call is not full qualification of a feature.

Alpha 1 has not been clean-installed on a second tablet. Use the exact stock
base and keep your own recovery backup. The EDL-only installer uses the
readback/sector-write/digest method used during development, with per-device GPT/LP discovery and AVB personalization. The Rust
and Python paths have offline tests; native Windows/macOS USB and installation
on a second physical tablet remain unqualified. A matching stock programmer,
stock base, active slot A and an accepted signing chain are prerequisites.
Image-declared indices do not establish protected rollback floors.
