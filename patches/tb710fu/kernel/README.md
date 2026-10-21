# TB710FU kernel patches

The port uses the tablet's Android 6.1 kernel base,
`5c2cea985a841939e6d074cbed2019dec0245fcd`, with its matching vendor modules
and module trust certificate. The build used Android Clang 17 `r487747c`.
Obtain the matching kernel source and device configuration separately.

The patches cover:

- Gunyah allocation bookkeeping, shared IRQ eventfds and PCI layout compatibility.
- Runtime memory sharing, VM-owned page pinning and the guest handoff interface.
- A bounded 2 GiB reserve pool and reclaim during periods with no active VM.
- UDMABUF support and Android 6.1 driver fixes for the graphics path.
- Optional VM-stage and memory diagnostics.

The JSON files record source revisions and input/output hashes for individual
patches. Check those pins and each patch's dependencies before applying it.
The files are not a single patch series for an arbitrary kernel.

## Allocation fix

`gunyah-kvcalloc.patch` retains the upstream fix from Android kernel commit
[`c9e2710a7bd01bbb73280dfe37937d5b6e24eb0b`](https://android.googlesource.com/kernel/common/+/c9e2710a7bd01bbb73280dfe37937d5b6e24eb0b).
It replaces large bookkeeping allocations with `kvcalloc` / `kvfree`, without
changing the guest page pin/share/lend operations. The patch retains its
upstream author and sign-off records.

The Rust helper checks the exact source and patch hashes, applies and reverses
the change in staging, and leaves the original source untouched:

```sh
cargo run --locked -p gb-build --example prepare_gunyah_fix -- \
  /path/to/kernel/common/drivers/virt/gunyah/vm_mgr_mm.c \
  patches/tb710fu/kernel/gunyah-kvcalloc.patch \
  /usr/bin/git artifacts/gunyah-source-fix
```

That command prepares source; it does not build or flash a kernel. Boot-image
assembly must retain the target's boot metadata, DTB, vendor module compatibility
and AVB chain.

## License

Kernel-derived changes retain their GPL terms and original notices. The reserve
pool includes code from Droid-VM; see [its source and license](reserve-core/README.md).
The project's root Apache license does not replace these component licenses.
