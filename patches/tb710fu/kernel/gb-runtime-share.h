/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Wire-compatible with Droid-VM/gunyah_host_mod GHSM_SHARE_BLOB ABI.
 * Source reference: 44e8ae5a088a3a35290a5cacb205640cff187b99.
 * Runtime RAM is host-accessible; this interface provides no attestation.
 */
#ifndef GB_RUNTIME_SHARE_H
#define GB_RUNTIME_SHARE_H

#include <linux/ioctl.h>
#include <linux/types.h>

struct ghsm_share_blob {
	__s32 vm_fd;
	__u32 label;
	__u32 flags;
	__u32 mem_handle;
	__u64 guest_phys_addr;
	__u64 memory_size;
	__u64 userspace_addr;
};

struct ghsm_unshare_blob {
	__s32 vm_fd;
	__u32 label;
};

/* Our in-tree optional RAM supply, not a stock/OEM ABI. flags0 binds;
 * flags1 queries this VM's existing binding. Outputs must enter as zero.
 * The506MiB/2042MiB windows correspond to512MiB/2048MiB guest RAM.
 */
#define GHSM_POOL_WINDOW_512 (506ULL << 20)
#define GHSM_POOL_WINDOW_2048 (2042ULL << 20)

struct ghsm_bind_ram_pool {
	__s32 vm_fd;
	__u32 flags;
	__u64 memory_size;
	__u32 available_2m;
	__u32 served_2m;
	__u32 held_2m;
	__u32 reserved;
};
#define GHSM_BIND_RAM_POOL _IOWR(0x47, 0x17, struct ghsm_bind_ram_pool)

/* Pin one explicitly bound RAM window before VM start. No firmware operation
 * or userspace unpin command: the real VM teardown owns this pin's lifetime.
 * This replaces io_uring-only pinning in app-inherited seccomp contexts.
 */
struct ghsm_pin_ram_window {
	__s32 vm_fd;
	__u32 flags;
	__u64 memory_size;
	__u64 userspace_addr;
	__u32 pinned_pages;
	__u32 reserved;
};
#define GHSM_PIN_RAM_WINDOW _IOWR(0x47, 0x18, struct ghsm_pin_ram_window)

struct gh_vm;
void gb_runtime_window_release(struct gh_vm *vm);

#define GHSM_SHARE_BLOB _IOWR(0x47, 0x14, struct ghsm_share_blob)
#define GHSM_UNSHARE_BLOB _IOW(0x47, 0x15, struct ghsm_unshare_blob)

#endif
