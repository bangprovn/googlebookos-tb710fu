// SPDX-License-Identifier: GPL-2.0-only
/* In-tree runtime-sharing adapter for the TB710FU Gunyah backend.
 * Uses the real driver layout and VM file operations, with no kprobes,
 * symbol lookup, module-signature changes or copied private structures.
 */
#include <linux/file.h>
#include <linux/gb-gunyah-pool.h>
#include <linux/compat.h>
#include <linux/fs.h>
#include <linux/gunyah_rsc_mgr.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/overflow.h>
#include <linux/sched/mm.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include "vm_mgr.h"
#include "rsc_mgr.h"
#include "gb-runtime-share.h"

/* Candidate resource budgets, not firmware limits. Large fragmented SCM
 * operations have reset this host; reject before issuing those operations.
 * Permit 2 GiB payload RAM plus bounded boot/device overhead per VM.
 */
#define GB_SHARE_MAX_BYTES ((u64)SZ_2G)
#define GB_SHARE_VM_BYTES (GB_SHARE_MAX_BYTES + SZ_64M)
#define GB_SHARE_MAX_SPANS 512
/* Candidate VM-wide dynamic-transfer budget, not a firmware capacity claim. */
#define GB_SHARE_VM_SPANS 4096

/* Serialize new-interface transactions, without changing the exported VM ABI.
 * Lock order is runtime lock, VM status_lock, then VM mm_lock.
 */
static DEFINE_MUTEX(gb_share_lock);
static DEFINE_MUTEX(gb_share_device_lock);
static bool gb_share_registered;

/* The optional pool permits only one bound VM. Keep its whole-window pin
 * separate from parcel mappings, which acquire their own pins. Never release
 * this pin on a failed share or copy_to_user; normal VM teardown releases it
 * after reset/reclaim. Real vm fops, current mm and status are checked below.
 * gb_share_lock protects every field and serializes creation with teardown.
 */
static struct {
	struct gh_vm *vm;
	struct page **pages;
	unsigned long npages;
} gb_window_pin;

static int gb_window_pin_create(struct gh_vm *vm, struct ghsm_pin_ram_window *p)
{
	struct page **pages;
	unsigned long npages = p->memory_size >> PAGE_SHIFT;
	u32 avail, served, held;
	long pinned;
	int ret;

	if (gb_window_pin.vm)
		return gb_window_pin.vm == vm ? -EALREADY : -EBUSY;
	/* A matching explicit pool binding is mandatory; this is not an arbitrary
	 * pin-any-process interface. Query never creates or changes a binding.
	 */
	ret = gb_gunyah_pool_control(vm, p->memory_size, true, &avail, &served, &held);
	if (ret)
		return ret;
	ret = account_locked_vm(vm->mm, npages, true);
	if (ret)
		return ret;
	pages = kvcalloc(npages, sizeof(*pages), GFP_KERNEL_ACCOUNT);
	if (!pages) {
		ret = -ENOMEM;
		goto unaccount;
	}
	/* Same long-term writable GUP contract as the stock parcel allocator.
	 * This performs no RM/SCM call and cannot start a guest.
	 */
	pinned = pin_user_pages_fast(p->userspace_addr, npages,
				     FOLL_WRITE | FOLL_LONGTERM, pages);
	if (pinned != npages) {
		ret = pinned < 0 ? pinned : -EFAULT;
		if (pinned > 0)
			unpin_user_pages(pages, pinned);
		kvfree(pages);
		goto unaccount;
	}
	gb_window_pin.vm = vm;
	gb_window_pin.pages = pages;
	gb_window_pin.npages = npages;
	p->pinned_pages = npages;
	return 0;
unaccount:
	account_locked_vm(vm->mm, npages, false);
	return ret;
}

void gb_runtime_window_release(struct gh_vm *vm)
{
	mutex_lock(&gb_share_lock);
	if (gb_window_pin.vm == vm) {
		unpin_user_pages(gb_window_pin.pages, gb_window_pin.npages);
		account_locked_vm(vm->mm, gb_window_pin.npages, false);
		kvfree(gb_window_pin.pages);
		gb_window_pin.vm = NULL;
		gb_window_pin.pages = NULL;
		gb_window_pin.npages = 0;
	}
	mutex_unlock(&gb_share_lock);
}

static struct gh_vm_mem *gb_share_find(struct gh_vm *vm, u32 label)
{
	struct gh_vm_mem *m;

	list_for_each_entry(m, &vm->memory_mappings, list)
		if (m->parcel.label == label)
			return m;
	return NULL;
}

/* Only for an unshared allocation or after firmware confirms reclaim.
 * Caller holds mm_lock. Failed firmware operations must retain this state.
 */
static void gb_share_drop(struct gh_vm *vm, struct gh_vm_mem *m)
{
	unpin_user_pages(m->pages, m->npages);
	account_locked_vm(vm->mm, m->npages, false);
	kvfree(m->pages);
	kfree(m->parcel.acl_entries);
	kvfree(m->parcel.mem_entries);
	list_del(&m->list);
	kfree(m);
}

static int gb_share_quota(struct gh_vm *vm, u64 extra)
{
	struct gh_vm_mem *m;
	u64 total = extra, bytes;

	list_for_each_entry(m, &vm->memory_mappings, list) {
		bytes = (u64)m->npages << PAGE_SHIFT;
		if (check_add_overflow(total, bytes, &total) || total > GB_SHARE_VM_BYTES)
			return -E2BIG;
	}
	return total > GB_SHARE_VM_BYTES ? -E2BIG : 0;
}

static int gb_share_span_quota(struct gh_vm *vm, size_t *total)
{
	struct gh_vm_mem *m;

	*total = 0;
	list_for_each_entry(m, &vm->memory_mappings, list) {
		if (!m->runtime_shared)
			continue;
		if (check_add_overflow(*total, m->parcel.n_mem_entries, total) ||
		    *total > GB_SHARE_VM_SPANS)
			return -ENOSPC;
	}
	return 0;
}

static int gb_share_create(struct gh_vm *vm, struct ghsm_share_blob *b)
{
	struct gh_userspace_memory_region region = {
		.label = b->label,
		.flags = b->flags,
		.guest_phys_addr = b->guest_phys_addr,
		.memory_size = b->memory_size,
		.userspace_addr = b->userspace_addr,
	};
	struct gh_vm_mem *m;
	u64 end;
	size_t spans;
	int ret;

	if (!b->memory_size || b->memory_size > GB_SHARE_MAX_BYTES ||
	    !PAGE_ALIGNED(b->memory_size) || !PAGE_ALIGNED(b->userspace_addr) ||
	    !PAGE_ALIGNED(b->guest_phys_addr) ||
	    !(b->flags & GH_MEM_ALLOW_READ) ||
	    b->flags & ~(GH_MEM_ALLOW_READ | GH_MEM_ALLOW_WRITE | GH_MEM_ALLOW_EXEC))
		return -EINVAL;
	if (check_add_overflow(b->guest_phys_addr, b->memory_size, &end) ||
	    check_add_overflow(b->userspace_addr, b->memory_size, &end))
		return -EOVERFLOW;
	if (!access_ok(u64_to_user_ptr(b->userspace_addr), b->memory_size))
		return -EFAULT;
	if (vm->vm_status != GH_RM_VM_STATUS_RUNNING)
		return -ENODEV;

	mutex_lock(&vm->mm_lock);
	ret = gb_share_quota(vm, b->memory_size);
	mutex_unlock(&vm->mm_lock);
	if (ret)
		return ret;
	ret = gh_vm_mem_alloc(vm, &region, false);
	if (ret) {
		pr_warn_ratelimited("gb-gunyah-phase-v1: allocation label=%u error=%d\n",
				    b->label, ret);
		return ret;
	}

	mutex_lock(&vm->mm_lock);
	m = gb_share_find(vm, b->label);
	if (!m) {
		ret = -ENOENT;
		goto unlock;
	}
	/* The allocator already rejects duplicate labels and overlapping GPAs.
	 * This marker prevents the new unshare ABI from removing boot mappings.
	 */
	m->runtime_shared = true;
	ret = gb_share_quota(vm, 0);
	if (ret || m->parcel.n_mem_entries > GB_SHARE_MAX_SPANS) {
		ret = -E2BIG;
		gb_share_drop(vm, m);
		goto unlock;
	}
	ret = gb_share_span_quota(vm, &spans);
	if (ret) {
		pr_warn_ratelimited("gb-gunyah-span-budget-v1: refused before firmware label=%u total_spans=%zu budget=%u\n",
				    b->label, spans, GB_SHARE_VM_SPANS);
		show_mem(0, NULL);
		gb_share_drop(vm, m);
		goto unlock;
	}
	pr_info_ratelimited("gb-gunyah-span-budget-v1: admitted label=%u total_spans=%zu\n",
			    b->label, spans);
	m->parcel.acl_entries[0].vmid = cpu_to_le16(vm->vmid);
	pr_info_ratelimited("gb-gunyah-runtime-v1: share begin label=%u entries=%zu\n",
			    b->label, m->parcel.n_mem_entries);
	ret = gh_rm_mem_share(vm->rm, &m->parcel);
	pr_info_ratelimited("gb-gunyah-runtime-v1: share result label=%u result=%d\n",
			    b->label, ret);
	if (ret) {
		pr_warn_ratelimited("gb-gunyah-phase-v1: share_wrapper label=%u spans=%zu total_spans=%zu error=%d\n",
				    b->label, m->parcel.n_mem_entries, spans, ret);
		/* E2BIG is reserved for safe pre-transfer refusals in this ABI.
		 * A late error may have changed firmware ownership: never retry it.
		 */
		if (ret == -E2BIG)
			ret = -EIO;
		/* SCM/RM rollback is not assumed. Leave failed mappings pinned
		 * for normal VM stop/reset/teardown; never reuse them live.
		 */
		goto unlock;
	}
	if (m->parcel.mem_handle == GH_MEM_HANDLE_INVAL) {
		ret = -EIO;
		goto unlock;
	}
	m->runtime_ready = true;
	b->mem_handle = m->parcel.mem_handle;
unlock:
	mutex_unlock(&vm->mm_lock);
	return ret;
}

static int gb_share_reclaim(struct gh_vm *vm, u32 label)
{
	struct gh_vm_mem *m;
	int ret;

	mutex_lock(&vm->mm_lock);
	m = gb_share_find(vm, label);
	if (!m || !m->runtime_shared) {
		ret = -ENOENT;
		goto unlock;
	}
	if (!m->runtime_ready) {
		ret = -EIO;
		goto unlock;
	}
	ret = gh_rm_mem_reclaim(vm->rm, &m->parcel);
	if (!ret)
		gb_share_drop(vm, m);
unlock:
	mutex_unlock(&vm->mm_lock);
	return ret;
}

static long gb_share_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	void __user *user = (void __user *)arg;
	struct ghsm_share_blob b;
	struct ghsm_unshare_blob u;
	struct ghsm_bind_ram_pool pool;
	struct ghsm_pin_ram_window pin;
	u64 end;
	struct gh_vm *vm;
	struct file *vm_file;
	int fd, ret;

	if (cmd == GHSM_SHARE_BLOB) {
		if (copy_from_user(&b, user, sizeof(b)))
			return -EFAULT;
		fd = b.vm_fd;
	} else if (cmd == GHSM_UNSHARE_BLOB) {
		if (copy_from_user(&u, user, sizeof(u)))
			return -EFAULT;
		fd = u.vm_fd;
	} else if (cmd == GHSM_BIND_RAM_POOL) {
		if (copy_from_user(&pool, user, sizeof(pool)))
			return -EFAULT;
		if (pool.flags > 1 || pool.reserved || pool.available_2m ||
		    pool.served_2m || pool.held_2m ||
		    (pool.memory_size != GHSM_POOL_WINDOW_512 &&
		     pool.memory_size != GHSM_POOL_WINDOW_2048))
			return -EINVAL;
		fd = pool.vm_fd;
	} else if (cmd == GHSM_PIN_RAM_WINDOW) {
		if (copy_from_user(&pin, user, sizeof(pin)))
			return -EFAULT;
		if (pin.flags || pin.reserved || pin.pinned_pages ||
		    (pin.memory_size != GHSM_POOL_WINDOW_512 &&
		     pin.memory_size != GHSM_POOL_WINDOW_2048) ||
		    !PAGE_ALIGNED(pin.userspace_addr))
			return -EINVAL;
		if (check_add_overflow(pin.userspace_addr, pin.memory_size, &end))
			return -EOVERFLOW;
		if (!access_ok(u64_to_user_ptr(pin.userspace_addr), pin.memory_size))
			return -EFAULT;
		fd = pin.vm_fd;
	} else {
		return -ENOTTY;
	}
	vm_file = fget(fd);
	if (!vm_file)
		return -EBADF;
	/* Match the real driver's fops, not a user-influenced dentry name. */
	if (!gh_vm_file_matches(vm_file)) {
		ret = -EINVAL;
		goto put;
	}
	vm = vm_file->private_data;
	if (vm->mm != current->mm) {
		ret = -EPERM;
		goto put;
	}
	ret = mutex_lock_interruptible(&gb_share_lock);
	if (ret)
		goto put;
	down_read(&vm->status_lock);
	if (cmd == GHSM_BIND_RAM_POOL) {
		ret = vm->vm_status == GH_RM_VM_STATUS_NO_STATE ?
			gb_gunyah_pool_control(vm, pool.memory_size, pool.flags == 1,
				&pool.available_2m, &pool.served_2m, &pool.held_2m) : -EBUSY;
		if (!ret && copy_to_user(user, &pool, sizeof(pool)))
			ret = -EFAULT;
	} else if (cmd == GHSM_PIN_RAM_WINDOW) {
		ret = vm->vm_status == GH_RM_VM_STATUS_NO_STATE ?
			gb_window_pin_create(vm, &pin) : -EBUSY;
		if (!ret && copy_to_user(user, &pin, sizeof(pin)))
			ret = -EFAULT;
	} else {
		ret = cmd == GHSM_SHARE_BLOB ? gb_share_create(vm, &b) : gb_share_reclaim(vm, u.label);
	}
	/* On copy failure the successful parcel remains tracked. The caller can
	 * reclaim by label, or close the VM to perform normal stop/reset/teardown.
	 */
	if (!ret && cmd == GHSM_SHARE_BLOB && copy_to_user(user, &b, sizeof(b)))
		ret = -EFAULT;
	up_read(&vm->status_lock);
	mutex_unlock(&gb_share_lock);
put:
	fput(vm_file);
	return ret;
}

static const struct file_operations gb_share_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = gb_share_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
	.llseek = noop_llseek,
};

static struct miscdevice gb_share_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "gunyah_share",
	.fops = &gb_share_fops,
	.mode = 0600,
};

int gb_runtime_share_register(struct device *parent)
{
	int ret = -EBUSY;

	mutex_lock(&gb_share_device_lock);
	if (!gb_share_registered) {
		gb_share_misc.parent = parent;
		ret = misc_register(&gb_share_misc);
		gb_share_registered = !ret;
	}
	mutex_unlock(&gb_share_device_lock);
	return ret;
}

void gb_runtime_share_unregister(struct device *parent)
{
	mutex_lock(&gb_share_device_lock);
	if (gb_share_registered && gb_share_misc.parent == parent) {
		misc_deregister(&gb_share_misc);
		gb_share_registered = false;
	}
	mutex_unlock(&gb_share_device_lock);
}
