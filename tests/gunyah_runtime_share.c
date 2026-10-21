/* SPDX-License-Identifier: GPL-2.0-only */
#include "gunyah_runtime_share_mock.h"
#ifndef GB_RUNTIME_SHARE_SOURCE
#error Define GB_RUNTIME_SHARE_SOURCE to the actual kernel adapter source
#endif
#include GB_RUNTIME_SHARE_SOURCE

static struct gh_vm vm = { .vmid = 101, .mm = &mm1, .vm_status = GH_RM_VM_STATUS_RUNNING,
	.mm_lock = PTHREAD_MUTEX_INITIALIZER, .status_lock = PTHREAD_RWLOCK_INITIALIZER };
static struct ghsm_share_blob request(u32 label)
{
	return (struct ghsm_share_blob){ .vm_fd = 11, .label = label,
		.flags = GH_MEM_ALLOW_READ | GH_MEM_ALLOW_WRITE,
		.guest_phys_addr = 0x90000000ULL + (u64)label * 65536,
		.userspace_addr = 0x10000000, .memory_size = 65536 };
}
static long share(struct ghsm_share_blob *b)
{
	return gb_share_ioctl(NULL, GHSM_SHARE_BLOB, (unsigned long)b);
}
static long unshare(u32 label)
{
	struct ghsm_unshare_blob u = { 11, label };
	return gb_share_ioctl(NULL, GHSM_UNSHARE_BLOB, (unsigned long)&u);
}
static void teardown_model(void)
{
	/* A reset/teardown model only; this does not test real firmware reset. */
	mutex_lock(&vm.mm_lock);
	while (!list_empty(&vm.memory_mappings)) {
		struct gh_vm_mem *m = container_of(vm.memory_mappings.next, struct gh_vm_mem, list);
		gb_share_drop(&vm, m);
	}
	mutex_unlock(&vm.mm_lock);
	gb_runtime_window_release(&vm);
	assert(!allocations && !pinned && !mm1.locked);
	assert(atomic_load(&vm_file.refs) == 1 && atomic_load(&foreign_file.refs) == 1);
}
static void *cycles(void *arg)
{
	u32 id = (uintptr_t)arg;
	for (u32 i = 0; i < 64; i++) {
		struct ghsm_share_blob b = request(1000 + id * 64 + i);
		assert(!share(&b)); assert(!unshare(b.label));
	}
	return NULL;
}
int main(void)
{
	_Static_assert(sizeof(struct ghsm_share_blob) == 40, "SHARE ABI");
	_Static_assert(sizeof(struct ghsm_unshare_blob) == 8, "UNSHARE ABI");
	_Static_assert(GHSM_SHARE_BLOB == 0xc0284714, "SHARE ioctl");
	_Static_assert(GHSM_UNSHARE_BLOB == 0x40084715, "UNSHARE ioctl");
	INIT_LIST_HEAD(&vm.memory_mappings);
	vm_file = (struct file){ &vm, &real_vm_fops, 1 };
	foreign_file = (struct file){ &vm, NULL, 1 };
	_Static_assert(sizeof(struct ghsm_bind_ram_pool) == 32, "POOL ABI");
	_Static_assert(GHSM_BIND_RAM_POOL == 0xc0204717, "POOL ioctl");
	struct ghsm_bind_ram_pool pool = {.vm_fd = 11, .memory_size = 2042ULL << 20};
	assert(gb_share_ioctl(NULL, GHSM_BIND_RAM_POOL, 0) == -EFAULT);
	assert(gb_share_ioctl(NULL, GHSM_BIND_RAM_POOL, (unsigned long)&pool) == -EBUSY);
	assert(!pool_controls);
	vm.vm_status = GH_RM_VM_STATUS_NO_STATE;
	for (int i = 0; i < 7; i++) {
		struct ghsm_bind_ram_pool bad = pool;
		switch (i) {
		case 0: bad.flags = 2; break;
		case 1: bad.reserved = 1; break;
		case 2: bad.available_2m = 1; break;
		case 3: bad.served_2m = 1; break;
		case 4: bad.held_2m = 1; break;
		case 5: bad.memory_size = 0; break;
		case 6: bad.memory_size -= PAGE_SIZE; break;
		}
		assert(gb_share_ioctl(NULL, GHSM_BIND_RAM_POOL, (unsigned long)&bad) == -EINVAL);
	}
	assert(!pool_controls);
	task.mm = &mm2;
	assert(gb_share_ioctl(NULL, GHSM_BIND_RAM_POOL, (unsigned long)&pool) == -EPERM);
	task.mm = &mm1;
	pool_result = -EOPNOTSUPP;
	assert(gb_share_ioctl(NULL, GHSM_BIND_RAM_POOL, (unsigned long)&pool) == -EOPNOTSUPP);
	pool_result = 0;
	copy_out_fail = true;
	assert(gb_share_ioctl(NULL, GHSM_BIND_RAM_POOL, (unsigned long)&pool) == -EFAULT);
	copy_out_fail = false;
	assert(!gb_share_ioctl(NULL, GHSM_BIND_RAM_POOL, (unsigned long)&pool));
	assert(pool.available_2m == 1024 && !pool.served_2m && pool.held_2m == 1024);
	pool = (struct ghsm_bind_ram_pool){.vm_fd = 11, .flags = 1, .memory_size = 2042ULL << 20};
	assert(!gb_share_ioctl(NULL, GHSM_BIND_RAM_POOL, (unsigned long)&pool));
	assert(pool.available_2m == 3 && pool.served_2m == 1021 && pool.held_2m == 1024);
	pool = (struct ghsm_bind_ram_pool){.vm_fd = 11, .memory_size = GHSM_POOL_WINDOW_512};
	assert(!gb_share_ioctl(NULL, GHSM_BIND_RAM_POOL, (unsigned long)&pool));
	assert(pool.available_2m == 1024 && !pool.served_2m && pool.held_2m == 1024);
	pool = (struct ghsm_bind_ram_pool){.vm_fd = 11, .flags = 1, .memory_size = GHSM_POOL_WINDOW_512};
	assert(!gb_share_ioctl(NULL, GHSM_BIND_RAM_POOL, (unsigned long)&pool));
	assert(pool.available_2m == 771 && pool.served_2m == 253 && pool.held_2m == 1024);
	assert(pool_controls == 6 && !shares && !reclaims);
	_Static_assert(sizeof(struct ghsm_pin_ram_window) == 32, "WINDOW PIN ABI");
	_Static_assert(GHSM_PIN_RAM_WINDOW == 0xc0204718, "WINDOW PIN ioctl");
	struct ghsm_pin_ram_window pin = {.vm_fd = 11, .memory_size = GHSM_POOL_WINDOW_512,
		.userspace_addr = 0x10000000};
	assert(gb_share_ioctl(NULL, GHSM_PIN_RAM_WINDOW, 0) == -EFAULT);
	for (int i = 0; i < 7; i++) {
		struct ghsm_pin_ram_window bad = pin;
		switch (i) {
		case 0: bad.flags = 1; break;
		case 1: bad.reserved = 1; break;
		case 2: bad.pinned_pages = 1; break;
		case 3: bad.memory_size -= PAGE_SIZE; break;
		case 4: bad.userspace_addr++; break;
		case 5: bad.userspace_addr = 0; break;
		case 6: bad.userspace_addr = UINT64_MAX - PAGE_SIZE + 1; break;
		}
		assert(gb_share_ioctl(NULL, GHSM_PIN_RAM_WINDOW, (unsigned long)&bad) ==
			(i == 5 ? -EFAULT : i == 6 ? -EOVERFLOW : -EINVAL));
	}
	struct ghsm_pin_ram_window bad_pin = pin;
	bad_pin.vm_fd = 99;
	assert(gb_share_ioctl(NULL, GHSM_PIN_RAM_WINDOW, (unsigned long)&bad_pin) == -EBADF);
	bad_pin.vm_fd = 12;
	assert(gb_share_ioctl(NULL, GHSM_PIN_RAM_WINDOW, (unsigned long)&bad_pin) == -EINVAL);
	task.mm = &mm2;
	assert(gb_share_ioctl(NULL, GHSM_PIN_RAM_WINDOW, (unsigned long)&pin) == -EPERM);
	task.mm = &mm1;
	vm.vm_status = GH_RM_VM_STATUS_RUNNING;
	assert(gb_share_ioctl(NULL, GHSM_PIN_RAM_WINDOW, (unsigned long)&pin) == -EBUSY);
	vm.vm_status = GH_RM_VM_STATUS_NO_STATE;
	assert(!gup_calls && !gb_window_pin.vm && !pinned && !mm1.locked);
	pool_result = -ENOENT;
	assert(gb_share_ioctl(NULL, GHSM_PIN_RAM_WINDOW, (unsigned long)&pin) == -ENOENT);
	pool_result = 0;
	account_error = -ENOMEM;
	assert(gb_share_ioctl(NULL, GHSM_PIN_RAM_WINDOW, (unsigned long)&pin) == -ENOMEM);
	account_error = 0; calloc_fail = true;
	assert(gb_share_ioctl(NULL, GHSM_PIN_RAM_WINDOW, (unsigned long)&pin) == -ENOMEM);
	calloc_fail = false;
	assert(!gup_calls && !allocations && !mm1.locked);
	for (int i = 0; i < 3; i++) {
		gup_result = i == 0 ? -EFAULT : i == 1 ? 0 : 7;
		assert(gb_share_ioctl(NULL, GHSM_PIN_RAM_WINDOW, (unsigned long)&pin) == -EFAULT);
		assert(!allocations && !pinned && !mm1.locked && !gb_window_pin.vm);
	}
	gup_result = -99999;
	for (int i = 0; i < 2; i++) {
		pin.memory_size = i ? GHSM_POOL_WINDOW_2048 : GHSM_POOL_WINDOW_512;
		copy_out_fail = i == 0;
		assert(gb_share_ioctl(NULL, GHSM_PIN_RAM_WINDOW, (unsigned long)&pin) == (i ? 0 : -EFAULT));
		copy_out_fail = false;
		assert(gb_window_pin.vm == &vm && pinned == pin.memory_size >> PAGE_SHIFT && mm1.locked == (long)pinned);
		assert(!shares && !reclaims);
		struct ghsm_pin_ram_window again = pin; again.pinned_pages = 0;
		assert(gb_share_ioctl(NULL, GHSM_PIN_RAM_WINDOW, (unsigned long)&again) == -EALREADY);
		struct gh_vm other_vm = {};
		gb_runtime_window_release(&other_vm); assert(gb_window_pin.vm == &vm);
		gb_runtime_window_release(&vm); gb_runtime_window_release(&vm);
		assert(!allocations && !pinned && !mm1.locked && !gb_window_pin.vm);
		pin.pinned_pages = 0;
	}
	vm.vm_status = GH_RM_VM_STATUS_RUNNING;
	struct ghsm_share_blob b = request(1), invalid;
	/* A late firmware failure must retain both the parcel and window pins
	 * until normal VM teardown. Never expose an early userspace unpin API.
	 */
	vm.vm_status = GH_RM_VM_STATUS_NO_STATE;
	assert(!gb_share_ioctl(NULL, GHSM_PIN_RAM_WINDOW, (unsigned long)&pin));
	vm.vm_status = GH_RM_VM_STATUS_RUNNING; share_error = -EIO;
	assert(share(&b) == -EIO && gb_window_pin.vm == &vm);
	assert(unshare(b.label) == -EIO && gb_window_pin.vm == &vm);
	share_error = 0; teardown_model();
	assert(gb_share_ioctl(NULL, 0, 0) == -ENOTTY);
	assert(gb_share_ioctl(NULL, GHSM_SHARE_BLOB, 0) == -EFAULT);
	invalid = b; invalid.vm_fd = 99; assert(share(&invalid) == -EBADF);
	invalid.vm_fd = 12; assert(share(&invalid) == -EINVAL);
	task.mm = &mm2; assert(share(&b) == -EPERM); assert(unshare(1) == -EPERM); task.mm = &mm1;
	interrupt_lock = 1; assert(share(&b) == -EINTR); interrupt_lock = 0;
	vm.vm_status = 0; assert(share(&b) == -ENODEV); vm.vm_status = GH_RM_VM_STATUS_RUNNING;
	for (int i = 0; i < 7; i++) {
		invalid = b;
		switch (i) {
		case 0: invalid.memory_size = 0; break;
		case 1: invalid.memory_size = SZ_2G + PAGE_SIZE; break;
		case 2: invalid.memory_size++; break;
		case 3: invalid.userspace_addr++; break;
		case 4: invalid.guest_phys_addr++; break;
		case 5: invalid.flags = 0; break;
		case 6: invalid.flags |= 8; break;
		}
		assert(share(&invalid) == -EINVAL);
	}
	invalid = b; invalid.guest_phys_addr = UINT64_MAX - PAGE_SIZE + 1;
	assert(share(&invalid) == -EOVERFLOW);
	invalid = b; invalid.userspace_addr = 0; assert(share(&invalid) == -EFAULT);
	alloc_error = -ENOMEM; assert(share(&b) == -ENOMEM); alloc_error = 0;
	model_mapping(&vm, 900, 0x100000, GB_SHARE_VM_BYTES);
	assert(share(&b) == -E2BIG); teardown_model();
	int before = shares;
	mock_spans = GB_SHARE_MAX_SPANS + 1; assert(share(&b) == -E2BIG);
	assert(shares == before); mock_spans = 1; teardown_model();
	/* VM-wide rejection releases only the new unshared allocation. */
	struct gh_vm_mem *prior = model_mapping(&vm, 900, 0x100000, PAGE_SIZE);
	prior->runtime_shared = true; prior->parcel.n_mem_entries = GB_SHARE_VM_SPANS;
	before = shares; assert(share(&b) == -ENOSPC); assert(shares == before);
	assert(!gb_share_find(&vm, 1) && gb_share_find(&vm, 900) == prior);
	assert(pinned == 1); teardown_model();
	/* A boundary-sized aggregate is allowed. Static boot mappings are excluded. */
	prior = model_mapping(&vm, 900, 0x100000, PAGE_SIZE);
	prior->runtime_shared = true; prior->parcel.n_mem_entries = GB_SHARE_VM_SPANS - 1;
	assert(!share(&b)); assert(!unshare(1)); teardown_model();
	prior = model_mapping(&vm, 900, 0x100000, PAGE_SIZE);
	prior->parcel.n_mem_entries = GB_SHARE_VM_SPANS + 1;
	assert(!share(&b)); assert(!unshare(1)); teardown_model();
	assert(!share(&b)); assert(b.mem_handle == 101);
	struct gh_vm_mem *m = gb_share_find(&vm, 1); assert(m && m->runtime_ready);
	assert(share(&b) == -EEXIST);
	invalid = request(2); invalid.guest_phys_addr = b.guest_phys_addr;
	assert(share(&invalid) == -EEXIST);
	reclaim_error = -EBUSY; assert(unshare(1) == -EBUSY);
	assert(gb_share_find(&vm, 1) == m && m->runtime_ready && pinned == 16);
	reclaim_error = 0; assert(!unshare(1)); assert(unshare(1) == -ENOENT); teardown_model();
	model_mapping(&vm, 1, b.guest_phys_addr, b.memory_size);
	assert(unshare(1) == -ENOENT); assert(pinned == 16); teardown_model();
	share_error = -EPERM; before = shares; assert(share(&b) == -EPERM);
	assert(shares == before + 1);
	m = gb_share_find(&vm, 1); assert(m && m->runtime_shared && !m->runtime_ready);
	share_error = 0; teardown_model();
	share_error = -EIO; assert(share(&b) == -EIO); share_error = 0;
	m = gb_share_find(&vm, 1); assert(m && m->runtime_shared && !m->runtime_ready);
	before = reclaims; assert(unshare(1) == -EIO); assert(reclaims == before && pinned == 16);
	teardown_model();
	share_error = -E2BIG; assert(share(&b) == -EIO); share_error = 0;
	assert(gb_share_find(&vm, 1) && !gb_share_find(&vm, 1)->runtime_ready);
	assert(unshare(1) == -EIO); teardown_model();
	copy_out_fail = true; assert(share(&b) == -EFAULT); copy_out_fail = false;
	assert(gb_share_find(&vm, 1)->runtime_ready); assert(!unshare(1)); teardown_model();
	struct device a = {1}, other = {2};
	register_error = -EIO; assert(gb_runtime_share_register(&a) == -EIO);
	register_error = 0; assert(!gb_runtime_share_register(&a));
	assert(gb_runtime_share_register(&other) == -EBUSY);
	gb_runtime_share_unregister(&other); assert(!deregistrations);
	gb_runtime_share_unregister(&a); assert(deregistrations == 1 && !gb_share_registered);
	assert(gb_share_misc.mode == 0600 && registrations == 2);
	pthread_t threads[4];
	for (uintptr_t i = 0; i < 4; i++) assert(!pthread_create(&threads[i], NULL, cycles, (void *)i));
	for (int i = 0; i < 4; i++) assert(!pthread_join(threads[i], NULL));
	teardown_model();
	puts("Runtime-share actual-source fault model passed, including 256 concurrent share/reclaim cycles.");
}
