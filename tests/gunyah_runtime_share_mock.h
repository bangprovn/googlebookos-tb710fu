/* SPDX-License-Identifier: GPL-2.0-only */
/* Host fault model, not Gunyah firmware or pin/migration emulation. */
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <sys/ioctl.h>

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef int32_t __s32;
typedef uint32_t __u32;
typedef uint64_t __u64;
#define __user
#define THIS_MODULE NULL
#define SZ_2G 0x80000000ULL
#define SZ_64M 0x04000000ULL
#define PAGE_SHIFT 12
#define PAGE_SIZE 4096
#define PAGE_ALIGNED(x) (!((x) & (PAGE_SIZE - 1)))
#define GH_MEM_ALLOW_READ 1
#define GH_MEM_ALLOW_WRITE 2
#define GH_MEM_ALLOW_EXEC 4
#define GH_RM_VM_STATUS_RUNNING 3
#define GH_RM_VM_STATUS_NO_STATE 0
#define GH_MEM_HANDLE_INVAL UINT32_MAX
#define GFP_KERNEL_ACCOUNT 0
#define FOLL_WRITE 1
#define FOLL_LONGTERM 2
#define cpu_to_le16(x) (x)
#define u64_to_user_ptr(x) ((void *)(uintptr_t)(x))
#define check_add_overflow(a, b, p) __builtin_add_overflow((a), (b), (p))
#define pr_info_ratelimited(...) ((void)0)
#define pr_warn_ratelimited(...) ((void)0)
#define noop_llseek NULL
#define compat_ptr_ioctl NULL
#define DEFINE_MUTEX(n) pthread_mutex_t n = PTHREAD_MUTEX_INITIALIZER
#define mutex_lock(p) assert(!pthread_mutex_lock(p))
#define mutex_unlock(p) assert(!pthread_mutex_unlock(p))
#define down_read(p) assert(!pthread_rwlock_rdlock(p))
#define up_read(p) assert(!pthread_rwlock_unlock(p))
static int interrupt_lock;
static int mutex_lock_interruptible(pthread_mutex_t *p)
{
	if (interrupt_lock) return -EINTR;
	mutex_lock(p); return 0;
}
struct list_head { struct list_head *next, *prev; };
#define INIT_LIST_HEAD(p) (*(p) = (struct list_head){ (p), (p) })
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
#define list_for_each_entry(pos, head, field) \
	for (struct list_head *n__ = (head)->next; n__ != (head) && \
	     ((pos) = container_of(n__, __typeof__(*(pos)), field), 1); n__ = n__->next)
static void list_add(struct list_head *n, struct list_head *h)
{
	n->next = h->next; n->prev = h; h->next->prev = n; h->next = n;
}
static void list_del(struct list_head *n)
{
	n->next->prev = n->prev; n->prev->next = n->next;
}
static bool list_empty(struct list_head *h) { return h->next == h; }
static int allocations;
static bool calloc_fail;
static void *mock_alloc(size_t n) { void *p = calloc(1, n); assert(p); ++allocations; return p; }
static void *kvcalloc(size_t n, size_t size, int flags)
{ (void)flags; return calloc_fail ? NULL : mock_alloc(n * size); }
static void kfree(void *p) { if (p) { --allocations; free(p); } }
#define kvfree kfree
struct mock_mm { long locked; };
struct mock_task { struct mock_mm *mm; };
static struct mock_mm mm1, mm2;
static struct mock_task task = { &mm1 };
static struct mock_task *current = &task;
struct gh_rm {};
struct gh_rm_mem_acl_entry { u16 vmid; };
struct gh_rm_mem_parcel {
	u32 label, mem_handle;
	size_t n_mem_entries;
	struct gh_rm_mem_acl_entry *acl_entries;
	void *mem_entries;
};
struct gh_vm_mem {
	struct list_head list;
	struct gh_rm_mem_parcel parcel;
	u64 guest_phys_addr;
	void *pages;
	unsigned long npages;
	bool runtime_shared, runtime_ready;
};
struct gh_vm {
	u16 vmid;
	struct gh_rm *rm;
	int vm_status;
	struct mock_mm *mm;
	pthread_mutex_t mm_lock;
	pthread_rwlock_t status_lock;
	struct list_head memory_mappings;
};
/* Pool callback is a stub here: this harness proves ioctl dispatch, ownership,
 * state and copy semantics, not actual page supply or pool lifecycle.
 */
static int pool_controls, pool_result;
static int gb_gunyah_pool_control(struct gh_vm *vm, u64 bytes, bool query,
				u32 *avail, u32 *served, u32 *held)
{
	(void)vm;
	assert(bytes == (506ULL << 20) || bytes == (2042ULL << 20));
	pool_controls++;
	if (pool_result) return pool_result;
	*served = query ? bytes >> 21 : 0;
	*avail = 1024 - *served;
	*held = 1024;
	return 0;
}
struct gh_userspace_memory_region {
	u32 label, flags;
	u64 guest_phys_addr, memory_size, userspace_addr;
};
struct device { int id; };
struct file;
struct file_operations {
	void *owner;
	long (*unlocked_ioctl)(struct file *, unsigned int, unsigned long);
	void *compat_ioctl, *llseek;
};
struct file { void *private_data; const struct file_operations *f_op; atomic_int refs; };
static const struct file_operations real_vm_fops;
static struct file vm_file, foreign_file;
static struct file *fget(int fd)
{
	struct file *f = fd == 11 ? &vm_file : fd == 12 ? &foreign_file : NULL;
	if (f) atomic_fetch_add(&f->refs, 1);
	return f;
}
static void fput(struct file *f) { assert(atomic_fetch_sub(&f->refs, 1) > 1); }
static bool gh_vm_file_matches(struct file *f)
{
	return f->f_op == &real_vm_fops && f->private_data;
}
static bool copy_in_fail, copy_out_fail;
static int copy_from_user(void *dst, const void *src, size_t n)
{
	if (!src || copy_in_fail) return 1;
	memcpy(dst, src, n); return 0;
}
static int copy_to_user(void *dst, const void *src, size_t n)
{
	if (!dst || copy_out_fail) return 1;
	memcpy(dst, src, n); return 0;
}
static bool access_ok(const void *p, u64 n)
{
	return (uintptr_t)p >= PAGE_SIZE && (uintptr_t)p + n < (1ULL << 47);
}
static unsigned long pinned;
struct page {};
static long gup_result = -99999;
static int gup_calls, account_error;
static long pin_user_pages_fast(u64 addr, unsigned long n, unsigned int flags, struct page **pages)
{
	assert(addr && pages && flags == (FOLL_WRITE | FOLL_LONGTERM));
	gup_calls++;
	long ret = gup_result == -99999 ? (long)n : gup_result;
	if (ret > 0) pinned += ret;
	return ret;
}
static void unpin_user_pages(void *pages, unsigned long n)
{
	assert(pages && pinned >= n); pinned -= n;
}
static int account_locked_vm(struct mock_mm *mm, unsigned long n, bool add)
{
	if (add && account_error) return account_error;
	mm->locked += add ? (long)n : -(long)n; assert(mm->locked >= 0); return 0;
}
static size_t mock_spans = 1;
static int alloc_error, share_error, reclaim_error, shares, reclaims;
static struct gh_vm_mem *model_mapping(struct gh_vm *vm, u32 label, u64 gpa, u64 bytes)
{
	struct gh_vm_mem *m = mock_alloc(sizeof(*m));
	m->parcel.label = label; m->parcel.mem_handle = GH_MEM_HANDLE_INVAL;
	m->parcel.n_mem_entries = mock_spans;
	m->parcel.acl_entries = mock_alloc(2 * sizeof(*m->parcel.acl_entries));
	m->parcel.mem_entries = mock_alloc(1); m->pages = mock_alloc(1);
	m->guest_phys_addr = gpa; m->npages = bytes >> PAGE_SHIFT;
	pinned += m->npages; account_locked_vm(vm->mm, m->npages, true);
	list_add(&m->list, &vm->memory_mappings); return m;
}
static int gh_vm_mem_alloc(struct gh_vm *vm, struct gh_userspace_memory_region *r, bool lend)
{
	assert(!lend); if (alloc_error) return alloc_error;
	mutex_lock(&vm->mm_lock);
	struct gh_vm_mem *m;
	list_for_each_entry(m, &vm->memory_mappings, list) {
		if (m->parcel.label == r->label || (m->guest_phys_addr < r->guest_phys_addr + r->memory_size &&
		    r->guest_phys_addr < m->guest_phys_addr + ((u64)m->npages << PAGE_SHIFT))) {
			mutex_unlock(&vm->mm_lock); return -EEXIST;
		}
	}
	model_mapping(vm, r->label, r->guest_phys_addr, r->memory_size);
	mutex_unlock(&vm->mm_lock); return 0;
}
static int gh_rm_mem_share(struct gh_rm *rm, struct gh_rm_mem_parcel *p)
{
	(void)rm; ++shares; if (share_error) return share_error;
	p->mem_handle = p->label + 100; return 0;
}
static int gh_rm_mem_reclaim(struct gh_rm *rm, struct gh_rm_mem_parcel *p)
{
	(void)rm; (void)p; ++reclaims; return reclaim_error;
}
struct miscdevice {
	int minor; const char *name; const struct file_operations *fops;
	struct device *parent; unsigned int mode;
};
#define MISC_DYNAMIC_MINOR 255
static int register_error, registrations, deregistrations;
static int misc_register(struct miscdevice *m) { (void)m; ++registrations; return register_error; }
static void misc_deregister(struct miscdevice *m) { (void)m; ++deregistrations; }

static void show_mem(unsigned int filter, void *mask) { (void)filter; (void)mask; }
