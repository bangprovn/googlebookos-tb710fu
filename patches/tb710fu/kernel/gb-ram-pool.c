// SPDX-License-Identifier: GPL-2.0-only
/* Optional early dense RAM supply. GPL-2.0 pool/owner core is retained from
 * Droid-VM/gh-hugepage-reserve e15c40d600dd19b2c5bcb220a92f7359c9ee0846.
 * No probes, private offsets, symbol resolution, CMA relabeling or reclaim
 * overrides. The caller must explicitly bind its real VM before allocation.
 */
#include <linux/gb-gunyah-pool.h>
#if IS_BUILTIN(CONFIG_GUNYAH)
#include <linux/file.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/ioport.h>
#include <linux/jiffies.h>
#include <linux/mm.h>
#include <linux/memblock.h>
#include <linux/mmzone.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pageblock-flags.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/swap.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include <trace/events/sched.h>
#include <trace/hooks/mm.h>
#include "vm_mgr.h"
#include "gb-runtime-share.h"

#include "reserve-core/gh_defs.h"
#include "reserve-core/gh_kernel_env.h"
#include "gb-pool-reclaim.h"
static bool gb_free_active;
bool gh_free_hook_active(void) { return READ_ONCE(gb_free_active); }
void gh_rebuild_order9(struct page *page) { gb_gunyah_pool_rebuild(page); }
#include "reserve-core/gh_owner.c.inc"
#define gh_page_has_mapping gb_pool_mapping_blocks_reclaim
#include "reserve-core/gh_pool.c.inc"
#undef gh_page_has_mapping

static unsigned int gb_pool_mib;
static bool gb_ready;
static DEFINE_MUTEX(gb_bind_lock);
static struct gh_vm *gb_bound_vm;
static pid_t gb_bound_tgid;
static u64 gb_bound_bytes;
static struct delayed_work gb_release_work;
static atomic_t gb_release_rounds = ATOMIC_INIT(0);

static int __init gb_pool_size(char *value)
{
	unsigned int mib;
	if (!kstrtouint(value, 0, &mib) && mib <= 2048 && !(mib & 1))
		gb_pool_mib = mib;
	else {
		gb_pool_mib = 0;
		pr_warn("gb-ram-pool-v1: invalid size; pool stays disabled\n");
	}
	return 0;
}
early_param("gb_vm_pool_mib", gb_pool_size);

/* Only this backend is used. Other core intake/CMA operations are absent
 * from the public adapter; no capability is claimed for them.
 */
static bool gb_cap(enum gh_kapi_cap cap) { return false; }
static struct page *gb_alloc(unsigned int order, int strong)
{
	if (order != GH_PAGE_ORDER || strong)
		return NULL;
	return alloc_pages(GFP_KERNEL | __GFP_COMP | __GFP_ZERO |
			   __GFP_NORETRY | __GFP_NOWARN, order);
}
static unsigned long gb_migratetype(unsigned long pfn)
{ return get_pageblock_migratetype(pfn_to_page(pfn)); }
static bool gb_movable(unsigned long pfn)
{ return !pfn_valid(pfn) || page_zonenum(pfn_to_page(pfn)) == ZONE_MOVABLE; }

struct gb_ranges { struct gh_ram_range *out; int count, max; };
static int gb_ram_range(unsigned long start, unsigned long count, void *arg)
{
	struct gb_ranges *r = arg;
	if (r->out && r->count < r->max)
		r->out[r->count] = (struct gh_ram_range){start, start + count};
	r->count++;
	return 0;
}
static int gb_walk_ram(struct gh_ram_range *out, int max)
{
	struct gb_ranges r = {.out = out, .max = max};
	int ret = walk_system_ram_range(0, max_pfn, &r, gb_ram_range);
	return ret ? ret : r.count;
}

static void gb_pool_free(void *data, struct page *page, struct zone *zone,
		int order, int migratetype, int flags, bool *bypass)
{
	if (order != GH_PAGE_ORDER || !READ_ONCE(gb_ready))
		return;
	if (gh_pool_released_return(page) == GH_RETURN_KEEP)
		*bypass = true;
}

/* A closed VM is not proof that its pages have been unmapped/unpinned.
 * The retained core tests real refcounts/mapping state before collection.
 * Dead-owner give-up relinquishes only the pool's reference, never firmware's.
 */
static void gb_release_fn(struct work_struct *work)
{
	int pending;
	pending = gh_pool_served_to_released();
	/* Order9 frees may wait in per-CPU lists before reaching the typed
	 * return callback. Drain through the real kernel API, in process context.
	 */
	drain_all_pages(NULL);
	gh_pool_served_to_ext(GH_EXPIRED);
	gh_pool_owner_sweep();
	pr_info("gb-ram-pool-v1: release avail=%d served=%d released=%d\n",
		gh_pool_avail(), gh_pool_served(), gh_pool_released());
	if (atomic_dec_if_positive(&gb_release_rounds) > 0 || pending)
		mod_delayed_work(system_wq, &gb_release_work, HZ);
}

static void gb_process_exit(void *unused, struct task_struct *task)
{
	pid_t tgid;
	int i;
	bool dead = false;
	if (!READ_ONCE(gb_ready) || !gh_pool_owner_any())
		return;
	tgid = task_tgid_nr(task);
	if (!gh_owner_tgid_maybe(tgid))
		return;
	gh_read_lock(&gh_pid_lock);
	for (i = 0; i < GH_VM_OWNER_MAX; i++)
		if (gh_owners[i].mm && gh_owners[i].tgid == tgid &&
		    !gh_owners[i].dead && gh_mm_users(gh_owners[i].mm) == 0)
			dead = true;
	gh_read_unlock(&gh_pid_lock);
	if (!dead)
		return;
	gh_pool_owner_mark_dead(tgid);
	atomic_set(&gb_release_rounds, GH_RELEASE_ROUNDS);
	mod_delayed_work(system_wq, &gb_release_work, HZ);
}

struct page *gb_gunyah_pool_take(gfp_t gfp, int nid, nodemask_t *mask)
{
	struct page *page;
	if (!READ_ONCE(gb_ready) || !current->mm || in_interrupt() || in_atomic() || irqs_disabled() ||
	    !(gfp & __GFP_MOVABLE) || !(gfp & __GFP_COMP) ||
	    (gfp & (__GFP_DMA | __GFP_DMA32 | __GFP_ACCOUNT)) ||
	    ((gfp & __GFP_THISNODE) && nid != 0) ||
	    (mask && !node_isset(0, *mask)) ||
	    !gh_pool_owner_maybe(current->mm))
		return NULL;
	/* A preallocated fast-path folio also serves GFP_TRANSHUGE_LIGHT.
	 * No reclaim/compaction is performed here; atomic/IRQ contexts remain
	 * excluded and native allocation hygiene runs outside all pool locks.
	 */
	page = gh_pool_avail_to_served(current->mm, task_tgid_nr(current));
	if (page)
		/* Native allocation hygiene, including HW KASAN tags and mandatory
		 * zeroing, outside every pool/owner/zone lock. Refcount2 is retained:
		 * one pool protection reference plus the new caller's reference.
		 */
		gb_gunyah_pool_prepare(page, gfp);
	return page;
}

int gb_gunyah_pool_control(struct gh_vm *vm, u64 bytes, bool query,
			  u32 *avail, u32 *served, u32 *held)
{
	int ret = 0;
	struct gh_pool_stats stats;
	if (!READ_ONCE(gb_ready))
		return -EOPNOTSUPP;
	if (bytes != GHSM_POOL_WINDOW_512 && bytes != GHSM_POOL_WINDOW_2048)
		return -EINVAL;
	mutex_lock(&gb_bind_lock);
	if (!query && !gb_bound_vm) {
		gh_pool_served_to_released();
		drain_all_pages(NULL);
		gh_pool_owner_sweep();
	}
	if (query) {
		if (gb_bound_vm != vm)
			ret = -ENOENT;
		else if (gb_bound_bytes != bytes)
			ret = -EINVAL;
	} else if (gb_bound_vm) {
		ret = gb_bound_vm == vm ? -EALREADY : -EBUSY;
	} else if (gh_pool_avail() < (bytes >> 21)) {
		ret = -ENOSPC;
	} else {
		gh_pool_owner_sweep();
		gh_pool_owner_add(current->mm, task_tgid_nr(current), current->comm);
		if (!gh_pool_owner_maybe(current->mm)) {
			ret = -ENOSPC;
		} else {
			gb_bound_vm = vm;
			gb_bound_bytes = bytes;
			gb_bound_tgid = task_tgid_nr(current);
		}
	}
	gh_pool_stats_snapshot(&stats);
	*avail = stats.avail;
	*served = stats.served;
	*held = stats.avail + stats.served + stats.released + stats.verify;
	mutex_unlock(&gb_bind_lock);
	return ret;
}

void gb_gunyah_pool_vm_release(struct gh_vm *vm)
{
	if (!READ_ONCE(gb_ready))
		return;
	mutex_lock(&gb_bind_lock);
	if (gb_bound_vm == vm) {
		gh_pool_owner_vm_dec(vm->mm, gb_bound_tgid);
		if (gh_mm_users(vm->mm) == 0)
			gh_pool_owner_mark_dead(gb_bound_tgid);
		gb_bound_vm = NULL;
		gb_bound_bytes = 0;
		atomic_set(&gb_release_rounds, GH_RELEASE_ROUNDS);
		mod_delayed_work(system_wq, &gb_release_work, HZ);
	}
	mutex_unlock(&gb_bind_lock);
}

static int __init gb_pool_init(void)
{
	struct gh_ram_range *ranges;
	enum gh_target_change change;
	int n, ret, i, target;
	if (!gb_pool_mib)
		return 0;
	if (PAGE_SHIFT != 12 || num_online_nodes() != 1 || !node_online(0) ||
	    ((u64)gb_pool_mib << 20) > ((u64)totalram_pages() << PAGE_SHIFT) / 2) {
		pr_warn("gb-ram-pool-v1: unsupported geometry/budget; disabled\n");
		return 0;
	}
	raw_spin_lock_init(&gh_pool_lock.l);
	rwlock_init(&gh_pid_lock);
	INIT_DELAYED_WORK(&gb_release_work, gb_release_fn);
	gh_kapi = (struct gh_kapi){.cap = gb_cap, .alloc_try = gb_alloc,
		.get_pfnblock_mt = gb_migratetype, .in_zone_movable = gb_movable};
	n = gb_walk_ram(NULL, 0);
	if (n <= 0)
		return 0;
	ranges = kcalloc(n, sizeof(*ranges), GFP_KERNEL);
	if (!ranges)
		return 0;
	ret = gb_walk_ram(ranges, n);
	target = gb_pool_mib / 2;
	if (ret != n || gh_pool_init_table(ranges, n, target)) {
		kfree(ranges);
		gh_pool_teardown_table();
		pr_warn("gb-ram-pool-v1: table unavailable; disabled\n");
		return 0;
	}
	kfree(ranges);
	/* Mark real CMA/ZONE_MOVABLE unavailable; never relabel or borrow it. */
	gh_pool_set_cma_config(GH_PAGE_ORDER, -1);
	gh_pool_mark_carveouts(MIGRATE_CMA);
	gh_pool_set_target(GH_TARGET_WANT, target, &change);
	for (i = 0; i < target; i++) {
		if (!gh_pool_ext_to_avail(GH_ALLOC_LIGHT, 0, NULL, 0))
			break;
		cond_resched();
	}
	ret = register_trace_android_vh_free_one_page_bypass(gb_pool_free, NULL);
	if (!ret) {
		WRITE_ONCE(gb_free_active, true);
		ret = register_trace_sched_process_exit(gb_process_exit, NULL);
		if (ret) {
			unregister_trace_android_vh_free_one_page_bypass(gb_pool_free, NULL);
			tracepoint_synchronize_unregister();
			WRITE_ONCE(gb_free_active, false);
		}
	}
	if (ret) {
		gh_pool_avail_to_ext(gh_pool_avail());
		gh_pool_teardown_table();
		pr_warn("gb-ram-pool-v1: typed callbacks unavailable; disabled\n");
		return 0;
	}
	WRITE_ONCE(gb_ready, true);
	gh_pool_set_ready(true);
	static_branch_enable(&gb_gunyah_pool_key);
	pr_info("gb-ram-pool-v1: ready target=%d avail=%d cma=disabled zeroing=native\n",
		target, gh_pool_avail());
	return 0;
}
subsys_initcall(gb_pool_init);
#endif
