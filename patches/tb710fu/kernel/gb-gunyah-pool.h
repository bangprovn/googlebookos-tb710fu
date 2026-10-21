/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_GB_GUNYAH_POOL_H
#define _LINUX_GB_GUNYAH_POOL_H

#include <linux/errno.h>
#include <linux/gfp_types.h>
#include <linux/jump_label.h>
#include <linux/kconfig.h>
#include <linux/nodemask.h>
#include <linux/types.h>

struct page;
struct gh_vm;
#if IS_BUILTIN(CONFIG_GUNYAH)
DECLARE_STATIC_KEY_FALSE(gb_gunyah_pool_key);
struct page *gb_gunyah_pool_take(gfp_t gfp, int preferred_nid,
			       nodemask_t *mask);
void gb_gunyah_pool_rebuild(struct page *page);
void gb_gunyah_pool_prepare(struct page *page, gfp_t gfp);
int gb_gunyah_pool_control(struct gh_vm *vm, u64 bytes, bool query,
			  u32 *avail, u32 *served, u32 *held);
void gb_gunyah_pool_vm_release(struct gh_vm *vm);
#else
static inline int gb_gunyah_pool_control(struct gh_vm *vm, u64 bytes,
		bool query, u32 *avail, u32 *served, u32 *held)
{ return -EOPNOTSUPP; }
static inline void gb_gunyah_pool_vm_release(struct gh_vm *vm) {}
#endif
#endif
