/* SPDX-License-Identifier: GPL-2.0-only */
/* Host-only resource/eventfd model for executing the actual patched driver.
 * Real wait-queue synchronization is modeled with pthread mutexes. This does
 * not simulate Gunyah interrupt delivery or replace a physical runtime test.
 */
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <sched.h>
#ifndef GB_GUNYAH_UAPI
#error Define GB_GUNYAH_UAPI to the exact kernel include/uapi/linux/gunyah.h
#endif
#include GB_GUNYAH_UAPI

typedef uint64_t u64;
typedef unsigned int __poll_t;
#define EPOLLIN 1
#define GFP_KERNEL 0
#define THIS_MODULE NULL
#define GH_RESOURCE_TYPE_BELL_TX 0
#define MODULE_DESCRIPTION(x)
#define MODULE_LICENSE(x)
#define DECLARE_GH_VM_FUNCTION_INIT(...)
#define pr_warn(...) ((void)0)
#define pr_err_ratelimited(...) ((void)0)
#define pr_info_ratelimited(...) ((void)0)
#define READ_ONCE(p) __atomic_load_n(&(p), __ATOMIC_ACQUIRE)
#define smp_load_acquire(p) __atomic_load_n(p, __ATOMIC_ACQUIRE)
#define smp_store_release(p, v) __atomic_store_n(p, v, __ATOMIC_RELEASE)
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define PTR_ERR(p) ((long)(intptr_t)(p))
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)

struct list_head { struct list_head *next, *prev; };
#define LIST_HEAD(n) struct list_head n = { &(n), &(n) }
#define INIT_LIST_HEAD(p) (*(p) = (struct list_head){ (p), (p) })
static void list_add(struct list_head *n, struct list_head *head)
{
	n->next = head->next; n->prev = head;
	head->next->prev = n; head->next = n;
}
static void list_del(struct list_head *n)
{
	n->next->prev = n->prev; n->prev->next = n->next;
	n->next = n->prev = NULL;
}
static bool list_empty(const struct list_head *head) { return head->next == head; }
#define list_for_each_entry(pos, head, field) \
	for (struct list_head *node__ = (head)->next; \
	     node__ != (head) && ((pos) = container_of(node__, __typeof__(*(pos)), field), 1); \
	     node__ = node__->next)
typedef pthread_mutex_t mock_mutex;
#define DEFINE_MUTEX(n) mock_mutex n = PTHREAD_MUTEX_INITIALIZER
#define mutex_lock(p) assert(!pthread_mutex_lock(p))
#define mutex_unlock(p) assert(!pthread_mutex_unlock(p))
static int allocated, allocation_fail_at, allocation_calls;
static void *kzalloc(size_t bytes, int flags)
{
	(void)flags;
	if (++allocation_calls == allocation_fail_at) return NULL;
	void *p = calloc(1, bytes); assert(p); ++allocated; return p;
}
static void kfree(void *p) { if (p) { --allocated; free(p); } }

struct wait_queue_entry;
typedef struct wait_queue_entry {
	int (*func)(struct wait_queue_entry *, unsigned int, int, void *);
} wait_queue_entry_t;
typedef struct {
	pthread_mutex_t lock;
	wait_queue_entry_t *waiters[16];
	size_t count;
} wait_queue_head_t;
struct file;
typedef struct poll_table_struct {
	void (*queue)(struct file *, wait_queue_head_t *, struct poll_table_struct *);
} poll_table;
struct eventfd_ctx { wait_queue_head_t queue; int refs; };
struct file { struct eventfd_ctx *ctx; bool regular; };
struct fd { struct file *file; };
static struct file handles[64];
static struct eventfd_ctx contexts[8];
static struct fd fdget(unsigned int fd)
{
	return (struct fd){ fd < 64 && (handles[fd].ctx || handles[fd].regular) ? &handles[fd] : NULL };
}
static void fdput(struct fd fd) { (void)fd; }
static struct eventfd_ctx *eventfd_ctx_fileget(struct file *file)
{
	if (!file || !file->ctx) return ERR_PTR(-EINVAL);
	++file->ctx->refs; return file->ctx;
}
static void eventfd_ctx_put(struct eventfd_ctx *ctx) { assert(ctx->refs > 0); --ctx->refs; }
static void init_waitqueue_func_entry(wait_queue_entry_t *wait,
	int (*fn)(wait_queue_entry_t *, unsigned int, int, void *)) { wait->func = fn; }
static void init_poll_funcptr(poll_table *pt,
	void (*queue)(struct file *, wait_queue_head_t *, poll_table *)) { pt->queue = queue; }
static void add_wait_queue(wait_queue_head_t *q, wait_queue_entry_t *wait)
{
	assert(!pthread_mutex_lock(&q->lock)); assert(q->count < 16);
	q->waiters[q->count++] = wait;
	assert(!pthread_mutex_unlock(&q->lock));
}
static unsigned int vfs_poll(struct file *file, poll_table *pt)
{
	pt->queue(file, &file->ctx->queue, pt); return 0;
}
static void eventfd_ctx_remove_wait_queue(struct eventfd_ctx *ctx, wait_queue_entry_t *wait, u64 *count)
{
	assert(!pthread_mutex_lock(&ctx->queue.lock));
	size_t i = 0;
	while (i < ctx->queue.count && ctx->queue.waiters[i] != wait) ++i;
	assert(i < ctx->queue.count);
	ctx->queue.waiters[i] = ctx->queue.waiters[--ctx->queue.count];
	*count = 0; assert(!pthread_mutex_unlock(&ctx->queue.lock));
}
static __poll_t key_to_poll(void *key) { return (__poll_t)(uintptr_t)key; }
static void signal_event(struct eventfd_ctx *ctx)
{
	assert(!pthread_mutex_lock(&ctx->queue.lock));
	for (size_t i = 0; i < ctx->queue.count; ++i)
		ctx->queue.waiters[i]->func(ctx->queue.waiters[i], 0, 0, (void *)EPOLLIN);
	assert(!pthread_mutex_unlock(&ctx->queue.lock));
}

struct gh_vm { unsigned int id; };
struct gh_resource { unsigned int capid; };
struct gh_vm_resource_ticket {
	unsigned int resource_type, label;
	void *owner;
	bool (*populate)(struct gh_vm_resource_ticket *, struct gh_resource *);
	void (*unpopulate)(struct gh_vm_resource_ticket *, struct gh_resource *);
};
struct gh_vm_function_instance { void *argp, *data; size_t arg_size; struct gh_vm *ghvm; };
struct mock_ticket { struct gh_vm_resource_ticket *ticket; struct gh_resource resource; };
static struct mock_ticket tickets[16];
static int ticket_adds, ticket_removes, ticket_error, mask_calls;
static atomic_uint sends[16];
static bool defer_resource;
static int gh_vm_add_resource_ticket(struct gh_vm *vm, struct gh_vm_resource_ticket *ticket)
{
	(void)vm;
	if (ticket_error) return ticket_error;
	for (size_t i = 0; i < 16; ++i) if (!tickets[i].ticket) {
		tickets[i] = (struct mock_ticket){ticket, {i}}; ++ticket_adds;
		if (!defer_resource) assert(ticket->populate(ticket, &tickets[i].resource));
		return 0;
	}
	assert(!"mock ticket budget exceeded"); return -ENOSPC;
}
static void gh_vm_remove_resource_ticket(struct gh_vm *vm, struct gh_vm_resource_ticket *ticket)
{
	(void)vm;
	for (size_t i = 0; i < 16; ++i) if (tickets[i].ticket == ticket) {
		ticket->unpopulate(ticket, &tickets[i].resource); tickets[i].ticket = NULL;
		++ticket_removes; return;
	}
	assert(!"removing unowned ticket");
}
static int gh_hypercall_bell_send(unsigned int capid, int value, void *result)
{
	(void)result; assert(capid < 16 && value == 1); atomic_fetch_add(&sends[capid], 1); return 0;
}
static int gh_hypercall_bell_set_mask(unsigned int capid, int mask, int ack)
{
	assert(capid < 16 && mask == 1 && ack == 1); ++mask_calls; return 0;
}
