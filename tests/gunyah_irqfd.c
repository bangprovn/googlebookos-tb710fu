/* SPDX-License-Identifier: GPL-2.0-only */
#include "gunyah_irqfd_mock.h"
#ifndef GB_IRQFD_SOURCE
#error Define GB_IRQFD_SOURCE to the patched gunyah_irqfd.c
#endif
#include GB_IRQFD_SOURCE

static struct gh_vm vm1 = {1}, vm2 = {2};
static struct gh_vm_function_instance instance(struct gh_vm *vm, struct gh_fn_irqfd_arg *args)
{
	return (struct gh_vm_function_instance){args, NULL, sizeof(*args), vm};
}
static void clean(void)
{
	assert(allocated == 0 && list_empty(&gh_irqfd_groups));
	for (size_t i = 0; i < 8; ++i) assert(!contexts[i].refs && !contexts[i].queue.count);
	for (size_t i = 0; i < 16; ++i) { assert(!tickets[i].ticket); atomic_store(&sends[i], 0); }
	ticket_adds = ticket_removes = mask_calls = ticket_error = 0;
	allocation_calls = allocation_fail_at = 0; defer_resource = false;
}
static void *writer(void *arg)
{
	struct eventfd_ctx *ctx = arg;
	for (int i = 0; i < 50000; ++i) { signal_event(ctx); if (!(i % 128)) sched_yield(); }
	return NULL;
}
int main(void)
{
	for (size_t i = 0; i < 8; ++i) assert(!pthread_mutex_init(&contexts[i].queue.lock, NULL));
	handles[10].ctx = handles[20].ctx = &contexts[0];
	handles[11].ctx = &contexts[1]; handles[12].ctx = &contexts[2];
	struct gh_fn_irqfd_arg aa = {10, 15, GH_IRQFD_FLAGS_LEVEL, 0};
	struct gh_fn_irqfd_arg bb = {11, 15, GH_IRQFD_FLAGS_LEVEL, 0};
	struct gh_fn_irqfd_arg cc = {12, 15, 0, 0};
	struct gh_fn_irqfd_arg alias = {20, 15, 0, 0};
	struct gh_vm_function_instance a = instance(&vm1, &aa), b = instance(&vm1, &bb);
	assert(!gh_irqfd_bind(&a)); assert(!gh_irqfd_bind(&b));
	assert(ticket_adds == 1 && mask_calls == 1);
	signal_event(&contexts[0]); signal_event(&contexts[1]); assert(atomic_load(&sends[0]) == 2);
	struct gh_vm_function_instance dup = instance(&vm1, &alias);
	alias.flags = GH_IRQFD_FLAGS_LEVEL;
	assert(gh_irqfd_bind(&dup) == -EEXIST);
	struct gh_vm_function_instance mixed = instance(&vm1, &cc);
	assert(gh_irqfd_bind(&mixed) == -EINVAL);
	alias.flags = 0; /* Existing removal ABI selects by label, not fd. */
	assert(gh_irqfd_compare(&a, &alias, sizeof(alias)));
	assert(gh_irqfd_compare(&b, &alias, sizeof(alias)));
	alias.label = 16; assert(!gh_irqfd_compare(&a, &alias, sizeof(alias))); alias.label = 15;
	alias.fd = 0; assert(gh_irqfd_compare(&a, &alias, sizeof(alias)));
	assert(!gh_irqfd_compare(&a, &aa, sizeof(aa) - 1));
	gh_irqfd_unbind(&a); assert(ticket_removes == 0);
	signal_event(&contexts[1]); assert(atomic_load(&sends[0]) == 3);
	gh_irqfd_unbind(&b); assert(ticket_removes == 1); clean();
	/* Model the manager's remove-all-matching loop using the legacy fd=0
	 * request; both producers detach before the one shared ticket is freed.
	 */
	a = instance(&vm1, &aa); b = instance(&vm1, &bb);
	assert(!gh_irqfd_bind(&a)); assert(!gh_irqfd_bind(&b));
	if (gh_irqfd_compare(&a, &alias, sizeof(alias))) gh_irqfd_unbind(&a);
	assert(ticket_removes == 0);
	if (gh_irqfd_compare(&b, &alias, sizeof(alias))) gh_irqfd_unbind(&b);
	assert(ticket_removes == 1); clean();
	/* Same label in distinct VMs has independent ownership and delivery. */
	a = instance(&vm1, &aa); b = instance(&vm2, &bb);
	assert(!gh_irqfd_bind(&a)); assert(!gh_irqfd_bind(&b));
	assert(ticket_adds == 2); signal_event(&contexts[0]); signal_event(&contexts[1]);
	assert(atomic_load(&sends[0]) == 1 && atomic_load(&sends[1]) == 1);
	gh_irqfd_unbind(&a); signal_event(&contexts[1]); assert(atomic_load(&sends[1]) == 2);
	gh_irqfd_unbind(&b); clean();
	/* One eventfd may still target distinct labels, as the original API
	 * allowed. Sharing a source does not conflate interrupt ownership.
	 */
	struct gh_fn_irqfd_arg other_label = {20, 16, GH_IRQFD_FLAGS_LEVEL, 0};
	a = instance(&vm1, &aa); b = instance(&vm1, &other_label);
	assert(!gh_irqfd_bind(&a)); assert(!gh_irqfd_bind(&b));
	signal_event(&contexts[0]);
	assert(atomic_load(&sends[0]) == 1 && atomic_load(&sends[1]) == 1);
	gh_irqfd_unbind(&a); signal_event(&contexts[0]);
	assert(atomic_load(&sends[0]) == 1 && atomic_load(&sends[1]) == 2);
	gh_irqfd_unbind(&b); clean();
	/* IRQ registration before RM resource population remains supported. */
	defer_resource = true; a = instance(&vm1, &aa); b = instance(&vm1, &bb);
	assert(!gh_irqfd_bind(&a)); assert(!gh_irqfd_bind(&b));
	signal_event(&contexts[0]); assert(!atomic_load(&sends[0]));
	assert(tickets[0].ticket->populate(tickets[0].ticket, &tickets[0].resource));
	signal_event(&contexts[1]); assert(atomic_load(&sends[0]) == 1);
	gh_irqfd_unbind(&b); gh_irqfd_unbind(&a); clean();
	/* Allocation, invalid descriptors/flags and RM failure leave no ownership. */
	for (int fail = 1; fail <= 2; ++fail) {
		allocation_fail_at = fail; a = instance(&vm1, &aa);
		assert(gh_irqfd_bind(&a) == -ENOMEM); clean();
	}
	ticket_error = -EBUSY; a = instance(&vm1, &aa);
	assert(gh_irqfd_bind(&a) == -EBUSY); clean();
	struct gh_fn_irqfd_arg bad = {(uint32_t)-1, 15, 0, 0}; a = instance(&vm1, &bad);
	assert(gh_irqfd_bind(&a) == -EBADF); clean();
	handles[13].regular = true; bad.fd = 13;
	assert(gh_irqfd_bind(&a) == -EINVAL); clean();
	bad.fd = 10; bad.flags = 2; assert(gh_irqfd_bind(&a) == -EINVAL); clean();
	a.arg_size = 0; assert(gh_irqfd_bind(&a) == -EINVAL); clean();
	/* Every write from both producers is forwarded; detaching one producer
	 * during concurrent writes cannot release the other producer's bell.
	 */
	a = instance(&vm1, &aa); b = instance(&vm1, &bb);
	assert(!gh_irqfd_bind(&a)); assert(!gh_irqfd_bind(&b));
	pthread_t first, second;
	assert(!pthread_create(&first, NULL, writer, &contexts[0]));
	assert(!pthread_create(&second, NULL, writer, &contexts[1]));
	assert(!pthread_join(first, NULL)); assert(!pthread_join(second, NULL));
	assert(atomic_load(&sends[0]) == 100000);
	assert(!pthread_create(&first, NULL, writer, &contexts[0]));
	gh_irqfd_unbind(&a); assert(ticket_removes == 0);
	assert(!pthread_join(first, NULL));
	unsigned int count = atomic_load(&sends[0]); signal_event(&contexts[1]);
	assert(atomic_load(&sends[0]) == count + 1);
	gh_irqfd_unbind(&b); clean();
	puts("Shared IRQ driver lifecycle, delivery, isolation, failure and concurrent-detach tests passed");
	return 0;
}
