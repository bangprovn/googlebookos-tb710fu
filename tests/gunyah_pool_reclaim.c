/* SPDX-License-Identifier: GPL-2.0-only */
/* Execute the exact adapter predicate with controlled page observations.
 * This is not a kernel folio/free/VM runtime emulator.
 */
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
struct page {
	void *mapping;
	bool head, anon, swapcache, pinned;
	int order, refs, maps;
};
#define READ_ONCE(x) (x)
#define PageHead(p) ((p)->head)
#define PageAnon(p) ((p)->anon)
#define PageSwapCache(p) ((p)->swapcache)
#define compound_order(p) ((p)->order)
#define page_count(p) ((p)->refs)
#define total_mapcount(p) ((p)->maps)
#define page_maybe_dma_pinned(p) ((p)->pinned)
static int accepted;
#define pr_info_ratelimited(...) (++accepted)
#include "../patches/tb710fu/kernel/gb-pool-reclaim.h"
int main(void)
{
	struct page quiescent = {.mapping=(void *)1, .head=true, .anon=true,
		.order=9, .refs=1};
	assert(!gb_pool_mapping_blocks_reclaim(&quiescent) && accepted==1);
	for (int field=0; field<9; field++) {
		struct page bad=quiescent;
		switch(field) {
		case 0: bad.head=false; break;
		case 1: bad.anon=false; break;
		case 2: bad.swapcache=true; break;
		case 3: bad.pinned=true; break;
		case 4: bad.order=8; break;
		case 5: bad.refs=2; break;
		case 6: bad.refs=0; break;
		case 7: bad.maps=1; break;
		case 8: bad.maps=-1; break;
		}
		assert(gb_pool_mapping_blocks_reclaim(&bad) && accepted==1);
	}
	quiescent.mapping=NULL;
	assert(!gb_pool_mapping_blocks_reclaim(&quiescent) && accepted==1);
	puts("Exact quiescent-anon predicate passed; active/file/swap/DMA/split states refused.");
}
