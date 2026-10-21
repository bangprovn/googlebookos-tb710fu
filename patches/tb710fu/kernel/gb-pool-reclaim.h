/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef GB_POOL_RECLAIM_H
#define GB_POOL_RECLAIM_H

/* The retained core tests count==1 before asking about mapping. On this6.1
 * kernel an unmapped anonymous THP can retain tagged anon_vma metadata in
 * ->mapping. That is not a page-cache reference. Permit only a complete order9
 * anonymous folio with the pool's sole reference, no subpage/PMD mappings, no
 * swap-cache membership and no DMA pin. Native put_page/free processing still
 * decides when it is actually free; only that free callback returns it to AVAIL.
 * Never clear mapping fields, manufacture refcounts, or reuse it directly here.
 */
static inline int gb_pool_mapping_blocks_reclaim(struct page *page)
{
	if (!READ_ONCE(page->mapping))
		return 0;
	if (!PageHead(page) || compound_order(page) != 9 || !PageAnon(page) ||
	    PageSwapCache(page) || page_count(page) != 1 ||
	    total_mapcount(page) != 0 || page_maybe_dma_pinned(page))
		return 1;
	pr_info_ratelimited("gb-ram-pool-v2: quiescent anonymous order9 metadata accepted; refs=1 maps=0 pins=0 swapcache=0\n");
	return 0;
}

#endif
