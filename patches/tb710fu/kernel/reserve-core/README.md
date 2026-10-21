# Reserve-pool core

The four source files in this directory and `LICENSE.txt` are retained from
[Droid-VM/gh-hugepage-reserve](https://github.com/Droid-VM/gh-hugepage-reserve/tree/e15c40d600dd19b2c5bcb220a92f7359c9ee0846),
commit `e15c40d600dd19b2c5bcb220a92f7359c9ee0846`, under GPL-2.0.
`upstream.json` records their original hashes.

The TB710FU adapter is `../gb-ram-pool.c`. It uses the owner and pool state
machines with kernel allocation/free operations. Allocation is optional,
bounded to 2048 MiB and at most half of managed RAM. Serving requires a valid
VM/current-mm binding. The adapter supports 4 KiB pages and order-9 blocks on
single-node kernels with built-in Gunyah support; other layouts disable the pool.

The adapter omits the upstream probes, private KAPI resolution, CMA reservoir,
pageblock relabeling and active reclaim. See the adjacent source manifests for
the required kernel revisions and patch dependencies.
