# EDL subprocess bridge

`scripts/install/edl_bridge.py` is GPL-3.0-only and uses B. Kerler's
[EDL client](https://github.com/bkerler/edl), also GPLv3, as a separately installed
host tool. The Rust `gb-installer` package embeds this bridge and is distributed
under GPL-3.0-only. The rest of this workspace retains its existing licenses.
The GPLv3 text is in `LICENSE` here.

Qualified upstream revision: `2f8e89a848afaaef68997fcbcb5b178d958d497b`.
No upstream source or programmer binary is bundled by this directory.
The installer requires a clean checkout at that revision and checks the stock
programmer's SHA-256. See `releases/alpha1/INSTALL.md` for setup.

The bridge reuses upstream Sahara, USB, Firehose configure/read/program/reset.
It adds a JSON subprocess boundary, one-device USB guard, UFS identity binding,
explicit initial-program NACK rejection and a longer digest response timeout.
The digest timeout follows the adapter used for this port's successful local
EDL writes. Program completion requires a matching device-side SHA-256.
Vendor module hooks are disabled; the bridge exposes no erase, provisioning,
slot-change, arbitrary XML or authentication-bypass operation.
