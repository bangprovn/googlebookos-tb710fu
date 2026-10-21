//! Tests the exact shared host/shim ABI, with no device or firmware execution.
#[path = "../../../patches/tb710fu/crosvm/shim_abi_v3.rs"]
mod abi;

fn main() {
    println!(
        "shim_abi={} handoff_bytes={} max_parcels={}",
        abi::SHIM_ABI_VERSION,
        std::mem::size_of::<abi::ShimHandoff>(),
        abi::SHIM_MAX_PARCELS
    );
}

#[cfg(test)]
mod tests {
    use super::abi;
    use std::mem::{offset_of, size_of};

    #[test]
    fn versioned_handoff_offsets_and_last_slot_fit_handoff_region() {
        assert_eq!(abi::SHIM_ABI_VERSION, 3);
        assert_eq!(size_of::<abi::ShimHeader>(), 64);
        assert_eq!(size_of::<abi::ShimParcel>(), 24);
        assert_eq!(offset_of!(abi::ShimHandoff, parcel), 24);
        assert_eq!(offset_of!(abi::ShimHandoff, status), 24 + 1024 * 24);
        assert!(size_of::<abi::ShimHandoff>() <= 65536);
        let mut handoff = abi::ShimHandoff::default();
        handoff.parcel[1023] = abi::ShimParcel {
            handle: 129,
            reserved: 0,
            base: 0x100600000,
            size: 10 << 20,
        };
        assert_eq!(handoff.version, 3);
        assert_eq!(handoff.parcel[1023].handle, 129);
        assert_eq!(handoff.parcel[1022].handle, 0);
        assert_eq!(handoff.ready, 0);
    }

    #[test]
    fn windows_fit_with_worst_case_scatter() {
        for memory_mib in [512u64, 2048] {
            let window = (memory_mib - 6) << 20; // Existing 4 MiB boot + 2 MiB handoff.
            let chunk = 2u64 << 20;
            let count = window.div_ceil(chunk);
            assert!(count <= abi::SHIM_MAX_PARCELS as u64);
            let mut covered = 0;
            for parcel in 0..count {
                let length = chunk.min(window - parcel * chunk);
                for page_size in [4096u64, 16384, 65536] {
                    assert_eq!(length % page_size, 0);
                    assert!(
                        length / page_size <= 65536,
                        "kernel span guard must hold even without contiguity"
                    );
                }
                covered += length;
            }
            assert_eq!(covered, window);
            assert!(covered <= (2u64 << 30) + (64 << 20));
        }
        assert!(
            (((2048u64 - 6) << 20).div_ceil(2 << 20)) > 128,
            "the prior 128-slot ABI cannot represent the worst fragmented 2 GiB transfer"
        );
    }
}
