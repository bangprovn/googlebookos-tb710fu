//! Exact shared wire ABI and flow-control checks, without firmware execution.
// Preserve hash-pinned upstream integration fragments verbatim.
#[rustfmt::skip]
#[path = "../../../patches/tb710fu/crosvm/shim_abi_v4.rs"]
mod abi;
#[allow(clippy::manual_is_multiple_of, clippy::manual_range_contains)]
// Preserve hash-pinned upstream integration fragments verbatim.
#[rustfmt::skip]
#[path = "../../../patches/tb710fu/crosvm/runtime_parcel_plan.rs"]
mod plan;
fn main() {
    println!(
        "stream_abi={} bytes={}",
        abi::SHIM_ABI_VERSION,
        std::mem::size_of::<abi::ShimHandoff>()
    );
    let mut p =
        plan::ParcelPlan::new(2 << 20, 2 << 20, abi::SHIM_MAX_PARCELS).expect("fixed input");
    assert!(!p.split_refused().expect("fixed input"));
    assert!(p.request().expect("fixed input").is_some());
    p.accepted().expect("fixed input");
    assert!(abi::validate_stream(p.count() as u32, 1, 1).expect("fixed input"));
}
#[cfg(test)]
mod tests {
    use super::{abi, plan};
    use std::mem::{align_of, offset_of, size_of};
    #[test]
    fn producer_and_consumer_have_distinct_cache_lines_without_hidden_padding() {
        assert_eq!(abi::SHIM_ABI_VERSION, 4);
        assert_eq!(size_of::<abi::ShimHeader>(), 64);
        assert_eq!(size_of::<abi::ShimParcel>(), 24);
        assert_eq!(align_of::<abi::ShimHandoff>(), 64);
        assert_eq!(offset_of!(abi::ShimHandoff, parcel), 64);
        assert_eq!(offset_of!(abi::ShimHandoff, accepted), 64 + 1024 * 24);
        assert_eq!(offset_of!(abi::ShimHandoff, status), 64 + 1024 * 24 + 8);
        assert_eq!(
            size_of::<abi::ShimHandoff>(),
            64 + 1024 * 24 + 32 + 256 + 32
        );
        let h = abi::ShimHandoff::default();
        assert_eq!((h.nparcels, h.accepted, h.ready, h.status), (0, 0, 0, 0));
        assert_eq!(h.version, 4);
        assert!(h.parcel.iter().all(|p| p.handle == 0));
    }
    #[test]
    fn stalled_acceptance_never_accumulates_a_second_unaccepted_grant() {
        for memory_mib in [512, 2048] {
            let mut p = plan::ParcelPlan::new((memory_mib - 6) << 20, 16 << 20, 1024).unwrap();
            let mut accepted = 0u32;
            let mut bytes = 0u64;
            while let Some((offset, length)) = p.request().unwrap() {
                assert!(abi::validate_stream(p.count() as u32, accepted, 0).unwrap());
                assert_eq!(offset, bytes);
                // Model the tightest guard: only fully scattered 2 MiB grants pass.
                if length > 2 << 20 {
                    assert!(p.split_refused().unwrap());
                    continue;
                }
                p.accepted().unwrap();
                bytes += length;
                for _ in 0..7 {
                    assert!(!abi::validate_stream(p.count() as u32, accepted, 0).unwrap());
                    assert_eq!(p.count() as u32 - accepted, 1);
                    assert!(abi::validate_stream(p.count() as u32, accepted, 1).is_err());
                }
                accepted += 1;
            }
            assert_eq!(bytes, (memory_mib - 6) << 20);
            assert_eq!(accepted, p.count() as u32);
            assert!(abi::validate_stream(p.count() as u32, accepted, 1).unwrap());
        }
    }
    #[test]
    fn corrupt_or_premature_progress_is_refused() {
        for args in [
            (1025, 0, 0),
            (1, 2, 0),
            (2, 0, 0),
            (0, 0, 1),
            (1, 0, 1),
            (1, 1, 2),
        ] {
            assert!(abi::validate_stream(args.0, args.1, args.2).is_err());
        }
        assert!(abi::validate_stream(0, 0, 0).unwrap());
        assert!(!abi::validate_stream(1, 0, 0).unwrap());
    }
}
