//! Exercises the exact scheduler compiled into the source-built VMM.
// Keep this exact module compatible with the pinned Android Rust toolchain.
#[allow(clippy::manual_is_multiple_of, clippy::manual_range_contains)]
// Preserve hash-pinned upstream integration fragments verbatim.
#[rustfmt::skip]
#[path = "../../../patches/tb710fu/crosvm/runtime_parcel_plan.rs"]
mod plan;
fn main() {
    let mut p = plan::ParcelPlan::new(506 << 20, 16 << 20, 1024).expect("fixed valid window");
    while p.request().expect("bounded fixed window").is_some() {
        p.accepted().expect("pending request");
    }
    println!("contiguous_512_mib_parcels={}", p.count());
    // Exercise the refusal API in non-test builds too.
    assert!(p.split_refused().is_err());
}
