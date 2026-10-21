//! Tests the exact RAM-pool ABI/receipt validation compiled by the private VMM.
// Preserve hash-pinned upstream integration fragments verbatim.
#[rustfmt::skip]
#[path = "../../../patches/tb710fu/crosvm/ram_pool.rs"]
mod ram_pool;
fn main() {
    let _ = ram_pool::control;
    let _ = ram_pool::pin_window;
    let _ = |s: ram_pool::Stats| (s.available_2m, s.served_2m, s.held_2m);
}
