//! Exercises the exact optional pre-pin gate compiled by the private VMM.
#[path = "../../../patches/tb710fu/crosvm/prepin_gate.rs"]
mod prepin_gate;
fn main() {
    eprintln!("Use cargo test --example check_prepin_gate; no device operation.");
    let _ = prepin_gate::coordinate::<fn(&str)>;
}
