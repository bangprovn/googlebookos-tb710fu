//! Checks the exact PMD retry/accounting code compiled by the private VMM.
// Preserve hash-pinned upstream integration fragments verbatim.
#[rustfmt::skip]
#[path = "../../../patches/tb710fu/crosvm/pmd_collapse.rs"]
mod pmd_collapse;
fn main() {
    let mut p = pmd_collapse::PmdCollapse::new(506 << 20);
    assert_eq!(p.run_pass(0, |_| true), Some((253, 0)));
    assert!(p.complete());
    assert_eq!(p.advised_bytes(), 506 << 20);
    assert!(p.missing().iter().all(|v| !v));
}
