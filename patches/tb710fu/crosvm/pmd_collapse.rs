// SPDX-License-Identifier: GPL-2.0-or-later
// Bounded bookkeeping for MADV_COLLAPSE, which requests PMD-sized THPs.
// Successful advice on a sub-PMD range does not establish a smaller folio.
pub const PMD_BYTES: u64 = 2 << 20;
pub const MAX_PASSES: usize = 4;
pub const MAX_ELAPSED_MS: u128 = 10_000;

pub struct PmdCollapse {
    missing: Vec<bool>,
    passes: usize,
}

impl PmdCollapse {
    pub fn new(bytes: u64) -> Self {
        Self { missing: vec![true; (bytes / PMD_BYTES) as usize], passes: 0 }
    }

    /// Deadline is checked between passes, not inside a kernel syscall.
    /// Returns attempted/failed requests; completed ranges are never retried.
    pub fn run_pass<F>(&mut self, elapsed_ms: u128, mut collapse: F) -> Option<(usize, usize)>
    where F: FnMut(u64) -> bool {
        if self.passes == MAX_PASSES || elapsed_ms >= MAX_ELAPSED_MS || self.complete() {
            return None;
        }
        self.passes += 1;
        let mut attempted = 0;
        let mut failed = 0;
        for (i, missing) in self.missing.iter_mut().enumerate() {
            if *missing {
                attempted += 1;
                *missing = !collapse(i as u64 * PMD_BYTES);
                failed += usize::from(*missing);
            }
        }
        Some((attempted, failed))
    }

    pub fn complete(&self) -> bool { !self.missing.iter().any(|v| *v) }
    pub fn missing(&self) -> &[bool] { &self.missing }
    pub fn advised_bytes(&self) -> u64 {
        self.missing.iter().filter(|v| !**v).count() as u64 * PMD_BYTES
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_only_failed_ranges_and_never_claim_a_tail() {
        let mut p = PmdCollapse::new(3 * PMD_BYTES + (1 << 20));
        let mut seen = Vec::new();
        assert_eq!(p.run_pass(0, |off| { seen.push(off); off != PMD_BYTES }), Some((3, 1)));
        assert_eq!(seen, vec![0, PMD_BYTES, 2 * PMD_BYTES]);
        assert_eq!(p.advised_bytes(), 2 * PMD_BYTES);
        seen.clear();
        assert_eq!(p.run_pass(100, |off| { seen.push(off); true }), Some((1, 0)));
        assert_eq!(seen, vec![PMD_BYTES]);
        assert_eq!(p.advised_bytes(), 3 * PMD_BYTES);
        assert_eq!(p.run_pass(200, |_| panic!("completed range retried")), None);
        assert_eq!(p.missing(), &[false, false, false]);
    }

    #[test]
    fn persistent_failure_is_bounded_by_passes_and_time() {
        let mut p = PmdCollapse::new(PMD_BYTES);
        for _ in 0..MAX_PASSES { assert_eq!(p.run_pass(0, |_| false), Some((1, 1))); }
        assert_eq!(p.run_pass(0, |_| panic!("retry budget exceeded")), None);
        assert_eq!(p.advised_bytes(), 0);
        let mut p = PmdCollapse::new(PMD_BYTES);
        assert_eq!(p.run_pass(MAX_ELAPSED_MS, |_| panic!("deadline exceeded")), None);
        assert!(!p.complete());
    }
}
