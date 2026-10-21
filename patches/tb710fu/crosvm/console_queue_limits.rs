// Copyright 2026 Googlebook port contributors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub(crate) fn valid(sizes: &[u16]) -> bool {
    sizes.len() == 2 && sizes.iter().all(|n| n.is_power_of_two() && *n <= 256)
}

pub(crate) fn apply(current: &mut [u16], requested: &[u16]) -> bool {
    if current.len() != requested.len() || !valid(requested) {
        return false;
    }
    current.copy_from_slice(requested);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserves_defaults_and_applies_donor_console_limits() {
        let mut sizes = [256, 256];
        assert!(apply(&mut sizes, &[2, 32]));
        assert_eq!(sizes, [2, 32]);
        assert!(apply(&mut sizes, &[256, 256]));
        assert_eq!(sizes, [256, 256]);
    }
    #[test]
    fn rejects_invalid_limits_without_partial_mutation() {
        for request in [
            vec![],
            vec![2],
            vec![2, 32, 4],
            vec![0, 32],
            vec![3, 32],
            vec![2, 512],
        ] {
            let mut sizes = [256, 256];
            assert!(!apply(&mut sizes, &request));
            assert_eq!(sizes, [256, 256]);
        }
        assert!(!apply(&mut [256], &[2, 32]));
    }
}
