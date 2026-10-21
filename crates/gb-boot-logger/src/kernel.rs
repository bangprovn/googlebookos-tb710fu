//! Append only new bytes when a bounded kernel ring drops its oldest prefix.
//! A linear-time prefix matcher avoids rescanning the ring quadratically.
pub fn overlap(previous: &[u8], current: &[u8]) -> usize {
    if current.is_empty() || previous.is_empty() {
        return 0;
    }
    if current.starts_with(previous) {
        return previous.len();
    }
    let mut prefix = vec![0usize; current.len()];
    for i in 1..current.len() {
        let mut matched = prefix[i - 1];
        while matched > 0 && current[i] != current[matched] {
            matched = prefix[matched - 1];
        }
        if current[i] == current[matched] {
            matched += 1;
        }
        prefix[i] = matched;
    }
    let mut matched = 0;
    for &byte in previous {
        if matched == current.len() {
            matched = prefix[matched - 1];
        }
        while matched > 0 && byte != current[matched] {
            matched = prefix[matched - 1];
        }
        if byte == current[matched] {
            matched += 1;
        }
    }
    matched
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rotation_retains_new_bytes_without_repeating_old_records() {
        let snapshots = [
            b"a\nb\nc\n".as_slice(),
            b"b\nc\nd\n",
            b"c\nd\ne\n",
            b"c\nd\ne\n",
        ];
        let mut result = Vec::new();
        let mut previous: &[u8] = &[];
        for current in snapshots {
            result.extend_from_slice(&current[overlap(previous, current)..]);
            previous = current;
        }
        assert_eq!(result, b"a\nb\nc\nd\ne\n");
        assert_eq!(overlap(b"old", b"lost data"), 0);
        assert_eq!(overlap(b"a\nb\nc\n", b"b\nc\n"), 4);
    }
    #[test]
    fn repeated_prefixes_match_exhaustive_suffix_reference() {
        let sequences: Vec<Vec<u8>> = (0..=6)
            .flat_map(|len| {
                (0..1u32 << len).map(move |n| (0..len).map(|i| ((n >> i) & 1) as u8).collect())
            })
            .collect();
        for previous in &sequences {
            for current in &sequences {
                let expected = (0..=previous.len().min(current.len()))
                    .rev()
                    .find(|&n| previous[previous.len() - n..] == current[..n])
                    .unwrap();
                assert_eq!(overlap(previous, current), expected);
            }
        }
    }
    #[test]
    #[ignore = "requires GB_TEST_KERNEL_CAPTURE from a private read-only diagnostic readback"]
    fn replay_recorded_ring_storm_preserves_records_with_bounded_growth() {
        let path = std::env::var("GB_TEST_KERNEL_CAPTURE").unwrap();
        assert!(std::fs::metadata(&path).unwrap().len() <= 8 * 1024 * 1024);
        let input = std::fs::read_to_string(path).unwrap();
        assert!(input.starts_with("GB_BOOT_DIAGNOSTICS_SERVICE_V1\n"));
        let first = input.find("<").unwrap();
        let body = &input[first..];
        let mut previous = Vec::new();
        let mut replay = Vec::new();
        for current in body.split("\n[kernel ring snapshot changed or rotated]\n") {
            let current = current.as_bytes();
            replay.extend_from_slice(&current[overlap(&previous, current)..]);
            previous.clear();
            previous.extend_from_slice(current);
        }
        assert!(
            replay.len() < input.len() / 4,
            "rotation duplicates were not removed"
        );
        let records = |s: &str| {
            s.lines()
                .filter(|l| l.starts_with('<'))
                .map(str::to_owned)
                .collect::<std::collections::BTreeSet<_>>()
        };
        assert_eq!(
            records(body),
            records(std::str::from_utf8(&replay).unwrap())
        );
        println!(
            "Replayed {} capture bytes into {} bytes without losing unique kernel records",
            input.len(),
            replay.len()
        );
    }
}
