//! Minimal dotted version comparison for CVE version ranges.
//!
//! Each dot-separated segment is compared as a `(numeric, suffix)` pair: the
//! leading digits numerically, then any trailing characters lexically. So
//! `2.4.49` reads as `[(2,""),(4,""),(49,"")]` and the OpenSSL letter releases
//! order correctly — `1.0.1f < 1.0.1g` — which the catalog's Heartbleed range
//! `1.0.1 .. 1.0.1f` depends on to exclude the patched `1.0.1g`. The suffix is
//! compared lexically, which matches single-letter release suffixes (the only
//! lettered versions in the catalog).

use std::cmp::Ordering;

/// Split a version into `(numeric, suffix)` per dot-separated segment.
fn segments(version: &str) -> Vec<(u64, String)> {
    version
        .split('.')
        .map(|segment| {
            let digits: String = segment.chars().take_while(char::is_ascii_digit).collect();
            let suffix: String = segment.chars().skip_while(char::is_ascii_digit).collect();
            (digits.parse::<u64>().unwrap_or(0), suffix)
        })
        .collect()
}

/// Compare two dotted version strings: numeric segments first, then any
/// trailing letter suffix lexically.
#[must_use]
pub fn cmp(a: &str, b: &str) -> Ordering {
    let (pa, pb) = (segments(a), segments(b));
    let empty = (0_u64, String::new());
    for i in 0..pa.len().max(pb.len()) {
        let x = pa.get(i).unwrap_or(&empty);
        let y = pb.get(i).unwrap_or(&empty);
        match x.0.cmp(&y.0).then_with(|| x.1.cmp(&y.1)) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    Ordering::Equal
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering::{Equal, Greater, Less};

    #[test]
    fn compares_numeric_segments() {
        assert_eq!(cmp("2.4.49", "2.4.50"), Less);
        assert_eq!(cmp("9.7", "8.5"), Greater);
        assert_eq!(cmp("1.0", "1.0.0"), Equal);
    }

    #[test]
    fn numeric_dominates_suffix() {
        // A bare version sorts before its lettered/patched releases...
        assert_eq!(cmp("8.9p1", "8.9"), Greater);
        assert_eq!(cmp("8.9p1", "9.0"), Less);
        // ...but the numeric component always wins over the suffix.
        assert_eq!(cmp("8.10", "8.9p1"), Greater);
    }

    #[test]
    fn letter_releases_order_within_a_segment() {
        // The Heartbleed boundary: 1.0.1f is vulnerable, 1.0.1g is patched.
        assert_eq!(cmp("1.0.1f", "1.0.1g"), Less);
        assert_eq!(cmp("1.0.1g", "1.0.1f"), Greater);
        assert_eq!(cmp("1.0.1", "1.0.1f"), Less);
    }
}
