//! Minimal dotted-numeric version comparison for CVE version ranges.
//!
//! Compares the leading numeric component of each dot-separated segment, so
//! `8.9p1` reads as `[8, 9]` and `2.4.49` as `[2, 4, 49]`. Sufficient for the
//! "is this version in the affected range" checks the catalog needs.

use std::cmp::Ordering;

fn parts(version: &str) -> Vec<u64> {
    version
        .split('.')
        .map(|segment| {
            let digits: String = segment.chars().take_while(char::is_ascii_digit).collect();
            digits.parse::<u64>().unwrap_or(0)
        })
        .collect()
}

/// Compare two dotted version strings numerically.
#[must_use]
pub fn cmp(a: &str, b: &str) -> Ordering {
    let (pa, pb) = (parts(a), parts(b));
    for i in 0..pa.len().max(pb.len()) {
        let x = pa.get(i).copied().unwrap_or(0);
        let y = pb.get(i).copied().unwrap_or(0);
        match x.cmp(&y) {
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
    fn ignores_non_numeric_suffix() {
        assert_eq!(cmp("8.9p1", "8.9"), Equal);
        assert_eq!(cmp("8.9p1", "9.0"), Less);
    }
}
