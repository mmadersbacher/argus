//! Minimal dotted version comparison for CVE version ranges.
//!
//! Each dot-separated segment is compared as a `(numeric, suffix)` pair: the
//! leading digits numerically, then any trailing suffix by *natural* order —
//! the suffix is split into runs of digits (compared numerically) and
//! non-digits (compared lexically). So `2.4.49 < 2.4.50`, the OpenSSL letter
//! releases order correctly (`1.0.1f < 1.0.1g`, which the catalog's Heartbleed
//! range depends on), and numeric patch levels in the suffix order by value
//! rather than lexically (`8.9p2 < 8.9p10`). A present suffix outranks an
//! absent one (`1.0.1f > 1.0.1`).
//!
//! Known limitation: a suffix is always treated as a *later* release, so
//! pre-release tags (`1.0.0-rc1`) sort *after* their final release rather than
//! before. SemVer pre-release ordering is intentionally not modelled — it does
//! not occur in the catalog and is ambiguous against the patch-letter
//! convention above.

use std::cmp::Ordering;

/// Split a version into `(numeric, suffix)` per dot-separated segment.
fn segments(version: &str) -> Vec<(u64, &str)> {
    version
        .split('.')
        .map(|segment| {
            let split = segment
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(segment.len());
            let (digits, suffix) = segment.split_at(split);
            // Empty digits (a text-leading segment) is numeric 0; a real but
            // overflowing run saturates to MAX — matching `runs()` below, so an
            // absurdly long version sorts high consistently instead of
            // collapsing to 0 (smallest) on one code path and MAX on the other.
            let value = if digits.is_empty() {
                0
            } else {
                digits.parse::<u64>().unwrap_or(u64::MAX)
            };
            (value, suffix)
        })
        .collect()
}

/// One run within a suffix: a block of digits (compared numerically) or of
/// non-digits (compared lexically).
#[derive(PartialEq, Eq)]
enum Run<'a> {
    Num(u64),
    Text(&'a str),
}

/// Split a suffix into alternating digit / non-digit runs.
fn runs(suffix: &str) -> Vec<Run<'_>> {
    let mut out = Vec::new();
    let mut rest = suffix;
    while let Some(first) = rest.chars().next() {
        let digits = first.is_ascii_digit();
        let end = rest
            .find(|c: char| c.is_ascii_digit() != digits)
            .unwrap_or(rest.len());
        let (head, tail) = rest.split_at(end);
        out.push(if digits {
            Run::Num(head.parse::<u64>().unwrap_or(u64::MAX))
        } else {
            Run::Text(head)
        });
        rest = tail;
    }
    out
}

/// Natural comparison of two suffixes (see module docs).
fn cmp_suffix(left: &str, right: &str) -> Ordering {
    let (left_runs, right_runs) = (runs(left), runs(right));
    for i in 0..left_runs.len().max(right_runs.len()) {
        match (left_runs.get(i), right_runs.get(i)) {
            (Some(lhs), Some(rhs)) => {
                let ord = match (lhs, rhs) {
                    (Run::Num(ln), Run::Num(rn)) => ln.cmp(rn),
                    (Run::Text(lt), Run::Text(rt)) => lt.cmp(rt),
                    // A numeric run sorts before a textual one at the same
                    // position — arbitrary but stable; effectively never hit.
                    (Run::Num(_), Run::Text(_)) => Ordering::Less,
                    (Run::Text(_), Run::Num(_)) => Ordering::Greater,
                };
                if ord != Ordering::Equal {
                    return ord;
                }
            }
            // A present run outranks a missing one: "1.0.1f" > "1.0.1".
            (Some(_), None) => return Ordering::Greater,
            (None, Some(_)) => return Ordering::Less,
            (None, None) => unreachable!("index is below the longer run count"),
        }
    }
    Ordering::Equal
}

/// Compare two dotted version strings: numeric segments first, then any
/// trailing suffix by natural order.
#[must_use]
pub fn cmp(a: &str, b: &str) -> Ordering {
    let (pa, pb) = (segments(a), segments(b));
    for i in 0..pa.len().max(pb.len()) {
        let x = pa.get(i).copied().unwrap_or((0, ""));
        let y = pb.get(i).copied().unwrap_or((0, ""));
        match x.0.cmp(&y.0).then_with(|| cmp_suffix(x.1, y.1)) {
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

    #[test]
    fn numeric_patch_levels_in_suffix_order_by_value_not_lexically() {
        // The lexical-suffix bug: "p10" < "p2" as text, but 10 > 2 by value.
        assert_eq!(cmp("8.9p10", "8.9p2"), Greater);
        assert_eq!(cmp("8.9p2", "8.9p10"), Less);
        assert_eq!(cmp("8.9p2", "8.9p2"), Equal);
    }

    #[test]
    fn equal_versions_compare_equal() {
        assert_eq!(cmp("1.2.3", "1.2.3"), Equal);
        assert_eq!(cmp("10.0", "10.0"), Equal);
    }

    #[test]
    fn overflowing_numeric_segment_saturates_high_consistently() {
        let huge = "99999999999999999999999999"; // > u64::MAX
                                                 // A leading numeric segment that overflows sorts ABOVE a normal release
                                                 // (saturates to MAX), not below it as a silent 0.
        assert_eq!(cmp(huge, "9.0"), Greater);
        // The same saturation in a suffix run, so both code paths agree.
        assert_eq!(cmp(&format!("1.0p{huge}"), "1.0p2"), Greater);
        // A text-leading segment is still numeric 0 (empty-digits, unchanged).
        assert_eq!(cmp("a", "1"), Less);
    }
}
