//! FF1 evaluation — correlation precision and honest confidence.
//!
//! Research question FF1: does the per-finding `match_confidence` actually
//! predict whether a catalog correlation is a true positive? The catalog has
//! two tiers — version-checked entries (a real version range → `High`) and
//! version-blind protocol/`Any` entries (matched on product alone → `Low`). The
//! claim ("honest confidence") is that `Low` findings are far more likely to be
//! false positives, so the label is a usable filter rather than decoration.
//!
//! Method: a ground-truth set pairs a product+version string with a CVE and the
//! NVD/vendor truth of whether that CVE applies to that version. The harness
//! feeds each string to [`argus_vuln::correlate_product`] and checks whether the
//! CVE is reported and at what confidence, then scores precision per tier. This
//! measures the correlator end to end — not a re-implementation of it.
//!
//! Dataset: a curated set is embedded; pass a path to run your own —
//! `cargo run -p argus-eval -- ff1 <file.csv>` with columns `product,cve_id,applies`.

use argus_core::Confidence;
use argus_vuln::correlate_product;

/// Default ground-truth set embedded in the crate (see `data/ff1-ground-truth.csv`).
const GROUND_TRUTH: &str = include_str!("../data/ff1-ground-truth.csv");

/// One ground-truth case: a product+version string, a CVE, and whether that CVE
/// really applies to that version per NVD / vendor advisory.
struct Case {
    product: String,
    cve_id: String,
    applies: bool,
}

/// What the correlator did with one case.
struct Outcome {
    applies: bool,
    reported: bool,
    confidence: Option<Confidence>,
}

/// Parse a `product,cve_id,applies` CSV (blank lines, `#` comments and a
/// `product` header row skipped). `applies` is true for `true`/`1`/`yes`.
fn parse(csv: &str) -> Vec<Case> {
    csv.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|line| {
            let mut col = line.split(',');
            let product = col.next()?.trim();
            let cve_id = col.next()?.trim();
            let applies = col.next()?.trim();
            if product.eq_ignore_ascii_case("product") {
                return None;
            }
            Some(Case {
                product: product.to_owned(),
                cve_id: cve_id.to_owned(),
                applies: matches!(applies, "true" | "1" | "yes"),
            })
        })
        .collect()
}

/// Run the correlator on one case and record whether the target CVE came back.
fn evaluate(case: &Case) -> Outcome {
    let hit = correlate_product(&case.product)
        .into_iter()
        .find(|v| v.cve_id == case.cve_id);
    Outcome {
        applies: case.applies,
        reported: hit.is_some(),
        confidence: hit.map(|v| v.match_confidence),
    }
}

/// Display label for a confidence tier.
fn label(c: Confidence) -> &'static str {
    match c {
        Confidence::Low => "Low",
        Confidence::Medium => "Medium",
        Confidence::High => "High",
        Confidence::Confirmed => "Confirmed",
    }
}

/// Precision (`tp / (tp + fp)`) for the reported subset, 0 if nothing reported.
fn precision(tp: usize, reported: usize) -> f64 {
    if reported == 0 {
        0.0
    } else {
        tp as f64 / reported as f64
    }
}

/// Run the FF1 harness on the embedded set, or on `path` if given.
pub fn run(path: Option<String>) {
    let data = path.map_or_else(
        || GROUND_TRUTH.to_owned(),
        |path| {
            std::fs::read_to_string(&path).unwrap_or_else(|e| {
                eprintln!("cannot read {path}: {e}");
                std::process::exit(1);
            })
        },
    );
    let cases = parse(&data);
    if cases.is_empty() {
        eprintln!("no cases parsed from the ground-truth set");
        std::process::exit(1);
    }
    let outcomes: Vec<Outcome> = cases.iter().map(evaluate).collect();

    let reported = outcomes.iter().filter(|o| o.reported).count();
    let tp = outcomes.iter().filter(|o| o.reported && o.applies).count();
    let fp = reported - tp;
    let missed = outcomes.iter().filter(|o| !o.reported && o.applies).count();
    let applies_total = outcomes.iter().filter(|o| o.applies).count();
    let recall = precision(tp, applies_total); // tp / (tp + fn)

    println!("FF1 — correlation precision & honest confidence (ground truth: NVD/vendor ranges)");
    println!(
        "dataset: {} cases ({} affected / {} not), {} CVEs\n",
        cases.len(),
        applies_total,
        cases.len() - applies_total,
        cases.len() / 2,
    );

    println!(
        "overall: precision {:.2} ({tp} TP, {fp} FP of {reported} reported), recall {:.2} ({tp}/{applies_total}), {missed} missed",
        precision(tp, reported),
        recall,
    );

    println!(
        "\n{:<11} {:>9} {:>4} {:>4} {:>11} {:>9}",
        "confidence", "reported", "TP", "FP", "precision", "FP-rate"
    );
    for c in [
        Confidence::Confirmed,
        Confidence::High,
        Confidence::Medium,
        Confidence::Low,
    ] {
        let rep = outcomes.iter().filter(|o| o.confidence == Some(c)).count();
        if rep == 0 {
            continue;
        }
        let t = outcomes
            .iter()
            .filter(|o| o.confidence == Some(c) && o.applies)
            .count();
        let p = precision(t, rep);
        println!(
            "{:<11} {:>9} {:>4} {:>4} {:>11.2} {:>9.2}",
            label(c),
            rep,
            t,
            rep - t,
            p,
            1.0 - p,
        );
    }

    // The honest exceptions, named: a High-confidence hit that is a false
    // positive means a catalog range too coarse to be trusted as "version
    // checked". A missed (applies but not reported) case means a catalog gap.
    println!("\nHigh-confidence false positives (range too coarse to trust):");
    let mut any_hi_fp = false;
    for (case, o) in cases.iter().zip(&outcomes) {
        if o.confidence == Some(Confidence::High) && !o.applies {
            any_hi_fp = true;
            println!(
                "  {:<22} {} reported on a patched version",
                case.product, case.cve_id
            );
        }
    }
    if !any_hi_fp {
        println!("  (none)");
    }

    println!(
        "\ninterpretation: filtering to version-checked (High) findings trades recall for\nprecision — version-blind (Low) hits are the false-positive reservoir and need\nverification, not blind trust. Run your own set: `cargo run -p argus-eval -- ff1 <file.csv>`."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_skipping_header_and_comments() {
        let c = parse("# c\nproduct,cve_id,applies\nLog4j 2.14.1,CVE-2021-44228,true\n");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].cve_id, "CVE-2021-44228");
        assert!(c[0].applies);
    }

    #[test]
    fn version_blind_hit_is_low_and_fires_on_a_patched_version() {
        // Log4j is a VersionRange::Any catalog entry: a patched 2.15.0 is still
        // reported (a false positive) — and it is flagged Low, which is the point.
        let patched = parse("Log4j 2.15.0,CVE-2021-44228,false");
        let o = evaluate(&patched[0]);
        assert!(o.reported, "Any-range entry reports regardless of version");
        assert_eq!(o.confidence, Some(Confidence::Low));
        assert!(
            !o.applies,
            "ground truth: 2.15.0 is patched -> this is a FP"
        );
    }

    #[test]
    fn version_checked_hit_is_high_and_suppressed_when_out_of_range() {
        // OpenSSH regreSSHion: in range -> reported High; the patched 9.8p1 is
        // out of range -> correctly not reported at all.
        let affected = parse("OpenSSH 9.6p1,CVE-2024-6387,true");
        let o = evaluate(&affected[0]);
        assert!(o.reported);
        assert_eq!(o.confidence, Some(Confidence::High));

        let patched = parse("OpenSSH 9.8p1,CVE-2024-6387,false");
        assert!(!evaluate(&patched[0]).reported);
    }

    #[test]
    fn embedded_set_separates_high_precision_from_low() {
        // The headline FF1 claim, asserted on the embedded set: the High tier is
        // strictly more precise than the Low tier.
        let cases = parse(GROUND_TRUTH);
        let outcomes: Vec<Outcome> = cases.iter().map(evaluate).collect();
        let prec = |c: Confidence| {
            let rep = outcomes.iter().filter(|o| o.confidence == Some(c)).count();
            let tp = outcomes
                .iter()
                .filter(|o| o.confidence == Some(c) && o.applies)
                .count();
            precision(tp, rep)
        };
        assert!(
            prec(Confidence::High) > prec(Confidence::Low),
            "High tier must be more precise than Low"
        );
    }
}
