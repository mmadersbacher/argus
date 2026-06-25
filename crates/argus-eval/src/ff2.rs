//! FF2 evaluation — prioritisation quality.
//!
//! Research question FF2: does the context-aware composite score prioritise
//! vulnerabilities better than a raw CVSS sort? Ground truth is the CISA KEV
//! catalog ("really exploited" → should rank high). The harness ranks a dataset
//! three ways and reports KEV recall@N, mean KEV rank, ROC-AUC (separation of
//! exploited from non-exploited) and average precision (the rare-positive
//! ranking standard).
//!
//! ## Avoiding circularity (the measure that actually counts)
//!
//! KEV is the ground truth **and** an input to the full composite (it floors the
//! likelihood term to ≥0.9, see [`argus_core::RiskScore::compute`]). Scoring the
//! full composite against KEV is therefore partly *definitional* — a chunk of
//! its separation is engineered, not discovered, and must not be reported as
//! predictive power. So the harness reports a third ranking, **`comp -KEV`**: the
//! same composite with KEV forced off (CVSS + EPSS only). Its ROC-AUC against KEV
//! is the **non-circular** result — can the model rank exploited bugs high
//! *without* being told they are exploited? Any lift there over CVSS-only is real
//! predictive signal, carried by EPSS (itself an independent exploitation-
//! probability model). The full `composite` column is kept to show the shipped
//! product's ranking, not as evidence of predictive power.
//!
//! A fully non-circular alternative (future work) is a **temporal holdout**:
//! score CVEs on a pre-date snapshot and measure recall against CVEs *added* to
//! KEV afterwards. The `comp -KEV` column is the cheap, dataset-local proxy.
//!
//! Dataset: a small curated CSV is embedded as the default; pass a path to run
//! against a real one — `cargo run -p argus-eval -- ff2 <file.csv>` with columns
//! `cve_id,cvss,epss,kev` (empty cvss = NVD has not scored it). The measurement
//! logic is dataset-agnostic; for a headline result feed the full FIRST.org
//! EPSS set joined with CISA KEV and NVD CVSS.

use argus_core::{
    Confidence, Criticality, Cvss, Epss, Exposure, RiskScore, Severity, Vulnerability,
};
use argus_vuln::risk_inputs;

/// Default dataset embedded in the crate (see `data/ff2-sample.csv`).
const SAMPLE: &str = include_str!("../data/ff2-sample.csv");

/// One scored vulnerability. `cvss` is `None` when NVD has not scored the CVE.
struct Finding {
    id: String,
    cvss: Option<f32>,
    kev: bool,
    /// The full product composite (CVSS + EPSS + KEV floor + exposure/crit).
    composite: f32,
    /// The composite with KEV **forced off** — CVSS + EPSS only. Measured
    /// against KEV ground truth this is the *non-circular* predictive signal:
    /// can the model rank exploited bugs high *without* being told they are
    /// exploited? (The full `composite` uses KEV as an input, so scoring it
    /// against KEV is partly definitional — see the module docs.)
    composite_no_kev: f32,
}

/// Composite score for a single CVE on a maximally-exposed, critical asset
/// (so the exposure/criticality factors are 1.0 and only CVSS + EPSS + the KEV
/// likelihood-floor drive it). A missing CVSS contributes zero severity but the
/// EPSS and KEV signals still score it — unlike a CVSS sort, which cannot.
fn composite_score(cvss: Option<f32>, epss: f32, kev: bool) -> f32 {
    let vuln = Vulnerability {
        cve_id: String::new(),
        cvss: cvss.map(|base_score| Cvss {
            base_score,
            vector: None,
        }),
        epss: Some(Epss {
            score: epss,
            percentile: None,
        }),
        kev,
        severity: cvss.map_or(Severity::None, Severity::from_cvss),
        match_confidence: Confidence::High,
    };
    let inputs = risk_inputs(&[vuln], Exposure::InternetFacing, Criticality::Critical);
    RiskScore::compute(&inputs).value
}

/// Parse a `cve_id,cvss,epss,kev` CSV. Blank lines, `#` comments and a `cve_id`
/// header row are skipped; an empty cvss cell yields `None`.
fn parse_dataset(csv: &str) -> Vec<Finding> {
    csv.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|line| {
            let mut col = line.split(',');
            let id = col.next()?.trim();
            if id.is_empty() || id.eq_ignore_ascii_case("cve_id") {
                return None;
            }
            let cvss_cell = col.next()?.trim();
            let cvss = if cvss_cell.is_empty() {
                None
            } else {
                cvss_cell.parse::<f32>().ok()
            };
            let epss = col.next()?.trim().parse::<f32>().ok()?;
            let kev = matches!(col.next()?.trim(), "true" | "1" | "yes");
            Some(Finding {
                composite: composite_score(cvss, epss, kev),
                composite_no_kev: composite_score(cvss, epss, false),
                id: id.to_owned(),
                cvss,
                kev,
            })
        })
        .collect()
}

/// Indices ordered by descending CVSS; CVEs with no CVSS sort to the very end.
fn rank_by_cvss(f: &[Finding]) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..f.len()).collect();
    idx.sort_by(|&a, &b| {
        let ka = f[a].cvss.unwrap_or(f32::NEG_INFINITY);
        let kb = f[b].cvss.unwrap_or(f32::NEG_INFINITY);
        kb.total_cmp(&ka)
    });
    idx
}

/// Indices ordered by descending composite score.
fn rank_by_composite(f: &[Finding]) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..f.len()).collect();
    idx.sort_by(|&a, &b| f[b].composite.total_cmp(&f[a].composite));
    idx
}

/// Indices ordered by descending KEV-excluded composite (the non-circular
/// predictive ranking).
fn rank_by_composite_no_kev(f: &[Finding]) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..f.len()).collect();
    idx.sort_by(|&a, &b| f[b].composite_no_kev.total_cmp(&f[a].composite_no_kev));
    idx
}

/// Fraction of KEV findings in the top-`n` of `ranking` (1.0 = all on top).
fn kev_recall(f: &[Finding], ranking: &[usize], n: usize) -> f64 {
    let total = f.iter().filter(|x| x.kev).count();
    if total == 0 {
        return 0.0;
    }
    let hits = ranking.iter().take(n).filter(|&&i| f[i].kev).count();
    hits as f64 / total as f64
}

/// Mean 1-indexed rank of the KEV findings (lower = prioritised higher).
fn mean_kev_rank(f: &[Finding], ranking: &[usize]) -> f64 {
    let ranks: Vec<usize> = ranking
        .iter()
        .enumerate()
        .filter(|&(_, &i)| f[i].kev)
        .map(|(pos, _)| pos + 1)
        .collect();
    if ranks.is_empty() {
        return 0.0;
    }
    ranks.iter().sum::<usize>() as f64 / ranks.len() as f64
}

/// ROC-AUC — the probability that a random KEV CVE outranks a random non-KEV
/// one under `scores` (the Mann-Whitney U statistic, with average ranks for
/// ties). `0.5` is no better than chance, `1.0` is perfect separation. Unlike
/// the mean rank it is **size-invariant**, so the composite-vs-CVSS comparison
/// is comparable across datasets of any size.
fn roc_auc(scores: &[f64], is_pos: &[bool]) -> f64 {
    let n_pos = is_pos.iter().filter(|&&p| p).count();
    let n_neg = is_pos.len() - n_pos;
    if n_pos == 0 || n_neg == 0 {
        return 0.0;
    }
    // Ascending ranks, averaged within each tie group (so the thousands of
    // identical CVSS 9.8s — and the no-CVSS floor — are handled correctly).
    let mut idx: Vec<usize> = (0..scores.len()).collect();
    idx.sort_by(|&a, &b| scores[a].total_cmp(&scores[b]));
    let mut ranks = vec![0.0_f64; scores.len()];
    let mut i = 0;
    while i < idx.len() {
        let mut j = i;
        while j + 1 < idx.len()
            && scores[idx[j + 1]].total_cmp(&scores[idx[i]]) == std::cmp::Ordering::Equal
        {
            j += 1;
        }
        let avg_rank = (i + 1 + j + 1) as f64 / 2.0;
        for &k in &idx[i..=j] {
            ranks[k] = avg_rank;
        }
        i = j + 1;
    }
    let sum_pos_ranks: f64 = (0..scores.len())
        .filter(|&k| is_pos[k])
        .map(|k| ranks[k])
        .sum();
    let u = sum_pos_ranks - (n_pos * (n_pos + 1)) as f64 / 2.0;
    u / (n_pos as f64 * n_neg as f64)
}

/// Average precision — the area under the precision–recall curve for `ranking`,
/// the standard summary for ranking a **rare** positive class (KEV is ~0.5% of
/// all scored CVEs). `1.0` means every KEV CVE is ranked above every non-KEV
/// one; it rewards putting exploited bugs at the very top, not just near it.
fn average_precision(f: &[Finding], ranking: &[usize]) -> f64 {
    let total_pos = f.iter().filter(|x| x.kev).count();
    if total_pos == 0 {
        return 0.0;
    }
    let mut tp = 0_usize;
    let mut sum = 0.0_f64;
    for (pos, &i) in ranking.iter().enumerate() {
        if f[i].kev {
            tp += 1;
            sum += tp as f64 / (pos + 1) as f64;
        }
    }
    sum / total_pos as f64
}

/// 1-indexed position of `id` in `ranking`, or 0 if absent.
fn position(f: &[Finding], ranking: &[usize], id: &str) -> usize {
    ranking
        .iter()
        .position(|&i| f[i].id == id)
        .map_or(0, |p| p + 1)
}

/// Run the FF2 harness on the embedded sample, or on `path` if given.
pub fn run(path: Option<String>) {
    let dataset = path.map_or_else(
        || SAMPLE.to_owned(),
        |path| {
            std::fs::read_to_string(&path).unwrap_or_else(|e| {
                eprintln!("cannot read {path}: {e}");
                std::process::exit(1);
            })
        },
    );
    let findings = parse_dataset(&dataset);
    if findings.is_empty() {
        eprintln!("no findings parsed from the dataset");
        std::process::exit(1);
    }

    let total = findings.len();
    let kev_n = findings.iter().filter(|f| f.kev).count();
    let no_cvss = findings.iter().filter(|f| f.cvss.is_none()).count();
    let by_cvss = rank_by_cvss(&findings);
    let by_comp = rank_by_composite(&findings);
    let by_comp_nokev = rank_by_composite_no_kev(&findings);

    println!("FF2 — prioritisation: composite vs CVSS-only (ground truth: CISA KEV)");
    println!("dataset: {total} CVEs, {kev_n} KEV, {no_cvss} without CVSS (NVD gap)");
    println!(
        "  'comp -KEV' (CVSS+EPSS, KEV excluded from the score) is the NON-CIRCULAR\n  \
         predictive measure; the full 'composite' uses KEV as an input, so scoring\n  \
         it against KEV is partly definitional — read 'comp -KEV' as the real signal.\n"
    );

    println!(
        "{:<18} {:>11} {:>11} {:>11}",
        "metric", "CVSS-only", "comp -KEV", "composite"
    );
    println!(
        "{:<18} {:>11.2} {:>11.2} {:>11.2}",
        "KEV recall@N",
        kev_recall(&findings, &by_cvss, kev_n),
        kev_recall(&findings, &by_comp_nokev, kev_n),
        kev_recall(&findings, &by_comp, kev_n),
    );
    println!(
        "{:<18} {:>11.2} {:>11.2} {:>11.2}  (lower=better)",
        "mean KEV rank",
        mean_kev_rank(&findings, &by_cvss),
        mean_kev_rank(&findings, &by_comp_nokev),
        mean_kev_rank(&findings, &by_comp),
    );
    // Size-invariant standards: the mean rank above scales with N and is hard to
    // compare across datasets; ROC-AUC and average precision are not.
    let is_kev: Vec<bool> = findings.iter().map(|f| f.kev).collect();
    let cvss_scores: Vec<f64> = findings
        .iter()
        .map(|f| f.cvss.map_or(f64::NEG_INFINITY, f64::from))
        .collect();
    let comp_scores: Vec<f64> = findings.iter().map(|f| f64::from(f.composite)).collect();
    let comp_nokev_scores: Vec<f64> = findings
        .iter()
        .map(|f| f64::from(f.composite_no_kev))
        .collect();
    println!(
        "{:<18} {:>11.3} {:>11.3} {:>11.3}  (0.5=chance, higher=better)",
        "ROC-AUC",
        roc_auc(&cvss_scores, &is_kev),
        roc_auc(&comp_nokev_scores, &is_kev),
        roc_auc(&comp_scores, &is_kev),
    );
    println!(
        "{:<18} {:>11.3} {:>11.3} {:>11.3}  (higher=better)",
        "avg precision",
        average_precision(&findings, &by_cvss),
        average_precision(&findings, &by_comp_nokev),
        average_precision(&findings, &by_comp),
    );

    // The FF2 effect: exploited (KEV) CVEs that a CVSS sort mis-ranks — low-CVSS
    // ones, and worst, the NVD-gap CVEs with no CVSS (sorted to the bottom). On a
    // full dataset there can be many, so the list is capped.
    let under: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.kev && f.cvss.is_none_or(|c| c < 7.0))
        .collect();
    let no_cvss_kev = under.iter().filter(|f| f.cvss.is_none()).count();
    println!(
        "\nexploited (KEV) CVEs CVSS-only under-ranks (cvss<7 or none): {} total, {no_cvss_kev} with no CVSS",
        under.len(),
    );
    for f in under.iter().take(25) {
        let cvss = f
            .cvss
            .map_or_else(|| "none".to_owned(), |c| format!("{c:.1}"));
        println!(
            "  {:<16} cvss {:>4}  cvss-rank {:>6}  composite-rank {:>6}",
            f.id,
            cvss,
            position(&findings, &by_cvss, &f.id),
            position(&findings, &by_comp, &f.id),
        );
    }
    if under.len() > 25 {
        println!("  ... and {} more", under.len() - 25);
    }
    if under.is_empty() {
        println!("  (none in this dataset)");
    }

    println!("\nRun against your own data: `cargo run -p argus-eval -- ff2 <file.csv>`");
    println!("(cve_id,cvss,epss,kev; empty cvss = NVD gap).");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_csv_skipping_comments_header_and_empty_cvss() {
        let csv = "# note\ncve_id,cvss,epss,kev\nCVE-1,9.8,0.9,true\nCVE-2,,0.8,true\nCVE-3,4.0,0.01,false\n";
        let f = parse_dataset(csv);
        assert_eq!(f.len(), 3);
        assert_eq!(f[1].cvss, None);
        assert!(f[0].kev);
        assert!(!f[2].kev);
    }

    #[test]
    fn cvss_sort_buries_a_no_cvss_kev_cve_that_composite_lifts() {
        // KEV CVE with no CVSS but high EPSS: CVSS-only sorts it last; the
        // composite (KEV floor + EPSS) ranks it above the low-risk noise.
        let f =
            parse_dataset("CVE-hi,9.8,0.02,false\nCVE-gap,,0.9,true\nCVE-noise,3.0,0.01,false\n");
        assert_eq!(position(&f, &rank_by_cvss(&f), "CVE-gap"), 3);
        assert!(position(&f, &rank_by_composite(&f), "CVE-gap") < 3);
    }

    #[test]
    fn composite_prioritises_kev_at_least_as_well_on_the_sample() {
        let f = parse_dataset(SAMPLE);
        assert!(!f.is_empty());
        let cvss = mean_kev_rank(&f, &rank_by_cvss(&f));
        let comp = mean_kev_rank(&f, &rank_by_composite(&f));
        assert!(
            comp < cvss,
            "composite should rank KEV CVEs higher: {comp} vs {cvss}"
        );
    }

    #[test]
    fn roc_auc_is_one_for_perfect_zero_for_reversed_half_for_tied() {
        // KEV scored strictly above non-KEV → perfect separation.
        assert!((roc_auc(&[3.0, 2.0, 1.0], &[true, false, false]) - 1.0).abs() < 1e-9);
        // KEV scored strictly below → worst.
        assert!(roc_auc(&[1.0, 2.0, 3.0], &[true, false, false]).abs() < 1e-9);
        // Everything tied → exactly chance (0.5), via the average-rank handling.
        assert!((roc_auc(&[1.0, 1.0, 1.0, 1.0], &[true, false, true, false]) - 0.5).abs() < 1e-9);
    }

    #[test]
    fn average_precision_is_one_when_all_positives_lead() {
        let f = parse_dataset("CVE-a,9.0,0.9,true\nCVE-b,8.0,0.9,true\nCVE-c,1.0,0.0,false\n");
        // The composite ranks both KEV CVEs first → every positive at precision 1.
        let ap = average_precision(&f, &rank_by_composite(&f));
        assert!((ap - 1.0).abs() < 1e-9, "AP should be 1.0, got {ap}");
    }

    #[test]
    fn no_kev_composite_excludes_the_kev_floor() {
        // The non-circular measure: with KEV forced off, the 0.9 likelihood
        // floor must NOT apply. For a KEV CVE with low EPSS, excluding KEV lowers
        // the score (the floor only lifts the full composite).
        let full = composite_score(Some(5.0), 0.01, true);
        let no_kev = composite_score(Some(5.0), 0.01, false);
        assert!(
            no_kev < full,
            "KEV floor must only affect the full composite"
        );
        // When EPSS already exceeds the floor, KEV adds nothing → the two agree.
        let full_hi = composite_score(Some(5.0), 0.95, true);
        let nokev_hi = composite_score(Some(5.0), 0.95, false);
        assert!((full_hi - nokev_hi).abs() < 1e-6);
    }

    #[test]
    fn no_kev_composite_is_populated_and_drops_the_floor_on_a_dataset() {
        let f = parse_dataset("CVE-k,5.0,0.01,true\nCVE-n,5.0,0.01,false\n");
        let kev = f.iter().find(|x| x.id == "CVE-k").expect("kev row");
        // The KEV row's full composite is floored above its KEV-excluded one.
        assert!(kev.composite > kev.composite_no_kev);
    }

    #[test]
    fn composite_separates_kev_by_auc_at_least_as_well_as_cvss() {
        // The FF2 claim restated in size-invariant terms: the composite's ROC-AUC
        // is no worse than CVSS-only's on the sample (and strictly better once a
        // no-CVSS KEV CVE is present, which CVSS sorts to the bottom).
        let f = parse_dataset(SAMPLE);
        let is_kev: Vec<bool> = f.iter().map(|x| x.kev).collect();
        let cvss: Vec<f64> = f
            .iter()
            .map(|x| x.cvss.map_or(f64::NEG_INFINITY, f64::from))
            .collect();
        let comp: Vec<f64> = f.iter().map(|x| f64::from(x.composite)).collect();
        assert!(
            roc_auc(&comp, &is_kev) >= roc_auc(&cvss, &is_kev),
            "composite AUC must beat or match CVSS-only"
        );
    }
}
