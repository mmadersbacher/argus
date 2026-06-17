//! FF2 evaluation harness — prioritisation quality.
//!
//! Research question FF2: does the context-aware composite score (CVSS + EPSS +
//! KEV + exposure + criticality) prioritise vulnerabilities better than a raw
//! CVSS sort? Ground truth is the CISA KEV catalog ("really exploited" → should
//! rank high). The harness ranks the dataset both ways and reports KEV recall@N
//! and the mean rank of KEV CVEs under each ranking.
//!
//! Dataset caveat (be honest in the thesis): the bundled offline catalog (~37
//! curated CVEs) is KEV-heavy and CVSS-high-heavy, and every entry carries a
//! CVSS — so it understates the effect and cannot show the "missing-CVSS / NVD
//! gap" case at all. The *measurement logic* here is the reusable artefact:
//! swap [`dataset`] for a live/official EPSS+KEV set and the metrics still hold.

#![allow(clippy::cast_precision_loss)]

use argus_core::{Confidence, Criticality, Cvss, Epss, Exposure, RiskScore, Vulnerability};
use argus_vuln::{catalog, risk_inputs};

/// One scored vulnerability: its CVSS, KEV ground-truth flag, and the Argus
/// composite score computed for a single-vuln, maximally-exposed asset (so the
/// exposure/criticality factors are 1.0 and only the CVE-intrinsic blend of
/// CVSS, EPSS and the KEV likelihood-floor drives the score).
struct Finding {
    id: &'static str,
    cvss: f32,
    kev: bool,
    composite: f32,
}

/// Build the evaluation dataset from the offline catalog.
fn dataset() -> Vec<Finding> {
    catalog::CATALOG
        .iter()
        .map(|rec| {
            let vuln = Vulnerability {
                cve_id: rec.cve_id.to_owned(),
                cvss: Some(Cvss {
                    base_score: rec.cvss,
                    vector: None,
                }),
                epss: Some(Epss {
                    score: rec.epss,
                    percentile: None,
                }),
                kev: rec.kev,
                severity: rec.severity,
                match_confidence: Confidence::High,
            };
            let inputs = risk_inputs(&[vuln], Exposure::InternetFacing, Criticality::Critical);
            Finding {
                id: rec.cve_id,
                cvss: rec.cvss,
                kev: rec.kev,
                composite: RiskScore::compute(&inputs).value,
            }
        })
        .collect()
}

/// Indices of `findings` ordered by descending CVSS.
fn rank_by_cvss(findings: &[Finding]) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..findings.len()).collect();
    idx.sort_by(|&a, &b| findings[b].cvss.total_cmp(&findings[a].cvss));
    idx
}

/// Indices of `findings` ordered by descending composite score.
fn rank_by_composite(findings: &[Finding]) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..findings.len()).collect();
    idx.sort_by(|&a, &b| findings[b].composite.total_cmp(&findings[a].composite));
    idx
}

/// Fraction of KEV findings that land in the top-`n` of `ranking`
/// (`n` = number of KEV findings). 1.0 means every KEV CVE is on top.
fn kev_recall(findings: &[Finding], ranking: &[usize], n: usize) -> f64 {
    let kev_total = findings.iter().filter(|f| f.kev).count();
    if kev_total == 0 {
        return 0.0;
    }
    let hits = ranking.iter().take(n).filter(|&&i| findings[i].kev).count();
    hits as f64 / kev_total as f64
}

/// Mean 1-indexed rank of the KEV findings (lower = prioritised higher).
fn mean_kev_rank(findings: &[Finding], ranking: &[usize]) -> f64 {
    let ranks: Vec<usize> = ranking
        .iter()
        .enumerate()
        .filter(|&(_, &i)| findings[i].kev)
        .map(|(pos, _)| pos + 1)
        .collect();
    if ranks.is_empty() {
        return 0.0;
    }
    ranks.iter().sum::<usize>() as f64 / ranks.len() as f64
}

/// 1-indexed position of `id` in `ranking`, or 0 if absent.
fn position(findings: &[Finding], ranking: &[usize], id: &str) -> usize {
    ranking
        .iter()
        .position(|&i| findings[i].id == id)
        .map_or(0, |p| p + 1)
}

fn main() {
    let findings = dataset();
    let total = findings.len();
    let kev_n = findings.iter().filter(|f| f.kev).count();

    let by_cvss = rank_by_cvss(&findings);
    let by_comp = rank_by_composite(&findings);

    println!("FF2 — prioritisation: composite vs CVSS-only (ground truth: CISA KEV)");
    println!(
        "dataset: {total} CVEs, {kev_n} KEV  [offline catalog — KEV-heavy, see source note]\n"
    );

    println!("{:<20} {:>11} {:>11}", "metric", "CVSS-only", "composite");
    println!(
        "{:<20} {:>11.2} {:>11.2}",
        "KEV recall@N",
        kev_recall(&findings, &by_cvss, kev_n),
        kev_recall(&findings, &by_comp, kev_n),
    );
    println!(
        "{:<20} {:>11.2} {:>11.2}  (lower is better)",
        "mean KEV rank",
        mean_kev_rank(&findings, &by_cvss),
        mean_kev_rank(&findings, &by_comp),
    );

    println!("\nlow-CVSS (<7.0) but KEV-listed CVEs — rank under each:");
    let mut any = false;
    for f in &findings {
        if f.kev && f.cvss < 7.0 {
            any = true;
            println!(
                "  {:<18} cvss {:>4}  cvss-rank {:>3}  composite-rank {:>3}",
                f.id,
                f.cvss,
                position(&findings, &by_cvss, f.id),
                position(&findings, &by_comp, f.id),
            );
        }
    }
    if !any {
        println!("  (none in this dataset)");
    }

    println!("\nNote: every catalog CVE carries a CVSS, so the missing-CVSS NVD-gap effect");
    println!("is not measurable here — that needs a live/official dataset. The metrics");
    println!("above are dataset-agnostic: replace dataset() and re-run.");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<Finding> {
        vec![
            Finding {
                id: "high-not-kev",
                cvss: 9.8,
                kev: false,
                composite: 70.0,
            },
            Finding {
                id: "low-but-kev",
                cvss: 5.0,
                kev: true,
                composite: 90.0,
            },
            Finding {
                id: "mid-kev",
                cvss: 7.5,
                kev: true,
                composite: 95.0,
            },
        ]
    }

    #[test]
    fn composite_ranks_low_cvss_kev_above_high_cvss_non_kev() {
        let f = fixture();
        let by_cvss = rank_by_cvss(&f);
        let by_comp = rank_by_composite(&f);
        // CVSS-only buries the exploited low-CVSS CVE at the bottom...
        assert_eq!(position(&f, &by_cvss, "low-but-kev"), 3);
        // ...the composite (KEV floor) lifts it to the top.
        assert_eq!(position(&f, &by_comp, "low-but-kev"), 2);
        // KEV recall@2 is perfect for the composite, partial for CVSS-only.
        assert!((kev_recall(&f, &by_comp, 2) - 1.0).abs() < f64::EPSILON);
        assert!(kev_recall(&f, &by_cvss, 2) < 1.0);
    }

    #[test]
    fn mean_kev_rank_is_lower_for_composite() {
        let f = fixture();
        let cvss_rank = mean_kev_rank(&f, &rank_by_cvss(&f));
        let comp_rank = mean_kev_rank(&f, &rank_by_composite(&f));
        assert!(comp_rank < cvss_rank);
    }
}
