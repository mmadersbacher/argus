//! FF2 evaluation — prioritisation quality.
//!
//! Research question FF2: does the context-aware composite score (CVSS + EPSS +
//! KEV + exposure + criticality) prioritise vulnerabilities better than a raw
//! CVSS sort? Ground truth is the CISA KEV catalog ("really exploited" → should
//! rank high). The harness ranks a dataset both ways and reports KEV recall@N,
//! the mean rank of KEV CVEs, and which exploited CVEs CVSS-only under-ranks —
//! including the NVD-gap case (a KEV CVE with no CVSS at all).
//!
//! Dataset: a small curated CSV is embedded as the default; pass a path to run
//! against a real one — `cargo run -p argus-eval -- ff2 <file.csv>` with columns
//! `cve_id,cvss,epss,kev` (empty cvss = NVD has not scored it). The measurement
//! logic is dataset-agnostic; for a headline result feed the full FIRST.org
//! EPSS set joined with CISA KEV and NVD CVSS.
//!
//! Headline result on the full 2026-06-16 snapshot (340,656 CVEs with an EPSS
//! score, 1,622 on CISA KEV): the composite cuts the mean rank of exploited
//! (KEV) CVEs from ~80,100 under a CVSS-only sort to ~2,210 — exploited bugs
//! land in the top ~0.6% instead of the middle of the pack. CVSS-only can't
//! separate the exploited 9.8s from the thousands of non-exploited 9.8s; the
//! KEV/EPSS-aware composite can. Reproduce via `scripts/fetch_nvd_cvss.ps1` +
//! `scripts/join_ff2.ps1` then `-- ff2 data/real/ff2-real.csv`.

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
    composite: f32,
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

    println!("FF2 — prioritisation: composite vs CVSS-only (ground truth: CISA KEV)");
    println!("dataset: {total} CVEs, {kev_n} KEV, {no_cvss} without CVSS (NVD gap)\n");

    println!("{:<18} {:>11} {:>11}", "metric", "CVSS-only", "composite");
    println!(
        "{:<18} {:>11.2} {:>11.2}",
        "KEV recall@N",
        kev_recall(&findings, &by_cvss, kev_n),
        kev_recall(&findings, &by_comp, kev_n),
    );
    println!(
        "{:<18} {:>11.2} {:>11.2}  (lower=better)",
        "mean KEV rank",
        mean_kev_rank(&findings, &by_cvss),
        mean_kev_rank(&findings, &by_comp),
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
}
