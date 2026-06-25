//! FF3 evaluation — measurable risk reduction (thesis goal #1).
//!
//! Research question FF3: does acting on Argus's prioritised "fix these this
//! week" plan make the network **measurably** safer, and does the prioritisation
//! concentrate that reduction into a few high-leverage fixes (so a busy admin
//! gets most of the benefit from the first handful of actions)?
//!
//! Method — no circularity: each asset is scored with the **real** engine
//! ([`argus_core::RiskScore`] over [`argus_vuln::risk_inputs`]). A remediation
//! "action" patches one asset's confirmed KEV / critical findings; the asset is
//! re-scored and the aggregate (mean asset risk, count of high-risk hosts) is
//! recomputed. Actions are applied worst-first (the largest risk drop first —
//! the order the action plan's KEV-then-critical ranking approximates) and the
//! cumulative reduction is reported after each. The headline is the absolute
//! before→after drop **and** the share of it captured by the top few actions.
//!
//! ```text
//! cargo run -p argus-eval -- ff3            # embedded school scenario
//! cargo run -p argus-eval -- ff3 <file.csv> # your own inventory
//! ```
//! CSV: `asset,exposure,criticality,cvss,epss,kev,severity,confirmed`, one row
//! per (asset, finding); empty `cvss` = no CVSS for that finding.

use argus_core::{
    Confidence, Criticality, Cvss, Epss, Exposure, RiskScore, Severity, Vulnerability,
};
use argus_vuln::risk_inputs;

/// "High-risk" threshold: a numeric risk score at or above this is a host an
/// admin should worry about (the `High`/`Critical` bands, `>= 60`).
const HIGH_RISK: f32 = 60.0;

/// Default scenario embedded in the crate (see `data/ff3-sample.csv`).
const SAMPLE: &str = include_str!("../data/ff3-sample.csv");

/// One finding on an asset.
struct Finding {
    cvss: Option<f32>,
    epss: f32,
    kev: bool,
    severity: Severity,
    confirmed: bool,
}

/// One asset and its findings (a unit of remediation).
struct AssetScenario {
    name: String,
    exposure: Exposure,
    criticality: Criticality,
    findings: Vec<Finding>,
}

fn parse_exposure(s: &str) -> Exposure {
    match s.trim().to_ascii_lowercase().as_str() {
        "internet_facing" | "internet-facing" | "internet" => Exposure::InternetFacing,
        "internal" => Exposure::Internal,
        _ => Exposure::Unknown,
    }
}

fn parse_criticality(s: &str) -> Criticality {
    match s.trim().to_ascii_lowercase().as_str() {
        "critical" => Criticality::Critical,
        "high" => Criticality::High,
        "low" => Criticality::Low,
        _ => Criticality::Medium,
    }
}

fn parse_severity(s: &str) -> Severity {
    match s.trim().to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::None,
    }
}

fn truthy(s: &str) -> bool {
    matches!(s.trim().to_ascii_lowercase().as_str(), "yes" | "true" | "1")
}

/// Parse the `asset,exposure,criticality,cvss,epss,kev,severity,confirmed` CSV,
/// grouping rows into assets (exposure/criticality taken from an asset's first
/// row). Blank lines, `#` comments and the header row are skipped.
fn parse_dataset(csv: &str) -> Vec<AssetScenario> {
    let mut assets: Vec<AssetScenario> = Vec::new();
    for line in csv.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let col: Vec<&str> = line.split(',').collect();
        if col.len() < 8 || col[0].eq_ignore_ascii_case("asset") {
            continue;
        }
        let name = col[0].trim().to_owned();
        let finding = Finding {
            cvss: col[3].trim().parse::<f32>().ok(),
            epss: col[4].trim().parse::<f32>().unwrap_or(0.0),
            kev: truthy(col[5]),
            severity: parse_severity(col[6]),
            confirmed: truthy(col[7]),
        };
        if let Some(existing) = assets.iter_mut().find(|a| a.name == name) {
            existing.findings.push(finding);
        } else {
            assets.push(AssetScenario {
                name,
                exposure: parse_exposure(col[1]),
                criticality: parse_criticality(col[2]),
                findings: vec![finding],
            });
        }
    }
    assets
}

/// The findings of an asset as [`Vulnerability`]s. With `patched`, the confirmed
/// KEV / critical findings are removed (the remediation a top action performs).
fn asset_vulns(a: &AssetScenario, patched: bool) -> Vec<Vulnerability> {
    a.findings
        .iter()
        .filter(|f| !(patched && f.confirmed && (f.kev || f.severity == Severity::Critical)))
        .map(|f| Vulnerability {
            cve_id: String::new(),
            cvss: f.cvss.map(|c| Cvss::new(c, None)),
            epss: Some(Epss::new(f.epss, None)),
            kev: f.kev,
            severity: f.severity,
            match_confidence: if f.confirmed {
                Confidence::Confirmed
            } else {
                Confidence::Low
            },
        })
        .collect()
}

/// Score one asset with the real engine, optionally after patching its top
/// findings.
fn asset_risk(a: &AssetScenario, patched: bool) -> f32 {
    let vulns = asset_vulns(a, patched);
    RiskScore::compute(&risk_inputs(&vulns, a.exposure, a.criticality)).value
}

/// Whether patching this asset's top findings actually changes its score (only
/// assets with a confirmed KEV/critical finding yield a remediation action).
fn is_actionable(a: &AssetScenario) -> bool {
    a.findings
        .iter()
        .any(|f| f.confirmed && (f.kev || f.severity == Severity::Critical))
}

fn mean(values: &[f32]) -> f32 {
    if values.is_empty() {
        0.0
    } else {
        values.iter().sum::<f32>() / values.len() as f32
    }
}

fn high_risk_count(values: &[f32]) -> usize {
    values.iter().filter(|&&v| v >= HIGH_RISK).count()
}

/// Run the FF3 harness on the embedded scenario, or on `path` if given.
pub fn run(path: Option<String>) {
    let data = path.map_or_else(
        || SAMPLE.to_owned(),
        |p| {
            std::fs::read_to_string(&p).unwrap_or_else(|e| {
                eprintln!("cannot read {p}: {e}");
                std::process::exit(1);
            })
        },
    );
    let assets = parse_dataset(&data);
    if assets.is_empty() {
        eprintln!("no assets parsed from the scenario");
        std::process::exit(1);
    }

    // Before: every asset's current risk.
    let before: Vec<f32> = assets.iter().map(|a| asset_risk(a, false)).collect();
    let mean_before = mean(&before);
    let high_before = high_risk_count(&before);

    // One remediation action per actionable asset, valued by the risk it
    // removes; worst-first is the order the prioritised plan approximates.
    let mut actions: Vec<(usize, f32, f32)> = assets // (asset idx, after-score, reduction)
        .iter()
        .enumerate()
        .filter(|(_, a)| is_actionable(a))
        .map(|(i, a)| {
            let after = asset_risk(a, true);
            (i, after, (before[i] - after).max(0.0))
        })
        .collect();
    actions.sort_by(|x, y| y.2.total_cmp(&x.2));

    let total_reduction: f32 = actions.iter().map(|(_, _, r)| r).sum::<f32>() / before.len() as f32;

    println!("FF3 — measurable risk reduction (thesis goal #1: 'the school is measurably safer')");
    println!(
        "scenario: {} assets, {} high-risk (>= {HIGH_RISK:.0}), mean risk {mean_before:.1}\n",
        assets.len(),
        high_before,
    );
    println!(
        "{:<3} {:<16} {:>10} {:>10} {:>14}",
        "#", "fix this asset", "risk->", "drop", "cum. % of total"
    );

    let mut current = before.clone();
    let mut cum = 0.0_f32;
    for (rank, (idx, after, reduction)) in actions.iter().enumerate() {
        current[*idx] = *after;
        cum += reduction / before.len() as f32;
        let pct = if total_reduction > f32::EPSILON {
            100.0 * cum / total_reduction
        } else {
            0.0
        };
        println!(
            "{:<3} {:<16} {:>10} {:>10.1} {:>13.0}%",
            rank + 1,
            truncate(&assets[*idx].name, 16),
            format!("{:.0}->{:.0}", before[*idx], after),
            reduction,
            pct,
        );
    }

    let mean_after = mean(&current);
    let high_after = high_risk_count(&current);
    let drop_pct = if mean_before > f32::EPSILON {
        100.0 * (mean_before - mean_after) / mean_before
    } else {
        0.0
    };

    println!(
        "\nafter the plan: mean risk {mean_before:.1} -> {mean_after:.1} ({drop_pct:.0}% lower), \
         high-risk hosts {high_before} -> {high_after}"
    );
    // Actionability (Pareto): what share of the whole reduction the first few
    // actions buy.
    for k in [1usize, 3] {
        if actions.len() >= k {
            let captured: f32 =
                actions.iter().take(k).map(|(_, _, r)| r).sum::<f32>() / before.len() as f32;
            let pct = if total_reduction > f32::EPSILON {
                100.0 * captured / total_reduction
            } else {
                0.0
            };
            println!("  top {k} action(s) capture {pct:.0}% of the achievable reduction");
        }
    }
    println!("\nRun on your own inventory: `cargo run -p argus-eval -- ff3 <file.csv>`");
}

/// Truncate a label to `max` chars for the fixed-width table.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_owned()
    } else {
        s.chars()
            .take(max - 1)
            .chain(std::iter::once('…'))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patching_kev_and_critical_lowers_an_asset_score() {
        let assets = parse_dataset(SAMPLE);
        let dc = assets.iter().find(|a| a.name == "dc-01").expect("dc-01");
        assert!(
            asset_risk(dc, true) < asset_risk(dc, false),
            "patching a DC's KEV/critical findings must lower its risk"
        );
        // A medium-only host has nothing to patch → not actionable, unchanged.
        let ws = assets.iter().find(|a| a.name == "ws-lab-01").expect("ws");
        assert!(!is_actionable(ws));
        assert!((asset_risk(ws, true) - asset_risk(ws, false)).abs() < f32::EPSILON);
    }

    #[test]
    fn the_plan_reduces_mean_risk_and_high_risk_host_count() {
        let assets = parse_dataset(SAMPLE);
        let before: Vec<f32> = assets.iter().map(|a| asset_risk(a, false)).collect();
        let after: Vec<f32> = assets
            .iter()
            .map(|a| asset_risk(a, is_actionable(a)))
            .collect();
        assert!(
            mean(&after) < mean(&before),
            "the plan must lower mean risk"
        );
        assert!(
            high_risk_count(&after) < high_risk_count(&before),
            "the plan must clear some high-risk hosts"
        );
        // The reduction is real and bounded (scores stay in 0..=100).
        assert!(after.iter().all(|&v| (0.0..=100.0).contains(&v)));
    }

    #[test]
    fn only_confirmed_kev_or_critical_findings_are_actionable() {
        // A version-blind (potential) KEV is not actionable — it never drove the
        // score, so "patching" it would be theatre.
        let csv = "asset,exposure,criticality,cvss,epss,kev,severity,confirmed\n\
                   pot,internal,high,9.8,0.9,yes,critical,no\n";
        let assets = parse_dataset(csv);
        assert!(!is_actionable(&assets[0]));
    }

    #[test]
    fn header_and_grouping_are_handled() {
        let assets = parse_dataset(SAMPLE);
        // dc-01 has two findings grouped under one asset.
        let dc = assets.iter().find(|a| a.name == "dc-01").unwrap();
        assert_eq!(dc.findings.len(), 2);
        assert_eq!(dc.criticality, Criticality::Critical);
        // The header row "asset,..." is not parsed as an asset.
        assert!(assets.iter().all(|a| a.name != "asset"));
    }
}
