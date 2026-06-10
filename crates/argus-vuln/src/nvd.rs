//! Live vulnerability intelligence — NVD 2.0 search + CISA KEV + FIRST.org EPSS.
//!
//! Best-effort enrichment layered on the offline [`crate::catalog`]: every call
//! degrades gracefully to whatever it already has if a feed is slow, throttled
//! or offline.
#![allow(clippy::cast_possible_truncation)] // CVSS scores: f64 JSON -> f32 domain type

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use argus_core::{Cvss, Epss, Severity, Vulnerability};

const NVD_API: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const KEV_FEED: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const EPSS_API: &str = "https://api.first.org/data/v1/epss";

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .user_agent("argus-vuln/0.1")
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

/// The authoritative CISA KEV CVE-id set (live), or `None` if the request /
/// parse failed (distinct from a reachable-but-empty feed). See
/// [`fetch_kev`] for the lossy wrapper.
pub async fn fetch_kev_checked() -> Option<HashSet<String>> {
    let json: serde_json::Value = client()
        .get(KEV_FEED)
        .send()
        .await
        .ok()?
        .json()
        .await
        .ok()?;
    let set = json["vulnerabilities"]
        .as_array()?
        .iter()
        .filter_map(|v| v["cveID"].as_str().map(str::to_owned))
        .collect();
    Some(set)
}

/// The authoritative CISA KEV CVE-id set (live). Empty on any failure.
pub async fn fetch_kev() -> HashSet<String> {
    fetch_kev_checked().await.unwrap_or_default()
}

/// Live EPSS scores for the given CVE ids (single batched request), or `None`
/// if the request / parse failed (distinct from a reachable-but-empty
/// response). See [`fetch_epss`] for the lossy wrapper.
pub async fn fetch_epss_checked(cves: &[String]) -> Option<HashMap<String, f32>> {
    if cves.is_empty() {
        return Some(HashMap::new());
    }
    let joined = cves.join(",");
    let json: serde_json::Value = client()
        .get(EPSS_API)
        .query(&[("cve", joined.as_str())])
        .send()
        .await
        .ok()?
        .json()
        .await
        .ok()?;
    let map = json["data"]
        .as_array()?
        .iter()
        .filter_map(|d| {
            let id = d["cve"].as_str()?.to_owned();
            let epss = d["epss"].as_str()?.parse::<f32>().ok()?;
            Some((id, epss))
        })
        .collect();
    Some(map)
}

/// Live EPSS scores for the given CVE ids (single batched request).
pub async fn fetch_epss(cves: &[String]) -> HashMap<String, f32> {
    fetch_epss_checked(cves).await.unwrap_or_default()
}

/// NVD 2.0 keyword search for a product → vulnerabilities (bounded), or `None`
/// if the NVD request / parse failed (distinct from a reachable-but-empty
/// result). See [`search`] for the lossy wrapper.
pub async fn search_checked(product: &str, limit: usize) -> Option<Vec<Vulnerability>> {
    let lim = limit.to_string();
    let json: serde_json::Value = client()
        .get(NVD_API)
        .query(&[("keywordSearch", product), ("resultsPerPage", lim.as_str())])
        .send()
        .await
        .ok()?
        .json()
        .await
        .ok()?;
    let out = json["vulnerabilities"]
        .as_array()?
        .iter()
        .filter_map(|item| {
            let cve = &item["cve"];
            let id = cve["id"].as_str()?.to_owned();
            let (score, severity) = extract_cvss(&cve["metrics"]);
            Some(Vulnerability {
                cve_id: id,
                cvss: score.map(|s| Cvss {
                    base_score: s,
                    vector: None,
                }),
                epss: None,
                kev: false,
                severity,
            })
        })
        .collect();
    Some(out)
}

/// NVD 2.0 keyword search for a product → vulnerabilities (bounded, best-effort).
pub async fn search(product: &str, limit: usize) -> Vec<Vulnerability> {
    search_checked(product, limit).await.unwrap_or_default()
}

fn extract_cvss(metrics: &serde_json::Value) -> (Option<f32>, Severity) {
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"] {
        if let Some(entry) = metrics[key].as_array().and_then(|a| a.first()) {
            if let Some(score) = entry["cvssData"]["baseScore"].as_f64() {
                let score = score as f32;
                return (Some(score), Severity::from_cvss(score));
            }
        }
    }
    (None, Severity::None)
}

/// Result of a live enrichment pass: the (possibly enriched) vulns plus a
/// reachability signal.
#[derive(Debug, Clone)]
pub struct Enrichment {
    /// The catalog vulns overlaid with whatever live data was reachable.
    pub vulns: Vec<Vulnerability>,
    /// `true` only if *every* attempted live call succeeded. A single failed
    /// feed (timeout / throttle / parse error) sets this to `false`, signalling
    /// that `vulns` may be incomplete and must NOT be used as a change-detection
    /// baseline (callers should keep the previous enriched set instead).
    pub live: bool,
}

/// Enrich catalog vulns with NVD search hits for `products`, then overlay
/// authoritative CISA-KEV flags and live EPSS scores, reporting whether the
/// live feeds were fully reachable.
///
/// `live` is `true` only when EVERY attempted live call succeeded: every
/// per-product NVD search returned `Some`, and (when the vuln set is non-empty)
/// both the KEV and EPSS fetches returned `Some`. Any failure flips it to
/// `false` so change detection can run on stable, non-regressive data instead
/// of a partial result.
pub async fn enrich_checked(mut vulns: Vec<Vulnerability>, products: &[String]) -> Enrichment {
    let mut live = true;
    for product in products {
        // nmap product strings are verbose ("PostgreSQL DB 9.6.0 or later");
        // NVD keyword search ANDs terms, so search the leading product token.
        let keyword = product.split_whitespace().next().unwrap_or(product);
        match search_checked(keyword, 5).await {
            Some(found) => {
                for vuln in found {
                    if !vulns.iter().any(|v| v.cve_id == vuln.cve_id) {
                        vulns.push(vuln);
                    }
                }
            }
            None => live = false,
        }
    }
    if vulns.is_empty() {
        return Enrichment { vulns, live };
    }
    let kev_checked = fetch_kev_checked().await;
    live &= kev_checked.is_some();
    let kev = kev_checked.unwrap_or_default();
    let ids: Vec<String> = vulns.iter().map(|v| v.cve_id.clone()).collect();
    let epss_checked = fetch_epss_checked(&ids).await;
    live &= epss_checked.is_some();
    let epss = epss_checked.unwrap_or_default();
    for v in &mut vulns {
        if !kev.is_empty() {
            v.kev = kev.contains(&v.cve_id);
        }
        if let Some(&score) = epss.get(&v.cve_id) {
            v.epss = Some(Epss {
                score,
                percentile: score,
            });
        }
    }
    Enrichment { vulns, live }
}

/// Best-effort enrichment wrapper that discards the reachability signal.
///
/// Enriches catalog vulns with NVD search hits for `products`, then overlays
/// authoritative CISA-KEV flags and live EPSS scores; on any failure it returns
/// whatever it already had. See [`enrich_checked`] for the variant that also
/// reports feed reachability.
pub async fn enrich(vulns: Vec<Vulnerability>, products: &[String]) -> Vec<Vulnerability> {
    enrich_checked(vulns, products).await.vulns
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_cvss_from_v31() {
        let metrics =
            serde_json::json!({ "cvssMetricV31": [{ "cvssData": { "baseScore": 9.8 } }] });
        let (score, severity) = extract_cvss(&metrics);
        assert_eq!(severity, Severity::Critical);
        assert!((score.unwrap() - 9.8).abs() < 0.01);
    }

    #[test]
    fn missing_metrics_yield_none() {
        let (score, severity) = extract_cvss(&serde_json::json!({}));
        assert!(score.is_none());
        assert_eq!(severity, Severity::None);
    }
}
