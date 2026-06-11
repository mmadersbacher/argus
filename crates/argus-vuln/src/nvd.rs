//! Raw clients for the live vulnerability feeds — NVD 2.0, CISA KEV and
//! FIRST.org EPSS.
//!
//! Every fetcher is best-effort and side-effect free: `None` means the
//! request or parse failed (distinct from a reachable-but-empty feed).
//! Caching, rate-limit pacing and CPE-grounded matching live one layer up in
//! [`crate::intel`].
#![allow(clippy::cast_possible_truncation)] // CVSS scores: f64 JSON -> f32 domain type

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use argus_core::Severity;

/// NVD 2.0 CVE API endpoint.
pub(crate) const NVD_API: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const KEV_FEED: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const EPSS_API: &str = "https://api.first.org/data/v1/epss";

pub(crate) fn client() -> reqwest::Client {
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

/// Extract the best available CVSS base score (v3.1 > v3.0 > v2) and the
/// derived severity from an NVD `metrics` object.
pub(crate) fn extract_cvss(metrics: &serde_json::Value) -> (Option<f32>, Severity) {
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
