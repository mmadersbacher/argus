//! Cached, CPE-grounded live vulnerability intelligence.
//!
//! [`IntelCache`] is the process-wide front door to the live feeds wrapped by
//! [`crate::nvd`]. It keys NVD lookups by the *application CPE* that nmap
//! reports per service (`cpe:/a:openbsd:openssh:8.9p1`), so correlation runs
//! on precise vendor+product identity instead of keyword guessing, and it
//! filters the returned CVEs against the service's observed version using the
//! version constraints NVD publishes under `configurations`. Every feed is
//! cached with a TTL so scans and scheduled re-scans do not hammer the
//! upstream APIs (NVD allows 5 requests / 30 s without an API key; set
//! `NVD_API_KEY` to lift that to 50).
//!
//! Matching is deliberately conservative:
//! - services without an application CPE are never sent to NVD (the curated
//!   offline [`crate::catalog`] still covers them),
//! - CVEs whose NVD record carries no *vulnerable* version constraint for the
//!   queried product are dropped (nothing to match on),
//! - a service with no observed version matches only constraints that apply
//!   to all versions — version-ranged CVEs are not guessed.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use argus_core::{Cvss, Epss, Service, Vulnerability};
use tokio::sync::{Mutex, RwLock};

use crate::nvd;
use crate::version;

/// KEV catalog refresh interval (CISA updates a few times per week).
const KEV_TTL: Duration = Duration::from_secs(12 * 60 * 60);
/// EPSS score refresh interval (FIRST.org publishes daily).
const EPSS_TTL: Duration = Duration::from_secs(24 * 60 * 60);
/// Per-product NVD CVE-set refresh interval.
const NVD_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// Minimum spacing between NVD requests without an API key (5 req / 30 s).
const NVD_SPACING: Duration = Duration::from_millis(6500);
/// Minimum spacing between NVD requests with an API key (50 req / 30 s).
const NVD_SPACING_KEYED: Duration = Duration::from_millis(700);
/// CVE ids per EPSS request — keeps the query string well under URL limits.
const EPSS_CHUNK: usize = 100;
/// Bound on cached NVD product entries: a long-lived daemon must not grow
/// without limit when scans surface ever-new product strings.
const MAX_PRODUCTS: usize = 512;
/// Bound on cached EPSS scores.
const MAX_EPSS: usize = 8192;

/// A cached value plus the instant it was stored.
#[derive(Debug, Clone)]
struct Stamp<T> {
    at: Instant,
    value: T,
}

impl<T> Stamp<T> {
    fn new(value: T) -> Self {
        Self {
            at: Instant::now(),
            value,
        }
    }

    fn fresh(&self, ttl: Duration) -> bool {
        self.at.elapsed() < ttl
    }
}

/// Drop the oldest entries (by store time) until `map` is within `cap`.
fn shrink_to<T>(map: &mut HashMap<String, Stamp<T>>, cap: usize) {
    if map.len() <= cap {
        return;
    }
    let mut by_age: Vec<(Instant, String)> = map.iter().map(|(k, s)| (s.at, k.clone())).collect();
    by_age.sort_unstable_by_key(|&(at, _)| at);
    let excess = map.len() - cap;
    for (_, key) in by_age.into_iter().take(excess) {
        map.remove(&key);
    }
}

/// Result of a live enrichment pass: the (possibly enriched) vulns plus a
/// reachability signal.
#[derive(Debug, Clone)]
pub struct Enrichment {
    /// The catalog vulns overlaid with whatever live data was reachable.
    pub vulns: Vec<Vulnerability>,
    /// `true` only if *every* attempted live call succeeded (cache hits
    /// count as success — cached data is current within its TTL). A single
    /// failed feed sets this to `false`, signalling that `vulns` may be
    /// incomplete and must NOT be used as a change-detection baseline
    /// (callers should keep the previous enriched set instead).
    pub live: bool,
}

/// The vendor/product/version triple of an application CPE.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CpeApp {
    vendor: String,
    product: String,
    version: Option<String>,
}

/// Parse an application CPE in 2.2 URI form (`cpe:/a:vendor:product:version`)
/// or 2.3 formatted form (`cpe:2.3:a:vendor:product:version:…`).
/// Non-application CPEs (`o:`, `h:`) and wildcard/blank versions (`*`, `-`)
/// yield `None` / a `None` version. Components are colon-split naively, which
/// is correct for every CPE nmap emits (escaped literal colons in vendor or
/// product names simply fail to match — they do not occur in practice).
fn parse_cpe(cpe: &str) -> Option<CpeApp> {
    let rest = cpe
        .strip_prefix("cpe:/")
        .or_else(|| cpe.strip_prefix("cpe:2.3:"))?;
    let mut parts = rest.split(':');
    if parts.next() != Some("a") {
        return None;
    }
    let vendor = parts.next()?.trim().to_lowercase();
    let product = parts.next()?.trim().to_lowercase();
    if vendor.is_empty() || product.is_empty() {
        return None;
    }
    let version = parts
        .next()
        .map(str::trim)
        .filter(|v| !v.is_empty() && *v != "*" && *v != "-")
        .map(str::to_lowercase);
    Some(CpeApp {
        vendor,
        product,
        version,
    })
}

/// One vulnerable version window from an NVD `cpeMatch` entry. An `exact`
/// version and the range bounds are mutually exclusive (NVD uses a wildcard
/// version in the criteria when range bounds are present).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct VersionConstraint {
    exact: Option<String>,
    start_including: Option<String>,
    start_excluding: Option<String>,
    end_including: Option<String>,
    end_excluding: Option<String>,
}

impl VersionConstraint {
    /// Whether this constraint applies to every version.
    fn unbounded(&self) -> bool {
        self == &Self::default()
    }

    /// Whether `v` satisfies the constraint.
    fn contains(&self, v: &str) -> bool {
        if let Some(exact) = self.exact.as_deref() {
            return version::cmp(v, exact) == Ordering::Equal;
        }
        self.start_including
            .as_deref()
            .is_none_or(|lo| version::cmp(v, lo) != Ordering::Less)
            && self
                .start_excluding
                .as_deref()
                .is_none_or(|lo| version::cmp(v, lo) == Ordering::Greater)
            && self
                .end_including
                .as_deref()
                .is_none_or(|hi| version::cmp(v, hi) != Ordering::Greater)
            && self
                .end_excluding
                .as_deref()
                .is_none_or(|hi| version::cmp(v, hi) == Ordering::Less)
    }
}

/// One NVD CVE for a cached product: the vulnerability plus the version
/// windows under which the product is vulnerable.
#[derive(Debug, Clone)]
struct ProductCve {
    vuln: Vulnerability,
    constraints: Vec<VersionConstraint>,
}

/// Parse one NVD 2.0 `vulnerabilities[]` item into a [`ProductCve`], keeping
/// only constraints from *vulnerable* `cpeMatch` entries whose CPE names the
/// queried `vendor:product`. Items without any such constraint yield `None`:
/// the CVE matched the query through an unrelated or non-vulnerable CPE, or
/// NVD has not analysed it yet — either way there is nothing sound to match
/// a version against, so it is dropped rather than guessed.
fn parse_nvd_item(item: &serde_json::Value, vendor: &str, product: &str) -> Option<ProductCve> {
    let cve = &item["cve"];
    let id = cve["id"].as_str()?;
    let (score, severity) = nvd::extract_cvss(&cve["metrics"]);
    let mut constraints = Vec::new();
    for config in cve["configurations"].as_array().into_iter().flatten() {
        for node in config["nodes"].as_array().into_iter().flatten() {
            for entry in node["cpeMatch"].as_array().into_iter().flatten() {
                if entry["vulnerable"].as_bool() != Some(true) {
                    continue;
                }
                let Some(app) = entry["criteria"].as_str().and_then(parse_cpe) else {
                    continue;
                };
                if app.vendor != vendor || app.product != product {
                    continue;
                }
                let bound = |key: &str| entry[key].as_str().map(str::to_owned);
                let constraint = VersionConstraint {
                    start_including: bound("versionStartIncluding"),
                    start_excluding: bound("versionStartExcluding"),
                    end_including: bound("versionEndIncluding"),
                    end_excluding: bound("versionEndExcluding"),
                    exact: None,
                };
                constraints.push(if constraint.unbounded() {
                    // No range bounds — the criteria's own version component
                    // (if any) is the constraint.
                    VersionConstraint {
                        exact: app.version,
                        ..constraint
                    }
                } else {
                    constraint
                });
            }
        }
    }
    if constraints.is_empty() {
        return None;
    }
    Some(ProductCve {
        vuln: Vulnerability {
            cve_id: id.to_owned(),
            cvss: score.map(|base_score| Cvss {
                base_score,
                vector: None,
            }),
            epss: None,
            kev: false,
            severity,
        },
        constraints,
    })
}

/// The CVEs from `cves` that apply to a service observed at `version`.
fn matching<'c>(
    cves: &'c [ProductCve],
    version: Option<&'c str>,
) -> impl Iterator<Item = &'c ProductCve> {
    cves.iter().filter(move |cve| {
        version.map_or_else(
            || cve.constraints.iter().any(VersionConstraint::unbounded),
            |v| cve.constraints.iter().any(|c| c.contains(v)),
        )
    })
}

/// Shared cache state behind [`IntelCache`].
struct Inner {
    /// NVD API key (`NVD_API_KEY`), lifting the rate limit when present.
    api_key: Option<String>,
    /// CISA KEV CVE-id set.
    kev: RwLock<Option<Stamp<Arc<HashSet<String>>>>>,
    /// Single-flight guard so concurrent ingests refresh KEV once, not N times.
    kev_refresh: Mutex<()>,
    /// Per-CVE EPSS scores; `None` records a known-absent score so repeated
    /// scans do not re-ask for CVEs EPSS has never heard of.
    epss: RwLock<HashMap<String, Stamp<Option<f32>>>>,
    /// Per-`vendor:product` NVD CVE sets.
    products: RwLock<HashMap<String, Stamp<Arc<Vec<ProductCve>>>>>,
    /// Paces NVD requests to the rate limit and doubles as the single-flight
    /// guard for product fetches.
    nvd_gate: Mutex<Option<Instant>>,
}

/// Process-wide cached vulnerability-intelligence client. Cloning is cheap
/// (shared `Arc` state) — hand clones to every ingest path so the whole
/// process shares one cache and one NVD rate-limit gate.
#[derive(Clone)]
pub struct IntelCache {
    inner: Arc<Inner>,
}

impl IntelCache {
    /// Create a cache; `nvd_api_key` lifts the NVD rate limit when set.
    #[must_use]
    pub fn new(nvd_api_key: Option<String>) -> Self {
        let api_key = nvd_api_key
            .map(|k| k.trim().to_owned())
            .filter(|k| !k.is_empty());
        Self {
            inner: Arc::new(Inner {
                api_key,
                kev: RwLock::new(None),
                kev_refresh: Mutex::new(()),
                epss: RwLock::new(HashMap::new()),
                products: RwLock::new(HashMap::new()),
                nvd_gate: Mutex::new(None),
            }),
        }
    }

    /// Create a cache configured from the environment (`NVD_API_KEY`).
    #[must_use]
    pub fn from_env() -> Self {
        let cache = Self::new(std::env::var("NVD_API_KEY").ok());
        if cache.inner.api_key.is_some() {
            tracing::info!("NVD API key configured (50 requests / 30 s)");
        } else {
            tracing::info!(
                "no NVD_API_KEY set — NVD lookups are paced to 5 requests / 30 s; \
                 get a free key at https://nvd.nist.gov/developers/request-an-api-key"
            );
        }
        cache
    }

    /// Enrich catalog vulns with version-matched NVD CVEs for each service's
    /// application CPE, then overlay authoritative CISA-KEV flags and current
    /// EPSS scores, reporting whether the live data was fully available.
    ///
    /// `live` is `true` only when every attempted lookup succeeded, from cache
    /// (current within its TTL) or the network. Any failed feed flips it to
    /// `false` so change detection can keep its previous, stable baseline
    /// instead of diffing against a partial result.
    pub async fn enrich_checked(
        &self,
        mut vulns: Vec<Vulnerability>,
        services: &[Service],
    ) -> Enrichment {
        let mut live = true;

        for service in services {
            let Some(app) = service.cpe.as_deref().and_then(parse_cpe) else {
                continue;
            };
            // Version: prefer the CPE's own component, fall back to the first
            // version-looking token of the product string.
            let observed = app.version.clone().or_else(|| {
                service
                    .product
                    .as_deref()
                    .and_then(crate::extract_version)
                    .map(str::to_owned)
            });
            match self.product_cves(&app.vendor, &app.product).await {
                Some(cves) => {
                    for hit in matching(&cves, observed.as_deref()) {
                        if !vulns.iter().any(|v| v.cve_id == hit.vuln.cve_id) {
                            vulns.push(hit.vuln.clone());
                        }
                    }
                }
                None => live = false,
            }
        }

        if vulns.is_empty() {
            return Enrichment { vulns, live };
        }

        match self.kev().await {
            Some(kev) => {
                for v in &mut vulns {
                    v.kev = kev.contains(&v.cve_id);
                }
            }
            None => live = false,
        }

        let ids: Vec<String> = vulns.iter().map(|v| v.cve_id.clone()).collect();
        match self.epss(&ids).await {
            Some(scores) => {
                for v in &mut vulns {
                    if let Some(&score) = scores.get(&v.cve_id) {
                        v.epss = Some(Epss {
                            score,
                            percentile: score,
                        });
                    }
                }
            }
            None => live = false,
        }

        Enrichment { vulns, live }
    }

    /// The KEV set from cache if fresh.
    async fn cached_kev(&self) -> Option<Arc<HashSet<String>>> {
        let guard = self.inner.kev.read().await;
        guard
            .as_ref()
            .filter(|s| s.fresh(KEV_TTL))
            .map(|s| Arc::clone(&s.value))
    }

    /// The KEV set, refreshed from CISA when stale. `None` on fetch failure.
    async fn kev(&self) -> Option<Arc<HashSet<String>>> {
        if let Some(hit) = self.cached_kev().await {
            return Some(hit);
        }
        let _flight = self.inner.kev_refresh.lock().await;
        if let Some(hit) = self.cached_kev().await {
            return Some(hit);
        }
        let set = Arc::new(nvd::fetch_kev_checked().await?);
        tracing::debug!(cves = set.len(), "CISA KEV catalog refreshed");
        *self.inner.kev.write().await = Some(Stamp::new(Arc::clone(&set)));
        Some(set)
    }

    /// EPSS scores for `ids` (cache first, batched fetch for the rest).
    /// `None` if any required fetch failed; ids EPSS does not know are simply
    /// absent from the result.
    async fn epss(&self, ids: &[String]) -> Option<HashMap<String, f32>> {
        let mut known = HashMap::new();
        let mut missing: Vec<String> = Vec::new();
        {
            let guard = self.inner.epss.read().await;
            for id in ids {
                match guard.get(id).filter(|s| s.fresh(EPSS_TTL)) {
                    Some(stamp) => {
                        if let Some(score) = stamp.value {
                            known.insert(id.clone(), score);
                        }
                    }
                    None => missing.push(id.clone()),
                }
            }
        }
        for chunk in missing.chunks(EPSS_CHUNK) {
            // A failed chunk fails the pass (partial EPSS must not look
            // complete), but chunks fetched before it stay cached.
            let scores = nvd::fetch_epss_checked(chunk).await?;
            let mut guard = self.inner.epss.write().await;
            for id in chunk {
                let score = scores.get(id).copied();
                if let Some(s) = score {
                    known.insert(id.clone(), s);
                }
                guard.insert(id.clone(), Stamp::new(score));
            }
            shrink_to(&mut guard, MAX_EPSS);
            drop(guard);
        }
        Some(known)
    }

    /// A product's CVE set from cache if fresh.
    async fn cached_product(&self, key: &str) -> Option<Arc<Vec<ProductCve>>> {
        let guard = self.inner.products.read().await;
        guard
            .get(key)
            .filter(|s| s.fresh(NVD_TTL))
            .map(|s| Arc::clone(&s.value))
    }

    /// A product's CVE set, fetched from NVD when stale. `None` on fetch
    /// failure (never cached — the next scan retries through the rate gate).
    async fn product_cves(&self, vendor: &str, product: &str) -> Option<Arc<Vec<ProductCve>>> {
        let key = format!("{vendor}:{product}");
        if let Some(hit) = self.cached_product(&key).await {
            return Some(hit);
        }
        // The gate paces NVD requests to the rate limit and doubles as a
        // single flight: a task that waited here re-checks the cache before
        // spending a request.
        let mut gate = self.inner.nvd_gate.lock().await;
        if let Some(hit) = self.cached_product(&key).await {
            return Some(hit);
        }
        let spacing = if self.inner.api_key.is_some() {
            NVD_SPACING_KEYED
        } else {
            NVD_SPACING
        };
        if let Some(last) = *gate {
            let wait = spacing.saturating_sub(last.elapsed());
            if !wait.is_zero() {
                tokio::time::sleep(wait).await;
            }
        }
        let fetched = self.fetch_product(vendor, product).await;
        // A failed request still counts toward the rate limit.
        *gate = Some(Instant::now());
        drop(gate);

        let cves = Arc::new(fetched?);
        let mut map = self.inner.products.write().await;
        map.insert(key, Stamp::new(Arc::clone(&cves)));
        shrink_to(&mut map, MAX_PRODUCTS);
        drop(map);
        Some(cves)
    }

    /// Fetch every NVD CVE whose configurations match `vendor:product`
    /// (one page; truncation beyond NVD's 2000-per-page maximum is logged).
    async fn fetch_product(&self, vendor: &str, product: &str) -> Option<Vec<ProductCve>> {
        let match_string = format!("cpe:2.3:a:{vendor}:{product}");
        let mut req = nvd::client().get(nvd::NVD_API).query(&[
            ("virtualMatchString", match_string.as_str()),
            ("resultsPerPage", "2000"),
        ]);
        if let Some(api_key) = self.inner.api_key.as_deref() {
            req = req.header("apiKey", api_key);
        }
        let json: serde_json::Value = req
            .send()
            .await
            .ok()?
            .error_for_status()
            .ok()?
            .json()
            .await
            .ok()?;
        let items = json["vulnerabilities"].as_array()?;
        let fetched = u64::try_from(items.len()).unwrap_or(u64::MAX);
        let total = json["totalResults"].as_u64().unwrap_or(fetched);
        if total > fetched {
            tracing::warn!(
                vendor,
                product,
                total,
                fetched,
                "NVD CVE set truncated to the first page"
            );
        }
        let cves: Vec<ProductCve> = items
            .iter()
            .filter_map(|item| parse_nvd_item(item, vendor, product))
            .collect();
        tracing::debug!(
            vendor,
            product,
            cves = cves.len(),
            "NVD product CVEs fetched"
        );
        Some(cves)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argus_core::Severity;

    #[test]
    fn parses_cpe_22_and_23() {
        let app = parse_cpe("cpe:/a:openbsd:openssh:8.9p1").expect("2.2 URI");
        assert_eq!(app.vendor, "openbsd");
        assert_eq!(app.product, "openssh");
        assert_eq!(app.version.as_deref(), Some("8.9p1"));

        let app = parse_cpe("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*").expect("2.3");
        assert_eq!(app.vendor, "apache");
        assert_eq!(app.product, "http_server");
        assert_eq!(app.version.as_deref(), Some("2.4.49"));
    }

    #[test]
    fn cpe_without_version_or_with_wildcard_has_no_version() {
        assert_eq!(parse_cpe("cpe:/a:igor_sysoev:nginx").unwrap().version, None);
        assert_eq!(
            parse_cpe("cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*")
                .unwrap()
                .version,
            None
        );
        assert_eq!(
            parse_cpe("cpe:2.3:a:openbsd:openssh:-:*:*:*:*:*:*:*")
                .unwrap()
                .version,
            None
        );
    }

    #[test]
    fn non_application_cpes_are_rejected() {
        assert!(parse_cpe("cpe:/o:linux:linux_kernel").is_none());
        assert!(parse_cpe("cpe:2.3:h:cisco:catalyst_2960").is_none());
        assert!(parse_cpe("not a cpe").is_none());
    }

    #[test]
    fn constraint_range_bounds() {
        let range = VersionConstraint {
            start_including: Some("1.0.1".into()),
            end_including: Some("1.0.1f".into()),
            ..VersionConstraint::default()
        };
        assert!(range.contains("1.0.1f"));
        assert!(range.contains("1.0.1"));
        assert!(!range.contains("1.0.1g"));
        assert!(!range.contains("1.0.0"));

        let below = VersionConstraint {
            end_excluding: Some("9.8".into()),
            ..VersionConstraint::default()
        };
        assert!(below.contains("9.7"));
        assert!(!below.contains("9.8"));

        let exact = VersionConstraint {
            exact: Some("2.4.49".into()),
            ..VersionConstraint::default()
        };
        assert!(exact.contains("2.4.49"));
        assert!(!exact.contains("2.4.50"));
    }

    /// An NVD item shaped like the 2.0 API response, with one vulnerable
    /// ranged entry for openssh, a non-vulnerable platform entry, and an
    /// unrelated product.
    fn nvd_item() -> serde_json::Value {
        serde_json::json!({
            "cve": {
                "id": "CVE-2024-6387",
                "metrics": { "cvssMetricV31": [{ "cvssData": { "baseScore": 8.1 } }] },
                "configurations": [{
                    "nodes": [{
                        "operator": "OR",
                        "cpeMatch": [
                            {
                                "vulnerable": true,
                                "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                                "versionStartIncluding": "8.5",
                                "versionEndExcluding": "9.8"
                            },
                            {
                                "vulnerable": false,
                                "criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"
                            },
                            {
                                "vulnerable": true,
                                "criteria": "cpe:2.3:a:other:product:*:*:*:*:*:*:*:*",
                                "versionEndExcluding": "99.0"
                            }
                        ]
                    }]
                }]
            }
        })
    }

    #[test]
    fn nvd_item_keeps_only_vulnerable_constraints_for_the_queried_product() {
        let cve = parse_nvd_item(&nvd_item(), "openbsd", "openssh").expect("parsed");
        assert_eq!(cve.vuln.cve_id, "CVE-2024-6387");
        assert_eq!(cve.vuln.severity, Severity::High);
        assert_eq!(cve.constraints.len(), 1);
        assert!(cve.constraints[0].contains("8.9p1"));
        assert!(!cve.constraints[0].contains("9.8"));
    }

    #[test]
    fn nvd_item_for_an_unmatched_product_is_dropped() {
        // The only cpeMatch for this vendor:product pair is non-vulnerable.
        assert!(parse_nvd_item(&nvd_item(), "linux", "linux_kernel").is_none());
    }

    #[test]
    fn nvd_item_with_exact_version_criteria_matches_exactly() {
        let item = serde_json::json!({
            "cve": {
                "id": "CVE-2000-1",
                "metrics": {},
                "configurations": [{
                    "nodes": [{ "cpeMatch": [{
                        "vulnerable": true,
                        "criteria": "cpe:2.3:a:acme:widget:1.2.3:*:*:*:*:*:*:*"
                    }]}]
                }]
            }
        });
        let cve = parse_nvd_item(&item, "acme", "widget").expect("parsed");
        assert!(cve.constraints[0].contains("1.2.3"));
        assert!(!cve.constraints[0].contains("1.2.4"));
    }

    #[test]
    fn versionless_service_matches_only_unbounded_constraints() {
        let ranged = ProductCve {
            vuln: Vulnerability {
                cve_id: "CVE-R".into(),
                cvss: None,
                epss: None,
                kev: false,
                severity: Severity::High,
            },
            constraints: vec![VersionConstraint {
                end_excluding: Some("9.8".into()),
                ..VersionConstraint::default()
            }],
        };
        let any = ProductCve {
            vuln: Vulnerability {
                cve_id: "CVE-A".into(),
                cvss: None,
                epss: None,
                kev: false,
                severity: Severity::Medium,
            },
            constraints: vec![VersionConstraint::default()],
        };
        let cves = vec![ranged, any];

        let with_version: Vec<&str> = matching(&cves, Some("8.9"))
            .map(|c| c.vuln.cve_id.as_str())
            .collect();
        assert_eq!(with_version, vec!["CVE-R", "CVE-A"]);

        let without: Vec<&str> = matching(&cves, None)
            .map(|c| c.vuln.cve_id.as_str())
            .collect();
        assert_eq!(without, vec!["CVE-A"]);
    }

    #[test]
    fn shrink_evicts_oldest_entries_first() {
        let mut map: HashMap<String, Stamp<u32>> = HashMap::new();
        map.insert(
            "old".into(),
            Stamp {
                at: Instant::now()
                    .checked_sub(Duration::from_secs(60))
                    .expect("recent instant"),
                value: 1,
            },
        );
        map.insert("new".into(), Stamp::new(2));
        shrink_to(&mut map, 1);
        assert!(map.contains_key("new"));
        assert!(!map.contains_key("old"));
    }
}
