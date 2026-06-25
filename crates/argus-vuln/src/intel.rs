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
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use argus_core::{Confidence, Cvss, Epss, Service, Vulnerability};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, OnceCell, RwLock};
use tokio::time::Instant as TokioInstant;

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
/// Hard cap on CVEs fetched per product across NVD pages. Real application
/// products stay well below this (browsers, the worst case, are ~4000);
/// hitting it is logged so truncation is never silent.
const MAX_NVD_RESULTS: u64 = 10_000;
/// On-disk snapshot format version — bump on layout changes so an old file
/// is discarded instead of misparsed. v2: EPSS entries store score +
/// percentile (was a bare score); vulns carry a match-confidence field.
const DISK_VERSION: u32 = 2;

/// A cached value plus the wall-clock time it was stored. Wall-clock (not
/// `Instant`) so stamps survive serialization across restarts; a clock that
/// jumped backwards simply makes the entry stale and it is refetched.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Stamp<T> {
    at: SystemTime,
    value: T,
}

impl<T> Stamp<T> {
    fn new(value: T) -> Self {
        Self {
            at: SystemTime::now(),
            value,
        }
    }

    fn fresh(&self, ttl: Duration) -> bool {
        self.at.elapsed().is_ok_and(|age| age < ttl)
    }
}

/// Drop the oldest entries (by store time) until `map` is within `cap`.
fn shrink_to<T>(map: &mut HashMap<String, Stamp<T>>, cap: usize) {
    if map.len() <= cap {
        return;
    }
    let mut by_age: Vec<(SystemTime, String)> =
        map.iter().map(|(k, s)| (s.at, k.clone())).collect();
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
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
            cvss: score.map(|base_score| Cvss::new(base_score, None)),
            epss: None,
            kev: false,
            severity,
            // Refined per match in `enrich_inner` (Confirmed/Medium); this
            // cached placeholder is never surfaced directly.
            match_confidence: Confidence::Medium,
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

/// The cache as written to / read from disk. `Arc`s are unwrapped to plain
/// values; staleness is re-checked against the TTLs on load, so an old file
/// degrades to an empty cache instead of serving expired data.
#[derive(Serialize, Deserialize)]
struct DiskCache {
    version: u32,
    kev: Option<Stamp<HashSet<String>>>,
    epss: HashMap<String, Stamp<Option<nvd::EpssScore>>>,
    products: HashMap<String, Stamp<Vec<ProductCve>>>,
}

/// A product's in-flight fetch, shared by every caller that wants the same
/// `vendor:product` while one network fetch is running. The [`OnceCell`] runs
/// the fetch exactly once; concurrent callers for the same key await that
/// single result instead of issuing duplicate NVD requests.
type Flight = Arc<OnceCell<Option<Arc<Vec<ProductCve>>>>>;

/// Paces NVD requests to the API rate limit *without* serializing the fetches
/// behind it. A reservation cursor records the earliest instant the next
/// request may start; [`acquire`](NvdRateGate::acquire) advances it under a
/// brief `std` lock held only for the arithmetic — never across the sleep or
/// the HTTP request. Callers therefore serialize their slot *reservations*
/// (microseconds) while their multi-page fetches run concurrently and the
/// aggregate request rate still stays within NVD's limit. This replaces the
/// old single global mutex that was held for a product's whole paginated
/// fetch, so one large product (browsers are ~4000 CVEs across several pages)
/// no longer stalls every other product's — or every other tenant's —
/// enrichment.
struct NvdRateGate {
    /// Earliest instant the next NVD request may begin; `None` until the
    /// first request reserves a slot.
    next: std::sync::Mutex<Option<TokioInstant>>,
    /// Minimum spacing between requests at the configured rate limit.
    spacing: Duration,
}

impl NvdRateGate {
    fn new(spacing: Duration) -> Self {
        Self {
            next: std::sync::Mutex::new(None),
            spacing,
        }
    }

    /// Reserve the next request slot and wait until it is due. The lock is
    /// held only to advance the cursor; the wait happens after it is released,
    /// so a reservation never blocks a concurrent fetch.
    async fn acquire(&self) {
        let wait = {
            let mut next = self
                .next
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let now = TokioInstant::now();
            let slot = (*next).filter(|n| *n > now).unwrap_or(now);
            *next = Some(slot + self.spacing);
            drop(next);
            slot.saturating_duration_since(now)
        };
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
    }
}

/// Shared cache state behind [`IntelCache`].
struct Inner {
    /// NVD API key (`NVD_API_KEY`), lifting the rate limit when present.
    api_key: Option<String>,
    /// CISA KEV CVE-id set.
    kev: RwLock<Option<Stamp<Arc<HashSet<String>>>>>,
    /// Single-flight guard so concurrent ingests refresh KEV once, not N times.
    kev_refresh: Mutex<()>,
    /// Per-CVE EPSS data; `None` records a known-absent score so repeated
    /// scans do not re-ask for CVEs EPSS has never heard of.
    epss: RwLock<HashMap<String, Stamp<Option<nvd::EpssScore>>>>,
    /// Per-`vendor:product` NVD CVE sets.
    products: RwLock<HashMap<String, Stamp<Arc<Vec<ProductCve>>>>>,
    /// Paces NVD requests to the API rate limit without serializing fetches.
    nvd_rate: NvdRateGate,
    /// Per-`vendor:product` single-flight registry: concurrent fetches of the
    /// same key share one network request; different keys never block each
    /// other. Held only for brief map operations (no `await` inside).
    inflight: std::sync::Mutex<HashMap<String, Flight>>,
    /// Snapshot file for persistence across restarts; `None` disables it.
    persist: Option<PathBuf>,
    /// Set on every cache write, cleared by [`IntelCache::flush`] — skips
    /// disk writes when an enrichment pass was served entirely from cache.
    dirty: AtomicBool,
    /// Serializes concurrent flushes (tenant scans can enrich in parallel).
    flush_lock: Mutex<()>,
}

/// Process-wide cached vulnerability-intelligence client. Cloning is cheap
/// (shared `Arc` state) — hand clones to every ingest path so the whole
/// process shares one cache and one NVD rate-limit gate.
#[derive(Clone)]
pub struct IntelCache {
    inner: Arc<Inner>,
}

/// Read and parse a snapshot file; `None` (logged) on any failure or on a
/// version mismatch.
fn load_snapshot(path: &Path) -> Option<DiskCache> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "intel cache snapshot unreadable");
            return None;
        }
    };
    let disk: DiskCache = match serde_json::from_slice(&bytes) {
        Ok(disk) => disk,
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "intel cache snapshot unparsable — starting cold");
            return None;
        }
    };
    if disk.version != DISK_VERSION {
        tracing::info!(
            found = disk.version,
            expected = DISK_VERSION,
            "intel cache snapshot from another format version — starting cold"
        );
        return None;
    }
    Some(disk)
}

impl IntelCache {
    /// Create a cache; `nvd_api_key` lifts the NVD rate limit when set.
    #[must_use]
    pub fn new(nvd_api_key: Option<String>) -> Self {
        Self::build(nvd_api_key, None)
    }

    /// Create a cache that restores its state from `path` (fresh entries
    /// only) and snapshots back to it after enrichment passes that changed
    /// it. A missing or invalid file simply starts the cache cold.
    #[must_use]
    pub fn with_persistence(nvd_api_key: Option<String>, path: impl Into<PathBuf>) -> Self {
        Self::build(nvd_api_key, Some(path.into()))
    }

    fn build(nvd_api_key: Option<String>, persist: Option<PathBuf>) -> Self {
        let api_key = nvd_api_key
            .map(|k| k.trim().to_owned())
            .filter(|k| !k.is_empty());
        let spacing = if api_key.is_some() {
            NVD_SPACING_KEYED
        } else {
            NVD_SPACING
        };
        // Restore only entries still fresh by their TTL — an old snapshot
        // degrades to a cold cache, never to stale intelligence.
        let mut kev = None;
        let mut epss = HashMap::new();
        let mut products = HashMap::new();
        if let Some(disk) = persist.as_deref().and_then(load_snapshot) {
            kev = disk.kev.filter(|s| s.fresh(KEV_TTL)).map(|s| Stamp {
                at: s.at,
                value: Arc::new(s.value),
            });
            epss = disk
                .epss
                .into_iter()
                .filter(|(_, s)| s.fresh(EPSS_TTL))
                .collect();
            products = disk
                .products
                .into_iter()
                .filter(|(_, s)| s.fresh(NVD_TTL))
                .map(|(k, s)| {
                    (
                        k,
                        Stamp {
                            at: s.at,
                            value: Arc::new(s.value),
                        },
                    )
                })
                .collect();
            tracing::info!(
                kev = kev.is_some(),
                epss = epss.len(),
                products = products.len(),
                "intel cache restored from disk"
            );
        }
        Self {
            inner: Arc::new(Inner {
                api_key,
                kev: RwLock::new(kev),
                kev_refresh: Mutex::new(()),
                epss: RwLock::new(epss),
                products: RwLock::new(products),
                nvd_rate: NvdRateGate::new(spacing),
                inflight: std::sync::Mutex::new(HashMap::new()),
                persist,
                dirty: AtomicBool::new(false),
                flush_lock: Mutex::new(()),
            }),
        }
    }

    /// Create a cache configured from the environment: `NVD_API_KEY` lifts
    /// the NVD rate limit, `ARGUS_INTEL_CACHE` overrides the snapshot file
    /// (default `intel-cache.json`; set it empty to disable persistence).
    #[must_use]
    pub fn from_env() -> Self {
        let path = std::env::var("ARGUS_INTEL_CACHE").map_or_else(
            |_| Some("intel-cache.json".to_owned()),
            |p| {
                let p = p.trim().to_owned();
                (!p.is_empty()).then_some(p)
            },
        );
        let api_key = std::env::var("NVD_API_KEY").ok();
        let cache = match path {
            Some(p) => Self::with_persistence(api_key, p),
            None => Self::new(api_key),
        };
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
        vulns: Vec<Vulnerability>,
        services: &[Service],
    ) -> Enrichment {
        let enrichment = self.enrich_inner(vulns, services).await;
        // One snapshot per enrichment pass (skipped when everything was a
        // cache hit) — feeds refresh hours apart, so write volume is trivial.
        self.flush().await;
        enrichment
    }

    /// [`Self::enrich_checked`] without the trailing snapshot flush.
    async fn enrich_inner(
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
                        let mut v = hit.vuln.clone();
                        // Confirmed when the observed version matched a real
                        // published range; otherwise precise CPE identity
                        // without a version check (Medium).
                        v.match_confidence = match observed.as_deref() {
                            Some(ver)
                                if hit
                                    .constraints
                                    .iter()
                                    .any(|c| !c.unbounded() && c.contains(ver)) =>
                            {
                                Confidence::Confirmed
                            }
                            _ => Confidence::Medium,
                        };
                        // Keep the strongest confidence if the catalog already
                        // added this CVE at a weaker tier (no first-seen demotion).
                        crate::merge_strongest(&mut vulns, v);
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
                    if let Some(&nvd::EpssScore { score, percentile }) = scores.get(&v.cve_id) {
                        v.epss = Some(Epss::new(score, Some(percentile)));
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
        self.inner.dirty.store(true, AtomicOrdering::Relaxed);
        Some(set)
    }

    /// EPSS scores for `ids` (cache first, batched fetch for the rest).
    /// `None` if any required fetch failed; ids EPSS does not know are simply
    /// absent from the result.
    async fn epss(&self, ids: &[String]) -> Option<HashMap<String, nvd::EpssScore>> {
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
            self.inner.dirty.store(true, AtomicOrdering::Relaxed);
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
        // Per-product single flight: the first caller for this key creates the
        // flight cell; concurrent callers for the *same* key share it and await
        // that one fetch. Different keys get different cells and fetch
        // concurrently, each request paced by the shared rate gate rather than
        // blocked behind another product's whole paginated fetch.
        let cell = {
            let mut inflight = self
                .inner
                .inflight
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            Arc::clone(
                inflight
                    .entry(key.clone())
                    .or_insert_with(|| Arc::new(OnceCell::new())),
            )
        };
        let result = cell
            .get_or_init(|| self.fetch_and_cache_product(vendor, product, &key))
            .await
            .clone();
        // Retire this flight so a later refresh (after the TTL) starts fresh —
        // but only if the registry still holds *our* cell, never a newer one.
        {
            let mut inflight = self
                .inner
                .inflight
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if inflight.get(&key).is_some_and(|c| Arc::ptr_eq(c, &cell)) {
                inflight.remove(&key);
            }
        }
        result
    }

    /// Fetch a product's CVE set through the rate gate and cache it on success.
    /// `None` on fetch failure (never cached as the product's truth — the next
    /// scan retries). Runs once per flight, driven by the caller's [`OnceCell`].
    async fn fetch_and_cache_product(
        &self,
        vendor: &str,
        product: &str,
        key: &str,
    ) -> Option<Arc<Vec<ProductCve>>> {
        let cves = Arc::new(self.fetch_product(vendor, product).await?);
        let mut map = self.inner.products.write().await;
        map.insert(key.to_owned(), Stamp::new(Arc::clone(&cves)));
        shrink_to(&mut map, MAX_PRODUCTS);
        drop(map);
        self.inner.dirty.store(true, AtomicOrdering::Relaxed);
        Some(cves)
    }

    /// Fetch every NVD CVE whose configurations match `vendor:product`,
    /// following pagination (2000 per page); every page reserves a slot from
    /// the shared [`NvdRateGate`] so requests pace to the rate limit while
    /// other products fetch concurrently. Stops at [`MAX_NVD_RESULTS`] (logged
    /// so truncation is never silent). `None` if any page fails: a partial CVE
    /// set must not be cached as the product's truth.
    async fn fetch_product(&self, vendor: &str, product: &str) -> Option<Vec<ProductCve>> {
        let match_string = format!("cpe:2.3:a:{vendor}:{product}");
        let mut cves: Vec<ProductCve> = Vec::new();
        let mut start_index: u64 = 0;
        loop {
            // Reserve a request slot from the shared rate gate before every
            // page — this is where NVD pacing happens now, off the lock so
            // concurrent products interleave instead of serializing.
            self.inner.nvd_rate.acquire().await;
            let index = start_index.to_string();
            let mut req = nvd::client().get(nvd::NVD_API).query(&[
                ("virtualMatchString", match_string.as_str()),
                ("resultsPerPage", "2000"),
                ("startIndex", index.as_str()),
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
            cves.extend(
                items
                    .iter()
                    .filter_map(|item| parse_nvd_item(item, vendor, product)),
            );
            let fetched = u64::try_from(items.len()).unwrap_or(u64::MAX);
            start_index = start_index.saturating_add(fetched);
            let total = json["totalResults"].as_u64().unwrap_or(start_index);
            // An empty page below `totalResults` means NVD's count and its
            // pages disagree — stop rather than loop on a phantom remainder.
            if start_index >= total || fetched == 0 {
                break;
            }
            if start_index >= MAX_NVD_RESULTS {
                tracing::warn!(
                    vendor,
                    product,
                    total,
                    fetched = start_index,
                    "NVD CVE set truncated at the pagination cap"
                );
                break;
            }
        }
        tracing::debug!(
            vendor,
            product,
            cves = cves.len(),
            "NVD product CVEs fetched"
        );
        Some(cves)
    }

    /// Snapshot the cache to its persistence file when dirty. Best-effort:
    /// every failure is logged and swallowed — persistence is an optimization,
    /// never a reason to fail an enrichment pass. The write is atomic
    /// (temp file + rename) so a crash cannot leave a half-written snapshot.
    async fn flush(&self) {
        let Some(path) = self.inner.persist.as_deref() else {
            return;
        };
        if !self.inner.dirty.swap(false, AtomicOrdering::Relaxed) {
            return;
        }
        let _serialized = self.inner.flush_lock.lock().await;
        let disk = DiskCache {
            version: DISK_VERSION,
            kev: self.inner.kev.read().await.as_ref().map(|s| Stamp {
                at: s.at,
                value: (*s.value).clone(),
            }),
            epss: self.inner.epss.read().await.clone(),
            products: self
                .inner
                .products
                .read()
                .await
                .iter()
                .map(|(k, s)| {
                    (
                        k.clone(),
                        Stamp {
                            at: s.at,
                            value: (*s.value).clone(),
                        },
                    )
                })
                .collect(),
        };
        let json = match serde_json::to_vec(&disk) {
            Ok(json) => json,
            Err(e) => {
                tracing::warn!(error = %e, "intel cache snapshot serialization failed");
                return;
            }
        };
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            let _ = tokio::fs::create_dir_all(parent).await;
        }
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        let result = match tokio::fs::write(&tmp, &json).await {
            Ok(()) => tokio::fs::rename(&tmp, path).await,
            Err(e) => Err(e),
        };
        match result {
            Ok(()) => {
                tracing::debug!(path = %path.display(), bytes = json.len(), "intel cache snapshot written");
            }
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "intel cache snapshot write failed");
            }
        }
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
                match_confidence: Confidence::Medium,
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
                match_confidence: Confidence::Medium,
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
                at: SystemTime::now() - Duration::from_secs(60),
                value: 1,
            },
        );
        map.insert("new".into(), Stamp::new(2));
        shrink_to(&mut map, 1);
        assert!(map.contains_key("new"));
        assert!(!map.contains_key("old"));
    }

    /// Unique per-test snapshot path that cleans up on drop.
    struct TempSnapshot(PathBuf);

    impl TempSnapshot {
        fn new(name: &str) -> Self {
            Self(std::env::temp_dir().join(format!(
                "argus-intel-test-{name}-{}.json",
                std::process::id()
            )))
        }
    }

    impl Drop for TempSnapshot {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn product_cve(cve_id: &str) -> ProductCve {
        ProductCve {
            vuln: Vulnerability {
                cve_id: cve_id.to_owned(),
                cvss: None,
                epss: None,
                kev: false,
                severity: Severity::High,
                match_confidence: Confidence::Medium,
            },
            constraints: vec![VersionConstraint::default()],
        }
    }

    #[tokio::test]
    async fn flush_and_reload_roundtrips_the_cache() {
        let snapshot = TempSnapshot::new("roundtrip");
        let cache = IntelCache::with_persistence(None, &snapshot.0);
        cache.inner.products.write().await.insert(
            "acme:widget".into(),
            Stamp::new(Arc::new(vec![product_cve("CVE-2024-1")])),
        );
        cache.inner.epss.write().await.insert(
            "CVE-2024-1".into(),
            Stamp::new(Some(crate::nvd::EpssScore {
                score: 0.5,
                percentile: 0.8,
            })),
        );
        *cache.inner.kev.write().await = Some(Stamp::new(Arc::new(HashSet::from([
            "CVE-2024-1".to_owned()
        ]))));
        cache.inner.dirty.store(true, AtomicOrdering::Relaxed);
        cache.flush().await;

        let restored = IntelCache::with_persistence(None, &snapshot.0);
        let cves = restored
            .cached_product("acme:widget")
            .await
            .expect("product survives the restart");
        assert_eq!(cves[0].vuln.cve_id, "CVE-2024-1");
        assert!(restored
            .cached_kev()
            .await
            .expect("kev survives")
            .contains("CVE-2024-1"));
        assert_eq!(
            restored
                .inner
                .epss
                .read()
                .await
                .get("CVE-2024-1")
                .map(|s| s.value),
            Some(Some(crate::nvd::EpssScore {
                score: 0.5,
                percentile: 0.8,
            }))
        );
    }

    #[tokio::test]
    async fn stale_snapshot_entries_are_dropped_on_load() {
        let snapshot = TempSnapshot::new("stale");
        let stale = SystemTime::now() - (NVD_TTL + Duration::from_secs(60));
        let disk = DiskCache {
            version: DISK_VERSION,
            kev: Some(Stamp::new(HashSet::from(["CVE-2024-1".to_owned()]))),
            epss: HashMap::new(),
            products: HashMap::from([(
                "acme:widget".to_owned(),
                Stamp {
                    at: stale,
                    value: vec![product_cve("CVE-2024-1")],
                },
            )]),
        };
        std::fs::write(&snapshot.0, serde_json::to_vec(&disk).unwrap()).unwrap();

        let cache = IntelCache::with_persistence(None, &snapshot.0);
        assert!(cache.cached_product("acme:widget").await.is_none());
        assert!(cache.cached_kev().await.is_some());
    }

    #[tokio::test]
    async fn snapshot_from_another_format_version_starts_cold() {
        let snapshot = TempSnapshot::new("version");
        let disk = DiskCache {
            version: DISK_VERSION + 1,
            kev: Some(Stamp::new(HashSet::from(["CVE-2024-1".to_owned()]))),
            epss: HashMap::new(),
            products: HashMap::new(),
        };
        std::fs::write(&snapshot.0, serde_json::to_vec(&disk).unwrap()).unwrap();

        let cache = IntelCache::with_persistence(None, &snapshot.0);
        assert!(cache.cached_kev().await.is_none());
    }

    #[tokio::test]
    async fn flush_without_changes_writes_nothing() {
        let snapshot = TempSnapshot::new("clean");
        let cache = IntelCache::with_persistence(None, &snapshot.0);
        cache.flush().await;
        assert!(!snapshot.0.exists());
    }

    #[tokio::test(start_paused = true)]
    async fn rate_gate_paces_requests_to_the_spacing() {
        let spacing = Duration::from_millis(500);
        let gate = NvdRateGate::new(spacing);
        let start = TokioInstant::now();
        // The first reservation is immediate; each later one is exactly one
        // spacing interval after the previous, so the aggregate request rate
        // never exceeds the limit regardless of how callers interleave.
        gate.acquire().await;
        assert_eq!(start.elapsed(), Duration::ZERO);
        gate.acquire().await;
        assert_eq!(start.elapsed(), spacing);
        gate.acquire().await;
        assert_eq!(start.elapsed(), spacing * 2);
    }

    #[tokio::test]
    async fn flight_cell_runs_the_fetch_once_for_concurrent_callers() {
        use std::sync::atomic::AtomicUsize;
        // Models the single-flight guarantee product_cves relies on: many
        // concurrent callers sharing one flight cell trigger exactly one
        // fetch, and all observe the same result.
        let cell: Flight = Arc::new(OnceCell::new());
        let calls = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let cell = Arc::clone(&cell);
            let calls = Arc::clone(&calls);
            handles.push(tokio::spawn(async move {
                cell.get_or_init(|| async {
                    calls.fetch_add(1, AtomicOrdering::Relaxed);
                    tokio::task::yield_now().await;
                    Some(Arc::new(vec![product_cve("CVE-2024-1")]))
                })
                .await
                .clone()
            }));
        }
        for handle in handles {
            let got = handle.await.unwrap().expect("flight result");
            assert_eq!(got[0].vuln.cve_id, "CVE-2024-1");
        }
        assert_eq!(
            calls.load(AtomicOrdering::Relaxed),
            1,
            "the fetch must run exactly once for the shared flight"
        );
    }
}
