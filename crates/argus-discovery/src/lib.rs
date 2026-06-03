//! # argus-discovery
//!
//! Light active discovery for Argus: a safe, unauthenticated TCP-connect scan
//! that finds live hosts and open services without raw sockets or root, plus an
//! optional `nmap` backend for real service/version fingerprints. The deeper
//! runZero-style features (subnet sampling, OS detection, passive sensing) get
//! layered on top later.

pub mod fingerprint;
pub mod nmap;
pub mod portscan;
pub mod target;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use argus_core::{Asset, AssetId, Criticality, Exposure, Interface, Protocol, Service};
use serde::Serialize;
use time::OffsetDateTime;
use tokio::sync::Semaphore;

pub use target::{expand, TargetError, MAX_HOSTS};

/// Tuning for a scan run.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Ports probed on each host.
    pub ports: Vec<u16>,
    /// Per-connection timeout.
    pub connect_timeout: Duration,
    /// Maximum hosts probed concurrently.
    pub concurrency: usize,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            ports: fingerprint::PORTS.to_vec(),
            connect_timeout: Duration::from_millis(700),
            concurrency: 256,
        }
    }
}

/// One live host found by a scan.
#[derive(Debug, Clone, Serialize)]
pub struct DiscoveredHost {
    /// The asset as it maps into the domain model.
    pub asset: Asset,
    /// Observed services (open ports).
    pub services: Vec<Service>,
    /// Raw list of open ports.
    pub open_ports: Vec<u16>,
    /// Placeholder insecure-service score (see [`fingerprint::insecure_service_score`]).
    pub insecure_score: f32,
}

/// Result of a scan run.
#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    /// How many hosts were probed.
    pub hosts_scanned: usize,
    /// Live hosts discovered.
    pub live: Vec<DiscoveredHost>,
    /// Wall-clock duration in milliseconds.
    pub duration_ms: u64,
}

/// Run a light connect scan over the given hosts.
pub async fn scan(targets: &[IpAddr], opts: &ScanOptions) -> ScanReport {
    let started = Instant::now();
    let sem = Arc::new(Semaphore::new(opts.concurrency.max(1)));
    let ports = Arc::new(opts.ports.clone());
    let connect_timeout = opts.connect_timeout;

    let mut handles = Vec::with_capacity(targets.len());
    for &ip in targets {
        let sem = Arc::clone(&sem);
        let ports = Arc::clone(&ports);
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.ok()?;
            let open = portscan::scan_host(ip, &ports, connect_timeout).await;
            if open.is_empty() {
                None
            } else {
                Some(build_host(ip, open))
            }
        }));
    }

    let mut live = Vec::new();
    for handle in handles {
        if let Ok(Some(host)) = handle.await {
            live.push(host);
        }
    }

    ScanReport {
        hosts_scanned: targets.len(),
        live,
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    }
}

fn build_host(ip: IpAddr, mut open: Vec<u16>) -> DiscoveredHost {
    open.sort_unstable();
    let (asset_type, fingerprint) = fingerprint::classify(&open);
    let insecure_score = fingerprint::insecure_service_score(&open);
    let now = OffsetDateTime::now_utc();

    let services = open
        .iter()
        .map(|&port| Service {
            port,
            protocol: Protocol::Tcp,
            product: fingerprint::service_name(port).map(str::to_owned),
            banner: None,
        })
        .collect();

    let asset = Asset {
        id: AssetId::new(),
        asset_type,
        criticality: Criticality::Medium,
        exposure: if is_internal(ip) {
            Exposure::Internal
        } else {
            Exposure::InternetFacing
        },
        fingerprint,
        interfaces: vec![Interface {
            mac: None,
            ip: Some(ip),
            vlan: None,
            hostname: None,
        }],
        first_seen: now,
        last_seen: now,
    };

    DiscoveredHost {
        asset,
        services,
        open_ports: open,
        insecure_score,
    }
}

/// Whether an address is on a private / internal range (light exposure heuristic).
pub(crate) fn is_internal(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // unique-local fc00::/7
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn empty_target_yields_empty_report() {
        let report = scan(&[], &ScanOptions::default()).await;
        assert_eq!(report.hosts_scanned, 0);
        assert!(report.live.is_empty());
    }

    #[test]
    fn loopback_is_internal() {
        assert!(is_internal("127.0.0.1".parse().unwrap()));
        assert!(is_internal("10.1.2.3".parse().unwrap()));
        assert!(!is_internal("8.8.8.8".parse().unwrap()));
    }
}
