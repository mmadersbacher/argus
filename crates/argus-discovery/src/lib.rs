//! # argus-discovery
//!
//! Light active discovery for Argus: a safe, unauthenticated TCP-connect scan
//! that finds live hosts and open services without raw sockets or root, an
//! optional `nmap` backend for real service/version fingerprints (incl. `-O` OS
//! detection when run as root), MAC/vendor enrichment from the ARP cache,
//! runZero-style subnet sampling, and an optional masscan high-speed SYN sweep
//! for large ranges. Passive sensing gets layered on top later.

pub mod arp;
pub mod fingerprint;
pub mod masscan;
pub mod nmap;
pub mod oui;
pub mod portscan;
pub mod sampling;
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
    /// Skip dead /24 subnets via sampling before the full scan.
    pub sample: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            ports: fingerprint::PORTS.to_vec(),
            connect_timeout: Duration::from_millis(700),
            concurrency: 256,
            sample: false,
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
    /// How many hosts were requested.
    pub hosts_scanned: usize,
    /// Live hosts discovered.
    pub live: Vec<DiscoveredHost>,
    /// Wall-clock duration in milliseconds.
    pub duration_ms: u64,
}

/// Run a light connect scan over the given hosts.
pub async fn scan(targets: &[IpAddr], opts: &ScanOptions) -> ScanReport {
    let started = Instant::now();
    let scanned: Vec<IpAddr> = if opts.sample {
        sampling::responsive_targets(targets, opts.connect_timeout).await
    } else {
        targets.to_vec()
    };

    let sem = Arc::new(Semaphore::new(opts.concurrency.max(1)));
    let ports = Arc::new(opts.ports.clone());
    let connect_timeout = opts.connect_timeout;

    let mut handles = Vec::with_capacity(scanned.len());
    for ip in scanned {
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
    enrich_macs(&mut live);

    ScanReport {
        hosts_scanned: targets.len(),
        live,
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    }
}

/// Deep, privileged scan: masscan sweep, then nmap SYN + OS detail.
///
/// A masscan high-speed SYN sweep finds live host:port pairs, then
/// [`nmap::scan_os`] re-probes only the responsive hosts — fast wide discovery,
/// accurate narrow fingerprinting.
///
/// Both stages need raw-socket privileges (root / `cap_net_raw`). This is
/// best-effort: if masscan finds nothing (e.g. run unprivileged) or nmap fails,
/// it returns an empty vector and the caller should fall back to [`scan`] or the
/// nmap connect scan.
pub async fn deep_scan(
    spec: &str,
    ports: &[u16],
    rate: u32,
    run_timeout: Duration,
) -> Vec<DiscoveredHost> {
    let Ok(sweep) = masscan::sweep(spec, ports, rate, run_timeout).await else {
        return Vec::new();
    };
    if sweep.is_empty() {
        return Vec::new();
    }
    // Re-probe only the responsive hosts with nmap for service + OS detail.
    let live = sweep
        .iter()
        .map(|h| h.ip.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    nmap::scan_os(&live, ports, run_timeout)
        .await
        .unwrap_or_default()
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

/// Enrich discovered hosts with a MAC address (from the kernel ARP cache) and a
/// vendor (OUI lookup) for any interface that has an IP but no MAC yet.
///
/// Works for hosts on the local subnet that were just contacted; loopback and
/// remote hosts have no ARP entry and are left unchanged.
pub fn enrich_macs(hosts: &mut [DiscoveredHost]) {
    if hosts.is_empty() {
        return;
    }
    let arp = arp::read_arp_table();
    if arp.is_empty() {
        return;
    }
    let oui = oui::OuiDb::load();

    for host in hosts.iter_mut() {
        let mut found_vendor: Option<String> = None;
        for iface in &mut host.asset.interfaces {
            if iface.mac.is_some() {
                continue;
            }
            let Some(ip) = iface.ip else { continue };
            if let Some(&mac) = arp.get(&ip) {
                iface.mac = Some(mac);
                if found_vendor.is_none() {
                    found_vendor = oui.vendor(mac).map(str::to_owned);
                }
            }
        }
        if host.asset.fingerprint.vendor.is_none() {
            if let Some(vendor) = found_vendor {
                host.asset.fingerprint.vendor = Some(vendor);
            }
        }
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

    #[test]
    fn enrich_on_empty_is_noop() {
        let mut hosts: Vec<DiscoveredHost> = Vec::new();
        enrich_macs(&mut hosts);
        assert!(hosts.is_empty());
    }
}
