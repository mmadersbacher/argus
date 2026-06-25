//! # argus-discovery
//!
//! Light active discovery for Argus: a safe, unauthenticated TCP-connect scan
//! that finds live hosts and open services without raw sockets or root, an
//! optional `nmap` backend for real service/version fingerprints (incl. `-O` OS
//! detection when run as root), MAC/vendor enrichment from the ARP cache,
//! runZero-style subnet sampling, and an optional masscan high-speed SYN sweep
//! for large ranges. Passive sensing gets layered on top later.

pub mod arp;
pub mod arpscan;
pub mod bacnet;
pub mod banner;
/// Shared hand-rolled ASN.1 BER codec for the SNMP and LDAP probes.
pub(crate) mod ber;
pub mod coap;
pub mod enip;
pub mod fingerprint;
pub mod fusion;
pub mod http;
pub mod ipp;
pub mod ldap;
pub mod masscan;
pub mod mdns;
pub mod miio;
pub mod modbus;
pub mod mqtt;
pub mod mssql;
pub mod netbios;
pub mod nmap;
pub mod oui;
pub mod pjl;
pub mod portscan;
pub mod rdns;
pub mod rtsp;
pub mod sampling;
pub mod smb;
pub mod snmp;
pub mod ssdp;
pub mod target;
pub mod tls;
pub mod wsd;

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use std::fmt::Write as _;

use argus_core::{
    Asset, AssetId, AssetType, Criticality, Exposure, Interface, MacAddr, Protocol, Service,
};
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
    /// How long to wait for a service's connect-time banner before giving up,
    /// or `None` to skip banner reads entirely (pure connect scan). Reading is
    /// always payload-free; a service that says nothing just yields no banner.
    pub banner_timeout: Option<Duration>,
    /// Maximum hosts probed concurrently.
    pub concurrency: usize,
    /// Skip dead /24 subnets via sampling before the full scan.
    pub sample: bool,
    /// Run an mDNS/DNS-SD sweep and merge its hostnames/models/services into
    /// the result (also surfaces in-scope devices that answer mDNS but expose
    /// no scanned TCP port). Unprivileged.
    pub mdns: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            ports: fingerprint::PORTS.to_vec(),
            connect_timeout: Duration::from_millis(700),
            banner_timeout: Some(Duration::from_secs(1)),
            concurrency: 256,
            sample: false,
            mdns: false,
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
    /// Whether the host offers the legacy **SMBv1** dialect, when an SMB probe
    /// ran: `Some(true)`/`Some(false)`; `None` if not probed (445 closed, or the
    /// light connect scan, which doesn't probe). Lets correlation *refute*
    /// SMBv1-only CVEs (EternalBlue) on evidence, instead of leaving them as
    /// unverified potentials.
    #[serde(default)]
    pub smb_v1: Option<bool>,
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
    let banner_timeout = opts.banner_timeout;

    let mut handles = Vec::with_capacity(scanned.len());
    for ip in scanned {
        let sem = Arc::clone(&sem);
        let ports = Arc::clone(&ports);
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.ok()?;
            let open = portscan::scan_host(ip, &ports, connect_timeout, banner_timeout).await;
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
    if opts.mdns {
        let found = mdns::discover(Duration::from_millis(2500)).await;
        let scope: HashSet<IpAddr> = targets.iter().copied().collect();
        merge_mdns(&mut live, found, &scope);
    }
    enrich_macs(&mut live);
    fusion::fuse_hosts(&mut live);

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
    let mut hosts = nmap::scan_os(&live, ports, run_timeout)
        .await
        .unwrap_or_default();
    enrich_macs(&mut hosts);
    fusion::fuse_hosts(&mut hosts);
    hosts
}

/// Unified post-processing for the hosts of any engine: hostnames + identity.
///
/// Runs an mDNS/DNS-SD sweep merged in scope, MAC/OUI vendor enrichment, then
/// signal fusion. Idempotent — safe to run on already-enriched hosts. This is
/// where hostnames/models and the confident identity come from, regardless of
/// whether the engine was connect, nmap or masscan+nmap.
pub async fn enrich(hosts: &mut Vec<DiscoveredHost>, scope: &[IpAddr]) {
    let set: HashSet<IpAddr> = scope.iter().copied().collect();

    // --- Discovery sources: ADD devices the connect scan cannot see. ---
    // Active ARP first (L2 ground truth on the local segment), then the four
    // multicast protocols run concurrently (independent UDP listens, so one
    // shared ~2.5s window instead of four serial ones).
    arp_discover(hosts, scope).await;
    let (mdns_found, ssdp_found, wsd_found, coap_found, miio_found) = tokio::join!(
        mdns::discover(Duration::from_millis(2500)),
        ssdp::discover(Duration::from_millis(2500)),
        wsd::discover(Duration::from_millis(2500)),
        coap::discover(Duration::from_secs(2)),
        miio::discover(scope, Duration::from_secs(2)),
    );
    merge_mdns(hosts, mdns_found, &set);
    merge_ssdp(hosts, ssdp_found, &set);
    merge_wsd(hosts, wsd_found, &set);
    merge_coap(hosts, coap_found, &set);
    merge_miio(hosts, miio_found, &set);

    // --- Enrichment: refine every known host with unicast probes. ---
    netbios_probe(hosts).await;
    snmp_probe(hosts).await;
    rdns_enrich(hosts).await;
    tls_enrich(hosts).await;
    http_enrich(hosts).await;
    ipp_enrich(hosts).await;
    pjl_enrich(hosts).await;
    rtsp_enrich(hosts).await;
    mqtt_enrich(hosts).await;
    // Enterprise + OT identity (directory, database, industrial controllers).
    ldap_enrich(hosts).await;
    smb_enrich(hosts).await;
    mssql_enrich(hosts).await;
    modbus_enrich(hosts).await;
    enip_enrich(hosts).await;
    bacnet_enrich(hosts).await;
    enrich_macs(hosts);
    fusion::fuse_hosts(hosts);
}

/// Active-ARP host discovery: sweep the in-scope local segment and merge every
/// device that replies into `hosts`, adding the ones not already present.
///
/// This is what turns "hosts with an open port" into "every device on the wire":
/// a device answering only ARP (firewalled phone, silent IoT, sleeping printer)
/// is added with its MAC set, then classified from its OUI by the later enrich
/// passes. Gated to internal IPv4 targets — ARP is IPv4-only and meaningful only
/// on a directly-attached segment — and to hosts where `arp-scan` is installed
/// and privileged; otherwise it is a no-op (best-effort, like masscan).
async fn arp_discover(hosts: &mut Vec<DiscoveredHost>, scope: &[IpAddr]) {
    let targets: Vec<IpAddr> = scope
        .iter()
        .copied()
        .filter(|ip| ip.is_ipv4() && is_internal(*ip))
        .collect();
    if targets.is_empty() || !arpscan::available().await {
        return;
    }
    let Ok(found) = arpscan::sweep(&targets, Duration::from_secs(15)).await else {
        return;
    };
    for arpscan::ArpHost { ip, mac } in found {
        if let Some(host) = hosts
            .iter_mut()
            .find(|h| h.asset.interfaces.iter().any(|i| i.ip == Some(ip)))
        {
            if let Some(iface) = host.asset.interfaces.first_mut() {
                iface.mac.get_or_insert(mac);
            }
        } else {
            let mut host = base_host(ip);
            if let Some(iface) = host.asset.interfaces.first_mut() {
                iface.mac = Some(mac);
            }
            hosts.push(host);
        }
    }
}

/// Find the host carrying `ip`, or append a fresh one; returns its index.
fn upsert_host(hosts: &mut Vec<DiscoveredHost>, ip: IpAddr) -> usize {
    let existing = hosts
        .iter()
        .position(|h| h.asset.interfaces.iter().any(|i| i.ip == Some(ip)));
    existing.unwrap_or_else(|| {
        hosts.push(base_host(ip));
        hosts.len() - 1
    })
}

/// Join the non-empty parts with ` | `, or `None` if all are empty.
fn join_nonempty(parts: &[Option<&str>]) -> Option<String> {
    let kept: Vec<&str> = parts
        .iter()
        .filter_map(|p| p.map(str::trim))
        .filter(|s| !s.is_empty())
        .collect();
    (!kept.is_empty()).then(|| kept.join(" | "))
}

/// Merge SSDP/UPnP findings: add in-scope responders, fold in friendlyName
/// (hostname), modelName (model), deviceType (asset class) and a SERVER banner.
fn merge_ssdp(
    hosts: &mut Vec<DiscoveredHost>,
    found: Vec<ssdp::SsdpHost>,
    scope: &HashSet<IpAddr>,
) {
    for s in found {
        if !scope.contains(&s.ip) {
            continue;
        }
        let idx = upsert_host(hosts, s.ip);
        let host = &mut hosts[idx];
        if let Some(name) = s.friendly_name.clone() {
            if let Some(iface) = host.asset.interfaces.first_mut() {
                iface.hostname.get_or_insert(name);
            }
        }
        if host.asset.fingerprint.model.is_none() {
            host.asset.fingerprint.model.clone_from(&s.model_name);
        }
        if host.asset.asset_type == AssetType::Unknown {
            if let Some(dt) = &s.device_type {
                host.asset.asset_type = ssdp_asset_type(dt);
            }
        }
        if !host.services.iter().any(|x| x.port == 1900) {
            let banner = join_nonempty(&[
                s.server.as_deref(),
                s.manufacturer.as_deref(),
                s.model_name.as_deref(),
                s.device_type.as_deref(),
            ]);
            host.services.push(Service {
                port: 1900,
                protocol: Protocol::Udp,
                product: Some("SSDP/UPnP".to_owned()),
                banner,
                cpe: None,
            });
        }
    }
}

/// UPnP `deviceType` → asset class. Gateways are network gear; most other UPnP
/// roots are consumer media/IoT. Anything unrecognised stays `Unknown` for fusion.
fn ssdp_asset_type(device_type: &str) -> AssetType {
    let d = device_type.to_lowercase();
    if d.contains("internetgateway") || d.contains("wandevice") || d.contains("wanconnection") {
        AssetType::Network
    } else if d.contains("mediarenderer")
        || d.contains("mediaserver")
        || d.contains("printer")
        || d.contains("light")
        || d.contains("basic")
    {
        AssetType::Iot
    } else {
        AssetType::Unknown
    }
}

/// Merge WS-Discovery findings: add in-scope responders, classify from the
/// advertised Types (printer/camera/computer), and record a Types/XAddrs banner.
fn merge_wsd(hosts: &mut Vec<DiscoveredHost>, found: Vec<wsd::WsdHost>, scope: &HashSet<IpAddr>) {
    for w in found {
        if !scope.contains(&w.ip) {
            continue;
        }
        let idx = upsert_host(hosts, w.ip);
        let host = &mut hosts[idx];
        if host.asset.asset_type == AssetType::Unknown {
            host.asset.asset_type = wsd_asset_type(&w.types);
        }
        if !host.services.iter().any(|x| x.port == 3702) {
            let types = w.types.join(" ");
            let banner = join_nonempty(&[
                (!types.is_empty()).then_some(types.as_str()),
                w.xaddrs.first().map(String::as_str),
            ]);
            host.services.push(Service {
                port: 3702,
                protocol: Protocol::Udp,
                product: Some("WS-Discovery".to_owned()),
                banner,
                cpe: None,
            });
        }
    }
}

/// WS-Discovery `Types` QNames → asset class.
fn wsd_asset_type(types: &[String]) -> AssetType {
    let joined = types.join(" ").to_lowercase();
    if joined.contains("print")
        || joined.contains("networkvideotransmitter")
        || joined.contains("onvif")
    {
        AssetType::Iot
    } else if joined.contains("computer") || joined.contains("device") {
        AssetType::It
    } else {
        AssetType::Unknown
    }
}

/// Merge CoAP findings: add in-scope responders as IoT and record their
/// advertised resource list.
fn merge_coap(
    hosts: &mut Vec<DiscoveredHost>,
    found: Vec<coap::CoapHost>,
    scope: &HashSet<IpAddr>,
) {
    for c in found {
        if !scope.contains(&c.ip) {
            continue;
        }
        let idx = upsert_host(hosts, c.ip);
        let host = &mut hosts[idx];
        if host.asset.asset_type == AssetType::Unknown {
            host.asset.asset_type = AssetType::Iot;
        }
        if !host.services.iter().any(|x| x.port == 5683) {
            let res = c.resources.join(",");
            host.services.push(Service {
                port: 5683,
                protocol: Protocol::Udp,
                product: Some("CoAP".to_owned()),
                banner: (!res.is_empty()).then_some(res),
                cpe: None,
            });
        }
    }
}

/// Merge miIO findings: record the UDP-54321 handshake (device id + stamp) as a
/// service. The Xiaomi-IoT classification is deliberately left to `fusion`, which
/// keys off this service — so the OUI alone never upgrades a host's class; only
/// the positive, unauthenticated miIO response does.
fn merge_miio(
    hosts: &mut Vec<DiscoveredHost>,
    found: Vec<miio::MiioHost>,
    scope: &HashSet<IpAddr>,
) {
    for m in found {
        if !scope.contains(&m.ip) {
            continue;
        }
        let idx = upsert_host(hosts, m.ip);
        let host = &mut hosts[idx];
        if !host.services.iter().any(|x| x.port == 54321) {
            host.services.push(Service {
                port: 54321,
                protocol: Protocol::Udp,
                product: Some("miIO".to_owned()),
                banner: Some(format!("device_id=0x{:08x} stamp={}", m.device_id, m.stamp)),
                cpe: None,
            });
        }
    }
}

/// Reverse-DNS (PTR) every host that still lacks a hostname, concurrently.
async fn rdns_enrich(hosts: &mut [DiscoveredHost]) {
    use tokio::task::JoinSet;
    let targets: Vec<(usize, IpAddr)> = hosts
        .iter()
        .enumerate()
        .filter_map(|(i, h)| {
            let iface = h.asset.interfaces.first()?;
            if iface.hostname.is_some() {
                return None;
            }
            iface.ip.map(|ip| (i, ip))
        })
        .collect();
    let mut set = JoinSet::new();
    for (idx, ip) in targets {
        set.spawn(async move { (idx, rdns::lookup(ip, Duration::from_millis(1500)).await) });
    }
    while let Some(joined) = set.join_next().await {
        let Ok((idx, Some(name))) = joined else {
            continue;
        };
        if let Some(iface) = hosts[idx].asset.interfaces.first_mut() {
            iface.hostname.get_or_insert(name);
        }
    }
}

/// Ports we attempt a TLS certificate harvest on.
const TLS_PORTS: &[u16] = &[443, 8443, 9443, 4443];

/// Harvest the leaf TLS certificate from each host's open TLS ports, folding the
/// subject/SAN hostname and an issuer/SAN banner back in.
async fn tls_enrich(hosts: &mut [DiscoveredHost]) {
    use tokio::task::JoinSet;
    if !tls::available().await {
        return;
    }
    let mut targets: Vec<(usize, IpAddr, u16)> = Vec::new();
    for (i, h) in hosts.iter().enumerate() {
        let Some(ip) = h.asset.interfaces.first().and_then(|f| f.ip) else {
            continue;
        };
        for &p in &h.open_ports {
            if TLS_PORTS.contains(&p) {
                targets.push((i, ip, p));
            }
        }
    }
    let mut set = JoinSet::new();
    for (idx, ip, port) in targets {
        set.spawn(async move { (idx, port, tls::cert(ip, port, Duration::from_secs(4)).await) });
    }
    while let Some(joined) = set.join_next().await {
        let Ok((idx, port, Some(cert))) = joined else {
            continue;
        };
        apply_tls(&mut hosts[idx], port, &cert);
    }
}

/// Fold a harvested certificate onto a host: a DNS-name identity and a banner.
fn apply_tls(host: &mut DiscoveredHost, port: u16, cert: &tls::TlsCert) {
    let name = cert
        .subject_cn
        .clone()
        .filter(|n| is_dns_name(n))
        .or_else(|| cert.sans.iter().find(|s| is_dns_name(s)).cloned());
    if let Some(name) = name {
        if let Some(iface) = host.asset.interfaces.first_mut() {
            iface.hostname.get_or_insert(name);
        }
    }
    let mut facet = String::from("tls:");
    if let Some(cn) = &cert.subject_cn {
        let _ = write!(facet, " CN={cn}");
    }
    if let Some(issuer) = &cert.issuer {
        let _ = write!(facet, " issuer={issuer}");
    }
    if !cert.sans.is_empty() {
        let _ = write!(facet, " SAN={}", cert.sans.join(","));
    }
    enrich_service_banner(host, port, facet, "tls:");
}

/// HTTP-fingerprint each host's open web ports (plain and TLS), concurrently.
async fn http_enrich(hosts: &mut [DiscoveredHost]) {
    use tokio::task::JoinSet;
    let mut targets: Vec<(usize, IpAddr, u16, bool)> = Vec::new();
    for (i, h) in hosts.iter().enumerate() {
        let Some(ip) = h.asset.interfaces.first().and_then(|f| f.ip) else {
            continue;
        };
        for &p in &h.open_ports {
            if let Some(is_tls) = web_kind(p) {
                targets.push((i, ip, p, is_tls));
            }
        }
    }
    let mut set = JoinSet::new();
    for (idx, ip, port, is_tls) in targets {
        set.spawn(async move {
            (
                idx,
                port,
                http::fingerprint(ip, port, is_tls, Duration::from_secs(4)).await,
            )
        });
    }
    while let Some(joined) = set.join_next().await {
        let Ok((idx, port, Some(info))) = joined else {
            continue;
        };
        apply_http(&mut hosts[idx], port, &info);
    }
}

/// Map a port to its web kind: `Some(false)` = plain HTTP, `Some(true)` = HTTPS,
/// `None` = not a web port we fingerprint.
fn web_kind(port: u16) -> Option<bool> {
    match port {
        80 | 8080 | 8000 | 8008 | 8081 | 8888 | 5000 | 3000 => Some(false),
        443 | 8443 | 9443 | 4443 => Some(true),
        _ => None,
    }
}

/// Fold an HTTP fingerprint onto a host as a service banner facet.
fn apply_http(host: &mut DiscoveredHost, port: u16, info: &http::HttpInfo) {
    let mut facet = format!("http:{}", info.status);
    if let Some(server) = &info.server {
        let _ = write!(facet, " Server={server}");
    }
    if let Some(pb) = &info.powered_by {
        let _ = write!(facet, " X-Powered-By={pb}");
    }
    if let Some(title) = &info.title {
        let _ = write!(facet, " title={title}");
    }
    enrich_service_banner(host, port, facet, "http:");
}

/// Append a banner `facet` to the service on `port` (creating a bare service if
/// none exists). `guard` makes it idempotent: a facet whose marker is already
/// present is not re-appended, so repeated enrich passes don't duplicate it.
fn enrich_service_banner(host: &mut DiscoveredHost, port: u16, facet: String, guard: &str) {
    if let Some(svc) = host.services.iter_mut().find(|s| s.port == port) {
        if svc.banner.as_deref().is_some_and(|b| b.contains(guard)) {
            return;
        }
        match &mut svc.banner {
            Some(b) => {
                b.push_str(" | ");
                b.push_str(&facet);
            }
            None => svc.banner = Some(facet),
        }
    } else {
        host.services.push(Service {
            port,
            protocol: Protocol::Tcp,
            product: None,
            banner: Some(facet),
            cpe: None,
        });
    }
}

/// Whether `s` is a usable DNS name (not empty, not an IP literal, not a wildcard).
fn is_dns_name(s: &str) -> bool {
    !s.is_empty() && s.contains('.') && !s.starts_with('*') && s.parse::<IpAddr>().is_err()
}

/// Union a fresh scan round into an accumulating inventory, keyed by IP.
///
/// A device seen in any round persists; per device, open ports and services are
/// unioned and any newly-learned fingerprint field (vendor/model/os/device_type),
/// hostname or MAC is kept. This is how a stateless multi-round scan beats
/// power-saving Wi-Fi, where a single sweep misses devices that are briefly
/// asleep — run a few rounds and the union holds every device that woke for any
/// one of them. Re-run [`fusion::fuse_hosts`] on the result to reclassify from the
/// unioned signals.
pub fn accumulate(into: &mut Vec<DiscoveredHost>, round: Vec<DiscoveredHost>) {
    for host in round {
        let ip = host.asset.interfaces.first().and_then(|i| i.ip);
        let existing = ip.and_then(|ip| {
            into.iter_mut()
                .find(|h| h.asset.interfaces.iter().any(|i| i.ip == Some(ip)))
        });
        match existing {
            Some(existing) => merge_round_host(existing, host),
            None => into.push(host),
        }
    }
}

/// Fold a later observation of the same host into the accumulated one.
fn merge_round_host(existing: &mut DiscoveredHost, new: DiscoveredHost) {
    for svc in new.services {
        if let Some(cur) = existing
            .services
            .iter_mut()
            .find(|s| s.port == svc.port && s.protocol == svc.protocol)
        {
            if cur.banner.is_none() {
                cur.banner = svc.banner;
            }
            if cur.product.is_none() {
                cur.product = svc.product;
            }
        } else {
            existing.services.push(svc);
        }
    }
    for port in new.open_ports {
        if !existing.open_ports.contains(&port) {
            existing.open_ports.push(port);
        }
    }
    existing.open_ports.sort_unstable();

    let (ef, nf) = (&mut existing.asset.fingerprint, new.asset.fingerprint);
    if ef.vendor.is_none() {
        ef.vendor = nf.vendor;
    }
    if ef.model.is_none() {
        ef.model = nf.model;
    }
    if ef.os.is_none() {
        ef.os = nf.os;
    }
    if ef.device_type.is_none() {
        ef.device_type = nf.device_type;
    }
    if existing.asset.asset_type == AssetType::Unknown {
        existing.asset.asset_type = new.asset.asset_type;
    }
    if let (Some(e), Some(n)) = (
        existing.asset.interfaces.first_mut(),
        new.asset.interfaces.first(),
    ) {
        if e.hostname.is_none() {
            e.hostname.clone_from(&n.hostname);
        }
        if e.mac.is_none() {
            e.mac = n.mac;
        }
    }
    existing.asset.last_seen = new.asset.last_seen;
}

/// Probe each host with an open IPP port (631) for printer make/model/state —
/// the exact identity a port-class "printer" guess cannot give.
async fn ipp_enrich(hosts: &mut [DiscoveredHost]) {
    use tokio::task::JoinSet;
    let mut targets: Vec<(usize, IpAddr)> = Vec::new();
    for (i, h) in hosts.iter().enumerate() {
        let Some(ip) = h.asset.interfaces.first().and_then(|f| f.ip) else {
            continue;
        };
        if h.open_ports.contains(&631) {
            targets.push((i, ip));
        }
    }
    let mut set = JoinSet::new();
    for (idx, ip) in targets {
        set.spawn(async move { (idx, ipp::query(ip, 631, Duration::from_secs(4)).await) });
    }
    while let Some(joined) = set.join_next().await {
        let Ok((idx, Some(printer))) = joined else {
            continue;
        };
        apply_ipp(&mut hosts[idx], &printer);
    }
}

/// Fold an IPP printer's attributes onto a host: its make/model and a banner.
fn apply_ipp(host: &mut DiscoveredHost, printer: &ipp::IppPrinter) {
    if host.asset.fingerprint.model.is_none() {
        host.asset
            .fingerprint
            .model
            .clone_from(&printer.make_and_model);
    }
    let mut facet = String::from("ipp:");
    if let Some(mm) = &printer.make_and_model {
        let _ = write!(facet, " {mm}");
    }
    if let Some(state) = &printer.state {
        let _ = write!(facet, " state={state}");
    }
    if let Some(loc) = &printer.location {
        let _ = write!(facet, " loc={loc}");
    }
    enrich_service_banner(host, 631, facet, "ipp:");
}

/// Probe each host with an open JetDirect port (9100) for its printer model via
/// PJL — the identity for a raw-port printer that exposes neither IPP nor mDNS.
async fn pjl_enrich(hosts: &mut [DiscoveredHost]) {
    use tokio::task::JoinSet;
    let mut targets: Vec<(usize, IpAddr)> = Vec::new();
    for (i, h) in hosts.iter().enumerate() {
        let Some(ip) = h.asset.interfaces.first().and_then(|f| f.ip) else {
            continue;
        };
        if h.open_ports.contains(&9100) {
            targets.push((i, ip));
        }
    }
    let mut set = JoinSet::new();
    for (idx, ip) in targets {
        set.spawn(async move { (idx, pjl::query(ip, 9100, Duration::from_secs(4)).await) });
    }
    while let Some(joined) = set.join_next().await {
        let Ok((idx, Some(info))) = joined else {
            continue;
        };
        apply_pjl(&mut hosts[idx], &info);
    }
}

/// Fold a PJL printer identity onto a host: its model and a banner.
fn apply_pjl(host: &mut DiscoveredHost, info: &pjl::PjlInfo) {
    if host.asset.fingerprint.model.is_none() {
        host.asset.fingerprint.model.clone_from(&info.id);
    }
    let mut facet = String::from("pjl:");
    if let Some(id) = &info.id {
        let _ = write!(facet, " {id}");
    }
    if let Some(status) = &info.status {
        let _ = write!(facet, " status={status}");
    }
    enrich_service_banner(host, 9100, facet, "pjl:");
}

/// Probe each host with an open RTSP port (554) for its camera/NVR server banner.
async fn rtsp_enrich(hosts: &mut [DiscoveredHost]) {
    use tokio::task::JoinSet;
    let mut targets: Vec<(usize, IpAddr)> = Vec::new();
    for (i, h) in hosts.iter().enumerate() {
        let Some(ip) = h.asset.interfaces.first().and_then(|f| f.ip) else {
            continue;
        };
        if h.open_ports.contains(&554) {
            targets.push((i, ip));
        }
    }
    let mut set = JoinSet::new();
    for (idx, ip) in targets {
        set.spawn(async move { (idx, rtsp::query(ip, 554, Duration::from_secs(4)).await) });
    }
    while let Some(joined) = set.join_next().await {
        let Ok((idx, Some(info))) = joined else {
            continue;
        };
        apply_rtsp(&mut hosts[idx], &info);
    }
}

/// Fold an RTSP server banner (the camera/NVR identifier) onto a host.
fn apply_rtsp(host: &mut DiscoveredHost, info: &rtsp::RtspInfo) {
    let mut facet = format!("rtsp:{}", info.status);
    if let Some(server) = &info.server {
        let _ = write!(facet, " Server={server}");
    }
    if let Some(public) = &info.public {
        let _ = write!(facet, " Public={public}");
    }
    enrich_service_banner(host, 554, facet, "rtsp:");
}

/// MQTT ports we confirm a broker on.
const MQTT_PORTS: &[u16] = &[1883, 8883];

/// Confirm an MQTT broker on each host's open MQTT ports via a `CONNECT`/`CONNACK`.
async fn mqtt_enrich(hosts: &mut [DiscoveredHost]) {
    use tokio::task::JoinSet;
    let mut targets: Vec<(usize, IpAddr, u16)> = Vec::new();
    for (i, h) in hosts.iter().enumerate() {
        let Some(ip) = h.asset.interfaces.first().and_then(|f| f.ip) else {
            continue;
        };
        for &p in &h.open_ports {
            if MQTT_PORTS.contains(&p) {
                targets.push((i, ip, p));
            }
        }
    }
    let mut set = JoinSet::new();
    for (idx, ip, port) in targets {
        set.spawn(async move {
            (
                idx,
                port,
                mqtt::query(ip, port, Duration::from_secs(4)).await,
            )
        });
    }
    while let Some(joined) = set.join_next().await {
        let Ok((idx, port, Some(info))) = joined else {
            continue;
        };
        let auth = if info.anonymous_ok {
            "anonymous-ok"
        } else {
            "auth-required"
        };
        let facet = format!("mqtt: broker rc={} {auth}", info.return_code);
        enrich_service_banner(&mut hosts[idx], port, facet, "mqtt:");
    }
}

/// Query the rootDSE of each host with an open LDAP port (389/636) — the naming
/// context + DC hostname identify an Active Directory domain controller.
async fn ldap_enrich(hosts: &mut [DiscoveredHost]) {
    use tokio::task::JoinSet;
    let mut targets: Vec<(usize, IpAddr, u16)> = Vec::new();
    for (i, h) in hosts.iter().enumerate() {
        let Some(ip) = h.asset.interfaces.first().and_then(|f| f.ip) else {
            continue;
        };
        if let Some(&port) = h.open_ports.iter().find(|&&p| p == 389 || p == 636) {
            targets.push((i, ip, port));
        }
    }
    let mut set = JoinSet::new();
    for (idx, ip, port) in targets {
        set.spawn(async move {
            (
                idx,
                port,
                ldap::query(ip, port, Duration::from_secs(4)).await,
            )
        });
    }
    while let Some(joined) = set.join_next().await {
        let Ok((idx, port, Some(dse))) = joined else {
            continue;
        };
        apply_ldap(&mut hosts[idx], port, &dse);
        // rootDSE is always readable (not a finding). If it advertises a base
        // DN, test whether the directory CONTENTS are readable without a bind —
        // that is the actual misconfiguration, and it unlocks AS-REP-roastable
        // detection (userAccountControl & DONT_REQ_PREAUTH).
        if let Some(base) = dse.default_naming_context.clone() {
            if let Some(ip) = hosts[idx].asset.interfaces.first().and_then(|f| f.ip) {
                if let Some(found) =
                    ldap::query_users(ip, port, &base, Duration::from_secs(4)).await
                {
                    apply_ldap_users(&mut hosts[idx], port, &found);
                }
            }
        }
    }
}

/// Fold an LDAP rootDSE onto a host: DC hostname + a domain banner.
fn apply_ldap(host: &mut DiscoveredHost, port: u16, dse: &ldap::LdapRootDse) {
    if let Some(name) = &dse.dns_host_name {
        if let Some(iface) = host.asset.interfaces.first_mut() {
            iface.hostname.get_or_insert_with(|| name.clone());
        }
    }
    // A defaultNamingContext / dnsHostName is AD-specific → a domain controller.
    let is_dc = dse.default_naming_context.is_some() || dse.dns_host_name.is_some();
    let mut facet = String::from(if is_dc {
        "ldap: domain-controller"
    } else {
        "ldap: directory"
    });
    if let Some(nc) = &dse.default_naming_context {
        let _ = write!(facet, " domain={nc}");
    }
    if let Some(h) = &dse.dns_host_name {
        let _ = write!(facet, " host={h}");
    }
    enrich_service_banner(host, port, facet, "ldap:");
}

/// Surface an anonymous-directory-read finding plus any AS-REP-roastable users.
fn apply_ldap_users(host: &mut DiscoveredHost, port: u16, found: &ldap::SubtreeFindings) {
    let mut facet = format!(
        "ldap: ANONYMOUS directory read — {} user(s) enumerable unauthenticated",
        found.users.len()
    );
    if !found.asrep_roastable.is_empty() {
        let _ = write!(
            facet,
            "; AS-REP-roastable: {}",
            found.asrep_roastable.join(", ")
        );
    }
    enrich_service_banner(host, port, facet, "ldap: ANONYMOUS");
}

/// SMB2 NEGOTIATE probe (445): record the dialect and whether the server
/// requires signing. Signing enabled-but-not-required is the NTLM-relay finding.
async fn smb_enrich(hosts: &mut [DiscoveredHost]) {
    use tokio::task::JoinSet;
    let mut targets: Vec<(usize, IpAddr)> = Vec::new();
    for (i, h) in hosts.iter().enumerate() {
        let Some(ip) = h.asset.interfaces.first().and_then(|f| f.ip) else {
            continue;
        };
        if h.open_ports.contains(&445) {
            targets.push((i, ip));
        }
    }
    let mut set = JoinSet::new();
    for (idx, ip) in targets {
        set.spawn(async move { (idx, smb::query(ip, Duration::from_secs(4)).await) });
    }
    while let Some(joined) = set.join_next().await {
        let Ok((idx, Some(info))) = joined else {
            continue;
        };
        apply_smb(&mut hosts[idx], &info);
    }
}

/// Fold an SMB2 NEGOTIATE result onto a host as a signing-posture facet.
fn apply_smb(host: &mut DiscoveredHost, info: &smb::SmbInfo) {
    let dialect = info.dialect.as_deref().unwrap_or("SMB2");
    let facet = if info.signing_required {
        format!("smb: {dialect} — signing required")
    } else {
        format!("smb: {dialect} — signing NOT required (NTLM-relay exposed)")
    };
    enrich_service_banner(host, 445, facet, "smb:");
}

/// Ask the SQL Server Browser (UDP 1434) of each host with an open 1433.
async fn mssql_enrich(hosts: &mut [DiscoveredHost]) {
    use tokio::task::JoinSet;
    let mut targets: Vec<(usize, IpAddr)> = Vec::new();
    for (i, h) in hosts.iter().enumerate() {
        let Some(ip) = h.asset.interfaces.first().and_then(|f| f.ip) else {
            continue;
        };
        if h.open_ports.contains(&1433) {
            targets.push((i, ip));
        }
    }
    let mut set = JoinSet::new();
    for (idx, ip) in targets {
        set.spawn(async move { (idx, mssql::query(ip, Duration::from_secs(3)).await) });
    }
    while let Some(joined) = set.join_next().await {
        let Ok((idx, Some(instances))) = joined else {
            continue;
        };
        apply_mssql(&mut hosts[idx], &instances);
    }
}

/// Fold MSSQL Browser instances onto a host: version model + an instance banner.
fn apply_mssql(host: &mut DiscoveredHost, instances: &[mssql::MssqlInstance]) {
    if host.asset.fingerprint.model.is_none() {
        if let Some(version) = instances.iter().find_map(|i| i.version.as_ref()) {
            host.asset.fingerprint.model = Some(format!("SQL Server {version}"));
        }
    }
    let mut facet = String::from("mssql:");
    for inst in instances {
        if let Some(name) = &inst.instance {
            let _ = write!(facet, " {name}");
        }
        if let Some(version) = &inst.version {
            let _ = write!(facet, "/{version}");
        }
        if let Some(port) = inst.tcp_port {
            let _ = write!(facet, "@{port}");
        }
    }
    enrich_service_banner(host, 1433, facet, "mssql:");
}

/// Read the device identification of each host with an open Modbus port (502).
async fn modbus_enrich(hosts: &mut [DiscoveredHost]) {
    use tokio::task::JoinSet;
    let mut targets: Vec<(usize, IpAddr)> = Vec::new();
    for (i, h) in hosts.iter().enumerate() {
        let Some(ip) = h.asset.interfaces.first().and_then(|f| f.ip) else {
            continue;
        };
        if h.open_ports.contains(&502) {
            targets.push((i, ip));
        }
    }
    let mut set = JoinSet::new();
    for (idx, ip) in targets {
        set.spawn(async move { (idx, modbus::query(ip, 502, Duration::from_secs(4)).await) });
    }
    while let Some(joined) = set.join_next().await {
        let Ok((idx, Some(id))) = joined else {
            continue;
        };
        apply_modbus(&mut hosts[idx], &id);
    }
}

/// Fold a Modbus device identification onto a host: vendor/product model.
fn apply_modbus(host: &mut DiscoveredHost, id: &modbus::ModbusId) {
    if host.asset.fingerprint.model.is_none() {
        host.asset.fingerprint.model.clone_from(&id.product_code);
    }
    let mut facet = String::from("modbus:");
    if let Some(vendor) = &id.vendor {
        let _ = write!(facet, " {vendor}");
    }
    if let Some(product) = &id.product_code {
        let _ = write!(facet, " {product}");
    }
    if let Some(rev) = &id.revision {
        let _ = write!(facet, " rev {rev}");
    }
    enrich_service_banner(host, 502, facet, "modbus:");
}

/// Probe every known host for an EtherNet/IP identity (UDP 44818) — the protocol
/// is UDP-only, so it is not gated on a TCP port.
async fn enip_enrich(hosts: &mut [DiscoveredHost]) {
    use tokio::task::JoinSet;
    let targets: Vec<(usize, IpAddr)> = hosts
        .iter()
        .enumerate()
        .filter_map(|(i, h)| {
            h.asset
                .interfaces
                .first()
                .and_then(|f| f.ip)
                .map(|ip| (i, ip))
        })
        .collect();
    let mut set = JoinSet::new();
    for (idx, ip) in targets {
        set.spawn(async move { (idx, enip::query(ip, Duration::from_millis(900)).await) });
    }
    while let Some(joined) = set.join_next().await {
        let Ok((idx, Some(id))) = joined else {
            continue;
        };
        apply_enip(&mut hosts[idx], &id);
    }
}

/// Fold an EtherNet/IP identity onto a host: product-name model + a banner.
fn apply_enip(host: &mut DiscoveredHost, id: &enip::EnipIdentity) {
    if host.asset.fingerprint.model.is_none() {
        host.asset.fingerprint.model.clone_from(&id.product_name);
    }
    let mut facet = String::from("enip: EtherNet/IP");
    if let Some(name) = &id.product_name {
        let _ = write!(facet, " {name}");
    }
    let _ = write!(facet, " vendor={} type={}", id.vendor_id, id.device_type);
    if let Some(rev) = &id.revision {
        let _ = write!(facet, " rev {rev}");
    }
    enrich_service_banner(host, 44818, facet, "enip:");
}

/// Probe every known host for a BACnet device (UDP 47808, unconfirmed Who-Is).
async fn bacnet_enrich(hosts: &mut [DiscoveredHost]) {
    use tokio::task::JoinSet;
    let targets: Vec<(usize, IpAddr)> = hosts
        .iter()
        .enumerate()
        .filter_map(|(i, h)| {
            h.asset
                .interfaces
                .first()
                .and_then(|f| f.ip)
                .map(|ip| (i, ip))
        })
        .collect();
    let mut set = JoinSet::new();
    for (idx, ip) in targets {
        set.spawn(async move {
            (
                idx,
                bacnet::query(ip, bacnet::BACNET_PORT, Duration::from_millis(900)).await,
            )
        });
    }
    while let Some(joined) = set.join_next().await {
        let Ok((idx, Some(dev))) = joined else {
            continue;
        };
        apply_bacnet(&mut hosts[idx], &dev);
    }
}

/// Fold a BACnet I-Am onto a host: device-instance + vendor banner.
fn apply_bacnet(host: &mut DiscoveredHost, dev: &bacnet::BacnetDevice) {
    let mut facet = String::from("bacnet:");
    if let Some(instance) = dev.device_instance {
        let _ = write!(facet, " device={instance}");
    }
    if let Some(vendor) = dev.vendor_id {
        let _ = write!(facet, " vendor={vendor}");
    }
    enrich_service_banner(host, bacnet::BACNET_PORT, facet, "bacnet:");
}

fn build_host(ip: IpAddr, mut open: Vec<(u16, Option<String>)>) -> DiscoveredHost {
    open.sort_unstable_by_key(|(port, _)| *port);
    let ports: Vec<u16> = open.iter().map(|(port, _)| *port).collect();
    let (asset_type, fingerprint) = fingerprint::classify(&ports);
    let insecure_score = fingerprint::insecure_service_score(&ports);
    let now = OffsetDateTime::now_utc();

    let services = open
        .into_iter()
        .map(|(port, raw)| Service {
            port,
            protocol: Protocol::Tcp,
            // Prefer a product parsed from the connect-time banner (e.g.
            // "OpenSSH 8.9p1" → version-specific CVEs); else the port's
            // canonical service token, as before.
            product: raw
                .as_deref()
                .and_then(banner::to_product)
                .or_else(|| fingerprint::service_name(port).map(str::to_owned)),
            banner: raw,
            cpe: None,
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
        open_ports: ports,
        insecure_score,
        // The light connect scan is payload-free — it does not probe SMB.
        smb_v1: None,
    }
}

/// Merge mDNS findings into the live set: enrich a matching host, or add an
/// in-scope device that answered mDNS but exposed no scanned TCP port.
fn merge_mdns(live: &mut Vec<DiscoveredHost>, found: Vec<mdns::MdnsHost>, scope: &HashSet<IpAddr>) {
    for m in found {
        if !scope.contains(&m.ip) {
            continue;
        }
        if let Some(host) = live
            .iter_mut()
            .find(|h| h.asset.interfaces.iter().any(|i| i.ip == Some(m.ip)))
        {
            apply_mdns(host, &m);
        } else {
            let mut host = base_host(m.ip);
            apply_mdns(&mut host, &m);
            live.push(host);
        }
    }
}

/// Apply an mDNS finding's hostname / model / service types onto a host.
fn apply_mdns(host: &mut DiscoveredHost, m: &mdns::MdnsHost) {
    if let Some(name) = &m.hostname {
        if let Some(iface) = host.asset.interfaces.first_mut() {
            if iface.hostname.is_none() {
                iface.hostname = Some(name.clone());
            }
        }
    }
    if host.asset.fingerprint.model.is_none() {
        host.asset.fingerprint.model.clone_from(&m.model);
    }
    if !m.services.is_empty() {
        if !host.services.iter().any(|s| s.port == 5353) {
            host.services.push(Service {
                port: 5353,
                protocol: Protocol::Udp,
                product: Some("mDNS".to_owned()),
                banner: Some(m.services.join(", ")),
                cpe: None,
            });
        }
        if host.asset.asset_type == argus_core::AssetType::Unknown {
            host.asset.asset_type = mdns_asset_type(&m.services);
        }
    }
}

/// Best-effort asset class from advertised mDNS service types.
fn mdns_asset_type(services: &[String]) -> argus_core::AssetType {
    use argus_core::AssetType;
    let has = |needle: &str| services.iter().any(|s| s.contains(needle));
    if has("_ipp")
        || has("_printer")
        || has("_pdl")
        || has("_scanner")
        || has("_googlecast")
        || has("_airplay")
        || has("_raop")
        || has("_spotify")
        || has("_hap")
        || has("_homekit")
    {
        AssetType::Iot
    } else if has("_workstation")
        || has("_smb")
        || has("_ssh")
        || has("_sftp")
        || has("_afpovertcp")
    {
        AssetType::It
    } else {
        AssetType::Unknown
    }
}

/// Build a minimal host from an IP alone (an mDNS-only device with no scanned
/// TCP port). Fusion + MAC/OUI enrichment refine it afterwards.
fn base_host(ip: IpAddr) -> DiscoveredHost {
    let now = OffsetDateTime::now_utc();
    DiscoveredHost {
        asset: Asset {
            id: AssetId::new(),
            asset_type: argus_core::AssetType::Unknown,
            criticality: Criticality::Medium,
            exposure: if is_internal(ip) {
                Exposure::Internal
            } else {
                Exposure::InternetFacing
            },
            fingerprint: argus_core::Fingerprint::default(),
            interfaces: vec![Interface {
                mac: None,
                ip: Some(ip),
                vlan: None,
                hostname: None,
            }],
            first_seen: now,
            last_seen: now,
        },
        services: Vec::new(),
        open_ports: Vec::new(),
        insecure_score: 0.0,
        smb_v1: None,
    }
}

/// Fill each host's MAC and resolve its OUI vendor.
///
/// MACs come from the kernel ARP cache (where missing) or from another probe
/// that already supplied one (e.g. NetBIOS, which carries the MAC in its payload
/// and so survives a NAT the ARP cache does not). The vendor is looked up from
/// whatever MAC the host ends up with.
pub fn enrich_macs(hosts: &mut [DiscoveredHost]) {
    if hosts.is_empty() {
        return;
    }
    let arp = arp::read_arp_table();
    let oui = oui::OuiDb::load();

    for host in hosts.iter_mut() {
        for iface in &mut host.asset.interfaces {
            if iface.mac.is_none() {
                if let Some(ip) = iface.ip {
                    if let Some(&mac) = arp.get(&ip) {
                        iface.mac = Some(mac);
                    }
                }
            }
        }
        if host.asset.fingerprint.vendor.is_none() {
            if let Some(mac) = host.asset.interfaces.iter().find_map(|i| i.mac) {
                if let Some(vendor) = oui.vendor(mac) {
                    host.asset.fingerprint.vendor = Some(vendor.to_owned());
                }
            }
        }
    }
}

/// Probe each host over SNMP (UDP 161, `public`), folding sysName/sysDescr in.
async fn snmp_probe(hosts: &mut [DiscoveredHost]) {
    use tokio::task::JoinSet;
    let targets: Vec<(usize, IpAddr)> = hosts
        .iter()
        .enumerate()
        .filter_map(|(i, h)| {
            h.asset
                .interfaces
                .first()
                .and_then(|f| f.ip)
                .map(|ip| (i, ip))
        })
        .collect();
    let mut set = JoinSet::new();
    for (idx, ip) in targets {
        set.spawn(async move { (idx, snmp::query(ip, Duration::from_millis(800)).await) });
    }
    while let Some(joined) = set.join_next().await {
        let Ok((idx, Some(res))) = joined else {
            continue;
        };
        let host = &mut hosts[idx];
        if let Some(name) = res.name {
            if let Some(iface) = host.asset.interfaces.first_mut() {
                iface.hostname.get_or_insert(name);
            }
        }
        if let Some(descr) = res.descr {
            if !host.services.iter().any(|s| s.port == 161) {
                host.services.push(Service {
                    port: 161,
                    protocol: Protocol::Udp,
                    product: Some("SNMP".to_owned()),
                    banner: Some(descr),
                    cpe: None,
                });
            }
        }
    }
}

/// Probe each host's NetBIOS node status (UDP 137), folding name + MAC back in.
async fn netbios_probe(hosts: &mut [DiscoveredHost]) {
    use tokio::task::JoinSet;
    let targets: Vec<(usize, IpAddr)> = hosts
        .iter()
        .enumerate()
        .filter_map(|(i, h)| {
            h.asset
                .interfaces
                .first()
                .and_then(|f| f.ip)
                .map(|ip| (i, ip))
        })
        .collect();
    let mut set = JoinSet::new();
    for (idx, ip) in targets {
        set.spawn(async move { (idx, netbios::query(ip, Duration::from_millis(800)).await) });
    }
    while let Some(joined) = set.join_next().await {
        let Ok((idx, Some(res))) = joined else {
            continue;
        };
        let Some(iface) = hosts[idx].asset.interfaces.first_mut() else {
            continue;
        };
        if let Some(name) = res.name {
            iface.hostname.get_or_insert(name);
        }
        if let Some(mac) = res.mac {
            iface.mac.get_or_insert(MacAddr(mac));
        }
    }
}

/// Whether an address is on a private / internal range (light exposure
/// heuristic). Covers RFC1918, loopback, link-local, CGNAT (RFC6598
/// `100.64.0.0/10`), IPv6 unique-local / link-local, and IPv4-mapped IPv6.
pub(crate) fn is_internal(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_internal_v4(v4),
        IpAddr::V6(v6) => {
            // Resolve an IPv4-mapped address (`::ffff:a.b.c.d`) by its V4
            // identity so `10.x` / loopback cannot slip through as public.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_internal_v4(v4);
            }
            v6.is_loopback()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // unique-local fc00::/7
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
        }
    }
}

/// IPv4 private/internal classification, including CGNAT (`100.64.0.0/10`).
fn is_internal_v4(v4: Ipv4Addr) -> bool {
    v4.is_private()
        || v4.is_loopback()
        || v4.is_link_local()
        || matches!(v4.octets(), [100, 64..=127, _, _]) // CGNAT (RFC 6598)
}

/// Whether `ip` must be refused as a scan target by a multi-tenant server
/// unless internal scanning is explicitly enabled.
///
/// Covers everything [`is_internal`] does — RFC1918, loopback, link-local
/// (incl. the `169.254.169.254` cloud-metadata endpoint), CGNAT, IPv6
/// ULA/link-local, IPv4-mapped IPv6 — plus unspecified, broadcast and
/// documentation ranges, so the server cannot be turned into an
/// internal-network pivot (SSRF).
#[must_use]
pub fn is_disallowed_target(ip: IpAddr) -> bool {
    if is_internal(ip) {
        return true;
    }
    match ip {
        IpAddr::V4(v4) => v4.is_unspecified() || v4.is_broadcast() || v4.is_documentation(),
        // Mirror the IPv4 documentation block for IPv6's `2001:db8::/32`.
        IpAddr::V6(v6) => {
            v6.is_unspecified() || (v6.segments()[0] == 0x2001 && v6.segments()[1] == 0x0db8)
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
    fn internal_ranges_are_detected() {
        assert!(is_internal("127.0.0.1".parse().unwrap()));
        assert!(is_internal("10.1.2.3".parse().unwrap()));
        assert!(is_internal("100.64.0.1".parse().unwrap())); // CGNAT
        assert!(is_internal("::ffff:10.0.0.1".parse().unwrap())); // IPv4-mapped
        assert!(!is_internal("8.8.8.8".parse().unwrap()));
        assert!(!is_internal("100.128.0.1".parse().unwrap())); // just outside CGNAT
    }

    #[test]
    fn disallowed_targets_block_internal_and_metadata() {
        assert!(is_disallowed_target("169.254.169.254".parse().unwrap())); // cloud metadata
        assert!(is_disallowed_target("127.0.0.1".parse().unwrap()));
        assert!(is_disallowed_target("0.0.0.0".parse().unwrap()));
        assert!(is_disallowed_target("::ffff:192.168.1.1".parse().unwrap()));
        // IPv6 documentation range (2001:db8::/32) — blocked like IPv4's.
        assert!(is_disallowed_target("2001:db8::1".parse().unwrap()));
        assert!(!is_disallowed_target("8.8.8.8".parse().unwrap()));
        assert!(!is_disallowed_target("1.1.1.1".parse().unwrap()));
        assert!(!is_disallowed_target(
            "2606:4700:4700::1111".parse().unwrap()
        )); // public IPv6
    }

    #[test]
    fn enrich_on_empty_is_noop() {
        let mut hosts: Vec<DiscoveredHost> = Vec::new();
        enrich_macs(&mut hosts);
        assert!(hosts.is_empty());
    }

    #[test]
    fn accumulate_unions_ports_and_persists_devices() {
        let ip = |n| IpAddr::V4(Ipv4Addr::new(192, 168, 8, n));
        let svc = |port| Service {
            port,
            protocol: Protocol::Tcp,
            product: None,
            banner: None,
            cpe: None,
        };

        let mut first = base_host(ip(50));
        first.open_ports = vec![80];
        first.services.push(svc(80));
        let mut acc = vec![first];

        // A later round: the same device now answers on 443, and a device that
        // was asleep in round one (.51) shows up.
        let mut same = base_host(ip(50));
        same.open_ports = vec![443];
        same.services.push(svc(443));
        accumulate(&mut acc, vec![same, base_host(ip(51))]);

        assert_eq!(acc.len(), 2, "the device asleep in round one now persists");
        let dev = acc
            .iter()
            .find(|h| h.asset.interfaces[0].ip == Some(ip(50)))
            .expect("device .50 present");
        assert_eq!(dev.open_ports, vec![80, 443], "ports unioned across rounds");
    }
}
