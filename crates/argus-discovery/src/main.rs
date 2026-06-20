//! `argus-discovery [target] [--rounds N]` — run a light scan and print it.
//!
//! `target` is an IP or CIDR; it defaults to `127.0.0.1`. Connect-scan only, no
//! privileges required. `--rounds N` runs the scan N times and unions the
//! results, so power-saving Wi-Fi devices that are briefly asleep for one sweep
//! still land in the inventory. Only scan networks you are authorized to test.

use std::process::ExitCode;
use std::time::Duration;

use argus_discovery::{accumulate, enrich, expand, fusion, scan, DiscoveredHost, ScanOptions};

#[tokio::main]
async fn main() -> ExitCode {
    let (target, rounds) = parse_args();

    let hosts = match expand(&target) {
        Ok(hosts) => hosts,
        Err(err) => {
            eprintln!("argus-discovery: {err}");
            return ExitCode::FAILURE;
        }
    };

    eprintln!(
        "scanning {} host(s) from '{target}' over {rounds} round(s) …",
        hosts.len()
    );

    let mut acc: Vec<DiscoveredHost> = Vec::new();
    for round in 1..=rounds {
        let report = scan(&hosts, &ScanOptions::default()).await;
        let mut live = report.live;
        // Full enrichment pass (ARP + mDNS/SSDP/WSD/CoAP/miIO + unicast probes +
        // MAC/OUI + fusion), like the API.
        enrich(&mut live, &hosts).await;
        let this_round = live.len();
        accumulate(&mut acc, live);
        if rounds > 1 {
            eprintln!(
                "  round {round}/{rounds}: {this_round} live, {} unioned",
                acc.len()
            );
            if round < rounds {
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        }
    }
    // Reclassify from the unioned signals (a device's full picture may only exist
    // across rounds — e.g. a MAC from one sweep, an mDNS name from another).
    fusion::fuse_hosts(&mut acc);
    acc.sort_by_key(host_sort_key);

    println!(
        "scanned {} host(s) over {rounds} round(s) — {} live",
        hosts.len(),
        acc.len()
    );
    for host in &acc {
        print_host(host);
    }
    ExitCode::SUCCESS
}

/// Parse `[target] [--rounds N]` from the command line. Target defaults to
/// loopback; rounds defaults to 1 and is clamped to at least 1.
fn parse_args() -> (String, u32) {
    let mut target = "127.0.0.1".to_owned();
    let mut rounds: u32 = 1;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--rounds" {
            rounds = args.next().and_then(|v| v.parse().ok()).unwrap_or(1).max(1);
        } else if !arg.starts_with('-') {
            target = arg;
        }
    }
    (target, rounds)
}

/// Sort key for stable output: the host's first IP, octet-ordered.
fn host_sort_key(host: &DiscoveredHost) -> (u8, [u8; 16]) {
    match host.asset.interfaces.first().and_then(|i| i.ip) {
        Some(std::net::IpAddr::V4(v4)) => {
            let mut key = [0u8; 16];
            key[..4].copy_from_slice(&v4.octets());
            (0, key)
        }
        Some(std::net::IpAddr::V6(v6)) => (1, v6.octets()),
        None => (2, [0u8; 16]),
    }
}

/// Print one host: identity line, evidence, then per-service banners.
fn print_host(host: &DiscoveredHost) {
    let iface = host.asset.interfaces.first();
    let ip = iface
        .and_then(|i| i.ip)
        .map_or_else(|| "?".to_owned(), |ip| ip.to_string());
    let host_name = iface.and_then(|i| i.hostname.as_deref()).unwrap_or("-");
    let fp = &host.asset.fingerprint;
    println!(
        "  {ip:<16} {host_name:<22} type={:?} dev={} vendor={} os={} model={} conf={} ports={:?}",
        host.asset.asset_type,
        fp.device_type.as_deref().unwrap_or("-"),
        fp.vendor.as_deref().unwrap_or("-"),
        fp.os.as_deref().unwrap_or("-"),
        fp.model.as_deref().unwrap_or("-"),
        fp.confidence,
        host.open_ports,
    );
    if !fp.evidence.is_empty() {
        println!("      evidence: {}", fp.evidence.join(" · "));
    }
    // Per-service banners — where the HTTP/TLS/SSDP/WS-Discovery/CoAP/SNMP/IPP/
    // PJL/RTSP/MQTT enrichment lands. Only services that revealed something show.
    for svc in &host.services {
        if let Some(banner) = &svc.banner {
            let product = svc.product.as_deref().unwrap_or("-");
            println!("      :{:<5} {product:<13} {banner}", svc.port);
        }
    }
}
