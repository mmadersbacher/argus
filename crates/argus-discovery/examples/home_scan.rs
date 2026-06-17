//! Live device-detection test: scan a subnet, then classify every host with the
//! same pipeline the API uses (ARP/OUI vendor + ports + service banners →
//! `argus-intel`). Prints a table so you can eyeball detection quality.
//!
//! ```text
//! cargo run --release --example home_scan -p argus-discovery -- 10.3.0.0/24
//! ```
//! Defaults to `10.3.0.0/24`. This scans real hosts — only run it on a network
//! you are authorised to scan (e.g. your own).

use argus_discovery::{expand, scan, ScanOptions};
use argus_intel::{classify, Features};

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() > n {
        format!("{}…", s.chars().take(n - 1).collect::<String>())
    } else {
        s.to_owned()
    }
}

#[tokio::main]
async fn main() {
    let spec = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "10.3.0.0/24".to_owned());
    let targets = match expand(&spec) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("bad target spec {spec:?}: {e}");
            std::process::exit(1);
        }
    };

    // Diagnostics: the vendor path depends on a readable ARP cache + OUI db.
    let arp = argus_discovery::arp::read_arp_table();
    let oui = argus_discovery::oui::OuiDb::load();
    eprintln!(
        "[diag] arp entries: {}, oui db prefixes: {}",
        arp.len(),
        oui.len()
    );
    let (mut rand, mut with_vendor, mut universal_no_vendor) = (0, 0, 0);
    for mac in arp.values() {
        if mac.0[0] & 0x02 != 0 {
            rand += 1;
        } else if oui.vendor(*mac).is_some() {
            with_vendor += 1;
        } else {
            universal_no_vendor += 1;
        }
    }
    eprintln!(
        "[diag] of {} arp macs: {rand} randomized (privacy MAC, no OUI), {with_vendor} resolved to a vendor, {universal_no_vendor} real but not in the (possibly dated) OUI db",
        arp.len()
    );

    println!("scanning {spec} ({} hosts)…", targets.len());
    let report = scan(&targets, &ScanOptions::default()).await;
    println!(
        "{} live hosts in {} ms\n",
        report.live.len(),
        report.duration_ms
    );

    println!(
        "{:<15} {:<20} {:<18} {:>4}  open ports",
        "IP", "vendor", "device_type", "conf"
    );
    println!("{}", "-".repeat(90));

    let mut hosts = report.live;
    hosts.sort_by_key(|h| h.asset.interfaces.first().and_then(|i| i.ip));
    let mut typed = 0usize;
    for host in &hosts {
        let ip = host
            .asset
            .interfaces
            .first()
            .and_then(|i| i.ip)
            .map_or_else(|| "?".to_owned(), |i| i.to_string());
        let vendor = host.asset.fingerprint.vendor.clone().unwrap_or_default();
        let cls = classify(&Features {
            vendor: host.asset.fingerprint.vendor.clone(),
            open_ports: host.services.iter().map(|s| s.port).collect(),
            services: host
                .services
                .iter()
                .filter_map(|s| s.product.clone())
                .collect(),
            cpes: host.services.iter().filter_map(|s| s.cpe.clone()).collect(),
            os: host.asset.fingerprint.os.clone(),
        });
        if cls.device_type != "host" {
            typed += 1;
        }
        println!(
            "{:<15} {:<20} {:<18} {:>3}%  {:?}",
            ip,
            truncate(&vendor, 19),
            cls.device_type,
            cls.confidence,
            host.open_ports
        );
    }
    println!("\n{typed}/{} hosts got a specific device type", hosts.len());
}
