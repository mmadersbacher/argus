//! `argus-discovery [target]` — run a light scan and print the result.
//!
//! `target` is an IP or CIDR; it defaults to `127.0.0.1`. Connect-scan only,
//! no privileges required. Only scan networks you are authorized to test.

use std::process::ExitCode;

use argus_discovery::{expand, scan, ScanOptions};

#[tokio::main]
async fn main() -> ExitCode {
    let target = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1".to_owned());

    let hosts = match expand(&target) {
        Ok(hosts) => hosts,
        Err(err) => {
            eprintln!("argus-discovery: {err}");
            return ExitCode::FAILURE;
        }
    };

    eprintln!("scanning {} host(s) from '{target}' …", hosts.len());
    let report = scan(&hosts, &ScanOptions::default()).await;

    println!(
        "scanned {} host(s) in {} ms — {} live",
        report.hosts_scanned,
        report.duration_ms,
        report.live.len()
    );
    for host in &report.live {
        let ip = host
            .asset
            .interfaces
            .first()
            .and_then(|i| i.ip)
            .map_or_else(|| "?".to_owned(), |ip| ip.to_string());
        let dtype = host.asset.fingerprint.device_type.as_deref().unwrap_or("-");
        println!(
            "  {ip:<18} {dtype:<22} ports={:?} insecure~{:.0}",
            host.open_ports, host.insecure_score
        );
    }
    ExitCode::SUCCESS
}
