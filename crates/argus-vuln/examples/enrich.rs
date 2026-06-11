//! Manual smoke test for the live intelligence path: enrich one application
//! CPE end to end against the real NVD / CISA KEV / EPSS feeds.
//!
//! Usage: `cargo run -p argus-vuln --example enrich -- "cpe:/a:openbsd:openssh:8.9p1"`
//! (set `NVD_API_KEY` to skip the unauthenticated rate-limit pacing).

use argus_core::{Protocol, Service};
use argus_vuln::intel::IntelCache;

#[tokio::main]
async fn main() {
    let cpe = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "cpe:/a:openbsd:openssh:8.9p1".to_owned());
    println!("enriching {cpe} ...");
    let service = Service {
        port: 0,
        protocol: Protocol::Tcp,
        product: None,
        banner: None,
        cpe: Some(cpe),
    };
    let result = IntelCache::from_env()
        .enrich_checked(Vec::new(), &[service])
        .await;
    println!("live: {}", result.live);
    for v in &result.vulns {
        println!(
            "{:<16} {:>4} cvss={:<4} epss={:<6} kev={}",
            v.cve_id,
            format!("{:?}", v.severity),
            v.cvss
                .as_ref()
                .map_or_else(String::new, |c| c.base_score.to_string()),
            v.epss.map_or_else(String::new, |e| e.score.to_string()),
            v.kev,
        );
    }
    println!("{} CVEs", result.vulns.len());
}
