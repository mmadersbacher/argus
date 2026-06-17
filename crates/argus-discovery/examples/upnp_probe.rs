//! UPnP/HTTP probe — can we identify the "host [49152]" devices over unicast
//! HTTP, where MAC-OUI and (blocked) mDNS fail?
//!
//! Scans a subnet for common UPnP/HTTP ports, then GETs likely device-description
//! paths and pulls Server header + manufacturer/modelName/friendlyName out of the
//! UPnP XML. Unicast, so AP isolation does not block it.
//!
//! ```text
//! cargo run --release --example upnp_probe -p argus-discovery -- 10.3.0.0/24
//! ```

use std::time::Duration;

use argus_discovery::{expand, scan, ScanOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const PROBE_PORTS: &[u16] = &[49152, 80, 8000, 8080, 5000, 443];
const PATHS: &[&str] = &[
    "/",
    "/rootDesc.xml",
    "/description.xml",
    "/DeviceDescription.xml",
    "/upnp/desc.xml",
];

/// One unauthenticated HTTP GET; returns the raw response text (headers + body).
async fn http_get(ip: std::net::IpAddr, port: u16, path: &str) -> Option<String> {
    let connect = TcpStream::connect((ip, port));
    let mut stream = timeout(Duration::from_millis(700), connect)
        .await
        .ok()?
        .ok()?;
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: argus-probe\r\nConnection: close\r\n\r\n"
    );
    timeout(Duration::from_secs(1), stream.write_all(req.as_bytes()))
        .await
        .ok()?
        .ok()?;
    let mut buf = Vec::new();
    let _ = timeout(Duration::from_secs(2), stream.read_to_end(&mut buf)).await;
    if buf.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// Text between `<name>` and `</name>`, trimmed.
fn tag(body: &str, name: &str) -> Option<String> {
    let open = format!("<{name}>");
    let start = body.find(&open)? + open.len();
    let end = body[start..].find(&format!("</{name}>"))? + start;
    let val = body[start..end].trim();
    (!val.is_empty()).then(|| val.to_owned())
}

/// Value of an HTTP header (case-insensitive name).
fn header(resp: &str, name: &str) -> Option<String> {
    let needle = format!("{}:", name.to_ascii_lowercase());
    resp.lines()
        .take_while(|l| !l.trim().is_empty())
        .find(|l| l.to_ascii_lowercase().starts_with(&needle))
        .and_then(|l| l.split_once(':'))
        .map(|(_, v)| v.trim().to_owned())
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

    let opts = ScanOptions {
        ports: PROBE_PORTS.to_vec(),
        banner_timeout: None,
        ..ScanOptions::default()
    };
    println!("scanning {spec} for UPnP/HTTP ports…");
    let report = scan(&targets, &opts).await;
    println!("{} hosts with a probe port open\n", report.live.len());

    let mut identified = 0usize;
    for host in &report.live {
        let Some(ip) = host.asset.interfaces.first().and_then(|i| i.ip) else {
            continue;
        };
        let mut hit: Option<String> = None;
        'host: for &port in &host.open_ports {
            if !PROBE_PORTS.contains(&port) {
                continue;
            }
            for path in PATHS {
                if let Some(resp) = http_get(ip, port, path).await {
                    let server = header(&resp, "server");
                    let mfr = tag(&resp, "manufacturer");
                    let model = tag(&resp, "modelName");
                    let friendly = tag(&resp, "friendlyName");
                    if mfr.is_some() || model.is_some() || friendly.is_some() || server.is_some() {
                        let mut parts = vec![format!("{ip}:{port}")];
                        if let Some(s) = server {
                            parts.push(format!("server={s}"));
                        }
                        if let Some(m) = mfr {
                            parts.push(format!("mfr={m}"));
                        }
                        if let Some(m) = model {
                            parts.push(format!("model={m}"));
                        }
                        if let Some(f) = friendly {
                            parts.push(format!("name={f}"));
                        }
                        hit = Some(parts.join("  "));
                        break 'host;
                    }
                }
            }
        }
        if let Some(line) = hit {
            identified += 1;
            println!("{line}");
        }
    }
    println!(
        "\n{identified}/{} hosts revealed something over unicast HTTP",
        report.live.len()
    );
}
