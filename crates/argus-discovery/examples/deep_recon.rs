//! deep_recon — squeeze every unicast signal out of each host on a locked-down
//! network (where mDNS/multicast is blocked): reverse-DNS hostname, HTTP server
//! header + page title, connect banners, and MAC-OUI vendor, then classify.
//!
//! ```text
//! cargo run --release --example deep_recon -p argus-discovery -- 10.3.0.0/24 10.3.0.1
//! ```
//! Args: subnet (default 10.3.0.0/24), DNS resolver (default 10.3.0.1).

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use argus_discovery::{expand, scan, ScanOptions};
use argus_intel::{classify, Features};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

const WEB_PORTS: &[u16] = &[80, 8080, 8000, 8443, 443, 5000];
const PATHS: &[&str] = &["/", "/rootDesc.xml", "/description.xml"];

// ---- reverse DNS (PTR) — a tiny unicast resolver, no extra crate ------------

fn ptr_query(ip: Ipv4Addr) -> Vec<u8> {
    let mut p = vec![0x13, 0x37, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]; // id, RD=1, qd=1
    let o = ip.octets();
    for label in [
        o[3].to_string(),
        o[2].to_string(),
        o[1].to_string(),
        o[0].to_string(),
    ] {
        p.push(u8::try_from(label.len()).unwrap_or(0));
        p.extend_from_slice(label.as_bytes());
    }
    for label in ["in-addr", "arpa"] {
        p.push(u8::try_from(label.len()).unwrap_or(0));
        p.extend_from_slice(label.as_bytes());
    }
    p.push(0);
    p.extend_from_slice(&[0, 12, 0, 1]); // qtype=PTR, qclass=IN
    p
}

/// Read a (possibly compressed) DNS name; returns (name, position after it).
fn read_name(buf: &[u8], start: usize) -> (String, usize) {
    let mut labels = Vec::new();
    let (mut pos, mut after, mut jumped) = (start, start, false);
    while pos < buf.len() {
        let len = buf[pos];
        if len & 0xc0 == 0xc0 {
            if pos + 1 >= buf.len() {
                break;
            }
            if !jumped {
                after = pos + 2;
            }
            pos = (usize::from(len & 0x3f) << 8) | usize::from(buf[pos + 1]);
            jumped = true;
        } else if len == 0 {
            if !jumped {
                after = pos + 1;
            }
            break;
        } else {
            pos += 1;
            let end = (pos + len as usize).min(buf.len());
            labels.push(String::from_utf8_lossy(&buf[pos..end]).into_owned());
            pos = end;
            if !jumped {
                after = pos;
            }
        }
    }
    (labels.join("."), after)
}

fn parse_ptr(buf: &[u8]) -> Option<String> {
    if buf.len() < 12 || u16::from_be_bytes([buf[6], buf[7]]) == 0 {
        return None; // no answers
    }
    let (_, mut pos) = read_name(buf, 12);
    pos += 4; // qtype + qclass
    let (_, p) = read_name(buf, pos);
    pos = p;
    if pos + 10 > buf.len() || u16::from_be_bytes([buf[pos], buf[pos + 1]]) != 12 {
        return None; // not a PTR answer
    }
    let (name, _) = read_name(buf, pos + 10);
    (!name.is_empty()).then_some(name)
}

async fn reverse_dns(resolver: Ipv4Addr, ip: Ipv4Addr) -> Option<String> {
    let sock = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    sock.send_to(&ptr_query(ip), (resolver, 53)).await.ok()?;
    let mut buf = [0u8; 1500];
    let (n, _) = timeout(Duration::from_millis(800), sock.recv_from(&mut buf))
        .await
        .ok()?
        .ok()?;
    parse_ptr(&buf[..n])
}

// ---- HTTP ------------------------------------------------------------------

fn header(resp: &str, name: &str) -> Option<String> {
    let needle = format!("{}:", name.to_ascii_lowercase());
    resp.lines()
        .take_while(|l| !l.trim().is_empty())
        .find(|l| l.to_ascii_lowercase().starts_with(&needle))
        .and_then(|l| l.split_once(':'))
        .map(|(_, v)| v.trim().to_owned())
}

fn html_title(body: &str) -> Option<String> {
    let lb = body.to_ascii_lowercase();
    let s = lb.find("<title")?;
    let gt = lb[s..].find('>')? + s + 1;
    let e = lb[gt..].find("</title>")? + gt;
    let t = body[gt..e].split_whitespace().collect::<Vec<_>>().join(" ");
    (!t.is_empty()).then(|| t.chars().take(60).collect())
}

async fn http_signals(ip: IpAddr, ports: &[u16]) -> Option<String> {
    for &port in ports {
        if !WEB_PORTS.contains(&port) {
            continue;
        }
        for path in PATHS {
            let Ok(Ok(mut s)) =
                timeout(Duration::from_millis(600), TcpStream::connect((ip, port))).await
            else {
                continue;
            };
            let req = format!("GET {path} HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: argus\r\nConnection: close\r\n\r\n");
            if timeout(Duration::from_secs(1), s.write_all(req.as_bytes()))
                .await
                .is_err()
            {
                continue;
            }
            let mut buf = Vec::new();
            let _ = timeout(Duration::from_secs(2), s.read_to_end(&mut buf)).await;
            if buf.is_empty() {
                continue;
            }
            let resp = String::from_utf8_lossy(&buf);
            let server = header(&resp, "server");
            let title = html_title(&resp);
            if server.is_some() || title.is_some() {
                let mut bits = Vec::new();
                if let Some(s) = server {
                    bits.push(format!(":{port} {s}"));
                }
                if let Some(t) = title {
                    bits.push(format!("\"{t}\""));
                }
                return Some(bits.join(" "));
            }
        }
    }
    None
}

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let spec = args.next().unwrap_or_else(|| "10.3.0.0/24".to_owned());
    let resolver: Ipv4Addr = args
        .next()
        .unwrap_or_else(|| "10.3.0.1".to_owned())
        .parse()
        .expect("resolver must be an IPv4 address");
    let targets = expand(&spec).unwrap_or_else(|e| {
        eprintln!("bad spec {spec:?}: {e}");
        std::process::exit(1);
    });

    let opts = ScanOptions {
        banner_timeout: Some(Duration::from_secs(1)),
        ..ScanOptions::default()
    };
    println!("deep recon of {spec} (resolver {resolver})…");
    let report = scan(&targets, &opts).await;
    println!("{} live hosts\n", report.live.len());

    let (mut named, mut httpd) = (0usize, 0usize);
    let mut rows = report.live;
    rows.sort_by_key(|h| h.asset.interfaces.first().and_then(|i| i.ip));
    for host in &rows {
        let Some(ip) = host.asset.interfaces.first().and_then(|i| i.ip) else {
            continue;
        };
        let vendor = host.asset.fingerprint.vendor.clone();
        let banners: Vec<String> = host
            .services
            .iter()
            .filter_map(|s| s.banner.clone())
            .collect();
        let hostname = match ip {
            IpAddr::V4(v4) => reverse_dns(resolver, v4).await,
            IpAddr::V6(_) => None,
        };
        let http = http_signals(ip, &host.open_ports).await;
        if hostname.is_some() {
            named += 1;
        }
        if http.is_some() {
            httpd += 1;
        }

        // Feed the gathered text into the classifier as extra service evidence.
        let mut services: Vec<String> = host
            .services
            .iter()
            .filter_map(|s| s.product.clone())
            .collect();
        services.extend(http.clone());
        services.extend(banners.iter().cloned());
        let cls = classify(&Features {
            vendor: vendor.clone(),
            open_ports: host.open_ports.clone(),
            services,
            cpes: Vec::new(),
            os: host.asset.fingerprint.os.clone(),
        });

        println!("{ip}  [{}]  conf {}%", cls.device_type, cls.confidence);
        if let Some(h) = &hostname {
            println!("    host:   {h}");
        }
        if let Some(v) = &vendor {
            println!("    vendor: {v}");
        }
        if let Some(h) = &http {
            println!("    http:   {h}");
        }
        for b in banners.iter().filter(|b| !b.trim().is_empty()).take(2) {
            println!(
                "    banner: {}",
                b.trim().chars().take(70).collect::<String>()
            );
        }
        println!("    ports:  {:?}", host.open_ports);
    }
    println!(
        "\n{} live | {named} named (reverse-DNS) | {httpd} http-identified",
        rows.len()
    );
}
