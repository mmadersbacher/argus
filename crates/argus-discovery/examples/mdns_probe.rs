//! mDNS reachability probe — does multicast DNS even get through on this network?
//!
//! Sends the DNS-SD meta-query (`_services._dns-sd._udp.local`, PTR, unicast
//! response) to 224.0.0.251:5353 and listens ~5s. Prints how many devices
//! answered and which service types showed up. If nothing comes back the
//! network is blocking mDNS (AP/client isolation) — common on shared WiFi.
//!
//! ```text
//! cargo run --release --example mdns_probe -p argus-discovery -- 10.3.0.164
//! ```
//! Binds to the given local IP so the multicast leaves the right interface
//! (defaults to 10.3.0.164 — pass your WLAN IP if different).

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

/// Build the DNS-SD service-enumeration query packet.
fn meta_query() -> Vec<u8> {
    let mut p = vec![
        0, 0, // id (mDNS ignores it)
        0, 0, // flags: standard query
        0, 1, // qdcount = 1
        0, 0, 0, 0, 0, 0, // an/ns/ar = 0
    ];
    for label in ["_services", "_dns-sd", "_udp", "local"] {
        p.push(u8::try_from(label.len()).unwrap_or(0));
        p.extend_from_slice(label.as_bytes());
    }
    p.push(0); // root label
    p.extend_from_slice(&[0, 12]); // qtype = PTR
    p.extend_from_slice(&[0x80, 1]); // qclass = IN, QU bit (unicast response)
    p
}

/// Pull service types (`_foo._tcp` / `._udp`) out of a response, loosely — good
/// enough for a probe without a full DNS name parser.
fn extract_services(pkt: &[u8], out: &mut BTreeSet<String>) {
    let mut labels: Vec<String> = Vec::new();
    let mut cur = String::new();
    for &b in pkt {
        if b.is_ascii_alphanumeric() || b == b'_' || b == b'-' {
            cur.push(b as char);
        } else if cur.len() >= 2 {
            labels.push(std::mem::take(&mut cur));
        } else {
            cur.clear();
        }
    }
    if cur.len() >= 2 {
        labels.push(cur);
    }
    for w in labels.windows(2) {
        if w[0].starts_with('_') && (w[1] == "_tcp" || w[1] == "_udp") {
            out.insert(format!("{}.{}", w[0], w[1]));
        }
    }
}

fn main() {
    let local: Ipv4Addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "10.3.0.164".to_owned())
        .parse()
        .expect("local IP must be a valid IPv4 address");

    // Bind to the mDNS port with address reuse and join the multicast group on
    // the chosen interface, so we catch BOTH unicast (QU) and multicast answers.
    let group = Ipv4Addr::new(224, 0, 0, 251);
    let sock: UdpSocket = (|| {
        let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        s.set_reuse_address(true)?;
        s.bind(&SockAddr::from(SocketAddrV4::new(
            Ipv4Addr::UNSPECIFIED,
            5353,
        )))?;
        s.join_multicast_v4(&group, &local)?;
        s.set_multicast_if_v4(&local)?;
        s.set_multicast_loop_v4(false)?; // ignore our own outgoing queries
        s.set_read_timeout(Some(Duration::from_millis(250)))?;
        std::io::Result::Ok(s.into())
    })()
    .unwrap_or_else(|e: std::io::Error| {
        eprintln!("socket setup failed on {local}: {e}");
        std::process::exit(1);
    });
    let target = SocketAddrV4::new(group, 5353);
    let query = meta_query();

    println!("probing mDNS from {local} for 5s…\n");
    let mut responders: BTreeMap<String, usize> = BTreeMap::new();
    let mut services: BTreeSet<String> = BTreeSet::new();
    let mut buf = [0u8; 8192];
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut next_send = Instant::now();
    while Instant::now() < deadline {
        if Instant::now() >= next_send {
            let _ = sock.send_to(&query, target);
            next_send = Instant::now() + Duration::from_secs(1);
        }
        if let Ok((n, src)) = sock.recv_from(&mut buf) {
            *responders.entry(src.ip().to_string()).or_default() += 1;
            extract_services(&buf[..n], &mut services);
        }
    }

    println!("{} device(s) answered mDNS:", responders.len());
    for (ip, count) in &responders {
        println!("  {ip}  ({count} packets)");
    }
    println!("\n{} service type(s) seen:", services.len());
    for s in &services {
        println!("  {s}");
    }
    if responders.is_empty() {
        println!("\nNo mDNS responses — this network is blocking multicast (AP isolation).");
        println!("mDNS-based detection would not help here.");
    }
}
