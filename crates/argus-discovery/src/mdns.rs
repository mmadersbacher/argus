//! mDNS / DNS-SD discovery (UDP 5353, hand-rolled, no DNS crate).
//!
//! Sends a one-shot multicast query (with the unicast-response bit, so devices
//! reply directly to our ephemeral port and we avoid fighting a local
//! `avahi-daemon` for port 5353) for the DNS-SD meta-service and a set of common
//! service types, then collects responses for a short window. From the replies
//! it extracts each responder's `.local` hostname (A record), advertised service
//! types (PTR/SRV) and a model string (TXT). This is how a Raspberry Pi running
//! avahi shows up as `raspberrypi.local` even on a bare network.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::{timeout, Instant};

const MDNS_V4: (Ipv4Addr, u16) = (Ipv4Addr::new(224, 0, 0, 251), 5353);

/// Service types we actively query for (the meta-query enumerates the rest).
const QUERY_NAMES: &[&str] = &[
    "_services._dns-sd._udp.local",
    "_workstation._tcp.local",
    "_ssh._tcp.local",
    "_sftp-ssh._tcp.local",
    "_http._tcp.local",
    "_https._tcp.local",
    "_ipp._tcp.local",
    "_ipps._tcp.local",
    "_printer._tcp.local",
    "_pdl-datastream._tcp.local",
    "_scanner._tcp.local",
    "_airplay._tcp.local",
    "_raop._tcp.local",
    "_googlecast._tcp.local",
    "_spotify-connect._tcp.local",
    "_smb._tcp.local",
    "_afpovertcp._tcp.local",
    "_device-info._tcp.local",
    "_homekit._tcp.local",
    "_hap._tcp.local",
    "_companion-link._tcp.local",
    "_amzn-wplay._tcp.local",
];

/// One responder discovered over mDNS.
#[derive(Debug, Clone)]
pub struct MdnsHost {
    /// The responding device's IP (the packet source).
    pub ip: IpAddr,
    /// `.local` hostname from an A record, if any.
    pub hostname: Option<String>,
    /// Model / friendly name from a TXT record, if any.
    pub model: Option<String>,
    /// Advertised service types, e.g. `_ssh._tcp`, `_ipp._tcp`.
    pub services: Vec<String>,
}

/// Send the query and collect responders for `window`.
pub async fn discover(window: Duration) -> Vec<MdnsHost> {
    let Ok(sock) = UdpSocket::bind(("0.0.0.0", 0)).await else {
        return Vec::new();
    };
    let _ = sock.set_multicast_ttl_v4(2);
    let query = build_query(QUERY_NAMES);
    if sock.send_to(&query, MDNS_V4).await.is_err() {
        return Vec::new();
    }

    let mut acc: BTreeMap<IpAddr, MdnsHost> = BTreeMap::new();
    let mut buf = vec![0u8; 8192];
    let deadline = Instant::now() + window;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match timeout(remaining, sock.recv_from(&mut buf)).await {
            Ok(Ok((n, src))) => parse_response(&buf[..n], src.ip(), &mut acc),
            _ => break,
        }
    }
    acc.into_values().collect()
}

fn build_query(names: &[&str]) -> Vec<u8> {
    let mut p = Vec::with_capacity(64);
    p.extend_from_slice(&[0x00, 0x00]); // transaction id
    p.extend_from_slice(&[0x00, 0x00]); // flags: standard query
    p.extend_from_slice(&u16::try_from(names.len()).unwrap_or(0).to_be_bytes()); // QDCOUNT
    p.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN, NS, AR = 0
    for name in names {
        encode_name(&mut p, name);
        p.extend_from_slice(&12u16.to_be_bytes()); // QTYPE = PTR
        p.extend_from_slice(&0x8001u16.to_be_bytes()); // QCLASS = IN + unicast-response bit
    }
    p
}

fn encode_name(p: &mut Vec<u8>, name: &str) {
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        if let Ok(len) = u8::try_from(label.len()) {
            p.push(len);
            p.extend_from_slice(label.as_bytes());
        }
    }
    p.push(0);
}

/// Read a (possibly compressed) DNS name starting at `pos`. Returns the dotted
/// name and the offset just past the name in the *record stream* (following the
/// first compression pointer, per DNS rules).
fn read_name(buf: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut next = start;
    let mut jumped = false;
    let mut guard = 0;
    loop {
        guard += 1;
        if guard > 128 {
            return None;
        }
        let len = *buf.get(pos)?;
        if len & 0xC0 == 0xC0 {
            let b2 = *buf.get(pos + 1)? as usize;
            if !jumped {
                next = pos + 2;
            }
            jumped = true;
            pos = (((len & 0x3F) as usize) << 8) | b2;
            continue;
        }
        if len == 0 {
            if !jumped {
                next = pos + 1;
            }
            break;
        }
        let s = pos + 1;
        let e = s + len as usize;
        labels.push(std::str::from_utf8(buf.get(s..e)?).ok()?.to_owned());
        pos = e;
    }
    Some((labels.join("."), next))
}

/// Whether a DNS name's last label is `local` (an mDNS `.local` name). Avoids a
/// raw `.ends_with(".local")`, which reads as a file-extension comparison.
fn is_dot_local(name: &str) -> bool {
    name.trim_end_matches('.')
        .rsplit('.')
        .next()
        .is_some_and(|last| last.eq_ignore_ascii_case("local"))
}

/// Extract a `_service._proto` type from a DNS-SD name, if present.
fn service_type(name: &str) -> Option<String> {
    let labels: Vec<&str> = name.trim_end_matches('.').split('.').collect();
    let i = labels.iter().position(|l| *l == "_tcp" || *l == "_udp")?;
    if i == 0 {
        return None;
    }
    Some(format!("{}.{}", labels[i - 1], labels[i]))
}

fn parse_txt(rdata: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < rdata.len() {
        let len = rdata[i] as usize;
        i += 1;
        let Some(kv) = rdata.get(i..i + len) else {
            break;
        };
        i += len;
        if let Ok(s) = std::str::from_utf8(kv) {
            if let Some((k, v)) = s.split_once('=') {
                out.push((k.to_lowercase(), v.to_owned()));
            }
        }
    }
    out
}

fn model_from_txt(key: &str, val: &str) -> Option<String> {
    if val.is_empty() {
        return None;
    }
    match key {
        "md" | "model" | "usb_mdl" | "product" | "ty" | "fn" => Some(val.to_owned()),
        _ => None,
    }
}

fn parse_response(buf: &[u8], src: IpAddr, acc: &mut BTreeMap<IpAddr, MdnsHost>) {
    if buf.len() < 12 {
        return;
    }
    let qd = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let counts = u16::from_be_bytes([buf[6], buf[7]]) as usize
        + u16::from_be_bytes([buf[8], buf[9]]) as usize
        + u16::from_be_bytes([buf[10], buf[11]]) as usize;

    let mut pos = 12;
    for _ in 0..qd {
        let Some((_, p)) = read_name(buf, pos) else {
            return;
        };
        pos = p + 4; // QTYPE + QCLASS
    }

    let entry = acc.entry(src).or_insert_with(|| MdnsHost {
        ip: src,
        hostname: None,
        model: None,
        services: Vec::new(),
    });

    for _ in 0..counts {
        let Some((name, p)) = read_name(buf, pos) else {
            break;
        };
        if p + 10 > buf.len() {
            break;
        }
        let rtype = u16::from_be_bytes([buf[p], buf[p + 1]]);
        let rdlen = u16::from_be_bytes([buf[p + 8], buf[p + 9]]) as usize;
        let rstart = p + 10;
        let Some(rdata) = buf.get(rstart..rstart + rdlen) else {
            break;
        };
        match rtype {
            1 => {
                // A record: the responder's hostname.
                if rdlen == 4 && entry.hostname.is_none() && is_dot_local(&name) {
                    entry.hostname = Some(name.trim_end_matches('.').to_owned());
                }
            }
            12 | 33 => {
                // PTR / SRV: service type lives in the record name and, for the
                // meta-query, in the PTR rdata (a name).
                for n in [Some(name.clone()), read_name(buf, rstart).map(|(n, _)| n)]
                    .into_iter()
                    .flatten()
                {
                    if let Some(st) = service_type(&n) {
                        if !entry.services.contains(&st) {
                            entry.services.push(st);
                        }
                    }
                }
            }
            16 => {
                for (k, v) in parse_txt(rdata) {
                    if entry.model.is_none() {
                        entry.model = model_from_txt(&k, &v);
                    }
                }
            }
            _ => {}
        }
        pos = rstart + rdlen;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_and_reads_a_name() {
        let mut p = Vec::new();
        encode_name(&mut p, "_ssh._tcp.local");
        let (name, next) = read_name(&p, 0).unwrap();
        assert_eq!(name, "_ssh._tcp.local");
        assert_eq!(next, p.len());
    }

    #[test]
    fn read_name_follows_compression_pointer() {
        // "local" at offset 0, then "raspberrypi" + pointer back to offset 0.
        let mut buf = Vec::new();
        buf.push(5);
        buf.extend_from_slice(b"local");
        buf.push(0); // offset 0..7 = "local."
        let name_start = buf.len();
        buf.push(11);
        buf.extend_from_slice(b"raspberrypi");
        buf.push(0xC0);
        buf.push(0x00); // pointer to offset 0
        let (name, next) = read_name(&buf, name_start).unwrap();
        assert_eq!(name, "raspberrypi.local");
        assert_eq!(next, buf.len());
    }

    #[test]
    fn service_type_extraction() {
        assert_eq!(
            service_type("Office._ipp._tcp.local"),
            Some("_ipp._tcp".to_owned())
        );
        assert_eq!(service_type("plainname"), None);
    }

    #[test]
    fn parses_an_a_record_response_to_hostname() {
        // Minimal mDNS response: 1 answer, A record raspberrypi.local -> 192.168.8.50.
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x00, 0x00]); // id
        buf.extend_from_slice(&[0x84, 0x00]); // flags: response + AA
        buf.extend_from_slice(&[0x00, 0x00]); // QDCOUNT 0
        buf.extend_from_slice(&[0x00, 0x01]); // ANCOUNT 1
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // NS, AR
        encode_name(&mut buf, "raspberrypi.local");
        buf.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
        buf.extend_from_slice(&0x8001u16.to_be_bytes()); // CLASS IN + flush
        buf.extend_from_slice(&120u32.to_be_bytes()); // TTL
        buf.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        buf.extend_from_slice(&[192, 168, 8, 50]); // RDATA

        let src: IpAddr = "192.168.8.50".parse().unwrap();
        let mut acc = BTreeMap::new();
        parse_response(&buf, src, &mut acc);
        let host = acc.get(&src).unwrap();
        assert_eq!(host.hostname.as_deref(), Some("raspberrypi.local"));
    }
}
