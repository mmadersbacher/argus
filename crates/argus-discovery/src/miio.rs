//! Xiaomi miIO discovery (UDP 54321) — the handshake that tells a Xiaomi
//! smart-home device apart from a Xiaomi phone.
//!
//! Every Mi Home / miIO device (smart plug, gateway, air purifier, robot vacuum,
//! sensor hub, …) answers an unauthenticated "Hello" on UDP 54321 with a 32-byte
//! header echoing its device id and an uptime stamp; phones and non-miIO gear
//! stay silent. No token is needed: the Hello response alone is positive proof of
//! a Xiaomi IoT device — something the OUI can never establish on its own, since
//! `Beijing Xiaomi Mobile Software` is shared across Xiaomi's entire catalogue,
//! phones included. The exact model still requires the per-device token, so this
//! confirms the device *class*, not the SKU.
//!
//! miIO has no multicast group, so discovery is a unicast fan-out: one Hello to
//! each in-scope IP from a single socket, then responses are collected for a
//! short window (the same shape as the multicast probes, just unicast sends).

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::{timeout, Instant};

const MIIO_PORT: u16 = 54321;

/// A confirmed miIO responder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MiioHost {
    /// The responding device's IP.
    pub ip: IpAddr,
    /// The device id echoed in the Hello response (stable per device).
    pub device_id: u32,
    /// The device's internal uptime stamp.
    pub stamp: u32,
}

/// The 32-byte miIO "Hello": magic `0x2131`, length `0x0020`, then all-`0xff`
/// device-id / stamp / checksum (the documented unauthenticated handshake).
fn build_hello() -> [u8; 32] {
    let mut p = [0xffu8; 32];
    p[0] = 0x21;
    p[1] = 0x31;
    p[2] = 0x00;
    p[3] = 0x20;
    p
}

/// Parse a miIO Hello response (magic `0x2131` + the full 32-byte header),
/// lifting the device id and stamp.
fn parse_hello(buf: &[u8], ip: IpAddr) -> Option<MiioHost> {
    if buf.len() < 32 || buf[0] != 0x21 || buf[1] != 0x31 {
        return None;
    }
    let device_id = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
    let stamp = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
    Some(MiioHost {
        ip,
        device_id,
        stamp,
    })
}

/// Send a Hello to every IPv4 target, then collect responders for `window`.
pub async fn discover(targets: &[IpAddr], window: Duration) -> Vec<MiioHost> {
    let Ok(sock) = UdpSocket::bind(("0.0.0.0", 0)).await else {
        return Vec::new();
    };
    let hello = build_hello();
    for ip in targets.iter().filter(|ip| ip.is_ipv4()) {
        let _ = sock.send_to(&hello, (*ip, MIIO_PORT)).await;
    }

    let mut acc: BTreeMap<IpAddr, MiioHost> = BTreeMap::new();
    let mut buf = [0u8; 1024];
    let deadline = Instant::now() + window;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match timeout(remaining, sock.recv_from(&mut buf)).await {
            Ok(Ok((n, src))) => {
                if let Some(h) = parse_hello(&buf[..n], src.ip()) {
                    acc.entry(src.ip()).or_insert(h);
                }
            }
            _ => break,
        }
    }
    acc.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn hello_header_is_correct() {
        let h = build_hello();
        assert_eq!(&h[..4], &[0x21, 0x31, 0x00, 0x20]);
        assert!(h[4..].iter().all(|&b| b == 0xff));
    }

    #[test]
    fn parses_a_real_hello_response() {
        // Captured live from 192.168.8.103: device_id=0x2cc9f8a8, stamp=0x3902b5.
        let raw = [
            0x21, 0x31, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x2c, 0xc9, 0xf8, 0xa8, 0x00, 0x39,
            0x02, 0xb5, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff,
        ];
        let r = parse_hello(&raw, ip("192.168.8.103")).unwrap();
        assert_eq!(r.device_id, 0x2cc9_f8a8);
        assert_eq!(r.stamp, 0x0039_02b5);
    }

    #[test]
    fn rejects_non_miio() {
        assert!(parse_hello(b"not a miio response at all really", ip("10.0.0.1")).is_none());
        // Right length, wrong magic.
        assert!(parse_hello(&[0u8; 32], ip("10.0.0.1")).is_none());
    }
}
