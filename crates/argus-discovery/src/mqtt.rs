//! MQTT broker probe (ports 1883 / 8883).
//!
//! Port 1883 being open says "maybe an MQTT broker"; a real `CONNECT`/`CONNACK`
//! handshake proves it and reveals whether the broker is open or requires auth —
//! the difference between a smart-home hub anyone can subscribe to and a locked
//! one. The probe is a single MQTT 3.1.1 `CONNECT` with a clean session and no
//! credentials, then a read of the `CONNACK`; it never publishes or subscribes,
//! so it does not touch broker state.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// What a `CONNACK` told us about the broker.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MqttInfo {
    /// `CONNACK` return code (0 = accepted, 4 = bad credentials, 5 = not
    /// authorized, …).
    pub return_code: u8,
    /// Whether the broker accepted an anonymous connection (return code 0).
    pub anonymous_ok: bool,
}

/// The MQTT 3.1.1 `CONNECT` packet: clean session, client id `argus`, no creds.
fn connect_packet() -> Vec<u8> {
    let mut p = vec![
        0x10, 0x11, // CONNECT, remaining length 17
        0x00, 0x04, b'M', b'Q', b'T', b'T', // protocol name
        0x04, // protocol level (3.1.1)
        0x02, // connect flags: clean session
        0x00, 0x3c, // keep-alive 60s
        0x00, 0x05, // client-id length
    ];
    p.extend_from_slice(b"argus");
    p
}

/// Whether `resp` is a `CONNACK`, and what it carried.
fn parse_connack(resp: &[u8]) -> Option<MqttInfo> {
    // CONNACK: 0x20, remaining-length 0x02, ack-flags, return-code.
    if resp.len() < 4 || resp[0] != 0x20 {
        return None;
    }
    let return_code = resp[3];
    Some(MqttInfo {
        return_code,
        anonymous_ok: return_code == 0,
    })
}

/// Probe an MQTT broker: connect, send `CONNECT`, read the `CONNACK`.
///
/// Returns `None` if the connection fails or the reply is not a `CONNACK` (so a
/// non-MQTT service on 1883 is not misreported).
pub async fn query(ip: IpAddr, port: u16, wait: Duration) -> Option<MqttInfo> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = timeout(wait, TcpStream::connect(addr)).await.ok()?.ok()?;
    timeout(wait, stream.write_all(&connect_packet()))
        .await
        .ok()?
        .ok()?;
    let mut buf = [0u8; 16];
    let n = timeout(wait, stream.read(&mut buf)).await.ok()?.ok()?;
    drop(stream);
    parse_connack(&buf[..n])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_packet_is_well_formed() {
        let p = connect_packet();
        assert_eq!(p[0], 0x10, "CONNECT control byte");
        assert_eq!(&p[2..8], b"\x00\x04MQTT");
        assert_eq!(p[8], 0x04, "protocol level 3.1.1");
        assert!(p.ends_with(b"argus"));
        // remaining length byte equals the rest of the packet.
        assert_eq!(usize::from(p[1]), p.len() - 2);
    }

    #[test]
    fn accepts_open_broker_connack() {
        let info = parse_connack(&[0x20, 0x02, 0x00, 0x00]).expect("is a CONNACK");
        assert_eq!(info.return_code, 0);
        assert!(info.anonymous_ok);
    }

    #[test]
    fn auth_required_connack_is_still_a_broker() {
        let info = parse_connack(&[0x20, 0x02, 0x00, 0x05]).expect("is a CONNACK");
        assert_eq!(info.return_code, 5);
        assert!(!info.anonymous_ok);
    }

    #[test]
    fn non_connack_is_rejected() {
        assert_eq!(parse_connack(&[0x30, 0x02, 0x00, 0x00]), None); // PUBLISH, not CONNACK
        assert_eq!(parse_connack(&[0x20, 0x02]), None); // too short
        assert_eq!(parse_connack(b"HTTP/1.1"), None);
    }
}
