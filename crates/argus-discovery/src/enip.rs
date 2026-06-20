//! EtherNet/IP List Identity probe (UDP 44818) — industrial device identity.
//!
//! Sends the encapsulation `ListIdentity` (0x0063) command; any EtherNet/IP
//! device — Rockwell/Allen-Bradley PLCs, drives, I/O blocks, many industrial and
//! building gateways — replies with a CIP Identity object: vendor id, device
//! type, product code, revision, serial number and a product-name string (e.g.
//! "1769-L36ERM/A LOGIX5336ERM"). This is the standard, **read-only** way to
//! identify an OT asset: a single discovery datagram that never touches the
//! device's control logic, so it is safe for fragile equipment.

use std::net::IpAddr;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

/// The CIP Identity object an EtherNet/IP device returns.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnipIdentity {
    /// CIP vendor id (1 = Rockwell, …).
    pub vendor_id: u16,
    /// CIP device type (0x0C = communications adapter, 0x0E = PLC, …).
    pub device_type: u16,
    /// Vendor-specific product code.
    pub product_code: u16,
    /// Device serial number.
    pub serial: u32,
    /// `major.minor` firmware revision.
    pub revision: Option<String>,
    /// Human-readable product name.
    pub product_name: Option<String>,
}

/// The 24-byte `ListIdentity` encapsulation request (command 0x0063, length 0).
fn list_identity_request() -> [u8; 24] {
    let mut p = [0u8; 24];
    p[0] = 0x63; // command 0x0063, little-endian
    p[1] = 0x00;
    p
}

/// Probe `ip` for its EtherNet/IP identity. `None` if it does not answer.
pub async fn query(ip: IpAddr, wait: Duration) -> Option<EnipIdentity> {
    let sock = UdpSocket::bind(("0.0.0.0", 0)).await.ok()?;
    sock.send_to(&list_identity_request(), (ip, 44818))
        .await
        .ok()?;
    let mut buf = [0u8; 1024];
    let (n, _) = timeout(wait, sock.recv_from(&mut buf)).await.ok()?.ok()?;
    parse(&buf[..n])
}

/// Parse a `ListIdentity` reply: 24-byte encapsulation header (command echoed as
/// 0x0063), then item-count, then the CIP Identity item (type 0x000C).
fn parse(resp: &[u8]) -> Option<EnipIdentity> {
    // Echoed command must be ListIdentity.
    if resp.len() < 24 || resp.first() != Some(&0x63) || resp.get(1) != Some(&0x00) {
        return None;
    }
    let mut pos = 24;
    let item_count = read_u16_le(resp, &mut pos)?;
    if item_count == 0 {
        return None;
    }
    let _item_type = read_u16_le(resp, &mut pos)?; // 0x000C CIP Identity
    let _item_len = read_u16_le(resp, &mut pos)?;
    let _encap_ver = read_u16_le(resp, &mut pos)?;
    pos = pos.checked_add(16)?; // socket address (sin_family/port/addr/zero)

    let vendor_id = read_u16_le(resp, &mut pos)?;
    let device_type = read_u16_le(resp, &mut pos)?;
    let product_code = read_u16_le(resp, &mut pos)?;
    let rev_major = *resp.get(pos)?;
    let rev_minor = *resp.get(pos + 1)?;
    pos += 2;
    let _status = read_u16_le(resp, &mut pos)?;
    let serial = read_u32_le(resp, &mut pos)?;
    let name_len = usize::from(*resp.get(pos)?);
    pos += 1;
    let product_name = resp
        .get(pos..pos.checked_add(name_len)?)
        .map(|b| String::from_utf8_lossy(b).trim().to_owned())
        .filter(|s| !s.is_empty());

    Some(EnipIdentity {
        vendor_id,
        device_type,
        product_code,
        serial,
        revision: Some(format!("{rev_major}.{rev_minor}")),
        product_name,
    })
}

/// Read a little-endian `u16` at `*pos`, advancing it.
fn read_u16_le(buf: &[u8], pos: &mut usize) -> Option<u16> {
    let v = u16::from_le_bytes([*buf.get(*pos)?, *buf.get(*pos + 1)?]);
    *pos += 2;
    Some(v)
}

/// Read a little-endian `u32` at `*pos`, advancing it.
fn read_u32_le(buf: &[u8], pos: &mut usize) -> Option<u32> {
    let v = u32::from_le_bytes([
        *buf.get(*pos)?,
        *buf.get(*pos + 1)?,
        *buf.get(*pos + 2)?,
        *buf.get(*pos + 3)?,
    ]);
    *pos += 4;
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_is_list_identity() {
        let r = list_identity_request();
        assert_eq!(r[0], 0x63, "command 0x0063 low byte");
        assert_eq!(r[1], 0x00);
        assert_eq!(r.len(), 24);
    }

    #[test]
    fn parses_a_rockwell_identity() {
        // 24-byte header with command 0x0063 echoed.
        let mut resp = vec![0u8; 24];
        resp[0] = 0x63;
        resp.extend_from_slice(&1u16.to_le_bytes()); // item count
        resp.extend_from_slice(&0x000Cu16.to_le_bytes()); // item type: CIP Identity
        resp.extend_from_slice(&0u16.to_le_bytes()); // item length (ignored)
        resp.extend_from_slice(&1u16.to_le_bytes()); // encap protocol version
        resp.extend_from_slice(&[0u8; 16]); // socket address
        resp.extend_from_slice(&1u16.to_le_bytes()); // vendor id = 1 (Rockwell)
        resp.extend_from_slice(&14u16.to_le_bytes()); // device type = 0x0E PLC
        resp.extend_from_slice(&54u16.to_le_bytes()); // product code
        resp.extend_from_slice(&[20, 11]); // revision 20.11
        resp.extend_from_slice(&0u16.to_le_bytes()); // status
        resp.extend_from_slice(&0x1234_5678u32.to_le_bytes()); // serial
        let name = b"1769-L36ERM/A LOGIX5336ERM";
        resp.push(u8::try_from(name.len()).unwrap());
        resp.extend_from_slice(name);
        resp.push(0x03); // state

        let id = parse(&resp).expect("parses");
        assert_eq!(id.vendor_id, 1);
        assert_eq!(id.device_type, 14);
        assert_eq!(id.product_code, 54);
        assert_eq!(id.serial, 0x1234_5678);
        assert_eq!(id.revision.as_deref(), Some("20.11"));
        assert_eq!(
            id.product_name.as_deref(),
            Some("1769-L36ERM/A LOGIX5336ERM")
        );
    }

    #[test]
    fn rejects_non_enip() {
        assert!(parse(&[0u8; 24]).is_none()); // wrong command
        assert!(parse(b"short").is_none());
    }
}
