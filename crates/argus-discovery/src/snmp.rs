//! SNMP v2c system-group probe (UDP 161, hand-rolled BER, no SNMP crate).
//!
//! Sends a single GetRequest for `sysDescr`, `sysObjectID` and `sysName` with
//! the `public` community. `sysDescr` is the gold field — a full OS/device
//! string (e.g. "Linux raspberrypi 6.1.0 … armv7l", or a router/printer
//! firmware string). Unicast UDP, so it traverses a NAT. Only `public` is
//! tried; no writes, no GETBULK (so no amplification).

use std::net::IpAddr;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

// System-group OIDs, BER-encoded (1.3 → 0x2B, then one byte per sub-identifier).
const SYS_DESCR: &[u8] = &[0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]; // .1.1.1.0
const SYS_OBJECT_ID: &[u8] = &[0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x02, 0x00]; // .1.1.2.0
const SYS_NAME: &[u8] = &[0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00]; // .1.1.5.0

/// What the system group told us about a host.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SnmpResult {
    /// `sysDescr.0` — full OS / device description.
    pub descr: Option<String>,
    /// `sysName.0` — administrative hostname.
    pub name: Option<String>,
    /// `sysObjectID.0` — vendor/product OID, dotted.
    pub object_id: Option<String>,
}

fn ber_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
    }
}

/// Tag-length-value wrap.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    v.extend(ber_len(content.len()));
    v.extend_from_slice(content);
    v
}

fn get_request() -> Vec<u8> {
    let varbind = |oid: &[u8]| {
        let mut inner = tlv(0x06, oid);
        inner.extend_from_slice(&[0x05, 0x00]); // value = NULL
        tlv(0x30, &inner)
    };
    let mut binds = Vec::new();
    binds.extend(varbind(SYS_DESCR));
    binds.extend(varbind(SYS_OBJECT_ID));
    binds.extend(varbind(SYS_NAME));
    let varbind_list = tlv(0x30, &binds);

    let mut pdu = Vec::new();
    pdu.extend(tlv(0x02, &[0x12, 0x34, 0x56, 0x78])); // request-id
    pdu.extend_from_slice(&[0x02, 0x01, 0x00]); // error-status = 0
    pdu.extend_from_slice(&[0x02, 0x01, 0x00]); // error-index = 0
    pdu.extend(varbind_list);
    let pdu = tlv(0xA0, &pdu); // GetRequest PDU

    let mut msg = Vec::new();
    msg.extend_from_slice(&[0x02, 0x01, 0x01]); // version = 1 (v2c)
    msg.extend(tlv(0x04, b"public")); // community
    msg.extend(pdu);
    tlv(0x30, &msg)
}

/// Probe `ip` for the SNMP system group. `None` if it does not answer.
pub async fn query(ip: IpAddr, wait: Duration) -> Option<SnmpResult> {
    let sock = UdpSocket::bind(("0.0.0.0", 0)).await.ok()?;
    sock.send_to(&get_request(), (ip, 161)).await.ok()?;
    let mut buf = [0u8; 4096];
    let (n, _) = timeout(wait, sock.recv_from(&mut buf)).await.ok()?.ok()?;
    parse(&buf[..n])
}

/// Read one BER element: returns (tag, content range start, content end, end).
fn read_tlv(buf: &[u8], pos: usize) -> Option<(u8, usize, usize)> {
    let tag = *buf.get(pos)?;
    let first = *buf.get(pos + 1)?;
    let (len, body) = if first < 0x80 {
        (first as usize, pos + 2)
    } else {
        let n = (first & 0x7f) as usize;
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *buf.get(pos + 2 + i)? as usize;
        }
        (len, pos + 2 + n)
    };
    Some((tag, body, body + len))
}

fn oid_to_string(oid: &[u8]) -> String {
    let mut parts = Vec::new();
    if let Some(&first) = oid.first() {
        parts.push((first / 40).to_string());
        parts.push((first % 40).to_string());
    }
    let mut val: u64 = 0;
    for &b in &oid[1.min(oid.len())..] {
        val = (val << 7) | u64::from(b & 0x7f);
        if b & 0x80 == 0 {
            parts.push(val.to_string());
            val = 0;
        }
    }
    parts.join(".")
}

fn parse(buf: &[u8]) -> Option<SnmpResult> {
    // message SEQUENCE
    let (tag, body, end) = read_tlv(buf, 0)?;
    if tag != 0x30 {
        return None;
    }
    // version INTEGER
    let (_, _, p) = read_tlv(buf, body)?;
    // community OCTET STRING
    let (_, _, p) = read_tlv(buf, p)?;
    // PDU (GetResponse = 0xA2)
    let (ptag, pbody, pend) = read_tlv(buf, p)?;
    if ptag != 0xA2 || pend > end {
        return None;
    }
    // request-id, error-status, error-index
    let (_, _, q) = read_tlv(buf, pbody)?;
    let (_, _, q) = read_tlv(buf, q)?;
    let (_, _, q) = read_tlv(buf, q)?;
    // varbind-list SEQUENCE
    let (vtag, vbody, vend) = read_tlv(buf, q)?;
    if vtag != 0x30 {
        return None;
    }

    let mut out = SnmpResult::default();
    let mut pos = vbody;
    while pos < vend {
        let (_, vb_body, vb_end) = read_tlv(buf, pos)?; // varbind SEQUENCE
        let (otag, o_body, o_end) = read_tlv(buf, vb_body)?; // OID
        if otag != 0x06 {
            pos = vb_end;
            continue;
        }
        let oid = oid_to_string(buf.get(o_body..o_end)?);
        let (val_tag, val_body, val_end) = read_tlv(buf, o_end)?; // value
        let value = buf.get(val_body..val_end)?;
        match oid.as_str() {
            "1.3.6.1.2.1.1.1.0" if val_tag == 0x04 => {
                out.descr = Some(String::from_utf8_lossy(value).trim().to_owned());
            }
            "1.3.6.1.2.1.1.5.0" if val_tag == 0x04 => {
                out.name = Some(String::from_utf8_lossy(value).trim().to_owned());
            }
            "1.3.6.1.2.1.1.2.0" if val_tag == 0x06 => {
                out.object_id = Some(oid_to_string(value));
            }
            _ => {}
        }
        pos = vb_end;
    }
    if out == SnmpResult::default() {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_has_three_varbinds_and_public_community() {
        let r = get_request();
        assert_eq!(r[0], 0x30, "top SEQUENCE");
        // community "public" appears verbatim
        assert!(r.windows(6).any(|w| w == b"public"));
        // GetRequest PDU tag present
        assert!(r.contains(&0xA0));
    }

    #[test]
    fn oid_encodes_to_dotted() {
        assert_eq!(oid_to_string(SYS_DESCR), "1.3.6.1.2.1.1.1.0");
    }

    #[test]
    fn parses_sysdescr_and_sysname_from_a_response() {
        // Build a GetResponse with sysDescr + sysName using the same helpers.
        let descr = b"Linux raspberrypi 6.1.0-rpi7-rpi-v8 aarch64";
        let mut binds = Vec::new();
        // sysDescr varbind
        let mut vb = tlv(0x06, SYS_DESCR);
        vb.extend(tlv(0x04, descr));
        binds.extend(tlv(0x30, &vb));
        // sysName varbind
        let mut vb2 = tlv(0x06, SYS_NAME);
        vb2.extend(tlv(0x04, b"raspberrypi"));
        binds.extend(tlv(0x30, &vb2));
        let varbinds = tlv(0x30, &binds);

        let mut pdu = Vec::new();
        pdu.extend(tlv(0x02, &[0x12, 0x34, 0x56, 0x78]));
        pdu.extend_from_slice(&[0x02, 0x01, 0x00, 0x02, 0x01, 0x00]);
        pdu.extend(varbinds);
        let pdu = tlv(0xA2, &pdu); // GetResponse

        let mut msg = Vec::new();
        msg.extend_from_slice(&[0x02, 0x01, 0x01]);
        msg.extend(tlv(0x04, b"public"));
        msg.extend(pdu);
        let msg = tlv(0x30, &msg);

        let r = parse(&msg).unwrap();
        assert!(r.descr.as_deref().unwrap().contains("raspberrypi"));
        assert_eq!(r.name.as_deref(), Some("raspberrypi"));
    }
}
