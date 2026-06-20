//! NetBIOS Name Service node-status probe (UDP 137, hand-rolled).
//!
//! Sends an NBSTAT request for the wildcard name `*` and parses the node-status
//! response: the machine name, the workgroup/domain, and the adapter MAC (the
//! MAC rides in the application payload, so it survives a NAT the way ARP does
//! not — letting us OUI-resolve a vendor for NetBIOS speakers across subnets).
//! Answered by Windows hosts and Linux Samba (`nmbd`).

use std::net::IpAddr;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

/// What a node-status response told us about a host.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetbiosResult {
    /// Unique workstation/computer name (suffix `<00>`).
    pub name: Option<String>,
    /// Workgroup / domain (group name, suffix `<00>`).
    pub workgroup: Option<String>,
    /// Adapter MAC from the statistics block, if non-zero.
    pub mac: Option<[u8; 6]>,
}

/// Build the NBSTAT request: header + the wildcard name `*` (first-level
/// encoded to `CKAAAA…AA`) + QTYPE=NBSTAT(0x21) + QCLASS=IN(0x01).
fn nbstat_request() -> Vec<u8> {
    let mut p = vec![
        0x13, 0x37, // transaction id
        0x00, 0x00, // flags: query
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // AN/NS/AR = 0
        0x20, // name length = 32
    ];
    p.extend_from_slice(b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); // encoded "*"
    p.push(0x00); // name terminator
    p.extend_from_slice(&[0x00, 0x21]); // QTYPE = NBSTAT
    p.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN
    p
}

/// Probe `ip` for its NetBIOS node status. `None` if it does not answer.
pub async fn query(ip: IpAddr, wait: Duration) -> Option<NetbiosResult> {
    let sock = UdpSocket::bind(("0.0.0.0", 0)).await.ok()?;
    sock.send_to(&nbstat_request(), (ip, 137)).await.ok()?;
    let mut buf = [0u8; 1024];
    let (n, _) = timeout(wait, sock.recv_from(&mut buf)).await.ok()?.ok()?;
    parse(&buf[..n])
}

fn parse(buf: &[u8]) -> Option<NetbiosResult> {
    if buf.len() < 12 || u16::from_be_bytes([buf[6], buf[7]]) == 0 {
        return None; // no answer records
    }
    // Answer name: a single label (len byte + bytes) then a 0 terminator.
    let mut pos = 12;
    let len = *buf.get(pos)? as usize;
    pos += 1 + len;
    if buf.get(pos) == Some(&0) {
        pos += 1;
    }
    // TYPE(2) CLASS(2) TTL(4) RDLENGTH(2)
    pos += 8;
    let rdlen = u16::from_be_bytes([*buf.get(pos)?, *buf.get(pos + 1)?]) as usize;
    pos += 2;
    let rdata = buf.get(pos..pos + rdlen)?;

    let num = *rdata.first()? as usize;
    let mut i = 1;
    let mut result = NetbiosResult::default();
    for _ in 0..num {
        let entry = rdata.get(i..i + 18)?;
        let raw = &entry[0..15];
        let suffix = entry[15];
        let is_group = u16::from_be_bytes([entry[16], entry[17]]) & 0x8000 != 0;
        let nm = String::from_utf8_lossy(raw).trim().to_owned();
        if suffix == 0x00 && !nm.is_empty() {
            if is_group {
                result.workgroup.get_or_insert(nm);
            } else {
                result.name.get_or_insert(nm);
            }
        }
        i += 18;
    }
    // Statistics block begins right after the names; first 6 bytes = unit ID MAC.
    if let Some(mac) = rdata.get(i..i + 6) {
        let m = [mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]];
        if m != [0u8; 6] {
            result.mac = Some(m);
        }
    }
    if result.name.is_none() && result.mac.is_none() {
        return None;
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_is_well_formed() {
        let r = nbstat_request();
        assert_eq!(r[5], 0x01, "QDCOUNT = 1");
        assert_eq!(r[12], 0x20, "name length 32");
        assert_eq!(&r[r.len() - 4..], &[0x00, 0x21, 0x00, 0x01], "NBSTAT/IN");
    }

    #[test]
    fn parses_name_workgroup_and_mac() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x13, 0x37]); // id
        buf.extend_from_slice(&[0x84, 0x00]); // flags: response
        buf.extend_from_slice(&[0x00, 0x00]); // QDCOUNT 0
        buf.extend_from_slice(&[0x00, 0x01]); // ANCOUNT 1
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // NS/AR
        buf.push(0x20); // answer name length
        buf.extend_from_slice(b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        buf.push(0x00); // terminator
        buf.extend_from_slice(&[0x00, 0x21]); // TYPE NBSTAT
        buf.extend_from_slice(&[0x00, 0x01]); // CLASS IN
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // TTL
                                                          // RDATA: 2 names + MAC
        let mut rdata = Vec::new();
        rdata.push(0x02); // number of names
        let mut name = b"MYPC".to_vec();
        name.resize(15, b' ');
        rdata.extend_from_slice(&name);
        rdata.push(0x00); // suffix <00> workstation
        rdata.extend_from_slice(&[0x04, 0x00]); // flags: unique
        let mut wg = b"WORKGROUP".to_vec();
        wg.resize(15, b' ');
        rdata.extend_from_slice(&wg);
        rdata.push(0x00); // suffix <00>
        rdata.extend_from_slice(&[0x84, 0x00]); // flags: group bit set
        rdata.extend_from_slice(&[0xB8, 0x27, 0xEB, 0x11, 0x22, 0x33]); // MAC (Pi OUI)
        buf.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
        buf.extend_from_slice(&rdata);

        let r = parse(&buf).unwrap();
        assert_eq!(r.name.as_deref(), Some("MYPC"));
        assert_eq!(r.workgroup.as_deref(), Some("WORKGROUP"));
        assert_eq!(r.mac, Some([0xB8, 0x27, 0xEB, 0x11, 0x22, 0x33]));
    }
}
