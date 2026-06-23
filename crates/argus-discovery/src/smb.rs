//! SMB2 NEGOTIATE probe (TCP 445, hand-rolled, no SMB crate).
//!
//! Sends a single SMB2 NEGOTIATE request over the Direct-TCP transport and
//! reads the server's NEGOTIATE response. Two facts are extracted, both
//! unauthenticated and read-only (no session setup, no tree connect):
//!
//! * **`signing_required`** — the `SMB2_NEGOTIATE_SIGNING_REQUIRED` bit of the
//!   server's `SecurityMode`. When signing is *enabled but not required* the
//!   host is an NTLM-relay target — the single most common Active-Directory
//!   misconfiguration, and cleanly detectable without credentials.
//! * **`dialect`** — the negotiated SMB2/3 dialect revision.
//!
//! SMBv1-only servers do not answer SMB2 and yield `None` (SMBv1 presence is
//! detected separately). The request offers 2.0.2 / 2.1 / 3.0 / 3.0.2 — not
//! 3.1.1 — so no negotiate-context block is needed.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// `SMB2_NEGOTIATE_SIGNING_ENABLED`.
const SIGNING_ENABLED: u16 = 0x0001;
/// `SMB2_NEGOTIATE_SIGNING_REQUIRED`.
const SIGNING_REQUIRED: u16 = 0x0002;

/// What an SMB2 NEGOTIATE response told us about a server.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SmbInfo {
    /// Negotiated SMB2/3 dialect (e.g. `3.1.1`), if recognised.
    pub dialect: Option<String>,
    /// `true` when the server *requires* SMB signing (hardened).
    pub signing_required: bool,
    /// `true` when the server merely *offers* signing (relay-exposed if not
    /// also required).
    pub signing_enabled: bool,
}

/// Map an SMB2 `DialectRevision` to its human dotted form.
fn dialect_name(rev: u16) -> Option<&'static str> {
    match rev {
        0x0202 => Some("2.0.2"),
        0x0210 => Some("2.1"),
        0x0300 => Some("3.0"),
        0x0302 => Some("3.0.2"),
        0x0311 => Some("3.1.1"),
        _ => None,
    }
}

/// Build the 64-byte SMB2 sync header for a NEGOTIATE request.
fn smb2_header() -> Vec<u8> {
    let mut h = Vec::with_capacity(64);
    h.extend_from_slice(&[0xFE, b'S', b'M', b'B']); // ProtocolId
    h.extend_from_slice(&64u16.to_le_bytes()); // StructureSize
    h.extend_from_slice(&0u16.to_le_bytes()); // CreditCharge
    h.extend_from_slice(&0u32.to_le_bytes()); // Status / ChannelSequence
    h.extend_from_slice(&0u16.to_le_bytes()); // Command = NEGOTIATE (0)
    h.extend_from_slice(&0u16.to_le_bytes()); // CreditRequest
    h.extend_from_slice(&0u32.to_le_bytes()); // Flags
    h.extend_from_slice(&0u32.to_le_bytes()); // NextCommand
    h.extend_from_slice(&0u64.to_le_bytes()); // MessageId
    h.extend_from_slice(&0u32.to_le_bytes()); // Reserved (PID)
    h.extend_from_slice(&0u32.to_le_bytes()); // TreeId
    h.extend_from_slice(&0u64.to_le_bytes()); // SessionId
    h.extend_from_slice(&[0u8; 16]); // Signature
    h
}

/// Build the full Direct-TCP-framed SMB2 NEGOTIATE request.
#[must_use]
fn build_negotiate() -> Vec<u8> {
    let dialects: [u16; 4] = [0x0202, 0x0210, 0x0300, 0x0302];

    let mut body = Vec::new();
    body.extend_from_slice(&36u16.to_le_bytes()); // StructureSize (36)
    body.extend_from_slice(&4u16.to_le_bytes()); // DialectCount
    body.extend_from_slice(&SIGNING_ENABLED.to_le_bytes()); // client SecurityMode
    body.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    body.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
    body.extend_from_slice(&[0u8; 16]); // ClientGuid
    body.extend_from_slice(&0u64.to_le_bytes()); // ClientStartTime (no 3.1.1)
    for d in dialects {
        body.extend_from_slice(&d.to_le_bytes());
    }

    let mut smb = smb2_header();
    smb.extend_from_slice(&body);

    // Direct-TCP transport: 1 zero byte + 3-byte big-endian length.
    let len = u32::try_from(smb.len()).unwrap_or(u32::MAX);
    let lenb = len.to_be_bytes(); // [b0, b1, b2, b3]; b0 == 0 for our size
    let mut pkt = Vec::with_capacity(4 + smb.len());
    pkt.push(0x00);
    pkt.extend_from_slice(&lenb[1..4]);
    pkt.extend_from_slice(&smb);
    pkt
}

/// Parse an SMB2 NEGOTIATE response: extract dialect + signing flags.
///
/// Layout: 4-byte Direct-TCP header, 64-byte SMB2 header, then the NEGOTIATE
/// response body whose `SecurityMode` is at body offset 2 and `DialectRevision`
/// at offset 4.
#[must_use]
fn parse_negotiate_response(buf: &[u8]) -> Option<SmbInfo> {
    let smb = buf.get(4..)?; // skip Direct-TCP header
    if smb.get(0..4)? != [0xFE, b'S', b'M', b'B'] {
        return None;
    }
    let command = u16::from_le_bytes([*smb.get(12)?, *smb.get(13)?]);
    if command != 0 {
        return None; // not a NEGOTIATE response
    }
    let body = smb.get(64..)?;
    let security_mode = u16::from_le_bytes([*body.get(2)?, *body.get(3)?]);
    let dialect_rev = u16::from_le_bytes([*body.get(4)?, *body.get(5)?]);
    Some(SmbInfo {
        dialect: dialect_name(dialect_rev).map(ToOwned::to_owned),
        signing_required: (security_mode & SIGNING_REQUIRED) != 0,
        signing_enabled: (security_mode & SIGNING_ENABLED) != 0,
    })
}

/// Probe `ip:445` with an SMB2 NEGOTIATE. `None` if it does not speak SMB2.
pub async fn query(ip: IpAddr, wait: Duration) -> Option<SmbInfo> {
    let addr = SocketAddr::new(ip, 445);
    let mut stream = timeout(wait, TcpStream::connect(addr)).await.ok()?.ok()?;
    timeout(wait, stream.write_all(&build_negotiate()))
        .await
        .ok()?
        .ok()?;
    let mut buf = vec![0u8; 1024];
    let n = timeout(wait, stream.read(&mut buf)).await.ok()?.ok()?;
    drop(stream);
    parse_negotiate_response(buf.get(..n)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiate_request_is_well_formed() {
        let r = build_negotiate();
        // Direct-TCP header: zero byte + 3-byte length matching the SMB payload.
        assert_eq!(r[0], 0x00);
        let len = (usize::from(r[1]) << 16) | (usize::from(r[2]) << 8) | usize::from(r[3]);
        assert_eq!(len, r.len() - 4, "framed length matches payload");
        // SMB2 ProtocolId then Command=NEGOTIATE(0).
        assert_eq!(&r[4..8], &[0xFE, b'S', b'M', b'B']);
        assert_eq!(u16::from_le_bytes([r[16], r[17]]), 0, "command NEGOTIATE");
        // Dialect 0x0202 appears in the dialect array.
        assert!(
            r.windows(2).any(|w| w == 0x0202u16.to_le_bytes()),
            "offers dialect 2.0.2"
        );
    }

    /// Craft an SMB2 NEGOTIATE response with a given SecurityMode + dialect.
    fn response(security_mode: u16, dialect: u16) -> Vec<u8> {
        let mut smb = vec![0xFEu8, b'S', b'M', b'B'];
        smb.extend_from_slice(&[0u8; 60]); // rest of the 64-byte header (command=0)
        let mut body = vec![0u8; 64];
        body[0..2].copy_from_slice(&65u16.to_le_bytes()); // StructureSize
        body[2..4].copy_from_slice(&security_mode.to_le_bytes());
        body[4..6].copy_from_slice(&dialect.to_le_bytes());
        let mut smb_msg = smb;
        smb_msg.extend_from_slice(&body);
        let mut pkt = vec![0x00, 0x00, 0x00, 0x00]; // Direct-TCP header (len unused by parser)
        pkt.extend_from_slice(&smb_msg);
        pkt
    }

    #[test]
    fn parses_signing_required() {
        // SecurityMode = ENABLED | REQUIRED (0x0003), dialect 3.1.1.
        let info = parse_negotiate_response(&response(0x0003, 0x0311)).expect("parses");
        assert!(info.signing_required);
        assert!(info.signing_enabled);
        assert_eq!(info.dialect.as_deref(), Some("3.1.1"));
    }

    #[test]
    fn parses_signing_not_required() {
        // SecurityMode = ENABLED only (0x0001), dialect 3.0.2 — the finding.
        let info = parse_negotiate_response(&response(0x0001, 0x0302)).expect("parses");
        assert!(!info.signing_required);
        assert!(info.signing_enabled);
        assert_eq!(info.dialect.as_deref(), Some("3.0.2"));
    }

    #[test]
    fn rejects_non_smb2() {
        assert_eq!(parse_negotiate_response(b"HTTP/1.1 400\r\n\r\n"), None);
        assert_eq!(parse_negotiate_response(&[]), None);
        // Truncated (no body) must not panic.
        let mut short = vec![0x00, 0x00, 0x00, 0x00, 0xFE, b'S', b'M', b'B'];
        short.extend_from_slice(&[0u8; 8]);
        assert_eq!(parse_negotiate_response(&short), None);
    }
}
