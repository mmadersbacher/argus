//! CoAP resource discovery (UDP 5683, hand-rolled, no CoAP crate).
//!
//! Sends a single CoAP GET for `/.well-known/core` (RFC 6690 CoRE Link Format)
//! to the "All CoAP Nodes" IPv4 multicast group `224.0.1.187:5683`, then
//! collects responses for a short window. Constrained IoT devices (sensors,
//! actuators, smart-home gear running the CoAP stack) answer with their
//! resource list, e.g. `</sensors/temp>;rt="temperature";if="sensor"`. From
//! each reply it extracts the responder's IP and the advertised resource paths.
//!
//! The message is built by hand per RFC 7252 §3 (4-byte header + Uri-Path
//! options); responses are parsed by walking the option list to the `0xFF`
//! payload marker and reading the link-format text after it.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::{timeout, Instant};

/// "All CoAP Nodes" IPv4 multicast group, default CoAP port (RFC 7252 §12.8).
const COAP_V4: (Ipv4Addr, u16) = (Ipv4Addr::new(224, 0, 1, 187), 5683);

/// Fixed Message ID — random/time APIs are deliberately not used here.
const MESSAGE_ID: u16 = 0x4242;

/// CoAP message type: Non-confirmable (no ACK expected for a multicast probe).
const TYPE_NON: u8 = 1;

/// CoAP method code GET = 0.01, encoded as `class<<5 | detail` = `0<<5 | 1`.
const CODE_GET: u8 = 0x01;

/// Option number for Uri-Path (RFC 7252 §5.10).
const OPT_URI_PATH: u16 = 11;

/// Payload marker byte (RFC 7252 §3): separates options from payload.
const PAYLOAD_MARKER: u8 = 0xFF;

/// One CoAP responder discovered on the link.
#[derive(Debug, Clone)]
pub struct CoapHost {
    /// The responding device's IP (the packet source).
    pub ip: IpAddr,
    /// Resource paths from the CoRE link payload, e.g. `/sensors/temp`.
    pub resources: Vec<String>,
}

/// Send the multicast GET and collect responders for `window`.
pub async fn discover(window: Duration) -> Vec<CoapHost> {
    let Ok(sock) = UdpSocket::bind(("0.0.0.0", 0)).await else {
        return Vec::new();
    };
    let _ = sock.set_multicast_ttl_v4(2);
    let request = build_get_wellknown_core(MESSAGE_ID);
    if sock.send_to(&request, COAP_V4).await.is_err() {
        return Vec::new();
    }

    let mut acc: BTreeMap<IpAddr, CoapHost> = BTreeMap::new();
    let mut buf = vec![0u8; 8192];
    let deadline = Instant::now() + window;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match timeout(remaining, sock.recv_from(&mut buf)).await {
            Ok(Ok((n, src))) => {
                let ip = src.ip();
                // Deduplicate by source IP: keep the first non-empty answer.
                if acc.contains_key(&ip) {
                    continue;
                }
                if let Some(payload) = extract_payload(&buf[..n]) {
                    if let Ok(text) = std::str::from_utf8(payload) {
                        let resources = parse_core_links(text);
                        if !resources.is_empty() {
                            acc.insert(ip, CoapHost { ip, resources });
                        }
                    }
                }
            }
            _ => break,
        }
    }
    acc.into_values().collect()
}

/// Build a Non-confirmable CoAP GET for `/.well-known/core` (RFC 7252 §3).
///
/// Layout: 4-byte header (`Ver|Type|TKL` byte, `Code` byte, 16-bit Message ID),
/// no token (TKL=0), then two Uri-Path options (`.well-known`, `core`).
fn build_get_wellknown_core(message_id: u16) -> Vec<u8> {
    let mut p = Vec::with_capacity(24);

    // Byte 0: Ver(2 bits)=01 | Type(2 bits) | TKL(4 bits)=0.
    let ver_type_tkl = (0b01 << 6) | ((TYPE_NON & 0x03) << 4);
    p.push(ver_type_tkl);
    // Byte 1: Code = 0.01 (GET).
    p.push(CODE_GET);
    // Bytes 2-3: Message ID (big-endian).
    p.extend_from_slice(&message_id.to_be_bytes());
    // No token (TKL = 0).

    // Two Uri-Path options. Both share option number 11, so the running delta
    // from the previous option (starting at 0) is 11 for the first and 0 for
    // the second.
    push_option(&mut p, OPT_URI_PATH, 0, b".well-known");
    push_option(&mut p, OPT_URI_PATH, OPT_URI_PATH, b"core");

    p
}

/// Append a single CoAP option (RFC 7252 §3.1).
///
/// `opt_num` is the option's number, `prev_num` the number of the previously
/// emitted option (0 if first). The header nibble is `(delta<<4)|len`, with the
/// `13`/`14` extended escapes when either value is >= 13.
fn push_option(p: &mut Vec<u8>, opt_num: u16, prev_num: u16, value: &[u8]) {
    let delta = opt_num.saturating_sub(prev_num);
    let len = u16::try_from(value.len()).unwrap_or(u16::MAX);

    let (delta_nibble, delta_ext) = nibble_and_ext(delta);
    let (len_nibble, len_ext) = nibble_and_ext(len);

    p.push((delta_nibble << 4) | len_nibble);
    p.extend_from_slice(&delta_ext);
    p.extend_from_slice(&len_ext);
    p.extend_from_slice(value);
}

/// Encode an option delta/length into its 4-bit nibble plus extended bytes.
///
/// 0..=12 → nibble is the value, no extension.
/// 13..=268 → nibble 13, one extension byte of `value - 13`.
/// 269.. → nibble 14, two extension bytes of `value - 269` (big-endian).
fn nibble_and_ext(value: u16) -> (u8, Vec<u8>) {
    if value < 13 {
        (u8::try_from(value).unwrap_or(0), Vec::new())
    } else if value < 269 {
        (13, vec![u8::try_from(value - 13).unwrap_or(0)])
    } else {
        (14, (value - 269).to_be_bytes().to_vec())
    }
}

/// Walk the CoAP header, token and option list to return the payload slice
/// (the bytes after the `0xFF` payload marker), or `None` if there is no
/// payload or the datagram is malformed.
fn extract_payload(datagram: &[u8]) -> Option<&[u8]> {
    // Fixed 4-byte header.
    let first = *datagram.first()?;
    let version = first >> 6;
    if version != 1 {
        return None;
    }
    let tkl = (first & 0x0F) as usize;
    // header(4) + token(tkl)
    let mut pos = 4 + tkl;
    if pos > datagram.len() {
        return None;
    }

    // Walk options. Each option starts with a nibble byte `(delta<<4)|len`.
    loop {
        // No more bytes after the options means there was no payload marker.
        let byte = *datagram.get(pos)?;
        if byte == PAYLOAD_MARKER {
            // Everything after the marker is the payload.
            return datagram.get(pos + 1..);
        }
        pos += 1;

        let delta_nibble = byte >> 4;
        let len_nibble = byte & 0x0F;

        // Resolve the option-length value (delta is not needed past this point,
        // but its extension bytes still consume datagram space and must be
        // skipped first, in field order: delta-ext then length-ext).
        let _delta = read_ext(datagram, &mut pos, delta_nibble)?;
        let length = read_ext(datagram, &mut pos, len_nibble)?;

        // Skip the option value.
        pos = pos.checked_add(length)?;
        if pos > datagram.len() {
            return None;
        }
    }
}

/// Resolve a delta/length nibble to its full value, consuming extension bytes.
///
/// Handles the basic case (0..=12), the `13` single-byte extension and the
/// `14` two-byte extension. `15` (reserved) is rejected.
fn read_ext(datagram: &[u8], pos: &mut usize, nibble: u8) -> Option<usize> {
    match nibble {
        0..=12 => Some(nibble as usize),
        13 => {
            let ext = *datagram.get(*pos)?;
            *pos += 1;
            Some(ext as usize + 13)
        }
        14 => {
            let hi = *datagram.get(*pos)?;
            let lo = *datagram.get(*pos + 1)?;
            *pos += 2;
            Some(((u16::from(hi) << 8) | u16::from(lo)) as usize + 269)
        }
        _ => None, // 15 is reserved / payload marker, invalid as an option nibble
    }
}

/// Extract the `<...>` URI-Reference targets from a CoRE Link Format payload
/// (RFC 6690). Each link starts with an angle-bracketed target; the rest of
/// the link (`;rt="..."` etc.) is ignored.
fn parse_core_links(payload: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = payload.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'<' {
            // Find the closing '>'.
            if let Some(rel) = payload[i + 1..].find('>') {
                let target = &payload[i + 1..i + 1 + rel];
                let target = target.trim();
                if !target.is_empty() && !out.contains(&target.to_owned()) {
                    out.push(target.to_owned());
                }
                i = i + 1 + rel + 1;
                continue;
            }
            break; // unterminated '<' — stop.
        }
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_request_has_valid_header_and_uri_path_options() {
        let r = build_get_wellknown_core(0x4242);

        // Header byte: version bits (7-6) must be 01.
        assert_eq!(r[0] >> 6, 0b01, "CoAP version must be 1");
        // TKL (low nibble) must be 0.
        assert_eq!(r[0] & 0x0F, 0, "token length must be 0");
        // Code byte = GET (0.01).
        assert_eq!(r[1], CODE_GET, "code must be GET (0.01)");
        // Message ID bytes echo what we passed in.
        assert_eq!(&r[2..4], &[0x42, 0x42], "message id must be 0x4242");

        // The Uri-Path option values appear verbatim in the option section.
        assert!(
            r.windows(b".well-known".len()).any(|w| w == b".well-known"),
            "must contain the .well-known Uri-Path option value"
        );
        assert!(
            r.windows(b"core".len()).any(|w| w == b"core"),
            "must contain the core Uri-Path option value"
        );

        // First option header: delta=11, len=11 (".well-known" is 11 bytes) →
        // byte (11<<4)|11 = 0xBB, immediately after the 4-byte header.
        assert_eq!(r[4], 0xBB, "first Uri-Path option header nibble");
        // Second option header: delta=0, len=4 ("core") → (0<<4)|4 = 0x04,
        // right after the 11-byte first option value.
        assert_eq!(r[4 + 1 + 11], 0x04, "second Uri-Path option header nibble");
    }

    #[test]
    fn parse_core_links_extracts_multiple_targets() {
        let payload = r#"</sensors/temp>;rt="temperature";if="sensor",</sensors/light>;rt="light-lux";if="sensor",</large>;sz=1280,</.well-known/core>"#;
        let links = parse_core_links(payload);
        assert_eq!(
            links,
            vec![
                "/sensors/temp".to_owned(),
                "/sensors/light".to_owned(),
                "/large".to_owned(),
                "/.well-known/core".to_owned(),
            ]
        );
    }

    #[test]
    fn parse_core_links_ignores_garbage_and_dedups() {
        let payload = "</a>,</a>,no-brackets-here,</b>";
        let links = parse_core_links(payload);
        assert_eq!(links, vec!["/a".to_owned(), "/b".to_owned()]);
    }

    #[test]
    fn extract_payload_finds_text_after_marker() {
        // Build a synthetic response: header + token + two options + 0xFF + body.
        let mut dg = Vec::new();
        // Header: ver=1, type=ACK(2), TKL=2.
        dg.push((0b01 << 6) | (2 << 4) | 0x02);
        dg.push(0x45); // Code 2.05 Content (class 2, detail 5) — value irrelevant here.
        dg.extend_from_slice(&0x4242u16.to_be_bytes()); // message id
        dg.extend_from_slice(&[0xAA, 0xBB]); // 2-byte token

        // Option 1: Content-Format (12), delta=12, len=1 → (12<<4)|1 = 0xC1.
        dg.push(0xC1);
        dg.push(40); // value: application/link-format
                     // Option 2: a long option to exercise the 13-extended length form.
                     // delta=2 (→ option 14), len=13 → nibble 13 + ext byte (13-13=0).
        dg.push((2 << 4) | 0x0D);
        dg.push(0); // length extension: 0 → total length 13
        dg.extend_from_slice(&[0x5A; 13]); // 13-byte value

        // Payload marker + CoRE link body.
        dg.push(PAYLOAD_MARKER);
        let body = b"</sensors/temp>;rt=\"temperature\"";
        dg.extend_from_slice(body);

        let payload = extract_payload(&dg).expect("payload after marker");
        assert_eq!(payload, body);

        let text = std::str::from_utf8(payload).unwrap();
        assert_eq!(parse_core_links(text), vec!["/sensors/temp".to_owned()]);
    }

    #[test]
    fn extract_payload_none_when_no_marker() {
        // Header + token + one option, but no 0xFF marker / no payload.
        let mut dg = Vec::new();
        dg.push((0b01 << 6) | (1 << 4)); // ver1, type NON, TKL0
        dg.push(CODE_GET);
        dg.extend_from_slice(&0x0001u16.to_be_bytes());
        dg.push(0xB4); // option: delta=11, len=4
        dg.extend_from_slice(b"core");
        assert!(extract_payload(&dg).is_none());
    }

    #[test]
    fn extract_payload_rejects_wrong_version() {
        let dg = [0x00u8, CODE_GET, 0x00, 0x01, PAYLOAD_MARKER, b'x'];
        assert!(extract_payload(&dg).is_none());
    }
}
