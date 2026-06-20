//! IPP `Get-Printer-Attributes` probe (TCP 631, hand-rolled RFC 8011 binary).
//!
//! POSTs a single `Get-Printer-Attributes` operation to a printer over HTTP and
//! reads back the identity a port-class "it's on 631, probably a printer" guess
//! can never give: `printer-make-and-model` (exact vendor/model, e.g.
//! "HP LaserJet MFP M428f-M429f"), `printer-info`, `printer-location`,
//! `printer-state` (idle/processing/stopped) and the printer name. The request
//! and response are encoded by hand per RFC 8011 §4.1.1 — no IPP crate. The
//! body is `application/ipp`, posted first to `/ipp/print` (the IANA default
//! IPP-over-HTTP path) and, if that fails, once more to `/` because some devices
//! root the service. Self-signed device TLS would be accepted, but the request
//! is plain HTTP; `danger_accept_invalid_certs` is set for parity with the other
//! probes in case a redirect lands on the device's HTTPS port.

use std::net::IpAddr;
use std::time::Duration;

/// Operation-attributes group tag (begins the only group we send).
const TAG_OPERATION_ATTRIBUTES: u8 = 0x01;
/// End-of-attributes delimiter.
const TAG_END_OF_ATTRIBUTES: u8 = 0x03;

/// Value-tag for `charset` (`attributes-charset`).
const TAG_CHARSET: u8 = 0x47;
/// Value-tag for `naturalLanguage` (`attributes-natural-language`).
const TAG_NATURAL_LANGUAGE: u8 = 0x48;
/// Value-tag for `uri` (`printer-uri`).
const TAG_URI: u8 = 0x45;
/// Value-tag for `enum` (e.g. `printer-state`).
const TAG_ENUM: u8 = 0x23;

/// Highest delimiter tag (a group delimiter is `0x00..=0x05`).
const MAX_DELIMITER_TAG: u8 = 0x05;

/// What a printer told us about itself over IPP.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IppPrinter {
    /// `printer-make-and-model` — exact vendor + model string.
    pub make_and_model: Option<String>,
    /// `printer-info` — free-text description.
    pub info: Option<String>,
    /// `printer-dns-sd-name` or `printer-name`.
    pub name: Option<String>,
    /// `printer-location` — admin-set location.
    pub location: Option<String>,
    /// `printer-state` mapped to idle/processing/stopped (or the raw number).
    pub state: Option<String>,
}

/// Probe `ip:port` for IPP printer attributes.
///
/// Tries `/ipp/print` first, then `/` once. Returns `None` if neither path
/// yields a parseable IPP response; `Some(IppPrinter)` if a response parsed,
/// even when individual fields are absent.
pub async fn query(ip: IpAddr, port: u16, wait: Duration) -> Option<IppPrinter> {
    let client = reqwest::Client::builder()
        .timeout(wait)
        .danger_accept_invalid_certs(true)
        .user_agent("argus-discovery")
        .build()
        .ok()?;

    let body = build_get_printer_attributes(ip, port);

    for path in ["/ipp/print", "/"] {
        let url = format!("http://{ip}:{port}{path}");
        let Ok(resp) = client
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/ipp")
            .body(body.clone())
            .send()
            .await
        else {
            continue;
        };
        if !resp.status().is_success() {
            continue;
        }
        let Ok(bytes) = resp.bytes().await else {
            continue;
        };
        let parsed = parse_attributes(&bytes);
        if parsed != IppPrinter::default() {
            return Some(parsed);
        }
    }
    None
}

/// Append one operation attribute (`value-tag | name-len | name | val-len | val`)
/// to `buf`, with both lengths as 2-byte big-endian per RFC 8011 §4.1.1.
fn push_attribute(buf: &mut Vec<u8>, value_tag: u8, name: &str, value: &[u8]) {
    buf.push(value_tag);
    let name_len = u16::try_from(name.len()).unwrap_or(u16::MAX);
    buf.extend_from_slice(&name_len.to_be_bytes());
    buf.extend_from_slice(&name.as_bytes()[..usize::from(name_len)]);
    let value_len = u16::try_from(value.len()).unwrap_or(u16::MAX);
    buf.extend_from_slice(&value_len.to_be_bytes());
    buf.extend_from_slice(&value[..usize::from(value_len)]);
}

/// Build the binary `Get-Printer-Attributes` request for `ipp://{ip}:{port}/ipp/print`.
fn build_get_printer_attributes(ip: IpAddr, port: u16) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&[0x02, 0x00]); // version-number: IPP 2.0
    buf.extend_from_slice(&[0x00, 0x0B]); // operation-id: Get-Printer-Attributes
    buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // request-id

    buf.push(TAG_OPERATION_ATTRIBUTES);
    push_attribute(&mut buf, TAG_CHARSET, "attributes-charset", b"utf-8");
    push_attribute(
        &mut buf,
        TAG_NATURAL_LANGUAGE,
        "attributes-natural-language",
        b"en",
    );
    let printer_uri = format!("ipp://{ip}:{port}/ipp/print");
    push_attribute(&mut buf, TAG_URI, "printer-uri", printer_uri.as_bytes());

    buf.push(TAG_END_OF_ATTRIBUTES);
    buf
}

/// True for value-tags whose value is a human-readable string we accept as
/// UTF-8 (keyword/name/text/uri/charset/naturalLanguage variants).
fn is_text_tag(tag: u8) -> bool {
    matches!(tag, 0x41 | 0x42 | 0x44 | 0x45 | 0x47 | 0x48 | 0x49)
}

/// Map an IPP `printer-state` enum to a label (3=idle, 4=processing, 5=stopped).
fn state_label(value: i64) -> String {
    match value {
        3 => "idle".to_owned(),
        4 => "processing".to_owned(),
        5 => "stopped".to_owned(),
        other => other.to_string(),
    }
}

/// Parse a binary IPP response into an `IppPrinter`, best-effort.
///
/// Layout (RFC 8011 §4.1.1): `version(2) status(2) request-id(4)` then a series
/// of attribute groups. Each group opens with a delimiter tag (`0x00..=0x05`);
/// inside a group every attribute is `value-tag(1) name-len(2) name
/// value-len(2) value`. A `name-len` of 0 marks an additional value of the
/// previous attribute (multi-value) — we skip those. Walking stops at the
/// end-of-attributes delimiter or when the buffer is exhausted.
fn parse_attributes(resp: &[u8]) -> IppPrinter {
    let mut out = IppPrinter::default();
    // The 8-byte operation header (version, status, request-id) precedes the
    // attribute groups; a shorter buffer has nothing to parse.
    if resp.len() < 8 {
        return out;
    }
    let mut pos = 8usize;

    while pos < resp.len() {
        let tag = resp[pos];
        if tag == TAG_END_OF_ATTRIBUTES {
            break;
        }
        if tag <= MAX_DELIMITER_TAG {
            // Group delimiter (operation/printer/job/etc.) — one byte, advance.
            pos += 1;
            continue;
        }

        // Attribute: value-tag already read as `tag`.
        let Some(name) = read_field(resp, pos + 1) else {
            break;
        };
        let value_pos = name.next;
        let Some(value) = read_field(resp, value_pos) else {
            break;
        };
        pos = value.next;

        // name-len 0 → additional value for the previous attribute; skip it.
        if name.bytes.is_empty() {
            continue;
        }

        let attr_name = String::from_utf8_lossy(name.bytes);
        if is_text_tag(tag) {
            let val = String::from_utf8_lossy(value.bytes).trim().to_owned();
            if val.is_empty() {
                continue;
            }
            match attr_name.as_ref() {
                "printer-make-and-model" => out.make_and_model = Some(val),
                "printer-info" => out.info = Some(val),
                "printer-location" => out.location = Some(val),
                "printer-dns-sd-name" => out.name = Some(val),
                // Only let printer-name fill the slot if dns-sd-name hasn't.
                "printer-name" if out.name.is_none() => out.name = Some(val),
                _ => {}
            }
        } else if tag == TAG_ENUM && attr_name == "printer-state" {
            if let Some(n) = read_be_int(value.bytes) {
                out.state = Some(state_label(n));
            }
        }
    }
    out
}

/// A length-prefixed field: its bytes plus the offset just past it.
struct Field<'a> {
    bytes: &'a [u8],
    next: usize,
}

/// Read a 2-byte big-endian length at `pos` followed by that many bytes.
fn read_field(buf: &[u8], pos: usize) -> Option<Field<'_>> {
    let len_hi = *buf.get(pos)?;
    let len_lo = *buf.get(pos + 1)?;
    let len = usize::from(u16::from_be_bytes([len_hi, len_lo]));
    let start = pos + 2;
    let end = start.checked_add(len)?;
    let bytes = buf.get(start..end)?;
    Some(Field { bytes, next: end })
}

/// Decode a big-endian two's-complement IPP integer/enum (1..=8 bytes).
fn read_be_int(bytes: &[u8]) -> Option<i64> {
    if bytes.is_empty() || bytes.len() > 8 {
        return None;
    }
    // Sign-extend from the high bit of the first byte.
    let negative = bytes[0] & 0x80 != 0;
    let mut acc: i64 = if negative { -1 } else { 0 };
    for &b in bytes {
        acc = (acc << 8) | i64::from(b);
    }
    Some(acc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Push an attribute into a hand-built test response with the real encoding.
    fn enc_attr(buf: &mut Vec<u8>, value_tag: u8, name: &str, value: &[u8]) {
        buf.push(value_tag);
        let name_len = u16::try_from(name.len()).unwrap();
        buf.extend_from_slice(&name_len.to_be_bytes());
        buf.extend_from_slice(name.as_bytes());
        let value_len = u16::try_from(value.len()).unwrap();
        buf.extend_from_slice(&value_len.to_be_bytes());
        buf.extend_from_slice(value);
    }

    #[test]
    fn request_has_correct_header_and_end_tag() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
        let req = build_get_printer_attributes(ip, 631);

        // version 2.0, operation-id 0x000B, request-id 0x00000001
        assert_eq!(&req[0..2], &[0x02, 0x00], "version 2.0");
        assert_eq!(&req[2..4], &[0x00, 0x0B], "Get-Printer-Attributes op-id");
        assert_eq!(&req[4..8], &[0x00, 0x00, 0x00, 0x01], "request-id");
        // operation-attributes group opens right after the header.
        assert_eq!(req[8], TAG_OPERATION_ATTRIBUTES);
        // last byte is end-of-attributes.
        assert_eq!(*req.last().unwrap(), TAG_END_OF_ATTRIBUTES);
    }

    #[test]
    fn request_contains_required_attribute_names() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let req = build_get_printer_attributes(ip, 631);

        let has = |needle: &[u8]| req.windows(needle.len()).any(|w| w == needle);
        assert!(has(b"attributes-charset"));
        assert!(has(b"attributes-natural-language"));
        assert!(has(b"printer-uri"));
        // printer-uri value names the device.
        assert!(has(b"ipp://10.0.0.1:631/ipp/print"));
        assert!(has(b"utf-8"));
    }

    #[test]
    fn parses_make_model_and_state() {
        // 8-byte operation header: version(2) status(2) request-id(4).
        let mut resp = vec![0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        // printer-attributes group delimiter.
        resp.push(0x04);
        // printer-make-and-model as nameWithoutLanguage (0x42).
        enc_attr(
            &mut resp,
            0x42,
            "printer-make-and-model",
            b"HP LaserJet MFP M428f",
        );
        // printer-state enum (0x23) with integer 3 = idle (4-byte BE).
        enc_attr(&mut resp, TAG_ENUM, "printer-state", &3i32.to_be_bytes());
        // printer-info text (0x41 keyword accepted as text here).
        enc_attr(&mut resp, 0x41, "printer-info", b"Front desk printer");
        resp.push(TAG_END_OF_ATTRIBUTES);

        let p = parse_attributes(&resp);
        assert_eq!(p.make_and_model.as_deref(), Some("HP LaserJet MFP M428f"));
        assert_eq!(p.state.as_deref(), Some("idle"));
        assert_eq!(p.info.as_deref(), Some("Front desk printer"));
    }

    #[test]
    fn multi_value_additional_values_are_skipped() {
        let mut resp = vec![0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        resp.push(0x04);
        // A real attribute...
        enc_attr(&mut resp, 0x44, "printer-name", b"lobby");
        // ...followed by an additional value (name-len 0) of the same attribute.
        enc_attr(&mut resp, 0x44, "", b"ignored-extra");
        resp.push(TAG_END_OF_ATTRIBUTES);

        let p = parse_attributes(&resp);
        assert_eq!(p.name.as_deref(), Some("lobby"));
    }

    #[test]
    fn state_numbers_map_to_labels() {
        assert_eq!(state_label(3), "idle");
        assert_eq!(state_label(4), "processing");
        assert_eq!(state_label(5), "stopped");
        assert_eq!(state_label(9), "9");
    }

    #[test]
    fn dns_sd_name_wins_over_printer_name() {
        let mut resp = vec![0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        resp.push(0x04);
        enc_attr(&mut resp, 0x42, "printer-name", b"raw-name");
        enc_attr(&mut resp, 0x42, "printer-dns-sd-name", b"Friendly Name");
        resp.push(TAG_END_OF_ATTRIBUTES);

        let p = parse_attributes(&resp);
        assert_eq!(p.name.as_deref(), Some("Friendly Name"));
    }

    #[test]
    fn empty_or_garbage_response_is_default() {
        assert_eq!(parse_attributes(&[]), IppPrinter::default());
        assert_eq!(parse_attributes(&[0x02, 0x00]), IppPrinter::default());
        // Header only, no attributes.
        let hdr = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03];
        assert_eq!(parse_attributes(&hdr), IppPrinter::default());
    }

    #[test]
    fn read_be_int_handles_signedness() {
        assert_eq!(read_be_int(&[0x00, 0x00, 0x00, 0x03]), Some(3));
        assert_eq!(read_be_int(&[0xFF, 0xFF, 0xFF, 0xFF]), Some(-1));
        assert_eq!(read_be_int(&[]), None);
        assert_eq!(read_be_int(&[0; 9]), None);
    }
}
