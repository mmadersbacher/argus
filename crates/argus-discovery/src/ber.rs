//! Minimal hand-rolled ASN.1 BER encode/decode shared by the SNMP and LDAP
//! probes — both speak tag/length/value framing, so they share one hardened
//! codec instead of two copies that can drift (an earlier divergence left the
//! SNMP decoder missing a length-overflow guard the LDAP one already had).

/// BER length encoding: short form for `< 128`, else long form
/// (`0x81 nn` for one byte, `0x82 hi lo` for two).
pub fn ber_len(len: usize) -> Vec<u8> {
    match u8::try_from(len) {
        Ok(b) if b < 0x80 => vec![b], // short form (< 128)
        Ok(b) => vec![0x81, b],       // single-byte long form (128..=255)
        Err(_) => {
            let hi = u8::try_from((len >> 8) & 0xff).unwrap_or(0xff);
            let lo = u8::try_from(len & 0xff).unwrap_or(0xff);
            vec![0x82, hi, lo]
        }
    }
}

/// Tag-length-value wrap of `content` under `tag`.
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    v.extend(ber_len(content.len()));
    v.extend_from_slice(content);
    v
}

/// Read one BER element at `pos`: returns `(tag, content_start, content_end)`.
///
/// Long-form lengths up to four bytes are supported; the indefinite form
/// (`n == 0`), an absurd width (`n > 4`, i.e. multi-GB), an arithmetic overflow,
/// or a length that overruns the buffer all yield `None` — so a crafted reply
/// can never panic or read out of bounds.
pub fn read_tlv(buf: &[u8], pos: usize) -> Option<(u8, usize, usize)> {
    let tag = *buf.get(pos)?;
    let first = *buf.get(pos + 1)?;
    let (len, body) = if first < 0x80 {
        (usize::from(first), pos + 2)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 {
            return None; // indefinite form / absurd width: reject.
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | usize::from(*buf.get(pos + 2 + i)?);
        }
        (len, pos + 2 + n)
    };
    let end = body.checked_add(len)?;
    if end > buf.len() {
        return None;
    }
    Some((tag, body, end))
}

/// Read a BER element's value (`buf[body..end]`) as a trimmed, lossy-UTF-8
/// string.
pub fn tlv_string(buf: &[u8], body: usize, end: usize) -> Option<String> {
    Some(
        String::from_utf8_lossy(buf.get(body..end)?)
            .trim()
            .to_owned(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ber_len_short_and_long_forms() {
        assert_eq!(ber_len(5), vec![5]); // short form
        assert_eq!(ber_len(200), vec![0x81, 200]); // single-byte long form
        assert_eq!(ber_len(256), vec![0x82, 0x01, 0x00]);
        assert_eq!(ber_len(0x1234), vec![0x82, 0x12, 0x34]);
    }

    #[test]
    fn tlv_wraps_tag_length_value() {
        assert_eq!(tlv(0x04, b"hi"), vec![0x04, 0x02, b'h', b'i']);
    }

    #[test]
    fn read_tlv_parses_short_form() {
        // tag 0x04, len 2, "ok" — value range [2, 4).
        let buf = [0x04, 0x02, b'o', b'k'];
        assert_eq!(read_tlv(&buf, 0), Some((0x04, 2, 4)));
        assert_eq!(tlv_string(&buf, 2, 4).as_deref(), Some("ok"));
    }

    #[test]
    fn read_tlv_rejects_overlong_or_truncated_length_without_overflow() {
        // 8 length-bytes of 0xFF would make `len` ~usize::MAX and overflow
        // `body + len`: must be rejected, not panic.
        let huge = [0x30, 0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert!(read_tlv(&huge, 0).is_none());
        // Truncated long-form header (claims 2 length bytes, only 1 present).
        assert!(read_tlv(&[0x30, 0x82, 0x01], 0).is_none());
        // Indefinite form (n == 0).
        assert!(read_tlv(&[0x30, 0x80], 0).is_none());
        // Length that overruns the buffer.
        assert!(read_tlv(&[0x04, 0x05, b'a', b'b'], 0).is_none());
    }
}
