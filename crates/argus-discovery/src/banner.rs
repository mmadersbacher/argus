//! Best-effort service-banner capture and product extraction.
//!
//! Many services announce themselves the moment a client connects (SSH, FTP,
//! SMTP, POP3, IMAP). The connect scanner reads that greeting *without sending
//! anything first* — so it stays safe for fragile OT/IoT endpoints — and turns
//! it into a `Product Version` string for version-specific CVE correlation in
//! the dependency-free light scan, where there is no nmap to fingerprint.

/// Longest sanitized banner kept (one greeting line is well under this).
const MAX_BANNER: usize = 200;

/// Sanitize a raw banner read into its first line: printable ASCII only,
/// trimmed and length-capped. `None` if nothing printable remains.
#[must_use]
pub fn sanitize(raw: &[u8]) -> Option<String> {
    let line: String = raw
        .iter()
        .take_while(|&&b| b != b'\r' && b != b'\n')
        .map(|&b| char::from(b))
        .filter(|c| ('\u{20}'..='\u{7e}').contains(c))
        .take(MAX_BANNER)
        .collect();
    let trimmed = line.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

/// Derive a `Product Version` string from a service banner, or `None` when the
/// banner names no correlatable product+version (the caller then keeps the
/// port's canonical service token).
#[must_use]
pub fn to_product(banner: &str) -> Option<String> {
    // SSH (RFC 4253): "SSH-<protoversion>-<softwareversion> [comments]". The
    // SOFTWARE version (OpenSSH_8.9p1, dropbear_2019.78) carries the
    // CVE-relevant identity — never the leading protocol version, which a
    // naive version scan would otherwise mistake for it (OpenSSH "2.0").
    if let Some(rest) = banner.strip_prefix("SSH-") {
        let (_, after) = rest.split_once('-')?;
        let software = after.split_whitespace().next()?;
        return (!software.is_empty()).then(|| software.replacen('_', " ", 1));
    }

    // Other server-initiated greetings (FTP "220", SMTP "220", POP3 "+OK",
    // IMAP "* OK"): drop the status prefix, then keep the greeting up to and
    // including the first version-looking token. With no such token there is
    // nothing to correlate, so return None and keep the canonical port token.
    let body = strip_status_prefix(banner);
    let tokens: Vec<&str> = body.split_whitespace().collect();
    let vpos = tokens.iter().position(|t| is_version(trim_parens(t)))?;
    let product = tokens[..=vpos]
        .iter()
        .map(|t| trim_parens(t))
        .filter(|t| !t.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    (!product.is_empty()).then_some(product)
}

/// Strip a leading protocol status prefix (numeric `220`/`220-`, POP3 `+OK`,
/// IMAP `* OK`) so the remainder begins at the product description.
fn strip_status_prefix(banner: &str) -> &str {
    let b = banner.trim_start();
    if b.len() >= 3 && b.as_bytes()[..3].iter().all(u8::is_ascii_digit) {
        return b[3..].trim_start_matches([' ', '-']);
    }
    if let Some(rest) = b.strip_prefix("+OK") {
        return rest.trim_start();
    }
    if let Some(rest) = b.strip_prefix("* OK") {
        return rest.trim_start();
    }
    b
}

/// Whether `tok` looks like a version: starts with a digit and contains a dot
/// (the same shape `argus_vuln::extract_version` keys on).
fn is_version(tok: &str) -> bool {
    tok.starts_with(|c: char| c.is_ascii_digit()) && tok.contains('.')
}

/// Trim wrapping parentheses, as in FTP's `220 (vsFTPd 3.0.3)`.
fn trim_parens(tok: &str) -> &str {
    tok.trim_matches(|c| c == '(' || c == ')')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_keeps_first_printable_line() {
        assert_eq!(
            sanitize(b"220 (vsFTPd 3.0.3)\r\nmore").as_deref(),
            Some("220 (vsFTPd 3.0.3)")
        );
        assert_eq!(sanitize(b"\r\n"), None);
        assert_eq!(sanitize(b""), None);
        // Non-printable bytes are dropped, not kept as garbage.
        assert_eq!(sanitize(b"ok\x00\x07line").as_deref(), Some("okline"));
    }

    #[test]
    fn ssh_uses_the_software_version_not_the_protocol_version() {
        // The crux: "2.0" is the SSH protocol version and must NOT win.
        assert_eq!(
            to_product("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1").as_deref(),
            Some("OpenSSH 8.9p1")
        );
        assert_eq!(
            to_product("SSH-2.0-OpenSSH_9.6p1").as_deref(),
            Some("OpenSSH 9.6p1")
        );
        assert_eq!(
            to_product("SSH-2.0-dropbear_2019.78").as_deref(),
            Some("dropbear 2019.78")
        );
    }

    #[test]
    fn ftp_and_smtp_with_a_version_yield_a_product() {
        assert_eq!(
            to_product("220 (vsFTPd 3.0.3)").as_deref(),
            Some("vsFTPd 3.0.3")
        );
        assert_eq!(
            to_product("220 ProFTPD 1.3.5 Server (Debian)").as_deref(),
            Some("ProFTPD 1.3.5")
        );
        // SMTP greeting carrying an Exim version.
        assert_eq!(
            to_product("220 mail ESMTP Exim 4.94").as_deref(),
            Some("mail ESMTP Exim 4.94")
        );
    }

    #[test]
    fn banner_without_a_version_yields_no_product() {
        // Nothing to correlate → caller keeps the canonical port token.
        assert_eq!(to_product("220 mail.example.com ESMTP Postfix"), None);
        assert_eq!(to_product("+OK Dovecot ready"), None);
        assert_eq!(to_product("* OK [CAPABILITY IMAP4rev1] ready"), None);
    }
}
