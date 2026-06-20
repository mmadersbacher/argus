//! TLS certificate harvest via `openssl s_client` (shell-out, no Rust TLS dep).
//!
//! On every TLS-speaking port a device hands out its leaf certificate before any
//! authentication, and that certificate is a strong identity signal: the subject
//! CN and the Subject Alternative Names frequently carry the device's real
//! hostname(s) (a NAS's `mybox.local`, a camera's serial, an appliance's FQDN),
//! and the issuer distinguishes a self-signed appliance cert from a public CA.
//! The SANs also make an excellent cross-observation dedup key.
//!
//! Rather than pull in a Rust TLS stack and a dangerous no-verify verifier, this
//! shells out to `openssl` — the same shell-out convention as [`crate::arpscan`],
//! [`crate::masscan`] and [`crate::nmap`]: `s_client` fetches the presented PEM
//! (stdin closed so it doesn't block), then `x509` decodes subject/issuer/SAN/
//! expiry. No certificate validation is performed — we are reading the cert, not
//! trusting it — so self-signed appliance certs are parsed fine.

use std::net::IpAddr;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::time::timeout;

/// Identity fields lifted from a leaf X.509 certificate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsCert {
    /// Subject CN (the cert's primary name), if present.
    pub subject_cn: Option<String>,
    /// Issuer CN/O — distinguishes self-signed appliance certs from a public CA.
    pub issuer: Option<String>,
    /// Subject Alternative Names (DNS names and IPs), sorted and de-duplicated.
    pub sans: Vec<String>,
    /// `notAfter` expiry string, verbatim from openssl.
    pub not_after: Option<String>,
}

/// Whether the `openssl` binary is runnable.
pub async fn available() -> bool {
    Command::new("openssl")
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .is_ok_and(|s| s.success())
}

/// Fetch and parse the leaf certificate presented by `ip:port`. `None` if the
/// host does not complete a TLS handshake or presents nothing parseable.
pub async fn cert(ip: IpAddr, port: u16, wait: Duration) -> Option<TlsCert> {
    let pem = fetch_pem(ip, port, wait).await?;
    let text = decode_cert(&pem, wait).await?;
    let parsed = parse_x509_text(&text);
    (parsed != TlsCert::default()).then_some(parsed)
}

/// Run `openssl s_client` and lift the first PEM certificate out of its output.
async fn fetch_pem(ip: IpAddr, port: u16, wait: Duration) -> Option<String> {
    let connect = format!("{ip}:{port}");
    let server = ip.to_string();
    let out = timeout(
        wait,
        Command::new("openssl")
            .args(["s_client", "-connect", &connect, "-servername", &server])
            .stdin(Stdio::null()) // EOF so s_client doesn't block on input
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output(),
    )
    .await
    .ok()?
    .ok()?;
    extract_pem(&String::from_utf8_lossy(&out.stdout))
}

/// Decode a PEM cert with `openssl x509`, returning its text fields.
async fn decode_cert(pem: &str, wait: Duration) -> Option<String> {
    let mut child = Command::new("openssl")
        .args([
            "x509",
            "-noout",
            "-subject",
            "-issuer",
            "-enddate",
            "-ext",
            "subjectAltName",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(pem.as_bytes()).await.ok()?;
        // `stdin` drops here → EOF for openssl.
    }
    let out = timeout(wait, child.wait_with_output()).await.ok()?.ok()?;
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Slice the first `BEGIN..END CERTIFICATE` PEM block out of `s`.
fn extract_pem(s: &str) -> Option<String> {
    const END: &str = "-----END CERTIFICATE-----";
    let begin = s.find("-----BEGIN CERTIFICATE-----")?;
    let end = s[begin..].find(END)? + begin + END.len();
    Some(s[begin..end].to_owned())
}

/// Parse the text emitted by `openssl x509 -subject -issuer -enddate -ext
/// subjectAltName` into a [`TlsCert`]. Tolerates both the `CN=value` and the
/// openssl-3 `CN = value` spacing, and the `/CN=value` legacy form.
fn parse_x509_text(out: &str) -> TlsCert {
    let mut c = TlsCert::default();
    for line in out.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("subject=") {
            c.subject_cn = extract_cn(rest);
        } else if let Some(rest) = line.strip_prefix("issuer=") {
            c.issuer = extract_cn(rest).or_else(|| Some(rest.trim().to_owned()));
        } else if let Some(rest) = line.strip_prefix("notAfter=") {
            c.not_after = Some(rest.trim().to_owned());
        } else if line.contains("DNS:") || line.contains("IP Address:") {
            for tok in line.split(',') {
                let tok = tok.trim();
                if let Some(d) = tok.strip_prefix("DNS:") {
                    c.sans.push(d.trim().to_owned());
                } else if let Some(i) = tok.strip_prefix("IP Address:") {
                    c.sans.push(i.trim().to_owned());
                }
            }
        }
    }
    c.sans.sort();
    c.sans.dedup();
    c
}

/// Pull the `CN` value out of an RDN string like `CN=foo, O=bar` (or the
/// space-padded / slash-separated variants openssl emits across versions).
fn extract_cn(dn: &str) -> Option<String> {
    for part in dn.split([',', '/']) {
        let p = part.trim();
        let rest = p
            .strip_prefix("CN=")
            .or_else(|| p.strip_prefix("CN = "))
            .or_else(|| p.strip_prefix("commonName="));
        if let Some(rest) = rest {
            let v = rest.trim();
            if !v.is_empty() {
                return Some(v.to_owned());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_first_pem_block() {
        let s =
            "junk before\n-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\ntail";
        let pem = extract_pem(s).unwrap();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(pem.ends_with("-----END CERTIFICATE-----"));
        assert!(extract_pem("no cert here").is_none());
    }

    #[test]
    fn extracts_cn_across_openssl_formats() {
        assert_eq!(
            extract_cn("CN=device.local, O=Acme").as_deref(),
            Some("device.local")
        );
        assert_eq!(
            extract_cn("C = US, O = Acme, CN = box.lan").as_deref(),
            Some("box.lan")
        );
        assert_eq!(
            extract_cn("/C=US/O=Acme/CN=legacy.host").as_deref(),
            Some("legacy.host")
        );
        assert_eq!(extract_cn("O=NoCommonName").as_deref(), None);
    }

    #[test]
    fn parses_full_x509_text() {
        let out = "subject=CN = nas.local, O = Synology\n\
                   issuer=CN = Synology Inc. CA\n\
                   notAfter=Jun 20 12:00:00 2027 GMT\n\
                   X509v3 Subject Alternative Name: \n\
                   \x20\x20\x20\x20DNS:nas.local, DNS:www.nas.local, IP Address:192.168.8.5\n";
        let c = parse_x509_text(out);
        assert_eq!(c.subject_cn.as_deref(), Some("nas.local"));
        assert_eq!(c.issuer.as_deref(), Some("Synology Inc. CA"));
        assert_eq!(c.not_after.as_deref(), Some("Jun 20 12:00:00 2027 GMT"));
        assert_eq!(c.sans, vec!["192.168.8.5", "nas.local", "www.nas.local"]);
    }

    #[test]
    fn empty_text_is_default() {
        assert_eq!(parse_x509_text(""), TlsCert::default());
    }
}
