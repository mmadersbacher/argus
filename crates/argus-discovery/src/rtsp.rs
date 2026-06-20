//! RTSP (port 554) OPTIONS probe — names the camera/NVR from its server banner.
//!
//! A port-class guess can say "554 is open, probably a camera"; it cannot say
//! *which* camera. This sends one RTSP `OPTIONS` request and reads the reply,
//! whose `Server` header carries the vendor/firmware identity (Hikvision,
//! Dahua, H264DVR, …) and whose `Public` header lists the supported methods.
//! That turns a generic IoT guess into a concrete vendor+model fingerprint for
//! CVE correlation, without any third-party RTSP client.
//!
//! Unlike the connect-time banner scanner, RTSP servers say nothing on connect
//! — they wait for a request — so this one *does* send a payload first. That is
//! the protocol's own client handshake (a read-only `OPTIONS`), not a probe
//! that could perturb a fragile endpoint.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Cap on the response read — an RTSP `OPTIONS` reply is a short status line
/// plus a handful of headers; 4 KiB is generous headroom.
const RESPONSE_READ: usize = 4096;

/// What an RTSP `OPTIONS` exchange reveals about the listening service.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RtspInfo {
    /// Numeric status from the `RTSP/1.0 <code> <reason>` line (e.g. 200, 401).
    pub status: u16,
    /// `Server` header — the camera/NVR identifier (vendor + firmware).
    pub server: Option<String>,
    /// `Public` header — the methods the server advertises as allowed.
    pub public: Option<String>,
}

/// Probe an RTSP service: connect, send one `OPTIONS`, parse the reply.
///
/// `wait` bounds both the TCP connect and the response read. Returns `None`
/// only when the connection or read fails, or when the response is not RTSP
/// (its first line does not start with `RTSP/`). Any well-formed RTSP reply —
/// including auth challenges like `401 Unauthorized`, which still expose the
/// `Server` banner — yields `Some(RtspInfo)`.
pub async fn query(ip: IpAddr, port: u16, wait: Duration) -> Option<RtspInfo> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = timeout(wait, TcpStream::connect(addr)).await.ok()?.ok()?;

    let request = format!(
        "OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: argus-discovery\r\n\r\n"
    );
    timeout(wait, stream.write_all(request.as_bytes()))
        .await
        .ok()?
        .ok()?;

    let mut buf = vec![0u8; RESPONSE_READ];
    let n = timeout(wait, stream.read(&mut buf)).await.ok()?.ok()?;
    drop(stream);
    if n == 0 {
        return None;
    }

    let resp = String::from_utf8_lossy(&buf[..n]);
    parse_options_response(&resp)
}

/// Parse an RTSP `OPTIONS` response: status line + case-insensitive headers.
///
/// Returns `None` if the first line does not start with `RTSP/` (the response
/// is not RTSP) or carries no parseable status code. `Server` and `Public`
/// headers are optional — absent headers stay `None`.
#[must_use]
pub fn parse_options_response(resp: &str) -> Option<RtspInfo> {
    // Split on CR/LF; the status line is the first non-empty line. Headers are
    // HTTP-style `Name: value`, so the same line framing applies to both.
    let mut lines = resp.split("\r\n").flat_map(|l| l.split('\n'));

    let status_line = lines.next()?;
    let after_proto = status_line.strip_prefix("RTSP/")?;
    // `after_proto` is now `1.0 200 OK`; the version sits before the first space,
    // the status code is the next whitespace-delimited token.
    let code_token = after_proto.split_whitespace().nth(1)?;
    let status: u16 = code_token.parse().ok()?;

    let mut info = RtspInfo {
        status,
        ..RtspInfo::default()
    };

    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        if name.trim().eq_ignore_ascii_case("server") {
            info.server = Some(value.to_owned());
        } else if name.trim().eq_ignore_ascii_case("public") {
            info.public = Some(value.to_owned());
        }
    }

    Some(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_hikvision_options_reply() {
        let resp = "RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: Hikvision/V5.5.800\r\n\
                    Public: OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN\r\n\r\n";
        let info = parse_options_response(resp).expect("valid RTSP reply parses");
        assert_eq!(info.status, 200);
        assert!(
            info.server
                .as_deref()
                .unwrap_or_default()
                .contains("Hikvision"),
            "server header should name the camera vendor"
        );
        assert!(
            info.public
                .as_deref()
                .unwrap_or_default()
                .contains("DESCRIBE"),
            "public header should list the advertised methods"
        );
    }

    #[test]
    fn parses_a_dahua_variant() {
        let resp = "RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: Dahua Rtsp Server/2.0\r\n\
                    Public: OPTIONS, DESCRIBE, SETUP, TEARDOWN, PLAY, PAUSE\r\n\r\n";
        let info = parse_options_response(resp).expect("valid RTSP reply parses");
        assert_eq!(info.status, 200);
        assert_eq!(info.server.as_deref(), Some("Dahua Rtsp Server/2.0"));
        assert!(info.public.as_deref().unwrap_or_default().contains("PAUSE"));
    }

    #[test]
    fn auth_challenge_still_yields_the_banner() {
        // A 401 is a valid RTSP reply and still exposes the Server identity.
        let resp = "RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\n\
                    WWW-Authenticate: Digest realm=\"IP Camera\"\r\n\
                    Server: H264DVR rtsp server\r\n\r\n";
        let info = parse_options_response(resp).expect("401 is still RTSP");
        assert_eq!(info.status, 401);
        assert_eq!(info.server.as_deref(), Some("H264DVR rtsp server"));
        assert_eq!(info.public, None);
    }

    #[test]
    fn case_insensitive_headers_are_matched() {
        let resp = "RTSP/1.0 200 OK\r\nSERVER: Axis/1.0\r\npUbLiC: OPTIONS, DESCRIBE\r\n\r\n";
        let info = parse_options_response(resp).expect("valid RTSP reply parses");
        assert_eq!(info.server.as_deref(), Some("Axis/1.0"));
        assert_eq!(info.public.as_deref(), Some("OPTIONS, DESCRIBE"));
    }

    #[test]
    fn bare_lf_line_endings_still_parse() {
        // Some embedded servers emit LF-only; the parser must not depend on CRLF.
        let resp = "RTSP/1.0 200 OK\nServer: Dahua Rtsp Server/2.0\n\n";
        let info = parse_options_response(resp).expect("LF-only reply parses");
        assert_eq!(info.status, 200);
        assert_eq!(info.server.as_deref(), Some("Dahua Rtsp Server/2.0"));
    }

    #[test]
    fn non_rtsp_response_is_rejected() {
        // An HTTP server answering on 554 must not be misread as a camera.
        let resp = "HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\n\r\n";
        assert_eq!(parse_options_response(resp), None);
    }

    #[test]
    fn garbage_first_line_is_rejected() {
        assert_eq!(parse_options_response(""), None);
        assert_eq!(parse_options_response("hello world"), None);
        // RTSP prefix but no numeric status code.
        assert_eq!(parse_options_response("RTSP/1.0\r\n\r\n"), None);
    }
}
