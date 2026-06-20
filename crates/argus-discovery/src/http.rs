//! Lightweight HTTP fingerprint of a single host:port.
//!
//! Fetches the root page over HTTP or HTTPS and reads back the identifying
//! response metadata a web-facing asset gives away for free: the HTTP status,
//! the `Server` and `X-Powered-By` headers, and the HTML `<title>`. Those four
//! fields are enough to pin a product/OS hint (e.g. "Apache" + "PHP/7.4", or a
//! device admin panel's title) without any active probing. Self-signed device
//! TLS is accepted (`danger_accept_invalid_certs`) because appliance certs are
//! almost never valid, and redirects are followed a few hops so a bare IP that
//! 301s to its hostname still yields a title. Body read is capped so a hostile
//! or huge page can't exhaust memory before the `<title>` is found.

use std::net::IpAddr;
use std::time::Duration;

/// Largest response body inspected for a `<title>` (64 KiB — a title that is
/// not in the first 64 KiB is not a title worth having).
const MAX_BODY: usize = 64 * 1024;

/// What the root page told us about a web-facing asset.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HttpInfo {
    /// HTTP status of the final (post-redirect) response.
    pub status: u16,
    /// `Server` response header, verbatim.
    pub server: Option<String>,
    /// `X-Powered-By` response header, verbatim.
    pub powered_by: Option<String>,
    /// First `<title>` text, whitespace-collapsed.
    pub title: Option<String>,
}

/// Fingerprint `ip:port`.
///
/// `tls` selects `https`, otherwise `http`. Returns `None` only if the request
/// fails outright; on any HTTP response a `HttpInfo` is returned (status is
/// always set, the rest best-effort).
pub async fn fingerprint(ip: IpAddr, port: u16, tls: bool, wait: Duration) -> Option<HttpInfo> {
    let scheme = if tls { "https" } else { "http" };
    let url = format!("{scheme}://{ip}:{port}/");

    let client = reqwest::Client::builder()
        .timeout(wait)
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::limited(4))
        .user_agent("argus-discovery")
        .build()
        .ok()?;

    let resp = client.get(&url).send().await.ok()?;

    let status = resp.status().as_u16();
    let server = header_string(resp.headers(), reqwest::header::SERVER.as_str());
    let powered_by = header_string(resp.headers(), "x-powered-by");

    // Cap the body before scanning for a title; an unbounded read of a hostile
    // page is the one way this probe could hurt the scanner.
    let body = resp.text().await.ok()?;
    let title = extract_title(slice_to_chars(&body, MAX_BODY));

    Some(HttpInfo {
        status,
        server,
        powered_by,
        title,
    })
}

/// Read a header as an owned `String`, trimmed; `None` if absent or non-UTF-8.
fn header_string(headers: &reqwest::header::HeaderMap, name: &str) -> Option<String> {
    let value = headers.get(name)?.to_str().ok()?.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

/// Truncate `s` to at most `max` bytes on a char boundary (so the cap can't
/// split a multi-byte UTF-8 sequence).
fn slice_to_chars(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Extract the first `<title>...</title>` text, case-insensitively, with all
/// interior whitespace runs collapsed to single spaces and the result trimmed.
/// `None` if there is no closed title element or it is empty after collapse.
fn extract_title(html: &str) -> Option<String> {
    let lower = html.to_ascii_lowercase();
    let open = lower.find("<title")?;
    // Skip to the end of the opening tag (handles `<title lang="en">`).
    let after_open = open + lower[open..].find('>')? + 1;
    let close_rel = lower[after_open..].find("</title>")?;
    let inner = &html[after_open..after_open + close_rel];

    let collapsed = inner.split_whitespace().collect::<Vec<_>>().join(" ");
    (!collapsed.is_empty()).then_some(collapsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_title() {
        assert_eq!(
            extract_title("<title>Foo Bar</title>").as_deref(),
            Some("Foo Bar")
        );
    }

    #[test]
    fn mixed_case_tag() {
        assert_eq!(
            extract_title("<HTML><TITLE>Admin Login</TITLE></HTML>").as_deref(),
            Some("Admin Login")
        );
        assert_eq!(
            extract_title("<TiTlE>RouterOS</tItLe>").as_deref(),
            Some("RouterOS")
        );
    }

    #[test]
    fn whitespace_is_collapsed() {
        assert_eq!(
            extract_title("<title>\n  Hello \n World\n</title>").as_deref(),
            Some("Hello World")
        );
        assert_eq!(
            extract_title("<title>   Lots\t\tof   space   </title>").as_deref(),
            Some("Lots of space")
        );
    }

    #[test]
    fn attributes_on_open_tag_are_skipped() {
        assert_eq!(
            extract_title("<title lang=\"en\" id=x>Dashboard</title>").as_deref(),
            Some("Dashboard")
        );
    }

    #[test]
    fn first_title_wins() {
        assert_eq!(
            extract_title("<title>One</title><title>Two</title>").as_deref(),
            Some("One")
        );
    }

    #[test]
    fn no_title_is_none() {
        assert_eq!(
            extract_title("<html><body>no title here</body></html>"),
            None
        );
        assert_eq!(extract_title(""), None);
        // Open tag with no close → not a usable title.
        assert_eq!(extract_title("<title>unterminated"), None);
        // Empty / whitespace-only title collapses to nothing.
        assert_eq!(extract_title("<title>   </title>"), None);
        assert_eq!(extract_title("<title></title>"), None);
    }

    #[test]
    fn char_boundary_truncation_is_safe() {
        // A multi-byte char straddling the cap must not panic.
        let s = "aé"; // 'é' is 2 bytes; cap at 2 lands mid-char.
        assert_eq!(slice_to_chars(s, 2), "a");
        assert_eq!(slice_to_chars(s, 3), "aé");
        assert_eq!(slice_to_chars("abc", 10), "abc");
    }
}
