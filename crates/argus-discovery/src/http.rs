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
    /// `<meta name="generator">` content — the CMS product + version a web app
    /// advertises (e.g. `WordPress 6.4.2`, `Moodle 4.1`, `Drupal 9`). The single
    /// strongest version-confirmed signal for self-hosted school web apps.
    pub generator: Option<String>,
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
    let capped = slice_to_chars(&body, MAX_BODY);
    let title = extract_title(capped);
    let generator = extract_generator(capped);

    Some(HttpInfo {
        status,
        server,
        powered_by,
        title,
        generator,
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

/// Extract the `content` of the first `<meta name="generator" content="...">`
/// tag — a CMS advertising its product + version. Attribute order is free and
/// quotes may be single, double or absent. The value is trimmed and length-
/// capped so a hostile page cannot smuggle a huge string into correlation.
fn extract_generator(html: &str) -> Option<String> {
    // ASCII-lowercase preserves byte offsets, so positions found in `lower`
    // index `html` (the original case) exactly — essential for the value.
    let lower = html.to_ascii_lowercase();
    let mut from = 0;
    while let Some(rel) = lower[from..].find("<meta") {
        let start = from + rel;
        let end = lower[start..].find('>').map_or(html.len(), |e| start + e);
        let tag_lower = &lower[start..end];
        from = end.max(start + 5); // always make progress
        if !(tag_lower.contains("name=\"generator\"")
            || tag_lower.contains("name='generator'")
            || tag_lower.contains("name=generator"))
        {
            continue;
        }
        if let Some(content) = meta_content(&html[start..end], tag_lower) {
            let trimmed = content.trim();
            if !trimmed.is_empty() {
                // A generator is "Product 1.2.3", not an essay; the version
                // token survives a generous char cap.
                return Some(trimmed.chars().take(120).collect());
            }
        }
    }
    None
}

/// Read the `content` attribute value out of one `<meta>` tag, handling double,
/// single or no quotes. `tag` is the original-case slice; `tag_lower` is its
/// ASCII-lowercase twin (same byte offsets), so the key is located
/// case-insensitively while the value is returned verbatim.
fn meta_content(tag: &str, tag_lower: &str) -> Option<String> {
    let key = tag_lower.find("content")?;
    let after = key + tag_lower[key..].find('=')? + 1;
    let rest = tag[after..].trim_start();
    let quote = rest.chars().next()?;
    if quote == '"' || quote == '\'' {
        let close = rest[1..].find(quote)?;
        Some(rest[1..=close].to_owned())
    } else {
        Some(rest.split_whitespace().next()?.to_owned())
    }
}

/// Probe a web port for a known IP-camera vendor's info endpoint and return a
/// correlatable product string (`Hikvision <model> <fw>` / `Dahua <type>`).
///
/// Two **read-only** GETs to documented info endpoints. On the cameras that
/// matter these answer unauthenticated (the very weakness behind their KEV
/// CVEs); a patched camera answers `401`/`404` and yields nothing, so there is
/// no false positive. Returns `None` for anything that is not a recognised
/// camera. Redirects are not followed (an info endpoint that 30x's is not it).
pub async fn camera_fingerprint(
    ip: IpAddr,
    port: u16,
    tls: bool,
    wait: Duration,
) -> Option<String> {
    let scheme = if tls { "https" } else { "http" };
    let client = reqwest::Client::builder()
        .timeout(wait)
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("argus-discovery")
        .build()
        .ok()?;

    // Hikvision ISAPI deviceInfo (XML).
    let hik = format!("{scheme}://{ip}:{port}/ISAPI/System/deviceInfo");
    if let Ok(resp) = client.get(&hik).send().await {
        if resp.status().is_success() {
            if let Ok(body) = resp.text().await {
                if let Some(p) = parse_hikvision(slice_to_chars(&body, MAX_BODY)) {
                    return Some(p);
                }
            }
        }
    }

    // Dahua magicBox getSystemInfo (key=value text).
    let dahua = format!("{scheme}://{ip}:{port}/cgi-bin/magicBox.cgi?action=getSystemInfo");
    if let Ok(resp) = client.get(&dahua).send().await {
        if resp.status().is_success() {
            if let Ok(body) = resp.text().await {
                if let Some(p) = parse_dahua(slice_to_chars(&body, MAX_BODY)) {
                    return Some(p);
                }
            }
        }
    }

    None
}

/// Parse a Hikvision ISAPI `deviceInfo` XML into `Hikvision <model> <firmware>`.
/// Requires the `DeviceInfo` root + a `model` tag so a random `200` at that path
/// is not mistaken for a camera.
fn parse_hikvision(xml: &str) -> Option<String> {
    if !xml.contains("DeviceInfo") {
        return None;
    }
    let model = xml_tag(xml, "model")?;
    Some(xml_tag(xml, "firmwareVersion").map_or_else(
        || format!("Hikvision {model}"),
        |fw| format!("Hikvision {model} {fw}"),
    ))
}

/// Parse a Dahua magicBox `getSystemInfo` body into `Dahua <deviceType>`.
fn parse_dahua(body: &str) -> Option<String> {
    let dtype = kv_value(body, "deviceType")?;
    Some(format!("Dahua {dtype}"))
}

/// Extract `<tag>value</tag>` (first occurrence), trimmed; `None` if absent or
/// empty.
fn xml_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    let value = xml[start..end].trim();
    (!value.is_empty()).then(|| value.to_owned())
}

/// Read a `key=value` line's value (the Dahua config-dump format), trimmed.
fn kv_value(body: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    body.lines()
        .filter_map(|l| l.trim().strip_prefix(&prefix))
        .map(str::trim)
        .find(|v| !v.is_empty())
        .map(str::to_owned)
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
    fn generator_extracts_cms_product_and_version() {
        // WordPress / Moodle advertise product + version in the generator meta.
        assert_eq!(
            extract_generator(r#"<meta name="generator" content="WordPress 6.4.2" />"#).as_deref(),
            Some("WordPress 6.4.2")
        );
        assert_eq!(
            extract_generator(r#"<head><meta name="generator" content="Moodle 4.1"></head>"#)
                .as_deref(),
            Some("Moodle 4.1")
        );
        // Attribute order is free; single quotes are accepted.
        assert_eq!(
            extract_generator(r"<meta content='Drupal 9 (https://drupal.org)' name='generator'>")
                .as_deref(),
            Some("Drupal 9 (https://drupal.org)")
        );
        // Case-insensitive tag/attribute names.
        assert_eq!(
            extract_generator(r#"<META NAME="generator" CONTENT="Joomla! 4.2">"#).as_deref(),
            Some("Joomla! 4.2")
        );
    }

    #[test]
    fn generator_absent_or_other_meta_yields_none() {
        assert_eq!(extract_generator("<meta charset=\"utf-8\">"), None);
        assert_eq!(
            extract_generator("<html><body>no meta here</body></html>"),
            None
        );
        // A name=generator with an empty content is not a usable signal.
        assert_eq!(
            extract_generator(r#"<meta name="generator" content="">"#),
            None
        );
    }

    #[test]
    fn hikvision_deviceinfo_xml_yields_vendor_model_firmware() {
        let xml = r#"<?xml version="1.0"?><DeviceInfo version="2.0" xmlns="http://www.hikvision.com/ver20/XMLSchema"><deviceName>IPCAMERA</deviceName><model>DS-2CD2042WD-I</model><firmwareVersion>V5.4.5</firmwareVersion></DeviceInfo>"#;
        assert_eq!(
            parse_hikvision(xml).as_deref(),
            Some("Hikvision DS-2CD2042WD-I V5.4.5")
        );
        // Model without firmware still identifies the vendor.
        assert_eq!(
            parse_hikvision("<DeviceInfo><model>DS-7608</model></DeviceInfo>").as_deref(),
            Some("Hikvision DS-7608")
        );
        // A 200 that is not the DeviceInfo XML is not a camera.
        assert_eq!(parse_hikvision("<html><model>x</model></html>"), None);
        assert_eq!(parse_hikvision("<DeviceInfo></DeviceInfo>"), None);
    }

    #[test]
    fn dahua_systeminfo_kv_yields_vendor_devicetype() {
        let body = "Appliance=IPC\r\ndeviceType=IPC-HFW4431R-Z\r\nhardwareVersion=1.00\r\n";
        assert_eq!(parse_dahua(body).as_deref(), Some("Dahua IPC-HFW4431R-Z"));
        assert_eq!(parse_dahua("serialNumber=123\nfoo=bar\n"), None);
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
