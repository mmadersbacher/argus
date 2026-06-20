//! SSDP / UPnP active discovery (UDP 1900 multicast M-SEARCH).
//!
//! Sends a one-shot SSDP `M-SEARCH` (the HTTPU control request) to the
//! `239.255.255.250:1900` multicast group with `ST: ssdp:all`, then collects the
//! unicast `HTTP/1.1 200 OK` replies for a short window. Each reply carries a
//! `LOCATION` header pointing at the device's UPnP descriptor XML; for every
//! unique device we then fetch that descriptor and pull the friendly name,
//! manufacturer and model out of its `<device>` element. This is how a smart TV,
//! a router's IGD, a NAS or a media renderer announces itself on a flat LAN
//! without any prior knowledge of its address.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::{timeout, Instant};

/// SSDP multicast endpoint (IPv4).
const SSDP_V4: (Ipv4Addr, u16) = (Ipv4Addr::new(239, 255, 255, 250), 1900);

/// `MX` value (max wait, in seconds) advertised in the M-SEARCH.
const MSEARCH_MX: u8 = 2;

/// Cap on how many bytes of a descriptor body we read/parse.
const MAX_DESCRIPTOR_BYTES: usize = 64 * 1024;

/// Per-descriptor HTTP request timeout.
const DESCRIPTOR_TIMEOUT: Duration = Duration::from_secs(2);

/// One device discovered over SSDP / UPnP.
#[derive(Debug, Clone)]
pub struct SsdpHost {
    /// The responding device's IP (the packet source).
    pub ip: IpAddr,
    /// `SERVER` header (OS/UPnP/product banner).
    pub server: Option<String>,
    /// `LOCATION` header — URL of the device descriptor XML.
    pub location: Option<String>,
    /// `ST` header — one representative search target the device answered for.
    pub st: Option<String>,
    /// `USN` header — unique service name.
    pub usn: Option<String>,
    /// `friendlyName` from the descriptor.
    pub friendly_name: Option<String>,
    /// `manufacturer` from the descriptor.
    pub manufacturer: Option<String>,
    /// `modelName` from the descriptor.
    pub model_name: Option<String>,
    /// `modelNumber` from the descriptor.
    pub model_number: Option<String>,
    /// `deviceType` from the descriptor.
    pub device_type: Option<String>,
}

/// Headers we care about, lifted from an SSDP response.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ParsedHeaders {
    location: Option<String>,
    server: Option<String>,
    st: Option<String>,
    usn: Option<String>,
}

/// Fields lifted from a UPnP device descriptor's `<device>` element.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct DescriptorInfo {
    friendly_name: Option<String>,
    manufacturer: Option<String>,
    model_name: Option<String>,
    model_number: Option<String>,
    device_type: Option<String>,
}

/// Send the M-SEARCH and collect responders for `window`, then enrich each unique
/// device with its UPnP descriptor.
pub async fn discover(window: Duration) -> Vec<SsdpHost> {
    let Ok(sock) = UdpSocket::bind(("0.0.0.0", 0)).await else {
        return Vec::new();
    };
    let _ = sock.set_multicast_ttl_v4(2);
    let msearch = build_msearch();
    if sock.send_to(&msearch, SSDP_V4).await.is_err() {
        return Vec::new();
    }

    // Collect raw responses, deduplicated by source IP (union of fields seen).
    let mut acc: BTreeMap<IpAddr, SsdpHost> = BTreeMap::new();
    let mut buf = vec![0u8; 8192];
    let deadline = Instant::now() + window;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match timeout(remaining, sock.recv_from(&mut buf)).await {
            Ok(Ok((n, src))) => {
                if let Ok(text) = std::str::from_utf8(&buf[..n]) {
                    merge_response(text, src.ip(), &mut acc);
                }
            }
            _ => break,
        }
    }

    // Enrich with descriptors. One shared client; failures leave fields None.
    let client = reqwest::Client::builder()
        .timeout(DESCRIPTOR_TIMEOUT)
        .build()
        .ok();
    let mut hosts: Vec<SsdpHost> = acc.into_values().collect();
    if let Some(client) = client {
        for host in &mut hosts {
            if let Some(url) = host.location.clone() {
                if let Some(info) = fetch_descriptor(&client, &url).await {
                    apply_descriptor(host, info);
                }
            }
        }
    }
    hosts
}

/// Build the SSDP `M-SEARCH` datagram (HTTPU request text).
fn build_msearch() -> Vec<u8> {
    // CRLF-terminated lines, trailing blank line, per the UPnP control spec.
    let req = format!(
        "M-SEARCH * HTTP/1.1\r\n\
         HOST: 239.255.255.250:1900\r\n\
         MAN: \"ssdp:discover\"\r\n\
         MX: {MSEARCH_MX}\r\n\
         ST: ssdp:all\r\n\
         \r\n"
    );
    req.into_bytes()
}

/// Parse an SSDP HTTP-style header block into the fields we keep.
fn parse_ssdp_headers(resp: &str) -> ParsedHeaders {
    let mut out = ParsedHeaders::default();
    // Skip the status/request line; headers follow until a blank line.
    for line in resp.lines().skip(1) {
        if line.trim().is_empty() {
            break;
        }
        let Some((key, val)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let val = val.trim();
        if val.is_empty() {
            continue;
        }
        // First occurrence wins for each header.
        if key.eq_ignore_ascii_case("LOCATION") {
            out.location.get_or_insert_with(|| val.to_owned());
        } else if key.eq_ignore_ascii_case("SERVER") {
            out.server.get_or_insert_with(|| val.to_owned());
        } else if key.eq_ignore_ascii_case("ST") {
            out.st.get_or_insert_with(|| val.to_owned());
        } else if key.eq_ignore_ascii_case("USN") {
            out.usn.get_or_insert_with(|| val.to_owned());
        }
    }
    out
}

/// Fold one SSDP response into the accumulator, keyed by source IP.
fn merge_response(resp: &str, src: IpAddr, acc: &mut BTreeMap<IpAddr, SsdpHost>) {
    let headers = parse_ssdp_headers(resp);
    let entry = acc.entry(src).or_insert_with(|| SsdpHost {
        ip: src,
        server: None,
        location: None,
        st: None,
        usn: None,
        friendly_name: None,
        manufacturer: None,
        model_name: None,
        model_number: None,
        device_type: None,
    });
    if entry.location.is_none() {
        entry.location = headers.location;
    }
    if entry.server.is_none() {
        entry.server = headers.server;
    }
    if entry.st.is_none() {
        entry.st = headers.st;
    }
    if entry.usn.is_none() {
        entry.usn = headers.usn;
    }
}

/// Fetch and parse a UPnP descriptor. `None` on any fetch/parse failure.
async fn fetch_descriptor(client: &reqwest::Client, url: &str) -> Option<DescriptorInfo> {
    let body = client.get(url).send().await.ok()?.text().await.ok()?;
    let slice = if body.len() > MAX_DESCRIPTOR_BYTES {
        // Trim on a char boundary so the parser gets valid UTF-8.
        let mut end = MAX_DESCRIPTOR_BYTES;
        while end > 0 && !body.is_char_boundary(end) {
            end -= 1;
        }
        &body[..end]
    } else {
        &body
    };
    Some(parse_descriptor(slice))
}

/// Extract device fields from a UPnP descriptor XML.
fn parse_descriptor(xml: &str) -> DescriptorInfo {
    let mut out = DescriptorInfo::default();
    let Ok(doc) = roxmltree::Document::parse(xml) else {
        return out;
    };
    // Use the first `<device>` element (the root device).
    let Some(device) = doc
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "device")
    else {
        return out;
    };
    for child in device.children().filter(roxmltree::Node::is_element) {
        let text = child.text().map(str::trim).filter(|t| !t.is_empty());
        let Some(text) = text else {
            continue;
        };
        match child.tag_name().name() {
            "friendlyName" => out.friendly_name.get_or_insert_with(|| text.to_owned()),
            "manufacturer" => out.manufacturer.get_or_insert_with(|| text.to_owned()),
            "modelName" => out.model_name.get_or_insert_with(|| text.to_owned()),
            "modelNumber" => out.model_number.get_or_insert_with(|| text.to_owned()),
            "deviceType" => out.device_type.get_or_insert_with(|| text.to_owned()),
            _ => continue,
        };
    }
    out
}

/// Copy descriptor fields onto a host (only filling empty slots).
fn apply_descriptor(host: &mut SsdpHost, info: DescriptorInfo) {
    if host.friendly_name.is_none() {
        host.friendly_name = info.friendly_name;
    }
    if host.manufacturer.is_none() {
        host.manufacturer = info.manufacturer;
    }
    if host.model_name.is_none() {
        host.model_name = info.model_name;
    }
    if host.model_number.is_none() {
        host.model_number = info.model_number;
    }
    if host.device_type.is_none() {
        host.device_type = info.device_type;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msearch_is_well_formed() {
        let m = build_msearch();
        let text = std::str::from_utf8(&m).unwrap();
        assert!(text.starts_with("M-SEARCH * HTTP/1.1\r\n"));
        assert!(text.contains("M-SEARCH"));
        assert!(text.contains("ssdp:all"));
        assert!(text.contains("HOST: 239.255.255.250:1900"));
        assert!(text.contains("\"ssdp:discover\""));
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[test]
    fn parses_a_realistic_ssdp_response() {
        // Mixed-case headers, CRLF lines, as a real device replies.
        let resp = "HTTP/1.1 200 OK\r\n\
            CACHE-CONTROL: max-age=1800\r\n\
            DATE: Sat, 20 Jun 2026 12:00:00 GMT\r\n\
            EXT:\r\n\
            LOCATION: http://192.168.8.1:5000/rootDesc.xml\r\n\
            Server: Linux/4.14 UPnP/1.1 MiniUPnPd/2.1\r\n\
            ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
            USN: uuid:abcdef01-2345-6789-abcd-ef0123456789::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
            \r\n";
        let h = parse_ssdp_headers(resp);
        assert_eq!(
            h.location.as_deref(),
            Some("http://192.168.8.1:5000/rootDesc.xml")
        );
        assert_eq!(
            h.server.as_deref(),
            Some("Linux/4.14 UPnP/1.1 MiniUPnPd/2.1")
        );
        assert_eq!(
            h.st.as_deref(),
            Some("urn:schemas-upnp-org:device:InternetGatewayDevice:1")
        );
        assert!(h.usn.as_deref().unwrap().starts_with("uuid:abcdef01"));
    }

    #[test]
    fn header_parsing_is_case_insensitive_and_skips_status_line() {
        let resp = "HTTP/1.1 200 OK\r\nlocation: http://10.0.0.5/desc.xml\r\n\r\n";
        let h = parse_ssdp_headers(resp);
        assert_eq!(h.location.as_deref(), Some("http://10.0.0.5/desc.xml"));
        assert_eq!(h.server, None);
    }

    #[test]
    fn parses_a_upnp_descriptor() {
        let xml = r#"<?xml version="1.0"?>
            <root xmlns="urn:schemas-upnp-org:device-1-0">
              <specVersion><major>1</major><minor>0</minor></specVersion>
              <device>
                <deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType>
                <friendlyName>Living Room TV</friendlyName>
                <manufacturer>Acme Corp</manufacturer>
                <modelName>SmartTV 9000</modelName>
                <modelNumber>ST-9000</modelNumber>
                <UDN>uuid:1234</UDN>
              </device>
            </root>"#;
        let d = parse_descriptor(xml);
        assert_eq!(d.friendly_name.as_deref(), Some("Living Room TV"));
        assert_eq!(d.manufacturer.as_deref(), Some("Acme Corp"));
        assert_eq!(d.model_name.as_deref(), Some("SmartTV 9000"));
        assert_eq!(d.model_number.as_deref(), Some("ST-9000"));
        assert_eq!(
            d.device_type.as_deref(),
            Some("urn:schemas-upnp-org:device:MediaRenderer:1")
        );
    }

    #[test]
    fn parse_descriptor_tolerates_garbage() {
        assert_eq!(
            parse_descriptor("not xml at all <<<"),
            DescriptorInfo::default()
        );
        assert_eq!(parse_descriptor("<root></root>"), DescriptorInfo::default());
    }

    #[test]
    fn merge_unions_fields_across_responses() {
        // Two responses from the same IP carrying different headers.
        let r1 = "HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.2/d.xml\r\n\r\n";
        let r2 = "HTTP/1.1 200 OK\r\nSERVER: Custom/1.0 UPnP/1.0\r\nST: upnp:rootdevice\r\n\r\n";
        let src: IpAddr = "192.168.1.2".parse().unwrap();
        let mut acc = BTreeMap::new();
        merge_response(r1, src, &mut acc);
        merge_response(r2, src, &mut acc);
        assert_eq!(acc.len(), 1);
        let host = acc.get(&src).unwrap();
        assert_eq!(host.location.as_deref(), Some("http://192.168.1.2/d.xml"));
        assert_eq!(host.server.as_deref(), Some("Custom/1.0 UPnP/1.0"));
        assert_eq!(host.st.as_deref(), Some("upnp:rootdevice"));
    }
}
