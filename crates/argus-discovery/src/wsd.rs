//! WS-Discovery (WSD) active discovery (UDP 3702, SOAP 1.2 over multicast).
//!
//! Sends a single WS-Discovery `Probe` to the `239.255.255.250:3702` multicast
//! group and collects `ProbeMatches` replies for a short window. Each match
//! carries an `EndpointReference` address (usually a `urn:uuid:...`), a set of
//! device `Types` QNames, and `XAddrs` transport URLs. This is how network
//! printers (`pri:PrintDeviceType`), ONVIF IP cameras
//! (`dn:NetworkVideoTransmitter`) and Windows machines announce themselves —
//! devices a plain TCP scan or mDNS sweep frequently misses. Response source IP
//! is taken as the device IP. Read-only: one multicast probe, no writes.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::{timeout, Instant};

const WSD_V4: (Ipv4Addr, u16) = (Ipv4Addr::new(239, 255, 255, 250), 3702);

/// Fixed MessageID for the probe. WS-Discovery only requires it to be a unique
/// URI per message; for a one-shot, single-message probe a constant `urn:uuid`
/// is sufficient (and we must not call any time/random API here).
const PROBE_MESSAGE_ID: &str = "urn:uuid:a1b2c3d4-e5f6-7890-abcd-ef0123456789";

/// One device discovered over WS-Discovery.
#[derive(Debug, Clone)]
pub struct WsdHost {
    /// The responding device's IP (the packet source).
    pub ip: IpAddr,
    /// `wsa:Address` from the `EndpointReference`, often a `urn:uuid:...`.
    pub endpoint: Option<String>,
    /// Tokens from `wsd:Types`, e.g. `wsdp:Device`, `pri:PrintDeviceType`,
    /// `dn:NetworkVideoTransmitter`.
    pub types: Vec<String>,
    /// Transport URLs from `wsd:XAddrs`; these usually embed the device IP/host
    /// and a service path.
    pub xaddrs: Vec<String>,
}

/// Send the probe and collect responders for `window`.
pub async fn discover(window: Duration) -> Vec<WsdHost> {
    let Ok(sock) = UdpSocket::bind(("0.0.0.0", 0)).await else {
        return Vec::new();
    };
    let _ = sock.set_multicast_ttl_v4(2);
    let probe = build_probe();

    let mut acc: BTreeMap<IpAddr, WsdHost> = BTreeMap::new();
    let mut buf = vec![0u8; 65536];
    let start = Instant::now();
    let deadline = start + window;
    // Re-send the probe up to three times spread across the window: WSD is lossy
    // UDP and a power-saving device may only wake partway through, so a single
    // probe under-discovers. Between sends we keep listening on short hops.
    let mut sends = 0u32;
    let mut next_send = start;
    loop {
        let now = Instant::now();
        if sends < 3 && now >= next_send {
            if sock.send_to(probe.as_bytes(), WSD_V4).await.is_err() && sends == 0 {
                return Vec::new();
            }
            sends += 1;
            next_send = now + window / 3;
        }
        let remaining = deadline.saturating_duration_since(now);
        if remaining.is_zero() {
            break;
        }
        // Cap the wait so an idle window still cycles back to re-send.
        let recv_wait = remaining.min(Duration::from_millis(400));
        match timeout(recv_wait, sock.recv_from(&mut buf)).await {
            Ok(Ok((n, src))) => {
                if let Ok(xml) = std::str::from_utf8(&buf[..n]) {
                    if let Some(host) = parse_probe_matches(xml, src.ip()) {
                        // Deduplicate by source IP; keep the first response.
                        acc.entry(src.ip()).or_insert(host);
                    }
                }
            }
            Ok(Err(_)) => break, // socket error
            Err(_) => {}         // recv timeout — loop to maybe re-send
        }
    }
    acc.into_values().collect()
}

/// Build the WS-Discovery `Probe` SOAP 1.2 envelope. The `Probe` body is empty
/// (no `Types`), which matches **every** WSD device — printers, cameras, Windows
/// hosts — exactly as Windows' own discovery does. A `Types`-restricted probe
/// would silently miss any device that does not claim that exact QName.
fn build_probe() -> String {
    format!(
        concat!(
            r#"<?xml version="1.0" encoding="utf-8"?>"#,
            r#"<soap:Envelope "#,
            r#"xmlns:soap="http://www.w3.org/2003/05/soap-envelope" "#,
            r#"xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" "#,
            r#"xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">"#,
            r#"<soap:Header>"#,
            r#"<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>"#,
            r#"<wsa:MessageID>{message_id}</wsa:MessageID>"#,
            r#"<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>"#,
            r#"</soap:Header>"#,
            r#"<soap:Body>"#,
            r#"<wsd:Probe/>"#,
            r#"</soap:Body>"#,
            r#"</soap:Envelope>"#,
        ),
        message_id = PROBE_MESSAGE_ID,
    )
}

/// Split a whitespace-separated WSD field (`Types`, `XAddrs`) into tokens.
fn tokens(text: &str) -> Vec<String> {
    text.split_whitespace().map(ToOwned::to_owned).collect()
}

/// Parse a `ProbeMatches` SOAP response. Returns the first `ProbeMatch`'s
/// endpoint/types/xaddrs keyed to the packet source `src`. Element matching is
/// by local tag name so it is agnostic to the responder's namespace prefixes.
fn parse_probe_matches(xml: &str, src: IpAddr) -> Option<WsdHost> {
    let doc = roxmltree::Document::parse(xml).ok()?;

    // A valid reply is a ProbeMatches body; bail out otherwise so unrelated
    // multicast chatter (Hello/Bye/SSDP) does not get logged as a device.
    let has_matches = doc
        .descendants()
        .any(|n| n.tag_name().name() == "ProbeMatches");
    if !has_matches {
        return None;
    }

    let mut endpoint: Option<String> = None;
    let mut types: Vec<String> = Vec::new();
    let mut xaddrs: Vec<String> = Vec::new();

    // Take the first ProbeMatch element if present, else fall back to scanning
    // the whole document (some stacks nest fields directly under the body).
    let scope = doc
        .descendants()
        .find(|n| n.tag_name().name() == "ProbeMatch")
        .unwrap_or_else(|| doc.root_element());

    for node in scope.descendants() {
        if !node.is_element() {
            continue;
        }
        match node.tag_name().name() {
            // wsa:Address inside the EndpointReference.
            "Address" if endpoint.is_none() => {
                if let Some(t) = node.text() {
                    let t = t.trim();
                    if !t.is_empty() {
                        endpoint = Some(t.to_owned());
                    }
                }
            }
            "Types" if types.is_empty() => {
                if let Some(t) = node.text() {
                    types = tokens(t);
                }
            }
            "XAddrs" if xaddrs.is_empty() => {
                if let Some(t) = node.text() {
                    xaddrs = tokens(t);
                }
            }
            _ => {}
        }
    }

    Some(WsdHost {
        ip: src,
        endpoint,
        types,
        xaddrs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_contains_action_and_discovery_namespace() {
        let p = build_probe();
        assert!(p.contains("Probe"), "envelope advertises a Probe");
        assert!(
            p.contains("http://schemas.xmlsoap.org/ws/2005/04/discovery"),
            "discovery namespace present"
        );
        // Hardcoded MessageID, no random/time API.
        assert!(p.contains(PROBE_MESSAGE_ID));
        assert!(p.contains("urn:schemas-xmlsoap-org:ws:2005:04:discovery"));
    }

    #[test]
    fn tokens_splits_on_whitespace() {
        assert_eq!(
            tokens(" wsdp:Device   pri:PrintDeviceType\n"),
            vec!["wsdp:Device".to_owned(), "pri:PrintDeviceType".to_owned()]
        );
        assert!(tokens("   ").is_empty());
    }

    #[test]
    fn parses_a_printer_probe_match() {
        // Realistic ProbeMatches from a network printer: device + print type,
        // an http XAddr carrying the device IP, and a urn:uuid endpoint.
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope
    xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
    xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
    xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"
    xmlns:wsdp="http://schemas.xmlsoap.org/ws/2006/02/devprof"
    xmlns:pri="http://schemas.microsoft.com/windows/2006/08/wdp/print">
  <soap:Header>
    <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches</wsa:Action>
    <wsa:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:To>
  </soap:Header>
  <soap:Body>
    <wsd:ProbeMatches>
      <wsd:ProbeMatch>
        <wsa:EndpointReference>
          <wsa:Address>urn:uuid:11111111-2222-3333-4444-555555555555</wsa:Address>
        </wsa:EndpointReference>
        <wsd:Types>wsdp:Device pri:PrintDeviceType</wsd:Types>
        <wsd:XAddrs>http://192.168.8.40:5357/wsd/print/svc</wsd:XAddrs>
        <wsd:MetadataVersion>1</wsd:MetadataVersion>
      </wsd:ProbeMatch>
    </wsd:ProbeMatches>
  </soap:Body>
</soap:Envelope>"#;

        let src: IpAddr = "192.168.8.40".parse().unwrap();
        let host = parse_probe_matches(xml, src).expect("parses a ProbeMatches reply");

        assert_eq!(host.ip, src);
        assert_eq!(
            host.endpoint.as_deref(),
            Some("urn:uuid:11111111-2222-3333-4444-555555555555")
        );
        assert!(host.types.contains(&"wsdp:Device".to_owned()));
        assert!(host.types.contains(&"pri:PrintDeviceType".to_owned()));
        assert_eq!(host.xaddrs, vec!["http://192.168.8.40:5357/wsd/print/svc"]);
    }

    #[test]
    fn parses_an_onvif_camera_probe_match() {
        // ONVIF cameras advertise dn:NetworkVideoTransmitter and an onvif XAddr.
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope
    xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
    xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
    xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
  <s:Body>
    <d:ProbeMatches>
      <d:ProbeMatch>
        <a:EndpointReference>
          <a:Address>urn:uuid:cafef00d-dead-beef-0000-001122334455</a:Address>
        </a:EndpointReference>
        <d:Types>dn:NetworkVideoTransmitter</d:Types>
        <d:XAddrs>http://192.168.8.77/onvif/device_service</d:XAddrs>
        <d:MetadataVersion>10</d:MetadataVersion>
      </d:ProbeMatch>
    </d:ProbeMatches>
  </s:Body>
</s:Envelope>"#;

        let src: IpAddr = "192.168.8.77".parse().unwrap();
        let host = parse_probe_matches(xml, src).expect("parses an ONVIF reply");
        assert_eq!(host.types, vec!["dn:NetworkVideoTransmitter"]);
        assert_eq!(
            host.xaddrs,
            vec!["http://192.168.8.77/onvif/device_service"]
        );
        assert!(host.endpoint.as_deref().unwrap().starts_with("urn:uuid:"));
    }

    #[test]
    fn rejects_non_probematches_xml() {
        // A Hello announcement is not a ProbeMatches reply.
        let xml = r#"<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">
            <soap:Body><wsd:Hello/></soap:Body></soap:Envelope>"#;
        let src: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(parse_probe_matches(xml, src).is_none());
    }
}
