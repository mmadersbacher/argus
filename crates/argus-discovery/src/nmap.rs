//! nmap orchestration: run nmap (connect scan, no root) and parse its XML into
//! discovered hosts with real service/version fingerprints.
//!
//! OS and MAC detection require root and are not requested here; MAC/vendor is
//! enriched separately (ARP table + OUI lookup).

use std::net::IpAddr;
use std::process::Stdio;
use std::str::FromStr;
use std::time::Duration;

use argus_core::{Asset, AssetId, Criticality, Exposure, Interface, MacAddr, Protocol, Service};
use roxmltree::Node;
use time::OffsetDateTime;
use tokio::process::Command;
use tokio::time::timeout;

use crate::{fingerprint, DiscoveredHost};

/// Errors from running or parsing nmap.
#[derive(Debug)]
pub enum NmapError {
    /// Failed to spawn the `nmap` process.
    Spawn(std::io::Error),
    /// nmap did not finish within the timeout.
    Timeout,
    /// Could not parse nmap's XML output.
    Parse(String),
}

impl std::fmt::Display for NmapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Spawn(e) => write!(f, "failed to run nmap: {e}"),
            Self::Timeout => write!(f, "nmap timed out"),
            Self::Parse(e) => write!(f, "failed to parse nmap output: {e}"),
        }
    }
}

impl std::error::Error for NmapError {}

/// Whether the `nmap` binary is runnable.
pub async fn available() -> bool {
    Command::new("nmap")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .is_ok_and(|s| s.success())
}

/// Run nmap against `spec` (IP/CIDR/host) restricted to `ports`, returning hosts.
///
/// Uses a TCP connect scan with light service/version detection, which needs no
/// elevated privileges.
///
/// # Errors
/// See [`NmapError`].
pub async fn scan(
    spec: &str,
    ports: &[u16],
    run_timeout: Duration,
) -> Result<Vec<DiscoveredHost>, NmapError> {
    run(
        spec,
        ports,
        run_timeout,
        &["-sT", "-sV", "--version-light", "-T4"],
    )
    .await
}

/// Run nmap with a SYN scan and OS detection (`-sS -O`) against `spec`.
///
/// Both flags send raw packets, so this needs root / `cap_net_raw`. Matched
/// hosts carry an `os` fingerprint (parsed from `<osmatch>`); without privileges
/// nmap cannot OS-match and [`scan`] is the better choice.
///
/// # Errors
/// See [`NmapError`].
pub async fn scan_os(
    spec: &str,
    ports: &[u16],
    run_timeout: Duration,
) -> Result<Vec<DiscoveredHost>, NmapError> {
    run(
        spec,
        ports,
        run_timeout,
        &["-sS", "-sV", "--version-light", "-O", "-T4"],
    )
    .await
}

/// Shared nmap runner. `scan_args` selects the scan type (connect vs SYN+OS);
/// the rest of the invocation (`-n -p … -oX -`) and XML parsing is common.
async fn run(
    spec: &str,
    ports: &[u16],
    run_timeout: Duration,
    scan_args: &[&str],
) -> Result<Vec<DiscoveredHost>, NmapError> {
    let port_list = ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let output = timeout(
        run_timeout,
        Command::new("nmap")
            .args(scan_args)
            .args(["-n", "-p", &port_list, "-oX", "-", spec])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output(),
    )
    .await
    .map_err(|_| NmapError::Timeout)?
    .map_err(NmapError::Spawn)?;

    let mut hosts = parse(&String::from_utf8_lossy(&output.stdout))?;
    crate::enrich_macs(&mut hosts);
    Ok(hosts)
}

/// Parse nmap XML (`-oX`) into discovered hosts.
///
/// Public so external `nmap -oX` exports can be imported, not only live scans.
/// Unlike [`scan`], this does not run ARP/OUI enrichment — imported XML carries
/// its own MAC/vendor data and the local ARP cache would not apply to it.
///
/// # Errors
/// Returns [`NmapError::Parse`] if the input is not valid nmap XML.
pub fn parse(xml: &str) -> Result<Vec<DiscoveredHost>, NmapError> {
    // nmap emits `<!DOCTYPE nmaprun>`, so DTDs must be allowed.
    let opts = roxmltree::ParsingOptions {
        allow_dtd: true,
        ..Default::default()
    };
    let doc = roxmltree::Document::parse_with_options(xml, opts)
        .map_err(|e| NmapError::Parse(e.to_string()))?;
    let now = OffsetDateTime::now_utc();
    Ok(doc
        .descendants()
        .filter(|n| n.has_tag_name("host"))
        .filter_map(|host| parse_host(host, now))
        .collect())
}

fn parse_host(host: Node<'_, '_>, now: OffsetDateTime) -> Option<DiscoveredHost> {
    let up = host
        .children()
        .find(|n| n.has_tag_name("status"))
        .and_then(|s| s.attribute("state"))
        .is_none_or(|st| st == "up");
    if !up {
        return None;
    }

    let mut ip: Option<IpAddr> = None;
    let mut mac: Option<MacAddr> = None;
    let mut vendor: Option<String> = None;
    for addr in host.children().filter(|n| n.has_tag_name("address")) {
        match addr.attribute("addrtype") {
            Some("ipv4" | "ipv6") => {
                ip = addr
                    .attribute("addr")
                    .and_then(|a| IpAddr::from_str(a).ok());
            }
            Some("mac") => {
                mac = addr.attribute("addr").and_then(MacAddr::parse);
                vendor = addr.attribute("vendor").map(str::to_owned);
            }
            _ => {}
        }
    }
    let ip = ip?;

    let hostname = host
        .descendants()
        .find(|n| n.has_tag_name("hostname"))
        .and_then(|h| h.attribute("name"))
        .map(str::to_owned);

    let (services, mut open_ports) = parse_ports(host);
    open_ports.sort_unstable();

    let os = host
        .descendants()
        .find(|n| n.has_tag_name("osmatch"))
        .and_then(|o| o.attribute("name"))
        .map(str::to_owned);

    let (asset_type, mut fingerprint) = fingerprint::classify(&open_ports);
    if os.is_some() {
        fingerprint.os = os;
    }
    if vendor.is_some() {
        fingerprint.vendor = vendor;
    }
    fingerprint.confidence = fingerprint.confidence.max(60); // nmap gives real evidence
    let insecure_score = fingerprint::insecure_service_score(&open_ports);

    let asset = Asset {
        id: AssetId::new(),
        asset_type,
        criticality: Criticality::Medium,
        exposure: if crate::is_internal(ip) {
            Exposure::Internal
        } else {
            Exposure::InternetFacing
        },
        fingerprint,
        interfaces: vec![Interface {
            mac,
            ip: Some(ip),
            vlan: None,
            hostname,
        }],
        first_seen: now,
        last_seen: now,
    };
    Some(DiscoveredHost {
        asset,
        services,
        open_ports,
        insecure_score,
    })
}

fn parse_ports(host: Node<'_, '_>) -> (Vec<Service>, Vec<u16>) {
    let mut services = Vec::new();
    let mut open_ports = Vec::new();
    let Some(ports_node) = host.children().find(|n| n.has_tag_name("ports")) else {
        return (services, open_ports);
    };
    for port in ports_node.children().filter(|n| n.has_tag_name("port")) {
        let is_open = port
            .children()
            .find(|n| n.has_tag_name("state"))
            .and_then(|s| s.attribute("state"))
            .is_some_and(|st| st == "open");
        if !is_open {
            continue;
        }
        let Some(portid) = port.attribute("portid").and_then(|p| p.parse::<u16>().ok()) else {
            continue;
        };
        open_ports.push(portid);
        let service = port.children().find(|n| n.has_tag_name("service"));
        let product = service.and_then(service_label);
        let cpe = service.and_then(service_cpe);
        services.push(Service {
            port: portid,
            protocol: Protocol::Tcp,
            product,
            banner: None,
            cpe,
        });
    }
    (services, open_ports)
}

/// The service's application CPE (`cpe:/a:…`), if nmap reported one.
///
/// A `<service>` may carry several `<cpe>` children (application, OS,
/// hardware); only the application entry identifies the vulnerable software,
/// so the OS/hardware ones are skipped.
fn service_cpe(svc: Node<'_, '_>) -> Option<String> {
    svc.children()
        .filter(|n| n.has_tag_name("cpe"))
        .filter_map(|n| n.text())
        .find(|t| t.starts_with("cpe:/a:") || t.starts_with("cpe:2.3:a:"))
        .map(str::to_owned)
}

fn service_label(svc: Node<'_, '_>) -> Option<String> {
    let name = svc.attribute("name").unwrap_or("");
    let prod = svc.attribute("product").unwrap_or("");
    let ver = svc.attribute("version").unwrap_or("");
    let mut label = if prod.is_empty() {
        name.to_owned()
    } else {
        prod.to_owned()
    };
    if !ver.is_empty() {
        label.push(' ');
        label.push_str(ver);
    }
    if label.is_empty() {
        None
    } else {
        Some(label)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Includes the `<!DOCTYPE nmaprun>` that nmap emits — regression guard for
    // the DTD-handling bug.
    const SAMPLE: &str = r#"<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun><host>
        <status state="up"/>
        <address addr="192.168.1.10" addrtype="ipv4"/>
        <address addr="00:11:22:33:44:55" addrtype="mac" vendor="Acme"/>
        <hostnames><hostname name="box.local"/></hostnames>
        <ports>
          <port protocol="tcp" portid="22"><state state="open"/>
            <service name="ssh" product="OpenSSH" version="8.9p1">
              <cpe>cpe:/o:linux:linux_kernel</cpe>
              <cpe>cpe:/a:openbsd:openssh:8.9p1</cpe>
            </service></port>
          <port protocol="tcp" portid="23"><state state="closed"/></port>
        </ports></host></nmaprun>"#;

    #[test]
    fn parses_open_ports_mac_and_service_version() {
        let hosts = parse(SAMPLE).expect("parse");
        assert_eq!(hosts.len(), 1);
        let h = &hosts[0];
        assert_eq!(h.open_ports, vec![22]);
        let iface = &h.asset.interfaces[0];
        assert_eq!(iface.ip.unwrap().to_string(), "192.168.1.10");
        assert_eq!(iface.mac.unwrap().to_string(), "00:11:22:33:44:55");
        assert_eq!(h.asset.fingerprint.vendor.as_deref(), Some("Acme"));
        let ssh = h
            .services
            .iter()
            .find(|s| s.product.as_deref() == Some("OpenSSH 8.9p1"))
            .expect("ssh service");
        // The application CPE is captured; the OS CPE sibling is skipped.
        assert_eq!(ssh.cpe.as_deref(), Some("cpe:/a:openbsd:openssh:8.9p1"));
    }

    #[test]
    fn malformed_xml_is_an_error() {
        assert!(parse("<nmaprun><host").is_err());
    }
}
