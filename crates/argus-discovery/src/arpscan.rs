//! Active ARP host discovery: the L2 primitive that finds **every** powered-on
//! device on the local segment, including ones a TCP-connect scan can never see.
//!
//! A connect scan only surfaces a host once it answers on an open TCP port, and
//! mDNS only surfaces devices that advertise. A phone with a host firewall, a
//! camera speaking only a proprietary UDP protocol, or a printer asleep on every
//! scanned port are all invisible to those engines — yet each must answer an ARP
//! request to participate in the network at all. ARP sits below the firewall, so
//! an active ARP sweep of the local subnet is the closest thing to ground truth
//! for "what is plugged in here".
//!
//! This shells out to `arp-scan` (the same shell-out pattern as [`crate::masscan`]
//! and [`crate::nmap`]) rather than crafting raw frames in-process: arp-scan is
//! purpose-built, handles retransmits, and needs the same `cap_net_raw` / root
//! privilege a hand-rolled `AF_PACKET` sender would. Like masscan, [`available`]
//! only checks the binary exists; a privilege failure surfaces at runtime as an
//! empty sweep, which callers treat as "nothing found".

use std::net::IpAddr;
use std::process::Stdio;
use std::str::FromStr;
use std::time::Duration;

use argus_core::MacAddr;
use tokio::process::Command;
use tokio::time::timeout;

/// Errors from running arp-scan. Parse failures are intentionally absent: the
/// output is line-oriented and unparseable lines (headers/footers) are skipped.
#[derive(Debug)]
pub enum ArpScanError {
    /// Failed to spawn the `arp-scan` process.
    Spawn(std::io::Error),
    /// arp-scan did not finish within the timeout.
    Timeout,
}

impl std::fmt::Display for ArpScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Spawn(e) => write!(f, "failed to run arp-scan: {e}"),
            Self::Timeout => write!(f, "arp-scan timed out"),
        }
    }
}

impl std::error::Error for ArpScanError {}

/// One device that answered an ARP request: its IP and the MAC behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpHost {
    /// The responding address (always IPv4 — ARP is IPv4-only).
    pub ip: IpAddr,
    /// The hardware address that replied. Resolved to an OUI vendor later by
    /// [`crate::enrich_macs`] against the IEEE database, for consistency with
    /// MACs obtained from the kernel cache or NetBIOS.
    pub mac: MacAddr,
}

/// Whether the `arp-scan` binary is runnable. Does not verify raw-socket access.
pub async fn available() -> bool {
    Command::new("arp-scan")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .is_ok_and(|s| s.success())
}

/// Active ARP sweep of `targets` (IPv4 only), returning the devices that replied.
///
/// arp-scan auto-selects the outgoing interface from the routing table, so only
/// directly-attached (same L2 segment) targets can answer — exactly the intended
/// scope. Requires raw-socket privileges (root / `cap_net_raw`); without them
/// arp-scan emits no results and this returns an empty vector rather than an error.
///
/// # Errors
/// Returns [`ArpScanError::Spawn`] if arp-scan cannot be launched, or
/// [`ArpScanError::Timeout`] if it does not finish within `run_timeout`.
pub async fn sweep(
    targets: &[IpAddr],
    run_timeout: Duration,
) -> Result<Vec<ArpHost>, ArpScanError> {
    let hosts: Vec<String> = targets
        .iter()
        .filter(|ip| ip.is_ipv4())
        .map(ToString::to_string)
        .collect();
    if hosts.is_empty() {
        return Ok(Vec::new());
    }

    // `--quiet` suppresses the per-host vendor lookup banner noise; `--ignoredups`
    // keeps one row per address. Explicit targets (not `--localnet`) honor the
    // caller's scope exactly. `--retry=3` matters on power-saving Wi-Fi LANs:
    // sleeping clients miss the first ARP request, so a single try under-counts.
    // Even so, no one sweep is complete on such a segment — full coverage comes
    // from unioning repeated scans in the persistent asset store.
    let mut cmd = Command::new("arp-scan");
    cmd.args(["--quiet", "--ignoredups", "--retry=3"]);
    cmd.args(&hosts);
    cmd.stdout(Stdio::piped()).stderr(Stdio::null());

    let output = timeout(run_timeout, cmd.output())
        .await
        .map_err(|_| ArpScanError::Timeout)?
        .map_err(ArpScanError::Spawn)?;

    Ok(parse(&String::from_utf8_lossy(&output.stdout)))
}

/// Parse arp-scan output into the responding hosts.
///
/// Result rows are `<ip>\t<mac>[\t<vendor>]`; the leading `Interface:` /
/// `Starting arp-scan` banner and the trailing `N packets received` / `Ending`
/// footer have no parseable `(IPv4, MAC)` pair in their first two columns and are
/// skipped — the same forgiving, comment-blind approach as [`crate::masscan::parse`].
/// Duplicate IPs keep the first MAC seen.
#[must_use]
pub fn parse(out: &str) -> Vec<ArpHost> {
    let mut seen = std::collections::HashSet::new();
    let mut hosts = Vec::new();
    for line in out.lines() {
        let mut cols = line.split_whitespace();
        let (Some(ip_s), Some(mac_s)) = (cols.next(), cols.next()) else {
            continue;
        };
        let Ok(ip) = IpAddr::from_str(ip_s) else {
            continue;
        };
        let Some(mac) = MacAddr::parse(mac_s) else {
            continue;
        };
        if mac.0 == [0u8; 6] || !seen.insert(ip) {
            continue;
        }
        hosts.push(ArpHost { ip, mac });
    }
    hosts
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str =
        "Interface: eth0, type: EN10MB, MAC: 5e:bb:f6:9e:ee:fa, IPv4: 192.168.8.106\n\
        Starting arp-scan 1.10.0 with 256 hosts\n\
        192.168.8.1\t62:96:ad:e4:79:00\t(Unknown: locally administered)\n\
        192.168.8.189\t74:56:3c:6e:a7:c6\tGIGA-BYTE TECHNOLOGY CO.,LTD.\n\
        \n\
        3 packets received by filter, 0 packets dropped by kernel\n\
        Ending arp-scan 1.10.0: 256 hosts scanned in 0.994 seconds\n";

    #[test]
    fn parses_result_rows_skips_banner_and_footer() {
        let hosts = parse(SAMPLE);
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].ip.to_string(), "192.168.8.1");
        assert_eq!(hosts[0].mac, MacAddr::parse("62:96:ad:e4:79:00").unwrap());
        assert_eq!(hosts[1].ip.to_string(), "192.168.8.189");
    }

    #[test]
    fn skips_incomplete_zero_mac() {
        let hosts = parse("192.168.8.7\t00:00:00:00:00:00\n");
        assert!(hosts.is_empty());
    }

    #[test]
    fn dedups_repeated_ip_keeps_first() {
        let input = "192.168.8.1\taa:bb:cc:dd:ee:ff\n192.168.8.1\t11:22:33:44:55:66\n";
        let hosts = parse(input);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].mac, MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap());
    }

    #[test]
    fn empty_targets_is_ok_empty() {
        // Pure parse path; sweep's early return is covered by hosts.is_empty().
        assert!(parse("").is_empty());
    }
}
