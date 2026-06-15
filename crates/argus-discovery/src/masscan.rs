//! masscan orchestration: a high-speed asynchronous SYN sweep used to find open
//! ports across large ranges quickly, before handing the live host:port set to
//! [`crate::nmap`] for service/OS detail.
//!
//! masscan needs raw sockets (root or the `cap_net_raw` capability). [`available`]
//! only checks the binary is present, not that it can bind raw sockets — a
//! privilege failure surfaces at runtime as an empty sweep (masscan exits with a
//! diagnostic on stderr but spawns fine), which callers treat as "nothing found".

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::process::Stdio;
use std::str::FromStr;
use std::time::Duration;

use tokio::process::Command;
use tokio::time::timeout;

/// Default sweep rate in packets/second — faster than the connect scanner.
///
/// A moderate default, but raw SYN sweeping at any rate is **not** guaranteed
/// safe for fragile OT/ICS devices. Lower the rate for sensitive segments, or
/// avoid masscan entirely there and use the payload-free connect scanner.
pub const DEFAULT_RATE: u32 = 1_000;

/// Errors from running masscan. Parse failures are intentionally absent: the
/// grepable `-oL` format is line-oriented and unparseable lines are skipped.
#[derive(Debug)]
pub enum MasscanError {
    /// Failed to spawn the `masscan` process.
    Spawn(std::io::Error),
    /// masscan did not finish within the timeout.
    Timeout,
}

impl std::fmt::Display for MasscanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Spawn(e) => write!(f, "failed to run masscan: {e}"),
            Self::Timeout => write!(f, "masscan timed out"),
        }
    }
}

impl std::error::Error for MasscanError {}

/// One host found by a sweep: an IP and the open TCP ports observed on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweepHost {
    /// The responsive address.
    pub ip: IpAddr,
    /// Open TCP ports, sorted and de-duplicated.
    pub ports: Vec<u16>,
}

/// Whether the `masscan` binary is runnable. Does not verify raw-socket access.
pub async fn available() -> bool {
    Command::new("masscan")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .is_ok_and(|s| s.success())
}

/// High-speed SYN sweep of `spec` (IP/CIDR/range) over `ports` at `rate`
/// packets/second, returning the live host:port set.
///
/// Uses masscan's grepable list output (`-oL -`). Requires raw-socket
/// privileges; without them masscan emits no results and this returns an empty
/// vector rather than an error.
///
/// # Errors
/// Returns [`MasscanError::Spawn`] if masscan cannot be launched, or
/// [`MasscanError::Timeout`] if it does not finish within `run_timeout`.
pub async fn sweep(
    spec: &str,
    ports: &[u16],
    rate: u32,
    run_timeout: Duration,
) -> Result<Vec<SweepHost>, MasscanError> {
    let port_list = ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let output = timeout(
        run_timeout,
        Command::new("masscan")
            .args([
                spec,
                "-p",
                &port_list,
                "--rate",
                &rate.to_string(),
                "--wait",
                "0",
                "-oL",
                "-",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output(),
    )
    .await
    .map_err(|_| MasscanError::Timeout)?
    .map_err(MasscanError::Spawn)?;

    Ok(parse(&String::from_utf8_lossy(&output.stdout)))
}

/// Parse masscan's grepable list (`-oL`) into hosts grouped by IP.
///
/// Each result line looks like `open tcp 80 192.0.2.10 1719000000`; comment
/// lines (`#masscan`, `# end`) and anything that is not an open TCP record are
/// ignored. Ports are sorted and de-duplicated per host.
#[must_use]
pub fn parse(list: &str) -> Vec<SweepHost> {
    let mut by_ip: BTreeMap<IpAddr, Vec<u16>> = BTreeMap::new();
    for line in list.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // `open <proto> <port> <ip> <timestamp>`
        if fields.len() < 5 || fields[0] != "open" || fields[1] != "tcp" {
            continue;
        }
        let (Ok(port), Ok(ip)) = (fields[2].parse::<u16>(), IpAddr::from_str(fields[3])) else {
            continue;
        };
        by_ip.entry(ip).or_default().push(port);
    }
    by_ip
        .into_iter()
        .map(|(ip, mut ports)| {
            ports.sort_unstable();
            ports.dedup();
            SweepHost { ip, ports }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "#masscan\n\
        open tcp 80 192.0.2.10 1719000000\n\
        open tcp 22 192.0.2.10 1719000000\n\
        open tcp 443 192.0.2.20 1719000000\n\
        # end\n";

    #[test]
    fn groups_open_ports_by_host_sorted() {
        let hosts = parse(SAMPLE);
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].ip.to_string(), "192.0.2.10");
        assert_eq!(hosts[0].ports, vec![22, 80]);
        assert_eq!(hosts[1].ip.to_string(), "192.0.2.20");
        assert_eq!(hosts[1].ports, vec![443]);
    }

    #[test]
    fn ignores_comments_and_non_open_lines() {
        let input = "# masscan 1.3\nclosed tcp 25 192.0.2.10 1\ngarbage line\n";
        assert!(parse(input).is_empty());
    }

    #[test]
    fn dedups_repeated_ports() {
        let input = "open tcp 80 192.0.2.10 1\nopen tcp 80 192.0.2.10 2\n";
        let hosts = parse(input);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].ports, vec![80]);
    }
}
