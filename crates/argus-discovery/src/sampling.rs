//! runZero-style subnet sampling: cheaply probe a sample of each /24 and only
//! keep the subnets that show signs of life, so dead /24s within a scanned
//! range are skipped before the full port scan.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use crate::portscan;

/// Commonly-used host/gateway octets — cheap, high-signal sample points.
pub const SAMPLE_OCTETS: &[u8] = &[1, 2, 100, 101, 200, 254];

/// Ports probed to detect a live host during sampling.
pub const PROBE_PORTS: &[u16] = &[80, 443, 22, 445, 3389];

/// /24 buckets at or below this size are kept without sampling (not worth it).
const SAMPLE_THRESHOLD: usize = 8;

/// Return the subset of `targets` that lies in /24s showing signs of life.
///
/// IPv4 targets are grouped by /24; small buckets are kept as-is, larger ones
/// are kept only if a sample address in the /24 responds. Non-IPv4 targets pass
/// through unchanged.
pub async fn responsive_targets(targets: &[IpAddr], connect_timeout: Duration) -> Vec<IpAddr> {
    let mut buckets: BTreeMap<[u8; 3], Vec<Ipv4Addr>> = BTreeMap::new();
    let mut keep: Vec<IpAddr> = Vec::new();

    for &ip in targets {
        match ip {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                buckets.entry([o[0], o[1], o[2]]).or_default().push(v4);
            }
            IpAddr::V6(_) => keep.push(ip),
        }
    }

    for (prefix, hosts) in buckets {
        if hosts.len() <= SAMPLE_THRESHOLD {
            keep.extend(hosts.into_iter().map(IpAddr::V4));
            continue;
        }
        let mut alive = false;
        for &octet in SAMPLE_OCTETS {
            let probe = IpAddr::V4(Ipv4Addr::new(prefix[0], prefix[1], prefix[2], octet));
            if portscan::host_responds(probe, PROBE_PORTS, connect_timeout).await {
                alive = true;
                break;
            }
        }
        if alive {
            keep.extend(hosts.into_iter().map(IpAddr::V4));
        }
    }

    keep
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn small_bucket_passes_through_without_probing() {
        let targets: Vec<IpAddr> = (1..=5)
            .map(|o| IpAddr::V4(Ipv4Addr::new(10, 0, 0, o)))
            .collect();
        let kept = responsive_targets(&targets, Duration::from_millis(50)).await;
        assert_eq!(kept.len(), 5);
    }

    #[tokio::test]
    async fn ipv6_passes_through() {
        let targets = vec![IpAddr::V6("::1".parse().unwrap())];
        let kept = responsive_targets(&targets, Duration::from_millis(50)).await;
        assert_eq!(kept.len(), 1);
    }
}
