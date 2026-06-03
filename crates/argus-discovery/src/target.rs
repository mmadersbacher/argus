//! Parse a scan-target spec into concrete host IPs, with a safety cap.

use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;

/// Maximum number of hosts a single light-mode scan will expand to.
pub const MAX_HOSTS: usize = 1024;

/// Error parsing or expanding a target spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetError {
    /// The spec was neither a valid IP nor a valid CIDR.
    Parse(String),
    /// The CIDR expands to more hosts than [`MAX_HOSTS`].
    TooLarge {
        /// Number of hosts the range would contain.
        hosts: u128,
        /// The configured maximum.
        max: usize,
    },
}

impl std::fmt::Display for TargetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(s) => write!(f, "invalid target '{s}' (expected IP or CIDR)"),
            Self::TooLarge { hosts, max } => {
                write!(
                    f,
                    "range too large: {hosts} hosts (max {max} in light mode)"
                )
            }
        }
    }
}

impl std::error::Error for TargetError {}

/// Expand a target spec into host IP addresses.
///
/// Accepts a single IP (`10.0.0.5`, `::1`) or a CIDR (`10.0.0.0/24`). The host
/// count is derived from the prefix length *before* enumeration, so an
/// oversized range is rejected without allocating it.
pub fn expand(spec: &str) -> Result<Vec<IpAddr>, TargetError> {
    let spec = spec.trim();
    if let Ok(ip) = IpAddr::from_str(spec) {
        return Ok(vec![ip]);
    }
    let net = IpNet::from_str(spec).map_err(|e| TargetError::Parse(e.to_string()))?;
    let addr_bits: u32 = if net.network().is_ipv4() { 32 } else { 128 };
    let host_bits = addr_bits - u32::from(net.prefix_len());
    let count = 1u128.checked_shl(host_bits).unwrap_or(u128::MAX);
    if count > MAX_HOSTS as u128 {
        return Err(TargetError::TooLarge {
            hosts: count,
            max: MAX_HOSTS,
        });
    }
    Ok(net.hosts().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_ip_yields_one() {
        assert_eq!(expand("10.0.0.5").unwrap().len(), 1);
    }

    #[test]
    fn small_cidr_excludes_network_and_broadcast() {
        // a /30 has 2 usable hosts
        assert_eq!(expand("192.168.1.0/30").unwrap().len(), 2);
    }

    #[test]
    fn oversized_range_is_rejected_without_allocating() {
        assert!(matches!(
            expand("10.0.0.0/8"),
            Err(TargetError::TooLarge { .. })
        ));
    }

    #[test]
    fn garbage_is_a_parse_error() {
        assert!(matches!(expand("not-an-ip"), Err(TargetError::Parse(_))));
    }
}
