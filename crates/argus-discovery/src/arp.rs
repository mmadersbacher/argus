//! Read the kernel ARP cache (`/proc/net/arp`) to map local IPs to MAC
//! addresses — no privileges required (Linux only).

use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;

use argus_core::MacAddr;

/// Parse the contents of `/proc/net/arp` into an IP→MAC map.
///
/// Incomplete entries (`00:00:00:00:00:00`) are skipped.
#[must_use]
pub fn parse_arp_table(contents: &str) -> HashMap<IpAddr, MacAddr> {
    let mut map = HashMap::new();
    // Columns: IP address | HW type | Flags | HW address | Mask | Device
    for line in contents.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 4 {
            continue;
        }
        let Ok(ip) = IpAddr::from_str(cols[0]) else {
            continue;
        };
        let Some(mac) = MacAddr::parse(cols[3]) else {
            continue;
        };
        if mac.0 == [0u8; 6] {
            continue;
        }
        map.insert(ip, mac);
    }
    map
}

/// Read the system ARP cache. Returns an empty map on non-Linux or on error.
#[must_use]
pub fn read_arp_table() -> HashMap<IpAddr, MacAddr> {
    std::fs::read_to_string("/proc/net/arp")
        .map(|s| parse_arp_table(&s))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str =
        "IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
192.168.1.99     0x1         0x0         00:00:00:00:00:00     *        eth0
";

    #[test]
    fn parses_complete_entries_and_skips_incomplete() {
        let map = parse_arp_table(SAMPLE);
        assert_eq!(map.len(), 1);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert_eq!(map.get(&ip).unwrap().to_string(), "aa:bb:cc:dd:ee:ff");
        assert!(!map.contains_key(&"192.168.1.99".parse::<IpAddr>().unwrap()));
    }
}
