//! Read the system ARP cache to map local IPs to MAC addresses — no privileges
//! required. Linux reads `/proc/net/arp`; Windows shells out to `arp -a`.

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

/// Parse Windows `arp -a` output into an IP→MAC map.
///
/// Rows look like `192.168.1.1   aa-bb-cc-dd-ee-ff   dynamic`. Interface and
/// header lines have no parseable IP in the first column and are skipped, so
/// this is locale-independent (works on a German `arp -a` too).
#[cfg(any(windows, test))]
fn parse_windows_arp(out: &str) -> HashMap<IpAddr, MacAddr> {
    let mut map = HashMap::new();
    for line in out.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 2 {
            continue;
        }
        let Ok(ip) = IpAddr::from_str(cols[0]) else {
            continue;
        };
        let Some(mac) = MacAddr::parse(cols[1]) else {
            continue;
        };
        if mac.0 == [0u8; 6] {
            continue;
        }
        map.insert(ip, mac);
    }
    map
}

/// Read the system ARP cache. Returns an empty map on error.
#[must_use]
pub fn read_arp_table() -> HashMap<IpAddr, MacAddr> {
    #[cfg(windows)]
    {
        std::process::Command::new("arp")
            .arg("-a")
            .output()
            .ok()
            .map(|o| parse_windows_arp(&String::from_utf8_lossy(&o.stdout)))
            .unwrap_or_default()
    }
    #[cfg(not(windows))]
    {
        std::fs::read_to_string("/proc/net/arp")
            .map(|s| parse_arp_table(&s))
            .unwrap_or_default()
    }
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

    // A German `arp -a` dump: interface/header lines have no IP in column 0 and
    // are skipped; MAC uses `-` separators.
    const WIN_SAMPLE: &str = "
Schnittstelle: 10.3.0.164 --- 0xf
  Internetadresse       Physische Adresse     Typ
  10.3.0.1              9a-1e-c0-f1-ed-69     dynamisch
  10.3.0.24             1c-af-4a-76-b9-98     dynamisch
  10.3.0.255            ff-ff-ff-ff-ff-ff     statisch
";

    #[test]
    fn parses_windows_arp_dump() {
        let map = parse_windows_arp(WIN_SAMPLE);
        let gw: IpAddr = "10.3.0.1".parse().unwrap();
        assert_eq!(map.get(&gw).unwrap().to_string(), "9a:1e:c0:f1:ed:69");
        assert!(map.contains_key(&"10.3.0.24".parse::<IpAddr>().unwrap()));
        // Header/interface lines are not hosts.
        assert!(!map.keys().any(|ip| ip.to_string() == "0xf"));
    }
}
