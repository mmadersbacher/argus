//! OUI → vendor lookup, loaded from nmap's `nmap-mac-prefixes` database.

use std::collections::HashMap;

use argus_core::MacAddr;

const CANDIDATE_PATHS: &[&str] = &[
    "/usr/share/nmap/nmap-mac-prefixes",
    "/usr/local/share/nmap/nmap-mac-prefixes",
];

/// An OUI (24-bit MAC prefix) → vendor lookup table.
pub struct OuiDb {
    map: HashMap<[u8; 3], String>,
}

impl OuiDb {
    /// Load from the first available `nmap-mac-prefixes` file. Empty if none found.
    #[must_use]
    pub fn load() -> Self {
        for path in CANDIDATE_PATHS {
            if let Ok(contents) = std::fs::read_to_string(path) {
                return Self {
                    map: parse(&contents),
                };
            }
        }
        Self {
            map: HashMap::new(),
        }
    }

    /// Whether the table is empty (database not found).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Number of known OUIs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Look up the vendor for a MAC address's OUI.
    #[must_use]
    pub fn vendor(&self, mac: MacAddr) -> Option<&str> {
        self.map.get(&mac.oui()).map(String::as_str)
    }
}

/// Parse `nmap-mac-prefixes` content (lines like `0001C8 Thomas-Conrad`).
fn parse(contents: &str) -> HashMap<[u8; 3], String> {
    let mut map = HashMap::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((prefix, vendor)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        if prefix.len() != 6 {
            continue;
        }
        let Ok(bits) = u32::from_str_radix(prefix, 16) else {
            continue;
        };
        let oui = [
            ((bits >> 16) & 0xff) as u8,
            ((bits >> 8) & 0xff) as u8,
            (bits & 0xff) as u8,
        ];
        map.insert(oui, vendor.trim().to_owned());
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "# nmap mac prefixes
AABBCC Acme Corp
0001C8 Thomas-Conrad
";

    #[test]
    fn parses_and_looks_up_vendor() {
        let db = OuiDb { map: parse(SAMPLE) };
        assert_eq!(db.len(), 2);
        assert_eq!(
            db.vendor(MacAddr([0xAA, 0xBB, 0xCC, 0x12, 0x34, 0x56])),
            Some("Acme Corp")
        );
        assert_eq!(
            db.vendor(MacAddr([0x00, 0x01, 0xC8, 0, 0, 0])),
            Some("Thomas-Conrad")
        );
        assert_eq!(db.vendor(MacAddr([0xFF, 0xFF, 0xFF, 0, 0, 0])), None);
    }
}
