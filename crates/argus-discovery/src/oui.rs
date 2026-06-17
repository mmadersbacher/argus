//! OUI → vendor lookup. Uses a bundled IEEE OUI snapshot (current, always
//! present, no external dependency); set `ARGUS_OUI_DB` to point at a newer file.

use std::collections::HashMap;

use argus_core::MacAddr;

/// Bundled IEEE MA-L assignments in `nmap-mac-prefixes` format (`AABBCC Vendor`).
/// Regenerate from <https://standards-oui.ieee.org/oui/oui.csv> (MA-L rows only).
const BUNDLED: &str = include_str!("../data/oui-prefixes.txt");

/// An OUI (24-bit MAC prefix) → vendor lookup table.
pub struct OuiDb {
    map: HashMap<[u8; 3], String>,
}

impl OuiDb {
    /// Load the OUI table: an `ARGUS_OUI_DB` file if set and non-empty, else the
    /// bundled IEEE snapshot (so vendor lookup always works, with or without nmap).
    #[must_use]
    pub fn load() -> Self {
        if let Ok(path) = std::env::var("ARGUS_OUI_DB") {
            if let Ok(contents) = std::fs::read_to_string(&path) {
                let map = parse(&contents);
                if !map.is_empty() {
                    return Self { map };
                }
            }
        }
        Self {
            map: parse(BUNDLED),
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

    #[test]
    fn bundled_db_loads_and_resolves_modern_ouis() {
        let db = OuiDb::load();
        assert!(
            db.len() > 30_000,
            "bundled IEEE db should hold tens of thousands of prefixes, got {}",
            db.len()
        );
        // 1C:AF:4A (Samsung) was absent from the 2019 nmap db; the IEEE snapshot has it.
        assert!(db
            .vendor(MacAddr([0x1C, 0xAF, 0x4A, 0, 0, 0]))
            .is_some_and(|v| v.contains("Samsung")));
    }
}
