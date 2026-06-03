//! Network-level entities: MAC addresses, interfaces, and services.

use std::net::IpAddr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A 48-bit IEEE 802 MAC address.
///
/// Serializes to and from the canonical `aa:bb:cc:dd:ee:ff` string form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    /// The 24-bit Organizationally Unique Identifier (first three octets),
    /// used for vendor lookup.
    #[must_use]
    pub fn oui(&self) -> [u8; 3] {
        [self.0[0], self.0[1], self.0[2]]
    }

    /// Parse a canonical `aa:bb:cc:dd:ee:ff` MAC string.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let mut bytes = [0u8; 6];
        let mut count = 0usize;
        for part in s.split(':') {
            if count >= 6 {
                return None;
            }
            bytes[count] = u8::from_str_radix(part, 16).ok()?;
            count += 1;
        }
        (count == 6).then_some(Self(bytes))
    }
}

impl std::fmt::Display for MacAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let b = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5]
        )
    }
}

impl Serialize for MacAddr {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for MacAddr {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| D::Error::custom(format!("invalid MAC address: {s}")))
    }
}

/// Transport / network protocol of an observed [`Service`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol.
    Udp,
    /// Internet Control Message Protocol.
    Icmp,
    /// Any other / unidentified protocol.
    Other,
}

/// A network service observed on an asset (an open port and what we know about it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Service {
    /// Port number the service listens on.
    pub port: u16,
    /// Transport protocol.
    pub protocol: Protocol,
    /// Detected product/service name (e.g. `OpenSSH`), if known.
    pub product: Option<String>,
    /// Raw banner text, if captured.
    pub banner: Option<String>,
}

/// A network interface belonging to an asset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Interface {
    /// Hardware (MAC) address, if known.
    pub mac: Option<MacAddr>,
    /// IP address bound to the interface, if known.
    pub ip: Option<IpAddr>,
    /// VLAN id, if known.
    pub vlan: Option<u16>,
    /// Hostname associated with the interface, if resolved.
    pub hostname: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_display_is_colon_hex() {
        let mac = MacAddr([0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]);
        assert_eq!(mac.to_string(), "00:1a:2b:3c:4d:5e");
    }

    #[test]
    fn mac_oui_is_first_three_octets() {
        let mac = MacAddr([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
        assert_eq!(mac.oui(), [0xde, 0xad, 0xbe]);
    }

    #[test]
    fn mac_roundtrips_as_string() {
        let mac = MacAddr([0x00, 0x16, 0x3e, 0x1a, 0x2b, 0x3c]);
        let json = serde_json::to_string(&mac).unwrap();
        assert_eq!(json, "\"00:16:3e:1a:2b:3c\"");
        let back: MacAddr = serde_json::from_str(&json).unwrap();
        assert_eq!(back, mac);
    }

    #[test]
    fn mac_parse_rejects_garbage() {
        assert!(MacAddr::parse("not-a-mac").is_none());
        assert!(MacAddr::parse("00:16:3e:1a:2b").is_none());
    }
}
