//! Network-level entities: MAC addresses, interfaces, and services.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// A 48-bit IEEE 802 MAC address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    /// The 24-bit Organizationally Unique Identifier (first three octets),
    /// used for vendor lookup.
    #[must_use]
    pub fn oui(&self) -> [u8; 3] {
        [self.0[0], self.0[1], self.0[2]]
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
}
