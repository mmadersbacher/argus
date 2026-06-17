//! Passive device fingerprinting from a DHCP request (Fingerbank-style).
//!
//! A DHCP DISCOVER/REQUEST is broadcast, so it is observed without probing the
//! host: the Parameter Request List (option 55) ordering is OS/stack-specific,
//! and the Vendor Class Identifier (option 60) is often an outright giveaway.
//! Passive — we read a broadcast, we never send.

use argus_core::Confidence;

/// The DHCP fields we fingerprint on (from an observed DISCOVER/REQUEST).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DhcpFingerprint {
    /// Option 55 — Parameter Request List, in the order the client sent it.
    pub param_request_list: Vec<u8>,
    /// Option 60 — Vendor Class Identifier, if present.
    pub vendor_class: Option<String>,
}

/// A device/OS guess from a DHCP fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DhcpGuess {
    /// Best-effort OS/device label.
    pub label: &'static str,
    /// Reliability of the guess.
    pub confidence: Confidence,
}

/// Option-55 sequences for common stacks (exact match, curated subset). The
/// full Fingerbank database would extend coverage, not change the method.
const PRL_SIGNATURES: &[(&[u8], &str)] = &[
    (
        &[1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252],
        "Windows",
    ),
    (&[1, 121, 3, 6, 15, 119, 252, 95, 44, 46], "Apple macOS"),
    (&[1, 121, 3, 6, 15, 119, 252], "Apple iOS/macOS"),
    (&[1, 3, 6, 15, 26, 28, 51, 58, 59, 43], "Android"),
    (
        &[1, 28, 2, 3, 15, 6, 119, 12, 44, 47, 26, 121, 42],
        "Linux (dhclient)",
    ),
];

/// Map a vendor-class string (option 60) to an OS/device — the strongest
/// single DHCP signal.
fn from_vendor_class(vc: &str) -> Option<&'static str> {
    let v = vc.to_ascii_lowercase();
    if v.starts_with("msft") {
        Some("Windows")
    } else if v.starts_with("android-dhcp") {
        Some("Android")
    } else if v.contains("dhcpcd") || v.contains("dhclient") {
        Some("Linux")
    } else if v.contains("polycom") || v.contains("yealink") || v.contains("aastra") {
        Some("VoIP phone")
    } else if v.contains("jetdirect") || v.starts_with("hp ") {
        Some("Printer (HP)")
    } else {
        None
    }
}

/// Classify a device/OS from an observed DHCP fingerprint. Vendor class wins
/// (high confidence); else an exact option-55 match (medium); else unknown.
#[must_use]
pub fn classify(fp: &DhcpFingerprint) -> DhcpGuess {
    if let Some(label) = fp.vendor_class.as_deref().and_then(from_vendor_class) {
        return DhcpGuess {
            label,
            confidence: Confidence::High,
        };
    }
    PRL_SIGNATURES
        .iter()
        .find(|(sig, _)| *sig == fp.param_request_list.as_slice())
        .map_or(
            DhcpGuess {
                label: "Unknown",
                confidence: Confidence::Low,
            },
            |(_, label)| DhcpGuess {
                label,
                confidence: Confidence::Medium,
            },
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendor_class_is_a_strong_signal() {
        for (vc, want) in [
            ("MSFT 5.0", "Windows"),
            ("android-dhcp-13", "Android"),
            ("dhcpcd-9.4.1", "Linux"),
        ] {
            let g = classify(&DhcpFingerprint {
                vendor_class: Some(vc.to_owned()),
                ..Default::default()
            });
            assert_eq!(g.label, want);
            assert_eq!(g.confidence, Confidence::High);
        }
    }

    #[test]
    fn windows_from_option_55_sequence() {
        let g = classify(&DhcpFingerprint {
            param_request_list: vec![1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252],
            vendor_class: None,
        });
        assert_eq!(g.label, "Windows");
        assert_eq!(g.confidence, Confidence::Medium);
    }

    #[test]
    fn unknown_when_nothing_matches() {
        let g = classify(&DhcpFingerprint {
            param_request_list: vec![1, 2, 3],
            vendor_class: None,
        });
        assert_eq!(g.label, "Unknown");
        assert_eq!(g.confidence, Confidence::Low);
    }
}
