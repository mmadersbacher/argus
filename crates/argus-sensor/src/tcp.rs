//! Passive OS fingerprinting from a TCP SYN (p0f-style).
//!
//! A host's TCP SYN leaks OS identity without ever touching it: the initial
//! TTL, the TCP window scale, whether timestamps are present, and the window
//! size differ by OS family. We never send anything — these features come from
//! a packet observed on the wire (capture layer, separate). The classifier is
//! pure and returns a [`Confidence`] so an OS-family-only guess (TTL alone)
//! reads as less certain than a multi-feature match.

use argus_core::Confidence;

/// Coarse OS family inferred from a passive TCP fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsFamily {
    /// Linux kernel (incl. Android, which is not separable by TCP alone).
    Linux,
    /// Microsoft Windows.
    Windows,
    /// Apple macOS / iOS / a BSD (TTL 64, window-scale 6, window 65535).
    AppleOrBsd,
    /// Router/switch/printer-class stack (initial TTL 255).
    NetworkDevice,
    /// Could not be attributed.
    Unknown,
}

/// The OS-relevant fields of an observed TCP SYN. Populated by the capture
/// layer; here it is just the classifier's input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpSyn {
    /// Observed IP TTL (already decremented by the path's hops).
    pub ttl: u8,
    /// TCP window size advertised in the SYN.
    pub window_size: u16,
    /// TCP window-scale option, if present.
    pub window_scale: Option<u8>,
    /// Whether the SYN carried a TCP timestamp option.
    pub timestamps: bool,
    /// Whether the IP Don't-Fragment bit was set.
    pub dont_fragment: bool,
}

/// A passive OS guess with its confidence and the estimated path length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OsGuess {
    /// Inferred OS family.
    pub family: OsFamily,
    /// How reliable the inference is.
    pub confidence: Confidence,
    /// Estimated number of hops (initial TTL − observed TTL).
    pub hops: u8,
}

/// Recover the likely initial TTL and hop count: the smallest standard initial
/// TTL (`64`, `128`, `255`) that is `>=` the observed value.
fn initial_ttl(ttl: u8) -> (u8, u8) {
    for initial in [64u8, 128, 255] {
        if ttl <= initial {
            return (initial, initial - ttl);
        }
    }
    (255, 0)
}

/// Refine an initial-TTL-64 fingerprint (the crowded unix-like bucket) using
/// window scale, timestamps and window size.
fn unix_like(syn: TcpSyn) -> (OsFamily, Confidence) {
    match (syn.window_scale, syn.timestamps) {
        // Linux/Android: high window scale + timestamps on.
        (Some(7 | 8), true) => (OsFamily::Linux, Confidence::High),
        // macOS/iOS/FreeBSD: window scale 6, timestamps on, classic 65535 window.
        (Some(6), true) if syn.window_size == 65535 => (OsFamily::AppleOrBsd, Confidence::High),
        (Some(6), true) => (OsFamily::AppleOrBsd, Confidence::Medium),
        // TTL 64 but no timestamps is unusual for modern unix — don't overclaim.
        (_, false) => (OsFamily::Unknown, Confidence::Low),
        // TTL 64 with timestamps but an unrecognised scale: unix-like, low conf.
        _ => (OsFamily::Linux, Confidence::Low),
    }
}

/// Classify the OS family behind a passively observed TCP SYN.
#[must_use]
pub fn classify(syn: TcpSyn) -> OsGuess {
    let (initial, hops) = initial_ttl(syn.ttl);
    let (family, confidence) = match initial {
        // Initial TTL 128 is a strong, almost-exclusive Windows signal; the
        // absence of TCP timestamps (Windows default) corroborates it.
        128 => {
            let conf = if syn.timestamps {
                Confidence::Medium
            } else {
                Confidence::High
            };
            (OsFamily::Windows, conf)
        }
        255 => (OsFamily::NetworkDevice, Confidence::Medium),
        64 => unix_like(syn),
        _ => (OsFamily::Unknown, Confidence::Low),
    };
    OsGuess {
        family,
        confidence,
        hops,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn syn(ttl: u8, window_size: u16, window_scale: Option<u8>, timestamps: bool) -> TcpSyn {
        TcpSyn {
            ttl,
            window_size,
            window_scale,
            timestamps,
            dont_fragment: true,
        }
    }

    #[test]
    fn windows_from_ttl_128_without_timestamps() {
        let g = classify(syn(128, 64240, Some(8), false));
        assert_eq!(g.family, OsFamily::Windows);
        assert_eq!(g.confidence, Confidence::High);
        assert_eq!(g.hops, 0);
    }

    #[test]
    fn linux_from_ttl_64_scale_7_timestamps() {
        let g = classify(syn(64, 29200, Some(7), true));
        assert_eq!(g.family, OsFamily::Linux);
        assert_eq!(g.confidence, Confidence::High);
    }

    #[test]
    fn apple_from_ttl_64_scale_6_window_65535() {
        let g = classify(syn(64, 65535, Some(6), true));
        assert_eq!(g.family, OsFamily::AppleOrBsd);
        assert_eq!(g.confidence, Confidence::High);
    }

    #[test]
    fn hops_are_recovered_from_a_decremented_ttl() {
        // Observed TTL 56 → initial 64, 8 hops away; still Linux.
        let g = classify(syn(56, 29200, Some(7), true));
        assert_eq!(g.family, OsFamily::Linux);
        assert_eq!(g.hops, 8);
    }

    #[test]
    fn network_device_from_ttl_255() {
        let g = classify(syn(255, 4128, None, false));
        assert_eq!(g.family, OsFamily::NetworkDevice);
    }

    #[test]
    fn ttl_64_without_timestamps_is_not_overclaimed() {
        let g = classify(syn(64, 8192, Some(8), false));
        assert_eq!(g.family, OsFamily::Unknown);
        assert_eq!(g.confidence, Confidence::Low);
    }
}
