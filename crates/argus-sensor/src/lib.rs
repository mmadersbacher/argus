//! # argus-sensor
//!
//! Passive sensing for Argus: derive OS/device identity from signals observed
//! on the wire, without ever probing the host. Two layers:
//!
//! - **Analysis** (this crate, pure + unit-tested): three passive signals —
//!   [`tcp::classify`] (TCP-SYN, p0f-style), [`dhcp::classify`] (DHCP option
//!   55/60, Fingerbank-style) and [`http::classify`] (HTTP User-Agent) — fused
//!   by [`observe`] into one [`PassiveObservation`]. Confidence rises when
//!   signals agree and is capped when they conflict (the agreement-weighted
//!   scheme used in `argus-intel`).
//! - **Capture** (separate, privileged — not in this crate): reading raw
//!   packets needs libpcap / Npcap and root/Administrator and is not
//!   CI-testable. It will feed the per-signal inputs into the pure analysis here
//!   behind a feature flag.
//!
//! Splitting analysis from capture keeps the whole fingerprint logic testable
//! with synthetic inputs — no capture, no privileges, no CI flakiness.

pub mod dhcp;
pub mod http;
pub mod tcp;

pub use dhcp::{DhcpFingerprint, DhcpGuess};
pub use http::UaGuess;
pub use tcp::{OsFamily, OsGuess, TcpSyn};

use argus_core::Confidence;

/// A fused identity from one or more passive signals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassiveObservation {
    /// Agreed OS family, if any signal attributed one.
    pub os: Option<OsFamily>,
    /// Free-text device/OS hint (e.g. `"Android"`, `"Printer (HP)"`, `"mobile"`).
    pub device_hint: Option<String>,
    /// Confidence — rises when signals agree, capped at `Medium` on conflict.
    pub confidence: Confidence,
}

/// Map a free-text OS label (from DHCP/HTTP) onto an [`OsFamily`] so signals of
/// different kinds can be checked for agreement. Android maps to `Linux` (it is
/// a Linux kernel) — consistent with the TCP fingerprint, which cannot separate
/// them either.
fn os_family_of(label: &str) -> Option<OsFamily> {
    if label == "Windows" {
        Some(OsFamily::Windows)
    } else if label == "Linux" || label == "Android" {
        Some(OsFamily::Linux)
    } else if label.starts_with("Apple") {
        Some(OsFamily::AppleOrBsd)
    } else {
        None
    }
}

/// Fuse the available passive signals into one observation.
///
/// Agreement across signals yields `Confirmed`, a lone signal carries `Medium`,
/// and a conflict keeps the first vote but caps confidence at `Medium`.
#[must_use]
pub fn observe(
    tcp: Option<OsGuess>,
    dhcp: Option<DhcpGuess>,
    http: Option<UaGuess>,
) -> PassiveObservation {
    let mut votes: Vec<OsFamily> = Vec::new();
    if let Some(t) = tcp {
        if t.family != OsFamily::Unknown {
            votes.push(t.family);
        }
    }
    if let Some(f) = dhcp.and_then(|d| os_family_of(d.label)) {
        votes.push(f);
    }
    if let Some(f) = http.and_then(|u| u.os).and_then(os_family_of) {
        votes.push(f);
    }

    // Prefer a concrete device label from DHCP, else the HTTP device class.
    let device_hint = dhcp
        .filter(|d| d.label != "Unknown")
        .map(|d| d.label.to_owned())
        .or_else(|| http.and_then(|u| u.device_class).map(ToOwned::to_owned));

    let (os, confidence) = match votes.as_slice() {
        [] => (None, Confidence::Low),
        [single] => (Some(*single), Confidence::Medium),
        [first, rest @ ..] => {
            if rest.iter().all(|f| f == first) {
                (Some(*first), Confidence::Confirmed)
            } else {
                (Some(*first), Confidence::Medium)
            }
        }
    };

    PassiveObservation {
        os,
        device_hint,
        confidence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(family: OsFamily) -> OsGuess {
        OsGuess {
            family,
            confidence: Confidence::High,
            hops: 0,
        }
    }

    #[test]
    fn agreeing_signals_are_confirmed() {
        // TCP says Linux, DHCP says Android (→ Linux): agreement → Confirmed.
        let o = observe(
            Some(os(OsFamily::Linux)),
            Some(DhcpGuess {
                label: "Android",
                confidence: Confidence::High,
            }),
            None,
        );
        assert_eq!(o.os, Some(OsFamily::Linux));
        assert_eq!(o.confidence, Confidence::Confirmed);
        assert_eq!(o.device_hint.as_deref(), Some("Android"));
    }

    #[test]
    fn a_single_signal_is_medium() {
        let o = observe(Some(os(OsFamily::Windows)), None, None);
        assert_eq!(o.os, Some(OsFamily::Windows));
        assert_eq!(o.confidence, Confidence::Medium);
    }

    #[test]
    fn conflicting_signals_are_capped_at_medium() {
        // TCP Windows vs DHCP Linux — keep the first, cap confidence.
        let o = observe(
            Some(os(OsFamily::Windows)),
            Some(DhcpGuess {
                label: "Linux",
                confidence: Confidence::Medium,
            }),
            None,
        );
        assert_eq!(o.confidence, Confidence::Medium);
    }

    #[test]
    fn no_signals_is_low_and_empty() {
        let o = observe(None, None, None);
        assert_eq!(o.os, None);
        assert_eq!(o.confidence, Confidence::Low);
        assert!(o.device_hint.is_none());
    }
}
