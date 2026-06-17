//! # argus-sensor
//!
//! Passive sensing for Argus: derive OS/device identity from packet features
//! observed on the wire, without ever probing the host. Two layers:
//!
//! - **Analysis** (this crate, pure + unit-tested): [`tcp::classify`] turns an
//!   observed TCP SYN into an [`tcp::OsGuess`] (p0f-style), with a
//!   [`argus_core::Confidence`] so a TTL-only guess reads as less certain than a
//!   multi-feature match. More passive signals (DHCP option-55, HTTP
//!   User-Agent) and a larger signature database are the next iterations.
//! - **Capture** (separate, privileged — not in this crate): reading raw
//!   packets needs libpcap / Npcap and root/Administrator and is not CI-testable.
//!   It will live behind a feature flag and feed [`tcp::TcpSyn`] values into the
//!   pure analysis here.
//!
//! Splitting analysis from capture keeps the whole fingerprint logic testable
//! with synthetic packets — no capture, no privileges, no CI flakiness.

pub mod tcp;

pub use tcp::{classify, OsFamily, OsGuess, TcpSyn};
