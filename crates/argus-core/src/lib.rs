//! # argus-core
//!
//! The shared domain model for the Argus cyber asset & exposure platform:
//! tenants, assets and their network entities, vulnerabilities, findings, and
//! the composite risk-scoring engine. This crate is pure (no I/O) so every
//! other crate — discovery, ingest, API — can depend on it freely.

pub mod asset;
pub mod finding;
pub mod ids;
pub mod network;
pub mod risk;
pub mod tenant;
pub mod vuln;

pub use asset::{Asset, AssetType, Criticality, Exposure, Fingerprint};
pub use finding::{Finding, FindingSource};
pub use ids::{AssetId, FindingId, TenantId, UserId};
pub use network::{Interface, MacAddr, Protocol, Service};
pub use risk::{RiskBand, RiskInputs, RiskScore};
pub use tenant::{Role, Tenant, User};
pub use vuln::{Confidence, Cvss, Epss, Severity, Vulnerability};
