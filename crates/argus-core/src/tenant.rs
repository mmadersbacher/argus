//! Multi-tenancy primitives: tenants (organizations) and their users.

use serde::{Deserialize, Serialize};

use crate::ids::{TenantId, UserId};

/// Role-based access level of a [`User`] within a [`Tenant`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Full administrative access.
    Admin,
    /// Can investigate and act on findings.
    Analyst,
    /// Read-only access.
    Viewer,
}

/// An organization; the isolation boundary for all data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tenant {
    /// Stable identifier.
    pub id: TenantId,
    /// Display name.
    pub name: String,
    /// URL-safe slug.
    pub slug: String,
}

/// A user belonging to exactly one [`Tenant`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    /// Stable identifier.
    pub id: UserId,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Email / login.
    pub email: String,
    /// Access role.
    pub role: Role,
}
