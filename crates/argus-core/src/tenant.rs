//! Multi-tenancy primitives: tenants (organizations) and their users.

use serde::{Deserialize, Serialize};

use crate::ids::{TenantId, UserId};

/// Role-based access level of a [`User`] within a [`Tenant`].
///
/// Variants are ordered by privilege (`Viewer < Analyst < Admin`), so role
/// checks can use plain comparisons: `role >= Role::Analyst`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Read-only access.
    Viewer,
    /// Can investigate and act on findings (run scans, import data).
    Analyst,
    /// Full administrative access (manage users and API keys).
    Admin,
}

impl Role {
    /// Stable lowercase name, as persisted in the database.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Analyst => "analyst",
            Self::Admin => "admin",
        }
    }

    /// Parse the stable lowercase name back into a role.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "viewer" => Some(Self::Viewer),
            "analyst" => Some(Self::Analyst),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_order_by_privilege() {
        assert!(Role::Viewer < Role::Analyst);
        assert!(Role::Analyst < Role::Admin);
        assert!(Role::Admin >= Role::Analyst);
    }

    #[test]
    fn role_str_roundtrip() {
        for role in [Role::Viewer, Role::Analyst, Role::Admin] {
            assert_eq!(Role::parse(role.as_str()), Some(role));
        }
        assert_eq!(Role::parse("root"), None);
    }
}
