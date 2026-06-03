//! Strongly-typed identifiers for domain entities, backed by UUIDv4.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

macro_rules! typed_id {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub struct $name(pub Uuid);

        impl $name {
            /// Generate a new random identifier.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

typed_id!(
    TenantId,
    "Identifier for a [`crate::tenant::Tenant`] (organization)."
);
typed_id!(UserId, "Identifier for a [`crate::tenant::User`].");
typed_id!(AssetId, "Identifier for an [`crate::asset::Asset`].");
typed_id!(FindingId, "Identifier for a [`crate::finding::Finding`].");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique() {
        assert_ne!(AssetId::new(), AssetId::new());
    }

    #[test]
    fn display_matches_inner_uuid() {
        let id = TenantId::new();
        assert_eq!(id.to_string(), id.0.to_string());
    }
}
