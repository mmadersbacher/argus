//! Storage abstraction over either Postgres (production) or an in-memory
//! store (zero-dependency local runs and tests).
//!
//! Every method is tenant-scoped exactly like [`crate::db`]; the Postgres arm
//! delegates to it, the memory arm keeps the same data in `HashMap`s behind a
//! mutex. Picking the backend is a one-line decision in `main` — the handlers
//! only ever see [`Store`].

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use argus_core::tenant::Role;
use sqlx::PgPool;
use uuid::Uuid;

use crate::db::{self, ApiKeyRow, UserRow};
use crate::seed::ScoredAsset;

/// A storage failure mapped to an HTTP-friendly shape.
#[derive(Debug)]
pub enum StoreError {
    /// A uniqueness constraint was violated (slug / email / key).
    Conflict(&'static str),
    /// Any other backend error (details logged, not surfaced to clients).
    Backend(String),
}

impl From<sqlx::Error> for StoreError {
    fn from(err: sqlx::Error) -> Self {
        if err
            .as_database_error()
            .is_some_and(sqlx::error::DatabaseError::is_unique_violation)
        {
            Self::Conflict("already exists")
        } else {
            Self::Backend(err.to_string())
        }
    }
}

/// The active storage backend.
#[derive(Clone)]
pub enum Store {
    /// Postgres-backed (production / docker-compose).
    Postgres(PgPool),
    /// Process-memory store (local dev without a database).
    Memory(Arc<Memory>),
}

impl Store {
    /// Build an in-memory store.
    #[must_use]
    pub fn memory() -> Self {
        Self::Memory(Arc::new(Memory::default()))
    }

    /// Human label for logs.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Postgres(_) => "postgres",
            Self::Memory(_) => "in-memory",
        }
    }

    // ---- tenants & users --------------------------------------------------

    /// Number of tenants (first-run detection).
    pub async fn tenant_count(&self) -> Result<i64, StoreError> {
        match self {
            Self::Postgres(pool) => Ok(db::tenant_count(pool).await?),
            Self::Memory(m) => Ok(i64::try_from(m.lock().tenants.len()).unwrap_or(i64::MAX)),
        }
    }

    /// Whether a tenant slug is taken.
    pub async fn tenant_slug_exists(&self, slug: &str) -> Result<bool, StoreError> {
        match self {
            Self::Postgres(pool) => Ok(db::tenant_slug_exists(pool, slug).await?),
            Self::Memory(m) => Ok(m.lock().tenants.values().any(|t| t.slug == slug)),
        }
    }

    /// Whether a login email is registered.
    pub async fn user_email_exists(&self, email: &str) -> Result<bool, StoreError> {
        match self {
            Self::Postgres(pool) => Ok(db::user_email_exists(pool, email).await?),
            Self::Memory(m) => Ok(m.lock().users.contains_key(email)),
        }
    }

    /// Create a tenant and its first (admin) user atomically.
    pub async fn register_tenant(
        &self,
        tenant_id: Uuid,
        name: &str,
        slug: &str,
        admin: &UserRow,
    ) -> Result<(), StoreError> {
        match self {
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                db::create_tenant(&mut *tx, tenant_id, name, slug).await?;
                db::create_user(&mut *tx, admin).await?;
                tx.commit().await?;
                Ok(())
            }
            Self::Memory(m) => {
                let mut inner = m.lock();
                let result = if inner.tenants.values().any(|t| t.slug == slug) {
                    Err(StoreError::Conflict("organization already exists"))
                } else if inner.users.contains_key(&admin.email) {
                    Err(StoreError::Conflict("email already registered"))
                } else {
                    inner.tenants.insert(
                        tenant_id,
                        MemTenant {
                            name: name.to_owned(),
                            slug: slug.to_owned(),
                        },
                    );
                    inner.users.insert(admin.email.clone(), clone_user(admin));
                    Ok(())
                };
                drop(inner);
                result
            }
        }
    }

    /// Create a standalone user (admin add-user flow).
    pub async fn create_user(&self, user: &UserRow) -> Result<(), StoreError> {
        match self {
            Self::Postgres(pool) => {
                db::create_user(pool, user).await?;
                Ok(())
            }
            Self::Memory(m) => {
                let mut inner = m.lock();
                let result = if inner.users.contains_key(&user.email) {
                    Err(StoreError::Conflict("email already registered"))
                } else {
                    inner.users.insert(user.email.clone(), clone_user(user));
                    Ok(())
                };
                drop(inner);
                result
            }
        }
    }

    /// Look up a user by login email.
    pub async fn find_user_by_email(&self, email: &str) -> Result<Option<UserRow>, StoreError> {
        match self {
            Self::Postgres(pool) => Ok(db::find_user_by_email(pool, email).await?),
            Self::Memory(m) => Ok(m.lock().users.get(email).map(clone_user)),
        }
    }

    /// List a tenant's users: `(id, email, role)`.
    pub async fn list_users(
        &self,
        tenant_id: Uuid,
    ) -> Result<Vec<(Uuid, String, Role)>, StoreError> {
        match self {
            Self::Postgres(pool) => Ok(db::list_users(pool, tenant_id).await?),
            Self::Memory(m) => {
                let mut out: Vec<(Uuid, String, Role)> = m
                    .lock()
                    .users
                    .values()
                    .filter(|u| u.tenant_id == tenant_id)
                    .map(|u| (u.id, u.email.clone(), u.role))
                    .collect();
                out.sort_by(|a, b| a.1.cmp(&b.1));
                Ok(out)
            }
        }
    }

    // ---- API keys ---------------------------------------------------------

    /// Store a new API key (hash only).
    pub async fn create_api_key(
        &self,
        id: Uuid,
        tenant_id: Uuid,
        name: &str,
        key_hash: &str,
        role: Role,
    ) -> Result<(), StoreError> {
        match self {
            Self::Postgres(pool) => {
                db::create_api_key(pool, id, tenant_id, name, key_hash, role).await?;
                Ok(())
            }
            Self::Memory(m) => {
                let mut inner = m.lock();
                // Mirror the Postgres UNIQUE(key_hash) constraint so a colliding
                // hash is a Conflict in both backends, not silently accepted.
                let result = if inner.api_keys.iter().any(|k| k.key_hash == key_hash) {
                    Err(StoreError::Conflict("api key already exists"))
                } else {
                    inner.api_keys.push(MemApiKey {
                        id,
                        tenant_id,
                        name: name.to_owned(),
                        key_hash: key_hash.to_owned(),
                        role,
                    });
                    Ok(())
                };
                drop(inner);
                result
            }
        }
    }

    /// Resolve an API key by hash.
    pub async fn find_api_key(&self, key_hash: &str) -> Result<Option<ApiKeyRow>, StoreError> {
        match self {
            Self::Postgres(pool) => Ok(db::find_api_key(pool, key_hash).await?),
            Self::Memory(m) => Ok(m
                .lock()
                .api_keys
                .iter()
                .find(|k| k.key_hash == key_hash)
                .map(|k| ApiKeyRow {
                    tenant_id: k.tenant_id,
                    role: k.role,
                })),
        }
    }

    /// List a tenant's API keys: `(id, name, role)`.
    pub async fn list_api_keys(
        &self,
        tenant_id: Uuid,
    ) -> Result<Vec<(Uuid, String, Role)>, StoreError> {
        match self {
            Self::Postgres(pool) => Ok(db::list_api_keys(pool, tenant_id).await?),
            Self::Memory(m) => {
                let mut out: Vec<(Uuid, String, Role)> = m
                    .lock()
                    .api_keys
                    .iter()
                    .filter(|k| k.tenant_id == tenant_id)
                    .map(|k| (k.id, k.name.clone(), k.role))
                    .collect();
                out.sort_by(|a, b| a.1.cmp(&b.1));
                Ok(out)
            }
        }
    }

    /// Delete one of the tenant's API keys; returns whether one was removed.
    pub async fn delete_api_key(&self, tenant_id: Uuid, id: Uuid) -> Result<bool, StoreError> {
        match self {
            Self::Postgres(pool) => Ok(db::delete_api_key(pool, tenant_id, id).await?),
            Self::Memory(m) => {
                let keys = &mut m.lock().api_keys;
                let before = keys.len();
                keys.retain(|k| !(k.tenant_id == tenant_id && k.id == id));
                Ok(keys.len() < before)
            }
        }
    }

    // ---- audit ------------------------------------------------------------

    /// Append an audit entry (best-effort).
    pub async fn audit(
        &self,
        tenant_id: Uuid,
        user_id: Option<Uuid>,
        action: &str,
        detail: serde_json::Value,
    ) {
        match self {
            Self::Postgres(pool) => db::audit(pool, tenant_id, user_id, action, detail).await,
            Self::Memory(m) => m.lock().audit.push(MemAudit {
                tenant_id,
                user_id,
                action: action.to_owned(),
                detail,
            }),
        }
    }

    // ---- assets -----------------------------------------------------------

    /// Insert or update an asset by correlation key.
    pub async fn upsert(&self, tenant_id: Uuid, asset: &ScoredAsset) -> Result<(), StoreError> {
        match self {
            Self::Postgres(pool) => {
                db::upsert(pool, tenant_id, asset).await?;
                Ok(())
            }
            Self::Memory(m) => {
                let body = serde_json::to_value(asset).expect("ScoredAsset serializes");
                m.lock().assets.insert(
                    (tenant_id, asset.asset.dedup_key()),
                    (body, asset.risk.value),
                );
                Ok(())
            }
        }
    }

    /// Load a tenant's full inventory, highest risk first.
    pub async fn load_all(&self, tenant_id: Uuid) -> Result<Vec<ScoredAsset>, StoreError> {
        match self {
            Self::Postgres(pool) => Ok(db::load_all(pool, tenant_id).await?),
            Self::Memory(m) => {
                let mut rows: Vec<(serde_json::Value, f32)> = m
                    .lock()
                    .assets
                    .iter()
                    .filter(|((tid, _), _)| *tid == tenant_id)
                    .map(|(_, (body, risk))| (body.clone(), *risk))
                    .collect();
                rows.sort_by(|a, b| b.1.total_cmp(&a.1));
                Ok(rows
                    .into_iter()
                    .filter_map(|(body, _)| serde_json::from_value(body).ok())
                    .collect())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// In-memory backing store
// ---------------------------------------------------------------------------

/// Process-memory storage. Lost on restart; intended for local runs and tests.
#[derive(Default)]
pub struct Memory {
    inner: Mutex<MemInner>,
}

impl Memory {
    fn lock(&self) -> std::sync::MutexGuard<'_, MemInner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[derive(Default)]
struct MemInner {
    tenants: HashMap<Uuid, MemTenant>,
    /// Keyed by email (the global login identity).
    users: HashMap<String, UserRow>,
    api_keys: Vec<MemApiKey>,
    /// Keyed by `(tenant_id, dedup_key)`; value is `(json body, risk)`.
    assets: HashMap<(Uuid, String), (serde_json::Value, f32)>,
    audit: Vec<MemAudit>,
}

struct MemTenant {
    #[allow(dead_code)] // kept for symmetry / future tenant listing
    name: String,
    slug: String,
}

struct MemApiKey {
    id: Uuid,
    tenant_id: Uuid,
    name: String,
    key_hash: String,
    role: Role,
}

struct MemAudit {
    #[allow(dead_code)]
    tenant_id: Uuid,
    #[allow(dead_code)]
    user_id: Option<Uuid>,
    #[allow(dead_code)]
    action: String,
    #[allow(dead_code)]
    detail: serde_json::Value,
}

fn clone_user(u: &UserRow) -> UserRow {
    UserRow {
        id: u.id,
        tenant_id: u.tenant_id,
        email: u.email.clone(),
        password_hash: u.password_hash.clone(),
        role: u.role,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admin(tenant: Uuid, email: &str) -> UserRow {
        UserRow {
            id: Uuid::new_v4(),
            tenant_id: tenant,
            email: email.to_owned(),
            password_hash: "hash".to_owned(),
            role: Role::Admin,
        }
    }

    #[tokio::test]
    async fn register_then_login_lookup() {
        let store = Store::memory();
        let tenant = Uuid::new_v4();
        store
            .register_tenant(tenant, "Acme", "acme", &admin(tenant, "a@b.c"))
            .await
            .unwrap();
        assert_eq!(store.tenant_count().await.unwrap(), 1);
        let found = store.find_user_by_email("a@b.c").await.unwrap();
        assert_eq!(found.unwrap().tenant_id, tenant);
    }

    #[tokio::test]
    async fn duplicate_slug_and_email_conflict() {
        let store = Store::memory();
        let t1 = Uuid::new_v4();
        store
            .register_tenant(t1, "Acme", "acme", &admin(t1, "a@b.c"))
            .await
            .unwrap();
        let t2 = Uuid::new_v4();
        let dup_slug = store
            .register_tenant(t2, "Acme2", "acme", &admin(t2, "other@b.c"))
            .await;
        assert!(matches!(dup_slug, Err(StoreError::Conflict(_))));
        let dup_email = store
            .register_tenant(t2, "Acme2", "acme2", &admin(t2, "a@b.c"))
            .await;
        assert!(matches!(dup_email, Err(StoreError::Conflict(_))));
    }

    #[tokio::test]
    async fn assets_are_tenant_scoped_and_risk_sorted() {
        let store = Store::memory();
        let t1 = Uuid::new_v4();
        let t2 = Uuid::new_v4();
        for asset in crate::seed::seed_assets() {
            store.upsert(t1, &asset).await.unwrap();
        }
        // t2 sees nothing.
        assert!(store.load_all(t2).await.unwrap().is_empty());
        let loaded = store.load_all(t1).await.unwrap();
        assert!(loaded.len() >= 6);
        // Sorted by risk, descending.
        for pair in loaded.windows(2) {
            assert!(pair[0].risk.value >= pair[1].risk.value);
        }
    }

    #[tokio::test]
    async fn api_key_lifecycle() {
        let store = Store::memory();
        let tenant = Uuid::new_v4();
        let id = Uuid::new_v4();
        store
            .create_api_key(id, tenant, "ci", "hash123", Role::Analyst)
            .await
            .unwrap();
        let found = store.find_api_key("hash123").await.unwrap().unwrap();
        assert_eq!(found.tenant_id, tenant);
        assert_eq!(found.role, Role::Analyst);
        assert!(store.delete_api_key(tenant, id).await.unwrap());
        assert!(store.find_api_key("hash123").await.unwrap().is_none());
    }
}
