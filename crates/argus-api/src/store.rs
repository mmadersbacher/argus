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
use time::OffsetDateTime;
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};
use uuid::Uuid;

use crate::db::{self, ApiKeyRow, DueMonitor, EventRow, MonitorRow, UserRow};
use crate::seed::ScoredAsset;

/// Memory-store retention cap: newest events kept per tenant. The in-memory
/// `events` Vec would otherwise grow unbounded across a long-running process.
const MAX_MEMORY_EVENTS_PER_TENANT: usize = 1000;

/// Per-tenant ingest serialization registry.
///
/// `ingest` holds the per-tenant guard for its whole body, so a manual
/// `POST /api/scan` and a scheduled run for the SAME tenant cannot interleave
/// (which would let one advance the diff baseline while the other reads a stale
/// one, duplicating events). Different tenants never block each other.
#[derive(Clone, Default)]
pub struct IngestLocks(Arc<Mutex<HashMap<Uuid, Arc<AsyncMutex<()>>>>>);

impl IngestLocks {
    /// Acquire the per-tenant ingest lock, creating it on first use. The
    /// returned guard must be held for the entire ingest body.
    pub async fn lock(&self, tenant: Uuid) -> OwnedMutexGuard<()> {
        let mutex = {
            let mut map = self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            Arc::clone(map.entry(tenant).or_default())
        };
        mutex.lock_owned().await
    }
}

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

    /// Atomically upsert one asset and record its change events.
    ///
    /// For Postgres this runs the asset upsert and all event inserts in ONE
    /// transaction; for the memory store both happen under the single mutex.
    /// This keeps the diff baseline (the stored asset) from advancing without
    /// its events also being persisted — so a crash or a concurrent scan can't
    /// leave the baseline ahead of the event feed.
    pub async fn commit_asset(
        &self,
        tenant_id: Uuid,
        asset: &ScoredAsset,
        events: &[(&str, &serde_json::Value)],
        dedup_key: &str,
        asset_name: &str,
    ) -> Result<(), StoreError> {
        match self {
            Self::Postgres(pool) => {
                db::commit_asset(pool, tenant_id, asset, events, dedup_key, asset_name).await?;
                Ok(())
            }
            Self::Memory(m) => {
                let body = serde_json::to_value(asset).expect("ScoredAsset serializes");
                let mut inner = m.lock();
                inner
                    .assets
                    .insert((tenant_id, dedup_key.to_owned()), (body, asset.risk.value));
                for (kind, detail) in events {
                    inner.next_event_id += 1;
                    let id = inner.next_event_id;
                    inner.events.push(MemEvent {
                        id,
                        tenant_id,
                        dedup_key: dedup_key.to_owned(),
                        asset_name: asset_name.to_owned(),
                        kind: (*kind).to_owned(),
                        detail: (*detail).clone(),
                        created_at: OffsetDateTime::now_utc(),
                    });
                }
                inner.cap_events(tenant_id);
                drop(inner);
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

    /// Load a single asset by its correlation key, if present.
    pub async fn load_one(
        &self,
        tenant_id: Uuid,
        dedup_key: &str,
    ) -> Result<Option<ScoredAsset>, StoreError> {
        match self {
            Self::Postgres(pool) => Ok(db::load_one(pool, tenant_id, dedup_key).await?),
            Self::Memory(m) => Ok(m
                .lock()
                .assets
                .get(&(tenant_id, dedup_key.to_owned()))
                .and_then(|(body, _)| serde_json::from_value(body.clone()).ok())),
        }
    }

    // ---- change events & monitors ------------------------------------------

    /// Record one change event for an asset.
    pub async fn record_event(
        &self,
        tenant_id: Uuid,
        dedup_key: &str,
        asset_name: &str,
        kind: &str,
        detail: &serde_json::Value,
    ) -> Result<(), StoreError> {
        match self {
            Self::Postgres(pool) => {
                db::record_event(pool, tenant_id, dedup_key, asset_name, kind, detail).await?;
                Ok(())
            }
            Self::Memory(m) => {
                let mut inner = m.lock();
                inner.next_event_id += 1;
                let id = inner.next_event_id;
                inner.events.push(MemEvent {
                    id,
                    tenant_id,
                    dedup_key: dedup_key.to_owned(),
                    asset_name: asset_name.to_owned(),
                    kind: kind.to_owned(),
                    detail: detail.clone(),
                    created_at: OffsetDateTime::now_utc(),
                });
                inner.cap_events(tenant_id);
                drop(inner);
                Ok(())
            }
        }
    }

    /// Prune stored change events to bound their growth.
    ///
    /// Postgres deletes events older than `retention_days` and returns the
    /// count removed. The memory store ignores the age window (it has no
    /// persistence to bound over time) and instead caps each tenant to the
    /// newest [`MAX_MEMORY_EVENTS_PER_TENANT`] events; it returns `0`.
    pub async fn prune_events(&self, retention_days: i64) -> Result<u64, StoreError> {
        match self {
            Self::Postgres(pool) => Ok(db::prune_events(pool, retention_days).await?),
            Self::Memory(m) => {
                let mut inner = m.lock();
                let tenants: Vec<Uuid> = {
                    let mut t: Vec<Uuid> = inner.events.iter().map(|e| e.tenant_id).collect();
                    t.sort_unstable();
                    t.dedup();
                    t
                };
                for tenant_id in tenants {
                    inner.cap_events(tenant_id);
                }
                drop(inner);
                Ok(0)
            }
        }
    }

    /// List a tenant's most recent change events, newest first.
    pub async fn list_events(
        &self,
        tenant_id: Uuid,
        limit: i64,
    ) -> Result<Vec<EventRow>, StoreError> {
        match self {
            Self::Postgres(pool) => Ok(db::list_events(pool, tenant_id, limit).await?),
            Self::Memory(m) => {
                let take = usize::try_from(limit).unwrap_or(0);
                Ok(m.lock()
                    .events
                    .iter()
                    .rev() // insertion order is oldest-first
                    .filter(|e| e.tenant_id == tenant_id)
                    .take(take)
                    .map(|e| EventRow {
                        id: e.id,
                        kind: e.kind.clone(),
                        dedup_key: e.dedup_key.clone(),
                        asset_name: e.asset_name.clone(),
                        detail: e.detail.clone(),
                        created_at: e.created_at,
                    })
                    .collect())
            }
        }
    }

    /// Fetch a tenant's monitor configuration, if one was ever saved.
    pub async fn get_monitor(&self, tenant_id: Uuid) -> Result<Option<MonitorRow>, StoreError> {
        match self {
            Self::Postgres(pool) => Ok(db::get_monitor(pool, tenant_id).await?),
            Self::Memory(m) => Ok(m.lock().monitors.get(&tenant_id).map(|mon| MonitorRow {
                target: mon.target.clone(),
                interval_minutes: mon.interval_minutes,
                enabled: mon.enabled,
                deep: mon.deep,
                last_run_at: mon.last_run_at,
            })),
        }
    }

    /// Create or replace a tenant's monitor (`last_run_at` is preserved).
    pub async fn set_monitor(
        &self,
        tenant_id: Uuid,
        target: &str,
        interval_minutes: i32,
        enabled: bool,
        deep: bool,
    ) -> Result<(), StoreError> {
        match self {
            Self::Postgres(pool) => {
                db::set_monitor(pool, tenant_id, target, interval_minutes, enabled, deep).await?;
                Ok(())
            }
            Self::Memory(m) => {
                let mut inner = m.lock();
                let last_run_at = inner
                    .monitors
                    .get(&tenant_id)
                    .and_then(|mon| mon.last_run_at);
                inner.monitors.insert(
                    tenant_id,
                    MemMonitor {
                        target: target.to_owned(),
                        interval_minutes,
                        enabled,
                        deep,
                        last_run_at,
                    },
                );
                drop(inner);
                Ok(())
            }
        }
    }

    /// Atomically claim every monitor that is due for a run, stamping its
    /// `last_run_at` *before* the scan so overlapping runs cannot start.
    pub async fn claim_due_monitors(&self) -> Result<Vec<DueMonitor>, StoreError> {
        match self {
            Self::Postgres(pool) => Ok(db::claim_due_monitors(pool).await?),
            Self::Memory(m) => {
                let now = OffsetDateTime::now_utc();
                let mut due = Vec::new();
                let mut inner = m.lock();
                for (tenant_id, mon) in &mut inner.monitors {
                    let is_due = mon.enabled
                        && mon.last_run_at.is_none_or(|last| {
                            last + time::Duration::minutes(i64::from(mon.interval_minutes)) <= now
                        });
                    if is_due {
                        mon.last_run_at = Some(now);
                        due.push(DueMonitor {
                            tenant_id: *tenant_id,
                            target: mon.target.clone(),
                            deep: mon.deep,
                        });
                    }
                }
                drop(inner);
                Ok(due)
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
    /// Change events, oldest first (mirrors the BIGSERIAL insertion order).
    events: Vec<MemEvent>,
    /// Last assigned event id (mirrors the Postgres BIGSERIAL).
    next_event_id: i64,
    /// One monitor per tenant, like the `monitors` table's tenant_id PK.
    monitors: HashMap<Uuid, MemMonitor>,
}

impl MemInner {
    /// Drop a tenant's oldest events beyond [`MAX_MEMORY_EVENTS_PER_TENANT`],
    /// keeping the newest. `events` is global and oldest-first, so we count the
    /// tenant's rows and retain only those at-or-after the cutoff index.
    fn cap_events(&mut self, tenant_id: Uuid) {
        let count = self
            .events
            .iter()
            .filter(|e| e.tenant_id == tenant_id)
            .count();
        if count <= MAX_MEMORY_EVENTS_PER_TENANT {
            return;
        }
        let mut to_drop = count - MAX_MEMORY_EVENTS_PER_TENANT;
        self.events.retain(|e| {
            if e.tenant_id == tenant_id && to_drop > 0 {
                to_drop -= 1;
                false
            } else {
                true
            }
        });
    }
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

struct MemEvent {
    id: i64,
    tenant_id: Uuid,
    dedup_key: String,
    asset_name: String,
    kind: String,
    detail: serde_json::Value,
    created_at: OffsetDateTime,
}

struct MemMonitor {
    target: String,
    interval_minutes: i32,
    enabled: bool,
    deep: bool,
    last_run_at: Option<OffsetDateTime>,
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

    #[tokio::test]
    async fn load_one_finds_upserted_asset_by_dedup_key() {
        let store = Store::memory();
        let tenant = Uuid::new_v4();
        let asset = crate::seed::seed_assets().into_iter().next().unwrap();
        let key = asset.asset.dedup_key();
        assert!(store.load_one(tenant, &key).await.unwrap().is_none());
        store.upsert(tenant, &asset).await.unwrap();
        let loaded = store.load_one(tenant, &key).await.unwrap().unwrap();
        assert_eq!(loaded.asset.dedup_key(), key);
        // Other tenants must not see it.
        assert!(store
            .load_one(Uuid::new_v4(), &key)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn events_are_tenant_scoped_newest_first_and_limited() {
        let store = Store::memory();
        let t1 = Uuid::new_v4();
        let t2 = Uuid::new_v4();
        for i in 0..3 {
            store
                .record_event(
                    t1,
                    "ip:10.0.0.5",
                    "web-01",
                    "vulns.changed",
                    &serde_json::json!({ "added": [format!("CVE-2024-{i}")], "removed": [], "kev_added": 0 }),
                )
                .await
                .unwrap();
        }
        store
            .record_event(
                t2,
                "ip:10.0.0.9",
                "db-01",
                "asset.new",
                &serde_json::json!({}),
            )
            .await
            .unwrap();

        // t2 sees only its own event.
        let other = store.list_events(t2, 50).await.unwrap();
        assert_eq!(other.len(), 1);
        assert_eq!(other[0].kind, "asset.new");

        // Newest first: ids strictly descending.
        let events = store.list_events(t1, 50).await.unwrap();
        assert_eq!(events.len(), 3);
        for pair in events.windows(2) {
            assert!(pair[0].id > pair[1].id);
        }
        assert_eq!(events[0].asset_name, "web-01");
        assert_eq!(events[0].dedup_key, "ip:10.0.0.5");

        // Limit caps the result, still newest first.
        let limited = store.list_events(t1, 2).await.unwrap();
        assert_eq!(limited.len(), 2);
        assert_eq!(limited[0].id, events[0].id);
    }

    #[tokio::test]
    async fn monitor_set_get_roundtrip_preserves_last_run() {
        let store = Store::memory();
        let tenant = Uuid::new_v4();
        assert!(store.get_monitor(tenant).await.unwrap().is_none());

        store
            .set_monitor(tenant, "10.0.0.0/24", 15, true, false)
            .await
            .unwrap();
        let saved = store.get_monitor(tenant).await.unwrap().unwrap();
        assert_eq!(saved.target, "10.0.0.0/24");
        assert_eq!(saved.interval_minutes, 15);
        assert!(saved.enabled);
        assert!(!saved.deep);
        assert!(saved.last_run_at.is_none());

        // Claim stamps last_run_at; a reconfigure must not erase it.
        let claimed = store.claim_due_monitors().await.unwrap();
        assert_eq!(claimed.len(), 1);
        store
            .set_monitor(tenant, "10.0.0.0/25", 30, true, true)
            .await
            .unwrap();
        let updated = store.get_monitor(tenant).await.unwrap().unwrap();
        assert_eq!(updated.target, "10.0.0.0/25");
        assert!(updated.last_run_at.is_some());
    }

    #[tokio::test]
    async fn claim_takes_due_monitors_exactly_once() {
        let store = Store::memory();
        let due_tenant = Uuid::new_v4();
        let disabled_tenant = Uuid::new_v4();
        store
            .set_monitor(due_tenant, "192.168.1.0/24", 15, true, false)
            .await
            .unwrap();
        store
            .set_monitor(disabled_tenant, "192.168.2.0/24", 15, false, false)
            .await
            .unwrap();

        // Never-run + enabled is due; disabled is not.
        let claimed = store.claim_due_monitors().await.unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].tenant_id, due_tenant);
        assert_eq!(claimed[0].target, "192.168.1.0/24");
        assert!(!claimed[0].deep);

        // The claim stamped last_run_at, so an immediate second claim is empty.
        let last_run = store
            .get_monitor(due_tenant)
            .await
            .unwrap()
            .unwrap()
            .last_run_at;
        assert!(last_run.is_some());
        assert!(store.claim_due_monitors().await.unwrap().is_empty());
    }
}
