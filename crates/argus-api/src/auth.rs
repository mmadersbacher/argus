//! Authentication and authorization.
//!
//! Argon2id password hashing, HS256 JWT sessions, hashed API keys, an
//! in-memory login rate limiter, and the [`AuthContext`] extractor that
//! authenticates every request and carries the tenant scope + role for RBAC.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use argus_core::tenant::Role;
use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use axum::http::StatusCode;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::AppState;

/// Header carrying a machine credential as an alternative to a Bearer JWT.
pub const API_KEY_HEADER: &str = "x-api-key";

/// Default session lifetime in hours (override via `ARGUS_TOKEN_TTL_HOURS`).
const DEFAULT_TOKEN_TTL_HOURS: i64 = 12;

/// JWT signing/verification keys derived from one shared secret.
#[derive(Clone)]
pub struct AuthKeys {
    encoding: EncodingKey,
    decoding: DecodingKey,
}

impl AuthKeys {
    /// Build the key pair from a shared secret.
    #[must_use]
    pub fn from_secret(secret: &[u8]) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
        }
    }
}

/// Load the JWT secret from `ARGUS_JWT_SECRET`, or generate an ephemeral one.
///
/// The generated fallback keeps development friction-free but invalidates all
/// sessions on restart — production deployments must set the env var.
#[must_use]
pub fn load_or_generate_secret() -> Vec<u8> {
    if let Ok(secret) = std::env::var("ARGUS_JWT_SECRET") {
        let trimmed = secret.trim();
        if trimmed.len() >= 32 {
            return trimmed.as_bytes().to_vec();
        }
        tracing::warn!("ARGUS_JWT_SECRET is shorter than 32 chars — ignoring it");
    }
    tracing::warn!(
        "ARGUS_JWT_SECRET not set — using an ephemeral secret; all sessions \
         are invalidated on restart. Set a 32+ char secret for production."
    );
    let mut secret = vec![0_u8; 32];
    rand::thread_rng().fill_bytes(&mut secret);
    secret
}

/// JWT claims for an interactive user session.
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// User id.
    pub sub: Uuid,
    /// Tenant (organization) the session is scoped to.
    pub tid: Uuid,
    /// Access role within the tenant.
    pub role: Role,
    /// Login email, echoed for display purposes.
    pub email: String,
    /// Expiry (unix seconds).
    pub exp: i64,
    /// Issued-at (unix seconds).
    pub iat: i64,
}

/// Session lifetime in hours from `ARGUS_TOKEN_TTL_HOURS` (clamped to
/// `1..=168`, default 12). Shared by the JWT expiry and the session cookie's
/// `Max-Age` so the two never drift apart.
#[must_use]
pub fn token_ttl_hours() -> i64 {
    std::env::var("ARGUS_TOKEN_TTL_HOURS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|h| (1..=168).contains(h))
        .unwrap_or(DEFAULT_TOKEN_TTL_HOURS)
}

/// Issue a signed session token for the given user.
pub fn issue_token(
    keys: &AuthKeys,
    user_id: Uuid,
    tenant_id: Uuid,
    role: Role,
    email: &str,
) -> Result<String, jsonwebtoken::errors::Error> {
    let ttl_hours = token_ttl_hours();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let claims = Claims {
        sub: user_id,
        tid: tenant_id,
        role,
        email: email.to_owned(),
        exp: now + ttl_hours * 3600,
        iat: now,
    };
    jsonwebtoken::encode(&Header::default(), &claims, &keys.encoding)
}

/// Verify a session token and return its claims.
pub fn verify_token(keys: &AuthKeys, token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let data = jsonwebtoken::decode::<Claims>(token, &keys.decoding, &Validation::default())?;
    Ok(data.claims)
}

/// Hash a password with Argon2id and a fresh random salt.
pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)?
        .to_string())
}

/// PHC hash used to equalize login timing when the email is unknown,
/// blunting user-enumeration via response-time differences.
pub fn dummy_hash() -> &'static str {
    static DUMMY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    DUMMY.get_or_init(|| hash_password("argus-timing-dummy").expect("argon2 hashes"))
}

/// Verify a password against a stored Argon2 hash (constant-time).
#[must_use]
pub fn verify_password(password: &str, stored_hash: &str) -> bool {
    PasswordHash::new(stored_hash).is_ok_and(|parsed| {
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
    })
}

/// Generate a new API key: `(plaintext, sha256-hex)`.
///
/// The plaintext (`argus_<hex>`) is returned to the caller exactly once;
/// only the hash is persisted.
#[must_use]
pub fn generate_api_key() -> (String, String) {
    let mut bytes = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let plaintext = format!("argus_{}", hex::encode(bytes));
    let hash = hash_api_key(&plaintext);
    (plaintext, hash)
}

/// SHA-256 hex digest of an API key plaintext (the stored lookup key).
#[must_use]
pub fn hash_api_key(plaintext: &str) -> String {
    hex::encode(Sha256::digest(plaintext.as_bytes()))
}

/// Sliding-window in-memory rate limiter for login attempts.
///
/// Keyed by an arbitrary string with a per-key cap over [`Self::WINDOW`]. The
/// login path uses two dimensions (see [`Self::PER_PAIR_MAX`] /
/// [`Self::PER_IP_MAX`]): a tight per-`(ip,email)` budget that stops targeted
/// brute force without letting an attacker lock a victim out (the victim logs
/// in from a different IP), plus a looser per-IP budget that caps password
/// spraying across many accounts from one source. In-memory only: resets on
/// restart and is per-instance, an acceptable bound for a single API node;
/// distributed spraying from many IPs is out of scope for this limiter.
#[derive(Default)]
pub struct LoginLimiter {
    attempts: Mutex<HashMap<String, Vec<Instant>>>,
}

impl LoginLimiter {
    /// Observation window for counting attempts.
    pub const WINDOW: Duration = Duration::from_secs(60);
    /// Max attempts per `(ip, email)` pair within [`Self::WINDOW`].
    pub const PER_PAIR_MAX: usize = 5;
    /// Max attempts per source IP within [`Self::WINDOW`].
    pub const PER_IP_MAX: usize = 50;

    /// Record an attempt for `key`; returns `false` when at/over `max`.
    pub fn allow(&self, key: &str, max: usize) -> bool {
        let now = Instant::now();
        let mut map = self
            .attempts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Opportunistic cleanup keeps the map from growing unboundedly.
        map.retain(|_, hits| {
            hits.retain(|t| now.duration_since(*t) < Self::WINDOW);
            !hits.is_empty()
        });
        let hits = map.entry(key.to_owned()).or_default();
        let allowed = hits.len() < max;
        if allowed {
            hits.push(now);
        }
        drop(map);
        allowed
    }
}

/// Authenticated request context: who is calling, for which tenant, as what.
///
/// Extracted, in order, from an `x-api-key` machine credential, an `HttpOnly`
/// session cookie (the browser console — CSRF-protected on unsafe methods), or
/// an `Authorization: Bearer <jwt>` session (programmatic clients). Every
/// `/api/*` handler takes this, which makes tenant scoping impossible to forget.
#[derive(Debug, Clone)]
pub struct AuthContext {
    /// Tenant all queries must be scoped to.
    pub tenant_id: Uuid,
    /// Interactive user id (`None` for API-key callers).
    pub user_id: Option<Uuid>,
    /// Login email (`None` for API-key callers).
    pub email: Option<String>,
    /// Effective access role.
    pub role: Role,
}

impl AuthContext {
    /// Enforce a minimum role; returns `403` when the caller is below it.
    pub fn require(&self, required: Role) -> Result<(), (StatusCode, String)> {
        if self.role >= required {
            Ok(())
        } else {
            Err((
                StatusCode::FORBIDDEN,
                format!("requires {} role", required.as_str()),
            ))
        }
    }
}

fn unauthorized(msg: &str) -> (StatusCode, String) {
    (StatusCode::UNAUTHORIZED, msg.to_owned())
}

impl<S> FromRequestParts<S> for AuthContext
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let state = AppState::from_ref(state);

        // Machine credential first: explicit header, no ambiguity with Bearer.
        if let Some(key) = parts.headers.get(API_KEY_HEADER) {
            let key = key.to_str().map_err(|_| unauthorized("invalid api key"))?;
            let found = state
                .store
                .find_api_key(&hash_api_key(key))
                .await
                .map_err(|_| unauthorized("invalid api key"))?
                .ok_or_else(|| unauthorized("invalid api key"))?;
            return Ok(Self {
                tenant_id: found.tenant_id,
                user_id: None,
                email: None,
                role: found.role,
            });
        }

        // Browser session: JWT in an HttpOnly cookie. Because the browser sends
        // it ambiently, every unsafe method must also echo the CSRF cookie in
        // the x-csrf-token header (double-submit). A present-but-invalid cookie
        // is rejected outright rather than falling through to the Bearer path.
        if let Some(token) = crate::cookies::read_cookie(&parts.headers, crate::cookies::SESSION_COOKIE)
        {
            let claims = verify_token(&state.keys, &token)
                .map_err(|_| unauthorized("invalid or expired session"))?;
            let csrf_cookie = crate::cookies::read_cookie(&parts.headers, crate::cookies::CSRF_COOKIE);
            let csrf_header = parts
                .headers
                .get(crate::cookies::CSRF_HEADER)
                .and_then(|v| v.to_str().ok());
            if !crate::cookies::csrf_ok(&parts.method, csrf_cookie.as_deref(), csrf_header) {
                return Err((
                    StatusCode::FORBIDDEN,
                    "CSRF token missing or invalid".to_owned(),
                ));
            }
            return Ok(Self {
                tenant_id: claims.tid,
                user_id: Some(claims.sub),
                email: Some(claims.email),
                role: claims.role,
            });
        }

        let header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| unauthorized("missing credentials"))?;
        let token = header
            .strip_prefix("Bearer ")
            .ok_or_else(|| unauthorized("expected Bearer token"))?;
        let claims = verify_token(&state.keys, token)
            .map_err(|_| unauthorized("invalid or expired token"))?;
        Ok(Self {
            tenant_id: claims.tid,
            user_id: Some(claims.sub),
            email: Some(claims.email),
            role: claims.role,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_roundtrip() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(verify_password("correct horse battery staple", &hash));
        assert!(!verify_password("wrong", &hash));
        assert!(!verify_password("anything", "not-a-phc-hash"));
    }

    #[test]
    fn jwt_roundtrip_and_tamper_rejection() {
        let keys = AuthKeys::from_secret(b"test-secret-test-secret-test-secret!");
        let user = Uuid::new_v4();
        let tenant = Uuid::new_v4();
        let token = issue_token(&keys, user, tenant, Role::Analyst, "a@b.c").unwrap();
        let claims = verify_token(&keys, &token).unwrap();
        assert_eq!(claims.sub, user);
        assert_eq!(claims.tid, tenant);
        assert_eq!(claims.role, Role::Analyst);

        let other = AuthKeys::from_secret(b"another-secret-another-secret-32b!!!");
        assert!(verify_token(&other, &token).is_err());
    }

    #[test]
    fn api_key_hash_is_deterministic_and_prefixed() {
        let (plain, hash) = generate_api_key();
        assert!(plain.starts_with("argus_"));
        assert_eq!(hash_api_key(&plain), hash);
        let (plain2, hash2) = generate_api_key();
        assert_ne!(plain, plain2);
        assert_ne!(hash, hash2);
    }

    #[test]
    fn login_limiter_blocks_after_max_attempts() {
        let limiter = LoginLimiter::default();
        let max = LoginLimiter::PER_PAIR_MAX;
        for _ in 0..max {
            assert!(limiter.allow("1.2.3.4|a@b.c", max));
        }
        assert!(!limiter.allow("1.2.3.4|a@b.c", max));
        // A different (ip, email) key is unaffected — the victim logging in
        // from another IP is not locked out by an attacker's attempts.
        assert!(limiter.allow("9.9.9.9|a@b.c", max));
    }

    #[test]
    fn require_enforces_role_floor() {
        let ctx = AuthContext {
            tenant_id: Uuid::new_v4(),
            user_id: None,
            email: None,
            role: Role::Analyst,
        };
        assert!(ctx.require(Role::Viewer).is_ok());
        assert!(ctx.require(Role::Analyst).is_ok());
        assert!(ctx.require(Role::Admin).is_err());
    }
}
