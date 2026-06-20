//! Account & access management endpoints: tenant signup, login, session
//! introspection, and admin-only user / API-key management.

use std::net::SocketAddr;

use argus_core::tenant::Role;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::header::SET_COOKIE;
use axum::http::StatusCode;
use axum::response::{AppendHeaders, IntoResponse};
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::{self, AuthContext, LoginLimiter};
use crate::{cookies, db, store_error, AppState};

const MIN_PASSWORD_LEN: usize = 10;

fn bad_request(msg: &str) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, msg.to_owned())
}

fn validate_credentials(email: &str, password: &str) -> Result<(), (StatusCode, String)> {
    if !is_plausible_email(email) {
        return Err(bad_request("invalid email address"));
    }
    if password.len() < MIN_PASSWORD_LEN {
        return Err(bad_request("password must be at least 10 characters"));
    }
    Ok(())
}

/// Light structural email check: exactly one `@`, a non-empty local part, and a
/// domain with a label and a 2+ character alphabetic TLD. Not RFC 5322 — just
/// enough to reject the obviously-malformed (`user@`, `@d`, `a@b`) that the old
/// `contains('@')` check let through, without pulling in a dependency.
fn is_plausible_email(email: &str) -> bool {
    if email.matches('@').count() != 1 {
        return false;
    }
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    if local.is_empty() {
        return false;
    }
    match domain.rsplit_once('.') {
        Some((host, tld)) => {
            !host.is_empty() && tld.len() >= 2 && tld.chars().all(|c| c.is_ascii_alphabetic())
        }
        None => false,
    }
}

/// URL-safe slug from an organization name (`Acme Corp` → `acme-corp`).
fn slugify(name: &str) -> String {
    let slug: String = name
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let slug = slug.trim_matches('-').to_owned();
    if slug.is_empty() {
        "org".to_owned()
    } else {
        slug
    }
}

fn hash_or_500(password: &str) -> Result<String, (StatusCode, String)> {
    auth::hash_password(password).map_err(|err| {
        tracing::error!(error = %err, "password hashing failed");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "hashing error".to_owned(),
        )
    })
}

/// Session payload returned by login and register. The JWT is delivered only
/// in the `HttpOnly` session cookie, never in this body, so it is never
/// readable from JavaScript.
#[derive(Serialize)]
pub struct SessionResponse {
    /// Login email.
    email: String,
    /// Access role.
    role: Role,
    /// Tenant the session is scoped to.
    tenant_id: Uuid,
}

fn session_response(
    state: &AppState,
    user_id: Uuid,
    tenant_id: Uuid,
    role: Role,
    email: &str,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = auth::issue_token(&state.keys, user_id, tenant_id, role, email).map_err(|err| {
        tracing::error!(error = %err, "token issuance failed");
        (StatusCode::INTERNAL_SERVER_ERROR, "token error".to_owned())
    })?;
    // The console authenticates with the HttpOnly session cookie (the JWT is
    // never exposed to JS); the JS-readable CSRF cookie is echoed back on unsafe
    // requests as a double-submit. Both expire with the JWT.
    let max_age = auth::token_ttl_hours() * 3600;
    let set_session = state
        .cookie_cfg
        .set(cookies::SESSION_COOKIE, &token, max_age, true);
    let set_csrf =
        state
            .cookie_cfg
            .set(cookies::CSRF_COOKIE, &cookies::new_csrf_token(), max_age, false);
    Ok((
        AppendHeaders([(SET_COOKIE, set_session), (SET_COOKIE, set_csrf)]),
        Json(SessionResponse {
            email: email.to_owned(),
            role,
            tenant_id,
        }),
    ))
}

/// `POST /api/auth/logout` — clear the session and CSRF cookies.
///
/// Deliberately unauthenticated and CSRF-exempt: clearing one's own cookies has
/// no security impact, and logout must work even after the session has expired.
pub async fn logout(State(state): State<AppState>) -> impl IntoResponse {
    let clear_session = state.cookie_cfg.clear(cookies::SESSION_COOKIE, true);
    let clear_csrf = state.cookie_cfg.clear(cookies::CSRF_COOKIE, false);
    (
        AppendHeaders([(SET_COOKIE, clear_session), (SET_COOKIE, clear_csrf)]),
        StatusCode::NO_CONTENT,
    )
}

/// `POST /api/auth/register` — self-service tenant signup.
#[derive(Deserialize)]
pub struct RegisterRequest {
    /// Organization (tenant) display name.
    organization: String,
    /// Admin login email.
    email: String,
    /// Admin password (min 10 chars).
    password: String,
}

/// Create a new tenant with its first (admin) user and return a session.
pub async fn register(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<RegisterRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !state.signup_enabled {
        return Err((
            StatusCode::FORBIDDEN,
            "self-service signup is disabled (ARGUS_SIGNUP_ENABLED=false)".to_owned(),
        ));
    }
    // Per-IP budget so an enabled signup endpoint can't be used for tenant-spam
    // or email-enumeration (the 409 below is an existence oracle). Mirrors login.
    if !state
        .limiter
        .allow(&format!("signup:{}", addr.ip()), LoginLimiter::PER_IP_MAX)
    {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "too many signup attempts — retry in a minute".to_owned(),
        ));
    }
    let organization = req.organization.trim();
    if organization.is_empty() {
        return Err(bad_request("organization name required"));
    }
    let email = req.email.trim().to_lowercase();
    validate_credentials(&email, &req.password)?;

    if state
        .store
        .user_email_exists(&email)
        .await
        .map_err(store_error)?
    {
        return Err((StatusCode::CONFLICT, "email already registered".to_owned()));
    }
    let password_hash = hash_or_500(&req.password)?;

    let tenant_id = Uuid::new_v4();
    let user = db::UserRow {
        id: Uuid::new_v4(),
        tenant_id,
        email: email.clone(),
        password_hash,
        role: Role::Admin,
    };

    // Disambiguate a taken slug with a short suffix; the store's uniqueness
    // guard still catches the rare race and surfaces it as a 409.
    let mut slug = slugify(organization);
    if state
        .store
        .tenant_slug_exists(&slug)
        .await
        .map_err(store_error)?
    {
        slug = format!("{slug}-{}", &tenant_id.simple().to_string()[..6]);
    }

    state
        .store
        .register_tenant(tenant_id, organization, &slug, &user)
        .await
        .map_err(store_error)?;

    state
        .store
        .audit(
            tenant_id,
            Some(user.id),
            "tenant.register",
            serde_json::json!({ "organization": organization, "email": email }),
        )
        .await;
    tracing::info!(%tenant_id, email, "tenant registered");
    session_response(&state, user.id, tenant_id, Role::Admin, &email)
}

/// `POST /api/auth/login` — credentials in, Bearer token out.
#[derive(Deserialize)]
pub struct LoginRequest {
    /// Login email.
    email: String,
    /// Password.
    password: String,
}

/// Authenticate a user and return a session token.
pub async fn login(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<LoginRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let email = req.email.trim().to_lowercase();
    // Two rate-limit dimensions: a loose per-IP budget (caps spraying across
    // many accounts) and a tight per-(ip,email) budget (stops targeted brute
    // force without letting an attacker lock the victim out from another IP).
    let ip = addr.ip();
    let too_many = !state
        .limiter
        .allow(&format!("ip:{ip}"), LoginLimiter::PER_IP_MAX)
        || !state
            .limiter
            .allow(&format!("pair:{ip}|{email}"), LoginLimiter::PER_PAIR_MAX);
    if too_many {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "too many login attempts — retry in a minute".to_owned(),
        ));
    }
    let user = state
        .store
        .find_user_by_email(&email)
        .await
        .map_err(store_error)?;
    let Some(user) = user else {
        // Burn comparable time for unknown emails to blunt user enumeration.
        let _ = auth::verify_password(&req.password, auth::dummy_hash());
        return Err((StatusCode::UNAUTHORIZED, "invalid credentials".to_owned()));
    };
    if !auth::verify_password(&req.password, &user.password_hash) {
        return Err((StatusCode::UNAUTHORIZED, "invalid credentials".to_owned()));
    }
    state
        .store
        .audit(
            user.tenant_id,
            Some(user.id),
            "auth.login",
            serde_json::json!({ "email": email }),
        )
        .await;
    session_response(&state, user.id, user.tenant_id, user.role, &email)
}

/// Caller identity as seen by the API.
#[derive(Serialize)]
pub struct MeResponse {
    /// Tenant scope.
    tenant_id: Uuid,
    /// User id (absent for API-key callers).
    user_id: Option<Uuid>,
    /// Login email (absent for API-key callers).
    email: Option<String>,
    /// Effective role.
    role: Role,
}

/// `GET /api/auth/me` — introspect the current credential.
pub async fn me(auth: AuthContext) -> Json<MeResponse> {
    Json(MeResponse {
        tenant_id: auth.tenant_id,
        user_id: auth.user_id,
        email: auth.email,
        role: auth.role,
    })
}

// ---------------------------------------------------------------------------
// Admin: users
// ---------------------------------------------------------------------------

/// A user as listed to tenant admins.
#[derive(Serialize)]
pub struct UserSummary {
    /// Stable identifier.
    id: Uuid,
    /// Login email.
    email: String,
    /// Access role.
    role: Role,
}

/// `GET /api/users` — list the tenant's users (admin only).
pub async fn list_users(
    auth: AuthContext,
    State(state): State<AppState>,
) -> Result<Json<Vec<UserSummary>>, (StatusCode, String)> {
    auth.require(Role::Admin)?;
    let users = state
        .store
        .list_users(auth.tenant_id)
        .await
        .map_err(store_error)?;
    Ok(Json(
        users
            .into_iter()
            .map(|(id, email, role)| UserSummary { id, email, role })
            .collect(),
    ))
}

/// `POST /api/users` — create a user in the caller's tenant.
#[derive(Deserialize)]
pub struct CreateUserRequest {
    /// Login email.
    email: String,
    /// Initial password (min 10 chars).
    password: String,
    /// Access role.
    role: Role,
}

/// Create a user in the caller's tenant (admin only).
pub async fn create_user(
    auth: AuthContext,
    State(state): State<AppState>,
    Json(req): Json<CreateUserRequest>,
) -> Result<Json<UserSummary>, (StatusCode, String)> {
    auth.require(Role::Admin)?;
    let email = req.email.trim().to_lowercase();
    validate_credentials(&email, &req.password)?;
    let password_hash = hash_or_500(&req.password)?;
    let user = db::UserRow {
        id: Uuid::new_v4(),
        tenant_id: auth.tenant_id,
        email: email.clone(),
        password_hash,
        role: req.role,
    };
    state.store.create_user(&user).await.map_err(store_error)?;
    state
        .store
        .audit(
            auth.tenant_id,
            auth.user_id,
            "user.create",
            serde_json::json!({ "email": email, "role": req.role.as_str() }),
        )
        .await;
    Ok(Json(UserSummary {
        id: user.id,
        email,
        role: req.role,
    }))
}

// ---------------------------------------------------------------------------
// Admin: API keys
// ---------------------------------------------------------------------------

/// An API key as listed to tenant admins (never includes the secret).
#[derive(Serialize)]
pub struct ApiKeySummary {
    /// Stable identifier.
    id: Uuid,
    /// Display name.
    name: String,
    /// Role the key grants.
    role: Role,
}

/// `GET /api/api-keys` — list the tenant's API keys (admin only).
pub async fn list_api_keys(
    auth: AuthContext,
    State(state): State<AppState>,
) -> Result<Json<Vec<ApiKeySummary>>, (StatusCode, String)> {
    auth.require(Role::Admin)?;
    let keys = state
        .store
        .list_api_keys(auth.tenant_id)
        .await
        .map_err(store_error)?;
    Ok(Json(
        keys.into_iter()
            .map(|(id, name, role)| ApiKeySummary { id, name, role })
            .collect(),
    ))
}

/// `POST /api/api-keys` — create a machine credential.
#[derive(Deserialize)]
pub struct CreateApiKeyRequest {
    /// Display name (e.g. "ci-importer").
    name: String,
    /// Role the key grants.
    role: Role,
}

/// The one-time response containing the plaintext key.
#[derive(Serialize)]
pub struct CreatedApiKey {
    /// Stable identifier.
    id: Uuid,
    /// Display name.
    name: String,
    /// Role the key grants.
    role: Role,
    /// Plaintext secret — shown exactly once, only the hash is stored.
    key: String,
}

/// Create an API key for the caller's tenant (admin only).
pub async fn create_api_key(
    auth: AuthContext,
    State(state): State<AppState>,
    Json(req): Json<CreateApiKeyRequest>,
) -> Result<Json<CreatedApiKey>, (StatusCode, String)> {
    auth.require(Role::Admin)?;
    let name = req.name.trim();
    if name.is_empty() {
        return Err(bad_request("key name required"));
    }
    let (plaintext, hash) = auth::generate_api_key();
    let id = Uuid::new_v4();
    state
        .store
        .create_api_key(id, auth.tenant_id, name, &hash, req.role)
        .await
        .map_err(store_error)?;
    state
        .store
        .audit(
            auth.tenant_id,
            auth.user_id,
            "apikey.create",
            serde_json::json!({ "name": name, "role": req.role.as_str() }),
        )
        .await;
    Ok(Json(CreatedApiKey {
        id,
        name: name.to_owned(),
        role: req.role,
        key: plaintext,
    }))
}

/// `DELETE /api/api-keys/{id}` — revoke a key (admin only).
pub async fn delete_api_key(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    auth.require(Role::Admin)?;
    let removed = state
        .store
        .delete_api_key(auth.tenant_id, id)
        .await
        .map_err(store_error)?;
    if !removed {
        return Err((StatusCode::NOT_FOUND, "api key not found".to_owned()));
    }
    state
        .store
        .audit(
            auth.tenant_id,
            auth.user_id,
            "apikey.delete",
            serde_json::json!({ "id": id }),
        )
        .await;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugify_normalizes() {
        assert_eq!(slugify("Acme Corp"), "acme-corp");
        assert_eq!(slugify("Über GmbH!"), "ber-gmbh");
        assert_eq!(slugify("___"), "org");
    }

    #[test]
    fn credential_validation() {
        assert!(validate_credentials("user@example.com", "long-enough-pw").is_ok());
        assert!(validate_credentials("not-an-email", "long-enough-pw").is_err());
        assert!(validate_credentials("user@example.com", "short").is_err());
    }

    #[test]
    fn email_rejects_malformed_but_accepts_real() {
        for ok in ["a@b.co", "user.name@sub.example.com", "x@y.io"] {
            assert!(is_plausible_email(ok), "{ok} should be accepted");
        }
        for bad in [
            "user@",       // no domain
            "@domain.com", // no local part
            "a@b",         // no TLD
            "a@b.c",       // 1-char TLD
            "a@b@c.com",   // two @
            "plain",       // no @
            "a@b.123",     // numeric TLD
        ] {
            assert!(!is_plausible_email(bad), "{bad} should be rejected");
        }
    }
}
