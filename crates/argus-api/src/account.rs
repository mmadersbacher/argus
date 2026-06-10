//! Account & access management endpoints: tenant signup, login, session
//! introspection, and admin-only user / API-key management.

use argus_core::tenant::Role;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::{self, AuthContext};
use crate::{db, db_error, AppState};

const MIN_PASSWORD_LEN: usize = 10;

fn bad_request(msg: &str) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, msg.to_owned())
}

/// Map a sqlx error, turning unique violations into a 409 instead of a 500.
fn conflict_or_db_error(err: sqlx::Error, conflict_msg: &str) -> (StatusCode, String) {
    if err
        .as_database_error()
        .is_some_and(sqlx::error::DatabaseError::is_unique_violation)
    {
        (StatusCode::CONFLICT, conflict_msg.to_owned())
    } else {
        db_error(err)
    }
}

fn validate_credentials(email: &str, password: &str) -> Result<(), (StatusCode, String)> {
    if !email.contains('@') || email.len() < 3 {
        return Err(bad_request("invalid email"));
    }
    if password.len() < MIN_PASSWORD_LEN {
        return Err(bad_request("password must be at least 10 characters"));
    }
    Ok(())
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

/// Session payload returned by login and register.
#[derive(Serialize)]
pub struct SessionResponse {
    /// Bearer token for subsequent requests.
    token: String,
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
) -> Result<Json<SessionResponse>, (StatusCode, String)> {
    let token = auth::issue_token(&state.keys, user_id, tenant_id, role, email).map_err(|err| {
        tracing::error!(error = %err, "token issuance failed");
        (StatusCode::INTERNAL_SERVER_ERROR, "token error".to_owned())
    })?;
    Ok(Json(SessionResponse {
        token,
        email: email.to_owned(),
        role,
        tenant_id,
    }))
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
    Json(req): Json<RegisterRequest>,
) -> Result<Json<SessionResponse>, (StatusCode, String)> {
    if !state.signup_enabled {
        return Err((
            StatusCode::FORBIDDEN,
            "self-service signup is disabled (ARGUS_SIGNUP_ENABLED=false)".to_owned(),
        ));
    }
    let organization = req.organization.trim();
    if organization.is_empty() {
        return Err(bad_request("organization name required"));
    }
    let email = req.email.trim().to_lowercase();
    validate_credentials(&email, &req.password)?;
    let password_hash = auth::hash_password(&req.password).map_err(|err| {
        tracing::error!(error = %err, "password hashing failed");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "hashing error".to_owned(),
        )
    })?;

    let tenant_id = Uuid::new_v4();
    let user = db::UserRow {
        id: Uuid::new_v4(),
        tenant_id,
        email: email.clone(),
        password_hash,
        role: Role::Admin,
    };

    // Disambiguate taken slugs with a short suffix (race on the unique index
    // is still caught below and surfaces as a 409).
    let mut slug = slugify(organization);
    if db::tenant_slug_exists(&state.pool, &slug)
        .await
        .map_err(db_error)?
    {
        slug = format!("{slug}-{}", &tenant_id.simple().to_string()[..6]);
    }

    let mut tx = state.pool.begin().await.map_err(db_error)?;
    db::create_tenant(&mut *tx, tenant_id, organization, &slug)
        .await
        .map_err(|e| conflict_or_db_error(e, "organization already exists"))?;
    db::create_user(&mut *tx, &user)
        .await
        .map_err(|e| conflict_or_db_error(e, "email already registered"))?;
    tx.commit().await.map_err(db_error)?;

    db::audit(
        &state.pool,
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
    Json(req): Json<LoginRequest>,
) -> Result<Json<SessionResponse>, (StatusCode, String)> {
    let email = req.email.trim().to_lowercase();
    if !state.limiter.allow(&email) {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "too many login attempts — retry in a minute".to_owned(),
        ));
    }
    let user = db::find_user_by_email(&state.pool, &email)
        .await
        .map_err(db_error)?;
    let Some(user) = user else {
        // Burn comparable time for unknown emails to blunt user enumeration.
        let _ = auth::verify_password(&req.password, auth::dummy_hash());
        return Err((StatusCode::UNAUTHORIZED, "invalid credentials".to_owned()));
    };
    if !auth::verify_password(&req.password, &user.password_hash) {
        return Err((StatusCode::UNAUTHORIZED, "invalid credentials".to_owned()));
    }
    db::audit(
        &state.pool,
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
    let users = db::list_users(&state.pool, auth.tenant_id)
        .await
        .map_err(db_error)?;
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
    let password_hash = auth_hash(&req.password)?;
    let user = db::UserRow {
        id: Uuid::new_v4(),
        tenant_id: auth.tenant_id,
        email: email.clone(),
        password_hash,
        role: req.role,
    };
    db::create_user(&state.pool, &user)
        .await
        .map_err(|e| conflict_or_db_error(e, "email already registered"))?;
    db::audit(
        &state.pool,
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

fn auth_hash(password: &str) -> Result<String, (StatusCode, String)> {
    auth::hash_password(password).map_err(|err| {
        tracing::error!(error = %err, "password hashing failed");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "hashing error".to_owned(),
        )
    })
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
    let keys = db::list_api_keys(&state.pool, auth.tenant_id)
        .await
        .map_err(db_error)?;
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
    db::create_api_key(&state.pool, id, auth.tenant_id, name, &hash, req.role)
        .await
        .map_err(db_error)?;
    db::audit(
        &state.pool,
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
    let removed = db::delete_api_key(&state.pool, auth.tenant_id, id)
        .await
        .map_err(db_error)?;
    if !removed {
        return Err((StatusCode::NOT_FOUND, "api key not found".to_owned()));
    }
    db::audit(
        &state.pool,
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
        assert!(validate_credentials("a@b.c", "long-enough-pw").is_ok());
        assert!(validate_credentials("not-an-email", "long-enough-pw").is_err());
        assert!(validate_credentials("a@b.c", "short").is_err());
    }
}
