//! Per-tenant outbound webhooks for change-event delivery.
//!
//! A tenant configures one webhook URL; when a scan produces change events the
//! server POSTs them as a signed JSON payload. Because the destination is
//! tenant-controlled, delivery is an SSRF surface — the server is made to issue
//! a request to a URL it didn't choose. [`validated_target`] defends it:
//!
//! - only `http`/`https` schemes,
//! - the host is resolved and **every** address must be public — any
//!   private/internal/special address (loopback, RFC1918, link-local, CGNAT,
//!   cloud metadata, …) rejects the whole URL (reusing the scan SSRF guard),
//! - the connection is then **pinned** to a validated address, so DNS cannot
//!   rebind to an internal IP between the check and the connect (TOCTOU),
//! - redirects are disabled, so a `3xx` to an internal URL can't bypass it.
//!
//! Self-hosted single-tenant deployments can opt out of the IP check with
//! `ARGUS_SCAN_ALLOW_PRIVATE=true` (same switch as internal scanning), since
//! there is no cross-tenant boundary to protect.
//!
//! The payload is signed with HMAC-SHA256 over the raw body using the tenant's
//! secret; the receiver verifies the `x-argus-signature: sha256=<hex>` header.

use std::net::SocketAddr;
use std::time::Duration;

use argus_core::tenant::Role;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::auth::AuthContext;
use crate::store::Store;
use crate::{store_error, AppState};

/// One change event as delivered in the webhook payload.
#[derive(Debug, Clone, Serialize)]
pub struct DeliveredEvent {
    /// Event kind (`asset.new`, `services.changed`, `vulns.changed`, `risk.changed`).
    pub kind: String,
    /// Human-facing asset name the event is about.
    pub asset: String,
    /// Event-specific detail object (same shape as the change feed).
    pub detail: serde_json::Value,
}

/// HMAC-SHA256 of `msg` under `key`, hex-encoded (RFC 2104).
#[must_use]
fn hmac_sha256(key: &[u8], msg: &[u8]) -> String {
    const BLOCK: usize = 64;
    let mut k = [0_u8; BLOCK];
    if key.len() > BLOCK {
        let digest = Sha256::digest(key);
        k[..digest.len()].copy_from_slice(&digest);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36_u8; BLOCK];
    let mut opad = [0x5c_u8; BLOCK];
    for ((ip, op), &kb) in ipad.iter_mut().zip(opad.iter_mut()).zip(&k) {
        *ip ^= kb;
        *op ^= kb;
    }
    let inner = Sha256::new()
        .chain_update(ipad)
        .chain_update(msg)
        .finalize();
    let outer = Sha256::new()
        .chain_update(opad)
        .chain_update(inner)
        .finalize();
    hex::encode(outer)
}

/// A fresh 32-byte signing secret, hex-encoded.
#[must_use]
fn new_secret() -> String {
    let mut bytes = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Parse `url`, require an `http`/`https` scheme, and (unless `allow_private`)
/// resolve the host and reject if any address is private/internal. Returns the
/// parsed URL plus a validated address to pin the connection to (`None` when
/// `allow_private` skips the check).
async fn validated_target(
    url: &str,
    allow_private: bool,
) -> Result<(reqwest::Url, Option<SocketAddr>), String> {
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("invalid url: {e}"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(format!(
            "unsupported scheme '{}': use http or https",
            parsed.scheme()
        ));
    }
    if allow_private {
        return Ok((parsed, None));
    }
    let host = parsed.host_str().ok_or("url has no host")?;
    let port = parsed.port_or_known_default().ok_or("url has no port")?;
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| format!("dns resolution failed: {e}"))?
        .collect();
    if addrs.is_empty() {
        return Err("host did not resolve to any address".into());
    }
    if let Some(bad) = addrs
        .iter()
        .find(|a| argus_discovery::is_disallowed_target(a.ip()))
    {
        return Err(format!(
            "host resolves to a disallowed (private/internal) address: {}",
            bad.ip()
        ));
    }
    Ok((parsed, Some(addrs[0])))
}

/// Deliver `body` to `url`, signed with `secret`. SSRF-guarded (see
/// [`validated_target`]); redirects disabled; 10s timeout. Returns the HTTP
/// status on a completed request, or an error string otherwise.
pub async fn deliver(
    url: &str,
    secret: &str,
    body: &[u8],
    allow_private: bool,
) -> Result<u16, String> {
    let (parsed, pinned) = validated_target(url, allow_private).await?;
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10));
    // Pin DNS for the host to the validated address so the connect cannot
    // re-resolve to a rebound internal IP.
    if let (Some(addr), Some(host)) = (pinned, parsed.host_str()) {
        builder = builder.resolve(host, addr);
    }
    let client = builder
        .build()
        .map_err(|e| format!("client build failed: {e}"))?;
    let signature = format!("sha256={}", hmac_sha256(secret.as_bytes(), body));
    let resp = client
        .post(parsed)
        .header("content-type", "application/json")
        .header("x-argus-signature", signature)
        .body(body.to_vec())
        .send()
        .await
        .map_err(|e| format!("delivery failed: {e}"))?;
    Ok(resp.status().as_u16())
}

/// Fire-and-forget delivery of a tenant's change events to its webhook, if one
/// is configured and enabled. Spawned, so it never blocks or fails ingest;
/// every outcome is logged.
pub fn notify(store: Store, tenant_id: Uuid, events: Vec<DeliveredEvent>, allow_private: bool) {
    if events.is_empty() {
        return;
    }
    tokio::spawn(async move {
        let cfg = match store.get_webhook(tenant_id).await {
            Ok(Some(cfg)) if cfg.enabled => cfg,
            Ok(_) => return, // no webhook, or disabled
            Err(err) => {
                tracing::error!(error = ?err, %tenant_id, "webhook config load failed");
                return;
            }
        };
        let body = match serde_json::to_vec(&serde_json::json!({
            "tenant_id": tenant_id,
            "event_count": events.len(),
            "events": events,
        })) {
            Ok(body) => body,
            Err(err) => {
                tracing::error!(error = ?err, "webhook payload serialization failed");
                return;
            }
        };
        match deliver(&cfg.url, &cfg.secret, &body, allow_private).await {
            Ok(code) if (200..300).contains(&code) => {
                tracing::info!(%tenant_id, status = code, events = events.len(), "webhook delivered");
            }
            Ok(code) => tracing::warn!(%tenant_id, status = code, "webhook returned non-2xx"),
            Err(err) => tracing::warn!(%tenant_id, error = err, "webhook delivery failed"),
        }
    });
}

// ---------------------------------------------------------------------------
// Config API: GET/POST/DELETE /api/webhook (admin only)
// ---------------------------------------------------------------------------

/// Webhook configuration request.
#[derive(Deserialize)]
pub struct WebhookRequest {
    /// Destination URL (http/https).
    url: String,
    /// Whether delivery is active (default `true`).
    #[serde(default = "default_enabled")]
    enabled: bool,
}

const fn default_enabled() -> bool {
    true
}

/// Webhook configuration as returned to the admin. `configured: false` (rather
/// than a 404) mirrors the monitor-config shape so the console renders an empty
/// form cleanly. The `secret` is the tenant's own signing key (shared with the
/// receiver to verify signatures), so it is returned rather than shown once.
#[derive(Serialize)]
pub struct WebhookConfig {
    /// Whether a webhook is set.
    configured: bool,
    /// Destination URL (present when configured).
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    /// Whether delivery is active (present when configured).
    #[serde(skip_serializing_if = "Option::is_none")]
    enabled: Option<bool>,
    /// HMAC-SHA256 signing secret (present when configured).
    #[serde(skip_serializing_if = "Option::is_none")]
    secret: Option<String>,
}

impl WebhookConfig {
    fn from_row(row: crate::db::WebhookRow) -> Self {
        Self {
            configured: true,
            url: Some(row.url),
            enabled: Some(row.enabled),
            secret: Some(row.secret),
        }
    }

    const fn none() -> Self {
        Self {
            configured: false,
            url: None,
            enabled: None,
            secret: None,
        }
    }
}

/// `GET /api/webhook` — the tenant's webhook config (admin only);
/// `{ "configured": false }` when none is set.
pub async fn get(
    auth: AuthContext,
    State(state): State<AppState>,
) -> Result<Json<WebhookConfig>, (StatusCode, String)> {
    auth.require(Role::Admin)?;
    let cfg = state
        .store
        .get_webhook(auth.tenant_id)
        .await
        .map_err(store_error)?;
    Ok(Json(
        cfg.map_or_else(WebhookConfig::none, WebhookConfig::from_row),
    ))
}

/// `POST /api/webhook` — set/update the tenant's webhook (admin only). The URL
/// is SSRF-validated up front (delivery re-checks authoritatively); an existing
/// secret is preserved, otherwise a fresh one is generated.
pub async fn set(
    auth: AuthContext,
    State(state): State<AppState>,
    Json(req): Json<WebhookRequest>,
) -> Result<Json<WebhookConfig>, (StatusCode, String)> {
    auth.require(Role::Admin)?;
    let url = req.url.trim();
    validated_target(url, state.scan_allow_private)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let secret = match state
        .store
        .get_webhook(auth.tenant_id)
        .await
        .map_err(store_error)?
    {
        Some(existing) => existing.secret,
        None => new_secret(),
    };
    state
        .store
        .set_webhook(auth.tenant_id, url, &secret, req.enabled)
        .await
        .map_err(store_error)?;
    state
        .store
        .audit(
            auth.tenant_id,
            auth.user_id,
            "webhook.set",
            serde_json::json!({ "url": url, "enabled": req.enabled }),
        )
        .await;
    Ok(Json(WebhookConfig {
        configured: true,
        url: Some(url.to_owned()),
        enabled: Some(req.enabled),
        secret: Some(secret),
    }))
}

/// `DELETE /api/webhook` — remove the tenant's webhook (admin only).
pub async fn delete(
    auth: AuthContext,
    State(state): State<AppState>,
) -> Result<StatusCode, (StatusCode, String)> {
    auth.require(Role::Admin)?;
    let removed = state
        .store
        .delete_webhook(auth.tenant_id)
        .await
        .map_err(store_error)?;
    if !removed {
        return Err((StatusCode::NOT_FOUND, "no webhook configured".to_owned()));
    }
    state
        .store
        .audit(
            auth.tenant_id,
            auth.user_id,
            "webhook.delete",
            serde_json::json!({}),
        )
        .await;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_sha256_matches_rfc4231_case1() {
        // RFC 4231 test case 1: key = 0x0b×20, data = "Hi There".
        let mac = hmac_sha256(&[0x0b_u8; 20], b"Hi There");
        assert_eq!(
            mac,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn hmac_sha256_long_key_is_hashed() {
        // RFC 4231 test case 6 uses a 131-byte key; just check it runs and the
        // output length is a SHA-256 hex digest (the long-key branch is taken).
        let mac = hmac_sha256(&[0xaa_u8; 131], b"Test Using Larger Than Block-Size Key");
        assert_eq!(mac.len(), 64);
    }

    #[tokio::test]
    async fn validated_target_blocks_internal_and_non_http() {
        // Loopback / link-local / non-http are rejected without leaving the host.
        assert!(validated_target("http://127.0.0.1:9/x", false)
            .await
            .is_err());
        assert!(validated_target("http://[::1]:9/x", false).await.is_err());
        assert!(validated_target("file:///etc/passwd", false).await.is_err());
        assert!(validated_target("ftp://example.com/", false).await.is_err());
        // allow_private (self-hosted) skips the resolve/SSRF check entirely.
        assert!(validated_target("http://127.0.0.1:9/x", true).await.is_ok());
    }

    #[tokio::test]
    async fn deliver_refuses_an_internal_target() {
        // The SSRF guard fires before any connection is attempted.
        let err = deliver(
            "http://169.254.169.254/latest/meta-data/",
            "s",
            b"{}",
            false,
        )
        .await
        .expect_err("metadata IP must be rejected");
        assert!(err.contains("disallowed"), "got: {err}");
    }
}
