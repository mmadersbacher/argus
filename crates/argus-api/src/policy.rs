//! `GET /api/policy` — advisory segmentation findings for the caller's
//! tenant. Rule evaluation is pure and lives in `argus-policy`; this module
//! only maps the stored inventory into the evaluator's input facts.

use argus_policy::{Advisory, PolicyAsset};
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

use crate::auth::AuthContext;
use crate::monitor;
use crate::{store_error, AppState};

/// Evaluate the segmentation rules. Readable by every authenticated role.
pub async fn get_policy(
    auth: AuthContext,
    State(state): State<AppState>,
) -> Result<Json<Vec<Advisory>>, (StatusCode, String)> {
    let assets = state
        .store
        .load_all(auth.tenant_id)
        .await
        .map_err(store_error)?;
    let facts: Vec<PolicyAsset> = assets
        .iter()
        .map(|a| PolicyAsset {
            name: monitor::asset_name(a),
            ip: a.asset.interfaces.iter().find_map(|i| i.ip),
            asset_type: a.asset.asset_type,
            criticality: a.asset.criticality,
            exposure: a.asset.exposure,
            open_ports: a.services.iter().map(|s| s.port).collect(),
            has_kev: a.vulnerabilities.iter().any(|v| v.kev),
            os: a.asset.fingerprint.os.clone(),
            device_role: a.asset.fingerprint.role(),
        })
        .collect();
    Ok(Json(argus_policy::evaluate(&facts)))
}
