//! Asset topology graph: `GET /api/graph` turns the tenant's inventory into a
//! node/edge graph the console renders force-directed. Nodes are assets plus a
//! hub per `/24` subnet they sit in; edges link each asset to its subnet hub.
//! This is an honest topology derived from observed IPs — not inferred traffic
//! links (Argus has no passive traffic data yet).

use std::collections::BTreeMap;
use std::net::IpAddr;

use argus_core::{AssetType, Exposure, RiskBand};
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Serialize;

use crate::auth::AuthContext;
use crate::seed::ScoredAsset;
use crate::{monitor, store_error, AppState};

/// Node category in the topology graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeKind {
    /// A discovered asset.
    Asset,
    /// A `/24` subnet hub that groups its assets.
    Subnet,
}

/// One graph node — an asset or a subnet hub.
#[derive(Debug, Clone, Serialize)]
pub struct GraphNode {
    /// Stable id: the asset uuid, or `subnet:<cidr>` for a hub.
    pub id: String,
    /// Node category.
    pub kind: NodeKind,
    /// Display label.
    pub label: String,
    /// Group key — the `/24` (or `unzoned`) the node belongs to; lets the
    /// client cluster and colour by zone.
    pub group: String,
    /// Asset type (asset nodes only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset_type: Option<AssetType>,
    /// Composite risk `0..=100` (asset nodes only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk: Option<f32>,
    /// Qualitative band (asset nodes only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub band: Option<RiskBand>,
    /// Network exposure (asset nodes only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exposure: Option<Exposure>,
    /// Number of assets in the subnet (subnet hubs only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<usize>,
}

/// One edge: an asset linked to its subnet hub.
#[derive(Debug, Clone, Serialize)]
pub struct GraphEdge {
    /// Source node id (asset).
    pub source: String,
    /// Target node id (subnet hub).
    pub target: String,
}

/// The full topology graph.
#[derive(Debug, Clone, Default, Serialize)]
pub struct GraphData {
    /// All nodes (assets + subnet hubs).
    pub nodes: Vec<GraphNode>,
    /// All edges (asset → subnet hub).
    pub edges: Vec<GraphEdge>,
}

/// Group key for an asset: its first IPv4 interface as a `/24`, else `unzoned`.
fn group_of(asset: &ScoredAsset) -> String {
    asset
        .asset
        .interfaces
        .iter()
        .find_map(|iface| match iface.ip {
            Some(IpAddr::V4(v4)) => {
                let o = v4.octets();
                Some(format!("{}.{}.{}.0/24", o[0], o[1], o[2]))
            }
            _ => None,
        })
        .unwrap_or_else(|| "unzoned".to_owned())
}

/// Build the topology graph from a tenant's inventory: one node per asset, one
/// hub per `/24` subnet, and an edge from each asset to its hub.
#[must_use]
pub fn build(assets: &[ScoredAsset]) -> GraphData {
    let mut nodes: Vec<GraphNode> = Vec::with_capacity(assets.len());
    let mut edges: Vec<GraphEdge> = Vec::with_capacity(assets.len());
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();

    for asset in assets {
        let group = group_of(asset);
        *counts.entry(group.clone()).or_default() += 1;
        let id = asset.asset.id.0.to_string();
        edges.push(GraphEdge {
            source: id.clone(),
            target: format!("subnet:{group}"),
        });
        nodes.push(GraphNode {
            id,
            kind: NodeKind::Asset,
            label: monitor::asset_name(asset),
            group,
            asset_type: Some(asset.asset.asset_type),
            risk: Some(asset.risk.value),
            band: Some(asset.risk.band),
            exposure: Some(asset.asset.exposure),
            count: None,
        });
    }

    for (group, count) in counts {
        nodes.push(GraphNode {
            id: format!("subnet:{group}"),
            kind: NodeKind::Subnet,
            label: group.clone(),
            group,
            asset_type: None,
            risk: None,
            band: None,
            exposure: None,
            count: Some(count),
        });
    }

    GraphData { nodes, edges }
}

/// `GET /api/graph` — the tenant's asset topology graph. Readable by every
/// authenticated role.
pub async fn get_graph(
    auth: AuthContext,
    State(state): State<AppState>,
) -> Result<Json<GraphData>, (StatusCode, String)> {
    let assets = state
        .store
        .load_all(auth.tenant_id)
        .await
        .map_err(store_error)?;
    Ok(Json(build(&assets)))
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn graph_has_one_node_and_edge_per_asset_plus_subnet_hubs() {
        let assets = crate::seed::seed_assets();
        let g = build(&assets);

        // One asset node and one edge per asset.
        let asset_nodes = g.nodes.iter().filter(|n| n.kind == NodeKind::Asset).count();
        assert_eq!(asset_nodes, assets.len());
        assert_eq!(g.edges.len(), assets.len());

        // Every edge points at a real subnet hub node.
        let hubs: HashSet<&str> = g
            .nodes
            .iter()
            .filter(|n| n.kind == NodeKind::Subnet)
            .map(|n| n.id.as_str())
            .collect();
        assert!(!hubs.is_empty());
        assert!(g.edges.iter().all(|e| hubs.contains(e.target.as_str())));

        // Subnet hub counts sum back to the asset total.
        let total: usize = g.nodes.iter().filter_map(|n| n.count).sum();
        assert_eq!(total, assets.len());
    }

    #[test]
    fn assets_in_the_same_24_share_a_hub() {
        // Two assets in 10.0.0.0/24, one in 10.0.9.0/24 → two hubs.
        let mut a = crate::seed::seed_assets()
            .into_iter()
            .take(3)
            .collect::<Vec<_>>();
        assert!(a.len() >= 3, "seed has at least 3 assets");
        let ips = ["10.0.0.5", "10.0.0.9", "10.0.9.5"];
        for (asset, ip) in a.iter_mut().zip(ips) {
            asset.asset.interfaces = vec![argus_core::Interface {
                mac: None,
                ip: Some(ip.parse().unwrap()),
                vlan: None,
                hostname: None,
            }];
        }
        let g = build(&a);
        let hubs: Vec<&str> = g
            .nodes
            .iter()
            .filter(|n| n.kind == NodeKind::Subnet)
            .map(|n| n.label.as_str())
            .collect();
        assert!(hubs.contains(&"10.0.0.0/24"));
        assert!(hubs.contains(&"10.0.9.0/24"));
        assert_eq!(hubs.len(), 2);
    }
}
