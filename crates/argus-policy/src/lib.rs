//! # argus-policy
//!
//! Advisory segmentation: evaluate a tenant's inventory against zoning and
//! exposure rules and emit [`Advisory`] findings — what to segment, isolate
//! or shut off, and why. Advisory only: Argus observes and recommends, it
//! never enforces.
//!
//! The evaluator is pure and IO-free (callers map their inventory into
//! [`PolicyAsset`] facts), so every rule is unit-testable. Zones are
//! approximated by IPv4 /24 — the same grouping the console's network view
//! uses — which is deliberately crude but works without switch/VLAN
//! telemetry.

use std::collections::BTreeMap;
use std::net::IpAddr;

use argus_core::{AssetType, Criticality, Exposure};
use serde::Serialize;

/// Management / database / remote-access ports that must not face the
/// internet. The criticality split mirrors `insecure_service_score` in
/// argus-discovery: cleartext or wormable services are critical, the rest
/// high.
const EXPOSED_CRITICAL_PORTS: &[u16] = &[23, 445, 3389, 5900, 2375];
/// Remaining management-plane ports: high (not critical) when exposed.
const EXPOSED_HIGH_PORTS: &[u16] = &[
    21, 22, 111, 135, 139, 161, 389, 623, 1433, 3306, 5432, 5985, 6379, 9200, 11211, 27017,
];
/// Industrial-control protocol ports (Modbus, S7, DNP3, BACnet) — these mark
/// OT process traffic that must never leave its cell/zone.
const ICS_PORTS: &[u16] = &[102, 502, 20000, 47808];
/// Clear-text legacy protocols worth flagging anywhere, not only at the edge.
const CLEARTEXT_PORTS: &[u16] = &[21, 23];

/// Minimum inventory size before the flat-network heuristic applies.
const FLAT_MIN_ASSETS: usize = 10;
/// Share of assets in one /24 that makes a network look unsegmented.
const FLAT_SHARE: f32 = 0.85;
/// Distinct asset types in that subnet before flatness is worth flagging.
const FLAT_MIN_TYPES: usize = 3;
/// Low-trust (IoT) device count that makes a shared zone noisy enough to
/// flag for co-located high-value assets.
const NOISY_IOT_COUNT: usize = 3;

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

/// One asset, reduced to the facts the policy rules consume.
#[derive(Debug, Clone)]
pub struct PolicyAsset {
    /// Display name (hostname > IP > id prefix, as shown in the console).
    pub name: String,
    /// Primary IP, if known (used for /24 zone grouping).
    pub ip: Option<IpAddr>,
    /// Classified asset type.
    pub asset_type: AssetType,
    /// Business criticality.
    pub criticality: Criticality,
    /// Network exposure.
    pub exposure: Exposure,
    /// Open TCP/UDP ports.
    pub open_ports: Vec<u16>,
    /// Whether the asset carries at least one CISA-KEV-listed CVE.
    pub has_kev: bool,
}

impl PolicyAsset {
    fn internet_facing(&self) -> bool {
        self.exposure == Exposure::InternetFacing
    }

    fn is_ot(&self) -> bool {
        matches!(self.asset_type, AssetType::Ot | AssetType::Iomt)
    }

    fn open_any(&self, ports: &[u16]) -> Vec<u16> {
        let mut hit: Vec<u16> = self
            .open_ports
            .iter()
            .copied()
            .filter(|p| ports.contains(p))
            .collect();
        hit.sort_unstable();
        hit.dedup();
        hit
    }

    /// `"192.168.1.0/24"` for IPv4; `None` for IPv6 or unknown IPs (zone
    /// heuristics skip those assets rather than guess).
    fn subnet(&self) -> Option<String> {
        match self.ip {
            Some(IpAddr::V4(v4)) => {
                let o = v4.octets();
                Some(format!("{}.{}.{}.0/24", o[0], o[1], o[2]))
            }
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Advisory model
// ---------------------------------------------------------------------------

/// Urgency of an advisory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AdvisoryLevel {
    /// Fix or isolate now.
    Critical,
    /// Schedule remediation.
    High,
    /// Improve when touching the zone next.
    Medium,
    /// Worth knowing.
    Low,
}

/// One affected asset within an advisory, with rule-specific evidence.
#[derive(Debug, Clone, Serialize)]
pub struct AffectedAsset {
    /// Display name.
    pub name: String,
    /// Rule-specific evidence (exposed ports, subnet, ...).
    pub evidence: String,
}

/// One actionable segmentation / exposure finding.
#[derive(Debug, Clone, Serialize)]
pub struct Advisory {
    /// Stable rule id (`kev-internet`, `mgmt-exposed`, ...).
    pub rule: &'static str,
    /// Urgency.
    pub level: AdvisoryLevel,
    /// One-line finding.
    pub title: String,
    /// Why this matters (the risk being taken).
    pub rationale: String,
    /// What to do about it.
    pub recommendation: String,
    /// Affected assets with evidence, worst-first where the rule has an
    /// internal ordering.
    pub affected: Vec<AffectedAsset>,
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

/// Evaluate every rule against the inventory. Advisories come back sorted by
/// urgency (critical first); rules that find nothing emit nothing.
#[must_use]
pub fn evaluate(assets: &[PolicyAsset]) -> Vec<Advisory> {
    let mut advisories: Vec<Advisory> = [
        kev_internet(assets),
        mgmt_exposed(assets),
        mgmt_reachable_internal(assets),
        ics_reachable(assets),
        iot_internet(assets),
        ot_mixed_zone(assets),
        cleartext_protocols(assets),
        high_value_in_noisy_zone(assets),
        flat_network(assets),
    ]
    .into_iter()
    .flatten()
    .collect();
    advisories.sort_by_key(|a| a.level);
    advisories
}

/// Internet-facing assets carrying KEV-listed CVEs: the intersection of
/// "reachable by anyone" and "exploitation observed in the wild".
fn kev_internet(assets: &[PolicyAsset]) -> Option<Advisory> {
    let affected: Vec<AffectedAsset> = assets
        .iter()
        .filter(|a| a.internet_facing() && a.has_kev)
        .map(|a| AffectedAsset {
            name: a.name.clone(),
            evidence: "internet-facing with KEV-listed CVE(s)".to_owned(),
        })
        .collect();
    (!affected.is_empty()).then(|| Advisory {
        rule: "kev-internet",
        level: AdvisoryLevel::Critical,
        title: format!(
            "{} internet-facing asset(s) carry actively exploited CVEs",
            affected.len()
        ),
        rationale: "These assets combine public reachability with vulnerabilities on the CISA \
                    Known Exploited Vulnerabilities catalog — the highest-probability breach \
                    path in the inventory."
            .to_owned(),
        recommendation: "Patch immediately, or pull the assets behind a VPN / allow-list \
                         firewall rule until patched."
            .to_owned(),
        affected,
    })
}

/// Management, database and remote-access services reachable from the
/// internet.
fn mgmt_exposed(assets: &[PolicyAsset]) -> Option<Advisory> {
    let mut affected = Vec::new();
    let mut worst_is_critical = false;
    for a in assets.iter().filter(|a| a.internet_facing()) {
        let crit = a.open_any(EXPOSED_CRITICAL_PORTS);
        let high = a.open_any(EXPOSED_HIGH_PORTS);
        if crit.is_empty() && high.is_empty() {
            continue;
        }
        worst_is_critical |= !crit.is_empty();
        let ports: Vec<String> = crit.iter().chain(&high).map(u16::to_string).collect();
        affected.push(AffectedAsset {
            name: a.name.clone(),
            evidence: format!("exposed: {}", ports.join(", ")),
        });
    }
    (!affected.is_empty()).then(|| Advisory {
        rule: "mgmt-exposed",
        level: if worst_is_critical {
            AdvisoryLevel::Critical
        } else {
            AdvisoryLevel::High
        },
        title: format!(
            "{} asset(s) expose management or database services to the internet",
            affected.len()
        ),
        rationale: "Remote-access, file-sharing and database ports on internet-facing assets \
                    are the standard initial-access surface (brute force, wormable exploits, \
                    credential stuffing)."
            .to_owned(),
        recommendation: "Close these ports at the edge; reach management planes through a VPN \
                         or bastion only. Databases belong on internal segments."
            .to_owned(),
        affected,
    })
}

/// Industrial-control protocol ports on internet-facing assets.
fn ics_reachable(assets: &[PolicyAsset]) -> Option<Advisory> {
    let affected: Vec<AffectedAsset> = assets
        .iter()
        .filter(|a| a.internet_facing())
        .filter_map(|a| {
            let ics = a.open_any(ICS_PORTS);
            (!ics.is_empty()).then(|| AffectedAsset {
                name: a.name.clone(),
                evidence: format!(
                    "ICS protocol port(s): {}",
                    ics.iter()
                        .map(u16::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            })
        })
        .collect();
    (!affected.is_empty()).then(|| Advisory {
        rule: "ics-internet",
        level: AdvisoryLevel::Critical,
        title: format!(
            "{} asset(s) expose industrial-control protocols to the internet",
            affected.len()
        ),
        rationale: "Modbus, S7, DNP3 and BACnet have no meaningful authentication — anyone who \
                    can reach the port can read or write process state."
            .to_owned(),
        recommendation: "Remove internet reachability entirely; ICS traffic stays inside its \
                         cell/zone with a unidirectional gateway or jump host for access."
            .to_owned(),
        affected,
    })
}

/// IoT / IoMT devices reachable from the internet.
fn iot_internet(assets: &[PolicyAsset]) -> Option<Advisory> {
    let affected: Vec<AffectedAsset> = assets
        .iter()
        .filter(|a| a.internet_facing() && matches!(a.asset_type, AssetType::Iot | AssetType::Iomt))
        .map(|a| AffectedAsset {
            name: a.name.clone(),
            evidence: "internet-facing IoT/IoMT device".to_owned(),
        })
        .collect();
    (!affected.is_empty()).then(|| Advisory {
        rule: "iot-internet",
        level: AdvisoryLevel::High,
        title: format!("{} IoT/IoMT device(s) are internet-facing", affected.len()),
        rationale: "Embedded devices rarely receive timely firmware fixes and are routinely \
                    conscripted into botnets; medical devices add safety impact."
            .to_owned(),
        recommendation: "Move them to an isolated VLAN with egress-only NAT; front any needed \
                         remote access with an authenticated proxy."
            .to_owned(),
        affected,
    })
}

/// OT / IoMT devices sharing a /24 with general-purpose IT.
fn ot_mixed_zone(assets: &[PolicyAsset]) -> Option<Advisory> {
    let mut zones: BTreeMap<String, (Vec<&PolicyAsset>, bool)> = BTreeMap::new();
    for a in assets {
        let Some(subnet) = a.subnet() else { continue };
        let entry = zones.entry(subnet).or_default();
        if a.is_ot() {
            entry.0.push(a);
        } else if matches!(a.asset_type, AssetType::It | AssetType::Unknown) {
            entry.1 = true;
        }
    }
    let affected: Vec<AffectedAsset> = zones
        .into_iter()
        .filter(|(_, (ot, has_it))| !ot.is_empty() && *has_it)
        .flat_map(|(subnet, (ot, _))| {
            ot.into_iter().map(move |a| AffectedAsset {
                name: a.name.clone(),
                evidence: format!("OT/IoMT in mixed zone {subnet}"),
            })
        })
        .collect();
    (!affected.is_empty()).then(|| Advisory {
        rule: "ot-mixed-zone",
        level: AdvisoryLevel::High,
        title: format!(
            "{} OT/IoMT device(s) share a subnet with general IT",
            affected.len()
        ),
        rationale: "A compromised workstation in the same broadcast domain can reach process \
                    equipment directly — the exact lateral path ICS segmentation models \
                    (Purdue/IEC 62443) exist to cut."
            .to_owned(),
        recommendation: "Put OT/IoMT in dedicated zones behind a firewall; allow only the \
                         specific engineering/historian flows that are actually needed."
            .to_owned(),
        affected,
    })
}

/// Clear-text legacy protocols (telnet, FTP) anywhere in the inventory.
fn cleartext_protocols(assets: &[PolicyAsset]) -> Option<Advisory> {
    let affected: Vec<AffectedAsset> = assets
        .iter()
        .filter_map(|a| {
            let hit = a.open_any(CLEARTEXT_PORTS);
            (!hit.is_empty()).then(|| AffectedAsset {
                name: a.name.clone(),
                evidence: hit
                    .iter()
                    .map(|p| match p {
                        21 => "ftp (21)".to_owned(),
                        23 => "telnet (23)".to_owned(),
                        other => other.to_string(),
                    })
                    .collect::<Vec<_>>()
                    .join(", "),
            })
        })
        .collect();
    (!affected.is_empty()).then(|| Advisory {
        rule: "cleartext-protocols",
        level: AdvisoryLevel::Medium,
        title: format!(
            "{} asset(s) run clear-text legacy protocols",
            affected.len()
        ),
        rationale: "Telnet and FTP transmit credentials unencrypted; one passive listener on \
                    the segment harvests them."
            .to_owned(),
        recommendation: "Replace with SSH/SFTP; where a device cannot be upgraded, wrap access \
                         in a jump host and restrict the port to it."
            .to_owned(),
        affected,
    })
}

/// High-value assets sharing a /24 with several low-trust IoT devices.
fn high_value_in_noisy_zone(assets: &[PolicyAsset]) -> Option<Advisory> {
    let mut iot_per_zone: BTreeMap<String, usize> = BTreeMap::new();
    for a in assets {
        if a.asset_type == AssetType::Iot {
            if let Some(subnet) = a.subnet() {
                *iot_per_zone.entry(subnet).or_default() += 1;
            }
        }
    }
    let affected: Vec<AffectedAsset> = assets
        .iter()
        .filter(|a| {
            matches!(a.criticality, Criticality::High | Criticality::Critical) && !a.is_ot()
        })
        .filter_map(|a| {
            let subnet = a.subnet()?;
            let iot = *iot_per_zone.get(&subnet).unwrap_or(&0);
            (iot >= NOISY_IOT_COUNT).then(|| AffectedAsset {
                name: a.name.clone(),
                evidence: format!("shares {subnet} with {iot} IoT device(s)"),
            })
        })
        .collect();
    (!affected.is_empty()).then(|| Advisory {
        rule: "high-value-noisy-zone",
        level: AdvisoryLevel::Medium,
        title: format!(
            "{} high-value asset(s) share a zone with low-trust devices",
            affected.len()
        ),
        rationale: "IoT devices are the weakest link in a segment; co-located critical systems \
                    inherit that blast radius."
            .to_owned(),
        recommendation: "Move critical systems (or the IoT fleet) into their own VLAN; deny \
                         east-west traffic between the two by default."
            .to_owned(),
        affected,
    })
}

/// Most of the inventory in one /24 with several asset classes: no
/// segmentation to speak of.
#[allow(clippy::cast_precision_loss)]
fn flat_network(assets: &[PolicyAsset]) -> Option<Advisory> {
    if assets.len() < FLAT_MIN_ASSETS {
        return None;
    }
    let mut zones: BTreeMap<String, Vec<&PolicyAsset>> = BTreeMap::new();
    for a in assets {
        if let Some(subnet) = a.subnet() {
            zones.entry(subnet).or_default().push(a);
        }
    }
    let (subnet, members) = zones.into_iter().max_by_key(|(_, m)| m.len())?;
    let share = members.len() as f32 / assets.len() as f32;
    let mut types: Vec<AssetType> = members.iter().map(|a| a.asset_type).collect();
    types.sort_by_key(|t| format!("{t:?}"));
    types.dedup();
    if share < FLAT_SHARE || types.len() < FLAT_MIN_TYPES {
        return None;
    }
    Some(Advisory {
        rule: "flat-network",
        level: AdvisoryLevel::Low,
        title: format!(
            "{:.0}% of the inventory sits in a single subnet ({subnet})",
            share * 100.0
        ),
        rationale: "One flat broadcast domain means any compromised device can reach every \
                    other device; segmentation is the cheapest blast-radius control."
            .to_owned(),
        recommendation: "Split the network by function (servers / clients / IoT / management) \
                         and default-deny traffic between the zones."
            .to_owned(),
        affected: vec![AffectedAsset {
            name: subnet,
            evidence: format!(
                "{} of {} assets, {} asset classes",
                members.len(),
                assets.len(),
                types.len()
            ),
        }],
    })
}

/// Management / remote-access ports reachable from elsewhere on a flat internal
/// segment. The school-edition counterpart to [`mgmt_exposed`]: a self-hosted
/// appliance sees a flat LAN where almost nothing is internet-facing, so the
/// real risk is "any device in the student/user /24 can reach this admin port".
/// Only fires for assets in a /24 that mixes at least two asset classes (a
/// single-purpose subnet is assumed intentionally isolated). Reachability is
/// INFERRED from the /24 — there is no VLAN telemetry — and the advisory says so.
fn mgmt_reachable_internal(assets: &[PolicyAsset]) -> Option<Advisory> {
    // Distinct asset classes per /24 (AssetType is not Ord/Hash, so key on its
    // Debug form). A zone mixing >=2 classes means a compromise of one class can
    // pivot to the others.
    let mut classes_per_zone: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for a in assets {
        if let Some(subnet) = a.subnet() {
            classes_per_zone
                .entry(subnet)
                .or_default()
                .push(format!("{:?}", a.asset_type));
        }
    }
    let distinct: BTreeMap<String, usize> = classes_per_zone
        .into_iter()
        .map(|(k, mut v)| {
            v.sort();
            v.dedup();
            (k, v.len())
        })
        .collect();

    let mut affected = Vec::new();
    let mut worst_is_critical = false;
    for a in assets.iter().filter(|a| !a.internet_facing()) {
        let Some(subnet) = a.subnet() else { continue };
        if distinct.get(&subnet).copied().unwrap_or(0) < 2 {
            continue; // single-class subnet: assume isolated by design
        }
        let crit = a.open_any(EXPOSED_CRITICAL_PORTS);
        let high = a.open_any(EXPOSED_HIGH_PORTS);
        if crit.is_empty() && high.is_empty() {
            continue;
        }
        worst_is_critical |= !crit.is_empty();
        let ports: Vec<String> = crit.iter().chain(&high).map(u16::to_string).collect();
        affected.push(AffectedAsset {
            name: a.name.clone(),
            evidence: format!("reachable in {subnet}: {}", ports.join(", ")),
        });
    }
    (!affected.is_empty()).then(|| Advisory {
        rule: "mgmt-reachable-internal",
        level: if worst_is_critical {
            AdvisoryLevel::High
        } else {
            AdvisoryLevel::Medium
        },
        title: format!(
            "{} asset(s) expose management/remote-access ports inside a flat segment",
            affected.len()
        ),
        rationale: "On an unsegmented internal network, any compromised device in the same \
                    subnet can reach these admin/database/remote-access ports — the standard \
                    lateral-movement path. Inferred from a shared /24; confirm whether VLAN \
                    isolation is actually in place."
            .to_owned(),
        recommendation: "Restrict these ports to a management VLAN / jump host; default-deny \
                         east-west traffic between device classes."
            .to_owned(),
        affected,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asset(name: &str, ip: &str, asset_type: AssetType) -> PolicyAsset {
        PolicyAsset {
            name: name.to_owned(),
            ip: Some(ip.parse().expect("test ip")),
            asset_type,
            criticality: Criticality::Medium,
            exposure: Exposure::Internal,
            open_ports: Vec::new(),
            has_kev: false,
        }
    }

    #[test]
    fn empty_inventory_yields_no_advisories() {
        assert!(evaluate(&[]).is_empty());
    }

    #[test]
    fn internal_mgmt_port_in_a_mixed_flat_zone_is_flagged() {
        // DC with RDP + an IoT camera in the same /24 -> reachable internally.
        let mut dc = asset("dc-1", "10.0.0.10", AssetType::It);
        dc.open_ports = vec![3389];
        let cam = asset("cam-1", "10.0.0.50", AssetType::Iot);
        let advisories = evaluate(&[dc, cam]);
        let adv = advisories
            .iter()
            .find(|a| a.rule == "mgmt-reachable-internal")
            .expect("advisory");
        assert_eq!(adv.level, AdvisoryLevel::High); // 3389 is a critical port
        assert!(adv.affected.iter().any(|x| x.name == "dc-1"));
    }

    #[test]
    fn internal_mgmt_port_in_single_class_subnet_is_not_flagged() {
        // Two IT hosts only, same /24, one with RDP -> assumed isolated by design.
        let mut dc = asset("dc-1", "10.0.1.10", AssetType::It);
        dc.open_ports = vec![3389];
        let srv = asset("srv-1", "10.0.1.11", AssetType::It);
        assert!(evaluate(&[dc, srv])
            .iter()
            .all(|a| a.rule != "mgmt-reachable-internal"));
    }

    #[test]
    fn internet_facing_mgmt_is_not_double_counted_as_internal() {
        let mut web = asset("web-1", "203.0.113.10", AssetType::It);
        web.exposure = Exposure::InternetFacing;
        web.open_ports = vec![3389];
        let cam = asset("cam-1", "203.0.113.50", AssetType::Iot);
        let advisories = evaluate(&[web, cam]);
        assert!(advisories.iter().any(|a| a.rule == "mgmt-exposed"));
        assert!(advisories
            .iter()
            .all(|a| a.rule != "mgmt-reachable-internal"));
    }

    #[test]
    fn kev_on_internet_facing_asset_is_critical() {
        let mut a = asset("web-1", "203.0.113.10", AssetType::It);
        a.exposure = Exposure::InternetFacing;
        a.has_kev = true;
        let advisories = evaluate(&[a]);
        assert_eq!(advisories[0].rule, "kev-internet");
        assert_eq!(advisories[0].level, AdvisoryLevel::Critical);
        // Internal KEV asset does not trigger the rule.
        let mut b = asset("db-1", "10.0.0.5", AssetType::It);
        b.has_kev = true;
        assert!(evaluate(&[b]).iter().all(|a| a.rule != "kev-internet"));
    }

    #[test]
    fn exposed_rdp_is_critical_exposed_ssh_alone_is_high() {
        let mut rdp = asset("ts-1", "203.0.113.20", AssetType::It);
        rdp.exposure = Exposure::InternetFacing;
        rdp.open_ports = vec![3389];
        let advisories = evaluate(&[rdp]);
        let mgmt = advisories
            .iter()
            .find(|a| a.rule == "mgmt-exposed")
            .expect("advisory");
        assert_eq!(mgmt.level, AdvisoryLevel::Critical);
        assert!(mgmt.affected[0].evidence.contains("3389"));

        let mut ssh = asset("jump-1", "203.0.113.21", AssetType::It);
        ssh.exposure = Exposure::InternetFacing;
        ssh.open_ports = vec![22];
        let advisories = evaluate(&[ssh]);
        let mgmt = advisories
            .iter()
            .find(|a| a.rule == "mgmt-exposed")
            .expect("advisory");
        assert_eq!(mgmt.level, AdvisoryLevel::High);
    }

    #[test]
    fn internal_mgmt_ports_do_not_trigger_exposure_rules() {
        let mut a = asset("dc-1", "10.0.0.10", AssetType::It);
        a.open_ports = vec![3389, 445, 389];
        let advisories = evaluate(&[a]);
        assert!(advisories.iter().all(|adv| adv.rule != "mgmt-exposed"));
        assert!(advisories.iter().all(|adv| adv.rule != "ics-internet"));
    }

    #[test]
    fn ics_port_on_the_internet_is_critical() {
        let mut plc = asset("plc-1", "203.0.113.30", AssetType::Ot);
        plc.exposure = Exposure::InternetFacing;
        plc.open_ports = vec![502];
        let advisories = evaluate(&[plc]);
        assert!(advisories
            .iter()
            .any(|a| a.rule == "ics-internet" && a.level == AdvisoryLevel::Critical));
    }

    #[test]
    fn ot_sharing_a_subnet_with_it_is_flagged() {
        let plc = asset("plc-1", "192.168.1.10", AssetType::Ot);
        let ws = asset("ws-1", "192.168.1.20", AssetType::It);
        let advisories = evaluate(&[plc, ws]);
        let adv = advisories
            .iter()
            .find(|a| a.rule == "ot-mixed-zone")
            .expect("advisory");
        assert_eq!(adv.affected.len(), 1);
        assert!(adv.affected[0].evidence.contains("192.168.1.0/24"));

        // OT alone in its subnet: no finding.
        let plc2 = asset("plc-2", "192.168.9.10", AssetType::Ot);
        assert!(evaluate(&[plc2]).iter().all(|a| a.rule != "ot-mixed-zone"));
    }

    #[test]
    fn telnet_anywhere_is_a_medium_advisory() {
        let mut cam = asset("cam-1", "10.0.5.5", AssetType::Iot);
        cam.open_ports = vec![23, 80];
        let advisories = evaluate(&[cam]);
        let adv = advisories
            .iter()
            .find(|a| a.rule == "cleartext-protocols")
            .expect("advisory");
        assert_eq!(adv.level, AdvisoryLevel::Medium);
        assert!(adv.affected[0].evidence.contains("telnet"));
    }

    #[test]
    fn high_value_asset_among_iot_is_flagged() {
        let mut db = asset("db-1", "10.0.7.2", AssetType::It);
        db.criticality = Criticality::Critical;
        let cams: Vec<PolicyAsset> = (0..3)
            .map(|i| {
                asset(
                    &format!("cam-{i}"),
                    &format!("10.0.7.{}", 10 + i),
                    AssetType::Iot,
                )
            })
            .collect();
        let mut all = vec![db];
        all.extend(cams);
        let advisories = evaluate(&all);
        let adv = advisories
            .iter()
            .find(|a| a.rule == "high-value-noisy-zone")
            .expect("advisory");
        assert_eq!(adv.affected.len(), 1);
        assert_eq!(adv.affected[0].name, "db-1");
    }

    #[test]
    fn flat_network_needs_size_share_and_type_mix() {
        // 10 assets, all in one /24, three classes -> flagged.
        let mut all: Vec<PolicyAsset> = (0..8)
            .map(|i| {
                asset(
                    &format!("it-{i}"),
                    &format!("10.1.1.{}", 10 + i),
                    AssetType::It,
                )
            })
            .collect();
        all.push(asset("cam-1", "10.1.1.100", AssetType::Iot));
        all.push(asset("sw-1", "10.1.1.1", AssetType::Network));
        let advisories = evaluate(&all);
        assert!(advisories.iter().any(|a| a.rule == "flat-network"));

        // Same shape but split across two subnets -> not flagged.
        let mut split: Vec<PolicyAsset> = (0..5)
            .map(|i| {
                asset(
                    &format!("a-{i}"),
                    &format!("10.1.1.{}", 10 + i),
                    AssetType::It,
                )
            })
            .collect();
        split.extend((0..5).map(|i| {
            asset(
                &format!("b-{i}"),
                &format!("10.1.2.{}", 10 + i),
                AssetType::It,
            )
        }));
        assert!(evaluate(&split).iter().all(|a| a.rule != "flat-network"));
    }

    #[test]
    fn advisories_come_back_sorted_by_urgency() {
        // telnet (medium) + KEV-internet (critical) in one inventory.
        let mut kev = asset("web-1", "203.0.113.10", AssetType::It);
        kev.exposure = Exposure::InternetFacing;
        kev.has_kev = true;
        let mut tel = asset("cam-1", "10.0.5.5", AssetType::Iot);
        tel.open_ports = vec![23];
        let advisories = evaluate(&[kev, tel]);
        let levels: Vec<AdvisoryLevel> = advisories.iter().map(|a| a.level).collect();
        let mut sorted = levels.clone();
        sorted.sort();
        assert_eq!(levels, sorted);
        assert_eq!(advisories[0].level, AdvisoryLevel::Critical);
    }

    #[test]
    fn ipv6_and_unknown_ips_are_skipped_by_zone_rules() {
        let mut v6 = asset("v6-1", "10.0.0.1", AssetType::Ot);
        v6.ip = Some("2001:db8::1".parse().expect("v6"));
        let mut unknown = asset("u-1", "10.0.0.2", AssetType::It);
        unknown.ip = None;
        // Must not panic and must not produce zone findings.
        assert!(evaluate(&[v6, unknown])
            .iter()
            .all(|a| a.rule != "ot-mixed-zone" && a.rule != "flat-network"));
    }
}
