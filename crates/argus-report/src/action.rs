//! The "fix these N things this week" action plan.
//!
//! A busy school admin does not want eight dashboards — they want a short,
//! ranked, plain-language list of what to actually do, worst-first, with a
//! rough effort estimate. This module synthesises one such list from every
//! signal Argus has: actively-exploited (KEV) findings, segmentation/exposure
//! advisories, and version-confirmed critical vulnerabilities. It is pure (no
//! I/O); the API maps its inputs in.

use argus_core::Severity;
use serde::Serialize;

use crate::AssetFacts;

/// How many items the plan keeps — a focused list, not a backlog.
const ACTION_LIMIT: usize = 12;

/// Urgency of a segmentation/exposure advisory. Mirrors
/// `argus_policy::AdvisoryLevel`; report stays policy-independent, so the API
/// maps the enum across into an [`AdvisoryFact`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AdvisoryUrgency {
    /// Fix or isolate now.
    Critical,
    /// Schedule remediation.
    High,
    /// Improve when next touching the zone.
    Medium,
    /// Worth knowing.
    Low,
}

/// One advisory reduced to the facts the action plan consumes (mapped by the
/// API from `argus_policy::Advisory`).
#[derive(Debug, Clone)]
pub struct AdvisoryFact {
    /// Stable rule id (`tier0-crown-jewel`, `eol-os`, `mgmt-exposed`, …).
    pub rule: String,
    /// Urgency.
    pub level: AdvisoryUrgency,
    /// One-line finding (becomes the action title).
    pub title: String,
    /// Why it matters (becomes the rationale).
    pub rationale: String,
    /// What to do (becomes the action).
    pub recommendation: String,
    /// Affected asset display names.
    pub affected: Vec<String>,
}

/// When an action should be tackled. Ordered: `Now < ThisWeek < Soon`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionPriority {
    /// Drop everything — actively exploited or domain-wide blast radius.
    Now,
    /// Schedule within the week.
    ThisWeek,
    /// Plan for soon.
    Soon,
}

/// Rough effort to carry out an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ActionEffort {
    /// A patch / config flip — minutes to an hour.
    Quick,
    /// Some planning — reconfigure a service, coordinate a window.
    Moderate,
    /// A project — re-segment a network, replace EOL hardware.
    Project,
}

/// One prioritised, plain-language remediation step.
#[derive(Debug, Clone, Serialize)]
pub struct ActionItem {
    /// When to tackle it.
    pub priority: ActionPriority,
    /// Plain-language headline.
    pub title: String,
    /// The concrete action to take.
    pub action: String,
    /// Rough effort.
    pub effort: ActionEffort,
    /// Why it matters (the risk being carried).
    pub rationale: String,
    /// Affected asset display names.
    pub affected: Vec<String>,
    /// Where the item came from (`kev`, `segmentation`, `vuln`).
    pub source: &'static str,
}

/// Join up to three CVE ids for a title, summarising the rest.
fn join_cves(cves: &[&str]) -> String {
    match cves {
        [] => String::new(),
        [one] => (*one).to_owned(),
        _ if cves.len() <= 3 => cves.join(", "),
        _ => format!("{}, {} and {} more", cves[0], cves[1], cves.len() - 2),
    }
}

/// Effort heuristic from an advisory rule id: network re-segmentation and EOL
/// replacement are projects; clear-text/config fixes are moderate; the rest
/// (mostly "close a port / patch") are quick.
fn advisory_effort(rule: &str) -> ActionEffort {
    if rule == "eol-os"
        || rule.contains("zone")
        || rule.contains("reachable")
        || rule == "flat-network"
    {
        ActionEffort::Project
    } else if rule.contains("cleartext") {
        ActionEffort::Moderate
    } else {
        ActionEffort::Quick
    }
}

/// Build the ranked "fix these this week" plan from the asset facts and the
/// segmentation advisories. Worst-first, capped at [`ACTION_LIMIT`].
pub(crate) fn action_plan(assets: &[AssetFacts], advisories: &[AdvisoryFact]) -> Vec<ActionItem> {
    let mut items: Vec<ActionItem> = Vec::new();

    // 1. Actively-exploited (KEV), version-confirmed — the highest-probability
    //    breach path in the inventory.
    for a in assets {
        let kev: Vec<&str> = a
            .vulns
            .iter()
            .filter(|v| v.kev && v.is_confirmed())
            .map(|v| v.cve_id.as_str())
            .collect();
        if !kev.is_empty() {
            items.push(ActionItem {
                priority: ActionPriority::Now,
                title: format!("Patch {} — actively exploited {}", a.name, join_cves(&kev)),
                action: "Apply the vendor security update now, or pull the host behind a \
                         firewall/VPN until it is patched."
                    .to_owned(),
                effort: ActionEffort::Quick,
                rationale: "On the CISA Known Exploited Vulnerabilities catalog — exploited in \
                            the wild, so the highest-probability breach path."
                    .to_owned(),
                affected: vec![a.name.clone()],
                source: "kev",
            });
        }
    }

    // 2. Segmentation / exposure advisories, by urgency.
    for adv in advisories {
        let priority = match adv.level {
            AdvisoryUrgency::Critical => ActionPriority::Now,
            AdvisoryUrgency::High => ActionPriority::ThisWeek,
            AdvisoryUrgency::Medium | AdvisoryUrgency::Low => ActionPriority::Soon,
        };
        items.push(ActionItem {
            priority,
            title: adv.title.clone(),
            action: adv.recommendation.clone(),
            effort: advisory_effort(&adv.rule),
            rationale: adv.rationale.clone(),
            affected: adv.affected.clone(),
            source: "segmentation",
        });
    }

    // 3. Version-confirmed Critical vulnerabilities not already flagged as KEV.
    for a in assets {
        let crit: Vec<&str> = a
            .vulns
            .iter()
            .filter(|v| v.is_confirmed() && !v.kev && v.severity == Severity::Critical)
            .map(|v| v.cve_id.as_str())
            .collect();
        if !crit.is_empty() {
            items.push(ActionItem {
                priority: ActionPriority::ThisWeek,
                title: format!("Patch {} — critical {}", a.name, join_cves(&crit)),
                action: "Schedule the vendor update this week; these are version-confirmed \
                         critical-severity flaws."
                    .to_owned(),
                effort: ActionEffort::Quick,
                rationale: "Version-confirmed critical vulnerabilities (not yet known-exploited, \
                            but high impact)."
                    .to_owned(),
                affected: vec![a.name.clone()],
                source: "vuln",
            });
        }
    }

    // Stable sort by urgency (Now first); keep the focused top slice.
    items.sort_by_key(|i| i.priority);
    items.truncate(ACTION_LIMIT);
    items
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AssetFacts;
    use argus_core::{AssetType, Criticality, DeviceRole, RiskBand, Vulnerability};
    use argus_core::{Confidence, Cvss, Exposure, RiskScore};
    use time::OffsetDateTime;

    fn vuln(cve: &str, sev: Severity, kev: bool, confirmed: bool) -> Vulnerability {
        Vulnerability {
            cve_id: cve.to_owned(),
            cvss: Some(Cvss::new(
                if sev == Severity::Critical { 9.8 } else { 7.5 },
                None,
            )),
            epss: None,
            kev,
            severity: sev,
            match_confidence: if confirmed {
                Confidence::Confirmed
            } else {
                Confidence::Low
            },
        }
    }

    fn asset(name: &str, vulns: Vec<Vulnerability>) -> AssetFacts {
        AssetFacts {
            name: name.to_owned(),
            ip: None,
            asset_type: AssetType::It,
            device_role: DeviceRole::Unknown,
            criticality: Criticality::Medium,
            exposure: Exposure::Internal,
            risk: RiskScore {
                value: 50.0,
                band: RiskBand::Medium,
                confidence: Confidence::High,
            },
            vulns,
            first_seen: OffsetDateTime::UNIX_EPOCH,
            last_seen: OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn advisory(rule: &str, level: AdvisoryUrgency) -> AdvisoryFact {
        AdvisoryFact {
            rule: rule.to_owned(),
            level,
            title: format!("{rule} finding"),
            rationale: "because reasons".to_owned(),
            recommendation: "do the thing".to_owned(),
            affected: vec!["host-1".to_owned()],
        }
    }

    #[test]
    fn kev_findings_rank_now_and_lead_the_plan() {
        let assets = vec![
            asset(
                "dc-1",
                vec![vuln("CVE-2024-6387", Severity::High, true, true)],
            ),
            asset(
                "ws-1",
                vec![vuln("CVE-2021-0000", Severity::Critical, false, true)],
            ),
        ];
        let plan = action_plan(&assets, &[]);
        assert_eq!(plan[0].priority, ActionPriority::Now);
        assert_eq!(plan[0].source, "kev");
        assert!(plan[0].title.contains("dc-1"));
        // The non-KEV critical is present but later (ThisWeek).
        assert!(plan
            .iter()
            .any(|i| i.source == "vuln" && i.priority == ActionPriority::ThisWeek));
    }

    #[test]
    fn advisories_map_urgency_to_priority_and_carry_remediation() {
        let advisories = vec![
            advisory("tier0-crown-jewel", AdvisoryUrgency::Critical),
            advisory("eol-os", AdvisoryUrgency::High),
            advisory("cleartext-protocols", AdvisoryUrgency::Medium),
        ];
        let plan = action_plan(&[], &advisories);
        let crit = plan.iter().find(|i| i.title.contains("tier0")).unwrap();
        assert_eq!(crit.priority, ActionPriority::Now);
        assert_eq!(crit.action, "do the thing");
        let eol = plan.iter().find(|i| i.title.contains("eol")).unwrap();
        assert_eq!(eol.priority, ActionPriority::ThisWeek);
        assert_eq!(eol.effort, ActionEffort::Project); // EOL replacement is a project
        let cleartext = plan.iter().find(|i| i.title.contains("cleartext")).unwrap();
        assert_eq!(cleartext.priority, ActionPriority::Soon);
        assert_eq!(cleartext.effort, ActionEffort::Moderate);
    }

    #[test]
    fn potential_and_non_critical_vulns_do_not_create_items() {
        // A version-blind (potential) KEV and a confirmed Medium must not appear.
        let assets = vec![asset(
            "host-1",
            vec![
                vuln("CVE-A", Severity::Critical, true, false), // potential KEV
                vuln("CVE-B", Severity::Medium, false, true),   // confirmed medium
            ],
        )];
        let plan = action_plan(&assets, &[]);
        assert!(plan.is_empty(), "no actionable item: {plan:?}");
    }

    #[test]
    fn the_plan_is_ordered_now_then_thisweek_then_soon_and_capped() {
        let mut advisories = Vec::new();
        for i in 0..20 {
            advisories.push(advisory(&format!("rule-{i}"), AdvisoryUrgency::Medium));
        }
        advisories.push(advisory("urgent", AdvisoryUrgency::Critical));
        let plan = action_plan(&[], &advisories);
        assert!(plan.len() <= ACTION_LIMIT);
        assert_eq!(plan[0].priority, ActionPriority::Now); // critical floated to the top
                                                           // priorities are non-decreasing
        let mut prev = ActionPriority::Now;
        for i in &plan {
            assert!(i.priority >= prev);
            prev = i.priority;
        }
    }
}
