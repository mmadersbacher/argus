//! # argus-intel
//!
//! Device classification for Argus. Turns discovery signals (MAC-OUI vendor,
//! open-port profile, service products, OS hint) into a confidence-scored
//! [`Classification`] with an explainable rationale.
//!
//! The bundled [`HeuristicClassifier`] is a rule / open-data model (vendor +
//! port + service signals) — **not** a trained neural net: a genuinely trained
//! classifier needs a labelled fingerprint dataset (the Fingerbank / Armis data
//! moat) we don't have. The [`Classifier`] trait is the seam where a trained
//! model drops in later behind the same interface.

use argus_core::AssetType;

/// Discovery-derived signals fed to a classifier.
#[derive(Debug, Clone, Default)]
pub struct Features {
    /// Vendor resolved from the MAC OUI, if known.
    pub vendor: Option<String>,
    /// Open TCP ports.
    pub open_ports: Vec<u16>,
    /// Service product strings.
    pub services: Vec<String>,
    /// Application CPEs nmap reported for the services
    /// (`cpe:/a:vendor:product:…`) — precise vendor/product identity.
    pub cpes: Vec<String>,
    /// OS hint, if detected.
    pub os: Option<String>,
}

/// A classification result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classification {
    /// Broad asset class.
    pub asset_type: AssetType,
    /// Specific device-type label.
    pub device_type: String,
    /// Confidence, `0..=100`.
    pub confidence: u8,
    /// Human-readable reasons behind the decision.
    pub rationale: Vec<String>,
}

/// A device classifier — implemented by the bundled heuristic model and,
/// eventually, by a trained model behind the same interface.
pub trait Classifier {
    /// Classify a host from its discovery [`Features`].
    fn classify(&self, features: &Features) -> Classification;
}

/// Confidence floor before any evidence is weighed.
const BASE_CONFIDENCE: i32 = 25;
/// Confidence added by each signal that *agrees* with the chosen asset type.
const W_VENDOR: i32 = 30;
const W_SERVICE: i32 = 25;
const W_PORT: i32 = 20;
const W_OS: i32 = 10;
/// Confidence removed when a strong identity signal (vendor or service)
/// points at a *different* asset type than the one chosen.
const CONFLICT_PENALTY: i32 = 15;
/// Confidence ceiling — a heuristic model never claims certainty.
const CONFIDENCE_CAP: i32 = 95;

/// Rule / open-data classifier: combines vendor (OUI), port profile and services.
#[derive(Debug, Clone, Copy, Default)]
pub struct HeuristicClassifier;

impl Classifier for HeuristicClassifier {
    fn classify(&self, features: &Features) -> Classification {
        let vendor_class = features.vendor.as_deref().and_then(vendor_hint);
        let service_class = service_hint(&features.services, &features.cpes);
        let port_class = port_hint(&features.open_ports);
        let has_ports = !features.open_ports.is_empty() && port_class.0 != AssetType::Unknown;
        let os_class = features.os.as_deref().and_then(os_hint);

        // Identity precedence: OUI vendor (physical identity) beats service
        // products (software identity) beats the port profile; an OS match
        // only types hosts whose port profile said nothing specific.
        let (asset_type, device_type) = vendor_class
            .map(|(t, l)| (t, l.to_owned()))
            .or_else(|| {
                service_class
                    .as_ref()
                    .map(|(t, l, _)| (*t, (*l).to_owned()))
            })
            .or_else(|| has_ports.then(|| (port_class.0, port_class.1.to_owned())))
            .or_else(|| os_class.map(|(t, l)| (t, l.to_owned())))
            .unwrap_or_else(|| (AssetType::Unknown, "host".to_owned()));

        // Confidence reflects how well the evidence *agrees* on `asset_type`,
        // not how much evidence there is. Strong identity signals (vendor,
        // service) that disagree lower confidence and are flagged; coarse
        // signals (port profile, OS family) only corroborate — being
        // unspecific, they never veto a precise signal, just note the mismatch.
        let mut rationale = Vec::new();
        let mut score = BASE_CONFIDENCE;

        if let (Some((t, label)), Some(vendor)) = (vendor_class, features.vendor.as_deref()) {
            if t == asset_type {
                rationale.push(format!("vendor \"{vendor}\" → {label}"));
                score += W_VENDOR;
            } else {
                rationale.push(format!("conflict: vendor \"{vendor}\" suggests {label}"));
                score -= CONFLICT_PENALTY;
            }
        }

        if let Some((t, label, evidence)) = &service_class {
            if *t == asset_type {
                rationale.push(format!("service \"{evidence}\" → {label}"));
                score += W_SERVICE;
            } else {
                rationale.push(format!("conflict: service \"{evidence}\" suggests {label}"));
                score -= CONFLICT_PENALTY;
            }
        }

        if has_ports {
            if port_class.0 == asset_type {
                rationale.push(format!(
                    "ports {:?} → {}",
                    features.open_ports, port_class.1
                ));
                score += W_PORT;
            } else {
                rationale.push(format!(
                    "note: port profile {:?} resembles {}",
                    features.open_ports, port_class.1
                ));
            }
        }

        // A matching OS family corroborates; a mismatching one says too little
        // to count for or against (kernel ≠ device role), so it stays silent.
        if let Some((t, label)) = os_class {
            if t == asset_type {
                rationale.push(format!("os → {label}"));
                score += W_OS;
            }
        }

        Classification {
            asset_type,
            device_type,
            confidence: u8::try_from(score.clamp(0, CONFIDENCE_CAP)).unwrap_or(0),
            rationale,
        }
    }
}

/// Classify with the default heuristic model.
#[must_use]
pub fn classify(features: &Features) -> Classification {
    HeuristicClassifier.classify(features)
}

/// Map an OUI vendor string to a device-class hint.
///
/// Vendor is the strongest single identity signal, so the order resolves the
/// most specific classes (medical, industrial, cameras) before generic IT.
fn vendor_hint(vendor: &str) -> Option<(AssetType, &'static str)> {
    let v = vendor.to_lowercase();
    let has = |needle: &str| v.contains(needle);
    if has("ge healthcare")
        || has("philips")
        || has("medtronic")
        || has("draeger")
        || has("dräger")
        || has("baxter")
        || has("hillrom")
        || has("siemens healthineers")
    {
        Some((AssetType::Iomt, "medical-device"))
    } else if has("hikvision")
        || has("dahua")
        || has("axis communications")
        || has("hanwha")
        || has("vivotek")
        || has("uniview")
    {
        Some((AssetType::Iot, "ip-camera"))
    } else if has("siemens")
        || has("rockwell")
        || has("schneider")
        || has("allen-bradley")
        || has("mitsubishi electric")
        || has("yokogawa")
        || has("honeywell")
        || has("abb")
        || has("emerson")
        || has("beckhoff")
        || has("wago")
    {
        Some((AssetType::Ot, "industrial-controller"))
    } else if has("fortinet")
        || has("palo alto")
        || has("sonicwall")
        || has("check point")
        || has("watchguard")
    {
        Some((AssetType::Network, "firewall"))
    } else if has("cisco")
        || has("juniper")
        || has("arista")
        || has("ubiquiti")
        || has("netgear")
        || has("aruba")
        || has("ruckus")
        || has("mikrotik")
        || has("tp-link")
        || has("zyxel")
    {
        Some((AssetType::Network, "network-device"))
    } else if has("synology") || has("qnap") || has("western digital") || has("netapp") {
        Some((AssetType::It, "nas-storage"))
    } else if has("hewlett") && has("print")
        || has("brother")
        || has("lexmark")
        || has("canon")
        || has("xerox")
        || has("kyocera")
        || has("ricoh")
    {
        Some((AssetType::Iot, "printer"))
    } else if has("vmware") || has("nutanix") || has("citrix") {
        Some((AssetType::It, "virtual-machine"))
    } else if has("amazon")
        || has("google")
        || has("microsoft azure")
        || has("digitalocean")
        || has("hetzner")
    {
        Some((AssetType::Cloud, "cloud-instance"))
    } else if has("apple") {
        Some((AssetType::Mobile, "apple-device"))
    } else if has("samsung")
        || has("lg electronics")
        || has("sonos")
        || has("roku")
        || has("espressif")
    {
        Some((AssetType::Iot, "consumer-iot"))
    } else if has("raspberry") {
        Some((AssetType::Iot, "raspberry-pi"))
    } else if has("dell")
        || has("hewlett")
        || has("supermicro")
        || has("lenovo")
        || has("intel")
        || has("fujitsu")
    {
        Some((AssetType::It, "server-or-workstation"))
    } else if has("microsoft") {
        Some((AssetType::It, "windows-host"))
    } else {
        None
    }
}

/// Identity evidence from service products and application CPEs.
///
/// First match wins, so rules are ordered most-specific first. Matching is
/// whole-token (split on non-alphanumerics) over the lowercased product
/// strings plus the vendor/product components of each CPE — `"Apache Axis"`
/// must not look like an Axis camera, but `cpe:/a:mikrotik:routeros` must
/// hit the `routeros` rule.
fn service_hint(services: &[String], cpes: &[String]) -> Option<(AssetType, &'static str, String)> {
    /// (token, class, label) — token is matched whole, never as a substring.
    const RULES: &[(&str, AssetType, &str)] = &[
        // cameras / NVRs
        ("hikvision", AssetType::Iot, "ip-camera"),
        ("dahua", AssetType::Iot, "ip-camera"),
        ("vivotek", AssetType::Iot, "ip-camera"),
        // routers / network OS
        ("routeros", AssetType::Network, "network-device"),
        ("mikrotik", AssetType::Network, "network-device"),
        ("openwrt", AssetType::Network, "network-device"),
        ("vyos", AssetType::Network, "network-device"),
        ("fortios", AssetType::Network, "firewall"),
        ("fortinet", AssetType::Network, "firewall"),
        // virtualization
        ("esxi", AssetType::It, "virtualization-host"),
        ("vcenter", AssetType::It, "virtualization-host"),
        ("proxmox", AssetType::It, "virtualization-host"),
        // storage
        ("synology", AssetType::It, "nas-storage"),
        ("qnap", AssetType::It, "nas-storage"),
        ("truenas", AssetType::It, "nas-storage"),
        // printing
        ("jetdirect", AssetType::Iot, "printer"),
        ("cups", AssetType::Iot, "printer"),
        ("printer", AssetType::Iot, "printer"),
        // embedded
        ("dropbear", AssetType::Iot, "embedded-device"),
        ("busybox", AssetType::Iot, "embedded-device"),
        ("lwip", AssetType::Iot, "embedded-device"),
        // windows software stack (generic — keep after everything specific)
        ("iis", AssetType::It, "windows-host"),
        ("exchange", AssetType::It, "windows-host"),
        ("windows", AssetType::It, "windows-host"),
    ];

    let mut tokens: Vec<String> = Vec::new();
    for s in services {
        tokens.extend(
            s.to_lowercase()
                .split(|c: char| !c.is_ascii_alphanumeric())
                .filter(|t| !t.is_empty())
                .map(str::to_owned),
        );
    }
    for cpe in cpes {
        // cpe:/a:vendor:product:version — vendor and product are identity.
        let rest = cpe
            .strip_prefix("cpe:/a:")
            .or_else(|| cpe.strip_prefix("cpe:2.3:a:"));
        if let Some(rest) = rest {
            for part in rest.split(':').take(2) {
                tokens.extend(
                    part.to_lowercase()
                        .split(|c: char| !c.is_ascii_alphanumeric())
                        .filter(|t| !t.is_empty())
                        .map(str::to_owned),
                );
            }
        }
    }
    RULES
        .iter()
        .find(|(needle, _, _)| tokens.iter().any(|t| t == needle))
        .map(|&(needle, asset_type, label)| (asset_type, label, needle.to_owned()))
}

/// Type a host from the detected operating system, as a fallback when
/// neither vendor, service nor port profile said anything specific.
fn os_hint(os: &str) -> Option<(AssetType, &'static str)> {
    let o = os.to_lowercase();
    let has = |needle: &str| o.contains(needle);
    if has("routeros") || has("junos") || has("ios-xe") || has("cisco ios") || has("nx-os") {
        Some((AssetType::Network, "network-device"))
    } else if has("esxi") {
        Some((AssetType::It, "virtualization-host"))
    } else if has("windows") {
        Some((AssetType::It, "windows-host"))
    } else if has("linux") || has("ubuntu") || has("debian") || has("centos") || has("freebsd") {
        Some((AssetType::It, "linux-host"))
    } else {
        None
    }
}

/// Map an open-port profile to a device-class hint.
fn port_hint(ports: &[u16]) -> (AssetType, &'static str) {
    let has = |p: u16| ports.contains(&p);
    if has(502) || has(102) || has(20000) || has(47808) || has(4840) {
        (AssetType::Ot, "industrial-controller")
    } else if has(554) {
        (AssetType::Iot, "ip-camera")
    } else if has(9100) || has(631) || has(515) {
        (AssetType::Iot, "printer")
    } else if has(8291) {
        (AssetType::Network, "network-device")
    } else if has(1883) || has(8883) {
        (AssetType::Iot, "iot-broker-or-device")
    } else if has(2375) {
        (AssetType::It, "container-host")
    } else if has(902) {
        (AssetType::It, "virtualization-host")
    } else if has(6379) || has(27017) || has(9200) || has(11211) || has(5984) {
        (AssetType::It, "data-store")
    } else if has(1433) || has(1521) || has(3306) || has(5432) {
        (AssetType::It, "database-server")
    } else if has(3389) || has(445) || has(139) || has(135) || has(5985) {
        (AssetType::It, "windows-host")
    } else if has(623) {
        (AssetType::It, "bmc-ipmi")
    } else if has(161) && !has(22) {
        (AssetType::Network, "network-device")
    } else if has(22) {
        (AssetType::It, "linux-host")
    } else if has(5060) {
        (AssetType::Iot, "voip-device")
    } else if has(80) || has(443) || has(8080) || has(8443) || has(8000) {
        (AssetType::It, "web-server")
    } else if has(23) {
        (AssetType::Network, "legacy-device")
    } else {
        (AssetType::Unknown, "host")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendor_drives_classification() {
        let f = Features {
            vendor: Some("Hikvision Digital Technology".into()),
            open_ports: vec![80],
            ..Default::default()
        };
        let c = classify(&f);
        assert_eq!(c.asset_type, AssetType::Iot);
        assert_eq!(c.device_type, "ip-camera");
        assert!(c.confidence > 50);
        assert!(!c.rationale.is_empty());
    }

    #[test]
    fn ports_classify_without_vendor() {
        let f = Features {
            open_ports: vec![445, 3389],
            ..Default::default()
        };
        let c = classify(&f);
        assert_eq!(c.asset_type, AssetType::It);
        assert_eq!(c.device_type, "windows-host");
    }

    #[test]
    fn modbus_is_ot() {
        let f = Features {
            open_ports: vec![502],
            ..Default::default()
        };
        assert_eq!(classify(&f).asset_type, AssetType::Ot);
    }

    #[test]
    fn more_signals_more_confidence() {
        let bare = Features {
            open_ports: vec![22],
            ..Default::default()
        };
        let rich = Features {
            vendor: Some("Cisco Systems".into()),
            open_ports: vec![22, 443],
            services: vec!["OpenSSH 8.6".into()],
            cpes: vec!["cpe:/a:openbsd:openssh:8.6".into()],
            os: Some("IOS".into()),
        };
        assert!(classify(&rich).confidence > classify(&bare).confidence);
    }

    #[test]
    fn cpe_identity_beats_the_port_profile() {
        // ssh+web ports alone would say linux-host; the RouterOS CPE says router.
        let f = Features {
            open_ports: vec![22, 80],
            services: vec!["MikroTik RouterOS sshd".into()],
            cpes: vec!["cpe:/a:mikrotik:routeros:6.49".into()],
            ..Default::default()
        };
        let c = classify(&f);
        assert_eq!(c.asset_type, AssetType::Network);
        assert_eq!(c.device_type, "network-device");
        assert!(c.rationale.iter().any(|r| r.contains("service")));
    }

    #[test]
    fn vendor_outranks_service_evidence() {
        // OUI says camera vendor; the ssh banner alone must not retype it.
        let f = Features {
            vendor: Some("Hikvision Digital Technology".into()),
            services: vec!["Dropbear sshd".into()],
            cpes: vec!["cpe:/a:matt_johnston:dropbear_ssh_server:2019.78".into()],
            ..Default::default()
        };
        let c = classify(&f);
        assert_eq!(c.device_type, "ip-camera");
    }

    #[test]
    fn dropbear_marks_embedded_devices() {
        let f = Features {
            open_ports: vec![22],
            services: vec!["Dropbear sshd 2019.78".into()],
            ..Default::default()
        };
        let c = classify(&f);
        assert_eq!(c.asset_type, AssetType::Iot);
        assert_eq!(c.device_type, "embedded-device");
    }

    #[test]
    fn token_matching_avoids_substring_false_positives() {
        // "Apache Axis" (SOAP stack) must not look like an Axis camera, and
        // nothing here should hit the printer rule.
        let f = Features {
            open_ports: vec![8080],
            services: vec!["Apache Axis 1.4".into()],
            ..Default::default()
        };
        let c = classify(&f);
        assert_eq!(c.device_type, "web-server");
    }

    #[test]
    fn printer_and_camera_ports_classify() {
        let printer = Features {
            open_ports: vec![80, 9100],
            ..Default::default()
        };
        assert_eq!(classify(&printer).device_type, "printer");
        let cam = Features {
            open_ports: vec![80, 554],
            ..Default::default()
        };
        assert_eq!(classify(&cam).device_type, "ip-camera");
    }

    #[test]
    fn conflicting_strong_signals_lower_confidence_and_are_flagged() {
        // OUI says IP camera (Iot); a service banner says ESXi (It). Both are
        // strong identity signals and they disagree — confidence must drop
        // below the vendor-only case and the clash must be in the rationale.
        let camera_only = Features {
            vendor: Some("Hikvision Digital Technology".into()),
            ..Default::default()
        };
        let conflicted = Features {
            vendor: Some("Hikvision Digital Technology".into()),
            services: vec!["VMware ESXi 7.0".into()],
            ..Default::default()
        };
        let base = classify(&camera_only);
        let clash = classify(&conflicted);
        assert_eq!(clash.asset_type, AssetType::Iot); // vendor still wins
        assert!(clash.confidence < base.confidence);
        assert!(clash.rationale.iter().any(|r| r.starts_with("conflict:")));
    }

    #[test]
    fn coarse_port_mismatch_does_not_penalize_a_precise_signal() {
        // A camera with only port 80 open: port_hint says "web-server", but an
        // unspecific HTTP port must not lower confidence in the OUI identity.
        let with_port = classify(&Features {
            vendor: Some("Hikvision Digital Technology".into()),
            open_ports: vec![80],
            ..Default::default()
        });
        let without_port = classify(&Features {
            vendor: Some("Hikvision Digital Technology".into()),
            ..Default::default()
        });
        assert_eq!(with_port.device_type, "ip-camera");
        assert_eq!(with_port.confidence, without_port.confidence);
        assert!(with_port.rationale.iter().any(|r| r.starts_with("note:")));
    }

    #[test]
    fn os_types_hosts_when_ports_are_silent() {
        let f = Features {
            os: Some("Microsoft Windows Server 2019".into()),
            ..Default::default()
        };
        let c = classify(&f);
        assert_eq!(c.asset_type, AssetType::It);
        assert_eq!(c.device_type, "windows-host");
        // With a specific port profile, the profile wins over the OS label.
        let db = Features {
            open_ports: vec![5432],
            os: Some("Linux 5.15".into()),
            ..Default::default()
        };
        assert_eq!(classify(&db).device_type, "database-server");
    }
}
