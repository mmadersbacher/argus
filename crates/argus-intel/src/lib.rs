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

/// Rule / open-data classifier: combines vendor (OUI), port profile and services.
#[derive(Debug, Clone, Copy, Default)]
pub struct HeuristicClassifier;

impl Classifier for HeuristicClassifier {
    fn classify(&self, features: &Features) -> Classification {
        let mut rationale = Vec::new();
        let mut confidence: u8 = 25;

        let vendor_class = features.vendor.as_deref().and_then(vendor_hint);
        if let (Some((_, label)), Some(vendor)) = (vendor_class, features.vendor.as_deref()) {
            rationale.push(format!("vendor \"{vendor}\" → {label}"));
            confidence = confidence.saturating_add(30);
        }

        let (port_type, port_label) = port_hint(&features.open_ports);
        if !features.open_ports.is_empty() {
            rationale.push(format!("ports {:?} → {port_label}", features.open_ports));
            confidence = confidence.saturating_add(20);
        }

        let (asset_type, device_type) = match vendor_class {
            Some((vt, vlabel)) => (vt, vlabel.to_owned()),
            None => (port_type, port_label.to_owned()),
        };

        if features.os.is_some() {
            confidence = confidence.saturating_add(10);
        }
        if !features.services.is_empty() {
            confidence = confidence.saturating_add(10);
        }

        Classification {
            asset_type,
            device_type,
            confidence: confidence.min(95),
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

/// Map an open-port profile to a device-class hint.
fn port_hint(ports: &[u16]) -> (AssetType, &'static str) {
    let has = |p: u16| ports.contains(&p);
    if has(502) || has(102) || has(20000) || has(47808) || has(4840) {
        (AssetType::Ot, "industrial-controller")
    } else if has(1883) || has(8883) {
        (AssetType::Iot, "iot-broker-or-device")
    } else if has(2375) {
        (AssetType::It, "container-host")
    } else if has(6379) || has(27017) || has(9200) || has(11211) || has(5984) {
        (AssetType::It, "data-store")
    } else if has(1433) || has(1521) || has(3306) || has(5432) {
        (AssetType::It, "database-server")
    } else if has(3389) || has(445) || has(139) || has(135) {
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
            services: Vec::new(),
            os: None,
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
            os: Some("IOS".into()),
        };
        assert!(classify(&rich).confidence > classify(&bare).confidence);
    }
}
