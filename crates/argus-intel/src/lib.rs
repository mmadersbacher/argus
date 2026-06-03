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
fn vendor_hint(vendor: &str) -> Option<(AssetType, &'static str)> {
    let v = vendor.to_lowercase();
    let has = |needle: &str| v.contains(needle);
    if has("hikvision") || has("dahua") || has("axis communications") {
        Some((AssetType::Iot, "ip-camera"))
    } else if has("siemens") || has("rockwell") || has("schneider") || has("allen-bradley") {
        Some((AssetType::Ot, "industrial-controller"))
    } else if has("ge healthcare") || has("philips") || has("medtronic") || has("draeger") {
        Some((AssetType::Iomt, "medical-device"))
    } else if has("cisco") || has("juniper") || has("arista") || has("ubiquiti") || has("netgear") {
        Some((AssetType::Network, "network-device"))
    } else if has("vmware") || has("microsoft") {
        Some((AssetType::It, "virtual-machine"))
    } else if has("apple") {
        Some((AssetType::Mobile, "apple-device"))
    } else if has("raspberry") {
        Some((AssetType::Iot, "raspberry-pi"))
    } else if has("dell") || has("hewlett") || has("supermicro") || has("lenovo") {
        Some((AssetType::It, "server-or-workstation"))
    } else {
        None
    }
}

/// Map an open-port profile to a device-class hint.
fn port_hint(ports: &[u16]) -> (AssetType, &'static str) {
    let has = |p: u16| ports.contains(&p);
    if has(502) {
        (AssetType::Ot, "industrial-controller")
    } else if has(3389) || has(445) || has(139) {
        (AssetType::It, "windows-host")
    } else if has(22) {
        (AssetType::It, "linux-host")
    } else if has(80) || has(443) || has(8080) || has(8443) {
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
