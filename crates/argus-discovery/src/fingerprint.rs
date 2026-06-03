//! Light port-based heuristics. Everything here is a placeholder that gets
//! replaced by real fingerprinting + CVE correlation as the engine grows.

use argus_core::{AssetType, Fingerprint};

/// Fingerprint-relevant TCP ports probed in light mode (normal traffic only).
pub const PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 502, 1433, 3306, 3389, 5432, 5900, 8080,
    8443,
];

/// Best-effort service name for a well-known port.
#[must_use]
pub fn service_name(port: u16) -> Option<&'static str> {
    Some(match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        110 => "pop3",
        135 => "msrpc",
        139 | 445 => "smb",
        143 => "imap",
        443 => "https",
        502 => "modbus",
        1433 => "mssql",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgres",
        5900 => "vnc",
        8080 => "http-alt",
        8443 => "https-alt",
        _ => return None,
    })
}

/// Guess an asset class and fingerprint from the set of open ports.
#[must_use]
pub fn classify(open: &[u16]) -> (AssetType, Fingerprint) {
    let has = |p: u16| open.contains(&p);
    let (asset_type, device_type, os) = if has(502) {
        (AssetType::Ot, "industrial-controller", None)
    } else if has(3389) || has(445) || has(139) {
        (AssetType::It, "windows-host", Some("Windows"))
    } else if has(22) {
        (AssetType::It, "linux-host", Some("Linux"))
    } else if has(80) || has(443) || has(8080) || has(8443) {
        (AssetType::It, "web-server", None)
    } else if has(23) {
        (AssetType::Network, "legacy-device", None)
    } else {
        (AssetType::Unknown, "host", None)
    };
    let confidence = if open.is_empty() { 0 } else { 35 };
    (
        asset_type,
        Fingerprint {
            device_type: Some(device_type.to_owned()),
            vendor: None,
            os: os.map(str::to_owned),
            confidence,
        },
    )
}

/// Heuristic "worst exposed insecure service" pseudo-CVSS (`0.0..=10.0`).
///
/// This is **not** a real vulnerability score — it is a placeholder so risk
/// scoring produces meaningful output before `argus-vuln` (CVE correlation)
/// lands. Cleartext and remote-management services weigh highest.
#[must_use]
pub fn insecure_service_score(open: &[u16]) -> f32 {
    open.iter()
        .map(|&p| match p {
            23 => 7.5,                 // telnet, cleartext
            3389 => 6.5,               // exposed RDP
            21 | 5900 => 6.0,          // ftp / VNC
            139 | 445 => 5.5,          // SMB
            1433 | 3306 | 5432 => 5.0, // exposed database
            _ => 2.0,
        })
        .fold(0.0_f32, f32::max)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modbus_is_ot() {
        let (t, fp) = classify(&[502]);
        assert_eq!(t, AssetType::Ot);
        assert_eq!(fp.device_type.as_deref(), Some("industrial-controller"));
    }

    #[test]
    fn ssh_is_linux_it() {
        let (t, fp) = classify(&[22]);
        assert_eq!(t, AssetType::It);
        assert_eq!(fp.os.as_deref(), Some("Linux"));
    }

    #[test]
    fn empty_is_unknown() {
        let (t, _) = classify(&[]);
        assert_eq!(t, AssetType::Unknown);
    }

    #[test]
    fn telnet_scores_highest_and_empty_is_zero() {
        assert!((insecure_service_score(&[23, 80]) - 7.5).abs() < f32::EPSILON);
        assert!(insecure_service_score(&[]).abs() < f32::EPSILON);
    }
}
