//! Light port-based heuristics. Everything here is a placeholder that gets
//! replaced by real fingerprinting + CVE correlation as the engine grows.

use argus_core::{AssetType, Fingerprint};

/// Fingerprint-relevant TCP ports probed in light mode (normal traffic only).
///
/// Spans remote-access, web, mail, directory, databases, container/orchestration
/// control planes, NoSQL/cache/search engines, IoT/OT control protocols and
/// common management consoles — enough to classify the bulk of an enterprise,
/// IoT and OT estate from a no-privilege connect scan.
pub const PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 102, 110, 111, 135, 139, 143, 161, 389, 443, 445, 502, 515, 554, 623,
    631, 636, 902, 993, 995, 1433, 1521, 1883, 2049, 2375, 3306, 3389, 4840, 5060, 5432, 5601,
    5672, 5900, 5984, 5985, 6379, 7001, 8000, 8080, 8291, 8443, 8883, 9000, 9092, 9100, 9200,
    11211, 20000, 27017, 47808,
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
        102 => "s7comm",
        110 => "pop3",
        111 => "rpcbind",
        135 => "msrpc",
        139 | 445 => "smb",
        143 => "imap",
        161 => "snmp",
        389 => "ldap",
        443 => "https",
        502 => "modbus",
        515 => "lpd",
        554 => "rtsp",
        623 => "ipmi",
        631 => "ipp",
        636 => "ldaps",
        902 => "vmware-auth",
        993 => "imaps",
        995 => "pop3s",
        1433 => "mssql",
        1521 => "oracle-db",
        1883 | 8883 => "mqtt",
        2049 => "nfs",
        2375 => "docker-api",
        3306 => "mysql",
        3389 => "rdp",
        4840 => "opc-ua",
        5060 => "sip",
        5432 => "postgres",
        5601 => "kibana",
        5672 => "amqp",
        5900 => "vnc",
        5984 => "couchdb",
        5985 => "winrm",
        6379 => "redis",
        7001 => "weblogic",
        8000 | 8080 => "http-alt",
        8291 => "winbox",
        8443 => "https-alt",
        9000 => "http-mgmt",
        9092 => "kafka",
        9100 => "jetdirect",
        9200 => "elasticsearch",
        11211 => "memcached",
        20000 => "dnp3",
        27017 => "mongodb",
        47808 => "bacnet",
        _ => return None,
    })
}

/// Guess an asset class and fingerprint from the set of open ports.
///
/// OT/ICS control protocols win first (they are the strongest single signal),
/// then storage/database servers, Windows, remote-access, *nix and web roles.
#[must_use]
pub fn classify(open: &[u16]) -> (AssetType, Fingerprint) {
    let has = |p: u16| open.contains(&p);
    let (asset_type, device_type, os) =
        if has(502) || has(102) || has(20000) || has(47808) || has(4840) {
            (AssetType::Ot, "industrial-controller", None)
        } else if has(554) {
            // RTSP: streaming video — overwhelmingly IP cameras / NVRs.
            (AssetType::Iot, "ip-camera", None)
        } else if has(9100) || has(631) || has(515) {
            (AssetType::Iot, "printer", None)
        } else if has(8291) {
            // Winbox is MikroTik-only, so it wins even when ssh/web are open.
            (AssetType::Network, "network-device", Some("RouterOS"))
        } else if has(1883) || has(8883) {
            (AssetType::Iot, "iot-broker-or-device", None)
        } else if has(2375) {
            (AssetType::It, "container-host", Some("Linux"))
        } else if has(902) {
            (AssetType::It, "virtualization-host", Some("ESXi"))
        } else if has(6379) || has(27017) || has(9200) || has(11211) || has(5984) {
            (AssetType::It, "data-store", Some("Linux"))
        } else if has(1433) || has(1521) || has(3306) || has(5432) {
            (AssetType::It, "database-server", None)
        } else if has(3389) || has(445) || has(139) || has(135) || has(5985) {
            (AssetType::It, "windows-host", Some("Windows"))
        } else if has(623) {
            (AssetType::It, "bmc-ipmi", None)
        } else if has(161) && !has(22) {
            (AssetType::Network, "network-device", None)
        } else if has(22) {
            (AssetType::It, "linux-host", Some("Linux"))
        } else if has(5060) {
            (AssetType::Iot, "voip-device", None)
        } else if has(80) || has(443) || has(8080) || has(8443) || has(8000) {
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
            model: None,
            confidence,
            evidence: Vec::new(),
        },
    )
}

/// Heuristic "worst exposed insecure service" pseudo-CVSS (`0.0..=10.0`).
///
/// This is **not** a real vulnerability score — it is a placeholder so risk
/// scoring produces meaningful output before `argus-vuln` (CVE correlation)
/// lands. Cleartext, control-plane and unauthenticated-by-default services
/// weigh highest.
#[must_use]
pub fn insecure_service_score(open: &[u16]) -> f32 {
    open.iter()
        .map(|&p| match p {
            23 => 7.5,                              // telnet, cleartext
            2375 => 9.0,                            // unauthenticated Docker API
            502 | 102 | 20000 | 47808 => 8.5,       // exposed industrial control
            6379 | 11211 | 27017 | 9200 => 8.0,     // data stores, no-auth by default
            623 => 7.0,                             // IPMI/BMC
            3389 => 6.5,                            // exposed RDP
            21 | 5900 => 6.0,                       // ftp / VNC
            139 | 445 => 5.5,                       // SMB
            161 | 1433 | 1521 | 3306 | 5432 => 5.0, // SNMP / exposed database
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

    #[test]
    fn every_probed_port_has_a_service_name() {
        for &port in PORTS {
            assert!(
                service_name(port).is_some(),
                "PORTS includes {port} but service_name() has no mapping"
            );
        }
    }
}
