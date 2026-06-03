//! Curated catalog of well-known CVEs.
//!
//! A seed set with real CVE ids, CVSS, approximate EPSS and CISA-KEV flags. The
//! full NVD/EPSS/KEV feeds plug in behind the same [`CveRecord`] shape later.

use argus_core::Severity;

use crate::{CveRecord, VersionRange};

/// The bundled CVE catalog.
pub const CATALOG: &[CveRecord] = &[
    CveRecord {
        cve_id: "CVE-2024-6387",
        product: "OpenSSH",
        affected: VersionRange::Range("8.5", "9.7"),
        cvss: 8.1,
        epss: 0.62,
        kev: false,
        severity: Severity::High,
        summary: "regreSSHion: unauthenticated RCE in OpenSSH server (sshd)",
    },
    CveRecord {
        cve_id: "CVE-2021-41773",
        product: "Apache",
        affected: VersionRange::Exact("2.4.49"),
        cvss: 7.5,
        epss: 0.975,
        kev: true,
        severity: Severity::High,
        summary: "Apache httpd 2.4.49 path traversal and remote code execution",
    },
    CveRecord {
        cve_id: "CVE-2011-2523",
        product: "vsftpd",
        affected: VersionRange::Exact("2.3.4"),
        cvss: 9.8,
        epss: 0.96,
        kev: false,
        severity: Severity::Critical,
        summary: "vsftpd 2.3.4 backdoor command execution",
    },
    CveRecord {
        cve_id: "CVE-2017-0144",
        product: "smb",
        affected: VersionRange::Any,
        cvss: 8.1,
        epss: 0.94,
        kev: true,
        severity: Severity::High,
        summary: "EternalBlue: SMBv1 remote code execution",
    },
    CveRecord {
        cve_id: "CVE-2019-0708",
        product: "rdp",
        affected: VersionRange::Any,
        cvss: 9.8,
        epss: 0.95,
        kev: true,
        severity: Severity::Critical,
        summary: "BlueKeep: Remote Desktop Services remote code execution",
    },
    CveRecord {
        cve_id: "CVE-2024-3094",
        product: "xz",
        affected: VersionRange::Range("5.6.0", "5.6.1"),
        cvss: 10.0,
        epss: 0.70,
        kev: true,
        severity: Severity::Critical,
        summary: "xz/liblzma upstream backdoor",
    },
];
