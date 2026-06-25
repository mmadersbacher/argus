//! Typed device role, derived from the free-form fingerprint `device_type`.
//!
//! [`AssetType`](crate::AssetType) is the broad *trust class* (IT/OT/IoT/IoMT);
//! `DeviceRole` is the orthogonal *function* — what the box actually is, for
//! risk and segmentation decisions (a Domain Controller is domain-wide blast
//! radius; a camera is an embedded-firmware liability; a NAS holds the data).
//!
//! The discovery pipeline writes a free-form `device_type` string (~250 distinct
//! values across the fusion and intel classifiers). `DeviceRole` is *derived*
//! from that string by ordered keyword match — it is never stored, so there is
//! no serde migration and the role tracks classifier improvements for free.

use serde::{Deserialize, Serialize};

/// What a device is, for risk/segmentation reasoning. Derived from the
/// fingerprint `device_type`; orthogonal to [`AssetType`](crate::AssetType).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum DeviceRole {
    /// Active Directory domain controller — Tier-0, domain-wide blast radius.
    DomainController,
    /// Virtualization host (ESXi/Proxmox/Hyper-V/…) — Tier-0, hosts many VMs.
    Hypervisor,
    /// General server (web/database/mail/host).
    Server,
    /// Network-attached storage / file server — holds the data.
    Nas,
    /// Printer / multifunction device.
    Printer,
    /// IP camera.
    Camera,
    /// Network video recorder.
    Nvr,
    /// Network infrastructure (router, switch, firewall, access point).
    NetworkDevice,
    /// Industrial / building-automation controller (PLC, Modbus, BACnet).
    IndustrialController,
    /// VoIP phone / SIP endpoint.
    VoipPhone,
    /// Networked medical device.
    MedicalDevice,
    /// Media / smart-TV / streaming device.
    MediaDevice,
    /// End-user workstation / desktop.
    Workstation,
    /// Mobile device (phone / tablet).
    Mobile,
    /// Generic consumer IoT / smart-home device.
    Iot,
    /// Role could not be resolved from the device type.
    #[default]
    Unknown,
}

impl DeviceRole {
    /// Every variant, in declaration order. Single source of truth for callers
    /// that enumerate all roles (reports); kept exhaustive by the `all_covers`
    /// test.
    pub const ALL: [Self; 16] = [
        Self::DomainController,
        Self::Hypervisor,
        Self::Server,
        Self::Nas,
        Self::Printer,
        Self::Camera,
        Self::Nvr,
        Self::NetworkDevice,
        Self::IndustrialController,
        Self::VoipPhone,
        Self::MedicalDevice,
        Self::MediaDevice,
        Self::Workstation,
        Self::Mobile,
        Self::Iot,
        Self::Unknown,
    ];

    /// Tier-0 "crown jewels": a compromise here is domain-wide / fleet-wide, not
    /// a single host. Drives the policy escalation.
    #[must_use]
    pub fn is_tier0(self) -> bool {
        matches!(self, Self::DomainController | Self::Hypervisor)
    }

    /// Operational-technology roles (process / safety impact), where Argus only
    /// ever observes and never writes.
    #[must_use]
    pub fn is_ot(self) -> bool {
        matches!(self, Self::IndustrialController | Self::MedicalDevice)
    }

    /// Resolve a role from a free-form `device_type` string by ordered keyword
    /// match — the **first** substring hit wins, so the table is sorted
    /// most-specific first (storage before "server", camera/nvr before generic,
    /// media before "server"). An empty or unrecognised string is `Unknown`.
    #[must_use]
    pub fn from_device_type(device_type: &str) -> Self {
        let lower = device_type.to_ascii_lowercase();
        ROLE_KEYWORDS
            .iter()
            .find(|(needle, _)| lower.contains(needle))
            .map_or(Self::Unknown, |(_, role)| *role)
    }
}

/// Ordered `(substring, role)` table for [`DeviceRole::from_device_type`].
/// Order is significant — the first contained substring wins. Substrings are
/// real `device_type` values emitted by `argus-discovery::fusion` and
/// `argus-intel`.
const ROLE_KEYWORDS: &[(&str, DeviceRole)] = &[
    // Tier-0 first.
    ("domain-controller", DeviceRole::DomainController),
    ("esxi", DeviceRole::Hypervisor),
    ("vcenter", DeviceRole::Hypervisor),
    ("proxmox", DeviceRole::Hypervisor),
    ("hyper-v", DeviceRole::Hypervisor),
    ("virtualization-host", DeviceRole::Hypervisor),
    ("nutanix", DeviceRole::Hypervisor),
    ("vmware", DeviceRole::Hypervisor),
    // OT / industrial / medical (specific, before any generic).
    ("industrial-controller", DeviceRole::IndustrialController),
    ("industrial", DeviceRole::IndustrialController),
    ("modbus", DeviceRole::IndustrialController),
    ("bacnet", DeviceRole::IndustrialController),
    ("allen-bradley", DeviceRole::IndustrialController),
    ("rockwell", DeviceRole::IndustrialController),
    ("beckhoff", DeviceRole::IndustrialController),
    ("siemens", DeviceRole::IndustrialController),
    ("schneider", DeviceRole::IndustrialController),
    ("wago", DeviceRole::IndustrialController),
    ("logix", DeviceRole::IndustrialController),
    ("plc", DeviceRole::IndustrialController),
    ("medical-device", DeviceRole::MedicalDevice),
    ("draeger", DeviceRole::MedicalDevice),
    ("medtronic", DeviceRole::MedicalDevice),
    ("baxter", DeviceRole::MedicalDevice),
    ("hillrom", DeviceRole::MedicalDevice),
    // Storage — before "server".
    ("nas-storage", DeviceRole::Nas),
    ("diskstation", DeviceRole::Nas),
    ("rackstation", DeviceRole::Nas),
    ("synology", DeviceRole::Nas),
    ("qnap", DeviceRole::Nas),
    ("truenas", DeviceRole::Nas),
    ("freenas", DeviceRole::Nas),
    ("openmediavault", DeviceRole::Nas),
    ("terramaster", DeviceRole::Nas),
    ("asustor", DeviceRole::Nas),
    ("unraid", DeviceRole::Nas),
    ("drobo", DeviceRole::Nas),
    ("nas", DeviceRole::Nas),
    // Cameras / NVR — before generic / network.
    ("ip-camera", DeviceRole::Camera),
    ("ipcam", DeviceRole::Camera),
    ("hikvision", DeviceRole::Camera),
    ("dahua", DeviceRole::Camera),
    ("reolink", DeviceRole::Camera),
    ("foscam", DeviceRole::Camera),
    ("amcrest", DeviceRole::Camera),
    ("lorex", DeviceRole::Camera),
    ("vivotek", DeviceRole::Camera),
    ("mobotix", DeviceRole::Camera),
    ("hanwha", DeviceRole::Camera),
    ("uniview", DeviceRole::Camera),
    ("vapix", DeviceRole::Camera),
    ("dvrdvs", DeviceRole::Camera),
    ("axis", DeviceRole::Camera),
    ("camera", DeviceRole::Camera),
    ("nvr", DeviceRole::Nvr),
    // Printers.
    ("laserjet", DeviceRole::Printer),
    ("officejet", DeviceRole::Printer),
    ("deskjet", DeviceRole::Printer),
    ("bizhub", DeviceRole::Printer),
    ("kyocera", DeviceRole::Printer),
    ("ricoh", DeviceRole::Printer),
    ("xerox", DeviceRole::Printer),
    ("workcentre", DeviceRole::Printer),
    ("jetdirect", DeviceRole::Printer),
    ("pixma", DeviceRole::Printer),
    ("imageclass", DeviceRole::Printer),
    ("printer", DeviceRole::Printer),
    // Network gear — before generic server/host.
    ("access-point", DeviceRole::NetworkDevice),
    ("router-or-ap", DeviceRole::NetworkDevice),
    ("mikrotik", DeviceRole::NetworkDevice),
    ("routeros", DeviceRole::NetworkDevice),
    ("routerboard", DeviceRole::NetworkDevice),
    ("pfsense", DeviceRole::NetworkDevice),
    ("opnsense", DeviceRole::NetworkDevice),
    ("sonicwall", DeviceRole::NetworkDevice),
    ("fortios", DeviceRole::NetworkDevice),
    ("fortigate", DeviceRole::NetworkDevice),
    ("fortinet", DeviceRole::NetworkDevice),
    ("watchguard", DeviceRole::NetworkDevice),
    ("ubiquiti", DeviceRole::NetworkDevice),
    ("edgerouter", DeviceRole::NetworkDevice),
    ("edgeos", DeviceRole::NetworkDevice),
    ("vyos", DeviceRole::NetworkDevice),
    ("firewall", DeviceRole::NetworkDevice),
    ("router", DeviceRole::NetworkDevice),
    ("switch", DeviceRole::NetworkDevice),
    ("network-device", DeviceRole::NetworkDevice),
    // VoIP.
    ("voip", DeviceRole::VoipPhone),
    ("snom", DeviceRole::VoipPhone),
    ("yealink", DeviceRole::VoipPhone),
    ("grandstream", DeviceRole::VoipPhone),
    ("polycom", DeviceRole::VoipPhone),
    ("soundpoint", DeviceRole::VoipPhone),
    // Media — before "server".
    ("smart-tv", DeviceRole::MediaDevice),
    ("smarttv", DeviceRole::MediaDevice),
    ("media-server", DeviceRole::MediaDevice),
    ("media-device", DeviceRole::MediaDevice),
    ("media-streamer", DeviceRole::MediaDevice),
    ("chromecast", DeviceRole::MediaDevice),
    ("appletv", DeviceRole::MediaDevice),
    ("firetv", DeviceRole::MediaDevice),
    ("roku", DeviceRole::MediaDevice),
    ("sonos", DeviceRole::MediaDevice),
    // Generic server roles.
    ("database-server", DeviceRole::Server),
    ("web-server", DeviceRole::Server),
    ("exchange", DeviceRole::Server),
    ("microsoft-iis", DeviceRole::Server),
    ("linux-host", DeviceRole::Server),
    ("server", DeviceRole::Server),
    // Workstation / mobile / IoT fall-through.
    ("workstation", DeviceRole::Workstation),
    ("windows-host", DeviceRole::Workstation),
    ("desktop", DeviceRole::Workstation),
    ("windows", DeviceRole::Workstation),
    ("mobile-device", DeviceRole::Mobile),
    ("apple-mobile", DeviceRole::Mobile),
    ("smart-home", DeviceRole::Iot),
    ("iot-device", DeviceRole::Iot),
    ("consumer-iot", DeviceRole::Iot),
    ("shelly", DeviceRole::Iot),
    ("tasmota", DeviceRole::Iot),
    ("tuya", DeviceRole::Iot),
    ("nest", DeviceRole::Iot),
    ("wemo", DeviceRole::Iot),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_representative_device_types_per_role() {
        let cases = [
            ("domain-controller", DeviceRole::DomainController),
            ("esxi", DeviceRole::Hypervisor),
            ("proxmox virtualization-host", DeviceRole::Hypervisor),
            ("synology diskstation", DeviceRole::Nas),
            ("nas-storage", DeviceRole::Nas),
            ("hikvision ip-camera", DeviceRole::Camera),
            ("axis", DeviceRole::Camera),
            ("nvr", DeviceRole::Nvr),
            ("hp laserjet", DeviceRole::Printer),
            ("mikrotik routeros", DeviceRole::NetworkDevice),
            ("fortigate firewall", DeviceRole::NetworkDevice),
            ("industrial-controller", DeviceRole::IndustrialController),
            ("siemens plc", DeviceRole::IndustrialController),
            ("yealink voip-phone", DeviceRole::VoipPhone),
            ("draeger medical-device", DeviceRole::MedicalDevice),
            ("samsung smart-tv", DeviceRole::MediaDevice),
            ("web-server", DeviceRole::Server),
            ("windows-host", DeviceRole::Workstation),
            ("mobile-device", DeviceRole::Mobile),
            ("shelly smart-home", DeviceRole::Iot),
        ];
        for (input, expected) in cases {
            assert_eq!(
                DeviceRole::from_device_type(input),
                expected,
                "device_type {input:?}",
            );
        }
    }

    #[test]
    fn unmatched_and_empty_are_unknown() {
        assert_eq!(DeviceRole::from_device_type(""), DeviceRole::Unknown);
        assert_eq!(DeviceRole::from_device_type("unknown"), DeviceRole::Unknown);
        assert_eq!(
            DeviceRole::from_device_type("some-future-gadget"),
            DeviceRole::Unknown
        );
    }

    #[test]
    fn most_specific_keyword_wins_over_generic() {
        // A NAS string that also contains "server"-ish noise must resolve to Nas
        // (storage keywords precede the generic "server" entry).
        assert_eq!(
            DeviceRole::from_device_type("synology diskstation nas file server"),
            DeviceRole::Nas
        );
        // "media-server" must be MediaDevice, not Server.
        assert_eq!(
            DeviceRole::from_device_type("plex media-server"),
            DeviceRole::MediaDevice
        );
        // Matching is case-insensitive.
        assert_eq!(
            DeviceRole::from_device_type("DOMAIN-CONTROLLER"),
            DeviceRole::DomainController
        );
    }

    #[test]
    fn tier0_and_ot_membership() {
        assert!(DeviceRole::DomainController.is_tier0());
        assert!(DeviceRole::Hypervisor.is_tier0());
        assert!(!DeviceRole::Workstation.is_tier0());
        assert!(DeviceRole::IndustrialController.is_ot());
        assert!(DeviceRole::MedicalDevice.is_ot());
        assert!(!DeviceRole::Camera.is_ot());
    }

    #[test]
    fn all_covers_every_variant() {
        for role in DeviceRole::ALL {
            match role {
                DeviceRole::DomainController
                | DeviceRole::Hypervisor
                | DeviceRole::Server
                | DeviceRole::Nas
                | DeviceRole::Printer
                | DeviceRole::Camera
                | DeviceRole::Nvr
                | DeviceRole::NetworkDevice
                | DeviceRole::IndustrialController
                | DeviceRole::VoipPhone
                | DeviceRole::MedicalDevice
                | DeviceRole::MediaDevice
                | DeviceRole::Workstation
                | DeviceRole::Mobile
                | DeviceRole::Iot
                | DeviceRole::Unknown => {}
            }
        }
        assert_eq!(DeviceRole::ALL.len(), 16);
    }
}
