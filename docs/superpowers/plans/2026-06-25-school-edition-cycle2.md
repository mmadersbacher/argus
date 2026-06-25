# School Edition — Cycle 2: typed DeviceRole taxonomy + Tier-0 escalation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give Argus a typed `DeviceRole` so policy/report/risk can reason about *what a device is* (a Domain Controller, a camera, a NAS) instead of a free-form `device_type` string — and use it to express the spec §5 "DC / Tier-0-aware escalation" the current model cannot.

**Architecture:** `DeviceRole` is a **role** dimension separate from `AssetType` (the IT/OT/IoT *trust class*). It is *derived*, not stored: the discovery pipeline already writes a free-form `Fingerprint.device_type: Option<String>` (~250 distinct values across two classifiers); `DeviceRole::from_device_type` maps that noisy vocabulary to a small, risk-relevant role set by ordered keyword match (most-specific first). Policy consumes the role; nothing in the wire format is removed (the role is an *added* report field, backward-compatible for the console).

**Tech Stack:** Rust 1.83 (edition 2021), the existing argus workspace; no new dependencies.

## Global Constraints

- Rust floor **1.83**, `edition = "2021"`, `unsafe_code = "forbid"` workspace-wide.
- **Before every commit:** `cargo fmt --all`; CI fails on `cargo fmt --all --check` and on `cargo clippy --workspace --all-targets -- -D warnings` (pedantic + nursery) separately from tests.
- `cargo test --workspace` stays green.
- Commits sole-authored by `mmadersbacher` (noreply email), **no Claude/AI trailer**, conventional-commit messages (`feat(core): …`).
- Keep `DeviceRole` derived from `device_type` — do **not** add a stored field to `Asset` (avoids a serde migration); expose it via a method.
- New variants go through the same `ALL` + exhaustive-guard pattern added in Cycle 2 prep (see `AssetType::ALL` / `risk::all_bands_is_exhaustive`).

## File structure

- `crates/argus-core/src/role.rs` — **new**: `DeviceRole` enum, `from_device_type`, `ALL`, `is_tier0`, `is_ot`, role tests.
- `crates/argus-core/src/lib.rs` — re-export `DeviceRole`.
- `crates/argus-core/src/asset.rs` — `Fingerprint::role()` helper (derive from `device_type`).
- `crates/argus-policy/src/lib.rs` — `PolicyAsset.device_role` field + `tier0_crown_jewel` advisory rule.
- `crates/argus-api/src/policy.rs` — populate `PolicyAsset.device_role` from the fingerprint.
- `crates/argus-report/src/lib.rs` — `by_role` inventory section keyed on `DeviceRole::ALL`.

---

### Task 1: `DeviceRole` enum + derivation (argus-core)

**Files:** Create `crates/argus-core/src/role.rs`; Modify `crates/argus-core/src/lib.rs` (module + re-export).

**Interfaces — Produces:**
- `enum DeviceRole { DomainController, Hypervisor, Server, Nas, Printer, Camera, Nvr, NetworkDevice, IndustrialController, VoipPhone, MedicalDevice, MediaDevice, Workstation, Mobile, Iot, Unknown }` — `#[derive(Debug,Clone,Copy,PartialEq,Eq,PartialOrd,Ord,Hash,Serialize,Deserialize,Default)]`, `#[serde(rename_all="snake_case")]`, `#[default] Unknown`.
- `DeviceRole::from_device_type(&str) -> DeviceRole` — lowercase, ordered keyword match, most-specific first; `None`/empty/unmatched → `Unknown`.
- `DeviceRole::ALL: [Self; 16]`.
- `DeviceRole::is_tier0(self) -> bool` — `DomainController | Hypervisor` (crown jewels: compromise = domain-wide).
- `DeviceRole::is_ot(self) -> bool` — `IndustrialController | MedicalDevice`.

**Derivation grounding** (real `device_type` substrings seen in `fusion.rs` + `argus-intel`): `domain-controller`→DomainController; `esxi|proxmox|vmware|vcenter|virtualization-host|nutanix|hyper-v`→Hypervisor; `nas|diskstation|synology|qnap|truenas|freenas|openmediavault|terramaster|rackstation|unraid|asustor`→Nas; `camera|ipcam|hikvision|dahua|axis|reolink|foscam|amcrest|lorex|vivotek|mobotix|hanwha|uniview|vapix|dvrdvs`→Camera; `nvr`→Nvr; `printer|laserjet|officejet|deskjet|bizhub|kyocera|ricoh|xerox|pixma|workcentre|jetdirect`→Printer; `router|switch|firewall|access-point|router-or-ap|mikrotik|routeros|pfsense|opnsense|sonicwall|fortios|fortinet|fortigate|watchguard|ubiquiti|edgerouter|vyos|network-device`→NetworkDevice; `industrial-controller|plc|modbus|bacnet|allen-bradley|rockwell|wago|beckhoff|siemens|schneider`→IndustrialController; `voip|snom|yealink|grandstream|polycom|soundpoint`→VoipPhone; `medical-device|draeger|medtronic|baxter|hillrom`→MedicalDevice; `smart-tv|smarttv|media-device|media-server|chromecast|roku|appletv|firetv|sonos`→MediaDevice; `database-server|web-server|exchange|iis|server`→Server; `mobile-device|apple-mobile|phone`→Mobile; `workstation|windows-host|desktop`→Workstation; `smart-home|iot-device|consumer-iot|shelly|tasmota|tuya|nest|wemo`→Iot. Order matters (e.g. `nas` before `server`, `camera`/`nvr` before generic, `industrial` before everything).

- [ ] Step 1: write `role.rs` with the enum, `ALL`, `is_tier0`, `is_ot`, and `from_device_type` (ordered `&[(&str, DeviceRole)]` keyword table; iterate, first substring hit wins).
- [ ] Step 2: tests — `from_device_type` maps representative real strings per role; `unknown`/`""` → `Unknown`; the most-specific-first ordering (e.g. `"synology diskstation nas"`→Nas not Server); `is_tier0`/`is_ot` membership; exhaustive `ALL` guard (match over every variant + `len()==16`).
- [ ] Step 3: `lib.rs` — `mod role; pub use role::DeviceRole;`
- [ ] Step 4: `cargo test -p argus-core` green; `cargo clippy -p argus-core --all-targets -- -D warnings` clean.
- [ ] Step 5: `cargo fmt --all` then commit `feat(core): typed DeviceRole derived from the free-form device_type`.

### Task 2: `Fingerprint::role()` (argus-core)

**Files:** Modify `crates/argus-core/src/asset.rs`.

**Interfaces — Consumes:** `DeviceRole::from_device_type`. **Produces:** `Fingerprint::role(&self) -> DeviceRole` (`self.device_type.as_deref().map_or(DeviceRole::Unknown, DeviceRole::from_device_type)`).

- [ ] Step 1: test — a `Fingerprint{ device_type: Some("domain-controller"), .. }` yields `DeviceRole::DomainController`; `None` → `Unknown`.
- [ ] Step 2: implement `Fingerprint::role`.
- [ ] Step 3: `cargo test -p argus-core` green; commit `feat(core): Fingerprint::role() resolves the typed device role`.

### Task 3: Tier-0 crown-jewel advisory (argus-policy)

**Files:** Modify `crates/argus-policy/src/lib.rs`.

**Interfaces — Consumes:** `argus_core::DeviceRole`. **Produces:** `PolicyAsset.device_role: DeviceRole`; a `tier0_crown_jewel` rule wired into `evaluate`.

**Rule:** a Tier-0 asset (`device_role.is_tier0()`) that is reachable from elsewhere on a mixed flat /24 (the `mgmt_reachable_internal` precondition) AND exposes a critical/high mgmt port → **Critical** advisory (vs the generic rule's High), rationale: "a Domain Controller / hypervisor is domain-wide blast radius; the same exposure on a workstation is not." Worst-first by role.

- [ ] Step 1: extend the `PolicyAsset` test helper with `device_role: DeviceRole::Unknown`; add `device_role` to the struct.
- [ ] Step 2: failing test — a DC (`device_role: DomainController`, port 3389) sharing a /24 with an IoT camera yields a `tier0-crown-jewel` Critical advisory naming the DC; a workstation in the same shape does **not**.
- [ ] Step 3: implement `tier0_crown_jewel`, add it to the `evaluate` array.
- [ ] Step 4: `cargo test -p argus-policy` green; clippy clean; commit `feat(policy): Tier-0 crown-jewel escalation for exposed DC/hypervisor`.

### Task 4: populate the role in the API (argus-api)

**Files:** Modify `crates/argus-api/src/policy.rs`.

**Interfaces — Consumes:** `Fingerprint::role`, `PolicyAsset.device_role`.

- [ ] Step 1: in the `PolicyAsset { … }` builder, add `device_role: a.asset.fingerprint.role()`.
- [ ] Step 2: `cargo test -p argus-api` green; clippy clean; commit `feat(api): pass the typed device role into the policy evaluator`.

### Task 5: report inventory by role (argus-report)

**Files:** Modify `crates/argus-report/src/lib.rs`.

**Interfaces — Consumes:** `DeviceRole::ALL`, `Fingerprint::role` (or an `AssetFacts.device_role` already mapped by the caller). **Produces:** `Inventory.by_role: Vec<RoleCount>` (added field; backward-compatible JSON).

- [ ] Step 1: add `RoleCount { role: DeviceRole, count: usize }` and `Inventory.by_role`; populate from `DeviceRole::ALL`, filter `count>0`, sort by count desc (same shape as `by_type`). Source the role from the asset facts (add `device_role` to `AssetFacts` if not present, mapped by the api caller).
- [ ] Step 2: test — an inventory with two DCs and one camera reports `by_role` containing DomainController=2, Camera=1, and excludes zero-count roles.
- [ ] Step 3: `cargo test -p argus-report` green; clippy clean; commit `feat(report): inventory breakdown by device role`.

### Final verification (all tasks)

- [ ] `cargo fmt --all --check` clean
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` clean
- [ ] `cargo test --workspace` green
- [ ] `web`: `npm run lint` + `npm test` green (the added report field must not break the console; the TS client ignores unknown fields)

## Self-review

- **Spec coverage:** §5 "DC/Tier-0-aware escalation" → Task 3; "school taxonomy classes (DC, camera, NAS, whiteboard, …)" → Task 1 role set (whiteboard/projector/classroom-management fold into `MediaDevice`/`Workstation` until discovery emits distinct strings — noted, not silently dropped). The web surfacing of the role is **out of scope** here (needs the ts-contract work, a separate cycle) — Task 5 only adds the server-side report field.
- **Type consistency:** `DeviceRole` variant names are identical across role.rs, policy, report. `is_tier0` used in Task 3 is defined in Task 1.
- **No placeholders:** every task names exact files, the derivation table is concrete and grounded in real `device_type` strings, each task ends in a commit.

## Out of scope (later cycles, independent subsystems)

- Core smart constructors / validated newtypes (Cvss/Epss/VlanId) — own cycle.
- Rust→TS codegen (`ts-rs`) + `noUncheckedIndexedAccess` + surfacing `DeviceRole` in the console — web-hardening cycle.
- `main.rs` scan/ingest/scheduler module extraction — mechanical refactor cycle.
- discovery `enrich` combinator + shared `ber` module (snmp/ldap) — discovery-refactor cycle.
- School catalog expansion (Moodle/Synology/QNAP/Sophos/MikroTik/ESXi/UniFi/Veeam/Zerologon) — content cycle.
