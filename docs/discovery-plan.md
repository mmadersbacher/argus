# Active Discovery — road to best-in-class (plan + status)

Goal: from a TCP-connect port scanner to a multi-protocol, unauthenticated asset
discovery engine in the spirit of runZero — so a home/office scan surfaces every
device (Raspberry Pi, printer, TV, phone, camera, router) **with name, vendor,
OS, model and a confidence**, not just "host with open ports".

Benchmark techniques (runZero / nmap / Fingerbank): multi-protocol probing (not
just TCP), L2/ARP, UDP + multicast, TLS certificate harvesting, and **signal
fusion** — combining many weak signals into one confident identity.

## What already exists
TCP-connect scan + /24 sampling, masscan SYN sweep, nmap `-sS -sV -O`, ARP-cache
→ MAC → **full IEEE OUI vendor DB** (Raspberry Pi prefixes already present),
banner→product parsing, SMBv1 probe, SSRF guard, port-pattern classification.
`Protocol::Udp` and `Asset::correlation_key()` (MAC→IP→id) already exist.

## Data-model changes (minimal)
- `argus-core::Fingerprint`: add `model: Option<String>`, `evidence: Vec<String>`
  (Default-derived — low ripple). No `Service` change for v1 (TLS cert feeds
  fusion + hostname rather than being stored per service).
- `argus-discovery::DiscoveredHost`: add `hostnames: Vec<(source, name)>` and
  reuse interfaces for MAC/IP; identity for dedup via `Asset::correlation_key`.

## Phases (each shippable + CI-green + measured on a real /24)

- **P0 — Fusion core.** `fusion.rs`: fuse(signals)→Fingerprint(device_type,
  vendor, os, model, confidence 0..100, evidence). Wires OUI + banners +
  port-class into a confident identity. Status: **DONE** (`fusion.rs`).
- **P1a — mDNS/DNS-SD** (5353). `_services._dns-sd._udp.local` → service types →
  SRV/TXT/A: hostname, model (TXT), device class. Finds Apple/printers/cast/Pi
  (`raspberrypi.local`). Status: **DONE** (`mdns.rs`).
- **P1b — SSDP/UPnP + WS-Discovery** (1900 / 3702).
  Status: **SSDP DONE + E2E-proven** — `ssdp.rs` M-SEARCH (`ssdp:all`) collects
  responders, then fetches each `LOCATION` descriptor (reqwest) and parses
  friendlyName/manufacturer/modelName/modelNumber/deviceType (roxmltree); merged
  as a discovery source. Real /24 lifted a Samsung TV's full identity
  (`Samsung | QE55Q65CAUXXN | dialreceiver`). **WSD DONE in code + unit-tested,
  NOT yet E2E-proven** — `wsd.rs` sends a SOAP Probe and parses ProbeMatch
  Types/XAddrs/endpoint, but no printer/camera/Windows host answered on the test
  /24 this run (Windows WSD may need probe-format tuning / firewall profile);
  flagged to verify live.
- **P1c — SNMP + NetBIOS** (161 / 137). Status: **DONE** (`snmp.rs`, `netbios.rs`).
- **P2 — TLS cert + JA fusion.**
  Status: **DONE + E2E-proven** — `tls.rs` shells to `openssl s_client | x509`
  (no Rust TLS dep, matches the masscan/arp-scan shell-out convention), parsing
  subject CN / issuer / SAN / notAfter; harvests on 443/8443/9443/4443; SAN/CN
  feed the hostname + a `tls:` service banner. Real /24 pulled
  `CN=mediarouter.home … SAN=mediarouter1-3.home` and per-Deco-node certs (SANs
  even leaked internal IPs). JA3/JA fingerprint not done (would need a real TLS
  stack); cert-based dedup key available via SAN but not yet wired into merge.
- **P1d — extra unauthenticated protocols (beyond original plan).**
  Status: **DONE** — `http.rs` (Server / X-Powered-By / `<title>` / status via
  reqwest, self-signed-tolerant; E2E-proven: `Server=WebServer title=403`),
  `coap.rs` (UDP 5683 multicast `/.well-known/core`; code+unit-tested, no live
  CoAP responder this run), `rdns.rs` (PTR via `getent hosts` → DNS+hosts+mDNS;
  E2E-proven: `mediarouter.home`, `tplinkdeco.net`). `fusion.rs` gained a
  `device_from_identity` fallback that classifies from SSDP/WSD/HTTP/CoAP/TLS
  strings when OUI gave no profile. **Deliberately excluded for safety:** active
  DHCP (lease disruption), NTP `readvar` (amplification), OT/ICS Modbus/BACnet
  (fragile devices) — documented, not silently dropped.
- **P1e — Xiaomi miIO + OUI-classification discipline.**
  Status: **DONE + E2E-proven** — `miio.rs` sends the unauthenticated miIO Hello
  (UDP 54321, unicast fan-out over scope); a response is positive proof of a
  Xiaomi smart-home device (a phone stays silent). `fusion` classifies Iot/
  smart-home-device only on the miIO signal, never on the Xiaomi OUI. This
  enforced a broader rule: a **multi-purpose-vendor OUI (Xiaomi/Samsung/LG/Google/
  Apple) must not assert a device class on its own** — only a protocol signal may.
  Samsung/LG/Google were pulled from `vendor_profile`'s confident branch (Apple
  stays port-gated; single-purpose Nest/Amazon/Sonos/Roku kept). Verified on a
  real /24: a portless Xiaomi (`device_id=0x2cc9f8a8`) → smart-home-device; two
  portless Samsung devices → honest `Unknown` (previously mis-guessed
  "smart-home-or-media"). The exact Xiaomi SKU still needs the per-device token.
  3 guard tests lock the discipline.
- **P1f — IPP/RTSP device-model probes + fusion evidence hierarchy.**
  Status: **DONE** (probes E2E-unproven — no 631/554 host on the test /24).
  `ipp.rs` (IPP `Get-Printer-Attributes`, port 631 → printer make/model/state) and
  `rtsp.rs` (RTSP `OPTIONS`, port 554 → Server banner = camera/NVR vendor) added as
  enrichment passes; their make/model flows into the identity haystack. **Fusion
  ordering bug fixed:** the port-pattern `device_type` (set in `build_host`) used
  to win because `device_from_identity` was guarded by `is_none()`. Now protocol
  identity OVERRIDES the port-class guess and the OUI profile; **priority is miIO >
  protocol-identity (SSDP/WSD/mDNS/IPP/RTSP/HTTP/TLS) > OUI vendor_profile >
  port-class**. Live proof: the gateway `.1 mediarouter.home` went It/web-server →
  Network/router-or-ap; a Samsung `.104` went to Iot/media-device on its mDNS name
  instead of an OUI guess. 2 guard tests lock the override. Discovery modules: 25.
- **P3 — Active ARP + dedup.** Privileged ARP sweep finds L3-filtered hosts;
  merge multi-homed observations into one asset via strong identity keys.
  Status: **active-ARP DONE** — `arpscan.rs` shells to `arp-scan` (`--quiet
  --ignoredups --retry=3`), wired as a discovery *source* at the head of
  `enrich()` so it adds L2-only devices (no open TCP port, no mDNS) which the
  connect scan structurally cannot see; new hosts carry their MAC and get OUI/
  NetBIOS/SNMP/fusion enrichment; `fusion` tags them `l2-only`. Verified on a
  real /24: surfaced a portless Samsung IoT device (IoT from OUI) and a
  MAC-randomised phone (present-but-unidentified) the old engine missed. Gated to
  internal IPv4 + `arp-scan` present + privileged (best-effort, like masscan).
  **Caveats / still open:** (1) power-saving Wi-Fi clients miss any single sweep —
  run-to-run counts vary (7→11→9), so true completeness needs the asset store to
  *union* repeated scans over time, not one snapshot; (2) identity-key dedup is
  still only IP-match — multi-homed/MAC-randomised merge via `correlation_key`
  not yet done; (3) native raw-socket sender in `argus-sensor` (no external
  `arp-scan` dep) remains a follow-up.

## Safety
Every new probe honors `is_disallowed_target`; small UDP queries (no SNMP/SSDP/NTP
amplification abuse); multicast only on the local segment; rate-limited;
"authorized targets only" stays. UDP/multicast/TLS need no root; only ARP/masscan/-O do.

## Honest scope
This reaches a very good *unauthenticated* discovery. Authenticated/agent-based
inventory and full external EASM (cert-transparency / passive DNS / ASN) remain
separate, larger tracks and are explicitly out of this push.
