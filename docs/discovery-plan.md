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
  vendor, os, model, confidence 0..100, evidence). Reverse-DNS populates
  hostnames. Wires OUI + banners + port-class into a confident identity. Status: —
- **P1a — mDNS/DNS-SD** (5353). `_services._dns-sd._udp.local` → service types →
  SRV/TXT/A: hostname, model (TXT), device class. Finds Apple/printers/cast/Pi
  (`raspberrypi.local`). Status: —
- **P1b — SSDP/UPnP + WS-Discovery** (1900 / 3702). M-SEARCH + descriptor XML
  (friendlyName/manufacturer/modelName); WSD Probe → printers/cameras/Windows.
  Status: —
- **P1c — SNMP + NetBIOS** (161 / 137). SNMP GET sysDescr/sysObjectID/sysName
  (exact OS/device); NBSTAT → Windows name + workgroup + MAC. Status: —
- **P2 — TLS cert + JA fusion.** rustls no-verify handshake → cert CN/SAN/issuer
  → identity + dedup key; feeds fusion. Status: —
- **P3 — Active ARP + dedup.** Privileged ARP sweep finds L3-filtered hosts;
  merge multi-homed observations into one asset via strong identity keys. Status: —

## Safety
Every new probe honors `is_disallowed_target`; small UDP queries (no SNMP/SSDP/NTP
amplification abuse); multicast only on the local segment; rate-limited;
"authorized targets only" stays. UDP/multicast/TLS need no root; only ARP/masscan/-O do.

## Honest scope
This reaches a very good *unauthenticated* discovery. Authenticated/agent-based
inventory and full external EASM (cert-transparency / passive DNS / ASN) remain
separate, larger tracks and are explicitly out of this push.
