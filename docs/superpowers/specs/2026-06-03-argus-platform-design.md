# Argus — Cyber Exposure & Asset Intelligence Platform

**Design-Spec** · Datum: 2026-06-03 · Status: Draft · Autor: Mario

> Armis-Centrix-inspirierte CAASM/Exposure-Management-Plattform. Ziel: **architektonisch
> und im Look-and-Feel ununterscheidbar von einem Enterprise-Produkt wie Armis**, gebaut
> vollständig auf Open-Source-Wissen und -Daten.

---

## 1. Vision (ein Satz)

Eine cloud-native Plattform, die jedes Gerät in einem Netz **kontinuierlich entdeckt,
identifiziert, bewertet und überwacht** — mit einem Asset-Graph, Exposure-Scoring und
einer Konsole, die in einem Demo Leute umhaut.

## 2. Ehrliche Scope-Grenze (nicht verhandelbar, einmal festgehalten)

| Dimension | Parität zu Armis? | Begründung |
|---|---|---|
| **System-Architektur** | **JA, 1:1** | Architektur ist Engineering, nicht Daten. Voll replizierbar. |
| **UX / Wow-Faktor** | **JA** | Reine Frontend-Arbeit. Voll replizierbar. |
| **Funktionaler Kern (Discovery→Score→Dashboard)** | **JA, echt lauffähig** | Auf eigenen/autorisierten Netzen mit OSS-Tooling machbar. |
| **Daten-/Geräte-Coverage** | **NEIN** | Armis' „Collective Asset Intelligence" = Telemetrie aus tausenden Enterprise-Netzen gleichzeitig. Struktureller Zugangs-Moat, nicht mit Fleiß lösbar. |

**Substitution der einen nicht-replizierbaren Box:** Armis' crowdsourced Knowledge Base
ersetzen wir durch **(a)** offene Fingerprint-Datenbanken (Fingerbank, IEEE-OUI,
Nmap-OS/Service-DB, p0f-Signaturen), **(b)** einen **selbst trainierten
Geräte-Klassifikator** auf kuratierten Open-Data + eigenen Lab-Captures, **(c)**
**per-Deployment-Verhaltens-Baselines** (Anomalie-Erkennung ohne Cross-Customer-Daten).
→ Die Architektur-Box bleibt identisch, nur ihre Datenquelle ist anders.

## 3. Referenz-Architektur (Armis) → unser Mirror

| Armis-Komponente | Funktion | Unser Pendant (Crate/Service) |
|---|---|---|
| Passive Collectors (agentless DPI) | Geräte aus Netzwerk-Traffic ableiten | `argus-sensor` (pcap/Zeek/p0f) |
| 100+ Integrationen | Daten aus Firewalls/EDR/Cloud/CMDB ziehen | `argus-connectors` (Cloud/AD/NetBox/EDR) |
| Aktive Erkennung (ergänzend) | Hosts/Ports/Services scannen | `argus-discovery` (nmap/masscan/arp-scan/naabu) |
| Ingestion & Normalization | Rohdaten vereinheitlichen | `argus-ingest` |
| Unified Asset Inventory | 1 Record je realem Gerät (Dedup) | `argus-core` (Asset-Graph + Dedup-Engine) |
| **Asset Intelligence Engine** | Geräte klassifizieren/baselinen | `argus-intel` (Open-Fingerprint-DBs + ML-Klassifikator) |
| Vulnerability-Korrelation | CVE ↔ Asset matchen | `argus-vuln` (NVD/KEV/EPSS CPE-Match + nuclei/OpenVAS) |
| Risk Engine | Risiko-Score je Asset & Org | `argus-risk` |
| Policy & Enforcement | Policy-Verstöße erkennen/durchsetzen | `argus-policy` (advisory + opt. NAC/Firewall) |
| Behavioral Anomaly Detection | Abweichung vom Geräte-Baseline | `argus-behavior` |
| Multi-Tenant Cloud Platform | Mandanten, API, Auth | `argus-api` (axum, RBAC, Multi-Tenant) |
| Web Console | Visualisierung & Steuerung | `argus-web` (Wow-Layer) |

## 4. Komponenten / Workspace-Layout

```
argus/
├─ crates/
│  ├─ argus-core         # Domänenmodell, Asset-Graph, Dedup, gemeinsame Typen
│  ├─ argus-discovery    # aktive Erkennung (Tool-Orchestrierung)
│  ├─ argus-sensor       # passives Sensing (pcap/Zeek/p0f)            [P2]
│  ├─ argus-intel        # Fingerprinting + Klassifikator
│  ├─ argus-vuln         # CVE-Korrelation
│  ├─ argus-risk         # Exposure-/Risk-Scoring
│  ├─ argus-behavior     # Anomalie-Baselines                          [P2]
│  ├─ argus-policy       # Policy-Engine (advisory)                    [P3]
│  ├─ argus-connectors   # externe Integrationen                       [P2]
│  ├─ argus-ingest       # Normalisierungs-Pipeline
│  ├─ argus-report       # Compliance-/Exec-Reports                    [P3]
│  └─ argus-api          # axum HTTP/WS/GraphQL, Auth, Multi-Tenant
└─ web/                  # argus-web: Next.js/TS Frontend
```

Konventionen wie SecurityToolKMU: `unsafe_code = "forbid"`, clippy pedantic+nursery,
`tracing`, `anyhow`/`thiserror`, cargo-deny, ADRs unter `docs/adr/`.

## 5. Datenmodell (Kern-Entities)

- **Tenant** (Org) → isoliert alle Daten. **User** (RBAC: Admin/Analyst/Viewer).
- **Asset** — ein reales Gerät. Dedup-Key über MAC/IP/Hostname/Fingerprint-Korrelation.
  Felder: type, vendor, os, criticality, first_seen, last_seen, exposure (internet-facing?).
- **Interface** (MAC/IP/VLAN) · **Service** (Port/Proto/Banner) · **Software** (CPE).
- **Vulnerability** (CVE, CVSS, EPSS, KEV-Flag) ↔ Asset (n:m via Software/Service).
- **Finding** — konkrete Beobachtung (Scan/Sensor-Ursprung, Confidence).
- **RiskScore** — je Asset + aggregiert je Tenant; Historie für Trends.
- **Sensor/ScanJob** — Herkunft der Daten, Status, Zeitstempel.
- **Alert** · **Policy** · **Baseline** (für Anomalie-Erkennung).

## 6. Tech-Stack + Begründung

- **Backend:** Rust · axum (HTTP/WS) · sqlx + **Postgres** · Tokio · async-trait ·
  Redis (Job-Queue/Cache) · `tracing`. Begründung: vorhandene Rust-Stärke, Performance,
  ein Sprach-Stack über alle Engines.
- **Frontend:** TypeScript · **Next.js (React)** · Tailwind · **Framer Motion**
  (Animationen) · **Cytoscape.js / Sigma.js** (Asset-Graph) · **Three.js** (3D-Hero) ·
  TanStack Query · WebSocket-Client.
- **Auth:** JWT/Session, RBAC, API-Keys; Tenant-Isolation per row-level (tenant_id) +
  Postgres RLS.
- **Deployment:** Container (Docker), 12-factor, cloud-native; lokal via docker-compose.

## 7. Der Wow-Layer (Frontend) — konkret

1. **Hero Asset-Graph** — force-directed, WebGL, Geräte als Icon-Nodes, Kanten =
   Verbindungen, Farbe = Risiko. Zoom/Pan, Live-Updates.
2. **Dashboard** — animierte Exposure-Gauge, Risiko-Heatmap, Trend-Sparklines,
   animierte Zähler (Assets/Vulns/kritische Findings).
3. **Echtzeit** — WebSocket: „Neues Asset entdeckt"-Toasts, Live-Scan-Progress.
4. **Device-Detail-Drawer** — Fingerprint, offene Services, CVE-Liste, Risk-Breakdown.
5. **Theme** — Dark/Glassmorphism, konsistente SVG-Iconographie, weiche
   Framer-Motion-Transitions.
6. **Onboarding/Empty-States** — geführter erster Scan, kein „leerer Bildschirm".

## 8. Multi-Tenancy & SaaS

Tenant-Isolation via `tenant_id` + Postgres Row-Level-Security. RBAC pro Tenant.
API-Keys je Org. Billing-ready Struktur (Plan/Quota-Felder) — Billing selbst erst P3+.

## 9. Non-Goals (explizit, damit kein Scope-Selbstbetrug entsteht)

- **Keine** Cross-Customer-Intelligence (der Daten-Moat). Nicht das Ziel.
- **Keine** IoMT-/OT-Coverage auf Armis-Niveau (Daten fehlen; OT-Discovery zudem riskant).
- **Keine** native Firewall/NAC-Enforcement-Parität — Segmentierung ist advisory +
  optionale Connectors.
- **Nicht** „identisch zu Armis" als Produkt-Outcome. Outcome = ehrliches OSS-CAASM-Tool
  mit Armis-Architektur und Enterprise-Optik.

## 10. Bau-Reihenfolge (Vollausbau, phasiert)

- **P0 — Foundations:** Repo, Workspace, CI, `argus-core`-Modell, Postgres-Schema,
  Auth/Tenant-Grundgerüst, leeres `argus-api` + `argus-web`-Shell.
- **P1 — Rückgrat (echt lauffähig):** `argus-discovery` (aktive Erkennung) → Inventar in
  Postgres → Basis-Fingerprinting (OUI/Nmap) → `argus-vuln` (NVD/KEV/EPSS) →
  `argus-risk` (Exposure-Score) → `argus-web` Dashboard + Asset-Graph. **Demo-fähiger
  Produkt-Slice.**
- **P2 — Intelligence:** `argus-sensor` (passiv), ML-Klassifikator in `argus-intel`,
  `argus-connectors` (Cloud/AD/NetBox), Continuous Monitoring + Change-Detection,
  `argus-behavior`-Baselines.
- **P3 — Enterprise/SaaS:** `argus-policy`, `argus-report` (Compliance), IR-Workflows,
  Multi-Tenancy-Härtung, Billing-Felder, Animations-Politur, Performance.

Jede Phase bekommt einen eigenen Implementierungsplan; P1 ist der erste Plan.

## 11. Risiken & offene Punkte

- **Autorisierung:** Aktive Scans nur auf eigenen/explizit autorisierten Netzen.
  Default = sicher; aktive Scans opt-in mit Scope-Eingabe. OT-Geräte können auf aktive
  Scans empfindlich reagieren → passive-first, aktive Scans mit Vorsicht.
- **Daten-Lizenzen:** Fingerbank/Nmap-DB-Nutzungsbedingungen prüfen (Attribution/Redistribution).
- **Scope-Creep:** 11 Crates sind viel. Disziplin: P1 zuerst voll lauffähig, dann erst P2.
- **Name:** „Argus" ist Working-Name (Kollision mit existierendem Netzwerk-Tool ARGUS möglich) — Final-Brand vor Public-Release.
- **„Echtzeit/Continuous":** in P1 als periodische Jobs, echtes Streaming erst P2.

## 12. Prior Art & abgeschaute Techniken (Research 2026-06-03)

Die Architektur fußt auf realem Verhalten der Referenzprodukte, nicht auf Annahmen.

| Quelle | Reale Technik | Was wir konkret übernehmen |
|---|---|---|
| **Armis** Multi-Detection-Engine | 7 Methoden (Passive Inspection, Integrationen, NetworkMapper, Wireless LAN, Smart Active Query, Asset Intelligence Engine, Threat Intel) | Mehrquellen-Discovery als Architektur-Prinzip — keine Methode allein, alle fließen in **einen** Asset-Record |
| **Armis** Smart Active Query | Aktiv aber **read-only**, **protokoll-nativ** (vendor-approved), nur bei niedriger Last → OT-sicher | `argus-discovery`: aktive Queries default read-only, protokoll-spezifisch statt generisch, opt-in mit Scope |
| **Armis** Asset Intelligence Engine | Crowdsourced KB (5 Mrd. Assets) + Verhaltens-Baselines → Alert/Quarantäne | **Substitut:** Open-Fingerprint-DBs + trainierter Klassifikator (`argus-intel`); Baselines **per-Deployment** (`argus-behavior`) statt cross-customer |
| **runZero** | Unauth active scan: nur „normaler" Traffic, **keine** malformed packets/Exploits, nur fingerprint-relevante Ports → OT-safe; **Subnet-Sampling** (Trickle in häufige Oktette je /24, nur antwortende Subnetze voll scannen) | `argus-discovery`: exakt dieses Safety-Modell + Subnet-Sampling-Algorithmus |
| **Axonius** | Adapter-Framework (auth/session/retry/backoff, Freshness+Source-Metadaten); Pipeline **Correlate → Normalize → Enrich** → 1 deduplizierter Record | `argus-connectors` (Adapter-Muster) + `argus-ingest` (3-Stufen-Pipeline) + `argus-core` Dedup |
| **NetBox** (Apache-2.0) | Postgres-Source-of-Truth, REST+GraphQL+Webhooks, Asset/IP/VLAN/Site-Schema | Datenmodell-Vorbild `argus-core`; GraphQL+Webhooks in `argus-api`; optionaler NetBox-Import-Connector |
| **Netdisco / LibreNMS / Open-AudIT** | L2-Discovery via SNMP/ARP/LLDP/CDP → Topologie | `argus-discovery`: SNMP/LLDP/CDP-Modul für Switch-/Topologie-Erkennung |
| **p0f v3 / PRADS / Satori** | Passives OS-Fingerprinting (TTL/TCP-Options/MSS/Window/DF; DHCP Option 55) | `argus-sensor`: p0f-Signatur-Ansatz + PRADS als Referenz für den passiven Sensor |
| **Fingerbank** | Offene DHCP-Fingerprint-DB (Option 55 + MAC-OUI + UA) | `argus-intel`: primäre offene Fingerprint-Quelle (Lizenz/API-Terms prüfen) |
| **Nmap** OS/Service-DB | Aktive Fingerprint-Signaturen | `argus-discovery`: **nur als externes Tool aufrufen** (⚠ NPSL — DB nicht bundlen/redistribuieren) |
| **CVE_Prioritizer** / vuln-intel-mcp | Composite-Score aus CVSS + EPSS + KEV | `argus-vuln` + `argus-risk`: exakt dieses Blending |
| **NVD API v2 / EPSS / CISA KEV** | CPE-Match (matchCriteriaId), KEV pro CVE, EPSS-Wahrscheinlichkeit | `argus-vuln`: Datenquellen für CVE↔Asset-Korrelation |
| arXiv 2502.09084 | Tabular-Transformer für OS-Fingerprinting | Beleg + Ansatz für den trainierten Klassifikator in `argus-intel` |

**Operative Realitäts-Notizen (in Risiken einfließen lassen):**
- **NVD scort die meisten CVEs nicht mehr** (NVD = Triage-Queue). → Nicht allein auf NVD-Enrichment verlassen; **EPSS + KEV (+ OSV/Vulners)** sind Pflicht-Quellen in `argus-vuln`.
- **Lizenzen:** Nmap-DB = NPSL (restriktiv, nur Tool-Aufruf), Fingerbank-DB/API-Terms prüfen, p0f = LGPL-nah. NetBox = Apache-2.0 (unkritisch).
- **Armis interner Stack** nicht sauber verifizierbar (Such-Verwechslung mit gleichnamiger Retail-Firma) — irrelevant für unsere Stack-Wahl.

## 13. Quellen

- Armis Asset Intelligence Engine — https://www.armis.com/platform/armis-asset-intelligence-engine/
- Armis Smart Active Querying — https://www.armis.com/platform/armis-centrix-smart-active-querying/ · https://www.armis.com/blog/armis-unleashes-smart-active-querying/
- Armis OT-Scanning FAQ — https://www.armis.com/faq/what-is-ot-scanning/
- runZero Discovery — https://help.runzero.com/docs/discovering-assets/ · https://www.runzero.com/blog/which-discovery-method-works-best-for-unmanaged-devices/
- Axonius Asset-Intelligence-Pipeline — https://www.axonius.com/blog/behind-actionability-the-axonius-asset-intelligence-pipeline
- NetBox (OSS DCIM/IPAM) — https://netboxlabs.com/blog/open-source-dcim-tools/
- Fingerbank — http://obilodeau.github.io/slides/defcon19-fingerbank/ · p0f v3 — https://lcamtuf.coredump.cx/p0f3/ · Satori — https://github.com/xnih/satori/wiki
- CVE_Prioritizer — https://github.com/TURROKS/CVE_Prioritizer · NVD-Scoring-Wandel — https://www.gblock.app/articles/nist-nvd-cve-enrichment-policy-change
- ML-OS-Fingerprinting — https://arxiv.org/pdf/2502.09084
