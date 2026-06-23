# Argus School Edition — Design Spec

> Status: **DESIGN / brainstorming output** — 2026-06-23. Pivot von der generischen
> CAASM-Plattform zu einer schul-spezifischen, self-hosted Single-Tenant-Appliance.
> Diplomarbeit-Liefergegenstand. Quelle: adversarialer Code-Review (2026-06-23) +
> 8-Domänen-Technologie-Sweep (2026-06-23).

---

## 0. Entscheidungen (festgehalten)

| Thema | Entscheidung |
|---|---|
| Deployment | **Self-hosted Single-Tenant-Appliance** im Schul-LAN. Daten verlassen die Appliance nie (DSGVO-by-design). |
| Edition-Modell | **Ein Codebase, zwei Editionen.** Die Multi-Tenant-SaaS wird als *General Edition* getaggt & geparkt. Die *School Edition* läuft denselben Code im Appliance-Modus. |
| Lizenz | **PolyForm Strict 1.0.0** (source-available, jede Nutzung außer Anschauen vorbehalten). Relicense von Apache-2.0. Schule erhält separaten Nutzungs-Grant. Thesis-IP schriftlich klären. |
| Zielschule | BHAK/BHAS Schwaz (AT Bundesschule, Oberstufe BHS). |
| Nicht-Ziel | **Kein SIEM, kein Log-Aggregation.** Argus bleibt CAASM/Exposure-Management. |

## 1. Vision & drei Thesis-Ziele

Eine Appliance, die ein überlasteter Schuladmin in unter einer Stunde aufstellt, die das
Netz **OT-sicher** inventarisiert, Schwachstellen **konfidenzbewusst** korreliert und eine
**priorisierte, umsetzbare "Top-N diese Woche"-Liste** liefert.

Die Arbeit misst sich an drei Zielen:

1. **Die Schule wird messbar sicherer** — vorher/nachher-Risikoreduktion am (simulierten, später realen) Netz.
2. **Mindestens eine echte, demonstrierbare Schwachstelle** wird gefunden — version-bestätigt, KEV-gestützt, reproduzierbar.
3. **Verteidigbare empirische Evaluation** — FF1/FF2 an echten/realistischen Daten, *nicht* zirkulär.

## 2. Scope (in / out)

**IN scope (Appliance scannt das interne LAN):**
- Netz-Infrastruktur: Switches, Wi-Fi-Controller (UniFi/Lancom), interne Firewall-/UTM-Mgmt-Plane, DHCP/DNS.
- Endpoints: Windows-Lab-PCs (Image-Klone), Lehrer-Laptops, BYOD (nur Inventar), Thin Clients.
- Klassenraum: interaktive Panels (Promethean/SMART/ViewSonic, embedded Android), Beamer (PJLink), Klassenraum-Management (Veyon/NetSupport).
- Server/Identity: Windows Server + Active Directory (DC = Tier-0), SMB-Fileserver, NAS (Synology/QNAP), Virtualisierung (ESXi/Proxmox/Hyper-V), Backup (Veeam).
- Drucker/MFP, VoIP/PBX (3CX/Asterisk/Auerswald), IoT.
- OT/Gebäude: IP-Kameras/NVR, BACnet-GLT, KNXnet/IP, Zutrittskontrolle, PV-Wechselrichter (Fronius/SMA).
- Self-hosted Edu-Web: Moodle, on-prem WordPress, Bibliothek (Littera/Koha), on-prem WebUntis-Host (Minderheit).

**OUT of scope (explizit benennen, nicht überdehnen):**
- **WebUntis (SaaS, Untis-gehostet)** und **Sokrates (BRZ/Bund-gehostet)** — kein LAN-Service. Nur als Scope-Grenze nennen. Argus "auditiert WebUntis/Sokrates" = Severity-/Scope-Inflation, verboten.
- **M365 / Google Workspace EDU** — Cloud-SaaS, keine LAN-Fläche.
- Externe Angriffsfläche (öffentliche Website, gehostetes Mail, SSL-VPN-Portal von außen) — **nur** über den optionalen *External-View*-Modus (Stretch, §5).

## 3. Architektur

- Rust-Workspace + Next.js-Konsole bleiben. School Edition = Deployment/Config-Divergenz, kein Rewrite: ein Tenant geseedet, Signup aus, `ARGUS_SCAN_ALLOW_PRIVATE=true`, paketiert als Docker-Compose-/VM-Image.
- Single-Tenant eliminiert die ungelösten Multi-Tenant-Probleme aus dem Review (Cross-Tenant-SSRF, Cluster-Rate-Limiter existieren nicht mehr).
- Appliance-NIC am Trunk/SPAN bzw. router-on-a-stick, damit der Scan-Vantage dem realen Deployment entspricht.

## 4. DIE zentrale Erkenntnis: `InternetFacing` → `Internal-Reachability`

**Befund (von zwei Agenten unabhängig):** 4 der 8 `argus-policy`-Regeln (`kev_internet`,
`mgmt_exposed`, `ics_internet`, `iot_internet`) gaten auf `Exposure::InternetFacing`. Eine
self-hosted Appliance sieht ein **flaches internes LAN** — vom ihrem Vantage ist praktisch
*nichts* internet-facing. **Heißt: im vorgesehenen Deployment feuert die halbe Advisory-Engine
fast nie.**

**Konsequenz — der wichtigste Umbau der School Edition:** Ein **Internal-Reachability-Modell**.
"Exponiert" wird umdefiniert als *"erreichbar aus dem allgemeinen Schüler-/User-VLAN"* statt
"internet-facing". Varianten von `mgmt_exposed` und `ics_reachable`, die auf `Exposure::Internal`
innerhalb der dominanten flachen Zone feuern. Ohne diesen Umbau produziert die Appliance kaum Findings.

## 5. Capability-Deltas — Spine (Pflicht) vs. Stretch

### SPINE (Pflicht — liefert alle drei Thesis-Ziele, defensible)

**Probes**
- `SMB2 NEGOTIATE` (payload-free): negotiated dialect (→ SMBv1-enabled), `SMB signing required` flag (→ NTLM-Relay-Precondition), OS-/Build-String (→ EOL-Erkennung). Mirror des bestehenden `smb_v1: Option<bool>`-Musters. **Höchster Hebel, niedrigster Aufwand.**
- Kamera-HTTP-Fingerprint: Hikvision `/ISAPI/System/deviceInfo`, Dahua `/cgi-bin/magicBox.cgi?action=getSystemInfo` → exaktes Modell + Firmware → version-confirmed CVE (CVE-2021-36260 KEV, CVE-2017-7921).
- HTTP-CMS-Version-Extraktion: `<meta generator>`, `/readme.html`, Asset-`?ver=`, Nextcloud `/status.php`, Moodle Footer/`upgrade.txt`. Ohne Versionsextraktion ist die ganze Web-CVE-Story hohl.
- **Opt-in Default-Credential-Modul** (Kameras, Drucker, NAS, UniFi): kuratierte Tabelle ≤2 Werkspaaren pro Produkt, *einmal* getestet, hart rate-capped, consent-gated, audit-logged. **Der einzige Schritt der TYPICAL→PROVEN hebt** — und das einzige echte OT-/Ethik-Risiko. Default AUS.

**Taxonomy** (Klassen, die die Konsole heute nicht hat)
- AD-Domain-Controller (Tier-0 "crown jewel"), IP-Camera/NVR, interactive-whiteboard/projector, classroom-management-host, NAS, KNX-Router, BACnet-Controller, access-controller, education-app (+ Datensensitivität "Schülerdaten").

**Catalog** (das "Gehirn" ist bereit, die schul-prävalenten Familien fehlen)
- Sophos XG/SFOS, MikroTik RouterOS, Synology DSM, QNAP QTS, Moodle, VMware ESXi (build-level statt nur vCenter-`Any`), UniFi, ≥1 Drucker-CVE (Kyocera/Canon/Ricoh), Kamera (CVE-2021-36260/2017-7921), VoIP/PBX (Auerswald CVE-2021-40859, 3CX, Asterisk), Samsung MagicINFO (CVE-2024-7399), Veeam (CVE-2024-40711 KEV), Samba Zerologon (CVE-2020-1472).

**Advisory**
- **Internal-Flat-LAN-Reachability-Regeln** (§4) — das wichtigste Delta.
- EOL-OS-Regel: Windows-Build → EOL-Datum (Win10 22H2 EOL 2025-10-14 ohne ESU, Win7/8.1, Server 2008/2012). Deterministisch, near-zero-FP.
- Cleartext-Mgmt-Regel (Telnet/FTP/HTTP-only auf Infra-Gerät).
- DC/Tier-0-aware Eskalation (RDP/SMB-signing-off auf einem DC schlägt dasselbe auf einer Workstation).
- Default-Cred-Klasse-Advisory (auch ohne aktiven Check: "Gerät mit notorisch-Default-Admin — Credentials prüfen").

**Report**
- "Fix these N things this week" — rangierte, plain-deutsche Aktionsliste mit konkreter Remediation + Aufwandsschätzung. **Die Antwort auf "Admins haben wenig Zeit".**
- DSGVO-by-design-Attestation ("Daten haben die Appliance nie verlassen; diese Findings nutzten Offline-Katalog vs. Live-NVD").

**Must-Fixes aus dem Code-Review** (Glaubwürdigkeit am echten Netz)
- `AtMost`-Over-Match (`catalog.rs:439/449`) → falsche High-Confidence-Criticals. **Tödlich, zuerst.**
- Dedup-Demotion (bestätigte High von früher-gesehener Low verdrängt) → dedup by `max(confidence)`.
- IIS-Banner-Recall-Loch (`extract_version` matcht `Microsoft-IIS/10.0` nie).
- Audit-Log Read-Pfad (eine Schule *will* den Trail sehen).
- Katalog-Erweiterung (74 CVEs → zu wenig fürs echte Netz).

**Bestätigte Spine-Erweiterungen (2026-06-23, Entscheidung gefroren):**
- **LLDP passive listener** — *höchster Honesty-Hebel*: wandelt die /24=Zone-Heuristik in echte VLAN-Topologie (löst das Überklaim-Problem der flat-network-Advisory + verbessert Switch-Fingerprint/CVE). Raw-socket-Capture (knüpft an den `argus-sensor`-Capture-Layer). → Phase S2.
- **External-View-Modus + DNS-Recon** (SPF/DMARC/CT-Subdomains) — der *einzige* Weg zur kritischen Severity (Sophos/FortiOS SSL-VPN KEV) + WordPress am Public-Host. Opt-in, scope-locked auf eigene IPs, dokumentiert autorisiert. → Phase S2/S3.

### STRETCH (markiert "nur wenn Zeit"; empfohlene Reihenfolge)

1. **KNXnet/IP-Probe** (UDP/3671 SEARCH/DESCRIPTION_REQUEST, detection-only) — kompletter Blind Spot, AT/DE-prävalent, sauberer safer Befund.
2. **Veyon-Probe** (TCP 11100) — schul-spezifisch, unter-erforscht → akademische Novelty.
3. **VNC/RFB security-type** (`None` = PROVEN unauth control), **RDP-NLA-Check**, **anon-LDAP-subtree → AS-REP-Chain**, **SIP/PBX-Fingerprint**, **PJL-FS-read**.

## 6. Hunting-Hitlist (rangiert: wo die echte Lücke realistisch sitzt)

| # | Befund | Evidenz | Häufigkeit | Anmerkung |
|---|---|---|---|---|
| 1 | IP-Kamera: Hikvision CVE-2021-36260 (KEV) / Default `admin/12345` | **proven** | sehr häufig | Eine echte ~60 € EOL-Kamera = unangreifbares Fallstudien-Artefakt. |
| 2 | SMB-signing-not-required + SMBv1/EOL-Windows | **proven** | near-universal | SMB2-Negotiate-Probe liefert es sauber unauth. |
| 3 | Drucker Default-Cred → scan-to-SMB Domain-Cred | typical→proven | sehr häufig | "proven" erst mit Default-Cred-Modul. |
| 4 | Self-hosted WordPress/Moodle stale → version→CVE | **proven** | häufig | Klassiker; PoC-bar im Lab. |
| 5 | EOL Windows 10 (nach Okt-2025) | **proven** (deterministisch) | sehr häufig | Garantierter Befund, auch ohne Exploit. |
| 6 | Perimeter Sophos/FortiOS SSL-VPN KEV | typical (version-confirmed) | häufig | Höchste Severity; braucht External-View. Exploit NICHT ausführen. |

**Garantie gegen "wir fanden nie einen echten Bug":** das Sim-Net (§7) enthält
vsftpd 2.3.4 / ProFTPD mod_copy / Apache 2.4.49 (CVE-2021-41773 KEV) — **bereits im Katalog**
→ garantierte version-confirmed Treffer.

## 7. Honesty-/Triage-Framework (entscheidet die Note)

Jeder Befund wird klassifiziert: **PROVEN** (HTTP-Request/Response oder Protokoll-Handshake
zeigt es) / **TYPICAL** (logisch plausibel, nicht demonstriert) / **THEORETICAL** (möglich, kein PoC).

- PROVEN-Klasse: SMB-signing, EOL-OS, Kamera-Version→KEV, CMS-Version→CVE, SNMP `public`, VNC-`None`, BACnet-I-Am-Reachability, Telnet-cleartext.
- TYPICAL/INFERRED (NICHT als proven verkaufen): EternalBlue (braucht aktiven MS17-010-Check → bricht OT-safe), Default-Creds *ohne* Check, flat-L2 (Single-Vantage-Inferenz), Local-Admin-Reuse (unauth unbeweisbar), AS-REP (Chain, braucht anon-LDAP).
- BACnet/Modbus/KNX = **Segmentierungs-/Reachability-Befunde** (Config), keine exploiteten Vulns. Appliance schreibt NIE auf OT (nur Who-Is/OPTIONS/SEARCH/ReadProperty).

## 8. Sim-Net Blueprint (master)

Ein reproduzierbares Lab auf einem Host (Proxmox VE empfohlen; nested ESXi / Docker+QEMU auf 32 GB).
Argus-Appliance als VM, NIC am Trunk.

**Topologie** (router-on-a-stick auf pfSense/OPNsense-VM, 802.1q):
- VLAN 10 Server `10.10.10.0/24` (DC, File/Print, Hypervisor, NAS, Web-Apps)
- VLAN 20 Staff `10.10.20.0/24` (Lehrer-Win11, MFP)
- VLAN 30 Student `10.10.30.0/24` (EOL-Win10-Klone, Veyon — bewusst flach/überbreit)
- VLAN 40 IoT/OT `10.10.40.0/24` (IP-Kamera, BACnet/Modbus, Smart-TV) — *bewusst aus Student routbar* → `ot_mixed_zone`/`ics_reachable`
- VLAN 99 Mgmt `10.10.99.0/24` (Firewall-/Switch-Mgmt, UniFi)
- **Bewusste Mis-Segmentierung:** kein Inter-VLAN-Deny Student↔IoT/OT und Student↔Server für einige Ports → Segmentierungs-Advisories haben echte Evidenz.

**Boxen (frei/community):**
1. Windows Server 2019 → DC (DNS/Kerberos/LDAP/SMB; signing off, anon-LDAP, ein DONT_REQ_PREAUTH-User).
2. EOL Win10 21H2 (nicht gepatcht, SMBv1 an) ×2-3 Klone → EternalBlue/SMBGhost + EOL + Clone-Fleet.
3. Win11 Lehrer-Client (domain-joined) → **sauberer Negativ-Asset** für Präzisionsmessung.
4. **Metasploitable3 (Win+Linux) / Vulhub** → vsftpd 2.3.4, ProFTPD mod_copy, Tomcat, Struts, Drupal, phpMyAdmin (Katalog-Treffer = garantierte FF1-True-Positives + demonstrierbare RCE).
5. Self-hosted WordPress (alt + vuln Plugin) → Katalog-WP-CVE.
6. **Self-hosted Moodle (aktuell) → OUT-OF-CATALOG-Holdout** (Argus darf NICHT flaggen → FF1 nicht-trivial).
7. Synology/QNAP (Xpenology-VM/Image) → NAS-Klasse + world-readable Share.
8. Drucker-Emulator (PJL-9100 + IPP-631 + SNMP `public`) mit Default-Web-Admin der eine "scan-to-SMB"-Cred hält → die ganze Drucker-Narrative self-contained.
9. IP-Kamera-Emulator (MediaMTX RTSP + Hikvision-Banner-Honeypot, vuln-Firmware-String) + optional **eine echte Billig-Kamera**.
10. BACnet-Sim (`bacserv`/bacpypes, 47808) + Modbus (`pymodbus`/conpot, 502).
11. Firewall-Target: 2. OPNsense / alte FortiGate-VM (CVE-2022-40684) oder Fingerprint-Mimic.
12. Linux-Server: alte OpenSSH + Apache 2.4.49 (CVE-2021-41773 KEV) → garantierte Katalog-Treffer.
13. Veyon auf den Win10-Klonen (11100).
14. UniFi-Controller (Docker) auf Mgmt-VLAN.

**Ground-Truth-CSV:** `(asset, ip, true device_type, exposure, criticality, expected CVEs/applies=yes|no)`
— inkl. Negativ-/Holdout-Assets. Jede VM Snapshot → byte-genau reproduzierbar für die Verteidigung.

## 9. Evaluation-Design (Fix der Thesis-Kernschwäche)

- **FF1 entzirkularisiert:** Ground-Truth aus dem Lab + **Out-of-Catalog-Holdout** (Moodle, UniFi, Drucker), den Argus NICHT flaggen darf. Misst, dass das Confidence-Modell auf *ungesehenen* Produkten nicht halluziniert. Präzision pro Tier (confirmed ~1.0, untere degradieren graceful). Zusätzlich Classifier-Confusion-Matrix aus den device_type-Labels.
- **FF2 echt:** `ff2.rs:61`-Fix — exposure/criticality **variieren** (flat Student-VLAN vs. segmentierter Server-VLAN; DC=critical vs. Kamera=low) statt pinnen. **EPSS-only-Baseline** zusätzlich zu CVSS-only. Datensatz aus dem realen Lab-Finding-Set (gemischte CVSS/EPSS/KEV) committen → reproduzierbar.
- **FF3 (Actionability, neu):** Liefert die "Top-N diese Woche"-Liste die 2-3 garantierten echten Befunde im Top-N? Vorher/nachher-Risikoreduktion (Fix anwenden → Re-Scan → Score-Drop) = das empirische Rückgrat für Ziel #1.
- **Ehrlicher Caveat im Text:** Eval *auf* dem Lab ist teils zirkulär; mitigiert durch Holdout + Aussage "Katalog-Coverage, nicht Detektionslogik, ist der limitierende Faktor".
- **Optionale Forschungs-Erweiterung (NICHT Spine, NICHT Pflicht):** FF2-Gewichte `[CVSS, EPSS, KEV, exposure, criticality] → Priorität` per **logistischer Regression mit KEV als Label** auf dem realen NVD+EPSS+KEV-Korpus *lernen* statt hand-gewichten — adressiert die "unkalibrierte Magic-Numbers"-Kritik mit echten Labels, leichtgewichtig (`linfa` oder offline-Notebook, gelernte Gewichte committen). **Explizit verworfen:** ML-Geräteklassifikation (keine Daten, Sim-Net-Zirkularität, Erklärbarkeitsverlust) und Anomalie-ML (keine Baseline-Daten). Begründung: EPSS *ist* bereits ein ML-Modell, das Argus konsumiert — ein eigenes Exploitation-Vorhersagemodell wäre EPSS mit weniger Daten neu erfunden.

## 10. Roadmap (phasen, Done-Kriterien)

| Phase | Inhalt | Done wenn |
|---|---|---|
| **S0** | Edition-Split (Branch/Tag `general`) + Relicense PolyForm Strict + Appliance-Packaging | `docker compose up` → fertige Single-Tenant-Schul-Appliance |
| **S1** | Must-Fixes (AtMost/dedup/IIS/audit-read) + Internal-Reachability-Policy + SMB2-Negotiate-Probe + EOL-OS-Regel | Lab-Scan: 0 bekannte False-Criticals, interne Reachability-Advisories feuern |
| **S2** | Schul-Taxonomie + Katalog-Erweiterung + Kamera-/CMS-Fingerprint + **LLDP-Listener** + **External-View+DNS** | Schul-Gerätetypen korrekt klassifiziert, schul-prävalente CVEs korrelieren, VLAN-Topologie aus LLDP statt /24-Heuristik, External-View liefert Public-Surface |
| **S3** | Opt-in Default-Cred-Modul + "Top-N diese Woche"-Report + DSGVO-Attestation | Admin-Liste rangiert + umsetzbar; Default-Cred-Befund PROVEN im Lab |
| **S4** | **Sim-Net aufbauen** (§8) + Ground-Truth-Labeling | Lab reproduzierbar, ≥1 garantierter version-confirmed Critical findbar |
| **S5** | FF1/FF2/FF3-Eval am Lab (+ optional Real-Deployment BHAK Schwaz) | Reproduzierbare Ergebnisse + Fallstudie geschrieben |
| **S6** *(stretch)* | KNX / Veyon / VNC / RDP-NLA / anon-LDAP→AS-REP / SIP — in dieser Reihenfolge | nur wenn Zeit |

## 11. Risiken & harte Voraussetzungen (HARD REALISM)

- **⚠️ Autorisierung:** *Schriftliche* Freigabe (Direktor **+** DSB) VOR jedem Scan des **realen** Netzes. Auch an der eigenen Schule. Bundesschul-Netz ohne Freigabe scannen = Rechtsproblem. **Längste Leitung — Prozess sofort/parallel starten.** Das Sim-Net entkoppelt die Eval davon: die Note hängt nicht am realen Deployment.
- **DSGVO:** Daten bleiben auf der Appliance; als Architektur-Eigenschaft dokumentieren. Default-Cred-Modul & Live-NVD-Lookups explizit ausweisen.
- **Default-Cred-Ethik/OT-Safety:** opt-in, rate-capped, read-after-login-only, audit-logged. Der einzige Modus mit echtem Risiko.
- **Deadline/kritischer Pfad:** S4+S5 (Lab + Eval) tragen die Note. Sim-Net entkoppelt von Drittpersonen-Terminen.
- **Scope-Disziplin:** Nicht in den Feature-Sumpf laufen. Spine zuerst vollständig, Stretch nur dann. "Zoom-out" wahren: jedes Delta dient einem der drei Ziele, sonst raus (YAGNI).
