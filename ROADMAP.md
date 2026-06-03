# Argus Roadmap

Tracking the phased build from the design spec. Checkboxes are the live task list.

**Status (2026-06-04):** P0 + P1 complete and verified — a working, persistent,
CVE-correlating CAASM / exposure-management platform with a polished console.
P2 / P3 (the deeper intelligence + enterprise/SaaS vision) is the remaining,
multi-week work.

## P0 — Foundations ✅
- [x] Repo + design spec
- [x] Prior-art research folded into spec
- [x] Cargo workspace + `argus-core` domain model (tenants, assets, network, vuln, findings, risk)
- [x] `argus-api` (axum: `/health`, `/api/assets`, `/api/assets/{id}`, `/api/summary`, `/api/scan`)
- [x] `web/` Next.js console: dark design system + dashboard wired to the API
- [x] Postgres schema + persistence (sqlx, JSONB document store)
- [ ] CI (GitHub Actions: fmt + clippy + test)

## P1 — Spine (demo-able, real) ✅
- [x] `argus-discovery` (light): safe TCP-connect host/service scan + heuristic + range cap + CLI
- [x] `argus-discovery` (deep, no-root): nmap service/version fingerprints, MAC + OUI vendor (ARP), subnet sampling
- [x] inventory + `POST /api/scan` → discovery → dedup-upsert, Postgres-persisted
- [x] `argus-vuln`: CVE correlation (catalog + version matching) → CVSS / EPSS / KEV → risk inputs
- [x] `argus-risk`: composite exposure score on every asset (seed + discovered)
- [x] web: metrics, risk distribution, SVG asset map, device-detail drawer with CVEs, Run-scan wiring, table CVE indicators
- [ ] `argus-discovery` (deep, root): masscan high-speed + `nmap -O` OS detection (needs sudo)

## P2 — Intelligence (remaining vision)
- [ ] `argus-sensor`: passive sensing (p0f/Zeek-style signatures)
- [ ] `argus-intel`: trained device classifier (Fingerbank features)
- [ ] `argus-connectors`: cloud/AD/NetBox adapters (Axonius adapter pattern)
- [ ] continuous monitoring + change detection
- [ ] `argus-behavior`: per-deployment anomaly baselines

## P3 — Enterprise / SaaS (remaining vision)
- [ ] `argus-policy`: advisory segmentation
- [ ] `argus-report`: compliance / exec reports
- [ ] IR workflows, multi-tenancy hardening, billing fields
- [ ] `argus-vuln` live NVD + EPSS + CISA-KEV feed (replace the seed catalog)
- [ ] animation polish + performance pass
