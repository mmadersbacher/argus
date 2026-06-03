# Argus Roadmap

Tracking the phased build from the design spec. Checkboxes are the live task list.

## P0 — Foundations
- [x] Repo + design spec
- [x] Prior-art research folded into spec
- [x] Cargo workspace + `argus-core` domain model (tenants, assets, network, vuln, findings, risk)
- [x] `argus-api` skeleton (axum: `/health`, `/api/assets`, `/api/assets/{id}`, `/api/summary`)
- [x] `web/` Next.js console: dark design system + dashboard (metrics, risk distribution, asset table) wired to the API
- [ ] Postgres schema + sqlx migrations
- [ ] CI (GitHub Actions: fmt + clippy + test)

## P1 — Spine (demo-able, real)
- [x] `argus-discovery` (light): safe TCP-connect host/service scan + port→device heuristic + range cap + CLI
- [x] inventory + `POST /api/scan` → discovery → dedup-merge into the live inventory (in-memory)
- [x] `argus-risk`: composite exposure score on every asset (seed + discovered)
- [x] web: dashboard (metrics, risk distribution), asset map (SVG graph), device-detail drawer, Run-scan wiring
- [ ] `argus-discovery` (deep): nmap/masscan, subnet sampling, banner & OS fingerprinting, MAC-OUI vendor
- [ ] `argus-vuln`: CPE match against NVD + EPSS + CISA KEV (replaces the placeholder risk signal)
- [ ] Postgres persistence (sqlx) replacing the in-memory inventory

## P2 — Intelligence
- [ ] `argus-sensor`: passive sensing (p0f/Zeek-style signatures)
- [ ] `argus-intel`: trained device classifier (Fingerbank features)
- [ ] `argus-connectors`: cloud/AD/NetBox adapters (Axonius adapter pattern)
- [ ] continuous monitoring + change detection
- [ ] `argus-behavior`: per-deployment anomaly baselines

## P3 — Enterprise / SaaS
- [ ] `argus-policy`: advisory segmentation
- [ ] `argus-report`: compliance / exec reports
- [ ] IR workflows, multi-tenancy hardening, billing fields
- [ ] animation polish + performance pass
