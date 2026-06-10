# Argus Roadmap

Tracking the phased build from the design spec. Checkboxes are the live task list.

**Status (2026-06-10):** P0 + P1 complete and verified — a working, persistent,
CVE-correlating CAASM / exposure-management platform with a polished console —
plus the SaaS foundation from P3: authentication (Argon2 + JWT + API keys),
enforced multi-tenancy (tenant-scoped schema + queries), RBAC, audit log,
login/signup console flow and hardened CORS. The remaining P2 / P3 work
(passive sensing, trained classifier, connectors, policy/reporting, billing)
is multi-week.

## P0 — Foundations ✅
- [x] Repo + design spec
- [x] Prior-art research folded into spec
- [x] Cargo workspace + `argus-core` domain model (tenants, assets, network, vuln, findings, risk)
- [x] `argus-api` (axum: `/health`, `/api/assets`, `/api/assets/{id}`, `/api/summary`, `/api/scan`)
- [x] `web/` Next.js console: dark design system + dashboard wired to the API
- [x] Postgres schema + persistence (sqlx, JSONB document store)
- [x] CI (GitHub Actions: fmt + clippy + test + web lint/build)

## P1 — Spine (demo-able, real) ✅
- [x] `argus-discovery` (light): safe TCP-connect host/service scan + heuristic + range cap + CLI
- [x] `argus-discovery` (deep, no-root): nmap service/version fingerprints, MAC + OUI vendor (ARP), subnet sampling
- [x] inventory + `POST /api/scan` → discovery → dedup-upsert, Postgres-persisted
- [x] `argus-vuln`: CVE correlation (catalog + version matching) → CVSS / EPSS / KEV → risk inputs
- [x] `argus-risk`: composite exposure score on every asset (seed + discovered)
- [x] web: metrics, risk distribution, SVG asset map, device-detail drawer with CVEs, Run-scan wiring, table CVE indicators
- [x] `argus-discovery` (deep, root): masscan high-speed sweep + `nmap -sS -O` OS detection, wired into `POST /api/scan` via `{"deep":true}` (needs root)

## P2 — Intelligence (remaining vision)
- [ ] `argus-sensor`: passive sensing (p0f/Zeek-style signatures)
- [ ] `argus-intel`: trained device classifier (Fingerbank features)
- [ ] `argus-connectors`: cloud/AD/NetBox adapters (Axonius adapter pattern)
- [ ] continuous monitoring + change detection
- [ ] `argus-behavior`: per-deployment anomaly baselines

## P3 — Enterprise / SaaS
- [x] Authentication: Argon2id passwords, HS256 JWT sessions, hashed API keys, login rate limit
- [x] Multi-tenancy enforced: sqlx migrations, tenant-scoped assets/users/keys, self-service tenant signup
- [x] RBAC (`viewer`/`analyst`/`admin`) on every route + per-tenant audit log
- [x] Console: login/signup page, session handling, user & API-key management (Settings)
- [ ] `argus-policy`: advisory segmentation
- [ ] `argus-report`: compliance / exec reports
- [ ] IR workflows, billing fields
- [ ] `argus-vuln` live NVD + EPSS + CISA-KEV feed (replace the seed catalog)
- [ ] animation polish + performance pass
