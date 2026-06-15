# Argus Roadmap

**North star:** a *deployable, multi-tenant SaaS* exposure-management platform.
Every goal below is judged against "can a hosted operator run this safely for
real tenants?" — not demo polish. Checkboxes are the live task list.

## Status (2026-06-15)

A working, persistent, CVE-correlating CAASM platform with a polished console:
P0 + P1 (discovery → correlation → risk) and the P3 SaaS foundation
(Argon2id + JWT + API keys, enforced multi-tenancy, RBAC, audit log) are done
and verified. Continuous monitoring (scheduled re-scans + change feed) and
**Console v2** (design system, real vulns/network/risk/policy/report pages) are
in. Vulnerability intelligence is live and CPE-grounded (NVD version-matched +
KEV + EPSS, cached). Risk scoring now carries a **match confidence** so a high
score backed only by version-blind matches is visibly less certain.

What is explicitly **not** done: this is a P1 analytical spine, not a finished
product. Scoring weights are an honest heuristic, not a calibrated model; the
offline catalog is a ~40-CVE baseline; the device classifier is heuristic
(no trained model); there is no passive sensing, no connectors, no billing, and
the central scanner reaches targets directly (no agent/relay model yet).

---

## Done

### P0 — Foundations ✅
- [x] Cargo workspace + `argus-core` domain model (tenants, assets, network, vuln, findings, risk)
- [x] `argus-api` (axum) + Postgres schema/persistence (sqlx, JSONB document store) + in-memory backend
- [x] `web/` Next.js console wired to the API
- [x] CI (GitHub Actions: fmt + clippy + test + web lint/build)

### P1 — Spine (demo-able, real) ✅
- [x] `argus-discovery` (light): payload-free TCP-connect scan + heuristic + range cap + CLI
- [x] `argus-discovery` (deep, no-root): nmap service/version fingerprints, MAC + OUI vendor (ARP), subnet sampling
- [x] `argus-discovery` (deep, root): masscan SYN sweep + `nmap -sS -O`, wired via `{"deep":true}`
- [x] `argus-vuln`: CVE correlation (catalog + version matching) → CVSS/EPSS/KEV → risk inputs
- [x] `argus-core::risk`: composite exposure score on every asset
- [x] `POST /api/scan` → discovery → dedup-upsert, Postgres-persisted

### P3 — SaaS foundation ✅
- [x] Auth: Argon2id passwords, HS256 JWT sessions, hashed API keys, two-axis login rate limit
- [x] Multi-tenancy enforced: tenant-scoped schema + every query; `tenant_id` only from the session, never client input
- [x] RBAC (`viewer`/`analyst`/`admin`) on every mutating route + per-tenant audit log
- [x] Console v2: design tokens + shared UI primitives, labeled sidebar, global search, a11y pass; all pages real (overview, assets, network, vulns, risk, policy, reports, settings)
- [x] `argus-policy`: advisory segmentation rules (`GET /api/policy`)
- [x] `argus-report`: exposure/posture reports, print-ready (`GET /api/report?days=1..90`)
- [x] IR workflow v1: per-(asset, CVE) finding triage + bulk triage
- [x] Continuous monitoring + change detection: scheduled re-scans, atomic claim, bounded concurrency, change-event feed (`GET /api/events`)

### P3 — Live intelligence ✅
- [x] CPE-grounded NVD matching: nmap CPEs per service, NVD queried by `vendor:product`, matched against published version constraints; KEV/EPSS overlays; process-wide TTL cache with rate-limit gate and disk snapshot

### Hardening pass (2026-06-15) ✅
- [x] **Match confidence**: every `Vulnerability` carries `match_confidence` (`confirmed` CPE+version → `high` catalog+version → `medium` CPE-only → `low` version-blind); `RiskScore` inherits the confidence of its highest-CVSS driver; surfaced per CVE and per asset in the console. Resolves the "honest confidence" gap by building it.
- [x] **CVSS extraction fix**: `extract_cvss` now takes the **max** base score across NVD metric entries (was an arbitrary first entry), so the risk engine is never silently under-scored.
- [x] **EPSS percentile fix**: real percentile parsed from FIRST.org and carried through; the catalog reports `percentile: None` instead of a wrong value.
- [x] **SSRF guard**: scan/monitor targets are restricted to public addresses (`is_disallowed_target` blocks RFC1918/loopback/link-local/CGNAT/metadata/IPv4-mapped); `ARGUS_SCAN_ALLOW_PRIVATE` opts in (auto-on for the dev store, off for Postgres).
- [x] **Signup default off**: `ARGUS_SIGNUP_ENABLED` defaults to `false` (was open).
- [x] **`is_internal` fix**: CGNAT (`100.64.0.0/10`) and IPv4-mapped IPv6 are correctly classified — stops false "internet-facing" exposure (which fed false-positive policy advisories).
- [x] **Honest "OT-safe" claim**: the payload-free connect scanner is safe; masscan's raw SYN sweep is explicitly labeled *not* OT-safe.
- [x] Docs (README/ROADMAP) aligned with the code: `argus-intel` is a heuristic classifier, not a trained one.

---

## Next — SaaS production-readiness (the north-star track)

Ordered by what blocks running this for real tenants. Each has a done-criterion.

- [ ] **Scan delivery model for hosted SaaS.** The central server must not scan
      networks directly for tenants (the SSRF guard is a stopgap, not an
      architecture). Introduce a tenant-deployed **agent/relay** that scans the
      tenant's own network and pushes results, or scope direct scans to
      operator-verified asset ownership.
      *Done when:* a tenant can inventory an internal network without the
      central API ever connecting to a private address.
- [ ] **Session cookies instead of `localStorage` JWT.** Move the bearer token
      to a `HttpOnly; Secure; SameSite` cookie with CSRF double-submit (the
      console and API are cross-origin, so this needs `SameSite=None` + an
      anti-CSRF token). *Done when:* no JWT is readable from JS and CSRF is
      covered by a test.
- [ ] **NVD enrichment concurrency.** The rate-limit gate currently serializes
      *all* product fetches process-wide (one slow product blocks every
      tenant). Replace the global `await`-held mutex with a per-product
      single-flight + a token-bucket limiter. *Done when:* a 4000-CVE product
      fetch does not stall other tenants' enrichment.
- [ ] **Horizontal scale.** Login rate limiter and the monitor scheduler are
      single-instance (in-memory limiter; atomic DB claim is replica-safe but
      the limiter is not). Back the limiter with Postgres/Redis. *Done when:*
      two API replicas share rate-limit and scheduler state.
- [ ] **Billing & plans** (`argus-api`): per-tenant plan, asset/seat limits
      enforced on ingest and user/key creation, usage metering. *Done when:* a
      tenant over its asset cap is rejected at ingest with a clear error.
- [ ] **Scheduled report delivery** (email/webhook) + per-framework compliance
      mappings on top of `argus-report`.

## Quality bar (cross-cutting, do alongside)

- [x] **Postgres integration tests.** Gated `argus-api` tests
      (`TEST_DATABASE_URL`, run by a CI Postgres service; self-skip locally so
      `cargo test` is green with no database) cover the `db.rs` path the memory
      backend cannot: FK-backed tenant scoping, the `commit_asset` transaction,
      the atomic monitor claim, and the bulk finding upsert.
- [ ] **Scan-pipeline e2e test**: drive `ingest()` (classify → enrich → score →
      diff → upsert → events) against real Postgres with a stub discovery
      result, so the full write path is covered, not just the store methods.
      Nothing spawns nmap/masscan yet either — a parser-level harness over
      canned tool output would close that.
- [ ] **Frontend data layer**: collapse the five near-identical polling hooks
      into one `usePolledResource<T>`; add `AbortController` + an in-flight
      sequence guard so slow polls can't show stale data; pause polling on
      hidden tabs; `aria-live` on the live regions.
- [ ] **Match confidence in the aggregation view**: surface per-CVE confidence
      on the Vulnerabilities page (`GET /api/vulns`), not just the asset drawer.
- [ ] **Scoring calibration**: the risk weights are an opinionated heuristic.
      Either keep them and label the score "heuristic" in the UI, or calibrate
      against a reference distribution. Do not call it a model until then.

## P2 — Intelligence (vision, not yet built)

- [ ] `argus-intel`: a *trained* device classifier (Fingerbank-style features) —
      today's classifier is heuristic rules and is labeled as such.
- [ ] `argus-sensor`: passive sensing (p0f/Zeek-style signatures)
- [ ] `argus-connectors`: cloud/AD/NetBox adapters (also the real source of
      VLAN/switch telemetry that would replace the policy engine's `/24` zone
      approximation)
- [ ] `argus-behavior`: per-deployment anomaly baselines
