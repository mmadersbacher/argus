# Argus Roadmap

## Vision (vollendeter Endzustand)

Eine Open-Source-CAASM-/Exposure-Management-Plattform, die jedes Gerät in einem
Netz **kontinuierlich entdeckt** (aktiv OT-sicher + passiv + Connectors),
**identifiziert** (heuristisch, später trainiertes Modell auf offenen
Fingerprint-Daten), seine Schwachstellen **konfidenzbewusst korreliert**
(NVD/KEV/EPSS) und **kontextbewusst priorisiert**, und **kontinuierlich
überwacht** (Re-Scan, Change-Detection, advisory Policy, Reports) — betreibbar
als sicheres Multi-Tenant-SaaS oder self-hosted, mit einem **Agent/Relay-Modell**
statt zentralem Scannen. Architektonisch an Armis/runZero orientiert, aber
vollständig auf offenen Daten — ehrlich über die eine nicht-replizierbare Grenze
(Cross-Customer-Intelligence; siehe Spec §2/§9).

**North star (operativ):** *deployable, multi-tenant SaaS* — jedes Ziel unten
misst sich an „kann ein Betreiber das sicher für echte Mandanten betreiben?",
nicht an Demo-Politur. Checkboxes sind die Live-Task-Liste.

> **Wichtig — Produkt-Vision ≠ Diplomarbeits-Scope.** Die Arbeit liefert den
> **P1-Spine** (Discovery → Korrelation → Priorisierung → Konsole) + die
> SaaS-Foundation + die **Evaluation zweier Forschungsfragen** (konfidenzbasierte
> CVE-Korrelation; kontextbewusste Priorisierung). Passive Sensing, trainiertes
> ML, Connectors, Agent/Relay und Billing sind **Produkt-Ausblick**, kein
> Liefergegenstand der Arbeit.

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
offline catalog is a ~75-CVE baseline; the device classifier is heuristic
(no trained model); passive-sensing **analysis** exists (`argus-sensor`) but
live packet capture is not yet wired; there are no connectors, no billing, and
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
- [x] **Session cookies instead of `localStorage` JWT.** The JWT now lives only
      in an `HttpOnly` session cookie — never in `localStorage` and never in a
      response body — so it is unreadable from JS. State-changing requests are
      guarded by a **double-submit CSRF** token (JS-readable CSRF cookie echoed
      in `x-csrf-token`), enforced for cookie auth only; Bearer/API-key clients
      are unaffected and keep working. The console sends `credentials: include`
      and the CSRF header; `/api/auth/logout` clears the cookies; CORS allows
      credentials. Cookie `Secure`/`SameSite` are env-configurable (cross-site
      HTTPS by default; `ARGUS_COOKIE_SECURE=false` + `ARGUS_COOKIE_SAMESITE=Lax`
      for localhost dev). CSRF is covered by a router-level integration test.
      *Verified over real HTTP* (running server + curl): the cookies are set
      with the right attributes (session `HttpOnly`, CSRF readable), cookie auth
      + double-submit are enforced (403 without/with-wrong header, pass with the
      matching one), logout clears both, and the body carries no token. Not yet
      exercised in a real browser — the topology-dependent step is whether the
      browser *sends* the cookie for the deployment's origin/HTTPS settings (a
      genuinely cross-domain console/API would need the CSRF token in the body
      or a shared cookie `Domain`, since JS can't read a cross-domain cookie).
- [x] **NVD enrichment concurrency.** The old global gate was held for a
      product's whole paginated fetch, so one slow/large product blocked every
      tenant. Replaced with a per-`vendor:product` single-flight (`OnceCell`)
      plus a reservation-based rate gate whose lock is held only for the slot
      arithmetic, never across the fetch — different products fetch
      concurrently while the aggregate request rate stays within NVD's limit.
      A 4000-CVE product fetch now delays others by at most one spacing
      interval, not its whole multi-page duration.
- [x] **Horizontal scale.** The login rate limiter is now Postgres-backed when
      the store is Postgres (`RateLimiter::Postgres` records each attempt in a
      shared `login_attempts` table and counts within the sliding window), so
      the cap holds cluster-wide instead of per-replica; the in-memory limiter
      stays for the dev store. The monitor scheduler was already replica-safe
      (atomic DB claim), so both now share state through Postgres. A periodic
      prune reclaims rows from keys that go quiet. Verified end-to-end against a
      real database: a gated SQL test plus an HTTP run where the 6th login for
      one `(ip,email)` returns 429 and the shared rows reflect the cap. *Caveat:*
      exercised with one API process against shared Postgres, not two literal
      replicas — but the shared state is the table itself, so replicas share it
      by construction. (A Redis option could lower per-attempt latency later.)
- [ ] **Billing & plans** (`argus-api`): per-tenant plan, asset/seat limits
      enforced on ingest and user/key creation, usage metering. *Done when:* a
      tenant over its asset cap is rejected at ingest with a clear error.
- [~] **Scheduled report delivery** (email/webhook). Outbound **webhook**
      delivery of change events is done: per-tenant config (`/api/webhook`,
      admin-only), an HMAC-SHA256-signed JSON payload (`x-argus-signature`,
      keyed on the secret string), and an SSRF-guarded sender that resolves and
      rejects any private/internal address (reusing the scan guard), **pins** the
      connection to a validated IP (no DNS rebinding) and disables redirects;
      `ARGUS_SCAN_ALLOW_PRIVATE` opts self-hosted deployments out. Fired
      fire-and-forget from `ingest`, so webhook trouble never delays or fails a
      scan. Verified end-to-end (real-HTTP delivery + valid HMAC + live SSRF
      rejection of loopback/metadata) and on real Postgres. Still open: email
      delivery, periodic *report* (vs. change-event) delivery, and per-framework
      compliance mappings on top of `argus-report`.

## Quality bar (cross-cutting, do alongside)

- [x] **Postgres integration tests.** Gated `argus-api` tests
      (`TEST_DATABASE_URL`, run by a CI Postgres service; self-skip locally so
      `cargo test` is green with no database) cover the `db.rs` path the memory
      backend cannot: FK-backed tenant scoping, the `commit_asset` transaction,
      the atomic monitor claim, and the bulk finding upsert.
- [x] **Scan-pipeline e2e test**: `ingest()` is driven end-to-end against both
      the in-memory store (`ingest_persists_classifies_and_is_idempotent`, runs
      on every `cargo test`) and real Postgres
      (`pg_ingest_drives_the_full_write_path_and_is_idempotent`, gated on
      `TEST_DATABASE_URL`, verified against postgres:18) — classify → enrich →
      score → diff → `commit_asset` (the transaction) → events, plus an
      idempotent re-scan (zero events) and change-on-mutation. Both are hermetic
      (stub services carry no product/CPE, so enrichment short-circuits with no
      network). The remaining nicety is a parser-level harness wiring canned
      nmap/masscan output through to scoring — the parsers themselves already
      have unit tests over their `SAMPLE` fixtures.
- [x] **Frontend data layer**: the five polling hooks are unified behind one
      `usePolledResource<T>` with an in-flight sequence guard, pause-when-hidden
      (refetch on re-show), and `AbortController` cancellation of superseded
      polls. `aria-live` is done the right way: a shared `<LiveRegion>` renders a
      concise sr-only `role="status"` summary per polled page (Overview,
      Vulnerabilities, Risk, Segmentation) that announces a short delta when the
      counts move, rather than re-reading the whole table on every tick (which
      would spam screen readers).
- [x] **Match confidence in the aggregation view**: `GET /api/vulns` carries a
      per-CVE `confidence` (the strongest match across instances) and the
      Vulnerabilities page renders it as a Confidence column, not just in the
      asset drawer.
- [x] **Scoring calibration** (honesty path): the risk weights are an
      opinionated heuristic, and the UI now says so — a tooltip on every risk
      badge, a methodology line on the Risk page, and "heuristic composite"
      stat hints. Calibration against a reference distribution is still open;
      until then the score is labelled heuristic, never a model.

## P2 — Intelligence (vision, not yet built)

- [ ] `argus-intel`: a *trained* device classifier (Fingerbank-style features) —
      today's classifier is heuristic rules and is labeled as such.
- [~] `argus-sensor`: passive-sensing **analysis** built + unit-tested (p0f-style
      TCP-SYN, DHCP option 55/60, HTTP User-Agent, agreement-weighted fusion);
      live packet **capture** (libpcap/Npcap, privileged) is not yet wired
- [ ] `argus-connectors`: cloud/AD/NetBox adapters (also the real source of
      VLAN/switch telemetry that would replace the policy engine's `/24` zone
      approximation)
- [ ] `argus-behavior`: per-deployment anomaly baselines
