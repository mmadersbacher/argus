# Argus

**Cyber Exposure & Asset Intelligence Platform** — an open-source CAASM/exposure-management
platform that continuously discovers, identifies, scores and monitors every asset on a network.

Argus mirrors the *architecture* of enterprise platforms like Armis Centrix™ and runZero,
built entirely on open-source data and tooling. It is **not** affiliated with Armis.

> Status: **P1 spine + SaaS foundation + Console v2** — discovery, CVE correlation, risk
> scoring, continuous monitoring and a fully built console (overview, assets, network,
> vulnerabilities, risk, settings) work end-to-end behind JWT/API-key auth with tenant
> isolation and RBAC. See [`ROADMAP.md`](ROADMAP.md) and the design spec under
> [`docs/superpowers/specs/`](docs/superpowers/specs/).

## What it does (target)

- **Discover** assets via active scanning (runZero-style, OT-safe) and later passive sensing
- **Identify** devices via open fingerprint data (Fingerbank/OUI/Nmap/p0f) + a trained classifier
- **Correlate** vulnerabilities (NVD CPE + EPSS + CISA KEV)
- **Score** per-asset exposure/risk
- **Visualize** everything in a real-time web console (asset graph, dashboards)

## Architecture

Rust workspace (backend + engines) + a TypeScript/Next.js web console, Postgres as the
source of truth. Full design: [`docs/superpowers/specs/2026-06-03-argus-platform-design.md`](docs/superpowers/specs/2026-06-03-argus-platform-design.md).

```
crates/
  argus-core         # domain model + risk scoring
  argus-discovery    # active discovery (nmap/masscan/arp-scan)   [P1]
  argus-vuln         # CVE correlation, live NVD/EPSS/KEV intel   [P1/P3]
  argus-intel        # device classification                      [P1]
  argus-report       # exposure / posture reports                 [P3]
  argus-policy       # advisory segmentation rules                [P3]
  argus-api          # axum HTTP, Postgres, auth, multi-tenant    [P0..P3]
  ...                # sensor, behavior, connectors               [P2/P3]
web/                 # Next.js console                            [P0/P1]
```

## Security model

Multi-tenant by construction: every API route is authenticated (Argon2id
passwords → HS256 JWT sessions, or hashed `x-api-key` machine credentials),
every query is scoped to the caller's tenant, and roles
(`viewer`/`analyst`/`admin`) gate scans, imports and administration. Logins,
scans, imports and credential changes land in a per-tenant audit log.
Deployment hardening (TLS, secrets, CORS): see [`DEPLOY.md`](DEPLOY.md).

## Development

Prerequisites: **Rust** (stable), **Node 20+**, **PostgreSQL 16+**.

```bash
cargo build          # build the workspace
cargo test           # run tests
cargo clippy         # lint
```

## License

Apache-2.0. See [`LICENSE`](LICENSE).
