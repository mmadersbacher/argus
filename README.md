# Argus

**Cyber Exposure & Asset Intelligence Platform** — an open-source CAASM/exposure-management
platform that continuously discovers, identifies, scores and monitors every asset on a network.

Argus mirrors the *architecture* of enterprise platforms like Armis Centrix™ and runZero,
built entirely on open-source data and tooling. It is **not** affiliated with Armis.

> Status: **early development** (P0 — foundations). See [`ROADMAP.md`](ROADMAP.md) and the
> design spec under [`docs/superpowers/specs/`](docs/superpowers/specs/).

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
  argus-core         # domain model (this crate)
  argus-discovery    # active discovery (nmap/masscan/arp-scan)   [P1]
  argus-vuln         # CVE correlation (NVD/EPSS/KEV)             [P1]
  argus-risk         # exposure/risk scoring                      [P1]
  argus-api          # axum HTTP/WS, Postgres, auth, multi-tenant [P0/P1]
  ...                # sensor, intel, behavior, policy, connectors [P2/P3]
web/                 # Next.js console                            [P0/P1]
```

## Development

Prerequisites: **Rust** (stable), **Node 20+**, **PostgreSQL 16+**.

```bash
cargo build          # build the workspace
cargo test           # run tests
cargo clippy         # lint
```

## License

Apache-2.0. See [`LICENSE`](LICENSE).
