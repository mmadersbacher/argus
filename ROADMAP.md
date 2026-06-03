# Argus Roadmap

Tracking the phased build from the design spec. Checkboxes are the live task list.

## P0 — Foundations
- [x] Repo + design spec
- [x] Prior-art research folded into spec
- [ ] Cargo workspace + `argus-core` domain model (in progress)
- [ ] Postgres schema + sqlx migrations
- [ ] `argus-api` skeleton (axum: health, `/api/assets`)
- [ ] `web/` Next.js shell + dark Enterprise-Security design system
- [ ] CI (GitHub Actions: fmt + clippy + test)

## P1 — Spine (demo-able, real)
- [ ] `argus-discovery`: active scan via nmap/masscan/arp-scan
      (runZero-style safety: normal traffic only, fingerprint-relevant ports, subnet sampling)
- [ ] ingest pipeline → asset inventory with dedup (MAC → IP → hostname)
- [ ] basic fingerprinting: MAC-OUI + nmap service/OS
- [ ] `argus-vuln`: CPE match against NVD + EPSS + CISA KEV
- [ ] `argus-risk`: composite exposure score wired onto assets
- [ ] web: dashboard + force-directed asset graph + device-detail drawer

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
