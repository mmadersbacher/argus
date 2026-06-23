# Argus sim-net (deliberately-vulnerable test lab)

A small, reproducible, **intentionally insecure** network for testing Argus
discovery + CVE correlation and for backing the thesis evaluation (FF1/FF2).

> ⚠️ **Authorized test use only.** Every container here is intentionally
> vulnerable. Run it on an isolated host. **Never** bridge `172.30.0.0/24` to a
> real, production or school network.

## What's in it (verified live with `nmap -sV`, 2026-06-23)

| Host | IP | Real finding (version-confirmed) | Why it's here |
|---|---|---|---|
| `metasploitable` | 172.30.0.10 | **ProFTPD 1.3.1** (tcp/2121) → `CVE-2019-12815` mod_copy (Critical) | Broad legacy surface (Apache 2.2.8, MySQL 5.0, Samba 3, Postfix, Postgres 8.3). Its Apache 2.2.8 is correctly **not** flagged — the catalog is 2.4-branch only. |
| `dvwa` | 172.30.0.20 | **Apache httpd 2.4.25** → `CVE-2021-40438` **and** `CVE-2023-25690` (Critical) | Vulnerable web app; clean version-confirmed Apache hits. |
| `holdout-caddy` | 172.30.0.30 | **none (expected)** | Out-of-catalog control: a clean modern server with no catalog CVE. Argus must report **zero** findings — the FF1 precision control that breaks the catalog-tested-against-itself circularity (spec §9). |

> Honest note: this `tleemcjr/metasploitable2` **container** runs `proftpd` on
> tcp/2121, **not** the classic VM's `vsftpd 2.3.4` on tcp/21 — so the guaranteed
> hit here is the ProFTPD mod_copy CVE, confirmed live. Clean version→CVE
> correlation needs nmap-normalised product strings (`-sV`), not raw
> connect-scan banners; run the lab through nmap (or the API's nmap path).

All images were verified to exist on Docker Hub on 2026-06-23. Verify pulls on
the host before relying on it: `docker compose -f deploy/simnet/docker-compose.yml pull`.

## Run it

```bash
docker compose -f deploy/simnet/docker-compose.yml up -d
docker compose -f deploy/simnet/docker-compose.yml ps    # confirm all are Up
```

## Scan it with Argus

```bash
# Discovery (fast, no CVE correlation in the CLI itself):
./target/debug/argus-discovery 172.30.0.0/24

# Full version→CVE correlation — feed nmap -sV output through the API:
nmap -sV -oX lab.xml 172.30.0.10 172.30.0.20 172.30.0.30
#   POST lab.xml to the running API's  /api/import/nmap  (auth required),
#   then GET /api/vulns to see the correlated, confidence-tagged CVEs.
```

## Expected result (the success criterion)

- `172.30.0.10` → `CVE-2019-12815` (ProFTPD 1.3.1), version-confirmed Critical.
- `172.30.0.20` → `CVE-2021-40438` + `CVE-2023-25690` (Apache 2.4.25), confirmed.
- `172.30.0.30` (Caddy) → **no findings**.
- `ground-truth.csv` is the labelled expectation: use it for the classifier
  confusion matrix and to confirm the prioritised "fix-these-first" list puts
  the Criticals at the top.

## Next (not yet here)

Per spec §8 the full lab also wants: a Windows/AD box (SMBv1/EOL-OS), a NAS, an
old OpenSSH box, an IP-camera/printer mock, and BACnet/Modbus emulators — added
as those probes/fingerprints land in later cycles.
