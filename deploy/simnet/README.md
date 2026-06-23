# Argus sim-net (deliberately-vulnerable test lab)

A small, reproducible, **intentionally insecure** network for testing Argus
discovery + CVE correlation and for backing the thesis evaluation (FF1/FF2).

> ⚠️ **Authorized test use only.** Every container here is intentionally
> vulnerable. Run it on an isolated host. **Never** bridge `172.30.0.0/24` to a
> real, production or school network.

## What's in it

| Host | IP | Role | Why it's here |
|---|---|---|---|
| `metasploitable` | 172.30.0.10 | legacy server | **Guaranteed finding:** runs vsftpd 2.3.4 → `CVE-2011-2523` (Critical 9.8, version-confirmed). Removes the "we never found a real bug" risk. |
| `dvwa` | 172.30.0.20 | web server | Vulnerable PHP/Apache/MySQL app — extra web surface (catalog hits version-dependent). |
| `holdout-caddy` | 172.30.0.30 | web server | **Out-of-catalog holdout:** a clean modern server with no catalog CVE. Argus must report **zero** findings — the FF1 precision control that breaks the catalog-tested-against-itself circularity. |

All images were verified to exist on Docker Hub on 2026-06-23. Because the lab
can't be pulled in CI, verify pulls on the host before relying on it:
`docker compose -f deploy/simnet/docker-compose.yml pull`.

## Run it

```bash
docker compose -f deploy/simnet/docker-compose.yml up -d
docker compose -f deploy/simnet/docker-compose.yml ps    # confirm all are Up
```

If `metasploitable` exits immediately, it needs an image-specific keep-alive
command — add one under its service and re-up.

## Scan it with Argus

```bash
# CLI (from the repo root, after `cargo build`):
./target/debug/argus-discovery 172.30.0.0/24

# or point the School Edition appliance's scan at 172.30.0.0/24
# (the appliance host must be able to route to the docker bridge)
```

## Expected result (the success criterion)

- `172.30.0.10` → a **version-confirmed Critical** `CVE-2011-2523` (vsftpd 2.3.4).
- `172.30.0.30` (Caddy) → **no findings**.
- `ground-truth.csv` is the labelled expectation: use it for the classifier
  confusion matrix and to confirm the prioritised "fix-these-first" list puts
  the guaranteed Critical at the top.

## Next (not yet here)

Per spec §8 the full lab also wants: a Windows/AD box (SMBv1/EOL-OS), a NAS, an
old Apache/OpenSSH Linux box, an IP-camera/printer mock, and BACnet/Modbus
emulators — added as those probes/fingerprints land in later cycles.
