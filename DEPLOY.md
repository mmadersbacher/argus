# Deploying Argus (self-host)

Argus ships as three containers — Postgres, the Rust API, and the Next.js
console — wired together with `docker compose`.

## Quick start

```bash
docker compose up --build
```

- Console: <http://localhost:3000>
- API: <http://localhost:8088> (health at `/health`)

The API connects to Postgres, creates its schema, and seeds the demo inventory
on first run. Inventory is persisted in the `argus-pgdata` volume, so it
survives `docker compose down` / `up` (use `docker compose down -v` to reset).

## Services

| Service    | Port | Notes |
|------------|------|-------|
| `web`      | 3000 | Next.js console (standalone build) |
| `api`      | 8088 | axum API; runs nmap-backed discovery (nmap is in the image) |
| `postgres` | —    | Postgres 18, internal only, data in the `argus-pgdata` volume |

## Configuration

| Env var               | Default                                          | Where |
|-----------------------|--------------------------------------------------|-------|
| `DATABASE_URL`        | `postgresql://argus:argus@postgres:5432/argus`   | api |
| `ARGUS_BIND`          | `0.0.0.0:8088`                                   | api |
| `NEXT_PUBLIC_API_URL` | `http://localhost:8088` (build arg)              | web (baked at build — it's the URL the **browser** calls) |

> Change the Postgres credentials for anything beyond a local demo, and put the
> stack behind a reverse proxy with TLS. Public multi-tenant operation also
> needs authentication + tenant isolation (see ROADMAP P3) — not yet built.

## Run natively (without Docker)

```bash
# Postgres must be running with an `argus` role + db
cargo run -p argus-api          # :8088
cd web && npm run dev           # :3000
```
