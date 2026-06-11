# Deploying Argus (self-host)

Argus ships as three containers — Postgres, the Rust API, and the Next.js
console — wired together with `docker compose`.

## Quick start

```bash
docker compose up --build
```

- Console: <http://localhost:3000>
- API: <http://localhost:8088> (health at `/health`)

On first run the API migrates its schema, creates the **bootstrap tenant and
admin user**, and seeds the demo inventory. The admin credentials are printed
**once** in the `api` container log:

```
docker compose logs api | grep "bootstrap admin"
```

Sign in at <http://localhost:3000/login> with those credentials (or set
`ARGUS_ADMIN_EMAIL` / `ARGUS_ADMIN_PASSWORD` beforehand). New organizations
can self-register on the login page while `ARGUS_SIGNUP_ENABLED=true`.

Inventory is persisted in the `argus-pgdata` volume, so it survives
`docker compose down` / `up` (use `docker compose down -v` to reset).

## Services

| Service    | Port | Notes |
|------------|------|-------|
| `web`      | 3000 | Next.js console (standalone build) |
| `api`      | 8088 | axum API; runs nmap-backed discovery (nmap is in the image) |
| `postgres` | —    | Postgres 18, internal only, data in the `argus-pgdata` volume |

## Authentication

All `/api/*` routes (except `/health`, `/api/auth/login`, `/api/auth/register`)
require a credential:

- **Users** sign in via `POST /api/auth/login` and send
  `Authorization: Bearer <jwt>`. Roles: `viewer` (read), `analyst`
  (read + scan/import), `admin` (everything incl. user/key management).
- **Machines** (CI importers, integrations) send `x-api-key: argus_…`.
  Admins create keys under Settings; only a hash is stored — the plaintext
  is shown exactly once.

Every tenant's data is isolated: assets, users, keys and the audit trail are
scoped by `tenant_id` in every query.

## Configuration

| Env var                | Default                                          | Where |
|------------------------|--------------------------------------------------|-------|
| `DATABASE_URL`         | `postgresql://argus:argus@postgres:5432/argus`   | api |
| `ARGUS_BIND`           | `0.0.0.0:8088`                                   | api |
| `ARGUS_JWT_SECRET`     | *(ephemeral random — set this in production!)*   | api — 32+ chars; unset means sessions die on restart |
| `ARGUS_TOKEN_TTL_HOURS`| `12`                                             | api |
| `ARGUS_CORS_ORIGIN`    | `http://localhost:3000,http://127.0.0.1:3000`    | api — comma-separated browser origins |
| `ARGUS_ADMIN_EMAIL`    | `admin@argus.local`                              | api — bootstrap admin (first run only) |
| `ARGUS_ADMIN_PASSWORD` | *(generated, printed once in the log)*           | api — first run only |
| `ARGUS_SIGNUP_ENABLED` | `true`                                           | api — self-service tenant signup |
| `ARGUS_SEED_DEMO`      | `true`                                           | api — demo assets in the bootstrap tenant |
| `NVD_API_KEY`          | *(unset — NVD lookups paced to 5 req / 30 s)*    | api — [free key](https://nvd.nist.gov/developers/request-an-api-key) lifts live CVE lookups to 50 req / 30 s |
| `NEXT_PUBLIC_API_URL`  | `http://localhost:8088` (build arg)              | web (baked at build — it's the URL the **browser** calls) |

> For anything beyond a local demo: set `ARGUS_JWT_SECRET`, change the
> Postgres credentials, restrict `ARGUS_CORS_ORIGIN` to your console origin,
> consider `ARGUS_SIGNUP_ENABLED=false`, and put the stack behind a reverse
> proxy with TLS.

## Run natively (without Docker)

```bash
# Postgres must be running with an `argus` role + db
cargo run -p argus-api          # :8088
cd web && npm run dev           # :3000
```
