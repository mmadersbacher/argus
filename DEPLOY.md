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

All `/api/*` routes (except `/health`, `/api/auth/login`, `/api/auth/register`,
`/api/auth/logout`) require a credential.

- **Console users** sign in via `POST /api/auth/login`. The JWT is set in an
  **`HttpOnly` session cookie** (never exposed to JavaScript), alongside a
  JS-readable CSRF cookie. The browser sends the session cookie automatically;
  state-changing requests (`POST`/`PATCH`/`DELETE`) must echo the CSRF cookie in
  an `x-csrf-token` header (double-submit). `POST /api/auth/logout` clears both.
  Roles: `viewer` (read), `analyst` (read + scan/import), `admin` (everything
  incl. user/key/webhook management).
- **Programmatic clients** (CI importers, integrations) use `x-api-key: argus_…`
  (preferred) or `Authorization: Bearer <jwt>`. Both are CSRF-exempt — a
  cross-site page can't set those headers. Admins create API keys under
  Settings; only a hash is stored — the plaintext is shown exactly once.

Because the console (`:3000`) and API (`:8088`) are different origins, the
session cookie is `Secure; SameSite=None` by default (correct for a cross-origin
HTTPS deployment). Tune it for your topology:

| Deployment                                    | `ARGUS_COOKIE_SECURE` | `ARGUS_COOKIE_SAMESITE` |
|-----------------------------------------------|-----------------------|-------------------------|
| Cross-origin over HTTPS (default)             | `true`                | `None`                  |
| Same-site (console + API behind one proxy)    | `true`                | `Lax`                   |
| Local plain-HTTP dev (`localhost`)            | `false`               | `Lax`                   |

A genuinely cross-*domain* console/API (different registrable domains) would
need the CSRF token surfaced in the login body instead of a cookie, since JS
can't read a cross-domain cookie; same-site-different-port (like `localhost`) is
fine. Login is rate-limited per IP and per `(IP, email)`; on Postgres the limit
is shared across replicas.

Every tenant's data is isolated: assets, users, keys, webhooks and the audit
trail are scoped by `tenant_id` in every query.

## Configuration

| Env var                | Default                                          | Where |
|------------------------|--------------------------------------------------|-------|
| `DATABASE_URL`         | `postgresql://argus:argus@postgres:5432/argus`   | api |
| `ARGUS_BIND`           | `127.0.0.1:8088`                                 | api — code default; docker-compose sets `0.0.0.0:8088` for the container |
| `ARGUS_JWT_SECRET`     | *(ephemeral random — set this in production!)*   | api — 32+ chars; unset means sessions die on restart |
| `ARGUS_TOKEN_TTL_HOURS`| `12`                                             | api |
| `ARGUS_CORS_ORIGIN`    | `http://localhost:3000,http://127.0.0.1:3000`    | api — comma-separated browser origins (credentials are allowed, so this can't be `*`) |
| `ARGUS_COOKIE_SECURE`  | `true`                                           | api — `Secure` attribute on the session/CSRF cookies; set `false` for local plain-HTTP dev |
| `ARGUS_COOKIE_SAMESITE`| `None`                                           | api — `Lax`/`Strict`/`None`; `None` requires `Secure`. Use `Lax` for same-site or dev |
| `ARGUS_SCAN_ALLOW_PRIVATE` | `false` on Postgres, `true` on the memory store | api — allow scans **and webhooks** to target private/internal addresses (self-hosted); off on a hosted multi-tenant server to block SSRF |
| `ARGUS_ADMIN_EMAIL`    | `admin@argus.local`                              | api — bootstrap admin (first run only) |
| `ARGUS_ADMIN_PASSWORD` | *(generated, printed once in the log)*           | api — first run only |
| `ARGUS_SIGNUP_ENABLED` | `false`                                          | api — self-service signup (code default off; the compose dev setup sets `true`) |
| `ARGUS_SEED_DEMO`      | `true`                                           | api — demo assets in the bootstrap tenant |
| `NVD_API_KEY`          | *(unset — NVD lookups paced to 5 req / 30 s)*    | api — [free key](https://nvd.nist.gov/developers/request-an-api-key) lifts live CVE lookups to 50 req / 30 s |
| `ARGUS_INTEL_CACHE`    | `intel-cache.json`                               | api — snapshot file for the live-intel cache (NVD/KEV/EPSS) so it survives restarts; set empty to disable |
| `NEXT_PUBLIC_API_URL`  | `http://localhost:8088` (build arg)              | web (baked at build — it's the URL the **browser** calls) |

> For anything beyond a local demo: set `ARGUS_JWT_SECRET`, change the
> Postgres credentials, restrict `ARGUS_CORS_ORIGIN` to your console origin,
> consider `ARGUS_SIGNUP_ENABLED=false`, and put the stack behind a reverse
> proxy with TLS.

## Webhooks (change-event delivery)

Each tenant can register one outbound webhook to receive change events
(`asset.new`, `services.changed`, `vulns.changed`, `risk.changed`) after each
scan. Admin-only:

- `POST /api/webhook` `{ "url": "https://…", "enabled": true }` — set/update;
  returns the signing `secret`.
- `GET /api/webhook` — current config (includes the secret).
- `DELETE /api/webhook` — remove it.

Deliveries are `POST`ed as JSON and signed with **HMAC-SHA256** over the raw
body (keyed on the `secret` *string's* bytes) in an
`x-argus-signature: sha256=<hex>` header:

```json
{ "tenant_id": "…", "event_count": 1,
  "events": [ { "kind": "asset.new", "asset": "web-01", "detail": { "risk": 75.0 } } ] }
```

Verify the signature before trusting a payload:

```python
import hmac, hashlib
expected = "sha256=" + hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()
# then constant-time compare with the x-argus-signature header
```

**SSRF safety:** the URL must be `http`/`https` and resolve to a public address.
Private/internal/metadata addresses are rejected at config time and again at
send time, the connection is pinned to a validated IP (so DNS can't rebind), and
redirects are disabled. Self-hosted single-tenant deployments may target
internal URLs by setting `ARGUS_SCAN_ALLOW_PRIVATE=true`. Delivery is
best-effort and fire-and-forget — webhook trouble never delays or fails a scan.

## Run natively (without Docker)

```bash
# Postgres must be running with an `argus` role + db
cargo run -p argus-api          # :8088
cd web && npm run dev           # :3000
```
