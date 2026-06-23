# Argus School Edition — Cycle 1 Implementation Plan (S0 Foundation + Correctness Must-Fixes)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Argus School Edition real as a deployable single-tenant appliance and remove the two correctness defects that would produce false High-confidence findings on a real school network.

**Architecture:** Same Rust workspace + Next.js console; the School Edition is a deployment/config profile (single-tenant, internal scanning on) plus targeted correctness fixes in `argus-vuln`. No new crates.

**Tech Stack:** Rust 1.83 (edition 2021), `sqlx`/Postgres, `axum`, Docker Compose. Tests via `cargo test`.

**Source spec:** `docs/superpowers/specs/2026-06-23-school-edition-design.md` (§0 Entscheidungen, §5 Spine, §10 Roadmap S0+S1).

**Scope of THIS cycle:** S0 (relicense + appliance packaging) + the two pure-`argus-vuln` must-fixes (AtMost over-match, IIS version-extraction recall hole).

**Explicitly DEFERRED to Cycle 2 (not silently dropped):** dedup-demotion fix (lives at the catalog↔live-NVD merge in `intel.rs:556`, needs the live-intel test harness), audit-log read path, internal-reachability policy model, SMB2-negotiate probe, EOL-OS advisory. These are documented in the spec; they are out of scope here on purpose.

## Global Constraints

- Rust version floor: **1.83** (`rust-version = "1.83"`, `edition = "2021"`).
- `unsafe_code = "forbid"` workspace-wide — never introduce `unsafe`.
- **Before every commit:** run `cargo fmt --all`. CI fails on `cargo fmt --all --check` separately from clippy.
- CI gate: `cargo clippy --workspace --all-targets -- -D warnings` (pedantic + nursery enabled). Every commit must be clippy-clean under `-D warnings`.
- `cargo test --workspace` must stay green (343 tests pass today; DB-gated tests self-skip without `TEST_DATABASE_URL`).
- License (new this cycle): **PolyForm Strict 1.0.0**, SPDX `PolyForm-Strict-1.0.0`.
- All work lands on a new `school-edition` branch, never on `main`.

---

### Task 1: Branch + relicense to PolyForm Strict 1.0.0

**Files:**
- Create branch: `school-edition`
- Modify: `Cargo.toml:9` (`[workspace.package] license`)
- Replace: `LICENSE`
- Modify: `README.md` (License section, currently `## License\n\nApache-2.0. See ...`)
- Commit (docs): `docs/superpowers/specs/2026-06-23-school-edition-design.md`, `docs/superpowers/plans/2026-06-23-school-edition-cycle1.md`

**Interfaces:**
- Consumes: nothing.
- Produces: the `school-edition` branch all later tasks commit to; the relicensed tree.

- [ ] **Step 1: Create the working branch**

```bash
cd ~/dev/argus
git checkout main && git pull --ff-only
git checkout -b school-edition
```

- [ ] **Step 2: Commit the design + plan docs first (so history starts clean)**

```bash
git add docs/superpowers/specs/2026-06-23-school-edition-design.md \
        docs/superpowers/plans/2026-06-23-school-edition-cycle1.md
git commit -m "docs: school-edition design spec + cycle-1 plan"
```

- [ ] **Step 3: Switch the workspace license field**

In `Cargo.toml`, under `[workspace.package]`, change:

```toml
license = "Apache-2.0"
```
to:
```toml
license = "PolyForm-Strict-1.0.0"
```

- [ ] **Step 4: Replace the LICENSE file with the PolyForm Strict 1.0.0 text**

The canonical text lives at `https://polyformproject.org/licenses/strict/1.0.0/`. Fetch and save the plain-text license verbatim:

```bash
curl -fsSL https://polyformproject.org/licenses/strict/1.0.0/ -o /tmp/polyform-strict.html
# Save the license body (the text from the "# PolyForm Strict License 1.0.0"
# heading through the end) verbatim into ./LICENSE. If offline, paste the
# canonical text manually — it must be byte-for-byte the published license.
```

Verify the file now begins with the PolyForm heading, not Apache:

```bash
head -1 LICENSE   # expect: PolyForm Strict License 1.0.0  (or its markdown "# " form)
```

- [ ] **Step 5: Update the README License section**

In `README.md`, replace the License section with:

```markdown
## License

**PolyForm Strict 1.0.0** (source-available). The source is published for review
and transparency; all use beyond viewing is reserved. See [`LICENSE`](LICENSE).
The General (multi-tenant SaaS) edition history remains under its prior
Apache-2.0 release tag. School deployments receive a separate, explicit usage
grant from the author.
```

- [ ] **Step 6: Verify the build still compiles with the new license metadata**

Run: `cargo build -p argus-core`
Expected: compiles (the license string is metadata; cargo accepts the SPDX id `PolyForm-Strict-1.0.0`).

- [ ] **Step 7: Commit**

```bash
cargo fmt --all
git add Cargo.toml LICENSE README.md
git commit -m "chore: relicense to PolyForm Strict 1.0.0 (source-available)"
```

---

### Task 2: Fix `AtMost` over-match (false High-confidence Criticals on ancient versions)

**Problem:** `VersionRange::AtMost(hi)` has no lower bound (`lib.rs:48`: `cmp(version, hi) != Greater`), so `AtMost("2.4.48")` matches Apache httpd `1.3.x`/`2.0`/`2.2` and `AtMost("2.441")` matches Jenkins `1.x` — all reported version-checked → **High confidence → drives the risk score**. These old branches are not in the real vulnerable set. Three records are affected.

**Files:**
- Modify: `crates/argus-vuln/src/catalog.rs:439` (CVE-2023-25690), `:449` (CVE-2021-40438), `:221` (CVE-2024-23897)
- Test: `crates/argus-vuln/src/lib.rs` (`#[cfg(test)] mod tests`)

**Interfaces:**
- Consumes: `correlate_product(&str) -> Vec<Vulnerability>` (existing, `lib.rs:143`), `VersionRange::Range` (existing).
- Produces: no API change; only catalog data changes from `AtMost` to bounded `Range`.

- [ ] **Step 1: Write the failing tests**

Add to `crates/argus-vuln/src/lib.rs` `mod tests`:

```rust
#[test]
fn apache_mod_proxy_cves_do_not_match_pre_2_4_versions() {
    // CVE-2021-40438 / CVE-2023-25690 affect the 2.4 branch only. An unbounded
    // AtMost falsely flagged httpd 1.3/2.0/2.2 as High-confidence Critical.
    let v = correlate_product("Apache httpd 1.3.41");
    assert!(!v.iter().any(|x| x.cve_id == "CVE-2021-40438"));
    assert!(!v.iter().any(|x| x.cve_id == "CVE-2023-25690"));
}

#[test]
fn apache_mod_proxy_cves_still_match_in_branch_versions() {
    let v = correlate_product("Apache httpd 2.4.40");
    assert!(v.iter().any(|x| x.cve_id == "CVE-2021-40438"));
    assert!(v.iter().any(|x| x.cve_id == "CVE-2023-25690"));
}

#[test]
fn jenkins_cli_cve_does_not_match_1x() {
    assert!(!correlate_product("Jenkins 1.650")
        .iter()
        .any(|x| x.cve_id == "CVE-2024-23897"));
    assert!(correlate_product("Jenkins 2.400")
        .iter()
        .any(|x| x.cve_id == "CVE-2024-23897"));
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p argus-vuln apache_mod_proxy_cves_do_not_match_pre_2_4_versions jenkins_cli_cve_does_not_match_1x -- --nocapture`
Expected: FAIL — `1.3.41` and `Jenkins 1.650` currently match (unbounded `AtMost`).

- [ ] **Step 3: Bound the three records to their real branches**

In `crates/argus-vuln/src/catalog.rs`:

CVE-2023-25690 (`:439`): change
```rust
        affected: VersionRange::AtMost("2.4.55"),
```
to
```rust
        // 2.4 branch only (fixed 2.4.56); bounded so it cannot match 1.3/2.0/2.2.
        affected: VersionRange::Range("2.4.0", "2.4.55"),
```

CVE-2021-40438 (`:449`): change
```rust
        affected: VersionRange::AtMost("2.4.48"),
```
to
```rust
        // 2.4 branch only (fixed 2.4.49); bounded against ancient-version FP.
        affected: VersionRange::Range("2.4.0", "2.4.48"),
```

CVE-2024-23897 (`:221`): change
```rust
        affected: VersionRange::AtMost("2.441"),
```
to
```rust
        // Jenkins 2.x weekly line (fixed 2.442); bounded so it cannot match 1.x.
        affected: VersionRange::Range("2.0", "2.441"),
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p argus-vuln`
Expected: PASS (new tests green, existing tests still green).

- [ ] **Step 5: Verify no other `AtMost` remains unbounded**

Run: `grep -n "AtMost" crates/argus-vuln/src/catalog.rs`
Expected: no output (all three converted; if any remain, evaluate each the same way).

- [ ] **Step 6: Commit**

```bash
cargo fmt --all && cargo clippy -p argus-vuln --all-targets -- -D warnings
git add crates/argus-vuln/src/catalog.rs crates/argus-vuln/src/lib.rs
git commit -m "fix(vuln): bound AtMost CVE ranges to their branch (no false ancient-version Criticals)"
```

---

### Task 3: Fix version extraction for `vendor/version` banners (IIS recall hole)

**Problem:** `extract_version` (`lib.rs:110-114`) only splits on whitespace, so `"Microsoft-IIS/10.0"` (slash, token starts with `M`) yields no version → every non-`Any` IIS record is filtered out → the IIS catalog entry can essentially never fire from a real nmap banner. Same for `"Apache/2.4.49"`, `"lighttpd/1.4.55"`.

**Files:**
- Modify: `crates/argus-vuln/src/lib.rs:110-114` (`extract_version`)
- Test: `crates/argus-vuln/src/lib.rs` (`mod tests`)

**Interfaces:**
- Consumes: nothing new.
- Produces: `extract_version(&str) -> Option<&str>` — same signature; now also splits on `/`.

- [ ] **Step 1: Write the failing tests**

Add to `mod tests`:

```rust
#[test]
fn extract_version_handles_slash_delimited_banner() {
    assert_eq!(extract_version("Microsoft-IIS/10.0"), Some("10.0"));
    assert_eq!(extract_version("Apache/2.4.49"), Some("2.4.49"));
    // Space-delimited and dot-less cases unchanged:
    assert_eq!(extract_version("OpenSSH 8.9p1"), Some("8.9p1"));
    assert_eq!(extract_version("Windows Server 2019"), None);
}

#[test]
fn iis_cve_matches_slash_banner_in_range() {
    // CVE-2015-1635 affects IIS 7.5-8.5. A real "Microsoft-IIS/8.0" banner must
    // now correlate; "Microsoft-IIS/10.0" (out of range) must not.
    assert!(correlate_product("Microsoft-IIS/8.0")
        .iter()
        .any(|x| x.cve_id == "CVE-2015-1635"));
    assert!(!correlate_product("Microsoft-IIS/10.0")
        .iter()
        .any(|x| x.cve_id == "CVE-2015-1635"));
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p argus-vuln extract_version_handles_slash_delimited_banner iis_cve_matches_slash_banner_in_range`
Expected: FAIL — `extract_version("Microsoft-IIS/10.0")` currently returns `None`, so the IIS CVE never matches.

- [ ] **Step 3: Split on `/` as well as whitespace**

In `crates/argus-vuln/src/lib.rs`, replace the body of `extract_version`:

```rust
fn extract_version(product: &str) -> Option<&str> {
    product
        .split_whitespace()
        .find(|tok| tok.starts_with(|c: char| c.is_ascii_digit()) && tok.contains('.'))
}
```
with:

```rust
fn extract_version(product: &str) -> Option<&str> {
    // Split on whitespace AND '/', so `vendor/version` banners (nmap's
    // "Microsoft-IIS/10.0", "Apache/2.4.49") yield the version, not just the
    // "Vendor 1.2.3" form. Still requires a leading digit + a dot, so a bare
    // year/model ("Windows Server 2019") is not mistaken for a version.
    product
        .split(|c: char| c.is_whitespace() || c == '/')
        .find(|tok| tok.starts_with(|c: char| c.is_ascii_digit()) && tok.contains('.'))
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p argus-vuln`
Expected: PASS (new tests green; existing version/correlation tests still green).

- [ ] **Step 5: Commit**

```bash
cargo fmt --all && cargo clippy -p argus-vuln --all-targets -- -D warnings
git add crates/argus-vuln/src/lib.rs
git commit -m "fix(vuln): extract version from vendor/version banners (closes IIS recall hole)"
```

---

### Task 4: School Edition appliance packaging (single-tenant, internal-scan profile)

**Problem:** The shipped `docker-compose.yml` defaults to the SaaS profile: signup ON (`ARGUS_SIGNUP_ENABLED=true`), demo seeding ON, and on Postgres `ARGUS_SCAN_ALLOW_PRIVATE` defaults OFF (`main.rs:87-90`: `matches!(store, Store::Memory(_))`). A school appliance needs the inverse: one tenant, no signup, no demo data, internal scanning ON.

**Files:**
- Create: `deploy/school/docker-compose.yml`
- Create: `deploy/school/.env.school.example`
- Modify: `DEPLOY.md` (add a "School Edition (single-tenant appliance)" section)

**Interfaces:**
- Consumes: existing env flags read by `argus-api/src/main.rs` — `ARGUS_SIGNUP_ENABLED`, `ARGUS_SEED_DEMO`, `ARGUS_SCAN_ALLOW_PRIVATE`, `ARGUS_ADMIN_EMAIL`, `ARGUS_ADMIN_PASSWORD`, `ARGUS_JWT_SECRET`, `DATABASE_URL`, `ARGUS_BIND`, `ARGUS_CORS_ORIGIN`.
- Produces: a self-contained appliance compose profile. No code change.

- [ ] **Step 1: Create the appliance compose file**

Create `deploy/school/docker-compose.yml`:

```yaml
# Argus School Edition — single-tenant, self-hosted appliance.
# Internal LAN scanning ON; no self-service signup; no demo data.
# Run from repo root: docker compose -f deploy/school/docker-compose.yml --env-file deploy/school/.env.school up -d
services:
  postgres:
    image: postgres:18
    environment:
      POSTGRES_USER: argus
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?set POSTGRES_PASSWORD}
      POSTGRES_DB: argus
    volumes:
      - argus-pgdata:/var/lib/postgresql
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U argus -d argus"]
      interval: 5s
      timeout: 3s
      retries: 12

  api:
    build:
      context: ../..
      dockerfile: Dockerfile.api
    environment:
      DATABASE_URL: postgresql://argus:${POSTGRES_PASSWORD:?set POSTGRES_PASSWORD}@postgres:5432/argus
      ARGUS_BIND: 0.0.0.0:8088
      RUST_LOG: info
      ARGUS_JWT_SECRET: ${ARGUS_JWT_SECRET:?set a 32+ char secret}
      ARGUS_CORS_ORIGIN: ${ARGUS_CORS_ORIGIN:-http://localhost:3000}
      ARGUS_ADMIN_EMAIL: ${ARGUS_ADMIN_EMAIL:?set the school admin email}
      ARGUS_ADMIN_PASSWORD: ${ARGUS_ADMIN_PASSWORD:?set the school admin password}
      # Appliance profile: single tenant, no demo, internal scanning ON.
      ARGUS_SIGNUP_ENABLED: "false"
      ARGUS_SEED_DEMO: "false"
      ARGUS_SCAN_ALLOW_PRIVATE: "true"
      NVD_API_KEY: ${NVD_API_KEY:-}
      ARGUS_INTEL_CACHE: /var/lib/argus/intel-cache.json
    volumes:
      - argus-intel:/var/lib/argus
    ports:
      - "8088:8088"
    depends_on:
      postgres:
        condition: service_healthy

  web:
    build:
      context: ../../web
      args:
        NEXT_PUBLIC_API_URL: http://localhost:8088
    ports:
      - "3000:3000"
    depends_on:
      - api

volumes:
  argus-pgdata:
  argus-intel:
```

- [ ] **Step 2: Create the env example**

Create `deploy/school/.env.school.example`:

```bash
# Copy to deploy/school/.env.school and fill in. Never commit the real file.
POSTGRES_PASSWORD=change-me-strong
# 32+ chars; without it sessions reset on every restart.
ARGUS_JWT_SECRET=change-me-to-a-long-random-32plus-char-secret
ARGUS_ADMIN_EMAIL=admin@schule.local
ARGUS_ADMIN_PASSWORD=change-me-strong-admin-password
# Browser origin the console is served from (adjust to the appliance host).
ARGUS_CORS_ORIGIN=http://localhost:3000
# Optional: lifts live NVD lookups 5 -> 50 req / 30s.
NVD_API_KEY=
```

- [ ] **Step 3: Ensure the real env file is git-ignored**

Run:
```bash
grep -qxF 'deploy/school/.env.school' .gitignore || echo 'deploy/school/.env.school' >> .gitignore
```

- [ ] **Step 4: Validate the compose file**

Run: `docker compose -f deploy/school/docker-compose.yml --env-file deploy/school/.env.school.example config -q`
Expected: exits 0 with no error (compose syntax + variable interpolation valid). If `docker` is unavailable in the dev environment, instead run `docker compose ... config` on the machine that will host the appliance and record the result.

- [ ] **Step 5: Document the appliance profile**

In `DEPLOY.md`, add a section:

```markdown
## School Edition (single-tenant appliance)

The School Edition runs the same image as a self-hosted, single-tenant appliance
inside the school LAN. Data never leaves the appliance.

    cp deploy/school/.env.school.example deploy/school/.env.school
    # edit deploy/school/.env.school (secrets, admin, CORS origin)
    docker compose -f deploy/school/docker-compose.yml --env-file deploy/school/.env.school up -d

Profile differences vs. the SaaS compose: self-service signup is OFF
(`ARGUS_SIGNUP_ENABLED=false`), demo seeding is OFF (`ARGUS_SEED_DEMO=false`),
and internal LAN scanning is ON (`ARGUS_SCAN_ALLOW_PRIVATE=true`) — required so
the appliance can inventory the school's own RFC1918 network. The first-run
admin is created from `ARGUS_ADMIN_EMAIL`/`ARGUS_ADMIN_PASSWORD`.

> Scanning a real (especially Bundesschule) network requires written
> authorization from the school leadership and DSB before first use.
```

- [ ] **Step 6: Commit**

```bash
git add deploy/school/docker-compose.yml deploy/school/.env.school.example .gitignore DEPLOY.md
git commit -m "feat(deploy): School Edition single-tenant appliance compose profile"
```

---

## Self-Review

**Spec coverage (S0 + the two in-scope must-fixes):**
- S0 relicense → Task 1. ✅
- S0 appliance packaging (single-tenant, signup off, demo off, allow_private on) → Task 4. ✅
- Must-fix AtMost over-match → Task 2. ✅
- Must-fix IIS recall hole → Task 3. ✅
- Edition split (branch) → Task 1 Step 1. ✅ (a `general` release tag on `main` is a one-line `git tag` the operator can add when publishing; noted, not required for the build.)
- Deferred items listed in header (dedup-demotion, audit-read, internal-reachability, SMB2, EOL-OS) → Cycle 2. ✅ (no silent omission)

**Placeholder scan:** No "TBD/TODO". The only external artifact fetched rather than pasted is the PolyForm Strict license text (a standard, must-be-verbatim legal document) — Task 1 Step 4 gives the canonical URL + a verification check.

**Type/identifier consistency:** `extract_version`, `correlate_product`, `VersionRange::Range`, CVE ids (`CVE-2021-40438`, `CVE-2023-25690`, `CVE-2024-23897`, `CVE-2015-1635`) and env var names (`ARGUS_SIGNUP_ENABLED`, `ARGUS_SEED_DEMO`, `ARGUS_SCAN_ALLOW_PRIVATE`) verified against the current source.
