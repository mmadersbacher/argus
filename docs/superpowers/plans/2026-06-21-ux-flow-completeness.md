# UX/Flow Completeness (TP2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Wire the TP1 primitives into the feature views — confirmations, toasts, accessible validation, sortable/paginated tables, shape-matched skeletons, tooltips — so every screen is functionally complete.

**Architecture:** No new primitives. Each task owns ONE feature file (avoids sequential-edit conflicts) and consumes `@/components/ui`. Feature views have no unit-test harness → verification is `npm test` (TP1 suite stays green) + `npm run build` + `npm run lint` + hex grep, plus a focused unit test for any new pure logic (sort comparators).

**Tech Stack:** Next 16.2.7, React 19.2.4, Tailwind v4, TS 5, `@/components/ui` barrel (ConfirmDialog, useToast/ToastProvider, Table+Column+SortState, Pagination, Checkbox, Tooltip, Tabs/TabPanel, Field, Skeleton/SkeletonTable, Icon `copy`).

## Global Constraints

- React 19.2.4 / Next 16.2.7 / Tailwind v4 / TS 5 — unchanged.
- **Color only via tokens.** Hex grep must stay 0: `grep -rnE '#[0-9a-fA-F]{3,6}' src --include=*.tsx --include=*.ts | grep -v globals.css` → nothing.
- **No new hand-rolled chrome** — use `@/components/ui`.
- **Behavior-preserving** for table migrations: same data, same handlers, same drawer-open behavior; only chrome + added sort/pagination/feedback change.
- `ToastProvider` is already mounted at root (TP1) — just `useToast()` in client components.
- Clipboard: guard `navigator.clipboard`; on failure toast an error, never throw.
- Next 16: read `node_modules/next/dist/docs/` before Next-specific code.
- All work under `web/`. Rust untouched.

---

### Task 1: Settings flow completeness

**Files:**
- Modify: `web/src/app/settings/page.tsx`

**Interfaces:**
- Consumes: `ConfirmDialog`, `useToast`, `Field`, `Input`, `Button`, `Icon` from `@/components/ui`.
- Produces: nothing exported.

- [ ] **Step 1: Gate webhook delete behind ConfirmDialog.** Add `open` state; the "Remove" button (`:409 remove()`) now opens a `<ConfirmDialog tone="danger" title="Remove webhook?" body="Delivery to this endpoint will stop." confirmLabel="Remove" busy={…}>` whose `onConfirm` runs the existing `deleteWebhook()` flow. Nothing deletes until confirmed.
- [ ] **Step 2: Gate API-key revoke behind ConfirmDialog.** Same pattern for `revokeKey(id)` (`:668`): `<ConfirmDialog tone="danger" title="Revoke API key?" body="Any client using this key will immediately lose access." confirmLabel="Revoke">`. Track which key id is pending.
- [ ] **Step 3: Toasts on all mutations.** `const { toast } = useToast();` — fire `toast({title:"Saved", tone:"ok"})` on monitoring-config save, webhook save, key create; `toast({title:"Webhook removed", tone:"ok"})` / `"API key revoked"` on the confirmed deletes; `toast({title:<msg>, tone:"danger"})` on each catch. Remove the inline `{saved && "Saved."}` spans (`:252,:414`) — toast is the single feedback channel.
- [ ] **Step 4: Copy-to-clipboard.** For the readOnly webhook-secret input and the one-time new-API-key plaintext, add a secondary `<Button size="sm" variant="secondary">` with `<Icon name="copy" size={14}/>` that does `await navigator.clipboard.writeText(value)` (guarded) then `toast({title:"Copied", tone:"ok"})`; on failure `toast({title:"Copy failed", tone:"danger"})`.
- [ ] **Step 5: Form a11y.** On the settings inputs that surface a `FormError`, add `aria-invalid={Boolean(error)}` and `aria-describedby` pointing to the FormError's `id`. Give the FormError an `id`.
- [ ] **Step 6: Verify.** `cd web && npm run build && npm run lint && npm test` all clean; hex grep CLEAN. Manually reason through: confirm dialogs block deletion; toasts fire; copy works.
- [ ] **Step 7: Commit** — `git commit -m "feat(settings): confirm destructive actions, toasts, copy-to-clipboard, form a11y"`

### Task 2: Login — Tabs primitive + form a11y

**Files:**
- Modify: `web/src/app/login/page.tsx`

**Interfaces:**
- Consumes: `Tabs`, `TabPanel`, `Field`, `Input`, `Button`, `FormError` from `@/components/ui`.

- [ ] **Step 1: Replace the hand-rolled `tab()` switcher** (`:45`, `aria-pressed`) with `<Tabs tabs={[{id:"login",label:"Sign in"},{id:"register",label:"Create organization"}]} active={mode} onChange={setMode as (id:string)=>void} />`. Keep `mode` state and the login/register submit handlers exactly.
- [ ] **Step 2: Wrap each mode's form body** in `<TabPanel when="login" active={mode}>…</TabPanel>` / `when="register"` (or keep conditional rendering but drive it by `mode` — whichever preserves the existing fields). Preserve all inputs/handlers.
- [ ] **Step 3: Form a11y.** Wire `aria-invalid` + `aria-describedby` from the inputs to the `FormError` (give it an `id`); ensure Enter submits (native form submit).
- [ ] **Step 4: Verify.** `npm run build && npm run lint && npm test` clean; hex CLEAN. Login + register flows still switch and submit.
- [ ] **Step 5: Commit** — `git commit -m "feat(login): Tabs primitive + accessible form errors"`

### Task 3: assets-view — Table primitive + sort + pagination + skeleton + scan toast

**Files:**
- Modify: `web/src/components/assets-view.tsx`
- Test (optional): `web/src/components/ui/__tests__/assets-sort.test.tsx` only if a standalone comparator is extracted.

**Interfaces:**
- Consumes: `Table`, `Column`, `SortState`, `Pagination`, `useToast`, `SkeletonTable`, `Badge`/`RiskBadge` from `@/components/ui`.

- [ ] **Step 1: Replace the hand-rolled assets `<table>`** with `<Table<Asset> columns=… rows=… getRowId=… sort=… onSortChange=… density="compact" />`. Define `Column<Asset>[]` matching the current columns (name/ip, type, risk, services, last-seen…), using `render` for the icon tile + RiskBadge cells so visuals are preserved. Row click still opens the asset drawer (wire via a cell or row handler — keep current behavior).
- [ ] **Step 2: Add client-side sort.** `const [sort,setSort]=useState<SortState>({key:"risk",dir:"desc"})`; sort the rows by the active column before passing to `Table` (numeric for risk/score, string locale-compare for name/type). Mark sortable columns `sortable:true`.
- [ ] **Step 3: Add pagination.** Page the sorted rows (e.g. 50/page); render `<Pagination page pageCount onPageChange />` below the table; reset to page 1 when the filter/search changes.
- [ ] **Step 4: Granular skeleton.** Replace the generic `LoadingState` with a stat-row + `<SkeletonTable rows={8} cols={5}/>` matching the assets layout.
- [ ] **Step 5: Scan toast.** On scan submit, fire `toast({title:"Scan started", tone:"ok"})` (and error toast on failure); the low-contrast `scanNote` text can be dropped in favor of the toast.
- [ ] **Step 6: Verify.** `npm run build && npm run lint && npm test` clean; hex CLEAN. Sort toggles, pagination works, drawer still opens, filter resets page.
- [ ] **Step 7: Commit** — `git commit -m "feat(assets): Table primitive with sort+pagination, skeleton, scan toast"`

### Task 4: vulns-view — Table + sort + pagination + selection→bulk-triage + skeleton + triage toasts + tooltips

**Files:**
- Modify: `web/src/components/vulns-view.tsx`

**Interfaces:**
- Consumes: `Table`, `Column`, `SortState`, `Pagination`, `Checkbox` (via Table selection), `useToast`, `SkeletonTable`, `Tooltip`, `Badge` from `@/components/ui`.

- [ ] **Step 1: Replace the hand-rolled CVE `<table>`** with `<Table>` (compact density), Column set matching current (CVE, CVSS numeric, EPSS numeric, KEV, affected-count…), `render` preserving badges/links (the ButtonLink from TP1 stays).
- [ ] **Step 2: Sort** on CVSS/EPSS/affected-count (numeric) and CVE id (string); KEV-first default preserved as the initial sort or a secondary order.
- [ ] **Step 3: Pagination** for the CVE list (e.g. 50/page), reset on filter change.
- [ ] **Step 4: Row selection → bulk triage.** Use the `Table` `selection`/`onSelectionChange` (Set of CVE ids or affected keys) to drive the existing `setFindingsBulk` flow; keep `BulkTriage` controls but source the target set from the table selection.
- [ ] **Step 5: Triage toasts.** `setFinding` (single) and `setFindingsBulk` success → `toast({title:"Triage saved", tone:"ok"})`; failures → danger toast. Replaces the current silent save.
- [ ] **Step 6: Skeleton + tooltips.** Generic `LoadingState` → shaped skeleton. Replace this view's informational native `title=` (confidence/severity hints) with `<Tooltip content=…>`.
- [ ] **Step 7: Verify.** `npm run build && npm run lint && npm test` clean; hex CLEAN. Sort/pagination/selection/bulk-triage/toasts all work; drawer still opens.
- [ ] **Step 8: Commit** — `git commit -m "feat(vulns): Table with sort+pagination+selection bulk-triage, toasts, skeleton, tooltips"`

### Task 5: risk-view — Table + sort + skeleton + tooltips

**Files:**
- Modify: `web/src/components/risk-view.tsx`

**Interfaces:**
- Consumes: `Table`, `Column`, `SortState`, `useToast` (if needed), `SkeletonTable`, `Tooltip`, `RiskBadge` from `@/components/ui`.

- [ ] **Step 1: Replace the hand-rolled top-risk `<table>`** with `<Table>` (compact), columns matching (asset, risk bar+badge via `render`, drivers…), preserve the inline risk bar and drawer-open.
- [ ] **Step 2: Sort** by risk score (numeric, default desc) and asset name.
- [ ] **Step 3: Skeleton** replacing generic `LoadingState`; if the events feed errors independently, show its own error/empty.
- [ ] **Step 4: Tooltips** for the risk-explanation / chevron-direction informational `title=`.
- [ ] **Step 5: Verify.** `npm run build && npm run lint && npm test` clean; hex CLEAN.
- [ ] **Step 6: Commit** — `git commit -m "feat(risk): Table with sort, skeleton, tooltips"`

### Task 6: reports-view — Table(s) + sort + skeleton + tooltips

**Files:**
- Modify: `web/src/components/reports-view.tsx`

**Interfaces:**
- Consumes: `Table`, `Column`, `SortState`, `SkeletonTable`, `Tooltip` from `@/components/ui`.

- [ ] **Step 1: Replace the hand-rolled top-10-assets and top-10-CVEs `<table>`s** with `<Table>` (compact), columns matching current (mono IPs, CVSS/EPSS, KEV-first). Print CSS (`#report-print`, `.no-print`) must still work — keep the printable wrapper; the `Table` markup is plain `<table>` so it prints fine.
- [ ] **Step 2: Sort** the two tables (risk / CVSS-EPSS-KEV) where it adds value; KEV-first preserved as default.
- [ ] **Step 3: Skeleton** replacing generic `LoadingState`.
- [ ] **Step 4: Tooltips** for the metric/info `title=` hints.
- [ ] **Step 5: Verify.** `npm run build && npm run lint && npm test` clean; hex CLEAN; print layout unaffected (the `@media print` rules still target `#report-print`).
- [ ] **Step 6: Commit** — `git commit -m "feat(reports): Table primitive, sort, skeleton, tooltips (print preserved)"`

### Task 7: Tooltip for remaining informational hints

**Files:**
- Modify: `web/src/components/asset-drawer.tsx`, `web/src/components/risk-badge.tsx`, `web/src/components/overview.tsx`, `web/src/components/data-sources.tsx`, `web/src/components/activity-feed.tsx`, `web/src/components/policy-view.tsx`

**Interfaces:**
- Consumes: `Tooltip` from `@/components/ui`.

- [ ] **Step 1: Replace informational `title=`** (confidence labels, KEV/EPSS explanations, metric hints, data-source status hints, activity-event detail, policy hints) with `<Tooltip content=…>` wrapping the existing focusable/hoverable element. The Tooltip child must be focusable (wrap a `<span tabIndex={0}>` or an existing button/badge if the target is non-interactive) so keyboard users get the hint too.
- [ ] **Step 2: Leave decorative/positional `title=`** on the SVG nodes in `graph-view.tsx`/`network-view.tsx` (these are not informational hover content; converting them would clutter the canvas). Do NOT touch those two files.
- [ ] **Step 3: Verify.** `npm run build && npm run lint && npm test` clean; hex CLEAN. Tooltips appear on hover/focus; no `title=` left on the informational targets in the six files above.
- [ ] **Step 4: Commit** — `git commit -m "feat(ui): tooltips for informational hints across views"`

---

## Self-review notes

- **Spec coverage:** ConfirmDialog (T1), toasts (T1,T3,T4 + settings/T1), form a11y (T1,T2), copy-to-clipboard (T1), Table+sort+pagination (T3,T4,T5,T6), selection→bulk (T4), skeletons (T3-T6), Tooltip (T4 self + T5,T6,T7), login Tabs (T2). All acceptance items mapped.
- **Conflict avoidance:** each task owns distinct files; T7's six files are disjoint from T3-T6's. No two tasks edit the same file.
- **Verification reality:** feature views have no unit tests; tasks verify via build+lint+hex+the TP1 suite staying green. The only place a unit test is warranted is if a sort comparator is extracted as pure logic — optional, noted in T3.
- **Deferred (TP3), not missed:** mobile card layouts, Menu wiring, breadcrumb, command palette, dashboard story, dark mode.
