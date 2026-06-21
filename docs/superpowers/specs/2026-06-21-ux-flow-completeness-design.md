# UX/Flow Completeness (TP2) — Design Spec

**Date:** 2026-06-21
**Status:** Approved (blanket "mach alles weiter" delegation) — proceeding to plan
**Scope:** Sub-project 2 of 3 in the "Argus Console — SaaS-level finalization" program.

## Program context

TP1 (design-system completion) is merged. It delivered the 11 primitives but
deliberately did NOT wire confirmations/toasts/validation into real flows. TP2
does exactly that: make every screen functionally complete by consuming the TP1
primitives. TP3 (visual polish + dark mode) follows.

**Benchmark:** Linear calm + Datadog density.

## Current state (recon, 2026-06-21, post-TP1)

- **Destructive actions have no confirmation** — `settings/page.tsx:345`
  `deleteWebhook()` (via `remove()` at :409) and `:494` `deleteApiKey(id)` (via
  `revokeKey()` at :668 "Revoke"). A misclick destroys credentials.
- **5 hand-rolled `<table>`** — `vulns-view`, `reports-view`, `risk-view`,
  `assets-view`, `settings/page.tsx` — none use the TP1 `Table` primitive; no
  sort, no pagination, loose density.
- **Silent state changes** — settings shows inline "Saved." text only
  (`:252,:414`); vulns triage (`setFinding`/`setFindingsBulk`) and assets scan
  submit give no confirmation.
- **Generic `LoadingState`** used in all data views — does not match page shape.
- **Login tabs hand-rolled** — `login/page.tsx:45` `tab()` helper with
  `aria-pressed`, not the `Tabs` primitive.
- **Native `title=` hints** across 12 files — informational ones (confidence,
  risk) should be `Tooltip`; decorative/SVG-node ones stay.
- **Forms lack `aria-invalid`/`aria-describedby`** linking `FormError` to inputs.

## Goal

Wire TP1 primitives into the feature views so every screen has: confirmations on
destructive actions, toast feedback on async actions, accessible form validation,
sortable/paginated data tables on the `Table` primitive, shape-matched loading
skeletons, and tooltips for informational hints. No new primitives.

## Scope — in

1. **Safety: ConfirmDialog on destructive actions.** Wire `ConfirmDialog`
   (tone="danger", `busy` during the call) into webhook delete (`remove()`) and
   API-key revoke (`revokeKey()`). No deletion fires until confirmed.
2. **Toast feedback.** `ToastProvider` is already mounted at root (TP1). Add
   `useToast()` success/error toasts to: settings (monitoring save, webhook
   save/delete, key create/revoke), vulns triage (`setFinding` +
   `setFindingsBulk`), assets scan submit. Inline "Saved." text is replaced by a
   toast (single feedback channel).
3. **Accessible form validation.** Link `FormError` to inputs via `aria-invalid`
   + `aria-describedby` on login + settings forms; mark required fields. When the
   API returns a field-specific error, surface it at the field; otherwise
   form-level but correctly associated.
4. **Copy-to-clipboard.** Webhook secret + freshly-created API-key plaintext get
   a copy button (the `copy` icon) that writes to clipboard and fires a "Copied"
   toast.
5. **Table migration + sort + pagination.** Replace the hand-rolled `<table>` in
   `assets-view`, `vulns-view`, `risk-view`, `reports-view` with the `Table`
   primitive (compact/Datadog density). Add column sort where meaningful
   (risk, CVSS, EPSS, name, last-seen). Add `Pagination` for the long lists
   (assets, vulns). Selection (checkbox column) where a bulk action exists
   (vulns bulk-triage).
6. **Granular skeletons.** Replace generic `LoadingState` in the data views with
   `SkeletonTable`/`Skeleton` shaped to each view (e.g. stat-card row +
   skeleton-table). Keep `LoadingState` only where a generic block is fine.
7. **Tooltip for informational hints.** Replace informational native `title=`
   (confidence labels in `asset-drawer`/`risk-badge`/`vulns-view`, and the
   metric/info hints in `overview`/`reports`/`risk`) with the `Tooltip`
   primitive. Leave decorative/positional `title=` on SVG nodes in
   `graph-view`/`network-view` (not informational hover content).
8. **Login tabs → `Tabs` primitive.** Replace the hand-rolled `tab()` switcher
   with `Tabs`/`TabPanel`, preserving the login/register flow.

## Scope — deferred to TP3 (not TP2)

- Mobile **card layouts** for tables — the `Table` primitive already scrolls
  (`overflow-x-auto`), which is acceptable for TP2; card layouts are polish.
- **Menu** wiring (topbar user menu, row-action menus), **breadcrumbs**,
  **command palette**, **dashboard story/trends/drill-down**, data-viz
  interactivity, density tuning, **dark mode** — all TP3.

## Architecture

- **No new primitives.** Pure consumption of the TP1 `@/components/ui` barrel
  into feature views. `ToastProvider` already wraps the app (TP1, root layout).
- **Token discipline preserved.** Hex grep must stay 0.
- **Behavior-preserving where it's a refactor** (table migration must keep the
  same data, handlers, drawer-open behavior) — only the chrome and the added
  sort/pagination/feedback change.
- **Clipboard:** `navigator.clipboard.writeText` guarded for unavailability;
  failure path toasts an error rather than throwing.
- **Next 16 caveat** (`web/AGENTS.md`): read `node_modules/next/dist/docs/`
  before Next-specific code.

## Verification

- `npm test` — TP1 primitive suite stays green; add focused tests where feasible
  for new pure logic (e.g. a sort comparator), but feature-view wiring is
  verified via build + lint + careful reading (no view unit-test harness exists).
- `npm run build` + `npm run lint` clean.
- Hex grep returns 0.
- Manual acceptance walk of each changed view's states.

## Acceptance criteria ("done" for TP2)

1. Webhook delete + API-key revoke both require `ConfirmDialog` confirmation.
2. Settings saves, webhook/key mutations, vulns triage (single + bulk), and
   assets scan submit all produce a toast (success and error paths).
3. Login + settings forms wire `aria-invalid`/`aria-describedby` to `FormError`.
4. Webhook secret + new API key have working copy-to-clipboard + "Copied" toast.
5. `assets/vulns/risk/reports` tables use the `Table` primitive; assets + vulns
   have sort + pagination; vulns has row-selection driving bulk-triage.
6. Data views use shape-matched skeletons (no bare generic `LoadingState` in the
   data views).
7. Login uses the `Tabs` primitive; informational `title=` hints use `Tooltip`.
8. `npm test` + `npm run build` + `npm run lint` pass; hex grep = 0.

## Out of scope

- All TP3 items (above).
- Any Rust/backend change.
