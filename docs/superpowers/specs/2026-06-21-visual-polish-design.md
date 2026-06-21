# Visual / Product Polish (TP3) — Design Spec

**Date:** 2026-06-21
**Status:** Approved (blanket "mach alles" delegation; dark-mode confirmed yes) — proceeding to plan
**Scope:** Sub-project 3 of 3 — the final SaaS-feel pass.

## Program context

TP1 (design system) + TP2 (flow completeness) are merged. TP3 is the visible
"top SaaS" elevation. Benchmark: Linear calm + Datadog density.

## Honest constraints (from recon — no hand-waving)

- **The API exposes NO time-series / history.** `Summary` is
  `{total_assets, internet_facing, critical_or_high, avg_risk}`; assets/CVEs are
  current-state snapshots. Therefore **TP3 ships NO synthetic trends, sparklines,
  or up/down deltas** — fabricating them would be lying with the UI. The
  dashboard "story" is built from data that actually exists: drill-down,
  top-critical-issues, and the real **change events** already produced by the
  monitoring diff (`services.changed`/`vulns.changed`/`risk.changed`). A
  time-range selector is likewise deferred (nothing to range over).
- **Token discipline is the dark-mode lever.** Every view consumes tokens only
  (hex grep = 0, enforced). So dark mode = define a `.dark` token override; the
  whole app re-themes automatically. The careful part is choosing dark values
  with correct contrast (esp. the risk-semantic colors, which were tuned for
  4.5:1 on white and need dark-surface equivalents).

## Scope — in

1. **Dark mode.** Add a `.dark` token override block in `globals.css` (dark
   values for every `--color-*`, incl. risk semantics with dark-surface
   contrast). Enable Tailwind v4's dark variant. A theme toggle (light / dark /
   system) in the topbar; persist to `localStorage`; respect
   `prefers-color-scheme`; a tiny inline script in `layout.tsx` sets the class
   before paint (no flash-of-wrong-theme). The deep-navy sidebar stays dark in
   both themes (it already is).
2. **Command palette (Cmd+K).** A global modal command palette (built on `Modal`
   + a filterable input + keyboard-navigable list): jump to any route, run key
   actions (start scan, toggle theme), and list a few recent assets if cheap.
   Mounted at app-shell level; opens on Cmd/Ctrl+K and a topbar affordance.
   Client-side filter only (no backend search dependency).
3. **Dashboard story (overview).** KPI stat-cards become drill-down links
   (clicking "Internet-facing" → assets filtered to internet-facing, etc.); add
   a "Top critical issues" panel (highest-risk assets + KEV CVEs, each linking
   to its drawer/filter); surface recent **change events** prominently. No fake
   trends (see constraints).
4. **Data-viz interactivity.** Graph + network views: search-to-highlight (type
   an IP/hostname → matching node highlights/centers), filter by risk band and
   asset type, layer toggles (e.g. hide unscanned / hide info-risk). Client-side.
5. **Whole-row click + micro-interaction polish.** Add an optional
   `onRowClick?(row)` to the `Table` primitive (keyboard-accessible row: role +
   tabindex + Enter/Space) so the data tables are fully row-clickable (TP2 used
   name-cell buttons); apply to assets/vulns/risk. Migrate the topbar's
   hand-rolled account menu to the `Menu` primitive. A consistency pass on
   spacing/transitions where it's visibly off.

## Scope — deferred / cut (YAGNI, stated)

- **Trends/sparklines/deltas, time-range selector, DatePicker** — no backing
  data; cut until the API exposes history (a separate backend project).
- **Breadcrumbs** — the nav is flat and the sidebar shows the active section;
  low value, cut.
- **Combobox primitive** — the command palette's bespoke filterable list covers
  the only near-term need; a general Combobox is deferred.

## Architecture

- **Dark mode mechanism:** Tailwind v4 — register the dark variant
  (`@custom-variant dark (&:where(.dark, .dark *));`) and put dark token values
  under a `.dark { --color-…: …; }` block. A `ThemeProvider` (client) manages
  `light|dark|system`, writes `localStorage`, toggles the `.dark` class on
  `<html>`; an inline pre-hydration script in `layout.tsx` applies the stored/
  system theme before first paint.
- **Command palette:** new `command-palette.tsx` (client) using `Modal` +
  `Portal` (already available); a registry of commands (label, group, icon,
  action); arrow-key navigation + Enter; mounted once in `app-shell`.
- **Table `onRowClick`:** extend the existing `Table` primitive — when provided,
  each `<tr>` gets `role="button"` semantics via a focusable/keyboard handler
  (Enter/Space), `cursor-pointer`, hover affordance; selection-checkbox clicks
  must `stopPropagation` so they don't trigger row-click. Backward-compatible
  (absent `onRowClick` = current behavior). The 3 views drop their name-cell
  buttons in favor of row-click.
- **No new color hex** — all dark values are tokens in `globals.css`. Hex grep
  stays 0 for `src/**` (globals.css is exempt, as always).
- **Next 16 caveat** (`web/AGENTS.md`): read `node_modules/next/dist/docs/`
  before Next-specific code (the layout inline-script + metadata).

## Verification

- `npm test` green (extend where pure logic is added — Table `onRowClick`
  keyboard handler, command-palette filter, theme reducer warrant focused tests).
- `npm run build` + `npm run lint` clean; hex grep = 0 in `src/**`.
- Manual: toggle dark/light/system with no flash; Cmd+K opens/filters/navigates;
  dashboard KPIs drill down; graph/network search+filter+layers work; tables are
  whole-row clickable with keyboard; account menu via Menu primitive.

## Acceptance criteria ("done" for TP3)

1. Dark mode works across every view (token-driven), persists, respects system
   pref, no flash; toggle in the topbar; risk colors legible on dark surfaces.
2. Cmd/Ctrl+K opens a command palette that navigates routes + runs key actions,
   keyboard-navigable.
3. Overview KPIs drill down to filtered views; a top-critical-issues panel and
   recent change events are present; NO fabricated trends.
4. Graph + network support search-to-highlight, risk/type filters, layer toggles.
5. `Table` supports keyboard-accessible `onRowClick`; assets/vulns/risk are
   whole-row clickable; topbar account menu uses the `Menu` primitive.
6. `npm test` + `npm run build` + `npm run lint` pass; hex grep = 0 in src.

## Out of scope

- Any backend/Rust change (incl. the history API that real trends would need).
- Combobox, DatePicker, breadcrumbs (cut above).
