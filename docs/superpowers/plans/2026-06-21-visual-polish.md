# Visual / Product Polish (TP3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Checkbox (`- [ ]`) steps.

**Goal:** Final SaaS-feel pass — dark mode, command palette (Cmd+K), dashboard drill-down + top-issues, data-viz interactivity, whole-row click + account-menu polish. No fabricated trends (no time-series data exists).

**Architecture:** Token-driven dark mode (`.dark` override + Tailwind v4 dark variant + ThemeProvider + no-flash inline script). New `command-palette.tsx` on `Modal`. `Table` gains keyboard-accessible `onRowClick`. Each task owns distinct files (no conflicts). Verification: `npm test` (focused tests for new pure logic) + `npm run build` + `npm run lint` + hex grep = 0 in src.

**Tech Stack:** Next 16.2.7, React 19.2.4, Tailwind v4, TS 5, `@/components/ui` (Modal, Portal, Menu, Table, Icon, useToast).

## Global Constraints

- React 19.2.4 / Next 16.2.7 / Tailwind v4 / TS 5 — unchanged.
- **Color only via tokens.** Dark values live in `globals.css` (`.dark { … }`). Hex grep on `src/**` (excluding globals.css) must stay 0.
- **No fabricated trends/sparklines/deltas** — the API has no history. Dashboard uses drill-down, top-issues, and real change events only.
- **Backward-compatible primitive changes** — `Table` `onRowClick` is optional; absent = current behavior.
- Sidebar stays dark in both themes.
- Next 16: read `node_modules/next/dist/docs/` before the layout inline-script / metadata.
- All work under `web/`. Rust untouched.

---

### Task 1: Dark mode + topbar (theme toggle + account-menu → Menu)

**Files:**
- Modify: `web/src/app/globals.css` (`.dark` token block + dark variant)
- Create: `web/src/components/theme.tsx` (ThemeProvider + useTheme + ThemeToggle)
- Modify: `web/src/app/layout.tsx` (no-flash inline script + mount ThemeProvider)
- Modify: `web/src/components/topbar.tsx` (theme toggle; migrate hand-rolled account menu to `Menu` primitive)
- Test: `web/src/components/ui/__tests__/theme.test.tsx`

**Interfaces:**
- Produces: `ThemeProvider`, `useTheme(): {theme:"light"|"dark"|"system", resolved:"light"|"dark", setTheme(t)}`, `ThemeToggle`.

- [ ] **Step 1: Register the dark variant + dark tokens in globals.css.** After `@import "tailwindcss";` add `@custom-variant dark (&:where(.dark, .dark *));`. Add a `.dark { --color-bg: …; --color-surface: …; --color-surface-2: …; --color-line: …; --color-line-strong: …; --color-fg: …; --color-fg-2: …; --color-muted: …; --color-faint: …; --color-accent: …; --color-accent-2: …; --color-accent-soft: …; --color-ok: …; --color-warn: …; --color-crit: …; --color-high: …; --color-med: …; --color-low: …; --color-info: …; }` block with dark-surface values (dark canvas ~#0b1220, surface ~#121a2b, raised borders, light fg, and risk colors brightened so small text passes ~4.5:1 on the dark surface). Keep the `@theme` light block as the default.
- [ ] **Step 2: Write `theme.tsx`.** `ThemeProvider` holds `theme` (light|dark|system) from `localStorage` ("argus-theme") defaulting to "system"; computes `resolved` via `matchMedia("(prefers-color-scheme: dark)")`; on change toggles `document.documentElement.classList` `.dark` and persists; listens to the media query while in system mode. `useTheme()` exposes it. `ThemeToggle` is a `Menu` (or 3-state button) cycling light/dark/system with the `sun`/`moon`/`monitor`-style icon (reuse existing icons or add minimal ones if needed — if adding, keep hex 0).
- [ ] **Step 3: No-flash script + provider in `layout.tsx`.** Add an inline `<script>` in `<head>` (or before `<body>` children) that reads `localStorage["argus-theme"]` (or system) and sets `document.documentElement.classList.add("dark")` synchronously before paint. Wrap the app in `<ThemeProvider>` (inside or around the existing providers). Read the Next 16 layout docs first if the structure differs.
- [ ] **Step 4: Topbar — theme toggle + Menu.** Add the `ThemeToggle` to the topbar. Replace the hand-rolled `menuOpen`/`menuRef`/outside-click account dropdown with the `Menu` primitive (items: account email/role display, theme toggle if not separate, logout). Preserve logout behavior.
- [ ] **Step 5: Test the theme reducer.** `theme.test.tsx`: render `ThemeProvider` + a consumer; assert `setTheme("dark")` adds `.dark` to `document.documentElement` and writes localStorage; `setTheme("light")` removes it.
- [ ] **Step 6: Verify.** `cd web && npm test` (theme test + suite green) + `npm run build` + `npm run lint` clean; hex grep src = 0. Manually: toggle persists, no flash, sidebar stays dark, risk colors legible in dark.
- [ ] **Step 7: Commit** — `git commit -m "feat(ui): dark mode (token-driven, no-flash, persisted) + topbar Menu"`

### Task 2: Command palette (Cmd+K)

**Files:**
- Create: `web/src/components/command-palette.tsx`
- Modify: `web/src/components/app-shell.tsx` (mount + global hotkey)
- Test: `web/src/components/ui/__tests__/command-palette.test.tsx`

**Interfaces:**
- Produces: `CommandPalette` (self-contained: own open state via a hotkey hook, or controlled by app-shell).

- [ ] **Step 1: Write the failing filter test.** `command-palette.test.tsx`: render the palette open; type "vuln"; assert only matching command(s) shown; ArrowDown+Enter triggers the selected command's action (mock router.push).
- [ ] **Step 2: Run, expect fail.**
- [ ] **Step 3: Implement `command-palette.tsx`.** Built on `Modal` (centered) + a text `Input` + a keyboard-navigable list (`role="listbox"`/`option`, arrow keys move active index, Enter runs it, Esc closes via Modal). A command registry: all routes (Overview/Assets/Vulns/Risk/Network/Graph/Policy/Reports/Settings) + actions (Start scan → navigate assets & focus scan, Toggle theme via `useTheme`). Client-side substring/fuzzy filter on label+group. Grouped display.
- [ ] **Step 4: Mount + hotkey in `app-shell.tsx`.** A window `keydown` for (Cmd|Ctrl)+K toggles open (preventDefault); render `<CommandPalette open onClose/>`. Ensure it doesn't fire inside text inputs unintentionally (Cmd+K is safe).
- [ ] **Step 5: Run test green.**
- [ ] **Step 6: Verify.** build + lint + test clean; hex 0. Manually: Cmd+K opens, filter works, Enter navigates, Esc closes, works in dark mode.
- [ ] **Step 7: Commit** — `git commit -m "feat(ui): Cmd+K command palette (route nav + actions)"`

### Task 3: Dashboard story (overview)

**Files:**
- Modify: `web/src/components/overview.tsx`

**Interfaces:**
- Consumes: existing data hooks, `StatCard`/`Panel`/`Link`/`RiskBadge`, `useRouter`.

- [ ] **Step 1: KPI drill-down.** Make each `StatCard` a link/clickable: "Internet-facing" → `/assets?exposure=internet_facing` (or the existing filter mechanism), "Critical/High" → `/assets` filtered to high risk (or `/vulns`), "Total assets" → `/assets`. Use the app's existing query-param filter convention (check assets-view's `urlQ`/filter handling) so the target view actually applies the filter.
- [ ] **Step 2: Top critical issues panel.** Add a `Panel title="Top critical issues"`: top N highest-risk assets (link each to its drawer/assets) + top N KEV/high-CVSS CVEs (link to vulns). Reuse the existing data already loaded by overview (or the same hooks risk/vulns views use).
- [ ] **Step 3: Surface recent change events.** Ensure the existing activity/change-events feed is prominent (it already exists via activity-feed) — wire it as a dashboard panel if not already, showing real `services.changed`/`vulns.changed`/`risk.changed` events.
- [ ] **Step 4: NO fabricated trends.** Do not add up/down deltas or sparklines — there is no historical data. Keep KPIs as current-state with drill-down.
- [ ] **Step 5: Verify.** build + lint + test clean; hex 0. Manually: KPI clicks navigate to the correctly-filtered view; top-issues link through; dark mode ok.
- [ ] **Step 6: Commit** — `git commit -m "feat(dashboard): KPI drill-down + top-critical-issues + change events (no fake trends)"`

### Task 4: Table whole-row click (primitive) + apply to data views

**Files:**
- Modify: `web/src/components/ui/data.tsx` (`Table` gains `onRowClick`)
- Modify: `web/src/components/assets-view.tsx`, `web/src/components/vulns-view.tsx`, `web/src/components/risk-view.tsx`
- Test: `web/src/components/ui/__tests__/table-rowclick.test.tsx`

**Interfaces:**
- Produces: `Table` `onRowClick?: (row: Row) => void` — when set, each `<tr>` is keyboard-accessible (Enter/Space), `cursor-pointer`, hover affordance; selection-checkbox cell `stopPropagation`s so it doesn't trigger row-click.

- [ ] **Step 1: Failing test.** `table-rowclick.test.tsx`: render a Table with `onRowClick`; click a row → handler called with that row; focus a row + press Enter → handler called; clicking the selection checkbox does NOT call `onRowClick`.
- [ ] **Step 2: Run, expect fail.**
- [ ] **Step 3: Implement in data.tsx.** Add `onRowClick?` to the Table props. When present: each body `<tr>` gets `onClick={() => onRowClick(row)}`, `tabIndex={0}`, `role="button"`, `onKeyDown` (Enter/Space → onRowClick + preventDefault for Space), `cursor-pointer`, and the existing hover class. In the selection checkbox `<td>`, wrap the Checkbox so its click `stopPropagation`s. Absent `onRowClick` = unchanged.
- [ ] **Step 4: Run test green.**
- [ ] **Step 5: Apply to the 3 views.** In assets/vulns/risk views, pass `onRowClick={(row)=>setSelectedId(row.id)}` (the drawer open) and revert the name cell from a `<button>` back to plain text (the whole row is now the click target). Keep all other behavior.
- [ ] **Step 6: Verify.** build + lint + test clean; hex 0. Manually: whole row opens the drawer; keyboard Enter on a focused row works; checkbox still selects without opening the drawer.
- [ ] **Step 7: Commit** — `git commit -m "feat(ui): Table onRowClick (keyboard-accessible); whole-row drawer open in data views"`

### Task 5: Graph-view interactivity

**Files:**
- Modify: `web/src/components/graph-view.tsx`

**Interfaces:**
- Consumes: `Input`/`Select`/`Checkbox`/`Button` from `@/components/ui`.

- [ ] **Step 1: Search-to-highlight.** Add a search `Input` (`.no-…` not needed) that, on match against node IP/hostname/type, highlights matching node(s) (e.g. ring/scale) and optionally centers/pans to the first match. Non-matches dim.
- [ ] **Step 2: Filters.** Add risk-band filter (multi via `Checkbox`s or a `Select`) and asset-type filter; nodes not matching are hidden or dimmed. Keep edges consistent.
- [ ] **Step 3: Layer toggles.** Toggles such as "hide unscanned" / "hide info-risk" using `Toggle`/`Checkbox`.
- [ ] **Step 4: Preserve** existing pan/zoom/fit/legend/drawer-on-click. Token classes only.
- [ ] **Step 5: Verify.** build + lint + test clean; hex 0. Manually: search highlights, filters/layers apply, pan/zoom/drawer intact, dark mode ok.
- [ ] **Step 6: Commit** — `git commit -m "feat(graph): search-highlight + risk/type filters + layer toggles"`

### Task 6: Network-view interactivity

**Files:**
- Modify: `web/src/components/network-view.tsx`

**Interfaces:**
- Consumes: `Input`/`Select`/`Checkbox` from `@/components/ui`.

- [ ] **Step 1: Search.** Add a search `Input` filtering host cards by IP/hostname/type (live).
- [ ] **Step 2: Filters.** Risk-band + asset-type filters (hide non-matching host cards; keep subnet grouping consistent — hide empty subnets).
- [ ] **Step 3: Preserve** subnet grouping, RiskBadge per subnet, drawer-on-click, legend. Token classes only.
- [ ] **Step 4: Verify.** build + lint + test clean; hex 0. Manually: search + filters work, grouping intact, drawer opens, dark mode ok.
- [ ] **Step 5: Commit** — `git commit -m "feat(network): search + risk/type filters"`

---

## Self-review notes

- **Spec coverage:** dark mode + topbar Menu (T1), command palette (T2), dashboard drill-down/top-issues/changes (T3), Table onRowClick + apply (T4), graph interactivity (T5), network interactivity (T6). Honest no-trends honored in T3 Step 4.
- **Conflict avoidance:** T1 owns globals/layout/topbar/theme; T2 owns command-palette/app-shell; T3 overview; T4 data.tsx + 3 views; T5 graph; T6 network. No file edited by two tasks.
- **Tests:** focused tests for the three pure-logic additions (theme reducer, command-palette filter+keyboard, Table onRowClick keyboard). View interactivity (graph/network/overview) verified via build+lint+manual (no view harness).
- **Cut, stated:** trends/sparklines/time-range/DatePicker (no data), breadcrumbs (flat nav), general Combobox (palette covers it).
