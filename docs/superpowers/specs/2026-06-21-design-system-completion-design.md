# Design System Completion (TP1) — Design Spec

**Date:** 2026-06-21
**Status:** Draft — awaiting user review
**Scope:** Sub-project 1 of 3 in the "Argus Console — SaaS-level finalization" program.

## Program context

Finalizing the Argus web console to SaaS level was decomposed into three
sequenced sub-projects (each gets its own spec → plan → implementation):

1. **TP1 — Design-system completion** (this spec). Foundation: the missing
   primitives. Prerequisite for the other two.
2. **TP2 — UX/flow completeness.** Wire primitives into flows: confirmations,
   toasts, validation, all states per view, table sorting/pagination, mobile.
3. **TP3 — Visual/product polish.** Command palette, dashboard story, data-viz
   interactivity, density tuning, micro-interactions, optional dark mode.

The order is dependency-driven: screens cannot be polished (TP3) or flows
completed (TP2) on hand-rolled provisional chrome — the primitives (TP1) must
exist first.

**Benchmark:** Linear-level calm/polish + Datadog-level information density.
Concretely: compact data surfaces (dense tables, sticky headers) without visual
noise; restrained typography and spacing; subtle, purposeful micro-interactions.

## Current state (audit summary, 2026-06-21)

Verified by reading the codebase, not assumed:

- **Strong foundation.** Token discipline near-perfect (exactly one hex
  violation: `argus-mark.tsx:32`). Primitive discipline good in shell/dashboard,
  ~6 hand-rolled spots in data views. A11y basics present (focus trap, ARIA,
  documented contrasts). Roadmap honestly labeled.
- **Design system ~40% complete.** ~12 standard primitives missing.
- **One safety defect.** Destructive actions (delete webhook, revoke API key in
  settings) have no confirmation — a misclick destroys credentials. Fixed in TP2,
  but TP1 delivers the `ConfirmDialog` primitive it depends on.
- **Screens functional but not top-tier** (generic loading states, silent state
  changes, tables break on mobile) — addressed in TP2/TP3, out of scope here.

Overall grade: **C+** — good foundation, substantial gaps.

## Goal

Bring `src/components/ui` from ~40% to feature-complete for the app's *current*
needs, so TP2/TP3 build exclusively on primitives. Every primitive added here
has a concrete present-day consumer (no speculative components).

## Scope

### In scope — 11 primitives

Each has a real consumer identified in the audit:

| # | Primitive | Concrete consumer (today) |
|---|-----------|---------------------------|
| 1 | `Modal` / `ConfirmDialog` | Destructive actions in settings (the safety defect) |
| 2 | `Toast` (+ provider/hook) | Silent state changes: scan submit, triage save, settings save, bulk apply |
| 3 | `Table` (+ sort, selection) | Settings hand-rolls tables; assets/vulns/risk/reports tables |
| 4 | `Tooltip` | Replaces native `title` misuse (confidence hints, invisible on touch) |
| 5 | `Tabs` | Login hand-rolls a tab switcher |
| 6 | `Textarea` | Triage notes misuse `Input` |
| 7 | `Menu` / `Dropdown` | Row actions; topbar user menu |
| 8 | `Checkbox` / `Radio` | Multi-select filters; table row selection |
| 9 | `Skeleton` | Granular per-shape loading (replaces generic `LoadingState`) |
| 10 | `Pagination` | Long vulns/assets lists |
| 11 | `Link` / `ButtonLink` | CVE/external links (currently raw `<a>`) |

### In scope — supporting work

- **Migrate the 6 hand-rolled spots** to the new primitives (proves them in real
  use): `assets-view` `GroupCard`; `vulns-view` `linkButtonClasses` + `BulkTriage`
  div; `asset-drawer` `VulnSection` + `BusinessContext` labels + Services table.
- **Hex fix:** move the brand gradient (`argus-mark.tsx:32`,
  `from-[#3b82f6] to-[#1e3a8a]`) into `globals.css` tokens.
- **Icons:** add `copy`, `eye`, `eye-off`, `info`, `spinner` to `icon.tsx`.

### Deferred (explicitly NOT in TP1)

- `Combobox`/typeahead, `Breadcrumb`, `DatePicker` → **TP3** (command palette,
  dashboard time-range own these).
- `Avatar`, `Card` variants → **YAGNI**; `Panel`/`StatCard` suffice.
- Wiring confirmations/toasts/validation into actual flows → **TP2** (TP1 only
  delivers the primitives; the safety *fix* lands in TP2).

## Architecture

### File organization

`ui.tsx` (~430 lines) would exceed ~1000 lines with 11 additions — too large.
Split into a directory, grouped by category, with a barrel so imports stay
`@/components/ui`:

```
src/components/ui/
  index.ts        # barrel re-export (public surface)
  layout.tsx      # PageHeader, Panel, StatCard
  controls.tsx    # Button, Input, Select, Textarea, Field, Toggle, Checkbox, Radio, Tabs
  overlays.tsx    # Drawer, Modal, ConfirmDialog, Menu, Tooltip
  feedback.tsx    # FormError, Badge, Toast (+ ToastProvider/useToast), Skeleton
  data.tsx        # Table, Pagination, Link/ButtonLink
  overlay-core.ts # shared: portal, useFocusTrap, useDismiss helpers
```

**Existing primitive signatures are unchanged** — they move files, the public
API (and the `@/components/ui` import path) is identical. This is a pure
reorganization for the consumers.

### Overlay foundation

A shared `overlay-core.ts`:
- **Portal** helper (render into `document.body`).
- **`useFocusTrap`** — extracted from the existing `Drawer` (Tab/Shift+Tab cycle,
  focus-on-open, focus-restore-on-close, body-scroll-lock). `Drawer` is refactored
  to consume it (no behavior change), then `Modal` reuses it.
- **`useDismiss`** — Escape + outside-click.
- **`@floating-ui/react@^0.27`** (verified: peerDep `react >=17`, satisfied by
  19.2.4) for positioned overlays (`Tooltip`, `Menu`): anchor reference,
  `flip`/`shift`/`offset` middleware for viewport collision handling, `autoUpdate`.

`Modal`/`ConfirmDialog` reuse the `Drawer` modal contract (already correct);
they are centered dialogs rather than slide-overs.

### Toast system

- `ToastProvider` mounted once in `src/app/layout.tsx`.
- `useToast()` returns `{ toast(opts) }`.
- Portal-rendered stack (top-right), auto-dismiss with a default timeout, manual
  dismiss, max-visible cap with queueing.
- Announced via `aria-live="polite"` (reuses the `live-region` pattern).

### Theming / benchmark application

- All color via existing tokens. New brand-gradient tokens added to `globals.css`
  (`--color-brand-from`, `--color-brand-to`) so `argus-mark` stops hard-coding hex.
- `Table` ships **Datadog density by default** (compact rows, sticky header,
  optional zebra striping, `tabular-nums` for numeric columns) with a
  `density?: "compact" | "comfortable"` escape hatch — calm Linear typography,
  dense data.

### Next 16 caveat

`web/AGENTS.md`: Next 16 has breaking changes — read `node_modules/next/dist/docs/`
before writing Next-specific code (relevant to portals/layout for the overlay and
toast work).

## Primitive API contracts

Signatures follow the existing typed-prop-object style and become part of the
design contract.

```ts
// overlays.tsx
Modal({ onClose, title, description?, size?: "sm"|"md"|"lg",
        children, footer? })
ConfirmDialog({ open, onConfirm, onCancel, title, body,
                confirmLabel?, tone?: "danger"|"primary", busy? })
Menu({ trigger, items: MenuItem[], align?: "start"|"end" })
//   MenuItem = { label, icon?, onSelect, tone?: "default"|"danger", disabled? }
//              | { separator: true }
Tooltip({ content, side?: "top"|"right"|"bottom"|"left", children })

// feedback.tsx
ToastProvider({ children })
useToast() -> { toast({ title, description?, tone?: "default"|"ok"|"warn"|"danger", duration? }) }
Skeleton({ variant?: "text"|"rect"|"circle", width?, height?, className? })
SkeletonTable({ rows?, cols? })   // composed convenience for table loading

// data.tsx
Table<Row>({ columns: Column<Row>[], rows: Row[], getRowId,
             sort?, onSortChange?, selection?, onSelectionChange?,
             density?: "compact"|"comfortable", empty?, sticky? })
//   Column = { key, header, render?(row), align?, sortable?, width?, numeric? }
Pagination({ page, pageCount, onPageChange, pageSize?, onPageSizeChange? })
Link({ href, external?, icon?, children, ...anchorProps })
ButtonLink(/* Button visual variants, renders <a> */)

// controls.tsx
Textarea(/* native textarea props */ { rows?, ...rest })
Checkbox({ checked, onChange, label?, indeterminate?, disabled? })
Radio({ checked, onChange, label?, name, value, disabled? })

// controls.tsx — tabs (inline control, not an overlay)
Tabs({ tabs: { id, label, icon? }[], active, onChange })
TabPanel({ when, active, children })
```

## Migration map (hand-rolled → primitive)

| File / spot | Replace with |
|-------------|--------------|
| `assets-view.tsx` `GroupCard` | `Button` variant or selectable `Panel` |
| `vulns-view.tsx` `linkButtonClasses` | `ButtonLink` |
| `vulns-view.tsx` `BulkTriage` div | `Panel` + primitives |
| `asset-drawer.tsx` `VulnSection` | `Panel` subsections |
| `asset-drawer.tsx` `BusinessContext` labels | `Field` |
| `asset-drawer.tsx` Services table | `Table` |
| `argus-mark.tsx:32` hex gradient | `globals.css` brand tokens |

## Verification

- **Per primitive:** keyboard operability, correct ARIA roles/states, focus
  management (open/close/restore), and the documented token-only color rule.
- **Overlays:** viewport-edge collision (Floating UI middleware), Escape +
  outside-click dismiss, portal stacking/z-index against the existing `Drawer`.
- **Token discipline:** re-run the hex grep
  (`grep -rnE '#[0-9a-fA-F]{3,6}' src --include=*.tsx --include=*.ts | grep -v globals.css`)
  → must be **0** after the `argus-mark` fix.
- **Build/lint:** `next build` + `eslint` clean. (Rust workspace untouched.)
- **A dev-only `/_ui` gallery route** rendering every primitive in every state,
  for visual QA against the benchmark. Not shipped to the nav.

## Acceptance criteria ("done" for TP1)

1. All 11 primitives exist in `src/components/ui/`, exported via the barrel,
   consumed via `@/components/ui`.
2. The 6 hand-rolled spots are migrated to primitives; the hex grep returns 0.
3. The 5 icons are added.
4. `next build` and `eslint` pass; existing primitive signatures unchanged.
5. The `/_ui` gallery renders every primitive/state without error.
6. No flow wiring beyond what migration requires (confirmations/toasts in actual
   destructive/async flows are TP2).

## Out of scope

- TP2 (flow completeness, the safety *fix*, validation, mobile tables).
- TP3 (command palette, dashboard story, data-viz interactivity, dark mode).
- Any Rust/backend change.
