# Design System Completion (TP1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the 11 missing UI primitives to the Argus web console on a Floating-UI hybrid overlay foundation, migrate the 6 hand-rolled spots onto them, and remove the last hex violation — so TP2/TP3 build exclusively on primitives.

**Architecture:** Split `ui.tsx` into a categorized `src/components/ui/` directory behind a barrel (import path stays `@/components/ui`). A shared `overlay-core.ts` (portal + focus-trap extracted from the existing `Drawer` + dismiss) backs `Modal`/`ConfirmDialog`; `@floating-ui/react` positions `Tooltip`/`Menu`. A `ToastProvider` in the root layout exposes `useToast()`. Tests use Vitest + React Testing Library (added here; the frontend had none).

**Tech Stack:** Next 16.2.7 (app router), React 19.2.4, Tailwind v4, TypeScript 5, `@floating-ui/react` ^0.27, Vitest + @testing-library/react + jsdom.

## Global Constraints

- React 19.2.4 / Next 16.2.7 / Tailwind v4 / TypeScript 5 — do not change these versions.
- **Color only via tokens** (Tailwind utilities: `bg-surface`, `text-muted`, `border-line`, `text-crit`, …). Zero raw hex outside `globals.css`. Verified by: `grep -rnE '#[0-9a-fA-F]{3,6}' src --include=*.tsx --include=*.ts | grep -v globals.css` → must return nothing.
- **No hand-rolled chrome** in feature code — buttons/inputs/panels/overlays come from `@/components/ui`.
- **Existing primitive signatures are unchanged.** Moving them between files is allowed; their public API and the `@/components/ui` import path are identical.
- Positioned overlays (`Tooltip`, `Menu`) use `@floating-ui/react` only — no broader component library.
- **Next 16 caveat** (`web/AGENTS.md`): Next 16 has breaking changes — read `node_modules/next/dist/docs/` before writing Next-specific code (portals, layout, route segment config).
- Gallery route is `/dev/ui` (a `_ui` folder would be a Next *private* folder and would not route).
- All work is under `web/`. The Rust workspace is untouched.
- Icons are decorative; the accessible name lives on the surrounding control (existing `icon.tsx` contract).

---

## Phase A — Foundation

### Task 1: Test foundation (Vitest + RTL)

**Files:**
- Modify: `web/package.json` (add devDeps + scripts)
- Create: `web/vitest.config.ts`
- Create: `web/vitest.setup.ts`
- Test: `web/src/components/ui/__tests__/smoke.test.tsx`

**Interfaces:**
- Consumes: nothing.
- Produces: `npm test` (runs `vitest run`), jsdom env, `@testing-library/jest-dom` matchers, `@/` alias resolution in tests.

- [ ] **Step 1: Install dev dependencies**

```bash
cd web
npm i -D vitest@^3 jsdom@^25 @testing-library/react@^16 @testing-library/user-event@^14 @testing-library/jest-dom@^6 @vitejs/plugin-react@^4
```

- [ ] **Step 2: Add scripts to package.json**

In `web/package.json` `"scripts"`, add:

```json
"test": "vitest run",
"test:watch": "vitest"
```

- [ ] **Step 3: Write vitest.config.ts**

```ts
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";

export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./vitest.setup.ts"],
  },
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
});
```

- [ ] **Step 4: Write vitest.setup.ts**

```ts
import "@testing-library/jest-dom/vitest";
```

- [ ] **Step 5: Write the smoke test**

```tsx
import { render, screen } from "@testing-library/react";
import { Button } from "@/components/ui";

test("ui barrel renders an existing primitive", () => {
  render(<Button>Save</Button>);
  expect(screen.getByRole("button", { name: "Save" })).toBeInTheDocument();
});
```

(`@/components/ui` currently resolves to the existing `ui.tsx` file, so this passes immediately and keeps passing after Task 3 swaps the file for the `ui/` directory barrel — proving the test foundation against real code now.)

- [ ] **Step 6: Run, expect pass**

Run: `cd web && npm test`
Expected: PASS — `Button` resolves via `@/components/ui` (the existing `ui.tsx`).

- [ ] **Step 7: Commit**

```bash
git add web/package.json web/package-lock.json web/vitest.config.ts web/vitest.setup.ts web/src/components/ui/__tests__/smoke.test.tsx
git commit -m "test: add vitest + react-testing-library frontend test foundation"
```

### Task 2: Add Floating UI dependency

**Files:**
- Modify: `web/package.json`

**Interfaces:**
- Produces: `@floating-ui/react` available for Tooltip (Task 13) and Menu (Task 14).

- [ ] **Step 1: Install**

```bash
cd web && npm i @floating-ui/react@^0.27
```

- [ ] **Step 2: Verify it resolves**

Run: `cd web && node -e "require.resolve('@floating-ui/react'); console.log('ok')"`
Expected: `ok`

- [ ] **Step 3: Commit**

```bash
git add web/package.json web/package-lock.json
git commit -m "build: add @floating-ui/react for positioned overlays"
```

### Task 3: Split ui.tsx into ui/ directory + barrel

**Files:**
- Create: `web/src/components/ui/layout.tsx` (PageHeader, Panel, StatCard — moved verbatim)
- Create: `web/src/components/ui/controls.tsx` (Button, Input, Select, Field, Toggle — moved verbatim)
- Create: `web/src/components/ui/overlays.tsx` (Drawer — moved verbatim for now)
- Create: `web/src/components/ui/feedback.tsx` (FormError, Badge — moved verbatim)
- Create: `web/src/components/ui/index.ts` (barrel)
- Delete: `web/src/components/ui.tsx`
- Modify: any importer using a default/path that breaks (imports were `@/components/ui` — unchanged by the barrel)

**Interfaces:**
- Consumes: existing `ui.tsx` exports.
- Produces: identical public exports via `@/components/ui` (barrel re-exports everything). The shared `cx` helper and `focusRing` constant move to `overlay-core.ts` is deferred to Task 4; for Task 3 keep a local `cx`/`focusRing` in each file or a tiny `ui/internal.ts`.

- [ ] **Step 1: Create `ui/internal.ts` with shared helpers**

```ts
export function cx(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(" ");
}
export const focusRing =
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40";
```

- [ ] **Step 2: Move PageHeader/Panel/StatCard into `layout.tsx`**

Cut those three components from `ui.tsx` into `layout.tsx`, add `"use client";` at top, `import { cx } from "./internal";`. Keep code byte-identical otherwise.

- [ ] **Step 3: Move Button/Input/Select/Field/Toggle into `controls.tsx`**

Cut into `controls.tsx`, `"use client";`, `import { cx, focusRing } from "./internal";`. Identical code.

- [ ] **Step 4: Move Drawer into `overlays.tsx`; FormError/Badge into `feedback.tsx`**

Each gets `"use client";` and the needed `import { cx, focusRing } from "./internal";` and `import { Icon } from "@/components/icon";` (Drawer). Identical code.

- [ ] **Step 5: Write the barrel `index.ts`**

```ts
export * from "./layout";
export * from "./controls";
export * from "./overlays";
export * from "./feedback";
```

- [ ] **Step 6: Delete old file, run build + the smoke test**

```bash
rm web/src/components/ui.tsx
cd web && npm test && npm run build
```
Expected: smoke test PASS; `next build` succeeds (all `@/components/ui` imports resolve through the barrel).

- [ ] **Step 7: Commit**

```bash
git add -A web/src/components/ui web/src/components/ui.tsx
git commit -m "refactor(ui): split ui.tsx into ui/ directory behind a barrel (no API change)"
```

### Task 4: overlay-core.ts (portal, focus trap, dismiss) + Drawer refactor

**Files:**
- Create: `web/src/components/ui/overlay-core.ts`
- Modify: `web/src/components/ui/overlays.tsx` (Drawer consumes the extracted hooks)
- Test: `web/src/components/ui/__tests__/overlay-core.test.tsx`

**Interfaces:**
- Produces:
  - `Portal({ children }: { children: React.ReactNode }): React.ReactPortal | null` — renders into `document.body`, SSR-safe (null until mounted).
  - `useFocusTrap(ref: React.RefObject<HTMLElement | null>, opts?: { initialFocus?: React.RefObject<HTMLElement | null> }): (e: React.KeyboardEvent) => void` — returns an `onKeyDown` trap handler; on mount locks body scroll, focuses `initialFocus` (or first focusable), restores previous focus + scroll on unmount.
  - `useDismiss(onDismiss: () => void): void` — Escape closes (window-level).

- [ ] **Step 1: Write the failing test**

```tsx
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Portal } from "@/components/ui/overlay-core";

test("Portal renders children into document.body", () => {
  render(<Portal><button>inside</button></Portal>);
  const btn = screen.getByRole("button", { name: "inside" });
  expect(btn.closest("body")).toBe(document.body);
});
```

- [ ] **Step 2: Run, expect fail**

Run: `cd web && npm test -- overlay-core`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement overlay-core.ts**

```ts
"use client";
import { useEffect, useState } from "react";
import { createPortal } from "react-dom";

export function Portal({ children }: { children: React.ReactNode }) {
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  return mounted ? createPortal(children, document.body) : null;
}

const SELECTOR =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

export function useFocusTrap(
  ref: React.RefObject<HTMLElement | null>,
  opts?: { initialFocus?: React.RefObject<HTMLElement | null> },
) {
  useEffect(() => {
    const prevFocus =
      document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    (opts?.initialFocus?.current ??
      ref.current?.querySelector<HTMLElement>(SELECTOR))?.focus();
    return () => {
      document.body.style.overflow = prevOverflow;
      prevFocus?.focus();
    };
  }, [ref, opts?.initialFocus]);

  return (e: React.KeyboardEvent) => {
    if (e.key !== "Tab" || !ref.current) return;
    const f = Array.from(ref.current.querySelectorAll<HTMLElement>(SELECTOR));
    if (f.length === 0) return;
    const first = f[0];
    const last = f[f.length - 1];
    const active = document.activeElement;
    if (e.shiftKey) {
      if (active === first || !ref.current.contains(active)) {
        e.preventDefault();
        last.focus();
      }
    } else if (active === last || !ref.current.contains(active)) {
      e.preventDefault();
      first.focus();
    }
  };
}

export function useDismiss(onDismiss: () => void) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onDismiss();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onDismiss]);
}
```

- [ ] **Step 4: Run, expect pass**

Run: `cd web && npm test -- overlay-core`
Expected: PASS.

- [ ] **Step 5: Refactor Drawer to consume the hooks**

In `overlays.tsx` `Drawer`: replace its inline Escape effect with `useDismiss(onClose)`; replace its focus/scroll effect + `trapFocus` with `const trap = useFocusTrap(asideRef, { initialFocus: closeRef });` and `onKeyDown={trap}`. Behavior identical. Keep the rest of the markup.

- [ ] **Step 6: Run build + full tests**

Run: `cd web && npm test && npm run build`
Expected: PASS / success (Drawer behavior unchanged).

- [ ] **Step 7: Commit**

```bash
git add web/src/components/ui/overlay-core.ts web/src/components/ui/overlays.tsx web/src/components/ui/__tests__/overlay-core.test.tsx
git commit -m "feat(ui): extract portal/focus-trap/dismiss into overlay-core; Drawer reuses it"
```

### Task 5: Brand tokens + argus-mark hex fix + 5 icons

**Files:**
- Modify: `web/src/app/globals.css` (add brand-gradient tokens)
- Modify: `web/src/components/argus-mark.tsx:32` (use tokens)
- Modify: `web/src/components/icon.tsx` (add `copy`, `eye`, `eye-off`, `info`, `spinner`)
- Test: `web/src/components/ui/__tests__/icon.test.tsx`

**Interfaces:**
- Produces: `IconName` union extended with `"copy" | "eye" | "eye-off" | "info" | "spinner"`.

- [ ] **Step 1: Add brand tokens to globals.css**

In the `@theme` block under "brand & semantic":

```css
  --color-brand-from: #3b82f6; /* argus mark gradient start */
  --color-brand-to: #1e3a8a; /* argus mark gradient end */
```

- [ ] **Step 2: Replace the hex in argus-mark.tsx:32**

Change `from-[#3b82f6] to-[#1e3a8a]` to `from-[var(--color-brand-from)] to-[var(--color-brand-to)]`.

- [ ] **Step 3: Write the failing icon test**

```tsx
import { render } from "@testing-library/react";
import { Icon } from "@/components/icon";

test.each(["copy", "eye", "eye-off", "info", "spinner"] as const)(
  "renders %s icon as svg",
  (name) => {
    const { container } = render(<Icon name={name} />);
    expect(container.querySelector("svg")).toBeInTheDocument();
  },
);
```

- [ ] **Step 4: Run, expect fail (TS/union + missing cases)**

Run: `cd web && npm test -- icon`
Expected: FAIL — names not in `IconName`.

- [ ] **Step 5: Extend IconName union and add cases**

Add to the union: `| "copy" | "eye" | "eye-off" | "info" | "spinner"`. Add these cases before `default:` (stroke-based, matching the file's style):

```tsx
    case "copy":
      return (
        <svg {...common}>
          <rect x="9" y="9" width="11" height="11" rx="2" />
          <path d="M5 15V5a2 2 0 0 1 2-2h8" />
        </svg>
      );
    case "eye":
      return (
        <svg {...common}>
          <path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Z" />
          <circle cx="12" cy="12" r="3" />
        </svg>
      );
    case "eye-off":
      return (
        <svg {...common}>
          <path d="M4 4l16 16" />
          <path d="M9.6 9.7A3 3 0 0 0 14.3 14.4" />
          <path d="M6.6 6.7C4.2 8.2 2.5 12 2.5 12s3.5 6.5 9.5 6.5c1.6 0 3-.4 4.2-1" />
          <path d="M9.9 5.7A8.7 8.7 0 0 1 12 5.5c6 0 9.5 6.5 9.5 6.5a17 17 0 0 1-2.4 3.1" />
        </svg>
      );
    case "info":
      return (
        <svg {...common}>
          <circle cx="12" cy="12" r="9" />
          <path d="M12 11v5M12 8h.01" />
        </svg>
      );
    case "spinner":
      return (
        <svg {...common} className="argus-spin">
          <path d="M12 3a9 9 0 1 0 9 9" />
        </svg>
      );
```

- [ ] **Step 6: Add the spin keyframe to globals.css**

```css
@keyframes argus-spin { to { transform: rotate(360deg); } }
.argus-spin { animation: argus-spin 0.7s linear infinite; transform-origin: center; }
```

- [ ] **Step 7: Run icon test + hex grep**

Run: `cd web && npm test -- icon`
Expected: PASS.
Run: `cd web && grep -rnE '#[0-9a-fA-F]{3,6}' src --include=*.tsx --include=*.ts | grep -v globals.css || echo CLEAN`
Expected: `CLEAN`.

- [ ] **Step 8: Commit**

```bash
git add web/src/app/globals.css web/src/components/argus-mark.tsx web/src/components/icon.tsx web/src/components/ui/__tests__/icon.test.tsx
git commit -m "feat(ui): brand-gradient tokens (hex grep now 0) + copy/eye/eye-off/info/spinner icons"
```

### Task 6: /dev/ui gallery route skeleton

**Files:**
- Create: `web/src/app/dev/ui/page.tsx`

**Interfaces:**
- Consumes: the barrel `@/components/ui`.
- Produces: a dev-only page that imports and renders primitives; each later primitive task adds its section here for visual QA. Not added to the sidebar nav.

- [ ] **Step 1: Create the gallery page**

```tsx
"use client";
import { PageHeader, Panel, Button } from "@/components/ui";

export default function UiGallery() {
  return (
    <div className="mx-auto max-w-5xl p-8">
      <PageHeader title="UI Gallery" description="Dev-only primitive showcase." />
      <Panel title="Buttons">
        <div className="flex gap-2">
          <Button>Primary</Button>
          <Button variant="secondary">Secondary</Button>
          <Button variant="ghost">Ghost</Button>
          <Button variant="danger">Danger</Button>
        </div>
      </Panel>
    </div>
  );
}
```

- [ ] **Step 2: Verify it builds and routes**

Run: `cd web && npm run build`
Expected: build lists `/dev/ui` as a route.

- [ ] **Step 3: Commit**

```bash
git add web/src/app/dev/ui/page.tsx
git commit -m "chore(ui): add /dev/ui gallery skeleton for primitive QA"
```

---

## Phase B — Primitives

> Each task: write failing RTL test → verify fail → implement in the right `ui/` file → export via barrel (already `export *`) → add a gallery section → verify pass + build → commit. Tests assert DOM/roles/ARIA/behavior, not computed CSS (jsdom has no layout).

### Task 7: Textarea

**Files:**
- Modify: `web/src/components/ui/controls.tsx`
- Test: `web/src/components/ui/__tests__/textarea.test.tsx`

**Interfaces:**
- Produces: `Textarea(props: React.TextareaHTMLAttributes<HTMLTextAreaElement> & { rows?: number }): JSX.Element` — token-styled, shares `controlBase`.

- [ ] **Step 1: Failing test**

```tsx
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Textarea } from "@/components/ui";

test("Textarea accepts input and forwards props", async () => {
  render(<Textarea aria-label="notes" rows={4} />);
  const el = screen.getByLabelText("notes");
  await userEvent.type(el, "hello");
  expect(el).toHaveValue("hello");
});
```

- [ ] **Step 2: Run, expect fail** — `cd web && npm test -- textarea` → FAIL (not exported).

- [ ] **Step 3: Implement in controls.tsx**

```tsx
export function Textarea({
  className,
  rows = 4,
  ...rest
}: React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <textarea
      rows={rows}
      className={cx(
        "w-full rounded-lg border border-line bg-surface px-3 py-2 text-sm text-fg transition-colors placeholder:text-faint focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/20 disabled:cursor-not-allowed disabled:opacity-50",
        className,
      )}
      {...rest}
    />
  );
}
```

- [ ] **Step 4: Run, expect pass.** Add a `<Textarea>` to the gallery.
- [ ] **Step 5: Commit** — `git commit -m "feat(ui): Textarea primitive"`

### Task 8: Checkbox + Radio

**Files:**
- Modify: `web/src/components/ui/controls.tsx`
- Test: `web/src/components/ui/__tests__/checkbox.test.tsx`

**Interfaces:**
- Produces:
  - `Checkbox({ checked, onChange, label?, indeterminate?, disabled? }: { checked: boolean; onChange: (v: boolean) => void; label?: string; indeterminate?: boolean; disabled?: boolean }): JSX.Element`
  - `Radio({ checked, onChange, name, value, label?, disabled? }: { checked: boolean; onChange: (v: string) => void; name: string; value: string; label?: string; disabled?: boolean }): JSX.Element`

- [ ] **Step 1: Failing test**

```tsx
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { Checkbox } from "@/components/ui";

function Harness() {
  const [v, setV] = useState(false);
  return <Checkbox checked={v} onChange={setV} label="Select" />;
}
test("Checkbox toggles via label click and exposes role", async () => {
  render(<Harness />);
  const box = screen.getByRole("checkbox", { name: "Select" });
  expect(box).not.toBeChecked();
  await userEvent.click(screen.getByText("Select"));
  expect(box).toBeChecked();
});
```

- [ ] **Step 2: Run, expect fail.**

- [ ] **Step 3: Implement in controls.tsx**

```tsx
export function Checkbox({
  checked, onChange, label, indeterminate, disabled,
}: {
  checked: boolean; onChange: (v: boolean) => void;
  label?: string; indeterminate?: boolean; disabled?: boolean;
}) {
  const input = (
    <input
      type="checkbox"
      checked={checked}
      disabled={disabled}
      ref={(el) => { if (el) el.indeterminate = Boolean(indeterminate); }}
      onChange={(e) => onChange(e.target.checked)}
      className={cx(
        "h-4 w-4 rounded border-line text-accent accent-accent",
        focusRing,
        disabled && "cursor-not-allowed opacity-50",
      )}
    />
  );
  if (!label) return input;
  return (
    <label className="inline-flex cursor-pointer items-center gap-2 text-sm text-fg-2">
      {input}
      {label}
    </label>
  );
}

export function Radio({
  checked, onChange, name, value, label, disabled,
}: {
  checked: boolean; onChange: (v: string) => void;
  name: string; value: string; label?: string; disabled?: boolean;
}) {
  const input = (
    <input
      type="radio"
      name={name}
      value={value}
      checked={checked}
      disabled={disabled}
      onChange={(e) => onChange(e.target.value)}
      className={cx("h-4 w-4 border-line text-accent accent-accent", focusRing,
        disabled && "cursor-not-allowed opacity-50")}
    />
  );
  if (!label) return input;
  return (
    <label className="inline-flex cursor-pointer items-center gap-2 text-sm text-fg-2">
      {input}
      {label}
    </label>
  );
}
```

- [ ] **Step 4: Run, expect pass.** Add to gallery.
- [ ] **Step 5: Commit** — `git commit -m "feat(ui): Checkbox + Radio primitives"`

### Task 9: Link + ButtonLink

**Files:**
- Modify: `web/src/components/ui/controls.tsx` (ButtonLink, reusing button variants) and `web/src/components/ui/feedback.tsx` is not needed; put `Link` in `controls.tsx` too.
- Test: `web/src/components/ui/__tests__/link.test.tsx`

**Interfaces:**
- Produces:
  - `Link({ href, external?, icon, children, className, ...rest }: { href: string; external?: boolean; icon?: boolean } & React.AnchorHTMLAttributes<HTMLAnchorElement>): JSX.Element` — accent text link; when `external`, adds `target="_blank" rel="noreferrer noopener"` and (if `icon`) a trailing `external` icon.
  - `ButtonLink(props)` — same visual variants/sizes as `Button` but renders an `<a>`. Reuses the exported `buttonVariants`/`buttonSizes` maps (export them from `controls.tsx`).

- [ ] **Step 1: Failing test**

```tsx
import { render, screen } from "@testing-library/react";
import { Link, ButtonLink } from "@/components/ui";

test("external Link is safe and labelled", () => {
  render(<Link href="https://x.test" external>CVE-2024-1</Link>);
  const a = screen.getByRole("link", { name: /CVE-2024-1/ });
  expect(a).toHaveAttribute("target", "_blank");
  expect(a).toHaveAttribute("rel", expect.stringContaining("noopener"));
});

test("ButtonLink renders an anchor styled as a button", () => {
  render(<ButtonLink href="/assets" variant="secondary">Open</ButtonLink>);
  expect(screen.getByRole("link", { name: "Open" })).toHaveAttribute("href", "/assets");
});
```

- [ ] **Step 2: Run, expect fail.**

- [ ] **Step 3: Export the button maps + implement**

In `controls.tsx`, change `const buttonVariants` / `const buttonSizes` to `export const ...`. Then add:

```tsx
import { Icon } from "@/components/icon";

export function Link({
  href, external, icon, children, className, ...rest
}: { href: string; external?: boolean; icon?: boolean } &
   React.AnchorHTMLAttributes<HTMLAnchorElement>) {
  return (
    <a
      href={href}
      className={cx("inline-flex items-center gap-1 text-accent underline-offset-2 hover:underline",
        focusRing, "rounded", className)}
      {...(external ? { target: "_blank", rel: "noreferrer noopener" } : {})}
      {...rest}
    >
      {children}
      {external && icon ? <Icon name="external" size={14} /> : null}
    </a>
  );
}

export function ButtonLink({
  variant = "primary", size = "md", className, ...rest
}: React.AnchorHTMLAttributes<HTMLAnchorElement> & {
  variant?: "primary" | "secondary" | "ghost" | "danger";
  size?: "sm" | "md";
}) {
  return (
    <a
      className={cx(
        "inline-flex items-center justify-center gap-1.5 rounded-lg font-medium transition-colors",
        focusRing, buttonVariants[variant], buttonSizes[size], className,
      )}
      {...rest}
    />
  );
}
```

- [ ] **Step 4: Run, expect pass.** Add to gallery.
- [ ] **Step 5: Commit** — `git commit -m "feat(ui): Link + ButtonLink primitives"`

### Task 10: Skeleton (+ SkeletonTable)

**Files:**
- Modify: `web/src/components/ui/feedback.tsx`
- Test: `web/src/components/ui/__tests__/skeleton.test.tsx`

**Interfaces:**
- Produces:
  - `Skeleton({ variant?, width?, height?, className? }: { variant?: "text" | "rect" | "circle"; width?: number | string; height?: number | string; className?: string }): JSX.Element` — pulse placeholder, `aria-hidden`, `data-testid="skeleton"`.
  - `SkeletonTable({ rows?, cols? }: { rows?: number; cols?: number }): JSX.Element`

- [ ] **Step 1: Failing test**

```tsx
import { render, screen } from "@testing-library/react";
import { Skeleton, SkeletonTable } from "@/components/ui";

test("Skeleton is decorative and present", () => {
  render(<Skeleton variant="circle" width={24} height={24} />);
  const s = screen.getByTestId("skeleton");
  expect(s).toHaveAttribute("aria-hidden", "true");
});
test("SkeletonTable renders requested row count", () => {
  render(<SkeletonTable rows={3} cols={2} />);
  expect(screen.getAllByTestId("skeleton-row")).toHaveLength(3);
});
```

- [ ] **Step 2: Run, expect fail.**

- [ ] **Step 3: Implement in feedback.tsx**

```tsx
export function Skeleton({
  variant = "rect", width, height, className,
}: { variant?: "text" | "rect" | "circle"; width?: number | string; height?: number | string; className?: string }) {
  const shape = variant === "circle" ? "rounded-full" : variant === "text" ? "rounded h-3" : "rounded-md";
  return (
    <span
      data-testid="skeleton"
      aria-hidden="true"
      className={cx("block animate-pulse bg-surface-2", shape, className)}
      style={{ width, height: variant === "text" ? height ?? undefined : height }}
    />
  );
}

export function SkeletonTable({ rows = 5, cols = 4 }: { rows?: number; cols?: number }) {
  return (
    <div className="space-y-2" aria-hidden="true">
      {Array.from({ length: rows }).map((_, r) => (
        <div key={r} data-testid="skeleton-row" className="flex gap-3">
          {Array.from({ length: cols }).map((_, c) => (
            <Skeleton key={c} variant="text" className="flex-1" />
          ))}
        </div>
      ))}
    </div>
  );
}
```

- [ ] **Step 4: Run, expect pass.** Add to gallery.
- [ ] **Step 5: Commit** — `git commit -m "feat(ui): Skeleton + SkeletonTable primitives"`

### Task 11: Tabs

**Files:**
- Modify: `web/src/components/ui/controls.tsx`
- Test: `web/src/components/ui/__tests__/tabs.test.tsx`

**Interfaces:**
- Produces:
  - `Tabs({ tabs, active, onChange }: { tabs: { id: string; label: string; icon?: IconName }[]; active: string; onChange: (id: string) => void }): JSX.Element` — `role="tablist"`, each trigger `role="tab"` with `aria-selected`, arrow-key roving.
  - `TabPanel({ when, active, children }: { when: string; active: string; children: React.ReactNode }): JSX.Element | null` — renders children only when `when === active`, with `role="tabpanel"`.

- [ ] **Step 1: Failing test**

```tsx
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { Tabs, TabPanel } from "@/components/ui";

function Harness() {
  const [a, setA] = useState("one");
  return (<>
    <Tabs tabs={[{ id: "one", label: "One" }, { id: "two", label: "Two" }]} active={a} onChange={setA} />
    <TabPanel when="one" active={a}>First</TabPanel>
    <TabPanel when="two" active={a}>Second</TabPanel>
  </>);
}
test("Tabs switch panels and set aria-selected", async () => {
  render(<Harness />);
  expect(screen.getByText("First")).toBeInTheDocument();
  await userEvent.click(screen.getByRole("tab", { name: "Two" }));
  expect(screen.getByRole("tab", { name: "Two" })).toHaveAttribute("aria-selected", "true");
  expect(screen.getByText("Second")).toBeInTheDocument();
});
```

- [ ] **Step 2: Run, expect fail.**

- [ ] **Step 3: Implement in controls.tsx**

```tsx
import { Icon, type IconName } from "@/components/icon";

export function Tabs({
  tabs, active, onChange,
}: { tabs: { id: string; label: string; icon?: IconName }[]; active: string; onChange: (id: string) => void }) {
  return (
    <div role="tablist" className="flex gap-1 border-b border-line">
      {tabs.map((t) => {
        const selected = t.id === active;
        return (
          <button
            key={t.id}
            role="tab"
            type="button"
            aria-selected={selected}
            tabIndex={selected ? 0 : -1}
            onClick={() => onChange(t.id)}
            onKeyDown={(e) => {
              const i = tabs.findIndex((x) => x.id === active);
              if (e.key === "ArrowRight") onChange(tabs[(i + 1) % tabs.length].id);
              if (e.key === "ArrowLeft") onChange(tabs[(i - 1 + tabs.length) % tabs.length].id);
            }}
            className={cx(
              "inline-flex items-center gap-1.5 -mb-px border-b-2 px-3 py-2 text-sm font-medium transition-colors",
              focusRing,
              selected ? "border-accent text-fg" : "border-transparent text-muted hover:text-fg",
            )}
          >
            {t.icon ? <Icon name={t.icon} size={15} /> : null}
            {t.label}
          </button>
        );
      })}
    </div>
  );
}

export function TabPanel({
  when, active, children,
}: { when: string; active: string; children: React.ReactNode }) {
  if (when !== active) return null;
  return <div role="tabpanel">{children}</div>;
}
```

- [ ] **Step 4: Run, expect pass.** Add to gallery; migrate the login tab switcher is TP2 (leave login as-is here).
- [ ] **Step 5: Commit** — `git commit -m "feat(ui): Tabs + TabPanel primitives"`

### Task 12: Pagination

**Files:**
- Modify: `web/src/components/ui/data.tsx` (create this file)
- Test: `web/src/components/ui/__tests__/pagination.test.tsx`
- Modify: `web/src/components/ui/index.ts` (add `export * from "./data";`)

**Interfaces:**
- Produces: `Pagination({ page, pageCount, onPageChange }: { page: number; pageCount: number; onPageChange: (p: number) => void }): JSX.Element | null` — null when `pageCount <= 1`; prev/next + current indicator; prev disabled on page 1, next disabled on last.

- [ ] **Step 1: Add data.tsx to the barrel**

In `index.ts` add: `export * from "./data";`

- [ ] **Step 2: Failing test**

```tsx
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Pagination } from "@/components/ui";

test("Pagination disables prev on first page and advances", async () => {
  const onChange = vi.fn();
  render(<Pagination page={1} pageCount={3} onPageChange={onChange} />);
  expect(screen.getByRole("button", { name: /previous/i })).toBeDisabled();
  await userEvent.click(screen.getByRole("button", { name: /next/i }));
  expect(onChange).toHaveBeenCalledWith(2);
});
```

- [ ] **Step 3: Run, expect fail.**

- [ ] **Step 4: Implement data.tsx**

```tsx
"use client";
import { cx } from "./internal";
import { Button } from "./controls";

export function Pagination({
  page, pageCount, onPageChange,
}: { page: number; pageCount: number; onPageChange: (p: number) => void }) {
  if (pageCount <= 1) return null;
  return (
    <div className="flex items-center justify-between gap-3 text-sm text-muted">
      <Button variant="secondary" size="sm" aria-label="Previous page"
        disabled={page <= 1} onClick={() => onPageChange(page - 1)}>
        Previous
      </Button>
      <span className="tabular-nums">Page {page} of {pageCount}</span>
      <Button variant="secondary" size="sm" aria-label="Next page"
        disabled={page >= pageCount} onClick={() => onPageChange(page + 1)}>
        Next
      </Button>
    </div>
  );
}
```

- [ ] **Step 5: Run, expect pass.** Add to gallery.
- [ ] **Step 6: Commit** — `git commit -m "feat(ui): Pagination primitive + data.tsx module"`

### Task 13: Tooltip (Floating UI)

**Files:**
- Modify: `web/src/components/ui/overlays.tsx`
- Test: `web/src/components/ui/__tests__/tooltip.test.tsx`

**Interfaces:**
- Produces: `Tooltip({ content, side?, children }: { content: React.ReactNode; side?: "top" | "right" | "bottom" | "left"; children: React.ReactElement }): JSX.Element` — wraps a single focusable child; shows on hover/focus; tooltip has `role="tooltip"`; positioned via Floating UI with `flip`/`shift`/`offset`.

- [ ] **Step 1: Failing test**

```tsx
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Tooltip } from "@/components/ui";

test("Tooltip appears on focus with role tooltip", async () => {
  render(<Tooltip content="More info"><button>Q</button></Tooltip>);
  await userEvent.tab();
  expect(await screen.findByRole("tooltip", { name: "More info" })).toBeInTheDocument();
});
```

- [ ] **Step 2: Run, expect fail.**

- [ ] **Step 3: Implement in overlays.tsx**

```tsx
import {
  useFloating, autoUpdate, offset, flip, shift,
  useHover, useFocus, useDismiss as useFloatingDismiss, useRole, useInteractions,
} from "@floating-ui/react";
import { useState } from "react";

export function Tooltip({
  content, side = "top", children,
}: { content: React.ReactNode; side?: "top" | "right" | "bottom" | "left"; children: React.ReactElement }) {
  const [open, setOpen] = useState(false);
  const { refs, floatingStyles, context } = useFloating({
    open, onOpenChange: setOpen, placement: side,
    whileElementsMounted: autoUpdate, middleware: [offset(6), flip(), shift({ padding: 6 })],
  });
  const hover = useHover(context, { move: false });
  const focus = useFocus(context);
  const dismiss = useFloatingDismiss(context);
  const role = useRole(context, { role: "tooltip" });
  const { getReferenceProps, getFloatingProps } = useInteractions([hover, focus, dismiss, role]);

  return (
    <>
      {/* attach ref + props to the single child */}
      <span ref={refs.setReference} {...getReferenceProps()} className="inline-flex">
        {children}
      </span>
      {open && (
        <div
          ref={refs.setFloating}
          style={floatingStyles}
          {...getFloatingProps()}
          className="z-50 max-w-xs rounded-md bg-fg px-2 py-1 text-xs text-white shadow-md"
        >
          {content}
        </div>
      )}
    </>
  );
}
```

- [ ] **Step 4: Run, expect pass.** Add to gallery.
- [ ] **Step 5: Commit** — `git commit -m "feat(ui): Tooltip primitive (floating-ui)"`

### Task 14: Menu / Dropdown (Floating UI)

**Files:**
- Modify: `web/src/components/ui/overlays.tsx`
- Test: `web/src/components/ui/__tests__/menu.test.tsx`

**Interfaces:**
- Produces:
  - `type MenuItem = { label: string; icon?: IconName; onSelect: () => void; tone?: "default" | "danger"; disabled?: boolean } | { separator: true }`
  - `Menu({ trigger, items, align? }: { trigger: React.ReactNode; items: MenuItem[]; align?: "start" | "end" }): JSX.Element` — button trigger toggles a `role="menu"`; items `role="menuitem"`; click-outside + Escape dismiss; selecting an item closes and calls `onSelect`.

- [ ] **Step 1: Failing test**

```tsx
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Menu } from "@/components/ui";

test("Menu opens and triggers item onSelect", async () => {
  const onSelect = vi.fn();
  render(<Menu trigger="Actions" items={[{ label: "Delete", tone: "danger", onSelect }]} />);
  await userEvent.click(screen.getByRole("button", { name: "Actions" }));
  await userEvent.click(screen.getByRole("menuitem", { name: "Delete" }));
  expect(onSelect).toHaveBeenCalledOnce();
});
```

- [ ] **Step 2: Run, expect fail.**

- [ ] **Step 3: Implement in overlays.tsx**

```tsx
import {
  useFloating as useMenuFloating, autoUpdate as menuAutoUpdate, offset as menuOffset,
  flip as menuFlip, shift as menuShift, useClick, useDismiss as useMenuDismiss,
  useRole as useMenuRole, useInteractions as useMenuInteractions, FloatingFocusManager,
} from "@floating-ui/react";
import { Icon, type IconName } from "@/components/icon";

export type MenuItem =
  | { label: string; icon?: IconName; onSelect: () => void; tone?: "default" | "danger"; disabled?: boolean }
  | { separator: true };

export function Menu({
  trigger, items, align = "start",
}: { trigger: React.ReactNode; items: MenuItem[]; align?: "start" | "end" }) {
  const [open, setOpen] = useState(false);
  const { refs, floatingStyles, context } = useMenuFloating({
    open, onOpenChange: setOpen, placement: align === "end" ? "bottom-end" : "bottom-start",
    whileElementsMounted: menuAutoUpdate, middleware: [menuOffset(4), menuFlip(), menuShift({ padding: 6 })],
  });
  const click = useClick(context);
  const dismiss = useMenuDismiss(context);
  const role = useMenuRole(context, { role: "menu" });
  const { getReferenceProps, getFloatingProps } = useMenuInteractions([click, dismiss, role]);

  return (
    <>
      <button type="button" ref={refs.setReference} {...getReferenceProps()}
        className={cx("inline-flex items-center gap-1.5 rounded-lg px-2.5 h-8 text-sm", focusRing, buttonVariants.secondary)}>
        {trigger}
      </button>
      {open && (
        <FloatingFocusManager context={context} modal={false}>
          <div ref={refs.setFloating} style={floatingStyles} {...getFloatingProps()}
            className="z-50 min-w-40 overflow-hidden rounded-lg border border-line bg-surface py-1 shadow-lg">
            {items.map((it, i) =>
              "separator" in it ? (
                <div key={i} className="my-1 border-t border-line" />
              ) : (
                <button key={i} role="menuitem" type="button" disabled={it.disabled}
                  onClick={() => { it.onSelect(); setOpen(false); }}
                  className={cx(
                    "flex w-full items-center gap-2 px-3 py-1.5 text-left text-sm transition-colors disabled:opacity-50",
                    it.tone === "danger" ? "text-crit hover:bg-crit/10" : "text-fg hover:bg-surface-2",
                  )}>
                  {it.icon ? <Icon name={it.icon} size={15} /> : null}
                  {it.label}
                </button>
              ),
            )}
          </div>
        </FloatingFocusManager>
      )}
    </>
  );
}
```

- [ ] **Step 4: Run, expect pass.** Add to gallery.
- [ ] **Step 5: Commit** — `git commit -m "feat(ui): Menu/Dropdown primitive (floating-ui)"`

### Task 15: Modal + ConfirmDialog

**Files:**
- Modify: `web/src/components/ui/overlays.tsx`
- Test: `web/src/components/ui/__tests__/modal.test.tsx`

**Interfaces:**
- Produces:
  - `Modal({ onClose, title, description?, size?, children, footer? }: { onClose: () => void; title: string; description?: string; size?: "sm" | "md" | "lg"; children: React.ReactNode; footer?: React.ReactNode }): JSX.Element` — centered dialog using `Portal` + `useFocusTrap` + `useDismiss`; `role="dialog"` `aria-modal`.
  - `ConfirmDialog({ open, onConfirm, onCancel, title, body, confirmLabel?, tone?, busy? }: { open: boolean; onConfirm: () => void; onCancel: () => void; title: string; body: React.ReactNode; confirmLabel?: string; tone?: "danger" | "primary"; busy?: boolean }): JSX.Element | null` — built on `Modal`; Cancel + Confirm buttons.

- [ ] **Step 1: Failing test**

```tsx
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ConfirmDialog } from "@/components/ui";

test("ConfirmDialog confirms and is a modal dialog", async () => {
  const onConfirm = vi.fn(), onCancel = vi.fn();
  render(<ConfirmDialog open title="Revoke key?" body="This cannot be undone."
    confirmLabel="Revoke" tone="danger" onConfirm={onConfirm} onCancel={onCancel} />);
  expect(screen.getByRole("dialog")).toHaveAttribute("aria-modal", "true");
  await userEvent.click(screen.getByRole("button", { name: "Revoke" }));
  expect(onConfirm).toHaveBeenCalledOnce();
});
```

- [ ] **Step 2: Run, expect fail.**

- [ ] **Step 3: Implement in overlays.tsx**

```tsx
import { Portal, useFocusTrap, useDismiss } from "./overlay-core";
import { useRef } from "react";

const modalSizes = { sm: "max-w-sm", md: "max-w-md", lg: "max-w-lg" };

export function Modal({
  onClose, title, description, size = "md", children, footer,
}: { onClose: () => void; title: string; description?: string;
     size?: "sm" | "md" | "lg"; children: React.ReactNode; footer?: React.ReactNode }) {
  const ref = useRef<HTMLDivElement>(null);
  const trap = useFocusTrap(ref);
  useDismiss(onClose);
  return (
    <Portal>
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
        <button type="button" aria-label="Close" onClick={onClose} className="absolute inset-0 bg-fg/40" />
        <div ref={ref} role="dialog" aria-modal="true" aria-label={title} onKeyDown={trap}
          className={cx("argus-rise relative w-full rounded-xl border border-line bg-surface shadow-xl", modalSizes[size])}>
          <div className="border-b border-line px-5 py-4">
            <h2 className="text-base font-semibold text-fg">{title}</h2>
            {description ? <p className="mt-1 text-sm text-muted">{description}</p> : null}
          </div>
          <div className="px-5 py-4">{children}</div>
          {footer ? <div className="flex justify-end gap-2 border-t border-line px-5 py-4">{footer}</div> : null}
        </div>
      </div>
    </Portal>
  );
}

export function ConfirmDialog({
  open, onConfirm, onCancel, title, body, confirmLabel = "Confirm", tone = "primary", busy,
}: { open: boolean; onConfirm: () => void; onCancel: () => void; title: string;
     body: React.ReactNode; confirmLabel?: string; tone?: "danger" | "primary"; busy?: boolean }) {
  if (!open) return null;
  return (
    <Modal onClose={onCancel} title={title}
      footer={<>
        <Button variant="secondary" onClick={onCancel} disabled={busy}>Cancel</Button>
        <Button variant={tone === "danger" ? "danger" : "primary"} onClick={onConfirm} disabled={busy}>
          {confirmLabel}
        </Button>
      </>}>
      <p className="text-sm text-fg-2">{body}</p>
    </Modal>
  );
}
```

(`Button` is imported into `overlays.tsx` from `./controls`.)

- [ ] **Step 4: Run, expect pass.** Add a ConfirmDialog demo (toggled by a button) to the gallery.
- [ ] **Step 5: Commit** — `git commit -m "feat(ui): Modal + ConfirmDialog primitives"`

### Task 16: Toast (provider + hook)

**Files:**
- Create: `web/src/components/ui/toast.tsx`
- Modify: `web/src/components/ui/index.ts` (`export * from "./toast";`)
- Modify: `web/src/app/layout.tsx` (wrap children in `<ToastProvider>`)
- Test: `web/src/components/ui/__tests__/toast.test.tsx`

**Interfaces:**
- Produces:
  - `ToastProvider({ children }: { children: React.ReactNode }): JSX.Element`
  - `useToast(): { toast: (o: { title: string; description?: string; tone?: "default" | "ok" | "warn" | "danger"; duration?: number }) => void }`

- [ ] **Step 1: Failing test**

```tsx
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ToastProvider, useToast } from "@/components/ui";

function Trigger() {
  const { toast } = useToast();
  return <button onClick={() => toast({ title: "Saved", tone: "ok" })}>go</button>;
}
test("toast() shows a message in a live region", async () => {
  render(<ToastProvider><Trigger /></ToastProvider>);
  await userEvent.click(screen.getByRole("button", { name: "go" }));
  expect(await screen.findByText("Saved")).toBeInTheDocument();
});
```

- [ ] **Step 2: Run, expect fail.**

- [ ] **Step 3: Implement toast.tsx**

```tsx
"use client";
import { createContext, useCallback, useContext, useRef, useState } from "react";
import { cx } from "./internal";
import { Portal } from "./overlay-core";

type Tone = "default" | "ok" | "warn" | "danger";
type ToastMsg = { id: number; title: string; description?: string; tone: Tone };
type ToastInput = { title: string; description?: string; tone?: Tone; duration?: number };

const ToastCtx = createContext<{ toast: (o: ToastInput) => void } | null>(null);

const toneRing: Record<Tone, string> = {
  default: "border-line", ok: "border-ok/30", warn: "border-warn/30", danger: "border-crit/30",
};

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [items, setItems] = useState<ToastMsg[]>([]);
  const seq = useRef(0);
  const toast = useCallback((o: ToastInput) => {
    const id = ++seq.current;
    setItems((xs) => [...xs, { id, title: o.title, description: o.description, tone: o.tone ?? "default" }]);
    const ms = o.duration ?? 4000;
    setTimeout(() => setItems((xs) => xs.filter((x) => x.id !== id)), ms);
  }, []);
  return (
    <ToastCtx.Provider value={{ toast }}>
      {children}
      <Portal>
        <div className="fixed right-4 top-4 z-[60] flex w-80 flex-col gap-2"
          role="region" aria-live="polite" aria-label="Notifications">
          {items.map((t) => (
            <div key={t.id}
              className={cx("argus-slide rounded-lg border bg-surface px-4 py-3 shadow-lg", toneRing[t.tone])}>
              <p className="text-sm font-semibold text-fg">{t.title}</p>
              {t.description ? <p className="mt-0.5 text-xs text-muted">{t.description}</p> : null}
            </div>
          ))}
        </div>
      </Portal>
    </ToastCtx.Provider>
  );
}

export function useToast() {
  const ctx = useContext(ToastCtx);
  if (!ctx) throw new Error("useToast must be used within <ToastProvider>");
  return ctx;
}
```

- [ ] **Step 4: Wrap the app**

In `web/src/app/layout.tsx`, import `ToastProvider` from `@/components/ui` and wrap the `<body>` children: `<ToastProvider>{children}</ToastProvider>`. (Read `node_modules/next/dist/docs/` first if layout shape differs from training data.)

- [ ] **Step 5: Run, expect pass + build.** Add a "fire toast" button to the gallery.
- [ ] **Step 6: Commit** — `git commit -m "feat(ui): Toast provider + useToast hook, mounted in root layout"`

### Task 17: Table (sort + selection + density)

**Files:**
- Modify: `web/src/components/ui/data.tsx`
- Test: `web/src/components/ui/__tests__/table.test.tsx`

**Interfaces:**
- Produces:
  - `type Column<Row> = { key: string; header: string; render?: (row: Row) => React.ReactNode; align?: "left" | "right"; sortable?: boolean; numeric?: boolean; width?: string }`
  - `type SortState = { key: string; dir: "asc" | "desc" }`
  - `Table<Row>({ columns, rows, getRowId, sort?, onSortChange?, selection?, onSelectionChange?, density?, empty?, sticky? }: { columns: Column<Row>[]; rows: Row[]; getRowId: (r: Row) => string; sort?: SortState; onSortChange?: (s: SortState) => void; selection?: Set<string>; onSelectionChange?: (s: Set<string>) => void; density?: "compact" | "comfortable"; empty?: React.ReactNode; sticky?: boolean }): JSX.Element` — semantic `<table>`; sortable headers are buttons toggling asc/desc with `aria-sort`; optional row-selection checkbox column; `compact` is the default density (Datadog).

- [ ] **Step 1: Failing test**

```tsx
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Table } from "@/components/ui";

type Row = { id: string; name: string; risk: number };
const rows: Row[] = [{ id: "a", name: "alpha", risk: 9 }, { id: "b", name: "beta", risk: 3 }];

test("Table renders rows and toggles sort with aria-sort", async () => {
  const onSort = vi.fn();
  render(<Table<Row>
    columns={[{ key: "name", header: "Name", sortable: true }, { key: "risk", header: "Risk", numeric: true }]}
    rows={rows} getRowId={(r) => r.id}
    sort={{ key: "name", dir: "asc" }} onSortChange={onSort} />);
  expect(screen.getAllByRole("row")).toHaveLength(3); // header + 2
  await userEvent.click(screen.getByRole("button", { name: /Name/ }));
  expect(onSort).toHaveBeenCalledWith({ key: "name", dir: "desc" });
});

test("Table shows empty slot when no rows", () => {
  render(<Table<Row> columns={[{ key: "name", header: "Name" }]} rows={[]}
    getRowId={(r) => r.id} empty={<span>No data</span>} />);
  expect(screen.getByText("No data")).toBeInTheDocument();
});
```

- [ ] **Step 2: Run, expect fail.**

- [ ] **Step 3: Implement in data.tsx**

```tsx
import { Checkbox } from "./controls";

export type Column<Row> = {
  key: string; header: string; render?: (row: Row) => React.ReactNode;
  align?: "left" | "right"; sortable?: boolean; numeric?: boolean; width?: string;
};
export type SortState = { key: string; dir: "asc" | "desc" };

export function Table<Row>({
  columns, rows, getRowId, sort, onSortChange, selection, onSelectionChange,
  density = "compact", empty, sticky,
}: {
  columns: Column<Row>[]; rows: Row[]; getRowId: (r: Row) => string;
  sort?: SortState; onSortChange?: (s: SortState) => void;
  selection?: Set<string>; onSelectionChange?: (s: Set<string>) => void;
  density?: "compact" | "comfortable"; empty?: React.ReactNode; sticky?: boolean;
}) {
  const pad = density === "compact" ? "px-3 py-2" : "px-4 py-3";
  const selectable = Boolean(selection && onSelectionChange);
  const allSelected = selectable && rows.length > 0 && rows.every((r) => selection!.has(getRowId(r)));
  const toggleAll = () => {
    const next = new Set<string>();
    if (!allSelected) rows.forEach((r) => next.add(getRowId(r)));
    onSelectionChange!(next);
  };
  const toggleOne = (id: string) => {
    const next = new Set(selection);
    next.has(id) ? next.delete(id) : next.add(id);
    onSelectionChange!(next);
  };
  const colCount = columns.length + (selectable ? 1 : 0);

  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-sm">
        <thead className={cx("bg-surface-2 text-left text-muted", sticky && "sticky top-0 z-10")}>
          <tr>
            {selectable && (
              <th className={cx(pad, "w-10")}>
                <Checkbox checked={allSelected} onChange={toggleAll} label="" />
              </th>
            )}
            {columns.map((c) => {
              const active = sort?.key === c.key;
              return (
                <th key={c.key} style={{ width: c.width }}
                  aria-sort={active ? (sort!.dir === "asc" ? "ascending" : "descending") : undefined}
                  className={cx(pad, "font-medium", c.numeric || c.align === "right" ? "text-right" : "text-left")}>
                  {c.sortable && onSortChange ? (
                    <button type="button" className={cx("inline-flex items-center gap-1 hover:text-fg", focusRing)}
                      onClick={() => onSortChange({ key: c.key, dir: active && sort!.dir === "asc" ? "desc" : "asc" })}>
                      {c.header}
                      {active ? <Icon name="chevron" size={13} /> : null}
                    </button>
                  ) : c.header}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 ? (
            <tr><td colSpan={colCount} className={cx(pad, "text-center text-muted")}>{empty ?? "No data"}</td></tr>
          ) : rows.map((r) => {
            const id = getRowId(r);
            return (
              <tr key={id} className="border-t border-line hover:bg-surface-2/60">
                {selectable && (
                  <td className={pad}>
                    <Checkbox checked={selection!.has(id)} onChange={() => toggleOne(id)} label="" />
                  </td>
                )}
                {columns.map((c) => (
                  <td key={c.key}
                    className={cx(pad, c.numeric ? "text-right tabular-nums" : c.align === "right" ? "text-right" : "text-left", "text-fg")}>
                    {c.render ? c.render(r) : String((r as Record<string, unknown>)[c.key] ?? "")}
                  </td>
                ))}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
```

(Imports needed in `data.tsx`: `cx`, `focusRing` from `./internal`; `Icon` from `@/components/icon`.)

- [ ] **Step 4: Run, expect pass.** Add a Table to the gallery (with sort + selection demo).
- [ ] **Step 5: Commit** — `git commit -m "feat(ui): Table primitive (sortable, selectable, density-aware)"`

---

## Phase C — Migration & verification

### Task 18: Migrate the 6 hand-rolled spots to primitives

**Files:**
- Modify: `web/src/components/assets-view.tsx` (`GroupCard`)
- Modify: `web/src/components/vulns-view.tsx` (`linkButtonClasses`, `BulkTriage`)
- Modify: `web/src/components/asset-drawer.tsx` (`VulnSection`, `BusinessContext` labels, Services table)

**Interfaces:**
- Consumes: `ButtonLink`, `Panel`, `Field`, `Table` from `@/components/ui`.
- Produces: no new exports; removes hand-rolled chrome.

- [ ] **Step 1: Replace `vulns-view.tsx` `linkButtonClasses`** with `<ButtonLink href=… variant="secondary" size="md">`; delete the `linkButtonClasses` constant.
- [ ] **Step 2: Replace `vulns-view.tsx` `BulkTriage` wrapper div** (`border border-line bg-surface-2/40 p-3`) with `<Panel>` (no title, `bodyClassName="p-3"`).
- [ ] **Step 3: Replace `assets-view.tsx` `GroupCard`** interactive card with a `<Button variant="secondary">` (or a selectable `Panel`) carrying the active state via `aria-pressed`; delete the inline template-literal styling.
- [ ] **Step 4: Replace `asset-drawer.tsx` `VulnSection`** wrapper divs with `<Panel>` subsections; `BusinessContext` `<label>`+overline with `<Field label=…>`; the Services `<div><table>` with `<Table>` (columns: product, port, proto…).
- [ ] **Step 5: Run build + lint + tests + hex grep**

Run: `cd web && npm test && npm run build && npm run lint`
Run: `cd web && grep -rnE '#[0-9a-fA-F]{3,6}' src --include=*.tsx --include=*.ts | grep -v globals.css || echo CLEAN`
Expected: all pass; `CLEAN`.

- [ ] **Step 6: Commit** — `git commit -m "refactor(ui): migrate 6 hand-rolled spots onto primitives"`

### Task 19: Final verification

**Files:** none (verification only).

- [ ] **Step 1: Full test suite** — `cd web && npm test` → all pass.
- [ ] **Step 2: Production build** — `cd web && npm run build` → success; `/dev/ui` present.
- [ ] **Step 3: Lint** — `cd web && npm run lint` → clean.
- [ ] **Step 4: Hex discipline** — `grep -rnE '#[0-9a-fA-F]{3,6}' src --include=*.tsx --include=*.ts | grep -v globals.css || echo CLEAN` → `CLEAN`.
- [ ] **Step 5: Acceptance review** — confirm against spec acceptance criteria: 11 primitives exist + barrel-exported; 6 migrations done; 5 icons added; build/lint/tests pass; `/dev/ui` renders all primitives. Tick each.
- [ ] **Step 6: Commit any final doc/touch-ups** — `git commit -m "chore(ui): TP1 design-system completion done"` (if anything pending).

---

## Self-review notes

- **Spec coverage:** all 11 primitives → Tasks 7–17; file split → Task 3; overlay foundation → Task 4; toast → Task 16; tokens/hex/icons → Task 5; migrations → Task 18; gallery → Task 6; verification/acceptance → Task 19. Deferred items (Combobox/Breadcrumb/DatePicker/Avatar) intentionally absent.
- **Type consistency:** `Column<Row>`/`SortState` defined in Task 17 and used only there; `MenuItem` in Task 14; `IconName` extended in Task 5 and consumed by Tabs/Menu; `buttonVariants`/`buttonSizes` exported in Task 9 and reused by Menu (Task 14) and ButtonLink (Task 9). `useFocusTrap`/`Portal`/`useDismiss` signatures defined in Task 4 and consumed by Modal (Task 15) and Toast (Task 16).
- **Ordering dependency:** Task 1's smoke test depends on Task 3's barrel — flagged in Task 1 Step 6. Floating UI (Task 2) precedes Tooltip/Menu (13/14). overlay-core (Task 4) precedes Modal/Toast (15/16). data.tsx created in Task 12, extended in Task 17.
