# Final Review Fix Report — Design-System Overlay Foundation

Branch: `feature/ui-design-system-tp1`  
Date: 2026-06-21

---

## Fix 1 — Stack-Aware Overlay Dismiss + Scroll-Lock

### Files changed
- `web/src/components/ui/overlay-core.ts`

### What changed

**Module-level stacking state added:**
```ts
const _dismissStack: symbol[] = [];
let _scrollLockCount = 0;
let _savedOverflow = "";
```

**(a) useDismiss — Escape → topmost only**  
Each `useDismiss` call pushes a unique `Symbol()` onto `_dismissStack` on mount and splices it out on unmount. The keydown handler only calls `onDismiss` when this instance's token is `_dismissStack[_dismissStack.length - 1]`. A stable `onDismissRef` (updated each render) avoids stale-closure issues without adding the callback to the effect deps array.

**(b) useFocusTrap — ref-counted scroll lock**  
Replaced the per-instance `prevOverflow` save/restore with a module-level counter. On mount: if `_scrollLockCount === 0`, save `document.body.style.overflow` into `_savedOverflow` and set `"hidden"`, then increment. On unmount: decrement, and if counter reaches 0 restore `_savedOverflow` and clear it. Focus restore remains per-instance (LIFO, correct for nesting).

---

## Fix 2 — Portal Tooltip and Menu Floating Layers

### Files changed
- `web/src/components/ui/overlays.tsx`

### What changed
Added `FloatingPortal` to the import from `@floating-ui/react`.

**Tooltip:** The floating `<div>` is now wrapped in `<FloatingPortal>` so it renders into `document.body` and cannot be clipped by any ancestor `overflow-hidden` panel or table.

**Menu:** The entire `<FloatingFocusManager>` (and its child floating `<div>`) is wrapped in `<FloatingPortal>`. This follows the Floating UI documented pattern for focus-managed menus. The existing `eslint-disable react-hooks/refs` comment on `refs.setFloating` is preserved unchanged.

No existing tooltip or menu tests broke — `@testing-library/react` queries `document.body` and `FloatingPortal` renders to body, so role-based queries still resolve.

---

## Fix 3 — Menu Separators + Keys

### Files changed
- `web/src/components/ui/overlays.tsx`

### What changed
- Separator `<div>` now carries `role="separator"`.
- Separator key changed from bare `key={i}` to `key={\`separator-${i}\`}`.
- Item key changed from bare `key={i}` to `key={it.label ?? i}` (stable by label, falls back to index).

---

## Fix 4 — cx Class-Conflict Comment

### Files changed
- `web/src/components/assets-view.tsx`

### What changed
Added a one-line comment above the `GroupCard → Button` className prop:
```tsx
// cx does NOT resolve Tailwind conflicts; rounded-xl wins over Button's rounded-lg only via source-order — revisit tailwind-merge if override count grows.
```

---

## New Tests

Added two tests in `web/src/components/ui/__tests__/overlay-core.test.tsx`:

1. **"Escape closes only the topmost overlay (stacking)"** — Mounts two overlays, fires Escape, asserts only the upper's `onDismiss` fired. Then unmounts the upper and asserts the lower's `onDismiss` fires on the next Escape.

2. **"scroll lock is held while any overlay is open, restored after last closes"** — Mounts two overlays with `useFocusTrap` (trapScroll=true). Asserts `document.body.style.overflow === "hidden"` after each mount, still `"hidden"` after unmounting the first, and `""` only after both are unmounted.

---

## Verification Output

### Tests
```
Test Files  14 passed (14)
     Tests  26 passed (26)
  Start at  21:55:06
  Duration  2.84s
```
All 26 tests green, including both new stacking tests.

### Lint
```
> web@0.1.0 lint
> eslint
(exit 0, no output = clean)
```

### Build
```
▲ Next.js 16.2.7 (Turbopack)
✓ Compiled successfully in 2.2s
✓ Generating static pages using 7 workers (15/15) in 290ms
(exit 0, clean)
```

### Hex color check
```
CLEAN
```
No bare hex literals in `.ts`/`.tsx` source files.
