"use client";
import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";

export function Portal({ children }: { children: React.ReactNode }) {
  const [mounted, setMounted] = useState(false);
  // Standard client-only mount guard: defer the portal to the client so
  // document.body is never touched during SSR. The one-time setState is intentional.
  // eslint-disable-next-line react-hooks/set-state-in-effect
  useEffect(() => setMounted(true), []);
  return mounted ? createPortal(children, document.body) : null;
}

const SELECTOR =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

// ---------------------------------------------------------------------------
// Module-level stacking coordination
// ---------------------------------------------------------------------------

/** Stack of dismiss tokens — topmost is the most recently opened overlay. */
const _dismissStack: symbol[] = [];

/** Scroll-lock ref count + saved overflow value. */
let _scrollLockCount = 0;
let _savedOverflow = "";

// ---------------------------------------------------------------------------

export function useFocusTrap(
  ref: React.RefObject<HTMLElement | null>,
  opts?: { initialFocus?: React.RefObject<HTMLElement | null> },
) {
  const initialFocus = opts?.initialFocus;
  useEffect(() => {
    const prevFocus =
      document.activeElement instanceof HTMLElement ? document.activeElement : null;

    // Ref-counted scroll lock: only save+lock on the first overlay.
    if (_scrollLockCount === 0) {
      _savedOverflow = document.body.style.overflow;
      document.body.style.overflow = "hidden";
    }
    _scrollLockCount++;

    (initialFocus?.current ??
      ref.current?.querySelector<HTMLElement>(SELECTOR))?.focus();

    return () => {
      // Per-instance focus restore (LIFO — correct for nesting).
      prevFocus?.focus();

      // Ref-counted scroll unlock: only restore on the last overlay.
      _scrollLockCount--;
      if (_scrollLockCount === 0) {
        document.body.style.overflow = _savedOverflow;
        _savedOverflow = "";
      }
    };
  }, [ref, initialFocus]);

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
  // Stable ref so the keydown handler always calls the latest callback.
  const onDismissRef = useRef(onDismiss);
  useEffect(() => {
    onDismissRef.current = onDismiss;
  });

  useEffect(() => {
    // Each overlay instance gets a unique symbol token pushed onto the stack.
    const token = Symbol();
    _dismissStack.push(token);

    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      // Only fire for the topmost overlay.
      if (_dismissStack[_dismissStack.length - 1] === token) {
        onDismissRef.current();
      }
    };
    window.addEventListener("keydown", onKey);

    return () => {
      window.removeEventListener("keydown", onKey);
      const idx = _dismissStack.lastIndexOf(token);
      if (idx !== -1) _dismissStack.splice(idx, 1);
    };
  }, []); // intentionally empty — token and handler are stable
}
