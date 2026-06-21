"use client";
import { useEffect, useState } from "react";
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

export function useFocusTrap(
  ref: React.RefObject<HTMLElement | null>,
  opts?: { initialFocus?: React.RefObject<HTMLElement | null> },
) {
  const initialFocus = opts?.initialFocus;
  useEffect(() => {
    const prevFocus =
      document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    (initialFocus?.current ??
      ref.current?.querySelector<HTMLElement>(SELECTOR))?.focus();
    return () => {
      document.body.style.overflow = prevOverflow;
      prevFocus?.focus();
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
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onDismiss();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onDismiss]);
}
