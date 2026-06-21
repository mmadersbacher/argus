"use client";

import { useRef } from "react";
import { Icon } from "@/components/icon";
import { cx, focusRing } from "./internal";
import { useDismiss, useFocusTrap } from "./overlay-core";

const ghostButton = "text-fg-2 hover:bg-surface-2 hover:text-fg";

/** Right-hand slide-over dialog — the one drawer shell for asset and CVE
 *  details. Owns the full modal contract: backdrop, Escape, focus trap,
 *  focus restore and body scroll lock. */
export function Drawer({
  onClose,
  overline,
  title,
  mono,
  badges,
  children,
  footer,
}: {
  onClose: () => void;
  overline: string;
  title: string;
  mono?: boolean;
  badges?: React.ReactNode;
  children: React.ReactNode;
  footer?: React.ReactNode;
}) {
  const asideRef = useRef<HTMLElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);

  useDismiss(onClose);
  const trap = useFocusTrap(asideRef, { initialFocus: closeRef });

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <button
        type="button"
        aria-label="Close"
        onClick={onClose}
        className="absolute inset-0 bg-fg/40"
      />
      <aside
        ref={asideRef}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        onKeyDown={trap}
        className="argus-slide relative flex h-full w-full max-w-md flex-col overflow-y-auto border-l border-line bg-surface"
      >
        <div className="border-b border-line px-6 pt-5 pb-4">
          <div className="flex items-start justify-between gap-4">
            <div className="min-w-0">
              <p className="text-[11px] font-medium uppercase tracking-[0.08em] text-muted">
                {overline}
              </p>
              <h2
                className={cx(
                  "mt-1 truncate font-semibold text-fg",
                  mono ? "font-mono text-base" : "text-lg",
                )}
              >
                {title}
              </h2>
            </div>
            <button
              ref={closeRef}
              type="button"
              aria-label="Close"
              onClick={onClose}
              className={cx(
                "inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-lg transition-colors",
                focusRing,
                ghostButton,
              )}
            >
              <Icon name="x" size={16} />
            </button>
          </div>
          {badges ? (
            <div className="mt-3 flex flex-wrap items-center gap-2">
              {badges}
            </div>
          ) : null}
        </div>
        <div className="flex-1 space-y-6 px-6 py-5">{children}</div>
        {footer ? (
          <div className="border-t border-line px-6 py-4 text-xs text-muted">
            {footer}
          </div>
        ) : null}
      </aside>
    </div>
  );
}
