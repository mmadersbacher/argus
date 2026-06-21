"use client";

import { useRef, useState } from "react";
import {
  useFloating,
  autoUpdate,
  offset,
  flip,
  shift,
  useHover,
  useFocus,
  useDismiss as useFloatingDismiss,
  useRole,
  useInteractions,
  useClick,
  FloatingFocusManager,
  FloatingPortal,
} from "@floating-ui/react";
import { Icon, type IconName } from "@/components/icon";
import { cx, focusRing } from "./internal";
import { Portal, useDismiss, useFocusTrap } from "./overlay-core";
import { Button, buttonVariants } from "./controls";

const modalSizes = { sm: "max-w-sm", md: "max-w-md", lg: "max-w-lg" };

export function Modal({
  onClose,
  title,
  description,
  size = "md",
  children,
  footer,
}: {
  onClose: () => void;
  title: string;
  description?: string;
  size?: "sm" | "md" | "lg";
  children: React.ReactNode;
  footer?: React.ReactNode;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const trap = useFocusTrap(ref);
  useDismiss(onClose);
  return (
    <Portal>
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
        <button
          type="button"
          aria-label="Close"
          onClick={onClose}
          className="absolute inset-0 bg-fg/40"
        />
        <div
          ref={ref}
          role="dialog"
          aria-modal="true"
          aria-label={title}
          onKeyDown={trap}
          className={cx(
            "argus-rise relative w-full rounded-xl border border-line bg-surface shadow-xl",
            modalSizes[size],
          )}
        >
          <div className="border-b border-line px-5 py-4">
            <h2 className="text-base font-semibold text-fg">{title}</h2>
            {description ? (
              <p className="mt-1 text-sm text-muted">{description}</p>
            ) : null}
          </div>
          <div className="px-5 py-4">{children}</div>
          {footer ? (
            <div className="flex justify-end gap-2 border-t border-line px-5 py-4">
              {footer}
            </div>
          ) : null}
        </div>
      </div>
    </Portal>
  );
}

export function ConfirmDialog({
  open,
  onConfirm,
  onCancel,
  title,
  body,
  confirmLabel = "Confirm",
  tone = "primary",
  busy,
}: {
  open: boolean;
  onConfirm: () => void;
  onCancel: () => void;
  title: string;
  body: React.ReactNode;
  confirmLabel?: string;
  tone?: "danger" | "primary";
  busy?: boolean;
}) {
  if (!open) return null;
  return (
    <Modal
      onClose={onCancel}
      title={title}
      footer={
        <>
          <Button variant="secondary" onClick={onCancel} disabled={busy}>
            Cancel
          </Button>
          <Button
            variant={tone === "danger" ? "danger" : "primary"}
            onClick={onConfirm}
            disabled={busy}
          >
            {confirmLabel}
          </Button>
        </>
      }
    >
      <p className="text-sm text-fg-2">{body}</p>
    </Modal>
  );
}

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
                buttonVariants.ghost,
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

/** Lightweight tooltip — wraps a single focusable child; shows on hover/focus.
 *  Positioned via Floating UI with flip/shift/offset middleware. */
export function Tooltip({
  content,
  side = "top",
  children,
}: {
  content: React.ReactNode;
  side?: "top" | "right" | "bottom" | "left";
  children: React.ReactElement;
}) {
  const [open, setOpen] = useState(false);
  const { refs, floatingStyles, context } = useFloating({
    open,
    onOpenChange: setOpen,
    placement: side,
    whileElementsMounted: autoUpdate,
    middleware: [offset(6), flip(), shift({ padding: 6 })],
  });
  const hover = useHover(context, { move: false });
  const focus = useFocus(context);
  const dismiss = useFloatingDismiss(context);
  const role = useRole(context, { role: "tooltip" });
  const { getReferenceProps, getFloatingProps } = useInteractions([
    hover,
    focus,
    dismiss,
    role,
  ]);

  return (
    <>
      <span ref={refs.setReference} {...getReferenceProps()} className="inline-flex">
        {children}
      </span>
      {open && (
        <FloatingPortal>
          <div
            // refs.setFloating is floating-ui's callback ref setter, not a render-time ref read
            // eslint-disable-next-line react-hooks/refs
            ref={refs.setFloating}
            style={floatingStyles}
            {...getFloatingProps()}
            className="z-50 max-w-xs rounded-md bg-fg px-2 py-1 text-xs text-white shadow-md"
          >
            {content}
          </div>
        </FloatingPortal>
      )}
    </>
  );
}

export type MenuItem =
  | { label: string; icon?: IconName; onSelect: () => void; tone?: "default" | "danger"; disabled?: boolean }
  | { separator: true };

export function Menu({
  trigger,
  items,
  align = "start",
  header,
  triggerClassName,
}: {
  trigger: React.ReactNode;
  items: MenuItem[];
  align?: "start" | "end";
  header?: React.ReactNode;
  /** Override the default secondary-button styling on the trigger wrapper. */
  triggerClassName?: string;
}) {
  const [open, setOpen] = useState(false);
  const { refs, floatingStyles, context } = useFloating({
    open,
    onOpenChange: setOpen,
    placement: align === "end" ? "bottom-end" : "bottom-start",
    whileElementsMounted: autoUpdate,
    middleware: [offset(4), flip(), shift({ padding: 6 })],
  });
  const click = useClick(context);
  const menuDismiss = useFloatingDismiss(context);
  const menuRole = useRole(context, { role: "menu" });
  const { getReferenceProps, getFloatingProps } = useInteractions([
    click,
    menuDismiss,
    menuRole,
  ]);

  return (
    <>
      <button
        type="button"
        ref={refs.setReference}
        {...getReferenceProps()}
        className={
          triggerClassName ??
          cx(
            "inline-flex items-center gap-1.5 rounded-lg px-2.5 h-8 text-sm",
            focusRing,
            buttonVariants.secondary,
          )
        }
      >
        {trigger}
      </button>
      {open && (
        <FloatingPortal>
          <FloatingFocusManager context={context} modal={false}>
            <div
              // refs.setFloating is floating-ui's callback ref setter, not a render-time ref read
              // eslint-disable-next-line react-hooks/refs
              ref={refs.setFloating}
              style={floatingStyles}
              {...getFloatingProps()}
              className="z-50 min-w-40 overflow-hidden rounded-lg border border-line bg-surface py-1 shadow-lg"
            >
              {header ? (
                <>
                  {header}
                  <div role="separator" className="my-1 border-t border-line" />
                </>
              ) : null}
              {items.map((it, i) =>
                "separator" in it ? (
                  <div key={`separator-${i}`} role="separator" className="my-1 border-t border-line" />
                ) : (
                  <button
                    key={it.label ?? i}
                    role="menuitem"
                    type="button"
                    disabled={it.disabled}
                    onClick={() => {
                      it.onSelect();
                      setOpen(false);
                    }}
                    className={cx(
                      "flex w-full items-center gap-2 px-3 py-1.5 text-left text-sm transition-colors disabled:opacity-50",
                      it.tone === "danger"
                        ? "text-crit hover:bg-crit/10"
                        : "text-fg hover:bg-surface-2",
                    )}
                  >
                    {it.icon ? <Icon name={it.icon} size={15} /> : null}
                    {it.label}
                  </button>
                ),
              )}
            </div>
          </FloatingFocusManager>
        </FloatingPortal>
      )}
    </>
  );
}
