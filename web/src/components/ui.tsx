"use client";

// Argus Console v2 UI primitives. Every page builds its chrome from these —
// no hand-rolled buttons, inputs or panels in feature code. Signatures are
// part of the design contract: do not change them.

import { useEffect, useRef } from "react";
import { Icon } from "@/components/icon";

function cx(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(" ");
}

/** Shared focus treatment for all interactive elements. */
const focusRing =
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40";

// ---- layout -----------------------------------------------------------------

export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string;
  description?: string;
  actions?: React.ReactNode;
}) {
  return (
    <div className="mb-6 flex flex-wrap items-start justify-between gap-x-6 gap-y-3">
      <div className="min-w-0">
        <h1 className="text-xl font-semibold tracking-tight text-fg">
          {title}
        </h1>
        {description ? (
          <p className="mt-1 text-sm text-muted">{description}</p>
        ) : null}
      </div>
      {actions ? (
        <div className="flex shrink-0 items-center gap-2">{actions}</div>
      ) : null}
    </div>
  );
}

export function Panel({
  title,
  description,
  actions,
  children,
  className,
  bodyClassName,
}: {
  title?: string;
  description?: string;
  actions?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  bodyClassName?: string;
}) {
  const hasHeader = Boolean(title || description || actions);
  return (
    <section
      className={cx(
        "overflow-hidden rounded-xl border border-line bg-surface shadow-[0_1px_2px_rgba(16,24,40,0.05)]",
        className,
      )}
    >
      {hasHeader ? (
        <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2 border-b border-line px-5 py-4">
          <div className="min-w-0">
            {title ? (
              <h2 className="text-sm font-semibold text-fg">{title}</h2>
            ) : null}
            {description ? (
              <p className="mt-0.5 text-xs text-muted">{description}</p>
            ) : null}
          </div>
          {actions ? (
            <div className="flex shrink-0 items-center gap-2">{actions}</div>
          ) : null}
        </div>
      ) : null}
      <div className={bodyClassName ?? "p-5"}>{children}</div>
    </section>
  );
}

const statTones: Record<
  "default" | "accent" | "danger" | "warn" | "ok",
  string
> = {
  default: "text-fg",
  accent: "text-accent",
  danger: "text-crit",
  warn: "text-warn",
  ok: "text-ok",
};

export function StatCard({
  label,
  value,
  hint,
  tone = "default",
}: {
  label: string;
  value: React.ReactNode;
  hint?: string;
  tone?: "default" | "accent" | "danger" | "warn" | "ok";
}) {
  return (
    <div className="rounded-xl border border-line bg-surface p-5 shadow-[0_1px_2px_rgba(16,24,40,0.05)]">
      <p className="text-[11px] font-medium uppercase tracking-[0.08em] text-muted">
        {label}
      </p>
      <p
        className={cx(
          "mt-2 text-2xl font-semibold tabular-nums",
          statTones[tone],
        )}
      >
        {value}
      </p>
      {hint ? <p className="mt-1 text-xs text-muted">{hint}</p> : null}
    </div>
  );
}

// ---- controls ----------------------------------------------------------------

const buttonVariants: Record<
  "primary" | "secondary" | "ghost" | "danger",
  string
> = {
  primary: "bg-accent text-white hover:bg-accent-2",
  secondary: "border border-line bg-surface text-fg hover:bg-surface-2",
  ghost: "text-fg-2 hover:bg-surface-2 hover:text-fg",
  danger: "bg-crit text-white hover:bg-crit/90",
};

const buttonSizes: Record<"sm" | "md", string> = {
  sm: "h-8 px-2.5 text-xs",
  md: "h-9 px-3.5 text-sm",
};

export function Button({
  variant = "primary",
  size = "md",
  className,
  ...rest
}: React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "secondary" | "ghost" | "danger";
  size?: "sm" | "md";
}) {
  return (
    <button
      className={cx(
        "inline-flex items-center justify-center gap-1.5 rounded-lg font-medium transition-colors disabled:pointer-events-none disabled:opacity-50",
        focusRing,
        buttonVariants[variant],
        buttonSizes[size],
        className,
      )}
      {...rest}
    />
  );
}

const controlBase =
  "h-9 w-full rounded-lg border border-line bg-surface px-3 text-sm text-fg transition-colors focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/20 disabled:cursor-not-allowed disabled:opacity-50";

export function Input({
  className,
  ...rest
}: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      className={cx(controlBase, "placeholder:text-faint", className)}
      {...rest}
    />
  );
}

export function Select({
  className,
  ...rest
}: React.SelectHTMLAttributes<HTMLSelectElement>) {
  return <select className={cx(controlBase, className)} {...rest} />;
}

export function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <label className="block">
      <span className="mb-1.5 block text-xs font-medium text-fg-2">
        {label}
      </span>
      {children}
      {hint ? (
        <span className="mt-1.5 block text-xs text-muted">{hint}</span>
      ) : null}
    </label>
  );
}

export function Toggle({
  checked,
  onChange,
  disabled,
  label,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
  label?: string;
}) {
  const toggle = (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={cx(
        "relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors disabled:cursor-not-allowed disabled:opacity-50",
        focusRing,
        checked ? "bg-accent" : "bg-line-strong",
      )}
    >
      <span
        className={cx(
          "absolute h-4 w-4 rounded-full bg-white shadow-sm transition-transform",
          checked ? "translate-x-[18px]" : "translate-x-[2px]",
        )}
      />
    </button>
  );
  if (!label) return toggle;
  return (
    <label className="inline-flex cursor-pointer items-center gap-2.5">
      {toggle}
      <span className="text-sm text-fg-2">{label}</span>
    </label>
  );
}

// ---- overlays -----------------------------------------------------------------

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

  // Escape closes — window-level so it works regardless of focus position.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  // While mounted: lock body scroll, move focus to the close button; on
  // unmount restore both the scroll state and the previously focused element.
  useEffect(() => {
    const previouslyFocused =
      document.activeElement instanceof HTMLElement
        ? document.activeElement
        : null;
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    closeRef.current?.focus();
    return () => {
      document.body.style.overflow = prevOverflow;
      previouslyFocused?.focus();
    };
  }, []);

  // Simple focus trap: Tab and Shift+Tab cycle within the aside.
  const trapFocus = (e: React.KeyboardEvent) => {
    if (e.key !== "Tab" || !asideRef.current) return;
    const focusables = asideRef.current.querySelectorAll<HTMLElement>(
      'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
    );
    if (focusables.length === 0) return;
    const first = focusables[0];
    const last = focusables[focusables.length - 1];
    const active = document.activeElement;
    if (e.shiftKey) {
      if (active === first || !asideRef.current.contains(active)) {
        e.preventDefault();
        last.focus();
      }
    } else if (active === last || !asideRef.current.contains(active)) {
      e.preventDefault();
      first.focus();
    }
  };

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
        onKeyDown={trapFocus}
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

// ---- feedback -----------------------------------------------------------------

/** Inline form error note — shared by settings and login. */
export function FormError({ children }: { children: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-crit/30 bg-crit/5 px-3 py-2 text-sm text-crit">
      {children}
    </div>
  );
}

// ---- badges -------------------------------------------------------------------

const badgeTones: Record<
  "neutral" | "accent" | "ok" | "warn" | "danger" | "info",
  string
> = {
  neutral: "bg-surface-2 text-fg-2 ring-line",
  accent: "bg-accent-soft text-accent ring-accent/20",
  ok: "bg-ok/10 text-ok ring-ok/20",
  warn: "bg-warn/10 text-warn ring-warn/20",
  danger: "bg-crit/10 text-crit ring-crit/20",
  info: "bg-info/10 text-info ring-info/20",
};

export function Badge({
  tone = "neutral",
  children,
}: {
  tone?: "neutral" | "accent" | "ok" | "warn" | "danger" | "info";
  children: React.ReactNode;
}) {
  return (
    <span
      className={cx(
        "inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset",
        badgeTones[tone],
      )}
    >
      {children}
    </span>
  );
}
