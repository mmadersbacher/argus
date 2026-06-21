"use client";

import { cx } from "./internal";

/** Inline form error note — shared by settings and login. */
export function FormError({ children }: { children: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-crit/30 bg-crit/5 px-3 py-2 text-sm text-crit">
      {children}
    </div>
  );
}

export function Skeleton({
  variant = "rect",
  width,
  height,
  className,
}: {
  variant?: "text" | "rect" | "circle";
  width?: number | string;
  height?: number | string;
  className?: string;
}) {
  const shape =
    variant === "circle"
      ? "rounded-full"
      : variant === "text"
        ? "rounded h-3"
        : "rounded-md";
  return (
    <span
      data-testid="skeleton"
      aria-hidden="true"
      className={cx("block animate-pulse bg-surface-2", shape, className)}
      style={{ width, height: variant === "text" ? height ?? undefined : height }}
    />
  );
}

export function SkeletonTable({
  rows = 5,
  cols = 4,
}: {
  rows?: number;
  cols?: number;
}) {
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
