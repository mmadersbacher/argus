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
