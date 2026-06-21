"use client";

import { cx, focusRing } from "./internal";
import { Icon, type IconName } from "@/components/icon";

export const buttonVariants: Record<
  "primary" | "secondary" | "ghost" | "danger",
  string
> = {
  primary: "bg-accent text-on-accent hover:bg-accent-2",
  secondary: "border border-line bg-surface text-fg hover:bg-surface-2",
  ghost: "text-fg-2 hover:bg-surface-2 hover:text-fg",
  danger: "bg-crit text-white hover:bg-crit/90",
};

export const buttonSizes: Record<"sm" | "md", string> = {
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

export function Checkbox({
  checked,
  onChange,
  label,
  ariaLabel,
  indeterminate,
  disabled,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label?: string;
  ariaLabel?: string;
  indeterminate?: boolean;
  disabled?: boolean;
}) {
  const input = (
    <input
      type="checkbox"
      checked={checked}
      disabled={disabled}
      aria-label={ariaLabel} // Note: passing both label and ariaLabel is unsupported; aria-label overrides visible label for AT

      ref={(el) => {
        if (el) el.indeterminate = Boolean(indeterminate);
      }}
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
  checked,
  onChange,
  name,
  value,
  label,
  disabled,
}: {
  checked: boolean;
  onChange: (v: string) => void;
  name: string;
  value: string;
  label?: string;
  disabled?: boolean;
}) {
  const input = (
    <input
      type="radio"
      name={name}
      value={value}
      checked={checked}
      disabled={disabled}
      onChange={(e) => onChange(e.target.value)}
      className={cx(
        "h-4 w-4 border-line text-accent accent-accent",
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

export function Link({
  href,
  external,
  icon,
  children,
  className,
  ...rest
}: {
  href: string;
  external?: boolean;
  icon?: boolean;
} & React.AnchorHTMLAttributes<HTMLAnchorElement>) {
  return (
    <a
      href={href}
      className={cx(
        "inline-flex items-center gap-1 text-accent underline-offset-2 hover:underline",
        focusRing,
        "rounded",
        className,
      )}
      {...(external ? { target: "_blank", rel: "noreferrer noopener" } : {})}
      {...rest}
    >
      {children}
      {external && icon ? <Icon name="external" size={14} /> : null}
    </a>
  );
}

export function ButtonLink({
  variant = "primary",
  size = "md",
  className,
  ...rest
}: React.AnchorHTMLAttributes<HTMLAnchorElement> & {
  variant?: "primary" | "secondary" | "ghost" | "danger";
  size?: "sm" | "md";
}) {
  return (
    <a
      className={cx(
        "inline-flex items-center justify-center gap-1.5 rounded-lg font-medium transition-colors",
        focusRing,
        buttonVariants[variant],
        buttonSizes[size],
        className,
      )}
      {...rest}
    />
  );
}

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
