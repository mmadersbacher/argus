// Shared loading / empty / error states for the data-backed views.
// Props are frozen — every page imports these.

import { Icon } from "@/components/icon";

export function LoadingState() {
  return (
    <div role="status" className="animate-pulse space-y-6">
      <div aria-hidden="true" className="space-y-2">
        <div className="h-6 w-48 rounded-md bg-line/70" />
        <div className="h-4 w-72 rounded-md bg-line/40" />
      </div>
      <div aria-hidden="true" className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="rounded-xl border border-line bg-surface p-5">
            <div className="h-3 w-20 rounded bg-line/70" />
            <div className="mt-3 h-7 w-16 rounded-md bg-line/40" />
          </div>
        ))}
      </div>
      <div aria-hidden="true" className="rounded-xl border border-line bg-surface p-5">
        <div className="h-4 w-36 rounded bg-line/70" />
        <div className="mt-5 space-y-3.5">
          {[100, 92, 96, 84, 90].map((w, i) => (
            <div
              key={i}
              className="h-4 rounded bg-line/40"
              style={{ width: `${w}%` }}
            />
          ))}
        </div>
      </div>
      <span className="sr-only">Loading…</span>
    </div>
  );
}

export function EmptyState({ title, hint }: { title: string; hint: string }) {
  return (
    <div className="flex flex-col items-center px-5 py-12 text-center">
      <div className="flex h-10 w-10 items-center justify-center rounded-full bg-surface-2 text-faint">
        <Icon name="search" size={18} />
      </div>
      <p className="mt-3 text-sm font-medium text-fg">{title}</p>
      <p className="mt-1 max-w-sm text-xs text-muted">{hint}</p>
    </div>
  );
}

export function ErrorState({ message }: { message: string }) {
  return (
    <div className="rounded-xl border border-crit/25 bg-surface p-6 shadow-[0_1px_2px_rgba(16,24,40,0.05)]">
      <div className="flex items-start gap-3">
        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-crit/10 text-crit">
          <Icon name="alert" size={18} />
        </div>
        <div className="min-w-0">
          <p className="text-sm font-semibold text-fg">argus-api unreachable</p>
          <p className="mt-1 text-sm text-muted">{message}</p>
          <p className="mt-3 font-mono text-xs text-muted">
            Start it with{" "}
            <span className="text-fg-2">cargo run -p argus-api</span> (expects
            http://127.0.0.1:8088)
          </p>
        </div>
      </div>
    </div>
  );
}
