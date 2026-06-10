"use client";

// Activity feed: change events recorded by scans and the continuous monitor
// (new assets, service/vuln/risk changes), newest first.

import type { ArgusEvent } from "@/lib/api";
import { bandOrder, timeAgo } from "@/lib/ui";
import { useEvents } from "@/lib/use-events";
import { EmptyState } from "@/components/states";

/** Neutral fallback for unknown kinds / missing detail (version skew). */
const FALLBACK_BADGE = { label: "Change", cls: "text-muted bg-surface-2 ring-line" };

/** Severity-rank comparison: lower bandOrder index = worse band. Tolerates a
 *  missing/partial detail (treats it as "not worse"). */
function gotWorse(e: Extract<ArgusEvent, { kind: "risk.changed" }>): boolean {
  if (e.detail == null) return false;
  return (
    bandOrder.indexOf(e.detail.new_band) < bandOrder.indexOf(e.detail.old_band)
  );
}

function kindBadge(e: ArgusEvent): { label: string; cls: string } {
  // Runtime guard: the TS union says detail is always present, but a
  // version-skewed API or a null detail must not crash the render.
  if (e == null || e.detail == null) return FALLBACK_BADGE;
  switch (e.kind) {
    case "asset.new":
      return { label: "New asset", cls: "text-accent bg-accent/10 ring-accent/30" };
    case "services.changed":
      return { label: "Services", cls: "text-med bg-med/10 ring-med/30" };
    case "vulns.changed":
      return { label: "Vulns", cls: "text-crit bg-crit/10 ring-crit/30" };
    case "risk.changed":
      return gotWorse(e)
        ? { label: "Risk up", cls: "text-crit bg-crit/10 ring-crit/30" }
        : {
            label: "Risk down",
            cls: "text-emerald-600 bg-emerald-500/10 ring-emerald-500/30",
          };
    default:
      return FALLBACK_BADGE;
  }
}

function summarize(e: ArgusEvent): string {
  // Runtime guard: a null/missing detail or an unknown future kind must yield
  // a safe generic string rather than dereferencing undefined.
  if (e == null || e.detail == null) return "changed";
  switch (e.kind) {
    case "asset.new": {
      const d = e.detail;
      return `risk ${d.risk.toFixed(1)} (${d.band}) · ${d.services} service${
        d.services === 1 ? "" : "s"
      }`;
    }
    case "services.changed": {
      const a = e.detail.added.length;
      const r = e.detail.removed.length;
      if (a > 0 && r > 0) return `+${a} service${a === 1 ? "" : "s"}, -${r}`;
      if (a > 0) return `+${a} service${a === 1 ? "" : "s"}`;
      if (r > 0) return `-${r} service${r === 1 ? "" : "s"}`;
      return "services unchanged";
    }
    case "vulns.changed": {
      const d = e.detail;
      const parts: string[] = [];
      if (d.added.length > 0) {
        parts.push(
          `${d.added.length} new CVE${d.added.length === 1 ? "" : "s"}${
            d.kev_added > 0 ? ` (${d.kev_added} KEV)` : ""
          }`,
        );
      }
      if (d.removed.length > 0) parts.push(`${d.removed.length} resolved`);
      return parts.join(" · ") || "vulns unchanged";
    }
    case "risk.changed": {
      const d = e.detail;
      return `risk ${d.old_band} → ${d.new_band} · ${d.new.toFixed(1)}`;
    }
    default:
      return "changed";
  }
}

export function ActivityFeed() {
  const { events, error, loading } = useEvents(20);

  return (
    <section className="rounded-xl border border-line bg-surface p-5">
      <div className="mb-4 flex items-center justify-between">
        <h2 className="text-sm font-semibold">Activity</h2>
        <span className="text-xs text-muted">latest changes</span>
      </div>

      {loading ? (
        <div className="space-y-2">
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="h-9 animate-pulse rounded-lg bg-surface-2" />
          ))}
        </div>
      ) : error ? (
        <p className="text-sm text-muted">
          <span className="font-medium text-crit">Feed unavailable.</span>{" "}
          {error}
        </p>
      ) : events.length === 0 ? (
        <EmptyState
          title="No activity yet"
          hint="Changes show up here after the next scan or monitor run."
        />
      ) : (
        <ul className="divide-y divide-line">
          {events.map((e) => {
            const badge = kindBadge(e);
            return (
              <li key={e.id} className="flex items-center gap-3 py-2.5 text-sm">
                <span
                  className={`inline-flex shrink-0 items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium ring-1 ${badge.cls}`}
                >
                  <span className="h-1.5 w-1.5 rounded-full bg-current" />
                  {badge.label}
                </span>
                <span className="min-w-0 flex-1 truncate">
                  <span className="font-medium text-fg">{e.asset_name}</span>
                  <span className="text-muted"> · {summarize(e)}</span>
                </span>
                <span className="shrink-0 text-xs tabular-nums text-muted">
                  {timeAgo(e.created_at)}
                </span>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
