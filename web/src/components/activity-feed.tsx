"use client";

// Activity feed: change events recorded by scans and the continuous monitor
// (new assets, service/vuln/risk changes), newest first.

import type { ArgusEvent } from "@/lib/api";
import { bandOrder, timeAgo } from "@/lib/ui";
import { useEvents } from "@/lib/use-events";
import { EmptyState } from "@/components/states";
import { Badge, Panel } from "@/components/ui";

type BadgeTone = React.ComponentProps<typeof Badge>["tone"];

/** Neutral fallback for unknown kinds / missing detail (version skew). */
const FALLBACK_BADGE: { label: string; tone: BadgeTone } = {
  label: "Change",
  tone: "neutral",
};

/** Severity-rank comparison: lower bandOrder index = worse band. Tolerates a
 *  missing/partial detail (treats it as "not worse"). */
function gotWorse(e: Extract<ArgusEvent, { kind: "risk.changed" }>): boolean {
  if (e.detail == null) return false;
  return (
    bandOrder.indexOf(e.detail.new_band) < bandOrder.indexOf(e.detail.old_band)
  );
}

function kindBadge(e: ArgusEvent): { label: string; tone: BadgeTone } {
  // Runtime guard: the TS union says detail is always present, but a
  // version-skewed API or a null detail must not crash the render.
  if (e == null || e.detail == null) return FALLBACK_BADGE;
  switch (e.kind) {
    case "asset.new":
      return { label: "New asset", tone: "accent" };
    case "services.changed":
      return { label: "Services", tone: "warn" };
    case "vulns.changed":
      return { label: "Vulns", tone: "danger" };
    case "risk.changed":
      return gotWorse(e)
        ? { label: "Risk up", tone: "danger" }
        : { label: "Risk down", tone: "ok" };
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

export function ActivityFeed({ className }: { className?: string }) {
  const { events, error, loading } = useEvents(20);

  return (
    <Panel
      title="Activity"
      actions={
        <span className="inline-flex items-center gap-1.5 text-xs font-medium text-muted">
          <span className="argus-pulse h-1.5 w-1.5 rounded-full bg-ok" />
          Live
        </span>
      }
      className={className}
      bodyClassName="min-h-0 flex-1 overflow-y-auto p-0"
    >
      {loading ? (
        <div className="space-y-2 p-5">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="h-9 animate-pulse rounded-lg bg-surface-2" />
          ))}
        </div>
      ) : error ? (
        <EmptyState title="Event feed unavailable" hint={error} />
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
              <li key={e.id} className="px-5 py-3 text-sm">
                <div className="flex items-center justify-between gap-3">
                  <Badge tone={badge.tone}>{badge.label}</Badge>
                  <span className="shrink-0 text-xs tabular-nums text-muted">
                    {timeAgo(e.created_at)}
                  </span>
                </div>
                <p className="mt-1.5 min-w-0 truncate">
                  <span className="font-medium text-fg">{e.asset_name}</span>
                  <span className="text-muted"> · {summarize(e)}</span>
                </p>
              </li>
            );
          })}
        </ul>
      )}
    </Panel>
  );
}
