"use client";

// Segmentation page: advisory zoning / exposure findings from GET /api/policy.
// Advisory only — Argus observes and recommends, it never enforces.

import type { Advisory, AdvisoryLevel } from "@/lib/api";
import { usePolicy } from "@/lib/use-policy";
import { LiveRegion } from "@/components/live-region";
import { Badge, PageHeader, Panel, StatCard } from "@/components/ui";
import { EmptyState, ErrorState, LoadingState } from "@/components/states";

const levelTone: Record<AdvisoryLevel, "danger" | "warn" | "info" | "neutral"> =
  {
    critical: "danger",
    high: "warn",
    medium: "info",
    low: "neutral",
  };

const levelLabel: Record<AdvisoryLevel, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
};

/** Affected assets shown before collapsing into a "+N more" suffix. */
const AFFECTED_SHOWN = 8;

function AdvisoryCard({ advisory }: { advisory: Advisory }) {
  const shown = advisory.affected.slice(0, AFFECTED_SHOWN);
  const extra = advisory.affected.length - shown.length;
  return (
    <Panel bodyClassName="p-5">
      <div className="flex flex-wrap items-start justify-between gap-x-4 gap-y-2">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone={levelTone[advisory.level]}>
              {levelLabel[advisory.level]}
            </Badge>
            <h3 className="text-sm font-semibold text-fg">{advisory.title}</h3>
          </div>
          <p className="mt-2 max-w-3xl text-sm leading-relaxed text-fg-2">
            {advisory.rationale}
          </p>
        </div>
      </div>

      <div className="mt-4 rounded-lg bg-accent-soft px-4 py-3">
        <p className="text-[11px] font-semibold uppercase tracking-[0.08em] text-accent">
          Recommendation
        </p>
        <p className="mt-1 text-sm leading-relaxed text-fg-2">
          {advisory.recommendation}
        </p>
      </div>

      <div className="mt-4">
        <p className="mb-2 text-[11px] font-semibold uppercase tracking-[0.08em] text-muted">
          Affected ({advisory.affected.length})
        </p>
        <ul className="grid gap-1.5 sm:grid-cols-2">
          {shown.map((a) => (
            <li
              key={`${a.name}-${a.evidence}`}
              className="flex min-w-0 items-baseline gap-2 text-sm"
            >
              <span className="shrink-0 font-medium text-fg">{a.name}</span>
              <span className="truncate text-xs text-muted">{a.evidence}</span>
            </li>
          ))}
        </ul>
        {extra > 0 ? (
          <p className="mt-1.5 text-xs text-muted">+{extra} more</p>
        ) : null}
      </div>
    </Panel>
  );
}

export function PolicyView() {
  const { advisories, error, loading } = usePolicy();

  if (loading && !advisories) return <LoadingState />;
  if (error && !advisories) return <ErrorState message={error} />;
  if (!advisories) return null;

  const countBy = (level: AdvisoryLevel) =>
    advisories.filter((a) => a.level === level).length;

  return (
    <div>
      <PageHeader
        title="Segmentation"
        description="Advisory zoning and exposure findings — what to segment, isolate or shut off, and why."
      />

      <LiveRegion
        message={`${advisories.length} segmentation advisories: ${countBy(
          "critical",
        )} critical, ${countBy("high")} high, ${countBy("medium")} medium, ${countBy(
          "low",
        )} low.`}
      />

      <div className="mb-6 grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatCard
          label="Critical"
          value={countBy("critical")}
          tone={countBy("critical") > 0 ? "danger" : "ok"}
        />
        <StatCard
          label="High"
          value={countBy("high")}
          tone={countBy("high") > 0 ? "warn" : "default"}
        />
        <StatCard label="Medium" value={countBy("medium")} />
        <StatCard label="Low" value={countBy("low")} />
      </div>

      {advisories.length === 0 ? (
        <EmptyState
          title="No advisories"
          hint="No zoning or exposure rule matched the current inventory — segmentation looks clean."
        />
      ) : (
        <div className="space-y-4">
          {advisories.map((a) => (
            <AdvisoryCard key={a.rule} advisory={a} />
          ))}
        </div>
      )}
    </div>
  );
}
