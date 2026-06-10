"use client";

import { bandOrder, bandStyles } from "@/lib/ui";
import { useInventory } from "@/lib/use-inventory";
import { ActivityFeed } from "@/components/activity-feed";
import { DataSources } from "@/components/data-sources";
import { ErrorState, LoadingState } from "@/components/states";

function Metric({
  label,
  value,
  hint,
  tone,
}: {
  label: string;
  value: number;
  hint: string;
  tone: string;
}) {
  return (
    <div className="rounded-xl border border-line bg-surface p-5">
      <div className="text-xs text-muted">{label}</div>
      <div className={`mt-2 text-3xl font-bold tabular-nums ${tone}`}>{value}</div>
      <div className="mt-1 text-xs text-muted">{hint}</div>
    </div>
  );
}

export function Overview() {
  const { summary, assets, error, loading } = useInventory();
  if (loading) return <LoadingState />;
  if (error) return <ErrorState message={error} />;

  const total = summary?.total_assets ?? assets.length;
  const counts = bandOrder.map((band) => ({
    band,
    n: assets.filter((a) => a.risk.band === band).length,
  }));
  const max = Math.max(total, 1);

  return (
    <div className="argus-rise space-y-7">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Overview</h1>
        <p className="mt-1 text-sm text-muted">Continuous asset discovery &amp; exposure</p>
      </div>

      <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Metric label="Total Assets" value={total} hint="in inventory" tone="text-accent" />
        <Metric
          label="Internet-facing"
          value={summary?.internet_facing ?? 0}
          hint="externally exposed"
          tone="text-low"
        />
        <Metric
          label="High / Critical"
          value={summary?.critical_or_high ?? 0}
          hint="need attention"
          tone="text-crit"
        />
        <Metric
          label="Avg Risk"
          value={Math.round(summary?.avg_risk ?? 0)}
          hint="0–100 composite"
          tone="text-fg"
        />
      </section>

      <section className="rounded-xl border border-line bg-surface p-5">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-sm font-semibold">Risk distribution</h2>
          <span className="text-xs text-muted">{total} assets</span>
        </div>
        <div className="flex h-3 w-full overflow-hidden rounded-full bg-surface-2">
          {counts.map(({ band, n }) =>
            n > 0 ? (
              <div
                key={band}
                className={`${bandStyles[band].bar} h-full`}
                style={{ width: `${(n / max) * 100}%` }}
                title={`${bandStyles[band].label}: ${n}`}
              />
            ) : null,
          )}
        </div>
        <div className="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-5">
          {counts.map(({ band, n }) => (
            <div key={band} className="flex items-center gap-2 text-xs text-muted">
              <span className={`h-2 w-2 rounded-full ${bandStyles[band].bar}`} />
              {bandStyles[band].label}
              <span className="ml-auto font-mono text-fg">{n}</span>
            </div>
          ))}
        </div>
      </section>

      <ActivityFeed />

      <DataSources assets={assets} summary={summary} />
    </div>
  );
}
