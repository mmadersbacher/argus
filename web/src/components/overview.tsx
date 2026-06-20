"use client";

// Dashboard: KPI row, risk distribution, data sources and the live activity
// feed. Data comes from the shared useInventory hook (15s polling).

import { useInventory } from "@/lib/use-inventory";
import { ActivityFeed } from "@/components/activity-feed";
import { LiveRegion } from "@/components/live-region";
import { DataSources } from "@/components/data-sources";
import { RiskDistribution } from "@/components/risk-distribution";
import { ErrorState, LoadingState } from "@/components/states";
import { PageHeader, Panel, StatCard } from "@/components/ui";

export function Overview() {
  const { summary, assets, error, loading } = useInventory();
  if (loading) return <LoadingState />;
  if (error) {
    return (
      <div className="argus-rise">
        <PageHeader
          title="Overview"
          description="Continuous asset discovery & exposure"
        />
        <ErrorState message={error} />
      </div>
    );
  }

  const total = summary?.total_assets ?? assets.length;
  const internetFacing = summary?.internet_facing ?? 0;
  const criticalOrHigh = summary?.critical_or_high ?? 0;

  return (
    <div className="argus-rise">
      <PageHeader
        title="Overview"
        description="Continuous asset discovery & exposure"
      />

      <LiveRegion
        message={`Inventory: ${total} assets, ${internetFacing} internet-facing, ${criticalOrHigh} high or critical, average risk ${Math.round(
          summary?.avg_risk ?? 0,
        )}.`}
      />

      <div className="space-y-6">
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <StatCard label="Total assets" value={total} hint="in inventory" />
          <StatCard
            label="Internet-facing"
            value={internetFacing}
            hint="externally exposed"
            tone={internetFacing > 0 ? "warn" : "default"}
          />
          <StatCard
            label="High / Critical"
            value={criticalOrHigh}
            hint="need attention"
            tone={criticalOrHigh > 0 ? "danger" : "default"}
          />
          <StatCard
            label="Avg risk"
            value={Math.round(summary?.avg_risk ?? 0)}
            hint="0–100 heuristic composite"
          />
        </div>

        <div className="grid gap-6 lg:grid-cols-3">
          <div className="space-y-6 lg:col-span-2">
            <Panel
              title="Risk distribution"
              description="Each band as a share of all assets"
              actions={
                <span className="text-xs tabular-nums text-muted">
                  {total} asset{total === 1 ? "" : "s"}
                </span>
              }
            >
              <RiskDistribution assets={assets} />
            </Panel>

            <DataSources assets={assets} summary={summary} />
          </div>

          <ActivityFeed className="flex h-full max-h-[820px] flex-col" />
        </div>
      </div>
    </div>
  );
}
