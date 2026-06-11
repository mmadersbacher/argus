"use client";

import { useEffect, useState } from "react";
import type { ArgusEvent, RiskBand } from "@/lib/api";
import {
  assetTypeIcon,
  assetTypeLabel,
  bandOrder,
  bandStyles,
  exposureLabel,
  timeAgo,
} from "@/lib/ui";
import { useInventory } from "@/lib/use-inventory";
import { useEvents } from "@/lib/use-events";
import { Badge, PageHeader, Panel, StatCard } from "@/components/ui";
import { Icon } from "@/components/icon";
import { RiskBadge } from "@/components/risk-badge";
import { RiskDistribution } from "@/components/risk-distribution";
import { AssetDrawer } from "@/components/asset-drawer";
import { EmptyState, ErrorState, LoadingState } from "@/components/states";

/** Mirrors RiskBand::from_value in crates/argus-core/src/risk.rs. */
function bandFromValue(value: number): RiskBand {
  if (value >= 80) return "critical";
  if (value >= 60) return "high";
  if (value >= 40) return "medium";
  if (value >= 20) return "low";
  return "info";
}

const bandStatTone: Record<RiskBand, "default" | "danger" | "warn"> = {
  critical: "danger",
  high: "danger",
  medium: "warn",
  low: "default",
  info: "default",
};

type RiskChangedEvent = Extract<ArgusEvent, { kind: "risk.changed" }>;

/** Lower index in bandOrder = worse band (critical first). */
function bandRank(band: RiskBand): number {
  return bandOrder.indexOf(band);
}

export function RiskView() {
  const { summary, assets, error, loading } = useInventory();
  const { events, error: eventsError } = useEvents(100);
  // Drawer selection by id, never by object: the asset is re-derived from the
  // latest poll data, so the drawer always shows fresh values.
  const [selectedId, setSelectedId] = useState<string | null>(null);

  // If the selected asset disappears after a poll, close the drawer.
  useEffect(() => {
    if (selectedId != null && !assets.some((a) => a.id === selectedId)) {
      // eslint-disable-next-line react-hooks/set-state-in-effect -- resetting stale selection after the asset left the inventory
      setSelectedId(null);
    }
  }, [assets, selectedId]);

  if (loading) return <LoadingState />;
  if (error) return <ErrorState message={error} />;

  const selected =
    selectedId == null
      ? null
      : assets.find((a) => a.id === selectedId) ?? null;

  const total = summary?.total_assets ?? assets.length;
  const avg =
    summary?.avg_risk ??
    (assets.length > 0
      ? assets.reduce((sum, a) => sum + a.risk.value, 0) / assets.length
      : 0);
  const avgBand = bandFromValue(avg);

  const highCritical =
    summary?.critical_or_high ??
    assets.filter((a) => a.risk.band === "critical" || a.risk.band === "high")
      .length;
  const kevAffected = assets.filter((a) =>
    a.vulnerabilities.some((v) => v.kev),
  ).length;
  const internetHigh = assets.filter(
    (a) =>
      a.exposure === "internet_facing" &&
      (a.risk.band === "critical" || a.risk.band === "high"),
  ).length;

  const topAssets = [...assets]
    .sort((a, b) => b.risk.value - a.risk.value)
    .slice(0, 10);

  // Runtime guard (same spirit as activity-feed): a version-skewed API or a
  // null/partial detail must not crash the render — only events with a detail
  // and two known bands are rendered.
  const changes = events.filter(
    (e): e is RiskChangedEvent =>
      e.kind === "risk.changed" &&
      e.detail != null &&
      e.detail.old_band in bandStyles &&
      e.detail.new_band in bandStyles,
  );

  return (
    <div className="space-y-6">
      <div className="argus-rise">
        <PageHeader
          title="Risk"
          description="Exposure scoring across the inventory"
        />
      </div>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Average risk"
          value={Math.round(avg)}
          hint={`${bandStyles[avgBand].label} band overall`}
          tone={bandStatTone[avgBand]}
        />
        <StatCard
          label="High & critical assets"
          value={highCritical}
          hint="Need attention first"
          tone={highCritical > 0 ? "danger" : "default"}
        />
        <StatCard
          label="KEV-affected assets"
          value={kevAffected}
          hint="Carry known exploited CVEs"
        />
        <StatCard
          label="Internet-facing high+"
          value={internetHigh}
          hint="Externally exposed, high or critical"
        />
      </div>

      <Panel
        title="Risk distribution"
        description="Assets per band across the inventory"
        actions={
          <span className="text-xs tabular-nums text-muted">
            {total} asset{total === 1 ? "" : "s"}
          </span>
        }
      >
        <RiskDistribution assets={assets} detailed />
      </Panel>

      <Panel
        title="Highest-risk assets"
        description="Top 10 by composite risk score"
        bodyClassName="p-0"
      >
        {topAssets.length === 0 ? (
          <EmptyState
            title="No assets in inventory yet"
            hint="Run a discovery scan or import nmap XML on the Assets page to populate the inventory."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-line bg-surface-2/60 text-left text-xs text-muted">
                  <th className="px-4 py-3 font-medium">Asset</th>
                  <th className="px-4 py-3 font-medium">Type</th>
                  <th className="px-4 py-3 font-medium">Exposure</th>
                  <th className="px-4 py-3 font-medium">CVEs</th>
                  <th className="px-4 py-3 text-right font-medium">Risk</th>
                </tr>
              </thead>
              <tbody>
                {topAssets.map((a) => {
                  const sub = [a.fingerprint.vendor, a.fingerprint.os]
                    .filter(Boolean)
                    .join(" · ");
                  const hasKev = a.vulnerabilities.some((v) => v.kev);
                  return (
                    <tr
                      key={a.id}
                      onClick={() => setSelectedId(a.id)}
                      className="cursor-pointer border-b border-line transition-colors last:border-0 hover:bg-surface-2/60"
                    >
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-3">
                          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-surface-2 text-muted">
                            <Icon name={assetTypeIcon[a.asset_type]} size={16} />
                          </span>
                          <div className="min-w-0">
                            {/* Keyboard path into the drawer: the row onClick
                                stays as mouse comfort, the title is the real
                                interactive element. */}
                            <button
                              type="button"
                              onClick={() => setSelectedId(a.id)}
                              className="block w-full truncate rounded text-left font-medium text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40"
                            >
                              {a.fingerprint.device_type ?? "Unknown device"}
                            </button>
                            <div className="truncate text-xs text-muted">
                              {sub || "—"}
                            </div>
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <Badge>{assetTypeLabel[a.asset_type]}</Badge>
                      </td>
                      <td className="px-4 py-3 text-xs text-fg-2">
                        {exposureLabel[a.exposure]}
                      </td>
                      <td className="px-4 py-3">
                        {a.vulnerabilities.length === 0 ? (
                          <span className="text-muted">—</span>
                        ) : (
                          <span className="flex items-center gap-2">
                            <span className="tabular-nums text-fg-2">
                              {a.vulnerabilities.length}
                            </span>
                            {hasKev ? <Badge tone="danger">KEV</Badge> : null}
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <div className="flex items-center justify-end gap-3">
                          <span className="h-1.5 w-16 shrink-0 overflow-hidden rounded-full bg-surface-2">
                            <span
                              className={`block h-full rounded-full ${bandStyles[a.risk.band].bar}`}
                              style={{
                                width: `${Math.min(100, Math.max(0, a.risk.value))}%`,
                              }}
                            />
                          </span>
                          <RiskBadge band={a.risk.band} value={a.risk.value} />
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <Panel
        title="Recent risk changes"
        description="Band transitions recorded by the change feed"
        bodyClassName="p-0"
      >
        {eventsError ? (
          <EmptyState title="Event feed unavailable" hint={eventsError} />
        ) : changes.length === 0 ? (
          <EmptyState
            title="No risk changes recorded yet"
            hint="Risk transitions appear here when rescans move an asset between bands."
          />
        ) : (
          <ul className="divide-y divide-line">
            {changes.map((e) => {
              const d = e.detail;
              const worsened =
                d.new > d.old ||
                (d.new === d.old && bandRank(d.new_band) < bandRank(d.old_band));
              return (
                <li
                  key={e.id}
                  className="flex flex-wrap items-center gap-x-4 gap-y-1.5 px-5 py-3"
                >
                  <span className="min-w-0 flex-1 truncate text-sm font-medium text-fg">
                    {e.asset_name}
                  </span>
                  <span className="flex shrink-0 items-center gap-2">
                    <RiskBadge band={d.old_band} />
                    <span
                      className={`inline-flex -rotate-90 ${
                        worsened ? "text-crit" : "text-ok"
                      }`}
                      aria-hidden
                    >
                      <Icon name="chevron" size={14} />
                    </span>
                    <span className="sr-only">
                      {worsened ? "risk increased" : "risk decreased"}
                    </span>
                    <RiskBadge band={d.new_band} value={d.new} />
                  </span>
                  <span className="w-16 shrink-0 text-right text-xs text-muted">
                    {timeAgo(e.created_at)}
                  </span>
                </li>
              );
            })}
          </ul>
        )}
      </Panel>

      <AssetDrawer asset={selected} onClose={() => setSelectedId(null)} />
    </div>
  );
}
