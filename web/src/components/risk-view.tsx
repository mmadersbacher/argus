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
import {
  Badge,
  Column,
  PageHeader,
  Panel,
  SkeletonTable,
  SortState,
  StatCard,
  Table,
  Tooltip,
} from "@/components/ui";
import { Icon } from "@/components/icon";
import { LiveRegion } from "@/components/live-region";
import { RiskBadge } from "@/components/risk-badge";
import { RiskDistribution } from "@/components/risk-distribution";
import { AssetDrawer } from "@/components/asset-drawer";
import { EmptyState, ErrorState } from "@/components/states";
import type { ScoredAsset } from "@/lib/api";

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
  const { summary, assets, error, loading, reload } = useInventory();
  const { events, error: eventsError } = useEvents(100);
  // Drawer selection by id, never by object: the asset is re-derived from the
  // latest poll data, so the drawer always shows fresh values.
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [sort, setSort] = useState<SortState>({ key: "risk", dir: "desc" });

  // If the selected asset disappears after a poll, close the drawer.
  useEffect(() => {
    if (selectedId != null && !assets.some((a) => a.id === selectedId)) {
      // eslint-disable-next-line react-hooks/set-state-in-effect -- resetting stale selection after the asset left the inventory
      setSelectedId(null);
    }
  }, [assets, selectedId]);

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="argus-rise">
          <PageHeader
            title="Risk"
            description="Heuristic exposure scoring across the inventory"
          />
        </div>
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <div
              key={i}
              aria-hidden="true"
              className="h-24 animate-pulse rounded-xl bg-surface-2"
            />
          ))}
        </div>
        <SkeletonTable rows={10} cols={5} />
      </div>
    );
  }
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

  // Sort top assets — nulls-last for risk score in both directions.
  const topAssets = [...assets]
    .sort((a, b) => {
      const dir = sort.dir === "asc" ? 1 : -1;
      if (sort.key === "name") {
        const na = a.fingerprint.device_type ?? null;
        const nb = b.fingerprint.device_type ?? null;
        if (na === null && nb === null) return 0;
        if (na === null) return 1; // nulls last regardless of direction
        if (nb === null) return -1;
        return dir * na.localeCompare(nb);
      }
      // sort.key === "risk" (default)
      const va = a.risk.value ?? null;
      const vb = b.risk.value ?? null;
      if (va === null && vb === null) return 0;
      if (va === null) return 1; // nulls last regardless of direction
      if (vb === null) return -1;
      return dir * (va - vb);
    })
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

  // Column definitions for the top-risk Table
  const columns: Column<ScoredAsset>[] = [
    {
      key: "name",
      header: "Asset",
      sortable: true,
      render: (a) => {
        const sub = [a.fingerprint.vendor, a.fingerprint.os]
          .filter(Boolean)
          .join(" · ");
        return (
          <div className="flex items-center gap-3">
            <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-surface-2 text-muted">
              <Icon name={assetTypeIcon[a.asset_type]} size={16} />
            </span>
            <div className="min-w-0">
              <button
                type="button"
                onClick={() => setSelectedId(a.id)}
                className="block max-w-full truncate rounded text-left font-medium text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40"
              >
                {a.fingerprint.device_type ?? "Unknown device"}
              </button>
              <div className="truncate text-xs text-muted">{sub || "—"}</div>
            </div>
          </div>
        );
      },
    },
    {
      key: "type",
      header: "Type",
      render: (a) => <Badge>{assetTypeLabel[a.asset_type]}</Badge>,
    },
    {
      key: "exposure",
      header: "Exposure",
      render: (a) => (
        <span className="text-xs text-fg-2">{exposureLabel[a.exposure]}</span>
      ),
    },
    {
      key: "cves",
      header: "CVEs",
      render: (a) => {
        const hasKev = a.vulnerabilities.some((v) => v.kev);
        return a.vulnerabilities.length === 0 ? (
          <span className="text-muted">—</span>
        ) : (
          <span className="flex items-center gap-2">
            <span className="tabular-nums text-fg-2">
              {a.vulnerabilities.length}
            </span>
            {hasKev ? <Badge tone="danger">KEV</Badge> : null}
          </span>
        );
      },
    },
    {
      key: "risk",
      header: "Risk",
      sortable: true,
      numeric: true,
      render: (a) => (
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
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <div className="argus-rise">
        <PageHeader
          title="Risk"
          description="Heuristic exposure scoring across the inventory"
        />
      </div>

      <LiveRegion
        message={`Average risk ${Math.round(avg)}, ${highCritical} high or critical assets, ${kevAffected} affected by known-exploited CVEs.`}
      />

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

      <p className="flex items-center gap-1.5 text-xs text-muted">
        Risk is a{" "}
        <Tooltip
          content="0–100 composite of CVSS severity, network exposure, and asset criticality — an opinionated weighting, not a calibrated or trained model."
          side="top"
        >
          <span
            tabIndex={0}
            className="cursor-help font-medium text-fg-2 underline decoration-dotted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40 rounded"
          >
            heuristic
          </span>
        </Tooltip>{" "}
        0–100 composite score.
      </p>

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
          <Table<ScoredAsset>
            columns={columns}
            rows={topAssets}
            getRowId={(a) => a.id}
            sort={sort}
            onSortChange={setSort}
            density="compact"
          />
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
                    <Tooltip
                      content={worsened ? "Risk worsened" : "Risk improved"}
                      side="top"
                    >
                      <span
                        tabIndex={0}
                        className={`inline-flex -rotate-90 cursor-default focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40 rounded ${
                          worsened ? "text-crit" : "text-ok"
                        }`}
                        aria-hidden
                      >
                        <Icon name="chevron" size={14} />
                      </span>
                    </Tooltip>
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

      <AssetDrawer asset={selected} onClose={() => setSelectedId(null)} onUpdated={reload} />
    </div>
  );
}
