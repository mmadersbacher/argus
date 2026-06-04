"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  getAssets,
  getSummary,
  runScan,
  type AssetType,
  type RiskBand,
  type ScoredAsset,
  type Summary,
} from "@/lib/api";
import {
  assetTypeLabel,
  bandOrder,
  bandStyles,
  exposureLabel,
} from "@/lib/ui";
import { Icon, type IconName } from "@/components/icon";
import { RiskBadge } from "@/components/risk-badge";
import { AssetDrawer } from "@/components/asset-drawer";
import { DataSources } from "@/components/data-sources";

const typeIcon: Record<AssetType, IconName> = {
  it: "server",
  ot: "cpu",
  iot: "network",
  iomt: "activity",
  network: "network",
  cloud: "cloud",
  mobile: "smartphone",
  unknown: "grid",
};

type Filter = { kind: "type"; value: AssetType } | { kind: "band"; value: RiskBand };

function DashboardSkeleton() {
  return (
    <div className="space-y-6">
      <div className="h-9 w-40 animate-pulse rounded-lg bg-surface" />
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {Array.from({ length: 8 }).map((_, i) => (
          <div key={i} className="h-24 animate-pulse rounded-xl border border-line bg-surface" />
        ))}
      </div>
      <div className="h-80 animate-pulse rounded-xl border border-line bg-surface" />
    </div>
  );
}

function ErrorState({ message }: { message: string }) {
  return (
    <div className="rounded-xl border border-crit/30 bg-crit/5 p-6">
      <div className="flex items-center gap-2 font-medium text-crit">
        <span className="h-2 w-2 rounded-full bg-crit" /> argus-api unreachable
      </div>
      <p className="mt-2 text-sm text-muted">{message}</p>
      <p className="mt-3 font-mono text-xs text-muted">
        Start it with <span className="text-fg">cargo run -p argus-api</span> (expects
        http://127.0.0.1:8088)
      </p>
    </div>
  );
}

/** A grouped-by card: icon tile + title + count + "Show Details". */
function GroupCard({
  icon,
  tile,
  title,
  count,
  active,
  onClick,
}: {
  icon: IconName;
  tile: string;
  title: string;
  count: number;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`group flex items-start gap-4 rounded-xl border bg-surface p-4 text-left transition hover:shadow-sm ${
        active ? "border-accent ring-1 ring-accent/30" : "border-line hover:border-accent/40"
      }`}
    >
      <span className={`flex h-12 w-12 shrink-0 items-center justify-center rounded-xl ${tile}`}>
        <Icon name={icon} size={24} />
      </span>
      <span className="min-w-0">
        <span className="block truncate font-semibold leading-tight">{title}</span>
        <span className="mt-0.5 block text-xs text-muted">
          {count} Asset{count === 1 ? "" : "s"}
        </span>
        <span className="mt-2 inline-flex items-center gap-1 rounded-md border border-line px-2 py-0.5 text-[11px] font-medium text-muted transition group-hover:border-accent/40 group-hover:text-accent">
          Show Details
        </span>
      </span>
    </button>
  );
}

export function Dashboard() {
  const [summary, setSummary] = useState<Summary | null>(null);
  const [assets, setAssets] = useState<ScoredAsset[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<ScoredAsset | null>(null);
  const [target, setTarget] = useState("127.0.0.1");
  const [scanning, setScanning] = useState(false);
  const [scanNote, setScanNote] = useState<string | null>(null);
  const [filter, setFilter] = useState<Filter | null>(null);
  const [q, setQ] = useState("");
  const [sortAsc, setSortAsc] = useState(false);
  const [detailed, setDetailed] = useState(false);
  const [showScan, setShowScan] = useState(false);
  const mounted = useRef(true);

  const load = useCallback(async () => {
    try {
      const [s, a] = await Promise.all([getSummary(), getAssets()]);
      if (!mounted.current) return;
      setSummary(s);
      setAssets(a);
      setError(null);
    } catch (e) {
      if (mounted.current) {
        setError(e instanceof Error ? e.message : "Failed to reach argus-api");
      }
    } finally {
      if (mounted.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    mounted.current = true;
    void load();
    const id = setInterval(() => void load(), 15000);
    return () => {
      mounted.current = false;
      clearInterval(id);
    };
  }, [load]);

  const onScan = async () => {
    setScanning(true);
    setScanNote(null);
    try {
      const r = await runScan(target.trim() || "127.0.0.1");
      await load();
      setScanNote(`${r.live} live · ${r.hosts_scanned} scanned · ${r.duration_ms} ms`);
    } catch (e) {
      setScanNote(e instanceof Error ? e.message : "scan failed");
    } finally {
      if (mounted.current) setScanning(false);
    }
  };

  if (loading) return <DashboardSkeleton />;
  if (error) return <ErrorState message={error} />;

  const byType = (Object.keys(assetTypeLabel) as AssetType[])
    .map((t) => ({ t, n: assets.filter((a) => a.asset_type === t).length }))
    .filter((g) => g.n > 0);
  const byBand = bandOrder
    .map((b) => ({ b, n: assets.filter((a) => a.risk.band === b).length }))
    .filter((g) => g.n > 0);

  let list = assets;
  if (filter?.kind === "type") list = list.filter((a) => a.asset_type === filter.value);
  if (filter?.kind === "band") list = list.filter((a) => a.risk.band === filter.value);
  if (q.trim()) {
    const s = q.toLowerCase();
    list = list.filter(
      (a) =>
        (a.fingerprint.device_type ?? "").toLowerCase().includes(s) ||
        (a.fingerprint.vendor ?? "").toLowerCase().includes(s) ||
        (a.interfaces[0]?.ip ?? "").includes(s),
    );
  }
  list = [...list].sort((a, b) =>
    sortAsc ? a.risk.value - b.risk.value : b.risk.value - a.risk.value,
  );

  const filterLabel =
    filter?.kind === "type"
      ? assetTypeLabel[filter.value]
      : filter?.kind === "band"
        ? bandStyles[filter.value].label
        : null;

  return (
    <div className="argus-rise space-y-7">
      {/* page header */}
      <div className="flex items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Assets</h1>
          <p className="mt-1 text-sm text-muted">
            <span className="font-medium text-fg">{summary?.total_assets ?? assets.length}</span>{" "}
            assets · {summary?.internet_facing ?? 0} internet-facing ·{" "}
            <span className="text-crit">{summary?.critical_or_high ?? 0}</span> high/critical
          </p>
        </div>
        <button
          type="button"
          onClick={() => setShowScan((v) => !v)}
          className="flex items-center gap-2 rounded-lg bg-accent px-4 py-2 text-sm font-medium text-white transition hover:bg-accent-2"
        >
          <Icon name="search" size={15} /> Run discovery
        </button>
      </div>

      {/* discovery panel (toggled) */}
      {showScan && (
        <section className="flex flex-wrap items-center gap-3 rounded-xl border border-line bg-surface p-4">
          <span className="text-sm font-medium">Active discovery</span>
          <input
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="IP or CIDR — e.g. 192.168.1.0/24"
            className="w-64 rounded-lg border border-line bg-surface-2 px-3 py-1.5 text-sm outline-none focus:border-accent"
          />
          <button
            type="button"
            onClick={() => void onScan()}
            disabled={scanning}
            className="rounded-lg bg-accent px-4 py-1.5 text-sm font-medium text-white transition hover:bg-accent-2 disabled:opacity-60"
          >
            {scanning ? "Scanning…" : "Run scan"}
          </button>
          {scanNote && <span className="text-xs text-muted">{scanNote}</span>}
          <span className="ml-auto text-xs text-muted">connect-scan · authorized targets only</span>
        </section>
      )}

      {/* grouped by: Asset Type */}
      <section>
        <div className="mb-3 flex items-end justify-between">
          <div>
            <div className="text-xs text-muted">Grouped by</div>
            <h2 className="text-base font-semibold">Asset Type ({byType.length})</h2>
          </div>
          {filter?.kind === "type" && (
            <button
              type="button"
              onClick={() => setFilter(null)}
              className="text-xs font-medium text-accent hover:underline"
            >
              Show All
            </button>
          )}
        </div>
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {byType.map(({ t, n }) => (
            <GroupCard
              key={t}
              icon={typeIcon[t]}
              tile="bg-accent/10 text-accent"
              title={assetTypeLabel[t]}
              count={n}
              active={filter?.kind === "type" && filter.value === t}
              onClick={() =>
                setFilter(filter?.kind === "type" && filter.value === t ? null : { kind: "type", value: t })
              }
            />
          ))}
        </div>
      </section>

      {/* grouped by: Risk Level */}
      <section>
        <div className="mb-3 flex items-end justify-between">
          <div>
            <div className="text-xs text-muted">Grouped by</div>
            <h2 className="text-base font-semibold">Risk Level ({byBand.length})</h2>
          </div>
          {filter?.kind === "band" && (
            <button
              type="button"
              onClick={() => setFilter(null)}
              className="text-xs font-medium text-accent hover:underline"
            >
              Show All
            </button>
          )}
        </div>
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {byBand.map(({ b, n }) => (
            <GroupCard
              key={b}
              icon="activity"
              tile={`${bandStyles[b].bg} ${bandStyles[b].text}`}
              title={`${bandStyles[b].label} risk`}
              count={n}
              active={filter?.kind === "band" && filter.value === b}
              onClick={() =>
                setFilter(filter?.kind === "band" && filter.value === b ? null : { kind: "band", value: b })
              }
            />
          ))}
        </div>
      </section>

      {/* data sources */}
      <DataSources assets={assets} summary={summary} />

      {/* asset list */}
      <section className="overflow-hidden rounded-xl border border-line bg-surface">
        <div className="flex flex-wrap items-center gap-3 border-b border-line px-5 py-3.5">
          <h2 className="text-sm font-semibold">{list.length} Assets</h2>
          {filterLabel && (
            <span className="inline-flex items-center gap-1.5 rounded-full bg-accent/10 px-2.5 py-0.5 text-xs font-medium text-accent">
              {filterLabel}
              <button type="button" onClick={() => setFilter(null)} aria-label="Clear filter">
                ✕
              </button>
            </span>
          )}
          <div className="ml-auto flex items-center gap-2">
            <div className="flex items-center gap-2 rounded-lg border border-line bg-surface-2 px-2.5 py-1.5 text-sm">
              <Icon name="search" size={14} />
              <input
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder="Filter…"
                className="w-28 bg-transparent text-sm outline-none placeholder:text-muted"
              />
            </div>
            <button
              type="button"
              onClick={() => setSortAsc((v) => !v)}
              className="flex items-center gap-1.5 rounded-lg border border-line px-3 py-1.5 text-sm text-fg transition hover:bg-surface-2"
            >
              Risk {sortAsc ? "↑" : "↓"}
            </button>
            <button
              type="button"
              onClick={() => setDetailed((v) => !v)}
              className={`flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-sm transition ${
                detailed ? "border-accent bg-accent/10 text-accent" : "border-line text-fg hover:bg-surface-2"
              }`}
            >
              <Icon name="sliders" size={14} /> Detailed View
            </button>
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs text-muted">
                <th className="px-5 py-2.5 font-medium">Asset</th>
                <th className="px-3 py-2.5 font-medium">Type</th>
                <th className="px-3 py-2.5 font-medium">Address</th>
                <th className="px-3 py-2.5 font-medium">Exposure</th>
                {detailed && <th className="px-3 py-2.5 font-medium">Services</th>}
                <th className="px-5 py-2.5 text-right font-medium">Risk</th>
              </tr>
            </thead>
            <tbody>
              {list.map((a) => {
                const iface = a.interfaces[0];
                const sub = [a.fingerprint.vendor, a.fingerprint.os].filter(Boolean).join(" · ");
                return (
                  <tr
                    key={a.id}
                    onClick={() => setSelected(a)}
                    className="cursor-pointer border-t border-line transition-colors hover:bg-surface-2"
                  >
                    <td className="px-5 py-3">
                      <div className="flex items-center gap-3">
                        <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-surface-2 text-muted">
                          <Icon name={typeIcon[a.asset_type]} size={16} />
                        </span>
                        <div>
                          <div className="font-medium">{a.fingerprint.device_type ?? "unknown device"}</div>
                          <div className="text-xs text-muted">{sub || "—"}</div>
                        </div>
                      </div>
                    </td>
                    <td className="px-3 py-3">
                      <span className="rounded-md border border-line bg-surface-2 px-2 py-0.5 text-xs text-muted">
                        {assetTypeLabel[a.asset_type]}
                      </span>
                    </td>
                    <td className="px-3 py-3 font-mono text-xs text-muted">
                      <div className="text-fg">{iface?.ip ?? "—"}</div>
                      <div>{iface?.mac ?? ""}</div>
                    </td>
                    <td className="px-3 py-3 text-xs">{exposureLabel[a.exposure]}</td>
                    {detailed && (
                      <td className="px-3 py-3 text-xs text-muted">
                        {a.services.length > 0
                          ? a.services.map((s) => s.port).slice(0, 6).join(", ")
                          : "—"}
                      </td>
                    )}
                    <td className="px-5 py-3 text-right">
                      <RiskBadge band={a.risk.band} value={a.risk.value} />
                      {a.vulnerabilities.length > 0 && (
                        <div className="mt-1 text-[11px] text-muted">
                          {a.vulnerabilities.length} CVE
                          {a.vulnerabilities.length > 1 ? "s" : ""}
                          {a.vulnerabilities.some((v) => v.kev) && (
                            <span className="ml-1 font-medium text-crit">· KEV</span>
                          )}
                        </div>
                      )}
                    </td>
                  </tr>
                );
              })}
              {list.length === 0 && (
                <tr>
                  <td colSpan={detailed ? 6 : 5} className="px-5 py-10 text-center text-sm text-muted">
                    No assets match this filter.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      <AssetDrawer asset={selected} onClose={() => setSelected(null)} />
    </div>
  );
}
