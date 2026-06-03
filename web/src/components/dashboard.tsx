"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  getAssets,
  getSummary,
  runScan,
  type ScoredAsset,
  type Summary,
} from "@/lib/api";
import {
  assetTypeLabel,
  bandOrder,
  bandStyles,
  exposureLabel,
} from "@/lib/ui";
import { RiskBadge } from "@/components/risk-badge";
import { AssetGraph } from "@/components/asset-graph";
import { AssetDrawer } from "@/components/asset-drawer";

type Accent = "accent" | "accent2" | "crit" | "low";

function MetricCard({
  label,
  value,
  hint,
  accent,
}: {
  label: string;
  value: number;
  hint: string;
  accent: Accent;
}) {
  const text =
    accent === "accent"
      ? "text-accent"
      : accent === "accent2"
        ? "text-accent-2"
        : accent === "crit"
          ? "text-crit"
          : "text-low";
  const bar =
    accent === "accent"
      ? "bg-accent"
      : accent === "accent2"
        ? "bg-accent-2"
        : accent === "crit"
          ? "bg-crit"
          : "bg-low";
  return (
    <div className="relative overflow-hidden rounded-xl border border-line bg-surface/70 p-5">
      <div className={`absolute -top-px right-5 left-5 h-px ${bar} opacity-50`} />
      <div className="text-xs text-muted">{label}</div>
      <div className={`mt-2 text-3xl font-semibold tabular-nums ${text}`}>{value}</div>
      <div className="mt-1 text-xs text-muted">{hint}</div>
    </div>
  );
}

function DashboardSkeleton() {
  return (
    <div className="space-y-6">
      <div className="h-16 animate-pulse rounded-xl border border-line bg-surface/70" />
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="h-28 animate-pulse rounded-xl border border-line bg-surface/70" />
        ))}
      </div>
      <div className="h-80 animate-pulse rounded-xl border border-line bg-surface/70" />
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

export function Dashboard() {
  const [summary, setSummary] = useState<Summary | null>(null);
  const [assets, setAssets] = useState<ScoredAsset[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<ScoredAsset | null>(null);
  const [target, setTarget] = useState("127.0.0.1");
  const [scanning, setScanning] = useState(false);
  const [scanNote, setScanNote] = useState<string | null>(null);
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

  const counts = bandOrder.map((band) => ({
    band,
    n: assets.filter((a) => a.risk.band === band).length,
  }));
  const total = assets.length || 1;
  const sorted = [...assets].sort((a, b) => b.risk.value - a.risk.value);

  return (
    <div className="argus-rise space-y-6">
      <section className="flex flex-wrap items-center gap-3 rounded-xl border border-line bg-surface/70 p-4">
        <span className="text-sm font-medium">Active discovery</span>
        <input
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="IP or CIDR — e.g. 192.168.1.0/24"
          className="w-64 rounded-lg border border-line bg-bg px-3 py-1.5 text-sm outline-none focus:border-accent"
        />
        <button
          onClick={() => void onScan()}
          disabled={scanning}
          className="rounded-lg bg-accent px-4 py-1.5 text-sm font-medium text-[#04222a] transition hover:brightness-110 disabled:opacity-60"
        >
          {scanning ? "Scanning…" : "Run scan"}
        </button>
        {scanNote && <span className="text-xs text-muted">{scanNote}</span>}
        <span className="ml-auto text-xs text-muted">connect-scan · authorized targets only</span>
      </section>

      <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard label="Total Assets" value={summary?.total_assets ?? assets.length} hint="in inventory" accent="accent" />
        <MetricCard label="Internet-facing" value={summary?.internet_facing ?? 0} hint="externally exposed" accent="low" />
        <MetricCard label="High / Critical" value={summary?.critical_or_high ?? 0} hint="need attention" accent="crit" />
        <MetricCard label="Avg Risk" value={Math.round(summary?.avg_risk ?? 0)} hint="0–100 composite" accent="accent2" />
      </section>

      <section className="grid gap-4 lg:grid-cols-3">
        <div className="rounded-xl border border-line bg-surface/70 p-5 lg:col-span-2">
          <div className="mb-2 flex items-center justify-between">
            <h2 className="text-sm font-medium">Asset map</h2>
            <span className="text-xs text-muted">click a node for details</span>
          </div>
          <AssetGraph assets={sorted} selectedId={selected?.id} onSelect={setSelected} />
        </div>

        <div className="rounded-xl border border-line bg-surface/70 p-5">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="text-sm font-medium">Risk distribution</h2>
            <span className="text-xs text-muted">{assets.length}</span>
          </div>
          <div className="flex h-3 w-full overflow-hidden rounded-full bg-surface-2">
            {counts.map(({ band, n }) =>
              n > 0 ? (
                <div
                  key={band}
                  className={`${bandStyles[band].bar} h-full`}
                  style={{ width: `${(n / total) * 100}%` }}
                  title={`${bandStyles[band].label}: ${n}`}
                />
              ) : null,
            )}
          </div>
          <div className="mt-4 space-y-2">
            {counts.map(({ band, n }) => (
              <div key={band} className="flex items-center gap-2 text-xs text-muted">
                <span className={`h-2 w-2 rounded-full ${bandStyles[band].bar}`} />
                {bandStyles[band].label}
                <span className="ml-auto font-mono text-fg">{n}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="overflow-hidden rounded-xl border border-line bg-surface/70">
        <div className="flex items-center justify-between border-b border-line px-5 py-4">
          <h2 className="text-sm font-medium">Assets</h2>
          <span className="text-xs text-muted">sorted by risk · click a row</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs text-muted">
                <th className="px-5 py-2.5 font-medium">Asset</th>
                <th className="px-3 py-2.5 font-medium">Type</th>
                <th className="px-3 py-2.5 font-medium">Address</th>
                <th className="px-3 py-2.5 font-medium">Exposure</th>
                <th className="px-5 py-2.5 text-right font-medium">Risk</th>
              </tr>
            </thead>
            <tbody>
              {sorted.map((a) => {
                const iface = a.interfaces[0];
                const sub = [a.fingerprint.vendor, a.fingerprint.os]
                  .filter(Boolean)
                  .join(" · ");
                return (
                  <tr
                    key={a.id}
                    onClick={() => setSelected(a)}
                    className="cursor-pointer border-t border-line/70 transition-colors hover:bg-surface-2/50"
                  >
                    <td className="px-5 py-3">
                      <div className="font-medium">
                        {a.fingerprint.device_type ?? "unknown device"}
                      </div>
                      <div className="text-xs text-muted">{sub}</div>
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
                    <td className="px-5 py-3 text-right">
                      <RiskBadge band={a.risk.band} value={a.risk.value} />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>

      <AssetDrawer asset={selected} onClose={() => setSelected(null)} />
    </div>
  );
}
