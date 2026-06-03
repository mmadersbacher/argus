"use client";

import { useEffect, useState } from "react";
import {
  getAssets,
  getSummary,
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
      <div className={`mt-2 text-3xl font-semibold tabular-nums ${text}`}>
        {value}
      </div>
      <div className="mt-1 text-xs text-muted">{hint}</div>
    </div>
  );
}

function DashboardSkeleton() {
  return (
    <div className="space-y-6">
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <div
            key={i}
            className="h-28 animate-pulse rounded-xl border border-line bg-surface/70"
          />
        ))}
      </div>
      <div className="h-28 animate-pulse rounded-xl border border-line bg-surface/70" />
      <div className="h-64 animate-pulse rounded-xl border border-line bg-surface/70" />
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
        Start it with{" "}
        <span className="text-fg">cargo run -p argus-api</span> (expects
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

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const [s, a] = await Promise.all([getSummary(), getAssets()]);
        if (!alive) return;
        setSummary(s);
        setAssets(a);
        setError(null);
      } catch (e) {
        if (!alive) return;
        setError(e instanceof Error ? e.message : "Failed to reach argus-api");
      } finally {
        if (alive) setLoading(false);
      }
    };
    void load();
    const id = setInterval(() => void load(), 15000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

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
      <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard
          label="Total Assets"
          value={summary?.total_assets ?? assets.length}
          hint="discovered"
          accent="accent"
        />
        <MetricCard
          label="Internet-facing"
          value={summary?.internet_facing ?? 0}
          hint="externally exposed"
          accent="low"
        />
        <MetricCard
          label="High / Critical"
          value={summary?.critical_or_high ?? 0}
          hint="need attention"
          accent="crit"
        />
        <MetricCard
          label="Avg Risk"
          value={Math.round(summary?.avg_risk ?? 0)}
          hint="0–100 composite"
          accent="accent2"
        />
      </section>

      <section className="rounded-xl border border-line bg-surface/70 p-5">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-sm font-medium">Risk distribution</h2>
          <span className="text-xs text-muted">{assets.length} assets</span>
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
        <div className="mt-3 flex flex-wrap gap-4">
          {counts.map(({ band, n }) => (
            <div key={band} className="flex items-center gap-2 text-xs text-muted">
              <span className={`h-2 w-2 rounded-full ${bandStyles[band].bar}`} />
              {bandStyles[band].label}{" "}
              <span className="font-mono text-fg">{n}</span>
            </div>
          ))}
        </div>
      </section>

      <section className="overflow-hidden rounded-xl border border-line bg-surface/70">
        <div className="flex items-center justify-between border-b border-line px-5 py-4">
          <h2 className="text-sm font-medium">Assets</h2>
          <span className="text-xs text-muted">sorted by risk</span>
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
                    className="border-t border-line/70 transition-colors hover:bg-surface-2/50"
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
                    <td className="px-3 py-3 text-xs">
                      {exposureLabel[a.exposure]}
                    </td>
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
    </div>
  );
}
