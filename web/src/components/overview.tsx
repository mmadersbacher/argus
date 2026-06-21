"use client";

// Dashboard: KPI row (with drill-down links), risk distribution, top-critical-issues
// panel, data-sources panel, and the live activity feed.
// Data: useInventory (15s poll) + useVulns (30s poll). No fabricated trends or deltas.

import Link from "next/link";
import { useInventory } from "@/lib/use-inventory";
import { useVulns } from "@/lib/use-vulns";
import { formatCvss } from "@/lib/ui";
import { ActivityFeed } from "@/components/activity-feed";
import { LiveRegion } from "@/components/live-region";
import { DataSources } from "@/components/data-sources";
import { RiskDistribution } from "@/components/risk-distribution";
import { RiskBadge, SeverityBadge } from "@/components/risk-badge";
import { ErrorState, LoadingState } from "@/components/states";
import { Badge, PageHeader, Panel, StatCard } from "@/components/ui";

// ------ KPI card wrapped in a Next.js Link ----------------------------------

/**
 * A StatCard that is also a keyboard-accessible link.
 * The <Link> renders as an <a>; we overlay it via a block wrapper so the whole
 * card surface is the click target, but the StatCard content is unchanged.
 */
function LinkedStatCard({
  href,
  label,
  value,
  hint,
  tone,
}: {
  href: string;
  label: string;
  value: React.ReactNode;
  hint?: string;
  tone?: "default" | "accent" | "danger" | "warn" | "ok";
}) {
  return (
    <Link
      href={href}
      className="group block rounded-xl focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40"
      aria-label={`${label}: ${typeof value === "number" ? value.toString() : String(value)}${hint ? ` — ${hint}` : ""}`}
    >
      {/* Hover ring to signal interactivity without overriding the StatCard layout */}
      <div className="transition-shadow group-hover:shadow-[0_0_0_2px_var(--color-accent-muted,theme(colors.blue.400/20))]  rounded-xl">
        <StatCard label={label} value={value} hint={hint} tone={tone} />
      </div>
    </Link>
  );
}

// ------ Top critical issues -------------------------------------------------

const TOP_N = 5;

function TopCriticalIssues({
  assets,
  vulns,
}: {
  assets: ReturnType<typeof useInventory>["assets"];
  vulns: ReturnType<typeof useVulns>["vulns"];
}) {
  // Top N highest-risk assets (by numeric risk value, desc)
  const topAssets = [...assets]
    .sort((a, b) => b.risk.value - a.risk.value)
    .slice(0, TOP_N);

  // Top N CVEs: KEV first, then by CVSS desc, nulls last
  const topCves = vulns === null
    ? []
    : [...vulns]
        .sort((a, b) => {
          // KEV > non-KEV
          if (a.kev !== b.kev) return a.kev ? -1 : 1;
          // CVSS desc, nulls last
          if (a.cvss === null && b.cvss === null) return 0;
          if (a.cvss === null) return 1;
          if (b.cvss === null) return -1;
          return b.cvss - a.cvss;
        })
        .slice(0, TOP_N);

  const hasAssets = topAssets.length > 0;
  const hasCves = topCves.length > 0;

  if (!hasAssets && !hasCves) return null;

  return (
    <Panel title="Top critical issues" description="Highest-risk assets and CVEs in scope">
      <div className="grid gap-6 sm:grid-cols-2">
        {/* Left: top assets */}
        <div>
          <p className="mb-3 text-[11px] font-medium uppercase tracking-[0.08em] text-muted">
            Assets by risk
          </p>
          {hasAssets ? (
            <ul className="divide-y divide-line rounded-lg border border-line">
              {topAssets.map((a) => {
                const label =
                  a.fingerprint.device_type ??
                  a.interfaces.find((i) => i.ip)?.ip ??
                  a.id;
                const sub = [
                  a.interfaces.find((i) => i.ip)?.ip,
                  a.fingerprint.vendor,
                ]
                  .filter(Boolean)
                  .join(" · ");
                return (
                  <li key={a.id}>
                    <Link
                      href="/assets"
                      className="flex items-center justify-between gap-3 rounded-lg px-3 py-2.5 transition-colors hover:bg-surface-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent/40"
                      aria-label={`${label} — risk ${Math.round(a.risk.value)}`}
                    >
                      <div className="min-w-0">
                        <p className="truncate text-sm font-medium text-fg">
                          {label}
                        </p>
                        {sub ? (
                          <p className="truncate text-xs text-muted">{sub}</p>
                        ) : null}
                      </div>
                      <RiskBadge band={a.risk.band} value={a.risk.value} />
                    </Link>
                  </li>
                );
              })}
            </ul>
          ) : (
            <p className="text-sm text-muted">No assets in inventory yet.</p>
          )}
          {hasAssets ? (
            <Link
              href="/assets"
              className="mt-3 inline-flex text-xs text-accent underline-offset-2 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40 rounded"
            >
              View all assets →
            </Link>
          ) : null}
        </div>

        {/* Right: top CVEs */}
        <div>
          <p className="mb-3 text-[11px] font-medium uppercase tracking-[0.08em] text-muted">
            CVEs by severity
          </p>
          {vulns === null ? (
            <p className="text-sm text-muted">Loading vulnerabilities…</p>
          ) : hasCves ? (
            <ul className="divide-y divide-line rounded-lg border border-line">
              {topCves.map((v) => (
                <li key={v.cve_id}>
                  <Link
                    href="/vulns"
                    className="flex items-center justify-between gap-3 rounded-lg px-3 py-2.5 transition-colors hover:bg-surface-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent/40"
                    aria-label={`${v.cve_id} — CVSS ${formatCvss(v.cvss)}${v.kev ? ", known exploited" : ""}`}
                  >
                    <div className="min-w-0 flex items-center gap-2">
                      <span className="font-mono text-xs text-fg">{v.cve_id}</span>
                      {v.kev ? (
                        <Badge tone="danger">KEV</Badge>
                      ) : null}
                    </div>
                    <div className="flex shrink-0 items-center gap-2">
                      <span className="tabular-nums text-xs text-muted">
                        CVSS {formatCvss(v.cvss)}
                      </span>
                      <SeverityBadge severity={v.severity} />
                    </div>
                  </Link>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-muted">No CVEs correlated yet.</p>
          )}
          {hasCves ? (
            <Link
              href="/vulns"
              className="mt-3 inline-flex text-xs text-accent underline-offset-2 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40 rounded"
            >
              View all vulnerabilities →
            </Link>
          ) : null}
        </div>
      </div>
    </Panel>
  );
}

// ------ Main component ------------------------------------------------------

export function Overview() {
  const { summary, assets, error, loading } = useInventory();
  const { vulns } = useVulns();

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
        {/* KPI row — each card navigates to the relevant view.
            Note: assets-view has no URL-based exposure/band filter, so
            internet-facing and avg-risk link to /assets (unfiltered).
            High/Critical links to /vulns which shows CVE severity. */}
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <LinkedStatCard
            href="/assets"
            label="Total assets"
            value={total}
            hint="in inventory"
          />
          <LinkedStatCard
            href="/assets"
            label="Internet-facing"
            value={internetFacing}
            hint="externally exposed"
            tone={internetFacing > 0 ? "warn" : "default"}
          />
          <LinkedStatCard
            href="/vulns"
            label="High / Critical"
            value={criticalOrHigh}
            hint="need attention"
            tone={criticalOrHigh > 0 ? "danger" : "default"}
          />
          <LinkedStatCard
            href="/assets"
            label="Avg risk"
            value={Math.round(summary?.avg_risk ?? 0)}
            hint="0–100 heuristic composite"
          />
        </div>

        {/* Top critical issues — derived from current inventory snapshot */}
        <TopCriticalIssues assets={assets} vulns={vulns} />

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

          {/* Activity feed — real services.changed / vulns.changed / risk.changed events */}
          <ActivityFeed className="flex h-full max-h-[820px] flex-col" />
        </div>
      </div>
    </div>
  );
}
