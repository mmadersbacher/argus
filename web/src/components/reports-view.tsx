"use client";

// Reports page: a point-in-time exposure report for the tenant, built
// server-side by argus-report (GET /api/report). The report sheet itself is
// print-ready — the Print button uses the browser's print-to-PDF, and the
// print CSS in globals.css renders only #report-print.

import { useState } from "react";
import type { HighlightLevel, ReportTopAsset, ReportTopCve } from "@/lib/api";
import { useReport } from "@/lib/use-report";
import {
  assetTypeLabel,
  bandStyles,
  deviceRoleLabel,
  exposureLabel,
  formatCvss,
  formatEpss,
  timeAgo,
} from "@/lib/ui";
import {
  Badge,
  Button,
  PageHeader,
  Panel,
  Select,
  StatCard,
  type Column,
  type SortState,
  Table,
  SkeletonTable,
  Tooltip,
} from "@/components/ui";
import { RiskBadge, SeverityBadge } from "@/components/risk-badge";
import { ErrorState } from "@/components/states";

const levelTone: Record<HighlightLevel, "danger" | "warn" | "info"> = {
  critical: "danger",
  warn: "warn",
  info: "info",
};

const levelLabel: Record<HighlightLevel, string> = {
  critical: "Critical",
  warn: "Attention",
  info: "Note",
};

const criticalityLabel: Record<string, string> = {
  low: "Low",
  medium: "Medium",
  high: "High",
  critical: "Critical",
};

// ── Sort helpers ─────────────────────────────────────────────────────────────

function sortAssets(
  rows: ReportTopAsset[],
  s: SortState,
): ReportTopAsset[] {
  return [...rows].sort((a, b) => {
    let av: number | null = null;
    let bv: number | null = null;
    if (s.key === "risk") {
      av = a.risk.value;
      bv = b.risk.value;
    } else if (s.key === "cves") {
      av = a.cves;
      bv = b.cves;
    } else if (s.key === "kev_cves") {
      av = a.kev_cves;
      bv = b.kev_cves;
    }
    // string columns
    if (av === null && bv === null) return 0;
    // nulls last regardless of direction
    if (av === null) return 1;
    if (bv === null) return -1;
    return s.dir === "asc" ? av - bv : bv - av;
  });
}

function sortCves(
  rows: ReportTopCve[],
  s: SortState,
): ReportTopCve[] {
  return [...rows].sort((a, b) => {
    // KEV-first tiebreaker preserved when sorting by other columns
    if (s.key === "kev") {
      const ak = a.kev ? 1 : 0;
      const bk = b.kev ? 1 : 0;
      return s.dir === "asc" ? ak - bk : bk - ak;
    }
    let av: number | null = null;
    let bv: number | null = null;
    if (s.key === "cvss") {
      av = a.cvss;
      bv = b.cvss;
    } else if (s.key === "epss") {
      av = a.epss;
      bv = b.epss;
    } else if (s.key === "affected") {
      av = a.affected;
      bv = b.affected;
    }
    if (av === null && bv === null) {
      // tiebreak: KEV first
      return (b.kev ? 1 : 0) - (a.kev ? 1 : 0);
    }
    if (av === null) return 1;  // nulls last
    if (bv === null) return -1;
    const cmp = s.dir === "asc" ? av - bv : bv - av;
    if (cmp !== 0) return cmp;
    // tiebreak: KEV first
    return (b.kev ? 1 : 0) - (a.kev ? 1 : 0);
  });
}

// ── Column definitions ────────────────────────────────────────────────────────

const assetColumns: Column<ReportTopAsset>[] = [
  {
    key: "name",
    header: "Asset",
    render: (a) => (
      <>
        <span className="font-medium text-fg">{a.name}</span>
        {a.ip && a.ip !== a.name ? (
          <span className="ml-2 font-mono text-xs text-muted">{a.ip}</span>
        ) : null}
      </>
    ),
  },
  {
    key: "asset_type",
    header: "Type",
    render: (a) => <span className="text-fg-2">{assetTypeLabel[a.asset_type]}</span>,
  },
  {
    key: "exposure",
    header: "Exposure",
    render: (a) => <span className="text-fg-2">{exposureLabel[a.exposure]}</span>,
  },
  {
    key: "cves",
    header: "CVEs",
    numeric: true,
    sortable: true,
    render: (a) => <span className="tabular-nums">{a.cves}</span>,
  },
  {
    key: "kev_cves",
    header: "KEV",
    sortable: true,
    render: (a) =>
      a.kev_cves > 0 ? (
        <Badge tone="danger">{a.kev_cves} KEV</Badge>
      ) : (
        <span className="text-muted">—</span>
      ),
  },
  {
    key: "risk",
    header: "Risk",
    sortable: true,
    render: (a) => <RiskBadge band={a.risk.band} value={a.risk.value} />,
  },
];

const cveColumns: Column<ReportTopCve>[] = [
  {
    key: "cve_id",
    header: "CVE",
    render: (v) => (
      <span className="font-mono text-xs text-fg">{v.cve_id}</span>
    ),
  },
  {
    key: "severity",
    header: "Severity",
    render: (v) => <SeverityBadge severity={v.severity} />,
  },
  {
    key: "cvss",
    header: "CVSS",
    numeric: true,
    sortable: true,
    render: (v) => <span className="tabular-nums">{formatCvss(v.cvss)}</span>,
  },
  {
    key: "epss",
    header: "EPSS",
    numeric: true,
    sortable: true,
    render: (v) => <span className="tabular-nums">{formatEpss(v.epss)}</span>,
  },
  {
    key: "kev",
    header: "KEV",
    sortable: true,
    render: (v) =>
      v.kev ? (
        <Badge tone="danger">KEV</Badge>
      ) : (
        <span className="text-muted">—</span>
      ),
  },
  {
    key: "affected",
    header: "Affected",
    numeric: true,
    sortable: true,
    render: (v) => <span className="tabular-nums">{v.affected}</span>,
  },
];

// ── Loading skeleton shaped for the reports page ──────────────────────────────

function ReportsSkeleton() {
  return (
    <div role="status" className="animate-pulse space-y-6">
      {/* letterhead */}
      <div aria-hidden="true" className="rounded-xl border border-line bg-surface p-5">
        <div className="h-5 w-52 rounded bg-line/70" />
        <div className="mt-2 h-3 w-36 rounded bg-line/40" />
      </div>
      {/* highlights */}
      <div aria-hidden="true" className="rounded-xl border border-line bg-surface p-5 space-y-2.5">
        <div className="h-4 w-40 rounded bg-line/70" />
        {[80, 95, 70].map((w, i) => (
          <div key={i} className="h-4 rounded bg-line/40" style={{ width: `${w}%` }} />
        ))}
      </div>
      {/* stat cards */}
      <div aria-hidden="true" className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-6">
        {Array.from({ length: 6 }).map((_, i) => (
          <div key={i} className="rounded-xl border border-line bg-surface p-5">
            <div className="h-3 w-20 rounded bg-line/70" />
            <div className="mt-3 h-7 w-16 rounded-md bg-line/40" />
          </div>
        ))}
      </div>
      {/* two-col panels */}
      <div aria-hidden="true" className="grid gap-6 lg:grid-cols-2">
        {[1, 2].map((i) => (
          <div key={i} className="rounded-xl border border-line bg-surface p-5 space-y-3">
            <div className="h-4 w-36 rounded bg-line/70" />
            <SkeletonTable rows={5} cols={2} />
          </div>
        ))}
      </div>
      {/* top-risk assets table */}
      <div aria-hidden="true" className="rounded-xl border border-line bg-surface p-5 space-y-3">
        <div className="h-4 w-44 rounded bg-line/70" />
        <SkeletonTable rows={10} cols={6} />
      </div>
      {/* top CVEs table */}
      <div aria-hidden="true" className="rounded-xl border border-line bg-surface p-5 space-y-3">
        <div className="h-4 w-52 rounded bg-line/70" />
        <SkeletonTable rows={10} cols={6} />
      </div>
      <span className="sr-only">Loading report…</span>
    </div>
  );
}

// ── Main view ─────────────────────────────────────────────────────────────────

export function ReportsView() {
  const [days, setDays] = useState(30);
  const { report, error, loading } = useReport(days);

  // Sort state: assets default desc by risk; CVEs default desc by CVSS (KEV-first is a tiebreaker)
  const [assetSort, setAssetSort] = useState<SortState>({ key: "risk", dir: "desc" });
  const [cveSort, setCveSort] = useState<SortState>({ key: "cvss", dir: "desc" });

  if (loading && !report) return <ReportsSkeleton />;
  if (error && !report) return <ErrorState message={error} />;
  if (!report) return null;

  const generated = new Date(report.generated_at).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
  const inv = report.inventory;
  const vulns = report.vulnerabilities;
  const distributionTotal = Math.max(1, inv.total);

  const sortedAssets = sortAssets(report.risk.top_assets, assetSort);
  const sortedCves = sortCves(vulns.top_cves, cveSort);

  return (
    <div>
      <PageHeader
        title="Reports"
        description="Point-in-time exposure report — print it or save it as PDF for stakeholders."
        actions={
          <div className="no-print flex items-center gap-2">
            <Select
              value={days}
              onChange={(e) => setDays(Number(e.target.value))}
              aria-label="Reporting period"
              className="w-auto"
            >
              <option value={7}>Last 7 days</option>
              <option value={30}>Last 30 days</option>
              <option value={90}>Last 90 days</option>
            </Select>
            <Button onClick={() => window.print()}>Print / PDF</Button>
          </div>
        }
      />

      <div id="report-print" className="space-y-6">
        {/* letterhead */}
        <Panel bodyClassName="px-5 py-4">
          <div className="flex flex-wrap items-baseline justify-between gap-x-6 gap-y-1">
            <div>
              <h2 className="text-base font-semibold text-fg">
                Argus Exposure Report
              </h2>
              <p className="mt-0.5 text-xs text-muted">
                Reporting period: last {report.period_days} days
              </p>
            </div>
            <p className="text-xs text-muted">Generated {generated}</p>
          </div>
        </Panel>

        {/* executive summary */}
        <Panel title="Executive summary">
          <ul className="space-y-2.5">
            {report.highlights.map((h) => (
              <li key={h.text} className="flex items-start gap-2.5">
                <span className="shrink-0 pt-px">
                  <Badge tone={levelTone[h.level]}>{levelLabel[h.level]}</Badge>
                </span>
                <span className="text-sm leading-relaxed text-fg-2">
                  {h.text}
                </span>
              </li>
            ))}
          </ul>
        </Panel>

        {/* key numbers */}
        <div className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-6">
          <StatCard label="Assets" value={inv.total} />
          <StatCard
            label="Internet-facing"
            value={inv.internet_facing}
            tone={inv.internet_facing > 0 ? "warn" : "default"}
          />
          <StatCard label="Unique CVEs" value={vulns.unique_cves} />
          <StatCard
            label="KEV CVEs"
            value={vulns.kev_cves}
            tone={vulns.kev_cves > 0 ? "danger" : "ok"}
          />
          <StatCard label="Avg. risk" value={report.risk.average.toFixed(1)} />
          <StatCard
            label="Scan coverage"
            value={`${report.monitoring.coverage_percent.toFixed(0)}%`}
            hint={`seen in ${report.period_days}d`}
          />
        </div>

        <div className="grid gap-6 lg:grid-cols-2">
          {/* risk distribution */}
          <Panel title="Risk distribution">
            <div className="space-y-2.5">
              {report.risk.distribution.map((b) => {
                const style = bandStyles[b.band];
                return (
                  <div key={b.band} className="flex items-center gap-3">
                    <span className={`w-16 text-xs font-medium ${style.text}`}>
                      {style.label}
                    </span>
                    <div className="h-2 flex-1 overflow-hidden rounded-full bg-surface-2">
                      <div
                        className={`h-full rounded-full ${style.bar}`}
                        style={{
                          width: `${(b.count / distributionTotal) * 100}%`,
                        }}
                      />
                    </div>
                    <span className="w-8 text-right text-xs tabular-nums text-fg-2">
                      {b.count}
                    </span>
                  </div>
                );
              })}
            </div>
          </Panel>

          {/* inventory breakdown */}
          <Panel title="Inventory">
            <div className="grid grid-cols-2 gap-6">
              <div>
                <p className="mb-2 text-[11px] font-semibold uppercase tracking-[0.08em] text-muted">
                  By type
                </p>
                <ul className="space-y-1.5">
                  {inv.by_type.map((t) => (
                    <li
                      key={t.asset_type}
                      className="flex items-center justify-between text-sm"
                    >
                      <span className="text-fg-2">
                        {assetTypeLabel[t.asset_type]}
                      </span>
                      <span className="tabular-nums text-fg">{t.count}</span>
                    </li>
                  ))}
                  {inv.by_type.length === 0 ? (
                    <li className="text-sm text-muted">No assets yet.</li>
                  ) : null}
                </ul>
              </div>
              <div>
                <p className="mb-2 text-[11px] font-semibold uppercase tracking-[0.08em] text-muted">
                  By criticality
                </p>
                <ul className="space-y-1.5">
                  {inv.by_criticality.map((c) => (
                    <li
                      key={c.criticality}
                      className="flex items-center justify-between text-sm"
                    >
                      <span className="text-fg-2">
                        {criticalityLabel[c.criticality] ?? c.criticality}
                      </span>
                      <span className="tabular-nums text-fg">{c.count}</span>
                    </li>
                  ))}
                </ul>
                <p className="mt-3 text-xs text-muted">
                  {inv.new_in_period} new · {inv.stale} not seen in{" "}
                  {report.period_days}d
                </p>
              </div>
            </div>
            {inv.by_role && inv.by_role.length > 0 ? (
              <div className="mt-6 border-t border-line pt-4">
                <p className="mb-2 text-[11px] font-semibold uppercase tracking-[0.08em] text-muted">
                  By device role
                </p>
                <ul className="grid grid-cols-2 gap-x-6 gap-y-1.5">
                  {inv.by_role.map((r) => (
                    <li
                      key={r.role}
                      className="flex items-center justify-between text-sm"
                    >
                      <span className="text-fg-2">
                        {deviceRoleLabel[r.role] ?? r.role}
                      </span>
                      <span className="tabular-nums text-fg">{r.count}</span>
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}
          </Panel>
        </div>

        {/* top risk assets */}
        <Panel
          title="Highest-risk assets"
          description="Top 10 by composite risk score."
          bodyClassName="overflow-x-auto"
        >
          {report.risk.top_assets.length === 0 ? (
            <p className="px-5 py-4 text-sm text-muted">No assets yet.</p>
          ) : (
            <Table<ReportTopAsset>
              columns={assetColumns}
              rows={sortedAssets}
              getRowId={(a) => `${a.name}-${a.ip ?? ""}`}
              sort={assetSort}
              onSortChange={setAssetSort}
              density="compact"
              empty="No assets yet."
            />
          )}
        </Panel>

        {/* top CVEs */}
        <Panel
          title="Most urgent vulnerabilities"
          description="Top 10 — KEV first, then exploit probability (EPSS), then CVSS."
          bodyClassName="overflow-x-auto"
          actions={
            <div className="no-print flex items-center gap-3 text-xs text-muted">
              <Tooltip
                content="CVSS: Common Vulnerability Scoring System — a standardised severity score from 0.0 to 10.0."
                side="top"
              >
                <span className="cursor-default underline decoration-dashed underline-offset-2" tabIndex={0}>
                  CVSS
                </span>
              </Tooltip>
              <Tooltip
                content="EPSS: Exploit Prediction Scoring System — probability (0–100%) that a CVE will be exploited in the next 30 days."
                side="top"
              >
                <span className="cursor-default underline decoration-dashed underline-offset-2" tabIndex={0}>
                  EPSS
                </span>
              </Tooltip>
              <Tooltip
                content="KEV: CISA Known Exploited Vulnerabilities catalogue — these CVEs have confirmed active exploitation."
                side="top"
              >
                <span className="cursor-default underline decoration-dashed underline-offset-2" tabIndex={0}>
                  KEV
                </span>
              </Tooltip>
            </div>
          }
        >
          {vulns.top_cves.length === 0 ? (
            <p className="px-5 py-4 text-sm text-muted">
              No correlated CVEs in the inventory.
            </p>
          ) : (
            <Table<ReportTopCve>
              columns={cveColumns}
              rows={sortedCves}
              getRowId={(v) => v.cve_id}
              sort={cveSort}
              onSortChange={setCveSort}
              density="compact"
              empty="No correlated CVEs in the inventory."
            />
          )}
        </Panel>

        <div className="grid gap-6 lg:grid-cols-2">
          {/* activity */}
          <Panel
            title="Changes in the period"
            description={`Recorded by continuous monitoring over the last ${report.period_days} days.`}
          >
            <dl className="grid grid-cols-2 gap-x-6 gap-y-3 text-sm">
              {[
                ["New assets", report.activity.new_assets],
                ["Service changes", report.activity.service_changes],
                ["Vulnerability changes", report.activity.vuln_changes],
                ["Risk-band changes", report.activity.risk_changes],
              ].map(([label, value]) => (
                <div
                  key={String(label)}
                  className="flex items-center justify-between"
                >
                  <dt className="text-fg-2">{label}</dt>
                  <dd className="tabular-nums font-medium text-fg">{value}</dd>
                </div>
              ))}
            </dl>
          </Panel>

          {/* monitoring */}
          <Panel title="Monitoring">
            {report.monitoring.configured ? (
              <dl className="space-y-3 text-sm">
                <div className="flex items-center justify-between">
                  <dt className="text-fg-2">Status</dt>
                  <dd>
                    {report.monitoring.enabled ? (
                      <Badge tone="ok">Enabled</Badge>
                    ) : (
                      <Badge tone="warn">Disabled</Badge>
                    )}
                  </dd>
                </div>
                <div className="flex items-center justify-between">
                  <dt className="text-fg-2">Target</dt>
                  <dd className="font-mono text-xs text-fg">
                    {report.monitoring.target}
                  </dd>
                </div>
                <div className="flex items-center justify-between">
                  <dt className="text-fg-2">Cadence</dt>
                  <dd className="text-fg">
                    every {report.monitoring.interval_minutes} min
                  </dd>
                </div>
                <div className="flex items-center justify-between">
                  <dt className="text-fg-2">Last run</dt>
                  <dd className="text-fg">
                    {report.monitoring.last_run_at
                      ? timeAgo(report.monitoring.last_run_at)
                      : "never"}
                  </dd>
                </div>
              </dl>
            ) : (
              <p className="text-sm text-muted">
                No monitor configured — the inventory only updates on manual
                scans. Configure one under Settings.
              </p>
            )}
          </Panel>
        </div>
      </div>
    </div>
  );
}
