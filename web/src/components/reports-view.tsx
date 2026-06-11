"use client";

// Reports page: a point-in-time exposure report for the tenant, built
// server-side by argus-report (GET /api/report). The report sheet itself is
// print-ready — the Print button uses the browser's print-to-PDF, and the
// print CSS in globals.css renders only #report-print.

import { useState } from "react";
import type { HighlightLevel } from "@/lib/api";
import { useReport } from "@/lib/use-report";
import {
  assetTypeLabel,
  bandStyles,
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
} from "@/components/ui";
import { RiskBadge, SeverityBadge } from "@/components/risk-badge";
import { ErrorState, LoadingState } from "@/components/states";

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

const th =
  "px-4 py-2.5 text-left text-[11px] font-semibold uppercase tracking-[0.08em] text-muted";
const td = "px-4 py-3";

export function ReportsView() {
  const [days, setDays] = useState(30);
  const { report, error, loading } = useReport(days);

  if (loading && !report) return <LoadingState />;
  if (error && !report) return <ErrorState message={error} />;
  if (!report) return null;

  const generated = new Date(report.generated_at).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
  const inv = report.inventory;
  const vulns = report.vulnerabilities;
  const distributionTotal = Math.max(1, inv.total);

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
            <table className="w-full min-w-[640px] text-sm">
              <thead>
                <tr className="border-b border-line">
                  <th className={th}>Asset</th>
                  <th className={th}>Type</th>
                  <th className={th}>Exposure</th>
                  <th className={th}>CVEs</th>
                  <th className={th}>KEV</th>
                  <th className={th}>Risk</th>
                </tr>
              </thead>
              <tbody>
                {report.risk.top_assets.map((a) => (
                  <tr
                    key={`${a.name}-${a.ip ?? ""}`}
                    className="border-b border-line last:border-0"
                  >
                    <td className={td}>
                      <span className="font-medium text-fg">{a.name}</span>
                      {a.ip && a.ip !== a.name ? (
                        <span className="ml-2 font-mono text-xs text-muted">
                          {a.ip}
                        </span>
                      ) : null}
                    </td>
                    <td className={`${td} text-fg-2`}>
                      {assetTypeLabel[a.asset_type]}
                    </td>
                    <td className={`${td} text-fg-2`}>
                      {exposureLabel[a.exposure]}
                    </td>
                    <td className={`${td} tabular-nums`}>{a.cves}</td>
                    <td className={td}>
                      {a.kev_cves > 0 ? (
                        <Badge tone="danger">{a.kev_cves} KEV</Badge>
                      ) : (
                        <span className="text-muted">—</span>
                      )}
                    </td>
                    <td className={td}>
                      <RiskBadge band={a.risk.band} value={a.risk.value} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>

        {/* top CVEs */}
        <Panel
          title="Most urgent vulnerabilities"
          description="Top 10 — KEV first, then exploit probability (EPSS), then CVSS."
          bodyClassName="overflow-x-auto"
        >
          {vulns.top_cves.length === 0 ? (
            <p className="px-5 py-4 text-sm text-muted">
              No correlated CVEs in the inventory.
            </p>
          ) : (
            <table className="w-full min-w-[640px] text-sm">
              <thead>
                <tr className="border-b border-line">
                  <th className={th}>CVE</th>
                  <th className={th}>Severity</th>
                  <th className={th}>CVSS</th>
                  <th className={th}>EPSS</th>
                  <th className={th}>KEV</th>
                  <th className={th}>Affected</th>
                </tr>
              </thead>
              <tbody>
                {vulns.top_cves.map((v) => (
                  <tr
                    key={v.cve_id}
                    className="border-b border-line last:border-0"
                  >
                    <td className={`${td} font-mono text-xs text-fg`}>
                      {v.cve_id}
                    </td>
                    <td className={td}>
                      <SeverityBadge severity={v.severity} />
                    </td>
                    <td className={`${td} tabular-nums`}>
                      {formatCvss(v.cvss)}
                    </td>
                    <td className={`${td} tabular-nums`}>
                      {formatEpss(v.epss)}
                    </td>
                    <td className={td}>
                      {v.kev ? (
                        <Badge tone="danger">KEV</Badge>
                      ) : (
                        <span className="text-muted">—</span>
                      )}
                    </td>
                    <td className={`${td} tabular-nums`}>{v.affected}</td>
                  </tr>
                ))}
              </tbody>
            </table>
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
