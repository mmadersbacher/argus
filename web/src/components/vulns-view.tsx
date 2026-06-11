"use client";

// Vulnerabilities page: CVE-centric rollup across the inventory.
// Data comes pre-sorted from GET /api/vulns (kev first, then cvss desc) —
// filters preserve that order, we never re-sort.

import { useEffect, useMemo, useState } from "react";
import type { Severity } from "@/lib/api";
import { useVulns } from "@/lib/use-vulns";
import { formatCvss, formatEpss } from "@/lib/ui";
import {
  Badge,
  Drawer,
  Input,
  PageHeader,
  Panel,
  Select,
  StatCard,
  Toggle,
} from "@/components/ui";
import { Icon } from "@/components/icon";
import { RiskBadge, SeverityBadge } from "@/components/risk-badge";
import { EmptyState, ErrorState, LoadingState } from "@/components/states";

const nvdUrl = (cveId: string) => `https://nvd.nist.gov/vuln/detail/${cveId}`;

// Anchor styled as a secondary button — external links cannot use <Button>.
const linkButtonClasses =
  "inline-flex h-9 items-center justify-center gap-1.5 rounded-lg border border-line bg-surface px-3.5 text-sm font-medium text-fg transition-colors hover:bg-surface-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40";

// ---- page -------------------------------------------------------------------

export function VulnsView() {
  const { vulns, error } = useVulns();
  // Selection holds the id, never the object — the drawer re-derives the row
  // from the freshest poll data each render so it can never go stale.
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [q, setQ] = useState("");
  const [severity, setSeverity] = useState<"all" | Severity>("all");
  const [kevOnly, setKevOnly] = useState(false);

  // If the selected CVE vanished from the rollup after a poll, close the drawer.
  useEffect(() => {
    if (selectedId === null) return;
    if (!(vulns ?? []).some((v) => v.cve_id === selectedId)) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setSelectedId(null);
    }
  }, [vulns, selectedId]);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (vulns ?? []).filter((v) => {
      if (needle && !v.cve_id.toLowerCase().includes(needle)) return false;
      if (severity !== "all" && v.severity !== severity) return false;
      if (kevOnly && !v.kev) return false;
      return true;
    });
  }, [vulns, q, severity, kevOnly]);

  // Full-page states only before the first successful load — after that,
  // failed polls keep the last good data on screen (the hook stays silent).
  if (vulns === null) {
    return error ? <ErrorState message={error} /> : <LoadingState />;
  }

  const selected =
    selectedId === null
      ? null
      : (vulns.find((v) => v.cve_id === selectedId) ?? null);

  const kevCount = vulns.filter((v) => v.kev).length;
  const criticalCount = vulns.filter((v) => v.severity === "critical").length;
  const assetsAffected = new Set(
    vulns.flatMap((v) => v.affected.map((a) => a.id)),
  ).size;

  return (
    <div className="space-y-6">
      <div className="argus-rise">
        <PageHeader
          title="Vulnerabilities"
          description="CVE exposure across the inventory"
        />
      </div>

      {vulns.length === 0 ? (
        <Panel bodyClassName="p-0">
          <EmptyState
            title="No vulnerabilities correlated yet"
            hint="Run a discovery scan or import nmap results from the Assets page to correlate CVE findings across your inventory."
          />
        </Panel>
      ) : (
        <>
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <StatCard label="Unique CVEs" value={vulns.length} />
            <StatCard
              label="Known exploited"
              value={kevCount}
              tone={kevCount > 0 ? "danger" : "default"}
              hint="CISA KEV catalog"
            />
            <StatCard
              label="Critical severity"
              value={criticalCount}
              tone={criticalCount > 0 ? "danger" : "default"}
            />
            <StatCard
              label="Assets affected"
              value={assetsAffected}
              hint="Distinct assets with findings"
            />
          </div>

          <Panel
            title="CVE findings"
            description={`${filtered.length} of ${vulns.length} CVEs`}
            actions={
              <>
                <div className="w-52">
                  <Input
                    value={q}
                    onChange={(e) => setQ(e.target.value)}
                    placeholder="Filter by CVE ID…"
                    aria-label="Filter by CVE ID"
                  />
                </div>
                <div className="w-36">
                  <Select
                    value={severity}
                    onChange={(e) => setSeverity(e.target.value as "all" | Severity)}
                    aria-label="Filter by severity"
                  >
                    <option value="all">All severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                    <option value="none">None</option>
                  </Select>
                </div>
                <Toggle checked={kevOnly} onChange={setKevOnly} label="KEV only" />
              </>
            }
            bodyClassName="p-0"
          >
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-line bg-surface-2/60 text-left text-xs text-muted">
                    <th className="px-4 py-3 font-medium">CVE</th>
                    <th className="px-4 py-3 font-medium">Severity</th>
                    <th className="px-4 py-3 font-medium">CVSS</th>
                    <th className="px-4 py-3 font-medium">EPSS</th>
                    <th className="px-4 py-3 font-medium">KEV</th>
                    <th className="px-4 py-3 font-medium">Affected assets</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((v) => {
                    const names = v.affected.slice(0, 2).map((a) => a.name);
                    const extra = v.affected.length - names.length;
                    return (
                      <tr
                        key={v.cve_id}
                        onClick={() => setSelectedId(v.cve_id)}
                        className="cursor-pointer border-b border-line transition-colors last:border-0 hover:bg-surface-2/60"
                      >
                        <td className="px-4 py-3">
                          <span className="inline-flex items-center gap-1.5">
                            {/* Keyboard path into the drawer — the row onClick
                                is mouse convenience only. */}
                            <button
                              type="button"
                              onClick={() => setSelectedId(v.cve_id)}
                              className="rounded text-left font-mono text-xs text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40"
                            >
                              {v.cve_id}
                            </button>
                            <a
                              href={nvdUrl(v.cve_id)}
                              target="_blank"
                              rel="noreferrer"
                              aria-label={`View ${v.cve_id} on NVD`}
                              onClick={(e) => e.stopPropagation()}
                              className="rounded text-muted transition-colors hover:text-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40"
                            >
                              <Icon name="external" size={13} />
                            </a>
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <SeverityBadge severity={v.severity} />
                        </td>
                        <td className="px-4 py-3 tabular-nums">
                          {formatCvss(v.cvss)}
                        </td>
                        <td className="px-4 py-3 tabular-nums">
                          {formatEpss(v.epss)}
                        </td>
                        <td className="px-4 py-3">
                          {v.kev ? (
                            <Badge tone="danger">KEV</Badge>
                          ) : (
                            <span className="text-muted">—</span>
                          )}
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <span className="tabular-nums text-fg">
                              {v.affected.length}
                            </span>
                            {names.length > 0 ? (
                              <span className="max-w-56 truncate text-xs text-muted">
                                {names.join(", ")}
                                {extra > 0 ? ` +${extra} more` : ""}
                              </span>
                            ) : null}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                  {filtered.length === 0 ? (
                    <tr>
                      <td colSpan={6}>
                        <EmptyState
                          title="No CVEs match"
                          hint="Adjust the filters or clear the CVE ID search to see more findings."
                        />
                      </td>
                    </tr>
                  ) : null}
                </tbody>
              </table>
            </div>
          </Panel>
        </>
      )}

      {selected ? (
        <Drawer
          onClose={() => setSelectedId(null)}
          overline="Vulnerability"
          title={selected.cve_id}
          mono
          badges={
            <>
              <SeverityBadge severity={selected.severity} />
              {selected.kev ? <Badge tone="danger">Known exploited</Badge> : null}
            </>
          }
          footer={
            <a
              href={nvdUrl(selected.cve_id)}
              target="_blank"
              rel="noreferrer"
              className={linkButtonClasses}
            >
              <Icon name="external" size={14} />
              View on NVD
            </a>
          }
        >
          <div className="grid grid-cols-2 gap-3">
            <StatCard
              label="CVSS"
              value={formatCvss(selected.cvss)}
              hint="Base score"
            />
            <StatCard
              label="EPSS"
              value={formatEpss(selected.epss)}
              hint="Exploit probability"
            />
          </div>

          <div>
            <p className="text-[11px] font-medium uppercase tracking-[0.08em] text-muted">
              Affected assets ({selected.affected.length})
            </p>
            {selected.affected.length === 0 ? (
              <p className="mt-2 text-sm text-muted">No assets affected.</p>
            ) : (
              <ul className="mt-2 divide-y divide-line rounded-lg border border-line">
                {selected.affected.map((a) => (
                  <li
                    key={a.id}
                    className="flex items-center justify-between gap-3 px-3 py-2.5"
                  >
                    <span className="min-w-0 truncate text-sm font-medium text-fg">
                      {a.name}
                    </span>
                    <RiskBadge band={a.band} value={a.risk} />
                  </li>
                ))}
              </ul>
            )}
          </div>
        </Drawer>
      ) : null}
    </div>
  );
}
