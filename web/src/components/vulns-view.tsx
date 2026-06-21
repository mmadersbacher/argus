"use client";

// Vulnerabilities page: CVE-centric rollup across the inventory.
// Data comes pre-sorted from GET /api/vulns (kev first, then cvss desc) —
// client-side sort + pagination layer is added below.

import { useEffect, useMemo, useState } from "react";
import {
  setFinding,
  setFindingsBulk,
  type Confidence,
  type FindingState,
  type FindingStatus,
  type Severity,
} from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { useVulns } from "@/lib/use-vulns";
import {
  confidenceHint,
  confidenceLabel,
  formatCvss,
  formatEpss,
  isConfirmedConfidence,
  timeAgo,
} from "@/lib/ui";
import {
  Badge,
  Button,
  ButtonLink,
  Drawer,
  Input,
  PageHeader,
  Panel,
  Pagination,
  Select,
  Skeleton,
  SkeletonTable,
  StatCard,
  Table,
  Toggle,
  Tooltip,
  useToast,
  type Column,
  type SortState,
} from "@/components/ui";
import { Icon } from "@/components/icon";
import { LiveRegion } from "@/components/live-region";
import { RiskBadge, SeverityBadge } from "@/components/risk-badge";
import { EmptyState, ErrorState } from "@/components/states";

const PAGE_SIZE = 50;

const nvdUrl = (cveId: string) => `https://nvd.nist.gov/vuln/detail/${cveId}`;

const statusLabel: Record<FindingStatus, string> = {
  open: "Open",
  acknowledged: "Acknowledged",
  resolved: "Resolved",
  false_positive: "False positive",
};

const statusTone: Record<FindingStatus, "neutral" | "warn" | "ok" | "info"> = {
  open: "neutral",
  acknowledged: "warn",
  resolved: "ok",
  false_positive: "info",
};

const STATUS_OPTIONS: FindingStatus[] = [
  "open",
  "acknowledged",
  "resolved",
  "false_positive",
];

/** Triage controls for one (asset, CVE) finding inside the drawer.
 *  Mount with a key per asset+CVE so local note state resets on switch.
 *  Status saves immediately on select; the note saves on blur. Triage is
 *  metadata only — the risk score deliberately stays unchanged. */
function FindingTriage({
  assetId,
  cveId,
  finding,
  canEdit,
  onChanged,
}: {
  assetId: string;
  cveId: string;
  finding: FindingState | null;
  canEdit: boolean;
  onChanged: () => Promise<void>;
}) {
  const { toast } = useToast();
  const [note, setNote] = useState(finding?.note ?? "");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const status = finding?.status ?? "open";

  const save = async (next: FindingStatus, nextNote: string) => {
    setSaving(true);
    setError(null);
    try {
      await setFinding(assetId, cveId, next, nextNote.trim() || undefined);
      await onChanged();
      toast({ title: "Triage saved", tone: "ok" });
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Failed to save";
      setError(msg);
      toast({ title: "Triage failed", description: msg, tone: "danger" });
    } finally {
      setSaving(false);
    }
  };

  if (!canEdit) {
    if (!finding) return null;
    return (
      <div className="mt-1.5 space-y-1">
        <Badge tone={statusTone[finding.status]}>
          {statusLabel[finding.status]}
        </Badge>
        {finding.note ? (
          <p className="text-xs text-fg-2">{finding.note}</p>
        ) : null}
        <p className="text-[11px] text-muted">
          by {finding.updated_by} · {timeAgo(finding.updated_at)}
        </p>
      </div>
    );
  }

  return (
    <div className="mt-2 space-y-1.5">
      <Select
        value={status}
        disabled={saving}
        onChange={(e) => void save(e.target.value as FindingStatus, note)}
        aria-label={`Triage status of ${cveId}`}
        className="h-8 w-auto text-xs"
      >
        {STATUS_OPTIONS.map((s) => (
          <option key={s} value={s}>
            {statusLabel[s]}
          </option>
        ))}
      </Select>
      {finding ? (
        <>
          <Input
            value={note}
            disabled={saving}
            onChange={(e) => setNote(e.target.value)}
            onBlur={() => {
              if (note.trim() !== finding.note) void save(status, note);
            }}
            placeholder="Add a note (optional)"
            maxLength={500}
            aria-label={`Triage note for ${cveId}`}
            className="h-8 text-xs"
          />
          <p className="text-[11px] text-muted">
            {statusLabel[finding.status]} by {finding.updated_by} ·{" "}
            {timeAgo(finding.updated_at)}
          </p>
        </>
      ) : null}
      {error ? <p className="text-xs text-crit">{error}</p> : null}
    </div>
  );
}

/** One triage decision applied to every affected asset of the CVE at once.
 *  Deliberately an explicit Apply button (unlike the per-asset select's
 *  save-on-change): overwriting N decisions must not happen on a misclick. */
function BulkTriage({
  cveId,
  assetIds,
  onChanged,
}: {
  cveId: string;
  assetIds: string[];
  onChanged: () => Promise<void>;
}) {
  const { toast } = useToast();
  const [status, setStatus] = useState<FindingStatus>("acknowledged");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const apply = async () => {
    setBusy(true);
    setError(null);
    try {
      await setFindingsBulk(cveId, assetIds, status, note.trim() || undefined);
      setNote("");
      await onChanged();
      toast({ title: "Triage saved", tone: "ok" });
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Failed to apply";
      setError(msg);
      toast({ title: "Triage failed", description: msg, tone: "danger" });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Panel bodyClassName="p-3">
      <p className="text-[11px] font-medium uppercase tracking-[0.08em] text-muted">
        Triage all affected assets
      </p>
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <Select
          value={status}
          disabled={busy}
          onChange={(e) => setStatus(e.target.value as FindingStatus)}
          aria-label={`Bulk triage status for ${cveId}`}
          className="h-8 w-auto text-xs"
        >
          {STATUS_OPTIONS.map((s) => (
            <option key={s} value={s}>
              {statusLabel[s]}
            </option>
          ))}
        </Select>
        <div className="min-w-36 flex-1">
          <Input
            value={note}
            disabled={busy}
            onChange={(e) => setNote(e.target.value)}
            placeholder="Shared note (optional)"
            maxLength={500}
            aria-label={`Bulk triage note for ${cveId}`}
            className="h-8 text-xs"
          />
        </div>
        <Button
          size="sm"
          variant="secondary"
          disabled={busy}
          onClick={() => void apply()}
        >
          Apply to {assetIds.length} assets
        </Button>
      </div>
      {error ? <p className="mt-1.5 text-xs text-crit">{error}</p> : null}
    </Panel>
  );
}

type VulnRow = {
  cve_id: string;
  cvss: number | null;
  epss: number | null;
  severity: Severity;
  kev: boolean;
  confidence: Confidence;
  affected: Array<{
    id: string;
    name: string;
    resolved_but_detected: boolean;
    band: string;
    risk: number;
    match_confidence: Confidence;
    finding: FindingState | null;
  }>;
};

/** Multi-CVE bulk triage for table-level row selection. */
function BulkSelectionTriage({
  cveIds,
  vulns,
  onChanged,
  onClearSelection,
}: {
  cveIds: string[];
  vulns: VulnRow[];
  onChanged: () => Promise<void>;
  onClearSelection: () => void;
}) {
  const { toast } = useToast();
  const [status, setStatus] = useState<FindingStatus>("acknowledged");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (cveIds.length === 0) return null;

  const apply = async () => {
    setBusy(true);
    setError(null);
    try {
      // Call setFindingsBulk for each selected CVE independently.
      const byId = new Map(vulns.map((v) => [v.cve_id, v]));
      await Promise.all(
        cveIds.map((cveId) => {
          const vuln = byId.get(cveId);
          if (!vuln) return Promise.resolve();
          const assetIds = vuln.affected.map((a) => a.id);
          if (assetIds.length === 0) return Promise.resolve();
          return setFindingsBulk(cveId, assetIds, status, note.trim() || undefined);
        }),
      );
      setNote("");
      await onChanged();
      onClearSelection();
      toast({ title: "Triage saved", tone: "ok" });
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Failed to apply";
      setError(msg);
      toast({ title: "Triage failed", description: msg, tone: "danger" });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Panel bodyClassName="p-3">
      <p className="text-[11px] font-medium uppercase tracking-[0.08em] text-muted">
        Triage {cveIds.length} selected {cveIds.length === 1 ? "CVE" : "CVEs"} — all affected assets
      </p>
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <Select
          value={status}
          disabled={busy}
          onChange={(e) => setStatus(e.target.value as FindingStatus)}
          aria-label="Bulk triage status for selected CVEs"
          className="h-8 w-auto text-xs"
        >
          {STATUS_OPTIONS.map((s) => (
            <option key={s} value={s}>
              {statusLabel[s]}
            </option>
          ))}
        </Select>
        <div className="min-w-36 flex-1">
          <Input
            value={note}
            disabled={busy}
            onChange={(e) => setNote(e.target.value)}
            placeholder="Shared note (optional)"
            maxLength={500}
            aria-label="Bulk triage note for selected CVEs"
            className="h-8 text-xs"
          />
        </div>
        <Button
          size="sm"
          variant="secondary"
          disabled={busy}
          onClick={() => void apply()}
        >
          Apply to {cveIds.length} {cveIds.length === 1 ? "CVE" : "CVEs"}
        </Button>
      </div>
      {error ? <p className="mt-1.5 text-xs text-crit">{error}</p> : null}
    </Panel>
  );
}

// ---- sort helpers -----------------------------------------------------------

function sortVulns(rows: VulnRow[], sort: SortState): VulnRow[] {
  return [...rows].sort((a, b) => {
    const dir = sort.dir === "asc" ? 1 : -1;
    switch (sort.key) {
      case "kev":
        // true > false
        if (a.kev === b.kev) return 0;
        return (a.kev ? 1 : -1) * dir;
      case "cvss": {
        if (a.cvss === null && b.cvss === null) return 0;
        if (a.cvss === null) return 1;   // nulls always last
        if (b.cvss === null) return -1;
        return (a.cvss - b.cvss) * dir;
      }
      case "epss": {
        if (a.epss === null && b.epss === null) return 0;
        if (a.epss === null) return 1;
        if (b.epss === null) return -1;
        return (a.epss - b.epss) * dir;
      }
      case "affected":
        return (a.affected.length - b.affected.length) * dir;
      case "cve_id":
        return a.cve_id.localeCompare(b.cve_id) * dir;
      default:
        return 0;
    }
  });
}

// ---- page -------------------------------------------------------------------

export function VulnsView() {
  const { vulns, error, reload } = useVulns();
  const { session } = useAuth();
  const canTriage = session?.role === "analyst" || session?.role === "admin";

  // Selection holds the id, never the object — the drawer re-derives the row
  // from the freshest poll data each render so it can never go stale.
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [q, setQ] = useState("");
  const [severity, setSeverity] = useState<"all" | Severity>("all");
  const [kevOnly, setKevOnly] = useState(false);
  const [confirmedOnly, setConfirmedOnly] = useState(false);
  const [sort, setSort] = useState<SortState>({ key: "kev", dir: "desc" });
  const [page, setPage] = useState(1);
  const [tableSelection, setTableSelection] = useState<Set<string>>(new Set());

  // If the selected CVE vanished from the rollup after a poll, close the drawer.
  useEffect(() => {
    if (selectedId === null) return;
    if (!(vulns ?? []).some((v) => v.cve_id === selectedId)) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setSelectedId(null);
    }
  }, [vulns, selectedId]);

  // Page is reset inline in each filter handler (see setQ, setSeverity, etc. wrappers below).
  // We do NOT use a useEffect for this — the lint rule forbids synchronous setState in effects.

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (vulns ?? []).filter((v) => {
      if (needle && !v.cve_id.toLowerCase().includes(needle)) return false;
      if (severity !== "all" && v.severity !== severity) return false;
      if (kevOnly && !v.kev) return false;
      if (confirmedOnly && !isConfirmedConfidence(v.confidence)) return false;
      return true;
    });
  }, [vulns, q, severity, kevOnly, confirmedOnly]);

  const sorted = useMemo(() => sortVulns(filtered, sort), [filtered, sort]);

  const pageCount = Math.max(1, Math.ceil(sorted.length / PAGE_SIZE));
  const pagedRows = sorted.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  const selectedCveIds = Array.from(tableSelection);

  // Full-page states only before the first successful load — after that,
  // failed polls keep the last good data on screen (the hook stays silent).
  if (vulns === null) {
    return error ? (
      <ErrorState message={error} />
    ) : (
      <div className="space-y-6">
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} variant="rect" height={80} className="rounded-xl" />
          ))}
        </div>
        <Panel bodyClassName="p-4">
          <SkeletonTable rows={8} cols={7} />
        </Panel>
      </div>
    );
  }

  const selected =
    selectedId === null
      ? null
      : (vulns.find((v) => v.cve_id === selectedId) ?? null);

  // Only confirmed (version-checked) CVEs count toward the headline numbers;
  // potentials are surfaced but not counted as if confirmed.
  const confirmed = vulns.filter((v) => isConfirmedConfidence(v.confidence));
  const potentialCount = vulns.length - confirmed.length;
  const kevCount = confirmed.filter((v) => v.kev).length;
  const assetsAffected = new Set(
    vulns.flatMap((v) => v.affected.map((a) => a.id)),
  ).size;

  const columns: Column<VulnRow>[] = [
    {
      key: "cve_id",
      header: "CVE",
      sortable: true,
      render: (v) => (
        <span className="inline-flex items-center gap-1.5">
          <span className="font-mono text-xs text-fg">{v.cve_id}</span>
          <ButtonLink
            href={nvdUrl(v.cve_id)}
            target="_blank"
            rel="noreferrer"
            aria-label={`View ${v.cve_id} on NVD`}
            variant="ghost"
            size="sm"
            onClick={(e: React.MouseEvent) => e.stopPropagation()}
            className="h-auto p-0 text-muted hover:text-accent"
          >
            <Icon name="external" size={13} />
          </ButtonLink>
        </span>
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
      sortable: true,
      numeric: true,
      render: (v) => formatCvss(v.cvss),
    },
    {
      key: "epss",
      header: "EPSS",
      sortable: true,
      numeric: true,
      render: (v) => formatEpss(v.epss),
    },
    {
      key: "confidence",
      header: "Confidence",
      render: (v) => (
        <Tooltip content={confidenceHint[v.confidence]}>
          <span
            tabIndex={0}
            className="cursor-help text-xs text-muted underline decoration-dotted underline-offset-2"
          >
            {confidenceLabel[v.confidence]}
          </span>
        </Tooltip>
      ),
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
      header: "Affected assets",
      sortable: true,
      render: (v) => {
        const names = v.affected.slice(0, 2).map((a) => a.name);
        const extra = v.affected.length - names.length;
        return (
          <div className="flex items-center gap-2">
            <span className="tabular-nums text-fg">{v.affected.length}</span>
            {names.length > 0 ? (
              <span className="max-w-56 truncate text-xs text-muted">
                {names.join(", ")}
                {extra > 0 ? ` +${extra} more` : ""}
              </span>
            ) : null}
            {v.affected.some((a) => a.resolved_but_detected) ? (
              <Badge tone="danger">Still detected</Badge>
            ) : null}
          </div>
        );
      },
    },
  ];

  return (
    <div className="space-y-6">
      <div className="argus-rise">
        <PageHeader
          title="Vulnerabilities"
          description="CVE exposure across the inventory"
        />
      </div>

      <LiveRegion
        message={`${vulns.length} CVEs (${confirmed.length} confirmed, ${potentialCount} potential) across ${assetsAffected} assets, ${kevCount} confirmed known-exploited.`}
      />

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
            <StatCard
              label="Confirmed"
              value={confirmed.length}
              tone={confirmed.length > 0 ? "danger" : "default"}
              hint="version-checked — drive risk"
            />
            <StatCard
              label="Potential"
              value={potentialCount}
              hint="product present, version unverified"
            />
            <StatCard
              label="Known exploited"
              value={kevCount}
              tone={kevCount > 0 ? "danger" : "default"}
              hint="CISA KEV, among confirmed"
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
                    onChange={(e) => { setQ(e.target.value); setPage(1); }}
                    placeholder="Filter by CVE ID…"
                    aria-label="Filter by CVE ID"
                  />
                </div>
                <div className="w-36">
                  <Select
                    value={severity}
                    onChange={(e) => { setSeverity(e.target.value as "all" | Severity); setPage(1); }}
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
                <Toggle
                  checked={confirmedOnly}
                  onChange={(v) => { setConfirmedOnly(v); setPage(1); }}
                  label="Confirmed only"
                />
                <Toggle checked={kevOnly} onChange={(v) => { setKevOnly(v); setPage(1); }} label="KEV only" />
              </>
            }
            bodyClassName="p-0"
          >
            <Table<VulnRow>
              columns={columns}
              rows={pagedRows}
              getRowId={(v) => v.cve_id}
              sort={sort}
              onSortChange={(s) => {
                setSort(s);
                setPage(1);
              }}
              selection={canTriage ? tableSelection : undefined}
              onSelectionChange={canTriage ? setTableSelection : undefined}
              onRowClick={(v) => setSelectedId(v.cve_id)}
              density="compact"
              empty={
                <EmptyState
                  title="No CVEs match"
                  hint="Adjust the filters or clear the CVE ID search to see more findings."
                />
              }
            />

            {canTriage && selectedCveIds.length > 0 ? (
              <div className="border-t border-line px-4 py-3">
                <BulkSelectionTriage
                  cveIds={selectedCveIds}
                  vulns={vulns}
                  onChanged={reload}
                  onClearSelection={() => setTableSelection(new Set())}
                />
              </div>
            ) : null}

            {pageCount > 1 ? (
              <div className="border-t border-line px-4 py-3">
                <Pagination
                  page={page}
                  pageCount={pageCount}
                  onPageChange={setPage}
                />
              </div>
            ) : null}
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
            <ButtonLink
              href={nvdUrl(selected.cve_id)}
              target="_blank"
              rel="noreferrer"
              variant="secondary"
              size="md"
            >
              <Icon name="external" size={14} />
              View on NVD
            </ButtonLink>
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

          {canTriage && selected.affected.length > 1 ? (
            <BulkTriage
              cveId={selected.cve_id}
              assetIds={selected.affected.map((a) => a.id)}
              onChanged={reload}
            />
          ) : null}

          <div>
            <p className="text-[11px] font-medium uppercase tracking-[0.08em] text-muted">
              Affected assets ({selected.affected.length})
            </p>
            {selected.affected.length === 0 ? (
              <p className="mt-2 text-sm text-muted">No assets affected.</p>
            ) : (
              <ul className="mt-2 divide-y divide-line rounded-lg border border-line">
                {selected.affected.map((a) => (
                  <li key={a.id} className="px-3 py-2.5">
                    <div className="flex items-center justify-between gap-3">
                      <span className="min-w-0 truncate text-sm font-medium text-fg">
                        {a.name}
                      </span>
                      <span className="flex shrink-0 items-center gap-2">
                        {a.resolved_but_detected ? (
                          <Badge tone="danger">Still detected</Badge>
                        ) : null}
                        <Tooltip content={confidenceHint[a.match_confidence]}>
                          <span
                            tabIndex={0}
                            className="cursor-help text-xs text-muted underline decoration-dotted underline-offset-2"
                          >
                            {confidenceLabel[a.match_confidence]}
                          </span>
                        </Tooltip>
                        <RiskBadge band={a.band} value={a.risk} />
                      </span>
                    </div>
                    <FindingTriage
                      key={`${a.id}-${selected.cve_id}`}
                      assetId={a.id}
                      cveId={selected.cve_id}
                      finding={a.finding}
                      canEdit={canTriage}
                      onChanged={reload}
                    />
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
