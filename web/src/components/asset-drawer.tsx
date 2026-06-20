"use client";

// Slide-over detail view for a single asset. The base props are frozen by
// the design contract ({ asset, onClose }; onUpdated is optional) — this
// component is imported across pages. The modal shell (backdrop, Escape,
// focus trap/restore, scroll lock) lives in the shared Drawer primitive;
// this file only renders the asset content.

import { useState } from "react";
import {
  updateAsset,
  type Criticality,
  type Exposure,
  type ScoredAsset,
  type Vulnerability,
} from "@/lib/api";
import { useAuth } from "@/lib/auth";
import {
  assetTypeLabel,
  confidenceHint,
  confidenceLabel,
  exposureLabel,
  formatCvss,
  formatEpss,
  isConfirmedConfidence,
} from "@/lib/ui";
import { Badge, Drawer, Select } from "@/components/ui";
import { RiskBadge, SeverityBadge } from "@/components/risk-badge";

const CRITICALITIES: Criticality[] = ["low", "medium", "high", "critical"];
const EXPOSURES: Exposure[] = ["internal", "internet_facing", "unknown"];

/** One CVE row inside the vulnerabilities section. */
function VulnItem({ v }: { v: Vulnerability }) {
  return (
    <li className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded-lg border border-line px-3 py-2.5">
      <a
        href={`https://nvd.nist.gov/vuln/detail/${v.cve_id}`}
        target="_blank"
        rel="noreferrer"
        className="rounded font-mono text-xs font-medium text-accent hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40"
      >
        {v.cve_id}
      </a>
      <SeverityBadge severity={v.severity} />
      {v.cvss ? (
        <span className="text-xs tabular-nums text-fg-2">
          CVSS {formatCvss(v.cvss.base_score)}
        </span>
      ) : null}
      {v.epss ? (
        <span className="text-xs tabular-nums text-muted">
          EPSS {formatEpss(v.epss.score)}
        </span>
      ) : null}
      <span
        className="cursor-help text-xs text-muted underline decoration-dotted underline-offset-2"
        title={confidenceHint[v.match_confidence]}
      >
        {confidenceLabel[v.match_confidence]}
      </span>
      {v.kev ? (
        <span className="ml-auto">
          <Badge tone="danger">KEV</Badge>
        </span>
      ) : null}
    </li>
  );
}

/** Vulnerabilities split into confirmed (version-checked, drives the score)
 *  and potential (product present but applicability unverified — leads to
 *  verify, never scored). This is the "is the host actually vulnerable, or is
 *  the product just present?" distinction made visible. */
function VulnSection({ vulns }: { vulns: Vulnerability[] }) {
  const confirmed = vulns.filter((v) => isConfirmedConfidence(v.match_confidence));
  const potential = vulns.filter((v) => !isConfirmedConfidence(v.match_confidence));
  return (
    <section>
      <Overline>
        Vulnerabilities <span className="tabular-nums">({vulns.length})</span>
      </Overline>
      {vulns.length === 0 ? (
        <p className="mt-2 text-sm text-muted">No known CVEs.</p>
      ) : (
        <div className="mt-3 space-y-4">
          <div>
            <p className="text-xs font-medium text-fg-2">
              Confirmed{" "}
              <span className="tabular-nums text-muted">({confirmed.length})</span>
              <span className="ml-2 font-normal text-muted">
                version-checked — drives the risk score
              </span>
            </p>
            {confirmed.length === 0 ? (
              <p className="mt-1.5 text-sm text-muted">
                No confirmed vulnerabilities.
              </p>
            ) : (
              <ul className="mt-1.5 space-y-2">
                {confirmed.map((v) => (
                  <VulnItem key={v.cve_id} v={v} />
                ))}
              </ul>
            )}
          </div>
          {potential.length > 0 && (
            <div className="opacity-80">
              <p className="text-xs font-medium text-fg-2">
                Potential{" "}
                <span className="tabular-nums text-muted">
                  ({potential.length})
                </span>
                <span className="ml-2 font-normal text-muted">
                  product present, version unverified — verify, not scored
                </span>
              </p>
              <ul className="mt-1.5 space-y-2">
                {potential.map((v) => (
                  <VulnItem key={v.cve_id} v={v} />
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </section>
  );
}

const criticalityLabel: Record<Criticality, string> = {
  low: "Low",
  medium: "Medium",
  high: "High",
  critical: "Critical",
};

/** Business-context editor: criticality/exposure overrides + risk recompute.
 *  Mount with a key per asset id so select state follows the selection.
 *  Overrides are analyst decisions — they win over discovery and survive
 *  re-scans; the risk score updates immediately. */
function BusinessContext({
  asset,
  onUpdated,
}: {
  asset: ScoredAsset;
  onUpdated?: () => void | Promise<void>;
}) {
  const { session } = useAuth();
  const canEdit = session?.role === "analyst" || session?.role === "admin";
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const save = async (body: {
    criticality?: Criticality;
    exposure?: Exposure;
  }) => {
    setSaving(true);
    setError(null);
    try {
      await updateAsset(asset.id, body);
      await onUpdated?.();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to save");
    } finally {
      setSaving(false);
    }
  };

  if (!canEdit) {
    return (
      <div className="grid grid-cols-2 gap-4">
        <Detail
          label="Criticality"
          value={criticalityLabel[asset.criticality]}
        />
        <Detail label="Exposure" value={exposureLabel[asset.exposure]} />
      </div>
    );
  }

  return (
    <section>
      <Overline>Business context</Overline>
      <div className="mt-2 grid grid-cols-2 gap-3">
        <label className="block">
          <span className="mb-1 block text-[11px] font-medium uppercase tracking-[0.08em] text-muted">
            Criticality
            {asset.overrides.criticality ? " · set by analyst" : ""}
          </span>
          <Select
            value={asset.criticality}
            disabled={saving}
            onChange={(e) =>
              void save({ criticality: e.target.value as Criticality })
            }
            className="h-8 text-xs"
          >
            {CRITICALITIES.map((c) => (
              <option key={c} value={c}>
                {criticalityLabel[c]}
              </option>
            ))}
          </Select>
        </label>
        <label className="block">
          <span className="mb-1 block text-[11px] font-medium uppercase tracking-[0.08em] text-muted">
            Exposure
            {asset.overrides.exposure ? " · set by analyst" : ""}
          </span>
          <Select
            value={asset.exposure}
            disabled={saving}
            onChange={(e) =>
              void save({ exposure: e.target.value as Exposure })
            }
            className="h-8 text-xs"
          >
            {EXPOSURES.map((x) => (
              <option key={x} value={x}>
                {exposureLabel[x]}
              </option>
            ))}
          </Select>
        </label>
      </div>
      <p className="mt-1.5 text-[11px] text-muted">
        Drives the risk score; survives re-scans.
      </p>
      {error ? <p className="mt-1 text-xs text-crit">{error}</p> : null}
    </section>
  );
}

function dash(value: string | null | undefined): string {
  return value && value.length > 0 ? value : "—";
}

function Overline({ children }: { children: React.ReactNode }) {
  return (
    <h3 className="text-[11px] font-medium uppercase tracking-[0.08em] text-muted">
      {children}
    </h3>
  );
}

function Detail({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="min-w-0">
      <div className="text-[11px] font-medium uppercase tracking-[0.08em] text-muted">
        {label}
      </div>
      <div
        className={
          mono
            ? "mt-1 truncate font-mono text-xs text-fg"
            : "mt-1 truncate text-sm text-fg"
        }
      >
        {value}
      </div>
    </div>
  );
}

export function AssetDrawer({
  asset,
  onClose,
  onUpdated,
}: {
  asset: ScoredAsset | null;
  onClose: () => void;
  /** Called after a business-context save so the host view can refresh. */
  onUpdated?: () => void | Promise<void>;
}) {
  if (!asset) return null;
  const iface = asset.interfaces[0];
  const fp = asset.fingerprint;
  const name = fp.device_type ?? "Unknown device";

  return (
    <Drawer
      onClose={onClose}
      overline={`${assetTypeLabel[asset.asset_type]} asset`}
      title={name}
      badges={
        <>
          <RiskBadge band={asset.risk.band} value={asset.risk.value} />
          <Badge
            tone={asset.exposure === "internet_facing" ? "warn" : "neutral"}
          >
            {exposureLabel[asset.exposure]}
          </Badge>
        </>
      }
      footer={
        <>
          First seen {new Date(asset.first_seen).toLocaleString()} · Last seen{" "}
          {new Date(asset.last_seen).toLocaleString()}
        </>
      }
    >
      <div className="grid grid-cols-2 gap-4">
        <Detail label="Vendor" value={dash(fp.vendor)} />
        <Detail label="OS" value={dash(fp.os)} />
        <Detail label="IP" value={dash(iface?.ip)} mono />
        <Detail label="MAC" value={dash(iface?.mac)} mono />
        <Detail label="Hostname" value={dash(iface?.hostname)} mono />
        <Detail label="ID confidence" value={`${fp.confidence}%`} />
        <Detail
          label="Risk confidence"
          value={confidenceLabel[asset.risk.confidence]}
        />
      </div>

      <BusinessContext key={asset.id} asset={asset} onUpdated={onUpdated} />

      <section>
        <Overline>
          Services{" "}
          <span className="tabular-nums">({asset.services.length})</span>
        </Overline>
        {asset.services.length === 0 ? (
          <p className="mt-2 text-sm text-muted">No services observed.</p>
        ) : (
          <div className="mt-2 overflow-hidden rounded-lg border border-line">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-line bg-surface-2/60 text-left text-xs text-muted">
                  <th className="px-3 py-2 font-medium">Port</th>
                  <th className="px-3 py-2 font-medium">Protocol</th>
                  <th className="px-3 py-2 font-medium">Product</th>
                </tr>
              </thead>
              <tbody>
                {asset.services.map((s) => (
                  <tr
                    key={`${s.protocol}-${s.port}`}
                    className="border-b border-line last:border-0"
                  >
                    <td className="px-3 py-2 font-mono text-xs tabular-nums text-fg">
                      {s.port}
                    </td>
                    <td className="px-3 py-2 text-xs uppercase text-muted">
                      {s.protocol}
                    </td>
                    <td className="px-3 py-2 text-xs text-fg-2">
                      {dash(s.product)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <VulnSection vulns={asset.vulnerabilities} />
    </Drawer>
  );
}
