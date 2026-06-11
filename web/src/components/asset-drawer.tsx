"use client";

// Slide-over detail view for a single asset. Props are frozen by the design
// contract ({ asset, onClose }) — this component is imported across pages.
// The modal shell (backdrop, Escape, focus trap/restore, scroll lock) lives
// in the shared Drawer primitive; this file only renders the asset content.

import type { ScoredAsset } from "@/lib/api";
import {
  assetTypeLabel,
  exposureLabel,
  formatCvss,
  formatEpss,
} from "@/lib/ui";
import { Badge, Drawer } from "@/components/ui";
import { RiskBadge, SeverityBadge } from "@/components/risk-badge";

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
}: {
  asset: ScoredAsset | null;
  onClose: () => void;
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
        <Detail label="Confidence" value={`${fp.confidence}%`} />
      </div>

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

      <section>
        <Overline>
          Vulnerabilities{" "}
          <span className="tabular-nums">({asset.vulnerabilities.length})</span>
        </Overline>
        {asset.vulnerabilities.length === 0 ? (
          <p className="mt-2 text-sm text-muted">No known CVEs.</p>
        ) : (
          <ul className="mt-2 space-y-2">
            {asset.vulnerabilities.map((v) => (
              <li
                key={v.cve_id}
                className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded-lg border border-line px-3 py-2.5"
              >
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
                {v.kev ? (
                  <span className="ml-auto">
                    <Badge tone="danger">KEV</Badge>
                  </span>
                ) : null}
              </li>
            ))}
          </ul>
        )}
      </section>
    </Drawer>
  );
}
