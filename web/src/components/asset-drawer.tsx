"use client";

import type { ScoredAsset } from "@/lib/api";
import { assetTypeLabel, exposureLabel } from "@/lib/ui";
import { RiskBadge } from "@/components/risk-badge";

function dash(value: string | null | undefined): string {
  return value && value.length > 0 ? value : "—";
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-xs text-muted">{label}</div>
      <div className="mt-0.5 text-sm">{value}</div>
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

  return (
    <div className="fixed inset-0 z-50">
      <button
        aria-label="Close details"
        className="absolute inset-0 bg-black/50 backdrop-blur-sm"
        onClick={onClose}
      />
      <aside className="argus-slide absolute top-0 right-0 h-full w-full max-w-md overflow-y-auto border-l border-line bg-surface p-6">
        <div className="flex items-start justify-between">
          <div>
            <div className="text-xs text-muted">
              {assetTypeLabel[asset.asset_type]} asset
            </div>
            <h2 className="text-lg font-semibold">{dash(fp.device_type)}</h2>
          </div>
          <button
            className="rounded-md border border-line px-2 py-1 text-xs text-muted hover:text-fg"
            onClick={onClose}
          >
            Close
          </button>
        </div>

        <div className="mt-4 flex items-center gap-3">
          <RiskBadge band={asset.risk.band} value={asset.risk.value} />
          <span className="text-xs text-muted">{exposureLabel[asset.exposure]}</span>
        </div>

        <div className="mt-6 grid grid-cols-2 gap-4">
          <Field label="Vendor" value={dash(fp.vendor)} />
          <Field label="OS" value={dash(fp.os)} />
          <Field label="IP" value={dash(iface?.ip)} />
          <Field label="MAC" value={dash(iface?.mac)} />
          <Field label="Hostname" value={dash(iface?.hostname)} />
          <Field label="Confidence" value={`${fp.confidence}%`} />
        </div>

        <div className="mt-6">
          <div className="mb-2 text-xs text-muted">
            Services ({asset.services.length})
          </div>
          {asset.services.length === 0 ? (
            <div className="text-sm text-muted">No services observed.</div>
          ) : (
            <div className="overflow-hidden rounded-lg border border-line">
              <table className="w-full text-sm">
                <tbody>
                  {asset.services.map((s) => (
                    <tr
                      key={`${s.protocol}-${s.port}`}
                      className="border-b border-line/60 last:border-0"
                    >
                      <td className="px-3 py-2 font-mono">{s.port}</td>
                      <td className="px-3 py-2 text-muted uppercase">{s.protocol}</td>
                      <td className="px-3 py-2 text-muted">{dash(s.product)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <div className="mt-6 text-[11px] text-muted">
          First seen {new Date(asset.first_seen).toLocaleString()} · last seen{" "}
          {new Date(asset.last_seen).toLocaleString()}
        </div>
      </aside>
    </div>
  );
}
