// Risk distribution bars — the one semantic for both the overview panel
// (compact) and the risk page (detailed): every bar's width is the band's
// share of ALL assets, so the same data renders identically on both pages.

import type { RiskBand, ScoredAsset } from "@/lib/api";
import { bandOrder, bandStyles } from "@/lib/ui";
import { RiskBadge } from "@/components/risk-badge";

export function RiskDistribution({
  assets,
  detailed,
}: {
  assets: ScoredAsset[];
  detailed?: boolean;
}) {
  const total = assets.length;
  const counts: Record<RiskBand, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const a of assets) counts[a.risk.band] += 1;

  return (
    <div className={detailed ? "space-y-4" : "space-y-3"}>
      {bandOrder.map((band) => {
        const s = bandStyles[band];
        const n = counts[band];
        const pct = total > 0 ? (n / total) * 100 : 0;
        return (
          <div key={band} className="flex items-center gap-3">
            {detailed ? (
              <span className="w-24 shrink-0">
                <RiskBadge band={band} />
              </span>
            ) : (
              <span className="flex w-20 shrink-0 items-center gap-2">
                <span className={`h-2 w-2 rounded-full ${s.bar}`} />
                <span className="text-xs font-medium text-fg-2">
                  {s.label}
                </span>
              </span>
            )}
            <div
              className={`flex-1 overflow-hidden rounded-full bg-surface-2 ${
                detailed ? "h-3" : "h-2"
              }`}
            >
              <div
                className={`h-full rounded-full ${s.bar}`}
                style={{
                  width: `${pct}%`,
                  minWidth: n > 0 ? 6 : undefined,
                }}
              />
            </div>
            <span className="w-16 shrink-0 text-right text-xs tabular-nums text-muted">
              {n} · {Math.round(pct)}%
            </span>
          </div>
        );
      })}
    </div>
  );
}
