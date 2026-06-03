"use client";

import type { ScoredAsset } from "@/lib/api";
import { bandStyles } from "@/lib/ui";

const W = 760;
const H = 380;
const CX = W / 2;
const CY = H / 2;
const R = Math.min(W, H) / 2 - 46;

export function AssetGraph({
  assets,
  selectedId,
  onSelect,
}: {
  assets: ScoredAsset[];
  selectedId?: string;
  onSelect: (a: ScoredAsset) => void;
}) {
  const n = Math.max(assets.length, 1);
  const nodes = assets.map((a, i) => {
    const angle = (i / n) * Math.PI * 2 - Math.PI / 2;
    const ring = 0.6 + 0.34 * ((i % 3) / 2); // 3 depth rings
    const r = R * ring;
    return { a, x: CX + Math.cos(angle) * r, y: CY + Math.sin(angle) * r };
  });

  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="h-auto w-full select-none">
      {nodes.map(({ a, x, y }) => (
        <line
          key={`edge-${a.id}`}
          x1={CX}
          y1={CY}
          x2={x}
          y2={y}
          className={a.id === selectedId ? "stroke-accent/50" : "stroke-line"}
          strokeWidth={1}
        />
      ))}

      <circle cx={CX} cy={CY} r={24} className="fill-surface-2 stroke-accent" strokeWidth={1.5} />
      <circle cx={CX} cy={CY} r={24} className="fill-none stroke-accent/40 argus-pulse" strokeWidth={1.5} />
      <text x={CX} y={CY + 4} textAnchor="middle" className="fill-accent font-mono text-[10px]">
        NET
      </text>

      {nodes.map(({ a, x, y }, i) => {
        const s = bandStyles[a.risk.band];
        const selected = a.id === selectedId;
        const radius = 7 + (a.risk.value / 100) * 10;
        const label = a.fingerprint.device_type ?? a.asset_type;
        return (
          <g
            key={a.id}
            className="argus-rise cursor-pointer"
            style={{ animationDelay: `${i * 45}ms` }}
            onClick={() => onSelect(a)}
          >
            <title>{`${label} — ${a.interfaces[0]?.ip ?? ""} (${s.label} ${Math.round(a.risk.value)})`}</title>
            {selected && (
              <circle cx={x} cy={y} r={radius + 7} className="fill-none stroke-accent" strokeWidth={1.5} />
            )}
            <circle
              cx={x}
              cy={y}
              r={radius}
              className={`${s.fill} transition-opacity ${selected ? "opacity-100" : "opacity-90 hover:opacity-100"}`}
            />
          </g>
        );
      })}
    </svg>
  );
}
