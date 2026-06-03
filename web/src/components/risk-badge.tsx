import type { RiskBand } from "@/lib/api";
import { bandStyles } from "@/lib/ui";

export function RiskBadge({ band, value }: { band: RiskBand; value?: number }) {
  const s = bandStyles[band];
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium ring-1 ${s.text} ${s.bg} ${s.ring}`}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
      {s.label}
      {typeof value === "number" ? (
        <span className="font-mono opacity-80">· {Math.round(value)}</span>
      ) : null}
    </span>
  );
}
