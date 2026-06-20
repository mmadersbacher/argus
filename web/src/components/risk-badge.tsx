import type { RiskBand, Severity } from "@/lib/api";
import { bandStyles } from "@/lib/ui";

export function RiskBadge({ band, value }: { band: RiskBand; value?: number }) {
  const s = bandStyles[band];
  return (
    <span
      title="Heuristic risk score — a composite weighting of CVSS severity, exposure and asset criticality, not a calibrated model"
      className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${s.text} ${s.bg} ${s.ring}`}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
      {s.label}
      {typeof value === "number" ? (
        <span className="tabular-nums opacity-75">{Math.round(value)}</span>
      ) : null}
    </span>
  );
}

/** CVE severities reuse the risk-band palette — severity IS risk semantics.
 *  "none" renders as a neutral "None" badge in the info tone. */
const severityBand: Record<Severity, RiskBand> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  none: "info",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  const s = bandStyles[severityBand[severity]];
  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${s.text} ${s.bg} ${s.ring}`}
    >
      {severity === "none" ? "None" : s.label}
    </span>
  );
}
