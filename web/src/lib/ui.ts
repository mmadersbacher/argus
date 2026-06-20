// Presentation maps: domain enums -> Tailwind classes and labels.
// Class strings are written as literals so the Tailwind v4 scanner picks them up.

import type { IconName } from "@/components/icon";
import type { AssetType, Confidence, Exposure, RiskBand } from "./api";

export interface BandStyle {
  label: string;
  text: string;
  bg: string;
  ring: string;
  bar: string;
}

export const bandStyles: Record<RiskBand, BandStyle> = {
  critical: { label: "Critical", text: "text-crit", bg: "bg-crit/10", ring: "ring-crit/25", bar: "bg-crit" },
  high: { label: "High", text: "text-high", bg: "bg-high/10", ring: "ring-high/25", bar: "bg-high" },
  medium: { label: "Medium", text: "text-med", bg: "bg-med/10", ring: "ring-med/25", bar: "bg-med" },
  low: { label: "Low", text: "text-low", bg: "bg-low/10", ring: "ring-low/25", bar: "bg-low" },
  info: { label: "Info", text: "text-info", bg: "bg-info/10", ring: "ring-info/25", bar: "bg-info" },
};

export const bandOrder: RiskBand[] = ["critical", "high", "medium", "low", "info"];

export const assetTypeLabel: Record<AssetType, string> = {
  it: "IT",
  ot: "OT",
  iot: "IoT",
  iomt: "IoMT",
  network: "Network",
  cloud: "Cloud",
  mobile: "Mobile",
  unknown: "Unknown",
};

export const exposureLabel: Record<Exposure, string> = {
  internal: "Internal",
  internet_facing: "Internet-facing",
  unknown: "Unknown",
};

/** Short label for a match/score confidence; `low` reads as "version-blind"
 *  in the vulnerability context, where that is the actionable meaning. */
export const confidenceLabel: Record<Confidence, string> = {
  confirmed: "Confirmed",
  high: "High",
  medium: "Medium",
  low: "Version-blind",
};

/** Tooltip explaining what a vulnerability's match confidence means. */
export const confidenceHint: Record<Confidence, string> = {
  confirmed:
    "Live NVD match — product CPE and the observed version were both verified.",
  high: "Catalog match with the observed version inside an explicit range.",
  medium: "Product identity matched, but the version was not verified.",
  low: "Matched on product name only — version not checked, so it may not apply.",
};

/** Whether a match confidence counts as a *confirmed* finding (version
 *  applicability verified) versus a *potential* one (product present but
 *  unverified). Mirrors `Vulnerability::is_confirmed` in the backend: only
 *  confirmed findings drive the risk score. */
export const isConfirmedConfidence = (c: Confidence): boolean =>
  c === "high" || c === "confirmed";

/** Icon tile per asset type — shared by the assets, network and risk views. */
export const assetTypeIcon: Record<AssetType, IconName> = {
  it: "server",
  ot: "cpu",
  iot: "network",
  iomt: "activity",
  network: "network",
  cloud: "cloud",
  mobile: "smartphone",
  unknown: "grid",
};

/** One precision for CVSS scores everywhere: "9.8" or "—". */
export function formatCvss(c: number | null | undefined): string {
  return c == null ? "—" : c.toFixed(1);
}

/** One precision for EPSS scores everywhere: "97.0%" or "—". */
export function formatEpss(e: number | null | undefined): string {
  return e == null ? "—" : `${(e * 100).toFixed(1)}%`;
}

/** Compact relative timestamp for feeds: "just now", "4m ago", "2h ago", "3d ago". */
export function timeAgo(iso: string): string {
  const then = new Date(iso).getTime();
  if (!Number.isFinite(then)) return "—";
  const s = Math.max(0, Math.floor((Date.now() - then) / 1000));
  if (s < 60) return "just now";
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}
