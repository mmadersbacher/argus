// Presentation maps: domain enums -> Tailwind classes and labels.
// Class strings are written as literals so the Tailwind v4 scanner picks them up.

import type { AssetType, Exposure, RiskBand } from "./api";

export interface BandStyle {
  label: string;
  text: string;
  bg: string;
  ring: string;
  bar: string;
  fill: string;
}

export const bandStyles: Record<RiskBand, BandStyle> = {
  critical: { label: "Critical", text: "text-crit", bg: "bg-crit/10", ring: "ring-crit/30", bar: "bg-crit", fill: "fill-crit" },
  high: { label: "High", text: "text-high", bg: "bg-high/10", ring: "ring-high/30", bar: "bg-high", fill: "fill-high" },
  medium: { label: "Medium", text: "text-med", bg: "bg-med/10", ring: "ring-med/30", bar: "bg-med", fill: "fill-med" },
  low: { label: "Low", text: "text-low", bg: "bg-low/10", ring: "ring-low/30", bar: "bg-low", fill: "fill-low" },
  info: { label: "Info", text: "text-info", bg: "bg-info/10", ring: "ring-info/30", bar: "bg-info", fill: "fill-info" },
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
