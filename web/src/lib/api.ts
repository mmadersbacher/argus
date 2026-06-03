// Typed client for the argus-api backend. Mirrors the JSON shapes emitted by
// crates/argus-api (serde) so the console stays in lockstep with the domain.

export type RiskBand = "info" | "low" | "medium" | "high" | "critical";
export type AssetType =
  | "it"
  | "ot"
  | "iot"
  | "iomt"
  | "network"
  | "cloud"
  | "mobile"
  | "unknown";
export type Criticality = "low" | "medium" | "high" | "critical";
export type Exposure = "internal" | "internet_facing" | "unknown";

export interface RiskScore {
  value: number;
  band: RiskBand;
}

export interface Fingerprint {
  device_type: string | null;
  vendor: string | null;
  os: string | null;
  confidence: number;
}

export interface NetInterface {
  mac: string | null;
  ip: string | null;
  vlan: number | null;
  hostname: string | null;
}

export interface ScoredAsset {
  id: string;
  asset_type: AssetType;
  criticality: Criticality;
  exposure: Exposure;
  fingerprint: Fingerprint;
  interfaces: NetInterface[];
  first_seen: string;
  last_seen: string;
  risk: RiskScore;
}

export interface Summary {
  total_assets: number;
  internet_facing: number;
  critical_or_high: number;
  avg_risk: number;
}

export const API_BASE =
  process.env.NEXT_PUBLIC_API_URL ?? "http://127.0.0.1:8088";

async function fetchJSON<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, { cache: "no-store" });
  if (!res.ok) {
    throw new Error(`${path} responded ${res.status}`);
  }
  return (await res.json()) as T;
}

export const getSummary = () => fetchJSON<Summary>("/api/summary");
export const getAssets = () => fetchJSON<ScoredAsset[]>("/api/assets");
