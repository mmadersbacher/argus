// Typed client for the argus-api backend. Mirrors the JSON shapes emitted by
// crates/argus-api (serde) so the console stays in lockstep with the domain.

import { clearSession, loadSession, type Role, type Session } from "./session";

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

export interface Service {
  port: number;
  protocol: string;
  product: string | null;
  banner: string | null;
}

export type Severity = "none" | "low" | "medium" | "high" | "critical";

export interface Cvss {
  base_score: number;
  vector: string | null;
}

export interface Epss {
  score: number;
  percentile: number;
}

export interface Vulnerability {
  cve_id: string;
  cvss: Cvss | null;
  epss: Epss | null;
  kev: boolean;
  severity: Severity;
}

export interface ScoredAsset {
  id: string;
  asset_type: AssetType;
  criticality: Criticality;
  exposure: Exposure;
  fingerprint: Fingerprint;
  interfaces: NetInterface[];
  services: Service[];
  vulnerabilities: Vulnerability[];
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

export interface ScanResult {
  target: string;
  hosts_scanned: number;
  live: number;
  duration_ms: number;
  /** Change events recorded by diffing this scan against the inventory. */
  changes: number;
}

export const API_BASE =
  process.env.NEXT_PUBLIC_API_URL ?? "http://127.0.0.1:8088";

/** Fetch wrapper: attaches the Bearer token, surfaces the API's error text,
 *  and bounces to /login when the session is rejected. Auth endpoints opt
 *  out of the bounce so a failed login shows its error inline. */
async function fetchJSON<T>(
  path: string,
  init?: RequestInit,
  opts?: { redirectOn401?: boolean },
): Promise<T> {
  const session = loadSession();
  const headers = new Headers(init?.headers);
  if (session && !headers.has("authorization")) {
    headers.set("authorization", `Bearer ${session.token}`);
  }
  const res = await fetch(`${API_BASE}${path}`, {
    cache: "no-store",
    ...init,
    headers,
  });
  if (res.status === 401 && (opts?.redirectOn401 ?? true)) {
    clearSession();
    if (typeof window !== "undefined") window.location.href = "/login";
    throw new Error("session expired");
  }
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(body || `${path} responded ${res.status}`);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

// ---- auth -----------------------------------------------------------------

export interface SessionResponse {
  token: string;
  email: string;
  role: Role;
  tenant_id: string;
}

export const login = (email: string, password: string) =>
  fetchJSON<SessionResponse>(
    "/api/auth/login",
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password }),
    },
    { redirectOn401: false },
  );

export const register = (
  organization: string,
  email: string,
  password: string,
) =>
  fetchJSON<SessionResponse>(
    "/api/auth/register",
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ organization, email, password }),
    },
    { redirectOn401: false },
  );

export interface UserSummary {
  id: string;
  email: string;
  role: Role;
}

export const listUsers = () => fetchJSON<UserSummary[]>("/api/users");

export const createUser = (email: string, password: string, role: Role) =>
  fetchJSON<UserSummary>("/api/users", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email, password, role }),
  });

export interface ApiKeySummary {
  id: string;
  name: string;
  role: Role;
}

export interface CreatedApiKey extends ApiKeySummary {
  /** Plaintext secret — shown exactly once. */
  key: string;
}

export const listApiKeys = () => fetchJSON<ApiKeySummary[]>("/api/api-keys");

export const createApiKey = (name: string, role: Role) =>
  fetchJSON<CreatedApiKey>("/api/api-keys", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ name, role }),
  });

export const deleteApiKey = (id: string) =>
  fetchJSON<void>(`/api/api-keys/${id}`, { method: "DELETE" });

export type { Role, Session };

// ---- inventory ------------------------------------------------------------

export const getSummary = () => fetchJSON<Summary>("/api/summary");
export const getAssets = () => fetchJSON<ScoredAsset[]>("/api/assets");

/** `deep` is only sent when true so the request shape stays unchanged for
 *  existing single-argument callers. */
export const runScan = (target: string, deep?: boolean) =>
  fetchJSON<ScanResult>("/api/scan", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(deep ? { target, deep } : { target }),
  });

export interface ImportResult {
  source: string;
  imported: number;
}

export const importNmap = (xml: string) =>
  fetchJSON<ImportResult>("/api/import/nmap", {
    method: "POST",
    headers: { "content-type": "text/xml" },
    body: xml,
  });

// ---- monitoring & change events ---------------------------------------------

export type EventKind =
  | "asset.new"
  | "services.changed"
  | "vulns.changed"
  | "risk.changed";

export interface AssetNewDetail {
  risk: number;
  band: RiskBand;
  services: number;
}

export interface ServiceDelta {
  port: number;
  product: string | null;
}

export interface ServicesChangedDetail {
  added: ServiceDelta[];
  removed: ServiceDelta[];
}

export interface VulnsChangedDetail {
  added: string[];
  removed: string[];
  kev_added: number;
}

export interface RiskChangedDetail {
  old: number;
  new: number;
  old_band: RiskBand;
  new_band: RiskBand;
}

interface EventBase {
  id: number;
  dedup_key: string;
  asset_name: string;
  /** RFC3339, like first_seen/last_seen. */
  created_at: string;
}

/** Change event from /api/events — discriminated on `kind` so `detail` is
 *  fully typed per event kind. */
export type ArgusEvent = EventBase &
  (
    | { kind: "asset.new"; detail: AssetNewDetail }
    | { kind: "services.changed"; detail: ServicesChangedDetail }
    | { kind: "vulns.changed"; detail: VulnsChangedDetail }
    | { kind: "risk.changed"; detail: RiskChangedDetail }
  );

/** Newest first; the API clamps limit to 1..=200 (default 50). */
export const fetchEvents = (limit = 50) =>
  fetchJSON<ArgusEvent[]>(`/api/events?limit=${limit}`);

export interface MonitorSettings {
  target: string;
  interval_minutes: number;
  enabled: boolean;
  deep: boolean;
}

export type MonitorConfig =
  | { configured: false }
  | ({ configured: true; last_run_at: string | null } & MonitorSettings);

export const fetchMonitor = () => fetchJSON<MonitorConfig>("/api/monitor");

// ---- vulnerabilities --------------------------------------------------------

export type FindingStatus =
  | "open"
  | "acknowledged"
  | "resolved"
  | "false_positive";

/** Analyst triage decision for one (asset, CVE) finding; absent = open.
 *  Triage is metadata only — it does not alter the computed risk score. */
export interface FindingState {
  status: FindingStatus;
  note: string;
  updated_by: string;
  /** RFC3339. */
  updated_at: string;
}

export interface VulnAffectedAsset {
  id: string;
  name: string;
  risk: number;
  band: RiskBand;
  finding: FindingState | null;
}

/** Vulnerability rollup across the inventory — one row per CVE. */
export interface VulnRow {
  cve_id: string;
  severity: Severity;
  cvss: number | null;
  epss: number | null;
  kev: boolean;
  affected: VulnAffectedAsset[];
}

export async function fetchVulns(): Promise<VulnRow[]> {
  return fetchJSON<VulnRow[]>("/api/vulns");
}

/** Set or clear ("open") the triage status of one finding. Requires analyst
 *  or higher; returns the new state, or null when back to open. */
export const setFinding = (
  asset_id: string,
  cve_id: string,
  status: FindingStatus,
  note?: string,
) =>
  fetchJSON<FindingState | null>("/api/findings", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ asset_id, cve_id, status, note }),
  });

/** Requires analyst or higher; 400 carries the validation error as text. */
export const saveMonitor = (cfg: MonitorSettings) =>
  fetchJSON<MonitorConfig>("/api/monitor", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(cfg),
  });

// ---- reports ----------------------------------------------------------------

export type HighlightLevel = "critical" | "warn" | "info";

export interface ReportHighlight {
  level: HighlightLevel;
  text: string;
}

export interface TypeCount {
  asset_type: AssetType;
  count: number;
}

export interface CriticalityCount {
  criticality: Criticality;
  count: number;
}

export interface BandCount {
  band: RiskBand;
  count: number;
}

export interface ReportInventory {
  total: number;
  internet_facing: number;
  new_in_period: number;
  stale: number;
  by_type: TypeCount[];
  by_criticality: CriticalityCount[];
}

export interface ReportTopAsset {
  name: string;
  ip: string | null;
  asset_type: AssetType;
  criticality: Criticality;
  exposure: Exposure;
  risk: RiskScore;
  cves: number;
  kev_cves: number;
}

export interface ReportRisk {
  average: number;
  distribution: BandCount[];
  top_assets: ReportTopAsset[];
}

export interface ReportTopCve {
  cve_id: string;
  severity: Severity;
  cvss: number | null;
  epss: number | null;
  kev: boolean;
  affected: number;
}

export interface ReportVulns {
  unique_cves: number;
  kev_cves: number;
  critical_cves: number;
  high_cves: number;
  assets_with_kev: number;
  top_cves: ReportTopCve[];
}

export interface ReportActivity {
  events_in_period: number;
  new_assets: number;
  service_changes: number;
  vuln_changes: number;
  risk_changes: number;
}

export interface ReportMonitoring {
  configured: boolean;
  enabled: boolean;
  interval_minutes: number | null;
  target: string | null;
  last_run_at: string | null;
  coverage_percent: number;
}

/** Point-in-time exposure report from GET /api/report. */
export interface ExposureReport {
  generated_at: string;
  period_days: number;
  highlights: ReportHighlight[];
  inventory: ReportInventory;
  risk: ReportRisk;
  vulnerabilities: ReportVulns;
  activity: ReportActivity;
  monitoring: ReportMonitoring;
}

/** The API clamps days to 1..=90 (event retention window). */
export const fetchReport = (days = 30) =>
  fetchJSON<ExposureReport>(`/api/report?days=${days}`);

// ---- policy / segmentation ---------------------------------------------------

export type AdvisoryLevel = "critical" | "high" | "medium" | "low";

export interface AffectedAsset {
  name: string;
  /** Rule-specific evidence (exposed ports, subnet, ...). */
  evidence: string;
}

/** One segmentation / exposure finding from GET /api/policy (sorted
 *  critical-first by the API). */
export interface Advisory {
  rule: string;
  level: AdvisoryLevel;
  title: string;
  rationale: string;
  recommendation: string;
  affected: AffectedAsset[];
}

export const fetchPolicy = () => fetchJSON<Advisory[]>("/api/policy");
