// Data Sources grid (Armis-style). Honest split: connectors that actually feed
// the inventory ("Connected", live) vs. roadmap integrations ("Planned", not
// yet built — no connector code exists for these).

import { Icon, type IconName } from "@/components/icon";
import type { ScoredAsset, Summary } from "@/lib/api";

type Planned = { name: string; sub: string; icon: IconName };

const planned: Planned[] = [
  { name: "Active Directory", sub: "identity", icon: "server" },
  { name: "Microsoft Intune", sub: "MDM", icon: "smartphone" },
  { name: "Qualys", sub: "vuln scanner", icon: "alert" },
  { name: "Tenable", sub: "vuln scanner", icon: "alert" },
  { name: "CrowdStrike", sub: "EDR", icon: "shield" },
  { name: "MS Defender", sub: "EDR", icon: "shield" },
  { name: "VMware vCenter", sub: "virtualization", icon: "server" },
  { name: "Cisco ISE", sub: "NAC", icon: "network" },
  { name: "SCCM", sub: "endpoint mgmt", icon: "cpu" },
  { name: "ServiceNow", sub: "CMDB", icon: "grid" },
  { name: "AWS", sub: "cloud", icon: "cloud" },
  { name: "Azure", sub: "cloud", icon: "cloud" },
];

export function DataSources({
  assets,
  summary,
}: {
  assets: ScoredAsset[];
  summary: Summary | null;
}) {
  const total = summary?.total_assets ?? assets.length;
  const cves = new Set<string>();
  let kev = 0;
  for (const a of assets) {
    for (const v of a.vulnerabilities) {
      cves.add(v.cve_id);
      if (v.kev) kev += 1;
    }
  }

  const connected: { name: string; sub: string; icon: IconName; metric: string }[] = [
    { name: "Active Discovery", sub: "nmap · connect scan", icon: "search", metric: `${total} assets` },
    { name: "NVD", sub: "NIST CVE feed", icon: "alert", metric: `${cves.size} CVEs` },
    { name: "CISA KEV", sub: "known exploited", icon: "shield", metric: `${kev} flagged` },
    { name: "EPSS", sub: "FIRST.org", icon: "activity", metric: "exploit prob." },
    { name: "Argus Intel", sub: "device classifier", icon: "cpu", metric: "classification" },
  ];

  return (
    <section className="space-y-6">
      {/* connected (real) */}
      <div>
        <div className="mb-3 flex items-end justify-between">
          <div>
            <div className="text-xs text-muted">Grouped by</div>
            <h2 className="text-base font-semibold">Data Source ({connected.length})</h2>
          </div>
          <span className="text-xs text-muted">live feeds &amp; sensors</span>
        </div>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
          {connected.map((s) => (
            <div
              key={s.name}
              className="flex flex-col items-center gap-1.5 rounded-xl border border-line bg-surface p-4 text-center"
            >
              <span className="flex h-11 w-11 items-center justify-center rounded-xl bg-accent/10 text-accent">
                <Icon name={s.icon} size={22} />
              </span>
              <span className="text-sm font-medium leading-tight">{s.name}</span>
              <span className="text-[11px] text-muted">{s.sub}</span>
              <span className="mt-1 inline-flex items-center gap-1 text-[11px] font-medium text-emerald-600">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" /> {s.metric}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* planned (roadmap) */}
      <div>
        <div className="mb-3 flex items-end justify-between">
          <h2 className="text-base font-semibold">
            Integrations <span className="font-normal text-muted">· planned</span>
          </h2>
          <span className="text-xs text-muted">roadmap — not yet built</span>
        </div>
        <div className="grid grid-cols-3 gap-3 sm:grid-cols-4 lg:grid-cols-6">
          {planned.map((s) => (
            <div
              key={s.name}
              className="flex flex-col items-center gap-1.5 rounded-xl border border-dashed border-line bg-surface-2 p-4 text-center"
            >
              <span className="flex h-11 w-11 items-center justify-center rounded-xl bg-surface text-muted">
                <Icon name={s.icon} size={20} />
              </span>
              <span className="text-sm font-medium leading-tight">{s.name}</span>
              <span className="text-[11px] text-muted">{s.sub}</span>
              <span className="mt-1 rounded-full border border-line px-2 py-0.5 text-[10px] font-medium text-muted">
                Planned
              </span>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
