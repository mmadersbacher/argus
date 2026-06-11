// Data sources panel. Honest split: connectors that actually feed the
// inventory ("Connected", live) vs. roadmap integrations ("Planned", not
// yet built — no connector code exists for these).

import { Icon, type IconName } from "@/components/icon";
import { Badge, Panel } from "@/components/ui";
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
    { name: "Nmap Import", sub: "scanner XML upload", icon: "server", metric: "file import" },
    { name: "NVD", sub: "NIST CVE feed", icon: "alert", metric: `${cves.size} CVEs` },
    { name: "CISA KEV", sub: "known exploited", icon: "shield", metric: `${kev} flagged` },
    { name: "EPSS", sub: "FIRST.org", icon: "activity", metric: "exploit prob." },
    { name: "Argus Intel", sub: "device classifier", icon: "cpu", metric: "classification" },
  ];

  return (
    <Panel
      title="Data sources"
      description="Feeds and sensors populating the inventory"
    >
      <div className="space-y-6">
        {/* connected (real) */}
        <div>
          <div className="mb-3 flex items-center justify-between gap-3">
            <p className="text-[11px] font-medium uppercase tracking-[0.08em] text-muted">
              Connected · {connected.length}
            </p>
            <span className="text-xs text-muted">live feeds &amp; sensors</span>
          </div>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3">
            {connected.map((s) => (
              <div
                key={s.name}
                className="rounded-lg border border-line bg-surface p-3.5"
              >
                <div className="flex items-center gap-2.5">
                  <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-surface-2 text-fg-2">
                    <Icon name={s.icon} size={16} />
                  </span>
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium leading-tight text-fg">
                      {s.name}
                    </p>
                    <p className="truncate text-xs text-muted">{s.sub}</p>
                  </div>
                </div>
                <p className="mt-2.5 inline-flex items-center gap-1.5 text-xs font-medium tabular-nums text-ok">
                  <span className="h-1.5 w-1.5 rounded-full bg-ok" />
                  {s.metric}
                </p>
              </div>
            ))}
          </div>
        </div>

        {/* planned (roadmap) */}
        <div>
          <div className="mb-3 flex items-center justify-between gap-3">
            <p className="text-[11px] font-medium uppercase tracking-[0.08em] text-muted">
              Planned · {planned.length}
            </p>
            <span className="text-xs text-muted">roadmap — not yet built</span>
          </div>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-4">
            {planned.map((s) => (
              <div
                key={s.name}
                className="flex flex-col items-start gap-2.5 rounded-lg border border-dashed border-line bg-surface-2/50 p-3"
              >
                <div className="flex w-full items-center gap-2.5">
                  <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-surface text-faint">
                    <Icon name={s.icon} size={15} />
                  </span>
                  <div className="min-w-0">
                    <p className="truncate text-xs font-medium leading-tight text-fg-2">
                      {s.name}
                    </p>
                    <p className="truncate text-[11px] text-muted">{s.sub}</p>
                  </div>
                </div>
                <Badge>Planned</Badge>
              </div>
            ))}
          </div>
        </div>
      </div>
    </Panel>
  );
}
