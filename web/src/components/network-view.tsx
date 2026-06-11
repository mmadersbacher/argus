"use client";

// Network view: the inventory grouped by IPv4 /24 subnet. Pure client-side
// grouping over useInventory — no extra endpoints.

import { useEffect, useMemo, useState } from "react";
import type { RiskBand, ScoredAsset } from "@/lib/api";
import { assetTypeIcon, bandOrder, bandStyles } from "@/lib/ui";
import { useInventory } from "@/lib/use-inventory";
import { Icon } from "@/components/icon";
import { AssetDrawer } from "@/components/asset-drawer";
import { RiskBadge } from "@/components/risk-badge";
import { PageHeader, Panel, StatCard } from "@/components/ui";
import { EmptyState, ErrorState, LoadingState } from "@/components/states";

/** Parses a dotted-quad IPv4 address; returns its four octets or null. */
function parseIPv4(ip: string): [number, number, number, number] | null {
  const m = ip.trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  const o = m.slice(1).map(Number) as [number, number, number, number];
  return o.every((n) => n <= 255) ? o : null;
}

interface HostEntry {
  asset: ScoredAsset;
  /** First IPv4 of the asset, null for the unassigned bucket. */
  ip: string | null;
  lastOctet: number;
  /** Bold card title: hostname, else best address, else fingerprint, else fallback. */
  title: string;
  /** Mono subline fallback chain: IPv4 -> any IP (incl. IPv6) -> MAC -> "no address",
   *  skipping a value that already is the title. */
  sub: string;
}

interface SubnetGroup {
  key: string;
  /** "192.168.1.0/24" or "Other / unassigned". */
  label: string;
  /** First three octets for deterministic tie-breaking; null for "Other". */
  prefix: [number, number, number] | null;
  hosts: HostEntry[];
  worst: RiskBand;
}

function toHostEntry(asset: ScoredAsset): HostEntry {
  // First interface carrying a parseable IPv4 address wins.
  let ip: string | null = null;
  let lastOctet = 0;
  for (const iface of asset.interfaces) {
    if (!iface.ip) continue;
    const octets = parseIPv4(iface.ip);
    if (octets) {
      ip = iface.ip.trim();
      lastOctet = octets[3];
      break;
    }
  }
  const hostname = asset.interfaces.find((i) => i.hostname)?.hostname ?? null;
  const mac = asset.interfaces.find((i) => i.mac)?.mac ?? null;
  // Best displayable address: IPv4 first, otherwise any address (e.g. IPv6) —
  // an IPv6-only host must still show its address even though it cannot be
  // grouped into an IPv4 /24.
  const rawIp = asset.interfaces.find((i) => i.ip)?.ip?.trim() ?? null;
  const displayIp = ip ?? rawIp;
  const title =
    hostname ?? displayIp ?? asset.fingerprint.device_type ?? "unknown host";
  const sub = (title === displayIp ? mac : displayIp ?? mac) ?? "no address";
  return { asset, ip, lastOctet, title, sub };
}

function groupBySubnet(assets: ScoredAsset[]): SubnetGroup[] {
  const map = new Map<string, SubnetGroup>();
  for (const asset of assets) {
    const entry = toHostEntry(asset);
    const octets = entry.ip ? parseIPv4(entry.ip) : null;
    const key = octets
      ? `${octets[0]}.${octets[1]}.${octets[2]}.0/24`
      : "other";
    let group = map.get(key);
    if (!group) {
      group = {
        key,
        label: octets ? key : "Other / unassigned",
        prefix: octets ? [octets[0], octets[1], octets[2]] : null,
        hosts: [],
        worst: "info",
      };
      map.set(key, group);
    }
    group.hosts.push(entry);
  }

  const groups = [...map.values()];
  for (const g of groups) {
    g.hosts.sort((a, b) =>
      g.prefix
        ? a.lastOctet - b.lastOctet
        : a.title.localeCompare(b.title),
    );
    g.worst =
      bandOrder.find((band) =>
        g.hosts.some((h) => h.asset.risk.band === band),
      ) ?? "info";
  }

  const subnets = groups
    .filter((g) => g.prefix !== null)
    .sort((a, b) => {
      if (a.hosts.length !== b.hosts.length) {
        return b.hosts.length - a.hosts.length;
      }
      for (let i = 0; i < 3; i++) {
        const d = (a.prefix as number[])[i] - (b.prefix as number[])[i];
        if (d !== 0) return d;
      }
      return 0;
    });
  const other = groups.find((g) => g.prefix === null);
  return other ? [...subnets, other] : subnets;
}

function HostCard({
  host,
  onSelect,
}: {
  host: HostEntry;
  onSelect: (asset: ScoredAsset) => void;
}) {
  const { asset, title, sub } = host;
  const band = asset.risk.band;
  const services = asset.services.length;
  return (
    <button
      type="button"
      onClick={() => onSelect(asset)}
      className="flex min-w-0 items-start gap-3 rounded-lg border border-line bg-surface p-3 text-left transition-colors hover:border-line-strong hover:bg-surface-2/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40"
    >
      <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-surface-2 text-muted">
        <Icon name={assetTypeIcon[asset.asset_type]} size={16} />
      </span>
      <span className="min-w-0 flex-1">
        <span className="block truncate text-sm font-semibold text-fg">
          {title}
        </span>
        <span className="block truncate font-mono text-xs text-muted">
          {sub}
        </span>
        <span className="mt-1.5 flex items-center gap-1.5 text-xs text-muted">
          <span
            className={`h-2 w-2 shrink-0 rounded-full ${bandStyles[band].bar}`}
            aria-hidden
          />
          <span>{bandStyles[band].label}</span>
          <span className="ml-auto tabular-nums">
            {services} {services === 1 ? "service" : "services"}
          </span>
        </span>
      </span>
    </button>
  );
}

export function NetworkView() {
  const { assets, summary, error, loading, reload } = useInventory();
  // Drawer selection by id, never by object: the asset is re-derived from the
  // latest poll data, so the drawer always shows fresh values.
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const groups = useMemo(() => groupBySubnet(assets), [assets]);

  // If the selected asset disappears after a poll, close the drawer.
  useEffect(() => {
    if (selectedId != null && !assets.some((a) => a.id === selectedId)) {
      // eslint-disable-next-line react-hooks/set-state-in-effect -- resetting stale selection after the asset left the inventory
      setSelectedId(null);
    }
  }, [assets, selectedId]);

  if (loading) return <LoadingState />;
  if (error) return <ErrorState message={error} />;

  const selected =
    selectedId == null
      ? null
      : assets.find((a) => a.id === selectedId) ?? null;

  const subnetCount = groups.filter((g) => g.prefix !== null).length;
  const internetFacing =
    summary?.internet_facing ??
    assets.filter((a) => a.exposure === "internet_facing").length;
  const openServices = assets.reduce((n, a) => n + a.services.length, 0);

  return (
    <div className="space-y-6">
      <div className="argus-rise">
        <PageHeader
          title="Network"
          description="Inventory grouped by IPv4 /24 subnet"
        />
      </div>

      {assets.length === 0 ? (
        <Panel bodyClassName="p-0">
          <EmptyState
            title="No assets discovered yet"
            hint="Run a discovery scan or import nmap XML on the Assets page to populate the network map."
          />
        </Panel>
      ) : (
        <div className="space-y-6">
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <StatCard
              label="Subnets"
              value={subnetCount}
              hint="IPv4 /24 networks"
            />
            <StatCard label="Hosts" value={assets.length} hint="Discovered assets" />
            <StatCard
              label="Internet-facing"
              value={internetFacing}
              hint="Exposed to the internet"
              tone={internetFacing > 0 ? "warn" : "default"}
            />
            <StatCard
              label="Open services"
              value={openServices}
              hint="Across all hosts"
            />
          </div>

          {groups.map((group) => (
            <Panel
              key={group.key}
              title={group.label}
              description={`${group.hosts.length} host${group.hosts.length === 1 ? "" : "s"}`}
              actions={<RiskBadge band={group.worst} />}
              bodyClassName="p-4"
            >
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-4">
                {group.hosts.map((host) => (
                  <HostCard
                    key={host.asset.id}
                    host={host}
                    onSelect={(a) => setSelectedId(a.id)}
                  />
                ))}
              </div>
            </Panel>
          ))}

          <div className="flex flex-wrap items-center gap-x-4 gap-y-2 px-1">
            <span className="text-[11px] font-medium uppercase tracking-[0.08em] text-muted">
              Risk bands
            </span>
            {[...bandOrder].reverse().map((band) => (
              <span
                key={band}
                className="inline-flex items-center gap-1.5 text-xs text-muted"
              >
                <span
                  className={`h-2 w-2 rounded-full ${bandStyles[band].bar}`}
                  aria-hidden
                />
                {bandStyles[band].label}
              </span>
            ))}
          </div>
        </div>
      )}

      <AssetDrawer asset={selected} onClose={() => setSelectedId(null)} onUpdated={reload} />
    </div>
  );
}
