"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import {
  importNmap,
  runScan,
  type AssetType,
  type RiskBand,
} from "@/lib/api";
import {
  assetTypeIcon,
  assetTypeLabel,
  bandOrder,
  bandStyles,
  exposureLabel,
} from "@/lib/ui";
import { useInventory } from "@/lib/use-inventory";
import { Icon, type IconName } from "@/components/icon";
import { RiskBadge } from "@/components/risk-badge";
import { AssetDrawer } from "@/components/asset-drawer";
import { EmptyState, ErrorState, LoadingState } from "@/components/states";
import {
  Badge,
  Button,
  Field,
  Input,
  PageHeader,
  Panel,
  Toggle,
} from "@/components/ui";

type Filter =
  | { kind: "type"; value: AssetType }
  | { kind: "band"; value: RiskBand };

/** Clickable group-by filter card: icon tile + label + count. */
function GroupCard({
  icon,
  tile,
  title,
  count,
  active,
  onClick,
}: {
  icon: IconName;
  tile: string;
  title: string;
  count: number;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <Button
      variant="secondary"
      onClick={onClick}
      aria-pressed={active}
      // cx does NOT resolve Tailwind conflicts; rounded-xl wins over Button's rounded-lg only via source-order — revisit tailwind-merge if override count grows.
      className={
        "flex w-full items-center gap-3 rounded-xl p-4 text-left shadow-[0_1px_2px_rgba(16,24,40,0.05)]" +
        (active ? " border-accent ring-1 ring-accent" : " hover:border-line-strong hover:bg-surface-2/60")
      }
    >
      <span
        className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg ${tile}`}
      >
        <Icon name={icon} size={18} />
      </span>
      <span className="min-w-0">
        <span className="block truncate text-sm font-medium text-fg">
          {title}
        </span>
        <span className="mt-0.5 block text-xs tabular-nums text-muted">
          {count} asset{count === 1 ? "" : "s"}
        </span>
      </span>
    </Button>
  );
}

export function AssetsView() {
  const { summary, assets, error, loading, reload } = useInventory();
  const router = useRouter();
  const searchParams = useSearchParams();
  const urlQ = searchParams.get("q") ?? "";

  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [target, setTarget] = useState("127.0.0.1");
  const [deep, setDeep] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [scanNote, setScanNote] = useState<string | null>(null);
  const [filter, setFilter] = useState<Filter | null>(null);
  const [q, setQ] = useState(urlQ);
  const [sortAsc, setSortAsc] = useState(false);
  const [showScan, setShowScan] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);
  const mounted = useRef(true);
  const debounceRef = useRef<number | null>(null);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      if (debounceRef.current !== null) {
        window.clearTimeout(debounceRef.current);
      }
    };
  }, []);

  // The URL ?q= param is the source of truth for the filter. Typing updates
  // local state immediately and writes the URL back debounced, so URL and
  // filter can never diverge — a repeated identical topbar search stays
  // consistent without any nonce tricks.
  const onQueryChange = (value: string) => {
    setQ(value);
    if (debounceRef.current !== null) window.clearTimeout(debounceRef.current);
    debounceRef.current = window.setTimeout(() => {
      debounceRef.current = null;
      router.replace(
        value ? `/assets?q=${encodeURIComponent(value)}` : "/assets",
        { scroll: false },
      );
    }, 300);
  };

  // Adopt the URL value into state on navigation (topbar search) whenever it
  // differs from what the filter box currently shows; drop any pending
  // write-back from typing so it cannot overwrite the navigation.
  const qRef = useRef(q);
  useEffect(() => {
    qRef.current = q;
  });
  useEffect(() => {
    if (urlQ === qRef.current) return;
    if (debounceRef.current !== null) {
      window.clearTimeout(debounceRef.current);
      debounceRef.current = null;
    }
    setQ(urlQ);
  }, [urlQ]);

  // Drawer selection holds only the id; the object is derived per render from
  // the latest poll data. When the id disappears after a poll, close.
  const selected = selectedId
    ? (assets.find((a) => a.id === selectedId) ?? null)
    : null;
  useEffect(() => {
    if (selectedId && !assets.some((a) => a.id === selectedId)) {
      // eslint-disable-next-line react-hooks/set-state-in-effect -- resetting stale selection after the asset left the inventory
      setSelectedId(null);
    }
  }, [assets, selectedId]);

  const onScan = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setScanning(true);
    setScanNote(null);
    try {
      const r = await runScan(target.trim() || "127.0.0.1", deep);
      await reload();
      if (mounted.current) {
        setScanNote(
          `${r.live} live · ${r.hosts_scanned} scanned · ${r.changes} change${r.changes === 1 ? "" : "s"} · ${r.duration_ms} ms`,
        );
      }
    } catch (err) {
      if (mounted.current) {
        setScanNote(err instanceof Error ? err.message : "scan failed");
      }
    } finally {
      if (mounted.current) setScanning(false);
    }
  };

  const onImport = async (file: File) => {
    const MAX_IMPORT_BYTES = 20 * 1024 * 1024; // 20 MB — guard against reading a huge file into memory
    if (file.size > MAX_IMPORT_BYTES) {
      setScanNote(
        `file too large (${(file.size / 1_048_576).toFixed(1)} MB; max 20 MB)`,
      );
      return;
    }
    setScanning(true);
    setScanNote(null);
    try {
      const xml = await file.text();
      const r = await importNmap(xml);
      await reload();
      if (mounted.current) {
        setScanNote(
          `imported ${r.imported} host${r.imported === 1 ? "" : "s"} from nmap XML`,
        );
      }
    } catch (err) {
      if (mounted.current) {
        setScanNote(err instanceof Error ? err.message : "import failed");
      }
    } finally {
      if (mounted.current) setScanning(false);
    }
  };

  if (loading) return <LoadingState />;
  if (error) return <ErrorState message={error} />;

  const byType = (Object.keys(assetTypeLabel) as AssetType[])
    .map((t) => ({ t, n: assets.filter((a) => a.asset_type === t).length }))
    .filter((g) => g.n > 0);
  const byBand = bandOrder
    .map((b) => ({ b, n: assets.filter((a) => a.risk.band === b).length }))
    .filter((g) => g.n > 0);

  let list = assets;
  if (filter?.kind === "type")
    list = list.filter((a) => a.asset_type === filter.value);
  if (filter?.kind === "band")
    list = list.filter((a) => a.risk.band === filter.value);
  if (q.trim()) {
    const s = q.trim().toLowerCase();
    list = list.filter(
      (a) =>
        (a.fingerprint.device_type ?? "").toLowerCase().includes(s) ||
        (a.fingerprint.vendor ?? "").toLowerCase().includes(s) ||
        a.interfaces.some(
          (i) =>
            (i.ip ?? "").includes(s) ||
            (i.hostname ?? "").toLowerCase().includes(s),
        ),
    );
  }
  list = [...list].sort((a, b) =>
    sortAsc ? a.risk.value - b.risk.value : b.risk.value - a.risk.value,
  );

  const filterLabel =
    filter?.kind === "type"
      ? assetTypeLabel[filter.value]
      : filter?.kind === "band"
        ? `${bandStyles[filter.value].label} risk`
        : null;

  const total = summary?.total_assets ?? assets.length;

  return (
    <div className="space-y-6">
      <div className="argus-rise">
        <PageHeader
          title="Assets"
          description={`${total} asset${total === 1 ? "" : "s"} tracked · ${summary?.internet_facing ?? 0} internet-facing · ${summary?.critical_or_high ?? 0} high or critical risk`}
          actions={
            <Button
              onClick={() => setShowScan((v) => !v)}
              aria-expanded={showScan}
            >
              <Icon name="search" size={15} />
              Run discovery
            </Button>
          }
        />
      </div>

      {showScan ? (
        <Panel
          title="Active discovery"
          description="Connect scan against an IP or CIDR — authorized targets only. Deep uses masscan + nmap (privileged)."
        >
          <form
            onSubmit={(e) => void onScan(e)}
            className="flex flex-wrap items-end gap-x-4 gap-y-3"
          >
            <div className="w-full sm:w-72">
              <Field label="Target">
                <Input
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="192.168.1.0/24"
                  disabled={scanning}
                />
              </Field>
            </div>
            <div className="flex h-9 items-center">
              <Toggle
                checked={deep}
                onChange={setDeep}
                disabled={scanning}
                label="Deep scan"
              />
            </div>
            <div className="flex items-center gap-2">
              <Button type="submit" disabled={scanning}>
                {scanning ? "Scanning…" : "Start scan"}
              </Button>
              <Button
                type="button"
                variant="secondary"
                disabled={scanning}
                onClick={() => fileRef.current?.click()}
              >
                Import nmap XML
              </Button>
            </div>
            <input
              ref={fileRef}
              type="file"
              accept=".xml,text/xml"
              className="hidden"
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) void onImport(f);
                e.target.value = "";
              }}
            />
          </form>
          {scanNote ? (
            <p className="mt-3 text-xs tabular-nums text-muted">{scanNote}</p>
          ) : null}
        </Panel>
      ) : null}

      <section>
        <div className="mb-3 flex h-7 items-center justify-between">
          <h2 className="text-[11px] font-medium uppercase tracking-[0.08em] text-muted">
            Grouped by type
          </h2>
          {filter?.kind === "type" ? (
            <Button variant="ghost" size="sm" onClick={() => setFilter(null)}>
              Show all
            </Button>
          ) : null}
        </div>
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          {byType.map(({ t, n }) => (
            <GroupCard
              key={t}
              icon={assetTypeIcon[t]}
              tile="bg-surface-2 text-fg-2"
              title={assetTypeLabel[t]}
              count={n}
              active={filter?.kind === "type" && filter.value === t}
              onClick={() =>
                setFilter(
                  filter?.kind === "type" && filter.value === t
                    ? null
                    : { kind: "type", value: t },
                )
              }
            />
          ))}
        </div>
      </section>

      <section>
        <div className="mb-3 flex h-7 items-center justify-between">
          <h2 className="text-[11px] font-medium uppercase tracking-[0.08em] text-muted">
            Grouped by risk
          </h2>
          {filter?.kind === "band" ? (
            <Button variant="ghost" size="sm" onClick={() => setFilter(null)}>
              Show all
            </Button>
          ) : null}
        </div>
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          {byBand.map(({ b, n }) => (
            <GroupCard
              key={b}
              icon="gauge"
              tile={`${bandStyles[b].bg} ${bandStyles[b].text}`}
              title={`${bandStyles[b].label} risk`}
              count={n}
              active={filter?.kind === "band" && filter.value === b}
              onClick={() =>
                setFilter(
                  filter?.kind === "band" && filter.value === b
                    ? null
                    : { kind: "band", value: b },
                )
              }
            />
          ))}
        </div>
      </section>

      <Panel
        title="Inventory"
        description={`${list.length} of ${assets.length} asset${assets.length === 1 ? "" : "s"}`}
        actions={
          <>
            {filterLabel ? (
              <Badge tone="accent">
                {filterLabel}
                <button
                  type="button"
                  onClick={() => setFilter(null)}
                  aria-label="Clear filter"
                  className="rounded-full transition-colors hover:text-accent-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40"
                >
                  <Icon name="x" size={12} />
                </button>
              </Badge>
            ) : null}
            <div className="w-40 sm:w-56">
              <Input
                value={q}
                onChange={(e) => onQueryChange(e.target.value)}
                placeholder="Filter assets…"
                aria-label="Filter assets"
              />
            </div>
            <Button
              variant="secondary"
              onClick={() => setSortAsc((v) => !v)}
              aria-label={`Sort by risk, ${sortAsc ? "ascending" : "descending"}`}
            >
              Risk
              <span
                className={`transition-transform ${sortAsc ? "rotate-180" : ""}`}
              >
                <Icon name="chevron" size={14} />
              </span>
            </Button>
          </>
        }
        bodyClassName="p-0"
      >
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-line bg-surface-2/60 text-left text-xs text-muted">
                <th className="px-4 py-3 font-medium">Asset</th>
                <th className="px-4 py-3 font-medium">Type</th>
                <th className="px-4 py-3 font-medium">Address</th>
                <th className="px-4 py-3 font-medium">Exposure</th>
                <th className="px-4 py-3 font-medium">Services</th>
                <th className="px-4 py-3 text-right font-medium">Risk</th>
              </tr>
            </thead>
            <tbody>
              {list.map((a) => {
                const iface = a.interfaces.find((i) => i.ip) ?? a.interfaces[0];
                const sub = [a.fingerprint.vendor, a.fingerprint.os]
                  .filter(Boolean)
                  .join(" · ");
                return (
                  <tr
                    key={a.id}
                    onClick={() => setSelectedId(a.id)}
                    className="cursor-pointer border-b border-line transition-colors last:border-0 hover:bg-surface-2/60"
                  >
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-3">
                        <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-surface-2 text-muted">
                          <Icon name={assetTypeIcon[a.asset_type]} size={16} />
                        </span>
                        <div className="min-w-0">
                          <button
                            type="button"
                            onClick={() => setSelectedId(a.id)}
                            className="block max-w-full truncate rounded text-left font-medium text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40"
                          >
                            {a.fingerprint.device_type ?? "Unknown device"}
                          </button>
                          <div className="truncate text-xs text-muted">
                            {sub || "—"}
                          </div>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <Badge>{assetTypeLabel[a.asset_type]}</Badge>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs">
                      <div className="text-fg">{iface?.ip ?? "—"}</div>
                      {iface?.mac ? (
                        <div className="text-muted">{iface.mac}</div>
                      ) : null}
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={
                          a.exposure === "internet_facing"
                            ? "font-medium text-warn"
                            : "text-fg-2"
                        }
                      >
                        {exposureLabel[a.exposure]}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-muted">
                      {a.services.length === 0
                        ? "—"
                        : a.services
                            .slice(0, 5)
                            .map((s) => s.port)
                            .join(", ") +
                          (a.services.length > 5
                            ? ` +${a.services.length - 5}`
                            : "")}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <RiskBadge band={a.risk.band} value={a.risk.value} />
                      {a.vulnerabilities.length > 0 ? (
                        <div className="mt-1 text-[11px] tabular-nums text-muted">
                          {a.vulnerabilities.length} CVE
                          {a.vulnerabilities.length > 1 ? "s" : ""}
                          {a.vulnerabilities.some((v) => v.kev) ? (
                            <span className="ml-1 font-medium text-crit">
                              KEV
                            </span>
                          ) : null}
                        </div>
                      ) : null}
                    </td>
                  </tr>
                );
              })}
              {list.length === 0 ? (
                <tr>
                  <td colSpan={6}>
                    <EmptyState
                      title="No assets match"
                      hint="Adjust the search or clear the active filter to see the full inventory."
                    />
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </Panel>

      <AssetDrawer asset={selected} onClose={() => setSelectedId(null)} onUpdated={reload} />
    </div>
  );
}
