"use client";

// Network topology: a physical-diagram-style tree rendered as positioned HTML
// nodes over an SVG edge layer (no graph library). Tiers, top to bottom:
//   Internet (cloud) → Gateway → one Switch per /24 subnet → device per asset.
// Device glyphs come from the shared asset-type icon set, the IP is the label
// and the risk band is a corner dot. Structure is derived from observed IPs
// (subnet membership) — Argus has no L2/traffic data, so this is logical, not
// physical cabling. Click a device for its drawer; drag to pan, wheel to zoom.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { PointerEvent as RPointerEvent, WheelEvent as RWheelEvent } from "react";
import type { AssetType, GraphData, GraphNode, RiskBand, ScoredAsset } from "@/lib/api";
import { assetTypeIcon, assetTypeLabel, bandStyles } from "@/lib/ui";
import { useGraph } from "@/lib/use-graph";
import { useInventory } from "@/lib/use-inventory";
import { AssetDrawer } from "@/components/asset-drawer";
import { Icon } from "@/components/icon";
import { Button, Input, PageHeader, Panel, Select, Toggle } from "@/components/ui";
import { EmptyState, ErrorState, LoadingState } from "@/components/states";

// ---- layout geometry (stage coordinates, pre-zoom) -------------------------
const PAD = 48;
const Y_INTERNET = 44;
const Y_GATEWAY = 156;
const Y_SWITCH = 280;
const Y_DEV_TOP = 396; // centre of the first device row
const DEV_W = 128; // horizontal cell per device
const DEV_H = 108; // vertical cell per device row
const COLS = 4; // devices per row within a subnet block
const BLOCK_GAP = 56; // gap between subnet blocks
const MIN_W = 640;
const ZOOM_MIN = 0.4;
const ZOOM_MAX = 2.2;

// info → critical, for the legend (low-to-high reading order).
const bandOrderReversed: RiskBand[] = ["info", "low", "medium", "high", "critical"];

// All asset types for the type-filter dropdown.
const ALL_ASSET_TYPES: AssetType[] = ["it", "ot", "iot", "iomt", "network", "cloud", "mobile", "unknown"];

interface Placed {
  x: number;
  y: number;
}
interface DeviceNode extends Placed {
  id: string;
  ip: string;
  hostname: string | null;
  type: AssetType;
  band: RiskBand;
  internetFacing: boolean;
  hasServices: boolean;
}
interface SwitchNode extends Placed {
  id: string;
  label: string;
  count: number;
  devices: DeviceNode[];
}
interface Edge {
  key: string;
  x1: number;
  y1: number;
  x2: number;
  y2: number;
  deviceId?: string; // set on switch→device edges for dimming
}
interface Layout {
  switches: SwitchNode[];
  internet: Placed;
  gateway: Placed;
  edges: Edge[];
  width: number;
  height: number;
}

/** First IPv4 (then any IP) of an asset, or null. */
function assetIp(asset: ScoredAsset | undefined): string | null {
  if (!asset) return null;
  const ips = asset.interfaces.map((i) => i.ip).filter((ip): ip is string => !!ip);
  return ips.find((ip) => ip.includes(".")) ?? ips[0] ?? null;
}

/** First hostname of an asset, or null. */
function assetHostname(asset: ScoredAsset | undefined): string | null {
  if (!asset) return null;
  return asset.interfaces.find((i) => i.hostname)?.hostname ?? null;
}

/** Sort key for an IPv4 string so .2 < .10 < .100 within a subnet. */
function ipSortKey(ip: string): number {
  const parts = ip.split(".").map((p) => Number.parseInt(p, 10));
  if (parts.length !== 4 || parts.some(Number.isNaN)) return Number.MAX_SAFE_INTEGER;
  return ((parts[0] * 256 + parts[1]) * 256 + parts[2]) * 256 + parts[3];
}

function prettySubnet(label: string): string {
  return label === "unzoned" ? "Unzoned" : label;
}

/** Turn the asset/subnet graph into a tiered, positioned topology. */
function layout(graph: GraphData, byId: Map<string, ScoredAsset>): Layout {
  const assetNodes = new Map<string, GraphNode>(
    graph.nodes.filter((n) => n.kind === "asset").map((n) => [n.id, n]),
  );
  // subnet id -> member asset ids (from membership edges)
  const members = new Map<string, string[]>();
  for (const e of graph.edges) {
    if (!members.has(e.target)) members.set(e.target, []);
    members.get(e.target)!.push(e.source);
  }

  const subnetNodes = graph.nodes
    .filter((n) => n.kind === "subnet")
    .sort((a, b) => a.label.localeCompare(b.label));

  // Width each subnet block needs, then place blocks left-to-right.
  const blockWidth = (n: number) => Math.min(Math.max(n, 1), COLS) * DEV_W;
  const totalBlocks =
    subnetNodes.reduce((w, s) => w + blockWidth(members.get(s.id)?.length ?? 0), 0) +
    BLOCK_GAP * Math.max(subnetNodes.length - 1, 0);
  const width = Math.max(totalBlocks + 2 * PAD, MIN_W);

  let cursor = (width - (totalBlocks || width - 2 * PAD)) / 2; // centre the row
  let maxRows = 1;
  const switches: SwitchNode[] = subnetNodes.map((sn) => {
    const ids = (members.get(sn.id) ?? []).slice();
    const devices: Omit<DeviceNode, "x" | "y">[] = ids
      .map((id) => {
        const gn = assetNodes.get(id);
        const asset = byId.get(id);
        const ip = assetIp(asset) ?? gn?.label ?? "—";
        const hostname = assetHostname(asset);
        const hasServices = (asset?.services?.length ?? 0) > 0;
        return {
          id,
          ip,
          hostname,
          type: (gn?.asset_type ?? "unknown") as AssetType,
          band: (gn?.band ?? "info") as RiskBand,
          internetFacing: gn?.exposure === "internet_facing",
          hasServices,
        };
      })
      .sort((a, b) => ipSortKey(a.ip) - ipSortKey(b.ip));

    const bw = blockWidth(devices.length);
    const blockX = cursor;
    const cols = Math.min(Math.max(devices.length, 1), COLS);
    const rows = Math.max(Math.ceil(devices.length / cols), 1);
    maxRows = Math.max(maxRows, rows);

    const placed: DeviceNode[] = devices.map((d, j) => {
      const col = j % cols;
      const row = Math.floor(j / cols);
      // Centre a short last row under the block.
      const inRow = Math.min(devices.length - row * cols, cols);
      const rowW = inRow * DEV_W;
      const rowX = blockX + (bw - rowW) / 2;
      return { ...d, x: rowX + col * DEV_W + DEV_W / 2, y: Y_DEV_TOP + row * DEV_H };
    });

    cursor += bw + BLOCK_GAP;
    return {
      id: sn.id,
      label: prettySubnet(sn.label),
      count: sn.count ?? devices.length,
      devices: placed,
      x: blockX + bw / 2,
      y: Y_SWITCH,
    };
  });

  const firstSwitch = switches[0]?.x ?? width / 2;
  const lastSwitch = switches[switches.length - 1]?.x ?? width / 2;
  const gateway: Placed = { x: (firstSwitch + lastSwitch) / 2, y: Y_GATEWAY };
  const internet: Placed = { x: gateway.x, y: Y_INTERNET };

  const edges: Edge[] = [
    { key: "net-gw", x1: internet.x, y1: internet.y, x2: gateway.x, y2: gateway.y },
  ];
  for (const s of switches) {
    edges.push({ key: `gw-${s.id}`, x1: gateway.x, y1: gateway.y, x2: s.x, y2: s.y });
    for (const d of s.devices) {
      edges.push({ key: `${s.id}-${d.id}`, x1: s.x, y1: s.y, x2: d.x, y2: d.y, deviceId: d.id });
    }
  }

  const height = Y_DEV_TOP + (maxRows - 1) * DEV_H + DEV_H / 2 + PAD;
  return { switches, internet, gateway, edges, width, height };
}

// ---- node chrome -----------------------------------------------------------
function Hub({
  x,
  y,
  icon,
  title,
  sub,
}: {
  x: number;
  y: number;
  icon: "cloud" | "network";
  title: string;
  sub?: string;
}) {
  return (
    <div
      className="absolute flex -translate-x-1/2 -translate-y-1/2 flex-col items-center"
      style={{ left: x, top: y }}
    >
      <div className="flex h-12 w-12 items-center justify-center rounded-xl border border-line bg-surface text-accent shadow-sm">
        <Icon name={icon} size={24} />
      </div>
      <div className="mt-1.5 text-center">
        <div className="text-xs font-semibold text-fg-2">{title}</div>
        {sub && <div className="text-[10px] text-muted">{sub}</div>}
      </div>
    </div>
  );
}

function SwitchTile({ node }: { node: SwitchNode }) {
  return (
    <div
      className="absolute flex -translate-x-1/2 -translate-y-1/2 flex-col items-center"
      style={{ left: node.x, top: node.y }}
    >
      <div className="flex h-10 items-center gap-1.5 rounded-lg border border-accent/30 bg-accent-soft px-3 text-accent shadow-sm">
        <Icon name="grid" size={16} />
        <span className="text-xs font-semibold tabular-nums">{node.label}</span>
      </div>
      <div className="mt-1 text-[10px] text-muted">
        Switch · {node.count} {node.count === 1 ? "host" : "hosts"}
      </div>
    </div>
  );
}

function Device({
  node,
  selected,
  highlight,
  dim,
  onSelect,
}: {
  node: DeviceNode;
  selected: boolean;
  highlight: boolean;
  dim: boolean;
  onSelect: (id: string) => void;
}) {
  return (
    <button
      type="button"
      onClick={() => onSelect(node.id)}
      className={[
        "absolute flex w-[112px] -translate-x-1/2 -translate-y-1/2 flex-col items-center rounded-xl border bg-surface px-2 py-2.5 text-center shadow-sm transition hover:border-accent hover:shadow-md",
        selected
          ? "border-accent ring-2 ring-accent/30"
          : highlight
            ? "border-accent ring-2 ring-accent/50 scale-110"
            : "border-line",
        dim ? "opacity-25" : "",
      ]
        .filter(Boolean)
        .join(" ")}
      style={{ left: node.x, top: node.y }}
      title={`${assetTypeLabel[node.type]} · ${node.ip}`}
    >
      <span className="relative flex h-9 w-9 items-center justify-center rounded-lg bg-surface-2 text-fg-2">
        <Icon name={assetTypeIcon[node.type]} size={20} />
        <span
          className={`absolute -right-1 -top-1 h-2.5 w-2.5 rounded-full ring-2 ring-surface ${bandStyles[node.band].bar}`}
          aria-hidden
        />
        {node.internetFacing && (
          <span className="absolute -left-1 -top-1 flex h-3.5 w-3.5 items-center justify-center rounded-full bg-surface text-accent ring-1 ring-line">
            <Icon name="external" size={9} />
          </span>
        )}
      </span>
      <span className="mt-1.5 font-mono text-[11px] font-medium tabular-nums text-fg">
        {node.ip}
      </span>
      <span className="text-[10px] text-muted">{assetTypeLabel[node.type]}</span>
    </button>
  );
}

// ---- filter state ----------------------------------------------------------
interface FilterState {
  search: string;
  riskBand: RiskBand | "all";
  assetType: AssetType | "all";
  hideUnscanned: boolean;
  hideInfo: boolean;
}

const DEFAULT_FILTERS: FilterState = {
  search: "",
  riskBand: "all",
  assetType: "all",
  hideUnscanned: false,
  hideInfo: false,
};

/** Returns true if the device passes the active filter set. */
function deviceVisible(node: DeviceNode, f: FilterState): boolean {
  if (f.riskBand !== "all" && node.band !== f.riskBand) return false;
  if (f.assetType !== "all" && node.type !== f.assetType) return false;
  if (f.hideUnscanned && !node.hasServices && node.band === "info") return false;
  if (f.hideInfo && node.band === "info") return false;
  return true;
}

/** Returns true if the device matches the search query. */
function deviceMatchesSearch(node: DeviceNode, q: string): boolean {
  if (!q) return true;
  const lq = q.toLowerCase();
  if (node.ip.toLowerCase().includes(lq)) return true;
  if (node.hostname?.toLowerCase().includes(lq)) return true;
  if (assetTypeLabel[node.type].toLowerCase().includes(lq)) return true;
  return false;
}

export function GraphView() {
  const { graph, error, loading, reload } = useGraph();
  const { assets, reload: reloadInventory } = useInventory();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [filters, setFilters] = useState<FilterState>(DEFAULT_FILTERS);

  const byId = useMemo(() => new Map(assets.map((a) => [a.id, a])), [assets]);
  const model = useMemo(
    () => (graph && graph.nodes.length > 0 ? layout(graph, byId) : null),
    [graph, byId],
  );

  // pan / zoom over the stage
  const viewportRef = useRef<HTMLDivElement>(null);
  const [view, setView] = useState({ k: 1, x: 0, y: 0 });
  const drag = useRef<{ px: number; py: number; vx: number; vy: number } | null>(null);

  const fit = useCallback(() => {
    const vp = viewportRef.current;
    if (!vp || !model) return;
    const k = Math.min(1, (vp.clientWidth - 24) / model.width, (vp.clientHeight - 24) / model.height);
    setView({ k, x: (vp.clientWidth - model.width * k) / 2, y: (vp.clientHeight - model.height * k) / 2 });
  }, [model]);

  // Fit whenever a new model loads or the viewport resizes.
  useEffect(() => {
    fit();
    const vp = viewportRef.current;
    if (!vp || typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver(() => fit());
    ro.observe(vp);
    return () => ro.disconnect();
  }, [fit]);

  // Derived: which device IDs are visible / highlighted / dimmed.
  const { visibleIds, highlightedIds, firstMatchNode } = useMemo(() => {
    if (!model) return { visibleIds: new Set<string>(), highlightedIds: new Set<string>(), firstMatchNode: null };

    const allDevices = model.switches.flatMap((s) => s.devices);
    const visible = new Set<string>();
    const highlighted = new Set<string>();
    let firstMatch: DeviceNode | null = null;

    const hasSearch = filters.search.trim().length > 0;

    for (const d of allDevices) {
      if (!deviceVisible(d, filters)) continue;
      visible.add(d.id);
      if (hasSearch && deviceMatchesSearch(d, filters.search)) {
        highlighted.add(d.id);
        if (!firstMatch) firstMatch = d;
      }
    }

    return { visibleIds: visible, highlightedIds: highlighted, firstMatchNode: firstMatch };
  }, [model, filters]);

  // Auto-pan to the first search match.
  useEffect(() => {
    if (!firstMatchNode || !viewportRef.current) return;
    const vp = viewportRef.current;
    setView((v) => ({
      ...v,
      x: vp.clientWidth / 2 - firstMatchNode.x * v.k,
      y: vp.clientHeight / 2 - firstMatchNode.y * v.k,
    }));
  }, [firstMatchNode]);

  const onWheel = useCallback((e: RWheelEvent) => {
    e.preventDefault();
    setView((v) => ({
      ...v,
      k: Math.min(ZOOM_MAX, Math.max(ZOOM_MIN, v.k * (e.deltaY < 0 ? 1.1 : 0.9))),
    }));
  }, []);

  const onPointerDown = useCallback(
    (e: RPointerEvent) => {
      drag.current = { px: e.clientX, py: e.clientY, vx: view.x, vy: view.y };
      (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId);
    },
    [view.x, view.y],
  );
  const onPointerMove = useCallback((e: RPointerEvent) => {
    const d = drag.current;
    if (!d) return;
    setView((v) => ({ ...v, x: d.vx + (e.clientX - d.px), y: d.vy + (e.clientY - d.py) }));
  }, []);
  const onPointerUp = useCallback(() => {
    drag.current = null;
  }, []);

  const zoom = (factor: number) =>
    setView((v) => ({ ...v, k: Math.min(ZOOM_MAX, Math.max(ZOOM_MIN, v.k * factor)) }));

  const selected = selectedId == null ? null : (assets.find((a) => a.id === selectedId) ?? null);
  const refresh = () => {
    void reload();
    void reloadInventory();
  };

  const isFiltered =
    filters.search !== DEFAULT_FILTERS.search ||
    filters.riskBand !== DEFAULT_FILTERS.riskBand ||
    filters.assetType !== DEFAULT_FILTERS.assetType ||
    filters.hideUnscanned !== DEFAULT_FILTERS.hideUnscanned ||
    filters.hideInfo !== DEFAULT_FILTERS.hideInfo;

  const hasSearch = filters.search.trim().length > 0;

  return (
    <div className="space-y-6">
      <div className="argus-rise">
        <PageHeader
          title="Topology"
          description="Network map — Internet, gateway, per-subnet switches and their devices"
        />
      </div>

      <Panel
        title="Network diagram"
        description="Click a device for details · drag to pan, scroll to zoom"
        actions={
          <div className="flex items-center gap-2">
            <Button variant="secondary" size="sm" onClick={() => zoom(1 / 1.2)}>
              −
            </Button>
            <Button variant="secondary" size="sm" onClick={() => zoom(1.2)}>
              +
            </Button>
            <Button variant="secondary" size="sm" onClick={fit}>
              Fit
            </Button>
            <Button variant="secondary" size="sm" onClick={refresh}>
              Refresh
            </Button>
          </div>
        }
        bodyClassName="p-4"
      >
        {loading && !graph ? (
          <LoadingState />
        ) : error && !graph ? (
          <ErrorState message={error} />
        ) : !model ? (
          <EmptyState
            title="No assets to map"
            hint="Run a discovery scan or import nmap results on the Assets page first."
          />
        ) : (
          <>
            {/* ---- filter bar ---- */}
            <div className="mb-3 flex flex-wrap items-center gap-2">
              <div className="w-52">
                <Input
                  placeholder="Search IP, hostname, type…"
                  value={filters.search}
                  onChange={(e) => setFilters((f) => ({ ...f, search: e.target.value }))}
                />
              </div>

              <Select
                value={filters.riskBand}
                onChange={(e) =>
                  setFilters((f) => ({ ...f, riskBand: e.target.value as RiskBand | "all" }))
                }
                className="w-36"
              >
                <option value="all">All risks</option>
                {bandOrderReversed.slice().reverse().map((b) => (
                  <option key={b} value={b}>
                    {bandStyles[b].label}
                  </option>
                ))}
              </Select>

              <Select
                value={filters.assetType}
                onChange={(e) =>
                  setFilters((f) => ({ ...f, assetType: e.target.value as AssetType | "all" }))
                }
                className="w-36"
              >
                <option value="all">All types</option>
                {ALL_ASSET_TYPES.map((t) => (
                  <option key={t} value={t}>
                    {assetTypeLabel[t]}
                  </option>
                ))}
              </Select>

              <Toggle
                checked={filters.hideUnscanned}
                onChange={(v) => setFilters((f) => ({ ...f, hideUnscanned: v }))}
                label="Hide unscanned"
              />

              <Toggle
                checked={filters.hideInfo}
                onChange={(v) => setFilters((f) => ({ ...f, hideInfo: v }))}
                label="Hide info-risk"
              />

              {isFiltered && (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setFilters(DEFAULT_FILTERS)}
                >
                  Clear
                </Button>
              )}

              {hasSearch && highlightedIds.size > 0 && (
                <span className="text-xs text-muted">
                  {highlightedIds.size} match{highlightedIds.size !== 1 ? "es" : ""}
                </span>
              )}
              {hasSearch && highlightedIds.size === 0 && (
                <span className="text-xs text-muted">No matches</span>
              )}
            </div>

            <div
              ref={viewportRef}
              onWheel={onWheel}
              onPointerDown={onPointerDown}
              onPointerMove={onPointerMove}
              onPointerUp={onPointerUp}
              onPointerLeave={onPointerUp}
              className="relative h-[68vh] w-full cursor-grab overflow-hidden rounded-lg border border-line bg-surface-2/30 active:cursor-grabbing"
            >
              <div
                className="absolute left-0 top-0 origin-top-left"
                style={{
                  width: model.width,
                  height: model.height,
                  transform: `translate(${view.x}px, ${view.y}px) scale(${view.k})`,
                }}
              >
                <svg
                  className="pointer-events-none absolute left-0 top-0"
                  width={model.width}
                  height={model.height}
                >
                  {model.edges.map((e) => {
                    // Dim edges to non-visible device nodes
                    const isDimEdge =
                      e.deviceId !== undefined && !visibleIds.has(e.deviceId);
                    const isHighlightEdge =
                      hasSearch &&
                      e.deviceId !== undefined &&
                      highlightedIds.has(e.deviceId);
                    const isSearchDimEdge =
                      hasSearch &&
                      e.deviceId !== undefined &&
                      !highlightedIds.has(e.deviceId) &&
                      visibleIds.has(e.deviceId);
                    return (
                      <line
                        key={e.key}
                        x1={e.x1}
                        y1={e.y1}
                        x2={e.x2}
                        y2={e.y2}
                        stroke="var(--color-line-strong)"
                        strokeWidth={isHighlightEdge ? 2 : 1.25}
                        opacity={isDimEdge || isSearchDimEdge ? 0.15 : 1}
                      />
                    );
                  })}
                </svg>

                <Hub {...model.internet} icon="cloud" title="Internet" />
                <Hub
                  {...model.gateway}
                  icon="network"
                  title="Gateway"
                  sub={`${model.switches.length} ${model.switches.length === 1 ? "subnet" : "subnets"}`}
                />
                {model.switches.map((s) => (
                  <SwitchTile key={s.id} node={s} />
                ))}
                {model.switches.flatMap((s) =>
                  s.devices.map((d) => {
                    const isVisible = visibleIds.has(d.id);
                    if (!isVisible) return null;
                    const isHighlighted = hasSearch ? highlightedIds.has(d.id) : false;
                    const isDimmed = hasSearch && !isHighlighted;
                    return (
                      <Device
                        key={d.id}
                        node={d}
                        selected={d.id === selectedId}
                        highlight={isHighlighted}
                        dim={isDimmed}
                        onSelect={setSelectedId}
                      />
                    );
                  }),
                )}
              </div>
            </div>

            <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-2 px-1">
              <span className="text-[11px] font-medium uppercase tracking-[0.08em] text-muted">
                Risk
              </span>
              {[...bandOrderReversed].map((band) => (
                <span key={band} className="inline-flex items-center gap-1.5 text-xs text-muted">
                  <span className={`h-2 w-2 rounded-full ${bandStyles[band].bar}`} aria-hidden />
                  {bandStyles[band].label}
                </span>
              ))}
              <span className="ml-auto text-[11px] text-muted">
                Switches = /24 subnets · edges = subnet membership, not physical links
              </span>
            </div>
          </>
        )}
      </Panel>

      <AssetDrawer asset={selected} onClose={() => setSelectedId(null)} onUpdated={refresh} />
    </div>
  );
}
