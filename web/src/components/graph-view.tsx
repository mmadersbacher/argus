"use client";

// Asset topology graph: force-directed (Cytoscape) over GET /api/graph — asset
// nodes clustered around their /24 subnet hubs, coloured by risk band. Cytoscape
// is imported dynamically inside the effect so it never runs during SSR. The
// graph does not poll (topology changes rarely); a manual Refresh re-lays it out.

import { useCallback, useEffect, useRef, useState } from "react";
import type { Core } from "cytoscape";
import type { RiskBand } from "@/lib/api";
import { bandOrder, bandStyles } from "@/lib/ui";
import { useGraph } from "@/lib/use-graph";
import { useInventory } from "@/lib/use-inventory";
import { AssetDrawer } from "@/components/asset-drawer";
import { Button, PageHeader, Panel } from "@/components/ui";
import { EmptyState, ErrorState, LoadingState } from "@/components/states";

// Concrete CSS colours per band (Cytoscape needs values, not Tailwind classes);
// they mirror the bandStyles palette used elsewhere.
const BAND_COLOR: Record<RiskBand, string> = {
  critical: "#dc2626",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  info: "#94a3b8",
};
const SUBNET_COLOR = "#475569";
const EDGE_COLOR = "#cbd5e1";

export function GraphView() {
  const { graph, error, loading, reload } = useGraph();
  // Drawer details come from the inventory (the graph endpoint is intentionally
  // light); selection is by id, re-derived from fresh poll data.
  const { assets, reload: reloadInventory } = useInventory();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  const onSelectAsset = useCallback((id: string) => setSelectedId(id), []);

  useEffect(() => {
    if (!graph || graph.nodes.length === 0 || !containerRef.current) return;
    let cy: Core | undefined;
    let cancelled = false;
    void (async () => {
      const cytoscape = (await import("cytoscape")).default;
      if (cancelled || !containerRef.current) return;
      cy = cytoscape({
        container: containerRef.current,
        elements: [
          ...graph.nodes.map((n) => ({ data: { ...n } })),
          ...graph.edges.map((e) => ({
            data: { source: e.source, target: e.target },
          })),
        ],
        style: [
          {
            selector: "node[kind = 'asset']",
            style: {
              "background-color": BAND_COLOR.info,
              width: "mapData(risk, 0, 100, 16, 46)",
              height: "mapData(risk, 0, 100, 16, 46)",
              label: "data(label)",
              "font-size": 7,
              color: "#334155",
              "text-valign": "bottom",
              "text-margin-y": 3,
              "min-zoomed-font-size": 6,
            },
          },
          { selector: "node[band = 'critical']", style: { "background-color": BAND_COLOR.critical } },
          { selector: "node[band = 'high']", style: { "background-color": BAND_COLOR.high } },
          { selector: "node[band = 'medium']", style: { "background-color": BAND_COLOR.medium } },
          { selector: "node[band = 'low']", style: { "background-color": BAND_COLOR.low } },
          { selector: "node[band = 'info']", style: { "background-color": BAND_COLOR.info } },
          {
            selector: "node[kind = 'subnet']",
            style: {
              "background-color": SUBNET_COLOR,
              shape: "round-rectangle",
              width: 24,
              height: 24,
              label: "data(label)",
              "font-size": 8,
              "font-weight": "bold",
              color: "#1e293b",
              "text-valign": "center",
              "text-halign": "right",
              "text-margin-x": 5,
            },
          },
          {
            selector: "edge",
            style: {
              width: 1,
              "line-color": EDGE_COLOR,
              "curve-style": "straight",
              opacity: 0.55,
            },
          },
        ],
        layout: {
          name: "cose",
          animate: false,
          padding: 30,
          idealEdgeLength: 70,
          nodeRepulsion: 9000,
        },
        wheelSensitivity: 0.2,
      });
      cy.on("tap", "node[kind = 'asset']", (evt) => {
        onSelectAsset(evt.target.id());
      });
    })();
    return () => {
      cancelled = true;
      cy?.destroy();
    };
  }, [graph, onSelectAsset]);

  const selected =
    selectedId == null
      ? null
      : (assets.find((a) => a.id === selectedId) ?? null);

  const refresh = () => {
    void reload();
    void reloadInventory();
  };

  return (
    <div className="space-y-6">
      <div className="argus-rise">
        <PageHeader
          title="Topology"
          description="Assets clustered by /24 subnet, coloured by risk"
        />
      </div>

      <Panel
        title="Asset graph"
        description="Click an asset node for details"
        actions={
          <Button variant="secondary" size="sm" onClick={refresh}>
            Refresh
          </Button>
        }
        bodyClassName="p-4"
      >
        {loading && !graph ? (
          <LoadingState />
        ) : error && !graph ? (
          <ErrorState message={error} />
        ) : graph && graph.nodes.length === 0 ? (
          <EmptyState
            title="No assets to map"
            hint="Run a discovery scan or import nmap results on the Assets page first."
          />
        ) : (
          <>
            <div
              ref={containerRef}
              className="h-[68vh] w-full rounded-lg border border-line bg-surface-2/30"
            />
            <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-2 px-1">
              <span className="text-[11px] font-medium uppercase tracking-[0.08em] text-muted">
                Risk bands
              </span>
              {[...bandOrder].reverse().map((band) => (
                <span
                  key={band}
                  className="inline-flex items-center gap-1.5 text-xs text-muted"
                >
                  <span
                    className="h-2 w-2 rounded-full"
                    style={{ backgroundColor: BAND_COLOR[band] }}
                    aria-hidden
                  />
                  {bandStyles[band].label}
                </span>
              ))}
              <span className="ml-auto text-[11px] text-muted">
                Hubs = /24 subnets · edges = membership (not traffic)
              </span>
            </div>
          </>
        )}
      </Panel>

      <AssetDrawer
        asset={selected}
        onClose={() => setSelectedId(null)}
        onUpdated={refresh}
      />
    </div>
  );
}
