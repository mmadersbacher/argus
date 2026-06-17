"use client";

import { useCallback } from "react";
import { fetchGraph, type GraphData } from "@/lib/api";
import { usePolledResource } from "@/lib/use-polled-resource";

export interface GraphFeed {
  /** null until the first successful load. */
  graph: GraphData | null;
  error: string | null;
  loading: boolean;
  reload: () => Promise<void>;
}

/** Loads the asset topology graph from argus-api. Topology changes rarely, so
 *  there is no polling — it reloads on mount and on an explicit refresh. */
export function useGraph(): GraphFeed {
  const { data, error, loading, reload } = usePolledResource(
    useCallback(() => fetchGraph(), []),
  );
  return { graph: data, error, loading, reload };
}
