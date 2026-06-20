"use client";

import { useCallback } from "react";
import { fetchPolicy, type Advisory } from "@/lib/api";
import { usePolledResource } from "@/lib/use-polled-resource";

export interface PolicyFeed {
  /** null until the first successful load. */
  advisories: Advisory[] | null;
  error: string | null;
  loading: boolean;
}

/** Segmentation advisories from argus-api, polled every 30s — they derive from
 *  the inventory server-side, same cadence as the CVE rollup. */
export function usePolicy(): PolicyFeed {
  const { data, error, loading } = usePolledResource(
    useCallback((signal: AbortSignal) => fetchPolicy(signal), []),
    { intervalMs: 30000 },
  );
  return { advisories: data, error, loading };
}
