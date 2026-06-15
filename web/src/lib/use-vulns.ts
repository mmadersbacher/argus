"use client";

import { useCallback } from "react";
import { fetchVulns, type VulnRow } from "@/lib/api";
import { usePolledResource } from "@/lib/use-polled-resource";

export interface VulnFeed {
  /** null until the first successful load — the view shows the loading or
   *  full-page error state only in that window. */
  vulns: VulnRow[] | null;
  error: string | null;
  loading: boolean;
  reload: () => Promise<void>;
}

/** CVE rollup from argus-api, polled every 30s. Derived server-side from the
 *  inventory, so a slower cadence than the 15s inventory poll is enough. */
export function useVulns(): VulnFeed {
  const { data, error, loading, reload } = usePolledResource(
    useCallback(() => fetchVulns(), []),
    { intervalMs: 30000 },
  );
  return { vulns: data, error, loading, reload };
}
