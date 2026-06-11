"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { fetchVulns, type VulnRow } from "@/lib/api";

export interface VulnFeed {
  /** null until the first successful load — the view shows the loading or
   *  full-page error state only in that window. */
  vulns: VulnRow[] | null;
  error: string | null;
  loading: boolean;
  reload: () => Promise<void>;
}

/** Loads the CVE rollup from argus-api and polls it every 30s. The rollup is
 *  derived server-side from the inventory, so a slower cadence than the
 *  15s inventory poll is enough.
 *
 *  Poll-failure policy: once data has arrived it is never discarded — a failed
 *  poll keeps the last good rows and stays silent (the next tick retries).
 *  `error` is only set while `vulns` is still null, i.e. before any data
 *  ever loaded. */
export function useVulns(): VulnFeed {
  const [vulns, setVulns] = useState<VulnRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const mounted = useRef(true);
  const hasData = useRef(false);

  const reload = useCallback(async () => {
    try {
      const v = await fetchVulns();
      if (!mounted.current) return;
      hasData.current = true;
      setVulns(v);
      setError(null);
    } catch (e) {
      // Silent after the first successful load — keep the stale rows on screen
      // instead of swapping a full page for an error banner on a transient blip.
      if (mounted.current && !hasData.current) {
        setError(e instanceof Error ? e.message : "Failed to reach argus-api");
      }
    } finally {
      if (mounted.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    mounted.current = true;
    // False positive: reload() is async data fetching — every setState in it
    // happens after an await, never synchronously in the effect body.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void reload();
    const id = setInterval(() => void reload(), 30000);
    return () => {
      mounted.current = false;
      clearInterval(id);
    };
  }, [reload]);

  return { vulns, error, loading, reload };
}
