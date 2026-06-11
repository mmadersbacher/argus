"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { fetchPolicy, type Advisory } from "@/lib/api";

export interface PolicyFeed {
  /** null until the first successful load. */
  advisories: Advisory[] | null;
  error: string | null;
  loading: boolean;
}

/** Loads the segmentation advisories and polls every 30s — they derive from
 *  the inventory server-side, same cadence as the CVE rollup.
 *
 *  Poll-failure policy mirrors the other feeds: data, once loaded, is never
 *  discarded; `error` only surfaces while nothing has loaded yet. */
export function usePolicy(): PolicyFeed {
  const [advisories, setAdvisories] = useState<Advisory[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const mounted = useRef(true);
  const hasData = useRef(false);

  const reload = useCallback(async () => {
    try {
      const a = await fetchPolicy();
      if (!mounted.current) return;
      hasData.current = true;
      setAdvisories(a);
      setError(null);
    } catch (e) {
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

  return { advisories, error, loading };
}
