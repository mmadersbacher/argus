"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { getAssets, getSummary, type ScoredAsset, type Summary } from "@/lib/api";

export interface Inventory {
  summary: Summary | null;
  assets: ScoredAsset[];
  error: string | null;
  loading: boolean;
  reload: () => Promise<void>;
}

/** Loads the inventory from argus-api and polls it every 15s. Shared by the
 *  Overview and Assets views so both stay in lockstep with one fetch path. */
export function useInventory(): Inventory {
  const [summary, setSummary] = useState<Summary | null>(null);
  const [assets, setAssets] = useState<ScoredAsset[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const mounted = useRef(true);

  const reload = useCallback(async () => {
    try {
      const [s, a] = await Promise.all([getSummary(), getAssets()]);
      if (!mounted.current) return;
      setSummary(s);
      setAssets(a);
      setError(null);
    } catch (e) {
      if (mounted.current) {
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
    const id = setInterval(() => void reload(), 15000);
    return () => {
      mounted.current = false;
      clearInterval(id);
    };
  }, [reload]);

  return { summary, assets, error, loading, reload };
}
