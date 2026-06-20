"use client";

import { useCallback } from "react";
import {
  getAssets,
  getSummary,
  type ScoredAsset,
  type Summary,
} from "@/lib/api";
import { usePolledResource } from "@/lib/use-polled-resource";

export interface Inventory {
  summary: Summary | null;
  assets: ScoredAsset[];
  error: string | null;
  loading: boolean;
  reload: () => Promise<void>;
}

/** Inventory (summary + assets) from argus-api, polled every 15s. Shared by
 *  the Overview and Assets views so both stay in lockstep with one fetch path. */
export function useInventory(): Inventory {
  const { data, error, loading, reload } = usePolledResource(
    useCallback(
      (signal: AbortSignal) =>
        Promise.all([getSummary(signal), getAssets(signal)]).then(
          ([summary, assets]) => ({ summary, assets }),
        ),
      [],
    ),
    { intervalMs: 15000 },
  );
  return {
    summary: data?.summary ?? null,
    assets: data?.assets ?? [],
    error,
    loading,
    reload,
  };
}
