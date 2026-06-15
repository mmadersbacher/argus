"use client";

import { useCallback } from "react";
import { fetchEvents, type ArgusEvent } from "@/lib/api";
import { usePolledResource } from "@/lib/use-polled-resource";

export interface EventFeed {
  events: ArgusEvent[];
  error: string | null;
  loading: boolean;
  reload: () => Promise<void>;
}

/** Change-event feed from argus-api, polled every 15s — same rhythm as the
 *  inventory so the dashboard updates in lockstep. */
export function useEvents(limit = 50): EventFeed {
  const { data, error, loading, reload } = usePolledResource(
    useCallback(() => fetchEvents(limit), [limit]),
    { intervalMs: 15000 },
  );
  return { events: data ?? [], error, loading, reload };
}
