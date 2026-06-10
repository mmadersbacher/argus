"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { fetchEvents, type ArgusEvent } from "@/lib/api";

export interface EventFeed {
  events: ArgusEvent[];
  error: string | null;
  loading: boolean;
  reload: () => Promise<void>;
}

/** Loads the change-event feed from argus-api and polls it every 15s — same
 *  rhythm as the inventory so the dashboard updates in lockstep. */
export function useEvents(limit = 50): EventFeed {
  const [events, setEvents] = useState<ArgusEvent[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const mounted = useRef(true);

  const reload = useCallback(async () => {
    try {
      const e = await fetchEvents(limit);
      if (!mounted.current) return;
      setEvents(e);
      setError(null);
    } catch (e) {
      if (mounted.current) {
        setError(e instanceof Error ? e.message : "Failed to reach argus-api");
      }
    } finally {
      if (mounted.current) setLoading(false);
    }
  }, [limit]);

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

  return { events, error, loading, reload };
}
