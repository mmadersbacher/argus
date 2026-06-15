"use client";

import { useCallback, useEffect, useRef, useState } from "react";

export interface PolledResource<T> {
  /** null until the first successful load. */
  data: T | null;
  error: string | null;
  loading: boolean;
  reload: () => Promise<void>;
}

interface Options {
  /** Poll interval in ms; omit for a one-shot resource that reloads only on
   *  `fetcher` change or an explicit `reload()`. */
  intervalMs?: number;
  /** Skip ticks while the tab is hidden and refetch on re-show. Default true. */
  pauseWhenHidden?: boolean;
}

/** The single data-fetching primitive behind every feed hook, so the polling
 *  contract lives in one place instead of being copied five times:
 *
 *  - stale-while-revalidate: once data has loaded it is never discarded; a
 *    failed poll keeps the last good data and `error` only surfaces while
 *    nothing has loaded yet;
 *  - overlap guard: out-of-order responses are dropped (only the newest
 *    in-flight request may update state), so a slow poll resolving late cannot
 *    paint stale data over a newer result;
 *  - pause-when-hidden: no polling against a backgrounded tab; refetch on
 *    re-show so the view is current the moment it is looked at again;
 *  - re-runs whenever `fetcher` identity changes — wrap it in `useCallback`
 *    keyed on its inputs (e.g. `[days]`).
 */
export function usePolledResource<T>(
  fetcher: () => Promise<T>,
  { intervalMs, pauseWhenHidden = true }: Options = {},
): PolledResource<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const mounted = useRef(true);
  const hasData = useRef(false);
  const seq = useRef(0);

  const reload = useCallback(async () => {
    const ticket = ++seq.current;
    try {
      const next = await fetcher();
      // Drop if unmounted or superseded by a newer in-flight request.
      if (!mounted.current || ticket !== seq.current) return;
      hasData.current = true;
      setData(next);
      setError(null);
    } catch (e) {
      if (!mounted.current || ticket !== seq.current) return;
      // Silent once data has loaded — keep the last good data on screen
      // instead of swapping it for a full-page error on a transient blip.
      if (!hasData.current) {
        setError(e instanceof Error ? e.message : "Failed to reach argus-api");
      }
    } finally {
      if (mounted.current && ticket === seq.current) setLoading(false);
    }
  }, [fetcher]);

  useEffect(() => {
    mounted.current = true;
    // False positive: reload() is async data fetching — every setState in it
    // happens after an await, never synchronously in the effect body.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void reload();

    let id: ReturnType<typeof setInterval> | undefined;
    if (intervalMs) {
      id = setInterval(() => {
        if (pauseWhenHidden && typeof document !== "undefined" && document.hidden) {
          return;
        }
        void reload();
      }, intervalMs);
    }

    const onVisible =
      pauseWhenHidden && intervalMs
        ? () => {
            if (!document.hidden) void reload();
          }
        : undefined;
    if (onVisible) document.addEventListener("visibilitychange", onVisible);

    return () => {
      mounted.current = false;
      if (id) clearInterval(id);
      if (onVisible) document.removeEventListener("visibilitychange", onVisible);
    };
  }, [reload, intervalMs, pauseWhenHidden]);

  return { data, error, loading, reload };
}
