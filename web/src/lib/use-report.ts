"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { fetchReport, type ExposureReport } from "@/lib/api";

export interface ReportFeed {
  /** null until the first successful load. */
  report: ExposureReport | null;
  error: string | null;
  loading: boolean;
  regenerate: () => Promise<void>;
}

/** Loads the exposure report for the given period. A report is a
 *  point-in-time document, so there is no polling — it reloads when `days`
 *  changes or when the caller regenerates explicitly.
 *
 *  Failure policy mirrors the other feeds: once a report has arrived it is
 *  never discarded; `error` only surfaces while nothing has loaded yet. */
export function useReport(days: number): ReportFeed {
  const [report, setReport] = useState<ExposureReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const mounted = useRef(true);
  const hasData = useRef(false);

  const regenerate = useCallback(async () => {
    try {
      const r = await fetchReport(days);
      if (!mounted.current) return;
      hasData.current = true;
      setReport(r);
      setError(null);
    } catch (e) {
      if (mounted.current && !hasData.current) {
        setError(e instanceof Error ? e.message : "Failed to reach argus-api");
      }
    } finally {
      if (mounted.current) setLoading(false);
    }
  }, [days]);

  useEffect(() => {
    mounted.current = true;
    // False positive: regenerate() is async data fetching — every setState in
    // it happens after an await, never synchronously in the effect body.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void regenerate();
    return () => {
      mounted.current = false;
    };
  }, [regenerate]);

  return { report, error, loading, regenerate };
}
