"use client";

import { useCallback } from "react";
import { fetchReport, type ExposureReport } from "@/lib/api";
import { usePolledResource } from "@/lib/use-polled-resource";

export interface ReportFeed {
  /** null until the first successful load. */
  report: ExposureReport | null;
  error: string | null;
  loading: boolean;
  regenerate: () => Promise<void>;
}

/** Exposure report for the given period. A report is a point-in-time document,
 *  so there is no polling — it reloads when `days` changes or when the caller
 *  regenerates explicitly. */
export function useReport(days: number): ReportFeed {
  const { data, error, loading, reload } = usePolledResource(
    useCallback(() => fetchReport(days), [days]),
  );
  return { report: data, error, loading, regenerate: reload };
}
