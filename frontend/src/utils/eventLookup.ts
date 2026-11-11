import { MutableRefObject } from 'react';
import { api } from '../api/client';
import { AnalysisEvent } from '../types';

export interface BoundedEventLookupOptions {
  analysisId: string;
  targetEventId: string;
  mountedRef: MutableRefObject<boolean>;
  epochRef: MutableRefObject<number>;
  clickSeqRef: MutableRefObject<number>;
  cacheRef: MutableRefObject<AnalysisEvent[]>;
  nextPageRef: MutableRefObject<number>;
  exhaustedRef: MutableRefObject<boolean>;
  maxPagesPerClick?: number;
  pageSize?: number;
  onStart?: () => void;
  onEventsMerged?: (events: AnalysisEvent[]) => void;
  onComplete?: (found: boolean) => void;
  onError?: (message: string) => void;
  onFinally?: () => void;
}

/**
 * Shared generation- and epoch-fenced bounded /events pagination helper.
 * Prevents stale analysisId responses, concurrent click races, and unmounted state updates.
 */
export async function runBoundedEventLookup({
  analysisId,
  targetEventId,
  mountedRef,
  epochRef,
  clickSeqRef,
  cacheRef,
  nextPageRef,
  exhaustedRef,
  maxPagesPerClick = 5,
  pageSize = 200,
  onStart,
  onEventsMerged,
  onComplete,
  onError,
  onFinally,
}: BoundedEventLookupOptions): Promise<void> {
  const myEpoch = epochRef.current;
  const myClick = ++clickSeqRef.current;

  const isSameAnalysis = () => mountedRef.current && epochRef.current === myEpoch;
  const isLatestIntent = () => isSameAnalysis() && clickSeqRef.current === myClick;

  if (cacheRef.current.some((e) => e.id === targetEventId)) {
    if (isLatestIntent()) {
      onComplete?.(true);
      onFinally?.();
    }
    return;
  }

  if (exhaustedRef.current) {
    if (isLatestIntent()) {
      onComplete?.(false);
      onFinally?.();
    }
    return;
  }

  if (isLatestIntent()) {
    onStart?.();
  }

  try {
    let pageCursor = nextPageRef.current;
    let fetched = 0;

    while (!exhaustedRef.current && fetched < maxPagesPerClick) {
      if (!isSameAnalysis()) {
        return;
      }

      const page = pageCursor;
      const res = await api.getEvents(analysisId, { page, page_size: pageSize });
      if (!isSameAnalysis()) {
        return;
      }

      fetched += 1;
      pageCursor = page + 1;
      nextPageRef.current = Math.max(nextPageRef.current, pageCursor);

      const seen = new Set(cacheRef.current.map((e) => e.id));
      const merged = [...cacheRef.current];
      for (const item of res.items) {
        if (!seen.has(item.id)) {
          seen.add(item.id);
          merged.push(item);
        }
      }

      cacheRef.current = merged;
      onEventsMerged?.(merged);

      if (res.items.length === 0 || merged.length >= res.total) {
        exhaustedRef.current = true;
      }

      const foundInMerged = merged.some((e) => e.id === targetEventId);
      if (foundInMerged) {
        break;
      }
      if (!isLatestIntent()) {
        // Newer click within same analysis supersedes this search cleanly without leaking requests.
        return;
      }
    }

    if (isLatestIntent()) {
      const found = cacheRef.current.some((e) => e.id === targetEventId);
      onComplete?.(found);
    }
  } catch (err) {
    if (isLatestIntent()) {
      onError?.(
        err instanceof Error ? err.message : 'Unable to fetch telemetry events from backend.'
      );
    }
  } finally {
    if (isLatestIntent()) {
      onFinally?.();
    }
  }
}
