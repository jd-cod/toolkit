'use client';

import { useCallback, useEffect, useRef, useState } from 'react';

interface RequestState<T> {
  loading: boolean;
  error: string;
  result: T | null;
}

/** Loading, error and result state for a tool that calls the backend. Only the latest request may set the result. */
export function useToolRequest<T>() {
  const [state, setState] = useState<RequestState<T>>({ loading: false, error: '', result: null });
  const latest = useRef(0);

  const run = useCallback(async (request: () => Promise<T>) => {
    const id = ++latest.current;
    setState({ loading: true, error: '', result: null });
    try {
      const result = await request();
      if (id === latest.current) setState({ loading: false, error: '', result });
    } catch (err: unknown) {
      if (id === latest.current) setState({ loading: false, error: err instanceof Error ? err.message : 'The request failed.', result: null });
    }
  }, []);

  const reset = useCallback(() => {
    latest.current += 1;
    setState({ loading: false, error: '', result: null });
  }, []);

  return { ...state, run, reset };
}

/**
 * Calls `onValue` once after mount with the value of a query-string parameter,
 * so a tool can be linked with its input filled in (for example /blacklist?target=192.0.2.1).
 */
export function useQueryPrefill(name: string, onValue: (value: string) => void) {
  const applied = useRef(false);
  const handler = useRef(onValue);
  useEffect(() => { handler.current = onValue; });

  useEffect(() => {
    if (applied.current) return;
    const value = new URLSearchParams(window.location.search).get(name);
    if (!value) return;
    const timer = window.setTimeout(() => {
      applied.current = true;
      handler.current(value);
    }, 0);
    return () => window.clearTimeout(timer);
  }, [name]);
}
