import { useCallback, useEffect, useState } from 'react';
import { ApiError } from '../api/client';

interface ApiState<T> {
  data: T | undefined;
  error: ApiError | undefined;
  loading: boolean;
}

/**
 * Loads data from the API, and loads it again whenever `deps` change or
 * `reload()` is called. While reloading, the previous data is kept so pages
 * can hold their layout (dimmed) instead of flashing a spinner.
 * An in-flight request is cancelled when a newer one starts.
 */
export function useApi<T>(fetcher: (signal: AbortSignal) => Promise<T>, deps: readonly unknown[]) {
  const [state, setState] = useState<ApiState<T>>({ data: undefined, error: undefined, loading: true });
  const [reloadCount, setReloadCount] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setState((previous) => ({ ...previous, loading: true }));

    fetcher(controller.signal).then(
      (data) => {
        if (!controller.signal.aborted) setState({ data, error: undefined, loading: false });
      },
      (error: unknown) => {
        if (controller.signal.aborted) return;
        const apiError = error instanceof ApiError ? error : new ApiError(0, 'Something went wrong');
        setState((previous) => ({ data: previous.data, error: apiError, loading: false }));
      },
    );
    return () => controller.abort();
    // The caller's deps decide when to refetch; `fetcher` is a new closure every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, reloadCount]);

  const reload = useCallback(() => setReloadCount((count) => count + 1), []);
  /** Replace the data directly, e.g. with the updated record a PATCH returned. */
  const setData = useCallback((data: T) => setState({ data, error: undefined, loading: false }), []);

  return { ...state, reload, setData };
}
