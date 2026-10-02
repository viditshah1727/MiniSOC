import { useCallback } from 'react';
import { useSearchParams } from 'react-router';

/**
 * List filters stored in the URL query string (?severity=HIGH&page=2), so a
 * filtered view can be bookmarked, shared, or linked to from another page.
 * Changing a filter always returns to page 1.
 */
export function useUrlFilters<Key extends string>(keys: readonly Key[]) {
  const [params, setParams] = useSearchParams();

  const filters = Object.fromEntries(keys.map((key) => [key, params.get(key) ?? ''])) as Record<Key, string>;
  const page = Math.max(1, Number(params.get('page')) || 1);

  const setFilter = useCallback(
    (key: Key, value: string) =>
      setParams(
        (previous) => {
          const next = new URLSearchParams(previous);
          if (value) next.set(key, value);
          else next.delete(key);
          next.delete('page');
          return next;
        },
        { replace: true },
      ),
    [setParams],
  );

  const setPage = useCallback(
    (nextPage: number) =>
      setParams((previous) => {
        const next = new URLSearchParams(previous);
        if (nextPage > 1) next.set('page', String(nextPage));
        else next.delete('page');
        return next;
      }),
    [setParams],
  );

  const clearFilters = useCallback(() => setParams({}, { replace: true }), [setParams]);
  const hasFilters = keys.some((key) => filters[key] !== '');

  return { filters, page, setFilter, setPage, clearFilters, hasFilters };
}
