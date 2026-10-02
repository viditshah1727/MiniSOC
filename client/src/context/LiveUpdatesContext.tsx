// One Server-Sent Events connection for the whole app (GET /api/stream).
// Pages subscribe to it to refresh themselves when alerts or incidents change.
// EventSource reconnects on its own if the connection drops.
import { createContext, type ReactNode, useCallback, useContext, useEffect, useRef, useState } from 'react';
import type { LiveUpdate } from '../types/api';

type Listener = (update: LiveUpdate) => void;

interface LiveUpdatesValue {
  connected: boolean;
  subscribe: (listener: Listener) => () => void;
}

const LiveUpdatesContext = createContext<LiveUpdatesValue | null>(null);

export function LiveUpdatesProvider({ children }: { children: ReactNode }) {
  const listeners = useRef(new Set<Listener>());
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    const source = new EventSource('/api/stream');
    source.onopen = () => setConnected(true);
    source.onerror = () => setConnected(false);
    source.onmessage = (message: MessageEvent<string>) => {
      const update = JSON.parse(message.data) as LiveUpdate;
      listeners.current.forEach((listener) => listener(update));
    };
    return () => source.close();
  }, []);

  const subscribe = useCallback((listener: Listener) => {
    listeners.current.add(listener);
    return () => {
      listeners.current.delete(listener);
    };
  }, []);

  return <LiveUpdatesContext.Provider value={{ connected, subscribe }}>{children}</LiveUpdatesContext.Provider>;
}

export function useLiveConnection(): boolean {
  return useContext(LiveUpdatesContext)?.connected ?? false;
}

/** Calls `onUpdate` for every live update, always with the latest callback. */
export function useLiveUpdates(onUpdate: Listener): void {
  const context = useContext(LiveUpdatesContext);
  const callback = useRef(onUpdate);
  useEffect(() => {
    callback.current = onUpdate;
  });

  useEffect(() => context?.subscribe((update) => callback.current(update)), [context]);
}

/**
 * Re-runs `reload` shortly after a relevant update arrives. Bursts (e.g. a
 * simulated attack emitting 30 events) are coalesced into a single reload.
 */
export function useLiveRefresh(reload: () => void, types: LiveUpdate['type'][], delayMs = 1000): void {
  const pending = useRef<number | undefined>(undefined);
  const watched = types.join(',');

  useLiveUpdates((update) => {
    if (!watched.split(',').includes(update.type) || pending.current !== undefined) return;
    pending.current = window.setTimeout(() => {
      pending.current = undefined;
      reload();
    }, delayMs);
  });

  useEffect(() => () => window.clearTimeout(pending.current), []);
}
