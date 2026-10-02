// In-process publish/subscribe for real-time UI updates.
// Services publish small notifications; the /api/stream endpoint forwards
// them to every connected browser as Server-Sent Events.
// A plain EventEmitter is enough for one server process. Running several
// instances would need a shared channel (e.g. PostgreSQL LISTEN/NOTIFY).
import { EventEmitter } from 'node:events';
import type { AlertStatus, IncidentStatus, Severity } from '../generated/prisma/enums.js';

export type LiveUpdate =
  | { type: 'event.created'; id: number }
  | { type: 'alert.created'; id: number; title: string; severity: Severity; riskScore: number }
  | { type: 'alert.updated'; id: number; status: AlertStatus }
  | { type: 'incident.created'; id: number; title: string; severity: Severity }
  | { type: 'incident.updated'; id: number; status: IncidentStatus };

const channel = new EventEmitter();
channel.setMaxListeners(0); // one listener per open browser tab; no artificial cap

export function publishLiveUpdate(update: LiveUpdate): void {
  channel.emit('update', update);
}

/** Returns an unsubscribe function. */
export function subscribeToLiveUpdates(listener: (update: LiveUpdate) => void): () => void {
  channel.on('update', listener);
  return () => {
    channel.off('update', listener);
  };
}
