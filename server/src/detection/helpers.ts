// Small helpers shared by the detection rules.
import type { Event } from '../generated/prisma/client.js';

/** Reads a string field from an event's JSON metadata (undefined if absent). */
export function readMetadataString(event: Pick<Event, 'metadata'>, key: string): string | undefined {
  const metadata = event.metadata;
  if (metadata && typeof metadata === 'object' && !Array.isArray(metadata)) {
    const value = metadata[key];
    return typeof value === 'string' ? value : undefined;
  }
  return undefined;
}

/** Distinct, non-empty values, in first-seen order. */
export function distinct<T>(values: (T | null | undefined)[]): T[] {
  return [...new Set(values.filter((value): value is T => value !== null && value !== undefined))];
}
