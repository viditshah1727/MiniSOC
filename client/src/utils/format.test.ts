import { describe, expect, it } from 'vitest';
import { alertRef, formatMinutes, humanizeKey, timeAgo } from './format';

describe('formatting helpers', () => {
  it('formats rule windows in the most natural unit', () => {
    expect(formatMinutes(5)).toBe('5 min');
    expect(formatMinutes(60)).toBe('1 h');
    expect(formatMinutes(90)).toBe('1 h 30 min');
    expect(formatMinutes(1440)).toBe('1 day');
    expect(formatMinutes(43200)).toBe('30 days');
  });

  it('turns camelCase evidence keys into readable labels', () => {
    expect(humanizeKey('failedAttemptsBefore')).toBe('Failed attempts before');
    expect(humanizeKey('usualSources')).toBe('Usual sources');
  });

  it('describes timestamps relative to now', () => {
    const now = Date.parse('2026-09-22T12:00:00Z');
    expect(timeAgo('2026-09-22T11:59:40Z', now)).toBe('just now');
    expect(timeAgo('2026-09-22T11:55:00Z', now)).toMatch(/5 minutes ago/);
    expect(timeAgo('2026-09-22T09:00:00Z', now)).toMatch(/3 hours ago/);
  });

  it('builds analyst-friendly references', () => {
    expect(alertRef(42)).toBe('ALR-42');
  });
});
