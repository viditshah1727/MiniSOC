// Display formatting. Times are shown in the analyst's local time zone;
// hovering a timestamp shows the exact UTC value (see <Time>).

const dateTimeFormat = new Intl.DateTimeFormat(undefined, {
  day: '2-digit',
  month: 'short',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hour12: false,
});
const dateFormat = new Intl.DateTimeFormat(undefined, { day: '2-digit', month: 'short', year: 'numeric' });
const shortTimeFormat = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', hour12: false });
const shortDayFormat = new Intl.DateTimeFormat(undefined, { weekday: 'short', hour: '2-digit', minute: '2-digit', hour12: false });
const relativeFormat = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });
const numberFormat = new Intl.NumberFormat();
const compactFormat = new Intl.NumberFormat(undefined, { notation: 'compact', maximumFractionDigits: 1 });

export const formatDateTime = (iso: string) => dateTimeFormat.format(new Date(iso));
export const formatDate = (iso: string) => dateFormat.format(new Date(iso));
export const formatNumber = (value: number) => numberFormat.format(value);
export const formatCompact = (value: number) => compactFormat.format(value);

/** Axis label for a chart bucket: "14:00" for hourly buckets, "Tue 06:00" for multi-day ranges. */
export function formatBucket(iso: string, range: '24h' | '7d'): string {
  return range === '24h' ? shortTimeFormat.format(new Date(iso)) : shortDayFormat.format(new Date(iso));
}

const RELATIVE_STEPS: [Intl.RelativeTimeFormatUnit, number][] = [
  ['day', 86_400],
  ['hour', 3_600],
  ['minute', 60],
];

/** "just now", "5 minutes ago", "yesterday", "3 days ago" */
export function timeAgo(iso: string, now: number = Date.now()): string {
  const seconds = Math.round((new Date(iso).getTime() - now) / 1000);
  for (const [unit, size] of RELATIVE_STEPS) {
    if (Math.abs(seconds) >= size) return relativeFormat.format(Math.round(seconds / size), unit);
  }
  return 'just now';
}

/** 5 -> "5 min", 90 -> "1 h 30 min", 43200 -> "30 days" */
export function formatMinutes(minutes: number): string {
  if (minutes % 1440 === 0) return `${minutes / 1440} day${minutes === 1440 ? '' : 's'}`;
  if (minutes < 60) return `${minutes} min`;
  const hours = Math.floor(minutes / 60);
  const rest = minutes % 60;
  return rest ? `${hours} h ${rest} min` : `${hours} h`;
}

/** "failedAttempts" -> "Failed attempts" (for evidence keys written by the rules). */
export function humanizeKey(key: string): string {
  const words = key.replace(/([a-z0-9])([A-Z])/g, '$1 $2').toLowerCase();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

/** Human-readable reference numbers, as analysts say them out loud. */
export const alertRef = (id: number) => `ALR-${id}`;
export const incidentRef = (id: number) => `INC-${id}`;
export const eventRef = (id: number) => `EVT-${id}`;
