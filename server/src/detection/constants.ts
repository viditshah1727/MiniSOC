// Detection-wide settings, in one place so there are no magic numbers in the rules.

/** Accounts that are privileged by definition (compared case-insensitively). */
export const PRIVILEGED_ACCOUNTS = ['root', 'admin', 'administrator', 'sysadmin'];

export function isPrivilegedAccount(username: string | null | undefined): boolean {
  return Boolean(username && PRIVILEGED_ACCOUNTS.includes(username.toLowerCase()));
}

/** After a rule alerts on an entity, further matches on it are suppressed for this long. */
export const ALERT_SUPPRESSION_MINUTES = 60;

/** A source IP with another alert in this period counts as "repeated activity". */
export const REPEATED_ACTIVITY_HOURS = 24;

/** Evidence lists are capped so one noisy attack cannot bloat an alert. */
export const MAX_EVIDENCE_EVENTS = 50;

export const MINUTE_MS = 60 * 1000;

export function minutesBefore(date: Date, minutes: number): Date {
  return new Date(date.getTime() - minutes * MINUTE_MS);
}
