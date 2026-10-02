import type { Severity } from '../generated/prisma/enums.js';

/** Severities from least to most severe. */
export const SEVERITY_ORDER: Severity[] = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

export function highestSeverity(severities: Severity[]): Severity {
  return severities.reduce<Severity>(
    (highest, current) => (SEVERITY_ORDER.indexOf(current) > SEVERITY_ORDER.indexOf(highest) ? current : highest),
    'INFO',
  );
}
