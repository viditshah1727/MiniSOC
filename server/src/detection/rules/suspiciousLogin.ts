// R003: a successful login from a source IP that is unusual for the account.
//
// "Unusual" means either:
//   1. the account has an established login history (a baseline) and has never
//      logged in from this IP during the look-back period, or
//   2. the IP has a bad reputation in threat intelligence.
import { prisma } from '../../db.js';
import { findIpIndicator } from '../../services/threatIntelService.js';
import { minutesBefore } from '../constants.js';
import { distinct } from '../helpers.js';
import type { DetectionRuleDefinition } from '../types.js';

const DEFAULT_MIN_BASELINE_LOGINS = 3; // "threshold": logins needed before an IP can be "new"
const DEFAULT_BASELINE_MINUTES = 30 * 24 * 60; // "window": 30 days of history

export const suspiciousLogin: DetectionRuleDefinition = {
  code: 'R003',
  name: 'Suspicious Login',
  description:
    'Successful login from a source IP the account has not used in the last 30 days (given at least 3 earlier logins), or from an IP with a bad threat-intel reputation.',
  severity: 'MEDIUM',
  mitreTechniqueIds: ['T1078', 'T1133'],
  defaults: { threshold: DEFAULT_MIN_BASELINE_LOGINS, windowMinutes: DEFAULT_BASELINE_MINUTES },
  thresholdLabel: 'earlier logins needed for a baseline',
  eventTypes: ['AUTH_SUCCESS'],
  recommendedSteps: [
    'Ask the account owner whether they logged in at this time from this location.',
    "Compare the source IP with the account's usual sources listed in the evidence.",
    'Check the source IP against threat intelligence and geolocation.',
    'Review what the session did after logging in (commands, sudo usage, downloads).',
    'If the login was not legitimate: reset the password, end active sessions and escalate to an incident.',
  ],

  async evaluate(event, settings) {
    if (!event.sourceIp || !event.username) return null;
    const minBaselineLogins = settings.threshold ?? DEFAULT_MIN_BASELINE_LOGINS;
    const baselineMinutes = settings.windowMinutes ?? DEFAULT_BASELINE_MINUTES;
    const baselineDays = Math.round(baselineMinutes / (24 * 60));

    const history = {
      eventType: 'AUTH_SUCCESS' as const,
      username: event.username,
      timestamp: { gte: minutesBefore(event.timestamp, baselineMinutes), lt: event.timestamp },
    };
    const [priorLogins, priorLoginsFromThisIp, usualSourceRows, intel] = await Promise.all([
      prisma.event.count({ where: history }),
      prisma.event.count({ where: { ...history, sourceIp: event.sourceIp } }),
      prisma.event.groupBy({
        by: ['sourceIp'],
        where: history,
        _count: { _all: true },
        orderBy: { _count: { sourceIp: 'desc' } },
        take: 3,
      }),
      findIpIndicator(event.sourceIp),
    ]);

    const isNewSource = priorLogins >= minBaselineLogins && priorLoginsFromThisIp === 0;
    const hasBadReputation = intel !== null && intel.reputation !== 'BENIGN';
    if (!isNewSource && !hasBadReputation) return null;

    const usualSources = distinct(usualSourceRows.map((row) => row.sourceIp));
    const reasons: string[] = [];
    if (isNewSource) {
      reasons.push(
        `first login from ${event.sourceIp} in ${baselineDays} days (usual sources: ${usualSources.join(', ')})`,
      );
    }
    if (hasBadReputation) {
      reasons.push(
        `${event.sourceIp} is listed as ${intel.reputation} in threat intelligence (${intel.confidence}% confidence)`,
      );
    }

    return {
      title: `Suspicious login for ${event.username} from ${event.sourceIp}`,
      description: `Successful login for "${event.username}" on ${event.hostname ?? 'unknown host'}: ${reasons.join('; ')}.`,
      dedupKey: `user:${event.username}|ip:${event.sourceIp}`,
      evidenceEventIds: [],
      evidence: {
        account: event.username,
        reasons,
        priorLoginsForAccount: priorLogins,
        usualSources,
        baselineDays,
      },
      threatIntelId: hasBadReputation ? intel.id : undefined,
    };
  },
};
