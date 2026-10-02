// R005: failed logins followed by a successful one from the same IP.
// The attacker probably guessed the password, so the account is compromised.
import { prisma } from '../../db.js';
import { MAX_EVIDENCE_EVENTS, minutesBefore } from '../constants.js';
import { distinct } from '../helpers.js';
import type { DetectionRuleDefinition } from '../types.js';

const DEFAULT_THRESHOLD = 3; // failed attempts before the success
const DEFAULT_WINDOW_MINUTES = 10;

export const bruteForceSuccess: DetectionRuleDefinition = {
  code: 'R005',
  name: 'Brute Force Followed by Successful Login',
  description: `A successful login from a source IP that failed to log in ${DEFAULT_THRESHOLD} or more times in the previous ${DEFAULT_WINDOW_MINUTES} minutes.`,
  severity: 'CRITICAL',
  mitreTechniqueIds: ['T1110', 'T1078'],
  defaults: { threshold: DEFAULT_THRESHOLD, windowMinutes: DEFAULT_WINDOW_MINUTES },
  thresholdLabel: 'failed logins before the success',
  eventTypes: ['AUTH_SUCCESS'],
  recommendedSteps: [
    'Treat the account as compromised until proven otherwise.',
    'Disable the account or force a password reset, and end its active sessions.',
    'Review everything the session did after logging in: commands, sudo usage, file changes.',
    'Block the source IP and look for the same IP in other alerts.',
    'Escalate to an incident and consider isolating the affected host.',
  ],

  async evaluate(event, settings) {
    if (!event.sourceIp) return null;
    const threshold = settings.threshold ?? DEFAULT_THRESHOLD;
    const windowMinutes = settings.windowMinutes ?? DEFAULT_WINDOW_MINUTES;

    const where = {
      eventType: 'AUTH_FAILURE' as const,
      sourceIp: event.sourceIp,
      timestamp: { gte: minutesBefore(event.timestamp, windowMinutes), lt: event.timestamp },
    };
    const failedAttempts = await prisma.event.count({ where });
    if (failedAttempts < threshold) return null;

    const failures = await prisma.event.findMany({
      where,
      select: { id: true, username: true },
      orderBy: { timestamp: 'asc' },
      take: MAX_EVIDENCE_EVENTS,
    });
    const account = event.username ?? 'unknown';

    return {
      title: `Successful login after brute force: ${account} from ${event.sourceIp}`,
      description:
        `${event.sourceIp} logged in as "${account}" on ${event.hostname ?? 'unknown host'} after ` +
        `${failedAttempts} failed attempts in the previous ${windowMinutes} minutes (threshold: ${threshold}). ` +
        'The password was probably guessed: treat the account as compromised.',
      dedupKey: `ip:${event.sourceIp}|user:${account}`,
      evidenceEventIds: failures.map((failure) => failure.id),
      evidence: {
        compromisedAccount: account,
        failedAttemptsBefore: failedAttempts,
        threshold,
        windowMinutes,
        accountsTried: distinct(failures.map((failure) => failure.username)),
      },
    };
  },
};
