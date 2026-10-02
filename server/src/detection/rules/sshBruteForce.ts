// R001: many failed SSH logins from one IP in a short window = password guessing.
import { prisma } from '../../db.js';
import { MAX_EVIDENCE_EVENTS, minutesBefore } from '../constants.js';
import { distinct } from '../helpers.js';
import type { DetectionRuleDefinition } from '../types.js';

const SSH_LOG_SOURCE = 'sshd';
const DEFAULT_THRESHOLD = 5; // failed attempts
const DEFAULT_WINDOW_MINUTES = 5;

export const sshBruteForce: DetectionRuleDefinition = {
  code: 'R001',
  name: 'SSH Brute Force',
  description: `${DEFAULT_THRESHOLD} or more failed SSH logins from the same source IP within ${DEFAULT_WINDOW_MINUTES} minutes.`,
  severity: 'HIGH',
  mitreTechniqueIds: ['T1110'],
  defaults: { threshold: DEFAULT_THRESHOLD, windowMinutes: DEFAULT_WINDOW_MINUTES },
  thresholdLabel: 'failed logins',
  eventTypes: ['AUTH_FAILURE'],
  recommendedSteps: [
    'Check how many attempts were made and over what time span.',
    'Look at the targeted accounts: one account hammered, or many accounts sprayed?',
    'Search for a successful login from the same IP after the failures (possible compromise, see R005).',
    'Check the source IP against threat intelligence.',
    'If the attack is ongoing, block the IP at the firewall (or fail2ban) and record the action.',
  ],

  async evaluate(event, settings) {
    if (event.source !== SSH_LOG_SOURCE || !event.sourceIp) return null;
    const threshold = settings.threshold ?? DEFAULT_THRESHOLD;
    const windowMinutes = settings.windowMinutes ?? DEFAULT_WINDOW_MINUTES;

    const where = {
      eventType: 'AUTH_FAILURE' as const,
      source: SSH_LOG_SOURCE,
      sourceIp: event.sourceIp,
      timestamp: { gte: minutesBefore(event.timestamp, windowMinutes), lte: event.timestamp },
    };
    const failedAttempts = await prisma.event.count({ where });
    if (failedAttempts < threshold) return null;

    const failures = await prisma.event.findMany({
      where,
      select: { id: true, username: true },
      orderBy: { timestamp: 'asc' },
      take: MAX_EVIDENCE_EVENTS,
    });
    const targetedAccounts = distinct(failures.map((failure) => failure.username));

    return {
      title: `SSH brute force from ${event.sourceIp}`,
      description:
        `${failedAttempts} failed SSH logins from ${event.sourceIp} within ${windowMinutes} minutes ` +
        `(threshold: ${threshold}) against ${event.hostname ?? 'the target host'}, ` +
        `trying ${targetedAccounts.length} account(s): ${targetedAccounts.join(', ') || 'unknown'}.`,
      dedupKey: `ip:${event.sourceIp}`,
      evidenceEventIds: failures.map((failure) => failure.id),
      evidence: { failedAttempts, threshold, windowMinutes, targetedAccounts },
    };
  },
};
