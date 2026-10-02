// R002: one source touching many different ports quickly = mapping exposed services.
import { prisma } from '../../db.js';
import { MAX_EVIDENCE_EVENTS, minutesBefore } from '../constants.js';
import { distinct } from '../helpers.js';
import type { DetectionRuleDefinition } from '../types.js';

const DEFAULT_THRESHOLD = 10; // distinct destination ports
const DEFAULT_WINDOW_MINUTES = 3;

export const portScan: DetectionRuleDefinition = {
  code: 'R002',
  name: 'Network Port Scan',
  description: `One source IP connects to ${DEFAULT_THRESHOLD} or more different destination ports within ${DEFAULT_WINDOW_MINUTES} minutes.`,
  severity: 'HIGH',
  mitreTechniqueIds: ['T1046', 'T1595'],
  defaults: { threshold: DEFAULT_THRESHOLD, windowMinutes: DEFAULT_WINDOW_MINUTES },
  thresholdLabel: 'distinct ports',
  eventTypes: ['NETWORK_CONNECTION'],
  recommendedSteps: [
    'Identify which ports and services were probed and which of them are actually exposed.',
    'Check whether the scan was followed by login attempts or exploitation of an open service.',
    'Confirm whether the source is an authorised scanner (e.g. vulnerability management); threat intel may say so.',
    'Check the source IP against threat intelligence and block it if it is malicious.',
  ],

  async evaluate(event, settings) {
    if (!event.sourceIp || event.destinationPort === null) return null;
    const threshold = settings.threshold ?? DEFAULT_THRESHOLD;
    const windowMinutes = settings.windowMinutes ?? DEFAULT_WINDOW_MINUTES;

    const where = {
      eventType: 'NETWORK_CONNECTION' as const,
      sourceIp: event.sourceIp,
      destinationPort: { not: null },
      timestamp: { gte: minutesBefore(event.timestamp, windowMinutes), lte: event.timestamp },
    };
    // One row per distinct port (a SQL GROUP BY), so a busy source stays cheap to check.
    const portRows = await prisma.event.groupBy({ by: ['destinationPort'], where });
    if (portRows.length < threshold) return null;

    const probes = await prisma.event.findMany({
      where,
      select: { id: true, destinationIp: true },
      orderBy: { timestamp: 'asc' },
      take: MAX_EVIDENCE_EVENTS,
    });
    const portsProbed = portRows
      .map((row) => row.destinationPort)
      .filter((port): port is number => port !== null)
      .sort((a, b) => a - b);
    const targets = distinct(probes.map((probe) => probe.destinationIp));

    return {
      title: `Port scan from ${event.sourceIp}`,
      description:
        `${event.sourceIp} connected to ${portsProbed.length} different ports within ${windowMinutes} minutes ` +
        `(threshold: ${threshold}) on ${targets.join(', ') || 'internal hosts'}: it is mapping which services are exposed.`,
      dedupKey: `ip:${event.sourceIp}`,
      evidenceEventIds: probes.map((probe) => probe.id),
      evidence: { distinctPorts: portsProbed.length, threshold, windowMinutes, portsProbed, targets },
    };
  },
};
