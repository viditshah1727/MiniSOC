// Realistic API payloads for component tests.
import type { AlertDetail, AlertListItem, DashboardStats, SecurityEvent } from '../types/api';

export function makeEvent(overrides: Partial<SecurityEvent> = {}): SecurityEvent {
  return {
    id: 1,
    timestamp: '2026-09-22T10:00:00.000Z',
    source: 'sshd',
    eventType: 'AUTH_FAILURE',
    severity: 'LOW',
    sourceIp: '203.0.113.45',
    destinationIp: '10.0.1.10',
    destinationPort: 22,
    hostname: 'web-01',
    username: 'root',
    message: 'Failed password for root from 203.0.113.45 port 51514 ssh2',
    metadata: { service: 'ssh' },
    createdAt: '2026-09-22T10:00:00.000Z',
    ...overrides,
  };
}

export const alertListItem: AlertListItem = {
  id: 21,
  title: 'Successful login after brute force: jsmith from 203.0.113.45',
  severity: 'CRITICAL',
  status: 'OPEN',
  riskScore: 100,
  riskLevel: 'CRITICAL',
  sourceIp: '203.0.113.45',
  hostname: 'bastion-01',
  username: 'jsmith',
  detectedAt: '2026-09-22T10:05:00.000Z',
  incidentId: null,
  rule: { code: 'R005', name: 'Brute Force Followed by Successful Login' },
  mitreTechnique: { id: 'T1110', name: 'Brute Force' },
  threatIntel: { reputation: 'MALICIOUS' },
};

const failures = [0, 1, 2].map((i) =>
  makeEvent({ id: i + 1, timestamp: `2026-09-22T10:0${i}:00.000Z`, username: i % 2 ? 'admin' : 'root' }),
);
const success = makeEvent({
  id: 4,
  timestamp: '2026-09-22T10:05:00.000Z',
  eventType: 'AUTH_SUCCESS',
  severity: 'INFO',
  username: 'jsmith',
  message: 'Accepted password for jsmith from 203.0.113.45 port 51514 ssh2',
});

export const alertDetail: AlertDetail = {
  ...alertListItem,
  description:
    '203.0.113.45 logged in as "jsmith" on bastion-01 after 3 failed attempts in the previous 10 minutes (threshold: 3).',
  riskFactors: [
    { label: 'Base score for CRITICAL severity', points: 90 },
    { label: 'Known malicious indicator: 203.0.113.45', points: 10 },
  ],
  evidence: { compromisedAccount: 'jsmith', failedAttemptsBefore: 3, accountsTried: ['root', 'admin'] },
  updatedAt: '2026-09-22T10:05:00.000Z',
  rule: {
    id: 5,
    code: 'R005',
    name: 'Brute Force Followed by Successful Login',
    description: 'A successful login from a source IP that failed to log in 3 or more times in the previous 10 minutes.',
    severity: 'CRITICAL',
    threshold: 3,
    windowMinutes: 10,
    recommendedSteps: ['Treat the account as compromised until proven otherwise.', 'Disable the account or force a password reset.'],
    techniques: [
      { id: 'T1110', name: 'Brute Force', tactics: ['Credential Access'] },
      { id: 'T1078', name: 'Valid Accounts', tactics: ['Initial Access'] },
    ],
  },
  mitreTechnique: { id: 'T1110', name: 'Brute Force', tactics: ['Credential Access'], description: 'Guessing passwords repeatedly.' },
  threatIntel: {
    id: 1,
    indicator: '203.0.113.45',
    type: 'IP',
    reputation: 'MALICIOUS',
    confidence: 95,
    source: 'internal-honeypot',
    description: 'SSH brute-force botnet node',
    firstSeen: '2026-08-01T00:00:00.000Z',
    lastSeen: '2026-09-22T08:00:00.000Z',
    createdAt: '2026-08-01T00:00:00.000Z',
  },
  event: success,
  evidenceEvents: [...failures, success],
  incident: null,
  activities: [
    { id: 1, type: 'CREATED', message: 'Raised by R005 (risk 100/100)', createdAt: '2026-09-22T10:05:00.000Z', user: null },
  ],
  relatedAlerts: [],
};

export function makeDashboard(overrides: Partial<DashboardStats> = {}): DashboardStats {
  return {
    range: '24h',
    since: '2026-09-21T11:00:00.000Z',
    kpis: {
      totalEvents: 1013,
      eventsInRange: 151,
      totalAlerts: 22,
      openAlerts: 9,
      criticalOpenAlerts: 3,
      openIncidents: 2,
      overallRisk: { score: 79, level: 'HIGH' },
    },
    eventsOverTime: Array.from({ length: 24 }, (_, i) => ({
      bucket: new Date(Date.UTC(2026, 8, 21, 11 + i)).toISOString(),
      events: i * 2,
      alerts: i % 6 === 0 ? 1 : 0,
    })),
    alertsBySeverity: [
      { severity: 'CRITICAL', count: 3 },
      { severity: 'HIGH', count: 4 },
      { severity: 'MEDIUM', count: 1 },
      { severity: 'LOW', count: 0 },
    ],
    topSourceIps: [{ ip: '203.0.113.45', alerts: 4, events: 11, reputation: 'MALICIOUS' }],
    detectionsByRule: [
      { code: 'R001', name: 'SSH Brute Force', count: 2 },
      { code: 'R005', name: 'Brute Force Followed by Successful Login', count: 1 },
    ],
    recentCriticalAlerts: [alertListItem],
    recentEvents: [makeEvent()],
    activeIncidents: [],
    ...overrides,
  };
}
