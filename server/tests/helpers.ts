// Shared helpers for the API test suite.
import type { Express } from 'express';
import request from 'supertest';
import { createApp } from '../src/app.js';
import { prisma } from '../src/db.js';
import { DETECTION_RULES } from '../src/detection/rules/index.js';
import { syncDetectionContent } from '../src/detection/sync.js';
import type { Role } from '../src/generated/prisma/enums.js';
import type { ValidEventInput } from '../src/schemas/events.js';
import { hashPassword } from '../src/services/authService.js';

export const TEST_PASSWORD = 'correct-horse-battery-staple';

export const TEST_USERS: Record<Role, { email: string; name: string }> = {
  ADMIN: { email: 'admin@test.local', name: 'Test Admin' },
  ANALYST: { email: 'analyst@test.local', name: 'Test Analyst' },
  VIEWER: { email: 'viewer@test.local', name: 'Test Viewer' },
};

let passwordHash: string | undefined; // bcrypt is slow on purpose: hash once per run

// Everything a test can create. Reference data (rules, MITRE techniques) stays.
const DATA_TABLES = ['events', 'alerts', 'incidents', 'activities', 'threat_intelligence', 'users', '_AlertEvidence'];
let referenceDataSynced = false;

/**
 * Gives every test a clean slate: empties the data tables, makes sure the
 * detection rules + MITRE techniques exist with default settings, and creates
 * the three test users.
 */
export async function resetDatabase(): Promise<void> {
  const tableList = DATA_TABLES.map((table) => `"${table}"`).join(', ');
  await prisma.$executeRawUnsafe(`TRUNCATE TABLE ${tableList} RESTART IDENTITY CASCADE`);

  if (!referenceDataSynced) {
    await syncDetectionContent();
    referenceDataSynced = true;
  }
  for (const rule of DETECTION_RULES) {
    // Undo any tuning a previous test did.
    await prisma.detectionRule.update({
      where: { code: rule.code },
      data: { enabled: true, threshold: rule.defaults.threshold, windowMinutes: rule.defaults.windowMinutes },
    });
  }

  passwordHash ??= await hashPassword(TEST_PASSWORD);
  for (const [role, user] of Object.entries(TEST_USERS)) {
    await prisma.user.create({ data: { ...user, role: role as Role, passwordHash } });
  }
}

// ─── Event builders: concise, realistic test telemetry ──────────────────────

/** A time `minutes` before a fixed reference point (tests stay deterministic). */
export const REFERENCE_TIME = new Date('2026-09-01T12:00:00Z');
export function minutesAgo(minutes: number, from: Date = REFERENCE_TIME): Date {
  return new Date(from.getTime() - minutes * 60_000);
}

type EventOverrides = Partial<ValidEventInput>;

export function sshFailure(sourceIp: string, username: string, timestamp: Date, extra: EventOverrides = {}) {
  return event({
    source: 'sshd',
    eventType: 'AUTH_FAILURE',
    severity: 'LOW',
    sourceIp,
    username,
    hostname: 'web-01',
    destinationPort: 22,
    message: `Failed password for ${username} from ${sourceIp} port 51514 ssh2`,
    timestamp,
    ...extra,
  });
}

export function sshSuccess(sourceIp: string, username: string, timestamp: Date, extra: EventOverrides = {}) {
  return event({
    source: 'sshd',
    eventType: 'AUTH_SUCCESS',
    sourceIp,
    username,
    hostname: 'web-01',
    destinationPort: 22,
    message: `Accepted password for ${username} from ${sourceIp} port 51514 ssh2`,
    timestamp,
    ...extra,
  });
}

export function connection(sourceIp: string, destinationPort: number, timestamp: Date, extra: EventOverrides = {}) {
  return event({
    source: 'firewall',
    eventType: 'NETWORK_CONNECTION',
    sourceIp,
    destinationIp: '10.0.1.10',
    destinationPort,
    hostname: 'web-01',
    message: `TCP SYN ${sourceIp} -> 10.0.1.10:${destinationPort}`,
    timestamp,
    ...extra,
  });
}

export function command(username: string, commandLine: string, timestamp: Date, extra: EventOverrides = {}) {
  return event({
    source: 'auditd',
    eventType: 'PROCESS_EXECUTION',
    username,
    hostname: 'web-01',
    message: `${username} executed: ${commandLine}`,
    metadata: { command: commandLine },
    timestamp,
    ...extra,
  });
}

function event(input: EventOverrides & Pick<ValidEventInput, 'source' | 'eventType' | 'message'>): ValidEventInput {
  return { severity: 'INFO', ...input };
}

/** Creates a threat-intel indicator for a test. */
export function addIndicator(data: {
  indicator: string;
  type: 'IP' | 'DOMAIN' | 'HASH';
  reputation?: 'MALICIOUS' | 'SUSPICIOUS' | 'BENIGN';
  confidence?: number;
}) {
  return prisma.threatIntelligence.create({
    data: {
      reputation: 'MALICIOUS',
      confidence: 90,
      source: 'test-feed',
      firstSeen: minutesAgo(60 * 24 * 30),
      lastSeen: minutesAgo(60),
      ...data,
    },
  });
}

export function buildApp(): Express {
  return createApp();
}

/** A supertest agent that is logged in (it keeps the session cookie). */
export async function loginAs(app: Express, role: Role) {
  const agent = request.agent(app);
  await agent.post('/api/auth/login').send({ email: TEST_USERS[role].email, password: TEST_PASSWORD }).expect(200);
  return agent;
}
