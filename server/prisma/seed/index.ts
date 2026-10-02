// `npm run db:seed`: resets the database to a realistic 7-day demo dataset.
//
// Every event is pushed through the REAL detection engine, so all alerts were
// genuinely raised by the rules; none are hand-made. Then a week of analyst
// work is replayed (triage, false positives, incidents, notes).
//
// WARNING: this deletes all existing MiniSOC data in the configured database.
import { config } from '../../src/config.js';
import { prisma } from '../../src/db.js';
import { syncDetectionContent } from '../../src/detection/sync.js';
import { hashPassword } from '../../src/services/authService.js';
import { ingestEvent } from '../../src/services/eventService.js';
import { seededRng } from '../../src/simulation/random.js';
import { threatIntelSeed } from './threatIntel.js';
import { buildTimeline } from './timeline.js';
import { alignTimestamps, replayAnalystWork, type Team } from './workflow.js';

const DEMO_USERS = [
  { key: 'alex', email: 'admin@minisoc.local', name: 'Alex Morgan', role: 'ADMIN' },
  { key: 'jordan', email: 'analyst@minisoc.local', name: 'Jordan Lee', role: 'ANALYST' },
  { key: 'sam', email: 'sam.rivera@minisoc.local', name: 'Sam Rivera', role: 'ANALYST' },
  { key: 'taylor', email: 'viewer@minisoc.local', name: 'Taylor Kim', role: 'VIEWER' },
] as const;

async function main() {
  if (config.isProduction) throw new Error('Refusing to load demo data into a production database.');
  const password = process.env.SEED_DEMO_PASSWORD;
  if (!password || password.length < 8) {
    throw new Error('Set SEED_DEMO_PASSWORD (at least 8 characters) in server/.env');
  }

  const startedAt = Date.now();
  const now = new Date();

  console.log('Resetting MiniSOC data...');
  await prisma.$executeRaw`
    TRUNCATE TABLE events, alerts, incidents, activities, threat_intelligence, users, "_AlertEvidence"
    RESTART IDENTITY CASCADE`;
  await syncDetectionContent();

  const passwordHash = await hashPassword(password);
  const team: Partial<Team> = {};
  for (const { key, ...user } of DEMO_USERS) {
    const created = await prisma.user.create({ data: { ...user, passwordHash } });
    if (key !== 'taylor') team[key] = { id: created.id, email: created.email, name: created.name, role: created.role };
  }

  await prisma.threatIntelligence.createMany({ data: threatIntelSeed(now) });

  const events = buildTimeline(now, seededRng(2026));
  console.log(`Ingesting ${events.length} events through the detection engine...`);
  let alertCount = 0;
  for (const [index, event] of events.entries()) {
    alertCount += (await ingestEvent(event)).alerts.length;
    if ((index + 1) % 250 === 0) console.log(`  ${index + 1}/${events.length} events, ${alertCount} alerts so far`);
  }

  console.log('Replaying analyst work (triage, incidents, notes)...');
  await replayAnalystWork(team as Team, now);
  await alignTimestamps();

  const byRule = await prisma.alert.groupBy({ by: ['ruleId'], _count: { _all: true } });
  const rules = await prisma.detectionRule.findMany({ orderBy: { code: 'asc' } });
  const [incidents, indicators] = await Promise.all([prisma.incident.count(), prisma.threatIntelligence.count()]);

  console.log(`\nDone in ${((Date.now() - startedAt) / 1000).toFixed(1)}s`);
  console.log(`  ${events.length} events -> ${alertCount} alerts -> ${incidents} incidents, ${indicators} threat-intel indicators`);
  for (const rule of rules) {
    const count = byRule.find((row) => row.ruleId === rule.id)?._count._all ?? 0;
    console.log(`  ${rule.code} ${rule.name.padEnd(42)} ${count} alert(s)`);
  }
  console.log('\nDemo accounts (password = SEED_DEMO_PASSWORD from server/.env):');
  for (const user of DEMO_USERS) console.log(`  ${user.role.padEnd(8)} ${user.email}`);
}

main()
  .catch((error) => {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  })
  .finally(() => prisma.$disconnect());
