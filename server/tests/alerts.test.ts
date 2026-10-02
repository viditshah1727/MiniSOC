import request from 'supertest';
import { beforeEach, describe, expect, it } from 'vitest';
import { prisma } from '../src/db.js';
import { ingestEvent } from '../src/services/eventService.js';
import { buildApp, connection, loginAs, minutesAgo, resetDatabase, sshFailure, sshSuccess } from './helpers.js';

const app = buildApp();
const ATTACKER = '203.0.113.45';
const SCANNER = '198.51.100.77';

/** R001 (HIGH) + R005 (CRITICAL) from ATTACKER, then R002 (HIGH) from SCANNER. */
async function seedAlerts() {
  for (let i = 0; i < 5; i++) await ingestEvent(sshFailure(ATTACKER, 'deploy', minutesAgo(30 - i * 0.5)));
  await ingestEvent(sshSuccess(ATTACKER, 'deploy', minutesAgo(27)));
  for (let port = 20; port < 30; port++) await ingestEvent(connection(SCANNER, port, minutesAgo(10 - (port - 20) * 0.1)));

  const byRule = async (code: string) => prisma.alert.findFirstOrThrow({ where: { rule: { code } } });
  return { bruteForce: await byRule('R001'), compromise: await byRule('R005'), scan: await byRule('R002') };
}

let alerts: Awaited<ReturnType<typeof seedAlerts>>;

beforeEach(async () => {
  await resetDatabase();
  alerts = await seedAlerts();
});

describe('GET /api/alerts', () => {
  it('lists alerts newest first with risk level, rule and MITRE technique', async () => {
    const agent = await loginAs(app, 'VIEWER');
    const res = await agent.get('/api/alerts').expect(200);

    expect(res.body.pagination.total).toBe(3);
    expect(res.body.data.map((a: { rule: { code: string } }) => a.rule.code)).toEqual(['R002', 'R005', 'R001']);
    expect(res.body.data[1]).toMatchObject({
      severity: 'CRITICAL',
      status: 'OPEN',
      riskScore: 100, // CRITICAL 90 + repeated activity 10
      riskLevel: 'CRITICAL',
      mitreTechnique: { id: 'T1110', name: 'Brute Force' },
    });
  });

  it('sorts by risk when asked', async () => {
    const agent = await loginAs(app, 'VIEWER');
    const res = await agent.get('/api/alerts?sort=risk').expect(200);
    const scores = res.body.data.map((a: { riskScore: number }) => a.riskScore);
    expect(scores).toEqual([...scores].sort((a, b) => b - a));
  });

  it.each([
    ['severity=CRITICAL', ['R005']],
    ['ruleCode=R002', ['R002']],
    ['mitreTechniqueId=T1046', ['R002']],
    [`sourceIp=${ATTACKER}`, ['R005', 'R001']],
    ['q=port%20scan', ['R002']],
    ['status=RESOLVED', []],
  ])('filters with %s', async (queryString, expectedRules) => {
    const agent = await loginAs(app, 'VIEWER');
    const res = await agent.get(`/api/alerts?${queryString}`).expect(200);
    expect(res.body.data.map((a: { rule: { code: string } }) => a.rule.code)).toEqual(expectedRules);
  });

  it('requires authentication', async () => {
    await request(app).get('/api/alerts').expect(401);
  });
});

describe('GET /api/alerts/:id', () => {
  it('returns everything needed to explain the alert', async () => {
    const agent = await loginAs(app, 'VIEWER');
    const { body } = await agent.get(`/api/alerts/${alerts.bruteForce.id}`).expect(200);
    const alert = body.data;

    // Why it fired
    expect(alert.description).toContain('5 failed SSH logins');
    expect(alert.evidence).toMatchObject({ failedAttempts: 5, threshold: 5, windowMinutes: 5 });
    expect(alert.evidenceEvents).toHaveLength(5);
    expect(alert.event.id).toBe(alert.evidenceEvents[4].id); // the 5th failure completed the pattern
    // How it was scored
    expect(alert.riskFactors).toEqual([{ label: 'Base score for HIGH severity', points: 70 }]);
    expect(alert.riskLevel).toBe('HIGH');
    // Rule, playbook and ATT&CK context
    expect(alert.rule).toMatchObject({ code: 'R001', threshold: 5, windowMinutes: 5 });
    expect(alert.rule.recommendedSteps.length).toBeGreaterThan(2);
    expect(alert.mitreTechnique).toMatchObject({ id: 'T1110', tactics: ['Credential Access'] });
    // Timeline + pivots
    expect(alert.activities.map((a: { type: string }) => a.type)).toEqual(['CREATED']);
    expect(alert.relatedAlerts.map((a: { id: number }) => a.id)).toEqual([alerts.compromise.id]);
    expect(alert.threatIntel).toBeNull();
    expect(alert.incident).toBeNull();
  });

  it('returns 404 for an unknown alert', async () => {
    const agent = await loginAs(app, 'VIEWER');
    const res = await agent.get('/api/alerts/424242').expect(404);
    expect(res.body).toEqual({ success: false, message: 'Alert not found' });
  });
});

describe('PATCH /api/alerts/:id', () => {
  it('lets an analyst start investigating, recording who did it', async () => {
    const agent = await loginAs(app, 'ANALYST');
    const { body } = await agent.patch(`/api/alerts/${alerts.scan.id}`).send({ status: 'INVESTIGATING' }).expect(200);

    expect(body.data.status).toBe('INVESTIGATING');
    const change = body.data.activities.at(-1);
    expect(change).toMatchObject({
      type: 'STATUS_CHANGE',
      message: 'Status changed from OPEN to INVESTIGATING',
      user: { name: 'Test Analyst' },
    });
  });

  it('marks a false positive with a justification note', async () => {
    const agent = await loginAs(app, 'ANALYST');
    const { body } = await agent
      .patch(`/api/alerts/${alerts.scan.id}`)
      .send({ status: 'FALSE_POSITIVE', note: 'Authorised vulnerability scan (change CHG-1042).' })
      .expect(200);

    expect(body.data.status).toBe('FALSE_POSITIVE');
    expect(body.data.activities.slice(-2).map((a: { type: string }) => a.type)).toEqual(['STATUS_CHANGE', 'NOTE']);
  });

  it('accepts a note on its own', async () => {
    const agent = await loginAs(app, 'ADMIN');
    const { body } = await agent.patch(`/api/alerts/${alerts.scan.id}`).send({ note: 'Checked firewall logs.' }).expect(200);
    expect(body.data.status).toBe('OPEN');
    expect(body.data.activities.at(-1)).toMatchObject({ type: 'NOTE', message: 'Checked firewall logs.' });
  });

  it('rejects no-op and invalid updates', async () => {
    const agent = await loginAs(app, 'ANALYST');
    const same = await agent.patch(`/api/alerts/${alerts.scan.id}`).send({ status: 'OPEN' }).expect(400);
    expect(same.body.message).toBe('Alert is already OPEN');
    await agent.patch(`/api/alerts/${alerts.scan.id}`).send({ status: 'DELETED' }).expect(400);
    await agent.patch(`/api/alerts/${alerts.scan.id}`).send({}).expect(400);
    await agent.patch('/api/alerts/424242').send({ status: 'RESOLVED' }).expect(404);
  });

  it('does not let a VIEWER change alerts', async () => {
    const agent = await loginAs(app, 'VIEWER');
    await agent.patch(`/api/alerts/${alerts.scan.id}`).send({ status: 'RESOLVED' }).expect(403);
    const unchanged = await prisma.alert.findUniqueOrThrow({ where: { id: alerts.scan.id } });
    expect(unchanged.status).toBe('OPEN');
  });
});
