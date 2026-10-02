// MITRE ATT&CK, threat intelligence and detection-rule management endpoints.
import { beforeEach, describe, expect, it } from 'vitest';
import { prisma } from '../src/db.js';
import { ingestEvent } from '../src/services/eventService.js';
import { addIndicator, buildApp, loginAs, minutesAgo, resetDatabase, sshFailure } from './helpers.js';

const app = buildApp();

beforeEach(async () => {
  await resetDatabase();
});

async function bruteForce(ip = '203.0.113.45', attempts = 5) {
  const alerts = [];
  for (let i = 0; i < attempts; i++) alerts.push(...(await ingestEvent(sshFailure(ip, 'deploy', minutesAgo(5 - i)))).alerts);
  return alerts;
}

describe('GET /api/mitre/techniques', () => {
  it('lists the local ATT&CK subset in kill-chain order with rules and alert counts', async () => {
    await bruteForce();
    const agent = await loginAs(app, 'VIEWER');
    const { body } = await agent.get('/api/mitre/techniques').expect(200);

    expect(body.data).toHaveLength(15);
    expect(body.data[0].tactics[0]).toBe('Reconnaissance');
    const bruteForceTechnique = body.data.find((t: { id: string }) => t.id === 'T1110');
    expect(bruteForceTechnique).toMatchObject({ name: 'Brute Force', alertCount: 1, openAlertCount: 1 });
    expect(bruteForceTechnique.rules.map((r: { code: string }) => r.code)).toEqual(['R001', 'R005']);
    // Techniques no rule detects are visible coverage gaps.
    expect(body.data.find((t: { id: string }) => t.id === 'T1190').rules).toEqual([]);
  });
});

describe('threat intelligence API', () => {
  it('creates indicators, normalising them to lowercase', async () => {
    const agent = await loginAs(app, 'ANALYST');
    const res = await agent
      .post('/api/threat-intelligence')
      .send({ type: 'DOMAIN', indicator: 'Bad-Site.Example', reputation: 'MALICIOUS', confidence: 90, source: 'analyst' })
      .expect(201);
    expect(res.body.data).toMatchObject({ indicator: 'bad-site.example', type: 'DOMAIN' });
    expect(new Date(res.body.data.firstSeen).getTime()).toBeLessThanOrEqual(new Date(res.body.data.lastSeen).getTime());
  });

  it.each([
    ['IP', 'not-an-ip'],
    ['DOMAIN', 'no spaces allowed.example'],
    ['HASH', 'd41d8cd98f00b204e9800998ecf8427e'], // MD5: only SHA-256 is accepted
  ])('rejects a malformed %s indicator', async (type, indicator) => {
    const agent = await loginAs(app, 'ANALYST');
    const res = await agent
      .post('/api/threat-intelligence')
      .send({ type, indicator, reputation: 'MALICIOUS', confidence: 90, source: 'analyst' })
      .expect(400);
    expect(res.body.errors[0].field).toBe('indicator');
  });

  it('rejects duplicates, bad confidence values and viewers', async () => {
    await addIndicator({ indicator: '203.0.113.45', type: 'IP' });
    const analyst = await loginAs(app, 'ANALYST');
    const body = { type: 'IP', indicator: '203.0.113.45', reputation: 'MALICIOUS', confidence: 90, source: 'analyst' };

    await analyst.post('/api/threat-intelligence').send(body).expect(409);
    await analyst.post('/api/threat-intelligence').send({ ...body, indicator: '203.0.113.46', confidence: 150 }).expect(400);
    const viewer = await loginAs(app, 'VIEWER');
    await viewer.post('/api/threat-intelligence').send({ ...body, indicator: '203.0.113.47' }).expect(403);
  });

  it('lists indicators with filters and the number of alerts each one enriched', async () => {
    await addIndicator({ indicator: '203.0.113.45', type: 'IP', confidence: 95 });
    await addIndicator({ indicator: 'bad.example', type: 'DOMAIN', reputation: 'SUSPICIOUS', confidence: 50 });
    await bruteForce('203.0.113.45');

    const agent = await loginAs(app, 'VIEWER');
    const ips = await agent.get('/api/threat-intelligence?type=IP').expect(200);
    expect(ips.body.data).toEqual([expect.objectContaining({ indicator: '203.0.113.45', alertCount: 1 })]);
    const suspicious = await agent.get('/api/threat-intelligence?reputation=SUSPICIOUS').expect(200);
    expect(suspicious.body.data.map((i: { indicator: string }) => i.indicator)).toEqual(['bad.example']);
    const search = await agent.get('/api/threat-intelligence?q=bad').expect(200);
    expect(search.body.pagination.total).toBe(1);
  });
});

describe('detection rule management', () => {
  it('lists rules with their tunable settings', async () => {
    const agent = await loginAs(app, 'VIEWER');
    const { body } = await agent.get('/api/rules').expect(200);
    expect(body.data.map((r: { code: string }) => r.code)).toEqual(['R001', 'R002', 'R003', 'R004', 'R005', 'R006']);
    const r004 = body.data.find((r: { code: string }) => r.code === 'R004');
    expect(r004.tunable).toEqual({ threshold: false, windowMinutes: false });
    expect(body.data[0]).toMatchObject({ threshold: 5, windowMinutes: 5, thresholdLabel: 'failed logins' });
  });

  it('lets an admin disable a rule, which stops it from firing', async () => {
    const admin = await loginAs(app, 'ADMIN');
    const rule = await prisma.detectionRule.findUniqueOrThrow({ where: { code: 'R001' } });
    await admin.patch(`/api/rules/${rule.id}`).send({ enabled: false }).expect(200);

    expect(await bruteForce()).toEqual([]);
  });

  it('lets an admin tune a threshold, and rejects settings a rule does not use', async () => {
    const admin = await loginAs(app, 'ADMIN');
    const r001 = await prisma.detectionRule.findUniqueOrThrow({ where: { code: 'R001' } });
    const r004 = await prisma.detectionRule.findUniqueOrThrow({ where: { code: 'R004' } });

    const tuned = await admin.patch(`/api/rules/${r001.id}`).send({ threshold: 3 }).expect(200);
    expect(tuned.body.data.threshold).toBe(3);
    expect(await bruteForce('203.0.113.9', 3)).toHaveLength(1);

    const invalid = await admin.patch(`/api/rules/${r004.id}`).send({ threshold: 2 }).expect(400);
    expect(invalid.body.message).toBe('R004 does not use a threshold');
  });

  it('does not let analysts change rules', async () => {
    const analyst = await loginAs(app, 'ANALYST');
    const rule = await prisma.detectionRule.findUniqueOrThrow({ where: { code: 'R001' } });
    await analyst.patch(`/api/rules/${rule.id}`).send({ enabled: false }).expect(403);
  });
});
