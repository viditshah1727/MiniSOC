import request from 'supertest';
import { beforeEach, describe, expect, it } from 'vitest';
import { prisma } from '../src/db.js';
import { ingestEvent } from '../src/services/eventService.js';
import { buildApp, command, connection, loginAs, minutesAgo, resetDatabase, sshFailure } from './helpers.js';

const app = buildApp();
const recent = (minutes: number) => minutesAgo(minutes, new Date()); // the dashboard looks back from "now"

beforeEach(async () => {
  await resetDatabase();
  // HIGH R001 from one IP, CRITICAL R004, plus an old event outside the 24 h range.
  for (let i = 0; i < 5; i++) await ingestEvent(sshFailure('203.0.113.45', 'deploy', recent(60 - i)));
  await ingestEvent(command('jsmith', 'sudo su -', recent(30)));
  await ingestEvent(connection('198.51.100.23', 443, recent(3 * 24 * 60)));
});

describe('GET /api/dashboard/stats', () => {
  it('returns KPIs that match the database', async () => {
    const agent = await loginAs(app, 'VIEWER');
    const { body } = await agent.get('/api/dashboard/stats').expect(200);
    const { kpis } = body.data;

    expect(kpis).toMatchObject({
      totalEvents: 7,
      eventsInRange: 6,
      totalAlerts: 2,
      openAlerts: 2,
      criticalOpenAlerts: 1,
      openIncidents: 0,
    });
    // Overall risk = average risk of open alerts: (HIGH 70 + CRITICAL 90) / 2
    expect(kpis.overallRisk).toEqual({ score: 80, level: 'HIGH' });
  });

  it('buckets events and alerts over time with no gaps', async () => {
    const agent = await loginAs(app, 'VIEWER');
    const day = (await agent.get('/api/dashboard/stats?range=24h').expect(200)).body.data;
    const week = (await agent.get('/api/dashboard/stats?range=7d').expect(200)).body.data;

    expect(day.eventsOverTime).toHaveLength(24);
    expect(week.eventsOverTime).toHaveLength(28);
    const sum = (series: { events: number; alerts: number }[], key: 'events' | 'alerts') =>
      series.reduce((total, bucket) => total + bucket[key], 0);
    expect(sum(day.eventsOverTime, 'events')).toBe(6);
    expect(sum(day.eventsOverTime, 'alerts')).toBe(2);
    expect(sum(week.eventsOverTime, 'events')).toBe(7);
  });

  it('breaks alerts down by severity, rule and source IP', async () => {
    const agent = await loginAs(app, 'VIEWER');
    const { body } = await agent.get('/api/dashboard/stats').expect(200);
    const data = body.data;

    expect(data.alertsBySeverity).toEqual([
      { severity: 'CRITICAL', count: 1 },
      { severity: 'HIGH', count: 1 },
      { severity: 'MEDIUM', count: 0 },
      { severity: 'LOW', count: 0 },
    ]);
    expect(data.detectionsByRule).toHaveLength(6);
    expect(data.detectionsByRule.find((r: { code: string }) => r.code === 'R001').count).toBe(1);
    expect(data.topSourceIps).toEqual([{ ip: '203.0.113.45', alerts: 1, events: 5, reputation: null }]);
  });

  it('lists recent high-priority alerts, recent events and active incidents', async () => {
    const agent = await loginAs(app, 'ANALYST');
    const r004 = await prisma.alert.findFirstOrThrow({ where: { rule: { code: 'R004' } } });
    await agent.post('/api/incidents').send({ alertIds: [r004.id] }).expect(201);

    const { body } = await agent.get('/api/dashboard/stats').expect(200);
    expect(body.data.recentCriticalAlerts.map((a: { severity: string }) => a.severity)).toEqual(['CRITICAL', 'HIGH']);
    expect(body.data.recentEvents).toHaveLength(7);
    expect(body.data.activeIncidents).toHaveLength(1);
    expect(body.data.kpis.openIncidents).toBe(1);
  });

  it('validates the range and requires a login', async () => {
    const agent = await loginAs(app, 'VIEWER');
    await agent.get('/api/dashboard/stats?range=1y').expect(400);
    await request(app).get('/api/dashboard/stats').expect(401);
  });
});
