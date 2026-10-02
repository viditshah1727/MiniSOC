import request from 'supertest';
import { beforeEach, describe, expect, it } from 'vitest';
import { prisma } from '../src/db.js';
import { ingestEvent } from '../src/services/eventService.js';
import { buildApp, connection, loginAs, minutesAgo, resetDatabase, sshFailure, sshSuccess } from './helpers.js';

const app = buildApp();

beforeEach(async () => {
  await resetDatabase();
});

const validEvent = {
  timestamp: '2026-09-01T10:00:00Z',
  source: 'sshd',
  eventType: 'AUTH_FAILURE',
  severity: 'LOW',
  sourceIp: '203.0.113.45',
  destinationIp: '10.0.1.10',
  destinationPort: 22,
  hostname: 'web-01',
  username: 'root',
  message: 'Failed password for root from 203.0.113.45 port 51514 ssh2',
  metadata: { service: 'ssh', pid: 4121 },
};

describe('POST /api/events', () => {
  it('stores a valid event and returns it with the alerts it raised', async () => {
    const agent = await loginAs(app, 'ANALYST');
    const res = await agent.post('/api/events').send(validEvent).expect(201);

    expect(res.body.success).toBe(true);
    expect(res.body.data.event).toMatchObject({
      id: expect.any(Number),
      eventType: 'AUTH_FAILURE',
      sourceIp: '203.0.113.45',
      metadata: { service: 'ssh', pid: 4121 },
    });
    expect(res.body.data.alerts).toEqual([]); // a single failure is not an attack
    expect(await prisma.event.count()).toBe(1);
  });

  it('defaults the timestamp to now and severity to INFO', async () => {
    const agent = await loginAs(app, 'ANALYST');
    const { timestamp: _timestamp, severity: _severity, ...minimal } = validEvent;
    const before = Date.now();
    const res = await agent.post('/api/events').send(minimal).expect(201);

    expect(res.body.data.event.severity).toBe('INFO');
    expect(new Date(res.body.data.event.timestamp).getTime()).toBeGreaterThanOrEqual(before - 1000);
  });

  it('returns the alert when the event completes an attack pattern', async () => {
    for (let i = 0; i < 4; i++) {
      await ingestEvent(sshFailure('203.0.113.45', 'root', minutesAgo(4 - i)));
    }
    const agent = await loginAs(app, 'ANALYST');
    const fifth = { ...validEvent, timestamp: minutesAgo(0).toISOString() };
    const res = await agent.post('/api/events').send(fifth).expect(201);

    expect(res.body.data.alerts).toHaveLength(1);
    expect(res.body.data.alerts[0]).toMatchObject({ severity: 'HIGH', rule: { code: 'R001' } });
  });

  it('requires authentication', async () => {
    await request(app).post('/api/events').send(validEvent).expect(401);
  });

  it('does not let a VIEWER ingest events', async () => {
    const agent = await loginAs(app, 'VIEWER');
    const res = await agent.post('/api/events').send(validEvent).expect(403);
    expect(res.body).toEqual({ success: false, message: 'You do not have permission to perform this action' });
  });

  it.each([
    ['an invalid IP address', { sourceIp: '999.1.1.1' }, 'sourceIp'],
    ['an unknown event type', { eventType: 'TELEPORT' }, 'eventType'],
    ['an out-of-range port', { destinationPort: 70000 }, 'destinationPort'],
    ['a future timestamp', { timestamp: '2999-01-01T00:00:00Z' }, 'timestamp'],
    ['a malformed SHA-256', { metadata: { sha256: 'abc123' } }, 'metadata.sha256'],
    ['a missing message', { message: undefined }, 'message'],
  ])('rejects %s', async (_case, override, field) => {
    const agent = await loginAs(app, 'ANALYST');
    const res = await agent
      .post('/api/events')
      .send({ ...validEvent, ...override })
      .expect(400);

    expect(res.body.message).toBe('Validation failed');
    expect(res.body.errors.map((e: { field: string }) => e.field)).toContain(field);
    expect(await prisma.event.count()).toBe(0);
  });
});

describe('GET /api/events', () => {
  beforeEach(async () => {
    await ingestEvent(sshFailure('203.0.113.45', 'root', minutesAgo(30)));
    await ingestEvent(sshSuccess('10.10.4.21', 'jsmith', minutesAgo(20)));
    await ingestEvent(connection('198.51.100.23', 443, minutesAgo(10), { severity: 'MEDIUM' }));
  });

  it('lists events newest first with pagination info', async () => {
    const agent = await loginAs(app, 'VIEWER');
    const res = await agent.get('/api/events?pageSize=2').expect(200);

    expect(res.body.data).toHaveLength(2);
    expect(res.body.data[0].eventType).toBe('NETWORK_CONNECTION');
    expect(res.body.pagination).toEqual({ page: 1, pageSize: 2, total: 3, totalPages: 2 });
  });

  it.each([
    ['severity', 'severity=MEDIUM', ['NETWORK_CONNECTION']],
    ['event type', 'eventType=AUTH_SUCCESS', ['AUTH_SUCCESS']],
    ['source IP', 'sourceIp=203.0.113.45', ['AUTH_FAILURE']],
    ['free text', 'q=JSMITH', ['AUTH_SUCCESS']],
    ['date range', `from=${minutesAgo(25).toISOString()}&to=${minutesAgo(15).toISOString()}`, ['AUTH_SUCCESS']],
  ])('filters by %s', async (_name, queryString, expectedTypes) => {
    const agent = await loginAs(app, 'VIEWER');
    const res = await agent.get(`/api/events?${queryString}`).expect(200);
    expect(res.body.data.map((e: { eventType: string }) => e.eventType)).toEqual(expectedTypes);
  });

  it('rejects invalid filters instead of ignoring them', async () => {
    const agent = await loginAs(app, 'VIEWER');
    await agent.get('/api/events?severity=EXTREME').expect(400);
    await agent.get('/api/events?pageSize=5000').expect(400);
  });
});

describe('GET /api/events/:id', () => {
  it('returns the event with the alerts it is evidence for', async () => {
    const failures = [];
    for (let i = 0; i < 5; i++) {
      failures.push((await ingestEvent(sshFailure('203.0.113.45', 'root', minutesAgo(5 - i)))).event);
    }
    const agent = await loginAs(app, 'VIEWER');
    const res = await agent.get(`/api/events/${failures[0]!.id}`).expect(200);

    expect(res.body.data.id).toBe(failures[0]!.id);
    expect(res.body.data.alerts).toHaveLength(1);
    expect(res.body.data.alerts[0]).toMatchObject({ rule: { code: 'R001' }, severity: 'HIGH' });
  });

  it('returns 404 for an unknown event and 400 for a malformed id', async () => {
    const agent = await loginAs(app, 'VIEWER');
    const missing = await agent.get('/api/events/999999').expect(404);
    expect(missing.body).toEqual({ success: false, message: 'Event not found' });
    await agent.get('/api/events/abc').expect(400);
  });
});
