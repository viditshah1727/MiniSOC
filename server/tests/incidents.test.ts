import { beforeEach, describe, expect, it } from 'vitest';
import { prisma } from '../src/db.js';
import { ingestEvent } from '../src/services/eventService.js';
import { buildApp, loginAs, minutesAgo, resetDatabase, sshFailure, sshSuccess, TEST_USERS } from './helpers.js';

const app = buildApp();
const ATTACKER = '203.0.113.45';

/** Brute force (R001, HIGH) followed by a successful login (R005, CRITICAL). */
async function seedCompromise() {
  for (let i = 0; i < 5; i++) await ingestEvent(sshFailure(ATTACKER, 'deploy', minutesAgo(30 - i * 0.5)));
  await ingestEvent(sshSuccess(ATTACKER, 'deploy', minutesAgo(27)));
  const bruteForce = await prisma.alert.findFirstOrThrow({ where: { rule: { code: 'R001' } } });
  const compromise = await prisma.alert.findFirstOrThrow({ where: { rule: { code: 'R005' } } });
  return { bruteForce, compromise };
}

async function userId(role: keyof typeof TEST_USERS) {
  return (await prisma.user.findUniqueOrThrow({ where: { email: TEST_USERS[role].email } })).id;
}

let alerts: Awaited<ReturnType<typeof seedCompromise>>;

beforeEach(async () => {
  await resetDatabase();
  alerts = await seedCompromise();
});

describe('POST /api/incidents', () => {
  it('escalates alerts into an incident, linking them and moving them to INVESTIGATING', async () => {
    const agent = await loginAs(app, 'ANALYST');
    const res = await agent
      .post('/api/incidents')
      .send({ alertIds: [alerts.bruteForce.id, alerts.compromise.id] })
      .expect(201);
    const incident = res.body.data;

    // Defaults come from the most severe alert; the creator becomes the assignee.
    expect(incident).toMatchObject({
      title: alerts.compromise.title,
      severity: 'CRITICAL',
      status: 'OPEN',
      assignee: { email: TEST_USERS.ANALYST.email },
      resolvedAt: null,
    });
    expect(incident.alerts.map((a: { id: number; status: string }) => [a.id, a.status])).toEqual([
      [alerts.bruteForce.id, 'INVESTIGATING'],
      [alerts.compromise.id, 'INVESTIGATING'],
    ]);
    // 5 failed logins + 1 successful login, shared between the two alerts
    expect(incident.events).toHaveLength(6);
    expect(incident.activities.map((a: { type: string }) => a.type)).toEqual([
      'CREATED',
      'ALERT_LINKED',
      'ALERT_LINKED',
      'ASSIGNMENT',
    ]);

    const alertActivity = await prisma.activity.findMany({ where: { alertId: alerts.compromise.id }, orderBy: { id: 'asc' } });
    expect(alertActivity.map((a) => a.message)).toContain(`Escalated to incident #${incident.id}`);
  });

  it('accepts a custom title, severity and assignee', async () => {
    const agent = await loginAs(app, 'ANALYST');
    const adminId = await userId('ADMIN');
    const res = await agent
      .post('/api/incidents')
      .send({ alertIds: [alerts.bruteForce.id], title: 'SSH attack on web-01', severity: 'MEDIUM', assigneeId: adminId })
      .expect(201);
    expect(res.body.data).toMatchObject({ title: 'SSH attack on web-01', severity: 'MEDIUM', assignee: { id: adminId } });
  });

  it('refuses to link an alert that already belongs to an incident', async () => {
    const agent = await loginAs(app, 'ANALYST');
    const first = await agent.post('/api/incidents').send({ alertIds: [alerts.compromise.id] }).expect(201);
    const second = await agent.post('/api/incidents').send({ alertIds: [alerts.compromise.id] }).expect(409);
    expect(second.body.message).toBe(`Alert #${alerts.compromise.id} is already part of incident #${first.body.data.id}`);
  });

  it('validates the request', async () => {
    const agent = await loginAs(app, 'ANALYST');
    await agent.post('/api/incidents').send({ alertIds: [] }).expect(400);
    await agent.post('/api/incidents').send({ alertIds: [424242] }).expect(404);
    const viewerAssignee = await agent
      .post('/api/incidents')
      .send({ alertIds: [alerts.bruteForce.id], assigneeId: await userId('VIEWER') })
      .expect(400);
    expect(viewerAssignee.body.message).toBe('Assignee must be an existing analyst or admin');
    expect(await prisma.incident.count()).toBe(0); // nothing half-created
  });

  it('does not let a VIEWER create incidents', async () => {
    const agent = await loginAs(app, 'VIEWER');
    await agent.post('/api/incidents').send({ alertIds: [alerts.bruteForce.id] }).expect(403);
  });
});

describe('working an incident', () => {
  async function createIncident() {
    const agent = await loginAs(app, 'ANALYST');
    const res = await agent.post('/api/incidents').send({ alertIds: [alerts.bruteForce.id, alerts.compromise.id] });
    return { agent, id: res.body.data.id as number };
  }

  it('resolving the incident resolves its alerts and stamps resolvedAt', async () => {
    const { agent, id } = await createIncident();
    await agent.patch(`/api/incidents/${id}`).send({ status: 'INVESTIGATING' }).expect(200);
    const { body } = await agent.patch(`/api/incidents/${id}`).send({ status: 'RESOLVED' }).expect(200);

    expect(body.data.status).toBe('RESOLVED');
    expect(body.data.resolvedAt).not.toBeNull();
    expect(body.data.alerts.every((a: { status: string }) => a.status === 'RESOLVED')).toBe(true);
    expect(body.data.activities.at(-1)).toMatchObject({
      type: 'STATUS_CHANGE',
      message: 'Status changed from INVESTIGATING to RESOLVED',
    });
  });

  it('reopening clears resolvedAt', async () => {
    const { agent, id } = await createIncident();
    await agent.patch(`/api/incidents/${id}`).send({ status: 'CLOSED' }).expect(200);
    const { body } = await agent.patch(`/api/incidents/${id}`).send({ status: 'INVESTIGATING' }).expect(200);
    expect(body.data.resolvedAt).toBeNull();
  });

  it('reassigns and unassigns, recording each change', async () => {
    const { agent, id } = await createIncident();
    const adminId = await userId('ADMIN');

    const assigned = await agent.patch(`/api/incidents/${id}`).send({ assigneeId: adminId }).expect(200);
    expect(assigned.body.data.assignee.id).toBe(adminId);
    expect(assigned.body.data.activities.at(-1).message).toBe('Assigned to Test Admin');

    const unassigned = await agent.patch(`/api/incidents/${id}`).send({ assigneeId: null }).expect(200);
    expect(unassigned.body.data.assignee).toBeNull();
    expect(unassigned.body.data.activities.at(-1).message).toBe('Unassigned');
  });

  it('rejects updates that change nothing', async () => {
    const { agent, id } = await createIncident();
    const res = await agent.patch(`/api/incidents/${id}`).send({ status: 'OPEN' }).expect(400);
    expect(res.body.message).toBe('Nothing to update: values are unchanged');
  });

  it('adds analyst notes to the timeline', async () => {
    const { agent, id } = await createIncident();
    const res = await agent
      .post(`/api/incidents/${id}/notes`)
      .send({ content: 'Password reset for deploy; attacker IP blocked.' })
      .expect(201);
    expect(res.body.data).toMatchObject({ type: 'NOTE', user: { name: 'Test Analyst' } });

    await agent.post(`/api/incidents/${id}/notes`).send({ content: '   ' }).expect(400);
    await agent.post('/api/incidents/424242/notes').send({ content: 'hello' }).expect(404);
  });

  it('lists incidents with assignee and alert count, filterable by status', async () => {
    const { agent } = await createIncident();
    const all = await agent.get('/api/incidents').expect(200);
    expect(all.body.data[0]).toMatchObject({ alertCount: 2, assignee: { name: 'Test Analyst' }, status: 'OPEN' });

    const resolved = await agent.get('/api/incidents?status=RESOLVED').expect(200);
    expect(resolved.body.data).toEqual([]);
  });
});

describe('GET /api/users', () => {
  it('lists the team without password hashes', async () => {
    const agent = await loginAs(app, 'VIEWER');
    const res = await agent.get('/api/users').expect(200);
    expect(res.body.data).toHaveLength(3);
    expect(res.body.data[0]).toEqual({ id: expect.any(Number), name: 'Test Admin', email: 'admin@test.local', role: 'ADMIN' });
  });
});
