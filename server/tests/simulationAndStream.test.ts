// The demo attack simulator and the real-time Server-Sent Events stream.
import type { AddressInfo } from 'node:net';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { config } from '../src/config.js';
import { ingestEvent } from '../src/services/eventService.js';
import { EMPLOYEES, IOCS } from '../src/simulation/environment.js';
import { addIndicator, buildApp, loginAs, minutesAgo, resetDatabase, sshFailure, sshSuccess, TEST_PASSWORD, TEST_USERS } from './helpers.js';

const app = buildApp();

beforeEach(async () => {
  await resetDatabase();
});

async function runScenario(scenario: string) {
  const agent = await loginAs(app, 'ANALYST');
  const res = await agent.post('/api/simulate').send({ scenario }).expect(201);
  return res.body.data as { eventsIngested: number; alerts: { rule: { code: string } }[] };
}
const ruleCodes = (result: Awaited<ReturnType<typeof runScenario>>) => result.alerts.map((a) => a.rule.code);

describe('attack simulator (demo only)', () => {
  it('lists the available scenarios', async () => {
    const agent = await loginAs(app, 'VIEWER');
    const { body } = await agent.get('/api/simulate/scenarios').expect(200);
    expect(body.data.map((s: { id: string }) => s.id)).toEqual([
      'ssh-brute-force',
      'port-scan',
      'suspicious-login',
      'privilege-escalation',
      'brute-force-compromise',
      'malware-download',
    ]);
  });

  it.each([
    ['ssh-brute-force', 'R001'],
    ['port-scan', 'R002'],
    ['privilege-escalation', 'R004'],
  ])('%s raises %s through the normal pipeline', async (scenario, rule) => {
    const result = await runScenario(scenario);
    expect(result.eventsIngested).toBeGreaterThan(0);
    expect(ruleCodes(result)).toContain(rule);
  });

  it('suspicious-login raises R003 for an employee with a login history', async () => {
    for (const employee of EMPLOYEES) {
      for (const daysAgo of [3, 2, 1]) {
        await ingestEvent(sshSuccess(employee.workstation.ip, employee.username, minutesAgo(daysAgo * 24 * 60, new Date())));
      }
    }
    expect(ruleCodes(await runScenario('suspicious-login'))).toEqual(['R003']);
  });

  it('the kill chain triggers the whole detection chain', async () => {
    await addIndicator({ indicator: IOCS.c2Domain, type: 'DOMAIN' });
    await addIndicator({ indicator: IOCS.c2Ip, type: 'IP' });
    await addIndicator({ indicator: IOCS.dropperHash, type: 'HASH' });

    const rules = ruleCodes(await runScenario('brute-force-compromise'));
    expect(rules).toEqual(expect.arrayContaining(['R002', 'R001', 'R005', 'R004', 'R006']));
  });

  it('is restricted to analysts and validates the scenario name', async () => {
    const viewer = await loginAs(app, 'VIEWER');
    await viewer.post('/api/simulate').send({ scenario: 'port-scan' }).expect(403);
    const analyst = await loginAs(app, 'ANALYST');
    await analyst.post('/api/simulate').send({ scenario: 'ransomware' }).expect(400);
  });

  it('does not exist at all when ENABLE_SIMULATION is off', async () => {
    config.enableSimulation = false;
    try {
      const productionApp = buildApp();
      const agent = await loginAs(productionApp, 'ANALYST');
      await agent.post('/api/simulate').send({ scenario: 'port-scan' }).expect(404);
    } finally {
      config.enableSimulation = true;
    }
  });
});

describe('GET /api/stream (Server-Sent Events)', () => {
  let close: (() => void) | undefined;
  afterEach(() => close?.());

  async function startServer() {
    const server = app.listen(0);
    close = () => server.close();
    await new Promise((resolve) => server.once('listening', resolve));
    return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  }

  it('requires a login', async () => {
    const base = await startServer();
    expect((await fetch(`${base}/api/stream`)).status).toBe(401);
  });

  it('pushes a new alert to connected browsers as it is raised', async () => {
    const base = await startServer();
    const login = await fetch(`${base}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: TEST_USERS.VIEWER.email, password: TEST_PASSWORD }),
    });
    const cookie = login.headers.getSetCookie()[0]!.split(';')[0]!;

    const controller = new AbortController();
    const stream = await fetch(`${base}/api/stream`, { headers: { Cookie: cookie }, signal: controller.signal });
    expect(stream.headers.get('content-type')).toBe('text/event-stream');

    // Raise an alert while the stream is open.
    for (let i = 0; i < 5; i++) await ingestEvent(sshFailure('203.0.113.45', 'root', minutesAgo(5 - i)));

    const reader = stream.body!.getReader();
    const decoder = new TextDecoder();
    let received = '';
    while (!received.includes('"type":"alert.created"')) {
      const { value, done } = await reader.read();
      if (done) break;
      received += decoder.decode(value);
    }
    controller.abort();

    const alertMessage = received.split('\n\n').find((chunk) => chunk.includes('alert.created'))!;
    const payload = JSON.parse(alertMessage.replace(/^data: /, ''));
    expect(payload).toMatchObject({ type: 'alert.created', severity: 'HIGH', title: 'SSH brute force from 203.0.113.45' });
  });
});
