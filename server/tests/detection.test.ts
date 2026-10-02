// Detection engine tests: every rule's trigger condition, its near-misses,
// and the engine behaviour around it (suppression, tuning, enrichment).
import { beforeEach, describe, expect, it } from 'vitest';
import { prisma } from '../src/db.js';
import type { ValidEventInput } from '../src/schemas/events.js';
import { ingestEvent } from '../src/services/eventService.js';
import {
  addIndicator,
  command,
  connection,
  minutesAgo,
  resetDatabase,
  sshFailure,
  sshSuccess,
} from './helpers.js';

const ATTACKER = '203.0.113.45';

beforeEach(async () => {
  await resetDatabase();
});

/** Ingests events in order and returns every alert they raised. */
async function ingestAll(events: ValidEventInput[]) {
  const raised = [];
  for (const event of events) raised.push(...(await ingestEvent(event)).alerts);
  return raised;
}

function failures(count: number, { ip = ATTACKER, spacingSeconds = 30, startMinutesAgo = 5 } = {}) {
  return Array.from({ length: count }, (_, i) =>
    sshFailure(ip, i % 2 ? 'admin' : 'root', new Date(minutesAgo(startMinutesAgo).getTime() + i * spacingSeconds * 1000)),
  );
}

async function loadAlert(id: number) {
  return prisma.alert.findUniqueOrThrow({
    where: { id },
    include: { rule: true, evidenceEvents: true, threatIntel: true, activities: true },
  });
}

describe('R001 SSH Brute Force', () => {
  it('raises one HIGH alert at the 5th failure within 5 minutes', async () => {
    const alerts = await ingestAll(failures(5));

    expect(alerts).toHaveLength(1);
    const alert = await loadAlert(alerts[0]!.id);
    expect(alert).toMatchObject({
      severity: 'HIGH',
      status: 'OPEN',
      sourceIp: ATTACKER,
      mitreTechniqueId: 'T1110',
      rule: { code: 'R001' },
      evidence: { failedAttempts: 5, threshold: 5, windowMinutes: 5, targetedAccounts: ['root', 'admin'] },
    });
    expect(alert.evidenceEvents).toHaveLength(5);
    expect(alert.description).toContain('5 failed SSH logins');
    expect(alert.activities.map((a) => a.type)).toEqual(['CREATED']);
  });

  it('does not fire for 4 failures', async () => {
    expect(await ingestAll(failures(4))).toEqual([]);
  });

  it('does not fire when the failures are spread over a longer period', async () => {
    // 5 failures, 2 minutes apart: never 5 inside any 5-minute window.
    expect(await ingestAll(failures(5, { spacingSeconds: 120, startMinutesAgo: 20 }))).toEqual([]);
  });

  it('only counts SSH failures (other log sources are ignored)', async () => {
    const vpnFailures = failures(6).map((e) => ({ ...e, source: 'vpn-gateway' }));
    const alerts = await ingestAll(vpnFailures);
    expect(alerts.map((a) => a.rule.code)).not.toContain('R001');
  });

  it('suppresses duplicates: a continuing attack yields a single alert', async () => {
    const alerts = await ingestAll(failures(15, { spacingSeconds: 10 }));
    expect(alerts.filter((a) => a.rule.code === 'R001')).toHaveLength(1);
  });

  it('respects a disabled rule', async () => {
    await prisma.detectionRule.update({ where: { code: 'R001' }, data: { enabled: false } });
    expect(await ingestAll(failures(6))).toEqual([]);
  });

  it('uses the threshold tuned in the database', async () => {
    await prisma.detectionRule.update({ where: { code: 'R001' }, data: { threshold: 3 } });
    const alerts = await ingestAll(failures(3));
    expect(alerts).toHaveLength(1);
    expect(alerts[0]!.description).toContain('threshold: 3');
  });
});

describe('R002 Network Port Scan', () => {
  const ports = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3306, 3389];

  it('raises a HIGH alert when one source hits 10+ distinct ports within 3 minutes', async () => {
    const probes = ports.map((port, i) => connection(ATTACKER, port, new Date(minutesAgo(2).getTime() + i * 5000)));
    const alerts = await ingestAll(probes);

    expect(alerts).toHaveLength(1);
    const alert = await loadAlert(alerts[0]!.id);
    expect(alert).toMatchObject({ severity: 'HIGH', mitreTechniqueId: 'T1046', rule: { code: 'R002' } });
    expect(alert.evidence).toMatchObject({ distinctPorts: 10, threshold: 10, portsProbed: ports.slice(0, 10) });
  });

  it('does not fire for 9 distinct ports', async () => {
    const probes = ports.slice(0, 9).map((port, i) => connection(ATTACKER, port, minutesAgo(2 - i * 0.1)));
    expect(await ingestAll(probes)).toEqual([]);
  });

  it('does not fire for many connections to the same few ports (normal traffic)', async () => {
    const busyClient = Array.from({ length: 30 }, (_, i) => connection('10.10.4.21', i % 2 ? 443 : 80, minutesAgo(2 - i * 0.05)));
    expect(await ingestAll(busyClient)).toEqual([]);
  });
});

describe('R003 Suspicious Login', () => {
  async function buildBaseline(username: string, ip: string) {
    for (const daysAgo of [5, 4, 3]) {
      await ingestEvent(sshSuccess(ip, username, minutesAgo(daysAgo * 24 * 60)));
    }
  }

  it('flags a login from a never-seen IP for an account with a login history', async () => {
    await buildBaseline('jsmith', '10.10.4.21');
    const alerts = await ingestAll([sshSuccess('198.51.100.23', 'jsmith', minutesAgo(0))]);

    expect(alerts).toHaveLength(1);
    const alert = await loadAlert(alerts[0]!.id);
    expect(alert).toMatchObject({ severity: 'MEDIUM', mitreTechniqueId: 'T1078', username: 'jsmith' });
    expect(alert.evidence).toMatchObject({ priorLoginsForAccount: 3, usualSources: ['10.10.4.21'], baselineDays: 30 });
  });

  it('does not flag a login from one of the usual IPs', async () => {
    await buildBaseline('jsmith', '10.10.4.21');
    expect(await ingestAll([sshSuccess('10.10.4.21', 'jsmith', minutesAgo(0))])).toEqual([]);
  });

  it('does not flag accounts without enough history to have a baseline', async () => {
    await ingestEvent(sshSuccess('10.10.4.21', 'newhire', minutesAgo(60)));
    expect(await ingestAll([sshSuccess('198.51.100.23', 'newhire', minutesAgo(0))])).toEqual([]);
  });

  it('flags any login from an IP with a bad threat-intel reputation and links the intel', async () => {
    const intel = await addIndicator({ indicator: '198.51.100.23', type: 'IP', reputation: 'SUSPICIOUS', confidence: 60 });
    const alerts = await ingestAll([sshSuccess('198.51.100.23', 'newhire', minutesAgo(0))]);

    expect(alerts).toHaveLength(1);
    const alert = await loadAlert(alerts[0]!.id);
    expect(alert.threatIntelId).toBe(intel.id);
    expect((alert.evidence as { reasons: string[] }).reasons[0]).toContain('SUSPICIOUS');
  });
});

describe('R004 Privilege Escalation', () => {
  it('raises a CRITICAL alert when a normal user spawns a root shell', async () => {
    const alerts = await ingestAll([command('jsmith', 'sudo su -', minutesAgo(0))]);

    expect(alerts).toHaveLength(1);
    const alert = await loadAlert(alerts[0]!.id);
    expect(alert).toMatchObject({ severity: 'CRITICAL', mitreTechniqueId: 'T1548', rule: { code: 'R004' } });
    expect(alert.description).toContain('switched to root');
  });

  it('maps credential access to T1003 and group changes to T1098', async () => {
    const [shadow] = await ingestAll([command('jsmith', 'sudo cat /etc/shadow', minutesAgo(1), { hostname: 'db-01' })]);
    const [group] = await ingestAll([command('jsmith', 'sudo usermod -aG sudo jsmith', minutesAgo(0), { hostname: 'app-01' })]);

    expect(shadow!.mitreTechniqueId).toBe('T1003');
    expect(group!.mitreTechniqueId).toBe('T1098');
  });

  it('ignores privileged accounts doing admin work', async () => {
    expect(await ingestAll([command('root', 'sudo su -', minutesAgo(0))])).toEqual([]);
  });

  it('ignores ordinary commands', async () => {
    const benign = ['ls -la /var/www', 'sudo systemctl restart nginx', 'chmod 755 deploy.sh', 'usermod -aG docker jsmith'];
    expect(await ingestAll(benign.map((c, i) => command('jsmith', c, minutesAgo(10 - i))))).toEqual([]);
  });
});

describe('R005 Brute Force Followed by Successful Login', () => {
  it('raises a CRITICAL alert when failures are followed by a success from the same IP', async () => {
    const alerts = await ingestAll([...failures(3), sshSuccess(ATTACKER, 'deploy', minutesAgo(0))]);

    const compromise = alerts.find((a) => a.rule.code === 'R005');
    expect(compromise).toBeDefined();
    const alert = await loadAlert(compromise!.id);
    expect(alert).toMatchObject({ severity: 'CRITICAL', mitreTechniqueId: 'T1110', username: 'deploy' });
    expect(alert.evidence).toMatchObject({ compromisedAccount: 'deploy', failedAttemptsBefore: 3 });
    expect(alert.evidenceEvents).toHaveLength(4); // 3 failures + the successful login
  });

  it('does not fire for a clean login', async () => {
    const alerts = await ingestAll([sshSuccess(ATTACKER, 'deploy', minutesAgo(0))]);
    expect(alerts.map((a) => a.rule.code)).not.toContain('R005');
  });

  it('does not fire when the failures came from a different IP', async () => {
    const alerts = await ingestAll([...failures(4, { ip: '192.0.2.10' }), sshSuccess(ATTACKER, 'deploy', minutesAgo(0))]);
    expect(alerts.map((a) => a.rule.code)).not.toContain('R005');
  });
});

describe('R006 Threat Intelligence Match', () => {
  it('flags a DNS lookup of a malicious domain (T1071)', async () => {
    const intel = await addIndicator({ indicator: 'update-check.example', type: 'DOMAIN', confidence: 88 });
    const alerts = await ingestAll([
      {
        source: 'dns',
        eventType: 'DNS_QUERY',
        severity: 'INFO',
        sourceIp: '10.0.2.15',
        hostname: 'ws-017',
        message: 'A? Update-Check.example',
        metadata: { domain: 'Update-Check.example' },
        timestamp: minutesAgo(0),
      },
    ]);

    expect(alerts).toHaveLength(1);
    expect(alerts[0]).toMatchObject({ severity: 'HIGH', mitreTechniqueId: 'T1071', threatIntelId: intel.id });
  });

  it('flags a download whose SHA-256 is known malware (T1105)', async () => {
    const hash = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';
    await addIndicator({ indicator: hash, type: 'HASH', confidence: 100 });
    const alerts = await ingestAll([
      {
        source: 'proxy',
        eventType: 'FILE_DOWNLOAD',
        severity: 'LOW',
        sourceIp: '10.0.2.15',
        hostname: 'ws-017',
        message: 'GET http://files.example/invoice.exe',
        metadata: { sha256: hash.toUpperCase(), fileName: 'invoice.exe' },
        timestamp: minutesAgo(0),
      },
    ]);

    expect(alerts).toHaveLength(1);
    expect(alerts[0]!.mitreTechniqueId).toBe('T1105');
  });

  it('ignores indicators that are only suspicious or below the confidence threshold', async () => {
    await addIndicator({ indicator: '192.0.2.200', type: 'IP', reputation: 'SUSPICIOUS', confidence: 95 });
    await addIndicator({ indicator: '192.0.2.201', type: 'IP', reputation: 'MALICIOUS', confidence: 50 });
    const alerts = await ingestAll([
      connection('10.0.2.15', 443, minutesAgo(1), { destinationIp: '192.0.2.200' }),
      connection('10.0.2.15', 443, minutesAgo(0), { destinationIp: '192.0.2.201' }),
    ]);
    expect(alerts).toEqual([]);
  });
});

describe('risk scoring and enrichment', () => {
  it('adds +10 for a known malicious source IP and +10 for a privileged account', async () => {
    await addIndicator({ indicator: ATTACKER, type: 'IP', confidence: 95 });
    // All five failures target "root", a privileged account.
    const events = failures(5).map((e) => ({ ...e, username: 'root' }));
    const [alert] = await ingestAll(events);

    expect(alert!.riskScore).toBe(90); // HIGH 70 + malicious 10 + privileged 10
    expect((alert!.riskFactors as { points: number }[]).map((f) => f.points)).toEqual([70, 10, 10]);
    expect(alert!.threatIntelId).not.toBeNull();
  });

  it('adds +10 for repeated activity when the same IP already raised an alert', async () => {
    const [scan] = await ingestAll(
      [22, 80, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443].map((port, i) => connection(ATTACKER, port, minutesAgo(30 - i * 0.1))),
    );
    const [bruteForce] = await ingestAll(failures(5).map((e) => ({ ...e, username: 'deploy' })));

    expect(scan!.riskScore).toBe(70);
    expect(bruteForce!.riskScore).toBe(80); // HIGH 70 + repeated 10
  });

  it('caps the score at 100 and says so', async () => {
    await addIndicator({ indicator: ATTACKER, type: 'IP', confidence: 95 });
    await ingestAll(failures(5)); // earlier alert from this IP => repeated activity
    const alerts = await ingestAll([sshSuccess(ATTACKER, 'root', minutesAgo(0))]);
    const compromise = alerts.find((a) => a.rule.code === 'R005')!;

    // CRITICAL 90 + repeated 10 + malicious 10 + privileged 10 = 120, capped to 100
    expect(compromise.riskScore).toBe(100);
    const factors = compromise.riskFactors as { label: string; points: number }[];
    expect(factors.reduce((sum, f) => sum + f.points, 0)).toBe(100);
    expect(factors.at(-1)!.label).toContain('Capped');
  });
});
