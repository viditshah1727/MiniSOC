// Attack patterns: sequences of events that tell a story. The seed uses them
// with fixed actors and a seeded RNG (reproducible history); the live
// simulator uses random actors so each demo run looks different.
// DEMO ONLY: nothing here is used by the production ingestion path.
import type { ValidEventInput } from '../schemas/events.js';
import {
  COMMON_PORTS,
  EMPLOYEES,
  GUESSED_ACCOUNTS,
  type Host,
  IOCS,
  SERVERS,
} from './environment.js';
import { commandExecuted, dnsLookup, fileDownload, firewallConnection, sshLoginAccepted, sshLoginFailed, vpnLogin } from './logEvents.js';
import { between, pick, type Rng, sample, secondsAfter } from './random.js';

/** Commands a normal user should never run: each one trips rule R004. */
export const ESCALATION_COMMANDS = [
  'sudo su -',
  'sudo -i',
  'sudo /bin/bash',
  'sudo cat /etc/shadow',
  'sudo usermod -aG sudo {user}',
  'chmod u+s /tmp/.cache/bash',
  'pkexec /bin/sh',
  "echo '{user} ALL=(ALL) NOPASSWD:ALL' | sudo tee -a /etc/sudoers",
];

export function escalationCommand(rng: Rng, user: string): string {
  return pick(rng, ESCALATION_COMMANDS).replaceAll('{user}', user);
}

/** Rapid failed SSH logins, optionally ending in a successful one. */
export function sshBruteForce(p: {
  start: Date;
  rng: Rng;
  attackerIp: string;
  target: Host;
  accounts: string[];
  attempts: number;
  secondsBetween?: [number, number];
  compromisedAccount?: string;
}): ValidEventInput[] {
  const [minGap, maxGap] = p.secondsBetween ?? [4, 18];
  const events: ValidEventInput[] = [];
  let at = p.start;
  for (let i = 0; i < p.attempts; i++) {
    events.push(sshLoginFailed({ at, rng: p.rng, ip: p.attackerIp, user: p.accounts[i % p.accounts.length]!, host: p.target }));
    at = secondsAfter(at, between(p.rng, minGap, maxGap));
  }
  if (p.compromisedAccount) {
    events.push(sshLoginAccepted({ at, rng: p.rng, ip: p.attackerIp, user: p.compromisedAccount, host: p.target }));
  }
  return events;
}

/** One source probing many ports in quick succession. */
export function portScan(p: { start: Date; rng: Rng; attackerIp: string; target: Host; ports: number[] }): ValidEventInput[] {
  let at = p.start;
  return p.ports.map((port) => {
    at = secondsAfter(at, between(p.rng, 1, 6));
    return firewallConnection({ at, rng: p.rng, srcIp: p.attackerIp, dstIp: p.target.ip, dstPort: port, host: p.target, action: 'BLOCK' });
  });
}

/** A compromised host calling home: DNS lookup of the C2 domain, then beacons to the C2 server. */
export function commandAndControl(p: { start: Date; rng: Rng; host: Host; domain: string; c2Ip: string }): ValidEventInput[] {
  const events: ValidEventInput[] = [dnsLookup({ at: p.start, rng: p.rng, host: p.host, domain: p.domain })];
  let at = p.start;
  for (let i = 0; i < 3; i++) {
    at = secondsAfter(at, between(p.rng, 55, 65)); // regular ~60 s beacon interval
    events.push(firewallConnection({ at, rng: p.rng, srcIp: p.host.ip, dstIp: p.c2Ip, dstPort: 443, host: p.host, action: 'ALLOW' }));
  }
  return events;
}

/** Full intrusion: recon, brute force, compromise, privilege escalation, C2 and a payload download. */
export function intrusionKillChain(p: { start: Date; rng: Rng; attackerIp: string; target: Host; victim: string }): ValidEventInput[] {
  const { rng } = p;
  const recon = portScan({ start: p.start, rng, attackerIp: p.attackerIp, target: p.target, ports: sample(rng, COMMON_PORTS, 14) });
  const bruteForce = sshBruteForce({
    start: secondsAfter(p.start, between(rng, 300, 600)),
    rng,
    attackerIp: p.attackerIp,
    target: p.target,
    accounts: ['root', 'admin', p.victim, 'ubuntu'],
    attempts: between(rng, 9, 13),
    compromisedAccount: p.victim,
  });
  const loginAt = bruteForce.at(-1)!.timestamp!;
  const escalation = commandExecuted({
    at: secondsAfter(loginAt, between(rng, 60, 180)),
    rng,
    user: p.victim,
    host: p.target,
    command: 'sudo su -',
    sessionIp: p.attackerIp,
  });
  const c2 = commandAndControl({
    start: secondsAfter(loginAt, between(rng, 240, 400)),
    rng,
    host: p.target,
    domain: IOCS.c2Domain,
    c2Ip: IOCS.c2Ip,
  });
  const payload = fileDownload({
    at: secondsAfter(loginAt, between(rng, 500, 700)),
    rng,
    host: p.target,
    user: 'root',
    domain: IOCS.telemetryC2Domain,
    fileName: 'kworker-update',
    sha256: IOCS.dropperHash,
  });
  return [...recon, ...bruteForce, escalation, ...c2, payload];
}

// ─── Live simulator (POST /api/simulate) ────────────────────────────────────

export const SCENARIO_IDS = [
  'ssh-brute-force',
  'port-scan',
  'suspicious-login',
  'privilege-escalation',
  'brute-force-compromise',
  'malware-download',
] as const;
export type ScenarioId = (typeof SCENARIO_IDS)[number];

export interface Scenario {
  id: ScenarioId;
  name: string;
  description: string;
  expectedRules: string[];
  build(rng: Rng, now: Date): ValidEventInput[];
}

/** A random address from the RFC 5737 documentation ranges. */
function randomExternalIp(rng: Rng): string {
  return `${pick(rng, ['192.0.2', '198.51.100', '203.0.113'])}.${between(rng, 2, 254)}`;
}

/** Shifts a sequence so its last event happens exactly at `now` (never in the future). */
function endingAt(now: Date, events: ValidEventInput[]): ValidEventInput[] {
  const last = events.at(-1)?.timestamp?.getTime() ?? now.getTime();
  const shift = now.getTime() - last;
  return events.map((event) => ({ ...event, timestamp: new Date((event.timestamp ?? now).getTime() + shift) }));
}

export const SCENARIOS: Scenario[] = [
  {
    id: 'ssh-brute-force',
    name: 'SSH brute force',
    description: 'An external IP guesses passwords for common accounts over SSH.',
    expectedRules: ['R001'],
    build: (rng, now) =>
      endingAt(
        now,
        sshBruteForce({
          start: now,
          rng,
          attackerIp: randomExternalIp(rng),
          target: pick(rng, [SERVERS.web01, SERVERS.bastion]),
          accounts: sample(rng, GUESSED_ACCOUNTS, 4),
          attempts: between(rng, 8, 14),
        }),
      ),
  },
  {
    id: 'port-scan',
    name: 'Port scan',
    description: 'An external IP probes many ports on an internet-facing server.',
    expectedRules: ['R002'],
    build: (rng, now) =>
      endingAt(
        now,
        portScan({ start: now, rng, attackerIp: randomExternalIp(rng), target: pick(rng, [SERVERS.web01, SERVERS.web02]), ports: sample(rng, COMMON_PORTS, between(rng, 12, 18)) }),
      ),
  },
  {
    id: 'suspicious-login',
    name: 'Login from a new location',
    description: 'An employee account logs in over VPN from an IP it has never used before.',
    expectedRules: ['R003'],
    build: (rng, now) => [vpnLogin({ at: now, rng, ip: randomExternalIp(rng), user: pick(rng, EMPLOYEES).username, success: true })],
  },
  {
    id: 'privilege-escalation',
    name: 'Privilege escalation',
    description: 'A normal user runs a command that grants root access on a server.',
    expectedRules: ['R004'],
    build: (rng, now) => {
      const user = pick(rng, EMPLOYEES).username;
      const host = pick(rng, [SERVERS.app01, SERVERS.db01, SERVERS.files01, SERVERS.web02]);
      return [commandExecuted({ at: now, rng, user, host, command: escalationCommand(rng, user) })];
    },
  },
  {
    id: 'brute-force-compromise',
    name: 'Full intrusion (kill chain)',
    description: 'Scan, brute force, successful login, root shell, C2 beaconing and a payload download.',
    expectedRules: ['R002', 'R001', 'R005', 'R003', 'R004', 'R006'],
    build: (rng, now) =>
      endingAt(
        now,
        intrusionKillChain({ start: now, rng, attackerIp: randomExternalIp(rng), target: pick(rng, [SERVERS.web01, SERVERS.web02, SERVERS.app01]), victim: 'deploy' }),
      ),
  },
  {
    id: 'malware-download',
    name: 'Malware download',
    description: 'A workstation resolves a known-bad domain and downloads a file with a known-malware hash.',
    expectedRules: ['R006'],
    build: (rng, now) => {
      const victim = pick(rng, EMPLOYEES);
      const domain = IOCS.telemetryC2Domain;
      return endingAt(now, [
        dnsLookup({ at: now, rng, host: victim.workstation, domain }),
        fileDownload({ at: secondsAfter(now, 2), rng, host: victim.workstation, user: victim.username, domain, fileName: 'invoice_0925.exe', sha256: pick(rng, [IOCS.dropperHash, IOCS.minerHash]) }),
      ]);
    },
  },
];

export function getScenario(id: ScenarioId): Scenario {
  return SCENARIOS.find((scenario) => scenario.id === id)!;
}
