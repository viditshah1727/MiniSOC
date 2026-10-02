// Seven days of activity for a small company: normal work plus several attack
// campaigns. The seed feeds every event through the real detection engine,
// so each alert on the dashboard is genuinely produced by a rule.
import type { ValidEventInput } from '../../src/schemas/events.js';
import {
  BENIGN_DOMAINS,
  BENIGN_EXTERNAL_IPS,
  COMMON_PORTS,
  EMPLOYEES,
  GUESSED_ACCOUNTS,
  type Host,
  IOCS,
  KNOWN_ATTACKERS,
  SERVER_LIST,
  SERVERS,
  SERVICE_ACCOUNTS,
  SYSADMIN,
  UNKNOWN_ATTACKERS,
  VULN_SCANNER,
} from '../../src/simulation/environment.js';
import {
  commandExecuted,
  dnsLookup,
  fileDownload,
  firewallConnection,
  sshLoginAccepted,
  sshLoginFailed,
  vpnLogin,
} from '../../src/simulation/logEvents.js';
import { between, pick, type Rng, sample } from '../../src/simulation/random.js';
import { intrusionKillChain, portScan, sshBruteForce } from '../../src/simulation/scenarios.js';

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAYS_OF_HISTORY = 7;

const EVERYDAY_COMMANDS = [
  'git pull',
  'docker ps',
  'df -h',
  'ls -la /srv/app',
  'tail -n 100 /var/log/app/app.log',
  'systemctl status nginx',
  'cat /etc/hosts',
  'python3 manage.py migrate',
];
const SYSADMIN_COMMANDS = ['sudo systemctl restart nginx', 'sudo apt-get upgrade -y', 'sudo journalctl -u sshd --since today', 'sudo su -'];

const person = (username: string) => EMPLOYEES.find((employee) => employee.username === username)!;
const deploy = SERVICE_ACCOUNTS.find((account) => account.username === 'deploy')!;
const backup = SERVICE_ACCOUNTS.find((account) => account.username === 'backup')!;

/** Each employee works from home via VPN some days, always from the same home IP. */
const homeIp = (index: number) => `192.0.2.${100 + index}`;

export function buildTimeline(now: Date, rng: Rng): ValidEventInput[] {
  return [...normalActivity(now, rng), ...attackCampaigns(now, rng)]
    .filter((event) => event.timestamp!.getTime() <= now.getTime())
    .sort((a, b) => a.timestamp!.getTime() - b.timestamp!.getTime());
}

/** A UTC time `daysAgo` days before now, at hh:mm (+ random seconds). */
function dayAt(now: Date, rng: Rng, daysAgo: number, hour: number, minute: number): Date {
  const date = new Date(now.getTime() - daysAgo * 24 * HOUR);
  date.setUTCHours(hour, minute, between(rng, 0, 59), 0);
  return date;
}

/** Mostly business hours, with a little activity at night. */
function workHour(rng: Rng): number {
  return rng() < 0.85 ? between(rng, 7, 18) : between(rng, 0, 23);
}

function normalActivity(now: Date, rng: Rng): ValidEventInput[] {
  const events: ValidEventInput[] = [];

  for (let daysAgo = DAYS_OF_HISTORY; daysAgo >= 0; daysAgo--) {
    const at = (hour: number) => dayAt(now, rng, daysAgo, hour, between(rng, 0, 59));
    const later = (date: Date, maxMinutes: number) => new Date(date.getTime() + between(rng, 1, maxMinutes) * MINUTE);

    // Employees: VPN from home on some days, SSH sessions from their workstation.
    // On the first day everyone uses both, so their login baseline (rule R003)
    // already knows both usual locations.
    const firstDay = daysAgo === DAYS_OF_HISTORY;
    EMPLOYEES.forEach((employee, index) => {
      if (!firstDay && rng() < 0.15) return; // day off
      if (firstDay || rng() < 0.35) {
        events.push(vpnLogin({ at: at(between(rng, 7, 9)), rng, ip: homeIp(index), user: employee.username, success: true }));
      }
      for (let session = between(rng, 1, 2); session > 0; session--) {
        const host = pick(rng, [SERVERS.bastion, SERVERS.app01, SERVERS.web02]);
        const loginAt = at(workHour(rng));
        if (rng() < 0.1) {
          // A mistyped password right before a good login: normal, must NOT alert.
          events.push(sshLoginFailed({ at: new Date(loginAt.getTime() - 25_000), rng, ip: employee.workstation.ip, user: employee.username, host }));
        }
        events.push(sshLoginAccepted({ at: loginAt, rng, ip: employee.workstation.ip, user: employee.username, host }));
        if (rng() < 0.6) {
          events.push(commandExecuted({ at: later(loginAt, 40), rng, user: employee.username, host, command: pick(rng, EVERYDAY_COMMANDS) }));
        }
      }
    });

    // The CI runner deploys a few times a day using the "deploy" service account.
    for (let deployment = between(rng, 3, 6); deployment > 0; deployment--) {
      const host = pick(rng, [SERVERS.web01, SERVERS.web02, SERVERS.app01]);
      events.push(sshLoginAccepted({ at: at(between(rng, 8, 19)), rng, ip: deploy.workstation.ip, user: 'deploy', host }));
    }

    // Nightly backup job.
    events.push(sshLoginAccepted({ at: at(2), rng, ip: backup.workstation.ip, user: 'backup', host: SERVERS.db01 }));

    // Sysadmin work: privileged account doing privileged things (must NOT trigger R004).
    for (let session = between(rng, 1, 3); session > 0; session--) {
      const host = pick(rng, SERVER_LIST);
      const loginAt = at(workHour(rng));
      events.push(sshLoginAccepted({ at: loginAt, rng, ip: SYSADMIN.workstation.ip, user: SYSADMIN.username, host }));
      events.push(commandExecuted({ at: later(loginAt, 20), rng, user: SYSADMIN.username, host, command: pick(rng, SYSADMIN_COMMANDS) }));
    }

    // DNS lookups and outbound HTTPS from workstations and servers.
    const machines: Host[] = [...EMPLOYEES.map((employee) => employee.workstation), ...SERVER_LIST];
    for (let lookup = between(rng, 30, 45); lookup > 0; lookup--) {
      events.push(dnsLookup({ at: at(workHour(rng)), rng, host: pick(rng, machines), domain: pick(rng, BENIGN_DOMAINS) }));
    }
    for (let connection = between(rng, 18, 28); connection > 0; connection--) {
      const host = pick(rng, machines);
      events.push(firewallConnection({ at: at(workHour(rng)), rng, srcIp: host.ip, dstIp: pick(rng, BENIGN_EXTERNAL_IPS), dstPort: pick(rng, [443, 443, 443, 80]), host, action: 'ALLOW' }));
    }

    // Internet background noise: single blocked probes (too few ports to be a scan).
    for (let probe = between(rng, 6, 12); probe > 0; probe--) {
      const target = pick(rng, [SERVERS.web01, SERVERS.web02]);
      const srcIp = `${pick(rng, ['198.51.100', '203.0.113'])}.${between(rng, 2, 254)}`;
      events.push(firewallConnection({ at: at(between(rng, 0, 23)), rng, srcIp, dstIp: target.ip, dstPort: pick(rng, [22, 23, 80, 443, 3389]), host: target, action: 'BLOCK' }));
    }

    // Software downloads from the package mirror.
    for (let download = between(rng, 2, 4); download > 0; download--) {
      const employee = pick(rng, EMPLOYEES);
      const fileName = pick(rng, ['node-v22.tar.xz', 'vscode-setup.deb', 'report-template.docx', 'python-3.13.pkg']);
      const sha256 = Array.from({ length: 64 }, () => '0123456789abcdef'[between(rng, 0, 15)]).join('');
      events.push(fileDownload({ at: at(workHour(rng)), rng, host: employee.workstation, user: employee.username, domain: 'packages.vendor.example', fileName, sha256 }));
    }
  }
  return events;
}

function attackCampaigns(now: Date, rng: Rng): ValidEventInput[] {
  const at = (daysAgo: number, hour: number, minute: number) => dayAt(now, rng, daysAgo, hour, minute);
  const minutesAgo = (minutes: number) => new Date(now.getTime() - minutes * MINUTE);

  return [
    // 6 days ago: an internet-wide scanner sweeps web-01 (R002).
    ...portScan({ start: at(6, 14, 10), rng, attackerIp: KNOWN_ATTACKERS.massScanner, target: SERVERS.web01, ports: sample(rng, COMMON_PORTS, 16) }),

    // 5 days ago: credential stuffing against the bastion host (R001).
    ...sshBruteForce({
      start: at(5, 3, 20),
      rng,
      attackerIp: KNOWN_ATTACKERS.credentialStuffer,
      target: SERVERS.bastion,
      accounts: ['root', 'admin', 'oracle', 'postgres', 'test', 'ubuntu'],
      attempts: 18,
    }),

    // 4 days ago: the authorised vulnerability scanner runs its weekly scan (R002, a false positive).
    ...portScan({ start: at(4, 10, 0), rng, attackerIp: VULN_SCANNER.ip, target: SERVERS.db01, ports: sample(rng, COMMON_PORTS, 20) }),

    // 3 days ago: a slower brute force from an IP threat intel does not know (R001 without enrichment).
    ...sshBruteForce({
      start: at(3, 21, 40),
      rng,
      attackerIp: UNKNOWN_ATTACKERS[0]!,
      target: SERVERS.web02,
      accounts: ['git', 'admin', 'root'],
      attempts: 7,
      secondsBetween: [20, 35],
    }),

    // 3 days ago: mgarcia's account logs in over VPN from a residential proxy (R003).
    vpnLogin({ at: at(3, 9, 12), rng, ip: KNOWN_ATTACKERS.residentialProxy, user: 'mgarcia', success: true }),

    // 2 days ago: full intrusion of web-01 through the "deploy" account (R002 R001 R005 R003 R004 R006).
    ...intrusionKillChain({ start: at(2, 1, 5), rng, attackerIp: KNOWN_ATTACKERS.bruteForceBotnet, target: SERVERS.web01, victim: 'deploy' }),

    // Yesterday: tnguyen adds themself to the sudo group on app-01 (R004).
    commandExecuted({ at: at(1, 15, 30), rng, user: 'tnguyen', host: SERVERS.app01, command: 'sudo usermod -aG sudo tnguyen' }),

    // Yesterday: okim downloads the EICAR antivirus test file (R006, a false positive).
    dnsLookup({ at: at(1, 11, 4), rng, host: person('okim').workstation, domain: 'files-share.example' }),
    fileDownload({ at: at(1, 11, 5), rng, host: person('okim').workstation, user: 'okim', domain: 'files-share.example', fileName: 'eicar_test.com', sha256: IOCS.eicarHash }),

    // Today: the credential stuffer is back, this time against web-01 (R001).
    ...sshBruteForce({ start: minutesAgo(10 * 60), rng, attackerIp: KNOWN_ATTACKERS.credentialStuffer, target: SERVERS.web01, accounts: sample(rng, GUESSED_ACCOUNTS, 5), attempts: 12 }),

    // Today: a Tor exit node scans web-02 (R002).
    ...portScan({ start: minutesAgo(5 * 60), rng, attackerIp: KNOWN_ATTACKERS.torExitNode, target: SERVERS.web02, ports: sample(rng, COMMON_PORTS, 13) }),

    // Today: dlopez's workstation resolves a phishing domain (R006).
    dnsLookup({ at: minutesAgo(150), rng, host: person('dlopez').workstation, domain: IOCS.phishingDomain }),

    // In the last hour: jsmith's password is guessed and the attacker reads /etc/shadow (R001 R005 R003 R004).
    // Left OPEN on purpose so there is a live incident to investigate in a demo.
    ...sshBruteForce({ start: minutesAgo(48), rng, attackerIp: KNOWN_ATTACKERS.bruteForceBotnet, target: SERVERS.bastion, accounts: ['root', 'jsmith', 'admin'], attempts: 9, compromisedAccount: 'jsmith' }),
    commandExecuted({ at: minutesAgo(20), rng, user: 'jsmith', host: SERVERS.bastion, command: 'sudo cat /etc/shadow', sessionIp: KNOWN_ATTACKERS.bruteForceBotnet }),
  ];
}
