// The fictional company network used by the demo data and the simulator.
// Every address is reserved for documentation or private use, and every
// domain uses the reserved ".example" TLD, so no real host is ever implicated:
//   internal:  10.0.0.0/8 (RFC 1918)
//   external:  192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (RFC 5737)
import { createHash } from 'node:crypto';

export interface Host {
  hostname: string;
  ip: string;
}

export interface Person {
  username: string;
  workstation: Host;
}

export const SERVERS = {
  web01: { hostname: 'web-01', ip: '10.0.1.10' }, // internet-facing, SSH exposed
  web02: { hostname: 'web-02', ip: '10.0.1.11' },
  app01: { hostname: 'app-01', ip: '10.0.2.20' },
  db01: { hostname: 'db-01', ip: '10.0.3.30' },
  bastion: { hostname: 'bastion-01', ip: '10.0.0.5' }, // SSH jump host
  files01: { hostname: 'files-01', ip: '10.0.4.40' },
} satisfies Record<string, Host>;

export const SERVER_LIST: Host[] = Object.values(SERVERS);

const employeeNames = ['jsmith', 'apatel', 'mgarcia', 'lchen', 'okim', 'rbrown', 'tnguyen', 'swilson', 'dlopez', 'kmurphy'];

/** Staff, each with their own workstation (10.10.4.21, .22, ...). */
export const EMPLOYEES: Person[] = employeeNames.map((username, i) => ({
  username,
  workstation: { hostname: `ws-${String(i + 11).padStart(3, '0')}`, ip: `10.10.4.${21 + i}` },
}));

/** Non-human accounts. "deploy" normally only logs in from the CI runner. */
export const SERVICE_ACCOUNTS: Person[] = [
  { username: 'deploy', workstation: { hostname: 'ci-runner-01', ip: '10.0.5.50' } },
  { username: 'backup', workstation: { hostname: 'files-01', ip: '10.0.4.40' } },
];

/** Privileged account, used by sysadmins from the bastion host. */
export const SYSADMIN: Person = { username: 'admin', workstation: SERVERS.bastion };

/** Internal vulnerability scanner: it port-scans on purpose (a classic false positive). */
export const VULN_SCANNER: Host = { hostname: 'vuln-scanner', ip: '10.0.9.9' };

export const BENIGN_DOMAINS = [
  'intranet.corp.example',
  'mail.corp.example',
  'git.corp.example',
  'packages.vendor.example',
  'docs.vendor.example',
  'updates.os.example',
  'cdn.assets.example',
];

export const BENIGN_EXTERNAL_IPS = ['192.0.2.20', '192.0.2.21', '198.51.100.10', '198.51.100.11'];

/** Attackers the threat-intel database already knows about. */
export const KNOWN_ATTACKERS = {
  bruteForceBotnet: '203.0.113.45',
  credentialStuffer: '203.0.113.77',
  torExitNode: '203.0.113.12',
  massScanner: '198.51.100.23',
  residentialProxy: '198.51.100.200',
};

/** Unknown attackers (not in threat intel): detection still works without intel. */
export const UNKNOWN_ATTACKERS = ['198.51.100.140', '192.0.2.150', '203.0.113.188'];

const fakeSha256 = (label: string) => createHash('sha256').update(`minisoc-demo:${label}`).digest('hex');

/** Indicators of compromise used by the attack scenarios (all present in the seeded intel). */
export const IOCS = {
  c2Ip: '192.0.2.66',
  malwareHostIp: '192.0.2.99',
  c2Domain: 'update-check.example',
  telemetryC2Domain: 'cdn-telemetry.example',
  phishingDomain: 'secure-login-portal.example',
  // SHA-256 of the harmless EICAR antivirus test file (a real, well-known test signature).
  eicarHash: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
  // Fictional hashes, derived from labels so they can never match a real file.
  dropperHash: fakeSha256('dropper'),
  minerHash: fakeSha256('cryptominer'),
  suspiciousToolHash: fakeSha256('remote-admin-tool'),
};

export const COMMON_PORTS = [
  21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900,
  6379, 8080, 8443, 9200,
];

/** Account names attackers typically guess. */
export const GUESSED_ACCOUNTS = ['root', 'admin', 'ubuntu', 'test', 'oracle', 'postgres', 'git', 'deploy', 'user'];
