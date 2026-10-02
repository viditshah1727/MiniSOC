// Seeded threat intelligence. In a real deployment these rows would come from
// feeds (AbuseIPDB, MISP, a honeypot, ...); here they are local demo data.
import type { Prisma } from '../../src/generated/prisma/client.js';
import { IOCS, KNOWN_ATTACKERS, VULN_SCANNER } from '../../src/simulation/environment.js';

type Indicator = Omit<Prisma.ThreatIntelligenceCreateManyInput, 'firstSeen' | 'lastSeen'> & {
  firstSeenDaysAgo: number;
  lastSeenHoursAgo: number;
};

const INDICATORS: Indicator[] = [
  // ── IP addresses ──
  { type: 'IP', indicator: KNOWN_ATTACKERS.bruteForceBotnet, reputation: 'MALICIOUS', confidence: 95, source: 'internal-honeypot', description: 'SSH brute-force botnet node; hits our honeypot daily', firstSeenDaysAgo: 41, lastSeenHoursAgo: 2 },
  { type: 'IP', indicator: KNOWN_ATTACKERS.credentialStuffer, reputation: 'MALICIOUS', confidence: 88, source: 'abuse-feed', description: 'Credential stuffing with leaked password lists', firstSeenDaysAgo: 22, lastSeenHoursAgo: 11 },
  { type: 'IP', indicator: KNOWN_ATTACKERS.torExitNode, reputation: 'MALICIOUS', confidence: 75, source: 'tor-exit-list', description: 'Tor exit node', firstSeenDaysAgo: 90, lastSeenHoursAgo: 5 },
  { type: 'IP', indicator: KNOWN_ATTACKERS.massScanner, reputation: 'SUSPICIOUS', confidence: 65, source: 'abuse-feed', description: 'Internet-wide port scanner', firstSeenDaysAgo: 120, lastSeenHoursAgo: 30 },
  { type: 'IP', indicator: KNOWN_ATTACKERS.residentialProxy, reputation: 'SUSPICIOUS', confidence: 60, source: 'vendor-feed', description: 'Residential proxy network exit', firstSeenDaysAgo: 14, lastSeenHoursAgo: 60 },
  { type: 'IP', indicator: IOCS.c2Ip, reputation: 'MALICIOUS', confidence: 90, source: 'vendor-feed', description: 'Command-and-control server for a post-exploitation framework', firstSeenDaysAgo: 18, lastSeenHoursAgo: 40 },
  { type: 'IP', indicator: IOCS.malwareHostIp, reputation: 'MALICIOUS', confidence: 82, source: 'vendor-feed', description: 'Malware distribution host', firstSeenDaysAgo: 9, lastSeenHoursAgo: 70 },
  { type: 'IP', indicator: VULN_SCANNER.ip, reputation: 'BENIGN', confidence: 100, source: 'asset-inventory', description: 'Internal vulnerability scanner (authorised weekly scans)', firstSeenDaysAgo: 300, lastSeenHoursAgo: 96 },
  // ── Domains ──
  { type: 'DOMAIN', indicator: IOCS.c2Domain, reputation: 'MALICIOUS', confidence: 88, source: 'vendor-feed', description: 'C2 domain disguised as a software update check', firstSeenDaysAgo: 16, lastSeenHoursAgo: 40 },
  { type: 'DOMAIN', indicator: IOCS.telemetryC2Domain, reputation: 'MALICIOUS', confidence: 80, source: 'vendor-feed', description: 'Payload delivery and C2 domain', firstSeenDaysAgo: 11, lastSeenHoursAgo: 40 },
  { type: 'DOMAIN', indicator: IOCS.phishingDomain, reputation: 'MALICIOUS', confidence: 92, source: 'phishing-feed', description: 'Credential-phishing site imitating the corporate login page', firstSeenDaysAgo: 3, lastSeenHoursAgo: 3 },
  { type: 'DOMAIN', indicator: 'files-share.example', reputation: 'SUSPICIOUS', confidence: 55, source: 'vendor-feed', description: 'Anonymous file-sharing service often abused for exfiltration', firstSeenDaysAgo: 60, lastSeenHoursAgo: 30 },
  // ── File hashes (SHA-256) ──
  { type: 'HASH', indicator: IOCS.eicarHash, reputation: 'MALICIOUS', confidence: 100, source: 'av-signatures', description: 'EICAR antivirus test file (harmless test signature)', firstSeenDaysAgo: 400, lastSeenHoursAgo: 30 },
  { type: 'HASH', indicator: IOCS.dropperHash, reputation: 'MALICIOUS', confidence: 95, source: 'malware-sandbox', description: 'Linux dropper that installs a cron-based persistence job', firstSeenDaysAgo: 12, lastSeenHoursAgo: 40 },
  { type: 'HASH', indicator: IOCS.minerHash, reputation: 'MALICIOUS', confidence: 90, source: 'malware-sandbox', description: 'Cryptocurrency miner', firstSeenDaysAgo: 27, lastSeenHoursAgo: 200 },
  { type: 'HASH', indicator: IOCS.suspiciousToolHash, reputation: 'SUSPICIOUS', confidence: 60, source: 'malware-sandbox', description: 'Remote administration tool (dual use)', firstSeenDaysAgo: 33, lastSeenHoursAgo: 300 },
];

export function threatIntelSeed(now: Date): Prisma.ThreatIntelligenceCreateManyInput[] {
  const hour = 3_600_000;
  return INDICATORS.map(({ firstSeenDaysAgo, lastSeenHoursAgo, ...indicator }) => ({
    ...indicator,
    firstSeen: new Date(now.getTime() - firstSeenDaysAgo * 24 * hour),
    lastSeen: new Date(now.getTime() - lastSeenHoursAgo * hour),
  }));
}
