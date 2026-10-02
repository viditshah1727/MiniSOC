// Builders for single, realistic-looking log events (what a log shipper would
// send to POST /api/events after parsing sshd, firewall, auditd, DNS or proxy logs).
import type { ValidEventInput } from '../schemas/events.js';
import type { Host } from './environment.js';
import { between, type Rng } from './random.js';

interface Base {
  at: Date;
  rng: Rng;
}

export function sshLoginFailed(p: Base & { ip: string; user: string; host: Host }): ValidEventInput {
  const port = between(p.rng, 32768, 60999);
  return {
    timestamp: p.at,
    source: 'sshd',
    eventType: 'AUTH_FAILURE',
    severity: 'LOW',
    sourceIp: p.ip,
    destinationIp: p.host.ip,
    destinationPort: 22,
    hostname: p.host.hostname,
    username: p.user,
    message: `Failed password for ${p.user} from ${p.ip} port ${port} ssh2`,
    metadata: { service: 'ssh', pid: between(p.rng, 1000, 32000) },
  };
}

export function sshLoginAccepted(p: Base & { ip: string; user: string; host: Host }): ValidEventInput {
  const port = between(p.rng, 32768, 60999);
  return {
    timestamp: p.at,
    source: 'sshd',
    eventType: 'AUTH_SUCCESS',
    severity: 'INFO',
    sourceIp: p.ip,
    destinationIp: p.host.ip,
    destinationPort: 22,
    hostname: p.host.hostname,
    username: p.user,
    message: `Accepted password for ${p.user} from ${p.ip} port ${port} ssh2`,
    metadata: { service: 'ssh', pid: between(p.rng, 1000, 32000) },
  };
}

export function vpnLogin(p: Base & { ip: string; user: string; success: boolean }): ValidEventInput {
  return {
    timestamp: p.at,
    source: 'vpn-gateway',
    eventType: p.success ? 'AUTH_SUCCESS' : 'AUTH_FAILURE',
    severity: p.success ? 'INFO' : 'LOW',
    sourceIp: p.ip,
    destinationIp: '10.0.0.2',
    destinationPort: 443,
    hostname: 'vpn-gw-01',
    username: p.user,
    message: p.success ? `VPN session established for ${p.user} from ${p.ip}` : `VPN authentication failed for ${p.user} from ${p.ip}`,
    metadata: { service: 'vpn' },
  };
}

export function firewallConnection(
  p: Base & { srcIp: string; dstIp: string; dstPort: number; host: Host; action: 'ALLOW' | 'BLOCK' },
): ValidEventInput {
  return {
    timestamp: p.at,
    source: 'firewall',
    eventType: 'NETWORK_CONNECTION',
    severity: p.action === 'BLOCK' ? 'LOW' : 'INFO',
    sourceIp: p.srcIp,
    destinationIp: p.dstIp,
    destinationPort: p.dstPort,
    hostname: p.host.hostname,
    message: `[UFW ${p.action}] IN=eth0 SRC=${p.srcIp} DST=${p.dstIp} PROTO=TCP SPT=${between(p.rng, 32768, 60999)} DPT=${p.dstPort}`,
    metadata: { action: p.action, protocol: 'TCP' },
  };
}

export function commandExecuted(p: Base & { user: string; host: Host; command: string; sessionIp?: string }): ValidEventInput {
  return {
    timestamp: p.at,
    source: 'auditd',
    eventType: 'PROCESS_EXECUTION',
    severity: 'INFO',
    sourceIp: p.sessionIp,
    hostname: p.host.hostname,
    username: p.user,
    message: `${p.user}@${p.host.hostname}: ${p.command}`,
    metadata: { command: p.command, processName: p.command.split(' ')[0] ?? p.command, pid: between(p.rng, 1000, 32000) },
  };
}

export function dnsLookup(p: Base & { host: Host; domain: string }): ValidEventInput {
  return {
    timestamp: p.at,
    source: 'dns',
    eventType: 'DNS_QUERY',
    severity: 'INFO',
    sourceIp: p.host.ip,
    destinationIp: '10.0.0.53',
    destinationPort: 53,
    hostname: p.host.hostname,
    message: `query[A] ${p.domain} from ${p.host.ip}`,
    metadata: { domain: p.domain, queryType: 'A' },
  };
}

export function fileDownload(
  p: Base & { host: Host; user: string; domain: string; fileName: string; sha256: string },
): ValidEventInput {
  const url = `https://${p.domain}/${p.fileName}`;
  return {
    timestamp: p.at,
    source: 'proxy',
    eventType: 'FILE_DOWNLOAD',
    severity: 'LOW',
    sourceIp: p.host.ip,
    destinationPort: 443,
    hostname: p.host.hostname,
    username: p.user,
    message: `GET ${url} 200 (${between(p.rng, 40, 9000)} KB)`,
    metadata: { url, domain: p.domain, fileName: p.fileName, sha256: p.sha256 },
  };
}
