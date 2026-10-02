// R004: a normal (non-privileged) user runs a command that grants or abuses
// root-level access. Each pattern below is one well-known escalation technique.
import { isPrivilegedAccount } from '../constants.js';
import { readMetadataString } from '../helpers.js';
import type { DetectionRuleDefinition } from '../types.js';

export interface PrivilegedOperation {
  pattern: RegExp;
  /** Completes the sentence "<user> ..." */
  behaviour: string;
  mitreTechniqueId: string;
}

export const PRIVILEGED_OPERATIONS: PrivilegedOperation[] = [
  { pattern: /\bsudo\s+(-\S+\s+)*su\b/, behaviour: 'switched to root with "sudo su"', mitreTechniqueId: 'T1548' },
  { pattern: /\bsudo\s+-[is]\b/, behaviour: 'opened a root shell with "sudo -i/-s"', mitreTechniqueId: 'T1548' },
  { pattern: /\bsudo\s+(\S*\/)?(ba|z|da)?sh\b/, behaviour: 'spawned a root shell through sudo', mitreTechniqueId: 'T1548' },
  { pattern: /\bpkexec\b/, behaviour: 'ran a command as root with pkexec', mitreTechniqueId: 'T1548' },
  { pattern: /\/etc\/sudoers\b|\bvisudo\b/, behaviour: 'modified sudo permissions (sudoers)', mitreTechniqueId: 'T1548' },
  { pattern: /\bchmod\s+(\S*\+s\b|[4-7][0-7]{3}\b)/, behaviour: 'set the SUID bit on a file', mitreTechniqueId: 'T1548' },
  { pattern: /\/etc\/shadow\b/, behaviour: 'read the password hash file /etc/shadow', mitreTechniqueId: 'T1003' },
  {
    pattern: /\busermod\b.*\s-a?G\s*\S*\b(sudo|wheel|admin)\b/,
    behaviour: 'added an account to an administrator group',
    mitreTechniqueId: 'T1098',
  },
  { pattern: /\bpasswd\s+root\b/, behaviour: "changed root's password", mitreTechniqueId: 'T1098' },
];

export function findPrivilegedOperation(command: string): PrivilegedOperation | undefined {
  return PRIVILEGED_OPERATIONS.find((operation) => operation.pattern.test(command));
}

export const privilegeEscalation: DetectionRuleDefinition = {
  code: 'R004',
  name: 'Privilege Escalation',
  description:
    'A non-privileged account runs a command that grants or abuses root access (root shell via sudo, sudoers or SUID changes, admin group changes, /etc/shadow access).',
  severity: 'CRITICAL',
  mitreTechniqueIds: ['T1548', 'T1059', 'T1098', 'T1003'],
  defaults: { threshold: null, windowMinutes: null },
  eventTypes: ['PROCESS_EXECUTION'],
  recommendedSteps: [
    'Confirm the exact command and whether it succeeded.',
    'Find out how the account obtained elevation: sudoers entry, misconfiguration or exploit.',
    'Check whether this account was recently the target of a brute-force or suspicious login.',
    "Review the account's recent activity for staging steps (downloads, new tools, new cron jobs).",
    'If unauthorised: isolate the host, disable the account and escalate to an incident.',
  ],

  async evaluate(event) {
    const command = readMetadataString(event, 'command');
    if (!command || !event.username || isPrivilegedAccount(event.username)) return null;

    const operation = findPrivilegedOperation(command);
    if (!operation) return null;

    const host = event.hostname ?? 'unknown host';
    return {
      title: `Privilege escalation by ${event.username} on ${host}`,
      description: `Non-privileged account "${event.username}" ${operation.behaviour} on ${host}. Command: ${command}`,
      dedupKey: `user:${event.username}|host:${host}`,
      evidenceEventIds: [],
      evidence: { account: event.username, host, command, behaviour: operation.behaviour },
      mitreTechniqueId: operation.mitreTechniqueId,
    };
  },
};
