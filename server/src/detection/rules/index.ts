// The rule registry. To add a detection: write a file implementing
// DetectionRuleDefinition, then add it to this list. On the next start the
// server syncs it into the detection_rules table and the engine runs it.
import type { DetectionRuleDefinition } from '../types.js';
import { bruteForceSuccess } from './bruteForceSuccess.js';
import { portScan } from './portScan.js';
import { privilegeEscalation } from './privilegeEscalation.js';
import { sshBruteForce } from './sshBruteForce.js';
import { suspiciousLogin } from './suspiciousLogin.js';
import { threatIntelMatch } from './threatIntelMatch.js';

export const DETECTION_RULES: DetectionRuleDefinition[] = [
  sshBruteForce, // R001
  portScan, // R002
  suspiciousLogin, // R003
  privilegeEscalation, // R004
  bruteForceSuccess, // R005
  threatIntelMatch, // R006
];

const rulesByCode = new Map(DETECTION_RULES.map((rule) => [rule.code, rule]));

export function getRuleDefinition(code: string): DetectionRuleDefinition | undefined {
  return rulesByCode.get(code);
}
