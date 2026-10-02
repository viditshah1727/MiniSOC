// Risk scoring: turns an alert into one 0-100 number an analyst can sort by,
// and records every point so the UI can show exactly why.
//
//   base score from severity   LOW 20 · MEDIUM 40 · HIGH 70 · CRITICAL 90
//   + 10  repeated activity    (source IP already alerted in the last 24 h)
//   + 10  known malicious IP   (threat intelligence says MALICIOUS)
//   + 10  privileged account   (root, admin, ...)
//   capped at 100
//
// Kept as a pure function (no database access) so it is trivial to unit-test.
import type { Severity } from '../generated/prisma/enums.js';
import { REPEATED_ACTIVITY_HOURS } from './constants.js';

export const BASE_SCORES: Record<Severity, number> = {
  INFO: 10,
  LOW: 20,
  MEDIUM: 40,
  HIGH: 70,
  CRITICAL: 90,
};
export const MODIFIER_POINTS = 10;
export const MAX_RISK_SCORE = 100;

export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

// A type alias (not an interface) so it can be stored in a JSON column as-is.
export type RiskFactor = { label: string; points: number };

export interface RiskInput {
  severity: Severity;
  repeatedActivity: boolean;
  /** The indicator value when threat intelligence marks it MALICIOUS. */
  maliciousIndicator: string | null;
  /** The account name when it is a privileged account. */
  privilegedAccount: string | null;
}

export interface RiskResult {
  score: number;
  level: RiskLevel;
  /** Every contribution; the points always add up to `score`. */
  factors: RiskFactor[];
}

export function calculateRiskScore(input: RiskInput): RiskResult {
  const factors: RiskFactor[] = [
    { label: `Base score for ${input.severity} severity`, points: BASE_SCORES[input.severity] },
  ];
  if (input.repeatedActivity) {
    factors.push({
      label: `Repeated activity: this source already triggered alerts in the last ${REPEATED_ACTIVITY_HOURS} hours`,
      points: MODIFIER_POINTS,
    });
  }
  if (input.maliciousIndicator) {
    factors.push({ label: `Known malicious indicator: ${input.maliciousIndicator}`, points: MODIFIER_POINTS });
  }
  if (input.privilegedAccount) {
    factors.push({ label: `Privileged account involved: ${input.privilegedAccount}`, points: MODIFIER_POINTS });
  }

  const total = factors.reduce((sum, factor) => sum + factor.points, 0);
  if (total > MAX_RISK_SCORE) {
    factors.push({ label: `Capped at the maximum of ${MAX_RISK_SCORE}`, points: MAX_RISK_SCORE - total });
  }
  const score = Math.min(total, MAX_RISK_SCORE);
  return { score, level: riskLevel(score), factors };
}

/** 0-30 Low · 31-60 Medium · 61-80 High · 81-100 Critical */
export function riskLevel(score: number): RiskLevel {
  if (score <= 30) return 'LOW';
  if (score <= 60) return 'MEDIUM';
  if (score <= 80) return 'HIGH';
  return 'CRITICAL';
}
