// Pure unit tests for the scoring formula (no database needed).
import { describe, expect, it } from 'vitest';
import { calculateRiskScore, riskLevel } from '../src/detection/riskScore.js';

const noModifiers = { repeatedActivity: false, maliciousIndicator: null, privilegedAccount: null };

describe('calculateRiskScore', () => {
  it.each([
    ['LOW', 20],
    ['MEDIUM', 40],
    ['HIGH', 70],
    ['CRITICAL', 90],
  ] as const)('uses the base score for %s severity', (severity, expected) => {
    const result = calculateRiskScore({ severity, ...noModifiers });
    expect(result.score).toBe(expected);
    expect(result.factors).toHaveLength(1);
  });

  it('adds 10 points per modifier and explains each one', () => {
    const result = calculateRiskScore({
      severity: 'MEDIUM',
      repeatedActivity: true,
      maliciousIndicator: '203.0.113.45',
      privilegedAccount: 'root',
    });

    expect(result.score).toBe(70);
    expect(result.level).toBe('HIGH');
    expect(result.factors.map((f) => f.points)).toEqual([40, 10, 10, 10]);
    expect(result.factors[2]!.label).toContain('203.0.113.45');
    expect(result.factors[3]!.label).toContain('root');
  });

  it('caps at 100 with a balancing factor so the breakdown still adds up', () => {
    const result = calculateRiskScore({
      severity: 'CRITICAL',
      repeatedActivity: true,
      maliciousIndicator: '203.0.113.45',
      privilegedAccount: 'root',
    });

    expect(result.score).toBe(100);
    expect(result.factors.reduce((sum, f) => sum + f.points, 0)).toBe(100);
    expect(result.factors.at(-1)).toEqual({ label: 'Capped at the maximum of 100', points: -20 });
  });
});

describe('riskLevel', () => {
  it.each([
    [0, 'LOW'],
    [30, 'LOW'],
    [31, 'MEDIUM'],
    [60, 'MEDIUM'],
    [61, 'HIGH'],
    [80, 'HIGH'],
    [81, 'CRITICAL'],
    [100, 'CRITICAL'],
  ] as const)('maps %i to %s', (score, level) => {
    expect(riskLevel(score)).toBe(level);
  });
});
