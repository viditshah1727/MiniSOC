// Detection rule management: list rules with their activity, and let an admin
// enable/disable or tune them without a code change.
import { prisma } from '../db.js';
import { getRuleDefinition } from '../detection/rules/index.js';
import type { RuleUpdateInput } from '../schemas/rules.js';
import type { AuthUser } from '../types/express.js';
import { badRequest, notFound } from '../utils/AppError.js';
import { logger } from '../utils/logger.js';

export async function listRules() {
  const [rules, alertCounts] = await Promise.all([
    prisma.detectionRule.findMany({
      orderBy: { code: 'asc' },
      include: { techniques: { select: { id: true, name: true } } },
    }),
    prisma.alert.groupBy({ by: ['ruleId'], _count: { _all: true } }),
  ]);

  return rules.map((rule) => {
    const definition = getRuleDefinition(rule.code);
    return {
      ...rule,
      alertCount: alertCounts.find((row) => row.ruleId === rule.id)?._count._all ?? 0,
      thresholdLabel: definition?.thresholdLabel ?? null,
      // Which settings this rule actually uses (single-event rules have none).
      tunable: {
        threshold: definition?.defaults.threshold !== null,
        windowMinutes: definition?.defaults.windowMinutes !== null,
      },
    };
  });
}

export async function updateRule(id: number, input: RuleUpdateInput, user: AuthUser) {
  const rule = await prisma.detectionRule.findUnique({ where: { id } });
  if (!rule) throw notFound('Detection rule');

  const definition = getRuleDefinition(rule.code);
  if (input.threshold !== undefined && definition?.defaults.threshold === null) {
    throw badRequest(`${rule.code} does not use a threshold`);
  }
  if (input.windowMinutes !== undefined && definition?.defaults.windowMinutes === null) {
    throw badRequest(`${rule.code} does not use a time window`);
  }

  // Changing detection logic is security-relevant: keep a record of who did it.
  logger.info(`Detection rule ${rule.code} updated by ${user.email}`, input);
  await prisma.detectionRule.update({ where: { id }, data: input });

  const rules = await listRules();
  return rules.find((r) => r.id === id)!;
}
