// MITRE ATT&CK view: each technique with the rules that detect it and how
// often it has been seen. Techniques without rules are coverage gaps.
import { prisma } from '../db.js';
import { TACTIC_ORDER } from '../detection/mitreTechniques.js';

function killChainPosition(tactics: string[]): number {
  const index = TACTIC_ORDER.indexOf(tactics[0] ?? '');
  return index === -1 ? TACTIC_ORDER.length : index;
}

export async function listTechniques() {
  const [techniques, alertCounts, openAlertCounts] = await Promise.all([
    prisma.mitreTechnique.findMany({
      include: {
        rules: { select: { id: true, code: true, name: true, enabled: true }, orderBy: { code: 'asc' } },
      },
    }),
    prisma.alert.groupBy({ by: ['mitreTechniqueId'], _count: { _all: true } }),
    prisma.alert.groupBy({
      by: ['mitreTechniqueId'],
      where: { status: { in: ['OPEN', 'INVESTIGATING'] } },
      _count: { _all: true },
    }),
  ]);

  const countFor = (rows: typeof alertCounts, id: string) =>
    rows.find((row) => row.mitreTechniqueId === id)?._count._all ?? 0;

  return techniques
    .map((technique) => ({
      ...technique,
      alertCount: countFor(alertCounts, technique.id),
      openAlertCount: countFor(openAlertCounts, technique.id),
    }))
    .sort((a, b) => killChainPosition(a.tactics) - killChainPosition(b.tactics) || a.id.localeCompare(b.id));
}
