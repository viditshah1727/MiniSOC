// Keeps the database in step with the detection content defined in code:
// the MITRE ATT&CK reference list and the detection rules.
// Runs on server start (and in the seed). Safe to run repeatedly: it upserts,
// and it never overwrites what an admin tuned (enabled flag, threshold, window).
import { prisma } from '../db.js';
import { MITRE_TECHNIQUES } from './mitreTechniques.js';
import { DETECTION_RULES } from './rules/index.js';

export async function syncDetectionContent(): Promise<void> {
  for (const technique of MITRE_TECHNIQUES) {
    await prisma.mitreTechnique.upsert({ where: { id: technique.id }, create: technique, update: technique });
  }

  for (const rule of DETECTION_RULES) {
    const techniques = rule.mitreTechniqueIds.map((id) => ({ id }));
    const definition = {
      name: rule.name,
      description: rule.description,
      severity: rule.severity,
      recommendedSteps: rule.recommendedSteps,
    };
    await prisma.detectionRule.upsert({
      where: { code: rule.code },
      create: {
        code: rule.code,
        ...definition,
        threshold: rule.defaults.threshold,
        windowMinutes: rule.defaults.windowMinutes,
        techniques: { connect: techniques },
      },
      update: { ...definition, techniques: { set: techniques } },
    });
  }
}
