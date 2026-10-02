import { z } from 'zod';

const NINETY_DAYS_IN_MINUTES = 90 * 24 * 60;

/** PATCH /api/rules/:id (admin only): switch a rule on/off or tune it. */
export const ruleUpdateSchema = z
  .object({
    enabled: z.boolean().optional(),
    threshold: z.number().int().min(1).max(1000).optional(),
    windowMinutes: z.number().int().min(1).max(NINETY_DAYS_IN_MINUTES).optional(),
  })
  .refine((body) => Object.values(body).some((value) => value !== undefined), {
    message: 'Provide enabled, threshold and/or windowMinutes',
  });

export type RuleUpdateInput = z.output<typeof ruleUpdateSchema>;
