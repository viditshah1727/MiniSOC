import { z } from 'zod';
import { AlertStatus, Severity } from '../generated/prisma/enums.js';
import { ipSchema, paginationSchema, searchSchema } from './common.js';

export const alertFilterSchema = z.object({
  status: z.enum(AlertStatus).optional(),
  severity: z.enum(Severity).optional(),
  ruleCode: z
    .string()
    .regex(/^R\d{3}$/, 'must look like R001')
    .optional(),
  mitreTechniqueId: z
    .string()
    .regex(/^T\d{4}(\.\d{3})?$/, 'must look like T1110')
    .optional(),
  sourceIp: ipSchema.optional(),
  q: searchSchema,
  sort: z.enum(['recent', 'risk']).default('recent'),
});

export const alertQuerySchema = paginationSchema.extend(alertFilterSchema.shape);

export type AlertFilter = z.output<typeof alertFilterSchema>;
export type AlertQuery = z.output<typeof alertQuerySchema>;

/** PATCH /api/alerts/:id: change the status, add a note, or both. */
export const alertUpdateSchema = z
  .object({
    status: z.enum(AlertStatus).optional(),
    note: z.string().trim().min(1).max(2000).optional(),
  })
  .refine((body) => body.status !== undefined || body.note !== undefined, {
    message: 'Provide a status, a note, or both',
  });

export type AlertUpdateInput = z.output<typeof alertUpdateSchema>;
