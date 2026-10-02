import { z } from 'zod';
import { IncidentStatus, Severity } from '../generated/prisma/enums.js';
import { paginationSchema, searchSchema } from './common.js';

const userId = z.number().int().positive();

/** POST /api/incidents: escalate one or more alerts into an incident. */
export const incidentCreateSchema = z.object({
  alertIds: z.array(z.number().int().positive()).min(1, 'select at least one alert').max(50),
  title: z.string().trim().min(3).max(200).optional(), // default: the first alert's title
  description: z.string().trim().max(5000).optional(),
  severity: z.enum(Severity).optional(), // default: the most severe linked alert
  assigneeId: userId.nullable().optional(), // default: whoever creates it; null = unassigned
});

/** PATCH /api/incidents/:id */
export const incidentUpdateSchema = z
  .object({
    status: z.enum(IncidentStatus).optional(),
    assigneeId: userId.nullable().optional(),
  })
  .refine((body) => body.status !== undefined || body.assigneeId !== undefined, {
    message: 'Provide a status and/or an assigneeId',
  });

/** POST /api/incidents/:id/notes */
export const incidentNoteSchema = z.object({
  content: z.string().trim().min(1, 'is required').max(5000),
});

export const incidentFilterSchema = z.object({
  status: z.enum(IncidentStatus).optional(),
  severity: z.enum(Severity).optional(),
  assigneeId: z.coerce.number().int().positive().optional(),
  q: searchSchema,
});

export const incidentQuerySchema = paginationSchema.extend(incidentFilterSchema.shape);

export type IncidentCreateInput = z.output<typeof incidentCreateSchema>;
export type IncidentUpdateInput = z.output<typeof incidentUpdateSchema>;
export type IncidentFilter = z.output<typeof incidentFilterSchema>;
export type IncidentQuery = z.output<typeof incidentQuerySchema>;
