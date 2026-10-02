import { z } from 'zod';
import { IndicatorType, Reputation } from '../generated/prisma/enums.js';
import { ipSchema, paginationSchema, searchSchema } from './common.js';

const domainSchema = z
  .string()
  .trim()
  .toLowerCase()
  .regex(/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/, 'must be a valid domain name');

const sha256Schema = z
  .string()
  .trim()
  .toLowerCase()
  .regex(/^[a-f0-9]{64}$/, 'must be a SHA-256 hash (64 hex characters)');

const commonFields = {
  reputation: z.enum(Reputation),
  confidence: z.number().int().min(0).max(100),
  source: z.string().trim().min(1).max(100),
  description: z.string().trim().max(500).optional(),
  firstSeen: z.coerce.date().optional(),
  lastSeen: z.coerce.date().optional(),
};

/** POST /api/threat-intelligence: the indicator format depends on its type. */
export const indicatorCreateSchema = z
  .discriminatedUnion('type', [
    z.object({ type: z.literal('IP'), indicator: ipSchema, ...commonFields }),
    z.object({ type: z.literal('DOMAIN'), indicator: domainSchema, ...commonFields }),
    z.object({ type: z.literal('HASH'), indicator: sha256Schema, ...commonFields }),
  ])
  .refine((body) => !body.firstSeen || !body.lastSeen || body.firstSeen <= body.lastSeen, {
    message: 'firstSeen must be before lastSeen',
    path: ['firstSeen'],
  });

export type IndicatorCreateInput = z.output<typeof indicatorCreateSchema>;

export const indicatorFilterSchema = z.object({
  type: z.enum(IndicatorType).optional(),
  reputation: z.enum(Reputation).optional(),
  q: searchSchema,
});

export const indicatorQuerySchema = paginationSchema.extend(indicatorFilterSchema.shape);

export type IndicatorQuery = z.output<typeof indicatorQuerySchema>;
