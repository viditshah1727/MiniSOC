import { z } from 'zod';
import { EventType, Severity } from '../generated/prisma/enums.js';
import { ipSchema, paginationSchema, searchSchema } from './common.js';

const CLOCK_SKEW_MS = 5 * 60 * 1000; // tolerate log sources whose clocks run slightly fast

/**
 * Source-specific details. The keys the detection rules rely on are validated;
 * any other JSON the log source sends is kept as-is.
 */
const metadataSchema = z
  .object({
    service: z.string().max(64).optional(), // e.g. "ssh", "vpn"
    command: z.string().max(2000).optional(), // PROCESS_EXECUTION
    processName: z.string().max(256).optional(),
    domain: z.string().max(253).optional(), // DNS_QUERY
    url: z.string().max(2048).optional(), // FILE_DOWNLOAD
    fileName: z.string().max(256).optional(),
    sha256: z
      .string()
      .regex(/^[a-fA-F0-9]{64}$/, 'must be a 64-character hex SHA-256 hash')
      .optional(),
  })
  .catchall(z.json());

/** Body of POST /api/events: one security event from a log source. */
export const eventInputSchema = z.object({
  timestamp: z.iso
    .datetime({ offset: true })
    .transform((value) => new Date(value))
    .refine((date) => date.getTime() <= Date.now() + CLOCK_SKEW_MS, 'cannot be in the future')
    .optional(),
  source: z.string().trim().min(1).max(64),
  eventType: z.enum(EventType),
  severity: z.enum(Severity).default('INFO'),
  sourceIp: ipSchema.optional(),
  destinationIp: ipSchema.optional(),
  destinationPort: z.number().int().min(0).max(65535).optional(),
  hostname: z.string().trim().min(1).max(255).optional(),
  username: z.string().trim().min(1).max(128).optional(),
  message: z.string().trim().min(1).max(2000),
  metadata: metadataSchema.optional(),
});

export type EventInput = z.input<typeof eventInputSchema>;
export type ValidEventInput = z.output<typeof eventInputSchema>;

/** Filters for the events list and the events CSV export. */
export const eventFilterSchema = z.object({
  severity: z.enum(Severity).optional(),
  eventType: z.enum(EventType).optional(),
  sourceIp: ipSchema.optional(),
  from: z.coerce.date().optional(),
  to: z.coerce.date().optional(),
  q: searchSchema,
});

/** Query string of GET /api/events. */
export const eventQuerySchema = paginationSchema.extend(eventFilterSchema.shape);

export type EventFilter = z.output<typeof eventFilterSchema>;
export type EventQuery = z.output<typeof eventQuerySchema>;
