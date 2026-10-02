// Security events: ingestion (store + detect) and querying.
import { prisma } from '../db.js';
import { runDetection } from '../detection/engine.js';
import type { Prisma } from '../generated/prisma/client.js';
import type { EventFilter, EventQuery, ValidEventInput } from '../schemas/events.js';
import { notFound } from '../utils/AppError.js';
import { publishLiveUpdate } from '../utils/liveUpdates.js';

/**
 * The core SOC pipeline for one event:
 *   validated input ─▶ stored in PostgreSQL ─▶ detection rules ─▶ alerts
 */
export async function ingestEvent(input: ValidEventInput) {
  const event = await prisma.event.create({
    data: { ...input, timestamp: input.timestamp ?? new Date() },
  });
  const alerts = await runDetection(event);

  publishLiveUpdate({ type: 'event.created', id: event.id });
  return { event, alerts };
}

/** Filters shared by the events list and the CSV export. */
export function buildEventFilter(query: EventFilter): Prisma.EventWhereInput {
  return {
    severity: query.severity,
    eventType: query.eventType,
    sourceIp: query.sourceIp,
    timestamp: { gte: query.from, lte: query.to },
    OR: query.q
      ? [
          { message: { contains: query.q, mode: 'insensitive' } },
          { username: { contains: query.q, mode: 'insensitive' } },
          { hostname: { contains: query.q, mode: 'insensitive' } },
          { source: { contains: query.q, mode: 'insensitive' } },
        ]
      : undefined,
  };
}

export async function listEvents(query: EventQuery) {
  const where = buildEventFilter(query);
  const [rows, total] = await prisma.$transaction([
    prisma.event.findMany({
      where,
      orderBy: [{ timestamp: 'desc' }, { id: 'desc' }],
      skip: (query.page - 1) * query.pageSize,
      take: query.pageSize,
      include: { _count: { select: { evidenceFor: true } } },
    }),
    prisma.event.count({ where }),
  ]);

  // Expose "how many alerts is this event part of" under a friendlier name.
  const items = rows.map(({ _count, ...event }) => ({ ...event, alertCount: _count.evidenceFor }));
  return { items, total };
}

const alertSummary = {
  select: {
    id: true,
    title: true,
    severity: true,
    status: true,
    riskScore: true,
    detectedAt: true,
    rule: { select: { code: true, name: true } },
  },
} as const;

export async function getEvent(id: number) {
  const event = await prisma.event.findUnique({
    where: { id },
    include: { evidenceFor: { ...alertSummary, orderBy: { detectedAt: 'desc' } } },
  });
  if (!event) throw notFound('Event');

  const { evidenceFor, ...rest } = event;
  return { ...rest, alerts: evidenceFor };
}
