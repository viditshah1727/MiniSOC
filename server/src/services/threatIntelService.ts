// Threat intelligence: a local database of known indicators (IPs, domains,
// file hashes) with a reputation. Used to enrich alerts and by rule R006.
// Data is seeded locally; the same table could be filled by a feed importer
// (AbuseIPDB, MISP, OTX, ...) without changing the detection code.
import { prisma } from '../db.js';
import type { IndicatorType } from '../generated/prisma/enums.js';
import type { IndicatorCreateInput, IndicatorQuery } from '../schemas/threatIntel.js';
import { conflict } from '../utils/AppError.js';

/** Indicators are stored trimmed and lowercase so lookups are exact matches. */
export function normalizeIndicator(value: string): string {
  return value.trim().toLowerCase();
}

export function findIndicator(type: IndicatorType, value: string) {
  return prisma.threatIntelligence.findUnique({
    where: { indicator_type: { indicator: normalizeIndicator(value), type } },
  });
}

export async function findIpIndicator(ip: string | null | undefined) {
  return ip ? findIndicator('IP', ip) : null;
}

export async function listIndicators(query: IndicatorQuery) {
  const where = {
    type: query.type,
    reputation: query.reputation,
    OR: query.q
      ? [
          { indicator: { contains: query.q, mode: 'insensitive' as const } },
          { description: { contains: query.q, mode: 'insensitive' as const } },
          { source: { contains: query.q, mode: 'insensitive' as const } },
        ]
      : undefined,
  };
  const [rows, total] = await prisma.$transaction([
    prisma.threatIntelligence.findMany({
      where,
      orderBy: [{ lastSeen: 'desc' }, { id: 'desc' }],
      skip: (query.page - 1) * query.pageSize,
      take: query.pageSize,
      include: { _count: { select: { alerts: true } } },
    }),
    prisma.threatIntelligence.count({ where }),
  ]);
  const items = rows.map(({ _count, ...indicator }) => ({ ...indicator, alertCount: _count.alerts }));
  return { items, total };
}

export async function createIndicator(input: IndicatorCreateInput) {
  const indicator = normalizeIndicator(input.indicator);
  if (await findIndicator(input.type, indicator)) {
    throw conflict(`${input.type} indicator ${indicator} already exists`);
  }

  const now = new Date();
  return prisma.threatIntelligence.create({
    data: {
      ...input,
      indicator,
      firstSeen: input.firstSeen ?? input.lastSeen ?? now,
      lastSeen: input.lastSeen ?? now,
    },
  });
}
