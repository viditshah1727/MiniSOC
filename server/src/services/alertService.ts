// Alerts: listing, the full investigation view, and analyst triage.
import { prisma } from '../db.js';
import { riskLevel } from '../detection/riskScore.js';
import type { Prisma } from '../generated/prisma/client.js';
import type { AlertFilter, AlertQuery, AlertUpdateInput } from '../schemas/alerts.js';
import type { AuthUser } from '../types/express.js';
import { badRequest, notFound } from '../utils/AppError.js';
import { publishLiveUpdate } from '../utils/liveUpdates.js';

/** The columns every alert list shows. */
export const alertListSelect = {
  id: true,
  title: true,
  severity: true,
  status: true,
  riskScore: true,
  sourceIp: true,
  hostname: true,
  username: true,
  detectedAt: true,
  incidentId: true,
  rule: { select: { code: true, name: true } },
  mitreTechnique: { select: { id: true, name: true } },
  threatIntel: { select: { reputation: true } },
} satisfies Prisma.AlertSelect;

/** Adds the risk category (LOW..CRITICAL) next to the numeric score. */
export function withRiskLevel<T extends { riskScore: number }>(alert: T) {
  return { ...alert, riskLevel: riskLevel(alert.riskScore) };
}

/** Filters shared by the alert list and the CSV export. */
export function buildAlertFilter(filter: AlertFilter): Prisma.AlertWhereInput {
  return {
    status: filter.status,
    severity: filter.severity,
    rule: filter.ruleCode ? { code: filter.ruleCode } : undefined,
    mitreTechniqueId: filter.mitreTechniqueId,
    sourceIp: filter.sourceIp,
    OR: filter.q
      ? [
          { title: { contains: filter.q, mode: 'insensitive' } },
          { description: { contains: filter.q, mode: 'insensitive' } },
          { hostname: { contains: filter.q, mode: 'insensitive' } },
          { username: { contains: filter.q, mode: 'insensitive' } },
        ]
      : undefined,
  };
}

export function alertOrder(sort: AlertFilter['sort']): Prisma.AlertOrderByWithRelationInput[] {
  return sort === 'risk'
    ? [{ riskScore: 'desc' }, { detectedAt: 'desc' }]
    : [{ detectedAt: 'desc' }, { id: 'desc' }];
}

export async function listAlerts(query: AlertQuery) {
  const where = buildAlertFilter(query);
  const [rows, total] = await prisma.$transaction([
    prisma.alert.findMany({
      where,
      orderBy: alertOrder(query.sort),
      skip: (query.page - 1) * query.pageSize,
      take: query.pageSize,
      select: alertListSelect,
    }),
    prisma.alert.count({ where }),
  ]);
  return { items: rows.map(withRiskLevel), total };
}

/** Everything the investigation page needs to explain why the alert exists. */
export async function getAlertDetail(id: number) {
  const alert = await prisma.alert.findUnique({
    where: { id },
    include: {
      rule: { include: { techniques: { select: { id: true, name: true, tactics: true } } } },
      mitreTechnique: true,
      threatIntel: true,
      event: true,
      evidenceEvents: { orderBy: [{ timestamp: 'asc' }, { id: 'asc' }] },
      incident: { select: { id: true, title: true, status: true, severity: true } },
      activities: {
        orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
        include: { user: { select: { id: true, name: true } } },
      },
    },
  });
  if (!alert) throw notFound('Alert');

  // The pivot every analyst does first: what else has this source done?
  const relatedAlerts = alert.sourceIp
    ? await prisma.alert.findMany({
        where: { sourceIp: alert.sourceIp, id: { not: alert.id } },
        orderBy: { detectedAt: 'desc' },
        take: 10,
        select: alertListSelect,
      })
    : [];

  return { ...withRiskLevel(alert), relatedAlerts: relatedAlerts.map(withRiskLevel) };
}

/** Analyst triage: change status (investigate / resolve / false positive) and/or add a note. */
export async function updateAlert(id: number, input: AlertUpdateInput, user: AuthUser) {
  const alert = await prisma.alert.findUnique({ where: { id }, select: { status: true } });
  if (!alert) throw notFound('Alert');

  const statusChanged = input.status !== undefined && input.status !== alert.status;
  if (!statusChanged && !input.note) throw badRequest(`Alert is already ${alert.status}`);

  const activities: Prisma.ActivityCreateManyAlertInput[] = [];
  if (statusChanged) {
    activities.push({ type: 'STATUS_CHANGE', message: `Status changed from ${alert.status} to ${input.status}`, userId: user.id });
  }
  if (input.note) {
    activities.push({ type: 'NOTE', message: input.note, userId: user.id });
  }

  const updated = await prisma.alert.update({
    where: { id },
    // createMany = one INSERT, so the timeline keeps this order.
    data: { status: statusChanged ? input.status : undefined, activities: { createMany: { data: activities } } },
    select: { status: true },
  });

  if (statusChanged) publishLiveUpdate({ type: 'alert.updated', id, status: updated.status });
  return getAlertDetail(id);
}
