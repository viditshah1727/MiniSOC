// Incidents: an analyst escalates alerts into a tracked case, works it
// (assignment, notes, status) and resolves it.
//
//   OPEN ─▶ INVESTIGATING ─▶ RESOLVED ─▶ CLOSED
import { prisma } from '../db.js';
import type { Prisma } from '../generated/prisma/client.js';
import type { IncidentStatus } from '../generated/prisma/enums.js';
import type { IncidentCreateInput, IncidentFilter, IncidentQuery, IncidentUpdateInput } from '../schemas/incidents.js';
import type { AuthUser } from '../types/express.js';
import { badRequest, conflict, notFound } from '../utils/AppError.js';
import { publishLiveUpdate } from '../utils/liveUpdates.js';
import { highestSeverity } from '../utils/severity.js';
import { alertListSelect, withRiskLevel } from './alertService.js';

const DONE_STATUSES: IncidentStatus[] = ['RESOLVED', 'CLOSED'];

export function buildIncidentFilter(filter: IncidentFilter): Prisma.IncidentWhereInput {
  return {
    status: filter.status,
    severity: filter.severity,
    assigneeId: filter.assigneeId,
    OR: filter.q
      ? [
          { title: { contains: filter.q, mode: 'insensitive' } },
          { description: { contains: filter.q, mode: 'insensitive' } },
        ]
      : undefined,
  };
}

export const incidentListInclude = {
  assignee: { select: { id: true, name: true } },
  _count: { select: { alerts: true } },
} satisfies Prisma.IncidentInclude;

export async function listIncidents(query: IncidentQuery) {
  const where = buildIncidentFilter(query);
  const [rows, total] = await prisma.$transaction([
    prisma.incident.findMany({
      where,
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      skip: (query.page - 1) * query.pageSize,
      take: query.pageSize,
      include: incidentListInclude,
    }),
    prisma.incident.count({ where }),
  ]);
  const items = rows.map(({ _count, ...incident }) => ({ ...incident, alertCount: _count.alerts }));
  return { items, total };
}

export async function getIncidentDetail(id: number) {
  const incident = await prisma.incident.findUnique({
    where: { id },
    include: {
      assignee: { select: { id: true, name: true, email: true, role: true } },
      alerts: { select: alertListSelect, orderBy: { detectedAt: 'asc' } },
      activities: {
        orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
        include: { user: { select: { id: true, name: true } } },
      },
    },
  });
  if (!incident) throw notFound('Incident');

  // The raw evidence behind every linked alert, in time order.
  const events = await prisma.event.findMany({
    where: { evidenceFor: { some: { incidentId: id } } },
    orderBy: [{ timestamp: 'asc' }, { id: 'asc' }],
    take: 200,
  });

  return { ...incident, alerts: incident.alerts.map(withRiskLevel), events };
}

/** Only analysts and admins can own an incident. */
async function findAssignee(assigneeId: number) {
  const assignee = await prisma.user.findUnique({ where: { id: assigneeId }, select: { id: true, name: true, role: true } });
  if (!assignee || assignee.role === 'VIEWER') throw badRequest('Assignee must be an existing analyst or admin');
  return assignee;
}

/** Escalates alerts into a new incident. All-or-nothing: runs in one transaction. */
export async function createIncident(input: IncidentCreateInput, user: AuthUser) {
  const alertIds = [...new Set(input.alertIds)];
  const alerts = await prisma.alert.findMany({
    where: { id: { in: alertIds } },
    select: { id: true, title: true, description: true, severity: true, status: true, incidentId: true },
    orderBy: { detectedAt: 'asc' },
  });
  if (alerts.length !== alertIds.length) throw notFound('One or more alerts');
  const alreadyLinked = alerts.find((alert) => alert.incidentId !== null);
  if (alreadyLinked) {
    throw conflict(`Alert #${alreadyLinked.id} is already part of incident #${alreadyLinked.incidentId}`);
  }

  const assigneeId = input.assigneeId === undefined ? user.id : input.assigneeId;
  const assignee = assigneeId === null ? null : await findAssignee(assigneeId);
  // Defaults come from the most severe alert (the earliest one on a tie).
  const severity = highestSeverity(alerts.map((alert) => alert.severity));
  const primaryAlert = alerts.find((alert) => alert.severity === severity)!;

  const incident = await prisma.$transaction(async (tx) => {
    const created = await tx.incident.create({
      data: {
        title: input.title ?? primaryAlert.title,
        description: input.description ?? primaryAlert.description,
        severity: input.severity ?? severity,
        assigneeId: assignee?.id ?? null,
        activities: {
          createMany: {
            data: [
              { type: 'CREATED', message: `Incident created from ${alerts.length} alert(s)`, userId: user.id },
              ...alerts.map((alert) => ({
                type: 'ALERT_LINKED' as const,
                message: `Linked alert #${alert.id}: ${alert.title}`,
                userId: user.id,
              })),
              ...(assignee ? [{ type: 'ASSIGNMENT' as const, message: `Assigned to ${assignee.name}`, userId: user.id }] : []),
            ],
          },
        },
      },
    });

    for (const alert of alerts) {
      // Escalating means someone is now working the alert.
      const moveToInvestigating = alert.status === 'OPEN';
      await tx.alert.update({
        where: { id: alert.id },
        data: {
          incidentId: created.id,
          status: moveToInvestigating ? 'INVESTIGATING' : undefined,
          activities: {
            createMany: {
              data: [
                { type: 'ALERT_LINKED', message: `Escalated to incident #${created.id}`, userId: user.id },
                ...(moveToInvestigating
                  ? [{ type: 'STATUS_CHANGE' as const, message: 'Status changed from OPEN to INVESTIGATING', userId: user.id }]
                  : []),
              ],
            },
          },
        },
      });
    }
    return created;
  });

  publishLiveUpdate({ type: 'incident.created', id: incident.id, title: incident.title, severity: incident.severity });
  return getIncidentDetail(incident.id);
}

/** Status changes and (re)assignment. Resolving an incident resolves its open alerts. */
export async function updateIncident(id: number, input: IncidentUpdateInput, user: AuthUser) {
  const incident = await prisma.incident.findUnique({
    where: { id },
    select: { status: true, assigneeId: true, resolvedAt: true },
  });
  if (!incident) throw notFound('Incident');

  const data: Prisma.IncidentUncheckedUpdateInput = {};
  const activities: Prisma.ActivityCreateManyIncidentInput[] = [];

  const statusChanged = input.status !== undefined && input.status !== incident.status;
  if (statusChanged) {
    data.status = input.status;
    activities.push({ type: 'STATUS_CHANGE', message: `Status changed from ${incident.status} to ${input.status}`, userId: user.id });
    const isDone = DONE_STATUSES.includes(input.status!);
    if (isDone && !incident.resolvedAt) data.resolvedAt = new Date();
    if (!isDone) data.resolvedAt = null; // reopened
  }

  if (input.assigneeId !== undefined && input.assigneeId !== incident.assigneeId) {
    const assignee = input.assigneeId === null ? null : await findAssignee(input.assigneeId);
    data.assigneeId = assignee?.id ?? null;
    activities.push({
      type: 'ASSIGNMENT',
      message: assignee ? `Assigned to ${assignee.name}` : 'Unassigned',
      userId: user.id,
    });
  }

  if (activities.length === 0) throw badRequest('Nothing to update: values are unchanged');

  await prisma.$transaction(async (tx) => {
    await tx.incident.update({ where: { id }, data: { ...data, activities: { createMany: { data: activities } } } });

    if (statusChanged && DONE_STATUSES.includes(input.status!)) {
      const openAlerts = await tx.alert.findMany({
        where: { incidentId: id, status: { in: ['OPEN', 'INVESTIGATING'] } },
        select: { id: true, status: true },
      });
      for (const alert of openAlerts) {
        await tx.alert.update({
          where: { id: alert.id },
          data: {
            status: 'RESOLVED',
            activities: {
              create: {
                type: 'STATUS_CHANGE',
                message: `Status changed from ${alert.status} to RESOLVED (incident #${id} ${input.status!.toLowerCase()})`,
                userId: user.id,
              },
            },
          },
        });
      }
    }
  });

  if (statusChanged) publishLiveUpdate({ type: 'incident.updated', id, status: input.status! });
  return getIncidentDetail(id);
}

export async function addIncidentNote(id: number, content: string, user: AuthUser) {
  const exists = await prisma.incident.findUnique({ where: { id }, select: { id: true } });
  if (!exists) throw notFound('Incident');

  return prisma.activity.create({
    data: { incidentId: id, type: 'NOTE', message: content, userId: user.id },
    include: { user: { select: { id: true, name: true } } },
  });
}
