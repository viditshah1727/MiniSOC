// CSV exports for alerts, events and an incident summary. Each export honours
// the same filters as its list page, capped so one request cannot dump the
// whole database into memory.
import { prisma } from '../db.js';
import { riskLevel } from '../detection/riskScore.js';
import type { AlertFilter } from '../schemas/alerts.js';
import type { EventFilter } from '../schemas/events.js';
import type { IncidentFilter } from '../schemas/incidents.js';
import { toCsv } from '../utils/csv.js';
import { alertOrder, buildAlertFilter } from './alertService.js';
import { buildEventFilter } from './eventService.js';
import { buildIncidentFilter } from './incidentService.js';

export const MAX_EXPORT_ROWS = 10_000;

export async function alertsCsv(filter: AlertFilter): Promise<string> {
  const alerts = await prisma.alert.findMany({
    where: buildAlertFilter(filter),
    orderBy: alertOrder(filter.sort),
    take: MAX_EXPORT_ROWS,
    include: { rule: { select: { code: true, name: true } } },
  });
  return toCsv(
    ['id', 'detected_at', 'severity', 'risk_score', 'risk_level', 'status', 'rule', 'title', 'source_ip', 'hostname', 'username', 'mitre_technique', 'incident_id'],
    alerts.map((a) => [
      a.id,
      a.detectedAt,
      a.severity,
      a.riskScore,
      riskLevel(a.riskScore),
      a.status,
      `${a.rule.code} ${a.rule.name}`,
      a.title,
      a.sourceIp,
      a.hostname,
      a.username,
      a.mitreTechniqueId,
      a.incidentId,
    ]),
  );
}

export async function eventsCsv(filter: EventFilter): Promise<string> {
  const events = await prisma.event.findMany({
    where: buildEventFilter(filter),
    orderBy: [{ timestamp: 'desc' }, { id: 'desc' }],
    take: MAX_EXPORT_ROWS,
  });
  return toCsv(
    ['id', 'timestamp', 'source', 'event_type', 'severity', 'source_ip', 'destination_ip', 'destination_port', 'hostname', 'username', 'message'],
    events.map((e) => [
      e.id,
      e.timestamp,
      e.source,
      e.eventType,
      e.severity,
      e.sourceIp,
      e.destinationIp,
      e.destinationPort,
      e.hostname,
      e.username,
      e.message,
    ]),
  );
}

/** One row per incident, including how long it took to resolve. */
export async function incidentsCsv(filter: IncidentFilter): Promise<string> {
  const incidents = await prisma.incident.findMany({
    where: buildIncidentFilter(filter),
    orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
    take: MAX_EXPORT_ROWS,
    include: { assignee: { select: { name: true } }, _count: { select: { alerts: true } } },
  });
  return toCsv(
    ['id', 'title', 'severity', 'status', 'assignee', 'alert_count', 'created_at', 'resolved_at', 'hours_to_resolve'],
    incidents.map((i) => [
      i.id,
      i.title,
      i.severity,
      i.status,
      i.assignee?.name ?? 'Unassigned',
      i._count.alerts,
      i.createdAt,
      i.resolvedAt,
      i.resolvedAt ? ((i.resolvedAt.getTime() - i.createdAt.getTime()) / 3_600_000).toFixed(1) : null,
    ]),
  );
}
