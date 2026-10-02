// Dashboard: every number on the SOC overview, computed in one request.
import { prisma } from '../db.js';
import { riskLevel } from '../detection/riskScore.js';
import type { AlertStatus, IncidentStatus, Severity } from '../generated/prisma/enums.js';
import { alertListSelect, withRiskLevel } from './alertService.js';
import { incidentListInclude } from './incidentService.js';

/** Chart ranges: how many time buckets, and how wide each one is. */
export const DASHBOARD_RANGES = {
  '24h': { bucketMinutes: 60, buckets: 24 },
  '7d': { bucketMinutes: 6 * 60, buckets: 28 },
} as const;
export type DashboardRange = keyof typeof DASHBOARD_RANGES;

const ACTIVE_ALERT_STATUSES: AlertStatus[] = ['OPEN', 'INVESTIGATING'];
const ACTIVE_INCIDENT_STATUSES: IncidentStatus[] = ['OPEN', 'INVESTIGATING'];
const CHART_SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

export async function getDashboardStats(range: DashboardRange) {
  const { bucketMinutes, buckets } = DASHBOARD_RANGES[range];
  const bucketMs = bucketMinutes * 60_000;
  // Align buckets to clock boundaries so the chart does not shift every second.
  const currentBucketStart = Math.floor(Date.now() / bucketMs) * bucketMs;
  const since = new Date(currentBucketStart - (buckets - 1) * bucketMs);

  const [kpis, eventsOverTime, alertsBySeverity, topSourceIps, detectionsByRule, recent] = await Promise.all([
    getKpis(since),
    getActivityOverTime(since, bucketMinutes, buckets),
    getAlertsBySeverity(since),
    getTopSourceIps(since),
    getDetectionsByRule(since),
    getRecentActivity(),
  ]);

  return { range, since, kpis, eventsOverTime, alertsBySeverity, topSourceIps, detectionsByRule, ...recent };
}

async function getKpis(since: Date) {
  const activeAlerts = { status: { in: ACTIVE_ALERT_STATUSES } };
  const [totalEvents, eventsInRange, totalAlerts, openAlerts, criticalOpenAlerts, openIncidents] = await Promise.all([
    prisma.event.count(),
    prisma.event.count({ where: { timestamp: { gte: since } } }),
    prisma.alert.count(),
    prisma.alert.aggregate({ where: activeAlerts, _count: { _all: true }, _avg: { riskScore: true } }),
    prisma.alert.count({ where: { ...activeAlerts, severity: 'CRITICAL' } }),
    prisma.incident.count({ where: { status: { in: ACTIVE_INCIDENT_STATUSES } } }),
  ]);

  // Overall risk = average risk score of the alerts nobody has closed yet.
  const overallScore = Math.round(openAlerts._avg.riskScore ?? 0);
  return {
    totalEvents,
    eventsInRange,
    totalAlerts,
    openAlerts: openAlerts._count._all,
    criticalOpenAlerts,
    openIncidents,
    overallRisk: { score: overallScore, level: riskLevel(overallScore) },
  };
}

type BucketRow = { bucket: Date; count: number };

/** Events and alerts per time bucket. date_bin() does the bucketing inside PostgreSQL. */
async function getActivityOverTime(since: Date, bucketMinutes: number, buckets: number) {
  const [eventRows, alertRows] = await Promise.all([
    prisma.$queryRaw<BucketRow[]>`
      SELECT date_bin(make_interval(mins => ${bucketMinutes}::int), "timestamp", ${since}::timestamptz) AS bucket,
             count(*)::int AS count
      FROM events
      WHERE "timestamp" >= ${since}::timestamptz
      GROUP BY bucket`,
    prisma.$queryRaw<BucketRow[]>`
      SELECT date_bin(make_interval(mins => ${bucketMinutes}::int), detected_at, ${since}::timestamptz) AS bucket,
             count(*)::int AS count
      FROM alerts
      WHERE detected_at >= ${since}::timestamptz
      GROUP BY bucket`,
  ]);

  const toMap = (rows: BucketRow[]) => new Map(rows.map((row) => [new Date(row.bucket).getTime(), row.count]));
  const events = toMap(eventRows);
  const alerts = toMap(alertRows);

  // Fill empty buckets with zeros so the chart has a continuous x-axis.
  return Array.from({ length: buckets }, (_, i) => {
    const start = since.getTime() + i * bucketMinutes * 60_000;
    return { bucket: new Date(start).toISOString(), events: events.get(start) ?? 0, alerts: alerts.get(start) ?? 0 };
  });
}

async function getAlertsBySeverity(since: Date) {
  const rows = await prisma.alert.groupBy({
    by: ['severity'],
    where: { detectedAt: { gte: since } },
    _count: { _all: true },
  });
  return CHART_SEVERITIES.map((severity) => ({
    severity,
    count: rows.find((row) => row.severity === severity)?._count._all ?? 0,
  }));
}

/** The source IPs behind the most alerts, with their event volume and reputation. */
async function getTopSourceIps(since: Date) {
  const rows = await prisma.alert.groupBy({
    by: ['sourceIp'],
    where: { detectedAt: { gte: since }, sourceIp: { not: null } },
    _count: { _all: true },
    orderBy: { _count: { sourceIp: 'desc' } },
    take: 8,
  });
  const ips = rows.map((row) => row.sourceIp).filter((ip): ip is string => ip !== null);

  const [eventRows, intel] = await Promise.all([
    prisma.event.groupBy({
      by: ['sourceIp'],
      where: { sourceIp: { in: ips }, timestamp: { gte: since } },
      _count: { _all: true },
    }),
    prisma.threatIntelligence.findMany({
      where: { type: 'IP', indicator: { in: ips } },
      select: { indicator: true, reputation: true },
    }),
  ]);

  return ips.map((ip, i) => ({
    ip,
    alerts: rows[i]!._count._all,
    events: eventRows.find((row) => row.sourceIp === ip)?._count._all ?? 0,
    reputation: intel.find((entry) => entry.indicator === ip)?.reputation ?? null,
  }));
}

async function getDetectionsByRule(since: Date) {
  const [rules, rows] = await Promise.all([
    prisma.detectionRule.findMany({ select: { id: true, code: true, name: true }, orderBy: { code: 'asc' } }),
    prisma.alert.groupBy({ by: ['ruleId'], where: { detectedAt: { gte: since } }, _count: { _all: true } }),
  ]);
  return rules.map((rule) => ({
    code: rule.code,
    name: rule.name,
    count: rows.find((row) => row.ruleId === rule.id)?._count._all ?? 0,
  }));
}

async function getRecentActivity() {
  const [criticalAlerts, recentEvents, activeIncidents] = await Promise.all([
    prisma.alert.findMany({
      where: { status: { in: ACTIVE_ALERT_STATUSES }, severity: { in: ['CRITICAL', 'HIGH'] } },
      orderBy: [{ detectedAt: 'desc' }, { id: 'desc' }],
      take: 6,
      select: alertListSelect,
    }),
    prisma.event.findMany({
      orderBy: [{ timestamp: 'desc' }, { id: 'desc' }],
      take: 8,
      select: {
        id: true,
        timestamp: true,
        eventType: true,
        severity: true,
        source: true,
        sourceIp: true,
        hostname: true,
        username: true,
        message: true,
      },
    }),
    prisma.incident.findMany({
      where: { status: { in: ACTIVE_INCIDENT_STATUSES } },
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: 6,
      include: incidentListInclude,
    }),
  ]);

  return {
    recentCriticalAlerts: criticalAlerts.map(withRiskLevel),
    recentEvents,
    activeIncidents: activeIncidents.map(({ _count, ...incident }) => ({ ...incident, alertCount: _count.alerts })),
  };
}
