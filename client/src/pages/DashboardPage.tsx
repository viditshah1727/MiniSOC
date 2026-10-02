import { Activity, Briefcase, ScrollText, ShieldAlert, Siren } from 'lucide-react';
import { useState } from 'react';
import { Link } from 'react-router';
import { api } from '../api';
import { AlertsTable } from '../components/alerts/AlertsTable';
import { ActivityChart } from '../components/charts/ActivityChart';
import { ChartCard } from '../components/charts/ChartCard';
import { RankedBars } from '../components/charts/RankedBars';
import { SeverityDonut } from '../components/charts/SeverityDonut';
import { RiskHero, StatTile } from '../components/dashboard/StatTiles';
import { EventDetailDrawer } from '../components/events/EventDetailDrawer';
import { EventsTable } from '../components/events/EventsTable';
import { IncidentsTable } from '../components/incidents/IncidentsTable';
import { ReputationBadge, RuleCode } from '../components/ui/Badges';
import { Card, CardHeader } from '../components/ui/Card';
import { Mono, PageHeader } from '../components/ui/Primitives';
import { EmptyState, ErrorState, LoadingState } from '../components/ui/States';
import { useLiveRefresh } from '../context/LiveUpdatesContext';
import { useApi } from '../hooks/useApi';
import type { DashboardRange } from '../types/api';
import { cn } from '../utils/cn';
import { formatDateTime, formatNumber } from '../utils/format';
import { SEVERITY_LABEL } from '../utils/labels';

const RANGES: { value: DashboardRange; label: string }[] = [
  { value: '24h', label: 'Last 24 hours' },
  { value: '7d', label: 'Last 7 days' },
];

function RangeToggle({ value, onChange }: { value: DashboardRange; onChange: (range: DashboardRange) => void }) {
  return (
    <div role="group" aria-label="Time range" className="inline-flex rounded-md border border-line-strong bg-surface p-0.5">
      {RANGES.map((range) => (
        <button
          key={range.value}
          type="button"
          aria-pressed={value === range.value}
          onClick={() => onChange(range.value)}
          className={cn(
            'rounded px-3 py-1.5 text-xs font-medium transition-colors',
            value === range.value ? 'bg-raised text-fg shadow-sm' : 'text-muted hover:text-fg',
          )}
        >
          {range.label}
        </button>
      ))}
    </div>
  );
}

export default function DashboardPage() {
  const [range, setRange] = useState<DashboardRange>('24h');
  const [selectedEvent, setSelectedEvent] = useState<number | null>(null);
  const { data: stats, error, loading, reload } = useApi((signal) => api.dashboard.stats(range, signal), [range]);
  useLiveRefresh(reload, ['event.created', 'alert.created', 'alert.updated', 'incident.created', 'incident.updated'], 1500);

  const rangeLabel = RANGES.find((r) => r.value === range)!.label.toLowerCase();

  return (
    <>
      <PageHeader
        title="Security overview"
        description="Detections, risk and response activity across the monitored environment."
        actions={<RangeToggle value={range} onChange={setRange} />}
      />

      {error && !stats && <ErrorState error={error} onRetry={reload} />}
      {!stats && !error && <LoadingState label="Loading dashboard..." />}

      {stats && (
        <div className={cn('grid grid-cols-12 gap-4 transition-opacity', loading && 'opacity-70')}>
          {/* KPIs */}
          <div className="col-span-12 xl:col-span-4">
            <RiskHero score={stats.kpis.overallRisk.score} level={stats.kpis.overallRisk.level} openAlerts={stats.kpis.openAlerts} />
          </div>
          <div className="col-span-12 grid grid-cols-2 gap-4 sm:grid-cols-4 xl:col-span-8">
            <StatTile
              label="Total events"
              value={stats.kpis.totalEvents}
              icon={ScrollText}
              caption={`${formatNumber(stats.kpis.eventsInRange)} in the ${rangeLabel}`}
              href="/events"
              trend={stats.eventsOverTime.map((point) => point.events)}
            />
            <StatTile
              label="Total alerts"
              value={stats.kpis.totalAlerts}
              icon={Siren}
              caption={`${formatNumber(stats.kpis.openAlerts)} still open`}
              href="/alerts"
            />
            <StatTile
              label="Open incidents"
              value={stats.kpis.openIncidents}
              icon={Briefcase}
              caption="Open or investigating"
              href="/incidents"
            />
            <StatTile
              label="Critical alerts"
              value={stats.kpis.criticalOpenAlerts}
              icon={ShieldAlert}
              caption="Critical and not yet closed"
              href="/alerts?severity=CRITICAL"
              attention={stats.kpis.criticalOpenAlerts > 0}
            />
          </div>

          {/* Charts */}
          <ChartCard
            className="col-span-12 xl:col-span-8"
            title="Security events over time"
            subtitle={`Ingested events and raised alerts, ${rangeLabel}`}
            refreshing={loading}
            table={{
              columns: ['Time', 'Events', 'Alerts'],
              rows: stats.eventsOverTime.map((p) => [formatDateTime(p.bucket), p.events, p.alerts]),
            }}
          >
            <ActivityChart data={stats.eventsOverTime} range={range} />
          </ChartCard>

          <ChartCard
            className="col-span-12 md:col-span-6 xl:col-span-4"
            title="Alerts by severity"
            subtitle={`Alerts raised in the ${rangeLabel}`}
            refreshing={loading}
            table={{ columns: ['Severity', 'Alerts'], rows: stats.alertsBySeverity.map((s) => [SEVERITY_LABEL[s.severity], s.count]) }}
          >
            <SeverityDonut data={stats.alertsBySeverity} />
          </ChartCard>

          <ChartCard
            className="col-span-12 md:col-span-6"
            title="Top source IPs"
            subtitle={`Sources behind the most alerts, ${rangeLabel}`}
            refreshing={loading}
            table={{
              columns: ['Source IP', 'Alerts', 'Events', 'Reputation'],
              rows: stats.topSourceIps.map((ip) => [ip.ip, ip.alerts, ip.events, ip.reputation ?? 'Unknown']),
            }}
          >
            {stats.topSourceIps.length === 0 ? (
              <EmptyState title="No alerting sources" description="No alert with a source IP in this period." />
            ) : (
              <RankedBars
                unit="alerts"
                bars={stats.topSourceIps.map((ip) => ({
                  key: ip.ip,
                  value: ip.alerts,
                  detail: `${formatNumber(ip.events)} events`,
                  href: `/alerts?sourceIp=${encodeURIComponent(ip.ip)}`,
                  label: (
                    <span className="flex items-center gap-2">
                      <Mono className="text-fg">{ip.ip}</Mono>
                      {ip.reputation && <ReputationBadge reputation={ip.reputation} />}
                    </span>
                  ),
                }))}
              />
            )}
          </ChartCard>

          <ChartCard
            className="col-span-12 md:col-span-6"
            title="Detections by rule"
            subtitle={`Which detection rules fired, ${rangeLabel}`}
            refreshing={loading}
            table={{ columns: ['Rule', 'Name', 'Alerts'], rows: stats.detectionsByRule.map((r) => [r.code, r.name, r.count]) }}
          >
            <RankedBars
              unit="alerts"
              bars={stats.detectionsByRule.map((rule) => ({
                key: rule.code,
                value: rule.count,
                href: `/alerts?ruleCode=${rule.code}`,
                label: (
                  <span className="flex items-center gap-2">
                    <RuleCode code={rule.code} />
                    <span className="truncate text-fg">{rule.name}</span>
                  </span>
                ),
              }))}
            />
          </ChartCard>

          {/* Work queues */}
          <Card className="col-span-12 2xl:col-span-7">
            <CardHeader
              title="Recent high-priority alerts"
              subtitle="Critical and high alerts that are not closed yet"
              actions={
                <Link to="/alerts?status=OPEN" className="text-xs font-medium text-accent hover:underline">
                  View queue
                </Link>
              }
            />
            {stats.recentCriticalAlerts.length === 0 ? (
              <EmptyState icon={Activity} title="Nothing urgent" description="No open critical or high alerts right now." />
            ) : (
              <AlertsTable alerts={stats.recentCriticalAlerts} compact />
            )}
          </Card>

          <Card className="col-span-12 2xl:col-span-5">
            <CardHeader
              title="Active incidents"
              subtitle="Open or under investigation"
              actions={
                <Link to="/incidents" className="text-xs font-medium text-accent hover:underline">
                  All incidents
                </Link>
              }
            />
            {stats.activeIncidents.length === 0 ? (
              <EmptyState icon={Briefcase} title="No active incidents" description="Escalate an alert to open one." />
            ) : (
              <IncidentsTable incidents={stats.activeIncidents} compact />
            )}
          </Card>

          <Card className="col-span-12">
            <CardHeader
              title="Recent events"
              subtitle="Latest telemetry received from all log sources"
              actions={
                <Link to="/events" className="text-xs font-medium text-accent hover:underline">
                  Explore events
                </Link>
              }
            />
            {stats.recentEvents.length === 0 ? (
              <EmptyState title="No events yet" description="Send events to POST /api/events or run the seed script." />
            ) : (
              <EventsTable events={stats.recentEvents} onSelect={setSelectedEvent} compact />
            )}
          </Card>
        </div>
      )}

      <EventDetailDrawer eventId={selectedEvent} onClose={() => setSelectedEvent(null)} />
    </>
  );
}
