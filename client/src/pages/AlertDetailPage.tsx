import { Link, useParams } from 'react-router';
import { api } from '../api';
import { AiAnalysisPanel } from '../components/alerts/AiAnalysisPanel';
import { AlertActions } from '../components/alerts/AlertActions';
import {
  EntitiesPanel,
  MitrePanel,
  PlaybookPanel,
  RiskPanel,
  ThreatIntelPanel,
  WhyItFiredPanel,
} from '../components/alerts/AlertPanels';
import { AlertsTable } from '../components/alerts/AlertsTable';
import { Timeline, type TimelineEntry } from '../components/timeline/Timeline';
import { AlertStatusBadge, RuleCode, SeverityBadge } from '../components/ui/Badges';
import { Card, CardBody, CardHeader } from '../components/ui/Card';
import { PageHeader, Time } from '../components/ui/Primitives';
import { ErrorState, LoadingState } from '../components/ui/States';
import { useSession } from '../context/AuthContext';
import { useLiveRefresh } from '../context/LiveUpdatesContext';
import { useApi } from '../hooks/useApi';
import type { AlertDetail } from '../types/api';
import { alertRef } from '../utils/format';

function timelineFor(alert: AlertDetail): TimelineEntry[] {
  return [
    ...alert.evidenceEvents.map((event) => ({
      kind: 'event' as const,
      at: event.timestamp,
      event,
      isTrigger: event.id === alert.event.id,
    })),
    ...alert.activities.map((activity) => ({ kind: 'activity' as const, at: activity.createdAt, activity })),
  ];
}

export default function AlertDetailPage() {
  const id = Number(useParams().id);
  const { features } = useSession();
  const { data: alert, error, reload, setData } = useApi((signal) => api.alerts.get(id, signal), [id]);
  useLiveRefresh(reload, ['alert.updated', 'incident.updated']);

  if (error && !alert) return <ErrorState error={error} onRetry={reload} />;
  if (!alert) return <LoadingState label="Loading alert..." />;

  return (
    <>
      <PageHeader
        eyebrow={
          <span>
            <Link to="/alerts" className="hover:text-fg">
              Alerts
            </Link>{' '}
            / <span className="font-mono">{alertRef(alert.id)}</span>
          </span>
        }
        title={alert.title}
        description={
          <span className="mt-1 flex flex-wrap items-center gap-2">
            <SeverityBadge severity={alert.severity} />
            <AlertStatusBadge status={alert.status} />
            <RuleCode code={alert.rule.code} />
            <span>{alert.rule.name}</span>
            <span className="text-faint">·</span>
            <span>
              Detected <Time iso={alert.detectedAt} />
            </span>
          </span>
        }
      />

      <div className="mb-4 rounded-lg border border-line bg-surface px-4 py-3">
        <AlertActions alert={alert} onUpdated={setData} />
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <div className="min-w-0 space-y-4 xl:col-span-2">
          <WhyItFiredPanel alert={alert} />

          <Card>
            <CardHeader title="Timeline" subtitle="The events that triggered the alert, then everything done about it" />
            <CardBody>
              <Timeline entries={timelineFor(alert)} />
            </CardBody>
          </Card>

          {alert.relatedAlerts.length > 0 && (
            <Card>
              <CardHeader title="Other alerts from this source" subtitle={`Everything else ${alert.sourceIp} has triggered`} />
              <AlertsTable alerts={alert.relatedAlerts} compact />
            </Card>
          )}
        </div>

        <div className="min-w-0 space-y-4">
          <RiskPanel alert={alert} />
          <EntitiesPanel alert={alert} />
          <MitrePanel alert={alert} />
          <ThreatIntelPanel alert={alert} />
          <PlaybookPanel steps={alert.rule.recommendedSteps} />
          {features.aiAssistant && <AiAnalysisPanel alertId={alert.id} />}
        </div>
      </div>
    </>
  );
}
