import { useState } from 'react';
import { Link, useParams } from 'react-router';
import { api } from '../api';
import { AlertsTable } from '../components/alerts/AlertsTable';
import { EventDetailDrawer } from '../components/events/EventDetailDrawer';
import { EventsTable } from '../components/events/EventsTable';
import { IncidentControls, IncidentNoteForm } from '../components/incidents/IncidentControls';
import { Timeline, type TimelineEntry } from '../components/timeline/Timeline';
import { IncidentStatusBadge, SeverityBadge } from '../components/ui/Badges';
import { Card, CardBody, CardHeader } from '../components/ui/Card';
import { PageHeader, Time } from '../components/ui/Primitives';
import { ErrorState, LoadingState } from '../components/ui/States';
import { useAuth } from '../context/AuthContext';
import { useLiveRefresh } from '../context/LiveUpdatesContext';
import { useApi } from '../hooks/useApi';
import type { IncidentDetail } from '../types/api';
import { incidentRef } from '../utils/format';

function timelineFor(incident: IncidentDetail): TimelineEntry[] {
  return [
    ...incident.events.map((event) => ({ kind: 'event' as const, at: event.timestamp, event })),
    ...incident.alerts.map((alert) => ({ kind: 'alert' as const, at: alert.detectedAt, alert })),
    ...incident.activities.map((activity) => ({ kind: 'activity' as const, at: activity.createdAt, activity })),
  ];
}

export default function IncidentDetailPage() {
  const id = Number(useParams().id);
  const { canEdit } = useAuth();
  const [selectedEvent, setSelectedEvent] = useState<number | null>(null);
  const { data: incident, error, reload, setData } = useApi((signal) => api.incidents.get(id, signal), [id]);
  useLiveRefresh(reload, ['incident.updated', 'alert.updated']);

  if (error && !incident) return <ErrorState error={error} onRetry={reload} />;
  if (!incident) return <LoadingState label="Loading incident..." />;

  return (
    <>
      <PageHeader
        eyebrow={
          <span>
            <Link to="/incidents" className="hover:text-fg">
              Incidents
            </Link>{' '}
            / <span className="font-mono">{incidentRef(incident.id)}</span>
          </span>
        }
        title={incident.title}
        description={
          <span className="mt-1 flex flex-wrap items-center gap-2">
            <SeverityBadge severity={incident.severity} />
            <IncidentStatusBadge status={incident.status} />
            <span>
              Opened <Time iso={incident.createdAt} />
            </span>
            {incident.resolvedAt && (
              <span>
                · Resolved <Time iso={incident.resolvedAt} />
              </span>
            )}
            <span>· Assigned to {incident.assignee?.name ?? 'nobody'}</span>
          </span>
        }
      />

      <div className="mb-4 rounded-lg border border-line bg-surface px-4 py-3">
        <IncidentControls incident={incident} onUpdated={setData} />
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <div className="min-w-0 space-y-4 xl:col-span-2">
          {incident.description && (
            <Card>
              <CardHeader title="Summary" />
              <CardBody>
                <p className="text-sm leading-relaxed whitespace-pre-line text-fg">{incident.description}</p>
              </CardBody>
            </Card>
          )}

          <Card>
            <CardHeader title="Linked alerts" subtitle={`${incident.alerts.length} alert(s) escalated into this incident`} />
            <AlertsTable alerts={incident.alerts} compact />
          </Card>

          <Card>
            <CardHeader title="Related events" subtitle="The evidence behind the linked alerts" />
            <EventsTable events={incident.events} onSelect={setSelectedEvent} compact />
          </Card>
        </div>

        <div className="min-w-0 space-y-4">
          {canEdit && (
            <Card>
              <CardBody>
                <IncidentNoteForm incidentId={incident.id} onAdded={reload} />
              </CardBody>
            </Card>
          )}
          <Card>
            <CardHeader title="Timeline" subtitle="Evidence, detections and analyst activity" />
            <CardBody>
              <Timeline entries={timelineFor(incident)} />
            </CardBody>
          </Card>
        </div>
      </div>

      <EventDetailDrawer eventId={selectedEvent} onClose={() => setSelectedEvent(null)} />
    </>
  );
}
