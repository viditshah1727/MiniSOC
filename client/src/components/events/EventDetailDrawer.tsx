// Full details of one event in a side panel: every field, the raw metadata,
// and the alerts it contributed to. Opened from any list of events.
import { Link } from 'react-router';
import { api } from '../../api';
import { useApi } from '../../hooks/useApi';
import { alertRef, eventRef } from '../../utils/format';
import { EVENT_TYPE_LABEL } from '../../utils/labels';
import { SeverityBadge } from '../ui/Badges';
import { Modal } from '../ui/Modal';
import { KeyValueList, Mono, Time } from '../ui/Primitives';
import { ErrorState, LoadingState } from '../ui/States';

function EventDetails({ id }: { id: number }) {
  const { data: event, error, loading, reload } = useApi((signal) => api.events.get(id, signal), [id]);

  if (error) return <ErrorState error={error} onRetry={reload} />;
  if (loading || !event) return <LoadingState />;

  return (
    <div className="space-y-6">
      <KeyValueList
        items={[
          ['Reference', <Mono key="ref">{eventRef(event.id)}</Mono>],
          ['Time', <Time key="time" iso={event.timestamp} />],
          ['Severity', <SeverityBadge key="severity" severity={event.severity} />],
          ['Type', EVENT_TYPE_LABEL[event.eventType]],
          ['Log source', <Mono key="source">{event.source}</Mono>],
          ['Source IP', event.sourceIp && <Mono key="src">{event.sourceIp}</Mono>],
          [
            'Destination',
            event.destinationIp && (
              <Mono key="dst">
                {event.destinationIp}
                {event.destinationPort !== null && `:${event.destinationPort}`}
              </Mono>
            ),
          ],
          ['Host', event.hostname],
          ['User', event.username],
          ['Ingested', <Time key="ingested" iso={event.createdAt} />],
        ]}
      />

      <section>
        <h3 className="mb-2 text-xs font-medium tracking-wide text-faint uppercase">Message</h3>
        <pre className="overflow-x-auto rounded-md border border-line bg-canvas p-3 font-mono text-[12px] whitespace-pre-wrap text-fg">
          {event.message}
        </pre>
      </section>

      {event.metadata && (
        <section>
          <h3 className="mb-2 text-xs font-medium tracking-wide text-faint uppercase">Metadata (JSON)</h3>
          <pre className="overflow-x-auto rounded-md border border-line bg-canvas p-3 font-mono text-[12px] text-muted">
            {JSON.stringify(event.metadata, null, 2)}
          </pre>
        </section>
      )}

      <section>
        <h3 className="mb-2 text-xs font-medium tracking-wide text-faint uppercase">Alerts this event is part of</h3>
        {event.alerts.length === 0 ? (
          <p className="text-sm text-muted">None: no detection rule matched this event.</p>
        ) : (
          <ul className="space-y-2">
            {event.alerts.map((alert) => (
              <li key={alert.id} className="flex items-center gap-2 text-sm">
                <SeverityBadge severity={alert.severity} />
                <Link to={`/alerts/${alert.id}`} className="font-medium text-fg hover:text-accent">
                  {alert.title}
                </Link>
                <span className="font-mono text-xs text-faint">{alertRef(alert.id)}</span>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}

export function EventDetailDrawer({ eventId, onClose }: { eventId: number | null; onClose: () => void }) {
  return (
    <Modal open={eventId !== null} onClose={onClose} title="Security event" variant="drawer">
      {eventId !== null && <EventDetails id={eventId} />}
    </Modal>
  );
}
