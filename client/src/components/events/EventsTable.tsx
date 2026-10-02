import { Siren } from 'lucide-react';
import type { SecurityEvent } from '../../types/api';
import { EVENT_TYPE_LABEL } from '../../utils/labels';
import { SeverityBadge } from '../ui/Badges';
import { Mono, Time } from '../ui/Primitives';

type EventRow = Pick<SecurityEvent, 'id' | 'timestamp' | 'eventType' | 'severity' | 'source' | 'sourceIp' | 'hostname' | 'username' | 'message'> & {
  destinationIp?: string | null;
  destinationPort?: number | null;
  alertCount?: number;
};

interface EventsTableProps {
  events: EventRow[];
  onSelect: (id: number) => void;
  /** Hide the destination column where space is tight (dashboard). */
  compact?: boolean;
}

export function EventsTable({ events, onSelect, compact = false }: EventsTableProps) {
  return (
    <div className="overflow-x-auto">
      <table className="data-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Severity</th>
            <th>Type</th>
            <th>Source IP</th>
            {!compact && <th>Destination</th>}
            <th>Host / user</th>
            <th>Message</th>
          </tr>
        </thead>
        <tbody>
          {events.map((event) => (
            <tr key={event.id} className="row-link" onClick={() => onSelect(event.id)}>
              <td className="text-muted">
                <Time iso={event.timestamp} />
              </td>
              <td>
                <SeverityBadge severity={event.severity} />
              </td>
              <td className="whitespace-nowrap">
                <span className="text-fg">{EVENT_TYPE_LABEL[event.eventType]}</span>
                <div className="text-xs text-faint">{event.source}</div>
              </td>
              <td>{event.sourceIp ? <Mono>{event.sourceIp}</Mono> : <span className="text-faint">—</span>}</td>
              {!compact && (
                <td className="whitespace-nowrap">
                  {event.destinationIp ? (
                    <Mono>
                      {event.destinationIp}
                      {event.destinationPort !== null && event.destinationPort !== undefined && `:${event.destinationPort}`}
                    </Mono>
                  ) : (
                    <span className="text-faint">—</span>
                  )}
                </td>
              )}
              <td className="whitespace-nowrap text-muted">
                <div>{event.hostname ?? '—'}</div>
                {event.username && <div className="text-xs text-faint">{event.username}</div>}
              </td>
              <td className="max-w-lg min-w-64">
                <div className="flex items-start gap-2">
                  {event.alertCount ? (
                    <Siren
                      role="img"
                      aria-label={`Part of ${event.alertCount} alert(s)`}
                      className="mt-0.5 size-3.5 shrink-0 text-sev-high"
                    />
                  ) : null}
                  {/* Log messages are untrusted input: React escapes them, never rendered as HTML. */}
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      onSelect(event.id);
                    }}
                    className="line-clamp-2 text-left font-mono text-[12px] text-muted hover:text-fg"
                  >
                    {event.message}
                  </button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
