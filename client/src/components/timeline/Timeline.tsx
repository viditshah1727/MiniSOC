// Chronological story of an alert or incident: the raw events that caused it
// plus everything analysts did afterwards. Bursts of identical events (e.g.
// 12 failed logins from one IP) are folded into one expandable entry.
import {
  Download,
  Globe,
  KeyRound,
  Link2,
  LogIn,
  type LucideIcon,
  Network,
  NotebookPen,
  RefreshCw,
  Siren,
  SquareTerminal,
  UserRound,
} from 'lucide-react';
import { Link } from 'react-router';
import type { Activity, ActivityType, EventType, SecurityEvent, Severity } from '../../types/api';
import { cn } from '../../utils/cn';
import { alertRef } from '../../utils/format';
import { EVENT_TYPE_LABEL, SEVERITY_COLOR } from '../../utils/labels';
import { SeverityBadge } from '../ui/Badges';
import { Time } from '../ui/Primitives';

export type TimelineEntry =
  | { kind: 'event'; at: string; event: SecurityEvent; isTrigger?: boolean }
  | { kind: 'activity'; at: string; activity: Activity }
  | { kind: 'alert'; at: string; alert: { id: number; title: string; severity: Severity; rule: { code: string } } };

type Row =
  | Exclude<TimelineEntry, { kind: 'event' }>
  | { kind: 'events'; at: string; events: SecurityEvent[]; isTrigger: boolean };

const EVENT_ICON: Record<EventType, LucideIcon> = {
  AUTH_SUCCESS: LogIn,
  AUTH_FAILURE: KeyRound,
  NETWORK_CONNECTION: Network,
  PROCESS_EXECUTION: SquareTerminal,
  DNS_QUERY: Globe,
  FILE_DOWNLOAD: Download,
};

const ACTIVITY_ICON: Record<ActivityType, LucideIcon> = {
  CREATED: Siren,
  STATUS_CHANGE: RefreshCw,
  ASSIGNMENT: UserRound,
  NOTE: NotebookPen,
  ALERT_LINKED: Link2,
};

/** Sorts entries and folds consecutive events of the same type from the same source. */
function buildRows(entries: TimelineEntry[]): Row[] {
  const sorted = [...entries].sort((a, b) => a.at.localeCompare(b.at) || (a.kind === 'event' ? -1 : 1));
  const rows: Row[] = [];
  for (const entry of sorted) {
    const previous = rows.at(-1);
    if (
      entry.kind === 'event' &&
      previous?.kind === 'events' &&
      previous.events[0]!.eventType === entry.event.eventType &&
      previous.events[0]!.sourceIp === entry.event.sourceIp &&
      !entry.isTrigger &&
      !previous.isTrigger
    ) {
      previous.events.push(entry.event);
    } else if (entry.kind === 'event') {
      rows.push({ kind: 'events', at: entry.at, events: [entry.event], isTrigger: Boolean(entry.isTrigger) });
    } else {
      rows.push(entry);
    }
  }
  return rows;
}

function Marker({ icon: Icon, color }: { icon: LucideIcon; color?: string }) {
  return (
    <span className="absolute top-0.5 -left-[25px] flex size-6 items-center justify-center rounded-full border border-line-strong bg-surface">
      <Icon aria-hidden className="size-3.5" style={color ? { color } : undefined} />
    </span>
  );
}

function EventsRow({ row }: { row: Extract<Row, { kind: 'events' }> }) {
  const first = row.events[0]!;
  const last = row.events.at(-1)!;
  const count = row.events.length;
  const summary = `${count > 1 ? `${count} × ` : ''}${EVENT_TYPE_LABEL[first.eventType]}${first.sourceIp ? ` from ${first.sourceIp}` : ''}${first.hostname ? ` on ${first.hostname}` : ''}`;

  return (
    <>
      <Marker icon={EVENT_ICON[first.eventType]} />
      <p className="text-xs text-faint">
        <Time iso={first.timestamp} />
        {count > 1 && (
          <>
            {' → '}
            <Time iso={last.timestamp} />
          </>
        )}
        {row.isTrigger && <span className="ml-2 rounded bg-sev-high/15 px-1.5 py-0.5 text-[11px] font-medium text-fg">Trigger event</span>}
      </p>
      <p className="mt-0.5 text-sm text-fg">{summary}</p>
      {count === 1 ? (
        <p className="mt-1 font-mono text-[12px] break-words text-muted">{first.message}</p>
      ) : (
        <details className="group mt-1">
          <summary className="cursor-pointer text-xs text-accent select-none hover:underline">Show {count} events</summary>
          <ul className="mt-1.5 space-y-1 border-l border-line pl-3">
            {row.events.map((event) => (
              <li key={event.id} className="font-mono text-[12px] break-words text-muted">
                <Time iso={event.timestamp} className="mr-2 text-faint" />
                {event.message}
              </li>
            ))}
          </ul>
        </details>
      )}
    </>
  );
}

export function Timeline({ entries }: { entries: TimelineEntry[] }) {
  const rows = buildRows(entries);

  return (
    <ol className="relative ml-3 space-y-5 border-l border-line pl-5">
      {rows.map((row, index) => (
        <li key={index} className="relative">
          {row.kind === 'events' && <EventsRow row={row} />}

          {row.kind === 'activity' && (
            <>
              <Marker
                icon={ACTIVITY_ICON[row.activity.type]}
                color={row.activity.type === 'CREATED' ? SEVERITY_COLOR.HIGH : undefined}
              />
              <p className="text-xs text-faint">
                <Time iso={row.at} />
                {' · '}
                {row.activity.user?.name ?? 'MiniSOC'}
              </p>
              <p className={cn('mt-0.5 text-sm', row.activity.type === 'NOTE' ? 'rounded-md border border-line bg-raised px-3 py-2 text-fg' : 'text-fg')}>
                {row.activity.message}
              </p>
            </>
          )}

          {row.kind === 'alert' && (
            <>
              <Marker icon={Siren} color={SEVERITY_COLOR[row.alert.severity]} />
              <p className="text-xs text-faint">
                <Time iso={row.at} /> · {row.alert.rule.code} fired
              </p>
              <p className="mt-0.5 flex flex-wrap items-center gap-2 text-sm">
                <SeverityBadge severity={row.alert.severity} />
                <Link to={`/alerts/${row.alert.id}`} className="font-medium text-fg hover:text-accent">
                  {row.alert.title}
                </Link>
                <span className="font-mono text-xs text-faint">{alertRef(row.alert.id)}</span>
              </p>
            </>
          )}
        </li>
      ))}
    </ol>
  );
}
