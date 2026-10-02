import { Download, ScrollText } from 'lucide-react';
import { useState } from 'react';
import { api } from '../api';
import { EventDetailDrawer } from '../components/events/EventDetailDrawer';
import { EventsTable } from '../components/events/EventsTable';
import { Card } from '../components/ui/Card';
import { DebouncedInput, FilterBar, SelectInput } from '../components/ui/FilterControls';
import { Pagination } from '../components/ui/Pagination';
import { Field, PageHeader } from '../components/ui/Primitives';
import { EmptyState, ErrorState, LoadingState } from '../components/ui/States';
import { useLiveRefresh } from '../context/LiveUpdatesContext';
import { useApi } from '../hooks/useApi';
import { useUrlFilters } from '../hooks/useUrlFilters';
import { cn } from '../utils/cn';
import { formatNumber } from '../utils/format';
import { EVENT_TYPE_LABEL, EVENT_TYPES, SEVERITIES, SEVERITY_LABEL } from '../utils/labels';

const FILTER_KEYS = ['q', 'severity', 'eventType', 'sourceIp', 'from', 'to'] as const;

/** <input type="datetime-local"> gives local time without a zone; send an exact instant. */
const toIso = (local: string) => (local ? new Date(local).toISOString() : undefined);

export default function EventsPage() {
  const { filters, page, setFilter, setPage, clearFilters, hasFilters } = useUrlFilters(FILTER_KEYS);
  const [selectedEvent, setSelectedEvent] = useState<number | null>(null);

  const query = { ...filters, from: toIso(filters.from), to: toIso(filters.to) };
  const events = useApi((signal) => api.events.list({ ...query, page, pageSize: 50 }, signal), [JSON.stringify(query), page]);
  useLiveRefresh(events.reload, ['event.created'], 2000);

  return (
    <>
      <PageHeader
        title="Security events"
        description={
          events.data
            ? `${formatNumber(events.data.pagination.total)} event(s) match. Click one for full details.`
            : 'Raw telemetry received from every log source.'
        }
        actions={
          <a
            href={api.reports.url('events', query)}
            className="inline-flex h-9 items-center gap-2 rounded-md border border-line-strong bg-raised px-3.5 text-sm font-medium text-fg hover:bg-overlay"
          >
            <Download aria-hidden className="size-4" />
            Export CSV
          </a>
        }
      />

      <FilterBar onClear={clearFilters} hasFilters={hasFilters}>
        <Field label="Search" htmlFor="event-q" className="w-full sm:w-64">
          <DebouncedInput id="event-q" icon value={filters.q} onChange={(v) => setFilter('q', v)} placeholder="Message, user, host, source..." />
        </Field>
        <Field label="Severity" htmlFor="event-severity">
          <SelectInput
            id="event-severity"
            value={filters.severity}
            onChange={(v) => setFilter('severity', v)}
            options={SEVERITIES.map((s) => ({ value: s, label: SEVERITY_LABEL[s] }))}
          />
        </Field>
        <Field label="Event type" htmlFor="event-type">
          <SelectInput
            id="event-type"
            value={filters.eventType}
            onChange={(v) => setFilter('eventType', v)}
            options={EVENT_TYPES.map((t) => ({ value: t, label: EVENT_TYPE_LABEL[t] }))}
          />
        </Field>
        <Field label="Source IP" htmlFor="event-ip" className="w-full sm:w-44">
          <DebouncedInput id="event-ip" value={filters.sourceIp} onChange={(v) => setFilter('sourceIp', v)} placeholder="10.10.4.21" />
        </Field>
        <Field label="From" htmlFor="event-from">
          <input id="event-from" type="datetime-local" value={filters.from} onChange={(e) => setFilter('from', e.target.value)} className="field" />
        </Field>
        <Field label="To" htmlFor="event-to">
          <input id="event-to" type="datetime-local" value={filters.to} onChange={(e) => setFilter('to', e.target.value)} className="field" />
        </Field>
      </FilterBar>

      <Card>
        {events.error ? (
          <ErrorState error={events.error} onRetry={events.reload} />
        ) : !events.data ? (
          <LoadingState />
        ) : events.data.items.length === 0 ? (
          <EmptyState icon={ScrollText} title="No events match these filters" description={hasFilters ? 'Try widening the time range or removing a filter.' : undefined} />
        ) : (
          <div className={cn('transition-opacity', events.loading && 'opacity-60')}>
            <EventsTable events={events.data.items} onSelect={setSelectedEvent} />
            <Pagination pagination={events.data.pagination} onPageChange={setPage} />
          </div>
        )}
      </Card>

      <EventDetailDrawer eventId={selectedEvent} onClose={() => setSelectedEvent(null)} />
    </>
  );
}
