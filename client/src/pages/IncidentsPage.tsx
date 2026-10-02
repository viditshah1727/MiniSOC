import { Briefcase, Download } from 'lucide-react';
import { api } from '../api';
import { IncidentsTable } from '../components/incidents/IncidentsTable';
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
import { INCIDENT_STATUS_LABEL, INCIDENT_STATUSES, SEVERITIES, SEVERITY_LABEL } from '../utils/labels';

const FILTER_KEYS = ['q', 'status', 'severity', 'assigneeId'] as const;

export default function IncidentsPage() {
  const { filters, page, setFilter, setPage, clearFilters, hasFilters } = useUrlFilters(FILTER_KEYS);
  const incidents = useApi((signal) => api.incidents.list({ ...filters, page, pageSize: 25 }, signal), [JSON.stringify(filters), page]);
  const users = useApi((signal) => api.users.list(signal), []);
  useLiveRefresh(incidents.reload, ['incident.created', 'incident.updated']);

  return (
    <>
      <PageHeader
        title="Incidents"
        description={
          incidents.data
            ? `${formatNumber(incidents.data.pagination.total)} incident(s). Incidents are opened from alerts.`
            : 'Tracked investigations escalated from alerts.'
        }
        actions={
          <a
            href={api.reports.url('incidents', filters)}
            className="inline-flex h-9 items-center gap-2 rounded-md border border-line-strong bg-raised px-3.5 text-sm font-medium text-fg hover:bg-overlay"
          >
            <Download aria-hidden className="size-4" />
            Incident summary (CSV)
          </a>
        }
      />

      <FilterBar onClear={clearFilters} hasFilters={hasFilters}>
        <Field label="Search" htmlFor="incident-q" className="w-full sm:w-64">
          <DebouncedInput id="incident-q" icon value={filters.q} onChange={(v) => setFilter('q', v)} placeholder="Title or description..." />
        </Field>
        <Field label="Status" htmlFor="incident-status">
          <SelectInput
            id="incident-status"
            value={filters.status}
            onChange={(v) => setFilter('status', v)}
            options={INCIDENT_STATUSES.map((s) => ({ value: s, label: INCIDENT_STATUS_LABEL[s] }))}
          />
        </Field>
        <Field label="Severity" htmlFor="incident-severity">
          <SelectInput
            id="incident-severity"
            value={filters.severity}
            onChange={(v) => setFilter('severity', v)}
            options={SEVERITIES.filter((s) => s !== 'INFO').map((s) => ({ value: s, label: SEVERITY_LABEL[s] }))}
          />
        </Field>
        <Field label="Assignee" htmlFor="incident-assignee">
          <SelectInput
            id="incident-assignee"
            value={filters.assigneeId}
            onChange={(v) => setFilter('assigneeId', v)}
            options={(users.data ?? []).filter((u) => u.role !== 'VIEWER').map((u) => ({ value: String(u.id), label: u.name }))}
          />
        </Field>
      </FilterBar>

      <Card>
        {incidents.error ? (
          <ErrorState error={incidents.error} onRetry={incidents.reload} />
        ) : !incidents.data ? (
          <LoadingState />
        ) : incidents.data.items.length === 0 ? (
          <EmptyState
            icon={Briefcase}
            title={hasFilters ? 'No incidents match these filters' : 'No incidents yet'}
            description="Open an alert and choose “Create incident” to start one."
          />
        ) : (
          <div className={cn('transition-opacity', incidents.loading && 'opacity-60')}>
            <IncidentsTable incidents={incidents.data.items} />
            <Pagination pagination={incidents.data.pagination} onPageChange={setPage} />
          </div>
        )}
      </Card>
    </>
  );
}
