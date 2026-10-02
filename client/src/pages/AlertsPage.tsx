import { Download, Siren, X } from 'lucide-react';
import { api } from '../api';
import { AlertsTable } from '../components/alerts/AlertsTable';
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
import { ALERT_STATUS_LABEL, ALERT_STATUSES, SEVERITIES, SEVERITY_LABEL } from '../utils/labels';

const FILTER_KEYS = ['q', 'status', 'severity', 'ruleCode', 'sourceIp', 'mitreTechniqueId', 'sort'] as const;

export default function AlertsPage() {
  const { filters, page, setFilter, setPage, clearFilters, hasFilters } = useUrlFilters(FILTER_KEYS);
  const alerts = useApi((signal) => api.alerts.list({ ...filters, page, pageSize: 25 }, signal), [JSON.stringify(filters), page]);
  const rules = useApi((signal) => api.rules.list(signal), []);
  useLiveRefresh(alerts.reload, ['alert.created', 'alert.updated']);

  return (
    <>
      <PageHeader
        title="Alerts"
        description={
          alerts.data
            ? `${formatNumber(alerts.data.pagination.total)} alert(s) match. Click one to see why it fired.`
            : 'Detections raised by the rules, ready for triage.'
        }
        actions={
          <a
            href={api.reports.url('alerts', filters)}
            className="inline-flex h-9 items-center gap-2 rounded-md border border-line-strong bg-raised px-3.5 text-sm font-medium text-fg hover:bg-overlay"
          >
            <Download aria-hidden className="size-4" />
            Export CSV
          </a>
        }
      />

      <FilterBar onClear={clearFilters} hasFilters={hasFilters}>
        <Field label="Search" htmlFor="alert-q" className="w-full sm:w-64">
          <DebouncedInput id="alert-q" icon value={filters.q} onChange={(v) => setFilter('q', v)} placeholder="Title, host, user..." />
        </Field>
        <Field label="Status" htmlFor="alert-status">
          <SelectInput
            id="alert-status"
            value={filters.status}
            onChange={(v) => setFilter('status', v)}
            options={ALERT_STATUSES.map((s) => ({ value: s, label: ALERT_STATUS_LABEL[s] }))}
          />
        </Field>
        <Field label="Severity" htmlFor="alert-severity">
          <SelectInput
            id="alert-severity"
            value={filters.severity}
            onChange={(v) => setFilter('severity', v)}
            options={SEVERITIES.filter((s) => s !== 'INFO').map((s) => ({ value: s, label: SEVERITY_LABEL[s] }))}
          />
        </Field>
        <Field label="Detection rule" htmlFor="alert-rule">
          <SelectInput
            id="alert-rule"
            value={filters.ruleCode}
            onChange={(v) => setFilter('ruleCode', v)}
            options={(rules.data ?? []).map((r) => ({ value: r.code, label: `${r.code} ${r.name}` }))}
          />
        </Field>
        <Field label="Source IP" htmlFor="alert-ip" className="w-full sm:w-44">
          <DebouncedInput id="alert-ip" value={filters.sourceIp} onChange={(v) => setFilter('sourceIp', v)} placeholder="203.0.113.45" />
        </Field>
        <Field label="Sort by" htmlFor="alert-sort">
          <SelectInput
            id="alert-sort"
            value={filters.sort || 'recent'}
            onChange={(v) => setFilter('sort', v === 'recent' ? '' : v)}
            allLabel={null}
            options={[
              { value: 'recent', label: 'Most recent' },
              { value: 'risk', label: 'Highest risk' },
            ]}
          />
        </Field>
      </FilterBar>

      {filters.mitreTechniqueId && (
        <p className="mb-3 flex items-center gap-2 text-sm text-muted">
          Showing alerts mapped to MITRE technique <span className="font-mono text-fg">{filters.mitreTechniqueId}</span>
          <button
            type="button"
            onClick={() => setFilter('mitreTechniqueId', '')}
            className="rounded p-0.5 text-faint hover:text-fg"
            aria-label="Remove technique filter"
          >
            <X className="size-3.5" />
          </button>
        </p>
      )}

      <Card>
        {alerts.error ? (
          <ErrorState error={alerts.error} onRetry={alerts.reload} />
        ) : !alerts.data ? (
          <LoadingState />
        ) : alerts.data.items.length === 0 ? (
          <EmptyState
            icon={Siren}
            title="No alerts match these filters"
            description={hasFilters ? 'Try removing a filter.' : 'Nothing has been detected yet.'}
          />
        ) : (
          <div className={cn('transition-opacity', alerts.loading && 'opacity-60')}>
            <AlertsTable alerts={alerts.data.items} />
            <Pagination pagination={alerts.data.pagination} onPageChange={setPage} />
          </div>
        )}
      </Card>
    </>
  );
}
