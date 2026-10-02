import { Plus, Radar } from 'lucide-react';
import { useState } from 'react';
import { Link } from 'react-router';
import { api } from '../api';
import { AddIndicatorDialog } from '../components/intel/AddIndicatorDialog';
import { ReputationBadge } from '../components/ui/Badges';
import { Button } from '../components/ui/Button';
import { Card } from '../components/ui/Card';
import { DebouncedInput, FilterBar, SelectInput } from '../components/ui/FilterControls';
import { Pagination } from '../components/ui/Pagination';
import { Field, Mono, PageHeader, Time } from '../components/ui/Primitives';
import { EmptyState, ErrorState, LoadingState } from '../components/ui/States';
import { useAuth } from '../context/AuthContext';
import { useApi } from '../hooks/useApi';
import { useUrlFilters } from '../hooks/useUrlFilters';
import type { IndicatorListItem, IndicatorType, Reputation } from '../types/api';
import { cn } from '../utils/cn';
import { formatNumber } from '../utils/format';
import { INDICATOR_TYPE_LABEL, REPUTATION_LABEL } from '../utils/labels';

const FILTER_KEYS = ['q', 'type', 'reputation'] as const;

function ConfidenceBar({ value }: { value: number }) {
  return (
    <div className="flex items-center gap-2" title={`${value}% confidence`}>
      <span className="tabular w-9 text-sm text-fg">{value}%</span>
      <div className="h-1.5 w-16 overflow-hidden rounded-full bg-raised" aria-hidden>
        <div className="h-full rounded-full bg-muted" style={{ width: `${value}%` }} />
      </div>
    </div>
  );
}

function IndicatorAlerts({ indicator }: { indicator: IndicatorListItem }) {
  if (indicator.alertCount === 0) return <span className="text-faint">0</span>;
  // IP indicators link to the alerts from that source.
  return indicator.type === 'IP' ? (
    <Link to={`/alerts?sourceIp=${encodeURIComponent(indicator.indicator)}`} className="tabular font-medium text-accent hover:underline">
      {indicator.alertCount}
    </Link>
  ) : (
    <span className="tabular text-fg">{indicator.alertCount}</span>
  );
}

export default function ThreatIntelPage() {
  const { canEdit } = useAuth();
  const [adding, setAdding] = useState(false);
  const { filters, page, setFilter, setPage, clearFilters, hasFilters } = useUrlFilters(FILTER_KEYS);
  const intel = useApi((signal) => api.threatIntel.list({ ...filters, page, pageSize: 25 }, signal), [JSON.stringify(filters), page]);

  return (
    <>
      <PageHeader
        title="Threat intelligence"
        description={
          <>
            {intel.data ? `${formatNumber(intel.data.pagination.total)} indicator(s). ` : ''}
            Known IPs, domains and file hashes used to enrich alerts. Local database: no external feed is queried.
          </>
        }
        actions={
          canEdit && (
            <Button variant="primary" icon={Plus} onClick={() => setAdding(true)}>
              Add indicator
            </Button>
          )
        }
      />

      <FilterBar onClear={clearFilters} hasFilters={hasFilters}>
        <Field label="Search" htmlFor="ti-q" className="w-full sm:w-64">
          <DebouncedInput id="ti-q" icon value={filters.q} onChange={(v) => setFilter('q', v)} placeholder="Indicator, source, description..." />
        </Field>
        <Field label="Type" htmlFor="ti-type">
          <SelectInput
            id="ti-type"
            value={filters.type}
            onChange={(v) => setFilter('type', v)}
            options={(Object.keys(INDICATOR_TYPE_LABEL) as IndicatorType[]).map((t) => ({ value: t, label: INDICATOR_TYPE_LABEL[t] }))}
          />
        </Field>
        <Field label="Reputation" htmlFor="ti-reputation">
          <SelectInput
            id="ti-reputation"
            value={filters.reputation}
            onChange={(v) => setFilter('reputation', v)}
            options={(Object.keys(REPUTATION_LABEL) as Reputation[]).map((r) => ({ value: r, label: REPUTATION_LABEL[r] }))}
          />
        </Field>
      </FilterBar>

      <Card>
        {intel.error ? (
          <ErrorState error={intel.error} onRetry={intel.reload} />
        ) : !intel.data ? (
          <LoadingState />
        ) : intel.data.items.length === 0 ? (
          <EmptyState icon={Radar} title="No indicators match" description={hasFilters ? 'Try removing a filter.' : undefined} />
        ) : (
          <div className={cn('transition-opacity', intel.loading && 'opacity-60')}>
            <div className="overflow-x-auto">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Indicator</th>
                    <th>Type</th>
                    <th>Reputation</th>
                    <th>Confidence</th>
                    <th>Source</th>
                    <th>First seen</th>
                    <th>Last seen</th>
                    <th>Alerts</th>
                  </tr>
                </thead>
                <tbody>
                  {intel.data.items.map((item) => (
                    <tr key={item.id}>
                      <td className="max-w-sm min-w-64">
                        <Mono className="break-all text-fg">{item.indicator}</Mono>
                        {item.description && <div className="mt-0.5 text-xs text-muted">{item.description}</div>}
                      </td>
                      <td className="whitespace-nowrap text-muted">{INDICATOR_TYPE_LABEL[item.type]}</td>
                      <td>
                        <ReputationBadge reputation={item.reputation} />
                      </td>
                      <td>
                        <ConfidenceBar value={item.confidence} />
                      </td>
                      <td className="whitespace-nowrap text-muted">{item.source}</td>
                      <td className="text-muted">
                        <Time iso={item.firstSeen} relative />
                      </td>
                      <td className="text-muted">
                        <Time iso={item.lastSeen} relative />
                      </td>
                      <td>
                        <IndicatorAlerts indicator={item} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination pagination={intel.data.pagination} onPageChange={setPage} />
          </div>
        )}
      </Card>

      <AddIndicatorDialog open={adding} onClose={() => setAdding(false)} onCreated={intel.reload} />
    </>
  );
}
