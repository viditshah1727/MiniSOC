// Alerts by severity: an at-a-glance part-to-whole (4 segments) with the total
// in the middle. The legend lists every count and share, so no value depends
// on reading angles or colours.
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip, type TooltipContentProps } from 'recharts';
import type { DashboardStats } from '../../types/api';
import { formatNumber } from '../../utils/format';
import { SEVERITY_COLOR, SEVERITY_LABEL } from '../../utils/labels';
import { CHART_COLORS } from './chartTheme';

type Slice = DashboardStats['alertsBySeverity'][number];

function SliceTooltip({ active, payload }: TooltipContentProps) {
  const slice = payload?.[0]?.payload as Slice | undefined;
  if (!active || !slice) return null;
  return (
    <div className="rounded-md border border-line-strong bg-overlay px-3 py-2 text-xs shadow-lg shadow-black/40">
      <span className="tabular font-semibold text-fg">{formatNumber(slice.count)}</span>{' '}
      <span className="text-muted">{SEVERITY_LABEL[slice.severity]}</span>
    </div>
  );
}

export function SeverityDonut({ data }: { data: DashboardStats['alertsBySeverity'] }) {
  const total = data.reduce((sum, slice) => sum + slice.count, 0);

  return (
    <div className="flex flex-col items-center gap-4 sm:flex-row sm:justify-center lg:flex-col xl:flex-row">
      <div className="relative size-44 shrink-0" role="img" aria-label={`${total} alerts by severity`}>
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={total ? data : [{ severity: 'INFO', count: 1 }]}
              dataKey="count"
              nameKey="severity"
              innerRadius="68%"
              outerRadius="100%"
              paddingAngle={total ? 2 : 0}
              stroke={CHART_COLORS.surface}
              strokeWidth={2}
              isAnimationActive={false}
            >
              {(total ? data : [{ severity: 'INFO' as const, count: 1 }]).map((slice) => (
                <Cell key={slice.severity} fill={total ? SEVERITY_COLOR[slice.severity] : CHART_COLORS.grid} />
              ))}
            </Pie>
            {total > 0 && <Tooltip content={SliceTooltip} />}
          </PieChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-semibold text-fg">{formatNumber(total)}</span>
          <span className="text-xs text-muted">alerts</span>
        </div>
      </div>

      <ul className="w-full max-w-56 space-y-2 text-sm">
        {data.map((slice) => (
          <li key={slice.severity} className="flex items-center gap-2">
            <span aria-hidden className="size-2.5 rounded-sm" style={{ backgroundColor: SEVERITY_COLOR[slice.severity] }} />
            <span className="flex-1 text-muted">{SEVERITY_LABEL[slice.severity]}</span>
            <span className="tabular font-medium text-fg">{formatNumber(slice.count)}</span>
            <span className="tabular w-10 text-right text-xs text-faint">
              {total ? `${Math.round((slice.count / total) * 100)}%` : '–'}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}
