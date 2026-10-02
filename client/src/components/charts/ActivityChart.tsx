// Events and alerts over time as two aligned "small multiples" that share the
// time axis. Events number in the tens and alerts in single digits, so one
// plot with two y-axes would invent a relationship; two stacked plots don't.
// syncId links them: hovering either shows one crosshair and one tooltip.
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  type TooltipContentProps,
  XAxis,
  YAxis,
} from 'recharts';
import type { DashboardRange, DashboardStats } from '../../types/api';
import { formatBucket, formatDateTime, formatNumber } from '../../utils/format';
import { AXIS_TICK, CHART_COLORS } from './chartTheme';

type Point = DashboardStats['eventsOverTime'][number] & { label: string };

function ActivityTooltip({ active, payload }: TooltipContentProps) {
  const point = payload?.[0]?.payload as Point | undefined;
  if (!active || !point) return null;
  return (
    <div className="rounded-md border border-line-strong bg-overlay px-3 py-2 text-xs shadow-lg shadow-black/40">
      <p className="mb-1.5 text-muted">{formatDateTime(point.bucket)}</p>
      {(
        [
          ['Events', point.events, CHART_COLORS.series1],
          ['Alerts', point.alerts, CHART_COLORS.series2],
        ] as const
      ).map(([name, value, color]) => (
        <p key={name} className="flex items-center gap-2">
          <span aria-hidden className="h-0.5 w-3 rounded-full" style={{ backgroundColor: color }} />
          <span className="tabular font-semibold text-fg">{formatNumber(value)}</span>
          <span className="text-muted">{name}</span>
        </p>
      ))}
    </div>
  );
}

function Legend() {
  return (
    <div className="mb-2 flex items-center gap-4 text-xs text-muted">
      <span className="flex items-center gap-1.5">
        <span aria-hidden className="h-0.5 w-3 rounded-full" style={{ backgroundColor: CHART_COLORS.series1 }} />
        Events (top)
      </span>
      <span className="flex items-center gap-1.5">
        <span aria-hidden className="size-2 rounded-sm" style={{ backgroundColor: CHART_COLORS.series2 }} />
        Alerts (bottom)
      </span>
    </div>
  );
}

export function ActivityChart({ data, range }: { data: DashboardStats['eventsOverTime']; range: DashboardRange }) {
  const points: Point[] = data.map((point) => ({ ...point, label: formatBucket(point.bucket, range) }));
  const margin = { top: 8, right: 8, bottom: 0, left: 0 };

  return (
    <div role="img" aria-label="Security events and alerts over time. Use the Table button for the values.">
      <Legend />
      <ResponsiveContainer width="100%" height={170}>
        <AreaChart data={points} syncId="activity" margin={margin}>
          <CartesianGrid vertical={false} stroke={CHART_COLORS.grid} />
          <XAxis dataKey="label" hide />
          <YAxis allowDecimals={false} tick={AXIS_TICK} axisLine={false} tickLine={false} width={36} className="tabular" />
          <Tooltip content={ActivityTooltip} cursor={{ stroke: CHART_COLORS.tick, strokeWidth: 1 }} />
          <Area
            type="monotone"
            dataKey="events"
            name="Events"
            stroke={CHART_COLORS.series1}
            strokeWidth={2}
            fill={CHART_COLORS.series1}
            fillOpacity={0.1}
            activeDot={{ r: 4, stroke: CHART_COLORS.surface, strokeWidth: 2 }}
            isAnimationActive={false}
          />
        </AreaChart>
      </ResponsiveContainer>
      <ResponsiveContainer width="100%" height={96}>
        <BarChart data={points} syncId="activity" margin={margin}>
          <CartesianGrid vertical={false} stroke={CHART_COLORS.grid} />
          <XAxis
            dataKey="label"
            tick={AXIS_TICK}
            axisLine={{ stroke: CHART_COLORS.axis }}
            tickLine={false}
            interval="preserveStartEnd"
            minTickGap={28}
          />
          <YAxis allowDecimals={false} tick={AXIS_TICK} axisLine={false} tickLine={false} width={36} />
          {/* Cursor only: the events chart above shows the shared tooltip. */}
          <Tooltip content={() => null} cursor={{ fill: CHART_COLORS.cursorFill }} />
          <Bar dataKey="alerts" name="Alerts" fill={CHART_COLORS.series2} radius={[4, 4, 0, 0]} maxBarSize={24} isAnimationActive={false} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
