// KPI tiles for the dashboard: one hero figure (overall risk) plus stat tiles.
import type { LucideIcon } from 'lucide-react';
import type { ReactNode } from 'react';
import { Link } from 'react-router';
import type { RiskLevel } from '../../types/api';
import { cn } from '../../utils/cn';
import { formatNumber } from '../../utils/format';
import { CHART_COLORS } from '../charts/chartTheme';
import { SeverityBadge } from '../ui/Badges';
import { Card } from '../ui/Card';
import { RiskMeter } from '../ui/RiskMeter';

/** The one number the dashboard leads with. */
export function RiskHero({ score, level, openAlerts }: { score: number; level: RiskLevel; openAlerts: number }) {
  return (
    <Card className="flex flex-col justify-between p-5" aria-label="Overall risk score">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-medium text-muted">Overall risk</h2>
        <SeverityBadge severity={level} />
      </div>
      <p className="mt-2 flex items-baseline gap-1">
        <span className="text-6xl leading-none font-semibold tracking-tight text-fg">
          {score}
        </span>
        <span className="text-lg text-faint">/100</span>
      </p>
      <div className="mt-4">
        <RiskMeter score={score} level={level} size="lg" showValue={false} />
        <p className="mt-2 text-xs text-muted">
          Average risk of {formatNumber(openAlerts)} open alert{openAlerts === 1 ? '' : 's'} ·{' '}
          <Link to="/alerts?sort=risk" className="text-accent hover:underline">
            triage by risk
          </Link>
        </p>
      </div>
    </Card>
  );
}

interface StatTileProps {
  label: string;
  value: number;
  icon: LucideIcon;
  caption: ReactNode;
  href: string;
  /** Draws attention when the number needs action (e.g. critical alerts > 0). */
  attention?: boolean;
  trend?: number[];
}

export function StatTile({ label, value, icon: Icon, caption, href, attention = false, trend }: StatTileProps) {
  return (
    <Link to={href} className="group block min-w-0">
      <Card className={cn('flex h-full flex-col p-4 transition-colors group-hover:border-line-strong', attention && 'border-sev-critical/40')}>
        <div className="flex items-center justify-between">
          <h2 className="text-sm text-muted">{label}</h2>
          <Icon aria-hidden className={cn('size-4', attention ? 'text-sev-critical' : 'text-faint')} />
        </div>
        <p className="mt-2 text-3xl font-semibold text-fg">{formatNumber(value)}</p>
        <div className="mt-auto flex items-end justify-between gap-2 pt-2">
          <p className="text-xs text-muted">{caption}</p>
          {trend && <Sparkline values={trend} />}
        </div>
      </Card>
    </Link>
  );
}

/** Tiny trend line in the series colour; decorative, the caption states the value. */
function Sparkline({ values }: { values: number[] }) {
  const width = 72;
  const height = 22;
  const max = Math.max(1, ...values);
  const step = values.length > 1 ? width / (values.length - 1) : width;
  const points = values.map((value, i) => `${(i * step).toFixed(1)},${(height - 2 - (value / max) * (height - 4)).toFixed(1)}`);

  return (
    <svg aria-hidden width={width} height={height} className="shrink-0 overflow-visible">
      <polyline points={points.join(' ')} fill="none" stroke={CHART_COLORS.series1} strokeWidth={1.5} strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  );
}
