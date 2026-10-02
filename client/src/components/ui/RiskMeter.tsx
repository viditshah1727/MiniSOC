// Risk score (0-100) as a number plus a meter. The fill colour carries the
// risk level; the track is a faint step of the same colour, so the level
// reads across the whole bar (and the number/label carry it without colour).
import type { RiskLevel } from '../../types/api';
import { cn } from '../../utils/cn';
import { SEVERITY_COLOR, SEVERITY_LABEL } from '../../utils/labels';

interface RiskMeterProps {
  score: number;
  level: RiskLevel;
  size?: 'sm' | 'lg';
  /** Hide the number when it is already shown nearby (e.g. the hero figure). */
  showValue?: boolean;
  className?: string;
}

export function RiskMeter({ score, level, size = 'sm', showValue = true, className }: RiskMeterProps) {
  const color = SEVERITY_COLOR[level];
  const label = `Risk ${score} of 100 (${SEVERITY_LABEL[level]})`;
  return (
    <div className={cn('flex items-center gap-2', className)} title={label}>
      {showValue && <span className={cn('tabular font-semibold text-fg', size === 'lg' ? 'text-base' : 'w-7 text-sm')}>{score}</span>}
      <div
        role="meter"
        aria-label={label}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={score}
        className={cn('overflow-hidden rounded-full', size === 'lg' ? 'h-2 flex-1' : 'h-1.5 w-14')}
        style={{ backgroundColor: `${color}2e` }}
      >
        <div className="h-full rounded-full" style={{ width: `${score}%`, backgroundColor: color }} />
      </div>
    </div>
  );
}
