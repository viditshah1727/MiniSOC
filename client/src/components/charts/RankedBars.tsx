// A ranked horizontal bar chart drawn with plain HTML. Used where labels are
// long or need badges (IP + reputation, rule code + name), which SVG axis
// labels handle badly. One series, so every bar uses the same colour.
import type { ReactNode } from 'react';
import { Link } from 'react-router';
import { formatNumber } from '../../utils/format';
import { CHART_COLORS } from './chartTheme';

export interface RankedBar {
  key: string;
  label: ReactNode;
  value: number;
  /** Extra detail shown next to the value, e.g. "40 events". */
  detail?: string;
  /** Makes the row a link (e.g. to the filtered alert list). */
  href?: string;
}

export function RankedBars({ bars, unit }: { bars: RankedBar[]; unit: string }) {
  const max = Math.max(1, ...bars.map((bar) => bar.value));

  return (
    <ul className="space-y-1">
      {bars.map((bar) => {
        const content = (
          <>
            <div className="mb-1 flex items-center justify-between gap-3 text-sm">
              <span className="min-w-0 truncate">{bar.label}</span>
              <span className="shrink-0 text-xs text-muted">
                <span className="tabular font-semibold text-fg">{formatNumber(bar.value)}</span> {unit}
                {bar.detail && <span className="text-faint"> · {bar.detail}</span>}
              </span>
            </div>
            <div className="h-2 rounded-r bg-transparent">
              <div
                className="h-full rounded-r transition-[width]"
                style={{ width: `${(bar.value / max) * 100}%`, minWidth: bar.value ? 4 : 0, backgroundColor: CHART_COLORS.series1 }}
              />
            </div>
          </>
        );
        return (
          <li key={bar.key}>
            {bar.href ? (
              <Link to={bar.href} className="block rounded-md px-2 py-1.5 hover:bg-raised/70">
                {content}
              </Link>
            ) : (
              <div className="px-2 py-1.5">{content}</div>
            )}
          </li>
        );
      })}
    </ul>
  );
}
